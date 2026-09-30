import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from cryptography.fernet import InvalidToken
from sqlalchemy.engine import make_url
from typer.testing import CliRunner

from funsecret import (
    CacheSecretManage,
    SecretManage,
    clear_secret_db,
    decrypt,
    encrypt,
    file_decrypt,
    file_encrypt,
    generate_key,
    get_md5_file,
    get_md5_str,
    list_sectet,
    load_secret_db,
    read_cache_secret,
    read_secret,
    save_secret_db,
    write_cache_secret,
    write_secret,
)
from funsecret.cli import app


@pytest.fixture
def manage(tmp_path: Path) -> SecretManage:
    return SecretManage(secret_dir=str(tmp_path))


def test_database_path(manage: SecretManage, tmp_path: Path) -> None:
    assert manage.engine.url.database == str(tmp_path / ".funsecret.db")


def test_import_does_not_create_cache_directory(tmp_path: Path) -> None:
    cache_path = tmp_path / "cache"
    env = os.environ.copy()
    env["FUN_CACHE_SECRET_PATH"] = str(cache_path)

    result = subprocess.run(
        [sys.executable, "-c", "import funsecret"],
        capture_output=True,
        check=False,
        env=env,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert not cache_path.exists()


def test_cache_secret_manager_and_default_functions(tmp_path: Path) -> None:
    from funsecret.secret import cache_secret

    manager = CacheSecretManage(
        secret_dir=str(tmp_path / "cache"), cipher_key=generate_key()
    )
    try:
        manager.write("app", "prod", value="encrypted")
        manager.write("app", "plain", value="visible", secret=False)
        assert manager.read("app", "prod") == "encrypted"
        assert manager.read("app", "plain", secret=False) == "visible"
        assert manager.read("missing", "value") is None

        with patch.object(cache_secret, "cache_manage", return_value=manager):
            write_cache_secret("wrapper", "app", "wrapper")
            assert read_cache_secret("app", "wrapper") == "wrapper"
    finally:
        manager.cache.close()


@pytest.mark.parametrize("function_name", ["load_os_environ", "save_os_environ"])
def test_cache_environment_functions(tmp_path: Path, function_name: str) -> None:
    from funsecret.secret import cache_secret

    manager = CacheSecretManage(
        secret_dir=str(tmp_path / function_name), cipher_key=generate_key()
    )
    try:
        with (
            patch.object(cache_secret, "cache_manage", return_value=manager),
            patch.dict(
                cache_secret.os.environ, {"FUNSECRET_TEST_VALUE": "saved"}, clear=True
            ),
        ):
            getattr(cache_secret, function_name)()
        assert manager.read("os", "environ", "FUNSECRET_TEST_VALUE") == "saved"
    finally:
        manager.cache.close()


def test_read_write_list_and_expiry(manage: SecretManage) -> None:
    manage.write("中文-secret", "app", "prod", "token")

    assert manage.read("app", "prod", "token") == "中文-secret"
    assert manage.list_secret() == {"app": {"prod": {"token": "中文-secret"}}}

    manage.write_key("expired", "value", expire_time=-1)
    assert manage.read_key("expired", save=False) is None


def test_default_database_functions(manage: SecretManage) -> None:
    import funsecret.secret.secret as secret_module

    with patch.object(secret_module, "cache_manage", return_value=manage):
        write_secret("value", "app", "prod")
        assert read_secret("app", "prod") == "value"
        assert list_sectet() == {"app": {"prod": "value"}}


def test_database_save_load_and_clear(tmp_path: Path, monkeypatch) -> None:
    import funsecret.secret.secret as secret_module

    monkeypatch.setenv("FUN_SECRET_PATH", str(tmp_path / "home"))
    default = SecretManage(secret_dir=str(tmp_path / "default"))
    default.write("source-value", "app", "prod")
    backup_url = f"sqlite:///{tmp_path / 'backup.db'}"

    with patch.object(secret_module, "cache_manage", return_value=default):
        save_secret_db(url=backup_url)

    backup = SecretManage(url=backup_url, secret_dir=str(tmp_path / "backup-key"))
    assert backup.read("app", "prod", secret=False, save=False) == "source-value"

    restored = SecretManage(secret_dir=str(tmp_path / "restored"))
    with patch.object(secret_module, "cache_manage", return_value=restored):
        load_secret_db(url=backup_url)
    assert restored.read("app", "prod", save=False) == "source-value"

    clear_secret_db(url=backup_url)
    assert SecretManage(url=backup_url).scalars() == []


def test_write_never_logs_secret_value_or_cipher_key(tmp_path: Path) -> None:
    with patch("funsecret.secret.secret.logger.debug") as debug:
        manage = SecretManage(secret_dir=str(tmp_path))
        manage.write("super-secret-value", "app", "prod")

    messages = " ".join(str(call) for call in debug.call_args_list)
    assert "super-secret-value" not in messages
    assert manage.cipher_key not in messages


def test_text_encryption_and_invalid_token() -> None:
    key = generate_key()
    encrypted = encrypt("中文-secret", key)

    assert encrypted != "中文-secret"
    assert decrypt(encrypted, key) == "中文-secret"
    with pytest.raises(InvalidToken):
        decrypt("not-a-token", key)


def test_file_encryption_round_trip(tmp_path: Path) -> None:
    key = generate_key()
    source = tmp_path / "source.txt"
    source.write_text("secret", encoding="utf-8")

    encrypted_path = file_encrypt(source, cipher_key=key)
    source.unlink()
    decrypted_path = file_decrypt(encrypted_path, cipher_key=key)

    assert Path(decrypted_path).read_text(encoding="utf-8") == "secret"


def test_file_encryption_requires_key(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    source.write_text("secret", encoding="utf-8")

    with pytest.raises(ValueError, match="cipher_key"):
        file_encrypt(source)


def test_md5_helpers(tmp_path: Path) -> None:
    source = tmp_path / "value.txt"
    source.write_text("hello", encoding="utf-8")

    assert get_md5_str("hello") == "5d41402abc4b2a76b9719d911017c592"
    assert get_md5_file(source, chunk=2) == get_md5_str("hello")


def test_cli_write_and_read() -> None:
    runner = CliRunner()
    with patch("funsecret.cli.write_secret") as write_secret:
        result = runner.invoke(app, ["write", "value", "app", "prod"])
    assert result.exit_code == 0
    write_secret.assert_called_once_with("value", "app", "prod", "", "", "")

    with patch("funsecret.cli.read_secret", return_value="value"):
        result = runner.invoke(app, ["read", "app", "prod"])
    assert result.exit_code == 0
    assert result.stdout.strip() == "value"


def test_cli_list_never_prints_values() -> None:
    with patch(
        "funsecret.cli.list_sectet", return_value={"app": {"prod": "secret-value"}}
    ):
        result = CliRunner().invoke(app, ["list"])

    assert result.exit_code == 0
    assert result.stdout.strip() == "app prod"
    assert "secret-value" not in result.stdout


def test_cli_info_hides_database_password() -> None:
    engine = SimpleNamespace(
        url=make_url("mysql+pymysql://user:secret-password@localhost/funsecret")
    )
    manager = SimpleNamespace(engine=engine, cipher_key="configured")
    with (
        patch("funsecret.cli.SecretManage", return_value=manager),
        patch("funsecret.cli.list_sectet", return_value={}),
    ):
        result = CliRunner().invoke(app, ["info"])

    assert result.exit_code == 0
    assert "secret-password" not in result.stdout
    assert "***" in result.stdout


def test_cli_uses_stored_database_url() -> None:
    with (
        patch("funsecret.cli.read_secret", return_value="sqlite:///backup.db"),
        patch("funsecret.cli.load_secret_db") as load_secret_db,
    ):
        result = CliRunner().invoke(app, ["load"])

    assert result.exit_code == 0
    load_secret_db.assert_called_once_with(url="sqlite:///backup.db", cipher_key=None)
