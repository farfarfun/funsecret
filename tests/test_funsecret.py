from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from cryptography.fernet import InvalidToken
from sqlalchemy.engine import make_url
from typer.testing import CliRunner

from funsecret import (
    SecretManage,
    decrypt,
    encrypt,
    file_decrypt,
    file_encrypt,
    generate_key,
)
from funsecret.cli import app


@pytest.fixture
def manage(tmp_path: Path) -> SecretManage:
    return SecretManage(secret_dir=str(tmp_path))


def test_database_path(manage: SecretManage, tmp_path: Path) -> None:
    assert manage.engine.url.database == str(tmp_path / ".funsecret.db")


def test_read_write_list_and_expiry(manage: SecretManage) -> None:
    manage.write("中文-secret", "app", "prod", "token")

    assert manage.read("app", "prod", "token") == "中文-secret"
    assert manage.list_secret() == {"app": {"prod": {"token": "中文-secret"}}}

    manage.write_key("expired", "value", expire_time=-1)
    assert manage.read_key("expired", save=False) is None


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
