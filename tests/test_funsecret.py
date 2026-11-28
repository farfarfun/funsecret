import base64
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote_plus

import pytest

from funsecret import (
    CacheSecretManage,
    InvalidToken,
    SecretManage,
    clear_secret_db,
    decrypt,
    delete_secret,
    encrypt,
    file_decrypt,
    file_encrypt,
    generate_key,
    get_md5_file,
    get_md5_str,
    list_secret,
    list_sectet,
    load_secret_db,
    read_cache_secret,
    read_secret,
    save_secret_db,
    write_cache_secret,
    write_secret,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def _cli_binary() -> Path:
    exe_name = "funsecret.exe" if os.name == "nt" else "funsecret"
    target_roots: list[Path] = []
    if env_target := os.environ.get("CARGO_TARGET_DIR"):
        target_roots.append(Path(env_target))
    target_roots.append(REPO_ROOT / "target")
    try:
        meta = subprocess.run(
            ["cargo", "metadata", "--no-deps", "--format-version", "1"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        target_dir = Path(json.loads(meta.stdout)["target_directory"])
        if target_dir not in target_roots:
            target_roots.insert(0, target_dir)
    except Exception:
        pass
    for root in target_roots:
        for profile in ("release", "debug"):
            candidate = root / profile / exe_name
            if candidate.is_file():
                return candidate
    pytest.skip("funsecret Rust CLI binary not built yet")


@pytest.fixture
def manage(tmp_path: Path) -> SecretManage:
    return SecretManage(secret_dir=str(tmp_path))


def test_database_path(manage: SecretManage, tmp_path: Path) -> None:
    assert manage.database_file == str(tmp_path / ".funsecret.db")


@pytest.mark.skipif(os.name != "posix", reason="文件权限位语义仅在 POSIX 系统上适用")
def test_database_file_and_dir_are_owner_only(tmp_path: Path) -> None:
    secret_dir = tmp_path / "owner-only"
    manage = SecretManage(secret_dir=str(secret_dir))
    assert manage.database_file is not None
    db_path = Path(manage.database_file)

    assert stat.S_IMODE(secret_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(db_path.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="文件权限位语义仅在 POSIX 系统上适用")
def test_cache_secret_dir_is_owner_only(tmp_path: Path) -> None:
    cache_dir = tmp_path / "owner-only-cache"
    _manager = CacheSecretManage(secret_dir=str(cache_dir), cipher_key=generate_key())
    assert stat.S_IMODE(cache_dir.stat().st_mode) == 0o700


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


def test_cache_secret_manager_and_default_functions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FUN_CACHE_SECRET_PATH", str(tmp_path / "default-cache"))
    manager = CacheSecretManage(
        secret_dir=str(tmp_path / "cache"), cipher_key=generate_key()
    )
    manager.write("app", "prod", value="encrypted")
    manager.write("app", "plain", value="visible", secret=False)
    assert manager.read("app", "prod") == "encrypted"
    assert manager.read("app", "plain", secret=False) == "visible"
    assert manager.read("missing", "value") is None

    write_cache_secret("wrapper", "app", "wrapper")
    assert read_cache_secret("app", "wrapper") == "wrapper"


def test_save_and_load_os_environ(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from funsecret.secret import cache_secret

    monkeypatch.setenv("FUN_CACHE_SECRET_PATH", str(tmp_path / "env-cache"))
    monkeypatch.setenv("FUNSECRET_TEST_VALUE", "saved")
    cache_secret.save_os_environ()

    monkeypatch.setenv("FUNSECRET_TEST_VALUE", "stale")
    cache_secret.load_os_environ()
    assert os.environ["FUNSECRET_TEST_VALUE"] == "saved"


def test_read_write_delete_list_and_expiry(manage: SecretManage) -> None:
    manage.write("中文-secret", "app", "prod", "token")

    assert manage.read("app", "prod", "token") == "中文-secret"
    assert manage.list_secret() == {"app": {"prod": {"token": "中文-secret"}}}

    manage.write_key("expired", "value", expire_time=-1)
    assert manage.read_key("expired", save=False) is None

    assert manage.delete("app", "prod", "token") is True
    assert manage.delete("app", "prod", "token") is False
    assert manage.read("app", "prod", "token") is None


def test_default_database_functions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FUN_SECRET_PATH", str(tmp_path))
    monkeypatch.delenv("FUN_SECRET_URL", raising=False)

    write_secret("value", "app", "prod")
    assert read_secret("app", "prod") == "value"
    assert list_secret() == {"app": {"prod": "value"}}
    assert list_sectet() == {"app": {"prod": "value"}}
    assert delete_secret("app", "prod") is True
    assert read_secret("app", "prod") is None


def test_database_save_load_and_clear(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("FUN_SECRET_URL", raising=False)
    default_home = tmp_path / "home"
    restored_home = tmp_path / "restored-home"
    backup_url = f"sqlite:///{tmp_path / 'backup.db'}"

    monkeypatch.setenv("FUN_SECRET_PATH", str(default_home))
    write_secret("source-value", "app", "prod")
    save_secret_db(url=backup_url)

    backup = SecretManage(url=backup_url, secret_dir=str(tmp_path / "backup-key"))
    assert backup.read("app", "prod", secret=False, save=False) == "source-value"

    monkeypatch.setenv("FUN_SECRET_PATH", str(restored_home))
    load_secret_db(url=backup_url)
    assert read_secret("app", "prod", save=False) == "source-value"

    clear_secret_db(url=backup_url)
    assert backup.list_entries(secret=False) == []


def test_text_encryption_and_invalid_token() -> None:
    key = generate_key()
    encrypted = encrypt("中文-secret", key)

    assert encrypted != "中文-secret"
    assert decrypt(encrypted, key) == "中文-secret"
    with pytest.raises(InvalidToken):
        decrypt("not-a-token", key)


def test_fernet_differential_compatibility_with_python_cryptography(
    tmp_path: Path,
) -> None:
    """确认 Rust 确定性 Fernet 与历史 Python cryptography.fernet 逐字节一致。"""
    fernet_mod = pytest.importorskip("cryptography.fernet")
    key = generate_key()
    py_fernet = fernet_mod.Fernet(key.encode())
    py_token = py_fernet._encrypt_from_parts(
        "中文-secret-兼容测试".encode(), 1024, b"123456789abcdefg"
    ).decode()
    rs_token = encrypt("中文-secret-兼容测试", key)

    assert rs_token == py_token
    assert decrypt(py_token, key) == "中文-secret-兼容测试"

    # 默认目录派生密钥必须与历史 Python 公式完全一致
    manage = SecretManage(secret_dir=str(tmp_path / "compat"))
    expected_key = base64.urlsafe_b64encode(
        quote_plus(str(tmp_path / "compat") * 2)[:32].encode("utf-8")
    ).decode()
    assert manage.cipher_key == expected_key


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


def test_rust_cli_end_to_end(tmp_path: Path) -> None:
    bin_path = _cli_binary()
    env = os.environ.copy()
    env["FUN_SECRET_PATH"] = str(tmp_path)
    env.pop("FUN_SECRET_URL", None)

    def run_cli(*args: str, stdin_text: str | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(bin_path), *args],
            input=stdin_text,
            capture_output=True,
            text=True,
            env=env,
            check=False,
            timeout=15,
        )

    # 通过 --stdin 写入含连字符开头与多行的密钥值
    secret_val = "-starts-with-dash\nline2"
    res = run_cli("write", "--stdin", "--json", "openai", "prod", "api_key", stdin_text=secret_val)
    assert res.returncode == 0, res.stderr
    assert json.loads(res.stdout)["written"] is True

    # list 不得泄露密钥值
    res = run_cli("list")
    assert res.returncode == 0
    assert res.stdout.strip() == "openai prod api_key"
    assert secret_val not in res.stdout

    # list --json 返回元数据且不含 value
    res = run_cli("list", "--json")
    assert res.returncode == 0
    entries = json.loads(res.stdout)
    assert len(entries) == 1
    assert entries[0]["path"] == ["openai", "prod", "api_key"]
    assert "value" not in entries[0]

    # read --json 无损读取多行值
    res = run_cli("read", "--json", "openai", "prod", "api_key")
    assert res.returncode == 0
    assert json.loads(res.stdout)["value"] == secret_val

    # info --json
    res = run_cli("info", "--json")
    assert res.returncode == 0
    info = json.loads(res.stdout)
    assert info["backend"] == "sqlite"
    assert info["secret_count"] == 1
    assert info["cipher_key_configured"] is True

    # delete 单条删除
    res = run_cli("delete", "--json", "openai", "prod", "api_key")
    assert res.returncode == 0
    assert json.loads(res.stdout)["deleted"] is True

    res = run_cli("read", "openai", "prod", "api_key")
    assert res.returncode == 1

    # clear --yes
    run_cli("write", "v1", "a", "b")
    backup_url = f"sqlite:///{tmp_path / 'sync-backup.db'}"
    save_res = run_cli("save", backup_url)
    assert save_res.returncode == 0, save_res.stderr
    assert save_res.stdout.strip() == "saved 1 secret"

    res = run_cli("clear", "--yes", "--json")
    assert res.returncode == 0
    assert json.loads(res.stdout)["cleared"] == 1

    load_res = run_cli("load", backup_url)
    assert load_res.returncode == 0, load_res.stderr
    assert load_res.stdout.strip() == "loaded 1 secret"

    silent_res = run_cli("save", "--silent", backup_url)
    assert silent_res.returncode == 0, silent_res.stderr
    assert silent_res.stdout.strip() == ""


def test_python_wheel_has_no_console_scripts() -> None:
    """对齐 funget：PyPI wheel 只提供 Python API，不安装 funsecret 命令行入口。"""
    import importlib.metadata as metadata

    scripts = [
        ep.name
        for ep in metadata.distribution("funsecret").entry_points
        if ep.group == "console_scripts"
    ]
    assert scripts == []
