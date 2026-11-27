from os import PathLike
from typing import Any

SecretTree = dict[str, Any]

class InvalidToken(ValueError): ...

class SecretManage:
    cipher_key: str
    secret_dir: str
    backend: str
    database_url: str
    database_file: str | None

    def __init__(
        self,
        secret_dir: str | None = None,
        url: str | None = None,
        cipher_key: str | None = None,
    ) -> None: ...
    @staticmethod
    def convert_key(
        cate1: str,
        cate2: str,
        cate3: str | None = None,
        cate4: str | None = None,
        cate5: str | None = None,
    ) -> str: ...
    def encrypt(self, text: str, secret: bool = True) -> str: ...
    def decrypt(self, encrypted_text: str, secret: bool = True) -> str: ...
    def read_key(
        self,
        key: str,
        value: str | None = None,
        save: bool = True,
        secret: bool = True,
        expire_time: int | None = None,
    ) -> str | None: ...
    def write_key(
        self,
        key: str,
        value: str | None,
        secret: bool = True,
        expire_time: int | None = None,
    ) -> None: ...
    def delete_key(self, key: str, secret: bool = True) -> bool: ...
    def read(
        self,
        cate1: str,
        cate2: str,
        cate3: str = "",
        cate4: str = "",
        cate5: str = "",
        value: str | None = None,
        save: bool = True,
        secret: bool = True,
        expire_time: int | None = None,
    ) -> str | None: ...
    def write(
        self,
        value: str,
        cate1: str,
        cate2: str = "",
        cate3: str = "",
        cate4: str = "",
        cate5: str = "",
        secret: bool = True,
        expire_time: int | None = None,
    ) -> None: ...
    def delete(
        self,
        cate1: str,
        cate2: str,
        cate3: str = "",
        cate4: str = "",
        cate5: str = "",
        secret: bool = True,
    ) -> bool: ...
    def list_secret(self, secret: bool = True) -> SecretTree: ...
    def list_entries(self, secret: bool = True) -> list[dict[str, Any]]: ...
    def info(self) -> dict[str, Any]: ...
    def clear(self) -> int: ...
    def sync_to(
        self,
        target: SecretManage,
        source_secret: bool = True,
        target_secret: bool = True,
    ) -> int: ...

class CacheSecretManage:
    cipher_key: str
    secret_dir: str

    def __init__(
        self,
        secret_dir: str | None = None,
        cipher_key: str | None = None,
    ) -> None: ...
    def encrypt(self, text: str) -> str: ...
    def decrypt(self, encrypted_text: str) -> str: ...
    def read(
        self,
        cate1: str,
        cate2: str,
        cate3: str = "",
        cate4: str = "",
        cate5: str = "",
        value: str | None = None,
        save: bool = True,
        secret: bool = True,
        expire_time: float | None = None,
    ) -> str | None: ...
    def write(
        self,
        cate1: str,
        cate2: str,
        cate3: str = "",
        cate4: str = "",
        cate5: str = "",
        value: str | None = None,
        secret: bool = True,
        expire_time: float | None = None,
    ) -> None: ...

def generate_key() -> str: ...
def encrypt(text: str | None, cipher_key: str | None = None) -> str | None: ...
def decrypt(encrypted_text: str | None, cipher_key: str | None = None) -> str | None: ...
def file_encrypt(
    src_path: str | PathLike[str],
    dst_path: str | PathLike[str] | None = None,
    cipher_key: str | None = None,
) -> str: ...
def file_decrypt(
    src_path: str | PathLike[str],
    dst_path: str | PathLike[str] | None = None,
    cipher_key: str | None = None,
) -> str: ...
def get_md5_str(value: str) -> str: ...
def get_md5_file(path: str | PathLike[str], chunk: int = 4096) -> str: ...
def get_secret_path(secret_dir: str | None = None) -> str: ...
def get_secret_url(secret_url: str | None = None) -> str | None: ...
def read_secret(
    cate1: str,
    cate2: str,
    cate3: str = "",
    cate4: str = "",
    cate5: str = "",
    value: str | None = None,
    save: bool = True,
    secret: bool = True,
    expire_time: int | None = None,
) -> str | None: ...
def write_secret(
    value: str,
    cate1: str,
    cate2: str = "",
    cate3: str = "",
    cate4: str = "",
    cate5: str = "",
    secret: bool = True,
    expire_time: int | None = None,
) -> None: ...
def delete_secret(
    cate1: str,
    cate2: str,
    cate3: str = "",
    cate4: str = "",
    cate5: str = "",
    secret: bool = True,
) -> bool: ...
def list_secret(secret: bool = True) -> SecretTree: ...
def list_sectet(secret: bool = True) -> SecretTree: ...
def load_secret_db(url: str | None = None, cipher_key: str | None = None) -> None: ...
def save_secret_db(url: str | None = None, cipher_key: str | None = None) -> None: ...
def clear_secret_db(url: str | None = None, cipher_key: str | None = None) -> None: ...
def read_cache_secret(
    cate1: str,
    cate2: str,
    cate3: str = "",
    cate4: str = "",
    cate5: str = "",
    value: str | None = None,
    save: bool = True,
    secret: bool = True,
    expire_time: float | None = None,
) -> str | None: ...
def write_cache_secret(
    value: str,
    cate1: str,
    cate2: str = "",
    cate3: str = "",
    cate4: str = "",
    cate5: str = "",
    secret: bool = True,
    expire_time: float | None = None,
) -> None: ...

__all__ = [
    "CacheSecretManage",
    "InvalidToken",
    "SecretManage",
    "clear_secret_db",
    "decrypt",
    "delete_secret",
    "encrypt",
    "file_decrypt",
    "file_encrypt",
    "generate_key",
    "get_md5_file",
    "get_md5_str",
    "get_secret_path",
    "get_secret_url",
    "list_secret",
    "list_sectet",
    "load_secret_db",
    "read_cache_secret",
    "read_secret",
    "save_secret_db",
    "write_cache_secret",
    "write_secret",
]
