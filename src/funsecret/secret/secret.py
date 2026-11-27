"""兼容旧导入路径 ``funsecret.secret.secret``。"""

from .._funsecret import (
    SecretManage,
    clear_secret_db,
    delete_secret,
    get_secret_path,
    get_secret_url,
    list_secret,
    load_secret_db,
    read_secret,
    save_secret_db,
    write_secret,
)

list_sectet = list_secret

__all__ = [
    "SecretManage",
    "clear_secret_db",
    "delete_secret",
    "get_secret_path",
    "get_secret_url",
    "list_secret",
    "list_sectet",
    "load_secret_db",
    "read_secret",
    "save_secret_db",
    "write_secret",
]
