"""兼容旧导入路径 ``funsecret.fernet.fernet``。"""

from .._funsecret import (
    InvalidToken,
    decrypt,
    encrypt,
    file_decrypt,
    file_encrypt,
    generate_key,
    get_md5_file,
    get_md5_str,
)

__all__ = [
    "InvalidToken",
    "decrypt",
    "encrypt",
    "file_decrypt",
    "file_encrypt",
    "generate_key",
    "get_md5_file",
    "get_md5_str",
]
