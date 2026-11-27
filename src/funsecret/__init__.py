"""funsecret —— 本地优先加密密钥管理（Rust 核心 + PyO3 包装）。

本模块仅做再导出，核心实现在 Rust 扩展 ``funsecret._funsecret`` 中，Python 侧零运行时依赖。
原生命令行工具通过 cargo / apt / brew / GitHub Release 分发。
"""

from pkgutil import extend_path

__path__ = extend_path(__path__, __name__)

from ._funsecret import (  # noqa: E402
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
    get_secret_path,
    get_secret_url,
    list_secret,
    load_secret_db,
    read_cache_secret,
    read_secret,
    save_secret_db,
    write_cache_secret,
    write_secret,
)

# 兼容历史拼写别名
list_sectet = list_secret

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
