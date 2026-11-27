"""短期加密缓存包装（核心由 Rust SQLite 实现）。"""

import os

from .._funsecret import (
    CacheSecretManage,
    read_cache_secret,
    write_cache_secret,
)


def load_os_environ() -> None:
    """用默认缓存中保存的值刷新当前进程里同名的环境变量。"""
    manage = CacheSecretManage()
    for key in list(os.environ.keys()):
        value = manage.read(cate1="os", cate2="environ", cate3=key, save=False)
        if value is not None:
            os.environ[key] = value


def save_os_environ() -> None:
    """把当前环境变量保存到默认缓存。"""
    manage = CacheSecretManage()
    for key, value in os.environ.items():
        manage.read(cate1="os", cate2="environ", cate3=key, value=value)


__all__ = [
    "CacheSecretManage",
    "load_os_environ",
    "read_cache_secret",
    "save_os_environ",
    "write_cache_secret",
]
