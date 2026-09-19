import base64
import hashlib
import os
from urllib.parse import quote_plus

from diskcache import Cache
from farlog import getLogger

from funsecret.fernet import decrypt, encrypt

logger = getLogger("funsecret")


class CacheSecretManage:
    """使用 diskcache 保存短期密钥。"""

    def __init__(
        self,
        secret_dir: str | None = None,
        cipher_key: str | None = None,
        *args: object,
        **kwargs: object,
    ) -> None:
        if secret_dir is None:
            secret_dir = os.environ.get("FUN_CACHE_SECRET_PATH")
        if secret_dir is None:
            secret_dir = f"{os.environ.get('FUN_CACHE_SECRET_HOME') or os.environ['HOME']}/.secret/cache"
        self.cache = Cache(directory=secret_dir)
        self.cipher_key = (
            cipher_key
            or base64.urlsafe_b64encode(
                quote_plus(secret_dir * 2)[:32].encode("utf-8")
            ).decode()
        )

    def encrypt(self, text: str) -> str:
        """使用当前密钥加密文本。"""
        encrypted = encrypt(text, self.cipher_key)
        assert encrypted is not None
        return encrypted

    def decrypt(self, encrypted_text: str) -> str:
        """使用当前密钥解密文本。"""
        decrypted = decrypt(encrypted_text, self.cipher_key)
        assert decrypted is not None
        return decrypted

    @staticmethod
    def _get_key(
        cate1: str,
        cate2: str,
        cate3: str = "",
        cate4: str = "",
        cate5: str = "",
    ) -> str:
        """把分类路径转换为缓存键。"""
        key = f"{cate1}-{cate2}-{cate3}-{cate4}-{cate5}"
        return hashlib.md5(key.encode(), usedforsecurity=False).hexdigest()

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
    ) -> str | None:
        """按分类路径读取缓存；传入 value 时先写入。"""
        cache_key = self._get_key(
            cate1=cate1, cate2=cate2, cate3=cate3, cate4=cate4, cate5=cate5
        )

        if save and value is not None:
            self.write(
                cate1=cate1,
                cate2=cate2,
                cate3=cate3,
                cate4=cate4,
                cate5=cate5,
                value=value,
                secret=secret,
                expire_time=expire_time,
            )
        if value is not None:
            return value

        cached_value: str | None = self.cache.get(cache_key)
        if cached_value is None:
            logger.warning(
                f"not found value from '{cate1}/{cate2}/{cate3}/{cate4}/{cate5}'"
            )
            return cached_value
        return self.decrypt(cached_value) if secret else cached_value

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
    ) -> None:
        """按分类路径写入缓存；expire_time 的单位为秒。"""
        if value is None:
            logger.error("value cannot be None")
            return
        cache_key = self._get_key(
            cate1=cate1, cate2=cate2, cate3=cate3, cate4=cate4, cate5=cate5
        )
        cache_value = self.encrypt(value) if secret else value
        self.cache.set(cache_key, cache_value, expire=expire_time)


manage = CacheSecretManage()


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
) -> str | None:
    """从默认缓存读取密钥；传入 value 时先写入。"""
    value = manage.read(
        cate1=cate1,
        cate2=cate2,
        cate3=cate3,
        cate4=cate4,
        cate5=cate5,
        value=value,
        save=save,
        secret=secret,
        expire_time=expire_time,
    )
    return value


def write_cache_secret(
    value: str,
    cate1: str,
    cate2: str = "",
    cate3: str = "",
    cate4: str = "",
    cate5: str = "",
    secret: bool = True,
    expire_time: float | None = None,
) -> None:
    """向默认缓存写入密钥。"""
    manage.write(
        value=value,
        cate1=cate1,
        cate2=cate2,
        cate3=cate3,
        cate4=cate4,
        cate5=cate5,
        secret=secret,
        expire_time=expire_time,
    )


def load_os_environ() -> None:
    """把当前环境变量写入默认缓存。"""
    for k, v in os.environ.items():
        manage.read(cate1="os", cate2="environ", cate3=k, value=v)


def save_os_environ() -> None:
    """把当前环境变量保存到默认缓存。"""
    for k, v in os.environ.items():
        manage.read(cate1="os", cate2="environ", cate3=k, value=v)
