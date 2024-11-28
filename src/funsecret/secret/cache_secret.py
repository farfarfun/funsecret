import base64
import os
import time

from diskcache import Cache
from funutil import getLogger

from funsecret.fernet import decrypt, encrypt

logger = getLogger("funsecret")


class CacheSecretManage:
    def __init__(self, secret_dir=None, cipher_key=None, *args, **kwargs):
        if secret_dir is None:
            secret_dir = os.environ.get("FUN_CACHE_SECRET_PATH")
        if secret_dir is None:
            secret_dir = f'{os.environ.get("FUN_CACHE_SECRET_HOME") or os.environ["HOME"]}/.secret_cache'
        self.cache = Cache(secret_dir=secret_dir)
        self.cipher_key = (
            cipher_key or base64.urlsafe_b64encode(secret_dir.encode("utf-8")).decode()
        )

    def encrypt(self, text):
        """
        加密，我也没测试过，不知道能不能正常使用，纯字母的应该没问题，中文的待商榷
        :param text: 需要加密的文本
        :return: 加密后的文本
        """
        return encrypt(text, self.cipher_key)

    def decrypt(self, encrypted_text):
        """
        解密，我也没测试过，不知道能不能正常使用，纯字母的应该没问题，中文的待商榷
        :param encrypted_text: 需要解密的文本
        :return:解密后的文本
        """
        return decrypt(encrypted_text, self.cipher_key)

    def read(
        self,
        cate1,
        cate2,
        cate3="",
        cate4="",
        cate5="",
        value=None,
        save=True,
        secret=True,
        expire_time=None,
    ):
        """
        按照分类读取保存的key，如果为空或者已过期，则返回None
        :param cate1: cate1
        :param cate2: cate2
        :param cate3: cate3
        :param cate4: cate4
        :param cate5: cate5
        :param value: 保存的数据
        :param save: 是否需要保存，保存的话，会覆盖当前保存的数据
        :param secret: 是否需要加密，如果加密的话，构造类的时候，cipher_key不能为空，这是加密解密的秘钥
        :param expire_time: 过期时间，unix时间戳，如果小于10000000的话，会当做保存数据的持续时间，加上当前的Unix时间戳作为过期时间
        :return: 保存的数据
        """
        cache_key = f"{cate1}-{cate2}-{cate3}-{cate4}-{cate5}"
        cache_value = value

        if secret:
            cache_key = self.encrypt(cache_key)
            cache_value = self.encrypt(cache_value) if cache_value else None

        if expire_time is not None and expire_time < 1000000000:
            expire_time += int(time.time())
        if save:
            self.write(
                value,
                cate1,
                cate2,
                cate3,
                cate4,
                cate5,
                secret=secret,
                expire_time=expire_time,
            )
        if value is not None:
            return value
        value = self.cache.get(cache_key)
        return self.decrypt(value) if value is not None and secret else value

    def write(
        self,
        value,
        cate1,
        cate2="",
        cate3="",
        cate4="",
        cate5="",
        secret=True,
        expire_time=99999999,
    ):
        """
        对数据进行保存
        :param value: 保存的数据
        :param cate1:cate1
        :param cate2:cate2
        :param cate3:cate3
        :param cate4:cate4
        :param cate5:cate5
        :param secret: 是否需要加密
        :param expire_time:过期时间，默认不过期
        """
        if value is None:
            return
        cache_key = f"{cate1}-{cate2}-{cate3}-{cate4}-{cate5}"
        cache_value = value

        if secret:
            cache_key = self.encrypt(cache_key)
            cache_value = self.encrypt(cache_value) if cache_value else None

        if expire_time is not None and expire_time < 1000000000:
            expire_time += int(time.time())

        self.cache.set(cache_key, cache_value, expire=expire_time)


def read_cache_secret(
    cate1,
    cate2,
    cate3="",
    cate4="",
    cate5="",
    value=None,
    save=True,
    secret=True,
    expire_time=9999999,
):
    manage = CacheSecretManage()
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
    if value is None:
        logger.warning(
            f"not found value from '{cate1}/{cate2}/{cate3}/{cate4}/{cate5}'"
        )
    return value


def write_cache_secret(
    value,
    cate1,
    cate2="",
    cate3="",
    cate4="",
    cate5="",
    secret=True,
    expire_time=9999999,
):
    manage = CacheSecretManage()
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


def load_os_environ():
    manage = CacheSecretManage()
    for k, v in os.environ.items():
        manage.read(cate1="os", cate2="environ", cate3=k, value=v)


def save_os_environ():
    manage = CacheSecretManage()
    for k, v in os.environ.items():
        manage.read(cate1="os", cate2="environ", cate3=k, value=v)
