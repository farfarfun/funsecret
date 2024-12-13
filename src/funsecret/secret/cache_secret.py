import base64
import hashlib
import os
from urllib.parse import quote_plus

from diskcache import Cache
from funutil import getLogger

from funsecret.fernet import decrypt, encrypt

logger = getLogger("funsecret")


class CacheSecretManage:
    def __init__(self, secret_dir=None, cipher_key=None, *args, **kwargs):
        if secret_dir is None:
            secret_dir = os.environ.get("FUN_CACHE_SECRET_PATH")
        if secret_dir is None:
            secret_dir = f'{os.environ.get("FUN_CACHE_SECRET_HOME") or os.environ["HOME"]}/.secret/cache'
        self.cache = Cache(directory=secret_dir)
        self.cipher_key = (
            cipher_key
            or base64.urlsafe_b64encode(
                quote_plus(secret_dir * 2)[:32].encode("utf-8")
            ).decode()
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

    @staticmethod
    def _get_key(
        cate1,
        cate2,
        cate3="",
        cate4="",
        cate5="",
    ):
        key = f"{cate1}-{cate2}-{cate3}-{cate4}-{cate5}"
        return hashlib.md5(key.encode("utf-8")).hexdigest()

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
        :param expire_time: 过期时间,单位为秒
        :return: 保存的数据
        """
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

        value = self.cache.get(cache_key)
        if value is None:
            logger.warning(
                f"not found value from '{cate1}/{cate2}/{cate3}/{cate4}/{cate5}'"
            )
            return value
        return self.decrypt(value) if secret else value

    def write(
        self,
        cate1,
        cate2,
        cate3="",
        cate4="",
        cate5="",
        value=None,
        secret=True,
        expire_time=None,
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
            logger.error("value cannot be None")
            return
        cache_key = self._get_key(
            cate1=cate1, cate2=cate2, cate3=cate3, cate4=cate4, cate5=cate5
        )
        cache_value = self.encrypt(value) if secret else value
        self.cache.set(cache_key, cache_value, expire=expire_time)


manage = CacheSecretManage()


def read_cache_secret(
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
    value,
    cate1,
    cate2="",
    cate3="",
    cate4="",
    cate5="",
    secret=True,
    expire_time=None,
):
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
    for k, v in os.environ.items():
        manage.read(cate1="os", cate2="environ", cate3=k, value=v)


def save_os_environ():
    for k, v in os.environ.items():
        manage.read(cate1="os", cate2="environ", cate3=k, value=v)
