import os
import pickle
import time

import orjson
from funddb.sqlalchemy import Base, BaseTable, create_engine, create_engine_sqlite
from funutil import getLogger
from sqlalchemy import BIGINT, String, UniqueConstraint, delete, select
from sqlalchemy.orm import mapped_column

from funsecret.fernet import decrypt, encrypt

local_secret_path = "~/.secret"
logger = getLogger("funsecret")


def set_secret_path(path):
    global local_secret_path
    local_secret_path = path


class SecretTable(Base):
    __tablename__ = "secret_manage"
    __table_args__ = (UniqueConstraint("cate1", "cate2", "cate3", "cate4", "cate5"),)

    cate1 = mapped_column(String(100), comment="一级分类", default="", primary_key=True)
    cate2 = mapped_column(String(100), comment="二级分类", default="", primary_key=True)
    cate3 = mapped_column(String(100), comment="三级分类", default="", primary_key=True)
    cate4 = mapped_column(String(100), comment="四级分类", default="", primary_key=True)
    cate5 = mapped_column(String(100), comment="五级分类", default="", primary_key=True)
    value = mapped_column(String(100), comment="值", default="")

    expire_time = mapped_column(BIGINT, comment="过期时间", default=9999999999)


class SecretManage(BaseTable):
    def __init__(self, secret_dir=None, url=None, cipher_key=None, *args, **kwargs):
        self.cipher_key = cipher_key
        if url is not None:
            uri = url
            engine = create_engine(uri)
        else:
            secret_dir = secret_dir or local_secret_path
            secret_dir = secret_dir.replace(
                "~", os.environ.get("FUN_SECRET_PATH", os.environ["HOME"])
            )
            if not os.path.exists(secret_dir):
                os.makedirs(secret_dir)
            engine = create_engine_sqlite(f"{secret_dir}/.funsecret.db")
        super(SecretManage, self).__init__(
            table=SecretTable, engine=engine, *args, **kwargs
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
        secret=False,
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

        self.execute(delete(SecretTable).where(SecretTable.expire_time < time.time()))

        sql = select(SecretTable.value, SecretTable.expire_time).where(
            SecretTable.cate1 == cate1,
            SecretTable.cate2 == cate2,
            SecretTable.cate3 == cate3,
            SecretTable.cate4 == cate4,
            SecretTable.cate5 == cate5,
        )
        data = [line for line in self.execute(sql)]
        if len(data) > 0:
            value, expire_time = data[0]
            if secret:
                value = self.decrypt(value)
            if (
                expire_time is None
                or expire_time == "None"
                or int(time.time()) < expire_time
            ):
                return value

        return None

    def write(
        self,
        value,
        cate1,
        cate2="",
        cate3="",
        cate4="",
        cate5="",
        secret=False,
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
        if expire_time is not None and expire_time < 1000000000:
            expire_time += int(time.time())
        if secret:
            value = self.encrypt(value)

        properties = {
            "cate1": cate1,
            "cate2": cate2,
            "cate3": cate3,
            "cate4": cate4,
            "cate5": cate5,
            "value": value,
            "expire_time": expire_time,
        }

        self.upsert(values=properties)

    def save_secret_str(self, path="~/.secret/secret_str", cipher_key=None):
        path = path.replace("~", os.environ["HOME"])
        res = []
        all_data = self.select_all()
        if cipher_key is not None:
            all_data["value"] = all_data["value"].apply(
                lambda x: encrypt(x, cipher_key)
            )
        with open(path, "wb") as fw:
            pickle.dump(all_data, fw)

        return res

    def load_secret_str(
        self, all_data=None, path="~/.secret/secret_str", cipher_key=None
    ):
        path = path.replace("~", os.environ["HOME"])
        if all_data is None:
            if not os.path.exists(path):
                print(f"{path} is not exists.")
                return
            with open(path, "rb") as fr:
                all_data = pickle.load(fr)
        all_data["value"] = all_data["value"].apply(lambda x: decrypt(x, cipher_key))
        for line in orjson.loads(all_data.to_json(orient="records")):
            self.write(**line)


def read_secret(
    cate1,
    cate2,
    cate3="",
    cate4="",
    cate5="",
    value=None,
    save=True,
    secret=False,
    expire_time=9999999,
):
    manage = SecretManage()
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
        logger.debug(f"not found value from {cate1}/{cate2}/{cate3}/{cate4}/{cate5}")
    return value


def write_secret(
    value,
    cate1,
    cate2="",
    cate3="",
    cate4="",
    cate5="",
    secret=False,
    expire_time=9999999,
):
    manage = SecretManage()
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


def save_secret_str(path="~/.secret/secret_str"):
    return SecretManage().save_secret_str(path)


def load_secret_str(secret_str=None, path="~/.secret/secret_str"):
    SecretManage().load_secret_str(secret_str, path)


def load_os_environ():
    manage = SecretManage()
    for k, v in os.environ.items():
        manage.read(cate1="os", cate2="environ", cate3=k, value=v)


def save_os_environ():
    manage = SecretManage()
    for k, v in os.environ.items():
        manage.read(cate1="os", cate2="environ", cate3=k, value=v)
