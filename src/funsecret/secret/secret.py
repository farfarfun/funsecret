import base64
import os
import time
from datetime import datetime
from typing import List
from urllib.parse import quote_plus

from funutil import getLogger
from funutil.cache import cache
from sqlalchemy import (
    BIGINT,
    Engine,
    String,
    Text,
    UniqueConstraint,
    delete,
    select,
    update,
)
from sqlalchemy import (
    create_engine as create_engine2,
)
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column
from tqdm import tqdm

from funsecret.fernet import decrypt, encrypt

logger = getLogger("funsecret")


class Base(DeclarativeBase):
    pass


@cache
def create_engine(uri, *args, **kwargs):
    return create_engine2(uri)


def get_secret_url(secret_url=None):
    if secret_url is not None:
        return secret_url
    return os.environ.get("FUN_SECRET_URL")


def get_secret_path(secret_dir):
    secret_dir = secret_dir or "~/.secret"
    secret_dir = secret_dir.replace(
        "~", os.environ.get("FUN_SECRET_PATH", os.environ["HOME"])
    )
    if not os.path.exists(secret_dir):
        os.makedirs(secret_dir)
    return secret_dir


class SecretTable(Base):
    __tablename__ = "secret"
    __table_args__ = (UniqueConstraint("key"),)
    gmt_create: Mapped[datetime] = mapped_column(
        comment="创建时间", default=datetime.now
    )
    gmt_modified: Mapped[datetime] = mapped_column(
        comment="修改时间", default=datetime.now, onupdate=datetime.now
    )

    key = mapped_column(String(200), comment="key", default="", primary_key=True)
    value = mapped_column(Text, comment="value", default="")

    expire_time = mapped_column(BIGINT, comment="过期时间", default=9999999999)

    @cache
    def exists(self, session: Session):
        return (
            session.execute(
                select(SecretTable).where(SecretTable.key == self.key)
            ).first()
            is not None
        )

    def to_dict(self):
        return {"key": self.key, "value": self.value, "expire_time": self.expire_time}

    def upsert(self, session: Session, update_data=True):
        logger.debug(f"upsert:{self.to_dict()}")
        if not self.exists(session):
            session.execute(insert(SecretTable).values(**self.to_dict()))
        elif update_data:
            session.execute(
                update(SecretTable)
                .where(SecretTable.key == self.key)
                .values(**self.to_dict())
            )
        session.commit()

    @staticmethod
    def select_all(engine):
        import pandas as pd

        with engine.begin() as conn:
            return pd.read_sql_table(SecretTable.__tablename__, conn)

    @staticmethod
    def delete_all(engine: Engine):
        logger.warning(f"delete_all:{SecretTable.__tablename__}")
        with Session(engine) as session:
            session.execute(delete(SecretTable))
            session.commit()


class SecretManage:
    def __init__(
        self,
        secret_dir: str = None,
        url: str = None,
        cipher_key: str = None,
        *args,
        **kwargs,
    ):
        secret_dir = get_secret_path(secret_dir)
        secret_url = get_secret_url(url)

        if secret_url is not None:
            self.engine = create_engine(secret_url)
        else:
            self.engine = create_engine(f"sqlite:///{secret_dir}/.funsecret.db")

        if cipher_key:
            self.cipher_key = cipher_key
        else:
            self.cipher_key = base64.urlsafe_b64encode(
                quote_plus(secret_dir * 2)[:32].encode("utf-8")
            ).decode()
        logger.debug(f"cipher_key: {self.cipher_key}")
        Base.metadata.create_all(self.engine)

    @staticmethod
    def convert_key(
        cate1: str, cate2: str, cate3: str = None, cate4: str = None, cate5: str = None
    ) -> str:
        return f"{cate1}--{cate2}--{cate3}--{cate4}--{cate5}"

    def encrypt(self, text: str, secret: bool = True) -> str:
        """
        加密，我也没测试过，不知道能不能正常使用，纯字母的应该没问题，中文的待商榷
        :param text: 需要加密的文本
        :param secret:是否加密
        :return: 加密后的文本
        """
        if secret and self.cipher_key:
            return encrypt(text, self.cipher_key)
        return text

    def decrypt(self, encrypted_text: str, secret: bool = True) -> str:
        """
        解密，我也没测试过，不知道能不能正常使用，纯字母的应该没问题，中文的待商榷
        :param encrypted_text: 需要解密的文本
        :param secret:是否加密
        :return:解密后的文本
        """
        if secret and self.cipher_key:
            return decrypt(encrypted_text, self.cipher_key)
        return encrypted_text

    def scalars(self) -> List[SecretTable]:
        with Session(self.engine) as session:
            return [data for data in session.execute(select(SecretTable)).scalars()]

    def read_key(
        self, key, value=None, save=True, secret=True, expire_time=None, *args, **kwargs
    ) -> str:
        """
        按照分类读取保存的key，如果为空或者已过期，则返回None
        :param key: cate1
        :param value: 保存的数据
        :param save: 是否需要保存，保存的话，会覆盖当前保存的数据
        :param secret: 是否需要加密，如果加密的话，构造类的时候，cipher_key不能为空，这是加密解密的秘钥
        :param expire_time: 过期时间，unix时间戳，如果小于10000000的话，会当做保存数据的持续时间，加上当前的Unix时间戳作为过期时间
        :return: 保存的数据
        """
        if expire_time is not None and expire_time < 1000000000:
            expire_time += int(time.time())
        if save:
            self.write_key(key=key, value=value, secret=secret, expire_time=expire_time)
        if value is not None:
            return value

        with Session(self.engine) as session:
            session.execute(
                delete(SecretTable).where(SecretTable.expire_time < time.time())
            )
            session.commit()

            sql = select(SecretTable).where(SecretTable.key == self.encrypt(key))
            datas = session.execute(sql).scalar()
            if datas is not None:
                value, expire_time = datas.value, datas.expire_time
                value = self.decrypt(value, secret=secret)
                if (
                    expire_time is None
                    or expire_time == "None"
                    or int(time.time()) < expire_time
                ):
                    return value
        return None

    def write_key(self, key, value, secret=True, expire_time=None, *args, **kwargs):
        """
        对数据进行保存
        :param value: 保存的数据
        :param key:key
        :param secret: 是否需要加密
        :param expire_time:过期时间，默认不过期
        """
        if value is None:
            return
        expire_time = expire_time or 999999999
        if expire_time is not None and expire_time < 1000000000:
            expire_time += int(time.time())

        with Session(self.engine) as session:
            SecretTable(
                key=self.encrypt(key, secret=secret),
                value=self.encrypt(value, secret=secret),
                expire_time=expire_time,
            ).upsert(session)

    def read(
        self, cate1, cate2, cate3="", cate4="", cate5="", value=None, *args, **kwargs
    ) -> str:
        """
        按照分类读取保存的key，如果为空或者已过期，则返回None
        :param cate1: cate1
        :param cate2: cate2
        :param cate3: cate3
        :param cate4: cate4
        :param cate5: cate5
        :param value: 保存的数据

        :return: 保存的数据
        """
        key = self.convert_key(cate1, cate2, cate3, cate4, cate5)
        return self.read_key(key, value=value, *args, **kwargs)

    def write(
        self, value, cate1, cate2="", cate3="", cate4="", cate5="", *args, **kwargs
    ):
        """
        对数据进行保存
        :param value: 保存的数据
        :param cate1:cate1
        :param cate2:cate2
        :param cate3:cate3
        :param cate4:cate4
        :param cate5:cate5
        """
        self.write_key(
            key=self.convert_key(cate1, cate2, cate3, cate4, cate5),
            value=value,
            *args,
            **kwargs,
        )


@cache
def cache_manage():
    return SecretManage()


def read_secret(
    cate1, cate2, cate3="", cate4="", cate5="", value=None, *args, **kwargs
) -> str:
    value = cache_manage().read(
        cate1=cate1,
        cate2=cate2,
        cate3=cate3,
        cate4=cate4,
        cate5=cate5,
        value=value,
        *args,
        **kwargs,
    )
    if value is None:
        logger.debug(f"not found value from {cate1}/{cate2}/{cate3}/{cate4}/{cate5}")
    return value


def write_secret(value, cate1, cate2="", cate3="", cate4="", cate5="", *args, **kwargs):
    cache_manage().write(
        value=value,
        cate1=cate1,
        cate2=cate2,
        cate3=cate3,
        cate4=cate4,
        cate5=cate5,
        *args,
        **kwargs,
    )


def _syc_secret_db(manage1, manage2):
    with Session(manage2.engine) as session:
        pbar = tqdm(manage1.scalars())
        success = 0
        for entity in pbar:
            try:
                entity.key = manage2.encrypt(manage1.decrypt(entity.key))
                entity.value = manage2.encrypt(manage1.decrypt(entity.value))
                entity.upsert(session)
                success += 1
                pbar.set_description(f"success: {success}")
            except Exception as e:
                logger.error(e)


def load_secret_db(url=None, cipher_key=None):
    manage1 = SecretManage(url=url, cipher_key=cipher_key)
    manage2 = cache_manage()
    _syc_secret_db(manage1, manage2)


def save_secret_db(url=None, cipher_key=None):
    manage1 = SecretManage(url=url, cipher_key=cipher_key)
    manage2 = cache_manage()
    _syc_secret_db(manage2, manage1)
