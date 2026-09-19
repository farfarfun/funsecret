import base64
import os
import time
from datetime import datetime
from typing import Any, TypeAlias
from urllib.parse import quote_plus

from farcache import cache
from farlog import getLogger
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
SecretTree: TypeAlias = dict[str, Any]


class Base(DeclarativeBase):
    """SQLAlchemy 声明式模型基类。"""


@cache
def create_engine(uri: str, *args: Any, **kwargs: Any) -> Engine:
    """创建并缓存数据库引擎。"""
    return create_engine2(uri, *args, **kwargs)


def get_secret_url(secret_url: str | None = None) -> str | None:
    """优先返回显式数据库地址，否则读取环境变量。"""
    if secret_url is not None:
        return secret_url
    return os.environ.get("FUN_SECRET_URL")


def get_secret_path(secret_dir: str | None = None) -> str:
    """返回本地密钥目录，并在缺失时创建。"""
    secret_dir = secret_dir or "~/.secret"
    secret_dir = secret_dir.replace(
        "~", os.environ.get("FUN_SECRET_PATH", os.environ["HOME"])
    )
    if not os.path.exists(secret_dir):
        os.makedirs(secret_dir)
    return secret_dir


class SecretTable(Base):
    """数据库中的单条密钥记录。"""

    __tablename__ = "secret"
    __table_args__ = (UniqueConstraint("key"),)
    gmt_create: Mapped[datetime] = mapped_column(
        comment="创建时间", default=datetime.now
    )
    gmt_modified: Mapped[datetime] = mapped_column(
        comment="修改时间", default=datetime.now, onupdate=datetime.now
    )

    key: Mapped[str] = mapped_column(
        String(200), comment="key", default="", primary_key=True
    )
    value: Mapped[str] = mapped_column(Text, comment="value", default="")

    expire_time: Mapped[int] = mapped_column(
        BIGINT, comment="过期时间", default=9999999999
    )

    @cache
    def exists(self, session: Session) -> bool:
        """判断当前键是否已经存在。"""
        return (
            session.execute(
                select(SecretTable).where(SecretTable.key == self.key)
            ).first()
            is not None
        )

    def to_dict(self) -> dict[str, str | int]:
        """返回可写入数据库的字段。"""
        return {"key": self.key, "value": self.value, "expire_time": self.expire_time}

    def upsert(
        self,
        session: Session,
        update_data: bool = True,
        commit: bool = True,
        existing_keys: set[str] | None = None,
    ) -> None:
        """按键新增或更新记录。"""
        key_exists = (
            self.key in existing_keys
            if existing_keys is not None
            else self.exists(session)
        )
        if not key_exists:
            session.execute(insert(SecretTable).values(**self.to_dict()))
            if existing_keys is not None:
                existing_keys.add(self.key)
        elif update_data:
            session.execute(
                update(SecretTable)
                .where(SecretTable.key == self.key)
                .values(**self.to_dict())
            )
        if commit:
            session.commit()

    @staticmethod
    def delete_all(engine: Engine) -> None:
        """删除指定数据库中的全部密钥。"""
        logger.warning(f"delete_all:{SecretTable.__tablename__}")
        with Session(engine) as session:
            session.execute(delete(SecretTable))
            session.commit()


class SecretManage:
    """管理本地或远端数据库中的加密密钥。"""

    def __init__(
        self,
        secret_dir: str | None = None,
        url: str | None = None,
        cipher_key: str | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        secret_dir = get_secret_path(secret_dir)
        secret_url = get_secret_url(url)

        if secret_url is not None:
            self.engine = create_engine(secret_url)
        else:
            self.engine = create_engine(
                f"sqlite:///{os.path.join(secret_dir, '.funsecret.db')}"
            )

        if cipher_key:
            self.cipher_key = cipher_key
        else:
            self.cipher_key = base64.urlsafe_b64encode(
                quote_plus(secret_dir * 2)[:32].encode("utf-8")
            ).decode()
        Base.metadata.create_all(self.engine)

    @staticmethod
    def convert_key(
        cate1: str,
        cate2: str,
        cate3: str | None = None,
        cate4: str | None = None,
        cate5: str | None = None,
    ) -> str:
        """把最多五级分类转换为数据库键。"""
        return f"{cate1}--{cate2}--{cate3}--{cate4}--{cate5}"

    def encrypt(self, text: str, secret: bool = True) -> str:
        """按配置加密文本；关闭加密时原样返回。"""
        if secret and self.cipher_key:
            encrypted = encrypt(text, self.cipher_key)
            assert encrypted is not None
            return encrypted
        return text

    def decrypt(self, encrypted_text: str, secret: bool = True) -> str:
        """按配置解密文本；关闭解密时原样返回。"""
        if secret and self.cipher_key:
            decrypted = decrypt(encrypted_text, self.cipher_key)
            assert decrypted is not None
            return decrypted
        return encrypted_text

    def scalars(self) -> list[SecretTable]:
        """返回数据库中的全部密钥记录。"""
        with Session(self.engine) as session:
            return [data for data in session.execute(select(SecretTable)).scalars()]

    def list_secret(self, secret: bool = True) -> SecretTree:
        """返回按分类嵌套的密钥树，并清理过期记录。"""
        result: SecretTree = {}

        with Session(self.engine) as session:
            session.execute(
                delete(SecretTable).where(SecretTable.expire_time < time.time())
            )
            session.commit()

            datas = session.execute(select(SecretTable)).scalars()
            for data in datas:
                key = self.decrypt(data.key, secret=secret)
                value = self.decrypt(data.value, secret=secret)
                parts = [part for part in (key or "").split("--") if part]

                if not parts:
                    continue

                current = result
                for part in parts[:-1]:
                    current = current.setdefault(part, {})
                current[parts[-1]] = value

        return result

    def read_key(
        self,
        key: str,
        value: str | None = None,
        save: bool = True,
        secret: bool = True,
        expire_time: int | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> str | None:
        """读取键；传入 value 时先写入，过期或不存在时返回 ``None``。"""
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

    def write_key(
        self,
        key: str,
        value: str | None,
        secret: bool = True,
        expire_time: int | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """写入键值；短过期时间按相对秒数处理。"""
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
        self,
        cate1: str,
        cate2: str,
        cate3: str = "",
        cate4: str = "",
        cate5: str = "",
        value: str | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> str | None:
        """按分类路径读取密钥；传入 value 时先写入。"""
        key = self.convert_key(cate1, cate2, cate3, cate4, cate5)
        return self.read_key(key, value=value, **kwargs)

    def write(
        self,
        value: str,
        cate1: str,
        cate2: str = "",
        cate3: str = "",
        cate4: str = "",
        cate5: str = "",
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """按分类路径写入密钥。"""
        self.write_key(
            key=self.convert_key(cate1, cate2, cate3, cate4, cate5),
            value=value,
            **kwargs,
        )


@cache
def cache_manage() -> SecretManage:
    """返回默认的密钥管理实例。"""
    return SecretManage()


def read_secret(
    cate1: str,
    cate2: str,
    cate3: str = "",
    cate4: str = "",
    cate5: str = "",
    value: str | None = None,
    *args: Any,
    **kwargs: Any,
) -> str | None:
    """从默认数据库读取密钥；传入 value 时先写入。"""
    value = cache_manage().read(
        cate1=cate1,
        cate2=cate2,
        cate3=cate3,
        cate4=cate4,
        cate5=cate5,
        value=value,
        **kwargs,
    )
    if value is None:
        logger.debug(f"not found value from {cate1}/{cate2}/{cate3}/{cate4}/{cate5}")
    return value


def write_secret(
    value: str,
    cate1: str,
    cate2: str = "",
    cate3: str = "",
    cate4: str = "",
    cate5: str = "",
    *args: Any,
    **kwargs: Any,
) -> None:
    """向默认数据库写入密钥。"""
    cache_manage().write(
        value=value,
        cate1=cate1,
        cate2=cate2,
        cate3=cate3,
        cate4=cate4,
        cate5=cate5,
        **kwargs,
    )


def list_sectet(secret: bool = True) -> SecretTree:
    """返回默认数据库中的密钥树。"""
    return cache_manage().list_secret(secret=secret)


def _syc_secret_db(
    manage1: SecretManage,
    manage2: SecretManage,
    source_secret: bool = True,
    target_secret: bool = True,
) -> None:
    with Session(manage2.engine) as session:
        existing_keys = {
            row[0] for row in session.execute(select(SecretTable.key)).all()
        }
        pbar = tqdm(manage1.scalars())
        for success, entity in enumerate(pbar, start=1):
            entity.key = manage2.encrypt(
                manage1.decrypt(entity.key, secret=source_secret),
                secret=target_secret,
            )
            entity.value = manage2.encrypt(
                manage1.decrypt(entity.value, secret=source_secret),
                secret=target_secret,
            )
            entity.upsert(session, commit=False, existing_keys=existing_keys)
            pbar.set_description(f"success: {success}")
        session.commit()


def load_secret_db(url: str | None = None, cipher_key: str | None = None) -> None:
    """从指定数据库加载密钥到默认数据库。"""
    manage1 = SecretManage(url=url, cipher_key=cipher_key)
    manage2 = cache_manage()
    _syc_secret_db(manage1, manage2, source_secret=cipher_key is not None)


def save_secret_db(url: str | None = None, cipher_key: str | None = None) -> None:
    """把默认数据库中的密钥保存到指定数据库。"""
    manage1 = SecretManage(url=url, cipher_key=cipher_key)
    manage2 = cache_manage()
    _syc_secret_db(manage2, manage1, target_secret=cipher_key is not None)


def clear_secret_db(url: str | None = None, cipher_key: str | None = None) -> None:
    """清空指定数据库；未指定时清空默认数据库。"""
    manage = SecretManage(url=url, cipher_key=cipher_key)
    SecretTable.delete_all(manage.engine)
