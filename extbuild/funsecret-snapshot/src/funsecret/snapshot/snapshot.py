"""把 funsecret 数据库保存到云盘快照或从中恢复。"""

from pathlib import Path
from tempfile import TemporaryDirectory

from fundrive.core import BaseDrive
from funtable.snapshot import DriveSnapshot

from funsecret import load_secret_db, save_secret_db

DATABASE_NAME = "funsecret.db"


def save_snapshot(table_fid: str, drive: BaseDrive) -> None:
    """把默认密钥数据库保存到指定云盘快照表。"""
    with TemporaryDirectory() as directory:
        database = Path(directory) / DATABASE_NAME
        save_secret_db(url=f"sqlite:///{database}")
        DriveSnapshot(table_fid=table_fid, drive=drive).update(
            str(database), partition="backup"
        )


def load_snapshot(table_fid: str, drive: BaseDrive) -> None:
    """下载最新云盘快照并加载到默认密钥数据库。"""
    with TemporaryDirectory() as directory:
        DriveSnapshot(table_fid=table_fid, drive=drive).download(directory)
        database = Path(directory) / DATABASE_NAME
        if not database.is_file():
            raise FileNotFoundError("快照中没有 funsecret.db")
        load_secret_db(url=f"sqlite:///{database}")
