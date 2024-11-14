import os

from fundrive.core import BaseDrive
from funsecret import SecretManage
from funtable import DriveSnapshot

cache_tmp = "./tmp/funsecret.cache"


def save_snapshot(table_fid, drive: BaseDrive):
    SecretManage().save_secret_str(path=cache_tmp, cipher_key=None)
    snapshot = DriveSnapshot(table_fid=table_fid, drive=drive)
    snapshot.update(cache_tmp, partition="backup")


def load_snapshot(table_fid, drive: BaseDrive):
    snapshot = DriveSnapshot(table_fid=table_fid, drive=drive)
    snapshot.download(dir_path=os.path.dirname(cache_tmp))
    SecretManage().load_secret_str(path=cache_tmp)
