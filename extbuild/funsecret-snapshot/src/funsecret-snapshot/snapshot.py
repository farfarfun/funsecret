import os
from datetime import datetime

from fundb.json import JSONStorage
from fundrive import LanZouSnapshot
from funsecret import SecretManage


def save_snapshot(bin_id, cipher_key, security_key):
    manage = SecretManage()
    bin_id = bin_id or manage.read("os", "environ", "FUNSECRET_SNAPSHOT_BIN_ID")
    cipher_key = cipher_key or manage.read("os", "environ", "FUNSECRET_SNAPSHOT_CIPHER_KEY")
    security_key = security_key or manage.read("os", "environ", "FUNSECRET_SNAPSHOT_CIPHER_KEY")

    cache_tmp = "./tmp/funsecret.cache"
    version = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    manage.read("os", "environ", "FUNSECRET_SNAPSHOT_VERSION", value=version)
    url = manage.read("os", "environ", "FUNSECRET_SNAPSHOT_URL")
    pwd = manage.read("os", "environ", "FUNSECRET_SNAPSHOT_PWD")
    fid = manage.read("os", "environ", "FUNSECRET_SNAPSHOT_FID")
    data = {"url": url, "pwd": pwd, "version": version}

    manage.save_secret_str(path=cache_tmp, cipher_key=cipher_key)
    LanZouSnapshot(fid=fid).update(file_path=cache_tmp)
    JSONStorage().update(bin_id, data=data, security_key=security_key)


def load_snapshot(bin_id, cipher_key, security_key):
    manage = SecretManage()
    bin_id = bin_id or manage.read("os", "environ", "FUNSECRET_SNAPSHOT_BIN_ID")
    cipher_key = cipher_key or manage.read("os", "environ", "FUNSECRET_SNAPSHOT_CIPHER_KEY")
    security_key = security_key or manage.read("os", "environ", "FUNSECRET_SNAPSHOT_CIPHER_KEY")

    cache_tmp = "./tmp/funsecret.cache"
    data = JSONStorage().request(bin_id, security_key=security_key)
    version = manage.read("os", "environ", "FUNSECRET_SNAPSHOT_VERSION")
    if version is not None and version == data["version"]:
        print("your version id newest.")
        return

    LanZouSnapshot(url=data["url"], pwd=data["pwd"]).download(dir_path=os.path.dirname(cache_tmp))
    manage.load_secret_str(path=cache_tmp, cipher_key=cipher_key)
