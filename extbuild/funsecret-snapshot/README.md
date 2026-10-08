# funsecret-snapshot

`funsecret-snapshot` 使用 `fundrive` 和 `funtable` 备份、恢复 funsecret 数据库。

该 distribution 有意安装到 `funsecret.snapshot` 命名空间，以扩展主包 API；它与主包共用
仓库和版本号以保证同步发布。调整为独立顶层导入名属于破坏性变更。

## 安装

```bash
pip install "funsecret-snapshot" "fundrive[dropbox]"
```

## 使用

先设置 Dropbox access token：

```bash
export DROPBOX_ACCESS_TOKEN="your-dropbox-access-token"
```

```python
import os

from fundrive.drives.dropbox import DropboxDrive
from funsecret.snapshot import load_snapshot, save_snapshot

drive = DropboxDrive()
if not drive.login(access_token=os.environ["DROPBOX_ACCESS_TOKEN"]):
    raise RuntimeError("Dropbox login failed")

table_fid = "/funsecret-snapshots"
if not drive.exist(table_fid):
    drive.mkdir("", "funsecret-snapshots")

save_snapshot(table_fid=table_fid, drive=drive)
load_snapshot(table_fid=table_fid, drive=drive)
```

`table_fid` 是保存快照的云盘目录 ID；其他 `fundrive` 驱动也可替换 `DropboxDrive`，具体认证方式参见 [fundrive 文档](https://github.com/farfarfun/fundrive)。
