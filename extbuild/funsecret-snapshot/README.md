# funsecret-snapshot

`funsecret-snapshot` 使用 `fundrive` 和 `funtable` 备份、恢复 funsecret 数据库。

## 安装

```bash
pip install funsecret-snapshot
```

## 使用

```python
from funsecret.snapshot import load_snapshot, save_snapshot

# drive 是已配置好的 fundrive BaseDrive 实例
save_snapshot(table_fid="your-table-file-id", drive=drive)
load_snapshot(table_fid="your-table-file-id", drive=drive)
```
