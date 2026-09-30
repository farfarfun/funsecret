# funsecret-snapshot

`funsecret-snapshot` 使用 `fundrive` 和 `funtable` 备份、恢复 funsecret 数据库。

该 distribution 有意安装到 `funsecret.snapshot` 命名空间，以扩展主包 API；它与主包共用
仓库和版本号以保证同步发布。调整为独立顶层导入名属于破坏性变更。

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
