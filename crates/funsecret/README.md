# funsecret CLI

`funsecret` 是本地优先的加密密钥管理命令行工具，零 Python 运行时依赖，支持：

- `funsecret write` / `funsecret write --stdin`：写入 2–5 级分类路径密钥（可选 `--expire` TTL）；
- `funsecret read`：按分类路径读取密钥（支持 `--json`）；
- `funsecret delete`：删除单条密钥；
- `funsecret list`：列出所有密钥路径，不显示值（支持 `--json` 返回时间戳与过期元数据）；
- `funsecret info`：显示存储后端、数据库位置与条目数（支持 `--json`）；
- `funsecret save` / `funsecret load`：与外部 SQLite / MySQL 数据库同步；
- `funsecret clear`：清空当前密钥数据库。
