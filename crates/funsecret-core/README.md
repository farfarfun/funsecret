# funsecret-core

`funsecret-core` 是 [funsecret](https://github.com/farfarfun/funsecret) 的纯 Rust 核心引擎，提供：

- 与 Python `cryptography.fernet` 字节级兼容的确定性/标准 Fernet 字符串与文件加解密、MD5 摘要；
- 本地 SQLite（`~/.secret/.funsecret.db`）加密密钥库管理，支持 2–5 级分类路径、过期时间与增删改查；
- SQLite / MySQL 数据库双向同步（兼容 `mysql+pymysql://` 等历史 URL 前缀）；
- 本地 SQLite TTL 短期缓存（`CacheSecretManage`）。

该 crate 零 Python 依赖，可直接嵌入 Rust 服务或工具链使用。
