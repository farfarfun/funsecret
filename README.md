# funsecret

`funsecret` 是一个本地优先的加密密钥管理工具。核心引擎采用 **Rust** 实现（`funsecret-core`），同时提供：

- **原生 CLI 二进制**（`funsecret`）：零 Python 依赖、毫秒级冷启动，内置 **SQLite3 / MySQL（含 MariaDB）/ PostgreSQL** 支持（兼容 SQLAlchemy 方言 URL 前缀，便于跨库迁移），通过 `cargo install` / `apt` / `brew` / GitHub Release 分发；
- **Python 扩展包**（PyPI `funsecret`）：基于 PyO3 + maturin 包装，零运行时依赖，兼容历史 Python API 与 `~/.secret/.funsecret.db` 数据库格式；
- **Rust 核心库**（`funsecret-core`）：供 Rust 服务与工具直接调用。

适合存这些内容：
- 账号密码
- token / access key
- 数据库连接信息
- 其他不想写进代码里的敏感配置

默认把数据保存在本机 `~/.secret/.funsecret.db`（权限 `0600`），按 2–5 级分类路径读取，例如 `app prod mysql password`。

## 安装

### 通过 pip / uv 安装（同时包含 Python API 与 Rust 驱动的 `funsecret` 命令）

```bash
pip install -U funsecret
```

### 独立原生命令行（零 Python 环境依赖）

```bash
# Cargo
cargo install funsecret

# 或从 GitHub Releases 下载对应平台的静态二进制 / .deb
```

本地源码开发：

```bash
cargo build --release --package funsecret
maturin develop --release
```

## 命令行快速开始

写入一个 secret：

```bash
funsecret write my-password app prod mysql password
```

通过 stdin 安全写入（适合含 `-` 开头或多行内容，不暴露在进程参数中）：

```bash
printf '%s' 'sk-xxxxx' | funsecret write --stdin openai prod api_key
```

可选指定过期时间（小于 `1000000000` 按相对秒数，否则按 Unix 时间戳）：

```bash
funsecret write --expire 3600 temp-token app dev token
```

读取一个 secret（支持 `--json` 无损输出）：

```bash
funsecret read app prod mysql password
funsecret read --json app prod mysql password
```

删除单条 secret：

```bash
funsecret delete app prod mysql password
```

查看有哪些 key（只显示路径，不显示值；支持 `--json` 返回时间戳元数据）：

```bash
funsecret list
funsecret list --json
```

查看当前存储信息（支持 `--json`）：

```bash
funsecret info
funsecret info --json
```

清空当前本地 secret：

```bash
funsecret clear
funsecret clear --yes
```

同步到/自外部数据库（支持 SQLite3 / MySQL / MariaDB / PostgreSQL，自动兼容 SQLAlchemy 方言 URL 前缀如 `sqlite+pysqlite:///`、`mysql+pymysql://`、`postgresql+psycopg2://`、`postgres://`）：

```bash
# MySQL / MariaDB
funsecret save mysql+pymysql://username:password@127.0.0.1:3306/funsecret --cipher-key my-secret-key
funsecret load mysql+pymysql://username:password@127.0.0.1:3306/funsecret --cipher-key my-secret-key

# PostgreSQL
funsecret save postgresql+psycopg2://username:password@127.0.0.1:5432/funsecret --cipher-key my-secret-key
funsecret load postgresql://username:password@127.0.0.1:5432/funsecret --cipher-key my-secret-key

# SQLite3
funsecret save sqlite:///backup.db --cipher-key my-secret-key
```

> 不传 `--cipher-key` 时目标库以明文写入/按明文读取；省略 URL 时自动使用 `funsecret db url` 路径中保存的默认地址。

## Python 用法

```python
from funsecret import delete_secret, list_secret, read_secret, write_secret

write_secret("my-password", "app", "prod", "mysql", "password")
password = read_secret("app", "prod", "mysql", "password")
tree = list_secret()
delete_secret("app", "prod", "mysql", "password")
```

## 环境变量

- `FUN_SECRET_PATH`：覆盖默认主目录（密钥目录为 `<FUN_SECRET_PATH>/.secret`）
- `FUN_SECRET_URL`：直接指定数据库 URL（`sqlite:///...` 或 `mysql://...`）
- `FUN_CACHE_SECRET_PATH` / `FUN_CACHE_SECRET_HOME`：短期缓存目录配置

## 快照扩展

云盘快照功能由工作区子包 [extbuild/funsecret-snapshot](extbuild/funsecret-snapshot/README.md) 单独提供。

---

## 关于 farfarfun

[farfarfun](https://github.com/farfarfun) 是一个专注于实用工具库的开源组织，涵盖云存储、数据处理、AI、多媒体与开发工具链等方向。

- 🏠 组织主页：<https://github.com/farfarfun>
- 📦 PyPI：<https://pypi.org/user/niuliangtao/>
- 📧 联系：farfarfun@qq.com

本项目基于 [MIT](LICENSE) 协议开源。
