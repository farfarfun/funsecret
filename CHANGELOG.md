# Changelog

## 2.1.0

### 变更

- **PyPI `funsecret` 不再打包命令行入口（完全对齐 `funget` 1.2+）**：`pip install funsecret` 仅提供零依赖 Python API，不再链接 `clap` 与 `env_logger`，减小 wheel 体积并避免与 `/usr/bin/funsecret` 抢占 `PATH`。命令行统一通过 `apt`、`brew`、`cargo install funsecret` 或 GitHub Release 静态二进制安装。

## 2.0.2（funsecret-core 0.2.0）

### 新增

- 为 `save` / `load`（以及 Python 的 `save_secret_db` / `load_secret_db`）接入原生 Rust 进度条 `indicatif`：在交互终端自动显示连接 Spinner 与同步进度条，非 TTY / `--json` / `-s --silent` 自动隐藏。
- 普通终端模式下 `funsecret save` / `funsecret load` 完成后明确打印结果汇总（如 `saved 42 secrets` / `loaded 42 secrets`），不再静默退出。
- `funsecret-core` 统一在 `sync_to` / `load_secret_db` / `save_secret_db` 接收 `progress: bool` 参数，避免拆分重复 API（同步升至 `0.2.0`）。

## 2.0.1

### 新增

- **`pip install funsecret` 重新提供 `funsecret` 命令行入口**：通过 PyO3 复用 Rust 原生 `funsecret::run`，旧版 Python 用户执行 `pip install -U funsecret` 即可无感升级到 Rust 版命令行（同时继续保留 `cargo install` / `apt` / `brew` / GitHub Release 独立静态二进制渠道，两者同源同版本）。

## 2.0.0（funsecret-core 0.1.0）

### 破坏性变更

- 主包与快照扩展的 Python 最低版本提升至 3.12；使用 3.10/3.11 的环境需升级解释器后再安装新版本。
- **核心引擎全面重写为 Rust（三 crate 虚拟工作区，对齐 `funget` 架构）**：
  - `funsecret-core`（0.1.0）：纯 Rust 核心库，零 Python 依赖，内置 Fernet 加解密、SQLite3 / MySQL（含 MariaDB）/ PostgreSQL 多库存储与同步及原生 SQLite 短期缓存。
  - `funsecret`（CLI 二进制）：原生静态命令行工具，通过 `cargo install` / `apt` / `brew` / GitHub Release 分发。
  - PyPI `funsecret`（PyO3 扩展，abi3-py312）：**零运行时依赖，仅提供 Python API，不再安装 `funsecret` 命令行入口**。
- 移除 SQLAlchemy 运行时依赖及 `SecretTable` ORM 类导出；`CacheSecretManage` 底层由 `diskcache` 迁移为原生 SQLite TTL 缓存（历史 `~/.secret/cache` 临时缓存不自动迁移）。

### 新增

- 原生支持 **SQLite3 / MySQL（MariaDB）/ PostgreSQL** 三类数据库，自动归一化 SQLAlchemy 风格方言 URL 前缀（`sqlite+pysqlite:///`、`mysql+pymysql://`、`mariadb+mariadbconnector://`、`postgresql+psycopg2://`、`postgres://` 等），支持跨库无缝迁移。
- CLI 新增 `delete`（别名 `rm`）单条删除、`write --stdin` 安全写入（支持多行与 `-` 开头密钥值且不进入进程参数）、`write --expire` TTL 设置，以及所有子命令的 `--json` 结构化输出。
- Python API 新增 `delete_secret`、`list_secret`（保留历史 `list_sectet` 别名）、`InvalidToken` 及 `.pyi` 类型存根。
- 新增 GitHub Actions CI、多平台 wheel/CLI/deb 自动发布工作流与与 Python `cryptography.fernet` 的逐字节差分兼容测试。

### 修复

- 修复 Windows 环境下未设置 `HOME` 时读取默认密钥目录可能触发 `KeyError` 的问题（支持回退 `USERPROFILE`）。

## 1.4.97

### 新增

- 补充密钥读写、加解密、文件加解密、CLI 和快照扩展测试。

### 修复

- 禁止日志输出密钥值，并让无效密文抛出明确的解密异常。
- 快照扩展改用当前数据库同步 API，修复已删除接口导致的运行错误。
- 默认缓存管理器改为首次调用时创建，导入包不再创建缓存目录。
- 明文数据库同步按明文键查询，修复保存后无法读取的问题。
- 本地密钥数据库目录/文件、缓存目录落盘权限收紧为仅当前用户可读写（0700/0600），避免多用户环境下被其他本地账户读取。
- 修复 `load_os_environ` 与 `save_os_environ` 实现完全相同、`load` 方向从未真正从缓存恢复环境变量的问题。

### 变更

- 主包和快照扩展迁移至 Hatchling；`uv.lock` 不纳入版本管理。
- 更新公开 API 的类型标注与中文说明，提升 `farlog` 依赖下限。
- 主包与快照扩展使用据实描述，并记录命名空间扩展兼容约束。

### 废弃

（无）

## 1.4.96 及更早版本

早期版本未维护 CHANGELOG，具体变更参见 git 提交历史。
