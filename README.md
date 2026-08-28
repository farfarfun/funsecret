# funsecret

`funsecret` 是一个简单的本地密钥管理工具。

适合存这些内容：
- 账号密码
- token / access key
- 数据库连接信息
- 其他不想写进代码里的敏感配置

它默认把数据保存在本机，按多级分类读取，例如 `app prod mysql password`。

## 安装

```bash
pip install funsecret
```

如果你要同步到 MySQL：

```bash
pip install "funsecret[mysql]"
```

如果你修改了本仓库源码并希望本地直接使用命令：

```bash
pip install -e .
```

## 命令行快速开始

写入一个 secret：

```bash
funsecret write my-password app prod mysql password
```

读取一个 secret：

```bash
funsecret read app prod mysql password
```

查看有哪些 key，只显示路径，不显示 value：

```bash
funsecret list
```

查看当前存储信息：

```bash
funsecret info
```

清空当前本地 secret：

```bash
funsecret clear
```

跳过确认直接清空：

```bash
funsecret clear --yes
```

## 命令说明

### `write`

```bash
funsecret write VALUE CATE1 CATE2 [CATE3] [CATE4] [CATE5]
```

示例：

```bash
funsecret write sk-xxxxx openai prod api_key
funsecret write root123 mysql local root password
```

### `read`

```bash
funsecret read CATE1 CATE2 [CATE3] [CATE4] [CATE5]
```

示例：

```bash
funsecret read openai prod api_key
funsecret read mysql local root password
```

### `list`

```bash
funsecret list
```

输出示例：

```text
openai prod api_key
mysql local root password
```

注意：`list` 不会输出 secret value。

### `info`

```bash
funsecret info
```

输出示例：

```text
backend: sqlite
database_url: sqlite:////Users/you/.secret/.funsecret.db
database_file: /Users/you/.secret/.funsecret.db
secret_count: 2
cipher_key_configured: yes
mysql_example_url: mysql+pymysql://username:password@127.0.0.1:3306/funsecret
```

### `save`

把当前本地 secret 保存到一个数据库。

```bash
funsecret save DB_URL
```

保存到 MySQL：

```bash
funsecret save mysql+pymysql://username:password@127.0.0.1:3306/funsecret
```

如果传了 `--cipher-key`，写入目标库时会加密：

```bash
funsecret save mysql+pymysql://username:password@127.0.0.1:3306/funsecret --cipher-key my-secret-key
```

如果不传 `--cipher-key`，保存到目标库时不加密。

### `load`

从一个数据库加载 secret 到当前本地库。

```bash
funsecret load DB_URL
```

从 MySQL 加载：

```bash
funsecret load mysql+pymysql://username:password@127.0.0.1:3306/funsecret
```

如果源库里的数据是加密的，可以传 `--cipher-key`：

```bash
funsecret load mysql+pymysql://username:password@127.0.0.1:3306/funsecret --cipher-key my-secret-key
```

如果不传 `--cipher-key`，默认按未加密数据读取。

## Python 用法

写入：

```python
from funsecret import write_secret

write_secret("my-password", "app", "prod", "mysql", "password")
write_secret("sk-xxxxx", "openai", "prod", "api_key")
```

读取：

```python
from funsecret import read_secret

password = read_secret("app", "prod", "mysql", "password")
api_key = read_secret("openai", "prod", "api_key")
```

也可以用 `read_secret(..., value=...)` 直接写入：

```python
from funsecret import read_secret

read_secret("app", "prod", "mysql", "password", value="my-password")
```

## 默认存储位置

默认使用本地 sqlite：

```text
~/.secret/.funsecret.db
```

也可以通过环境变量控制：
- `FUN_SECRET_PATH`：本地 secret 目录
- `FUN_SECRET_URL`：直接指定数据库 URL

## 快照扩展

快照功能需要单独安装：

```bash
pip install funsecret-snapshot
```

保存快照：

```python
from funsecret.snapshot import save_snapshot

save_snapshot(bin_id, cipher_key, security_key)
```

读取快照：

```python
from funsecret.snapshot import load_snapshot

load_snapshot(bin_id, cipher_key, security_key)
```
