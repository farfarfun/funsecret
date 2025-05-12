# funsecret

funsecret 是一个轻量级的 Python 密钥管理工具，用于安全地存储和访问敏感信息（如账号密码）。以下是它的主要功能和特点：

核心功能
* 本地密钥存储：将敏感信息保存在本地，避免在代码中使用明文凭证
* 结构化存储：使用多级路径（类似命名空间）组织密钥
* 读写 API：提供简洁的读写接口
* 快照功能：通过 funsecret_snapshot 扩展包支持某些平台的快照功能


## 安装

```bash
pip install funsecret
```

## 写入或者更新

```python
from funsecret import read_secret, write_secret

write_secret("your username", "wechat", "login", "username")
read_secret("wechat", "login", "username", value="your username")
```

## 读取

```python
from funsecret import read_secret

username = read_secret("wechat", "login", "username")
password = read_secret("wechat", "login", "password")
```

## 快照

快照功能需要单独安装

```bash
pip install funsecret_snapshot
```

目前只支持保存 lanzou

### 保存

```python
from funsecret_snapshot import save_snapshot

bin_id = '**'
cipher_key = '******'
security_key = "******"
save_snapshot(bin_id, cipher_key, security_key)
```

### 读取

```python
from funsecret_snapshot import load_snapshot

bin_id = '**'
cipher_key = '******'
security_key = "******"
load_snapshot(bin_id, cipher_key, security_key)
```
