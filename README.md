# funsecret

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
