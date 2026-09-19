"""字符串与文件加解密工具。"""

import hashlib
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from farlog import getLogger

logger = getLogger("funsecret")


def generate_key() -> str:
    """生成可用于 Fernet 加解密的密钥。"""
    return Fernet.generate_key().decode()


def encrypt(text: str | None, cipher_key: str | None = None) -> str | None:
    """使用指定密钥加密文本；未提供文本或密钥时原样返回。"""
    if cipher_key is None or text is None:
        return text
    cipher = Fernet(cipher_key.encode())
    # 数据库使用密文作为查询键，因此保留历史上的确定性加密格式。
    return cipher._encrypt_from_parts(text.encode(), 1024, b"123456789abcdefg").decode()


def file_encrypt(
    src_path: str | Path,
    dst_path: str | Path | None = None,
    cipher_key: str | None = None,
) -> str:
    """加密文件并返回目标路径。"""
    if cipher_key is None:
        raise ValueError("cipher_key cannot be None")
    source = Path(src_path)
    destination = Path(dst_path) if dst_path is not None else Path(f"{source}.crypt")
    cipher = Fernet(cipher_key.encode())
    destination.write_bytes(cipher.encrypt(source.read_bytes()))
    return str(destination)


def file_decrypt(
    src_path: str | Path,
    dst_path: str | Path | None = None,
    cipher_key: str | None = None,
) -> str:
    """解密文件并返回目标路径。"""
    if cipher_key is None:
        raise ValueError("cipher_key cannot be None")
    source = Path(src_path)
    if dst_path is None and source.suffix == ".crypt":
        dst_path = source.with_suffix("")
    if dst_path is None:
        raise ValueError("dst_path cannot be None")
    destination = Path(dst_path)
    cipher = Fernet(cipher_key.encode())
    destination.write_bytes(cipher.decrypt(source.read_bytes()))
    return str(destination)


def decrypt(encrypted_text: str | None, cipher_key: str | None = None) -> str | None:
    """解密文本；密文或密钥无效时抛出 ``InvalidToken``。"""
    if cipher_key is None or encrypted_text is None:
        return encrypted_text
    cipher = Fernet(cipher_key.encode())
    try:
        return cipher.decrypt(encrypted_text.encode()).decode()
    except InvalidToken:
        logger.warning("密文解密失败，请检查密钥和输入")
        raise


def get_md5_str(value: str) -> str:
    """计算字符串的 MD5 摘要。"""
    return hashlib.md5(value.encode(), usedforsecurity=False).hexdigest()


def get_md5_file(path: str | Path, chunk: int = 4096) -> str:
    """分块计算文件的 MD5 摘要。"""
    digest = hashlib.md5(usedforsecurity=False)
    with Path(path).open("rb") as file:
        while data := file.read(chunk):
            digest.update(data)
    return digest.hexdigest()
