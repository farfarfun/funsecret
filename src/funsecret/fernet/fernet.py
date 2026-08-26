import hashlib

from cryptography.fernet import Fernet


def generate_key():
    return Fernet.generate_key().decode()


def encrypt(text, cipher_key=None):
    """
    加密，我也没测试过，不知道能不能正常使用，纯字母的应该没问题，中文的待商榷
    :param text: 需要加密的文本
    :param cipher_key: 加密key
    :return: 加密后的文本
    """
    if cipher_key is None or text is None:
        return text
    cipher = Fernet(bytes(cipher_key, encoding="utf8"))
    # return cipher.encrypt(text.encode()).decode()
    return cipher._encrypt_from_parts(
        text.encode(), 1024, "123456789abcdefg".encode("utf-8")
    ).decode()


def file_encrypt(src_path, dst_path=None, cipher_key=None):
    if cipher_key is None:
        raise Exception("cipher_key cannot be None.")
    cipher = Fernet(bytes(cipher_key, encoding="utf8"))
    if dst_path is None:
        dst_path = src_path + ".crypt"
    with open(dst_path, "wb") as fw:
        with open(src_path, "rb") as fr:
            fw.write(cipher.encrypt(fr.read()))
    return dst_path


def file_decrypt(src_path, dst_path=None, cipher_key=None):
    if cipher_key is None:
        raise Exception("cipher_key cannot be None.")
    cipher = Fernet(bytes(cipher_key, encoding="utf8"))
    if dst_path is None and src_path.endswith(".crypt"):
        dst_path = src_path.replace(".crypt", "")
    if dst_path is None:
        raise Exception("dst_path cannot be None.")
    with open(dst_path, "wb") as fw:
        with open(src_path, "rb") as fr:
            fw.write(cipher.decrypt(fr.read()))
    return dst_path


def decrypt(encrypted_text, cipher_key=None):
    """
    解密，我也没测试过，不知道能不能正常使用，纯字母的应该没问题，中文的待商榷
    :param cipher_key: 加密key
    :param encrypted_text: 需要解密的文本
    :return:解密后的文本
    """
    if cipher_key is None or encrypted_text is None:
        return encrypted_text
    cipher = Fernet(bytes(cipher_key, encoding="utf8"))
    try:
        return cipher.decrypt(bytes(encrypted_text, encoding="utf8")).decode()
    except Exception as e:
        print(e)
        return encrypted_text


def get_md5_str(strs: str):
    """
    计算字符串md5值
    :param strs: 输入字符串
    :return: 字符串md5
    """
    m = hashlib.md5()
    m.update(strs.encode())
    return m.hexdigest()


def get_md5_file(path, chunk=1024 * 4):
    m = hashlib.md5()
    with open(path, "rb") as f:
        while True:
            data = f.read(chunk)
            if not data:
                break
            m.update(data)

    return m.hexdigest()
