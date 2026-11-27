//! Fernet 字符串与文件加解密及 MD5 摘要工具。
//!
//! 加密格式与 Python `cryptography.fernet.Fernet` 逐字节兼容：
//! - 密钥为 32 字节 URL-safe Base64（前 16 字节 HMAC-SHA256 签名密钥，后 16 字节 AES-128-CBC 加密密钥）。
//! - 数据库键值加密使用确定性时间戳 `1024` 与固定 IV `b"123456789abcdefg"`，与历史
//!   `Fernet._encrypt_from_parts(text.encode(), 1024, b"123456789abcdefg")` 保持 100% 互通。

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use aes::Aes128;
use base64::engine::general_purpose::URL_SAFE;
use base64::Engine;
use cbc::{Decryptor, Encryptor};
use cipher::block_padding::Pkcs7;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::{FunSecretError, Result};

type Aes128CbcEnc = Encryptor<Aes128>;
type Aes128CbcDec = Decryptor<Aes128>;
type HmacSha256 = Hmac<Sha256>;

const FERNET_VERSION: u8 = 0x80;
const DETERMINISTIC_TIMESTAMP: u64 = 1024;
const DETERMINISTIC_IV: [u8; 16] = *b"123456789abcdefg";
const MIN_TOKEN_LEN: usize = 1 + 8 + 16 + 16 + 32;

struct FernetKeys {
    signing: [u8; 16],
    encryption: [u8; 16],
}

fn parse_fernet_key(cipher_key: &str) -> Result<FernetKeys> {
    let raw = URL_SAFE.decode(cipher_key.as_bytes()).map_err(|_| {
        FunSecretError::InvalidCipherKey(
            "Fernet key must be 32 url-safe base64-encoded bytes.".to_string(),
        )
    })?;
    if raw.len() != 32 {
        return Err(FunSecretError::InvalidCipherKey(
            "Fernet key must be 32 url-safe base64-encoded bytes.".to_string(),
        ));
    }
    let mut signing = [0u8; 16];
    let mut encryption = [0u8; 16];
    signing.copy_from_slice(&raw[..16]);
    encryption.copy_from_slice(&raw[16..32]);
    Ok(FernetKeys {
        signing,
        encryption,
    })
}

/// 生成可用于 Fernet 加解密的 32 字节 URL-safe Base64 密钥。
pub fn generate_key() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE.encode(bytes)
}

/// 等价于 Python `urllib.parse.quote_plus(value, safe="")`。
pub(crate) fn quote_plus(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 2);
    for byte in input.bytes() {
        match byte {
            b' ' => out.push('+'),
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                use std::fmt::Write;
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

/// 按历史公式从本地密钥目录派生默认 Fernet 密钥。
///
/// 等价于 Python：
/// `base64.urlsafe_b64encode(quote_plus(secret_dir * 2)[:32].encode("utf-8")).decode()`
pub fn derive_default_key(secret_dir: &str) -> String {
    let doubled = format!("{secret_dir}{secret_dir}");
    let quoted = quote_plus(&doubled);
    let prefix = &quoted[..quoted.len().min(32)];
    URL_SAFE.encode(prefix.as_bytes())
}

fn encrypt_from_parts(
    plaintext: &[u8],
    cipher_key: &str,
    timestamp: u64,
    iv: &[u8; 16],
) -> Result<String> {
    let keys = parse_fernet_key(cipher_key)?;
    let pad_len = 16 - (plaintext.len() % 16);
    let mut buf = vec![0u8; plaintext.len() + pad_len];
    buf[..plaintext.len()].copy_from_slice(plaintext);
    let ciphertext = Aes128CbcEnc::new(&keys.encryption.into(), iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
        .map_err(|_| FunSecretError::InvalidToken)?;

    let mut payload = Vec::with_capacity(1 + 8 + 16 + ciphertext.len() + 32);
    payload.push(FERNET_VERSION);
    payload.extend_from_slice(&timestamp.to_be_bytes());
    payload.extend_from_slice(iv);
    payload.extend_from_slice(ciphertext);

    let mut mac =
        HmacSha256::new_from_slice(&keys.signing).expect("HMAC accepts keys of any valid length");
    mac.update(&payload);
    let tag = mac.finalize().into_bytes();
    payload.extend_from_slice(&tag);

    Ok(URL_SAFE.encode(payload))
}

/// 使用确定性 IV/时间戳加密文本（用于数据库索引键和值，与历史 Python 实现一致）。
pub fn encrypt(text: &str, cipher_key: &str) -> Result<String> {
    encrypt_from_parts(
        text.as_bytes(),
        cipher_key,
        DETERMINISTIC_TIMESTAMP,
        &DETERMINISTIC_IV,
    )
}

/// 使用标准随机 IV 和当前时间戳加密字节流，返回 Fernet Base64 密文字节。
pub fn encrypt_bytes(data: &[u8], cipher_key: &str) -> Result<Vec<u8>> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);
    let token = encrypt_from_parts(data, cipher_key, timestamp, &iv)?;
    Ok(token.into_bytes())
}

/// 解密 Fernet Token 字节流，不检查 TTL（与 `Fernet.decrypt(token)` 一致）。
pub fn decrypt_bytes(token: &[u8], cipher_key: &str) -> Result<Vec<u8>> {
    let keys = parse_fernet_key(cipher_key)?;
    let raw = URL_SAFE
        .decode(token)
        .map_err(|_| FunSecretError::InvalidToken)?;

    if raw.len() < MIN_TOKEN_LEN || raw[0] != FERNET_VERSION {
        return Err(FunSecretError::InvalidToken);
    }

    let basic_len = raw.len() - 32;
    let ciphertext = &raw[25..basic_len];
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err(FunSecretError::InvalidToken);
    }

    let mut mac =
        HmacSha256::new_from_slice(&keys.signing).expect("HMAC accepts keys of any valid length");
    mac.update(&raw[..basic_len]);
    let expected = mac.finalize().into_bytes();
    let provided = &raw[basic_len..];

    if expected.as_slice().ct_eq(provided).unwrap_u8() != 1 {
        log::warn!("密文解密失败，请检查密钥和输入");
        return Err(FunSecretError::InvalidToken);
    }

    let mut iv = [0u8; 16];
    iv.copy_from_slice(&raw[9..25]);
    let mut buf = ciphertext.to_vec();
    let plain = Aes128CbcDec::new(&keys.encryption.into(), &iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| {
            log::warn!("密文解密失败，请检查密钥和输入");
            FunSecretError::InvalidToken
        })?;
    Ok(plain.to_vec())
}

/// 解密 Fernet 密文字符串。
pub fn decrypt(encrypted_text: &str, cipher_key: &str) -> Result<String> {
    let bytes = decrypt_bytes(encrypted_text.as_bytes(), cipher_key)?;
    String::from_utf8(bytes).map_err(|_| FunSecretError::InvalidToken)
}

/// 加密文件并返回目标路径。未指定 `dst_path` 时默认追加 `.crypt` 后缀。
pub fn file_encrypt(
    src_path: impl AsRef<Path>,
    dst_path: Option<&Path>,
    cipher_key: &str,
) -> Result<PathBuf> {
    let src = src_path.as_ref();
    let destination = match dst_path {
        Some(path) => path.to_path_buf(),
        None => {
            let mut os = src.as_os_str().to_os_string();
            os.push(".crypt");
            PathBuf::from(os)
        }
    };
    let data = std::fs::read(src)?;
    let encrypted = encrypt_bytes(&data, cipher_key)?;
    std::fs::write(&destination, encrypted)?;
    Ok(destination)
}

/// 解密文件并返回目标路径。未指定 `dst_path` 且源文件以 `.crypt` 结尾时自动去掉该后缀。
pub fn file_decrypt(
    src_path: impl AsRef<Path>,
    dst_path: Option<&Path>,
    cipher_key: &str,
) -> Result<PathBuf> {
    let src = src_path.as_ref();
    let destination = match dst_path {
        Some(path) => path.to_path_buf(),
        None => {
            if src.extension().and_then(|ext| ext.to_str()) == Some("crypt") {
                src.with_extension("")
            } else {
                return Err(FunSecretError::InvalidArgument(
                    "dst_path cannot be None".to_string(),
                ));
            }
        }
    };
    let data = std::fs::read(src)?;
    let decrypted = decrypt_bytes(&data, cipher_key)?;
    std::fs::write(&destination, decrypted)?;
    Ok(destination)
}

/// 计算字符串的 MD5 十六进制摘要。
pub fn get_md5_str(value: &str) -> String {
    let digest = Md5::digest(value.as_bytes());
    format!("{digest:x}")
}

/// 分块计算文件的 MD5 十六进制摘要。
pub fn get_md5_file(path: impl AsRef<Path>, chunk: usize) -> Result<String> {
    let chunk_size = chunk.max(1);
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Md5::new();
    let mut buffer = vec![0u8; chunk_size];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_encrypt_and_decrypt_round_trip() {
        let key = generate_key();
        let c1 = encrypt("中文-secret", &key).unwrap();
        let c2 = encrypt("中文-secret", &key).unwrap();
        assert_eq!(c1, c2);
        assert_ne!(c1, "中文-secret");
        assert_eq!(decrypt(&c1, &key).unwrap(), "中文-secret");
    }

    #[test]
    fn invalid_token_returns_error() {
        let key = generate_key();
        assert!(matches!(
            decrypt("not-a-token", &key),
            Err(FunSecretError::InvalidToken)
        ));
    }

    #[test]
    fn file_round_trip_and_missing_dst() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("source.txt");
        std::fs::write(&src, "secret").unwrap();
        let key = generate_key();

        let encrypted = file_encrypt(&src, None, &key).unwrap();
        assert_eq!(encrypted, dir.path().join("source.txt.crypt"));
        std::fs::remove_file(&src).unwrap();

        let decrypted = file_decrypt(&encrypted, None, &key).unwrap();
        assert_eq!(decrypted, src);
        assert_eq!(std::fs::read_to_string(&decrypted).unwrap(), "secret");

        let plain = dir.path().join("plain.bin");
        std::fs::write(&plain, "abc").unwrap();
        assert!(matches!(
            file_decrypt(&plain, None, &key),
            Err(FunSecretError::InvalidArgument(_))
        ));
    }

    #[test]
    fn md5_matches_known_digest() {
        assert_eq!(get_md5_str("hello"), "5d41402abc4b2a76b9719d911017c592");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("value.txt");
        std::fs::write(&path, "hello").unwrap();
        assert_eq!(get_md5_file(&path, 2).unwrap(), get_md5_str("hello"));
    }

    #[test]
    fn quote_plus_matches_python_rules() {
        assert_eq!(quote_plus("/home/a b/.secret"), "%2Fhome%2Fa+b%2F.secret");
    }
}
