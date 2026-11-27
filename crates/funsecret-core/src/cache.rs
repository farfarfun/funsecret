//! 原生 SQLite 短期密钥缓存（替代历史 `diskcache` 实现，零 Python 运行时依赖）。

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::Result;
use crate::fernet::{decrypt, derive_default_key, encrypt, get_md5_str};
use crate::store::{set_owner_only_dir, set_owner_only_file, user_home_dir};

const CACHE_DB_FILENAME: &str = "funsecret_cache.db";

fn now_unix_secs_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// 解析短期缓存目录（不主动创建，按需落盘）。
pub fn resolve_cache_dir(secret_dir: Option<&str>) -> Result<String> {
    if let Some(dir) = secret_dir {
        return Ok(dir.to_string());
    }
    if let Ok(path) = std::env::var("FUN_CACHE_SECRET_PATH") {
        if !path.is_empty() {
            return Ok(path);
        }
    }
    let home = match std::env::var("FUN_CACHE_SECRET_HOME") {
        Ok(val) if !val.is_empty() => val,
        _ => user_home_dir()?,
    };
    Ok(format!("{home}/.secret/cache"))
}

/// 使用原生 SQLite 保存短期加密密钥。
#[derive(Debug, Clone)]
pub struct CacheSecretManage {
    secret_dir: String,
    db_path: PathBuf,
    cipher_key: String,
}

impl CacheSecretManage {
    /// 创建缓存管理器，目录权限收紧为 `0700`，数据库文件权限收紧为 `0600`。
    pub fn new(secret_dir: Option<&str>, cipher_key: Option<&str>) -> Result<Self> {
        let resolved_dir = resolve_cache_dir(secret_dir)?;
        let dir_path = Path::new(&resolved_dir);
        if !dir_path.exists() {
            std::fs::create_dir_all(dir_path)?;
            set_owner_only_dir(dir_path)?;
        }

        let db_path = dir_path.join(CACHE_DB_FILENAME);
        let key = match cipher_key {
            Some(k) if !k.is_empty() => k.to_string(),
            _ => derive_default_key(&resolved_dir),
        };

        let manage = Self {
            secret_dir: resolved_dir,
            db_path,
            cipher_key: key,
        };
        manage.ensure_schema()?;
        Ok(manage)
    }

    /// 返回当前生效的 Fernet 密钥。
    pub fn cipher_key(&self) -> &str {
        &self.cipher_key
    }

    /// 返回缓存目录路径。
    pub fn secret_dir(&self) -> &str {
        &self.secret_dir
    }

    /// 把分类路径转换为 MD5 缓存键。
    pub fn cache_key(cate1: &str, cate2: &str, cate3: &str, cate4: &str, cate5: &str) -> String {
        let raw = format!("{cate1}-{cate2}-{cate3}-{cate4}-{cate5}");
        get_md5_str(&raw)
    }

    /// 加密缓存文本。
    pub fn encrypt(&self, text: &str) -> Result<String> {
        encrypt(text, &self.cipher_key)
    }

    /// 解密缓存文本。
    pub fn decrypt(&self, encrypted_text: &str) -> Result<String> {
        decrypt(encrypted_text, &self.cipher_key)
    }

    fn open_conn(&self) -> Result<Connection> {
        let conn = Connection::open(&self.db_path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        Ok(conn)
    }

    fn ensure_schema(&self) -> Result<()> {
        let conn = self.open_conn()?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS cache_secret (
                key TEXT NOT NULL PRIMARY KEY,
                value TEXT NOT NULL,
                expire_at REAL NULL
            );",
        )?;
        if self.db_path.exists() {
            set_owner_only_file(&self.db_path)?;
        }
        Ok(())
    }

    /// 按分类路径写入缓存；`expire_time` 单位为秒（`None` 表示永不过期）。
    #[allow(clippy::too_many_arguments)]
    pub fn write(
        &self,
        cate1: &str,
        cate2: &str,
        cate3: &str,
        cate4: &str,
        cate5: &str,
        value: Option<&str>,
        secret: bool,
        expire_time: Option<f64>,
    ) -> Result<()> {
        let Some(val) = value else {
            log::error!("value cannot be None");
            return Ok(());
        };
        let key = Self::cache_key(cate1, cate2, cate3, cate4, cate5);
        let stored = if secret {
            self.encrypt(val)?
        } else {
            val.to_string()
        };
        let expire_at = expire_time.map(|ttl| now_unix_secs_f64() + ttl);

        let conn = self.open_conn()?;
        conn.execute(
            "INSERT INTO cache_secret (key, value, expire_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                expire_at = excluded.expire_at",
            params![key, stored, expire_at],
        )?;
        Ok(())
    }

    /// 按分类路径读取缓存；传入 `value` 且 `save = true` 时先写入。
    #[allow(clippy::too_many_arguments)]
    pub fn read(
        &self,
        cate1: &str,
        cate2: &str,
        cate3: &str,
        cate4: &str,
        cate5: &str,
        value: Option<&str>,
        save: bool,
        secret: bool,
        expire_time: Option<f64>,
    ) -> Result<Option<String>> {
        if save && value.is_some() {
            self.write(
                cate1,
                cate2,
                cate3,
                cate4,
                cate5,
                value,
                secret,
                expire_time,
            )?;
        }
        if let Some(val) = value {
            return Ok(Some(val.to_string()));
        }

        let key = Self::cache_key(cate1, cate2, cate3, cate4, cate5);
        let now = now_unix_secs_f64();
        let conn = self.open_conn()?;
        conn.execute(
            "DELETE FROM cache_secret WHERE expire_at IS NOT NULL AND expire_at <= ?1",
            params![now],
        )?;
        let row: Option<(String, Option<f64>)> = conn
            .query_row(
                "SELECT value, expire_at FROM cache_secret WHERE key = ?1",
                params![key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;

        let Some((cached, expire_at)) = row else {
            log::warn!("not found value from '{cate1}/{cate2}/{cate3}/{cate4}/{cate5}'");
            return Ok(None);
        };
        if expire_at.is_some_and(|exp| now >= exp) {
            return Ok(None);
        }
        if secret {
            Ok(Some(self.decrypt(&cached)?))
        } else {
            Ok(Some(cached))
        }
    }
}

/// 从默认缓存读取密钥。
#[allow(clippy::too_many_arguments)]
pub fn read_cache_secret(
    cate1: &str,
    cate2: &str,
    cate3: &str,
    cate4: &str,
    cate5: &str,
    value: Option<&str>,
    save: bool,
    secret: bool,
    expire_time: Option<f64>,
) -> Result<Option<String>> {
    let manage = CacheSecretManage::new(None, None)?;
    manage.read(
        cate1,
        cate2,
        cate3,
        cate4,
        cate5,
        value,
        save,
        secret,
        expire_time,
    )
}

/// 向默认缓存写入密钥。
#[allow(clippy::too_many_arguments)]
pub fn write_cache_secret(
    value: &str,
    cate1: &str,
    cate2: &str,
    cate3: &str,
    cate4: &str,
    cate5: &str,
    secret: bool,
    expire_time: Option<f64>,
) -> Result<()> {
    let manage = CacheSecretManage::new(None, None)?;
    manage.write(
        cate1,
        cate2,
        cate3,
        cate4,
        cate5,
        Some(value),
        secret,
        expire_time,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fernet::generate_key;

    #[test]
    fn cache_read_write_and_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let cache_dir = dir.path().join("cache");
        let key = generate_key();
        let manager =
            CacheSecretManage::new(Some(cache_dir.to_str().unwrap()), Some(&key)).unwrap();

        manager
            .write("app", "prod", "", "", "", Some("encrypted"), true, None)
            .unwrap();
        manager
            .write("app", "plain", "", "", "", Some("visible"), false, None)
            .unwrap();
        manager
            .write("app", "expired", "", "", "", Some("gone"), true, Some(-1.0))
            .unwrap();

        assert_eq!(
            manager
                .read("app", "prod", "", "", "", None, true, true, None)
                .unwrap()
                .as_deref(),
            Some("encrypted")
        );
        assert_eq!(
            manager
                .read("app", "plain", "", "", "", None, true, false, None)
                .unwrap()
                .as_deref(),
            Some("visible")
        );
        assert_eq!(
            manager
                .read("app", "expired", "", "", "", None, true, true, None)
                .unwrap(),
            None
        );
        assert_eq!(
            manager
                .read("missing", "value", "", "", "", None, true, true, None)
                .unwrap(),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn cache_dir_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let cache_dir = dir.path().join("owner-only-cache");
        let _manager =
            CacheSecretManage::new(Some(cache_dir.to_str().unwrap()), Some(&generate_key()))
                .unwrap();

        assert_eq!(
            std::fs::metadata(&cache_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}
