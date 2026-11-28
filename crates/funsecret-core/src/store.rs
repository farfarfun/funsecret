//! 本地 SQLite3 与远端 MySQL / MariaDB / PostgreSQL 加密密钥存储管理。
//!
//! 兼容 SQLAlchemy 风格的数据库方言 URL 前缀（如 `sqlite+pysqlite:///`、
//! `mysql+pymysql://`、`mariadb+mariadbconnector://`、`postgresql+psycopg2://`、
//! `postgres://`），便于在不同数据库后端之间无缝迁移。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::Local;
use mysql::prelude::Queryable;
use mysql::{Opts, Pool, Row as MysqlRow};
use postgres::Client as PgClient;
use rusqlite::{params, Connection, OptionalExtension};
use rustls::{ClientConfig as RustlsClientConfig, RootCertStore};
use serde::Serialize;
use serde_json::{Map, Value};
use tokio_postgres_rustls::MakeRustlsConnect;
use url::Url;

use crate::error::{FunSecretError, Result};
use crate::fernet::{decrypt, derive_default_key, encrypt};
use crate::progress::SyncProgress;

/// 默认 MySQL 连接串示例（用于 `info` 输出）。
pub const MYSQL_EXAMPLE_URL: &str = "mysql+pymysql://username:password@127.0.0.1:3306/funsecret";

/// 默认外部数据库 URL 在密钥库中的分类路径。
pub const DEFAULT_DB_URL_CATEGORY: [&str; 3] = ["funsecret", "db", "url"];

const DEFAULT_RELATIVE_EXPIRE_SECS: i64 = 999_999_999;
const RELATIVE_EXPIRE_THRESHOLD: i64 = 1_000_000_000;

/// 嵌套密钥树（与 Python `dict[str, Any]` 一致）。
pub type SecretTree = Map<String, Value>;

/// 单条密钥路径的元数据（不包含密钥值）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecretEntry {
    /// 2–5 级分类路径。
    pub path: Vec<String>,
    /// 空格拼接的展示路径。
    pub display_path: String,
    /// 创建时间（ISO/SQL 文本）。
    pub gmt_create: Option<String>,
    /// 修改时间（ISO/SQL 文本）。
    pub gmt_modified: Option<String>,
    /// 过期时间戳（Unix 秒）。
    pub expire_time: i64,
}

/// 当前存储后端信息（用于 `info` 命令）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoreInfo {
    pub backend: String,
    pub database_url: String,
    pub database_file: Option<String>,
    pub secret_count: usize,
    pub cipher_key_configured: bool,
    pub mysql_example_url: String,
}

/// 数据库原始记录行（同步用）。
#[derive(Debug, Clone)]
pub struct SecretRecord {
    pub key: String,
    pub value: String,
    pub expire_time: i64,
    pub gmt_create: Option<String>,
    pub gmt_modified: Option<String>,
}

#[derive(Debug, Clone)]
enum Backend {
    Sqlite { path: Option<PathBuf>, url: String },
    Mysql { raw_url: String, mysql_url: String },
    Postgres { raw_url: String, pg_url: String },
}

fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn now_sql_timestamp() -> String {
    Local::now().format("%Y-%m-%d %H:%M:%S%.6f").to_string()
}

pub(crate) fn user_home_dir() -> Result<String> {
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return Ok(home);
        }
    }
    #[cfg(windows)]
    if let Ok(profile) = std::env::var("USERPROFILE") {
        if !profile.is_empty() {
            return Ok(profile);
        }
    }
    Err(FunSecretError::InvalidArgument(
        "cannot determine home directory (set HOME or FUN_SECRET_PATH)".to_string(),
    ))
}

#[cfg(unix)]
pub(crate) fn set_owner_only_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn set_owner_only_dir(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
pub(crate) fn set_owner_only_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn set_owner_only_file(_path: &Path) -> Result<()> {
    Ok(())
}

/// 优先返回显式数据库地址，否则读取 `FUN_SECRET_URL` 环境变量。
pub fn get_secret_url(secret_url: Option<&str>) -> Option<String> {
    if let Some(url) = secret_url {
        return Some(url.to_string());
    }
    std::env::var("FUN_SECRET_URL")
        .ok()
        .filter(|v| !v.is_empty())
}

/// 返回本地密钥目录，缺失时创建为仅当前用户可读写执行（`0700`）。
pub fn get_secret_path(secret_dir: Option<&str>) -> Result<String> {
    let template = secret_dir.unwrap_or("~/.secret");
    let resolved = if template.contains('~') {
        let base = match std::env::var("FUN_SECRET_PATH") {
            Ok(val) if !val.is_empty() => val,
            _ => user_home_dir()?,
        };
        template.replace('~', &base)
    } else {
        template.to_string()
    };

    let path = Path::new(&resolved);
    if !path.exists() {
        std::fs::create_dir_all(path)?;
        set_owner_only_dir(path)?;
    }
    Ok(resolved)
}

/// 隐藏数据库连接串中的密码（替换为 `***`）。
pub fn hide_password_url(raw_url: &str) -> String {
    if raw_url.starts_with("sqlite") {
        return raw_url.to_string();
    }
    if let Ok(mut parsed) = Url::parse(raw_url) {
        if parsed.password().is_some() {
            let _ = parsed.set_password(Some("***"));
            return parsed.to_string();
        }
    }
    raw_url.to_string()
}

fn parse_backend(raw_url: &str) -> Result<Backend> {
    let Some((scheme_raw, rest)) = raw_url.split_once("://") else {
        return Err(FunSecretError::UnsupportedUrl(hide_password_url(raw_url)));
    };
    let scheme_lower = scheme_raw.to_ascii_lowercase();
    let base_dialect = scheme_lower
        .split_once('+')
        .map_or(scheme_lower.as_str(), |(base, _)| base);

    match base_dialect {
        "sqlite" | "sqlite3" => {
            if rest == ":memory:" || rest == "/:memory:" || rest.is_empty() || rest == "/" {
                return Ok(Backend::Sqlite {
                    path: None,
                    url: raw_url.to_string(),
                });
            }
            // 遵循 SQLAlchemy 惯例：`sqlite:///rel.db` -> `rel.db`，`sqlite:////abs.db` -> `/abs.db`。
            let file_str = rest.strip_prefix('/').unwrap_or(rest);
            Ok(Backend::Sqlite {
                path: Some(PathBuf::from(file_str)),
                url: raw_url.to_string(),
            })
        }
        "mysql" | "mariadb" => Ok(Backend::Mysql {
            raw_url: raw_url.to_string(),
            mysql_url: format!("mysql://{rest}"),
        }),
        "postgresql" | "postgres" => Ok(Backend::Postgres {
            raw_url: raw_url.to_string(),
            pg_url: format!("postgresql://{rest}"),
        }),
        _ => Err(FunSecretError::UnsupportedUrl(hide_password_url(raw_url))),
    }
}

fn build_pg_tls_connector() -> Result<MakeRustlsConnect> {
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = RustlsClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| FunSecretError::Postgres(format!("failed to configure TLS: {e}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(MakeRustlsConnect::new(config))
}

fn normalize_expire_time(expire_time: Option<i64>) -> i64 {
    let raw = match expire_time {
        Some(v) if v != 0 => v,
        _ => DEFAULT_RELATIVE_EXPIRE_SECS,
    };
    if raw < RELATIVE_EXPIRE_THRESHOLD {
        raw.saturating_add(now_unix_secs())
    } else {
        raw
    }
}

/// 拆分数据库键为非空分类路径段。
pub fn split_key_parts(key: &str) -> Vec<String> {
    key.split("--")
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

/// 管理本地 SQLite3 或远端 MySQL / MariaDB / PostgreSQL 中的加密密钥。
#[derive(Debug, Clone)]
pub struct SecretManage {
    backend: Backend,
    cipher_key: String,
    secret_dir: String,
}

impl SecretManage {
    /// 创建密钥管理器；未传 `url` 且未设 `FUN_SECRET_URL` 时默认使用 `~/.secret/.funsecret.db`。
    pub fn new(
        secret_dir: Option<&str>,
        url: Option<&str>,
        cipher_key: Option<&str>,
    ) -> Result<Self> {
        let resolved_dir = get_secret_path(secret_dir)?;
        let resolved_url = get_secret_url(url);

        let backend = match resolved_url {
            Some(u) => parse_backend(&u)?,
            None => {
                let db_path = PathBuf::from(&resolved_dir).join(".funsecret.db");
                let url_str = format!("sqlite:///{}", db_path.display());
                Backend::Sqlite {
                    path: Some(db_path),
                    url: url_str,
                }
            }
        };

        let key = match cipher_key {
            Some(k) if !k.is_empty() => k.to_string(),
            _ => derive_default_key(&resolved_dir),
        };

        let manage = Self {
            backend,
            cipher_key: key,
            secret_dir: resolved_dir,
        };
        manage.ensure_schema()?;
        Ok(manage)
    }

    /// 返回当前生效的 Fernet 密钥。
    pub fn cipher_key(&self) -> &str {
        &self.cipher_key
    }

    /// 返回当前本地密钥目录。
    pub fn secret_dir(&self) -> &str {
        &self.secret_dir
    }

    /// 返回后端名称（`"sqlite"`、`"mysql"` 或 `"postgresql"`）。
    pub fn backend_name(&self) -> &'static str {
        match &self.backend {
            Backend::Sqlite { .. } => "sqlite",
            Backend::Mysql { .. } => "mysql",
            Backend::Postgres { .. } => "postgresql",
        }
    }

    /// 返回隐藏密码后的数据库 URL。
    pub fn masked_url(&self) -> String {
        match &self.backend {
            Backend::Sqlite { url, .. } => url.clone(),
            Backend::Mysql { raw_url, .. } | Backend::Postgres { raw_url, .. } => {
                hide_password_url(raw_url)
            }
        }
    }

    /// 若为文件 SQLite 后端，返回数据库文件路径。
    pub fn database_file(&self) -> Option<&Path> {
        match &self.backend {
            Backend::Sqlite { path, .. } => path.as_deref(),
            Backend::Mysql { .. } | Backend::Postgres { .. } => None,
        }
    }

    /// 把最多五级分类转换为数据库键（与 Python `SecretManage.convert_key` 一致）。
    pub fn convert_key(cate1: &str, cate2: &str, cate3: &str, cate4: &str, cate5: &str) -> String {
        format!("{cate1}--{cate2}--{cate3}--{cate4}--{cate5}")
    }

    /// 按配置加密文本；`secret = false` 时原样返回。
    pub fn encrypt(&self, text: &str, secret: bool) -> Result<String> {
        if secret && !self.cipher_key.is_empty() {
            encrypt(text, &self.cipher_key)
        } else {
            Ok(text.to_string())
        }
    }

    /// 按配置解密文本；`secret = false` 时原样返回。
    pub fn decrypt(&self, encrypted_text: &str, secret: bool) -> Result<String> {
        if secret && !self.cipher_key.is_empty() {
            decrypt(encrypted_text, &self.cipher_key)
        } else {
            Ok(encrypted_text.to_string())
        }
    }

    fn open_sqlite(&self) -> Result<Connection> {
        match &self.backend {
            Backend::Sqlite {
                path: Some(path), ..
            } => {
                if let Some(parent) = path.parent() {
                    if !parent.as_os_str().is_empty() && !parent.exists() {
                        std::fs::create_dir_all(parent)?;
                    }
                }
                let conn = Connection::open(path)?;
                conn.busy_timeout(std::time::Duration::from_secs(5))?;
                Ok(conn)
            }
            Backend::Sqlite { path: None, .. } => Ok(Connection::open_in_memory()?),
            _ => Err(FunSecretError::UnsupportedUrl(
                "expected sqlite backend".to_string(),
            )),
        }
    }

    fn open_mysql_pool(&self) -> Result<Pool> {
        match &self.backend {
            Backend::Mysql { mysql_url, .. } => {
                let opts = Opts::from_url(mysql_url)
                    .map_err(|e| FunSecretError::Mysql(format!("invalid mysql url: {e}")))?;
                Pool::new(opts).map_err(|e| FunSecretError::Mysql(e.to_string()))
            }
            _ => Err(FunSecretError::UnsupportedUrl(
                "expected mysql backend".to_string(),
            )),
        }
    }

    fn open_postgres_client(&self) -> Result<PgClient> {
        match &self.backend {
            Backend::Postgres { pg_url, .. } => {
                let tls = build_pg_tls_connector()?;
                PgClient::connect(pg_url, tls).map_err(|e| FunSecretError::Postgres(e.to_string()))
            }
            _ => Err(FunSecretError::UnsupportedUrl(
                "expected postgresql backend".to_string(),
            )),
        }
    }

    fn ensure_schema(&self) -> Result<()> {
        match &self.backend {
            Backend::Sqlite { path, .. } => {
                let conn = self.open_sqlite()?;
                conn.execute_batch(
                    "CREATE TABLE IF NOT EXISTS secret (
                        gmt_create DATETIME DEFAULT CURRENT_TIMESTAMP,
                        gmt_modified DATETIME DEFAULT CURRENT_TIMESTAMP,
                        key VARCHAR(200) NOT NULL PRIMARY KEY,
                        value TEXT NOT NULL DEFAULT '',
                        expire_time BIGINT NOT NULL DEFAULT 9999999999,
                        UNIQUE (key)
                    );",
                )?;
                if let Some(file_path) = path {
                    if file_path.exists() {
                        set_owner_only_file(file_path)?;
                    }
                }
                Ok(())
            }
            Backend::Mysql { .. } => {
                let pool = self.open_mysql_pool()?;
                let mut conn = pool
                    .get_conn()
                    .map_err(|e| FunSecretError::Mysql(e.to_string()))?;
                conn.query_drop(
                    "CREATE TABLE IF NOT EXISTS secret (
                        gmt_create DATETIME NULL,
                        gmt_modified DATETIME NULL,
                        `key` VARCHAR(200) NOT NULL PRIMARY KEY,
                        `value` TEXT,
                        expire_time BIGINT DEFAULT 9999999999
                    ) DEFAULT CHARSET=utf8mb4",
                )
                .map_err(|e| FunSecretError::Mysql(e.to_string()))?;
                Ok(())
            }
            Backend::Postgres { .. } => {
                let mut client = self.open_postgres_client()?;
                client
                    .batch_execute(
                        "CREATE TABLE IF NOT EXISTS secret (
                            gmt_create TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            gmt_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            key VARCHAR(200) NOT NULL PRIMARY KEY,
                            value TEXT NOT NULL DEFAULT '',
                            expire_time BIGINT NOT NULL DEFAULT 9999999999
                        );",
                    )
                    .map_err(|e| FunSecretError::Postgres(e.to_string()))?;
                Ok(())
            }
        }
    }

    fn purge_expired_sqlite(conn: &Connection) -> Result<()> {
        conn.execute(
            "DELETE FROM secret WHERE expire_time < ?1",
            params![now_unix_secs()],
        )?;
        Ok(())
    }

    fn purge_expired_mysql(conn: &mut mysql::PooledConn) -> Result<()> {
        conn.exec_drop(
            "DELETE FROM secret WHERE expire_time < ?",
            (now_unix_secs(),),
        )
        .map_err(|e| FunSecretError::Mysql(e.to_string()))?;
        Ok(())
    }

    fn purge_expired_postgres(client: &mut PgClient) -> Result<()> {
        let now = now_unix_secs();
        client
            .execute("DELETE FROM secret WHERE expire_time < $1", &[&now])
            .map_err(|e| FunSecretError::Postgres(e.to_string()))?;
        Ok(())
    }

    /// 返回数据库中的全部原始记录（供同步使用）。
    pub fn scalars(&self) -> Result<Vec<SecretRecord>> {
        match &self.backend {
            Backend::Sqlite { .. } => {
                let conn = self.open_sqlite()?;
                let mut stmt = conn.prepare(
                    "SELECT key, value, expire_time, CAST(gmt_create AS TEXT), CAST(gmt_modified AS TEXT) FROM secret",
                )?;
                let rows = stmt.query_map([], |row| {
                    Ok(SecretRecord {
                        key: row.get(0)?,
                        value: row.get(1)?,
                        expire_time: row.get::<_, Option<i64>>(2)?.unwrap_or(9_999_999_999),
                        gmt_create: row.get(3)?,
                        gmt_modified: row.get(4)?,
                    })
                })?;
                let mut out = Vec::new();
                for item in rows {
                    out.push(item?);
                }
                Ok(out)
            }
            Backend::Mysql { .. } => {
                let pool = self.open_mysql_pool()?;
                let mut conn = pool
                    .get_conn()
                    .map_err(|e| FunSecretError::Mysql(e.to_string()))?;
                let rows: Vec<MysqlRow> = conn
                    .query(
                        "SELECT `key`, `value`, expire_time, CAST(gmt_create AS CHAR), CAST(gmt_modified AS CHAR) FROM secret",
                    )
                    .map_err(|e| FunSecretError::Mysql(e.to_string()))?;
                let mut out = Vec::with_capacity(rows.len());
                for row in rows {
                    let key: String = row.get(0).unwrap_or_default();
                    let value: String = row.get(1).unwrap_or_default();
                    let expire_time: i64 = row
                        .get::<Option<i64>, _>(2)
                        .flatten()
                        .unwrap_or(9_999_999_999);
                    let gmt_create: Option<String> = row.get::<Option<String>, _>(3).flatten();
                    let gmt_modified: Option<String> = row.get::<Option<String>, _>(4).flatten();
                    out.push(SecretRecord {
                        key,
                        value,
                        expire_time,
                        gmt_create,
                        gmt_modified,
                    });
                }
                Ok(out)
            }
            Backend::Postgres { .. } => {
                let mut client = self.open_postgres_client()?;
                let rows = client
                    .query(
                        "SELECT key, value, expire_time, CAST(gmt_create AS TEXT), CAST(gmt_modified AS TEXT) FROM secret",
                        &[],
                    )
                    .map_err(|e| FunSecretError::Postgres(e.to_string()))?;
                let mut out = Vec::with_capacity(rows.len());
                for row in rows {
                    let key: String = row.get(0);
                    let value: Option<String> = row.get(1);
                    let expire_time: Option<i64> = row.get(2);
                    let gmt_create: Option<String> = row.get(3);
                    let gmt_modified: Option<String> = row.get(4);
                    out.push(SecretRecord {
                        key,
                        value: value.unwrap_or_default(),
                        expire_time: expire_time.unwrap_or(9_999_999_999),
                        gmt_create,
                        gmt_modified,
                    });
                }
                Ok(out)
            }
        }
    }

    /// 按键写入或更新记录；短过期时间按相对秒数处理。
    pub fn write_key(
        &self,
        key: &str,
        value: Option<&str>,
        secret: bool,
        expire_time: Option<i64>,
    ) -> Result<()> {
        let Some(val) = value else {
            return Ok(());
        };
        let normalized_expire = normalize_expire_time(expire_time);
        let enc_key = self.encrypt(key, secret)?;
        let enc_val = self.encrypt(val, secret)?;
        let now_ts = now_sql_timestamp();

        match &self.backend {
            Backend::Sqlite { .. } => {
                let conn = self.open_sqlite()?;
                conn.execute(
                    "INSERT INTO secret (gmt_create, gmt_modified, key, value, expire_time)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(key) DO UPDATE SET
                        gmt_modified = excluded.gmt_modified,
                        value = excluded.value,
                        expire_time = excluded.expire_time",
                    params![now_ts, now_ts, enc_key, enc_val, normalized_expire],
                )?;
                Ok(())
            }
            Backend::Mysql { .. } => {
                let pool = self.open_mysql_pool()?;
                let mut conn = pool
                    .get_conn()
                    .map_err(|e| FunSecretError::Mysql(e.to_string()))?;
                conn.exec_drop(
                    "INSERT INTO secret (gmt_create, gmt_modified, `key`, `value`, expire_time)
                     VALUES (NOW(), NOW(), ?, ?, ?)
                     ON DUPLICATE KEY UPDATE
                        gmt_modified = NOW(),
                        `value` = VALUES(`value`),
                        expire_time = VALUES(expire_time)",
                    (enc_key, enc_val, normalized_expire),
                )
                .map_err(|e| FunSecretError::Mysql(e.to_string()))?;
                Ok(())
            }
            Backend::Postgres { .. } => {
                let mut client = self.open_postgres_client()?;
                client
                    .execute(
                        "INSERT INTO secret (gmt_create, gmt_modified, key, value, expire_time)
                         VALUES (CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, $1, $2, $3)
                         ON CONFLICT (key) DO UPDATE SET
                            gmt_modified = CURRENT_TIMESTAMP,
                            value = EXCLUDED.value,
                            expire_time = EXCLUDED.expire_time",
                        &[&enc_key, &enc_val, &normalized_expire],
                    )
                    .map_err(|e| FunSecretError::Postgres(e.to_string()))?;
                Ok(())
            }
        }
    }

    /// 按键读取记录；传入 `value` 且 `save = true` 时先写入；过期或不存在返回 `Ok(None)`。
    pub fn read_key(
        &self,
        key: &str,
        value: Option<&str>,
        save: bool,
        secret: bool,
        expire_time: Option<i64>,
    ) -> Result<Option<String>> {
        if save && value.is_some() {
            self.write_key(key, value, secret, expire_time)?;
        }
        if let Some(val) = value {
            return Ok(Some(val.to_string()));
        }

        let enc_key = self.encrypt(key, secret)?;
        let now = now_unix_secs();

        let fetched: Option<(String, Option<i64>)> = match &self.backend {
            Backend::Sqlite { .. } => {
                let conn = self.open_sqlite()?;
                Self::purge_expired_sqlite(&conn)?;
                conn.query_row(
                    "SELECT value, expire_time FROM secret WHERE key = ?1",
                    params![enc_key],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?
            }
            Backend::Mysql { .. } => {
                let pool = self.open_mysql_pool()?;
                let mut conn = pool
                    .get_conn()
                    .map_err(|e| FunSecretError::Mysql(e.to_string()))?;
                Self::purge_expired_mysql(&mut conn)?;
                conn.exec_first(
                    "SELECT `value`, expire_time FROM secret WHERE `key` = ?",
                    (enc_key,),
                )
                .map_err(|e| FunSecretError::Mysql(e.to_string()))?
            }
            Backend::Postgres { .. } => {
                let mut client = self.open_postgres_client()?;
                Self::purge_expired_postgres(&mut client)?;
                client
                    .query_opt(
                        "SELECT value, expire_time FROM secret WHERE key = $1",
                        &[&enc_key],
                    )
                    .map_err(|e| FunSecretError::Postgres(e.to_string()))?
                    .map(|row| {
                        let v: Option<String> = row.get(0);
                        let exp: Option<i64> = row.get(1);
                        (v.unwrap_or_default(), exp)
                    })
            }
        };

        if let Some((stored_val, stored_exp)) = fetched {
            let decrypted = self.decrypt(&stored_val, secret)?;
            if stored_exp.is_none_or(|exp| now < exp) {
                return Ok(Some(decrypted));
            }
        }
        Ok(None)
    }

    /// 按键删除单条记录，返回是否实际删除了记录。
    pub fn delete_key(&self, key: &str, secret: bool) -> Result<bool> {
        let enc_key = self.encrypt(key, secret)?;
        match &self.backend {
            Backend::Sqlite { .. } => {
                let conn = self.open_sqlite()?;
                let affected =
                    conn.execute("DELETE FROM secret WHERE key = ?1", params![enc_key])?;
                Ok(affected > 0)
            }
            Backend::Mysql { .. } => {
                let pool = self.open_mysql_pool()?;
                let mut conn = pool
                    .get_conn()
                    .map_err(|e| FunSecretError::Mysql(e.to_string()))?;
                conn.exec_drop("DELETE FROM secret WHERE `key` = ?", (enc_key,))
                    .map_err(|e| FunSecretError::Mysql(e.to_string()))?;
                Ok(conn.affected_rows() > 0)
            }
            Backend::Postgres { .. } => {
                let mut client = self.open_postgres_client()?;
                let affected = client
                    .execute("DELETE FROM secret WHERE key = $1", &[&enc_key])
                    .map_err(|e| FunSecretError::Postgres(e.to_string()))?;
                Ok(affected > 0)
            }
        }
    }

    /// 清空当前数据库中的全部密钥，返回删除条数。
    pub fn clear(&self) -> Result<usize> {
        log::warn!("delete_all:secret");
        match &self.backend {
            Backend::Sqlite { .. } => {
                let conn = self.open_sqlite()?;
                let affected = conn.execute("DELETE FROM secret", [])?;
                Ok(affected)
            }
            Backend::Mysql { .. } => {
                let pool = self.open_mysql_pool()?;
                let mut conn = pool
                    .get_conn()
                    .map_err(|e| FunSecretError::Mysql(e.to_string()))?;
                conn.query_drop("DELETE FROM secret")
                    .map_err(|e| FunSecretError::Mysql(e.to_string()))?;
                Ok(conn.affected_rows() as usize)
            }
            Backend::Postgres { .. } => {
                let mut client = self.open_postgres_client()?;
                let affected = client
                    .execute("DELETE FROM secret", &[])
                    .map_err(|e| FunSecretError::Postgres(e.to_string()))?;
                Ok(affected as usize)
            }
        }
    }

    /// 按分类路径读取密钥。
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
        expire_time: Option<i64>,
    ) -> Result<Option<String>> {
        let key = Self::convert_key(cate1, cate2, cate3, cate4, cate5);
        self.read_key(&key, value, save, secret, expire_time)
    }

    /// 按分类路径写入密钥。
    #[allow(clippy::too_many_arguments)]
    pub fn write(
        &self,
        value: &str,
        cate1: &str,
        cate2: &str,
        cate3: &str,
        cate4: &str,
        cate5: &str,
        secret: bool,
        expire_time: Option<i64>,
    ) -> Result<()> {
        let key = Self::convert_key(cate1, cate2, cate3, cate4, cate5);
        self.write_key(&key, Some(value), secret, expire_time)
    }

    /// 按分类路径删除单条密钥。
    pub fn delete(
        &self,
        cate1: &str,
        cate2: &str,
        cate3: &str,
        cate4: &str,
        cate5: &str,
        secret: bool,
    ) -> Result<bool> {
        let key = Self::convert_key(cate1, cate2, cate3, cate4, cate5);
        self.delete_key(&key, secret)
    }

    /// 列出所有未过期的密钥路径元数据（不解密、不返回密钥值）。
    pub fn list_entries(&self, secret: bool) -> Result<Vec<SecretEntry>> {
        let rows = self.fetch_active_rows()?;
        let mut entries = Vec::with_capacity(rows.len());
        for row in rows {
            let decrypted_key = self.decrypt(&row.key, secret)?;
            let parts = split_key_parts(&decrypted_key);
            if parts.is_empty() {
                continue;
            }
            let display_path = parts.join(" ");
            entries.push(SecretEntry {
                path: parts,
                display_path,
                gmt_create: row.gmt_create,
                gmt_modified: row.gmt_modified,
                expire_time: row.expire_time,
            });
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(entries)
    }

    /// 返回按分类嵌套的密钥树，并先清理过期记录（与 Python `list_secret` 一致）。
    pub fn list_secret(&self, secret: bool) -> Result<SecretTree> {
        let rows = self.fetch_active_rows()?;
        let mut root = SecretTree::new();
        for row in rows {
            let decrypted_key = self.decrypt(&row.key, secret)?;
            let decrypted_val = self.decrypt(&row.value, secret)?;
            let parts = split_key_parts(&decrypted_key);
            if parts.is_empty() {
                continue;
            }
            insert_into_tree(&mut root, &parts, decrypted_val);
        }
        Ok(root)
    }

    /// 获取当前存储后端信息与密钥计数。
    pub fn info(&self) -> Result<StoreInfo> {
        let entries = self.list_entries(true)?;
        Ok(StoreInfo {
            backend: self.backend_name().to_string(),
            database_url: self.masked_url(),
            database_file: self.database_file().map(|p| p.display().to_string()),
            secret_count: entries.len(),
            cipher_key_configured: !self.cipher_key.is_empty(),
            mysql_example_url: MYSQL_EXAMPLE_URL.to_string(),
        })
    }

    /// 将当前数据库中的全部记录同步到目标库（按需加解密，支持 SQLite3 / MySQL / PostgreSQL 任意互迁）。
    pub fn sync_to(
        &self,
        target: &SecretManage,
        source_secret: bool,
        target_secret: bool,
        progress: bool,
    ) -> Result<usize> {
        self.sync_to_labeled(target, source_secret, target_secret, progress, "syncing")
    }

    fn sync_to_labeled(
        &self,
        target: &SecretManage,
        source_secret: bool,
        target_secret: bool,
        progress: bool,
        label: &str,
    ) -> Result<usize> {
        let bar = SyncProgress::start(label, progress);
        let rows = self.scalars()?;
        bar.set_total(rows.len());
        let mut count = 0usize;

        match &target.backend {
            Backend::Sqlite { .. } => {
                let mut conn = target.open_sqlite()?;
                let tx = conn.transaction()?;
                let now_ts = now_sql_timestamp();
                {
                    let mut stmt = tx.prepare(
                        "INSERT INTO secret (gmt_create, gmt_modified, key, value, expire_time)
                         VALUES (?1, ?2, ?3, ?4, ?5)
                         ON CONFLICT(key) DO UPDATE SET
                            gmt_modified = excluded.gmt_modified,
                            value = excluded.value,
                            expire_time = excluded.expire_time",
                    )?;
                    for row in rows {
                        let plain_key = self.decrypt(&row.key, source_secret)?;
                        let plain_val = self.decrypt(&row.value, source_secret)?;
                        let target_key = target.encrypt(&plain_key, target_secret)?;
                        let target_val = target.encrypt(&plain_val, target_secret)?;
                        let created = row.gmt_create.as_deref().unwrap_or(&now_ts);
                        stmt.execute(params![
                            created,
                            now_ts,
                            target_key,
                            target_val,
                            row.expire_time
                        ])?;
                        count += 1;
                        bar.inc(1);
                    }
                }
                tx.commit()?;
            }
            Backend::Mysql { .. } => {
                let pool = target.open_mysql_pool()?;
                let mut conn = pool
                    .get_conn()
                    .map_err(|e| FunSecretError::Mysql(e.to_string()))?;
                let mut tx = conn
                    .start_transaction(mysql::TxOpts::default())
                    .map_err(|e| FunSecretError::Mysql(e.to_string()))?;
                for row in rows {
                    let plain_key = self.decrypt(&row.key, source_secret)?;
                    let plain_val = self.decrypt(&row.value, source_secret)?;
                    let target_key = target.encrypt(&plain_key, target_secret)?;
                    let target_val = target.encrypt(&plain_val, target_secret)?;
                    tx.exec_drop(
                        "INSERT INTO secret (gmt_create, gmt_modified, `key`, `value`, expire_time)
                         VALUES (NOW(), NOW(), ?, ?, ?)
                         ON DUPLICATE KEY UPDATE
                            gmt_modified = NOW(),
                            `value` = VALUES(`value`),
                            expire_time = VALUES(expire_time)",
                        (target_key, target_val, row.expire_time),
                    )
                    .map_err(|e| FunSecretError::Mysql(e.to_string()))?;
                    count += 1;
                    bar.inc(1);
                }
                tx.commit()
                    .map_err(|e| FunSecretError::Mysql(e.to_string()))?;
            }
            Backend::Postgres { .. } => {
                let mut client = target.open_postgres_client()?;
                let mut tx = client
                    .transaction()
                    .map_err(|e| FunSecretError::Postgres(e.to_string()))?;
                let stmt = tx
                    .prepare(
                        "INSERT INTO secret (gmt_create, gmt_modified, key, value, expire_time)
                         VALUES (CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, $1, $2, $3)
                         ON CONFLICT (key) DO UPDATE SET
                            gmt_modified = CURRENT_TIMESTAMP,
                            value = EXCLUDED.value,
                            expire_time = EXCLUDED.expire_time",
                    )
                    .map_err(|e| FunSecretError::Postgres(e.to_string()))?;
                for row in rows {
                    let plain_key = self.decrypt(&row.key, source_secret)?;
                    let plain_val = self.decrypt(&row.value, source_secret)?;
                    let target_key = target.encrypt(&plain_key, target_secret)?;
                    let target_val = target.encrypt(&plain_val, target_secret)?;
                    tx.execute(&stmt, &[&target_key, &target_val, &row.expire_time])
                        .map_err(|e| FunSecretError::Postgres(e.to_string()))?;
                    count += 1;
                    bar.inc(1);
                }
                tx.commit()
                    .map_err(|e| FunSecretError::Postgres(e.to_string()))?;
            }
        }
        bar.finish();
        Ok(count)
    }

    fn fetch_active_rows(&self) -> Result<Vec<SecretRecord>> {
        match &self.backend {
            Backend::Sqlite { .. } => {
                let conn = self.open_sqlite()?;
                Self::purge_expired_sqlite(&conn)?;
            }
            Backend::Mysql { .. } => {
                let pool = self.open_mysql_pool()?;
                let mut conn = pool
                    .get_conn()
                    .map_err(|e| FunSecretError::Mysql(e.to_string()))?;
                Self::purge_expired_mysql(&mut conn)?;
            }
            Backend::Postgres { .. } => {
                let mut client = self.open_postgres_client()?;
                Self::purge_expired_postgres(&mut client)?;
            }
        }
        self.scalars()
    }
}

fn insert_into_tree(root: &mut SecretTree, parts: &[String], value: String) {
    let mut current = root;
    for part in &parts[..parts.len() - 1] {
        let entry = current
            .entry(part.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        if !entry.is_object() {
            *entry = Value::Object(Map::new());
        }
        current = entry.as_object_mut().expect("ensured object");
    }
    current.insert(parts[parts.len() - 1].clone(), Value::String(value));
}

/// 将任意深度的密钥树展开为排序后的路径列表。
pub fn iter_tree_paths(tree: &SecretTree) -> Vec<Vec<String>> {
    let mut paths = Vec::new();
    collect_paths(tree, &mut Vec::new(), &mut paths);
    paths.sort();
    paths
}

fn collect_paths(tree: &SecretTree, prefix: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
    let ordered: BTreeMap<&String, &Value> = tree.iter().collect();
    for (k, v) in ordered {
        prefix.push(k.clone());
        if let Some(obj) = v.as_object() {
            collect_paths(obj, prefix, out);
        } else {
            out.push(prefix.clone());
        }
        prefix.pop();
    }
}

/// 从默认数据库读取密钥；传入 `value` 时先写入。
#[allow(clippy::too_many_arguments)]
pub fn read_secret(
    cate1: &str,
    cate2: &str,
    cate3: &str,
    cate4: &str,
    cate5: &str,
    value: Option<&str>,
    save: bool,
    secret: bool,
    expire_time: Option<i64>,
) -> Result<Option<String>> {
    let manage = SecretManage::new(None, None, None)?;
    let found = manage.read(
        cate1,
        cate2,
        cate3,
        cate4,
        cate5,
        value,
        save,
        secret,
        expire_time,
    )?;
    if found.is_none() {
        log::debug!("not found value from {cate1}/{cate2}/{cate3}/{cate4}/{cate5}");
    }
    Ok(found)
}

/// 向默认数据库写入密钥。
#[allow(clippy::too_many_arguments)]
pub fn write_secret(
    value: &str,
    cate1: &str,
    cate2: &str,
    cate3: &str,
    cate4: &str,
    cate5: &str,
    secret: bool,
    expire_time: Option<i64>,
) -> Result<()> {
    let manage = SecretManage::new(None, None, None)?;
    manage.write(
        value,
        cate1,
        cate2,
        cate3,
        cate4,
        cate5,
        secret,
        expire_time,
    )
}

/// 从默认数据库删除单条密钥。
pub fn delete_secret(
    cate1: &str,
    cate2: &str,
    cate3: &str,
    cate4: &str,
    cate5: &str,
    secret: bool,
) -> Result<bool> {
    let manage = SecretManage::new(None, None, None)?;
    manage.delete(cate1, cate2, cate3, cate4, cate5, secret)
}

/// 返回默认数据库中的密钥树。
pub fn list_secret(secret: bool) -> Result<SecretTree> {
    let manage = SecretManage::new(None, None, None)?;
    manage.list_secret(secret)
}

/// 从外部数据库加载密钥到默认数据库。
pub fn load_secret_db(
    url: Option<&str>,
    cipher_key: Option<&str>,
    progress: bool,
) -> Result<usize> {
    let source = SecretManage::new(None, url, cipher_key)?;
    let target = SecretManage::new(None, None, None)?;
    source.sync_to_labeled(&target, cipher_key.is_some(), true, progress, "loading")
}

/// 把默认数据库中的密钥保存到外部数据库。
pub fn save_secret_db(
    url: Option<&str>,
    cipher_key: Option<&str>,
    progress: bool,
) -> Result<usize> {
    let source = SecretManage::new(None, None, None)?;
    let target = SecretManage::new(None, url, cipher_key)?;
    source.sync_to_labeled(&target, true, cipher_key.is_some(), progress, "saving")
}

/// 清空指定数据库；未指定 `url` 时清空默认数据库。
pub fn clear_secret_db(url: Option<&str>, cipher_key: Option<&str>) -> Result<usize> {
    let manage = SecretManage::new(None, url, cipher_key)?;
    manage.clear()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write_delete_list_and_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let manage = SecretManage::new(Some(dir.path().to_str().unwrap()), None, None).unwrap();

        manage
            .write("中文-secret", "app", "prod", "token", "", "", true, None)
            .unwrap();
        assert_eq!(
            manage
                .read("app", "prod", "token", "", "", None, true, true, None)
                .unwrap()
                .as_deref(),
            Some("中文-secret")
        );

        let entries = manage.list_entries(true).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, vec!["app", "prod", "token"]);

        let tree = manage.list_secret(true).unwrap();
        assert_eq!(
            serde_json::Value::Object(tree),
            serde_json::json!({ "app": { "prod": { "token": "中文-secret" } } })
        );

        // 过期记录自动失效
        manage
            .write_key("expired", Some("value"), true, Some(-1))
            .unwrap();
        assert_eq!(
            manage.read_key("expired", None, false, true, None).unwrap(),
            None
        );

        // 单条删除
        assert!(manage.delete("app", "prod", "token", "", "", true).unwrap());
        assert!(!manage.delete("app", "prod", "token", "", "", true).unwrap());
        assert!(manage.list_entries(true).unwrap().is_empty());
    }

    #[test]
    fn save_load_and_clear_between_sqlite_dbs() {
        let dir = tempfile::tempdir().unwrap();
        let default_dir = dir.path().join("default");
        let restored_dir = dir.path().join("restored");
        let backup_file = dir.path().join("backup.db");
        let backup_url = format!("sqlite+pysqlite:///{}", backup_file.display());

        let default = SecretManage::new(Some(default_dir.to_str().unwrap()), None, None).unwrap();
        default
            .write("source-value", "app", "prod", "", "", "", true, None)
            .unwrap();

        let backup =
            SecretManage::new(Some(dir.path().to_str().unwrap()), Some(&backup_url), None).unwrap();
        assert_eq!(default.sync_to(&backup, true, false, false).unwrap(), 1);
        assert_eq!(
            backup
                .read("app", "prod", "", "", "", None, false, false, None)
                .unwrap()
                .as_deref(),
            Some("source-value")
        );

        let restored = SecretManage::new(Some(restored_dir.to_str().unwrap()), None, None).unwrap();
        assert_eq!(backup.sync_to(&restored, false, true, false).unwrap(), 1);
        assert_eq!(
            restored
                .read("app", "prod", "", "", "", None, false, true, None)
                .unwrap()
                .as_deref(),
            Some("source-value")
        );

        assert_eq!(backup.clear().unwrap(), 1);
        assert!(backup.scalars().unwrap().is_empty());
    }

    #[test]
    fn parses_sqlalchemy_dialects_for_sqlite_mysql_and_postgres() {
        // SQLite3
        assert!(matches!(
            parse_backend("sqlite:////tmp/a.db").unwrap(),
            Backend::Sqlite { path: Some(p), .. } if p == Path::new("/tmp/a.db")
        ));
        assert!(matches!(
            parse_backend("sqlite+pysqlite:///rel.db").unwrap(),
            Backend::Sqlite { path: Some(p), .. } if p == Path::new("rel.db")
        ));
        assert!(matches!(
            parse_backend("sqlite3:///:memory:").unwrap(),
            Backend::Sqlite { path: None, .. }
        ));

        // MySQL / MariaDB
        for url in [
            "mysql://u:p@127.0.0.1:3306/db",
            "mysql+pymysql://u:p@127.0.0.1:3306/db",
            "mysql+mysqldb://u:p@127.0.0.1:3306/db",
            "mariadb+mariadbconnector://u:p@127.0.0.1:3306/db",
        ] {
            assert!(matches!(
                parse_backend(url).unwrap(),
                Backend::Mysql { mysql_url, .. } if mysql_url == "mysql://u:p@127.0.0.1:3306/db"
            ));
        }

        // PostgreSQL
        for url in [
            "postgresql://u:p@127.0.0.1:5432/db",
            "postgres://u:p@127.0.0.1:5432/db",
            "postgresql+psycopg2://u:p@127.0.0.1:5432/db",
            "postgresql+psycopg://u:p@127.0.0.1:5432/db",
            "postgresql+asyncpg://u:p@127.0.0.1:5432/db",
        ] {
            assert!(matches!(
                parse_backend(url).unwrap(),
                Backend::Postgres { pg_url, .. } if pg_url == "postgresql://u:p@127.0.0.1:5432/db"
            ));
        }

        assert!(matches!(
            parse_backend("oracle://u:p@localhost/orcl"),
            Err(FunSecretError::UnsupportedUrl(_))
        ));
    }

    #[test]
    fn builds_postgres_tls_connector_without_panicking() {
        assert!(build_pg_tls_connector().is_ok());
    }

    #[test]
    fn hides_password_in_mysql_and_postgres_urls() {
        for raw in [
            "mysql+pymysql://user:secret-password@localhost/funsecret",
            "postgresql+psycopg2://user:secret-password@localhost:5432/funsecret",
        ] {
            let masked = hide_password_url(raw);
            assert!(!masked.contains("secret-password"));
            assert!(masked.contains("***"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn database_dir_and_file_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let secret_dir = dir.path().join("owner-only");
        let manage = SecretManage::new(Some(secret_dir.to_str().unwrap()), None, None).unwrap();
        let db_file = manage.database_file().unwrap();

        assert_eq!(
            std::fs::metadata(&secret_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(db_file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
