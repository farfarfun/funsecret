//! funsecret-core 错误类型定义。

use thiserror::Error;

/// `funsecret-core` 统一结果类型。
pub type Result<T> = std::result::Result<T, FunSecretError>;

/// `funsecret-core` 错误枚举。
#[derive(Debug, Error)]
pub enum FunSecretError {
    /// Fernet 密钥格式非法（必须为 32 字节 URL-safe Base64）。
    #[error("invalid cipher key: {0}")]
    InvalidCipherKey(String),

    /// Fernet 密文无效、签名校验失败或密钥不匹配。
    #[error("invalid fernet token")]
    InvalidToken,

    /// 参数或分类路径非法。
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// 不支持的数据库 URL。
    #[error("unsupported database url: {0}")]
    UnsupportedUrl(String),

    /// 文件系统 I/O 错误。
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// SQLite 错误。
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// MySQL 错误。
    #[error("mysql error: {0}")]
    Mysql(String),

    /// PostgreSQL 错误。
    #[error("postgres error: {0}")]
    Postgres(String),
}
