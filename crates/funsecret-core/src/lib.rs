//! funsecret 纯 Rust 核心库。

pub mod cache;
pub mod error;
pub mod fernet;
pub mod store;

pub use cache::{read_cache_secret, write_cache_secret, CacheSecretManage};
pub use error::{FunSecretError, Result};
pub use fernet::{
    decrypt, decrypt_bytes, derive_default_key, encrypt, encrypt_bytes, file_decrypt, file_encrypt,
    generate_key, get_md5_file, get_md5_str,
};
pub use store::{
    clear_secret_db, delete_secret, get_secret_path, get_secret_url, hide_password_url,
    iter_tree_paths, list_secret, load_secret_db, read_secret, save_secret_db, split_key_parts,
    write_secret, SecretEntry, SecretManage, SecretRecord, SecretTree, StoreInfo,
    DEFAULT_DB_URL_CATEGORY, MYSQL_EXAMPLE_URL,
};
