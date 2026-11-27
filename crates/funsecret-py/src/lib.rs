//! funsecret 的 Python 扩展模块（PyO3）。
//!
//! 将 `funsecret-core` 的全部能力暴露给 Python，Python 侧零运行时依赖。

use std::path::PathBuf;

use funsecret_core::{
    clear_secret_db as core_clear_secret_db, decrypt as core_decrypt,
    delete_secret as core_delete_secret, encrypt as core_encrypt,
    file_decrypt as core_file_decrypt, file_encrypt as core_file_encrypt,
    generate_key as core_generate_key, get_md5_file as core_get_md5_file,
    get_md5_str as core_get_md5_str, get_secret_path as core_get_secret_path,
    get_secret_url as core_get_secret_url, list_secret as core_list_secret,
    load_secret_db as core_load_secret_db, read_cache_secret as core_read_cache_secret,
    read_secret as core_read_secret, save_secret_db as core_save_secret_db,
    write_cache_secret as core_write_cache_secret, write_secret as core_write_secret,
    CacheSecretManage as CoreCacheSecretManage, FunSecretError, SecretManage as CoreSecretManage,
};
use pyo3::create_exception;
use pyo3::exceptions::{PyIOError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyModule};
use serde_json::Value;

create_exception!(_funsecret, InvalidToken, PyValueError);

fn to_py_err(err: FunSecretError) -> PyErr {
    match err {
        FunSecretError::InvalidToken => InvalidToken::new_err(err.to_string()),
        FunSecretError::InvalidCipherKey(msg)
        | FunSecretError::InvalidArgument(msg)
        | FunSecretError::UnsupportedUrl(msg) => PyValueError::new_err(msg),
        FunSecretError::Io(io_err) => PyIOError::new_err(io_err.to_string()),
        FunSecretError::Sqlite(sql_err) => PyRuntimeError::new_err(sql_err.to_string()),
        FunSecretError::Mysql(msg) | FunSecretError::Postgres(msg) => PyRuntimeError::new_err(msg),
    }
}

fn json_value_to_py(py: Python<'_>, value: &Value) -> PyResult<Py<PyAny>> {
    match value {
        Value::Null => Ok(py.None()),
        Value::Bool(b) => Ok(b.into_pyobject(py)?.to_owned().into_any().unbind()),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_pyobject(py)?.into_any().unbind())
            } else if let Some(u) = n.as_u64() {
                Ok(u.into_pyobject(py)?.into_any().unbind())
            } else {
                let f = n.as_f64().unwrap_or(0.0);
                Ok(f.into_pyobject(py)?.into_any().unbind())
            }
        }
        Value::String(s) => Ok(s.into_pyobject(py)?.into_any().unbind()),
        Value::Array(arr) => {
            let list = PyList::empty(py);
            for item in arr {
                list.append(json_value_to_py(py, item)?)?;
            }
            Ok(list.into_any().unbind())
        }
        Value::Object(map) => {
            let dict = PyDict::new(py);
            for (k, v) in map {
                dict.set_item(k, json_value_to_py(py, v)?)?;
            }
            Ok(dict.into_any().unbind())
        }
    }
}

fn tree_to_py_dict(py: Python<'_>, tree: &serde_json::Map<String, Value>) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new(py);
    for (k, v) in tree {
        dict.set_item(k, json_value_to_py(py, v)?)?;
    }
    Ok(dict.unbind())
}

#[pyfunction]
fn generate_key() -> String {
    core_generate_key()
}

#[pyfunction]
#[pyo3(signature = (text, cipher_key = None))]
fn encrypt(text: Option<&str>, cipher_key: Option<&str>) -> PyResult<Option<String>> {
    match (text, cipher_key) {
        (Some(t), Some(k)) => core_encrypt(t, k).map(Some).map_err(to_py_err),
        (Some(t), None) => Ok(Some(t.to_string())),
        (None, _) => Ok(None),
    }
}

#[pyfunction]
#[pyo3(signature = (encrypted_text, cipher_key = None))]
fn decrypt(encrypted_text: Option<&str>, cipher_key: Option<&str>) -> PyResult<Option<String>> {
    match (encrypted_text, cipher_key) {
        (Some(t), Some(k)) => core_decrypt(t, k).map(Some).map_err(to_py_err),
        (Some(t), None) => Ok(Some(t.to_string())),
        (None, _) => Ok(None),
    }
}

#[pyfunction]
#[pyo3(signature = (src_path, dst_path = None, cipher_key = None))]
fn file_encrypt(
    py: Python<'_>,
    src_path: PathBuf,
    dst_path: Option<PathBuf>,
    cipher_key: Option<String>,
) -> PyResult<String> {
    let key = cipher_key.ok_or_else(|| PyValueError::new_err("cipher_key cannot be None"))?;
    let out = py
        .detach(|| core_file_encrypt(&src_path, dst_path.as_deref(), &key))
        .map_err(to_py_err)?;
    Ok(out.to_string_lossy().into_owned())
}

#[pyfunction]
#[pyo3(signature = (src_path, dst_path = None, cipher_key = None))]
fn file_decrypt(
    py: Python<'_>,
    src_path: PathBuf,
    dst_path: Option<PathBuf>,
    cipher_key: Option<String>,
) -> PyResult<String> {
    let key = cipher_key.ok_or_else(|| PyValueError::new_err("cipher_key cannot be None"))?;
    let out = py
        .detach(|| core_file_decrypt(&src_path, dst_path.as_deref(), &key))
        .map_err(to_py_err)?;
    Ok(out.to_string_lossy().into_owned())
}

#[pyfunction]
fn get_md5_str(value: &str) -> String {
    core_get_md5_str(value)
}

#[pyfunction]
#[pyo3(signature = (path, chunk = 4096))]
fn get_md5_file(py: Python<'_>, path: PathBuf, chunk: usize) -> PyResult<String> {
    py.detach(|| core_get_md5_file(&path, chunk))
        .map_err(to_py_err)
}

#[pyfunction]
#[pyo3(signature = (secret_dir = None))]
fn get_secret_path(secret_dir: Option<&str>) -> PyResult<String> {
    core_get_secret_path(secret_dir).map_err(to_py_err)
}

#[pyfunction]
#[pyo3(signature = (secret_url = None))]
fn get_secret_url(secret_url: Option<&str>) -> Option<String> {
    core_get_secret_url(secret_url)
}

/// 管理本地 SQLite 或远端 MySQL 中的加密密钥。
#[pyclass(name = "SecretManage")]
struct PySecretManage {
    inner: CoreSecretManage,
}

#[pymethods]
impl PySecretManage {
    #[new]
    #[pyo3(signature = (secret_dir = None, url = None, cipher_key = None))]
    fn new(
        py: Python<'_>,
        secret_dir: Option<String>,
        url: Option<String>,
        cipher_key: Option<String>,
    ) -> PyResult<Self> {
        let inner = py
            .detach(|| {
                CoreSecretManage::new(secret_dir.as_deref(), url.as_deref(), cipher_key.as_deref())
            })
            .map_err(to_py_err)?;
        Ok(Self { inner })
    }

    #[getter]
    fn cipher_key(&self) -> &str {
        self.inner.cipher_key()
    }

    #[getter]
    fn secret_dir(&self) -> &str {
        self.inner.secret_dir()
    }

    #[getter]
    fn backend(&self) -> &str {
        self.inner.backend_name()
    }

    #[getter]
    fn database_url(&self) -> String {
        self.inner.masked_url()
    }

    #[getter]
    fn database_file(&self) -> Option<String> {
        self.inner
            .database_file()
            .map(|p| p.to_string_lossy().into_owned())
    }

    #[staticmethod]
    #[pyo3(signature = (cate1, cate2, cate3 = None, cate4 = None, cate5 = None))]
    fn convert_key(
        cate1: &str,
        cate2: &str,
        cate3: Option<&str>,
        cate4: Option<&str>,
        cate5: Option<&str>,
    ) -> String {
        let c3 = cate3.unwrap_or("None");
        let c4 = cate4.unwrap_or("None");
        let c5 = cate5.unwrap_or("None");
        CoreSecretManage::convert_key(cate1, cate2, c3, c4, c5)
    }

    #[pyo3(signature = (text, secret = true))]
    fn encrypt(&self, text: &str, secret: bool) -> PyResult<String> {
        self.inner.encrypt(text, secret).map_err(to_py_err)
    }

    #[pyo3(signature = (encrypted_text, secret = true))]
    fn decrypt(&self, encrypted_text: &str, secret: bool) -> PyResult<String> {
        self.inner
            .decrypt(encrypted_text, secret)
            .map_err(to_py_err)
    }

    #[pyo3(signature = (key, value = None, save = true, secret = true, expire_time = None))]
    fn read_key(
        &self,
        py: Python<'_>,
        key: String,
        value: Option<String>,
        save: bool,
        secret: bool,
        expire_time: Option<i64>,
    ) -> PyResult<Option<String>> {
        let inner = self.inner.clone();
        py.detach(move || inner.read_key(&key, value.as_deref(), save, secret, expire_time))
            .map_err(to_py_err)
    }

    #[pyo3(signature = (key, value, secret = true, expire_time = None))]
    fn write_key(
        &self,
        py: Python<'_>,
        key: String,
        value: Option<String>,
        secret: bool,
        expire_time: Option<i64>,
    ) -> PyResult<()> {
        let inner = self.inner.clone();
        py.detach(move || inner.write_key(&key, value.as_deref(), secret, expire_time))
            .map_err(to_py_err)
    }

    #[pyo3(signature = (key, secret = true))]
    fn delete_key(&self, py: Python<'_>, key: String, secret: bool) -> PyResult<bool> {
        let inner = self.inner.clone();
        py.detach(move || inner.delete_key(&key, secret))
            .map_err(to_py_err)
    }

    #[pyo3(signature = (cate1, cate2, cate3 = "", cate4 = "", cate5 = "", value = None, save = true, secret = true, expire_time = None))]
    #[allow(clippy::too_many_arguments)]
    fn read(
        &self,
        py: Python<'_>,
        cate1: String,
        cate2: String,
        cate3: &str,
        cate4: &str,
        cate5: &str,
        value: Option<String>,
        save: bool,
        secret: bool,
        expire_time: Option<i64>,
    ) -> PyResult<Option<String>> {
        let inner = self.inner.clone();
        let (c3, c4, c5) = (cate3.to_string(), cate4.to_string(), cate5.to_string());
        py.detach(move || {
            inner.read(
                &cate1,
                &cate2,
                &c3,
                &c4,
                &c5,
                value.as_deref(),
                save,
                secret,
                expire_time,
            )
        })
        .map_err(to_py_err)
    }

    #[pyo3(signature = (value, cate1, cate2 = "", cate3 = "", cate4 = "", cate5 = "", secret = true, expire_time = None))]
    #[allow(clippy::too_many_arguments)]
    fn write(
        &self,
        py: Python<'_>,
        value: String,
        cate1: String,
        cate2: &str,
        cate3: &str,
        cate4: &str,
        cate5: &str,
        secret: bool,
        expire_time: Option<i64>,
    ) -> PyResult<()> {
        let inner = self.inner.clone();
        let (c2, c3, c4, c5) = (
            cate2.to_string(),
            cate3.to_string(),
            cate4.to_string(),
            cate5.to_string(),
        );
        py.detach(move || inner.write(&value, &cate1, &c2, &c3, &c4, &c5, secret, expire_time))
            .map_err(to_py_err)
    }

    #[pyo3(signature = (cate1, cate2, cate3 = "", cate4 = "", cate5 = "", secret = true))]
    #[allow(clippy::too_many_arguments)]
    fn delete(
        &self,
        py: Python<'_>,
        cate1: String,
        cate2: String,
        cate3: &str,
        cate4: &str,
        cate5: &str,
        secret: bool,
    ) -> PyResult<bool> {
        let inner = self.inner.clone();
        let (c3, c4, c5) = (cate3.to_string(), cate4.to_string(), cate5.to_string());
        py.detach(move || inner.delete(&cate1, &cate2, &c3, &c4, &c5, secret))
            .map_err(to_py_err)
    }

    #[pyo3(signature = (secret = true))]
    fn list_secret(&self, py: Python<'_>, secret: bool) -> PyResult<Py<PyDict>> {
        let inner = self.inner.clone();
        let tree = py
            .detach(move || inner.list_secret(secret))
            .map_err(to_py_err)?;
        tree_to_py_dict(py, &tree)
    }

    #[pyo3(signature = (secret = true))]
    fn list_entries(&self, py: Python<'_>, secret: bool) -> PyResult<Py<PyAny>> {
        let inner = self.inner.clone();
        let entries = py
            .detach(move || inner.list_entries(secret))
            .map_err(to_py_err)?;
        let val =
            serde_json::to_value(entries).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        json_value_to_py(py, &val)
    }

    fn info(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let inner = self.inner.clone();
        let info = py.detach(move || inner.info()).map_err(to_py_err)?;
        let val = serde_json::to_value(info).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        json_value_to_py(py, &val)
    }

    fn clear(&self, py: Python<'_>) -> PyResult<usize> {
        let inner = self.inner.clone();
        py.detach(move || inner.clear()).map_err(to_py_err)
    }

    #[pyo3(signature = (target, source_secret = true, target_secret = true))]
    fn sync_to(
        &self,
        py: Python<'_>,
        target: &PySecretManage,
        source_secret: bool,
        target_secret: bool,
    ) -> PyResult<usize> {
        let source = self.inner.clone();
        let dst = target.inner.clone();
        py.detach(move || source.sync_to(&dst, source_secret, target_secret))
            .map_err(to_py_err)
    }
}

/// 使用原生 SQLite 保存短期加密密钥。
#[pyclass(name = "CacheSecretManage")]
struct PyCacheSecretManage {
    inner: CoreCacheSecretManage,
}

#[pymethods]
impl PyCacheSecretManage {
    #[new]
    #[pyo3(signature = (secret_dir = None, cipher_key = None))]
    fn new(
        py: Python<'_>,
        secret_dir: Option<String>,
        cipher_key: Option<String>,
    ) -> PyResult<Self> {
        let inner = py
            .detach(|| CoreCacheSecretManage::new(secret_dir.as_deref(), cipher_key.as_deref()))
            .map_err(to_py_err)?;
        Ok(Self { inner })
    }

    #[getter]
    fn cipher_key(&self) -> &str {
        self.inner.cipher_key()
    }

    #[getter]
    fn secret_dir(&self) -> &str {
        self.inner.secret_dir()
    }

    fn encrypt(&self, text: &str) -> PyResult<String> {
        self.inner.encrypt(text).map_err(to_py_err)
    }

    fn decrypt(&self, encrypted_text: &str) -> PyResult<String> {
        self.inner.decrypt(encrypted_text).map_err(to_py_err)
    }

    #[pyo3(signature = (cate1, cate2, cate3 = "", cate4 = "", cate5 = "", value = None, save = true, secret = true, expire_time = None))]
    #[allow(clippy::too_many_arguments)]
    fn read(
        &self,
        py: Python<'_>,
        cate1: String,
        cate2: String,
        cate3: &str,
        cate4: &str,
        cate5: &str,
        value: Option<String>,
        save: bool,
        secret: bool,
        expire_time: Option<f64>,
    ) -> PyResult<Option<String>> {
        let inner = self.inner.clone();
        let (c3, c4, c5) = (cate3.to_string(), cate4.to_string(), cate5.to_string());
        py.detach(move || {
            inner.read(
                &cate1,
                &cate2,
                &c3,
                &c4,
                &c5,
                value.as_deref(),
                save,
                secret,
                expire_time,
            )
        })
        .map_err(to_py_err)
    }

    #[pyo3(signature = (cate1, cate2, cate3 = "", cate4 = "", cate5 = "", value = None, secret = true, expire_time = None))]
    #[allow(clippy::too_many_arguments)]
    fn write(
        &self,
        py: Python<'_>,
        cate1: String,
        cate2: String,
        cate3: &str,
        cate4: &str,
        cate5: &str,
        value: Option<String>,
        secret: bool,
        expire_time: Option<f64>,
    ) -> PyResult<()> {
        let inner = self.inner.clone();
        let (c3, c4, c5) = (cate3.to_string(), cate4.to_string(), cate5.to_string());
        py.detach(move || {
            inner.write(
                &cate1,
                &cate2,
                &c3,
                &c4,
                &c5,
                value.as_deref(),
                secret,
                expire_time,
            )
        })
        .map_err(to_py_err)
    }
}

#[pyfunction]
#[pyo3(signature = (cate1, cate2, cate3 = "", cate4 = "", cate5 = "", value = None, save = true, secret = true, expire_time = None))]
#[allow(clippy::too_many_arguments)]
fn read_secret(
    py: Python<'_>,
    cate1: String,
    cate2: String,
    cate3: &str,
    cate4: &str,
    cate5: &str,
    value: Option<String>,
    save: bool,
    secret: bool,
    expire_time: Option<i64>,
) -> PyResult<Option<String>> {
    let (c3, c4, c5) = (cate3.to_string(), cate4.to_string(), cate5.to_string());
    py.detach(move || {
        core_read_secret(
            &cate1,
            &cate2,
            &c3,
            &c4,
            &c5,
            value.as_deref(),
            save,
            secret,
            expire_time,
        )
    })
    .map_err(to_py_err)
}

#[pyfunction]
#[pyo3(signature = (value, cate1, cate2 = "", cate3 = "", cate4 = "", cate5 = "", secret = true, expire_time = None))]
#[allow(clippy::too_many_arguments)]
fn write_secret(
    py: Python<'_>,
    value: String,
    cate1: String,
    cate2: &str,
    cate3: &str,
    cate4: &str,
    cate5: &str,
    secret: bool,
    expire_time: Option<i64>,
) -> PyResult<()> {
    let (c2, c3, c4, c5) = (
        cate2.to_string(),
        cate3.to_string(),
        cate4.to_string(),
        cate5.to_string(),
    );
    py.detach(move || core_write_secret(&value, &cate1, &c2, &c3, &c4, &c5, secret, expire_time))
        .map_err(to_py_err)
}

#[pyfunction]
#[pyo3(signature = (cate1, cate2, cate3 = "", cate4 = "", cate5 = "", secret = true))]
fn delete_secret(
    py: Python<'_>,
    cate1: String,
    cate2: String,
    cate3: &str,
    cate4: &str,
    cate5: &str,
    secret: bool,
) -> PyResult<bool> {
    let (c3, c4, c5) = (cate3.to_string(), cate4.to_string(), cate5.to_string());
    py.detach(move || core_delete_secret(&cate1, &cate2, &c3, &c4, &c5, secret))
        .map_err(to_py_err)
}

#[pyfunction]
#[pyo3(signature = (secret = true))]
fn list_secret(py: Python<'_>, secret: bool) -> PyResult<Py<PyDict>> {
    let tree = py
        .detach(move || core_list_secret(secret))
        .map_err(to_py_err)?;
    tree_to_py_dict(py, &tree)
}

#[pyfunction]
#[pyo3(signature = (url = None, cipher_key = None))]
fn load_secret_db(py: Python<'_>, url: Option<String>, cipher_key: Option<String>) -> PyResult<()> {
    py.detach(move || core_load_secret_db(url.as_deref(), cipher_key.as_deref()))
        .map(|_| ())
        .map_err(to_py_err)
}

#[pyfunction]
#[pyo3(signature = (url = None, cipher_key = None))]
fn save_secret_db(py: Python<'_>, url: Option<String>, cipher_key: Option<String>) -> PyResult<()> {
    py.detach(move || core_save_secret_db(url.as_deref(), cipher_key.as_deref()))
        .map(|_| ())
        .map_err(to_py_err)
}

#[pyfunction]
#[pyo3(signature = (url = None, cipher_key = None))]
fn clear_secret_db(
    py: Python<'_>,
    url: Option<String>,
    cipher_key: Option<String>,
) -> PyResult<()> {
    py.detach(move || core_clear_secret_db(url.as_deref(), cipher_key.as_deref()))
        .map(|_| ())
        .map_err(to_py_err)
}

#[pyfunction]
#[pyo3(signature = (cate1, cate2, cate3 = "", cate4 = "", cate5 = "", value = None, save = true, secret = true, expire_time = None))]
#[allow(clippy::too_many_arguments)]
fn read_cache_secret(
    py: Python<'_>,
    cate1: String,
    cate2: String,
    cate3: &str,
    cate4: &str,
    cate5: &str,
    value: Option<String>,
    save: bool,
    secret: bool,
    expire_time: Option<f64>,
) -> PyResult<Option<String>> {
    let (c3, c4, c5) = (cate3.to_string(), cate4.to_string(), cate5.to_string());
    py.detach(move || {
        core_read_cache_secret(
            &cate1,
            &cate2,
            &c3,
            &c4,
            &c5,
            value.as_deref(),
            save,
            secret,
            expire_time,
        )
    })
    .map_err(to_py_err)
}

#[pyfunction]
#[pyo3(signature = (value, cate1, cate2 = "", cate3 = "", cate4 = "", cate5 = "", secret = true, expire_time = None))]
#[allow(clippy::too_many_arguments)]
fn write_cache_secret(
    py: Python<'_>,
    value: String,
    cate1: String,
    cate2: &str,
    cate3: &str,
    cate4: &str,
    cate5: &str,
    secret: bool,
    expire_time: Option<f64>,
) -> PyResult<()> {
    let (c2, c3, c4, c5) = (
        cate2.to_string(),
        cate3.to_string(),
        cate4.to_string(),
        cate5.to_string(),
    );
    py.detach(move || {
        core_write_cache_secret(&value, &cate1, &c2, &c3, &c4, &c5, secret, expire_time)
    })
    .map_err(to_py_err)
}

#[pymodule]
fn _funsecret(py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    pyo3_log::init();

    module.add("InvalidToken", py.get_type::<InvalidToken>())?;
    module.add_class::<PySecretManage>()?;
    module.add_class::<PyCacheSecretManage>()?;

    module.add_function(wrap_pyfunction!(generate_key, module)?)?;
    module.add_function(wrap_pyfunction!(encrypt, module)?)?;
    module.add_function(wrap_pyfunction!(decrypt, module)?)?;
    module.add_function(wrap_pyfunction!(file_encrypt, module)?)?;
    module.add_function(wrap_pyfunction!(file_decrypt, module)?)?;
    module.add_function(wrap_pyfunction!(get_md5_str, module)?)?;
    module.add_function(wrap_pyfunction!(get_md5_file, module)?)?;
    module.add_function(wrap_pyfunction!(get_secret_path, module)?)?;
    module.add_function(wrap_pyfunction!(get_secret_url, module)?)?;
    module.add_function(wrap_pyfunction!(read_secret, module)?)?;
    module.add_function(wrap_pyfunction!(write_secret, module)?)?;
    module.add_function(wrap_pyfunction!(delete_secret, module)?)?;
    module.add_function(wrap_pyfunction!(list_secret, module)?)?;
    module.add_function(wrap_pyfunction!(load_secret_db, module)?)?;
    module.add_function(wrap_pyfunction!(save_secret_db, module)?)?;
    module.add_function(wrap_pyfunction!(clear_secret_db, module)?)?;
    module.add_function(wrap_pyfunction!(read_cache_secret, module)?)?;
    module.add_function(wrap_pyfunction!(write_cache_secret, module)?)?;

    Ok(())
}
