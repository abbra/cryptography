// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::backend::utils;
use crate::buf::CffiBuf;
use crate::error::CryptographyResult;

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.mlkem512")]
pub(crate) struct MlKem512PrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.mlkem512")]
pub(crate) struct MlKem512PublicKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
}

#[pyo3::pyfunction]
fn generate_key() -> CryptographyResult<MlKem512PrivateKey> {
    Ok(MlKem512PrivateKey {
        pkey: openssl::pkey::PKey::generate_ml_kem(openssl::pkey_ml_kem::Variant::MlKem512)?,
    })
}

pub(crate) fn private_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> MlKem512PrivateKey {
    MlKem512PrivateKey {
        pkey: pkey.to_owned(),
    }
}

pub(crate) fn public_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> MlKem512PublicKey {
    MlKem512PublicKey {
        pkey: pkey.to_owned(),
    }
}

#[pyo3::pyfunction]
fn from_private_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlKem512PrivateKey> {
    let pkey = openssl::pkey::PKey::private_key_from_raw_bytes_ex(data.as_bytes(), "ML-KEM-512")
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("Invalid ML-KEM-512 private key"))?;
    Ok(MlKem512PrivateKey { pkey })
}

#[pyo3::pyfunction]
fn from_public_bytes(data: &[u8]) -> pyo3::PyResult<MlKem512PublicKey> {
    let pkey = openssl::pkey::PKey::public_key_from_raw_bytes_ex(data, "ML-KEM-512")
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("Invalid ML-KEM-512 public key"))?;
    Ok(MlKem512PublicKey { pkey })
}

#[pyo3::pymethods]
impl MlKem512PrivateKey {
    fn decapsulate<'p>(
        &self,
        py: pyo3::Python<'p>,
        ciphertext: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        // ML-KEM-512 ciphertext must be exactly 768 bytes
        if ciphertext.as_bytes().len() != 768 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "ML-KEM-512 ciphertext must be 768 bytes",
            )
            .into());
        }

        let mut ctx = openssl::pkey_ctx::PkeyCtx::new(&self.pkey)?;
        ctx.decapsulate_init()?;

        let mut shared_secret = vec![];
        ctx.decapsulate_to_vec(ciphertext.as_bytes(), &mut shared_secret)?;

        Ok(pyo3::types::PyBytes::new(py, &shared_secret))
    }

    fn public_key(&self) -> CryptographyResult<MlKem512PublicKey> {
        let raw_bytes = self.pkey.raw_public_key()?;
        Ok(MlKem512PublicKey {
            pkey: openssl::pkey::PKey::public_key_from_raw_bytes_ex(&raw_bytes, "ML-KEM-512")?,
        })
    }

    fn private_bytes_raw<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let raw_bytes = self.pkey.raw_private_key()?;
        Ok(pyo3::types::PyBytes::new(py, &raw_bytes))
    }

    fn private_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: &pyo3::Bound<'p, pyo3::PyAny>,
        format: &pyo3::Bound<'p, pyo3::PyAny>,
        encryption_algorithm: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        utils::pkey_private_bytes(
            py,
            slf,
            &slf.borrow().pkey,
            encoding,
            format,
            encryption_algorithm,
            true,
            true,
        )
    }

    fn __eq__(&self, other: pyo3::PyRef<'_, Self>) -> bool {
        self.pkey.public_eq(&other.pkey)
    }

    fn __copy__(slf: pyo3::PyRef<'_, Self>) -> pyo3::PyRef<'_, Self> {
        slf
    }

    fn __deepcopy__<'p>(
        slf: pyo3::PyRef<'p, Self>,
        _memo: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> pyo3::PyRef<'p, Self> {
        slf
    }
}

#[pyo3::pymethods]
impl MlKem512PublicKey {
    fn encapsulate<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<(
        pyo3::Bound<'p, pyo3::types::PyBytes>,
        pyo3::Bound<'p, pyo3::types::PyBytes>,
    )> {
        let mut ctx = openssl::pkey_ctx::PkeyCtx::new(&self.pkey)?;
        ctx.encapsulate_init()?;

        let mut ciphertext = vec![];
        let mut shared_secret = vec![];
        ctx.encapsulate_to_vec(&mut ciphertext, &mut shared_secret)?;

        Ok((
            pyo3::types::PyBytes::new(py, &ciphertext),
            pyo3::types::PyBytes::new(py, &shared_secret),
        ))
    }

    fn public_bytes_raw<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let raw_bytes = self.pkey.raw_public_key()?;
        Ok(pyo3::types::PyBytes::new(py, &raw_bytes))
    }

    fn public_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: &pyo3::Bound<'p, pyo3::PyAny>,
        format: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        utils::pkey_public_bytes(py, slf, &slf.borrow().pkey, encoding, format, true, true)
    }

    fn __eq__(&self, other: pyo3::PyRef<'_, Self>) -> bool {
        self.pkey.public_eq(&other.pkey)
    }

    fn __copy__(slf: pyo3::PyRef<'_, Self>) -> pyo3::PyRef<'_, Self> {
        slf
    }

    fn __deepcopy__<'p>(
        slf: pyo3::PyRef<'p, Self>,
        _memo: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> pyo3::PyRef<'p, Self> {
        slf
    }
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod mlkem512 {
    #[pymodule_export]
    use super::{
        from_private_bytes, from_public_bytes, generate_key, MlKem512PrivateKey, MlKem512PublicKey,
    };
}
