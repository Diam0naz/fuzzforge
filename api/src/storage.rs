use std::path::{Path, PathBuf};

use axum::extract::multipart::Field;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::error::ApiError;
use crate::validate::{self, BundleFormat, BundleInfo};

/// Local-disk, content-addressed bundle storage.
///
/// `/<root>/bundles/<sha256>.tar[.gz]` means the same bundle uploaded twice
/// costs one copy and jobs can share it safely. In v1 this lives on one box
/// with a nightly backup; replacing it with an object store later does not
/// change the job row or the worker contract.
#[derive(Clone)]
pub struct Storage {
    root: PathBuf,
}

pub struct StoredBundle {
    pub sha256: String,
    pub bytes: u64,
    pub path: PathBuf,
    pub format: BundleFormat,
    pub info: BundleInfo,
}

impl Storage {
    pub fn new(dir: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(dir.join("bundles"))?;
        std::fs::create_dir_all(dir.join("tmp"))?;
        let root = std::fs::canonicalize(dir)?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Stream one multipart field to a temp file, hash it, validate the
    /// archive, then move it into the content-addressed store.
    ///
    /// The upload is never buffered in memory, and the size cap is enforced
    /// while streaming so a 2 GB blob cannot fill the disk or the process.
    pub async fn store_bundle(
        &self,
        mut field: Field<'_>,
        max_bytes: usize,
        max_unpacked_bytes: u64,
    ) -> Result<StoredBundle, ApiError> {
        let tmp_path = self
            .root
            .join("tmp")
            .join(format!("{}.upload", Uuid::new_v4()));

        let mut file = tokio::fs::File::create(&tmp_path)
            .await
            .map_err(ApiError::internal)?;
        let mut hasher = Sha256::new();
        let mut bytes: u64 = 0;

        loop {
            let chunk = match field.chunk().await {
                Ok(chunk) => chunk,
                Err(error) => {
                    let _ = tokio::fs::remove_file(&tmp_path).await;
                    return Err(error.into());
                }
            };

            let Some(chunk) = chunk else {
                break;
            };

            bytes = bytes.saturating_add(chunk.len() as u64);
            if bytes > max_bytes as u64 {
                drop(file);
                let _ = tokio::fs::remove_file(&tmp_path).await;
                return Err(ApiError::payload_too_large(format!(
                    "bundle exceeds the {} byte upload limit",
                    max_bytes
                )));
            }

            hasher.update(&chunk);
            if let Err(error) = file.write_all(&chunk).await {
                let _ = tokio::fs::remove_file(&tmp_path).await;
                return Err(ApiError::internal(error));
            }
        }

        if let Err(error) = file.flush().await {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(ApiError::internal(error));
        }
        drop(file);

        if bytes == 0 {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(ApiError::bad_request("bundle is empty"));
        }

        let format = validate::detect_format(&tmp_path).map_err(ApiError::internal)?;
        let sha256 = hex::encode(hasher.finalize());

        let validation_path = tmp_path.clone();
        let info = match tokio::task::spawn_blocking(move || {
            validate::validate(&validation_path, format, max_unpacked_bytes)
        })
        .await
        {
            Ok(Ok(info)) => info,
            Ok(Err(message)) => {
                let _ = tokio::fs::remove_file(&tmp_path).await;
                return Err(ApiError::bad_request(format!("invalid bundle: {message}")));
            }
            Err(error) => {
                let _ = tokio::fs::remove_file(&tmp_path).await;
                return Err(ApiError::internal(error));
            }
        };

        let final_path = self
            .root
            .join("bundles")
            .join(format!("{sha256}.{}", format.extension()));

        if tokio::fs::try_exists(&final_path)
            .await
            .map_err(ApiError::internal)?
        {
            let _ = tokio::fs::remove_file(&tmp_path).await;
        } else {
            tokio::fs::rename(&tmp_path, &final_path)
                .await
                .map_err(ApiError::internal)?;
        }

        Ok(StoredBundle {
            sha256,
            bytes,
            path: final_path,
            format,
            info,
        })
    }
}
