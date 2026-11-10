use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};

/// API configuration, all from the environment so the same binary runs
/// locally and in the container.
#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub bind_addr: SocketAddr,
    /// Absolute once `Storage::new` canonicalizes it.
    pub storage_dir: PathBuf,
    pub cors_origins: Vec<String>,
    pub max_upload_bytes: usize,
    pub max_unpacked_bytes: u64,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://fuzzforge:fuzzforge@localhost:5432/fuzzforge".into());

        let bind_addr = std::env::var("BIND_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:8080".into())
            .parse()
            .context("BIND_ADDR must be an address like 127.0.0.1:8080")?;

        let storage_dir =
            PathBuf::from(std::env::var("STORAGE_DIR").unwrap_or_else(|_| "./data".into()));

        let cors_origins = std::env::var("CORS_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:3000".into())
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();

        let max_upload_bytes = env_parse("MAX_UPLOAD_BYTES", 100 * 1024 * 1024)?;
        let max_unpacked_bytes = env_parse("MAX_UNPACKED_BYTES", 2 * 1024 * 1024 * 1024)?;

        Ok(Self {
            database_url,
            bind_addr,
            storage_dir,
            cors_origins,
            max_upload_bytes,
            max_unpacked_bytes,
        })
    }
}

fn env_parse<T>(name: &str, default: T) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match std::env::var(name) {
        Ok(raw) => raw
            .parse()
            .map_err(|e| anyhow::anyhow!("{name} is invalid: {e}")),
        Err(_) => Ok(default),
    }
}
