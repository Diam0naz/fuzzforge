use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    /// Where this process reads and writes bundles/runs. Inside a container
    /// this is the mounted path, e.g. `/data`.
    pub storage_dir: PathBuf,
    /// The same directory as seen by the Docker daemon on the host. Docker
    /// resolves `-v` paths on the host, not in this process's namespace.
    pub host_storage_dir: PathBuf,

    pub sandbox_image: String,
    pub docker_bin: String,
    /// Refusing an unpinned image by default is deliberate: a tag is not a
    /// reproducibility contract.
    pub allow_unpinned_image: bool,

    pub poll_interval: Duration,
    pub job_timeout: Duration,
    pub repro_timeout: Duration,
    pub max_attempts: i32,
    pub stale_after_secs: i64,

    pub minimize: bool,
    pub minimize_max_trials: usize,
    pub minimize_max_seconds: u64,

    pub sandbox_memory: String,
    pub sandbox_cpus: String,
    pub sandbox_pids: u32,
    /// Size of the writable tmpfs at /work. A cold release build of an Anchor
    /// + Trident project needs several GB for vendor + target.
    pub sandbox_work_size: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let storage_dir = PathBuf::from(env_string("STORAGE_DIR", "./data"));
        std::fs::create_dir_all(storage_dir.join("bundles"))?;
        std::fs::create_dir_all(storage_dir.join("runs"))?;
        std::fs::create_dir_all(storage_dir.join("tmp"))?;
        let storage_dir = std::fs::canonicalize(&storage_dir)
            .with_context(|| format!("canonicalize STORAGE_DIR {}", storage_dir.display()))?;

        let host_storage_dir = match std::env::var("HOST_STORAGE_DIR") {
            Ok(value) if !value.trim().is_empty() => {
                let path = PathBuf::from(value);
                if path.is_absolute() {
                    path
                } else {
                    std::env::current_dir()
                        .context("resolve relative HOST_STORAGE_DIR")?
                        .join(path)
                }
            }
            _ => storage_dir.clone(),
        };

        Ok(Self {
            database_url: env_string(
                "DATABASE_URL",
                "postgres://fuzzforge:fuzzforge@localhost:5432/fuzzforge",
            ),
            storage_dir,
            host_storage_dir,
            sandbox_image: env_string("SANDBOX_IMAGE", "fuzzforge/sandbox:latest"),
            docker_bin: env_string("DOCKER_BIN", "docker"),
            allow_unpinned_image: env_bool("ALLOW_UNPINNED_IMAGE", false),
            poll_interval: Duration::from_secs(env_parse("POLL_INTERVAL_SECS", 2)?),
            job_timeout: Duration::from_secs(env_parse("JOB_TIMEOUT_SECS", 30 * 60)?),
            repro_timeout: Duration::from_secs(env_parse("REPRO_TIMEOUT_SECS", 3 * 60)?),
            max_attempts: env_parse("MAX_ATTEMPTS", 3)?,
            stale_after_secs: env_parse("STALE_AFTER_SECS", 90 * 60)?,
            minimize: env_bool("MINIMIZE", true),
            minimize_max_trials: env_parse("MINIMIZE_MAX_TRIALS", 60)?,
            minimize_max_seconds: env_parse("MINIMIZE_MAX_SECS", 10 * 60)?,
            sandbox_memory: env_string("SANDBOX_MEMORY", "4g"),
            sandbox_cpus: env_string("SANDBOX_CPUS", "2"),
            sandbox_pids: env_parse("SANDBOX_PIDS", 256)?,
            sandbox_work_size: env_string("SANDBOX_WORK_SIZE", "8g"),
        })
    }
}

fn env_string(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
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

fn env_bool(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(raw) => matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
}
