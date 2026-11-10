use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use fuzzforge_common::{Job, SandboxResult, Summary};
use tokio::process::Command;
use uuid::Uuid;

use crate::config::Config;
use crate::minimizer::{self, Limits, Reproducer};

#[derive(Debug, Clone)]
pub struct ImageInfo {
    pub requested: String,
    /// The digest-bearing reference recorded in the report. For a pinned
    /// image this is the requested reference; otherwise the local image ID.
    pub resolved: String,
    /// False only when ALLOW_UNPINNED_IMAGE was explicitly set for local
    /// development. The report must never call an image ID "pinned".
    pub pinned: bool,
}

#[derive(Debug, Clone)]
pub struct SandboxProfile {
    pub image: String,
    pub memory: String,
    pub cpus: String,
    pub pids: u32,
    pub work_size: String,
}

impl SandboxProfile {
    /// The command printed in the report. It must be copy-pasteable on a
    /// machine that has Docker and the pinned image, and nothing else.
    pub fn run_command(&self) -> String {
        let flags = self.flags();
        format!(
            "mkdir -p fuzzforge-out && chmod 777 fuzzforge-out\n\
             docker run --rm \\\n{flags} \\\n  -v \"$PWD:/in:ro\" \\\n  -v \"$PWD/fuzzforge-out:/out:rw\" \\\n  {} fuzzforge-run",
            self.image
        )
    }

    pub fn case_command(&self) -> String {
        let flags = self.flags();
        format!(
            "mkdir -p fuzzforge-out && chmod 777 fuzzforge-out\n\
             # save the case JSON below as fuzzforge-out/case.json first\n\
             docker run --rm \\\n{flags} \\\n  -v \"$PWD:/in:ro\" \\\n  -v \"$PWD/fuzzforge-out:/out:rw\" \\\n  {} fuzzforge-reproduce --case /out/case.json",
            self.image
        )
    }

    fn flags(&self) -> String {
        format!(
            "  --init \\\n  --network none \\\n  --read-only \\\n  --tmpfs /work:rw,exec,nosuid,nodev,size={work_size},mode=1777 \\\n  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777 \\\n  --cap-drop ALL \\\n  --security-opt no-new-privileges:true \\\n  --ipc none \\\n  --pids-limit {pids} \\\n  --memory {memory} \\\n  --memory-swap {memory} \\\n  --cpus {cpus} \\\n  --ulimit nofile=1024:1024 \\\n  --stop-timeout 10 \\\n  --user 1000:1000 \\\n  --workdir /work \\\n  --env HOME=/work",
            pids = self.pids,
            memory = self.memory,
            cpus = self.cpus,
            work_size = self.work_size,
        )
    }
}

#[derive(Debug, Clone)]
pub struct MinimizeOutcome {
    pub enabled: bool,
    pub trials: usize,
    pub improved: usize,
}

#[derive(Debug, Clone)]
pub struct RunOutcome {
    pub summary: Summary,
    pub image: ImageInfo,
    pub profile: SandboxProfile,
    pub minimize: MinimizeOutcome,
}

pub async fn execute(config: &Config, job: &Job) -> Result<RunOutcome> {
    let bundle_path = PathBuf::from(&job.bundle_path);
    if !tokio::fs::try_exists(&bundle_path)
        .await
        .with_context(|| format!("check bundle {}", bundle_path.display()))?
    {
        bail!("bundle is missing: {}", bundle_path.display());
    }

    let host_bundle = to_host_path(config, &bundle_path)?;
    let run_dir = config.storage_dir.join("runs").join(job.id.to_string());
    let host_run_dir = config
        .host_storage_dir
        .join("runs")
        .join(job.id.to_string());
    tokio::fs::create_dir_all(&run_dir).await?;
    make_writable(&run_dir)?;

    let image = resolve_image(config).await?;
    let profile = SandboxProfile {
        image: image.resolved.clone(),
        memory: config.sandbox_memory.clone(),
        cpus: config.sandbox_cpus.clone(),
        pids: config.sandbox_pids,
        work_size: config.sandbox_work_size.clone(),
    };

    tracing::info!(
        job_id = %job.id,
        image = %image.resolved,
        run_dir = %run_dir.display(),
        "starting sandbox"
    );

    let command = vec!["fuzzforge-run".to_string()];
    let status = run_sandbox(
        config,
        &host_bundle,
        &host_run_dir,
        &run_dir,
        &image.requested,
        &command,
        config.job_timeout,
        "runner.log",
    )
    .await?;

    let result_path = run_dir.join("result.json");
    if !status.success() {
        let tail = read_log_tail(&run_dir.join("runner.log")).await;
        // A non-zero exit is only fatal if the adapter failed before writing
        // its result. A harness that exits non-zero after recording cases is
        // still a usable run.
        if !tokio::fs::try_exists(&result_path).await.unwrap_or(false) {
            bail!("sandbox exited with {}: {}", describe_status(status), tail);
        }
        tracing::warn!(
            job_id = %job.id,
            status = %describe_status(status),
            "sandbox exited non-zero but wrote result.json; reporting what it found"
        );
    }

    let raw = tokio::fs::read(&result_path).await.with_context(|| {
        format!(
            "sandbox did not write {}. The adapter in sandbox/bin/fuzzforge-run \
                 is the version-specific seam and probably needs updating.",
            result_path.display()
        )
    })?;
    let sandbox: SandboxResult =
        serde_json::from_slice(&raw).context("sandbox wrote an invalid result.json")?;

    let log_tail = match sandbox.log_tail.clone() {
        Some(tail) if !tail.trim().is_empty() => Some(tail),
        _ => {
            let tail = read_log_tail(&run_dir.join("runner.log")).await;
            if tail.is_empty() {
                None
            } else {
                Some(tail)
            }
        }
    };

    let mut summary = Summary {
        executions: sandbox.executions,
        failures: sandbox.failures,
        trident_version: sandbox.trident_version,
        log_tail,
    };

    let mut minimize = MinimizeOutcome {
        enabled: config.minimize,
        trials: 0,
        improved: 0,
    };

    if config.minimize && !summary.failures.is_empty() {
        let reproducer = DockerReproducer {
            config,
            image: image.requested.clone(),
            host_bundle: host_bundle.clone(),
            host_run_dir: host_run_dir.clone(),
            run_dir: run_dir.clone(),
        };
        let outcome = minimizer::shrink(
            &summary.failures,
            &reproducer,
            Limits {
                max_trials: config.minimize_max_trials,
                max_seconds: config.minimize_max_seconds,
            },
        )
        .await;
        minimize.trials = outcome.trials;
        minimize.improved = outcome.improved;
        summary.failures = outcome.failures;
    }

    Ok(RunOutcome {
        summary,
        image,
        profile,
        minimize,
    })
}

/// Best-effort cleanup used by the worker's outer timeout. The runner kills
/// its own container on timeout; this covers the case where the runner future
/// is cancelled before it can.
pub async fn cleanup(config: &Config, job_id: Uuid) {
    let run_dir = config.storage_dir.join("runs").join(job_id.to_string());
    kill_container(config, &run_dir.join("container.cid")).await;
}

fn to_host_path(config: &Config, path: &Path) -> Result<PathBuf> {
    let relative = path.strip_prefix(&config.storage_dir).with_context(|| {
        format!(
            "bundle path {} is outside STORAGE_DIR {}",
            path.display(),
            config.storage_dir.display()
        )
    })?;
    Ok(config.host_storage_dir.join(relative))
}

async fn resolve_image(config: &Config) -> Result<ImageInfo> {
    let requested = config.sandbox_image.clone();
    let output = Command::new(&config.docker_bin)
        .args(["image", "inspect", "--format", "{{.Id}}", &requested])
        .output()
        .await
        .with_context(|| format!("run `{} image inspect`", config.docker_bin))?;

    if !output.status.success() {
        bail!(
            "sandbox image {requested} is not available locally. \
             Build it with `make sandbox-build`, or pull the pinned digest. Docker said: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let image_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let pinned = requested.contains("@sha256:");
    let resolved = if pinned {
        requested.clone()
    } else {
        tracing::warn!(
            image = %requested,
            "running an unpinned sandbox image; this violates the reproducibility contract"
        );
        image_id
    };

    Ok(ImageInfo {
        requested,
        resolved,
        pinned,
    })
}

#[allow(clippy::too_many_arguments)]
async fn run_sandbox(
    config: &Config,
    host_bundle: &Path,
    host_run_dir: &Path,
    run_dir: &Path,
    image: &str,
    command: &[String],
    time_limit: Duration,
    log_name: &str,
) -> Result<ExitStatus> {
    let cidfile = run_dir.join("container.cid");
    let _ = tokio::fs::remove_file(&cidfile).await;

    let mut args = base_args(config, host_bundle, host_run_dir, image, &cidfile);
    args.extend(command.iter().cloned());

    let log_path = run_dir.join(log_name);
    let stdout = std::fs::File::create(&log_path)
        .with_context(|| format!("create sandbox log {}", log_path.display()))?;
    let stderr = stdout.try_clone().context("clone sandbox log handle")?;

    let mut child = Command::new(&config.docker_bin)
        .args(&args)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("spawn {}", config.docker_bin))?;

    match tokio::time::timeout(time_limit, child.wait()).await {
        Ok(status) => Ok(status.context("wait for docker run")?),
        Err(_) => {
            kill_container(config, &cidfile).await;
            let _ = child.wait().await;
            bail!(
                "sandbox exceeded its {} second limit and was killed",
                time_limit.as_secs()
            )
        }
    }
}

fn base_args(
    config: &Config,
    host_bundle: &Path,
    host_run_dir: &Path,
    image: &str,
    cidfile: &Path,
) -> Vec<String> {
    vec![
        "run".into(),
        "--rm".into(),
        "--init".into(),
        "--network".into(),
        "none".into(),
        "--read-only".into(),
        // mode=1777: the container runs as uid 1000, so the root-owned tmpfs
        // mounts must be world-writable or the adapter cannot create /work.
        "--tmpfs".into(),
        format!(
            "/work:rw,exec,nosuid,nodev,size={},mode=1777",
            config.sandbox_work_size
        ),
        "--tmpfs".into(),
        "/tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges:true".into(),
        "--ipc".into(),
        "none".into(),
        "--pids-limit".into(),
        config.sandbox_pids.to_string(),
        "--memory".into(),
        config.sandbox_memory.clone(),
        "--memory-swap".into(),
        config.sandbox_memory.clone(),
        "--cpus".into(),
        config.sandbox_cpus.clone(),
        "--ulimit".into(),
        "nofile=1024:1024".into(),
        "--stop-timeout".into(),
        "10".into(),
        "--user".into(),
        "1000:1000".into(),
        "--workdir".into(),
        "/work".into(),
        "--env".into(),
        "HOME=/work".into(),
        "--cidfile".into(),
        cidfile.to_string_lossy().into_owned(),
        "-v".into(),
        format!("{}:/in:ro", host_bundle.display()),
        "-v".into(),
        format!("{}:/out:rw", host_run_dir.display()),
        image.into(),
    ]
}

async fn kill_container(config: &Config, cidfile: &Path) {
    let Ok(contents) = tokio::fs::read_to_string(cidfile).await else {
        return;
    };
    let cid = contents.trim();
    if cid.is_empty() {
        return;
    }

    for args in [vec!["kill", cid], vec!["rm", "-f", cid]] {
        let _ = Command::new(&config.docker_bin)
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
    }
    let _ = tokio::fs::remove_file(cidfile).await;
}

async fn read_log_tail(path: &Path) -> String {
    let bytes = tokio::fs::read(path).await.unwrap_or_default();
    let text = String::from_utf8_lossy(&bytes);
    let trimmed = text.trim_end();
    let tail: String = trimmed.chars().rev().take(4_000).collect();
    tail.chars().rev().collect::<String>().trim().to_string()
}

fn describe_status(status: ExitStatus) -> String {
    match status.code() {
        Some(code) => format!("exit code {code}"),
        None => format!("signal ({status})"),
    }
}

#[cfg(unix)]
fn make_writable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(0o777);
    std::fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn make_writable(_path: &Path) -> Result<()> {
    Ok(())
}

struct DockerReproducer<'a> {
    config: &'a Config,
    image: String,
    host_bundle: PathBuf,
    host_run_dir: PathBuf,
    run_dir: PathBuf,
}

#[async_trait::async_trait]
impl Reproducer for DockerReproducer<'_> {
    async fn reproduces(&self, invariant: &str, candidate: &str) -> bool {
        let filename = format!("case-{}.json", Uuid::new_v4());
        let case_path = self.run_dir.join(&filename);
        let payload = serde_json::json!({
            "invariant": invariant,
            "reproducer": candidate,
        });

        if let Err(error) = tokio::fs::write(&case_path, payload.to_string()).await {
            tracing::warn!(%error, "could not write minimization case");
            return false;
        }

        let command = vec![
            "fuzzforge-reproduce".to_string(),
            "--case".to_string(),
            format!("/out/{filename}"),
        ];
        let result = run_sandbox(
            self.config,
            &self.host_bundle,
            &self.host_run_dir,
            &self.run_dir,
            &self.image,
            &command,
            self.config.repro_timeout,
            "repro.log",
        )
        .await;

        let _ = tokio::fs::remove_file(&case_path).await;

        match result {
            // 42 is the contract: the candidate still violates the invariant.
            Ok(status) => status.code() == Some(42),
            Err(error) => {
                tracing::debug!(%error, "minimization run failed");
                false
            }
        }
    }
}
