mod config;
mod db;
mod minimizer;
mod report;
mod runner;

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use fuzzforge_common::queue;
use tokio::time::timeout;
use tracing_subscriber::EnvFilter;

use crate::config::Config;

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("fuzzforge_worker=info,info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let config = Arc::new(Config::from_env()?);
    let pool = db::connect(&config.database_url).await?;
    let worker_id = format!("worker-{}", uuid::Uuid::new_v4());

    if !config.sandbox_image.contains("@sha256:") && !config.allow_unpinned_image {
        anyhow::bail!(
            "SANDBOX_IMAGE must be pinned by digest (…@sha256:…). \
             Set ALLOW_UNPINNED_IMAGE=1 only for local development."
        );
    }

    tracing::info!(
        %worker_id,
        image = %config.sandbox_image,
        minimize = config.minimize,
        "worker started"
    );

    let mut last_reap = Instant::now() - Duration::from_secs(config.stale_after_secs as u64);

    loop {
        if last_reap.elapsed() >= Duration::from_secs(60) {
            match queue::requeue_stale(&pool, config.stale_after_secs, config.max_attempts).await {
                Ok(0) => {}
                Ok(count) => tracing::warn!(count, "requeued stale jobs"),
                Err(error) => tracing::error!(%error, "failed to requeue stale jobs"),
            }
            last_reap = Instant::now();
        }

        let job = match queue::claim_next(&pool, &worker_id, config.max_attempts).await {
            Ok(Some(job)) => job,
            Ok(None) => {
                tokio::time::sleep(config.poll_interval).await;
                continue;
            }
            Err(error) => {
                tracing::error!(%error, "failed to claim job");
                tokio::time::sleep(config.poll_interval).await;
                continue;
            }
        };

        tracing::info!(
            job_id = %job.id,
            attempt = job.attempts,
            bundle = %job.bundle_sha256,
            "job claimed"
        );
        let started = Instant::now();

        // The runner enforces its own timeout and kills the container. This
        // outer timeout is a backstop for a hung Docker CLI, not the primary
        // control.
        let backstop = config.job_timeout + Duration::from_secs(60);
        let run = timeout(backstop, runner::execute(&config, &job)).await;

        match run {
            Ok(Ok(outcome)) => {
                tracing::info!(
                    job_id = %job.id,
                    executions = outcome.summary.executions,
                    failures = outcome.summary.failures.len(),
                    "sandbox finished"
                );
                if let Err(error) = report::write(&pool, &job, &outcome, &worker_id).await {
                    tracing::error!(job_id = %job.id, %error, "failed to write report");
                    let _ = report::fail(&pool, &job, &error.to_string(), &worker_id).await;
                }
            }
            Ok(Err(error)) => {
                tracing::error!(job_id = %job.id, %error, "sandbox failed");
                let _ = report::fail(&pool, &job, &error.to_string(), &worker_id).await;
            }
            Err(_) => {
                tracing::error!(job_id = %job.id, "worker backstop timeout");
                runner::cleanup(&config, job.id).await;
                let _ = report::fail(
                    &pool,
                    &job,
                    "worker timed out while waiting for the sandbox",
                    &worker_id,
                )
                .await;
            }
        }

        tracing::info!(
            job_id = %job.id,
            elapsed_secs = started.elapsed().as_secs(),
            "job finished"
        );
    }
}
