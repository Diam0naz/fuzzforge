//! Postgres-backed job queue.
//!
//! `SELECT ... FOR UPDATE SKIP LOCKED` is the whole trick. It gives correct
//! multi-worker claiming without Redis, SQS, or a broker to operate. That is
//! the right trade for a service that will not have hundreds of concurrent
//! fuzzing jobs for a long time.

use crate::Job;
use sqlx::PgPool;

/// Atomically claim the next queued job.
///
/// `worker_id` is recorded so a stuck job can be traced to (and requeued
/// from) the process that claimed it.
pub async fn claim_next(
    pool: &PgPool,
    worker_id: &str,
    max_attempts: i32,
) -> sqlx::Result<Option<Job>> {
    sqlx::query_as::<_, Job>(
        r#"
        UPDATE jobs
        SET status = 'running',
            worker_id = $1,
            started_at = now(),
            attempts = attempts + 1
        WHERE id = (
            SELECT id
            FROM jobs
            WHERE status = 'queued'
              AND attempts < $2
            ORDER BY created_at
            FOR UPDATE SKIP LOCKED
            LIMIT 1
        )
        RETURNING id, bundle_path, bundle_sha256, invariant_spec, attempts
        "#,
    )
    .bind(worker_id)
    .bind(max_attempts)
    .fetch_optional(pool)
    .await
}

/// Put jobs claimed by a dead worker back in the queue, or fail them once
/// their attempt budget is exhausted.
///
/// A worker that is SIGKILLed mid-job never gets to update the row. Without
/// this, the job sits in `running` forever and the customer waits forever.
pub async fn requeue_stale(
    pool: &PgPool,
    stale_after_secs: i64,
    max_attempts: i32,
) -> sqlx::Result<u64> {
    let result = sqlx::query(
        r#"
        WITH stale AS (
            SELECT id
            FROM jobs
            WHERE status = 'running'
              AND started_at < now() - ($1::bigint * interval '1 second')
            FOR UPDATE SKIP LOCKED
        )
        UPDATE jobs j
        SET status = CASE WHEN j.attempts >= $2 THEN 'failed' ELSE 'queued' END,
            worker_id = NULL,
            started_at = NULL,
            error = CASE
                WHEN j.attempts >= $2
                    THEN coalesce(j.error, 'worker lost; attempt limit reached')
                ELSE j.error
            END,
            finished_at = CASE WHEN j.attempts >= $2 THEN now() ELSE NULL END
        WHERE j.id IN (SELECT id FROM stale)
        "#,
    )
    .bind(stale_after_secs)
    .bind(max_attempts)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}
