use chrono::{DateTime, Utc};
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::error::ApiError;

/// The subset of a job the read routes need.
///
/// `report_md` and `report_json` are deliberately NOT selected here: a status
/// page polls this endpoint every few seconds, and a large report should not
/// ride along with every poll. Report routes fetch the body separately after
/// authorization.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct JobRecord {
    pub id: Uuid,
    pub status: String,
    pub token_hash: String,
    pub bundle_sha256: String,
    pub invariant_spec: String,
    pub executions: Option<i64>,
    pub failure_count: Option<i32>,
    pub error: Option<String>,
    pub report_available: bool,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
}

/// 256 bits of OS randomness, hex encoded. This is the only credential that
/// can read a job, so it is generated once and never logged.
pub fn new_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn tokens_match(provided: &str, expected_hash: &str) -> bool {
    let provided_hash = hash_token(provided);
    // Both sides are fixed-length hex digests; compare without an early exit.
    provided_hash
        .as_bytes()
        .ct_eq(expected_hash.as_bytes())
        .into()
}

/// Accept either `Authorization: Bearer <token>` or `?token=`, because a job
/// link is meant to be pasteable into a browser while the frontend can still
/// use the header for API calls.
pub fn token_from(headers: &axum::http::HeaderMap, query_token: Option<&str>) -> Option<String> {
    if let Some(value) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(value) = value.to_str() {
            if let Some(token) = value.strip_prefix("Bearer ") {
                if !token.is_empty() {
                    return Some(token.to_string());
                }
            }
        }
    }
    query_token
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_string)
}

pub async fn fetch_authorized(
    pool: &PgPool,
    id: Uuid,
    token: Option<&str>,
) -> Result<JobRecord, ApiError> {
    let Some(token) = token else {
        return Err(ApiError::unauthorized());
    };

    let job = sqlx::query_as::<_, JobRecord>(
        r#"
        SELECT id, status, token_hash, bundle_sha256, invariant_spec,
               executions, failure_count, error,
               (report_md IS NOT NULL) AS report_available,
               created_at, started_at, finished_at
        FROM jobs
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| ApiError::not_found("job not found"))?;

    if !tokens_match(token, &job.token_hash) {
        return Err(ApiError::unauthorized());
    }

    Ok(job)
}

pub async fn fetch_report_markdown(pool: &PgPool, id: Uuid) -> Result<Option<String>, ApiError> {
    Ok(
        sqlx::query_scalar::<_, Option<String>>("SELECT report_md FROM jobs WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await?,
    )
}

pub async fn fetch_report_json(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<serde_json::Value>, ApiError> {
    Ok(sqlx::query_scalar::<_, Option<serde_json::Value>>(
        "SELECT report_json FROM jobs WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_unique_and_hashable() {
        let a = new_token();
        let b = new_token();
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
        assert_eq!(hash_token(&a), hash_token(&a));
        assert_ne!(hash_token(&a), hash_token(&b));
    }

    #[test]
    fn token_comparison_rejects_wrong_token() {
        let token = new_token();
        let hash = hash_token(&token);
        assert!(tokens_match(&token, &hash));
        assert!(!tokens_match(&new_token(), &hash));
    }
}
