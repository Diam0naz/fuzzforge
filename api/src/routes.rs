use std::sync::Arc;

use axum::extract::multipart::Field;
use axum::extract::{DefaultBodyLimit, Multipart, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use uuid::Uuid;

use crate::auth;
use crate::config::Config;
use crate::error::ApiError;
use crate::storage::Storage;

const MAX_INVARIANT_SPEC_BYTES: usize = 8_000;
const MAX_EMAIL_BYTES: usize = 320;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub storage: Storage,
    pub config: Arc<Config>,
}

pub fn router(state: AppState, config: &Config) -> anyhow::Result<Router> {
    let mut cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);

    if !config.cors_origins.is_empty() {
        let mut origins = Vec::with_capacity(config.cors_origins.len());
        for origin in &config.cors_origins {
            origins.push(
                origin
                    .parse::<HeaderValue>()
                    .map_err(|e| anyhow::anyhow!("invalid CORS origin {origin}: {e}"))?,
            );
        }
        cors = cors.allow_origin(AllowOrigin::list(origins));
    }

    Ok(Router::new()
        .route("/healthz", get(health))
        .route("/jobs", post(submit))
        .route("/jobs/{id}", get(get_job))
        .route("/jobs/{id}/report", get(get_report))
        .route("/jobs/{id}/report.json", get(get_report_json))
        .layer(DefaultBodyLimit::max(
            config.max_upload_bytes.saturating_add(1024 * 1024),
        ))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state))
}

async fn health(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Debug, Default, Deserialize)]
struct TokenQuery {
    #[serde(default)]
    token: Option<String>,
}

#[derive(Debug, Serialize)]
struct SubmitResponse {
    id: Uuid,
    token: String,
    status: &'static str,
    /// Surfaced by the frontend. This prototype starts compute immediately;
    /// a real deployment should gate this on payment or manual approval.
    notice: &'static str,
}

async fn submit(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<SubmitResponse>), ApiError> {
    let mut bundle = None;
    let mut invariant_spec = String::new();
    let mut email: Option<String> = None;

    while let Some(field) = multipart.next_field().await? {
        let name = field.name().unwrap_or_default().to_string();

        match name.as_str() {
            "bundle" => {
                if bundle.is_some() {
                    return Err(ApiError::bad_request("only one bundle may be submitted"));
                }
                bundle = Some(
                    state
                        .storage
                        .store_bundle(
                            field,
                            state.config.max_upload_bytes,
                            state.config.max_unpacked_bytes,
                        )
                        .await?,
                );
            }
            "invariant_spec" => {
                invariant_spec =
                    read_text(field, MAX_INVARIANT_SPEC_BYTES, "invariant_spec").await?;
            }
            "email" => {
                let value = read_text(field, MAX_EMAIL_BYTES, "email").await?;
                let value = value.trim().to_string();
                if !value.is_empty() {
                    if !value.contains('@') {
                        return Err(ApiError::bad_request("email is not a valid address"));
                    }
                    email = Some(value);
                }
            }
            _ => drain(field).await?,
        }
    }

    let Some(bundle) = bundle else {
        return Err(ApiError::bad_request("missing multipart field `bundle`"));
    };

    let invariant_spec = invariant_spec.trim().to_string();
    let invariant_spec = if invariant_spec.is_empty() {
        "No invariant specification was provided. Every Trident failure is reported.".to_string()
    } else {
        invariant_spec
    };

    let id = Uuid::new_v4();
    let token = auth::new_token();
    let token_hash = auth::hash_token(&token);

    sqlx::query(
        r#"
        INSERT INTO jobs (
            id, status, token_hash, bundle_path, bundle_sha256, bundle_bytes,
            invariant_spec, contact_email
        )
        VALUES ($1, 'queued', $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(id)
    .bind(&token_hash)
    .bind(bundle.path.to_string_lossy().to_string())
    .bind(&bundle.sha256)
    .bind(bundle.bytes as i64)
    .bind(&invariant_spec)
    .bind(&email)
    .execute(&state.pool)
    .await?;

    tracing::info!(
        %id,
        bundle_sha256 = %bundle.sha256,
        bundle_bytes = bundle.bytes,
        files = bundle.info.files,
        unpacked_bytes = bundle.info.unpacked_bytes,
        bundle_format = ?bundle.format,
        has_trident_tests = bundle.info.has_trident_tests,
        "job queued"
    );

    Ok((
        StatusCode::CREATED,
        Json(SubmitResponse {
            id,
            token,
            status: "queued",
            notice: "Prototype: compute starts immediately. Keep this link; it is the only way to read the job.",
        }),
    ))
}

#[derive(Debug, Serialize)]
struct JobStatusResponse {
    id: Uuid,
    status: String,
    bundle_sha256: String,
    invariant_spec: String,
    executions: Option<i64>,
    failure_count: Option<i32>,
    error: Option<String>,
    created_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
    report_available: bool,
}

async fn get_job(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Query(query): Query<TokenQuery>,
) -> Result<Json<JobStatusResponse>, ApiError> {
    let token = auth::token_from(&headers, query.token.as_deref());
    let job = auth::fetch_authorized(&state.pool, id, token.as_deref()).await?;

    let report_available = job.status == "done" && job.report_available;

    Ok(Json(JobStatusResponse {
        id: job.id,
        status: job.status,
        bundle_sha256: job.bundle_sha256,
        invariant_spec: job.invariant_spec,
        executions: job.executions,
        failure_count: job.failure_count,
        error: job.error,
        created_at: job.created_at,
        started_at: job.started_at,
        finished_at: job.finished_at,
        report_available,
    }))
}

async fn get_report(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Query(query): Query<TokenQuery>,
) -> Result<Response, ApiError> {
    let token = auth::token_from(&headers, query.token.as_deref());
    let job = auth::fetch_authorized(&state.pool, id, token.as_deref()).await?;

    if job.status != "done" {
        return Err(ApiError::conflict("report is not ready yet"));
    }
    let Some(markdown) = auth::fetch_report_markdown(&state.pool, job.id).await? else {
        return Err(ApiError::not_found("report is missing"));
    };

    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/markdown; charset=utf-8"),
    );
    response_headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"fuzzforge-{}.md\"", job.id))
            .map_err(ApiError::internal)?,
    );
    response_headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response_headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );

    Ok((response_headers, markdown).into_response())
}

async fn get_report_json(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Query(query): Query<TokenQuery>,
) -> Result<Response, ApiError> {
    let token = auth::token_from(&headers, query.token.as_deref());
    let job = auth::fetch_authorized(&state.pool, id, token.as_deref()).await?;

    if job.status != "done" {
        return Err(ApiError::conflict("report is not ready yet"));
    }
    let Some(report) = auth::fetch_report_json(&state.pool, job.id).await? else {
        return Err(ApiError::not_found("report is missing"));
    };

    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    response_headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!(
            "attachment; filename=\"fuzzforge-{}.json\"",
            job.id
        ))
        .map_err(ApiError::internal)?,
    );
    response_headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response_headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );

    Ok((response_headers, Json(report)).into_response())
}

async fn read_text(mut field: Field<'_>, max_bytes: usize, name: &str) -> Result<String, ApiError> {
    let mut buffer = Vec::new();
    while let Some(chunk) = field.chunk().await? {
        if buffer.len().saturating_add(chunk.len()) > max_bytes {
            return Err(ApiError::bad_request(format!(
                "{name} exceeds the {max_bytes} byte limit"
            )));
        }
        buffer.extend_from_slice(&chunk);
    }
    String::from_utf8(buffer)
        .map_err(|_| ApiError::bad_request(format!("{name} must be valid UTF-8")))
}

async fn drain(mut field: Field<'_>) -> Result<(), ApiError> {
    while field.chunk().await?.is_some() {}
    Ok(())
}
