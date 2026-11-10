//! Types shared by the API and the worker.
//!
//! The worker and API are separate binaries but they agree on the job record,
//! the sandbox result contract, and the shape of a failing case. Keeping those
//! in one crate means a change to the contract breaks the build instead of
//! silently producing an empty report.

use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

pub mod queue;

/// A claimed job. This is deliberately a narrow projection of the `jobs` row:
/// the worker has no business reading the customer's contact email or token.
#[derive(Debug, Clone, FromRow)]
pub struct Job {
    pub id: Uuid,
    pub bundle_path: String,
    pub bundle_sha256: String,
    pub invariant_spec: String,
    pub attempts: i32,
}

/// One failing case.
///
/// `reproducer` is the serialized input as text. Keeping it as text (rather
/// than a typed struct) is intentional: the fuzz harness, not this service,
/// owns the input format. The minimizer works on the text and the report
/// prints it verbatim.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Failure {
    pub invariant: String,
    pub reproducer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// True only when a smaller input was re-run and still violated the
    /// invariant. Never set this to true just because a shrink pass ran.
    #[serde(default)]
    pub minimized: bool,
}

/// The JSON contract between the sandbox image and the worker.
///
/// The sandbox writes this file to `/out/result.json`. The exact Trident
/// invocation is version-specific and lives in `sandbox/bin/fuzzforge-run`;
/// this struct is the version-agnostic seam.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxResult {
    #[serde(default)]
    pub executions: u64,
    #[serde(default)]
    pub trident_version: Option<String>,
    #[serde(default)]
    pub failures: Vec<Failure>,
    /// Short tail of the fuzz log, included in the dry report for context.
    #[serde(default)]
    pub log_tail: Option<String>,
}

/// What the worker hands to the report builder.
#[derive(Debug, Clone, Default)]
pub struct Summary {
    pub executions: u64,
    pub failures: Vec<Failure>,
    pub trident_version: Option<String>,
    pub log_tail: Option<String>,
}
