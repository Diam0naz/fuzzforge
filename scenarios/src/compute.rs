//! Compute-unit profile and budget-cliff check.
//!
//! A program instruction that works in every test can still be unusable in
//! production if some reachable state pushes it past the compute budget: the
//! transaction dies on the meter and, when the instruction is an exit path
//! (withdraw, close, liquidate), funds are stuck. Unit tests rarely notice,
//! because they run one cheap state.
//!
//! Harnesses call [`observe`] with the compute units of every successful
//! program instruction. This module keeps the high-water mark per
//! (build, instruction, lane) for the whole fuzzing process and reports any
//! instruction that exceeds the limit. [`exhausted`] recognises a transaction
//! that ran out of budget outright.
//!
//! Environment:
//! * `FF_CU_LIMIT`: units one instruction may use (default 200,000, what a
//!   transaction gets per instruction when the sender sets no budget).
//! * `FF_CU_OUT`: directory to write the profile to, one `cu-<pid>.tsv` per
//!   fuzzer worker. Merge with `tools/cu-profile.sh`.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Mutex, OnceLock};

/// Per-instruction budget of a transaction with no ComputeBudget instruction.
pub const DEFAULT_IX_BUDGET: u64 = 200_000;

#[derive(Default)]
struct Profile {
    /// (side, instruction, lane) -> (high-water mark, mark when last written).
    marks: BTreeMap<(String, String, String), (u64, u64)>,
}

static PROFILE: Mutex<Option<Profile>> = Mutex::new(None);

pub fn limit() -> u64 {
    static LIMIT: OnceLock<u64> = OnceLock::new();
    *LIMIT.get_or_init(|| {
        std::env::var("FF_CU_LIMIT").ok().and_then(|v| v.parse().ok()).unwrap_or(DEFAULT_IX_BUDGET)
    })
}

fn out_dir() -> Option<&'static str> {
    static DIR: OnceLock<Option<String>> = OnceLock::new();
    DIR.get_or_init(|| std::env::var("FF_CU_OUT").ok()).as_deref()
}

fn write_profile(profile: &Profile, dir: &str) {
    let _ = std::fs::create_dir_all(dir);
    let path = format!("{dir}/cu-{}.tsv", std::process::id());
    let tmp = format!("{path}.tmp");
    let Ok(mut f) = std::fs::File::create(&tmp) else { return };
    for ((side, ix, lane), (max, _)) in &profile.marks {
        let _ = writeln!(f, "{max}\t{side}\t{ix}\t{lane}");
    }
    let _ = std::fs::rename(&tmp, &path);
}

/// Record the compute units of one successful instruction. `side` names the
/// build ("candidate" or "reference"), `lane` the scenario it ran in (a pool, a
/// mint profile). Returns a violation message when `cu` exceeds [`limit`].
pub fn observe(side: &str, ix: &str, lane: &str, cu: u64) -> Option<String> {
    let mut guard = PROFILE.lock().unwrap_or_else(|e| e.into_inner());
    let profile = guard.get_or_insert_with(Profile::default);
    let key = (side.to_string(), ix.to_string(), lane.to_string());
    let (max, written) = profile.marks.entry(key).or_insert((0, 0));
    if cu > *max {
        *max = cu;
        // Rewrite the file on a new lane or a rise of at least 1%.
        if *written == 0 || cu > *written + *written / 100 {
            *written = cu;
            if let Some(dir) = out_dir() {
                write_profile(profile, dir);
            }
        }
    }
    (cu > limit()).then(|| {
        format!("[compute] {lane}: {ix} used {cu} compute units, over the {} limit", limit())
    })
}

/// True when a failed transaction's logs show it ran out of compute budget.
pub fn exhausted(logs: &[String]) -> bool {
    logs.iter().any(|l| l.contains("exceeded CUs meter") || l.contains("Computational budget exceeded"))
}

/// Current high-water marks as (units, side, instruction, lane), highest first.
pub fn high_water() -> Vec<(u64, String, String, String)> {
    let guard = PROFILE.lock().unwrap_or_else(|e| e.into_inner());
    let mut rows: Vec<_> = guard
        .iter()
        .flat_map(|p| p.marks.iter())
        .map(|((side, ix, lane), (max, _))| (*max, side.clone(), ix.clone(), lane.clone()))
        .collect();
    rows.sort_by(|a, b| b.cmp(a));
    rows
}
