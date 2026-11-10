use std::collections::HashSet;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fuzzforge_common::Failure;

/// A check that answers one question: does this candidate still violate the
/// invariant? The real implementation re-runs the sandbox; tests use a fake.
#[async_trait]
pub trait Reproducer: Send + Sync {
    async fn reproduces(&self, invariant: &str, candidate: &str) -> bool;
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_trials: usize,
    pub max_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct ShrinkOutcome {
    pub failures: Vec<Failure>,
    pub trials: usize,
    /// How many times a strictly smaller candidate reproduced. Zero is a
    /// legitimate result and must not be reported as "minimized".
    pub improved: usize,
}

/// Delta-debug each failing input, keeping only candidates that still
/// reproduce in the sandbox.
///
/// Every candidate is a real re-run, so this is bounded by both a trial count
/// and a wall-clock budget. It never claims a case was minimized unless a
/// smaller input was actually observed to fail.
pub async fn shrink(
    failures: &[Failure],
    checker: &dyn Reproducer,
    limits: Limits,
) -> ShrinkOutcome {
    let started = Instant::now();
    let deadline = Duration::from_secs(limits.max_seconds);
    let mut trials = 0usize;
    let mut improved = 0usize;
    let mut result = Vec::with_capacity(failures.len());

    for failure in failures {
        let mut best = failure.clone();
        best.minimized = false;

        // A Trident 0.12 case is an iteration seed, not an editable input.
        // Shrinking the seed would just run a different iteration, so report
        // it as-is instead of pretending it was minimized.
        if !best.reproducer.is_empty() && !is_seed_reproducer(&best.reproducer) {
            loop {
                if trials >= limits.max_trials || started.elapsed() >= deadline {
                    break;
                }

                let mut changed = false;
                for candidate in candidates(&best.reproducer) {
                    if candidate.len() >= best.reproducer.len() {
                        continue;
                    }
                    if trials >= limits.max_trials || started.elapsed() >= deadline {
                        break;
                    }

                    trials += 1;
                    if checker.reproduces(&best.invariant, &candidate).await {
                        best.reproducer = candidate;
                        best.minimized = true;
                        improved += 1;
                        changed = true;
                        // Restart from the smaller input so every pass uses
                        // the current best, not the original.
                        break;
                    }
                }

                if !changed {
                    break;
                }
            }
        }

        result.push(best);
    }

    ShrinkOutcome {
        failures: result,
        trials,
        improved,
    }
}

const MAX_CANDIDATES: usize = 256;

/// True when the reproducer is `{"test": ..., "seed": "<64 hex>"}`.
///
/// Trident 0.12 identifies a failure by its 32-byte iteration seed. That seed
/// is the whole case: there are no bytes to delete or values to zero, and any
/// edit changes which iteration runs. Delta debugging is meaningless here.
pub fn is_seed_reproducer(input: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(input) else {
        return false;
    };
    let Some(seed) = value.get("seed").and_then(|seed| seed.as_str()) else {
        return false;
    };
    seed.len() == 64 && seed.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Produce smaller candidate inputs.
///
/// JSON gets structural edits (drop keys, drop array elements, truncate
/// strings, zero numbers). Anything else gets line-based deletion. The
/// harness owns the input format, so this is intentionally format-tolerant
/// rather than schema-aware.
pub fn candidates(input: &str) -> Vec<String> {
    let mut rendered = Vec::new();

    if let Ok(value) = serde_json::from_str::<serde_json::Value>(input) {
        let mut values = Vec::new();
        walk_json(&value, &mut values, 0);

        let mut seen = HashSet::new();
        for value in values {
            if let Ok(text) = serde_json::to_string(&value) {
                if text != input && seen.insert(text.clone()) {
                    rendered.push(text);
                }
            }
        }
    }

    if rendered.is_empty() {
        rendered = line_candidates(input);
    }

    rendered.truncate(MAX_CANDIDATES);
    rendered
}

fn walk_json(value: &serde_json::Value, out: &mut Vec<serde_json::Value>, depth: usize) {
    use serde_json::Value;
    if depth > 32 || out.len() >= MAX_CANDIDATES {
        return;
    }

    match value {
        Value::Object(map) => {
            for key in map.keys().take(64) {
                let mut clone = value.clone();
                if let Value::Object(object) = &mut clone {
                    object.remove(key);
                }
                out.push(clone);
                if out.len() >= MAX_CANDIDATES {
                    return;
                }
            }
            // For each child edit, splice it into a clone of the parent so the
            // candidate keeps the object shape. A bare `0` is not a useful
            // reproducer when the harness expects `{"amount": 0}`.
            for (key, child) in map.iter().take(64) {
                let mut edits = Vec::new();
                walk_json(child, &mut edits, depth + 1);
                for edit in edits {
                    let mut clone = value.clone();
                    if let Value::Object(object) = &mut clone {
                        object.insert(key.clone(), edit);
                    }
                    out.push(clone);
                    if out.len() >= MAX_CANDIDATES {
                        return;
                    }
                }
            }
        }
        Value::Array(items) => {
            for index in 0..items.len().min(64) {
                let mut clone = items.clone();
                clone.remove(index);
                out.push(Value::Array(clone));
                if out.len() >= MAX_CANDIDATES {
                    return;
                }
            }
            if items.len() > 2 {
                out.push(Value::Array(items[..items.len() / 2].to_vec()));
                out.push(Value::Array(items[items.len() / 2..].to_vec()));
            }
            for (index, child) in items.iter().take(64).enumerate() {
                let mut edits = Vec::new();
                walk_json(child, &mut edits, depth + 1);
                for edit in edits {
                    let mut clone = items.clone();
                    clone[index] = edit;
                    out.push(Value::Array(clone));
                    if out.len() >= MAX_CANDIDATES {
                        return;
                    }
                }
            }
        }
        Value::String(text) if !text.is_empty() => {
            out.push(Value::String(String::new()));
            let count = text.chars().count();
            if count > 8 {
                out.push(Value::String(
                    text.chars().take(count / 2).collect::<String>(),
                ));
            }
        }
        Value::Number(number) => {
            if number.as_f64().map(|value| value != 0.0).unwrap_or(false) {
                out.push(Value::from(0));
            }
        }
        Value::Bool(true) => out.push(Value::Bool(false)),
        _ => {}
    }
}

fn line_candidates(input: &str) -> Vec<String> {
    let lines: Vec<&str> = input.lines().collect();
    if lines.len() < 2 {
        return Vec::new();
    }

    let mut out = Vec::new();

    // Single-line deletion first: smallest useful edit.
    for remove in 0..lines.len().min(128) {
        let kept: Vec<&str> = lines
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != remove)
            .map(|(_, line)| *line)
            .collect();
        out.push(kept.join("\n"));
    }

    // Then larger chunks, which converge faster on long traces.
    for chunk in [4usize, 16, 64] {
        if lines.len() <= chunk {
            continue;
        }
        for start in (0..lines.len()).step_by(chunk) {
            if out.len() >= MAX_CANDIDATES {
                return out;
            }
            let end = (start + chunk).min(lines.len());
            let kept: Vec<&str> = lines
                .iter()
                .enumerate()
                .filter(|(index, _)| *index < start || *index >= end)
                .map(|(_, line)| *line)
                .collect();
            out.push(kept.join("\n"));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Contains(&'static str);

    #[async_trait]
    impl Reproducer for Contains {
        async fn reproduces(&self, _invariant: &str, candidate: &str) -> bool {
            candidate.contains(self.0)
        }
    }

    #[test]
    fn json_candidates_remove_fields_and_shrink_values() {
        let input = r#"{"amount":1000000,"recipient":"abcdefghijklmnop","ok":true}"#;
        let all = candidates(input);
        assert!(all.iter().any(|c| c == r#"{"amount":1000000,"ok":true}"#));
        assert!(all.iter().any(|c| c.contains(r#""amount":0"#)));
        assert!(all.iter().any(|c| c.contains(r#""ok":false"#)));
    }

    #[tokio::test]
    async fn shrink_keeps_only_smaller_reproducing_inputs() {
        let failure = Failure {
            invariant: "balance must stay non-negative".into(),
            reproducer: r#"{"keep":"x","drop1":1,"drop2":2}"#.into(),
            note: None,
            minimized: false,
        };
        let outcome = shrink(
            &[failure],
            &Contains(r#""keep":"x""#),
            Limits {
                max_trials: 100,
                max_seconds: 10,
            },
        )
        .await;

        assert_eq!(outcome.failures.len(), 1);
        assert!(outcome.failures[0].minimized);
        assert_eq!(outcome.failures[0].reproducer, r#"{"keep":"x"}"#);
        assert!(outcome.trials > 0);
    }

    #[tokio::test]
    async fn no_reproduction_means_not_minimized() {
        let failure = Failure {
            invariant: "x".into(),
            reproducer: r#"{"a":1,"b":2}"#.into(),
            note: None,
            minimized: false,
        };
        let outcome = shrink(
            &[failure],
            &Contains("never-present"),
            Limits {
                max_trials: 10,
                max_seconds: 5,
            },
        )
        .await;

        assert!(!outcome.failures[0].minimized);
        assert_eq!(outcome.improved, 0);
    }

    #[test]
    fn non_json_input_falls_back_to_lines() {
        let input = "line one\nline two\nline three";
        let all = candidates(input);
        assert!(all.iter().any(|c| c == "line one\nline three"));
    }

    #[test]
    fn seed_reproducers_are_recognized_and_not_shrunk() {
        let seed = "a".repeat(64);
        let input = serde_json::json!({ "test": "fuzz_0", "seed": seed }).to_string();
        assert!(is_seed_reproducer(&input));
        assert!(!is_seed_reproducer(r#"{"test":"fuzz_0","seed":"abc"}"#));
        assert!(!is_seed_reproducer("plain text"));
    }

    #[tokio::test]
    async fn seed_reproducers_are_never_claimed_as_minimized() {
        let seed = "b".repeat(64);
        let failure = Failure {
            invariant: "assertion failed".into(),
            reproducer: serde_json::json!({ "test": "fuzz_0", "seed": seed }).to_string(),
            note: None,
            minimized: false,
        };
        let outcome = shrink(
            std::slice::from_ref(&failure),
            &Contains("anything"),
            Limits {
                max_trials: 100,
                max_seconds: 5,
            },
        )
        .await;

        assert_eq!(outcome.trials, 0);
        assert_eq!(outcome.improved, 0);
        assert!(!outcome.failures[0].minimized);
        assert_eq!(outcome.failures[0].reproducer, failure.reproducer);
    }

    #[test]
    fn candidate_generation_is_bounded() {
        let input = serde_json::json!({
            "items": (0..2_000).collect::<Vec<_>>(),
        })
        .to_string();
        let all = candidates(&input);
        assert!(!all.is_empty());
        assert!(all.len() <= MAX_CANDIDATES);
    }
}
