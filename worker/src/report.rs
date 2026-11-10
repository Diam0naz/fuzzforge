use std::fmt::Write as _;

use anyhow::{bail, Result};
use chrono::{DateTime, SecondsFormat, Utc};
use fuzzforge_common::Job;
use sqlx::PgPool;

use crate::runner::RunOutcome;

pub async fn write(pool: &PgPool, job: &Job, outcome: &RunOutcome, worker_id: &str) -> Result<()> {
    let generated = Utc::now();
    let failure_count = outcome.summary.failures.len() as i32;
    let markdown = render_markdown(job, outcome, worker_id, generated);

    let report_json = serde_json::json!({
        "schema": "fuzzforge/report/v1",
        "generated_at": generated.to_rfc3339_opts(SecondsFormat::Secs, true),
        "worker_id": worker_id,
        "job": {
            "id": job.id,
            "attempt": job.attempts,
            "bundle_sha256": job.bundle_sha256,
            "invariant_spec": job.invariant_spec,
        },
        "sandbox": {
            "image_requested": outcome.image.requested,
            "image_resolved": outcome.image.resolved,
            "pinned": outcome.image.pinned,
            "trident_version": outcome.summary.trident_version,
            "memory": outcome.profile.memory,
            "cpus": outcome.profile.cpus,
            "pids_limit": outcome.profile.pids,
            "work_tmpfs": outcome.profile.work_size,
            "network": "none",
            "read_only_rootfs": true,
            "capabilities": "none",
        },
        "summary": {
            "executions": outcome.summary.executions,
            "failures": failure_count,
            "minimization": {
                "enabled": outcome.minimize.enabled,
                "trials": outcome.minimize.trials,
                "improvements": outcome.minimize.improved,
            },
        },
        "reproduction": {
            "whole_run_command": outcome.profile.run_command(),
            "single_case_command": outcome.profile.case_command(),
            "case_exit_code": 42,
        },
        "failures": outcome.summary.failures,
        "log_tail": outcome.summary.log_tail,
    });

    let result = sqlx::query(
        r#"
        UPDATE jobs
        SET status = 'done',
            executions = $2,
            failure_count = $3,
            report_md = $4,
            report_json = $5,
            error = NULL,
            finished_at = now()
        WHERE id = $1 AND status = 'running'
        "#,
    )
    .bind(job.id)
    .bind(outcome.summary.executions as i64)
    .bind(failure_count)
    .bind(markdown)
    .bind(report_json)
    .execute(pool)
    .await?;

    if result.rows_affected() == 0 {
        bail!("job {} is no longer in the running state", job.id);
    }

    Ok(())
}

pub async fn fail(pool: &PgPool, job: &Job, error: &str, worker_id: &str) -> Result<()> {
    let message: String = error.chars().take(4_000).collect();
    tracing::warn!(job_id = %job.id, worker_id, error = %message, "marking job failed");

    let _ = worker_id;
    let result = sqlx::query(
        r#"
        UPDATE jobs
        SET status = 'failed',
            error = $2,
            finished_at = now()
        WHERE id = $1 AND status = 'running'
        "#,
    )
    .bind(job.id)
    .bind(message)
    .execute(pool)
    .await?;

    if result.rows_affected() == 0 {
        tracing::warn!(job_id = %job.id, "failed job was no longer running; not overwriting");
    }

    Ok(())
}

fn render_markdown(
    job: &Job,
    outcome: &RunOutcome,
    worker_id: &str,
    generated: DateTime<Utc>,
) -> String {
    let mut md = String::new();
    let failures = &outcome.summary.failures;

    let _ = writeln!(md, "# Fuzzforge report\n");
    let _ = writeln!(md, "- **Job:** `{}`", job.id);
    let _ = writeln!(md, "- **Bundle SHA-256:** `{}`", job.bundle_sha256);
    let _ = writeln!(
        md,
        "- **Sandbox image:** `{}` (requested `{}`, {})",
        outcome.image.resolved,
        outcome.image.requested,
        if outcome.image.pinned {
            "pinned"
        } else {
            "local image ID, NOT pinned"
        }
    );
    let _ = writeln!(
        md,
        "- **Trident:** {}",
        outcome
            .summary
            .trident_version
            .as_deref()
            .unwrap_or("unknown (see sandbox log)")
    );
    let _ = writeln!(md, "- **Worker:** `{worker_id}`");
    let _ = writeln!(
        md,
        "- **Generated:** {}",
        generated.to_rfc3339_opts(SecondsFormat::Secs, true)
    );
    let _ = writeln!(md, "- **Attempt:** {}", job.attempts);
    let _ = writeln!(md);

    let _ = writeln!(md, "## Summary\n");
    let _ = writeln!(md, "| Metric | Value |");
    let _ = writeln!(md, "| --- | --- |");
    let _ = writeln!(md, "| Executions | {} |", outcome.summary.executions);
    let _ = writeln!(md, "| Failing cases | {} |", failures.len());
    let _ = writeln!(
        md,
        "| Minimization | {} |",
        if outcome.minimize.enabled {
            format!(
                "enabled ({} trials, {} improvements)",
                outcome.minimize.trials, outcome.minimize.improved
            )
        } else {
            "disabled".to_string()
        }
    );
    let _ = writeln!(md);

    let _ = writeln!(md, "## Reproducibility contract\n");
    if outcome.image.pinned {
        let _ = writeln!(
            md,
            "Every failing case below was produced by the sandbox image recorded above, \
             pinned by digest. The commands in **Reproduce** use only the bundle you \
             uploaded and that image — no Fuzzforge infrastructure.\n"
        );
        let _ = writeln!(
            md,
            "If a case does not reproduce, this report is void: reply to the engagement \
             thread and we will re-run it at our cost. Pinning by digest is why the \
             command is trustworthy; a tag would not be.\n"
        );
    } else {
        let _ = writeln!(
            md,
            "**This run used an unpinned local image (`ALLOW_UNPINNED_IMAGE=1`).** \
             The commands below are a development aid, not the reproducibility \
             contract. Before a report is delivered to a customer, re-run it with \
             `SANDBOX_IMAGE` set to `image@sha256:…`.\n"
        );
    }
    let _ = writeln!(
        md,
        "**This is not a proof of safety.** Fuzzing explores the paths the \
         submitted harness reaches. It does not prove the absence of bugs, and it \
         is not a substitute for a manual audit.\n"
    );

    let _ = writeln!(md, "## Invariant specification (as submitted)\n");
    for line in job.invariant_spec.lines() {
        let _ = writeln!(md, "> {line}");
    }
    let _ = writeln!(md);

    let _ = writeln!(md, "## Failing cases\n");
    if failures.is_empty() {
        let _ = writeln!(
            md,
            "The harness reported no failing cases in this run. That means this \
             campaign did not find a violation; it does not mean the program is safe.\n"
        );
    } else {
        for (index, failure) in failures.iter().enumerate() {
            let _ = writeln!(
                md,
                "### {}. {}\n",
                index + 1,
                one_line(&failure.invariant, 200)
            );
            let _ = writeln!(
                md,
                "- **Minimized:** {}",
                if failure.minimized { "yes" } else { "no" }
            );
            if let Some(note) = &failure.note {
                let _ = writeln!(md, "- **Note:** {}", one_line(note, 500));
            }
            let _ = writeln!(md);

            let fence = fence_for(&failure.reproducer);
            let language = if serde_json::from_str::<serde_json::Value>(&failure.reproducer).is_ok()
            {
                "json"
            } else {
                "text"
            };
            let _ = writeln!(md, "**Raw reproducer**\n");
            let _ = writeln!(md, "{fence}{language}\n{}\n{fence}\n", failure.reproducer);

            // `fuzzforge-reproduce` reads {invariant, reproducer}; print a
            // ready-to-save wrapper so the single-case command is actually
            // usable without guessing the format.
            let case_json = serde_json::json!({
                "invariant": failure.invariant,
                "reproducer": failure.reproducer,
            });
            let pretty = serde_json::to_string_pretty(&case_json).unwrap_or_default();
            let fence = fence_for(&pretty);
            let _ = writeln!(
                md,
                "<details><summary><code>case.json</code> for single-case replay</summary>\n"
            );
            let _ = writeln!(md, "{fence}json\n{pretty}\n{fence}\n</details>\n");
        }
    }

    let _ = writeln!(md, "## Reproduce the whole run\n");
    let _ = writeln!(
        md,
        "Save your bundle as a directory (the one containing `Anchor.toml`) and run:\n"
    );
    let fence = fence_for(&outcome.profile.run_command());
    let _ = writeln!(
        md,
        "{fence}sh\n{}\n{fence}\n",
        outcome.profile.run_command()
    );
    if outcome.image.pinned {
        let _ = writeln!(
            md,
            "The result is written to `fuzzforge-out/result.json`. Requires Docker and \
             the pinned image above; it will pull the image by digest if needed.\n"
        );
    } else {
        let _ = writeln!(
            md,
            "The result is written to `fuzzforge-out/result.json`. This command uses a \
             local image ID, not a digest, so it only works on the machine that built \
             the image.\n"
        );
    }

    if !failures.is_empty() {
        let _ = writeln!(md, "## Reproduce a single case\n");
        let _ = writeln!(
            md,
            "Save the `case.json` block from any failing case above as \
             `fuzzforge-out/case.json`, then run:\n"
        );
        let fence = fence_for(&outcome.profile.case_command());
        let _ = writeln!(
            md,
            "{fence}sh\n{}\n{fence}\n",
            outcome.profile.case_command()
        );
        let _ = writeln!(
            md,
            "Exit code **42** means the invariant still fails. Exit code **0** means \
             it does not, and the report is void.\n"
        );
        let _ = writeln!(
            md,
            "The raw reproducer is the failing input itself; `case.json` wraps it \
             with the invariant so the replay script can check the right property.\n"
        );
    }

    if let Some(tail) = &outcome.summary.log_tail {
        if !tail.trim().is_empty() {
            let _ = writeln!(md, "<details><summary>Sandbox log tail</summary>\n");
            let fence = fence_for(tail);
            let _ = writeln!(md, "{fence}text\n{}\n{fence}\n", tail.trim_end());
            let _ = writeln!(md, "</details>\n");
        }
    }

    md
}

fn one_line(text: &str, max: usize) -> String {
    let flattened = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flattened.chars().count() > max {
        format!("{}…", flattened.chars().take(max).collect::<String>())
    } else {
        flattened
    }
}

fn fence_for(content: &str) -> String {
    if content.contains("````") {
        "`````".to_string()
    } else if content.contains("```") {
        "````".to_string()
    } else {
        "```".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::{ImageInfo, MinimizeOutcome, SandboxProfile};
    use fuzzforge_common::{Failure, Summary};

    #[test]
    fn report_contains_the_pinned_command_and_cases() {
        let job = Job {
            id: uuid::Uuid::nil(),
            bundle_path: "/data/bundles/x.tar.gz".into(),
            bundle_sha256: "abc123".into(),
            invariant_spec: "total supply is conserved".into(),
            attempts: 1,
        };
        let outcome = RunOutcome {
            summary: Summary {
                executions: 42,
                failures: vec![Failure {
                    invariant: "supply".into(),
                    reproducer: r#"{"amount":1}"#.into(),
                    note: None,
                    minimized: true,
                }],
                trident_version: Some("0.12.0".into()),
                log_tail: Some("log line".into()),
            },
            image: ImageInfo {
                requested: "fuzzforge/sandbox@sha256:deadbeef".into(),
                resolved: "fuzzforge/sandbox@sha256:deadbeef".into(),
                pinned: true,
            },
            profile: SandboxProfile {
                image: "fuzzforge/sandbox@sha256:deadbeef".into(),
                memory: "4g".into(),
                cpus: "2".into(),
                pids: 256,
                work_size: "8g".into(),
            },
            minimize: MinimizeOutcome {
                enabled: true,
                trials: 3,
                improved: 1,
            },
        };

        let markdown = render_markdown(&job, &outcome, "worker-test", Utc::now());
        assert!(markdown.contains("fuzzforge/sandbox@sha256:deadbeef"));
        assert!(markdown.contains(r#"{"amount":1}"#));
        assert!(markdown.contains("case.json"));
        assert!(markdown.contains(r#""invariant": "supply""#));
        assert!(markdown.contains("Exit code **42**"));
        assert!(markdown.contains("not a proof of safety"));
    }
}
