//! `--status`: one `project.ops.status/v1` document for the estate
//! collector's `project-ops-status` kind, read from the state directory
//! without the lock and without opening anything for writing: it reads
//! `last-pass.json`, lists `journal.sealed.*` and stats `journal.jsonl`.
//!
//! It answers whether the consumer has recently and successfully checked for
//! work (not whether there was work), and whether sealed journal generations
//! still have headroom before operator custody is due.

use std::path::Path;

use serde_json::{Value, json};

use crate::store::{
    LastPass, MAX_JOURNAL_BYTES, MAX_SEALED_JOURNALS, live_journal_bytes, read_last_pass,
    sealed_journal_count, stamp,
};

pub const STATUS_SCHEMA: &str = "project.ops.status/v1";
pub const PROJECT: &str = "constellation-remediation-consumer";
/// A pass older than this is not fresh (the timer polls 10 s after a pass).
pub const PASS_FRESH_SECONDS: u64 = 120;
/// Operator custody is due once this many sealed segments are present.
pub const CUSTODY_DUE_SEGMENTS: usize = 12;
/// Critical once this many are present; the consumer refuses at
/// [`MAX_SEALED_JOURNALS`].
pub const CRITICAL_SEGMENTS: usize = 15;
/// A last pass stamped further than this in the future is not trusted.
const FUTURE_SKEW_MS: u64 = 5_000;

struct Observed {
    state: &'static str,
    reason: String,
    observed_at: String,
    facts: Value,
}

fn concern(id: &str, slug: &str, description: &str, observed: Observed) -> Value {
    json!({
        "id": id,
        "question": format!("remediation.consumer.question.{slug}/v1"),
        "profile": format!("remediation.consumer.profile.{slug}/v1"),
        "required": true,
        "description": description,
        "observation": {
            "observation_present": true,
            "local_state": observed.state,
            "domain_state": null,
            "observed_at": observed.observed_at,
            "valid_for_seconds": PASS_FRESH_SECONDS,
            "reason": observed.reason,
            "facts": observed.facts,
        },
    })
}

fn pass_fresh(last: &Result<LastPass, String>, now_ms: u64, generated: &str) -> Observed {
    let (state, reason, facts) = match last {
        Err(error) => (
            "ABSENT",
            format!("no readable last pass: {error}"),
            json!({}),
        ),
        Ok(last) if last.at_unix_ms > now_ms.saturating_add(FUTURE_SKEW_MS) => (
            "ABSENT",
            format!("last pass at {} is in the future", last.at),
            json!({"last_pass_at": last.at}),
        ),
        Ok(last) => {
            let age = now_ms.saturating_sub(last.at_unix_ms) / 1000;
            let fresh = age <= PASS_FRESH_SECONDS;
            (
                if fresh { "PRESENT" } else { "ABSENT" },
                format!(
                    "last pass {age} s ago ({}); fresh within {PASS_FRESH_SECONDS} s",
                    last.result
                ),
                json!({"last_pass_at": last.at, "age_seconds": age}),
            )
        }
    };
    Observed {
        state,
        reason,
        observed_at: generated.to_owned(),
        facts,
    }
}

fn pass_succeeding(last: &Result<LastPass, String>, generated: &str) -> Observed {
    match last {
        Err(error) => Observed {
            state: "ABSENT",
            reason: format!("no readable last pass: {error}"),
            observed_at: generated.to_owned(),
            facts: json!({}),
        },
        Ok(last) => {
            let judged = last.result != "fault";
            Observed {
                state: if judged { "PRESENT" } else { "ABSENT" },
                reason: if judged {
                    format!("last pass judged: {}", last.result)
                } else {
                    format!(
                        "last pass failed on its own state: {}",
                        last.error.as_deref().unwrap_or("no error recorded")
                    )
                },
                observed_at: last.at.clone(),
                facts: json!({
                    "result": last.result,
                    "abstain_reason": last.abstain_reason,
                    "idle": last.idle,
                }),
            }
        }
    }
}

fn generations(sealed: Option<usize>, bound: usize, generated: &str) -> Observed {
    let facts = json!({
        "sealed_segments": sealed,
        "threshold": bound,
        "max_sealed_journals": MAX_SEALED_JOURNALS,
    });
    let (state, reason) = match sealed {
        None => ("UNKNOWN", "state directory unreadable".to_owned()),
        Some(count) if count < bound => (
            "PRESENT",
            format!("{count} sealed segments present, below {bound}"),
        ),
        Some(count) => (
            "ABSENT",
            format!(
                "{count} sealed segments present (threshold {bound}, refusal at {MAX_SEALED_JOURNALS}); operator custody due"
            ),
        ),
    };
    Observed {
        state,
        reason,
        observed_at: generated.to_owned(),
        facts,
    }
}

/// The status document for the consumer state directory `dir` at `now_ms`.
#[must_use]
pub fn document(dir: &Path, now_ms: u64, version: &str) -> Value {
    let generated = stamp(now_ms);
    let last = read_last_pass(dir);
    let sealed = sealed_journal_count(dir);
    let journal_bytes = live_journal_bytes(dir);
    let concerns = vec![
        concern(
            "remediation.consumer.pass-fresh",
            "pass-fresh",
            "The consumer completed a pass that held its lock within the last 120 seconds.",
            pass_fresh(&last, now_ms, &generated),
        ),
        concern(
            "remediation.consumer.pass-succeeding",
            "pass-succeeding",
            "The consumer's last pass reached a judged result rather than failing on its own state.",
            pass_succeeding(&last, &generated),
        ),
        concern(
            "remediation.journal.generations-headroom",
            "generations-headroom",
            "Fewer than 12 sealed journal segments are present; at 12 operator custody is due.",
            generations(sealed, CUSTODY_DUE_SEGMENTS, &generated),
        ),
        concern(
            "remediation.journal.generations-critical",
            "generations-critical",
            "Fewer than 15 sealed journal segments are present; the consumer refuses at 16.",
            generations(sealed, CRITICAL_SEGMENTS, &generated),
        ),
    ];
    let last_pass = last.as_ref().ok();
    json!({
        "schema": STATUS_SCHEMA,
        "project": PROJECT,
        "generated_at": generated,
        "manifest": {"schema": "project.concerns/v1", "path": ".ops/concerns.toml"},
        "producer": {"id": format!("{PROJECT}.status"), "version": version},
        "authority": {"read_only": true, "lock_taken": false},
        "extensions": {
            "constellation.remediation-consumer": {
                "state_dir": dir,
                "last_pass_error": last.as_ref().err(),
                "last_pass_at": last_pass.map(|l| &l.at),
                "last_result": last_pass.map(|l| &l.result),
                "idle": last_pass.map(|l| l.idle),
                "consecutive_idle_passes": last_pass.map(|l| l.consecutive_idle_passes),
                "idle_since": last_pass.and_then(|l| l.idle_since.as_ref()),
                "sealed_segments": sealed,
                "journal_bytes": journal_bytes,
                "journal_max_bytes": MAX_JOURNAL_BYTES,
                "max_sealed_journals": MAX_SEALED_JOURNALS,
                "custody_due_segments": CUSTODY_DUE_SEGMENTS,
                "critical_segments": CRITICAL_SEGMENTS,
                "pass_fresh_seconds": PASS_FRESH_SECONDS,
            },
        },
        "concerns": concerns,
    })
}
