//! The daily digest: one v1 notice restating every active condition and
//! every input that is not current. Triggers are notified once and an
//! accepted notice is never repeated, so without it a condition that stays
//! active for days is silent after its first message.

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::config::{Config, EffectiveRule};
use crate::inputs::{InputReport, InputStatus};
use crate::intent::{self, ATTENTION_POLICY_ID, INTENT_V1};
use crate::nq;
use crate::registry::{Class, RESEND_INTERVAL_SECONDS};
use crate::state::State;
use crate::util::{format_seconds, read_bounded, truncate, write_atomic};

const RECORD_FILE: &str = "digest.json";
const INTENT_FILE: &str = "digest-intent.json";
const SUMMARY_MAX: usize = 512;
const ANCHOR: &str = "daily-digest";

/// The newest digest attempt, beside the state file. Kept out of
/// `state.json` so an earlier build still reads its state.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Record {
    /// UTC day (`YYYY-MM-DD`) the attempt belongs to.
    pub day: String,
    pub at: i64,
    pub stable_event_id: String,
    pub outcome: String,
    pub network: bool,
    pub notification_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Record {
    fn settled(&self) -> bool {
        self.outcome == "accepted" || (self.outcome == "refused" && !self.network)
    }
}

fn day(now: i64) -> String {
    format_seconds(now - now.rem_euclid(86_400))[..10].to_owned()
}

/// Whether the day's digest is due at `now`.
#[must_use]
pub fn due(offset_seconds: i64, record: Option<&Record>, now: i64) -> bool {
    if now.rem_euclid(86_400) < offset_seconds {
        return false;
    }
    match record {
        Some(record) if record.day == day(now) => {
            !record.settled() && now - record.at >= RESEND_INTERVAL_SECONDS
        }
        _ => true,
    }
}

fn span(seconds: i64) -> String {
    let seconds = seconds.max(0);
    let (days, hours, minutes) = (
        seconds / 86_400,
        seconds % 86_400 / 3600,
        seconds % 3600 / 60,
    );
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    }
}

/// The digest text: active conditions (pages first, then oldest first) and
/// inputs that are not current, truncated to the v1 summary bound.
#[must_use]
pub fn summary(
    site: &str,
    state: &State,
    rules: &[EffectiveRule],
    inputs: &[InputReport],
    suspensions: &[crate::config::Suspension],
    now: i64,
) -> String {
    let suspended: Vec<String> = suspensions
        .iter()
        .map(|s| {
            // Short: the 512-byte summary must still reach the inputs line. The
            // reason and resume condition are in the report and on the dashboard.
            format!(
                "{}{} (owner {}, since {})",
                s.rule,
                s.target
                    .as_deref()
                    .map_or_else(String::new, |t| format!("/{t}")),
                s.owner,
                s.since
            )
        })
        .collect();
    let mut active: Vec<(bool, i64, String)> = state
        .conditions
        .values()
        .filter(|condition| {
            condition.active && !suspensions.iter().any(|s| s.covers(&condition.key))
        })
        .map(|condition| {
            let class = rules
                .iter()
                .find(|rule| rule.rule.id == condition.key.rule)
                .map_or(Class::Notice, |rule| rule.class);
            let since = condition
                .first_seen
                .or(condition.transition_at)
                .unwrap_or(now);
            let target = condition
                .key
                .target_class
                .as_deref()
                .map_or_else(String::new, |target| format!("/{target}"));
            (
                class != Class::Page,
                since,
                format!(
                    "{} {}{target} for {} ({})",
                    class.as_str(),
                    condition.key.rule,
                    span(now - since),
                    intent::incident_ref(&condition.key.id(), condition.first_seen),
                ),
            )
        })
        .collect();
    active.sort();
    let not_current: Vec<String> = inputs
        .iter()
        .filter(|input| input.status != InputStatus::Ok)
        .map(|input| format!("{} ({})", input.label, input.causes.join(", ")))
        .collect();
    let mut text = format!("DIGEST {site} {}: ", day(now));
    let metric_values: Vec<&str> = inputs
        .iter()
        .filter_map(|input| input.identity["value_code_notes"].as_array())
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if !metric_values.is_empty() {
        text.push_str("Metric values: ");
        text.push_str(&metric_values.join("; "));
        text.push_str(". ");
    }
    if active.is_empty() {
        text.push_str("no active conditions");
    } else {
        text.push_str(&format!("{} active: ", active.len()));
        text.push_str(
            &active
                .into_iter()
                .map(|(_, _, line)| line)
                .collect::<Vec<_>>()
                .join("; "),
        );
    }
    if !suspended.is_empty() {
        text.push_str(". Suspended: ");
        text.push_str(&suspended.join("; "));
    }
    let paused: Vec<String> = inputs
        .iter()
        .filter(|input| input.kind == "estate")
        .flat_map(|input| {
            input.identity["paused"]
                .as_array()
                .cloned()
                .unwrap_or_default()
        })
        .map(|service| {
            format!(
                "{} since {}",
                service["name"].as_str().unwrap_or("?"),
                service["since"].as_str().unwrap_or("?")
            )
        })
        .collect();
    if !paused.is_empty() {
        text.push_str(". Declared paused: ");
        text.push_str(&paused.join("; "));
    }
    // An input whose only fault is a rejected definition is `ok` for every
    // other one, but the rejection is never left out of the restatement.
    let rejected: Vec<String> = inputs
        .iter()
        .filter(|input| !input.rejected_rules.is_empty())
        .map(|input| format!("{} ({})", input.label, crate::engine::rejected_names(input)))
        .collect();
    if !rejected.is_empty() {
        text.push_str(". Rejected definitions: ");
        text.push_str(&rejected.join("; "));
    }
    if not_current.is_empty() {
        text.push_str(". All inputs current.");
    } else {
        text.push_str(". Inputs not current: ");
        text.push_str(&not_current.join("; "));
        text.push('.');
    }
    if text.len() > SUMMARY_MAX {
        text = format!("{} …", truncate(&text, SUMMARY_MAX - 4));
    }
    text
}

/// Send the digest when due. Returns the attempt for the pass report, or
/// `None` when the digest is not configured or not due.
pub fn send_if_due(
    config: &Config,
    state: &State,
    rules: &[EffectiveRule],
    inputs: &[InputReport],
    policy_digest: &str,
    now: i64,
) -> Result<Option<Value>, String> {
    let Some(settings) = &config.digest else {
        return Ok(None);
    };
    let state_dir = config.state_dir();
    let record_path = state_dir.join(RECORD_FILE);
    let record = read_record(&record_path);
    if !due(settings.offset_seconds()?, record.as_ref(), now) {
        return Ok(None);
    }
    let stable_event_id = format!("{}-attention-digest-{now}", config.site);
    let inspection_reference = config.runbooks.monitor_url.as_ref().map_or_else(
        || format!("constellation-monitor:docs/ATTENTION.md#{ANCHOR}"),
        |base| format!("{base}#{ANCHOR}"),
    );
    let local = config.routes.local(INTENT_V1);
    let label = config.routes.notice_transport.destination_label();
    let route = &config.routes.notice_route;
    let body = json!({
        "schema": INTENT_V1,
        "attention_kind": "operator_assertion",
        "stable_event_id": stable_event_id,
        "attention_policy_id": ATTENTION_POLICY_ID,
        "attention_policy_digest": policy_digest,
        "transition_id": stable_event_id,
        "route_reference": route,
        "destination_identity": format!("{label}:{route}"),
        "summary": summary(&config.site, state, rules, inputs, &config.suspensions, now),
        "inspection_reference": truncate(&inspection_reference, 1024),
        "response_class": "attention",
    });
    let intent_path = state_dir.join(INTENT_FILE);
    write_atomic(&intent_path, &intent::canonical(&body)?)?;
    let outcome = if local {
        nq::deliver_local(config, &intent_path, route)
    } else {
        nq::submit(config, &intent_path, route)
    };
    let record = Record {
        day: day(now),
        at: now,
        stable_event_id: stable_event_id.clone(),
        outcome: outcome.outcome.clone(),
        network: config.routes.delivers(INTENT_V1),
        notification_id: outcome.notification_id.clone(),
        error: outcome.error.clone(),
    };
    let mut bytes = serde_json::to_vec_pretty(&record).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    write_atomic(&record_path, &bytes)?;
    Ok(Some(json!({
        "stable_event_id": stable_event_id,
        "route": route,
        "summary": body["summary"],
        "outcome": outcome.outcome,
        "settled": record.settled(),
        "notification_id": outcome.notification_id,
        "error": outcome.error,
    })))
}

/// Keep today's digest obligation visible between bounded retry attempts.
/// An omitted digest configuration creates no obligation.
pub fn current_outcome(config: &Config, now: i64) -> Option<Record> {
    config.digest.as_ref()?;
    let mut record = read_record(&config.state_dir().join(RECORD_FILE))
        .filter(|record| record.day == day(now))?;
    // A deliberate refusal settles the day even if networking is later enabled.
    // Preserve the attempt time, but do not revive its delivery obligation.
    if record.settled() && record.outcome != "accepted" {
        record.outcome = "skipped".into();
    }
    Some(record)
}

fn read_record(path: &Path) -> Option<Record> {
    read_bounded(path, 64 * 1024)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 1_791_936_000; // 2026-10-14T00:00:00Z

    fn record(at: i64, outcome: &str) -> Record {
        Record {
            day: day(at),
            at,
            stable_event_id: "s".into(),
            outcome: outcome.into(),
            network: true,
            notification_id: None,
            error: None,
        }
    }

    #[test]
    fn due_once_a_day_after_the_offset_and_retried_after_failure() {
        let offset = 40 * 60;
        assert_eq!(day(DAY + 5), "2026-10-14");
        assert!(!due(offset, None, DAY + offset - 1));
        assert!(due(offset, None, DAY + offset));
        let sent = record(DAY + offset, "accepted");
        assert!(!due(offset, Some(&sent), DAY + 86_399));
        assert!(due(offset, Some(&sent), DAY + 86_400 + offset));
        let failed = record(DAY + offset, "failed");
        assert!(!due(
            offset,
            Some(&failed),
            DAY + offset + RESEND_INTERVAL_SECONDS - 1
        ));
        assert!(due(
            offset,
            Some(&failed),
            DAY + offset + RESEND_INTERVAL_SECONDS
        ));
    }

    #[test]
    fn span_is_coarse() {
        assert_eq!(span(59), "0m");
        assert_eq!(span(3 * 3600 + 120), "3h 2m");
        assert_eq!(span(3 * 86_400 + 5 * 3600), "3d 5h");
    }
}
