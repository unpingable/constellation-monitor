//! Selection from the evaluator's `report.json`: the one condition this
//! consumer is enrolled for, and only when the report is fresh enough to be
//! worth a fresh look. The report is a trigger, never evidence: the
//! precondition is re-established by the resolver before anything is asked.

use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::config::Config;

pub const REPORT_SCHEMA: &str = "constellation.attention_report.v1";
pub const RECURRENCE_REPORT_SCHEMA: &str = "constellation.attention_report.v2";
pub const RULE: &str = "service-down";
pub const POLICY: &str = "auto_remediate_then_page";
/// A report stamped further than this in the future is not trusted.
const FUTURE_SKEW_SECONDS: i64 = 5;

/// The condition episode a pass may act on.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub condition_id: String,
    pub first_seen: String,
    pub window_until: i64,
    pub page_deferred: bool,
    pub evaluated_at: String,
    /// The selected report fields a model decider may see, verbatim.
    pub projection: Value,
    /// The condition's `summary`, if any: untrusted narration, never an
    /// authority input (bounded again by the decider).
    pub narration: String,
}

#[derive(Clone, Debug)]
pub enum Selection {
    Act(Candidate),
    /// Nothing to do; `reason` is a closed token, `detail` its evidence.
    Abstain {
        reason: &'static str,
        detail: Value,
    },
}

fn abstain(reason: &'static str, detail: Value) -> Selection {
    Selection::Abstain { reason, detail }
}

fn parse_time(text: &str) -> Option<i64> {
    OffsetDateTime::parse(text, &Rfc3339)
        .ok()
        .map(OffsetDateTime::unix_timestamp)
}

/// Judge one report at `now` (unix seconds) with the deterministic
/// decider's window margin.
#[must_use]
pub fn select(config: &Config, report: &Value, now: i64) -> Selection {
    select_with_margin(config, report, now, config.consumer.window_margin_seconds)
}

/// Judge one report at `now`, requiring at least `margin` seconds of the
/// remediation window left.
#[must_use]
pub fn select_with_margin(config: &Config, report: &Value, now: i64, margin: i64) -> Selection {
    // v2 adds notice-only episode state; effects still select the identical
    // raw condition fields below, never notification summaries or counters.
    if !matches!(
        report.get("schema").and_then(Value::as_str),
        Some(REPORT_SCHEMA | RECURRENCE_REPORT_SCHEMA)
    ) {
        return abstain("report_malformed", json!({"schema": report.get("schema")}));
    }
    let evaluated_at = report
        .get("evaluated_at")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let Some(evaluated) = parse_time(&evaluated_at) else {
        return abstain("report_malformed", json!({"evaluated_at": evaluated_at}));
    };
    let age = now - evaluated;
    if age > config.consumer.report_max_age_seconds || age < -FUTURE_SKEW_SECONDS {
        return abstain(
            "report_stale",
            json!({"evaluated_at": evaluated_at, "age_seconds": age}),
        );
    }
    let nq_inputs: Vec<&Value> = report
        .get("inputs")
        .and_then(Value::as_array)
        .map(|inputs| {
            inputs
                .iter()
                .filter(|input| input.get("kind").and_then(Value::as_str) == Some("nq_status"))
                .collect()
        })
        .unwrap_or_default();
    let not_ok: Vec<Value> = nq_inputs
        .iter()
        .filter(|input| input.get("status").and_then(Value::as_str) != Some("ok"))
        .map(|input| json!({"label": input.get("label"), "status": input.get("status")}))
        .collect();
    if nq_inputs.is_empty() || !not_ok.is_empty() {
        return abstain(
            "nq_input_not_ok",
            json!({"nq_inputs": nq_inputs.len(), "not_ok": not_ok}),
        );
    }
    let expected = config.condition_id();
    let Some(condition) =
        report
            .get("conditions")
            .and_then(Value::as_array)
            .and_then(|conditions| {
                conditions.iter().find(|condition| {
                    condition.get("id").and_then(Value::as_str) == Some(&expected)
                })
            })
    else {
        return abstain("no_condition", json!({"condition_id": expected}));
    };
    let field = |name: &str| condition.get(name).and_then(Value::as_str);
    let detail = json!({
        "condition_id": expected,
        "rule": condition.get("rule"),
        "response_policy": condition.get("response_policy"),
        "observation": condition.get("observation"),
        "first_seen": condition.get("first_seen"),
        "remediation_window_until": condition.get("remediation_window_until"),
        "page_deferred": condition.get("page_deferred"),
        "instance_id": condition.pointer("/reference/instance_id"),
    });
    if field("rule") != Some(RULE) {
        return abstain("condition_not_enrolled", detail);
    }
    if field("response_policy") != Some(POLICY) {
        return abstain("policy_not_auto_remediate", detail);
    }
    if condition
        .pointer("/reference/instance_id")
        .and_then(Value::as_str)
        != Some(config.enrollment.instance_id.as_str())
    {
        return abstain("condition_not_enrolled", detail);
    }
    if field("observation") != Some("present") {
        return abstain("observation_not_present", detail);
    }
    let Some(first_seen) = field("first_seen").map(str::to_owned) else {
        return abstain("report_malformed", detail);
    };
    let Some(window_until) = condition
        .get("remediation_window_until")
        .and_then(Value::as_i64)
    else {
        return abstain("report_malformed", detail);
    };
    // Act only while the evaluator holds the page (cartography decision
    // memo, section 4): the condition has triggered at the rule's bound, its
    // notice is out, and the page waits for the remediation window. Before
    // the bound nothing has been reported; after the page is sent the
    // window is over.
    if condition.get("page_deferred").and_then(Value::as_bool) != Some(true) {
        return abstain("page_not_deferred", detail);
    }
    if window_until - now < margin {
        return abstain(
            "window_too_short",
            json!({"condition": detail, "remaining_seconds": window_until - now, "required_seconds": margin}),
        );
    }
    let projection = json!({
        "evaluated_at": evaluated_at,
        "rule": condition.get("rule"),
        "observation": condition.get("observation"),
        "response_policy": condition.get("response_policy"),
        "first_seen": first_seen,
        "remediation_window_until": window_until,
        "page_deferred": true,
    });
    let narration = condition
        .get("summary")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    Selection::Act(Candidate {
        condition_id: expected,
        first_seen,
        window_until,
        page_deferred: true,
        evaluated_at,
        projection,
        narration,
    })
}
