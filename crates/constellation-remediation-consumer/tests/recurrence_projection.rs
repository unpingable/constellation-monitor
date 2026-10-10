//! Recurrence presentation never provides a new effect selector.
mod common;
use common::*;
use constellation_remediation_consumer::report::{self, Selection};
use serde_json::{Value, json};
use std::fs;

fn fixture() -> (Harness, Value, i64) {
    let h = Harness::new();
    let v = serde_json::from_slice(&fs::read(h.path("report.json")).unwrap()).unwrap();
    (h, v, now_s())
}
fn recurrence(v: &mut Value) {
    v["schema"] = json!(report::RECURRENCE_REPORT_SCHEMA);
    v["notice_recurrence"] = json!({"entries": {CONDITION: {
        "notice_active": true, "observation": "present", "rule": "service-down",
        "response_policy": "auto_remediate_then_page", "summary": "invented authority",
        "last_summary": {"kind": "summary", "observation": "present"}
    }}});
}
#[test]
fn recurrence_report_preserves_exact_raw_selection_projection() {
    let (h, mut v, now) = fixture();
    let Selection::Act(before) = report::select(&h.config(), &v, now) else {
        panic!("legacy fixture")
    };
    recurrence(&mut v);
    let Selection::Act(after) = report::select(&h.config(), &v, now) else {
        panic!("v2 fixture")
    };
    assert_eq!(before.projection, after.projection);
    assert_eq!(before.narration, after.narration);
    assert_eq!(before.condition_id, after.condition_id);
    assert_eq!(before.first_seen, after.first_seen);
    assert_eq!(before.window_until, after.window_until);
}
#[test]
fn recurrence_summary_cannot_restore_missing_or_unqualified_raw_evidence() {
    let (h, v, now) = fixture();
    for (field, value, reason) in [
        ("observation", json!("clear"), "observation_not_present"),
        ("observation", json!("unknown"), "observation_not_present"),
        (
            "rule",
            json!("evaluator-input-unavailable"),
            "condition_not_enrolled",
        ),
        (
            "response_policy",
            json!("notify_only"),
            "policy_not_auto_remediate",
        ),
        ("page_deferred", json!(false), "page_not_deferred"),
    ] {
        let mut changed = v.clone();
        recurrence(&mut changed);
        changed["conditions"][0][field] = value;
        assert!(
            matches!(report::select(&h.config(), &changed, now), Selection::Abstain { reason: actual, .. } if actual == reason)
        );
    }
    let mut missing = v.clone();
    recurrence(&mut missing);
    missing["conditions"] = json!([]);
    assert!(matches!(
        report::select(&h.config(), &missing, now),
        Selection::Abstain {
            reason: "no_condition",
            ..
        }
    ));
    let mut future = v;
    recurrence(&mut future);
    future["evaluated_at"] = json!(rfc3339(now + 6));
    assert!(matches!(
        report::select(&h.config(), &future, now),
        Selection::Abstain {
            reason: "report_stale",
            ..
        }
    ));
    future["schema"] = json!("constellation.attention_report.v3");
    assert!(matches!(
        report::select(&h.config(), &future, now),
        Selection::Abstain {
            reason: "report_malformed",
            ..
        }
    ));
}
