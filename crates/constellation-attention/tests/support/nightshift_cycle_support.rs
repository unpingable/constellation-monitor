//! Owner-shaped substitution cycles; no acquired evidence or Current-now claim.
use super::{Harness, causes, rfc3339};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../artifacts/nightshift-cycle-support-v1"
);
const AT: i64 = 1_785_182_430; // 2026-07-27T20:00:30Z
const INCIDENT: &str =
    "constellation:labelwatch:nightshift:evaluator-input-unavailable:observation.indeterminate";

fn cycle(name: &str) -> Value {
    serde_json::from_slice(&fs::read(Path::new(FIXTURE).join(format!("{name}.json"))).unwrap())
        .unwrap()
}

fn seal(value: &mut Value, field: &str) {
    value.as_object_mut().unwrap().remove(field);
    value[field] = json!(format!(
        "sha256:{:x}",
        Sha256::digest(serde_jcs::to_vec(value).unwrap())
    ));
}

fn seal_posture(value: &mut Value) {
    seal(&mut value["observation"]["posture"], "posture_id");
    value["attention"]["source_posture_id"] = value["observation"]["posture"]["posture_id"].clone();
    seal(value, "state_digest");
}

fn seal_support(value: &mut Value) {
    seal(&mut value["observation"]["support"], "support_id");
    value["observation"]["posture"]["present_support"] = value["observation"]["support"].clone();
    seal_posture(value);
}

fn configure(harness: &mut Harness, opted: Option<bool>) {
    let store = harness.path("nightshift.sqlite");
    let connection = rusqlite::Connection::open(&store).unwrap();
    connection
        .execute_batch(
            &fs::read_to_string(Path::new(super::FIXTURES).join("nightshift-schema.sql")).unwrap(),
        )
        .unwrap();
    let option = opted.map_or_else(String::new, |value| {
        format!("require_cycle_support = {value}\n")
    });
    harness.raw(&format!(
        "[inputs.nightshift]\nlabel = \"observation\"\nstore_path = {store:?}\n{option}"
    ));
}

fn insert(harness: &Harness, cycle: &Value) {
    let connection = rusqlite::Connection::open(harness.path("nightshift.sqlite")).unwrap();
    connection
        .execute(
            "INSERT INTO canonical_recurrence_slots VALUES (?1, ?2, 'done', '{}', 'd', ?3)",
            rusqlite::params![
                cycle["slot"]["slot_id"].as_str().unwrap(),
                cycle["cycle_id"].as_str().unwrap(),
                cycle["updated_at"].as_str().unwrap()
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO canonical_observation_cycles VALUES (?1, ?2, ?3, 'closed', ?4, ?5, ?6)",
            rusqlite::params![
                cycle["cycle_id"].as_str().unwrap(),
                cycle["slot"]["slot_id"].as_str().unwrap(),
                cycle["version"].as_i64().unwrap(),
                cycle["state_digest"].as_str().unwrap(),
                serde_json::to_string(cycle).unwrap(),
                cycle["updated_at"].as_str().unwrap()
            ],
        )
        .unwrap();
}

#[test]
fn new_loss_after_older_current_is_not_current_but_recurrence_is_clear() {
    let mut harness = Harness::new();
    configure(&mut harness, Some(true));
    insert(&harness, &cycle("current"));
    let loss = cycle("unsupported");
    insert(&harness, &loss);
    let report = harness.evaluate(AT);
    assert_eq!(
        report["inputs"][0]["status"], "not_current",
        "behavioral regression: newest unsupported cycle remained an OK input"
    );
    assert_eq!(causes(&report["inputs"][0]), ["indeterminate"]);
    assert_eq!(
        report["inputs"][0]["identity"]["cycle_id"],
        loss["cycle_id"]
    );
    let recurrence = report["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["rule"] == "nightshift-recurrence-missing")
        .unwrap();
    assert_eq!(recurrence["observation"], "clear");
    assert_eq!(report["exit_code"], 3);
}

#[test]
fn legacy_default_and_explicit_false_keep_recurrence_only_contract() {
    for opted in [None, Some(false)] {
        let mut harness = Harness::new();
        configure(&mut harness, opted);
        let mut malformed = cycle("unsupported");
        malformed.as_object_mut().unwrap().remove("observation");
        insert(&harness, &malformed);
        let report = harness.evaluate(AT);
        assert_eq!(report["inputs"][0]["status"], "ok");
        assert_eq!(report["exit_code"], 0);
    }
}

#[test]
fn historical_current_and_condition_present_are_not_unavailability() {
    for name in ["current", "condition-present"] {
        let mut harness = Harness::new();
        configure(&mut harness, Some(true));
        insert(&harness, &cycle(name));
        let report = harness.evaluate(AT + 100);
        assert_eq!(report["inputs"][0]["status"], "ok", "{name}: {report}");
        // Tick 100/101 is an authority-local historical interval, never converted
        // into a new wall-clock lifetime by this reader.
        assert!(report["inputs"][0]["identity"].get("fresh_until").is_none());
    }
}

#[test]
fn support_loss_preserves_the_existing_indeterminate_incident_lineage() {
    let mut harness = Harness::new();
    configure(&mut harness, Some(true));
    insert(&harness, &cycle("current"));
    insert(&harness, &cycle("unsupported"));
    harness.evaluate(AT);
    harness.evaluate(AT + 301);
    let before = harness.state()["conditions"][INCIDENT].clone();
    assert_eq!(before["active"], true);
    harness.evaluate(AT + 302);
    let after = harness.state()["conditions"][INCIDENT].clone();
    assert_eq!(after["active"], true);
    assert_eq!(after["first_seen"], before["first_seen"]);
    assert_eq!(after["last_intent"], before["last_intent"]);
}

#[test]
fn malformed_snapshot_and_intrinsic_support_controls_are_unreadable() {
    for case in [
        "missing_observation",
        "missing_support",
        "wrong_cycle",
        "wrong_observation",
        "wrong_inputs",
        "wrong_present_support",
        "wrong_current_equation",
        "invalid_support_id",
        "equal_expiry",
        "wrong_expiry_clock",
        "current_contradiction",
        "wrong_posture_id",
        "wrong_attention_basis",
        "future",
        "invalid_json",
    ] {
        let mut harness = Harness::new();
        configure(&mut harness, Some(true));
        let mut value = cycle("current");
        match case {
            "missing_observation" => {
                value.as_object_mut().unwrap().remove("observation");
                seal(&mut value, "state_digest");
            }
            "missing_support" => {
                value["observation"]
                    .as_object_mut()
                    .unwrap()
                    .remove("support");
                seal(&mut value, "state_digest");
            }
            "wrong_cycle" => {
                value["observation"]["support"]["observation_cycle_id"] = json!("cycle:other");
                seal_support(&mut value);
            }
            "wrong_observation" => {
                value["observation"]["observation_id"] =
                    json!(format!("sha256:{}", "2".repeat(64)));
                seal(&mut value, "state_digest");
            }
            "wrong_inputs" => {
                value["observation"]["support"]["diagnostic_inputs_id"] =
                    json!(format!("sha256:{}", "2".repeat(64)));
                seal_support(&mut value);
            }
            "wrong_present_support" => {
                value["observation"]["posture"]["present_support"] =
                    cycle("unsupported")["observation"]["support"].clone();
                seal_posture(&mut value);
            }
            "wrong_current_equation" => {
                value["observation"]["posture"]["current"] = json!(false);
                seal_posture(&mut value);
            }
            "invalid_support_id" => {
                value["observation"]["support"]["support_id"] =
                    json!(format!("sha256:{}", "2".repeat(64)));
                seal_posture(&mut value);
            }
            "equal_expiry" => {
                value["observation"]["support"]["expiry"]["tick"] = json!(100);
                seal_support(&mut value);
            }
            "wrong_expiry_clock" => {
                value["observation"]["support"]["expiry"]["clock_id"] = json!("different-clock");
                seal_support(&mut value);
            }
            "current_contradiction" => {
                value["observation"]["support"]["contradiction_refs"] =
                    json!([format!("sha256:{}", "2".repeat(64))]);
                seal_support(&mut value);
            }
            "wrong_posture_id" => {
                value["observation"]["posture"]["posture_id"] =
                    json!(format!("sha256:{}", "2".repeat(64)));
                seal(&mut value, "state_digest");
            }
            "wrong_attention_basis" => {
                value["attention"]["source_posture_id"] =
                    json!(format!("sha256:{}", "2".repeat(64)));
                seal(&mut value, "state_digest");
            }
            "future" => {
                value["updated_at"] = json!(rfc3339(AT + 3600));
                seal(&mut value, "state_digest");
            }
            "invalid_json" => {}
            _ => unreachable!(),
        }
        insert(&harness, &value);
        if case == "invalid_json" {
            rusqlite::Connection::open(harness.path("nightshift.sqlite"))
                .unwrap()
                .execute(
                    "UPDATE canonical_observation_cycles SET snapshot_json='{'",
                    [],
                )
                .unwrap();
        }
        let report = harness.evaluate(AT);
        assert_eq!(
            report["inputs"][0]["status"], "unavailable",
            "{case}: {report}"
        );
        assert_eq!(
            causes(&report["inputs"][0]),
            ["unreadable"],
            "{case}: {report}"
        );
        assert_eq!(report["exit_code"], 3);
    }
}

#[test]
fn unknown_support_is_indeterminate_and_not_a_recurrence_failure() {
    let mut harness = Harness::new();
    configure(&mut harness, Some(true));
    insert(&harness, &cycle("unknown"));
    let report = harness.evaluate(AT + 30);
    assert_eq!(report["inputs"][0]["status"], "not_current");
    assert_eq!(causes(&report["inputs"][0]), ["indeterminate"]);
}

#[test]
fn required_support_missing_store_or_closed_cycle_does_not_warm_as_ok() {
    for missing_store in [false, true] {
        let mut harness = Harness::new();
        configure(&mut harness, Some(true));
        if missing_store {
            fs::remove_file(harness.path("nightshift.sqlite")).unwrap();
        }
        let report = harness.evaluate(AT);
        assert_eq!(
            report["inputs"][0]["status"], "unavailable",
            "behavioral regression: required support absence was hidden by recurrence startup warming"
        );
        assert_eq!(causes(&report["inputs"][0]), ["unreadable"]);
        assert_eq!(report["exit_code"], 3);
    }
}
