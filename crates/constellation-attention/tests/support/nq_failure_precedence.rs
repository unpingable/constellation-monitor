//! One exact disposable-VM NQ export plus clearly controlled API fixtures.
//! Exercise the real Attention binary and persisted condition transitions.

use super::*;

const MEMORY: &str = "constellation:labelwatch:host_posture:memory-pressure";

/// Exact NQ status export captured after ordinary watcher revoke and refused
/// collection on a disposable VM. No production data and no retiming. Anchor
/// Attention's clock to the export so fixture age cannot hide the defect.
#[test]
fn actual_nq_failed_instance_does_not_make_old_io_absence_clear() {
    let (harness, path) = nq_status_harness();
    use_sample(&path, "failed-instance-retained-evaluation.json");
    let snapshot: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let now = at(snapshot["generated_at"].as_str().unwrap()) + 1;
    let report = harness.evaluate(now);
    let io = report["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|condition| condition["rule"] == "io-pressure")
        .expect("the retained IO evaluation is still reported");
    assert_eq!(io["observation"], "unknown", "{report}");
    assert_eq!(report["inputs"][0]["status"], "not_current");
    assert!(
        report["inputs"][0]["error"]
            .as_str()
            .unwrap()
            .contains("io-installed")
    );
}

/// Retain the complete memory instance/evaluation shapes from the existing
/// public NQ sample. Change times/state explicitly for each boundary scenario.
fn memory_snapshot(generated: i64, evaluated: i64, state: &str) -> Value {
    let mut snapshot: Value = serde_json::from_slice(
        &fs::read(Path::new(FIXTURES).join("nq-status/healthy.json")).unwrap(),
    )
    .unwrap();
    snapshot["generated_at"] = json!(rfc3339(generated));
    let components = snapshot["components"].as_array_mut().unwrap();
    components.retain(|component| {
        component["kind"] == "instance" && component["id"] == "host-memory"
            || component["kind"] == "evaluation"
                && component["detail"]["result"]["context"]["instance_id"] == "host-memory"
    });
    assert_eq!(components.len(), 2);
    let evaluation = components
        .iter_mut()
        .find(|component| component["kind"] == "evaluation")
        .unwrap();
    evaluation["observed_at"] = json!(rfc3339(evaluated));
    evaluation["code"] = json!(if state == "present" {
        "condition_present"
    } else {
        "condition_explicitly_absent"
    });
    let envelope = &mut evaluation["detail"]["result"];
    envelope["started_at"] = json!(rfc3339(evaluated));
    envelope["evaluated_at"] = json!(rfc3339(evaluated));
    envelope["watermark"]["watermark_received_at"] = json!(rfc3339(evaluated));
    envelope["result"]["state"] = json!(state);
    envelope["result"]["summary"] = json!("controlled memory-pressure fixture");
    envelope["result"]["evidence"][0]["observed_at"] = json!(rfc3339(evaluated));
    let envelope = envelope.clone();
    let instance = components
        .iter_mut()
        .find(|component| component["kind"] == "instance")
        .unwrap();
    instance["observed_at"] = json!(rfc3339(evaluated));
    instance["detail"]["result"]["result"]["evaluations"] = json!([envelope]);
    snapshot
}

fn instance(snapshot: &mut Value) -> &mut Value {
    snapshot["components"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|component| component["kind"] == "instance")
        .unwrap()
}

/// NQ's admission_refused projection has no run or new evaluation. Its fresh
/// instance status is failed/admission_refused, with a v1 collection outcome.
fn refused_instance(snapshot: &mut Value, generated: i64) {
    snapshot["generated_at"] = json!(rfc3339(generated));
    let component = instance(snapshot);
    component["observed_at"] = json!(rfc3339(generated - 1));
    component["state"] = json!("failed");
    component["code"] = json!("admission_refused");
    component["detail"] = json!({
        "detail_kind": "collection",
        "result": {
            "schema": "nq.collection_outcome.v1",
            "instance_id": "host-memory",
            "result": {
                "outcome": "admission_refused",
                "refusal": {
                    "responsible_instance_id": "host-memory",
                    "boundary": "active_binding",
                    "code": "missing_active_binding",
                    "details": {"kind": "none"}
                }
            }
        }
    });
}

fn memory_condition(report: &Value) -> &Value {
    report["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|condition| condition["id"] == MEMORY)
        .expect("the consumed memory lineage remains reported")
}

#[test]
fn fresh_failed_instance_cannot_refresh_an_old_absent_evaluation() {
    let (harness, path) = nq_status_harness();
    let mut snapshot = memory_snapshot(T0, T0 - 1_000, "explicitly_absent");
    let old_evaluation = snapshot["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|component| component["kind"] == "evaluation")
        .unwrap()
        .clone();
    for offset in [0, 60, 180, 360] {
        refused_instance(&mut snapshot, T0 + offset);
        write_status(&path, &snapshot);
        let report = harness.evaluate(T0 + offset);
        assert_eq!(
            memory_condition(&report)["observation"],
            "unknown",
            "a fresh failed instance cannot turn historical absence into Clear: {report}"
        );
        assert_eq!(report["inputs"][0]["status"], "not_current");
        assert!(
            report["inputs"][0]["error"]
                .as_str()
                .unwrap()
                .contains("host-memory")
        );
        assert!(
            snapshot["components"]
                .as_array()
                .unwrap()
                .contains(&old_evaluation)
        );
    }
}

#[test]
fn failed_attempts_cannot_finish_resolving_an_active_memory_incident() {
    let (harness, path) = nq_status_harness();
    for offset in (0..=660).step_by(60) {
        write_status(
            &path,
            &memory_snapshot(T0 + offset, T0 + offset - 1, "present"),
        );
        harness.evaluate(T0 + offset);
    }
    assert_eq!(harness.state()["conditions"][MEMORY]["active"], true);
    // Carry an incident written under registry v7 / memory-pressure v1
    // across the new policy identity without resetting or re-keying it.
    let mut old_state = harness.state();
    old_state["conditions"][MEMORY]["rule_version"] = json!(1);
    fs::write(
        harness.path("state/state.json"),
        serde_json::to_vec(&old_state).unwrap(),
    )
    .unwrap();

    // One successful absent observation starts confirmation. Later attempts
    // fail without a new evaluation; they must hold, not confirm recovery.
    let mut snapshot = memory_snapshot(T0 + 720, T0 + 719, "explicitly_absent");
    write_status(&path, &snapshot);
    let report = harness.evaluate(T0 + 720);
    assert_eq!(memory_condition(&report)["observation"], "clear");
    let clear_since = harness.state()["conditions"][MEMORY]["clear_since"].clone();
    assert!(!clear_since.is_null());
    let mut resolves = Vec::new();
    for offset in [780, 840, 900] {
        refused_instance(&mut snapshot, T0 + offset);
        write_status(&path, &snapshot);
        let report = harness.evaluate(T0 + offset);
        resolves.extend(
            intents(&report)
                .into_iter()
                .filter(|(id, _, action)| id == MEMORY && action == "resolve"),
        );
    }
    assert!(
        resolves.is_empty(),
        "failure must not manufacture recovery: {resolves:?}"
    );
    let state = harness.state();
    assert_eq!(state["conditions"][MEMORY]["active"], true);
    assert_eq!(state["conditions"][MEMORY]["rule_version"], 1);
    assert_eq!(state["conditions"][MEMORY]["clear_since"], clear_since);
    assert_eq!(
        memory_condition(&harness.report())["observation"],
        "unknown"
    );
}

#[test]
fn missing_instance_outcome_cannot_establish_success() {
    for missing in ["state", "code"] {
        let (harness, path) = nq_status_harness();
        let mut snapshot = memory_snapshot(T0, T0 - 1, "explicitly_absent");
        instance(&mut snapshot)
            .as_object_mut()
            .unwrap()
            .remove(missing);
        write_status(&path, &snapshot);
        let report = harness.evaluate(T0);
        assert_eq!(
            memory_condition(&report)["observation"],
            "unknown",
            "missing {missing}"
        );
        assert_eq!(report["inputs"][0]["status"], "not_current");
    }
}

#[test]
fn healthy_complete_instance_keeps_the_existing_absent_result() {
    let (harness, path) = nq_status_harness();
    write_status(&path, &memory_snapshot(T0, T0 - 1, "explicitly_absent"));
    let report = harness.evaluate(T0);
    assert_eq!(report["inputs"][0]["status"], "ok");
    assert_eq!(memory_condition(&report)["observation"], "clear");
    assert!(intents(&report).is_empty());
}

/// Admitted partial/failed reports still reach NQ's detector-state mapping.
/// These current memory profiles cannot evaluate such reports; their NQ
/// judgment, rather than coarse instance health, supplies the Unknown reason.
#[test]
fn admitted_partial_and_failed_reports_preserve_nq_detector_judgments() {
    for (state, code, status) in [
        ("degraded", "report_partial", "partial"),
        ("failed", "report_failed", "failed"),
    ] {
        let (harness, path) = nq_status_harness();
        let mut snapshot = memory_snapshot(T0, T0 - 1, "explicitly_absent");
        let evaluation = snapshot["components"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|component| component["kind"] == "evaluation")
            .unwrap();
        evaluation["state"] = json!("degraded");
        evaluation["code"] = json!("cannot_evaluate");
        let envelope = &mut evaluation["detail"]["result"];
        envelope["result"]["state"] = json!("cannot_evaluate");
        envelope["result"]["summary"] = json!("controlled admitted incomplete report");
        envelope["result"]["evidence"] = json!([]);
        let envelope = envelope.clone();
        let component = instance(&mut snapshot);
        component["state"] = json!(state);
        component["code"] = json!(code);
        component["detail"]["result"]["result"]["report_status"] = json!(status);
        component["detail"]["result"]["result"]["evaluations"] = json!([envelope]);
        write_status(&path, &snapshot);
        let report = harness.evaluate(T0);
        assert_eq!(memory_condition(&report)["observation"], "unknown");
        let error = report["inputs"][0]["error"].as_str().unwrap();
        assert!(error.contains("host memory (cannot_evaluate)"), "{report}");
        assert!(
            !error.contains("without an admitted collection outcome"),
            "{report}"
        );
    }
}

#[test]
fn other_nonadmitted_and_mismatched_outcomes_cannot_reuse_absence() {
    for (state, code) in [
        ("failed", "collection_failed"),
        ("degraded", "helper_refused"),
        ("failed", "report_rejected"),
        ("healthy", "report_failed"),
        ("failed", "report_complete"),
    ] {
        let (harness, path) = nq_status_harness();
        let mut snapshot = memory_snapshot(T0, T0 - 1, "explicitly_absent");
        let component = instance(&mut snapshot);
        component["state"] = json!(state);
        component["code"] = json!(code);
        write_status(&path, &snapshot);
        let report = harness.evaluate(T0);
        assert_eq!(
            memory_condition(&report)["observation"],
            "unknown",
            "{report}"
        );
        assert_eq!(report["inputs"][0]["status"], "not_current");
    }
}
