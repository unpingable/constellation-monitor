//! End-to-end passes of the `constellation-attention` binary against fixture
//! inputs and a fake `nq` that records submissions.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use constellation_status_projection::{
    ModeV1, ProjectedComponentV1, ProjectedStateV1, STATUS_ARTIFACT_SCHEMA_V1, StatusArtifactV1,
};
use serde_json::{Value, json};
use tempfile::TempDir;

const T0: i64 = 1_790_942_400; // 2026-10-02T12:00:00Z
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn rfc3339(seconds: i64) -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::from_unix_timestamp(seconds)
        .unwrap()
        .format(&Rfc3339)
        .unwrap()
}

fn status_object(state: ProjectedStateV1, generated_s: i64, fresh_for_s: i64) -> StatusArtifactV1 {
    let generated = u64::try_from(generated_s * 1000).unwrap();
    let fresh = u64::try_from((generated_s + fresh_for_s) * 1000).unwrap();
    let mut artifact = StatusArtifactV1 {
        schema: STATUS_ARTIFACT_SCHEMA_V1.into(),
        artifact_id: String::new(),
        projection_id: "operator-filesystem-capacity".into(),
        projection_generation: "filesystem-capacity-v1".into(),
        policy_digest: format!("sha256:{}", "a".repeat(64)),
        generated_at_unix_ms: generated,
        fresh_until_unix_ms: if fresh_for_s == 0 { generated } else { fresh },
        admitted_clock_uncertainty_ms: 1000,
        observation_window: None,
        aggregate_state: state,
        components: vec![ProjectedComponentV1 {
            id: "filesystem-capacity".into(),
            display_name: Some("Filesystem capacity pressure (/)".into()),
            state,
            mode: ModeV1::Normal,
            reason: None,
            detail: None,
        }],
        basis_digest: Some(format!("sha256:{}", "b".repeat(64))),
        mutation_authority: "none".into(),
        non_authorization: "Derived status is read-only and grants no authority or permission."
            .into(),
    };
    artifact.artifact_id = artifact.compute_id().unwrap();
    artifact
}

/// Publish a status object the way the runner does: object file plus CURRENT.
fn publish(root: &Path, artifact: &StatusArtifactV1) {
    fs::create_dir_all(root.join("objects")).unwrap();
    let hex = artifact.artifact_id.trim_start_matches("sha256:");
    fs::write(
        root.join("objects").join(format!("{hex}.json")),
        artifact.canonical_bytes().unwrap(),
    )
    .unwrap();
    let pointer = serde_jcs::to_vec(&json!({
        "schema": "constellation.status_current_pointer.v1",
        "artifact_id": artifact.artifact_id,
    }))
    .unwrap();
    fs::write(root.join("CURRENT"), pointer).unwrap();
}

struct Harness {
    dir: TempDir,
    extra_config: String,
    page_route: bool,
    network: bool,
}

impl Harness {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("fake")).unwrap();
        fs::create_dir_all(dir.path().join("state")).unwrap();
        Self {
            dir,
            extra_config: String::new(),
            page_route: true,
            network: true,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn root(&self, label: &str) -> PathBuf {
        self.path(&format!("hp-{label}"))
    }

    fn host_posture(&mut self, label: &str) -> &mut Self {
        let root = self.root(label);
        fs::create_dir_all(&root).unwrap();
        self.extra_config.push_str(&format!(
            "\n[[inputs.host_posture]]\nlabel = \"{label}\"\npublication_root = \"{}\"\n",
            root.display()
        ));
        self
    }

    fn raw(&mut self, toml: &str) -> &mut Self {
        self.extra_config.push('\n');
        self.extra_config.push_str(toml);
        self
    }

    fn config_path(&self) -> PathBuf {
        let page = if self.page_route {
            "page_route = \"pagerduty-ops\"\n"
        } else {
            ""
        };
        let text = format!(
            "schema = \"constellation.attention_config.v1\"\n\
             site = \"labelwatch\"\n\
             state_path = \"{state}\"\n\
             [runbooks]\n\
             cartography_url = \"https://docs.example.org/beta-observability/RUNBOOKS.md\"\n\
             [nq]\n\
             program = \"{nq}\"\n\
             config = \"/etc/nq/nqd-ops.toml\"\n\
             [routes]\n\
             notice_route = \"operations\"\n\
             notice_transport = \"slack\"\n\
             {page}\
             network_enabled = {network}\n\
             {extra}\n",
            state = self.path("state/state.json").display(),
            nq = Path::new(FIXTURES).join("fake-nq.sh").display(),
            network = self.network,
            extra = self.extra_config,
        );
        let path = self.path("attention.toml");
        fs::write(&path, text).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    fn command(&self, arguments: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_constellation-attention"))
            .args(arguments)
            .env("FAKE_NQ_DIR", self.path("fake"))
            .output()
            .unwrap()
    }

    fn evaluate_at(&self, at: i64, extra: &[&str]) -> Output {
        let config = self.config_path();
        let now = rfc3339(at);
        let mut arguments = vec![
            "evaluate",
            "--config",
            config.to_str().unwrap(),
            "--now",
            &now,
        ];
        arguments.extend_from_slice(extra);
        self.command(&arguments)
    }

    fn evaluate(&self, at: i64) -> Value {
        let output = self.evaluate_at(at, &[]);
        assert!(
            matches!(output.status.code(), Some(0 | 3)),
            "pass failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        self.report()
    }

    fn report(&self) -> Value {
        serde_json::from_slice(&fs::read(self.path("state/report.json")).unwrap()).unwrap()
    }

    fn state(&self) -> Value {
        serde_json::from_slice(&fs::read(self.path("state/state.json")).unwrap()).unwrap()
    }

    fn calls(&self) -> Vec<String> {
        fs::read_to_string(self.path("fake/calls.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn fake(&self, name: &str, content: &str) {
        fs::write(self.path("fake").join(name), content).unwrap();
    }

    fn submitted_intent(&self, id: &str) -> Vec<u8> {
        fs::read(self.path("fake/intents").join(format!("{id}.json"))).unwrap()
    }
}

/// Status with `state`, generated 5 s before `at` (beyond the 1 s clock
/// uncertainty) and fresh for five minutes.
fn set(harness: &Harness, label: &str, state: ProjectedStateV1, at: i64) {
    publish(&harness.root(label), &status_object(state, at - 5, 300));
}

fn intents(report: &Value) -> Vec<(String, String, String)> {
    report["intents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|intent| {
            (
                intent["condition_id"].as_str().unwrap().to_owned(),
                intent["route_role"].as_str().unwrap().to_owned(),
                intent["action"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

const UNKNOWN_ROOT: &str = "constellation:labelwatch:host_posture:host-posture-unknown:root";

#[test]
fn persistence_bound_trigger_continue_recover_resolve() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    // Unknown begins at T0; bound is 600 s.
    for offset in [0, 300, 600] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        let report = harness.evaluate(T0 + offset);
        assert!(intents(&report).is_empty(), "below bound at +{offset}");
    }
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 660);
    let report = harness.evaluate(T0 + 660);
    assert_eq!(
        intents(&report),
        vec![
            (UNKNOWN_ROOT.into(), "notice".into(), "trigger".into()),
            (UNKNOWN_ROOT.into(), "page".into(), "trigger".into()),
        ]
    );
    for offset in [720, 780] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        assert!(intents(&harness.evaluate(T0 + offset)).is_empty());
    }
    // Recovery: needs 120 s of clear before the one resolve.
    for offset in [840, 900] {
        set(&harness, "root", ProjectedStateV1::Healthy, T0 + offset);
        assert!(intents(&harness.evaluate(T0 + offset)).is_empty());
    }
    set(&harness, "root", ProjectedStateV1::Healthy, T0 + 960);
    let report = harness.evaluate(T0 + 960);
    assert_eq!(
        intents(&report),
        vec![
            (UNKNOWN_ROOT.into(), "notice".into(), "resolve".into()),
            (UNKNOWN_ROOT.into(), "page".into(), "resolve".into()),
        ]
    );
    set(&harness, "root", ProjectedStateV1::Healthy, T0 + 1020);
    assert!(intents(&harness.evaluate(T0 + 1020)).is_empty());
    let calls = harness.calls();
    assert_eq!(calls.len(), 4, "{calls:?}");
    assert!(calls[0].contains("labelwatch-host-posture-unknown-root-trigger-1790943060"));
    assert!(calls[2].contains("labelwatch-host-posture-unknown-root-resolve-1790943360"));
    // The resolved condition is forgotten; the intent files go with it.
    assert!(
        harness.state()["conditions"]
            .as_object()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn below_bound_presence_is_reset_by_a_clear_pass() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    set(&harness, "root", ProjectedStateV1::Unknown, T0);
    harness.evaluate(T0);
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 500);
    harness.evaluate(T0 + 500);
    set(&harness, "root", ProjectedStateV1::Healthy, T0 + 560);
    harness.evaluate(T0 + 560);
    for offset in [620, 900, 1200] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        assert!(intents(&harness.evaluate(T0 + offset)).is_empty());
    }
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 1260);
    assert_eq!(intents(&harness.evaluate(T0 + 1260)).len(), 2);
}

#[test]
fn flap_within_confirmation_window_sends_nothing() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    for offset in [0, 660] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    assert_eq!(harness.calls().len(), 2);
    for (offset, state) in [
        (720, ProjectedStateV1::Healthy),
        (780, ProjectedStateV1::Unknown),
        (840, ProjectedStateV1::Healthy),
        (900, ProjectedStateV1::Unknown),
        (960, ProjectedStateV1::Unknown),
    ] {
        set(&harness, "root", state, T0 + offset);
        assert!(
            intents(&harness.evaluate(T0 + offset)).is_empty(),
            "+{offset}"
        );
    }
    assert_eq!(harness.calls().len(), 2);
    assert_eq!(harness.state()["conditions"][UNKNOWN_ROOT]["active"], true);
}

#[test]
fn stale_current_is_unknown_and_never_disk_pressure() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    // Degraded but published once (T0-5) and fresh for 300 s only.
    publish(
        &harness.root("root"),
        &status_object(ProjectedStateV1::Degraded, T0 - 5, 300),
    );
    let mut last = Value::Null;
    for offset in (0..=1500).step_by(60) {
        last = harness.evaluate(T0 + offset);
    }
    let triggered: Vec<_> = harness
        .calls()
        .iter()
        .filter(|call| call.contains("-trigger-"))
        .map(|call| call.split(' ').nth(2).unwrap().to_owned())
        .collect();
    // host-disk (900 s) would fire at +960 on current data but never fires on
    // stale data; stale CURRENT pages as host-posture-unknown (stale from
    // +300, beyond 600 s at +960), and the newest status is older than 600 s
    // from +600, actionable after 300 s more (+960).
    assert!(
        triggered.iter().all(|event| !event.contains("host-disk")),
        "{triggered:?}"
    );
    assert!(
        triggered
            .iter()
            .any(|event| event == "labelwatch-host-posture-unknown-root-trigger-1790943360"),
        "{triggered:?}"
    );
    assert!(
        triggered
            .iter()
            .any(|event| event == "labelwatch-nq-no-fresh-acquisition-root-trigger-1790943360"),
        "{triggered:?}"
    );
    assert_eq!(last["inputs"][0]["status"], "not_current");
}

#[test]
fn host_disk_is_a_notice_by_default() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    for offset in (0..=960).step_by(60) {
        set(&harness, "root", ProjectedStateV1::Degraded, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    let calls = harness.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert!(calls[0].starts_with("submit operations labelwatch-host-disk-root-trigger-"));
}

fn golden(name: &str, bytes: &[u8]) {
    let path = Path::new(FIXTURES).join("golden").join(name);
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        fs::write(&path, bytes).unwrap();
    }
    let expected = fs::read(&path).unwrap();
    assert_eq!(
        String::from_utf8_lossy(bytes),
        String::from_utf8_lossy(&expected),
        "golden {name}"
    );
}

#[test]
fn golden_intents_trigger_and_resolve_v2_and_v1() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    for offset in [0, 660, 720, 840] {
        let state = if offset < 700 {
            ProjectedStateV1::Unknown
        } else {
            ProjectedStateV1::Healthy
        };
        set(&harness, "root", state, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    let calls = harness.calls();
    assert_eq!(calls.len(), 4, "{calls:?}");
    let id = |index: usize| calls[index].split(' ').nth(3).unwrap().to_owned();
    // Calls run notice then page within one action (role order).
    golden("trigger-notice-v1.json", &harness.submitted_intent(&id(0)));
    golden("trigger-page-v2.json", &harness.submitted_intent(&id(1)));
    golden("resolve-notice-v1.json", &harness.submitted_intent(&id(2)));
    golden("resolve-page-v2.json", &harness.submitted_intent(&id(3)));
    let trigger: Value = serde_json::from_slice(&harness.submitted_intent(&id(1))).unwrap();
    assert_eq!(trigger["condition"]["target_class"], "root");
    assert_eq!(trigger["destination_identity"], "pagerduty:pagerduty-ops");
    assert_eq!(
        trigger["runbook_url"],
        "https://docs.example.org/beta-observability/RUNBOOKS.md#host-posture-unknown"
    );
    // Canonical: re-encoding with JCS reproduces the bytes exactly.
    assert_eq!(
        serde_jcs::to_vec(&trigger).unwrap(),
        harness.submitted_intent(&id(1))
    );
}

#[test]
fn sink_failure_keeps_semantic_state_and_resends_newest_later() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    harness.fake("next_state", "failed");
    for offset in [0, 660] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    let state = harness.state();
    let condition = &state["conditions"][UNKNOWN_ROOT];
    assert_eq!(condition["active"], true);
    assert_eq!(condition["first_seen"], T0);
    assert_eq!(condition["last_intent"]["page"]["outcome"], "failed");
    let output = harness.evaluate_at(T0 + 720, &[]);
    assert_eq!(
        output.status.code(),
        Some(3),
        "a failed delivery stays visible"
    );
    // Not yet: the resend interval is 900 s after the attempt at +660.
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 1500);
    harness.evaluate(T0 + 1500);
    assert_eq!(harness.calls().len(), 2);
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 1600);
    harness.fake("next_state", "accepted");
    let report = harness.evaluate(T0 + 1600);
    assert_eq!(harness.calls().len(), 2 + 2);
    let calls = harness.calls();
    assert_eq!(
        calls[2],
        "submit operations labelwatch-host-posture-unknown-root-trigger-1790944000 n3 accepted new"
    );
    assert_eq!(
        calls[3],
        "resubmit n2 labelwatch-host-posture-unknown-root-trigger-1790944000 n4 accepted"
    );
    assert_eq!(report["intents"][1]["operation"], "resubmit");
    assert_eq!(report["intents"][1]["retry_of"], "n2");
    let state = harness.state();
    let condition = &state["conditions"][UNKNOWN_ROOT];
    assert_eq!(
        condition["first_seen"], T0,
        "sink outcome never moves first_seen"
    );
    assert_eq!(condition["last_intent"]["page"]["outcome"], "accepted");
    assert_eq!(
        condition["last_intent"]["page"]["transition_id"],
        "labelwatch-host-posture-unknown-root-trigger-1790943060"
    );
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 3000);
    harness.evaluate(T0 + 3000);
    assert_eq!(
        harness.calls().len(),
        4,
        "accepted records are never resent"
    );
}

#[test]
fn uncertain_notice_is_never_resent_but_pagerduty_is() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    harness.fake("next_state", "unknown");
    for offset in [0, 660, 1600] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    let calls = harness.calls();
    assert_eq!(calls.len(), 3, "{calls:?}");
    assert!(calls[2].starts_with("resubmit n2 "));
}

#[test]
fn crash_before_retention_resubmits_the_same_event() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    set(&harness, "root", ProjectedStateV1::Unknown, T0);
    harness.evaluate(T0);
    harness.fake("crash", "");
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 660);
    let output = harness.evaluate_at(T0 + 660, &[]);
    assert_eq!(output.status.code(), None, "the pass was killed");
    let state = harness.state();
    let page = &state["conditions"][UNKNOWN_ROOT]["last_intent"]["notice"];
    assert_eq!(page["outcome"], "unknown");
    assert_eq!(page["notification_id"], Value::Null);
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 720);
    let report = harness.evaluate(T0 + 720);
    assert_eq!(report["intents"][0]["operation"], "submit_again");
    let events: Vec<String> = harness
        .calls()
        .iter()
        .map(|call| call.split(' ').nth(2).unwrap().to_owned())
        .collect();
    assert!(
        events
            .iter()
            .all(|event| event == "labelwatch-host-posture-unknown-root-trigger-1790943060"),
        "{events:?}"
    );
    assert_eq!(events.len(), 2, "notice and page, once each");
}

#[test]
fn crash_after_retention_converges_on_the_retained_record() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    set(&harness, "root", ProjectedStateV1::Unknown, T0);
    harness.evaluate(T0);
    harness.fake("crash_after", "");
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 660);
    assert_eq!(harness.evaluate_at(T0 + 660, &[]).status.code(), None);
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 720);
    harness.evaluate(T0 + 720);
    let calls = harness.calls();
    assert_eq!(calls.len(), 3, "{calls:?}");
    // +660: notice retained, then the pass died. +720: the notice converges
    // on its retained record and the page is submitted for the first time.
    assert!(calls[0].ends_with(" new"));
    assert!(calls[1].ends_with(" existing"), "{calls:?}");
    assert!(calls[2].starts_with("submit pagerduty-ops ") && calls[2].ends_with(" new"));
    assert_eq!(calls[0].split(' ').nth(2), calls[1].split(' ').nth(2));
    assert_eq!(calls[0].split(' ').nth(2), calls[2].split(' ').nth(2));
    let state = harness.state();
    assert_eq!(
        state["conditions"][UNKNOWN_ROOT]["last_intent"]["notice"]["notification_id"],
        "n1"
    );
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 780);
    harness.evaluate(T0 + 780);
    assert_eq!(harness.calls().len(), 3, "never double-triggered");
}

#[test]
fn dry_run_calls_nothing_and_keeps_state() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    set(&harness, "root", ProjectedStateV1::Unknown, T0);
    harness.evaluate(T0);
    let before = fs::read(harness.path("state/state.json")).unwrap();
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 660);
    let output = harness.evaluate_at(T0 + 660, &["--dry-run"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(harness.calls().is_empty());
    assert_eq!(fs::read(harness.path("state/state.json")).unwrap(), before);
    let report: Value =
        serde_json::from_slice(&fs::read(harness.path("state/dry-run/report.json")).unwrap())
            .unwrap();
    assert_eq!(report["dry_run"], true);
    assert_eq!(report["intents"].as_array().unwrap().len(), 2);
    assert_eq!(report["intents"][0]["outcome"], "not_submitted");
    let written = fs::read_dir(harness.path("state/dry-run/intents"))
        .unwrap()
        .count();
    assert_eq!(written, 2);
    // The real pass afterwards still triggers.
    assert_eq!(intents(&harness.evaluate(T0 + 660)).len(), 2);
}

#[test]
fn unreadable_input_is_a_notice_and_never_pages() {
    let mut harness = Harness::new();
    let store = harness.path("missing/nightshift.sqlite");
    harness.raw(&format!(
        "[inputs.nightshift]\nlabel = \"observation\"\nstore_path = \"{}\"\n",
        store.display()
    ));
    for offset in (0..=420).step_by(60) {
        harness.evaluate(T0 + offset);
    }
    let calls = harness.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert!(calls[0].starts_with(
        "submit operations labelwatch-evaluator-input-unavailable-observation-trigger-"
    ));
    let intent: Value = serde_json::from_slice(&harness.submitted_intent("n1")).unwrap();
    assert_eq!(intent["schema"], "nq.notification_delivery_intent.v1");
    assert!(
        intent["summary"].as_str().unwrap().contains(
            "constellation:labelwatch:nightshift:evaluator-input-unavailable:observation"
        )
    );
}

#[test]
fn triggers_are_ordered_before_resolves_one_intent_per_condition() {
    let mut harness = Harness::new();
    harness.host_posture("alpha").host_posture("beta");
    // alpha: unknown from T0, triggers at +660, clear from +720, resolves at +840.
    // beta: unknown from +180, triggers at +840.
    for offset in (0..=840).step_by(60) {
        let alpha = if offset < 720 {
            ProjectedStateV1::Unknown
        } else {
            ProjectedStateV1::Healthy
        };
        let beta = if offset >= 180 {
            ProjectedStateV1::Unknown
        } else {
            ProjectedStateV1::Healthy
        };
        set(&harness, "alpha", alpha, T0 + offset);
        set(&harness, "beta", beta, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    let report = harness.report();
    let alpha = "constellation:labelwatch:host_posture:host-posture-unknown:alpha";
    let beta = "constellation:labelwatch:host_posture:host-posture-unknown:beta";
    assert_eq!(
        intents(&report),
        vec![
            (beta.into(), "notice".into(), "trigger".into()),
            (beta.into(), "page".into(), "trigger".into()),
            (alpha.into(), "notice".into(), "resolve".into()),
            (alpha.into(), "page".into(), "resolve".into()),
        ]
    );
}

#[test]
fn service_down_from_nq_status_export() {
    let mut harness = Harness::new();
    let status = harness.path("nq-status.json");
    harness.raw(&format!(
        "[inputs.nq_status]\nlabel = \"nqd\"\npath = \"{}\"\n",
        status.display()
    ));
    let fixture: Value = serde_json::from_slice(
        &fs::read(Path::new(FIXTURES).join("nq-status-export-unit-failed.json")).unwrap(),
    )
    .unwrap();
    for offset in (0..=240).step_by(60) {
        let mut value = fixture.clone();
        value["generated_at"] = json!(rfc3339(T0 + offset));
        for component in value["components"].as_array_mut().unwrap() {
            if component["kind"] == "evaluation" {
                component["detail"]["result"]["evaluated_at"] = json!(rfc3339(T0 + offset - 10));
            }
        }
        fs::write(&status, serde_json::to_vec(&value).unwrap()).unwrap();
        harness.evaluate(T0 + offset);
    }
    let calls = harness.calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    let intent: Value = serde_json::from_slice(&harness.submitted_intent("n2")).unwrap();
    assert_eq!(
        intent["condition"],
        json!({"component":"service","rule":"service-down","site":"labelwatch","target_class":"nqd.service"})
    );
    assert_eq!(intent["details"]["input"]["instance_id"], "unit-nqd");
    // Memory pressure is explicitly absent: no condition opened.
    assert!(
        !harness.state()["conditions"]
            .as_object()
            .unwrap()
            .keys()
            .any(|key| key.contains("memory-pressure"))
    );
    // A stale export holds state and raises the input notice, nothing else.
    let report = harness.evaluate(T0 + 1000);
    assert_eq!(report["inputs"][0]["status"], "not_current");
    assert!(intents(&report).is_empty());
}

#[test]
fn nightshift_recurrence_missing_from_scratch_store() {
    let mut harness = Harness::new();
    let store = harness.path("nightshift.sqlite");
    let connection = rusqlite::Connection::open(&store).unwrap();
    connection
        .execute_batch(
            &fs::read_to_string(Path::new(FIXTURES).join("nightshift-schema.sql")).unwrap(),
        )
        .unwrap();
    for (index, (status, at)) in [
        ("closed", T0 - 600),
        ("closed", T0 - 300),
        ("missed", T0 - 1),
    ]
    .into_iter()
    .enumerate()
    {
        connection
            .execute(
                "INSERT INTO canonical_recurrence_slots VALUES (?1, ?2, 'done', '{}', 'd', ?3)",
                (
                    format!("slot-{index}"),
                    format!("cycle-{index}"),
                    rfc3339(at),
                ),
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO canonical_observation_cycles VALUES (?1, ?2, 1, ?3, 'd', '{}', ?4)",
                (
                    format!("cycle-{index}"),
                    format!("slot-{index}"),
                    status,
                    rfc3339(at),
                ),
            )
            .unwrap();
    }
    drop(connection);
    harness.raw(&format!(
        "[inputs.nightshift]\nlabel = \"observation\"\nstore_path = \"{}\"\n",
        store.display()
    ));
    // Last closed at T0-300: older than 1800 s from T0+1501; actionable after 300 s more.
    let report = harness.evaluate(T0 + 1560);
    assert_eq!(report["inputs"][0]["identity"]["cycle_id"], "cycle-1");
    assert!(intents(&report).is_empty());
    harness.evaluate(T0 + 1800);
    assert!(harness.calls().is_empty());
    let report = harness.evaluate(T0 + 1870);
    assert_eq!(intents(&report).len(), 2);
    assert!(
        harness.calls()[1]
            .contains("labelwatch-nightshift-recurrence-missing-observation-trigger-")
    );
}

#[test]
fn sqlite_health_from_saved_check_result() {
    let mut harness = Harness::new();
    let result = harness.path("freelist.json");
    harness.raw(&format!(
        "[[inputs.saved_checks]]\nreference = \"atproto-freelist\"\npath = \"{}\"\n",
        result.display()
    ));
    let failed =
        fs::read_to_string(Path::new(FIXTURES).join("saved-check-result-failed.json")).unwrap();
    fs::write(&result, &failed).unwrap();
    // read_attempted_at is 2026-10-02T11:55:01Z; bound 600 s of persistence.
    harness.evaluate(T0);
    harness.evaluate(T0 + 600);
    assert!(harness.calls().is_empty());
    harness.evaluate(T0 + 660);
    let calls = harness.calls();
    assert_eq!(calls.len(), 1, "notice only: {calls:?}");
    assert!(
        calls[0]
            .starts_with("submit operations labelwatch-sqlite-health-atproto-freelist-trigger-")
    );
    fs::copy(
        Path::new(FIXTURES).join("saved-check-result-passed.json"),
        &result,
    )
    .unwrap();
    harness.evaluate(T0 + 720);
    harness.evaluate(T0 + 840);
    assert!(harness.calls()[1].contains("-resolve-"));
}

#[test]
fn network_disabled_retains_refusals_without_resending() {
    let mut harness = Harness::new();
    harness.network = false;
    harness.host_posture("root");
    for offset in [0, 660] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 3000);
    let output = harness.evaluate_at(T0 + 3000, &[]);
    assert_eq!(output.status.code(), Some(0));
    let calls = harness.calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert!(calls.iter().all(|call| call.contains(" refused ")));
}

#[test]
fn command_error_is_recorded_and_retried_with_the_same_bytes() {
    let mut harness = Harness::new();
    harness.page_route = false;
    harness.host_posture("root");
    harness.fake("command_error", "");
    for offset in [0, 660] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    let state = harness.state();
    assert_eq!(
        state["conditions"][UNKNOWN_ROOT]["last_intent"]["notice"]["outcome"],
        "command_error"
    );
    fs::remove_file(harness.path("fake/command_error")).unwrap();
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 1600);
    harness.evaluate(T0 + 1600);
    let calls = harness.calls();
    assert_eq!(calls.len(), 1);
    assert!(calls[0].contains("labelwatch-host-posture-unknown-root-trigger-1790943060"));
}

#[test]
fn check_config_rejects_digest_like_labels_and_forbidden_pages() {
    let mut harness = Harness::new();
    harness.raw(&format!(
        "[[inputs.host_posture]]\nlabel = \"sha256-root\"\npublication_root = \"{}\"\n",
        harness.root("x").display()
    ));
    let config = harness.config_path();
    let output = harness.command(&["check-config", "--config", config.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("looks like a digest"));

    let mut harness = Harness::new();
    harness.raw("[rules.memory-pressure]\nclass = \"page\"\n");
    let config = harness.config_path();
    let output = harness.command(&["check-config", "--config", config.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("may not page"));

    let mut harness = Harness::new();
    harness.raw("[rules.docket-unsettled]\nenabled = true\n");
    let config = harness.config_path();
    let output = harness.command(&["check-config", "--config", config.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("input not deployed"));

    let mut harness = Harness::new();
    harness.host_posture("root");
    harness.raw("[rules.host-disk]\nclass = \"page\"\nthreshold_seconds = 1800\n");
    let config = harness.config_path();
    let output = harness.command(&["check-config", "--config", config.to_str().unwrap()]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rules_lists_the_closed_registry() {
    let harness = Harness::new();
    let output = harness.command(&["rules"]);
    assert_eq!(output.status.code(), Some(0));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    let ids: Vec<&str> = value["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|rule| rule["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        [
            "host-posture-unknown",
            "host-disk",
            "nq-no-fresh-acquisition",
            "service-down",
            "memory-pressure",
            "nightshift-recurrence-missing",
            "sqlite-health",
            "evaluator-input-unavailable",
            "docket-unsettled",
            "ag-executor-unavailable",
        ]
    );
    assert_eq!(value["rules"][8]["disabled"], "input not deployed");
}

#[test]
fn state_round_trips_across_processes() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    for offset in [0, 660, 720] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    let path = harness.path("state/state.json");
    let state = constellation_attention::state::State::load(&path, "labelwatch").unwrap();
    state.save(&path).unwrap();
    let reloaded = constellation_attention::state::State::load(&path, "labelwatch").unwrap();
    assert_eq!(state, reloaded);
    let config = harness.config_path();
    let output = harness.command(&["state", "--config", config.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0));
    // A corrupt state file stops the pass instead of being replaced.
    fs::write(&path, b"{not json").unwrap();
    let output = harness.evaluate_at(T0 + 780, &[]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(fs::read(&path).unwrap(), b"{not json");
}

#[test]
fn host_posture_fixture_objects_decode() {
    let dir = Path::new(FIXTURES).join("host-posture");
    for (name, state) in [
        ("healthy", ProjectedStateV1::Healthy),
        ("degraded", ProjectedStateV1::Degraded),
        ("unknown", ProjectedStateV1::Unknown),
    ] {
        let bytes = status_object(state, T0, 300).canonical_bytes().unwrap();
        golden(&format!("../host-posture/{name}.json"), &bytes);
        StatusArtifactV1::decode_canonical(&fs::read(dir.join(format!("{name}.json"))).unwrap())
            .unwrap();
    }
}

#[test]
fn packaged_example_configuration_is_valid() {
    let text = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../packaging/attention/attention.toml.example"),
    )
    .unwrap();
    let config: constellation_attention::config::Config = toml::from_str(&text).unwrap();
    config.validate().unwrap();
    assert_eq!(config.site, "labelwatch");
    assert!(!config.routes.network_enabled);
}
