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
    notice_transport: &'static str,
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
            notice_transport: "slack",
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
             site = \"reference\"\n\
             state_path = \"{state}\"\n\
             [runbooks]\n\
             cartography_url = \"https://docs.example.org/beta-observability/RUNBOOKS.md\"\n\
             [nq]\n\
             program = \"{nq}\"\n\
             config = \"/etc/nq/nqd-ops.toml\"\n\
             [routes]\n\
             notice_route = \"operations\"\n\
             notice_transport = \"{transport}\"\n\
             {page}\
             network_enabled = {network}\n\
             {extra}\n",
            state = self.path("state/state.json").display(),
            nq = Path::new(FIXTURES).join("fake-nq.sh").display(),
            network = self.network,
            transport = self.notice_transport,
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

const UNKNOWN_ROOT: &str = "constellation:reference:host_posture:host-posture-unknown:root";

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
    assert!(calls[0].contains("reference-host-posture-unknown-root-trigger-1790943060"));
    assert!(calls[2].contains("reference-host-posture-unknown-root-resolve-1790943360"));
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
            .any(|event| event == "reference-host-posture-unknown-root-trigger-1790943360"),
        "{triggered:?}"
    );
    assert!(
        triggered
            .iter()
            .any(|event| event == "reference-nq-no-fresh-acquisition-root-trigger-1790943360"),
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
    assert!(calls[0].starts_with("submit operations reference-host-disk-root-trigger-"));
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
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 720);
    let output = harness.evaluate_at(T0 + 720, &[]);
    assert_eq!(
        output.status.code(),
        Some(3),
        "a failed delivery stays visible"
    );
    assert_eq!(harness.calls().len(), 2, "not yet: 60 s after the attempt");
    // PagerDuty is resubmitted 120 s after the failed attempt.
    harness.fake("next_state", "accepted");
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 780);
    let report = harness.evaluate(T0 + 780);
    let calls = harness.calls();
    assert_eq!(calls.len(), 3, "{calls:?}");
    assert_eq!(
        calls[2],
        "resubmit n2 reference-host-posture-unknown-root-trigger-1790943180 n3 accepted"
    );
    assert_eq!(report["intents"][0]["operation"], "resubmit");
    assert_eq!(report["intents"][0]["retry_of"], "n2");
    // The Slack notice waits the full 900 s after its failed attempt.
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 1500);
    harness.evaluate(T0 + 1500);
    assert_eq!(harness.calls().len(), 3);
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 1560);
    harness.evaluate(T0 + 1560);
    let calls = harness.calls();
    assert_eq!(
        calls[3],
        "submit operations reference-host-posture-unknown-root-trigger-1790943960 n4 accepted new"
    );
    let state = harness.state();
    let condition = &state["conditions"][UNKNOWN_ROOT];
    assert_eq!(
        condition["first_seen"], T0,
        "sink outcome never moves first_seen"
    );
    assert_eq!(condition["last_intent"]["page"]["outcome"], "accepted");
    assert_eq!(
        condition["last_intent"]["page"]["transition_id"],
        "reference-host-posture-unknown-root-trigger-1790943060"
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
            .all(|event| event == "reference-host-posture-unknown-root-trigger-1790943060"),
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
        "submit operations reference-evaluator-input-unavailable-observation.unreadable-trigger-"
    ));
    let intent: Value = serde_json::from_slice(&harness.submitted_intent("n1")).unwrap();
    assert_eq!(intent["schema"], "nq.notification_delivery_intent.v1");
    assert!(intent["summary"].as_str().unwrap().contains(
        "constellation:reference:nightshift:evaluator-input-unavailable:observation.unreadable"
    ));
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
    let alpha = "constellation:reference:host_posture:host-posture-unknown:alpha";
    let beta = "constellation:reference:host_posture:host-posture-unknown:beta";
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

fn nq_status_harness() -> (Harness, PathBuf) {
    let mut harness = Harness::new();
    let status = harness.path("nq-status.json");
    harness.raw(&format!(
        "[inputs.nq_status]\nlabel = \"nqd\"\npath = \"{}\"\n",
        status.display()
    ));
    (harness, status)
}

fn use_sample(status: &Path, name: &str) {
    fs::copy(Path::new(FIXTURES).join("nq-status").join(name), status).unwrap();
}

fn at(value: &str) -> i64 {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .unwrap()
        .unix_timestamp()
}

/// Real `nq --json status export` samples from the nqd-ops spike (nq 0.2.1):
/// cron.service stopped, then started again.
#[test]
fn service_down_from_real_nq_status_export() {
    let (harness, status) = nq_status_harness();
    use_sample(&status, "healthy.json");
    let report = harness.evaluate(at("2026-10-02T21:31:10Z"));
    assert_eq!(report["inputs"][0]["status"], "ok");
    assert!(intents(&report).is_empty());
    use_sample(&status, "cron-down.json");
    for time in [
        "2026-10-02T21:32:20Z",
        "2026-10-02T21:34:20Z",
        "2026-10-02T21:35:20Z",
    ] {
        assert!(intents(&harness.evaluate(at(time))).is_empty(), "{time}");
    }
    // Present since 21:32:20; beyond the 180 s bound at 21:35:30.
    let report = harness.evaluate(at("2026-10-02T21:35:30Z"));
    let cron = "constellation:reference:service:service-down:cron.service";
    assert_eq!(
        intents(&report),
        vec![
            (cron.into(), "notice".into(), "trigger".into()),
            (cron.into(), "page".into(), "trigger".into()),
        ]
    );
    let intent: Value = serde_json::from_slice(&harness.submitted_intent("n2")).unwrap();
    assert_eq!(
        intent["condition"],
        json!({"component":"service","rule":"service-down","site":"reference","target_class":"cron.service"})
    );
    assert_eq!(intent["details"]["input"]["instance_id"], "unit-cron");
    assert_eq!(
        intent["details"]["input"]["collected_at"],
        "2026-10-02T21:32:14Z"
    );
    // ssh stays explicitly absent and memory pressure never opens a condition.
    let state = harness.state();
    let keys: Vec<&String> = state["conditions"].as_object().unwrap().keys().collect();
    assert_eq!(keys, vec![cron], "{keys:?}");
    use_sample(&status, "recovered.json");
    assert!(intents(&harness.evaluate(at("2026-10-02T21:48:40Z"))).is_empty());
    let report = harness.evaluate(at("2026-10-02T21:50:40Z"));
    assert_eq!(
        intents(&report),
        vec![
            (cron.into(), "notice".into(), "resolve".into()),
            (cron.into(), "page".into(), "resolve".into()),
        ]
    );
}

/// The daemon was stopped: the export still answers from the store, but every
/// instance's last collection is 195 s old. That is a stale input (notice),
/// never a page and never a service condition.
#[test]
fn stopped_daemon_is_a_stale_input_notice() {
    let (harness, status) = nq_status_harness();
    use_sample(&status, "daemon-stopped.json");
    let start = at("2026-10-02T21:48:35Z");
    let mut report = Value::Null;
    for offset in (0..=360).step_by(60) {
        report = harness.evaluate(start + offset);
    }
    assert_eq!(report["inputs"][0]["status"], "not_current");
    assert!(
        report["inputs"][0]["error"]
            .as_str()
            .unwrap()
            .contains("unit-cron")
    );
    let calls = harness.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert!(
        calls[0].starts_with(
            "submit operations reference-evaluator-input-unavailable-nqd.stale-trigger-"
        )
    );
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
        harness.calls()[1].contains("reference-nightshift-recurrence-missing-observation-trigger-")
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
        calls[0].starts_with("submit operations reference-sqlite-health-atproto-freelist-trigger-")
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
    assert!(calls[0].contains("reference-host-posture-unknown-root-trigger-1790943060"));
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

    // Page eligibility is the registry's: host-disk (attention) cannot be
    // overridden onto the PagerDuty route, only its threshold tuned.
    let mut harness = Harness::new();
    harness.host_posture("root");
    harness.raw("[rules.host-disk]\nclass = \"page\"\n");
    let config = harness.config_path();
    let output = harness.command(&["check-config", "--config", config.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("rule host-disk may not page: its response class is attention")
    );

    let mut harness = Harness::new();
    harness.host_posture("root");
    harness.raw(
        "[rules.host-disk]\nthreshold_seconds = 1800\n[rules.service-down]\nclass = \"notice\"\n",
    );
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
    let state = constellation_attention::state::State::load(&path, "reference").unwrap();
    state.save(&path).unwrap();
    let reloaded = constellation_attention::state::State::load(&path, "reference").unwrap();
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
    assert_eq!(config.site, "reference");
    assert!(!config.routes.network_enabled);
}

/// A real export re-timed so that it is generated at `t`, with every
/// collection and evaluation at `t - 3`, then edited.
fn retimed(name: &str, t: i64, edit: impl Fn(&mut Value)) -> Value {
    let mut value: Value = serde_json::from_slice(
        &fs::read(Path::new(FIXTURES).join("nq-status").join(name)).unwrap(),
    )
    .unwrap();
    value["generated_at"] = json!(rfc3339(t));
    for component in value["components"].as_array_mut().unwrap() {
        if component["kind"] == "instance" {
            component["observed_at"] = json!(rfc3339(t - 3));
        }
        if component["kind"] == "evaluation" {
            component["detail"]["result"]["evaluated_at"] = json!(rfc3339(t - 3));
        }
    }
    edit(&mut value);
    value
}

fn write_status(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

/// The newest `cron.service` evaluation component of an export.
fn cron_eval(value: &mut Value) -> &mut Value {
    value["components"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .rev()
        .find(|component| {
            component["kind"] == "evaluation"
                && component["detail"]["result"]["context"]["instance_id"] == "unit-cron"
        })
        .unwrap()
}

const CRON: &str = "constellation:reference:service:service-down:cron.service";

/// Drive `cron.service` down until the page triggers; returns the export time
/// of the triggering pass.
fn trigger_cron(harness: &Harness, status: &Path) -> i64 {
    let t = at("2026-10-02T21:32:17Z");
    for offset in [0, 60, 120, 181] {
        write_status(status, &retimed("cron-down.json", t + offset, |_| {}));
        harness.evaluate(t + offset + 3);
    }
    assert_eq!(harness.state()["conditions"][CRON]["active"], true);
    assert_eq!(harness.calls().len(), 2);
    t + 181
}

fn cron_state(state: &'static str) -> impl Fn(&mut Value) {
    move |value: &mut Value| {
        cron_eval(value)["detail"]["result"]["result"]["state"] = json!(state);
    }
}

/// Review A1: the same unit exported under an unrecognised profile version
/// is evidence the evaluator cannot read. The open page holds, the input is
/// not current, and only verified recovery resolves.
#[test]
fn unrecognised_profile_version_holds_an_open_page() {
    let (harness, status) = nq_status_harness();
    let t = trigger_cron(&harness, &status);
    let mut report = Value::Null;
    for offset in (60..=480).step_by(60) {
        let value = retimed("cron-down.json", t + offset, |value| {
            cron_eval(value)["detail"]["result"]["profile"]["profile"]["version"] = json!(3);
        });
        write_status(&status, &value);
        report = harness.evaluate(t + offset + 3);
    }
    let calls = harness.calls();
    assert!(
        calls.iter().all(|call| !call.contains("-resolve-")),
        "{calls:?}"
    );
    assert_eq!(harness.state()["conditions"][CRON]["active"], true);
    assert_eq!(report["inputs"][0]["status"], "not_current");
    let error = report["inputs"][0]["error"].as_str().unwrap();
    assert!(
        error.contains("unrecognised profile \"nq.systemd_unit\" version 3"),
        "{error}"
    );
    assert!(
        calls
            .iter()
            .any(|call| call
                .contains("reference-evaluator-input-unavailable-nqd.unrecognised-trigger-")),
        "{calls:?}"
    );
    // Verified recovery under the recognised profile resolves with the
    // recovery summary.
    let before = harness.calls().len();
    for offset in [540, 600, 660] {
        write_status(
            &status,
            &retimed(
                "cron-down.json",
                t + offset,
                cron_state("explicitly_absent"),
            ),
        );
        harness.evaluate(t + offset + 3);
    }
    let calls = harness.calls();
    let resolves: Vec<&String> = calls[before..]
        .iter()
        .filter(|call| call.contains("service-down-cron.service-resolve-"))
        .collect();
    assert_eq!(resolves.len(), 2, "{calls:?}");
    let id = resolves[1].split(' ').nth(3).unwrap();
    let intent: Value = serde_json::from_slice(&harness.submitted_intent(id)).unwrap();
    assert!(
        intent["summary"]
            .as_str()
            .unwrap()
            .ends_with("underlying state clear for at least 120 s."),
        "{intent}"
    );
}

/// Review A2: a watcher that vanishes from a current export is not a
/// recovery. The page holds and the input reports the missing condition.
#[test]
fn vanished_watcher_holds_an_open_page() {
    let (harness, status) = nq_status_harness();
    let t = trigger_cron(&harness, &status);
    let mut report = Value::Null;
    for offset in (60..=480).step_by(60) {
        let value = retimed("cron-down.json", t + offset, |value| {
            value["components"]
                .as_array_mut()
                .unwrap()
                .retain(|component| {
                    component["id"] != "unit-cron"
                        && component["detail"]["result"]["context"]["instance_id"] != "unit-cron"
                });
        });
        write_status(&status, &value);
        report = harness.evaluate(t + offset + 3);
    }
    let calls = harness.calls();
    assert!(
        calls.iter().all(|call| !call.contains("-resolve-")),
        "{calls:?}"
    );
    assert_eq!(harness.state()["conditions"][CRON]["active"], true);
    assert_eq!(report["inputs"][0]["status"], "not_current");
    assert!(
        report["inputs"][0]["error"]
            .as_str()
            .unwrap()
            .contains("open condition constellation:reference:service:service-down:cron.service is no longer reported"),
        "{}",
        report["inputs"][0]
    );
    let condition = report["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|condition| condition["id"] == CRON)
        .unwrap();
    assert_eq!(condition["observation"], "unknown");
    assert!(
        calls
            .iter()
            .any(|call| call
                .contains("reference-evaluator-input-unavailable-nqd.unreported-trigger-")),
        "{calls:?}"
    );
}

/// Removing a rule from configuration is explicit: the open page resolves at
/// once, and the resolve says recovery was not observed.
#[test]
fn removed_rule_resolves_without_claiming_recovery() {
    let (mut harness, status) = nq_status_harness();
    let t = trigger_cron(&harness, &status);
    harness.raw("[rules.service-down]\nenabled = false\n");
    write_status(&status, &retimed("cron-down.json", t + 60, |_| {}));
    let report = harness.evaluate(t + 63);
    assert_eq!(
        intents(&report),
        vec![
            (CRON.into(), "notice".into(), "resolve".into()),
            (CRON.into(), "page".into(), "resolve".into()),
        ]
    );
    for id in ["n3", "n4"] {
        let intent: Value = serde_json::from_slice(&harness.submitted_intent(id)).unwrap();
        assert!(
            intent["summary"]
                .as_str()
                .unwrap()
                .ends_with(": no longer evaluated; recovery not observed."),
            "{intent}"
        );
    }
}

/// Review A3: a unit whose name maps to no bounded target class makes the
/// input not current (so the operator is told), never a silent skip.
#[test]
fn untargetable_unit_makes_the_input_not_current() {
    let (harness, status) = nq_status_harness();
    let t = at("2026-10-02T21:32:17Z");
    let mut codes = Vec::new();
    for offset in (0..=420).step_by(60) {
        let value = retimed("cron-down.json", t + offset, |value| {
            cron_eval(value)["detail"]["result"]["context"]["subject"] =
                json!("systemd-unit:1853ff04ff7a42679bf212ec9a569c4f/getty@tty1.service");
        });
        write_status(&status, &value);
        codes.push(harness.evaluate_at(t + offset + 3, &[]).status.code());
    }
    assert!(codes.iter().all(|code| *code == Some(3)), "{codes:?}");
    let report = harness.report();
    assert_eq!(report["inputs"][0]["status"], "not_current");
    assert!(
        report["inputs"][0]["error"]
            .as_str()
            .unwrap()
            .contains("\"getty@tty1.service\" (instance \"unit-cron\")")
    );
    let calls = harness.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert!(calls[0].contains("reference-evaluator-input-unavailable-nqd.untargetable-trigger-"));
}

/// Review A4: a trigger the nq command refused before custody is retried on
/// the next pass, not after the 900 s resend interval.
#[test]
fn command_error_trigger_is_retried_on_the_next_pass() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    harness.fake("command_error", "");
    for offset in [0, 660] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    assert!(harness.calls().is_empty());
    fs::remove_file(harness.path("fake/command_error")).unwrap();
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 720);
    let report = harness.evaluate(T0 + 720);
    assert_eq!(report["intents"][0]["operation"], "submit_again");
    let calls = harness.calls();
    assert_eq!(
        calls,
        vec![
            "submit operations reference-host-posture-unknown-root-trigger-1790943060 n1 accepted new",
            "submit pagerduty-ops reference-host-posture-unknown-root-trigger-1790943060 n2 accepted new",
        ]
    );
    for offset in [1260, 1320, 1380] {
        set(&harness, "root", ProjectedStateV1::Healthy, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    let calls = harness.calls();
    assert_eq!(calls.len(), 4, "{calls:?}");
    assert!(calls[2].contains("-resolve-") && calls[3].contains("-resolve-"));
}

/// Review A4: when the resolve is decided while the trigger was never
/// retained, the trigger goes first in that pass.
#[test]
fn resolve_sends_a_never_retained_trigger_first() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    harness.fake("command_error", "");
    for offset in (0..=1200).step_by(60) {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    for offset in [1260, 1320] {
        set(&harness, "root", ProjectedStateV1::Healthy, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    assert!(harness.calls().is_empty());
    fs::remove_file(harness.path("fake/command_error")).unwrap();
    set(&harness, "root", ProjectedStateV1::Healthy, T0 + 1380);
    let report = harness.evaluate(T0 + 1380);
    let operations: Vec<(&str, &str)> = report["intents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|intent| {
            (
                intent["action"].as_str().unwrap(),
                intent["operation"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        operations,
        vec![
            ("trigger", "submit_before_resolve"),
            ("trigger", "submit_before_resolve"),
            ("resolve", "submit"),
            ("resolve", "submit"),
        ]
    );
    let calls = harness.calls();
    assert_eq!(
        calls,
        vec![
            "submit operations reference-host-posture-unknown-root-trigger-1790943060 n1 accepted new",
            "submit pagerduty-ops reference-host-posture-unknown-root-trigger-1790943060 n2 accepted new",
            "submit operations reference-host-posture-unknown-root-resolve-1790943780 n3 accepted new",
            "submit pagerduty-ops reference-host-posture-unknown-root-resolve-1790943780 n4 accepted new",
        ]
    );
    assert_eq!(report["dropped_triggers"], json!([]));
    assert!(
        harness.state()["conditions"]
            .as_object()
            .unwrap()
            .is_empty()
    );
}

/// Review A4: a trigger NQ still refuses when its resolve goes out is
/// reported as dropped and the pass exits non-zero; it is never sent after
/// the resolve.
#[test]
fn never_retained_trigger_is_reported_as_dropped() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    harness.fake("command_error", "");
    for offset in [0, 660] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    for offset in [720, 840] {
        set(&harness, "root", ProjectedStateV1::Healthy, T0 + offset);
        let output = harness.evaluate_at(T0 + offset, &[]);
        assert_eq!(output.status.code(), Some(3));
    }
    let report = harness.report();
    let dropped = report["dropped_triggers"].as_array().unwrap();
    assert_eq!(dropped.len(), 2, "{report}");
    assert_eq!(
        dropped[0]["stable_event_id"],
        "reference-host-posture-unknown-root-trigger-1790943060"
    );
    assert_eq!(dropped[0]["outcome"], "command_error");
    fs::remove_file(harness.path("fake/command_error")).unwrap();
    for offset in [900, 960, 1800] {
        set(&harness, "root", ProjectedStateV1::Healthy, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    let calls = harness.calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert!(
        calls
            .iter()
            .all(|call| call.contains("-resolve-1790943240"))
    );
}

/// Review A5: a missing retained intent file fails only its follow-up. A
/// PagerDuty resubmit needs only NQ's record id and still goes out (second
/// review N-b); a Slack resend needs the bytes and is reported unreadable.
#[test]
fn missing_intent_file_fails_only_its_follow_up() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    harness.host_posture("data");
    harness.fake("next_state", "failed");
    set(&harness, "data", ProjectedStateV1::Healthy, T0);
    for offset in [0, 660] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    for role in ["page", "notice"] {
        let file = harness.state()["conditions"][UNKNOWN_ROOT]["last_intent"][role]["intent_file"]
            .as_str()
            .unwrap()
            .to_owned();
        fs::remove_file(harness.path("state/intents").join(file)).unwrap();
    }
    harness.fake("next_state", "accepted");
    let mut last = None;
    for offset in (720..=2400).step_by(60) {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        set(&harness, "data", ProjectedStateV1::Unknown, T0 + offset);
        let output = harness.evaluate_at(T0 + offset, &[]);
        assert_eq!(output.status.code(), Some(3), "+{offset}");
        last = Some(output);
    }
    let stderr = String::from_utf8_lossy(&last.unwrap().stderr).into_owned();
    assert!(stderr.contains("outcome=intent_unreadable"), "{stderr}");
    let data = "reference-host-posture-unknown-data-trigger-";
    let calls = harness.calls();
    assert_eq!(
        calls.iter().filter(|call| call.contains(data)).count(),
        2,
        "the second condition is still notified: {calls:?}"
    );
    assert!(
        calls
            .iter()
            .any(|call| call.starts_with("resubmit n2 ") && call.ends_with(" accepted")),
        "{calls:?}"
    );
    let report = harness.report();
    assert!(
        report["intents"]
            .as_array()
            .unwrap()
            .iter()
            .any(|intent| intent["outcome"] == "intent_unreadable")
    );
}

/// Review A7: a pass whose clock is earlier than the last completed pass is
/// refused, so an event identity is never replayed for a new incident.
#[test]
fn clock_regression_is_refused() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    for offset in [0, 660] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    for offset in [720, 840] {
        set(&harness, "root", ProjectedStateV1::Healthy, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    assert_eq!(harness.calls().len(), 4);
    let state = fs::read(harness.path("state/state.json")).unwrap();
    for offset in [0, 660] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        for extra in [&[][..], &["--dry-run"][..]] {
            let output = harness.evaluate_at(T0 + offset, extra);
            assert_eq!(output.status.code(), Some(1));
            assert!(String::from_utf8_lossy(&output.stderr).contains("the clock moved backwards"));
        }
    }
    assert_eq!(harness.calls().len(), 4);
    assert_eq!(fs::read(harness.path("state/state.json")).unwrap(), state);
}

/// Review A11: a CURRENT naming another projection that writes the same
/// status object schema is unavailable, never read as disk pressure.
#[test]
fn foreign_projection_is_unavailable() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    let mut report = Value::Null;
    for offset in (0..=960).step_by(60) {
        let mut artifact = status_object(ProjectedStateV1::Degraded, T0 + offset - 5, 300);
        artifact.projection_id = "operator-memory-pressure".into();
        artifact.projection_generation = "memory-pressure-v1".into();
        artifact.components[0].id = "memory-pressure".into();
        artifact.artifact_id = artifact.compute_id().unwrap();
        publish(&harness.root("root"), &artifact);
        report = harness.evaluate(T0 + offset);
    }
    assert_eq!(report["inputs"][0]["status"], "unavailable");
    assert!(
        report["inputs"][0]["error"]
            .as_str()
            .unwrap()
            .contains("\"operator-memory-pressure\"")
    );
    let calls = harness.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert!(calls[0].contains("reference-evaluator-input-unavailable-root.unreadable-trigger-"));
}

/// Review N3: `nq.host_memory` is read only at the profile version it was
/// qualified against.
#[test]
fn unrecognised_host_memory_version_is_not_current() {
    let (harness, status) = nq_status_harness();
    let t = at("2026-10-02T21:32:17Z");
    let value = retimed("healthy.json", t, |value| {
        for component in value["components"].as_array_mut().unwrap() {
            if component["kind"] == "evaluation"
                && component["detail"]["result"]["context"]["instance_id"] == "host-memory"
            {
                component["detail"]["result"]["profile"]["profile"]["version"] = json!(2);
            }
        }
    });
    write_status(&status, &value);
    let report = harness.evaluate(t + 3);
    assert_eq!(report["inputs"][0]["status"], "not_current");
    assert!(
        report["inputs"][0]["error"]
            .as_str()
            .unwrap()
            .contains("unrecognised profile \"nq.host_memory\" version 2")
    );
}

/// Review A9: an unknown run longer than one pass interval does not count
/// toward persistence; the interval's start moves forward by the run.
#[test]
fn long_unknown_gap_does_not_count_toward_persistence() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    set(&harness, "root", ProjectedStateV1::Degraded, T0);
    harness.evaluate(T0);
    let current = harness.root("root").join("CURRENT");
    fs::remove_file(&current).unwrap();
    for offset in (60..=900).step_by(60) {
        harness.evaluate(T0 + offset);
    }
    let disk = |calls: &[String]| {
        calls
            .iter()
            .filter(|call| call.contains("reference-host-disk-root-trigger-"))
            .count()
    };
    set(&harness, "root", ProjectedStateV1::Degraded, T0 + 960);
    harness.evaluate(T0 + 960);
    assert_eq!(disk(&harness.calls()), 0, "{:?}", harness.calls());
    let state = harness.state();
    assert_eq!(
        state["conditions"]["constellation:reference:host_posture:host-disk:root"]["first_seen"],
        T0 + 900,
        "T0 plus the 900 s unknown run"
    );
    for offset in (1020..=1800).step_by(60) {
        set(&harness, "root", ProjectedStateV1::Degraded, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    assert_eq!(disk(&harness.calls()), 0);
    set(&harness, "root", ProjectedStateV1::Degraded, T0 + 1860);
    harness.evaluate(T0 + 1860);
    assert_eq!(disk(&harness.calls()), 1, "{:?}", harness.calls());
}

/// One unknown pass inside an interval is tolerated: persistence and the
/// resolve confirmation keep their start.
#[test]
fn single_unknown_pass_keeps_the_interval() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    let current = harness.root("root").join("CURRENT");
    for offset in (0..=660).step_by(60) {
        if offset == 300 {
            fs::remove_file(&current).unwrap();
        } else {
            set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        }
        harness.evaluate(T0 + offset);
    }
    assert_eq!(harness.state()["conditions"][UNKNOWN_ROOT]["active"], true);
    assert_eq!(
        harness.state()["conditions"][UNKNOWN_ROOT]["first_seen"],
        T0
    );
    // Clear at +720, unknown at +780, clear at +840: resolved.
    set(&harness, "root", ProjectedStateV1::Healthy, T0 + 720);
    harness.evaluate(T0 + 720);
    fs::remove_file(&current).unwrap();
    harness.evaluate(T0 + 780);
    set(&harness, "root", ProjectedStateV1::Healthy, T0 + 840);
    let report = harness.evaluate(T0 + 840);
    assert_eq!(intents(&report).len(), 2);
    assert!(
        intents(&report)
            .iter()
            .all(|(_, _, action)| action == "resolve")
    );
}

/// A long unknown run inside the resolve confirmation is not counted as clear.
#[test]
fn long_unknown_gap_does_not_count_as_clear() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    for offset in [0, 660] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    set(&harness, "root", ProjectedStateV1::Healthy, T0 + 720);
    harness.evaluate(T0 + 720);
    let current = harness.root("root").join("CURRENT");
    fs::remove_file(&current).unwrap();
    for offset in [780, 840, 900] {
        harness.evaluate(T0 + offset);
    }
    // Clear since +720, unknown +780..+900 (180 s): clear_since moves to +900.
    set(&harness, "root", ProjectedStateV1::Healthy, T0 + 960);
    assert!(intents(&harness.evaluate(T0 + 960)).is_empty());
    set(&harness, "root", ProjectedStateV1::Healthy, T0 + 1020);
    assert_eq!(intents(&harness.evaluate(T0 + 1020)).len(), 2);
}

/// A `local_file` notice route keeps qualification notices out of
/// production channels: `deliver-local`, no `--enable-network`, destination
/// `local-inbox:<route>`, and a rendered message under NQ's 4 KiB limit.
#[test]
fn local_file_notices_use_deliver_local() {
    let mut harness = Harness::new();
    harness.page_route = false;
    harness.network = false;
    harness.notice_transport = "local_file";
    harness.host_posture("root");
    harness.fake("local_route", "operations");
    for offset in [0, 660] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        let output = harness.evaluate_at(T0 + offset, &[]);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let calls = harness.calls();
    assert_eq!(
        calls,
        vec![
            "submit local:operations reference-host-posture-unknown-root-trigger-1790943060 n1 accepted new"
        ]
    );
    let intent: Value = serde_json::from_slice(&harness.submitted_intent("n1")).unwrap();
    assert_eq!(intent["destination_identity"], "local-inbox:operations");
    assert_eq!(intent["schema"], "nq.notification_delivery_intent.v1");
    assert!(
        constellation_attention::intent::local_inbox_message_bytes(&intent)
            < constellation_attention::intent::LOCAL_INBOX_MESSAGE_MAX
    );
    assert_eq!(
        harness.state()["conditions"][UNKNOWN_ROOT]["last_intent"]["notice"]["outcome"],
        "accepted"
    );
    // A definite failure is retried with a new event after the interval;
    // the resolve goes to the same inbox.
    harness.fake("next_state", "failed");
    for offset in [720, 780] {
        set(&harness, "root", ProjectedStateV1::Healthy, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    set(&harness, "root", ProjectedStateV1::Healthy, T0 + 840);
    let output = harness.evaluate_at(T0 + 840, &[]);
    assert_eq!(
        output.status.code(),
        Some(3),
        "a failed local delivery counts"
    );
    harness.fake("next_state", "accepted");
    set(&harness, "root", ProjectedStateV1::Healthy, T0 + 1740);
    harness.evaluate(T0 + 1740);
    let calls = harness.calls();
    assert_eq!(
        calls[1..],
        [
            "submit local:operations reference-host-posture-unknown-root-resolve-1790943240 n2 failed new",
            "submit local:operations reference-host-posture-unknown-root-resolve-1790944140 n3 accepted new",
        ]
    );
}

/// Review S7: the reader takes exactly one raw `nq --json saved-check
/// evaluate` document per reference (`/var/lib/nq-ops-results/<reference>.json`
/// on the Linode). The run summary document is not that shape and is held as
/// not current, never read as a pass or a failure.
#[test]
fn saved_check_reads_the_per_reference_evaluate_document() {
    let mut harness = Harness::new();
    let result = harness.path("atproto-freelist.json");
    harness.raw(&format!(
        "[[inputs.saved_checks]]\nreference = \"atproto-freelist\"\npath = \"{}\"\n",
        result.display()
    ));
    let evaluate = |outcome: &str, at: i64| {
        json!({
            "reference": "atproto-freelist",
            "evaluation_id": format!("sc-{at}"),
            "outcome": outcome,
            "detail": {
                "binding": {
                    "definition_digest": format!("sha256:{}", "8".repeat(64)),
                    "source_observed_at": rfc3339(at - 1),
                    "target": "/var/lib/nightshift/atproto-saved-check/store.sqlite",
                },
                "read_attempted_at": rfc3339(at),
                "refusal_reason": null,
            },
            "retained": false,
            "indeterminate": false,
        })
    };
    fs::write(&result, evaluate("failed", T0).to_string()).unwrap();
    let report = harness.evaluate(T0 + 5);
    assert_eq!(report["inputs"][0]["status"], "ok");
    assert_eq!(report["inputs"][0]["identity"]["outcome"], "failed");
    assert_eq!(
        report["inputs"][0]["identity"]["evaluation_id"],
        format!("sc-{T0}")
    );
    fs::write(&result, evaluate("passed", T0 + 60).to_string()).unwrap();
    let report = harness.evaluate(T0 + 65);
    assert_eq!(report["inputs"][0]["status"], "ok");
    // The run summary the nq-ops timer writes as latest.json.
    let run = json!({
        "schema": "nq-ops.saved-check-run.v1",
        "generated_at": rfc3339(T0 + 120),
        "results": [evaluate("failed", T0 + 120)],
    });
    fs::write(&result, run.to_string()).unwrap();
    let report = harness.evaluate(T0 + 125);
    assert_eq!(report["inputs"][0]["status"], "not_current");
    assert_eq!(report["inputs"][0]["identity"]["outcome"], "missing");
}

fn cron_calls(harness: &Harness) -> Vec<String> {
    harness
        .calls()
        .into_iter()
        .filter(|call| call.contains("service-down-cron"))
        .collect()
}

/// Second review P4: nqd crash-looping makes every watcher stale on 2 of
/// every 5 passes while cron.service stays down. The unknown passes do not
/// count, but they do not erase the observed presence either: it pages.
#[test]
fn intermittent_stale_input_still_pages_a_continuing_condition() {
    let (harness, status) = nq_status_harness();
    let t = at("2026-10-02T21:32:17Z");
    for step in 0..120 {
        let offset = step * 60;
        let stale = step % 5 >= 3;
        let value = retimed("cron-down.json", t + offset, |value| {
            if stale {
                for component in value["components"].as_array_mut().unwrap() {
                    if component["kind"] == "instance" {
                        component["observed_at"] = json!(rfc3339(t + offset - 400));
                    }
                }
            }
        });
        write_status(&status, &value);
        harness.evaluate(t + offset + 3);
    }
    let calls = cron_calls(&harness);
    assert_eq!(calls.len(), 2, "{:?}", harness.calls());
    assert!(calls.iter().all(|call| call.contains("-trigger-")));
    assert_eq!(harness.state()["conditions"][CRON]["active"], true);
}

/// Second review P4b: NQ's detector answers `cannot_evaluate` on 2 of every
/// 6 passes while cron.service stays down for two hours. It pages.
#[test]
fn intermittent_indeterminate_detector_still_pages() {
    let (harness, status) = nq_status_harness();
    let t = at("2026-10-02T21:32:17Z");
    let mut trigger_step = None;
    for step in 0..120 {
        let offset = step * 60;
        let state = if step % 6 >= 4 {
            "cannot_evaluate"
        } else {
            "present"
        };
        write_status(
            &status,
            &retimed("cron-down.json", t + offset, cron_state(state)),
        );
        let report = harness.evaluate(t + offset + 3);
        if trigger_step.is_none() && !intents(&report).is_empty() {
            trigger_step = Some(step);
        }
    }
    let calls = cron_calls(&harness);
    assert_eq!(calls.len(), 2, "{:?}", harness.calls());
    // Present 0..3, unknown 4..5 (shifted out), present again from 6:
    // 240 s of observed presence exceeds the 180 s bound at step 6.
    assert_eq!(trigger_step, Some(6));
}

/// Second review P6: relabelling the NQ status input and then losing it is
/// an outage, not a configuration removal. The page holds.
#[test]
fn relabelled_input_outage_holds_an_open_page() {
    let (mut harness, status) = nq_status_harness();
    let t = trigger_cron(&harness, &status);
    harness.extra_config = harness
        .extra_config
        .replace("label = \"nqd\"", "label = \"ops\"");
    for offset in [60, 120] {
        write_status(&status, &retimed("cron-down.json", t + offset, |_| {}));
        harness.evaluate(t + offset + 3);
    }
    assert_eq!(cron_calls(&harness).len(), 2, "rename alone holds");
    assert_eq!(harness.state()["conditions"][CRON]["input_label"], "ops");
    fs::remove_file(&status).unwrap();
    for offset in (180..=900).step_by(60) {
        harness.evaluate(t + offset + 3);
    }
    let calls = cron_calls(&harness);
    assert!(
        calls.iter().all(|call| !call.contains("-resolve-")),
        "{calls:?}"
    );
    assert_eq!(harness.state()["conditions"][CRON]["active"], true);
    assert!(
        harness
            .calls()
            .iter()
            .any(|call| call.contains("evaluator-input-unavailable-ops"))
    );
}

/// A relabel before the condition is observed under the new label holds it
/// too: the NQ status input kind is still configured.
#[test]
fn relabel_without_observation_is_not_a_removal() {
    let (mut harness, status) = nq_status_harness();
    let t = trigger_cron(&harness, &status);
    harness.extra_config = harness
        .extra_config
        .replace("label = \"nqd\"", "label = \"ops\"");
    fs::remove_file(&status).unwrap();
    for offset in (60..=600).step_by(60) {
        harness.evaluate(t + offset + 3);
    }
    assert!(
        cron_calls(&harness)
            .iter()
            .all(|call| !call.contains("-resolve-"))
    );
    assert_eq!(harness.state()["conditions"][CRON]["active"], true);
}

/// Second review R5: a lasting fault of one class (a watched templated
/// unit) does not mask a later fault of another (nqd stops collecting).
#[test]
fn lasting_input_fault_does_not_mask_a_later_stall() {
    let (harness, status) = nq_status_harness();
    let t = at("2026-10-02T21:32:17Z");
    let templated = |value: &mut Value| {
        cron_eval(value)["detail"]["result"]["context"]["subject"] =
            json!("systemd-unit:1853ff04ff7a42679bf212ec9a569c4f/getty@tty1.service");
    };
    for offset in (0..=600).step_by(60) {
        write_status(&status, &retimed("cron-down.json", t + offset, templated));
        harness.evaluate(t + offset + 3);
    }
    let notices = |harness: &Harness, cause: &str| {
        harness
            .calls()
            .iter()
            .filter(|call| {
                call.contains(&format!("evaluator-input-unavailable-nqd.{cause}-trigger-"))
            })
            .count()
    };
    assert_eq!(notices(&harness, "untargetable"), 1);
    // nqd stops: every collection ages while the templated watcher remains.
    for offset in (660..=1320).step_by(60) {
        let value = retimed("cron-down.json", t + offset, |value| {
            templated(value);
            for component in value["components"].as_array_mut().unwrap() {
                if component["kind"] == "instance" {
                    component["observed_at"] = json!(rfc3339(t + 597));
                }
            }
        });
        write_status(&status, &value);
        harness.evaluate(t + offset + 3);
    }
    assert_eq!(notices(&harness, "stale"), 1, "{:?}", harness.calls());
    let report = harness.report();
    let causes = report["inputs"][0]["causes"].as_array().unwrap();
    assert!(causes.contains(&json!("stale")) && causes.contains(&json!("untargetable")));
}

/// Second review R1: a detector that stays `cannot_evaluate` on an
/// otherwise current export reaches the operator as an input notice.
#[test]
fn sustained_cannot_evaluate_is_an_input_notice() {
    let (harness, status) = nq_status_harness();
    let t = at("2026-10-02T21:32:17Z");
    let mut codes = Vec::new();
    for offset in (0..=420).step_by(60) {
        write_status(
            &status,
            &retimed("cron-down.json", t + offset, cron_state("cannot_evaluate")),
        );
        codes.push(harness.evaluate_at(t + offset + 3, &[]).status.code());
    }
    assert!(codes.iter().all(|code| *code == Some(3)), "{codes:?}");
    let report = harness.report();
    assert_eq!(report["inputs"][0]["causes"], json!(["indeterminate"]));
    assert!(
        report["inputs"][0]["error"]
            .as_str()
            .unwrap()
            .contains("cron.service (cannot_evaluate)")
    );
    let calls = harness.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert!(calls[0].contains("evaluator-input-unavailable-nqd.indeterminate-trigger-"));
}

/// An open input notice under the pre-cause key format is closed as no
/// longer evaluated, never held forever.
#[test]
fn input_notice_in_the_old_key_format_is_closed() {
    let mut harness = Harness::new();
    let store = harness.path("missing/nightshift.sqlite");
    harness.raw(&format!(
        "[inputs.nightshift]\nlabel = \"observation\"\nstore_path = \"{}\"\n",
        store.display()
    ));
    for offset in (0..=420).step_by(60) {
        harness.evaluate(T0 + offset);
    }
    let path = harness.path("state/state.json");
    let text = fs::read_to_string(&path)
        .unwrap()
        .replace("observation.unreadable", "observation");
    fs::write(&path, text).unwrap();
    let report = harness.evaluate(T0 + 480);
    let old = "constellation:reference:nightshift:evaluator-input-unavailable:observation";
    assert!(
        intents(&report).contains(&(old.into(), "notice".into(), "resolve".into())),
        "{:?}",
        intents(&report)
    );
}

/// Second review P8: a PagerDuty trigger NQ retained but could not deliver
/// is resubmitted after 120 s, not 900 s.
#[test]
fn failed_pagerduty_trigger_is_resubmitted_after_a_pause() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    for offset in (0..=600).step_by(60) {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    harness.fake("next_state", "failed");
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 660);
    harness.evaluate(T0 + 660);
    harness.fake("next_state", "accepted");
    for offset in (720..=1260).step_by(60) {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    let calls = harness.calls();
    assert!(
        calls.contains(
            &"resubmit n2 reference-host-posture-unknown-root-trigger-1790943180 n3 accepted"
                .to_owned()
        ),
        "{calls:?}"
    );
}

/// Second review P8/R3: a resolve that supersedes a retained trigger that
/// was never accepted reports it as dropped and exits 3.
#[test]
fn resolve_superseding_an_unaccepted_trigger_is_reported() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    harness.fake("next_state", "failed");
    for offset in (0..=780).step_by(60) {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    let mut codes = Vec::new();
    for offset in [840, 900, 960] {
        set(&harness, "root", ProjectedStateV1::Healthy, T0 + offset);
        codes.push(harness.evaluate_at(T0 + offset, &[]).status.code());
    }
    assert_eq!(codes[2], Some(3));
    let report = harness.report();
    assert_eq!(intents(&report).len(), 2, "the resolve went out");
    let dropped = report["dropped_triggers"].as_array().unwrap();
    assert!(
        dropped
            .iter()
            .any(|entry| entry["route_role"] == "page" && entry["outcome"] == "failed"),
        "{report}"
    );
}

/// Second review A7/R4: a forward clock step lets its own pass proceed;
/// once the clock is corrected, passes refuse until the operator checks the
/// clock and runs `reset-clock`, which deletes nothing. Then passes proceed
/// and the open page is held, not replayed.
#[test]
fn forward_clock_step_recovers_with_reset_clock() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    for offset in [0, 660] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    assert_eq!(harness.calls().len(), 2);
    // A one-off forward step of a day: that pass proceeds.
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 86_400);
    let output = harness.evaluate_at(T0 + 86_400, &[]);
    assert_eq!(output.status.code(), Some(0));
    // The clock is corrected: passes refuse with the recovery hint.
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 720);
    let output = harness.evaluate_at(T0 + 720, &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("reset-clock"));
    let config = harness.config_path();
    let now = rfc3339(T0 + 780);
    let output = harness.command(&[
        "reset-clock",
        "--config",
        config.to_str().unwrap(),
        "--now",
        &now,
    ]);
    assert_eq!(output.status.code(), Some(0));
    let answer: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(answer["clamped_timestamps"].as_u64().unwrap() >= 1);
    let state = harness.state();
    assert_eq!(state["updated_at"], T0 + 780);
    assert_eq!(state["conditions"][UNKNOWN_ROOT]["active"], true);
    for offset in [840, 900, 3600] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        let output = harness.evaluate_at(T0 + offset, &[]);
        assert_eq!(output.status.code(), Some(0));
    }
    assert_eq!(harness.calls().len(), 2, "no re-trigger after recovery");
    for offset in [3660, 3720, 3780] {
        set(&harness, "root", ProjectedStateV1::Healthy, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    assert_eq!(harness.calls().len(), 4, "{:?}", harness.calls());
}

// Second review attack tests, kept as regression tests.

/// Second review A2: a removed watcher holds its page for hours, every pass
/// exits 3, and other units on the same input still page.
#[test]
fn removed_watcher_holds_for_hours_and_other_units_still_page() {
    let (harness, status) = nq_status_harness();
    let t = trigger_cron(&harness, &status);
    let mut codes = Vec::new();
    for offset in (60..=3 * 3600).step_by(600) {
        let ssh_down = offset >= 2 * 3600;
        let value = retimed("cron-down.json", t + offset, |value| {
            value["components"]
                .as_array_mut()
                .unwrap()
                .retain(|component| {
                    component["id"] != "unit-cron"
                        && component["detail"]["result"]["context"]["instance_id"] != "unit-cron"
                });
            if ssh_down {
                for component in value["components"].as_array_mut().unwrap() {
                    if component["kind"] == "evaluation"
                        && component["detail"]["result"]["context"]["instance_id"] == "unit-ssh"
                    {
                        component["detail"]["result"]["result"]["state"] = json!("present");
                    }
                }
            }
        });
        write_status(&status, &value);
        codes.push(harness.evaluate_at(t + offset + 3, &[]).status.code());
    }
    assert!(
        cron_calls(&harness)
            .iter()
            .all(|call| !call.contains("-resolve-"))
    );
    assert_eq!(harness.state()["conditions"][CRON]["active"], true);
    assert!(codes.iter().all(|code| *code == Some(3)), "{codes:?}");
    assert!(
        harness
            .calls()
            .iter()
            .any(|call| call.contains("service-down-ssh.service-trigger")),
        "{:?}",
        harness.calls()
    );
}

/// Second review A6: a corrupt state file stops every pass (exit 1) and is
/// never replaced.
#[test]
fn corrupt_state_stops_every_pass() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    set(&harness, "root", ProjectedStateV1::Unknown, T0);
    harness.evaluate(T0);
    fs::write(harness.path("state/state.json"), b"{\"schema\":").unwrap();
    for offset in [660, 3600] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        assert_eq!(harness.evaluate_at(T0 + offset, &[]).status.code(), Some(1));
    }
    assert!(harness.calls().is_empty());
    assert_eq!(
        fs::read(harness.path("state/state.json")).unwrap(),
        b"{\"schema\":"
    );
}

/// Second review A8: a pass, real or dry, never overlaps another.
#[test]
fn overlapping_pass_is_refused() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    set(&harness, "root", ProjectedStateV1::Unknown, T0);
    harness.evaluate(T0);
    let lock = fs::OpenOptions::new()
        .write(true)
        .open(harness.path("state/state.json.lock"))
        .unwrap();
    lock.try_lock().unwrap();
    for extra in [&[][..], &["--dry-run"][..]] {
        let output = harness.evaluate_at(T0 + 60, extra);
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("holds the state lock"));
    }
}

/// Second review A10, a documented limit (N1): service-down keys on the
/// unit name, so a healthy unit of the same name on another machine in the
/// same export hides it. One nqd watches one host.
#[test]
fn same_unit_on_two_machines_is_a_documented_limit() {
    let (harness, status) = nq_status_harness();
    let t = at("2026-10-02T21:32:17Z");
    for offset in [0, 60, 120, 181, 240] {
        let value = retimed("cron-down.json", t + offset, |value| {
            let mut other = cron_eval(value).clone();
            other["id"] = json!("9f9f9f9f-0000-4000-8000-000000000000");
            other["detail"]["result"]["context"]["instance_id"] = json!("unit-cron-b");
            other["detail"]["result"]["context"]["subject"] =
                json!("systemd-unit:2222222222222222222222222222222a/cron.service");
            other["detail"]["result"]["result"]["state"] = json!("explicitly_absent");
            other["detail"]["result"]["evaluated_at"] = json!(rfc3339(t + offset - 2));
            let mut instance = value["components"]
                .as_array()
                .unwrap()
                .iter()
                .find(|component| component["id"] == "unit-cron")
                .unwrap()
                .clone();
            instance["id"] = json!("unit-cron-b");
            value["components"].as_array_mut().unwrap().push(other);
            value["components"].as_array_mut().unwrap().push(instance);
        });
        write_status(&status, &value);
        harness.evaluate(t + offset + 3);
    }
    assert!(harness.calls().is_empty(), "{:?}", harness.calls());
}

/// Drive a trigger that NQ refuses before custody, then a clear, so the
/// resolve is decided while the trigger was never retained.
fn pending_setup(harness: &mut Harness) {
    harness.host_posture("root");
    harness.fake("command_error", "");
    for offset in [0, 660] {
        set(harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    for offset in [720, 780] {
        set(harness, "root", ProjectedStateV1::Healthy, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    assert!(harness.calls().is_empty());
    fs::remove_file(harness.path("fake/command_error")).unwrap();
}

/// Second review P1: a crash before NQ retains the pending trigger leaves it
/// in state; the next pass sends trigger then resolve, once each.
#[test]
fn crash_before_pending_trigger_is_retained() {
    let mut harness = Harness::new();
    pending_setup(&mut harness);
    harness.fake("crash", "");
    set(&harness, "root", ProjectedStateV1::Healthy, T0 + 840);
    let _ = harness.evaluate_at(T0 + 840, &[]);
    let state = harness.state();
    assert_eq!(
        state["conditions"][UNKNOWN_ROOT]["pending_trigger"]
            .as_object()
            .unwrap()
            .len(),
        2
    );
    for offset in [900, 960, 1800] {
        set(&harness, "root", ProjectedStateV1::Healthy, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    let calls = harness.calls();
    assert_eq!(calls.len(), 4, "{calls:?}");
    assert!(calls[0].contains("-trigger-") && calls[1].contains("-trigger-"));
    assert!(calls[2].contains("-resolve-") && calls[3].contains("-resolve-"));
}

/// Second review P2: a crash after NQ retains the pending trigger converges
/// on the retained record; no double trigger.
#[test]
fn crash_after_pending_trigger_is_retained() {
    let mut harness = Harness::new();
    pending_setup(&mut harness);
    harness.fake("crash_after", "");
    set(&harness, "root", ProjectedStateV1::Healthy, T0 + 840);
    let _ = harness.evaluate_at(T0 + 840, &[]);
    for offset in [900, 960, 1800] {
        set(&harness, "root", ProjectedStateV1::Healthy, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    let calls = harness.calls();
    let new_triggers = calls
        .iter()
        .filter(|call| call.contains("-trigger-") && call.ends_with(" new"))
        .count();
    assert_eq!(new_triggers, 2, "one retained trigger per route: {calls:?}");
    assert_eq!(
        calls
            .iter()
            .filter(|call| call.contains("-resolve-"))
            .count(),
        2
    );
}

/// Second review P3: the condition recurs while a trigger is pending. The
/// old incident's trigger and resolve go out, then one new trigger per route
/// after the bound.
#[test]
fn recurrence_while_a_trigger_is_pending() {
    let mut harness = Harness::new();
    pending_setup(&mut harness);
    harness.fake("crash", "");
    set(&harness, "root", ProjectedStateV1::Healthy, T0 + 840);
    let _ = harness.evaluate_at(T0 + 840, &[]);
    for offset in (900..=1800).step_by(60) {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    let calls = harness.calls();
    assert_eq!(
        calls
            .iter()
            .filter(|call| call.contains("-trigger-1790943060"))
            .count(),
        2,
        "{calls:?}"
    );
    assert_eq!(
        calls
            .iter()
            .filter(|call| call.contains("-resolve-"))
            .count(),
        2
    );
    let later = calls
        .iter()
        .filter(|call| call.contains("-trigger-") && !call.contains("1790943060"))
        .count();
    assert_eq!(later, 2, "{calls:?}");
}

/// Second review P5: nqd stopped for ten minutes during an active page:
/// held, no re-trigger when it returns, and observed recovery resolves.
#[test]
fn nqd_stop_during_an_active_page_holds_it() {
    let (harness, status) = nq_status_harness();
    let t = trigger_cron(&harness, &status);
    for offset in (60..=600).step_by(60) {
        let value = retimed("cron-down.json", t + offset, |value| {
            for component in value["components"].as_array_mut().unwrap() {
                if component["kind"] == "instance" {
                    component["observed_at"] = json!(rfc3339(t - 3));
                }
            }
        });
        write_status(&status, &value);
        harness.evaluate(t + offset + 3);
    }
    assert_eq!(cron_calls(&harness).len(), 2, "held: {:?}", harness.calls());
    for offset in [660, 720] {
        write_status(&status, &retimed("cron-down.json", t + offset, |_| {}));
        harness.evaluate(t + offset + 3);
    }
    assert_eq!(cron_calls(&harness).len(), 2, "no re-trigger");
    for offset in [780, 840, 900] {
        write_status(
            &status,
            &retimed(
                "cron-down.json",
                t + offset,
                cron_state("explicitly_absent"),
            ),
        );
        harness.evaluate(t + offset + 3);
    }
    assert_eq!(
        cron_calls(&harness)
            .iter()
            .filter(|call| call.contains("-resolve-"))
            .count(),
        2
    );
}

/// Second review P7, deliberate: dropping the NQ status input from the
/// configuration for one pass resolves the open page as no longer
/// evaluated; restoring it re-pages as a new incident after the bound.
#[test]
fn transient_config_drop_resolves_then_repages() {
    let (mut harness, status) = nq_status_harness();
    let t = trigger_cron(&harness, &status);
    let saved = harness.extra_config.clone();
    harness.extra_config.clear();
    write_status(&status, &retimed("cron-down.json", t + 60, |_| {}));
    let report = harness.evaluate(t + 63);
    assert_eq!(intents(&report).len(), 2);
    harness.extra_config = saved;
    for offset in (120..=600).step_by(60) {
        write_status(&status, &retimed("cron-down.json", t + offset, |_| {}));
        harness.evaluate(t + offset + 3);
    }
    let calls = cron_calls(&harness);
    assert_eq!(calls.len(), 6, "{calls:?}");
    assert!(calls[2].contains("-resolve-") && calls[3].contains("-resolve-"));
    assert!(calls[4].contains("-trigger-") && calls[5].contains("-trigger-"));
    let id = calls[3].split(' ').nth(3).unwrap();
    let intent: Value = serde_json::from_slice(&harness.submitted_intent(id)).unwrap();
    assert!(
        intent["summary"]
            .as_str()
            .unwrap()
            .ends_with("no longer evaluated; recovery not observed.")
    );
}

const STALE_NQD: &str = "constellation:reference:nq:evaluator-input-unavailable:nqd.stale";

/// Use the real parser and a fresh binary invocation for every persisted pass.
/// A fresh export does not renew the instance collection times.
fn input_staleness(harness: &Harness, status: &Path, now: i64, stale: bool) -> Value {
    let value = retimed("healthy.json", now, |value| {
        if stale {
            for component in value["components"].as_array_mut().unwrap() {
                if component["kind"] == "instance" {
                    component["observed_at"] = json!(rfc3339(now - 400));
                }
            }
        }
    });
    write_status(status, &value);
    harness.evaluate(now)
}

fn stale_input_row(report: &Value) -> &Value {
    report["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == STALE_NQD)
        .unwrap()
}

fn stale_transition(action: &str) -> Vec<(String, String, String)> {
    vec![(STALE_NQD.into(), "notice".into(), action.into())]
}

/// Exact reported pattern: resolve 10:53, stale returns 10:53:59, trigger 10:59.
#[test]
fn stale_input_retriggers_301_seconds_after_1053_resolve() {
    let (harness, status) = nq_status_harness();
    let start = at("2026-10-06T10:45:00Z");
    for offset in [0, 60, 120, 180, 240, 300] {
        let report = input_staleness(&harness, &status, start + offset, true);
        assert!(intents(&report).is_empty());
        assert_eq!(stale_input_row(&report)["observation"], "present");
        assert_eq!(stale_input_row(&report)["active"], false);
    }
    let report = input_staleness(&harness, &status, start + 301, true);
    assert_eq!(intents(&report), stale_transition("trigger"));
    for offset in [360, 420, 479] {
        assert!(intents(&input_staleness(&harness, &status, start + offset, false)).is_empty());
    }
    let resolved = at("2026-10-06T10:53:00Z");
    let report = input_staleness(&harness, &status, resolved, false);
    assert_eq!(intents(&report), stale_transition("resolve"));
    assert_eq!(stale_input_row(&report)["observation"], "clear");
    assert_eq!(stale_input_row(&report)["active"], false);
    assert!(harness.state()["conditions"].get(STALE_NQD).is_none());
    let returned = resolved + 59;
    for offset in [0, 60, 120, 180, 240, 300] {
        let report = input_staleness(&harness, &status, returned + offset, true);
        assert!(intents(&report).is_empty());
        assert_eq!(stale_input_row(&report)["observation"], "present");
        assert_eq!(stale_input_row(&report)["persisted_seconds"], offset);
    }
    let report = input_staleness(&harness, &status, at("2026-10-06T10:59:00Z"), true);
    assert_eq!(intents(&report), stale_transition("trigger"));
    assert_eq!(stale_input_row(&report)["persisted_seconds"], 301);
    assert_eq!(stale_input_row(&report)["persistence_bound_seconds"], 300);
    assert_eq!(harness.calls().len(), 3);
    assert!(
        harness
            .calls()
            .iter()
            .all(|call| call.starts_with("submit operations "))
    );
}

#[test]
fn stale_input_below_bound_oscillation_never_triggers() {
    let (harness, status) = nq_status_harness();
    for episode in 0..3 {
        let start = T0 + episode * 400;
        for offset in [0, 60, 120, 180, 240, 300] {
            let report = input_staleness(&harness, &status, start + offset, true);
            assert!(intents(&report).is_empty());
            assert_eq!(stale_input_row(&report)["persisted_seconds"], offset);
        }
        let report = input_staleness(&harness, &status, start + 301, false);
        assert!(intents(&report).is_empty());
        assert!(harness.state()["conditions"].get(STALE_NQD).is_none());
    }
    assert!(harness.calls().is_empty());
}

#[test]
fn stale_input_short_clear_and_other_fault_do_not_resolve_it() {
    let (harness, status) = nq_status_harness();
    input_staleness(&harness, &status, T0, true);
    input_staleness(&harness, &status, T0 + 301, true);
    for offset in [360, 420, 479] {
        assert!(intents(&input_staleness(&harness, &status, T0 + offset, false)).is_empty());
    }
    // Present at the 120 s boundary cancels confirmation rather than resolving.
    assert!(intents(&input_staleness(&harness, &status, T0 + 480, true)).is_empty());
    input_staleness(&harness, &status, T0 + 600, false);
    // Another fault makes stale unknown, not clear. Its long run is excluded.
    fs::write(&status, b"").unwrap();
    for offset in [660, 720, 780] {
        let report = harness.evaluate(T0 + offset);
        assert_eq!(stale_input_row(&report)["observation"], "unknown");
        assert_eq!(stale_input_row(&report)["active"], true);
        assert!(intents(&report).is_empty());
    }
    for offset in [840, 899] {
        assert!(intents(&input_staleness(&harness, &status, T0 + offset, false)).is_empty());
    }
    let report = input_staleness(&harness, &status, T0 + 900, false);
    assert_eq!(intents(&report), stale_transition("resolve"));
    assert_eq!(harness.calls().len(), 2);
}

#[test]
fn stale_input_repeated_episodes_keep_condition_identity_but_get_new_events() {
    let (harness, status) = nq_status_harness();
    for episode in 0..3 {
        let start = T0 + episode * 600;
        input_staleness(&harness, &status, start, true);
        let report = input_staleness(&harness, &status, start + 301, true);
        assert_eq!(intents(&report), stale_transition("trigger"));
        input_staleness(&harness, &status, start + 360, false);
        let report = input_staleness(&harness, &status, start + 480, false);
        assert_eq!(intents(&report), stale_transition("resolve"));
        assert!(harness.state()["conditions"].get(STALE_NQD).is_none());
    }
    let calls = harness.calls();
    assert_eq!(calls.len(), 6);
    let events: std::collections::BTreeSet<_> = calls
        .iter()
        .map(|call| call.split_whitespace().nth(2).unwrap())
        .collect();
    assert_eq!(events.len(), 6);
    for index in 1..=6 {
        let intent: Value =
            serde_json::from_slice(&harness.submitted_intent(&format!("n{index}"))).unwrap();
        assert_eq!(intent["response_class"], "attention");
        assert!(intent["summary"].as_str().unwrap().contains(STALE_NQD));
    }
}

/// Pin a delivery limit: a failed resolve is not a post-resolution cooldown.
#[test]
fn stale_input_recurrence_can_replace_an_unaccepted_resolve() {
    let (harness, status) = nq_status_harness();
    input_staleness(&harness, &status, T0, true);
    input_staleness(&harness, &status, T0 + 301, true);
    harness.fake("next_state", "failed");
    input_staleness(&harness, &status, T0 + 360, false);
    input_staleness(&harness, &status, T0 + 480, false);
    assert_eq!(
        harness.state()["conditions"][STALE_NQD]["last_intent"]["notice"]["action"],
        "resolve"
    );
    assert_eq!(
        harness.state()["conditions"][STALE_NQD]["last_intent"]["notice"]["outcome"],
        "failed"
    );
    harness.fake("next_state", "accepted");
    input_staleness(&harness, &status, T0 + 539, true);
    let report = input_staleness(&harness, &status, T0 + 840, true);
    assert_eq!(intents(&report), stale_transition("trigger"));
    assert_eq!(harness.calls().len(), 3);
    assert_eq!(
        harness.state()["conditions"][STALE_NQD]["last_intent"]["notice"]["action"],
        "trigger"
    );
    assert_eq!(
        harness.state()["conditions"][STALE_NQD]["last_intent"]["notice"]["outcome"],
        "accepted"
    );
}

// Third review regressions.

fn nq_notices(harness: &Harness) -> Vec<String> {
    harness
        .calls()
        .into_iter()
        .filter(|call| call.contains("evaluator-input-unavailable-nqd."))
        .collect()
}

/// Third review N2: an export alternating every pass between unreadable
/// and stale still raises an input notice after its bound. The class it is
/// not showing is unknown, not clear, while the input has any fault.
#[test]
fn alternating_fault_classes_still_notify() {
    let (harness, status) = nq_status_harness();
    let t = at("2026-10-02T21:32:17Z");
    for step in 0..20 {
        let offset = step * 60;
        if step % 2 == 0 {
            fs::write(&status, b"not json").unwrap();
        } else {
            let value = retimed("healthy.json", t + offset, |value| {
                for component in value["components"].as_array_mut().unwrap() {
                    if component["kind"] == "instance" {
                        component["observed_at"] = json!(rfc3339(t + offset - 400));
                    }
                }
            });
            write_status(&status, &value);
        }
        let output = harness.evaluate_at(t + offset + 3, &[]);
        assert_eq!(output.status.code(), Some(3));
    }
    let notices = nq_notices(&harness);
    assert!(
        notices.iter().any(|call| call.contains("-trigger-")),
        "{:?}",
        harness.calls()
    );
}

/// Third review N2c: a wedged nqd times out one pass in three and is stale
/// on the rest while cron.service is down. Service-down stays unknown, and
/// the operator is told the input is blind.
#[test]
fn wedged_nqd_raises_an_input_notice() {
    let (harness, status) = nq_status_harness();
    let t = at("2026-10-02T21:32:17Z");
    for step in 0..30 {
        let offset = step * 60;
        if step % 3 == 0 {
            fs::write(&status, b"").unwrap();
        } else {
            let value = retimed("cron-down.json", t + offset, |value| {
                for component in value["components"].as_array_mut().unwrap() {
                    if component["kind"] == "instance" {
                        component["observed_at"] = json!(rfc3339(t + offset - 400));
                    }
                }
            });
            write_status(&status, &value);
        }
        harness.evaluate(t + offset + 3);
    }
    assert!(cron_calls(&harness).is_empty(), "{:?}", harness.calls());
    assert!(
        nq_notices(&harness)
            .iter()
            .any(|call| call.contains("-trigger-")),
        "{:?}",
        harness.calls()
    );
}

/// Third review N5: a lasting fault (a watched templated unit) does not
/// hide that an open condition is no longer reported.
#[test]
fn lasting_fault_does_not_mask_unreported() {
    let (harness, status) = nq_status_harness();
    let t = trigger_cron(&harness, &status);
    for offset in (60..=900).step_by(60) {
        let value = retimed("cron-down.json", t + offset, |value| {
            value["components"]
                .as_array_mut()
                .unwrap()
                .retain(|component| {
                    component["id"] != "unit-cron"
                        && component["detail"]["result"]["context"]["instance_id"] != "unit-cron"
                });
            for component in value["components"].as_array_mut().unwrap() {
                if component["kind"] == "evaluation"
                    && component["detail"]["result"]["context"]["instance_id"] == "unit-ssh"
                {
                    component["detail"]["result"]["context"]["subject"] =
                        json!("systemd-unit:1853ff04ff7a42679bf212ec9a569c4f/getty@tty1.service");
                }
            }
        });
        write_status(&status, &value);
        harness.evaluate(t + offset + 3);
    }
    assert_eq!(harness.state()["conditions"][CRON]["active"], true);
    let report = harness.report();
    let causes = report["inputs"][0]["causes"].as_array().unwrap();
    assert!(
        causes.contains(&json!("untargetable")) && causes.contains(&json!("unreported")),
        "{}",
        report["inputs"][0]
    );
    assert!(
        report["inputs"][0]["error"]
            .as_str()
            .unwrap()
            .contains(CRON)
    );
    let notices = nq_notices(&harness);
    for class in ["untargetable", "unreported"] {
        assert!(
            notices
                .iter()
                .any(|call| call.contains(&format!("nqd.{class}-trigger-"))),
            "{notices:?}"
        );
    }
}

/// Write an executable shell script into the harness directory.
fn script(harness: &Harness, name: &str, body: &str) -> PathBuf {
    let path = harness.path(name);
    fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// Production (nq#20): a slow `status export` answered after the pass
/// started. Its `generated_at` is later than the pass start, which is not a
/// snapshot from the future: skew is measured when the command answered.
#[test]
fn slow_export_is_not_read_as_a_future_snapshot() {
    let mut harness = Harness::new();
    let file = harness.path("slow-status.json");
    let command = script(
        &harness,
        "slow-nq",
        &format!("sleep 3\ncat {}", file.display()),
    );
    harness.raw(&format!(
        "[inputs.nq_status]\nlabel = \"nqd\"\ncommand = [\"{}\"]\n",
        command.display()
    ));
    let t = at("2026-10-02T21:32:17Z");
    // Generated 62 s after the pass start: beyond the 60 s skew allowance
    // from the start, within it from the answer (3 s later).
    write_status(&file, &retimed("healthy.json", t + 62, |_| {}));
    let report = harness.evaluate(t);
    assert_eq!(
        report["inputs"][0]["status"], "ok",
        "{}",
        report["inputs"][0]
    );
}

// Evaluation-history source (nq#20).

/// The newest evaluation envelope per instance of a real export sample.
fn fixture_envelopes(name: &str) -> Vec<Value> {
    let value: Value = serde_json::from_slice(
        &fs::read(Path::new(FIXTURES).join("nq-status").join(name)).unwrap(),
    )
    .unwrap();
    let mut newest: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();
    for component in value["components"].as_array().unwrap() {
        if component["kind"] == "evaluation" {
            let envelope = component["detail"]["result"].clone();
            let instance = envelope["context"]["instance_id"]
                .as_str()
                .unwrap()
                .to_owned();
            newest.insert(instance, envelope);
        }
    }
    newest.into_values().collect()
}

fn history_harness(window: u32) -> Harness {
    let mut harness = Harness::new();
    fs::create_dir_all(harness.path("fake/history")).unwrap();
    // Input commands run with a cleared environment: bind the fake's
    // directory in a wrapper.
    let wrapper = script(
        &harness,
        "nq-wrapper",
        &format!(
            "FAKE_NQ_DIR={} exec {} \"$@\"",
            harness.path("fake").display(),
            Path::new(FIXTURES).join("fake-nq.sh").display()
        ),
    );
    harness.raw(&format!(
        "[inputs.nq_status]\nlabel = \"nqd\"\nsource = \"evaluation_history\"\n\
         window_records = {window}\n\
         command = [\"{}\", \"--config\", \"/etc/nq/nqd-ops.toml\", \"--json\"]\n",
        wrapper.display()
    ));
    harness
}

fn history_len(harness: &Harness) -> usize {
    fs::read_dir(harness.path("fake/history")).unwrap().count()
}

/// Append one evaluation per instance at `at - 3` (skipping instances the
/// edit drops by returning false) and set the page time to `at`.
fn append_round(harness: &Harness, at: i64, edit: impl Fn(&mut Value) -> bool) {
    let mut sequence = history_len(harness);
    for mut envelope in fixture_envelopes("cron-down.json") {
        envelope["evaluated_at"] = json!(rfc3339(at - 3));
        if !edit(&mut envelope) {
            continue;
        }
        sequence += 1;
        fs::write(
            harness.path(&format!("fake/history/{sequence}.json")),
            serde_json::to_vec(&envelope).unwrap(),
        )
        .unwrap();
    }
    harness.fake("history_generated_at", &rfc3339(at));
}

fn set_state(envelope: &mut Value, instance: &str, state: &str) {
    if envelope["context"]["instance_id"] == instance {
        envelope["result"]["state"] = json!(state);
    }
}

fn history_calls(harness: &Harness) -> Vec<String> {
    fs::read_to_string(harness.path("fake/history_calls.log"))
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// Service-down from evaluation-history pages: the newest 300 evaluations,
/// frozen at the store-wide sequence the probe reports.
#[test]
fn service_down_from_evaluation_history() {
    let harness = history_harness(300);
    let t = at("2026-10-02T21:32:17Z");
    // 100 earlier healthy rounds (400 records), beyond the window.
    for round in (1..=100).rev() {
        append_round(&harness, t - 60 * round, |envelope| {
            set_state(envelope, "unit-cron", "explicitly_absent");
            true
        });
    }
    let mut report = Value::Null;
    for offset in [0, 60, 120, 181] {
        append_round(&harness, t + offset, |_| true);
        report = harness.evaluate(t + offset + 3);
    }
    assert_eq!(
        report["inputs"][0]["status"], "ok",
        "{}",
        report["inputs"][0]
    );
    assert_eq!(
        report["inputs"][0]["identity"]["schema"],
        "nq.evaluation_history.v1"
    );
    assert_eq!(report["inputs"][0]["identity"]["through_sequence"], 416);
    assert_eq!(
        intents(&report),
        vec![
            (CRON.into(), "notice".into(), "trigger".into()),
            (CRON.into(), "page".into(), "trigger".into()),
        ]
    );
    let calls = history_calls(&harness);
    assert_eq!(
        calls[calls.len() - 2..],
        ["evaluations 1 none none", "evaluations 300 116 416"]
    );
    // Recovery from the same source resolves.
    for offset in [240, 300, 360] {
        append_round(&harness, t + offset, |envelope| {
            set_state(envelope, "unit-cron", "explicitly_absent");
            true
        });
        report = harness.evaluate(t + offset + 3);
    }
    assert!(
        intents(&report)
            .iter()
            .all(|(_, _, action)| action == "resolve")
    );
    assert_eq!(cron_calls(&harness).len(), 4);
}

/// A window larger than NQ's 1000-row page is read in pages under one
/// frozen upper bound.
#[test]
fn evaluation_history_window_spans_pages() {
    let harness = history_harness(2500);
    let t = at("2026-10-02T21:32:17Z");
    for round in (0..660).rev() {
        append_round(&harness, t - 60 * round, |_| true);
    }
    let report = harness.evaluate(t + 3);
    assert_eq!(
        report["inputs"][0]["status"], "ok",
        "{}",
        report["inputs"][0]
    );
    assert_eq!(
        history_calls(&harness),
        [
            "evaluations 1 none none",
            "evaluations 1000 140 2640",
            "evaluations 1000 1140 2640",
            "evaluations 500 2140 2640",
        ]
    );
}

/// A page that is not complete, or whose upper bound moved, is not current:
/// every NQ condition holds.
#[test]
fn incomplete_or_moved_history_is_not_current() {
    for (control, message) in [
        ("history_incomplete", "is not complete"),
        ("history_moved", "moved from through_sequence"),
    ] {
        let harness = history_harness(100);
        let t = at("2026-10-02T21:32:17Z");
        for round in (0..30).rev() {
            append_round(&harness, t - 60 * round, |_| true);
        }
        harness.fake(control, "");
        let report = harness.evaluate(t + 3);
        assert_eq!(report["inputs"][0]["status"], "not_current");
        assert_eq!(report["inputs"][0]["causes"], json!(["stale"]));
        assert!(
            report["inputs"][0]["error"]
                .as_str()
                .unwrap()
                .contains(message),
            "{}",
            report["inputs"][0]
        );
    }
}

/// A watcher whose evaluations leave the window while its page is open is
/// `unreported`, and its newest evaluations going old is `stale`.
#[test]
fn evaluation_history_unreported_and_stale() {
    let harness = history_harness(50);
    let t = at("2026-10-02T21:32:17Z");
    for offset in [0, 60, 120, 181] {
        append_round(&harness, t + offset, |_| true);
        harness.evaluate(t + offset + 3);
    }
    assert_eq!(harness.state()["conditions"][CRON]["active"], true);
    // 20 rounds without unit-cron push it out of the 50-record window.
    let mut report = Value::Null;
    for step in 1..=20 {
        let at_ = t + 181 + 60 * step;
        append_round(&harness, at_, |envelope| {
            envelope["context"]["instance_id"] != "unit-cron"
        });
        report = harness.evaluate(at_ + 3);
    }
    // The remembered watcher stopped evaluating: stale as well (round 5).
    assert_eq!(
        report["inputs"][0]["causes"],
        json!(["stale", "unreported"])
    );
    assert!(
        cron_calls(&harness)
            .iter()
            .all(|call| !call.contains("-resolve-"))
    );
    // No new evaluations: the page is generated later, the newest are old.
    let later = t + 181 + 60 * 20 + 300;
    harness.fake("history_generated_at", &rfc3339(later));
    let report = harness.evaluate(later + 3);
    let causes = report["inputs"][0]["causes"].as_array().unwrap();
    assert!(causes.contains(&json!("stale")), "{}", report["inputs"][0]);
}

#[test]
fn evaluation_history_configuration_is_bounded() {
    let mut harness = Harness::new();
    harness.raw(
        "[inputs.nq_status]\nlabel = \"nqd\"\nsource = \"evaluation_history\"\n\
         path = \"/var/lib/nq-status.json\"\n",
    );
    let config = harness.config_path();
    let output = harness.command(&["check-config", "--config", config.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("needs a command"));
    let mut harness = Harness::new();
    harness.raw(
        "[inputs.nq_status]\nlabel = \"nqd\"\nsource = \"evaluation_history\"\n\
         window_records = 6000\ncommand = [\"/usr/bin/nq\", \"--json\"]\n",
    );
    let config = harness.config_path();
    let output = harness.command(&["check-config", "--config", config.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("50..=5000"));
}

/// Production: NQ's `fs-zonestorage` filesystem capacity watcher feeds
/// `host-disk:fs-zonestorage` with the same bound (900 s) and class as the
/// host-posture source.
#[test]
fn nq_filesystem_capacity_feeds_host_disk() {
    let harness = history_harness(300);
    let t = at("2026-10-02T21:32:17Z");
    let zonestorage = |envelope: &mut Value| {
        if envelope["context"]["instance_id"] == "fs-root-capacity" {
            envelope["context"]["instance_id"] = json!("fs-zonestorage");
            envelope["result"]["state"] = json!("present");
        }
        set_state(envelope, "unit-cron", "explicitly_absent");
        true
    };
    let disk = "constellation:reference:host_posture:host-disk:fs-zonestorage";
    let mut report = Value::Null;
    for offset in (0..=900).step_by(60) {
        append_round(&harness, t + offset, zonestorage);
        report = harness.evaluate(t + offset + 3);
        assert!(intents(&report).is_empty(), "+{offset}");
    }
    let condition = report["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|condition| condition["id"] == disk)
        .unwrap()
        .clone();
    assert_eq!(condition["observation"], "present");
    assert_eq!(condition["persistence_bound_seconds"], 900);
    append_round(&harness, t + 960, zonestorage);
    let report = harness.evaluate(t + 963);
    // host-disk is attention: a notice, never a page.
    assert_eq!(
        intents(&report),
        vec![(disk.into(), "notice".into(), "trigger".into())]
    );
    let intent: Value = serde_json::from_slice(&harness.submitted_intent("n1")).unwrap();
    assert_eq!(intent["response_class"], "attention");
    assert!(
        intent["summary"]
            .as_str()
            .unwrap()
            .starts_with(&format!("TRIGGER {disk} [notice]"))
    );
}

/// The status-export source maps the same profile; an unrecognised version
/// of it is not current rather than ignored.
#[test]
fn filesystem_capacity_version_is_checked() {
    let (harness, status) = nq_status_harness();
    let t = at("2026-10-02T21:32:17Z");
    let value = retimed("healthy.json", t, |value| {
        for component in value["components"].as_array_mut().unwrap() {
            if component["kind"] == "evaluation"
                && component["detail"]["result"]["context"]["instance_id"] == "fs-root-capacity"
            {
                component["detail"]["result"]["profile"]["profile"]["version"] = json!(2);
            }
        }
    });
    write_status(&status, &value);
    let report = harness.evaluate(t + 3);
    assert_eq!(report["inputs"][0]["causes"], json!(["unrecognised"]));
    write_status(&status, &retimed("healthy.json", t + 60, |_| {}));
    let report = harness.evaluate(t + 63);
    let condition = report["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|condition| {
            condition["id"] == "constellation:reference:host_posture:host-disk:fs-root-capacity"
        })
        .unwrap()
        .clone();
    assert_eq!(condition["observation"], "clear");
}

// Fifth review regressions (evaluation-history mode).

/// Fifth review H1: a watcher that stops evaluating stays stale after its
/// records leave the window; it never "recovers" by scrolling out. When it
/// returns, its unit is observed again and a later outage pages.
#[test]
fn dead_watcher_stays_stale_after_leaving_the_window() {
    let mut harness = history_harness(50);
    let t = at("2026-10-02T21:32:17Z");
    let healthy = |envelope: &mut Value| {
        set_state(envelope, "unit-cron", "explicitly_absent");
        true
    };
    for offset in [0, 60, 120] {
        append_round(&harness, t + offset, healthy);
        harness.evaluate(t + offset + 3);
    }
    let mut last = Value::Null;
    for step in 1..=40 {
        let at_ = t + 120 + 60 * step;
        append_round(&harness, at_, |envelope| {
            envelope["context"]["instance_id"] != "unit-cron"
        });
        last = harness.evaluate(at_ + 3);
        if step >= 4 {
            let causes = last["inputs"][0]["causes"].as_array().unwrap();
            assert!(
                causes.contains(&json!("stale")),
                "step {step}: {}",
                last["inputs"][0]
            );
        }
    }
    assert!(
        last["inputs"][0]["error"]
            .as_str()
            .unwrap()
            .contains("unit-cron")
    );
    let stale = |harness: &Harness, action: &str| {
        harness
            .calls()
            .iter()
            .filter(|call| call.contains(&format!("nqd.stale-{action}-")))
            .count()
    };
    assert_eq!(stale(&harness, "trigger"), 1);
    assert_eq!(stale(&harness, "resolve"), 0, "{:?}", harness.calls());
    assert!(
        harness.state()["nq_watchers"]["nqd"]
            .as_object()
            .unwrap()
            .contains_key("unit-cron")
    );
    // The watcher returns with cron down: stale resolves, cron pages.
    let back = t + 120 + 60 * 40;
    for step in 1..=6 {
        append_round(&harness, back + 60 * step, |_| true);
        harness.evaluate(back + 60 * step + 3);
    }
    assert_eq!(cron_calls(&harness).len(), 2, "{:?}", harness.calls());
    // Retiring a watcher the operator removed clears it from the roster.
    harness.extra_config = harness.extra_config.replace(
        "window_records = 50",
        "window_records = 50\nretired_instances = [\"unit-ssh\"]",
    );
    let at_ = back + 60 * 7;
    append_round(&harness, at_, |envelope| {
        envelope["context"]["instance_id"] != "unit-ssh"
    });
    harness.evaluate(at_ + 3);
    assert!(
        !harness.state()["nq_watchers"]["nqd"]
            .as_object()
            .unwrap()
            .contains_key("unit-ssh")
    );
}

/// Fifth review H2a: two evaluations of one watcher in the same second; the
/// later sequence wins. H2b: a later sequence with an earlier evaluated_at
/// loses.
#[test]
fn history_ties_go_to_the_later_sequence() {
    let harness = history_harness(300);
    let t = at("2026-10-02T21:32:17Z");
    for offset in [0, 60, 120, 181, 240] {
        append_round(&harness, t + offset, |envelope| {
            set_state(envelope, "unit-cron", "present");
            true
        });
        append_round(&harness, t + offset, |envelope| {
            set_state(envelope, "unit-cron", "explicitly_absent");
            envelope["context"]["instance_id"] == "unit-cron"
        });
        harness.evaluate(t + offset + 3);
    }
    assert!(cron_calls(&harness).is_empty(), "{:?}", harness.calls());
    let harness = history_harness(300);
    for offset in [0, 60, 120, 181] {
        append_round(&harness, t + offset, |envelope| {
            set_state(envelope, "unit-cron", "present");
            true
        });
        append_round(&harness, t + offset, |envelope| {
            set_state(envelope, "unit-cron", "explicitly_absent");
            envelope["evaluated_at"] = json!(rfc3339(t + offset - 50));
            envelope["context"]["instance_id"] == "unit-cron"
        });
        harness.evaluate(t + offset + 3);
    }
    assert_eq!(cron_calls(&harness).len(), 2, "{:?}", harness.calls());
}

/// Fifth review H4: a host-posture label equal to an NQ filesystem watcher
/// id feeds one host-disk condition from two inputs. Neither wins: the
/// condition is unknown and both inputs report `unrecognised`.
#[test]
fn host_disk_fed_by_two_inputs_is_unrecognised() {
    let mut harness = history_harness(300);
    harness.host_posture("fs-root-capacity");
    let t = at("2026-10-02T21:32:17Z");
    for offset in (0..=1200).step_by(60) {
        set(
            &harness,
            "fs-root-capacity",
            ProjectedStateV1::Healthy,
            t + offset,
        );
        append_round(&harness, t + offset, |envelope| {
            set_state(envelope, "fs-root-capacity", "present");
            set_state(envelope, "unit-cron", "explicitly_absent");
            true
        });
        harness.evaluate(t + offset + 3);
    }
    let report = harness.report();
    let condition = report["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|condition| {
            condition["id"] == "constellation:reference:host_posture:host-disk:fs-root-capacity"
        })
        .unwrap()
        .clone();
    assert_eq!(condition["observation"], "unknown");
    for input in report["inputs"].as_array().unwrap() {
        assert!(
            input["causes"]
                .as_array()
                .unwrap()
                .contains(&json!("unrecognised")),
            "{input}"
        );
    }
    let calls = harness.calls();
    assert!(
        calls.iter().all(|call| !call.contains("host-disk")),
        "{calls:?}"
    );
    assert!(
        calls
            .iter()
            .any(|call| call.contains("evaluator-input-unavailable-nqd.unrecognised-trigger-")),
        "{calls:?}"
    );
}

/// Fifth review H5: an open NQ host-disk page holds through a relabel of
/// the NQ input and the removal of its filesystem watcher.
#[test]
fn nq_host_disk_holds_through_relabel_and_watcher_removal() {
    let mut harness = history_harness(300);
    let t = at("2026-10-02T21:32:17Z");
    let present = |envelope: &mut Value| {
        set_state(envelope, "fs-root-capacity", "present");
        set_state(envelope, "unit-cron", "explicitly_absent");
        true
    };
    for offset in (0..=960).step_by(60) {
        append_round(&harness, t + offset, present);
        harness.evaluate(t + offset + 3);
    }
    assert!(
        harness
            .calls()
            .iter()
            .any(|call| call.contains("host-disk-fs-root-capacity-trigger"))
    );
    harness.extra_config = harness
        .extra_config
        .replace("label = \"nqd\"", "label = \"ops\"");
    for offset in (1020..=1200).step_by(60) {
        append_round(&harness, t + offset, present);
        harness.evaluate(t + offset + 3);
    }
    for step in 1..=80 {
        let at_ = t + 1200 + 60 * step;
        append_round(&harness, at_, |envelope| {
            set_state(envelope, "unit-cron", "explicitly_absent");
            envelope["context"]["instance_id"] != "fs-root-capacity"
        });
        harness.evaluate(at_ + 3);
    }
    assert!(
        !harness
            .calls()
            .iter()
            .any(|call| call.contains("host-disk") && call.contains("-resolve-"))
    );
    let report = harness.report();
    let causes = report["inputs"][0]["causes"].as_array().unwrap();
    assert!(causes.contains(&json!("stale")), "{}", report["inputs"][0]);
    assert!(
        report["inputs"][0]["error"]
            .as_str()
            .unwrap()
            .contains("fs-root-capacity")
    );
}

/// A forward clock step leaves future evaluation times in the history and
/// the roster. After `reset-clock`, a watcher that dies is stale within the
/// bound: neither the roster nor the window keeps it fresh.
#[test]
fn watcher_dies_after_reset_clock_is_stale_within_the_bound() {
    let harness = history_harness(50);
    let t = at("2026-10-02T21:32:17Z");
    let healthy = |envelope: &mut Value| {
        set_state(envelope, "unit-cron", "explicitly_absent");
        true
    };
    for offset in [0, 60] {
        append_round(&harness, t + offset, healthy);
        harness.evaluate(t + offset + 3);
    }
    // One pass at a clock stepped forward a day.
    append_round(&harness, t + 86_400, healthy);
    harness.evaluate(t + 86_403);
    assert_eq!(
        harness.state()["nq_watchers"]["nqd"]["unit-cron"],
        t + 86_397
    );
    let config = harness.config_path();
    let now = rfc3339(t + 300);
    let output = harness.command(&[
        "reset-clock",
        "--config",
        config.to_str().unwrap(),
        "--now",
        &now,
    ]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(harness.state()["nq_watchers"]["nqd"]["unit-cron"], t + 300);
    // cron's watcher dies at the corrected time.
    let mut stale_at = None;
    for step in 1..=6 {
        let at_ = t + 300 + 60 * step;
        append_round(&harness, at_, |envelope| {
            envelope["context"]["instance_id"] != "unit-cron"
        });
        let report = harness.evaluate(at_ + 3);
        let causes = report["inputs"][0]["causes"].as_array().unwrap().clone();
        if stale_at.is_none() && causes.contains(&json!("stale")) {
            stale_at = Some(60 * step);
        }
    }
    // Stale once more than 180 s have passed since t + 300.
    assert_eq!(stale_at, Some(240), "{:?}", harness.report()["inputs"][0]);
}

/// Roster ids are bounded, and error text carrying ids is truncated.
#[test]
fn roster_ids_are_bounded_and_error_text_truncated() {
    let harness = history_harness(300);
    let t = at("2026-10-02T21:32:17Z");
    let long = "w".repeat(200);
    append_round(&harness, t, |envelope| {
        if envelope["context"]["instance_id"] == "unit-ssh" {
            envelope["context"]["instance_id"] = json!(long.clone());
        }
        true
    });
    let report = harness.evaluate(t + 3);
    let roster = harness.state()["nq_watchers"]["nqd"].clone();
    assert!(!roster.as_object().unwrap().contains_key(&long));
    assert!(roster.as_object().unwrap().contains_key("unit-cron"));
    let error = report["inputs"][0]["error"].as_str().unwrap();
    assert!(error.contains("beyond 128 printable bytes"), "{error}");
    // Many stale watchers: the listed ids are cut at 512 bytes.
    let harness = history_harness(2000);
    for index in 0..100 {
        append_round(&harness, t - 3600, |envelope| {
            let instance = envelope["context"]["instance_id"]
                .as_str()
                .unwrap()
                .to_owned();
            envelope["context"]["instance_id"] = json!(format!("{instance}-{index}"));
            true
        });
    }
    harness.fake("history_generated_at", &rfc3339(t));
    let report = harness.evaluate(t + 3);
    let error = report["inputs"][0]["error"].as_str().unwrap();
    assert!(error.len() < 2048, "{}", error.len());
}

// PagerDuty routing semantics: response_class.

/// Every intent carries `response_class`: v2 is always `page`; v1 is `page`
/// for a page rule's decision, `attention` for a notice rule and for a
/// configuration-removal resolve. The fake nq refuses a v2 intent that is
/// not a page, as NQ does, so the suite proves none reaches PagerDuty.
#[test]
fn every_intent_carries_its_response_class() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    for offset in (0..=660).step_by(60) {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    let intent = |harness: &Harness, call: &str| -> Value {
        let id = call.split(' ').nth(3).unwrap();
        serde_json::from_slice(&harness.submitted_intent(id)).unwrap()
    };
    let calls = harness.calls();
    // host-posture-unknown (page): the notice and the page both say page.
    assert!(calls[0].starts_with("submit operations ") && calls[0].contains("-trigger-"));
    assert_eq!(intent(&harness, &calls[0])["response_class"], "page");
    assert!(calls[1].starts_with("submit pagerduty-ops "));
    assert_eq!(intent(&harness, &calls[1])["response_class"], "page");
    // Removing the page rule from configuration: the resolve is attention
    // on the notice route and still a page on PagerDuty.
    harness.raw("[rules.host-posture-unknown]\nenabled = false\n");
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 720);
    let report = harness.evaluate(T0 + 720);
    assert_eq!(intents(&report).len(), 2);
    let calls = harness.calls();
    assert!(calls[2].starts_with("submit operations ") && calls[2].contains("-resolve-"));
    assert_eq!(intent(&harness, &calls[2])["response_class"], "attention");
    assert!(calls[3].starts_with("submit pagerduty-ops ") && calls[3].contains("-resolve-"));
    assert_eq!(intent(&harness, &calls[3])["response_class"], "page");
    // host-disk (attention): a notice only.
    for offset in (780..=1740).step_by(60) {
        set(&harness, "root", ProjectedStateV1::Degraded, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    let calls = harness.calls();
    assert_eq!(calls.len(), 5, "{calls:?}");
    assert!(
        calls[4].starts_with("submit operations ") && calls[4].contains("host-disk-root-trigger")
    );
    assert_eq!(intent(&harness, &calls[4])["response_class"], "attention");
    // Every v2 the fake accepted is a page.
    for call in calls.iter().filter(|call| call.contains("pagerduty-ops")) {
        let value = intent(&harness, call);
        assert_eq!(value["schema"], "nq.notification_delivery_intent.v2");
        assert_eq!(value["response_class"], "page");
    }
}

/// Strip `response_class` from the retained page intent, as a build before
/// 784df43 wrote it.
fn make_legacy_page(harness: &Harness) {
    let file = harness.state()["conditions"][UNKNOWN_ROOT]["last_intent"]["page"]["intent_file"]
        .as_str()
        .unwrap()
        .to_owned();
    let path = harness.path("state/intents").join(file);
    let mut intent: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    intent.as_object_mut().unwrap().remove("response_class");
    fs::write(&path, serde_jcs::to_vec(&intent).unwrap()).unwrap();
}

/// NQ 0.2.2 (mirrored by the fake) retains a non-page v2 as a refused
/// record, reason `response_class_not_page`, and sends nothing.
#[test]
fn fake_nq_retains_a_non_page_v2_as_refused() {
    let harness = Harness::new();
    let intent = harness.path("legacy.json");
    fs::write(
        &intent,
        br#"{"schema":"nq.notification_delivery_intent.v2","stable_event_id":"reference-x-trigger-1"}"#,
    )
    .unwrap();
    let output = Command::new(Path::new(FIXTURES).join("fake-nq.sh"))
        .args([
            "--config",
            "/etc/nq/nqd-ops.toml",
            "--json",
            "notification",
            "submit",
        ])
        .arg("--intent")
        .arg(&intent)
        .args(["--route", "pagerduty-ops", "--enable-network"])
        .env("FAKE_NQ_DIR", harness.path("fake"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let answer: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(answer["delivery_state"], "refused");
    assert_eq!(answer["notification_id"], "n1");
}

/// Round-5-style state across the upgrade: a page retained `failed` whose
/// intent file has no `response_class`. Resubmitting that record would be
/// refused every 120 s; instead the page is re-rendered under a new event
/// id, submitted, and delivered.
#[test]
fn legacy_failed_page_is_rerendered_and_delivered() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    harness.fake("next_state", "failed");
    for offset in [0, 660] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    make_legacy_page(&harness);
    // NQ's retained copy of that record is the legacy intent too.
    harness.fake("records/nopage-n2", "");
    harness.fake("next_state", "accepted");
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 780);
    let output = harness.evaluate_at(T0 + 780, &[]);
    assert!(String::from_utf8_lossy(&output.stderr).contains("re-rendered as a page"));
    let calls = harness.calls();
    assert_eq!(
        calls[2],
        "submit pagerduty-ops reference-host-posture-unknown-root-trigger-1790943180 n3 accepted new",
        "{calls:?}"
    );
    let intent: Value = serde_json::from_slice(&harness.submitted_intent("n3")).unwrap();
    assert_eq!(intent["response_class"], "page");
    assert_eq!(
        intent["transition_id"],
        "reference-host-posture-unknown-root-trigger-1790943060"
    );
    assert_eq!(
        harness.state()["conditions"][UNKNOWN_ROOT]["last_intent"]["page"]["outcome"],
        "accepted"
    );
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 1200);
    harness.evaluate(T0 + 1200);
    assert!(
        harness
            .calls()
            .iter()
            .all(|call| !call.starts_with("resubmit")),
        "{:?}",
        harness.calls()
    );
}

/// A legacy page that NQ never answered (command error before custody) is
/// re-rendered on the next pass rather than sent again as non-page bytes.
#[test]
fn legacy_unanswered_page_is_rerendered() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    harness.fake("command_error", "");
    for offset in [0, 660] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    make_legacy_page(&harness);
    fs::remove_file(harness.path("fake/command_error")).unwrap();
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 720);
    harness.evaluate(T0 + 720);
    let calls = harness.calls();
    let page: Vec<&String> = calls
        .iter()
        .filter(|call| call.contains("pagerduty-ops"))
        .collect();
    assert_eq!(page.len(), 1, "{calls:?}");
    assert!(page[0].ends_with(" accepted new"), "{calls:?}");
    assert!(page[0].contains("-trigger-1790943120"), "{calls:?}");
}

// response_policy (cartography #55).

fn remediation_harness(window: Option<i64>) -> (Harness, PathBuf) {
    let (mut harness, status) = nq_status_harness();
    harness.raw(&format!(
        "[[remediation.targets]]\nrule = \"service-down\"\ntarget_class = \"cron.service\"\n\
         policy = \"auto_remediate_then_page\"\n{}",
        window.map_or_else(String::new, |window| format!("window_seconds = {window}\n"))
    ));
    (harness, status)
}

fn cron_row(report: &Value) -> Value {
    report["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|condition| condition["id"] == CRON)
        .unwrap()
        .clone()
}

/// Default: every rule is observe_only, and service-down pages at the bound.
#[test]
fn observe_only_is_the_default_policy() {
    let (harness, status) = nq_status_harness();
    let t = trigger_cron(&harness, &status);
    let report = harness.report();
    let row = cron_row(&report);
    assert_eq!(row["response_policy"], "observe_only");
    assert_eq!(row["remediation_window_until"], Value::Null);
    assert!(harness.calls()[1].starts_with("submit pagerduty-ops "));
    let _ = t;
}

/// auto_remediate_then_page: the notice goes out at the bound, the page
/// waits for the remediation window (first_seen + 240 s) and goes out once
/// the condition is still present then.
#[test]
fn remediation_target_defers_the_page_until_the_window_expires() {
    let (harness, status) = remediation_harness(None);
    let t = at("2026-10-02T21:32:17Z");
    let first_seen = t + 3;
    let mut report = Value::Null;
    for offset in [0, 60, 120, 181] {
        write_status(&status, &retimed("cron-down.json", t + offset, |_| {}));
        report = harness.evaluate(t + offset + 3);
    }
    assert_eq!(
        intents(&report),
        vec![(CRON.into(), "notice".into(), "trigger".into())]
    );
    let row = cron_row(&report);
    assert_eq!(row["response_policy"], "auto_remediate_then_page");
    assert_eq!(row["remediation_window_until"], first_seen + 240);
    assert_eq!(row["page_deferred"], true);
    assert!(
        cron_calls(&harness)
            .iter()
            .all(|call| !call.contains("pagerduty"))
    );
    // Still present inside the window: held.
    write_status(&status, &retimed("cron-down.json", t + 236, |_| {}));
    assert!(intents(&harness.evaluate(t + 239)).is_empty());
    // At the window's end and present: the page goes out.
    write_status(&status, &retimed("cron-down.json", t + 240, |_| {}));
    let report = harness.evaluate(t + 243);
    assert_eq!(
        intents(&report),
        vec![(CRON.into(), "page".into(), "trigger".into())]
    );
    let calls = cron_calls(&harness);
    assert_eq!(calls.len(), 2, "{calls:?}");
    let id = calls[1].split(' ').nth(3).unwrap();
    let intent: Value = serde_json::from_slice(&harness.submitted_intent(id)).unwrap();
    assert_eq!(intent["response_class"], "page");
    assert_eq!(
        intent["transition_id"],
        format!("reference-service-down-cron.service-trigger-{}", t + 184)
    );
    assert_eq!(
        intent["stable_event_id"],
        format!("reference-service-down-cron.service-trigger-{}", t + 243)
    );
    // Never twice; recovery then resolves on both routes.
    for offset in [300, 360] {
        write_status(&status, &retimed("cron-down.json", t + offset, |_| {}));
        harness.evaluate(t + offset + 3);
    }
    assert_eq!(cron_calls(&harness).len(), 2);
    for offset in [420, 480, 540] {
        write_status(
            &status,
            &retimed(
                "cron-down.json",
                t + offset,
                cron_state("explicitly_absent"),
            ),
        );
        harness.evaluate(t + offset + 3);
    }
    let calls = cron_calls(&harness);
    assert_eq!(
        calls
            .iter()
            .filter(|call| call.contains("-resolve-"))
            .count(),
        2,
        "{calls:?}"
    );
}

/// A condition that clears inside the remediation window never pages; the
/// resolve notice says it recovered within the window.
#[test]
fn recovery_inside_the_remediation_window_never_pages() {
    let (harness, status) = remediation_harness(None);
    let t = at("2026-10-02T21:32:17Z");
    for offset in [0, 60, 120, 181] {
        write_status(&status, &retimed("cron-down.json", t + offset, |_| {}));
        harness.evaluate(t + offset + 3);
    }
    for offset in (200..=380).step_by(60) {
        write_status(
            &status,
            &retimed(
                "cron-down.json",
                t + offset,
                cron_state("explicitly_absent"),
            ),
        );
        harness.evaluate(t + offset + 3);
    }
    let calls = cron_calls(&harness);
    assert!(
        calls.iter().all(|call| !call.contains("pagerduty")),
        "{calls:?}"
    );
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert!(calls[1].starts_with("submit operations ") && calls[1].contains("-resolve-"));
    let id = calls[1].split(' ').nth(3).unwrap();
    let intent: Value = serde_json::from_slice(&harness.submitted_intent(id)).unwrap();
    assert!(
        intent["summary"]
            .as_str()
            .unwrap()
            .ends_with("recovered within the remediation window; no page was sent."),
        "{intent}"
    );
    assert_eq!(intent["response_class"], "attention");
}

#[test]
fn remediation_configuration_refusals() {
    for (toml, message) in [
        (
            "[[remediation.targets]]\nrule = \"host-disk\"\ntarget_class = \"root\"\npolicy = \"auto_remediate_then_page\"\n",
            "cannot carry remediation targets",
        ),
        (
            "[[remediation.targets]]\nrule = \"service-down\"\ntarget_class = \"getty@tty1.service\"\npolicy = \"auto_remediate_then_page\"\n",
            "remediation target_class",
        ),
        (
            "[[remediation.targets]]\nrule = \"service-down\"\ntarget_class = \"cron.service\"\npolicy = \"observe_only\"\n",
            "must be auto_remediate_then_page",
        ),
        (
            "[[remediation.targets]]\nrule = \"service-down\"\ntarget_class = \"cron.service\"\npolicy = \"auto_remediate_then_page\"\nwindow_seconds = 30\n",
            "window_seconds must be 60..=600",
        ),
        (
            "[[remediation.targets]]\nrule = \"service-down\"\ntarget_class = \"cron.service\"\npolicy = \"auto_remediate_then_page\"\n\
             [[remediation.targets]]\nrule = \"service-down\"\ntarget_class = \"cron.service\"\npolicy = \"auto_remediate_then_page\"\nwindow_seconds = 300\n",
            "listed twice",
        ),
        (
            "[[remediation.targets]]\nrule = \"service-down\"\ntarget_class = \"cron.service\"\npolicy = \"restart\"\n",
            "invalid configuration",
        ),
    ] {
        let mut harness = Harness::new();
        harness.raw(toml);
        let config = harness.config_path();
        let output = harness.command(&["check-config", "--config", config.to_str().unwrap()]);
        assert_eq!(output.status.code(), Some(2), "{toml}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(message), "{toml}: {stderr}");
    }
    let mut harness = Harness::new();
    harness.raw(
        "[[remediation.targets]]\nrule = \"service-down\"\ntarget_class = \"attention-canary.service\"\npolicy = \"auto_remediate_then_page\"\nwindow_seconds = 240\n",
    );
    let config = harness.config_path();
    let output = harness.command(&["check-config", "--config", config.to_str().unwrap()]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Review F1: a held page whose input goes stale (unknown) across the window's
/// end is not held forever: it goes out at the first pass after expiry, and a
/// later recovery resolves both routes as an ordinary recovery.
#[test]
fn held_page_with_stale_input_pages_at_window_expiry() {
    let (harness, status) = remediation_harness(Some(600));
    let t = at("2026-10-02T21:32:17Z");
    for offset in [0, 60, 120, 181] {
        write_status(&status, &retimed("cron-down.json", t + offset, |_| {}));
        harness.evaluate(t + offset + 3);
    }
    // The last status (present) is never refreshed: the input goes stale.
    let mut paged_at = None;
    for offset in (241..=3600).step_by(60) {
        harness.evaluate(t + offset);
        if paged_at.is_none()
            && cron_calls(&harness)
                .iter()
                .any(|call| call.contains("pagerduty"))
        {
            paged_at = Some(offset);
        }
    }
    let paged_at = paged_at.expect("the held page never went out");
    assert!(
        (603..=663).contains(&paged_at),
        "paged at {paged_at}, window ends at 603"
    );
    let row = cron_row(&harness.report());
    assert_eq!(row["page_deferred"], false);
    let pages = cron_calls(&harness)
        .iter()
        .filter(|call| call.contains("pagerduty") && call.contains("-trigger-"))
        .count();
    assert_eq!(pages, 1);
    // Recovery after the window: both routes resolve, not "within the window".
    for offset in (3601..=3900).step_by(60) {
        write_status(
            &status,
            &retimed(
                "cron-down.json",
                t + offset,
                cron_state("explicitly_absent"),
            ),
        );
        harness.evaluate(t + offset + 3);
    }
    let calls = cron_calls(&harness);
    assert!(
        calls
            .iter()
            .any(|call| call.contains("pagerduty") && call.contains("-resolve-")),
        "{calls:?}"
    );
}
