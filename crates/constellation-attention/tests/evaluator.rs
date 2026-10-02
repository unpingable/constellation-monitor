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
             site = \"labelwatch\"\n\
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
    let cron = "constellation:labelwatch:service:service-down:cron.service";
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
        json!({"component":"service","rule":"service-down","site":"labelwatch","target_class":"cron.service"})
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
        calls[0]
            .starts_with("submit operations labelwatch-evaluator-input-unavailable-nqd-trigger-")
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

const CRON: &str = "constellation:labelwatch:service:service-down:cron.service";

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
            .any(|call| call.contains("labelwatch-evaluator-input-unavailable-nqd-trigger-")),
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
            .contains("open condition constellation:labelwatch:service:service-down:cron.service is no longer reported"),
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
            .any(|call| call.contains("labelwatch-evaluator-input-unavailable-nqd-trigger-")),
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
    assert!(calls[0].contains("labelwatch-evaluator-input-unavailable-nqd-trigger-"));
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
            "submit operations labelwatch-host-posture-unknown-root-trigger-1790943060 n1 accepted new",
            "submit pagerduty-ops labelwatch-host-posture-unknown-root-trigger-1790943060 n2 accepted new",
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
            "submit operations labelwatch-host-posture-unknown-root-trigger-1790943060 n1 accepted new",
            "submit pagerduty-ops labelwatch-host-posture-unknown-root-trigger-1790943060 n2 accepted new",
            "submit operations labelwatch-host-posture-unknown-root-resolve-1790943780 n3 accepted new",
            "submit pagerduty-ops labelwatch-host-posture-unknown-root-resolve-1790943780 n4 accepted new",
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
        "labelwatch-host-posture-unknown-root-trigger-1790943060"
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

/// Review A5: a missing retained intent file fails that follow-up only.
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
    let file = harness.state()["conditions"][UNKNOWN_ROOT]["last_intent"]["page"]["intent_file"]
        .as_str()
        .unwrap()
        .to_owned();
    fs::remove_file(harness.path("state/intents").join(file)).unwrap();
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
    let data = "labelwatch-host-posture-unknown-data-trigger-";
    let calls = harness.calls();
    assert_eq!(
        calls.iter().filter(|call| call.contains(data)).count(),
        2,
        "the second condition is still notified: {calls:?}"
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
    assert!(calls[0].contains("labelwatch-evaluator-input-unavailable-root-trigger-"));
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
    harness.raw("[rules.host-disk]\nclass = \"page\"\n");
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
            .filter(|call| call.contains("labelwatch-host-disk-root-trigger-"))
            .count()
    };
    set(&harness, "root", ProjectedStateV1::Degraded, T0 + 960);
    harness.evaluate(T0 + 960);
    assert_eq!(disk(&harness.calls()), 0, "{:?}", harness.calls());
    let state = harness.state();
    assert_eq!(
        state["conditions"]["constellation:labelwatch:host_posture:host-disk:root"]["first_seen"],
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
    assert_eq!(disk(&harness.calls()), 2, "{:?}", harness.calls());
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
            "submit local:operations labelwatch-host-posture-unknown-root-trigger-1790943060 n1 accepted new"
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
            "submit local:operations labelwatch-host-posture-unknown-root-resolve-1790943240 n2 failed new",
            "submit local:operations labelwatch-host-posture-unknown-root-resolve-1790944140 n3 accepted new",
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
