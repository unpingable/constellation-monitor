//! Evaluator passes against fixture inputs and a fake `nq` that records submissions.
//!
//! Chosen-time, persistent passes use the debug CLI where available and the
//! public engine API in release builds. Both run in a child process so crash
//! recovery, environment isolation, files, and delivery assertions stay identical.
//! Dry runs and real-clock passes exercise the CLI in both profiles.

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
    page_reference: &'static str,
    page_transport: &'static str,
    notice_reference: &'static str,
    network: bool,
    notice_transport: &'static str,
    runbook_base: &'static str,
    nq_routes_override: Option<String>,
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
            page_reference: "pagerduty-ops",
            page_transport: "pagerduty",
            notice_reference: "operations",
            network: true,
            notice_transport: "slack",
            runbook_base: "https://docs.example.org/beta-observability/RUNBOOKS.md",
            nq_routes_override: None,
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
        let nq_config = self.path("nq.toml");
        fs::write(
            &nq_config,
            self.nq_routes_override.clone().unwrap_or_else(|| {
                format!(
                    "[[notification_routes]]\nreference = {:?}\ntransport = {:?}\n{}",
                    self.page_reference,
                    self.page_transport,
                    if self.notice_reference == self.page_reference {
                        String::new()
                    } else {
                        format!(
                            "[[notification_routes]]\nreference = {:?}\ntransport = {:?}\n",
                            self.notice_reference, self.notice_transport
                        )
                    },
                )
            }),
        )
        .unwrap();
        let page = if self.page_route {
            format!("page_route = {:?}\n", self.page_reference)
        } else {
            String::new()
        };
        let text = format!(
            "schema = \"constellation.attention_config.v1\"\n\
             site = \"labelwatch\"\n\
             state_path = \"{state}\"\n\
             [runbooks]\n\
             cartography_url = \"{runbook_base}\"\n\
             [nq]\n\
             program = \"{nq}\"\n\
             config = \"{nq_config}\"\n\
             [routes]\n\
             notice_route = \"{notice_reference}\"\n\
             notice_transport = \"{transport}\"\n\
             {page}\
             network_enabled = {network}\n\
             {extra}\n",
            state = self.path("state/state.json").display(),
            nq_config = nq_config.display(),
            notice_reference = self.notice_reference,
            nq = Path::new(FIXTURES).join("fake-nq.sh").display(),
            network = self.network,
            transport = self.notice_transport,
            runbook_base = self.runbook_base,
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
        if extra == ["--dry-run"] {
            return self.evaluate_cli_at(at, extra);
        }
        assert!(extra.is_empty(), "unexpected test arguments: {extra:?}");
        self.evaluate_persisted_at(at)
    }

    // Persistent chosen-time CLI passes are documented as debug-only.
    #[cfg(debug_assertions)]
    fn evaluate_persisted_at(&self, at: i64) -> Output {
        self.evaluate_cli_at(at, &[])
    }

    #[cfg(not(debug_assertions))]
    fn evaluate_persisted_at(&self, at: i64) -> Output {
        self.engine_at("evaluate", at)
    }

    fn evaluate_cli_at(&self, at: i64, extra: &[&str]) -> Output {
        #[cfg(not(debug_assertions))]
        assert_eq!(extra, ["--dry-run"]);
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

    // Choosing reset-clock's time is documented as debug-only too.
    #[cfg(debug_assertions)]
    fn reset_clock_at(&self, at: i64) -> Output {
        self.command(&[
            "reset-clock",
            "--config",
            self.config_path().to_str().unwrap(),
            "--now",
            &rfc3339(at),
        ])
    }

    #[cfg(not(debug_assertions))]
    fn reset_clock_at(&self, at: i64) -> Output {
        self.engine_at("reset-clock", at)
    }

    #[cfg(not(debug_assertions))]
    fn engine_at(&self, operation: &str, at: i64) -> Output {
        let result_path = self.path("engine-result.json");
        let mut output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "engine_process", "--ignored", "--nocapture"])
            .env("ATTENTION_TEST_CONFIG", self.config_path())
            .env("ATTENTION_TEST_NOW", at.to_string())
            .env("ATTENTION_TEST_OPERATION", operation)
            .env("ATTENTION_TEST_RESULT", &result_path)
            .env("FAKE_NQ_DIR", self.path("fake"))
            .output()
            .unwrap();
        if operation == "reset-clock" && output.status.success() {
            output.stdout = fs::read(result_path).unwrap();
        }
        output
    }

    fn evaluate_now(&self) -> Output {
        self.command(&["evaluate", "--config", self.config_path().to_str().unwrap()])
    }

    fn evaluate(&self, at: i64) -> Value {
        let output = self.evaluate_at(at, &[]);
        assert!(
            matches!(output.status.code(), Some(0 | 3 | 4)),
            "pass failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report = self.report();
        assert_eq!(
            report["exit_code"],
            output.status.code().unwrap(),
            "{report}"
        );
        assert!(
            matches!(
                (
                    output.status.code().unwrap(),
                    report["exit_class"].as_str().unwrap()
                ),
                (0, "clean")
                    | (3, "input_error")
                    | (
                        4,
                        "delivery_partial" | "delivery_failed" | "intent_log_unwritable"
                    )
            ),
            "{report}"
        );
        report
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

/// Release counterpart to the debug CLI's chosen-time path. Keep each pass
/// isolated: the fake NQ deliberately kills its parent in crash-recovery tests.
#[cfg(not(debug_assertions))]
#[test]
#[ignore = "subprocess entry point for chosen-time engine passes"]
fn engine_process() {
    use constellation_attention::config::Config;
    use constellation_attention::engine::{self, PassOptions};

    let config_path = std::env::var_os("ATTENTION_TEST_CONFIG").unwrap();
    let config = Config::load(Path::new(&config_path)).unwrap();
    let now = std::env::var("ATTENTION_TEST_NOW")
        .unwrap()
        .parse::<i64>()
        .unwrap();
    let result = match std::env::var("ATTENTION_TEST_OPERATION").unwrap().as_str() {
        "evaluate" => engine::evaluate(
            &config,
            &PassOptions {
                dry_run: false,
                now,
                now_ms: now * 1000,
            },
        )
        .map(|result| result.exit_code),
        "reset-clock" => engine::reset_clock(&config, now).map(|answer| {
            fs::write(
                std::env::var_os("ATTENTION_TEST_RESULT").unwrap(),
                serde_json::to_vec(&answer).unwrap(),
            )
            .unwrap();
            0
        }),
        operation => panic!("unexpected test operation: {operation}"),
    };
    std::process::exit(match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("constellation-attention: {error}");
            1
        }
    });
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

fn system_seconds() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

#[test]
fn chosen_time_cli_dry_run_does_not_create_live_state() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    set(&harness, "root", ProjectedStateV1::Healthy, T0);
    let output = harness.evaluate_at(T0, &["--dry-run"]);
    assert_eq!(output.status.code(), Some(0));
    let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["evaluated_at"], rfc3339(T0));
    assert_eq!(summary["dry_run"], true);
    assert!(harness.path("state/dry-run/report.json").is_file());
    assert!(!harness.path("state/state.json").exists());
    assert!(!harness.path("state/report.json").exists());
    assert!(harness.calls().is_empty());
}

#[cfg(not(debug_assertions))]
#[test]
fn release_cli_refuses_chosen_time_for_persistent_commands() {
    let harness = Harness::new();
    for (command, message) in [
        ("evaluate", "--now is accepted only with --dry-run"),
        ("reset-clock", "reset-clock uses the system clock"),
    ] {
        let output = harness.command(&[
            command,
            "--config",
            harness.config_path().to_str().unwrap(),
            "--now",
            &rfc3339(T0),
        ]);
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains(message));
        assert!(!harness.path("state/state.json").exists());
        assert!(!harness.path("state/report.json").exists());
        assert!(harness.calls().is_empty());
    }
}

/// Exercise the shipped CLI's persistent path without a chosen time. Age
/// persisted intervals instead of sleeping; leave ample input freshness.
#[test]
fn real_clock_cli_persists_delivers_resets_and_resolves() {
    let mut harness = Harness::new();
    harness.page_route = false;
    harness.network = false;
    harness.notice_transport = "local_file";
    harness.host_posture("root");
    harness.fake("local_route", "operations");
    let start = system_seconds();
    publish(
        &harness.root("root"),
        &status_object(ProjectedStateV1::Unknown, start - 5, 3600),
    );
    assert_eq!(harness.evaluate_now().status.code(), Some(0));
    assert!(intents(&harness.report()).is_empty());
    let mut state = harness.state();
    assert!((start..=system_seconds()).contains(&state["updated_at"].as_i64().unwrap()));
    state["conditions"][UNKNOWN_ROOT]["first_seen"] = json!(start - 3600);
    fs::write(
        harness.path("state/state.json"),
        serde_json::to_vec(&state).unwrap(),
    )
    .unwrap();
    assert_eq!(harness.evaluate_now().status.code(), Some(0));
    assert_eq!(
        intents(&harness.report()),
        vec![(UNKNOWN_ROOT.into(), "notice".into(), "trigger".into())]
    );
    assert_eq!(harness.report()["dry_run"], false);
    let trigger: Value = serde_json::from_slice(&harness.submitted_intent("n1")).unwrap();
    assert_eq!(trigger["destination_identity"], "local-inbox:operations");
    assert!(trigger["summary"].as_str().unwrap().starts_with("TRIGGER "));
    assert!(
        trigger["stable_event_id"]
            .as_str()
            .unwrap()
            .starts_with("labelwatch-host-posture-unknown-root-trigger-")
    );
    assert!(harness.calls()[0].starts_with("submit local:operations "));
    let mut state = harness.state();
    assert_eq!(state["conditions"][UNKNOWN_ROOT]["active"], true);
    let retained = state["conditions"][UNKNOWN_ROOT]["last_intent"].clone();
    assert_eq!(retained["notice"]["outcome"], "accepted");
    assert_eq!(harness.evaluate_now().status.code(), Some(0));
    assert!(intents(&harness.report()).is_empty());
    assert_eq!(harness.calls().len(), 1);

    // Simulate a corrected forward clock step, then use release-safe reset-clock.
    state["updated_at"] = json!(system_seconds() + 86_400);
    let future_state = serde_json::to_vec(&state).unwrap();
    fs::write(harness.path("state/state.json"), &future_state).unwrap();
    let refused = harness.evaluate_now();
    assert_eq!(refused.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("the clock moved backwards"));
    assert_eq!(
        fs::read(harness.path("state/state.json")).unwrap(),
        future_state
    );
    let log_before = fs::read(harness.path("state/intents.jsonl")).unwrap();
    let reset_start = system_seconds();
    let output = harness.command(&[
        "reset-clock",
        "--config",
        harness.config_path().to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(0));
    let answer: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(answer["clamped_timestamps"].as_u64().unwrap() >= 1);
    let state = harness.state();
    assert!((reset_start..=system_seconds()).contains(&state["updated_at"].as_i64().unwrap()));
    assert_eq!(state["conditions"][UNKNOWN_ROOT]["active"], true);
    assert_eq!(state["conditions"][UNKNOWN_ROOT]["last_intent"], retained);
    assert_eq!(
        fs::read(harness.path("state/intents.jsonl")).unwrap(),
        log_before
    );
    assert_eq!(harness.calls().len(), 1);

    publish(
        &harness.root("root"),
        &status_object(ProjectedStateV1::Healthy, system_seconds() - 5, 3600),
    );
    assert_eq!(harness.evaluate_now().status.code(), Some(0));
    assert!(intents(&harness.report()).is_empty());
    let mut state = harness.state();
    assert!(state["conditions"][UNKNOWN_ROOT]["clear_since"].is_i64());
    state["conditions"][UNKNOWN_ROOT]["clear_since"] = json!(system_seconds() - 600);
    fs::write(
        harness.path("state/state.json"),
        serde_json::to_vec(&state).unwrap(),
    )
    .unwrap();
    assert_eq!(harness.evaluate_now().status.code(), Some(0));
    assert_eq!(
        intents(&harness.report()),
        vec![(UNKNOWN_ROOT.into(), "notice".into(), "resolve".into())]
    );
    let resolve: Value = serde_json::from_slice(&harness.submitted_intent("n2")).unwrap();
    assert_eq!(resolve["destination_identity"], "local-inbox:operations");
    assert!(resolve["summary"].as_str().unwrap().starts_with("RESOLVE "));
    assert!(
        resolve["stable_event_id"]
            .as_str()
            .unwrap()
            .starts_with("labelwatch-host-posture-unknown-root-resolve-")
    );
    assert_eq!(harness.calls().len(), 2);
    assert!(harness.state()["conditions"][UNKNOWN_ROOT].is_null());
    let log = fs::read_to_string(harness.path("state/intents.jsonl")).unwrap();
    let actions: Vec<Value> = log
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(actions.len(), 2);
    assert_eq!(actions[0]["action"], "trigger");
    assert_eq!(actions[1]["action"], "resolve");
    assert!(actions.iter().all(|entry| entry["outcome"] == "accepted"));
}

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
    for index in 0..4 {
        let intent: Value = serde_json::from_slice(&harness.submitted_intent(&id(index))).unwrap();
        if intent["schema"] == "nq.notification_delivery_intent.v1" {
            assert!(
                intent.get("runbook_url").is_none(),
                "v1 refuses all unknown fields"
            );
        } else {
            assert_eq!(intent["runbook_url"], intent["inspection_reference"]);
        }
    }
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
fn loopback_runbooks_reach_notice_and_page_without_nq_runbook_url() {
    let mut harness = Harness::new();
    harness.runbook_base = "http://127.0.0.1:8088/RUNBOOKS.md";
    harness.host_posture("root");
    // The fake NQ rejects any HTTP runbook_url before retaining the intent.
    for offset in [0, 660, 720, 840] {
        let state = if offset < 700 {
            ProjectedStateV1::Unknown
        } else {
            ProjectedStateV1::Healthy
        };
        set(&harness, "root", state, T0 + offset);
        let output = harness.evaluate_at(T0 + offset, &[]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert_eq!(harness.report()["exit_code"], 0);
        assert_eq!(harness.report()["exit_class"], "clean");
        assert!(harness.report()["first_error"].is_null());
        assert_eq!(
            String::from_utf8_lossy(&output.stderr)
                .matches("runbook_url_withheld:")
                .count(),
            usize::from(offset == 660 || offset == 840)
        );
        if offset == 660 || offset == 840 {
            assert!(String::from_utf8_lossy(&output.stderr).contains("for 1 intents"));
        }
    }
    let calls = harness.calls();
    assert_eq!(calls.len(), 4, "{calls:?}");
    for (index, name) in [
        "http-trigger-notice-v1.json",
        "http-trigger-page-v2.json",
        "http-resolve-notice-v1.json",
        "http-resolve-page-v2.json",
    ]
    .iter()
    .enumerate()
    {
        let id = calls[index].split(' ').nth(3).unwrap();
        let bytes = harness.submitted_intent(id);
        golden(name, &bytes);
        let intent: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(intent.get("runbook_url").is_none());
        assert_eq!(
            intent["inspection_reference"],
            "http://127.0.0.1:8088/RUNBOOKS.md#host-posture-unknown"
        );
    }
}

#[test]
fn rehearsal_local_page_route_delivers_v1_with_loopback_runbooks() {
    let mut harness = Harness::new();
    harness.runbook_base = "http://127.0.0.1:8088/RUNBOOKS.md";
    harness.page_reference = "site-page-inbox";
    harness.page_transport = "local_file";
    harness.network = false;
    harness.fake("local_route", "site-page-inbox");
    harness.host_posture("root");
    for (offset, state) in [
        (0, ProjectedStateV1::Unknown),
        (660, ProjectedStateV1::Unknown),
        (720, ProjectedStateV1::Healthy),
        (840, ProjectedStateV1::Healthy),
    ] {
        set(&harness, "root", state, T0 + offset);
        let output = harness.evaluate_at(T0 + offset, &[]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert!(!String::from_utf8_lossy(&output.stderr).contains("runbook_url_withheld:"));
        let report = harness.report();
        assert_eq!(report["page_delivery"], "local_file route; v1 copy");
        assert_eq!(report["exit_class"], "clean");
        assert!(report["first_error"].is_null());
    }
    let calls = harness.calls();
    assert_eq!(calls.len(), 4, "{calls:?}");
    for (index, call) in calls.iter().enumerate() {
        let id = call.split(' ').nth(3).unwrap();
        let intent: Value = serde_json::from_slice(&harness.submitted_intent(id)).unwrap();
        assert_eq!(intent["schema"], "nq.notification_delivery_intent.v1");
        assert!(intent.get("runbook_url").is_none());
        assert_eq!(intent["response_class"], "page");
        assert_eq!(
            intent["inspection_reference"],
            "http://127.0.0.1:8088/RUNBOOKS.md#host-posture-unknown"
        );
        if index % 2 == 1 {
            assert!(call.starts_with("submit local:site-page-inbox "), "{call}");
            assert!(call.contains(" accepted "), "{call}");
            assert_eq!(
                intent["destination_identity"],
                "local-inbox:site-page-inbox"
            );
        }
    }
}

#[test]
fn shared_local_page_and_notice_route_delivers_one_copy() {
    let mut harness = Harness::new();
    harness.page_reference = "site-page-inbox";
    harness.page_transport = "local_file";
    harness.notice_reference = "site-page-inbox";
    harness.notice_transport = "local_file";
    harness.network = false;
    harness.fake("local_route", "site-page-inbox");
    harness.host_posture("root");
    for (offset, state) in [
        (0, ProjectedStateV1::Unknown),
        (660, ProjectedStateV1::Unknown),
        (720, ProjectedStateV1::Healthy),
        (840, ProjectedStateV1::Healthy),
    ] {
        set(&harness, "root", state, T0 + offset);
        let output = harness.evaluate_at(T0 + offset, &[]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
    }
    assert_eq!(harness.calls().len(), 2, "one trigger and one resolve");
    assert!(
        harness
            .calls()
            .iter()
            .all(|call| call.starts_with("submit local:site-page-inbox "))
    );
}

#[test]
fn upgrade_repairs_unretained_v1_and_local_page_intents() {
    let mut harness = Harness::new();
    harness.page_reference = "site-page-inbox";
    harness.page_transport = "local_file";
    harness.network = false;
    harness.fake("local_route", "site-page-inbox");
    harness.fake("command_error", "");
    harness.host_posture("root");
    for offset in [0, 660] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate_at(T0 + offset, &[]);
    }
    let mut state = harness.state();
    let last = state["conditions"][UNKNOWN_ROOT]["last_intent"]
        .as_object_mut()
        .unwrap();
    for (role, record) in last {
        let path = harness
            .path("state/intents")
            .join(record["intent_file"].as_str().unwrap());
        let mut intent: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        intent["runbook_url"] = intent["inspection_reference"].clone();
        if role == "page" {
            intent["schema"] = json!("nq.notification_delivery_intent.v2");
            intent["destination_identity"] = json!("pagerduty:site-page-inbox");
            intent["condition"] = json!({"site": "labelwatch"});
            intent["action"] = json!("trigger");
            intent["severity"] = json!("critical");
            intent["details"] = json!({});
            record["schema"] = intent["schema"].clone();
            record["network"] = json!(false);
        }
        fs::write(path, serde_jcs::to_vec(&intent).unwrap()).unwrap();
    }
    fs::write(
        harness.path("state/state.json"),
        serde_json::to_vec(&state).unwrap(),
    )
    .unwrap();
    fs::remove_file(harness.path("fake/command_error")).unwrap();
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 720);
    let output = harness.evaluate_at(T0 + 720, &[]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report = harness.report();
    assert_eq!(report["intents"][0]["outcome"], "route_retired");
    assert_eq!(
        report["intents"][0]["schema"],
        "nq.notification_delivery_intent.v2"
    );
    let fresh = report["intents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["route_role"] == "page" && item["outcome"] == "accepted")
        .unwrap();
    assert_eq!(fresh["schema"], "nq.notification_delivery_intent.v1");
    assert_eq!(harness.calls().len(), 2);
    // Local retries must still deliver when network is disabled.
    harness.fake("next_state", "failed");
    for offset in [780, 900] {
        set(&harness, "root", ProjectedStateV1::Healthy, T0 + offset);
        harness.evaluate_at(T0 + offset, &[]);
    }
    harness.fake("next_state", "accepted");
    set(&harness, "root", ProjectedStateV1::Healthy, T0 + 1800);
    let output = harness.evaluate_at(T0 + 1800, &[]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(harness.report()["intents"][0]["outcome"], "accepted");
    assert_eq!(harness.report()["intents"][0]["route"], "site-page-inbox");
}

#[test]
fn dry_run_with_loopback_runbooks_does_not_log_withholding() {
    let mut harness = Harness::new();
    harness.runbook_base = "http://127.0.0.1:8088/RUNBOOKS.md";
    harness.host_posture("root");
    set(&harness, "root", ProjectedStateV1::Unknown, T0);
    harness.evaluate(T0);
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 660);
    let output = harness.evaluate_at(T0 + 660, &["--dry-run"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(!String::from_utf8_lossy(&output.stderr).contains("runbook_url_withheld:"));
    let report: Value =
        serde_json::from_slice(&fs::read(harness.path("state/dry-run/report.json")).unwrap())
            .unwrap();
    assert_eq!(report["intents"].as_array().unwrap().len(), 2);
    assert_eq!(
        report["delivery"],
        json!({"operations": {"outcome": "skipped", "last_attempt_at": null}, "pagerduty-ops": {"outcome": "skipped", "last_attempt_at": null}})
    );
    assert!(harness.calls().is_empty());
}

#[test]
fn withholding_log_counts_v2_submissions_once_per_pass() {
    let mut harness = Harness::new();
    harness.runbook_base = "http://127.0.0.1:8088/RUNBOOKS.md";
    harness.host_posture("alpha").host_posture("beta");
    for offset in [0, 660] {
        for label in ["alpha", "beta"] {
            set(&harness, label, ProjectedStateV1::Unknown, T0 + offset);
        }
        let output = harness.evaluate_at(T0 + offset, &[]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            stderr.matches("runbook_url_withheld:").count(),
            usize::from(offset == 660)
        );
        if offset == 660 {
            assert!(stderr.contains("for 2 intents"), "{stderr}");
        }
    }
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
        Some(4),
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
        "resubmit n2 labelwatch-host-posture-unknown-root-trigger-1790943180 n3 accepted"
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
        "submit operations labelwatch-host-posture-unknown-root-trigger-1790943960 n4 accepted new"
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
    harness.evaluate(T0);
    for offset in (900..=1320).step_by(60) {
        harness.evaluate(T0 + offset);
    }
    let calls = harness.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert!(calls[0].starts_with(
        "submit operations labelwatch-evaluator-input-unavailable-observation.unreadable-trigger-"
    ));
    let intent: Value = serde_json::from_slice(&harness.submitted_intent("n1")).unwrap();
    assert_eq!(intent["schema"], "nq.notification_delivery_intent.v1");
    assert!(intent["summary"].as_str().unwrap().contains(
        "constellation:labelwatch:nightshift:evaluator-input-unavailable:observation.unreadable"
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
    assert!(calls[0].starts_with(
        "submit operations labelwatch-evaluator-input-unavailable-nqd.stale-trigger-"
    ));
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

/// All configured, enabled transports are required when they have an obligation.
#[test]
fn retained_refusal_reason_reaches_reports_log_and_retry_pause() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    harness.fake("next_state", "refused");
    harness.fake("state-operations", "accepted");
    for offset in [0, 660, 720, 780] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        let output = harness.evaluate_at(T0 + offset, &[]);
        if offset == 0 {
            continue;
        }
        assert_eq!(output.status.code(), Some(4));
        let report = harness.report();
        assert_eq!(report["delivery"]["pagerduty-ops"]["outcome"], "refused");
        assert_eq!(
            report["delivery"]["pagerduty-ops"]["error"],
            "refused: routing_key_malformed"
        );
        assert!(
            report["first_error"]
                .as_str()
                .unwrap()
                .contains("routing_key_malformed")
        );
        if offset != 720 {
            let row = report["intents"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["route_role"] == "page")
                .unwrap();
            assert_eq!(row["error"], "refused: routing_key_malformed");
            assert!(String::from_utf8_lossy(&output.stderr).contains("routing_key_malformed"));
        }
    }
    let log = fs::read_to_string(harness.path("state/intents.jsonl")).unwrap();
    assert_eq!(
        log.lines()
            .filter(|line| line.contains("routing_key_malformed"))
            .count(),
        2
    );
    assert!(harness.calls().last().unwrap().starts_with("resubmit "));
}

#[test]
fn retained_refusal_does_not_guess_a_missing_or_foreign_reason() {
    for inspection in [
        "[]",
        r#"[{"notification_id":"other","delivery_state":"refused","pagerduty":{"last_event":{"detail":{"reason":"routing_key_malformed"}}}}]"#,
    ] {
        let mut harness = Harness::new();
        harness.host_posture("root");
        harness.fake("state-pagerduty-ops", "refused");
        harness.fake("inspect_result", inspection);
        for offset in [0, 660] {
            set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
            harness.evaluate(T0 + offset);
        }
        assert_eq!(
            harness.report()["delivery"]["pagerduty-ops"]["error"],
            "refused: NQ supplied no refusal reason"
        );
    }
}

#[test]
fn required_route_failures_are_distinct_and_partial_delivery_is_explicit() {
    for outcome in ["failed", "refused", "unknown", "pending"] {
        for partial in [false, true] {
            let mut harness = Harness::new();
            harness.host_posture("root");
            harness.fake("state-operations", outcome);
            harness.fake(
                "state-pagerduty-ops",
                if partial { "accepted" } else { outcome },
            );
            set(&harness, "root", ProjectedStateV1::Unknown, T0);
            harness.evaluate(T0);
            set(&harness, "root", ProjectedStateV1::Unknown, T0 + 660);
            let output = harness.evaluate_at(T0 + 660, &[]);
            assert_eq!(output.status.code(), Some(4));
            let report = harness.report();
            assert_eq!(report["exit_code"], 4);
            assert_eq!(
                report["exit_class"],
                if partial {
                    "delivery_partial"
                } else {
                    "delivery_failed"
                }
            );
            assert_eq!(report["delivery_class"], report["exit_class"]);
            if outcome == "unknown" {
                for row in report["intents"].as_array().unwrap() {
                    if row["route_role"] == "notice" || !partial {
                        assert_eq!(row["outcome"], "failed");
                        assert!(
                            row["error"]
                                .as_str()
                                .unwrap()
                                .contains("delivery result unknown")
                        );
                    }
                }
                assert!(
                    report["first_error"]
                        .as_str()
                        .unwrap()
                        .contains("failed: delivery result unknown")
                );
                let log = fs::read_to_string(harness.path("state/intents.jsonl")).unwrap();
                assert!(!log.contains("\"outcome\":\"unknown\""));
                assert_eq!(
                    harness.state()["conditions"][UNKNOWN_ROOT]["last_intent"]["notice"]["outcome"],
                    "unknown"
                );
                // No new attempt during the retry pause, with the same wording.
                set(&harness, "root", ProjectedStateV1::Unknown, T0 + 720);
                harness.evaluate(T0 + 720);
                let waiting = harness.report();
                assert_eq!(waiting["unresolved_deliveries"][0]["outcome"], "failed");
                assert!(
                    waiting["first_error"]
                        .as_str()
                        .unwrap()
                        .contains("failed: delivery result unknown")
                );
            }
            assert_eq!(
                report["delivery"]["operations"]["outcome"],
                if outcome == "refused" {
                    "refused"
                } else {
                    "failed"
                }
            );
            assert_eq!(
                report["delivery"]["pagerduty-ops"]["outcome"],
                if partial {
                    "accepted"
                } else if outcome == "refused" {
                    "refused"
                } else {
                    "failed"
                }
            );
            assert_eq!(harness.state()["conditions"][UNKNOWN_ROOT]["active"], true);
            assert_eq!(harness.calls().len(), 2);
        }
    }
}

#[test]
fn disabled_route_failure_does_not_count_but_local_delivery_is_required() {
    let mut harness = Harness::new();
    harness.network = false;
    harness.notice_transport = "local_file";
    harness.host_posture("root");
    harness.fake("command_error-pagerduty-ops", "");
    for offset in [0, 660] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        let output = harness.evaluate_at(T0 + offset, &[]);
        assert_eq!(output.status.code(), Some(0));
    }
    let report = harness.report();
    assert_eq!(report["exit_class"], "clean");
    assert_eq!(
        report["delivery"],
        json!({"operations": {"outcome": "accepted", "last_attempt_at": rfc3339(T0 + 660)}, "pagerduty-ops": {"outcome": "skipped", "last_attempt_at": rfc3339(T0 + 660)}})
    );
    assert!(report["first_error"].is_null());
    // An omitted (optional) page route has no obligation or report entry.
    let mut fresh = Harness::new();
    fresh.page_route = false;
    fresh.network = false;
    fresh.host_posture("root");
    fresh.fake("command_error", "");
    for offset in [0, 660] {
        set(&fresh, "root", ProjectedStateV1::Unknown, T0 + offset);
        assert_eq!(fresh.evaluate_at(T0 + offset, &[]).status.code(), Some(0));
    }
    assert_eq!(
        fresh.report()["delivery"],
        json!({"operations": {"outcome": "skipped", "last_attempt_at": rfc3339(T0 + 660)}})
    );
}

#[test]
fn consecutive_failing_passes_attempt_each_identity_once_without_multiplying() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    harness.fake("command_error", "");
    set(&harness, "root", ProjectedStateV1::Unknown, T0);
    harness.evaluate(T0);
    let mut identities = Vec::new();
    for offset in [660, 720] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        assert_eq!(harness.evaluate_at(T0 + offset, &[]).status.code(), Some(4));
        let report = harness.report();
        let pass: Vec<_> = report["intents"]
            .as_array()
            .unwrap()
            .iter()
            .map(|intent| (intent["route"].clone(), intent["stable_event_id"].clone()))
            .collect();
        assert_eq!(pass.len(), 2);
        identities.push(pass);
    }
    assert_eq!(identities[0], identities[1]);
    let attempts = fs::read_to_string(harness.path("fake/attempts.log")).unwrap();
    let attempts: Vec<_> = attempts.lines().collect();
    assert_eq!(attempts.len(), 4);
    assert_eq!(attempts[..2], attempts[2..]);
    assert_ne!(attempts[0], attempts[1]);
    assert!(
        harness.state()["conditions"][UNKNOWN_ROOT]
            .get("pending_trigger")
            .is_none()
    );
}

#[test]
fn packaged_unit_keeps_delivery_failure_visible_without_a_notification_loop() {
    let unit = include_str!("../../../packaging/attention/constellation-attention.service");
    let directives: Vec<_> = unit
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect();
    for name in ["SuccessExitStatus=", "Restart=", "OnFailure="] {
        assert!(
            !directives
                .iter()
                .any(|line| line.trim_start().starts_with(name)),
            "{name}"
        );
    }
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
    let report = harness.report();
    assert_eq!(report["exit_code"], 4);
    assert_eq!(report["exit_class"], "delivery_failed");
    assert!(
        report["first_error"]
            .as_str()
            .unwrap()
            .contains("notification condition target_class is refused")
    );
    fs::remove_file(harness.path("fake/command_error")).unwrap();
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 1600);
    harness.evaluate(T0 + 1600);
    let calls = harness.calls();
    assert_eq!(calls.len(), 1);
    assert!(calls[0].contains("labelwatch-host-posture-unknown-root-trigger-1790943060"));
    assert_eq!(harness.report()["exit_class"], "clean");
    assert!(harness.report()["first_error"].is_null());
}

#[test]
fn report_classifies_input_and_delivery_failures_and_keeps_one_error_line() {
    let mut harness = Harness::new();
    harness.page_route = false;
    harness.host_posture("root");
    let output = harness.evaluate_at(T0, &[]);
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(harness.report()["exit_code"], 3);
    assert_eq!(harness.report()["exit_class"], "input_error");
    assert!(
        harness.report()["first_error"]
            .as_str()
            .unwrap()
            .starts_with("input root:")
    );

    fs::create_dir(harness.path("state/intents.jsonl")).unwrap();
    harness.fake("command_error", "");
    let output = harness.evaluate_at(T0 + 360, &[]);
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(harness.report()["exit_class"], "input_error");
    assert_eq!(harness.report()["delivery_class"], "delivery_failed");
    assert!(harness.report()["intent_log_error"].is_string());
    assert_eq!(
        harness.report()["delivery"]["operations"]["outcome"],
        "failed"
    );
    assert_eq!(
        harness.report()["first_error"]
            .as_str()
            .unwrap()
            .lines()
            .count(),
        1
    );
}

#[test]
fn report_includes_intent_log_failure_without_overwriting_route_outcomes() {
    for (network, partial) in [(true, false), (true, true), (false, false)] {
        let mut harness = Harness::new();
        harness.network = network;
        harness.host_posture("root");
        if partial {
            harness.fake("state-operations", "failed");
        }
        set(&harness, "root", ProjectedStateV1::Unknown, T0);
        harness.evaluate(T0);
        fs::create_dir(harness.path("state/intents.jsonl")).unwrap();
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + 660);
        let output = harness.evaluate_at(T0 + 660, &[]);
        assert_eq!(output.status.code(), Some(4));
        let report = harness.report();
        assert_eq!(report["exit_code"], 4);
        assert_eq!(report["exit_class"], "intent_log_unwritable");
        assert_eq!(
            report["delivery_class"],
            if partial { "delivery_partial" } else { "clean" }
        );
        assert_eq!(
            report["delivery"]["operations"]["outcome"],
            if !network {
                "skipped"
            } else if partial {
                "failed"
            } else {
                "accepted"
            }
        );
        assert_eq!(
            report["delivery"]["pagerduty-ops"]["outcome"],
            if network { "accepted" } else { "skipped" }
        );
        assert_eq!(
            report["delivery"]["pagerduty-ops"]["last_attempt_at"],
            rfc3339(T0 + 660)
        );
        assert!(
            report["intent_log_error"]
                .as_str()
                .unwrap()
                .starts_with("intent_log_unwritable")
        );
        if !partial {
            assert!(
                report["first_error"]
                    .as_str()
                    .unwrap()
                    .starts_with("intent_log_unwritable")
            );
        }
    }
}

#[test]
fn retained_route_acceptance_keeps_its_original_attempt_time() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    set(&harness, "root", ProjectedStateV1::Unknown, T0);
    let idle = harness.evaluate(T0);
    assert_eq!(
        idle["delivery"]["operations"],
        json!({"outcome": "skipped", "last_attempt_at": null})
    );
    for offset in [660, 720] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        let report = harness.evaluate(T0 + offset);
        for route in ["operations", "pagerduty-ops"] {
            assert_eq!(
                report["delivery"][route],
                json!({"outcome": "accepted", "last_attempt_at": rfc3339(T0 + 660)})
            );
        }
        assert_eq!(
            report["intents"].as_array().unwrap().len(),
            if offset == 660 { 2 } else { 0 }
        );
    }
    assert_eq!(harness.calls().len(), 2);
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
            "io-pressure",
            "nightshift-recurrence-missing",
            "sqlite-health",
            "service-not-doing-its-job",
            "remediation-journal-critical",
            "metric-alert-firing",
            "evaluator-input-unavailable",
            "docket-unsettled",
            "ag-executor-unavailable",
        ]
    );
    assert_eq!(value["rules"][12]["disabled"], "input not deployed");
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
        calls.iter().any(|call| call
            .contains("labelwatch-evaluator-input-unavailable-nqd.unrecognised-trigger-")),
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
            .any(|call| call
                .contains("labelwatch-evaluator-input-unavailable-nqd.unreported-trigger-")),
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
    assert!(calls[0].contains("labelwatch-evaluator-input-unavailable-nqd.untargetable-trigger-"));
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
        assert_eq!(output.status.code(), Some(4));
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
        assert_eq!(output.status.code(), Some(4), "+{offset}");
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
    assert!(calls[0].contains("labelwatch-evaluator-input-unavailable-root.unreadable-trigger-"));
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

/// NQ #28: an `nq.host_io` evaluation feeds `io-pressure` the way
/// `nq.host_memory` feeds `memory-pressure`: present opens the condition
/// row, explicitly absent clears it, and the profile is read only at the
/// version it was qualified against.
#[test]
fn io_pressure_from_an_nq_host_io_evaluation() {
    let (harness, status) = nq_status_harness();
    let t = at("2026-10-02T21:32:17Z");
    let with_io = |state: &str, version: u64| {
        retimed("healthy.json", t, |value| {
            let components = value["components"].as_array_mut().unwrap();
            let mut cloned = Vec::new();
            for component in components.iter() {
                let memory = component["kind"] == "instance" && component["id"] == "host-memory"
                    || component["kind"] == "evaluation"
                        && component["detail"]["result"]["context"]["instance_id"] == "host-memory";
                if !memory {
                    continue;
                }
                let text = serde_json::to_string(component)
                    .unwrap()
                    .replace("host-memory", "io-host")
                    .replace("nq.host_memory.pressure_stall", "nq.host_io.pressure_stall")
                    .replace("nq.host_memory_scope.v1", "nq.host_io_scope.v1")
                    .replace("\"nq.host_memory\"", "\"nq.host_io\"")
                    .replace("\"host_memory\"", "\"host_io\"")
                    .replace("memory_pressure_stall", "io_pressure_stall")
                    .replace(
                        "2b007ccd-a213-45a1-823a-db4746d51580",
                        "2b007ccd-a213-45a1-823a-db4746d5ffff",
                    );
                let mut clone: Value = serde_json::from_str(&text).unwrap();
                if clone["kind"] == "evaluation" {
                    clone["detail"]["result"]["result"]["state"] = json!(state);
                    clone["detail"]["result"]["profile"]["profile"]["version"] = json!(version);
                }
                cloned.push(clone);
            }
            assert_eq!(
                cloned.len(),
                2,
                "fixture must carry the memory instance and evaluation"
            );
            components.extend(cloned);
        })
    };
    write_status(&status, &with_io("present", 1));
    let report = harness.evaluate(t + 3);
    assert_eq!(
        report["inputs"][0]["status"], "ok",
        "{}",
        report["inputs"][0]
    );
    let io: Vec<&Value> = report["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["id"].as_str().unwrap().contains(":io-pressure"))
        .collect();
    assert_eq!(io.len(), 1, "{:?}", report["conditions"]);
    assert_eq!(io[0]["observation"], "present", "{}", io[0]);
    assert_eq!(io[0]["rule"], "io-pressure");
    assert!(
        intents(&report).is_empty(),
        "a notice needs 600 s of persistence"
    );
    write_status(&status, &with_io("explicitly_absent", 1));
    let report = harness.evaluate(t + 63);
    assert_eq!(report["inputs"][0]["status"], "ok");
    assert!(
        !report["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"].as_str().unwrap().contains(":io-pressure")
                && c["observation"] == "present"),
        "{:?}",
        report["conditions"]
    );
    write_status(&status, &with_io("present", 2));
    let report = harness.evaluate(t + 123);
    assert_eq!(report["inputs"][0]["status"], "not_current");
    assert!(
        report["inputs"][0]["error"]
            .as_str()
            .unwrap()
            .contains("unrecognised profile \"nq.host_io\" version 2")
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
        Some(4),
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
    harness.evaluate(T0);
    for offset in (900..=1320).step_by(60) {
        harness.evaluate(T0 + offset);
    }
    let path = harness.path("state/state.json");
    let text = fs::read_to_string(&path)
        .unwrap()
        .replace("observation.unreadable", "observation");
    fs::write(&path, text).unwrap();
    let report = harness.evaluate(T0 + 1380);
    let old = "constellation:labelwatch:nightshift:evaluator-input-unavailable:observation";
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
            &"resubmit n2 labelwatch-host-posture-unknown-root-trigger-1790943180 n3 accepted"
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
    assert_eq!(codes[2], Some(4));
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
    let output = harness.reset_clock_at(T0 + 780);
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
    let disk = "constellation:labelwatch:host_posture:host-disk:fs-zonestorage";
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
            .starts_with(&format!("TRIGGER {disk}@{} [notice]", rfc3339(t + 3)))
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
            condition["id"] == "constellation:labelwatch:host_posture:host-disk:fs-root-capacity"
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
            condition["id"] == "constellation:labelwatch:host_posture:host-disk:fs-root-capacity"
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
    let output = harness.reset_clock_at(t + 300);
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
    harness.config_path();
    let intent = harness.path("legacy.json");
    fs::write(
        &intent,
        br#"{"schema":"nq.notification_delivery_intent.v2","stable_event_id":"labelwatch-x-trigger-1","destination_identity":"pagerduty:pagerduty-ops"}"#,
    )
    .unwrap();
    let output = Command::new(Path::new(FIXTURES).join("fake-nq.sh"))
        .args([
            "--config",
            harness.path("nq.toml").to_str().unwrap(),
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
        "submit pagerduty-ops labelwatch-host-posture-unknown-root-trigger-1790943180 n3 accepted new",
        "{calls:?}"
    );
    let intent: Value = serde_json::from_slice(&harness.submitted_intent("n3")).unwrap();
    assert_eq!(intent["response_class"], "page");
    assert_eq!(
        intent["transition_id"],
        "labelwatch-host-posture-unknown-root-trigger-1790943060"
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
        format!("labelwatch-service-down-cron.service-trigger-{}", t + 184)
    );
    assert_eq!(
        intent["stable_event_id"],
        format!("labelwatch-service-down-cron.service-trigger-{}", t + 243)
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

/// A condition that stays active is restated once a day after `at_utc`;
/// a failed digest is retried after the resend interval, an accepted one is not.
#[test]
fn daily_digest_restates_active_conditions_once_a_day() {
    let mut harness = Harness::new();
    harness
        .host_posture("root")
        .raw("[digest]\nat_utc = \"00:40\"\n");
    let midnight = T0 - T0.rem_euclid(86_400) + 86_400;
    let mut at = midnight;
    // Unknown persists past the 600 s bound before the digest time.
    while at < midnight + 2400 {
        set(&harness, "root", ProjectedStateV1::Unknown, at);
        let report = harness.evaluate(at);
        assert!(report.get("digest").is_none(), "no digest before 00:40Z");
        at += 300;
    }
    harness.fake("next_state", "failed");
    set(&harness, "root", ProjectedStateV1::Unknown, at);
    let report = harness.evaluate(at);
    let summary = report["digest"]["summary"].as_str().unwrap();
    assert!(summary.starts_with("DIGEST labelwatch "), "{summary}");
    assert!(
        summary.contains("page host-posture-unknown/root for "),
        "{summary}"
    );
    assert!(summary.ends_with(". All inputs current."), "{summary}");
    assert_eq!(report["digest"]["settled"], false);
    let digests = |h: &Harness| {
        h.calls()
            .iter()
            .filter(|c| c.contains("attention-digest"))
            .count()
    };
    // Retried no sooner than the resend interval.
    set(&harness, "root", ProjectedStateV1::Unknown, at + 300);
    let waiting = harness.evaluate(at + 300);
    assert!(waiting.get("digest").is_none());
    assert_eq!(waiting["exit_code"], 4);
    assert_eq!(waiting["delivery"]["operations"]["outcome"], "failed");
    assert_eq!(waiting["exit_class"], "delivery_partial");
    assert_eq!(
        waiting["delivery"]["operations"]["last_attempt_at"],
        rfc3339(at)
    );
    assert_eq!(
        waiting["first_error"],
        "delivery operations (daily-digest): digest retry pause: failed"
    );
    assert_eq!(
        waiting["unresolved_deliveries"][0]["condition_id"],
        "daily-digest"
    );
    harness.fake("next_state", "accepted");
    set(&harness, "root", ProjectedStateV1::Unknown, at + 900);
    assert_eq!(harness.evaluate(at + 900)["digest"]["settled"], true);
    set(&harness, "root", ProjectedStateV1::Unknown, at + 3600);
    assert!(
        harness.evaluate(at + 3600).get("digest").is_none(),
        "one accepted digest a day"
    );
    assert_eq!(digests(&harness), 2);
    set(
        &harness,
        "root",
        ProjectedStateV1::Unknown,
        midnight + 86_400 + 2400,
    );
    assert!(
        harness
            .evaluate(midnight + 86_400 + 2400)
            .get("digest")
            .is_some(),
        "next day"
    );
}

#[test]
fn digest_retry_pause_retains_the_route_and_command_error() {
    let mut harness = Harness::new();
    harness.page_route = false;
    harness
        .host_posture("root")
        .raw("[digest]\nat_utc = \"00:40\"\n");
    harness.fake("command_error", "");
    let at = T0 - T0.rem_euclid(86_400) + 86_400 + 2400;
    set(&harness, "root", ProjectedStateV1::Healthy, at);
    let failed = harness.evaluate(at);
    let reason = failed["digest"]["error"].as_str().unwrap();
    assert!(reason.contains("notification condition target_class is refused"));
    assert!(
        failed["first_error"]
            .as_str()
            .unwrap()
            .starts_with("digest operations:")
    );
    fs::remove_file(harness.path("fake/command_error")).unwrap();
    set(&harness, "root", ProjectedStateV1::Healthy, at + 300);
    let waiting = harness.evaluate(at + 300);
    assert_eq!(waiting["exit_code"], 4);
    assert!(waiting.get("digest").is_none());
    assert_eq!(
        waiting["first_error"],
        format!(
            "delivery operations (daily-digest): digest retry pause: {}",
            reason.lines().next().unwrap()
        )
    );
    assert_eq!(
        waiting["delivery"]["operations"]["last_attempt_at"],
        rfc3339(at)
    );
    let attempts = fs::read_to_string(harness.path("fake/attempts.log")).unwrap();
    assert_eq!(attempts.lines().count(), 1);
}

#[test]
fn digest_refused_without_network_stays_settled_after_network_is_enabled() {
    let mut harness = Harness::new();
    harness.network = false;
    harness.page_route = false;
    harness
        .host_posture("root")
        .raw("[digest]\nat_utc = \"00:40\"\n");
    let at = T0 - T0.rem_euclid(86_400) + 86_400 + 2400;
    set(&harness, "root", ProjectedStateV1::Healthy, at);
    let refused = harness.evaluate(at);
    assert_eq!(refused["digest"]["outcome"], "refused");
    assert_eq!(refused["digest"]["settled"], true);
    assert_eq!(refused["exit_code"], 0);
    harness.network = true;
    for offset in [60, 900, 3600] {
        set(&harness, "root", ProjectedStateV1::Healthy, at + offset);
        let report = harness.evaluate(at + offset);
        assert_eq!(report["exit_code"], 0);
        assert_eq!(report["exit_class"], "clean");
        assert_eq!(report["delivery_class"], "clean");
        assert_eq!(
            report["delivery"]["operations"],
            json!({"outcome": "skipped", "last_attempt_at": rfc3339(at)})
        );
        assert!(report.get("digest").is_none());
        assert!(report["first_error"].is_null());
    }
    assert_eq!(harness.calls().len(), 1);
    // The next UTC day creates a new obligation and can deliver normally.
    set(&harness, "root", ProjectedStateV1::Healthy, at + 86_400);
    let next = harness.evaluate(at + 86_400);
    assert_eq!(next["digest"]["outcome"], "accepted");
    assert_eq!(
        next["delivery"]["operations"]["last_attempt_at"],
        rfc3339(at + 86_400)
    );
    assert_eq!(harness.calls().len(), 2);
}

fn write_estate(harness: &Harness, at: i64, services: &[(&str, &str, &str)]) {
    let services: Vec<Value> = services
        .iter()
        .map(|(name, verdict, reason)| {
            let mut s = serde_json::json!({"name": name, "verdict": verdict, "reason": reason, "since": rfc3339(T0)});
            if *verdict == "PAUSED" {
                s["declared"] = serde_json::json!({"state": "paused", "since": "2026-09-13", "reason": "operator pause"});
            }
            s
        })
        .collect();
    let doc = serde_json::json!({"schema": "constellation.estate/v1", "site": "labelwatch",
        "generated_at": rfc3339(at), "services": services});
    fs::write(
        harness.path("estate.json"),
        serde_json::to_vec(&doc).unwrap(),
    )
    .unwrap();
}

fn estate_harness() -> Harness {
    let mut harness = Harness::new();
    let path = harness.path("estate.json");
    harness.raw(&format!("[inputs.estate]\npath = \"{}\"\n", path.display()));
    harness
}

/// A service that is running but not doing its job is noticed after the
/// persistence bound, and the notice says why; a declared pause never is.
#[test]
fn estate_degraded_service_triggers_with_reason_and_pause_stays_quiet() {
    let harness = estate_harness();
    let rows = [
        (
            "driftwatch",
            "PAUSED",
            "declared paused since 2026-09-13: operator pause",
        ),
        ("weatherwatch", "DEGRADED", "observation.loss DEGRADED"),
        ("factsapi", "OK", "running"),
    ];
    for offset in [0, 300] {
        write_estate(&harness, T0 + offset, &rows);
        assert!(
            intents(&harness.evaluate(T0 + offset)).is_empty(),
            "below the 600 s bound"
        );
    }
    write_estate(&harness, T0 + 660, &rows);
    let report = harness.evaluate(T0 + 660);
    let fired = intents(&report);
    let id = "constellation:labelwatch:service:service-not-doing-its-job:weatherwatch";
    assert_eq!(
        fired,
        vec![(id.to_owned(), "notice".to_owned(), "trigger".to_owned())]
    );
    let record = report["intents"][0]["notification_id"].as_str().unwrap();
    let sent: Value = serde_json::from_slice(&harness.submitted_intent(record)).unwrap();
    let summary = sent["summary"].as_str().unwrap();
    assert!(
        summary.contains("Now: observation.loss DEGRADED."),
        "{summary}"
    );
    let quiet = report["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .all(|c| !c["id"].as_str().unwrap().ends_with(":driftwatch") || c["active"] == false);
    assert!(quiet, "a declared pause never triggers");
    // Recovery resolves after the confirmation window.
    let healthy = [rows[0], ("weatherwatch", "OK", "running"), rows[2]];
    for offset in [720, 900] {
        write_estate(&harness, T0 + offset, &healthy);
        harness.evaluate(T0 + offset);
    }
    let state = harness.state();
    assert!(
        state["conditions"]
            .get(id)
            .is_none_or(|c| c["active"] == false),
        "{state}"
    );
}

/// A stale estate document changes no condition and marks the input not current.
#[test]
fn stale_estate_is_unknown_not_clear() {
    let harness = estate_harness();
    write_estate(&harness, T0, &[("pds", "DOWN", "docker pds is exited")]);
    let report = harness.evaluate(T0 + 601);
    assert!(intents(&report).is_empty());
    let input = report["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["kind"] == "estate")
        .unwrap()
        .clone();
    assert_eq!(input["status"], "not_current", "{input}");
    assert!(
        input["causes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c == "stale")
    );
}

/// The digest lists declared-paused services so a pause is never invisible.
#[test]
fn digest_lists_declared_paused_services() {
    let mut harness = estate_harness();
    harness.raw("[digest]\nat_utc = \"00:00\"\n");
    write_estate(
        &harness,
        T0,
        &[
            ("driftwatch", "PAUSED", "declared paused"),
            ("pds", "OK", "running"),
        ],
    );
    let report = harness.evaluate(T0);
    let summary = report["digest"]["summary"].as_str().unwrap();
    assert!(
        summary.contains("Declared paused: driftwatch since 2026-09-13"),
        "{summary}"
    );
}

/// A removed watcher's open page closes once the operator retires its target:
/// resolved as "no longer evaluated" (never as recovery), and the NQ input is
/// current again so passes stop exiting 3.
#[test]
fn retired_target_resolves_a_removed_watchers_page() {
    let (mut harness, status) = nq_status_harness();
    let t = trigger_cron(&harness, &status);
    let gone = |offset: i64| {
        retimed("cron-down.json", t + offset, |value| {
            value["components"]
                .as_array_mut()
                .unwrap()
                .retain(|component| {
                    component["id"] != "unit-cron"
                        && component["detail"]["result"]["context"]["instance_id"] != "unit-cron"
                });
        })
    };
    write_status(&status, &gone(60));
    assert_eq!(
        harness.evaluate_at(t + 63, &[]).status.code(),
        Some(3),
        "held open while unretired"
    );
    harness
        .extra_config
        .push_str("retired_instances = [\"unit-cron\"]\nretired_targets = [\"cron.service\"]\n");
    write_status(&status, &gone(120));
    let output = harness.evaluate_at(t + 123, &[]);
    let report = harness.report();
    let state = harness.state();
    assert!(
        state["conditions"]
            .get(CRON)
            .is_none_or(|c| c["active"] == false),
        "{state}"
    );
    let resolves: Vec<String> = cron_calls(&harness)
        .into_iter()
        .filter(|call| call.contains("-resolve-"))
        .collect();
    assert!(!resolves.is_empty(), "{:?}", harness.calls());
    let record = report["intents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["condition_id"] == CRON && i["route_role"] == "notice")
        .unwrap()["notification_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let sent: Value = serde_json::from_slice(&harness.submitted_intent(&record)).unwrap();
    assert!(
        sent["summary"]
            .as_str()
            .unwrap()
            .contains("no longer evaluated; recovery not observed"),
        "{sent}"
    );
    let nq = report["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["label"] == "nqd")
        .unwrap()
        .clone();
    assert_eq!(nq["status"], "ok", "{nq}");
    assert_eq!(output.status.code(), Some(0));
}

fn saved_check_harness(outcome_file: &str) -> Harness {
    let mut harness = Harness::new();
    let result = harness.path("labeler.json");
    fs::copy(Path::new(FIXTURES).join(outcome_file), &result).unwrap();
    harness.raw(&format!(
        "[[inputs.saved_checks]]\nreference = \"sqlite.freelist-labeler\"\npath = \"{}\"\nmax_age_seconds = 3600\n",
        result.display()
    ));
    harness
}

/// A declared suspension holds the condition as it is: an open one stays open
/// (no resolve is claimed), nothing triggers while suspended, the report and
/// digest say so, and lifting it resumes normal evaluation.
#[test]
fn suspension_holds_an_open_condition_without_resolving_or_triggering() {
    let mut harness = saved_check_harness("saved-check-result-failed.json");
    let read_at = |h: &Harness| {
        let v: Value = serde_json::from_slice(&fs::read(h.path("labeler.json")).unwrap()).unwrap();
        at(v["detail"]["read_attempted_at"].as_str().unwrap())
    };
    let t = read_at(&harness);
    for offset in [0, 300, 660] {
        harness.evaluate(t + offset);
    }
    let id = "constellation:labelwatch:nq:sqlite-health:sqlite.freelist-labeler";
    assert_eq!(
        harness.state()["conditions"][id]["active"],
        true,
        "open before the suspension"
    );
    let calls_before = harness.calls().len();
    harness.raw("[[suspensions]]\nrule = \"sqlite-health\"\ntarget = \"sqlite.freelist-labeler\"\nowner = \"operator\"\nreason = \"Driftwatch paused; store frozen\"\nresume_when = \"Driftwatch resumes ingest\"\nsince = \"2026-10-14\"\n[digest]\nat_utc = \"00:00\"\n");
    // Even with the check now passing, a suspended condition is not resolved.
    fs::copy(
        Path::new(FIXTURES).join("saved-check-result-passed.json"),
        harness.path("labeler.json"),
    )
    .unwrap();
    let first = harness.evaluate(t + 720);
    let digest = first["digest"]["summary"].as_str().unwrap().to_owned();
    for offset in [900, 1200] {
        harness.evaluate(t + offset);
    }
    let report = harness.report();
    let condition = report["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap()
        .clone();
    assert_eq!(
        condition["active"], true,
        "suspended is not healthy: {condition}"
    );
    assert_eq!(condition["suspended"]["owner"], "operator");
    assert_eq!(
        harness
            .calls()
            .iter()
            .filter(|c| c.contains("sqlite-health"))
            .count(),
        harness.calls()[..calls_before]
            .iter()
            .filter(|c| c.contains("sqlite-health"))
            .count(),
        "no intent while suspended: {:?}",
        harness.calls()
    );
    assert!(
        !digest.contains("1 active"),
        "a suspended condition is not listed as active: {digest}"
    );
    assert!(
        digest.contains("sqlite-health/sqlite.freelist-labeler (owner operator"),
        "{digest}"
    );
    // Lifting the suspension resumes evaluation: the passing check now resolves it.
    harness.extra_config = harness
        .extra_config
        .split("[[suspensions]]")
        .next()
        .unwrap()
        .to_owned();
    for offset in [1260, 1500] {
        harness.evaluate(t + offset);
    }
    assert!(
        harness.calls()[calls_before..]
            .iter()
            .any(|c| c.contains("sqlite-health") && c.contains("-resolve-")),
        "{:?}",
        harness.calls()
    );
}

/// A suspension must name an owner, a reason, a resume condition and a rule that exists.
#[test]
fn suspension_without_owner_or_known_rule_is_refused() {
    let mut harness = Harness::new();
    harness.raw("[[suspensions]]\nrule = \"no-such-rule\"\nowner = \"o\"\nreason = \"r\"\nresume_when = \"w\"\nsince = \"2026-10-14\"\n");
    assert_eq!(
        harness
            .command(&[
                "check-config",
                "--config",
                harness.config_path().to_str().unwrap()
            ])
            .status
            .code(),
        Some(2)
    );
    let mut harness = Harness::new();
    harness.raw("[[suspensions]]\nrule = \"sqlite-health\"\nowner = \"\"\nreason = \"r\"\nresume_when = \"w\"\nsince = \"2026-10-14\"\n");
    assert_eq!(
        harness
            .command(&[
                "check-config",
                "--config",
                harness.config_path().to_str().unwrap()
            ])
            .status
            .code(),
        Some(2)
    );
}

/// A suspension is policy: adding one changes the attention policy digest, so
/// the declared-versus-deployed check sees it; with none the digest is unchanged.
#[test]
fn suspension_changes_the_policy_digest() {
    let digest = |h: &Harness| -> String {
        let out = h.command(&[
            "check-config",
            "--config",
            h.config_path().to_str().unwrap(),
        ]);
        serde_json::from_slice::<Value>(&out.stdout).unwrap()["attention_policy_digest"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let mut harness = Harness::new();
    let plain = digest(&harness);
    harness.raw("[[suspensions]]\nrule = \"sqlite-health\"\nowner = \"o\"\nreason = \"r\"\nresume_when = \"w\"\nsince = \"2026-10-14\"\n");
    assert_ne!(digest(&harness), plain);
}

/// Every delivery outcome is appended to intents.jsonl, so the resolve of a
/// condition the evaluator forgets in the same pass is still visible to
/// consumers such as constellation-incidents.
#[test]
fn intent_log_keeps_the_resolve_of_a_forgotten_condition() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    for offset in [0, 300, 660] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    for offset in [720, 780, 900] {
        set(&harness, "root", ProjectedStateV1::Healthy, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    assert!(
        harness.state()["conditions"].get(UNKNOWN_ROOT).is_none(),
        "forgotten once settled"
    );
    let log = fs::read_to_string(harness.path("state/intents.jsonl")).unwrap();
    let lines: Vec<Value> = log
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let actions: Vec<(&str, &str)> = lines
        .iter()
        .filter(|l| l["condition_id"] == UNKNOWN_ROOT)
        .map(|l| {
            (
                l["action"].as_str().unwrap(),
                l["outcome"].as_str().unwrap(),
            )
        })
        .collect();
    assert!(
        actions.contains(&("trigger", "accepted")) && actions.contains(&("resolve", "accepted")),
        "{actions:?}"
    );
    assert!(
        lines
            .iter()
            .all(|l| l["at"].is_string() && l["stable_event_id"].is_string())
    );
}

// ---- metric alerts (vmalert as an input) ----

const METRIC_ALERTS_VECTOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../estate/fixtures/vmalert-rules-runtime-v1.json"
);
const SWAP: &str = "constellation:labelwatch:host_posture:metric-alert-firing:host-swap-exhausted";

/// The shared producer vector, retimed so the document was generated at `at`
/// and every rule evaluated two seconds earlier, then edited.
fn write_metric_alerts(harness: &Harness, at: i64, edit: impl Fn(&mut Value)) {
    let vector: Value = serde_json::from_slice(&fs::read(METRIC_ALERTS_VECTOR).unwrap()).unwrap();
    let mut doc = vector["document"].clone();
    doc["generated_at"] = json!(rfc3339(at));
    for rule in doc["rules"].as_array_mut().unwrap() {
        rule["last_evaluation"] = json!(rfc3339(at - 2));
    }
    edit(&mut doc);
    fs::write(
        harness.path("metric-alerts.json"),
        serde_json::to_vec(&doc).unwrap(),
    )
    .unwrap();
}

fn metric_rule<'a>(doc: &'a mut Value, name: &str) -> &'a mut Value {
    doc["rules"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|r| r["name"] == name)
        .unwrap()
}

/// The producer computes `firing_sites` over every instance; a test that
/// edits instances by hand must keep that summary consistent.
fn refresh_firing_sites(rule: &mut Value) {
    let mut sites = serde_json::Map::new();
    for i in rule["instances"].as_array().cloned().unwrap_or_default() {
        if i["state"] == "firing" {
            let site = i["labels"]["site"].as_str().unwrap_or("").to_owned();
            let n = sites.get(&site).and_then(Value::as_u64).unwrap_or(0);
            sites.insert(site, json!(n + 1));
        }
    }
    rule["firing_sites"] = Value::Object(sites);
}

fn quiet(doc: &mut Value, name: &str) {
    let rule = metric_rule(doc, name);
    rule["state"] = json!("inactive");
    rule["instances"] = json!([]);
    rule["instance_count"] = json!(0);
    refresh_firing_sites(rule);
}

fn metric_alerts_harness() -> Harness {
    let mut harness = Harness::new();
    let path = harness.path("metric-alerts.json");
    harness.raw(&format!(
        "[inputs.metric_alerts]\npath = \"{}\"\n",
        path.display()
    ));
    harness
}

fn metric_input(report: &Value) -> Value {
    report["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["kind"] == "metric_alerts")
        .unwrap()
        .clone()
}

fn causes(input: &Value) -> Vec<String> {
    input["causes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_owned())
        .collect()
}

fn alert_intents(report: &Value) -> Vec<(String, String, String)> {
    intents(report)
        .into_iter()
        .filter(|(id, _, _)| id.contains(":metric-alert-firing:"))
        .collect()
}

fn condition<'a>(report: &'a Value, id: &str) -> Option<&'a Value> {
    report["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
}

/// A firing opted-in rule is a notice after the bound, carrying the alert's
/// own summary; a rule without the label, a pending rule and an inactive rule
/// are not; a rule whose query errors is unknown and faults the input; and
/// the condition resolves once vmalert reports the rule inactive.
#[test]
fn metric_alert_firing_from_the_shared_vector() {
    let harness = metric_alerts_harness();
    write_metric_alerts(&harness, T0, |_| {});
    let report = harness.evaluate(T0);
    assert!(alert_intents(&report).is_empty(), "below the 60 s bound");
    let input = metric_input(&report);
    assert_eq!(input["status"], "not_current", "{input}");
    assert_eq!(
        causes(&input),
        ["indeterminate"],
        "HostIoPressureSevere health err"
    );
    assert!(
        input["error"]
            .as_str()
            .unwrap()
            .contains("alert HostIoPressureSevere: health \"err\": error when executing query"),
        "{input}"
    );
    let ids: Vec<&str> = report["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .filter(|id| id.contains(":metric-alert-firing:"))
        .collect();
    assert_eq!(
        ids,
        [
            "constellation:labelwatch:host_posture:metric-alert-firing:host-io-pressure-high",
            "constellation:labelwatch:host_posture:metric-alert-firing:host-io-pressure-severe",
            "constellation:labelwatch:host_posture:metric-alert-firing:host-memory-pressure-high",
            SWAP,
        ],
        "opted-in rules only: CrowDefinitionDrift and Watchdog carry no attention label"
    );
    let severe = condition(
        &report,
        "constellation:labelwatch:host_posture:metric-alert-firing:host-io-pressure-severe",
    )
    .unwrap();
    assert_eq!(severe["observation"], "unknown", "{severe}");
    assert_eq!(
        condition(
            &report,
            "constellation:labelwatch:host_posture:metric-alert-firing:host-memory-pressure-high"
        )
        .unwrap()["observation"],
        "clear",
        "pending is vmalert's own hold, not firing"
    );

    write_metric_alerts(&harness, T0 + 90, |_| {});
    let report = harness.evaluate(T0 + 90);
    assert_eq!(
        alert_intents(&report),
        vec![(SWAP.to_owned(), "notice".to_owned(), "trigger".to_owned())]
    );
    let record = report["intents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["condition_id"] == SWAP)
        .unwrap()["notification_id"]
        .as_str()
        .unwrap();
    let sent: Value = serde_json::from_slice(&harness.submitted_intent(record)).unwrap();
    let summary = sent["summary"].as_str().unwrap();
    assert!(
        summary.contains(
            "Now: HostSwapExhausted firing on labelwatch (127.0.0.1:19100): swap 5.369e+10% free on labelwatch (127.0.0.1:19100) for 30 min."
        ),
        "{summary}"
    );
    assert_eq!(
        sent["inspection_reference"],
        "constellation-monitor:docs/ATTENTION.md#metric-alert-firing"
    );

    for offset in [150, 400] {
        write_metric_alerts(&harness, T0 + offset, |doc| quiet(doc, "HostSwapExhausted"));
        harness.evaluate(T0 + offset);
    }
    let state = harness.state();
    assert!(
        state["conditions"]
            .get(SWAP)
            .is_none_or(|c| c["active"] == false),
        "{state}"
    );
}

fn value_code_rule(doc: &mut Value, state: &str, value: &str) {
    value_code_rows(doc, state, &[value]);
}

fn write_reconfiguration(harness: &Harness, at: i64) {
    fs::write(
        harness.path("state/reconfigured"),
        serde_json::to_vec(&json!({
            "run_id": "apply-1", "at": rfc3339(at), "reason": "vmalert restarted",
        }))
        .unwrap(),
    )
    .unwrap();
}

#[test]
fn first_pass_without_a_closed_cycle_warms_then_faults() {
    for open in [false, true] {
        let mut harness = Harness::new();
        let store = harness.path("nightshift.db");
        let connection = rusqlite::Connection::open(&store).unwrap();
        connection
            .execute_batch(
                &fs::read_to_string(Path::new(FIXTURES).join("nightshift-schema.sql")).unwrap(),
            )
            .unwrap();
        if open {
            connection.execute_batch(
                "INSERT INTO canonical_recurrence_slots VALUES ('s', 'c', 'done', '{}', 'd', '2026-10-02T12:00:00Z');
                 INSERT INTO canonical_observation_cycles VALUES ('c', 's', 1, 'open', 'd', '{}', '2026-10-02T12:00:00Z');"
            ).unwrap();
        }
        drop(connection);
        harness.raw(&format!(
            "[inputs.nightshift]\nlabel = \"observation\"\nstore_path = {:?}\n",
            store
        ));
        for offset in [0, 899, 900] {
            let report = harness.evaluate(T0 + offset);
            let input = &report["inputs"][0];
            assert_eq!(
                input["status"],
                if offset < 900 { "ok" } else { "unavailable" }
            );
            assert_eq!(
                causes(input),
                [if offset < 900 { "warming" } else { "empty" }]
            );
            assert_eq!(report["exit_code"], if offset < 900 { 0 } else { 3 });
            if offset < 900 {
                assert!(input.get("error").is_none());
                assert_eq!(report["exit_class"], "clean");
            } else {
                assert_eq!(input["error"], "no closed observation cycle");
            }
        }
    }
}

#[test]
fn observation_grace_uses_the_earlier_metric_first_seen() {
    let mut harness = metric_alerts_harness();
    write_metric_alerts(&harness, T0, |doc| value_code_rule(doc, "inactive", "1"));
    harness.evaluate(T0);
    let path = harness.path("state/state-attention-lifecycle.json");
    let mut saved: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    saved["first_seen"] = json!(T0 + 600);
    fs::write(path, serde_json::to_vec(&saved).unwrap()).unwrap();
    let store = harness.path("nightshift.db");
    let connection = rusqlite::Connection::open(&store).unwrap();
    connection
        .execute_batch(
            &fs::read_to_string(Path::new(FIXTURES).join("nightshift-schema.sql")).unwrap(),
        )
        .unwrap();
    drop(connection);
    harness.raw(&format!(
        "[inputs.nightshift]\nlabel = \"observation\"\nstore_path = {:?}\n",
        store
    ));
    write_metric_alerts(&harness, T0 + 900, |doc| {
        value_code_rule(doc, "inactive", "1")
    });
    let report = harness.evaluate(T0 + 900);
    let input = report["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|input| input["kind"] == "nightshift")
        .unwrap();
    assert_eq!(input["status"], "unavailable");
    assert_eq!(causes(input), ["empty"]);
}

#[test]
fn reconfiguration_warms_unevaluated_and_new_missing_rules_for_one_grace() {
    for code in ["2", "3"] {
        let harness = metric_alerts_harness();
        write_metric_alerts(&harness, T0, |doc| value_code_rule(doc, "inactive", "1"));
        harness.evaluate(T0);
        let at = T0 + 3600;
        write_reconfiguration(&harness, at);
        for offset in [0, 899, 900] {
            write_metric_alerts(&harness, at + offset, |doc| {
                value_code_rule(doc, "firing", code);
                let mut new = doc["rules"][0].clone();
                new["name"] = json!("ProbeDown");
                let rule = &mut doc["rules"][0];
                rule["labels"]
                    .as_object_mut()
                    .unwrap()
                    .remove("constellation_value_codes");
                rule["last_evaluation"] = Value::Null;
                doc["rules"].as_array_mut().unwrap().push(new);
            });
            let report = harness.evaluate(at + offset);
            let input = metric_input(&report);
            assert_eq!(input["identity"]["reconfigured_at"], rfc3339(at));
            assert_eq!(input["identity"]["first_seen"], rfc3339(T0));
            assert_eq!(
                input["status"],
                if offset < 900 { "ok" } else { "not_current" }
            );
            assert_eq!(report["exit_code"], if offset < 900 { 0 } else { 3 });
            assert!(alert_intents(&report).is_empty());
            assert_eq!(condition(&report, SWAP).unwrap()["observation"], "unknown");
            if offset < 900 {
                assert_eq!(causes(&input), ["warming"]);
                let warming = input["identity"]["warming_rules"].as_array().unwrap();
                assert_eq!(warming.len(), 2);
                for rule in warming {
                    assert_eq!(rule["since_reconfiguration"], true);
                    assert_eq!(rule["since"], rfc3339(at));
                    assert_eq!(rule["bound_exceeded"], false);
                }
            } else {
                assert!(
                    input["error"]
                        .as_str()
                        .unwrap()
                        .contains("has no valid last_evaluation")
                );
                assert!(
                    input["error"]
                        .as_str()
                        .unwrap()
                        .contains(&format!("value code {code}"))
                );
            }
            assert!(!harness.path("state/reconfigured").exists());
        }
        let saved: Value = serde_json::from_slice(
            &fs::read(harness.path("state/state-metric-alerts.json")).unwrap(),
        )
        .unwrap();
        assert!(saved.get("reconfigured_at").is_none());
        let lifecycle: Value = serde_json::from_slice(
            &fs::read(harness.path("state/state-attention-lifecycle.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(lifecycle["reconfigured_at"], at);
    }
}

#[test]
fn reconfiguration_marker_dry_run_and_stale_custody() {
    for stale in [false, true] {
        let harness = metric_alerts_harness();
        write_metric_alerts(&harness, T0, |doc| value_code_rule(doc, "inactive", "1"));
        harness.evaluate(T0);
        let at = T0 + 21_600;
        write_reconfiguration(&harness, if stale { T0 } else { at });
        let marker = harness.path("state/reconfigured");
        let before = fs::read(&marker).unwrap();
        let history_path = harness.path("state/state-metric-alerts.json");
        let history = fs::read(&history_path).unwrap();
        write_metric_alerts(&harness, at, |doc| value_code_rule(doc, "firing", "3"));
        let output = harness.evaluate_at(at, &["--dry-run"]);
        assert_eq!(
            output.status.code(),
            Some(if stale { 3 } else { 0 }),
            "{output:?}"
        );
        assert_eq!(fs::read(&marker).unwrap(), before);
        assert_eq!(fs::read(&history_path).unwrap(), history);
        let output = harness.evaluate_at(at, &[]);
        assert_eq!(
            output.status.code(),
            Some(if stale { 3 } else { 0 }),
            "{output:?}"
        );
        assert!(!marker.exists());
        if stale {
            assert!(
                String::from_utf8(output.stderr)
                    .unwrap()
                    .contains("ignoring stale reconfiguration marker")
            );
            assert!(
                metric_input(&harness.report())["identity"]
                    .get("reconfigured_at")
                    .is_none()
            );
        }
    }
}

#[test]
fn reconfiguration_survives_an_unreadable_metric_report() {
    let harness = metric_alerts_harness();
    write_metric_alerts(&harness, T0, |doc| value_code_rule(doc, "inactive", "1"));
    harness.evaluate(T0);
    let at = T0 + 3600;
    fs::remove_file(harness.path("metric-alerts.json")).unwrap();
    write_reconfiguration(&harness, at);
    let report = harness.evaluate(at);
    assert_eq!(report["exit_code"], 3);
    assert_eq!(
        metric_input(&report)["identity"]["reconfigured_at"],
        rfc3339(at)
    );
    assert!(!harness.path("state/reconfigured").exists());
    write_metric_alerts(&harness, at + 60, |doc| value_code_rule(doc, "firing", "3"));
    let report = harness.evaluate(at + 60);
    assert_eq!(report["exit_code"], 0);
    assert_eq!(
        metric_input(&report)["identity"]["reconfigured_at"],
        rfc3339(at)
    );
}

#[test]
fn reconfiguration_never_resets_a_rules_warming_bound() {
    let harness = metric_alerts_harness();
    write_metric_alerts(&harness, T0, |doc| value_code_rule(doc, "firing", "5"));
    harness.evaluate(T0);
    let at = T0 + 21_600;
    write_reconfiguration(&harness, at);
    write_metric_alerts(&harness, at, |doc| {
        value_code_rule(doc, "firing", "3");
        doc["rules"][0]["last_evaluation"] = Value::Null;
    });
    let report = harness.evaluate(at);
    let input = metric_input(&report);
    assert_eq!(report["exit_code"], 3);
    let warming = &input["identity"]["warming_rules"][0];
    assert_eq!(warming["since"], rfc3339(T0));
    assert_eq!(warming["bound_exceeded"], true);
    assert_eq!(warming["since_reconfiguration"], true);
}

#[test]
fn unevaluated_rules_obey_the_bound_and_reset_after_healthy_evaluation() {
    for marked in [false, true] {
        let mut harness = metric_alerts_harness();
        harness.raw("warming_bound = 100\n");
        write_metric_alerts(&harness, T0, |doc| value_code_rule(doc, "inactive", "1"));
        harness.evaluate(T0);
        let at = T0 + 3600;
        write_reconfiguration(&harness, at);
        for (offset, missing, clean) in [
            (0, true, true),
            (100, true, false),
            (101, false, true),
            (102, true, true),
        ] {
            write_metric_alerts(&harness, at + offset, |doc| {
                value_code_rule(doc, "inactive", "1");
                if !marked {
                    doc["rules"][0]["labels"]
                        .as_object_mut()
                        .unwrap()
                        .remove("constellation_value_codes");
                }
                if missing {
                    doc["rules"][0]["last_evaluation"] = Value::Null;
                }
            });
            let report = harness.evaluate(at + offset);
            let input = metric_input(&report);
            assert_eq!(report["exit_code"], if clean { 0 } else { 3 }, "{input}");
            if missing {
                let rule = &input["identity"]["warming_rules"][0];
                assert_eq!(rule["codes"], json!([]));
                assert_eq!(rule["since_reconfiguration"], true);
                assert_eq!(rule["bound_exceeded"], !clean);
                assert_eq!(
                    rule["since"],
                    rfc3339(if offset == 102 { at + 102 } else { at })
                );
            }
        }
    }
}

#[test]
fn reconfiguration_does_not_hide_other_faults() {
    for fault in ["stale", "drift", "health", "code4"] {
        let harness = metric_alerts_harness();
        write_metric_alerts(&harness, T0, |doc| value_code_rule(doc, "inactive", "1"));
        harness.evaluate(T0);
        let at = T0 + 3600;
        write_reconfiguration(&harness, at);
        write_metric_alerts(&harness, at, |doc| {
            value_code_rule(doc, "firing", if fault == "code4" { "4" } else { "3" });
            match fault {
                "stale" => doc["generated_at"] = json!(rfc3339(at - 400)),
                "drift" => doc["declared_policy_sha256"] = json!("different"),
                "health" => doc["rules"][0]["health"] = json!("err"),
                _ => {}
            }
        });
        assert_eq!(harness.evaluate(at)["exit_code"], 3, "{fault}");
    }
}

#[test]
fn invalid_reconfiguration_markers_are_quarantined_without_stopping_alerting() {
    for marker in [
        json!({"run_id": "a", "at": rfc3339(T0 + 301), "reason": "rules changed"}),
        json!({"run_id": "", "at": rfc3339(T0), "reason": "rules changed"}),
        json!({"run_id": "a", "at": "invalid", "reason": "rules changed"}),
        json!({"run_id": "a", "at": rfc3339(T0), "reason": "other"}),
        json!({"at": rfc3339(T0)}),
        json!({"run_id": "a", "at": rfc3339(T0), "reason": "rules changed", "extra": true}),
    ] {
        let harness = metric_alerts_harness();
        write_metric_alerts(&harness, T0, |doc| value_code_rule(doc, "inactive", "1"));
        harness.evaluate(T0);
        let at = T0 + 3600;
        let mut marker = marker;
        if marker["at"] == rfc3339(T0 + 301) {
            marker["at"] = json!(rfc3339(at + 301));
        }
        let bytes = serde_json::to_vec(&marker).unwrap();
        fs::write(harness.path("state/reconfigured"), &bytes).unwrap();
        write_metric_alerts(&harness, at, |doc| value_code_rule(doc, "firing", "2"));
        let lifecycle_path = harness.path("state/state-attention-lifecycle.json");
        let before = fs::read(&lifecycle_path).unwrap();
        let output = harness.evaluate_at(at, &["--dry-run"]);
        assert_eq!(output.status.code(), Some(3), "{output:?}");
        assert_eq!(fs::read(harness.path("state/reconfigured")).unwrap(), bytes);
        assert_eq!(fs::read(&lifecycle_path).unwrap(), before);
        let report = harness.evaluate(at);
        assert_eq!(report["exit_code"], 3);
        assert_eq!(report["exit_class"], "input_error");
        let fault = report["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|input| input["label"] == "reconfiguration_marker")
            .unwrap();
        assert!(fault["error"].as_str().unwrap().starts_with("invalid: "));
        assert_eq!(metric_input(&report)["status"], "not_current");
        assert!(!harness.path("state/reconfigured").exists());
        assert_eq!(
            fs::read(harness.path(&format!("state/reconfigured.invalid-{at}"))).unwrap(),
            bytes
        );
        write_metric_alerts(&harness, at + 60, |doc| value_code_rule(doc, "firing", "2"));
        let report = harness.evaluate(at + 60);
        assert!(
            report["inputs"]
                .as_array()
                .unwrap()
                .iter()
                .all(|input| input["label"] != "reconfiguration_marker")
        );
        assert_eq!(report["exit_code"], 3);
    }
}

#[test]
fn marker_accepts_five_minutes_of_future_clock_skew() {
    for skew in [1, 300] {
        let harness = metric_alerts_harness();
        write_metric_alerts(&harness, T0, |doc| value_code_rule(doc, "inactive", "1"));
        harness.evaluate(T0);
        let at = T0 + 3600;
        write_reconfiguration(&harness, at + skew);
        write_metric_alerts(&harness, at, |doc| value_code_rule(doc, "firing", "3"));
        let report = harness.evaluate(at);
        assert_eq!(report["exit_code"], 0);
        assert_eq!(
            metric_input(&report)["identity"]["reconfigured_at"],
            rfc3339(at)
        );
        assert!(!harness.path("state/reconfigured").exists());
        let lifecycle: Value = serde_json::from_slice(
            &fs::read(harness.path("state/state-attention-lifecycle.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(lifecycle["reconfigured_at"], at);
        for offset in [899, 900] {
            write_metric_alerts(&harness, at + offset, |doc| {
                value_code_rule(doc, "firing", "3")
            });
            let report = harness.evaluate(at + offset);
            assert_eq!(report["exit_code"], if offset < 900 { 0 } else { 3 });
        }
    }
}

fn value_code_rows(doc: &mut Value, state: &str, values: &[&str]) {
    doc["rules"]
        .as_array_mut()
        .unwrap()
        .retain(|r| r["name"] == "HostSwapExhausted");
    let rule = metric_rule(doc, "HostSwapExhausted");
    rule["labels"]["constellation_value_codes"] = json!("v1");
    rule["state"] = json!(state);
    let template = rule["instances"][0].clone();
    let mut counts = std::collections::BTreeMap::<&str, u64>::new();
    let instances: Vec<Value> = values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let mut instance = template.clone();
            instance["labels"]["instance"] = json!(format!("instance-{index}"));
            instance["state"] = json!(state);
            instance["value"] = json!(value);
            let meaning = match *value {
                "1" => "present",
                "2" => "acquisition_failed",
                "3" => "missing",
                "4" => "stale",
                "5" => "invalid_or_warming",
                _ => "invalid code",
            };
            instance["summary"] = json!(format!("evidence code={value} ({meaning})"));
            *counts.entry(value).or_default() += 1;
            instance
        })
        .collect();
    rule["instances"] = json!(instances);
    rule["instance_count"] = json!(values.len());
    rule["value_code_counts"] = json!(
        counts
            .into_iter()
            .map(|(value, count)| json!({
                "site": "labelwatch", "state": state, "value": value, "count": count
            }))
            .collect::<Vec<_>>()
    );
    refresh_firing_sites(rule);
}

#[test]
fn indeterminate_metric_notice_names_rules_and_codes_without_instance_detail() {
    let mut harness = metric_alerts_harness();
    harness.raw("warmup_grace = 0\n");
    for offset in [0, 360] {
        write_metric_alerts(&harness, T0 + offset, |doc| {
            value_code_rule(doc, "firing", "3");
            let template = doc["rules"][0].clone();
            doc["rules"] = json!([template.clone(), template.clone(), template]);
            for (rule, (name, value)) in doc["rules"].as_array_mut().unwrap().iter_mut().zip([
                ("ProbeHttpFailing", "2"),
                ("ProbeDown", "3"),
                ("HostPidTableNearLimit", "3"),
            ]) {
                rule["name"] = json!(name);
                rule["instances"] = json!([]);
                rule["value_code_counts"][0]["value"] = json!(value);
            }
        });
        let report = harness.evaluate(T0 + offset);
        if offset == 360 {
            let record = report["intents"][0]["notification_id"].as_str().unwrap();
            let sent: Value = serde_json::from_slice(&harness.submitted_intent(record)).unwrap();
            let summary = sent["summary"].as_str().unwrap();
            assert!(
                summary.contains(concat!(
                    "Now: indeterminate rules: ",
                    "HostPidTableNearLimit (host-pid-table-near-limit): code 3 (missing); ",
                    "ProbeDown (probe-down): code 3 (missing); ",
                    "ProbeHttpFailing (probe-http-failing): code 2 (acquisition_failed)."
                )),
                "{summary}"
            );
            println!("D1 notice: {summary}");
        }
    }
}

#[test]
fn indeterminate_metric_notice_limits_sorted_identities_to_eight() {
    let mut harness = metric_alerts_harness();
    harness.raw("warmup_grace = 0\n");
    for offset in [0, 360] {
        write_metric_alerts(&harness, T0 + offset, |doc| {
            value_code_rows(doc, "firing", &["1", "3", "2"]);
            let template = doc["rules"][0].clone();
            doc["rules"] = json!(
                (0..10)
                    .rev()
                    .map(|index| {
                        let mut rule = template.clone();
                        rule["name"] = json!(format!("Rule{index:02}"));
                        rule
                    })
                    .collect::<Vec<_>>()
            );
        });
        let report = harness.evaluate(T0 + offset);
        if offset == 360 {
            let intent = report["intents"]
                .as_array()
                .unwrap()
                .iter()
                .find(|intent| {
                    intent["condition_id"]
                        .as_str()
                        .unwrap()
                        .ends_with(":metric_alerts.indeterminate")
                })
                .unwrap();
            let record = intent["notification_id"].as_str().unwrap();
            let sent: Value = serde_json::from_slice(&harness.submitted_intent(record)).unwrap();
            let summary = sent["summary"].as_str().unwrap();
            let expected = (0..8).map(|index| format!(
                "Rule{index:02} (rule{index:02}): code 2 (acquisition_failed), code 3 (missing)"
            )).collect::<Vec<_>>().join("; ");
            assert!(
                summary.contains(&format!("Now: indeterminate rules: {expected}; +2 more.")),
                "{summary}"
            );
            assert!(!summary.contains("Rule08"));
            assert!(!summary.contains("Rule09"));
            assert!(!summary.contains("code 1"));
        }
    }
}

#[test]
fn indeterminate_metric_notice_survives_disabled_metric_notices_and_scopes_codes() {
    let mut harness = metric_alerts_harness();
    harness.raw("sites = [\"testbed\"]\n[rules.metric-alert-firing]\nenabled = false\n");
    for offset in [0, 360] {
        write_metric_alerts(&harness, T0 + offset, |doc| {
            value_code_rule(doc, "firing", "1");
            doc["rules"][0]["value_code_counts"] = json!([
                {"site": "elsewhere", "state": "firing", "value": "2", "count": 1},
                {"site": "testbed", "state": "pending", "value": "5", "count": 1},
                {"site": "testbed", "state": "firing", "value": "4", "count": 1},
                {"site": "testbed", "state": "firing", "value": "3", "count": 0}
            ]);
        });
        let report = harness.evaluate(T0 + offset);
        assert!(alert_intents(&report).is_empty());
        if offset == 360 {
            let record = report["intents"][0]["notification_id"].as_str().unwrap();
            let sent: Value = serde_json::from_slice(&harness.submitted_intent(record)).unwrap();
            let summary = sent["summary"].as_str().unwrap();
            assert!(summary.contains("Now: indeterminate rules: HostSwapExhausted (host-swap-exhausted.testbed): code 4 (stale)."), "{summary}");
            assert!(!summary.contains("code 2"));
            assert!(!summary.contains("code 3"));
        }
    }
}

#[test]
fn mixed_metric_notice_keeps_full_legends_and_describes_unknown_rows() {
    for (code, meaning) in [
        ("2", "acquisition_failed"),
        ("3", "missing"),
        ("4", "stale"),
        ("5", "invalid_or_warming"),
    ] {
        let harness = metric_alerts_harness();
        let legend = "(1=failed, 2=exporter unreachable, 3=missing, 4=stale, 5=warming)";
        for offset in [0, 90] {
            write_metric_alerts(&harness, T0 + offset, |doc| {
                value_code_rows(doc, "firing", &["1", code]);
                let rule = &mut doc["rules"][0];
                rule["name"] = json!("ProbeHttpFailing");
                for (index, instance) in rule["instances"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .enumerate()
                {
                    instance["summary"] = json!(format!(
                        "service HTTP probe /health on labelwatch: evidence code={} {legend}",
                        if index == 0 { "1" } else { code }
                    ));
                }
            });
            let report = harness.evaluate(T0 + offset);
            if offset == 90 {
                let record = report["intents"][0]["notification_id"].as_str().unwrap();
                let sent: Value =
                    serde_json::from_slice(&harness.submitted_intent(record)).unwrap();
                let summary = sent["summary"].as_str().unwrap();
                assert_eq!(summary.matches(legend).count(), 2, "{summary}");
                assert!(
                    summary.contains("ProbeHttpFailing firing on labelwatch (instance-0)"),
                    "{summary}"
                );
                assert!(
                    summary.contains(&format!(
                        "held unknown (code {code}: {meaning}) on labelwatch (instance-1)"
                    )),
                    "{summary}"
                );
                assert!(!summary.contains("firing on labelwatch (instance-1)"));
            }
        }
    }
}

#[test]
fn pid_table_notice_uses_instance_then_host_then_site() {
    for (labels, location) in [
        (
            json!({"site": "testbed", "instance": "exporter:9100", "host": "node"}),
            "testbed (exporter:9100)",
        ),
        (json!({"site": "testbed", "host": "node"}), "testbed (node)"),
        (json!({"site": "testbed"}), "testbed"),
    ] {
        let harness = metric_alerts_harness();
        for offset in [0, 90] {
            write_metric_alerts(&harness, T0 + offset, |doc| {
                value_code_rule(doc, "firing", "1");
                let rule = &mut doc["rules"][0];
                rule["name"] = json!("HostPidTableNearLimit");
                rule["instances"][0]["labels"] = labels.clone();
                rule["value_code_counts"][0]["site"] = json!("testbed");
                refresh_firing_sites(rule);
            });
            let report = harness.evaluate(T0 + offset);
            if offset == 90 {
                let record = report["intents"][0]["notification_id"].as_str().unwrap();
                let sent: Value =
                    serde_json::from_slice(&harness.submitted_intent(record)).unwrap();
                let summary = sent["summary"].as_str().unwrap();
                assert!(
                    summary.contains(&format!(
                        "Now: HostPidTableNearLimit firing on {location}: evidence code=1"
                    )),
                    "{summary}"
                );
                assert!(!summary.contains("(?)"), "{summary}");
            }
        }
    }
}

#[test]
fn mixed_value_codes_are_present_with_partial_coverage_in_report_and_digest() {
    for scoped in [false, true] {
        let mut harness = metric_alerts_harness();
        harness.raw("warmup_grace = 0\n");
        if scoped {
            harness.raw("sites = [\"labelwatch\"]\n");
        }
        harness.raw("[digest]\nat_utc = \"12:01\"\n");
        let id = if scoped {
            format!("{SWAP}.labelwatch")
        } else {
            SWAP.to_owned()
        };
        for offset in [0, 90] {
            write_metric_alerts(&harness, T0 + offset, |doc| {
                value_code_rows(doc, "firing", &["1", "3"]);
            });
            let report = harness.evaluate(T0 + offset);
            let c = condition(&report, &id).unwrap();
            assert_eq!(c["observation"], "present", "{c}");
            assert!(
                c["note"]
                    .as_str()
                    .unwrap()
                    .contains("value code 3 (missing)")
            );
            let input = metric_input(&report);
            assert_eq!(input["status"], "not_current");
            assert_eq!(causes(&input), ["indeterminate"]);
            assert!(
                input["error"]
                    .as_str()
                    .unwrap()
                    .contains("value code 3 (missing)")
            );
            assert_eq!(alert_intents(&report).len(), usize::from(offset == 90));
            if offset == 90 {
                let digest = report["digest"]["summary"].as_str().unwrap();
                assert!(digest.contains("value code 3 (missing)"), "{digest}");
                assert!(digest.contains("indeterminate"), "{digest}");
                assert_eq!(harness.state()["conditions"][&id]["active"], true);
            }
        }
    }
}

#[test]
fn all_missing_value_code_rows_are_unknown_held() {
    let mut harness = metric_alerts_harness();
    harness.raw("warmup_grace = 0\n");
    for offset in [0, 360] {
        write_metric_alerts(&harness, T0 + offset, |doc| {
            value_code_rows(doc, "firing", &["3", "3"]);
        });
        let report = harness.evaluate(T0 + offset);
        let c = condition(&report, SWAP).unwrap();
        assert_eq!(c["observation"], "unknown");
        assert!(
            c["note"]
                .as_str()
                .unwrap()
                .contains("value code 3 (missing)")
        );
        assert_eq!(causes(&metric_input(&report)), ["indeterminate"]);
        assert!(alert_intents(&report).is_empty());
        assert!(
            harness.state()["conditions"]
                .get(SWAP)
                .is_none_or(|c| c["active"] == false)
        );
    }
}

#[test]
fn disappearing_present_row_with_warming_remaining_never_clears() {
    let harness = metric_alerts_harness();
    for offset in [0, 90, 150, 400] {
        write_metric_alerts(&harness, T0 + offset, |doc| {
            value_code_rows(doc, "firing", &["1", "5"]);
            if offset >= 150 {
                let rule = metric_rule(doc, "HostSwapExhausted");
                rule["instances"].as_array_mut().unwrap().remove(0);
                rule["value_code_counts"].as_array_mut().unwrap().remove(0);
                rule["instance_count"] = json!(1);
                refresh_firing_sites(rule);
            }
        });
        let report = harness.evaluate(T0 + offset);
        let c = condition(&report, SWAP).unwrap();
        assert_eq!(
            c["observation"],
            if offset < 150 { "present" } else { "unknown" }
        );
        assert!(
            c["note"]
                .as_str()
                .unwrap()
                .contains("value code 5 (invalid_or_warming)")
        );
        assert_eq!(causes(&metric_input(&report)), ["warming"]);
        assert_eq!(alert_intents(&report).len(), usize::from(offset == 90));
        if offset >= 90 {
            assert_eq!(harness.state()["conditions"][SWAP]["active"], true);
        }
    }
}

#[test]
fn metric_value_codes_from_the_shared_vector() {
    let vector: Value = serde_json::from_slice(&fs::read(METRIC_ALERTS_VECTOR).unwrap()).unwrap();
    for case in vector["value_code_cases"].as_array().unwrap() {
        let mut harness = metric_alerts_harness();
        harness.raw("warmup_grace = 0\n");
        harness.raw("[digest]\nat_utc = \"00:00\"\n");
        write_metric_alerts(&harness, T0, |doc| {
            let mut rule = case["document_rule"].clone();
            rule["last_evaluation"] = json!(rfc3339(T0 - 2));
            doc["rules"] = json!([rule]);
        });
        let report = harness.evaluate(T0);
        if case["observation"] == "rejected" {
            assert!(condition(&report, SWAP).is_none(), "{case}: {report}");
            let input = metric_input(&report);
            assert!(causes(&input).contains(&"rejected".into()), "{input}");
            assert!(
                input["rejected_rules"][0]["reason"]
                    .as_str()
                    .unwrap()
                    .contains(case["meaning"].as_str().unwrap()),
                "{input}"
            );
            assert!(alert_intents(&report).is_empty());
            continue;
        }
        let c = condition(&report, SWAP).unwrap();
        assert_eq!(c["observation"], case["observation"], "{case}: {c}");
        if let Some(meaning) = case["meaning"].as_str() {
            assert!(c["note"].as_str().unwrap().contains(meaning), "{case}: {c}");
            assert!(
                report["digest"]["summary"]
                    .as_str()
                    .unwrap()
                    .contains(meaning),
                "{report}"
            );
        }
        assert!(
            alert_intents(&report).is_empty(),
            "no immediate notice: {case}"
        );
        if case["observation"] == "unknown" {
            assert!(
                harness.state()["conditions"]
                    .get(SWAP)
                    .is_none_or(|c| c["active"] == false)
            );
            let input = metric_input(&report);
            let expected = if c["note"].as_str().unwrap().contains("invalid_or_warming") {
                "warming"
            } else {
                "indeterminate"
            };
            assert!(causes(&input).contains(&expected.into()), "{input}");
        }
    }
}

#[test]
fn value_codes_hold_an_open_condition_until_healthy_recovery() {
    let harness = metric_alerts_harness();
    for offset in [0, 90] {
        write_metric_alerts(&harness, T0 + offset, |doc| {
            value_code_rule(doc, "firing", "1")
        });
        let report = harness.evaluate(T0 + offset);
        assert_eq!(condition(&report, SWAP).unwrap()["observation"], "present");
        assert_eq!(alert_intents(&report).len(), usize::from(offset == 90));
        if offset == 90 {
            let record = report["intents"]
                .as_array()
                .unwrap()
                .iter()
                .find(|i| i["condition_id"] == SWAP)
                .unwrap()["notification_id"]
                .as_str()
                .unwrap();
            let sent: Value = serde_json::from_slice(&harness.submitted_intent(record)).unwrap();
            assert!(
                sent["summary"]
                    .as_str()
                    .unwrap()
                    .contains("evidence code=1 (present)"),
                "{sent}"
            );
        }
    }
    for (offset, state, code) in [
        (150, "firing", "2"),
        (400, "pending", "3"),
        (650, "firing", "4"),
        (700, "pending", "5"),
    ] {
        write_metric_alerts(&harness, T0 + offset, |doc| {
            value_code_rule(doc, state, code)
        });
        let report = harness.evaluate(T0 + offset);
        assert_eq!(condition(&report, SWAP).unwrap()["observation"], "unknown");
        assert!(alert_intents(&report).is_empty());
        assert_eq!(harness.state()["conditions"][SWAP]["active"], true);
    }
    for (offset, fault) in [
        (800, "health"),
        (950, "evaluation"),
        (1100, "drift"),
        (1250, "stale"),
    ] {
        write_metric_alerts(&harness, T0 + offset, |doc| {
            value_code_rule(doc, "firing", "1");
            quiet(doc, "HostSwapExhausted");
            let rule = metric_rule(doc, "HostSwapExhausted");
            rule["value_code_counts"] = json!([]);
            match fault {
                "health" => rule["health"] = json!("err"),
                "evaluation" => rule["last_evaluation"] = json!(rfc3339(T0)),
                "drift" => doc["declared_policy_sha256"] = json!("different"),
                "stale" => doc["generated_at"] = json!(rfc3339(T0)),
                _ => unreachable!(),
            }
        });
        let report = harness.evaluate(T0 + offset);
        assert_eq!(
            condition(&report, SWAP).unwrap()["observation"],
            "unknown",
            "{fault}"
        );
        assert!(alert_intents(&report).is_empty());
    }
    for offset in [1400, 1530] {
        write_metric_alerts(&harness, T0 + offset, |doc| {
            value_code_rule(doc, "firing", "1");
            quiet(doc, "HostSwapExhausted");
            metric_rule(doc, "HostSwapExhausted")["value_code_counts"] = json!([]);
        });
        let report = harness.evaluate(T0 + offset);
        assert_eq!(condition(&report, SWAP).unwrap()["observation"], "clear");
        assert_eq!(alert_intents(&report).len(), usize::from(offset == 1530));
    }
    assert!(
        harness.state()["conditions"]
            .get(SWAP)
            .is_none_or(|c| c["active"] == false)
    );
}

#[test]
fn only_code_five_is_informational_across_fresh_passes() {
    let harness = metric_alerts_harness();
    for offset in [0, 360, 3660, 21_599] {
        write_metric_alerts(&harness, T0 + offset, |doc| {
            value_code_rule(doc, "firing", "5");
            let template = doc["rules"][0].clone();
            doc["rules"] = json!([template.clone(), template]);
            doc["rules"][0]["name"] = json!("HostLinkFlapping");
            doc["rules"][1]["name"] = json!("HostOomKill");
        });
        let output = harness.evaluate_at(T0 + offset, &[]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let report = harness.report();
        assert_eq!(report["exit_code"], 0);
        assert_eq!(report["exit_class"], "clean");
        assert!(report["first_error"].is_null());
        let input = metric_input(&report);
        assert_eq!(input["status"], "ok");
        assert_eq!(causes(&input), ["warming"]);
        assert!(input.get("error").is_none());
        assert_eq!(input["identity"]["first_seen"], rfc3339(T0));
        assert_eq!(input["identity"]["warmup_grace"], 900);
        assert_eq!(input["identity"]["warming_bound"], 21_600);
        let rules = input["identity"]["warming_rules"].as_array().unwrap();
        assert_eq!(rules.len(), 2);
        for rule in rules {
            assert_eq!(rule["codes"], json!([5]));
            assert_eq!(rule["since"], rfc3339(T0));
            assert_eq!(rule["elapsed_seconds"], offset);
            assert_eq!(rule["bound_exceeded"], false);
        }
        for target in ["host-link-flapping", "host-oom-kill"] {
            let id = SWAP.replace("host-swap-exhausted", target);
            assert_eq!(condition(&report, &id).unwrap()["observation"], "unknown");
        }
        assert!(intents(&report).is_empty());
    }
}

#[test]
fn acquisition_codes_warm_only_during_initial_grace() {
    for code in ["2", "3"] {
        let mut harness = metric_alerts_harness();
        for offset in [0, 899, 900, 1199, 1200, 1201] {
            write_metric_alerts(&harness, T0 + offset, |doc| {
                value_code_rule(doc, "pending", code);
            });
            let report = harness.evaluate(T0 + offset);
            let input = metric_input(&report);
            assert_eq!(condition(&report, SWAP).unwrap()["observation"], "unknown");
            assert_eq!(
                input["status"],
                if offset < 900 { "ok" } else { "not_current" }
            );
            assert_eq!(
                causes(&input),
                [if offset < 900 {
                    "warming"
                } else {
                    "indeterminate"
                }]
            );
            assert_eq!(report["exit_code"], if offset < 900 { 0 } else { 3 });
            assert_eq!(intents(&report).len(), usize::from(offset == 1201));
            assert!(alert_intents(&report).is_empty());
        }
        // A missing report and an input relabel do not renew the host's grace.
        fs::remove_file(harness.path("metric-alerts.json")).unwrap();
        harness.evaluate(T0 + 1300);
        harness.raw("label = \"renamed\"\n");
        write_metric_alerts(&harness, T0 + 1400, |doc| {
            value_code_rule(doc, "firing", code)
        });
        let report = harness.evaluate(T0 + 1400);
        let input = metric_input(&report);
        assert_eq!(input["status"], "not_current");
        assert_eq!(input["identity"]["first_seen"], rfc3339(T0));
    }
}

#[test]
fn configurable_warming_bound_can_expire_inside_grace() {
    for code in ["2", "3", "5"] {
        let mut harness = metric_alerts_harness();
        harness.raw("warmup_grace = 1000\nwarming_bound = 100\n");
        for offset in [0, 99, 100, 400, 401] {
            write_metric_alerts(&harness, T0 + offset, |doc| {
                value_code_rule(doc, "firing", code)
            });
            let report = harness.evaluate(T0 + offset);
            let input = metric_input(&report);
            assert_eq!(
                input["status"],
                if offset < 100 { "ok" } else { "not_current" }
            );
            assert_eq!(
                input["identity"]["warming_rules"][0]["bound_exceeded"],
                offset >= 100
            );
            assert_eq!(intents(&report).len(), usize::from(offset == 401));
            if offset == 401 {
                let record = report["intents"][0]["notification_id"].as_str().unwrap();
                let sent: Value =
                    serde_json::from_slice(&harness.submitted_intent(record)).unwrap();
                assert!(sent["summary"].as_str().unwrap().contains(&format!(
                    "HostSwapExhausted (host-swap-exhausted): code {code}"
                )));
            }
        }
    }
}

#[test]
fn warming_interval_resets_only_on_qualified_nonwarming_observation() {
    let mut harness = metric_alerts_harness();
    harness.raw("warming_bound = 100\n");
    for offset in [0, 50, 60, 70, 80, 100, 150, 160, 250] {
        write_metric_alerts(&harness, T0 + offset, |doc| {
            value_code_rule(doc, "firing", "5");
            if offset == 70 {
                value_code_rule(doc, "firing", "4");
            }
            if offset == 80 {
                quiet(doc, "HostSwapExhausted");
                metric_rule(doc, "HostSwapExhausted")["last_series_fetched"] = json!(0);
            }
            if matches!(offset, 50 | 150) {
                quiet(doc, "HostSwapExhausted");
                if offset == 50 {
                    doc["generated_at"] = json!(rfc3339(T0 - 400));
                }
            }
        });
        let report = harness.evaluate(T0 + offset);
        let input = metric_input(&report);
        if offset == 100 {
            assert_eq!(input["status"], "not_current");
            assert_eq!(input["identity"]["warming_rules"][0]["since"], rfc3339(T0));
        } else if offset >= 160 {
            assert_eq!(input["status"], "ok");
            assert_eq!(
                input["identity"]["warming_rules"][0]["since"],
                rfc3339(T0 + 160)
            );
        }
    }
}

#[test]
fn warming_history_obeys_dry_run_and_clock_reset() {
    let mut harness = metric_alerts_harness();
    harness.raw("warming_bound = 100\n");
    write_metric_alerts(&harness, T0, |doc| value_code_rule(doc, "firing", "5"));
    let output = harness.evaluate_at(T0, &["--dry-run"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(!harness.path("state/state.json").exists());
    assert!(!harness.path("state/state-metric-alerts.json").exists());
    assert!(
        !harness
            .path("state/state-attention-lifecycle.json")
            .exists()
    );
    write_reconfiguration(&harness, T0 + 50);
    for offset in [50, 1000] {
        write_metric_alerts(&harness, T0 + offset, |doc| {
            value_code_rule(doc, "firing", "5")
        });
        harness.evaluate(T0 + offset);
    }
    let output = harness.reset_clock_at(T0 + 20);
    assert!(output.status.success(), "{output:?}");
    let history: Value =
        serde_json::from_slice(&fs::read(harness.path("state/state-metric-alerts.json")).unwrap())
            .unwrap();
    let history = &history["history"];
    assert_eq!(history["first_seen"], T0 + 20);
    assert_eq!(
        history["warming_since"]["HostSwapExhausted (host-swap-exhausted)"],
        T0 + 20
    );
    let lifecycle: Value = serde_json::from_slice(
        &fs::read(harness.path("state/state-attention-lifecycle.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(lifecycle["first_seen"], T0 + 20);
    assert_eq!(lifecycle["reconfigured_at"], T0 + 20);
    assert_eq!(
        lifecycle["identities"]["host-swap-exhausted"]["grace_at"],
        T0 + 20
    );
    write_metric_alerts(&harness, T0 + 21, |doc| value_code_rule(doc, "firing", "5"));
    let report = harness.evaluate(T0 + 21);
    assert_eq!(metric_input(&report)["status"], "ok");
}

#[test]
fn absent_rule_returns_with_a_fresh_warming_interval() {
    let harness = metric_alerts_harness();
    write_metric_alerts(&harness, T0, |doc| value_code_rule(doc, "firing", "5"));
    harness.evaluate(T0);
    write_metric_alerts(&harness, T0 + 60, |doc| {
        value_code_rule(doc, "firing", "1");
        doc["rules"][0]["name"] = json!("HostOomKill");
    });
    harness.evaluate(T0 + 60);
    let history: Value =
        serde_json::from_slice(&fs::read(harness.path("state/state-metric-alerts.json")).unwrap())
            .unwrap();
    assert_eq!(history["history"]["warming_since"], json!({}));

    write_metric_alerts(&harness, T0 + 25_200, |doc| {
        value_code_rule(doc, "firing", "5")
    });
    let report = harness.evaluate(T0 + 25_200);
    let input = metric_input(&report);
    assert_eq!(input["status"], "ok");
    let rule = &input["identity"]["warming_rules"][0];
    assert_eq!(rule["since"], rfc3339(T0 + 25_200));
    assert_eq!(rule["elapsed_seconds"], 0);
    assert_eq!(rule["bound_exceeded"], false);
}

#[test]
fn stale_or_unreadable_report_keeps_absent_rule_history() {
    for unreadable in [false, true] {
        let harness = metric_alerts_harness();
        write_metric_alerts(&harness, T0, |doc| value_code_rule(doc, "firing", "5"));
        harness.evaluate(T0);
        let path = harness.path("state/state-metric-alerts.json");
        let before = fs::read(&path).unwrap();
        if unreadable {
            fs::remove_file(harness.path("metric-alerts.json")).unwrap();
        } else {
            write_metric_alerts(&harness, T0 + 60, |doc| {
                doc["rules"] = json!([]);
                doc["generated_at"] = json!(rfc3339(T0 - 400));
            });
        }
        harness.evaluate(T0 + 60);
        let after: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let before: Value = serde_json::from_slice(&before).unwrap();
        assert_eq!(after["history"], before["history"]);
        assert_eq!(after["updated_at"], T0 + 60);
        write_metric_alerts(&harness, T0 + 25_200, |doc| {
            value_code_rule(doc, "firing", "5")
        });
        let report = harness.evaluate(T0 + 25_200);
        let input = metric_input(&report);
        assert_eq!(input["status"], "not_current");
        let rule = &input["identity"]["warming_rules"][0];
        assert_eq!(rule["since"], rfc3339(T0));
        assert_eq!(rule["elapsed_seconds"], 25_200);
        assert_eq!(rule["bound_exceeded"], true);
    }
}

#[test]
fn metric_history_preserves_rollback_state_keys_and_dry_run_custody() {
    let harness = metric_alerts_harness();
    write_metric_alerts(&harness, T0, |doc| value_code_rule(doc, "firing", "5"));
    harness.evaluate(T0);
    let state = harness.state();
    // f7b74cc State denies unknown fields; nq_watchers is its sole optional
    // top-level field and is omitted when empty in this fixture.
    assert_eq!(
        state
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["conditions", "schema", "site", "updated_at"]
    );
    assert_eq!(state["schema"], "constellation.attention_state.v1");
    let state_path = harness.path("state/state.json");
    let path = harness.path("state/state-metric-alerts.json");
    let before_state = fs::read(&state_path).unwrap();
    let before = fs::read(&path).unwrap();
    let history: Value = serde_json::from_slice(&before).unwrap();
    assert_eq!(
        history["schema"],
        "constellation.attention_metric_alerts_state.v1"
    );
    assert_eq!(history["site"], "labelwatch");
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    write_metric_alerts(&harness, T0 + 60, |doc| value_code_rule(doc, "firing", "1"));
    let output = harness.evaluate_at(T0 + 60, &["--dry-run"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(fs::read(&state_path).unwrap(), before_state);
}

#[test]
fn metric_history_refuses_malformed_or_foreign_custody() {
    let harness = metric_alerts_harness();
    write_metric_alerts(&harness, T0, |doc| value_code_rule(doc, "firing", "5"));
    harness.evaluate(T0);
    let path = harness.path("state/state-metric-alerts.json");
    let history: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let before_state = fs::read(harness.path("state/state.json")).unwrap();
    for (field, value) in [
        ("schema", json!("unknown")),
        ("site", json!("foreign")),
        ("extra", json!(true)),
        (
            "history",
            json!({"first_seen": T0, "warming_since": {}, "extra": true}),
        ),
    ] {
        let mut bad = history.clone();
        bad[field] = value;
        let bytes = serde_json::to_vec(&bad).unwrap();
        fs::write(&path, &bytes).unwrap();
        let output = harness.evaluate_at(T0 + 60, &[]);
        assert_eq!(output.status.code(), Some(1), "{field}: {output:?}");
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(
            fs::read(harness.path("state/state.json")).unwrap(),
            before_state
        );
    }
}

#[test]
fn missing_metric_history_never_resolves_an_established_acquisition_fault() {
    const FAULT: &str = "constellation:labelwatch:host_posture:evaluator-input-unavailable:metric_alerts.indeterminate";
    for code in ["2", "3"] {
        for condition_only in [false, true] {
            let mut harness = metric_alerts_harness();
            let original_config = harness.extra_config.clone();
            harness.raw("warmup_grace = 0\n");
            for offset in (0..=360).step_by(60) {
                write_metric_alerts(&harness, T0 + offset, |doc| {
                    value_code_rule(doc, "firing", code)
                });
                assert_eq!(harness.evaluate(T0 + offset)["exit_code"], 3);
            }
            let mut state = harness.state();
            assert_eq!(state["conditions"][FAULT]["active"], true);
            let transition = state["conditions"][FAULT]["transition_at"].clone();
            // Upgrade from the old state shape, or deletion on a running site.
            // Conditions must establish the input even without updated_at > 0.
            if condition_only {
                state["updated_at"] = json!(0);
                state["conditions"]
                    .as_object_mut()
                    .unwrap()
                    .retain(|id, _| id == FAULT);
                fs::write(
                    harness.path("state/state.json"),
                    serde_json::to_vec(&state).unwrap(),
                )
                .unwrap();
            }
            fs::remove_file(harness.path("state/state-metric-alerts.json")).unwrap();
            harness.extra_config = original_config;
            for offset in (420..=1740).step_by(60) {
                write_metric_alerts(&harness, T0 + offset, |doc| {
                    value_code_rule(doc, "firing", code)
                });
                let output = harness.evaluate_at(T0 + offset, &[]);
                assert_eq!(output.status.code(), Some(3), "{output:?}");
                let report = harness.report();
                let input = metric_input(&report);
                assert_eq!(input["identity"]["first_seen"], rfc3339(T0 + 420 - 900));
                assert_eq!(input["status"], "not_current");
                assert_eq!(causes(&input), ["indeterminate"]);
                assert_eq!(report["exit_code"], 3);
                assert!(input["identity"].get("warming_rules").is_none());
                assert!(intents(&report).is_empty(), "{report}");
                let state = harness.state();
                assert_eq!(state["conditions"][FAULT]["active"], true);
                assert_eq!(state["conditions"][FAULT]["transition_at"], transition);
                assert_eq!(state["conditions"][FAULT]["clear_since"], Value::Null);
            }
        }
    }
}

#[test]
fn missing_metric_history_with_a_last_pass_or_metric_condition_has_no_grace() {
    for metric_condition in [false, true] {
        let harness = metric_alerts_harness();
        let mut state = if metric_condition {
            write_metric_alerts(&harness, T0, |doc| value_code_rule(doc, "firing", "1"));
            harness.evaluate(T0);
            fs::remove_file(harness.path("state/state-metric-alerts.json")).unwrap();
            let mut state = constellation_attention::state::State::load(
                &harness.path("state/state.json"),
                "labelwatch",
            )
            .unwrap();
            state
                .conditions
                .retain(|_, condition| condition.key.rule == "metric-alert-firing");
            assert!(!state.conditions.is_empty());
            state
        } else {
            constellation_attention::state::State::empty("labelwatch")
        };
        state.updated_at = if metric_condition { 0 } else { T0 };
        state.save(&harness.path("state/state.json")).unwrap();
        write_metric_alerts(&harness, T0 + 60, |doc| value_code_rule(doc, "firing", "2"));
        let report = harness.evaluate(T0 + 60);
        assert_eq!(report["exit_code"], 3);
        assert_eq!(
            metric_input(&report)["identity"]["first_seen"],
            rfc3339(T0 + 60 - 900)
        );
    }
}

#[test]
fn fresh_install_grace_starts_when_the_first_report_appears() {
    for code in ["2", "3"] {
        let harness = metric_alerts_harness();
        for offset in [0, 60, 600] {
            harness.evaluate(T0 + offset);
            let saved: Value = serde_json::from_slice(
                &fs::read(harness.path("state/state-metric-alerts.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(saved["history"], Value::Null);
            assert_eq!(saved["updated_at"], T0 + offset);
        }
        for offset in [660, 1559, 1560] {
            write_metric_alerts(&harness, T0 + offset, |doc| {
                value_code_rule(doc, "firing", code)
            });
            let report = harness.evaluate(T0 + offset);
            let input = metric_input(&report);
            assert_eq!(input["identity"]["first_seen"], rfc3339(T0 + 660));
            assert_eq!(
                input["status"],
                if offset < 1560 { "ok" } else { "not_current" }
            );
            assert_eq!(report["exit_code"], if offset < 1560 { 0 } else { 3 });
        }
    }
}

#[test]
fn empty_attention_roster_preserves_the_warming_bound() {
    for unlabelled in [false, true] {
        let mut harness = metric_alerts_harness();
        harness.raw("warming_bound = 100\n");
        write_metric_alerts(&harness, T0, |doc| value_code_rule(doc, "firing", "5"));
        harness.evaluate(T0);
        for offset in [60, 90] {
            write_metric_alerts(&harness, T0 + offset, |doc| {
                if unlabelled {
                    for rule in doc["rules"].as_array_mut().unwrap() {
                        rule["labels"]["attention"] = json!("false");
                    }
                } else {
                    doc["rules"] = json!([]);
                }
            });
            let report = harness.evaluate(T0 + offset);
            assert_eq!(causes(&metric_input(&report)), ["empty"]);
        }
        write_metric_alerts(&harness, T0 + 100, |doc| {
            value_code_rule(doc, "firing", "5")
        });
        let report = harness.evaluate(T0 + 100);
        assert_eq!(report["exit_code"], 3);
        let input = metric_input(&report);
        let rule = &input["identity"]["warming_rules"][0];
        assert_eq!(rule["since"], rfc3339(T0));
        assert_eq!(rule["elapsed_seconds"], 100);
        assert_eq!(rule["bound_exceeded"], true);
    }
}

#[test]
fn roll_forward_prunes_warming_from_before_untracked_passes() {
    for legacy in [false, true] {
        let harness = metric_alerts_harness();
        write_metric_alerts(&harness, T0, |doc| value_code_rule(doc, "firing", "5"));
        harness.evaluate(T0);
        let path = harness.path("state/state-metric-alerts.json");
        let mut old: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        if legacy {
            old.as_object_mut().unwrap().remove("updated_at");
        }
        // The rollback binary can observe recovery and later warming without
        // maintaining the sidecar. Restore its untouched pre-rollback bytes.
        for (offset, code) in [(60, "1"), (120, "5")] {
            write_metric_alerts(&harness, T0 + offset, |doc| {
                value_code_rule(doc, "firing", code)
            });
            harness.evaluate(T0 + offset);
        }
        fs::write(&path, serde_json::to_vec(&old).unwrap()).unwrap();
        for offset in [180, 240] {
            write_metric_alerts(&harness, T0 + offset, |doc| {
                value_code_rule(doc, "firing", "5")
            });
            let report = harness.evaluate(T0 + offset);
            let input = metric_input(&report);
            assert_eq!(input["identity"]["first_seen"], rfc3339(T0));
            assert_eq!(
                input["identity"]["warming_rules"][0]["since"],
                rfc3339(T0 + 180)
            );
            let saved: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            assert_eq!(saved["updated_at"], T0 + offset);
        }
    }
}

#[test]
fn warming_does_not_mask_another_rules_acquisition_fault() {
    let mut harness = metric_alerts_harness();
    harness.raw("warmup_grace = 0\n");
    for offset in [0, 301] {
        write_metric_alerts(&harness, T0 + offset, |doc| {
            value_code_rule(doc, "firing", "5");
            let template = doc["rules"][0].clone();
            doc["rules"] = json!([template.clone(), template]);
            doc["rules"][0]["name"] = json!("HostLinkFlapping");
            doc["rules"][1]["name"] = json!("ProbeDown");
            doc["rules"][1]["value_code_counts"][0]["value"] = json!("2");
        });
        let report = harness.evaluate(T0 + offset);
        let input = metric_input(&report);
        assert_eq!(input["status"], "not_current");
        assert_eq!(causes(&input), ["indeterminate", "warming"]);
        assert_eq!(
            input["identity"]["warming_rules"].as_array().unwrap().len(),
            1
        );
        assert_eq!(report["exit_code"], 3);
        assert!(
            report["first_error"]
                .as_str()
                .unwrap()
                .contains("ProbeDown")
        );
        if offset == 301 {
            let record = report["intents"][0]["notification_id"].as_str().unwrap();
            let sent: Value = serde_json::from_slice(&harness.submitted_intent(record)).unwrap();
            let summary = sent["summary"].as_str().unwrap();
            assert!(summary.contains("ProbeDown (probe-down): code 2 (acquisition_failed)"));
            assert!(!summary.contains("HostLinkFlapping"));
        }
    }
}

#[test]
fn warming_configuration_rejects_invalid_bounds() {
    for setting in [
        "warmup_grace = -1",
        "warming_bound = 0",
        "warming_bound = -1",
    ] {
        let mut harness = metric_alerts_harness();
        harness.raw(setting);
        let output = harness.command(&[
            "check-config",
            "--config",
            harness.config_path().to_str().unwrap(),
        ]);
        assert_eq!(output.status.code(), Some(2), "{setting}: {output:?}");
    }
}

#[test]
fn never_present_warming_surfaces_through_input_unavailable() {
    let mut harness = metric_alerts_harness();
    harness.raw("[digest]\nat_utc = \"12:05\"\n");
    for offset in [0, 21_599, 21_600, 21_899, 21_900, 21_901] {
        write_metric_alerts(&harness, T0 + offset, |doc| {
            value_code_rule(doc, "pending", "5")
        });
        let report = harness.evaluate(T0 + offset);
        assert!(alert_intents(&report).is_empty());
        assert_eq!(condition(&report, SWAP).unwrap()["observation"], "unknown");
        assert!(
            harness.state()["conditions"]
                .get(SWAP)
                .is_none_or(|c| c["active"] == false)
        );
        let input_intents = intents(&report)
            .into_iter()
            .filter(|(id, _, _)| id.ends_with(":metric_alerts.indeterminate"))
            .count();
        assert_eq!(input_intents, usize::from(offset == 21_901), "{report}");
        let input = metric_input(&report);
        assert_eq!(
            input["status"],
            if offset < 21_600 { "ok" } else { "not_current" }
        );
        assert_eq!(report["exit_code"], if offset < 21_600 { 0 } else { 3 });
        if offset == 21_901 {
            let record = report["intents"][0]["notification_id"].as_str().unwrap();
            let sent: Value = serde_json::from_slice(&harness.submitted_intent(record)).unwrap();
            assert!(
                sent["summary"].as_str().unwrap().contains(
                    "HostSwapExhausted (host-swap-exhausted): code 5 (invalid_or_warming); warming for 6h 5m (bound 6h)"
                )
            );
        }
    }
}

#[test]
fn value_codes_are_scoped_by_site_and_survive_truncated_detail() {
    let mut harness = metric_alerts_harness();
    harness.raw("sites = [\"crow\", \"testbed\", \"labelwatch\"]\n");
    write_metric_alerts(&harness, T0, |doc| {
        value_code_rule(doc, "firing", "1");
        let rule = metric_rule(doc, "HostSwapExhausted");
        rule["instances"] = json!([]);
        rule["instance_count"] = json!(80);
        rule["firing_sites"] = json!({"crow": 41, "testbed": 39});
        rule["value_code_counts"] = json!([
            {"site":"crow", "state":"firing", "value":"1", "count":40},
            {"site":"crow", "state":"firing", "value":"4", "count":1},
            {"site":"testbed", "state":"firing", "value":"1", "count":39}
        ]);
    });
    let report = harness.evaluate(T0);
    for (site, observation) in [
        ("crow", "present"),
        ("testbed", "present"),
        ("labelwatch", "clear"),
    ] {
        let c = condition(&report, &format!("{SWAP}.{site}")).unwrap();
        assert_eq!(c["observation"], observation, "{c}");
    }
    let c = condition(&report, &format!("{SWAP}.crow")).unwrap();
    assert!(c["note"].as_str().unwrap().contains("value code 4 (stale)"));
}

#[test]
fn marked_active_rules_without_complete_values_never_guess() {
    let harness = metric_alerts_harness();
    for (offset, malformed) in [
        (0, Value::Null),
        (60, json!([])),
        (120, json!([{"site":"labelwatch"}])),
    ] {
        write_metric_alerts(&harness, T0 + offset, |doc| {
            value_code_rule(doc, "firing", "1");
            metric_rule(doc, "HostSwapExhausted")["value_code_counts"] = malformed.clone();
        });
        let report = harness.evaluate(T0 + offset);
        assert!(condition(&report, SWAP).is_none(), "{report}");
        assert!(causes(&metric_input(&report)).contains(&"rejected".into()));
        assert!(alert_intents(&report).is_empty());
    }
}

#[test]
fn out_of_range_codes_reject_only_the_rule_and_hold_its_open_condition() {
    let mut harness = metric_alerts_harness();
    harness.raw("sites = [\"labelwatch\"]\n");
    let swap = format!("{SWAP}.labelwatch");
    let other = "constellation:labelwatch:host_posture:metric-alert-firing:other-metric.labelwatch";
    for (offset, bad_code) in [(0, false), (90, false), (150, true), (300, true)] {
        write_metric_alerts(&harness, T0 + offset, |doc| {
            value_code_rule(doc, "firing", "1");
            let mut healthy = metric_rule(doc, "HostSwapExhausted").clone();
            healthy["name"] = json!("OtherMetric");
            if bad_code {
                let rule = metric_rule(doc, "HostSwapExhausted");
                // The invalid code is beyond bounded instance detail and on
                // another site. It still rejects the entire definition.
                rule["value_code_counts"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({
                        "site":"crow", "state":"pending", "value":"6", "count":1
                    }));
                healthy["state"] = json!("inactive");
                healthy["instances"] = json!([]);
                healthy["value_code_counts"] = json!([]);
            }
            doc["rules"].as_array_mut().unwrap().push(healthy);
        });
        let report = harness.evaluate(T0 + offset);
        if bad_code {
            let input = metric_input(&report);
            assert!(causes(&input).contains(&"rejected".into()), "{input}");
            assert!(causes(&input).contains(&"unreported".into()), "{input}");
            assert_eq!(input["rejected_rules"].as_array().unwrap().len(), 1);
            assert_eq!(harness.state()["conditions"][&swap]["active"], true);
            assert!(alert_intents(&report).iter().all(|(id, _, _)| id == other));
            assert_eq!(condition(&report, other).unwrap()["observation"], "clear");
        } else {
            assert_eq!(condition(&report, other).unwrap()["observation"], "present");
            assert_eq!(
                alert_intents(&report).len(),
                if offset == 90 { 2 } else { 0 }
            );
        }
    }
    assert!(
        harness.state()["conditions"]
            .get(other)
            .is_none_or(|c| c["active"] == false)
    );
}

#[test]
fn plain_zero_results_with_fetched_series_remain_clear() {
    let harness = metric_alerts_harness();
    write_metric_alerts(&harness, T0, |doc| {
        quiet(doc, "HostSwapExhausted");
        let rule = metric_rule(doc, "HostSwapExhausted");
        rule["last_samples"] = json!(0);
        rule["last_series_fetched"] = json!(1);
    });
    let report = harness.evaluate(T0);
    assert_eq!(condition(&report, SWAP).unwrap()["observation"], "clear");
}

/// A stale document, or a rule vmalert stopped evaluating, is unknown: an
/// open condition holds and nothing resolves, and the input says why.
#[test]
fn stale_metric_alerts_hold_the_open_condition() {
    let harness = metric_alerts_harness();
    write_metric_alerts(&harness, T0, |_| {});
    write_metric_alerts(&harness, T0 + 90, |_| {});
    harness.evaluate(T0);
    assert_eq!(alert_intents(&harness.evaluate(T0 + 90)).len(), 1);
    // The producer stops: the same document ages past max_age_seconds.
    let report = harness.evaluate(T0 + 90 + 301);
    assert!(alert_intents(&report).is_empty());
    let input = metric_input(&report);
    assert_eq!(input["status"], "not_current");
    assert!(causes(&input).contains(&"stale".to_owned()), "{input}");
    assert_eq!(condition(&report, SWAP).unwrap()["observation"], "unknown");
    // Fresh document, but vmalert last evaluated the swap rule ten minutes ago
    // and now calls it inactive: not recovery.
    for offset in [500, 700] {
        write_metric_alerts(&harness, T0 + offset, |doc| {
            quiet(doc, "HostSwapExhausted");
            metric_rule(doc, "HostSwapExhausted")["last_evaluation"] =
                json!(rfc3339(T0 + offset - 600));
        });
        let report = harness.evaluate(T0 + offset);
        assert!(alert_intents(&report).is_empty(), "{report}");
        let input = metric_input(&report);
        assert!(
            causes(&input).contains(&"indeterminate".to_owned()),
            "{input}"
        );
        assert_eq!(condition(&report, SWAP).unwrap()["observation"], "unknown");
    }
    assert_eq!(harness.state()["conditions"][SWAP]["active"], true);
}

/// When vmalert's effective policy is not the declared one, a firing alert is
/// still an observation (it triggers), but a changed definition's silence is
/// not recovery (nothing clears), and the input is not current.
#[test]
fn policy_drift_keeps_firing_present_but_never_clears() {
    let harness = metric_alerts_harness();
    let drift = |doc: &mut Value| {
        doc["declared_policy_sha256"] =
            json!("sha256:0000000000000000000000000000000000000000000000000000000000000000");
        doc["policy_matches_declared"] = json!(false);
    };
    write_metric_alerts(&harness, T0, drift);
    harness.evaluate(T0);
    write_metric_alerts(&harness, T0 + 90, drift);
    let report = harness.evaluate(T0 + 90);
    assert_eq!(alert_intents(&report).len(), 1, "{report}");
    let input = metric_input(&report);
    assert_eq!(input["status"], "not_current");
    assert!(
        causes(&input).contains(&"unrecognised".to_owned()),
        "{input}"
    );
    assert!(
        input["error"]
            .as_str()
            .unwrap()
            .contains("is not the declared")
    );
    for offset in [150, 400, 700] {
        write_metric_alerts(&harness, T0 + offset, |doc| {
            drift(doc);
            quiet(doc, "HostSwapExhausted");
        });
        let report = harness.evaluate(T0 + offset);
        assert!(alert_intents(&report).is_empty(), "{report}");
        assert_eq!(condition(&report, SWAP).unwrap()["observation"], "unknown");
    }
    assert_eq!(harness.state()["conditions"][SWAP]["active"], true);
    // Declared and effective agree again: the inactive rule now clears.
    for offset in [800, 1000] {
        write_metric_alerts(&harness, T0 + offset, |doc| quiet(doc, "HostSwapExhausted"));
        harness.evaluate(T0 + offset);
    }
    let state = harness.state();
    assert!(
        state["conditions"]
            .get(SWAP)
            .is_none_or(|c| c["active"] == false),
        "{state}"
    );
}

/// A document with no opted-in rule is `empty`; a missing file is unreadable;
/// neither claims anything about any alert.
#[test]
fn metric_alerts_without_opt_in_or_file_are_faults_not_clears() {
    let harness = metric_alerts_harness();
    write_metric_alerts(&harness, T0, |doc| {
        for rule in doc["rules"].as_array_mut().unwrap() {
            rule["labels"].as_object_mut().unwrap().remove("attention");
        }
    });
    let report = harness.evaluate(T0);
    let input = metric_input(&report);
    assert_eq!(input["status"], "not_current");
    assert_eq!(causes(&input), ["empty"], "{input}");
    assert!(condition(&report, SWAP).is_none());
    fs::remove_file(harness.path("metric-alerts.json")).unwrap();
    let report = harness.evaluate(T0 + 60);
    let input = metric_input(&report);
    assert_eq!(input["status"], "unavailable");
    assert_eq!(causes(&input), ["unreadable"], "{input}");
}

const SWAP_TESTBED: &str =
    "constellation:labelwatch:host_posture:metric-alert-firing:host-swap-exhausted.testbed";
const SWAP_CROW: &str =
    "constellation:labelwatch:host_posture:metric-alert-firing:host-swap-exhausted.crow";

/// The vector's HostSwapExhausted instance relabelled to `testbed`, plus a
/// second firing instance on `crow` and a third on `elsewhere`.
fn swap_on_three_sites(doc: &mut Value) {
    let rule = metric_rule(doc, "HostSwapExhausted");
    let instances = rule["instances"].as_array_mut().unwrap();
    let mut crow = instances[0].clone();
    let mut elsewhere = instances[0].clone();
    instances[0]["labels"]["site"] = json!("testbed");
    crow["labels"]["site"] = json!("crow");
    crow["labels"]["instance"] = json!("10.0.0.2:19100");
    crow["summary"] = json!("swap 1% free on crow (10.0.0.2:19100) for 30 min");
    elsewhere["labels"]["site"] = json!("elsewhere");
    instances.push(crow);
    instances.push(elsewhere);
    refresh_firing_sites(rule);
    rule["instance_count"] = json!(3);
}

/// With `sites`, one vmalert serving several sites yields one condition per
/// (rule, listed site): a rule firing on crow is not the rule firing on
/// testbed, each clears on its own, and an instance of an unlisted site is
/// counted but is no condition.
#[test]
fn metric_alerts_keyed_per_site() {
    let mut harness = metric_alerts_harness();
    harness.raw("sites = [\"testbed\", \"crow\"]\n");
    write_metric_alerts(&harness, T0, swap_on_three_sites);
    let report = harness.evaluate(T0);
    let ids: Vec<&str> = report["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .filter(|id| id.contains(":metric-alert-firing:"))
        .collect();
    assert_eq!(
        ids,
        [
            "constellation:labelwatch:host_posture:metric-alert-firing:host-io-pressure-high.crow",
            "constellation:labelwatch:host_posture:metric-alert-firing:host-io-pressure-high.testbed",
            "constellation:labelwatch:host_posture:metric-alert-firing:host-io-pressure-severe.crow",
            "constellation:labelwatch:host_posture:metric-alert-firing:host-io-pressure-severe.testbed",
            "constellation:labelwatch:host_posture:metric-alert-firing:host-memory-pressure-high.crow",
            "constellation:labelwatch:host_posture:metric-alert-firing:host-memory-pressure-high.testbed",
            SWAP_CROW,
            SWAP_TESTBED,
        ],
        "one condition per listed site; none for elsewhere, none unkeyed"
    );
    assert!(condition(&report, SWAP).is_none());
    let testbed = condition(&report, SWAP_TESTBED).unwrap();
    let crow = condition(&report, SWAP_CROW).unwrap();
    assert_eq!(testbed["observation"], "present", "{testbed}");
    assert_eq!(crow["observation"], "present", "{crow}");
    assert_eq!(
        condition(
            &report,
            "constellation:labelwatch:host_posture:metric-alert-firing:host-io-pressure-high.crow"
        )
        .unwrap()["observation"],
        "clear"
    );
    // Each condition carries its own site's instances only; the unlisted
    // site is counted and named once, on the first listed site.
    for (row, site, host) in [
        (testbed, "testbed", "127.0.0.1:19100"),
        (crow, "crow", "10.0.0.2:19100"),
    ] {
        let reference = &row["reference"];
        assert_eq!(reference["site"], site, "{reference}");
        assert_eq!(reference["instances_other_sites"], 1, "{reference}");
        let instances = reference["instances"].as_array().unwrap();
        assert_eq!(instances.len(), 1, "{reference}");
        assert_eq!(instances[0]["labels"]["site"], site);
        assert_eq!(instances[0]["labels"]["instance"], host);
    }
    assert!(
        testbed["note"]
            .as_str()
            .unwrap()
            .contains("1 firing on unlisted sites (elsewhere)"),
        "{testbed}"
    );
    assert!(
        !crow["note"].as_str().unwrap().contains("elsewhere"),
        "{crow}"
    );

    write_metric_alerts(&harness, T0 + 90, swap_on_three_sites);
    let report = harness.evaluate(T0 + 90);
    assert_eq!(
        alert_intents(&report),
        vec![
            (
                SWAP_CROW.to_owned(),
                "notice".to_owned(),
                "trigger".to_owned()
            ),
            (
                SWAP_TESTBED.to_owned(),
                "notice".to_owned(),
                "trigger".to_owned()
            ),
        ]
    );
    let record = report["intents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["condition_id"] == SWAP_CROW)
        .unwrap()["notification_id"]
        .as_str()
        .unwrap();
    let sent: Value = serde_json::from_slice(&harness.submitted_intent(record)).unwrap();
    let summary = sent["summary"].as_str().unwrap();
    assert!(
        summary.contains(
            "Now: HostSwapExhausted firing on crow (10.0.0.2:19100): swap 1% free on crow (10.0.0.2:19100) for 30 min."
        ),
        "{summary}"
    );
    assert!(!summary.contains("testbed"), "{summary}");

    // Only the testbed instance quiets: the rule still fires on crow.
    let quiet_testbed = |doc: &mut Value| {
        swap_on_three_sites(doc);
        let rule = metric_rule(doc, "HostSwapExhausted");
        rule["instances"]
            .as_array_mut()
            .unwrap()
            .retain(|i| i["labels"]["site"] != "testbed");
        rule["instance_count"] = json!(2);
        refresh_firing_sites(rule);
    };
    for offset in [150, 400] {
        write_metric_alerts(&harness, T0 + offset, quiet_testbed);
        let report = harness.evaluate(T0 + offset);
        assert_eq!(
            condition(&report, SWAP_TESTBED).unwrap()["observation"],
            "clear"
        );
        assert_eq!(
            condition(&report, SWAP_CROW).unwrap()["observation"],
            "present"
        );
    }
    let state = harness.state();
    assert!(
        state["conditions"]
            .get(SWAP_TESTBED)
            .is_none_or(|c| c["active"] == false),
        "{state}"
    );
    assert_eq!(state["conditions"][SWAP_CROW]["active"], true, "{state}");
}

/// `sites` entries are bounded tokens, distinct and at most eight.
#[test]
fn metric_alert_sites_are_validated_by_check_config() {
    let refused = |sites: &str, message: &str| {
        let mut harness = metric_alerts_harness();
        harness.raw(&format!("sites = {sites}\n"));
        let config = harness.config_path();
        let output = harness.command(&["check-config", "--config", config.to_str().unwrap()]);
        assert_eq!(output.status.code(), Some(2), "{sites}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(message), "{sites}: {stderr}");
    };
    refused("[\"crow\", \"crow\"]", "lists \"crow\" twice");
    refused("[\"Crow\"]", "inputs.metric_alerts.sites entry \"Crow\"");
    refused("[\"-crow\"]", "inputs.metric_alerts.sites entry \"-crow\"");
    refused("[]", "must list 1..=8 sites");
    refused(
        "[\"s1\", \"s2\", \"s3\", \"s4\", \"s5\", \"s6\", \"s7\", \"s8\", \"s9\"]",
        "must list 1..=8 sites",
    );
    refused("[\"sha256-root\"]", "looks like a digest");

    let mut harness = metric_alerts_harness();
    harness.raw("sites = [\"labelwatch\", \"crow\"]\n");
    let config = harness.config_path();
    let output = harness.command(&["check-config", "--config", config.to_str().unwrap()]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// An inactive rule whose query fetched no series is unknown, not clear, and
/// faults nothing: the metric is missing or its window has no history yet.
#[test]
fn metric_alert_with_no_data_is_unknown_not_clear() {
    let harness = metric_alerts_harness();
    write_metric_alerts(&harness, T0, |doc| {
        metric_rule(doc, "HostIoPressureHigh")["last_series_fetched"] = json!(0);
    });
    let report = harness.evaluate(T0);
    let input = metric_input(&report);
    assert_eq!(input["status"], "not_current", "{input}");
    assert_eq!(
        causes(&input),
        ["indeterminate"],
        "only the vector's erroring rule"
    );
    let c = condition(
        &report,
        "constellation:labelwatch:host_posture:metric-alert-firing:host-io-pressure-high",
    )
    .unwrap();
    assert_eq!(c["observation"], "unknown");
    assert!(
        c["note"]
            .as_str()
            .unwrap()
            .contains("query fetched no series"),
        "{c}"
    );
    // With data fetched and the rule inactive, the same condition is clear.
    write_metric_alerts(&harness, T0 + 60, |doc| {
        metric_rule(doc, "HostIoPressureHigh")["last_series_fetched"] = json!(2);
    });
    let report = harness.evaluate(T0 + 60);
    assert_eq!(
        condition(
            &report,
            "constellation:labelwatch:host_posture:metric-alert-firing:host-io-pressure-high"
        )
        .unwrap()["observation"],
        "clear"
    );
}

/// Per-site presence comes from the producer's complete firing summary, so a
/// site whose firing instance fell past the truncated detail is still present.
#[test]
fn per_site_presence_uses_the_complete_firing_summary() {
    let mut harness = Harness::new();
    let path = harness.path("metric-alerts.json");
    harness.raw(&format!(
        "[inputs.metric_alerts]\npath = \"{}\"\nsites = [\"testbed\", \"crow\"]\n",
        path.display()
    ));
    write_metric_alerts(&harness, T0, |doc| {
        let rule = metric_rule(doc, "HostSwapExhausted");
        rule["instances"] = json!([]); // detail truncated away entirely
        rule["instance_count"] = json!(40);
        rule["firing_sites"] = json!({"crow": 1, "testbed": 39});
    });
    let report = harness.evaluate(T0);
    for site in ["testbed", "crow"] {
        let c = condition(
            &report,
            &format!("constellation:labelwatch:host_posture:metric-alert-firing:host-swap-exhausted.{site}"),
        )
        .unwrap();
        assert_eq!(c["observation"], "present", "{c}");
    }
}

// ---- per-definition admission (2026-10-22 testbed drill) ----

const OBSERVATION_RULE: &str = "ServiceMetricsObservationNeedsAttention";
const REJECTED_INPUT: &str =
    "constellation:labelwatch:host_posture:evaluator-input-unavailable:metric_alerts.rejected";
const UNTARGETABLE_INPUT: &str =
    "constellation:labelwatch:host_posture:evaluator-input-unavailable:metric_alerts.untargetable";

/// The testbed drill's document: the vector's host-pressure rules keyed to
/// site `testbed` (the erroring one healthy, so only admission is at stake),
/// plus P3-like service rules, one of them with a name whose site-keyed
/// target is 51 bytes.
fn p3_with_an_overlong_rule(doc: &mut Value, swap_firing: bool) {
    metric_rule(doc, "HostIoPressureSevere")["health"] = json!("ok");
    metric_rule(doc, "HostIoPressureSevere")["last_error"] = json!("");
    let template = metric_rule(doc, "HostSwapExhausted").clone();
    {
        let swap = metric_rule(doc, "HostSwapExhausted");
        swap["instances"][0]["labels"]["site"] = json!("testbed");
        refresh_firing_sites(swap);
    }
    if !swap_firing {
        quiet(doc, "HostSwapExhausted");
    }
    for (name, firing) in [
        (OBSERVATION_RULE, true),
        ("ServiceLastSuccessNeedsAttention", false),
    ] {
        let mut rule = template.clone();
        rule["name"] = json!(name);
        rule["file"] = json!("service.rules.yml");
        rule["group"] = json!("service");
        rule["labels"] = json!({"area": "service", "attention": "true", "runbook": "service-obligations", "severity": "warn"});
        rule["instances"][0]["labels"]["site"] = json!("testbed");
        rule["instances"][0]["labels"]["alertname"] = json!(name);
        rule["instances"][0]["summary"] = json!(format!("{name} on testbed"));
        if !firing {
            rule["state"] = json!("inactive");
            rule["instances"] = json!([]);
            rule["instance_count"] = json!(0);
        }
        refresh_firing_sites(&mut rule);
        doc["rules"].as_array_mut().unwrap().push(rule);
    }
}

/// One opted-in definition whose derived target overflows the 48-byte bound
/// is rejected alone: it is named in the report as
/// `metric_alerts.rule_rejected:<name>` and raises the input's `rejected`
/// class (a notice after 300 s that names it), while the input stays `ok`
/// and every other definition triggers and resolves as usual. The pass
/// exits 3.
#[test]
fn an_overlong_metric_alert_is_rejected_alone() {
    let mut harness = metric_alerts_harness();
    harness.raw("sites = [\"testbed\"]\n");
    let swap =
        "constellation:labelwatch:host_posture:metric-alert-firing:host-swap-exhausted.testbed";
    write_metric_alerts(&harness, T0, |doc| p3_with_an_overlong_rule(doc, true));
    let output = harness.evaluate_at(T0, &[]);
    assert_eq!(
        output.status.code(),
        Some(3),
        "a rejected definition is an input problem"
    );
    let report = harness.report();
    let input = metric_input(&report);
    assert_eq!(input["status"], "ok", "{input}");
    assert_eq!(causes(&input), ["rejected"], "{input}");
    let rejected = input["rejected_rules"].as_array().unwrap();
    assert_eq!(rejected.len(), 1, "{input}");
    assert_eq!(
        rejected[0]["fault"],
        "metric_alerts.rule_rejected:ServiceMetricsObservationNeedsAttention"
    );
    assert_eq!(
        rejected[0]["target"],
        "service-metrics-observation-needs-attention.testbed"
    );
    assert_eq!(rejected[0]["site"], "testbed");
    assert!(
        rejected[0]["reason"]
            .as_str()
            .unwrap()
            .contains("is 51 bytes"),
        "{input}"
    );
    // The rejected definition is no condition; every other one is.
    let ids: Vec<&str> = report["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .filter(|id| id.contains(":metric-alert-firing:"))
        .collect();
    assert_eq!(
        ids,
        [
            "constellation:labelwatch:host_posture:metric-alert-firing:host-io-pressure-high.testbed",
            "constellation:labelwatch:host_posture:metric-alert-firing:host-io-pressure-severe.testbed",
            "constellation:labelwatch:host_posture:metric-alert-firing:host-memory-pressure-high.testbed",
            swap,
            "constellation:labelwatch:host_posture:metric-alert-firing:service-last-success-needs-attention.testbed",
        ]
    );
    assert_eq!(condition(&report, swap).unwrap()["observation"], "present");
    assert_eq!(
        condition(
            &report,
            "constellation:labelwatch:host_posture:metric-alert-firing:host-io-pressure-high.testbed"
        )
        .unwrap()["observation"],
        "clear"
    );
    let rejected_condition = condition(&report, REJECTED_INPUT).unwrap();
    assert_eq!(rejected_condition["observation"], "present");
    assert!(
        rejected_condition["note"].as_str().unwrap().starts_with(
            "metric_alerts.rule_rejected:ServiceMetricsObservationNeedsAttention: derived target"
        ),
        "{rejected_condition}"
    );
    // Other fault classes are clear: the input is ok for every other rule.
    assert_eq!(
        condition(&report, UNTARGETABLE_INPUT).unwrap()["observation"],
        "clear"
    );

    // The host-pressure rule triggers on its own bound.
    write_metric_alerts(&harness, T0 + 90, |doc| p3_with_an_overlong_rule(doc, true));
    let report = harness.evaluate(T0 + 90);
    assert_eq!(
        alert_intents(&report),
        vec![(swap.to_owned(), "notice".to_owned(), "trigger".to_owned())]
    );
    // The rejection is noticed after 300 s, and the notice names the rule.
    write_metric_alerts(&harness, T0 + 360, |doc| {
        p3_with_an_overlong_rule(doc, true)
    });
    let report = harness.evaluate(T0 + 360);
    assert_eq!(
        intents(&report),
        vec![(
            REJECTED_INPUT.to_owned(),
            "notice".to_owned(),
            "trigger".to_owned()
        )]
    );
    let record = report["intents"][0]["notification_id"].as_str().unwrap();
    let sent: Value = serde_json::from_slice(&harness.submitted_intent(record)).unwrap();
    let summary = sent["summary"].as_str().unwrap();
    assert!(
        summary.contains("Now: rejected rules: ServiceMetricsObservationNeedsAttention (testbed); see report.json metric_alerts.rejected_rules."),
        "{summary}"
    );
    // The host-pressure rule resolves on its own recovery while the
    // rejection stays open.
    for offset in [420, 560] {
        write_metric_alerts(&harness, T0 + offset, |doc| {
            p3_with_an_overlong_rule(doc, false);
        });
        harness.evaluate(T0 + offset);
    }
    let state = harness.state();
    assert!(
        state["conditions"]
            .get(swap)
            .is_none_or(|c| c["active"] == false),
        "{state}"
    );
    assert_eq!(state["conditions"][REJECTED_INPUT]["active"], true);

    // The rule file is fixed (the definition is gone): the rejection
    // resolves after its confirmation window and passes exit 0.
    let fixed = |doc: &mut Value| {
        p3_with_an_overlong_rule(doc, false);
        doc["rules"]
            .as_array_mut()
            .unwrap()
            .retain(|r| r["name"] != OBSERVATION_RULE);
    };
    write_metric_alerts(&harness, T0 + 600, fixed);
    let report = harness.evaluate(T0 + 600);
    assert!(causes(&metric_input(&report)).is_empty());
    assert_eq!(
        condition(&report, REJECTED_INPUT).unwrap()["observation"],
        "clear"
    );
    write_metric_alerts(&harness, T0 + 730, fixed);
    let output = harness.evaluate_at(T0 + 730, &[]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        intents(&harness.report()),
        vec![(
            REJECTED_INPUT.to_owned(),
            "notice".to_owned(),
            "resolve".to_owned()
        )]
    );
}

/// A rejected definition while vmalert's policy drifted from the declared one:
/// the existing drift semantics hold (a firing alert still triggers, nothing
/// clears), and the rejection is reported beside the drift.
#[test]
fn a_rejected_definition_under_policy_drift_keeps_drift_semantics() {
    let mut harness = metric_alerts_harness();
    harness.raw("sites = [\"testbed\"]\n");
    let drifted = |doc: &mut Value, firing: bool| {
        p3_with_an_overlong_rule(doc, firing);
        doc["declared_policy_sha256"] =
            json!("sha256:0000000000000000000000000000000000000000000000000000000000000000");
        doc["policy_matches_declared"] = json!(false);
    };
    let swap =
        "constellation:labelwatch:host_posture:metric-alert-firing:host-swap-exhausted.testbed";
    write_metric_alerts(&harness, T0, |doc| drifted(doc, true));
    harness.evaluate(T0);
    write_metric_alerts(&harness, T0 + 90, |doc| drifted(doc, true));
    let report = harness.evaluate(T0 + 90);
    assert_eq!(alert_intents(&report).len(), 1, "firing still triggers");
    let input = metric_input(&report);
    assert_eq!(input["status"], "not_current");
    assert_eq!(causes(&input), ["unrecognised", "rejected"], "{input}");
    for offset in [150, 400] {
        write_metric_alerts(&harness, T0 + offset, |doc| drifted(doc, false));
        let report = harness.evaluate(T0 + offset);
        assert_eq!(condition(&report, swap).unwrap()["observation"], "unknown");
    }
    assert_eq!(harness.state()["conditions"][swap]["active"], true);
}

// ---- remediation-journal-critical (page before the journal ceiling) ----

const JOURNAL_PAGE: &str =
    "constellation:labelwatch:service:remediation-journal-critical:remediation-consumer";
const CONSUMER_NOTICE: &str =
    "constellation:labelwatch:service:service-not-doing-its-job:remediation-consumer";

/// The estate document as the collector writes it for the remediation
/// consumer with `sealed` sealed journal segments (its `--status` concerns:
/// headroom ABSENT at 12, critical ABSENT at 15). `None` leaves the row out.
fn write_journal_estate(
    harness: &Harness,
    at: i64,
    sealed: Option<u64>,
    critical_state: Option<&str>,
) {
    let mut services =
        vec![json!({"name": "factsapi", "verdict": "OK", "reason": "running", "concerns": []})];
    if let Some(sealed) = sealed {
        let concern = |id: &str, bound: u64| {
            let (state, reason) = if sealed < bound {
                (
                    "PRESENT",
                    format!("{sealed} sealed segments present, below {bound}"),
                )
            } else {
                (
                    "ABSENT",
                    format!(
                        "{sealed} sealed segments present (threshold {bound}, refusal at 16); operator custody due"
                    ),
                )
            };
            json!({"id": id, "required": true, "state": state, "reason": reason,
                   "observed_at": rfc3339(at - 5), "valid_for_seconds": 120})
        };
        let headroom = concern("remediation.journal.generations-headroom", 12);
        let mut critical = concern("remediation.journal.generations-critical", 15);
        if let Some(state) = critical_state {
            critical["state"] = json!(state);
        }
        let failing: Vec<String> = [&headroom, &critical]
            .iter()
            .filter(|c| c["state"] != "PRESENT")
            .map(|c| {
                format!(
                    "{} {}",
                    c["id"].as_str().unwrap().split_once('.').unwrap().1,
                    c["state"].as_str().unwrap()
                )
            })
            .collect();
        let (verdict, reason) = if failing.is_empty() {
            (
                "OK".to_owned(),
                "running, 5 required concerns present".to_owned(),
            )
        } else {
            ("DEGRADED".to_owned(), failing.join("; "))
        };
        services.push(
            json!({"name": "remediation-consumer", "verdict": verdict, "reason": reason,
            "since": rfc3339(T0), "concerns": [headroom, critical]}),
        );
    }
    let doc = json!({"schema": "constellation.estate/v1", "site": "labelwatch",
        "generated_at": rfc3339(at), "services": services});
    fs::write(
        harness.path("estate.json"),
        serde_json::to_vec(&doc).unwrap(),
    )
    .unwrap();
}

/// At 12 sealed segments only the existing notice goes out (the service is
/// DEGRADED); the journal page stays clear.
#[test]
fn journal_headroom_at_12_is_only_the_service_notice() {
    let harness = estate_harness();
    for offset in (0..=720).step_by(60) {
        write_journal_estate(&harness, T0 + offset, Some(12), None);
        harness.evaluate(T0 + offset);
    }
    let report = harness.report();
    assert_eq!(
        condition(&report, JOURNAL_PAGE).unwrap()["observation"],
        "clear"
    );
    let calls = harness.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert!(
        calls[0].starts_with(
            "submit operations labelwatch-service-not-doing-its-job-remediation-consumer-trigger-"
        ),
        "{calls:?}"
    );
}

/// At 15 sealed segments the page rule triggers after 600 s: a v2 page with
/// `response_class: page` naming the segment count, and its notice copy; a
/// missing row or a STALE or UNKNOWN concern holds it; recovery (custody
/// back below 15) resolves it after the 120 s confirmation.
#[test]
fn journal_critical_at_15_pages_holds_on_unknown_and_resolves() {
    let harness = estate_harness();
    for offset in [0, 300, 600] {
        write_journal_estate(&harness, T0 + offset, Some(15), None);
        let report = harness.evaluate(T0 + offset);
        assert!(
            intents(&report).iter().all(|(id, _, _)| id != JOURNAL_PAGE),
            "below the 600 s bound at +{offset}"
        );
    }
    write_journal_estate(&harness, T0 + 660, Some(15), None);
    let report = harness.evaluate(T0 + 660);
    let page: Vec<_> = intents(&report)
        .into_iter()
        .filter(|(id, _, _)| id == JOURNAL_PAGE)
        .collect();
    assert_eq!(
        page,
        vec![
            (
                JOURNAL_PAGE.to_owned(),
                "notice".to_owned(),
                "trigger".to_owned()
            ),
            (
                JOURNAL_PAGE.to_owned(),
                "page".to_owned(),
                "trigger".to_owned()
            ),
        ]
    );
    // The service notice fires on its own rule as before.
    assert!(
        intents(&report)
            .iter()
            .any(|(id, role, action)| id == CONSUMER_NOTICE
                && role == "notice"
                && action == "trigger")
    );
    let record = report["intents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["condition_id"] == JOURNAL_PAGE && i["route_role"] == "page")
        .unwrap()["notification_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let sent: Value = serde_json::from_slice(&harness.submitted_intent(&record)).unwrap();
    assert_eq!(sent["schema"], "nq.notification_delivery_intent.v2");
    assert_eq!(sent["response_class"], "page");
    assert_eq!(sent["severity"], "critical");
    assert_eq!(
        sent["condition"],
        json!({"site": "labelwatch", "component": "service", "rule": "remediation-journal-critical", "target_class": "remediation-consumer"})
    );
    assert_eq!(
        sent["inspection_reference"],
        "constellation-monitor:docs/ATTENTION.md#remediation-journal-critical"
    );
    let summary = sent["summary"].as_str().unwrap();
    assert!(
        summary.contains("Now: remediation-consumer: 15 sealed segments present (threshold 15, refusal at 16); operator custody due."),
        "{summary}"
    );
    assert_eq!(sent["details"]["input"]["sealed_segments"], 15);

    // Unknown holds: a missing row, a STALE and an UNKNOWN concern, and a
    // stale document neither resolve nor re-trigger, for longer than the
    // confirmation window.
    let held: [(i64, Option<u64>, Option<&str>); 4] = [
        (720, None, None),
        (780, Some(12), Some("STALE")),
        (900, Some(12), Some("UNKNOWN")),
        (960, None, None),
    ];
    for (offset, sealed, state) in held {
        write_journal_estate(&harness, T0 + offset, sealed, state);
        let report = harness.evaluate(T0 + offset);
        let row = condition(&report, JOURNAL_PAGE).unwrap();
        assert_eq!(row["observation"], "unknown", "+{offset}: {row}");
        assert!(
            intents(&report).iter().all(|(id, _, _)| id != JOURNAL_PAGE),
            "+{offset}"
        );
    }
    write_journal_estate(&harness, T0 + 1000, Some(12), None);
    let report = harness.evaluate(T0 + 1000 + 601);
    assert_eq!(
        condition(&report, JOURNAL_PAGE).unwrap()["observation"],
        "unknown",
        "a stale estate document is unknown"
    );
    assert_eq!(harness.state()["conditions"][JOURNAL_PAGE]["active"], true);

    // Custody: back below 15. Clear for 120 s resolves both routes.
    let start = T0 + 1700;
    for offset in [0, 60] {
        write_journal_estate(&harness, start + offset, Some(12), None);
        let report = harness.evaluate(start + offset);
        assert_eq!(
            condition(&report, JOURNAL_PAGE).unwrap()["observation"],
            "clear"
        );
        assert!(intents(&report).iter().all(|(id, _, _)| id != JOURNAL_PAGE));
    }
    write_journal_estate(&harness, start + 120, Some(12), None);
    let report = harness.evaluate(start + 120);
    let resolved: Vec<_> = intents(&report)
        .into_iter()
        .filter(|(id, _, _)| id == JOURNAL_PAGE)
        .collect();
    assert_eq!(
        resolved,
        vec![
            (
                JOURNAL_PAGE.to_owned(),
                "notice".to_owned(),
                "resolve".to_owned()
            ),
            (
                JOURNAL_PAGE.to_owned(),
                "page".to_owned(),
                "resolve".to_owned()
            ),
        ]
    );
}

/// Without a remediation-consumer row from the start, the rule is unknown
/// and never triggers.
#[test]
fn journal_critical_without_a_consumer_row_is_unknown() {
    let harness = estate_harness();
    for offset in (0..=900).step_by(300) {
        write_journal_estate(&harness, T0 + offset, None, None);
        let report = harness.evaluate(T0 + offset);
        let row = condition(&report, JOURNAL_PAGE).unwrap();
        assert_eq!(row["observation"], "unknown", "{row}");
        assert!(
            row["note"]
                .as_str()
                .unwrap()
                .contains("has no remediation-consumer row"),
            "{row}"
        );
    }
    assert!(harness.calls().is_empty());
}

/// Adds an opted-in, firing copy of the swap rule under `name` (site testbed).
fn add_alert(doc: &mut Value, name: &str) {
    let mut rule = metric_rule(doc, "HostSwapExhausted").clone();
    rule["name"] = json!(name);
    rule["instances"][0]["labels"]["site"] = json!("testbed");
    rule["instances"][0]["labels"]["alertname"] = json!(name);
    refresh_firing_sites(&mut rule);
    doc["rules"].as_array_mut().unwrap().push(rule);
}

const SECOND_LONG: &str = "ServiceObservationCoverageNeedsAttentionNow";

/// A second rejection joins the open `rejected` condition (no new notice),
/// the notice text names every rejected rule before the byte detail so
/// nothing is cut, fixing the first while the second remains resolves
/// nothing, and the digest restates a rejected-only input.
#[test]
fn rejections_join_one_condition_and_name_every_rule() {
    let mut harness = metric_alerts_harness();
    harness.raw("sites = [\"testbed\"]\n[digest]\nat_utc = \"12:10\"\n");
    let one = |doc: &mut Value| p3_with_an_overlong_rule(doc, false);
    let two = |doc: &mut Value| {
        add_alert(doc, SECOND_LONG);
        p3_with_an_overlong_rule(doc, false);
    };
    write_metric_alerts(&harness, T0, one);
    harness.evaluate(T0);
    write_metric_alerts(&harness, T0 + 360, one);
    assert_eq!(
        intents(&harness.evaluate(T0 + 360)),
        vec![(
            REJECTED_INPUT.to_owned(),
            "notice".to_owned(),
            "trigger".to_owned()
        )]
    );
    // The second rejection joins: no new intent, both listed.
    write_metric_alerts(&harness, T0 + 420, two);
    let report = harness.evaluate(T0 + 420);
    assert!(intents(&report).is_empty(), "{report}");
    let input = metric_input(&report);
    assert_eq!(input["status"], "ok");
    assert_eq!(input["rejected_rules"].as_array().unwrap().len(), 2);
    let row = condition(&report, REJECTED_INPUT).unwrap();
    assert_eq!(row["observation"], "present");
    assert!(row["note"].as_str().unwrap().contains(SECOND_LONG), "{row}");
    assert_eq!(
        row["reference"]["reason"],
        format!(
            "rejected rules: {SECOND_LONG} (testbed), ServiceMetricsObservationNeedsAttention (testbed); see report.json metric_alerts.rejected_rules"
        )
    );
    // The daily digest (due at 12:10) restates the rejected-only input.
    write_metric_alerts(&harness, T0 + 600, two);
    let report = harness.evaluate(T0 + 600);
    let digest = report["digest"]["summary"].as_str().unwrap();
    assert!(
        digest.contains(&format!("Rejected definitions: metric_alerts (rejected rules: {SECOND_LONG} (testbed), ServiceMetricsObservationNeedsAttention (testbed)")),
        "{digest}"
    );
    // The first is fixed, the second remains: nothing resolves.
    let second_only = |doc: &mut Value| {
        two(doc);
        doc["rules"]
            .as_array_mut()
            .unwrap()
            .retain(|r| r["name"] != OBSERVATION_RULE);
    };
    for offset in [660, 900] {
        write_metric_alerts(&harness, T0 + offset, second_only);
        let report = harness.evaluate(T0 + offset);
        assert!(intents(&report).is_empty(), "+{offset}: {report}");
        assert_eq!(
            condition(&report, REJECTED_INPUT).unwrap()["observation"],
            "present"
        );
    }
    assert_eq!(
        harness.state()["conditions"][REJECTED_INPUT]["active"],
        true
    );
}

/// A notice for two rejections keeps both names and the incident reference
/// inside the v1 summary bound.
#[test]
fn a_two_rejection_notice_keeps_both_names_and_the_incident() {
    let mut harness = metric_alerts_harness();
    harness.raw("sites = [\"testbed\"]\n");
    let two = |doc: &mut Value| {
        add_alert(doc, SECOND_LONG);
        p3_with_an_overlong_rule(doc, false);
    };
    write_metric_alerts(&harness, T0, two);
    harness.evaluate(T0);
    write_metric_alerts(&harness, T0 + 360, two);
    let report = harness.evaluate(T0 + 360);
    let record = report["intents"][0]["notification_id"].as_str().unwrap();
    let sent: Value = serde_json::from_slice(&harness.submitted_intent(record)).unwrap();
    let summary = sent["summary"].as_str().unwrap();
    assert!(summary.contains(OBSERVATION_RULE), "{summary}");
    assert!(summary.contains(SECOND_LONG), "{summary}");
    assert!(
        summary.contains(&format!("{REJECTED_INPUT}@{}", rfc3339(T0))),
        "{summary}"
    );
}

/// A rule whose token another rule now shares is refused with it: neither
/// takes over the target, and the open condition of the rule that was active
/// is held (`unreported`), never resolved.
#[test]
fn a_shared_target_refuses_both_and_holds_the_open_condition() {
    let mut harness = metric_alerts_harness();
    harness.raw("sites = [\"testbed\"]\n");
    let swap =
        "constellation:labelwatch:host_posture:metric-alert-firing:host-swap-exhausted.testbed";
    let base = |doc: &mut Value| p3_with_an_overlong_rule(doc, true);
    write_metric_alerts(&harness, T0, base);
    harness.evaluate(T0);
    write_metric_alerts(&harness, T0 + 90, base);
    assert_eq!(alert_intents(&harness.evaluate(T0 + 90)).len(), 1);
    // A new inactive rule whose token equals the active one's, sorted first.
    let shared = |doc: &mut Value| {
        p3_with_an_overlong_rule(doc, true);
        add_alert(doc, "host-swap-exhausted");
        let rule = metric_rule(doc, "host-swap-exhausted");
        rule["state"] = json!("inactive");
        rule["instances"] = json!([]);
        refresh_firing_sites(rule);
        doc["rules"].as_array_mut().unwrap().rotate_right(1);
    };
    for offset in [150, 400, 700] {
        write_metric_alerts(&harness, T0 + offset, shared);
        let report = harness.evaluate(T0 + offset);
        assert!(alert_intents(&report).is_empty(), "+{offset}: {report}");
        let row = condition(&report, swap).unwrap();
        assert_eq!(row["observation"], "unknown", "{row}");
        let input = metric_input(&report);
        assert_eq!(input["status"], "not_current", "{input}");
        assert!(causes(&input).contains(&"unreported".to_owned()), "{input}");
        let rules: Vec<&str> = input["rejected_rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["rule"].as_str().unwrap())
            .filter(|r| r.contains("wap"))
            .collect();
        assert_eq!(
            rules,
            ["host-swap-exhausted", "HostSwapExhausted"],
            "{input}"
        );
    }
    assert_eq!(harness.state()["conditions"][swap]["active"], true);
}

/// One site's overflow refuses that site only; the rule is evaluated on the
/// sites whose target fits.
#[test]
fn an_overflowing_site_keeps_the_rule_on_other_sites() {
    let mut harness = metric_alerts_harness();
    harness.raw("sites = [\"testbed\", \"labelwatch\"]\n");
    write_metric_alerts(&harness, T0, |doc| {
        add_alert(doc, "HostMetricsAcquisitionNeedsAttention");
    });
    let report = harness.evaluate(T0);
    assert_eq!(
        condition(
            &report,
            "constellation:labelwatch:host_posture:metric-alert-firing:host-metrics-acquisition-needs-attention.testbed"
        )
        .unwrap()["observation"],
        "present"
    );
    let input = metric_input(&report);
    let rejected = input["rejected_rules"].as_array().unwrap();
    assert_eq!(rejected.len(), 1, "{input}");
    assert_eq!(rejected[0]["site"], "labelwatch");
    assert!(
        rejected[0]["reason"]
            .as_str()
            .unwrap()
            .contains("is 51 bytes")
    );
}

/// Real evaluator notices, including its daily digest and resolves, are looked
/// up by the incident authority after each sync (not by a second id allocator).
#[test]
fn repeated_notices_resolve_to_the_incident_store() {
    use std::io::Write;
    use std::process::Stdio;

    let fixture: Value = serde_json::from_str(include_str!(
        "../../../incidents/fixtures/repeated-notice.json"
    ))
    .unwrap();
    let mut harness = Harness::new();
    harness
        .host_posture("root")
        .raw("[digest]\nat_utc = \"00:00\"\n");
    let mut passes = Vec::new();
    let mut reference = String::new();
    for step in fixture["steps"].as_array().unwrap() {
        let at = fixture["start"].as_i64().unwrap() + step["offset"].as_i64().unwrap();
        let state = if step["state"] == "unknown" {
            ProjectedStateV1::Unknown
        } else {
            ProjectedStateV1::Healthy
        };
        set(&harness, "root", state, at);
        let report = harness.evaluate(at);
        let expected_intents = if matches!(step["offset"].as_i64(), Some(660 | 840 | 2460 | 86580))
        {
            2
        } else {
            0
        };
        assert_eq!(
            report["intents"].as_array().unwrap().len(),
            expected_intents
        );
        let mut summaries = Vec::new();
        for record in report["intents"].as_array().unwrap() {
            let sent: Value = serde_json::from_slice(
                &harness.submitted_intent(record["notification_id"].as_str().unwrap()),
            )
            .unwrap();
            let summary = sent["summary"].as_str().unwrap().to_owned();
            if record["action"] == "trigger" {
                reference = summary.split_whitespace().nth(1).unwrap().to_owned();
            }
            assert!(summary.contains(&reference), "{summary}");
            assert!(
                !summary.contains("inc-"),
                "attention must not allocate an id"
            );
            summaries.push(summary);
        }
        if step["offset"] == 86400 {
            let summary = report["digest"]["summary"].as_str().unwrap();
            assert!(summary.contains(&reference), "{summary}");
            summaries.push(summary.to_owned());
        }
        passes.push(json!({"at": at, "report": report, "reference": reference,
                          "expected": step["incident"], "summaries": summaries}));
    }
    let mut child = Command::new("python3")
        .args([
            "-c",
            r#"
import importlib.util, json, sys, tempfile
spec = importlib.util.spec_from_file_location('inc', sys.argv[1])
inc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inc)
with tempfile.TemporaryDirectory() as directory:
    store = inc.SqliteStore(directory + '/incidents.sqlite')
    for p in json.load(sys.stdin):
        inc.sync(store, p['report'], {}, None, {}, p['at'])
        if p['reference']:
            row = inc.find(store, p['reference'])
            assert row and row['id'] == p['expected'], (p, row)
            assert all(p['reference'] in text for text in p['summaries'])
"#,
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../incidents/constellation-incidents.py"
            ),
        ])
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&passes).unwrap())
        .unwrap();
    assert!(child.wait().unwrap().success());
}

#[test]
fn preexisting_fault_stays_open_while_other_identities_reconfigure() {
    const FAULT: &str = "constellation:labelwatch:host_posture:evaluator-input-unavailable:metric_alerts.indeterminate";
    for missing_evaluation in [false, true] {
        let harness = metric_alerts_harness();
        for offset in [0, 900, 960, 1020, 1080, 1140, 1200, 1260] {
            write_metric_alerts(&harness, T0 + offset, |doc| {
                value_code_rule(doc, "firing", "2")
            });
            harness.evaluate(T0 + offset);
        }
        assert_eq!(harness.state()["conditions"][FAULT]["active"], true);
        let calls = harness.calls();
        let at = T0 + 1320;
        write_reconfiguration(&harness, at);
        for offset in (0..=900).step_by(60) {
            write_metric_alerts(&harness, at + offset, |doc| {
                value_code_rule(doc, "firing", "2");
                if missing_evaluation {
                    doc["rules"][0]["last_evaluation"] = Value::Null;
                }
                let mut new = doc["rules"][0].clone();
                new["name"] = json!("NewProbe");
                doc["rules"].as_array_mut().unwrap().push(new);
            });
            let report = harness.evaluate(at + offset);
            assert_eq!(report["exit_code"], 3);
            assert_eq!(condition(&report, FAULT).unwrap()["observation"], "present");
            assert_eq!(harness.state()["conditions"][FAULT]["active"], true);
            assert!(
                !intents(&report)
                    .iter()
                    .any(|(_, _, action)| action == "resolve")
            );
            if offset < 900 {
                let warming = metric_input(&report)["identity"]["warming_rules"].clone();
                let warming = warming.as_array().unwrap();
                assert_eq!(warming.len(), 1, "{warming:?}");
                assert_eq!(warming[0]["rule"], "NewProbe");
            }
        }
        assert_eq!(harness.calls(), calls, "no resolve or retrigger");
    }
}

#[test]
fn release_upgrade_with_open_code_two_fault_never_rearms_it() {
    const FAULT: &str = "constellation:labelwatch:host_posture:evaluator-input-unavailable:metric_alerts.indeterminate";
    for unset_updated_at in [false, true] {
        let harness = metric_alerts_harness();
        for offset in [0, 900, 960, 1020, 1080, 1140, 1200, 1260] {
            write_metric_alerts(&harness, T0 + offset, |doc| {
                value_code_rule(doc, "firing", "2");
                doc["rules"][0]["name"] = json!("ProbeDown");
            });
            harness.evaluate(T0 + offset);
        }
        let mut state = harness.state();
        assert_eq!(state["conditions"][FAULT]["active"], true);
        assert_eq!(state["conditions"].as_object().unwrap().len(), 1);
        // N8: the release persists only the aggregate input incident, with
        // no firing condition for this probe and no lifecycle sidecar.
        fs::remove_file(harness.path("state/state-attention-lifecycle.json")).unwrap();
        if unset_updated_at {
            state["updated_at"] = json!(0);
            fs::write(
                harness.path("state/state.json"),
                serde_json::to_vec(&state).unwrap(),
            )
            .unwrap();
        }
        let calls = harness.calls();
        let at = T0 + 1320;
        write_reconfiguration(&harness, at);
        for offset in [0, 60, 899, 900, 1200] {
            write_metric_alerts(&harness, at + offset, |doc| {
                value_code_rule(doc, "firing", "2");
                doc["rules"][0]["name"] = json!("ProbeDown");
            });
            let report = harness.evaluate(at + offset);
            assert_eq!(report["exit_code"], 3);
            assert_eq!(causes(&metric_input(&report)), ["indeterminate"]);
            assert_eq!(condition(&report, FAULT).unwrap()["observation"], "present");
            assert_eq!(harness.state()["conditions"][FAULT]["active"], true);
            assert!(intents(&report).is_empty());
        }
        assert_eq!(harness.calls(), calls, "no resolve or retrigger");
        let lifecycle: Value = serde_json::from_slice(
            &fs::read(harness.path("state/state-attention-lifecycle.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(lifecycle["identities"].as_object().unwrap().len(), 1);
        for identity in lifecycle["identities"].as_object().unwrap().values() {
            assert_eq!(identity["faulting"], true);
            assert_eq!(identity["grace_at"], Value::Null);
        }
    }
}

#[test]
fn release_upgrade_seeds_every_first_pass_identity_without_grace() {
    let harness = metric_alerts_harness();
    write_metric_alerts(&harness, T0, |doc| value_code_rule(doc, "inactive", "1"));
    harness.evaluate(T0);
    fs::remove_file(harness.path("state/state-attention-lifecycle.json")).unwrap();
    let at = T0 + 3600;
    write_reconfiguration(&harness, at);
    write_metric_alerts(&harness, at, |doc| {
        value_code_rule(doc, "firing", "3");
        doc["rules"][0]["name"] = json!("NewProbe");
    });
    let report = harness.evaluate(at);
    assert_eq!(report["exit_code"], 3);
    assert_eq!(causes(&metric_input(&report)), ["indeterminate"]);
    // After that first pass, genuinely new identities can receive grace.
    write_metric_alerts(&harness, at + 60, |doc| {
        value_code_rule(doc, "firing", "3");
        doc["rules"][0]["name"] = json!("LaterProbe");
    });
    assert_eq!(harness.evaluate(at + 60)["exit_code"], 0);
}

#[test]
fn warming_never_resolves_an_open_input_fault() {
    const FAULT: &str = "constellation:labelwatch:host_posture:evaluator-input-unavailable:metric_alerts.indeterminate";
    for mode in ["value", "startup", "reconfiguration"] {
        let mut harness = metric_alerts_harness();
        harness.raw("warmup_grace = 0\n");
        for offset in (0..=420).step_by(60) {
            write_metric_alerts(&harness, T0 + offset, |doc| {
                value_code_rule(doc, "firing", "2")
            });
            harness.evaluate(T0 + offset);
        }
        assert_eq!(harness.state()["conditions"][FAULT]["active"], true);
        // Recovery of this identity without recovery of the aggregate input:
        // another rule remains warming. A later apply can then rearm it.
        harness.extra_config = harness
            .extra_config
            .replace("warmup_grace = 0", "warmup_grace = 900");
        if mode == "startup" {
            let path = harness.path("state/state-metric-alerts.json");
            let mut state: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            state["history"]["first_seen"] = json!(T0 + 480);
            fs::write(path, serde_json::to_vec(&state).unwrap()).unwrap();
        }
        if mode == "reconfiguration" {
            write_reconfiguration(&harness, T0 + 480);
        }
        for offset in [480, 540, 600, 660, 720, 780, 840] {
            write_metric_alerts(&harness, T0 + offset, |doc| {
                value_code_rule(doc, "firing", if mode == "startup" { "3" } else { "5" });
                if mode == "reconfiguration" {
                    let mut new = doc["rules"][0].clone();
                    new["name"] = json!("NewProbe");
                    new["last_evaluation"] = Value::Null;
                    doc["rules"].as_array_mut().unwrap().push(new);
                }
            });
            let report = harness.evaluate(T0 + offset);
            assert_eq!(report["exit_code"], 0);
            assert_eq!(condition(&report, FAULT).unwrap()["observation"], "unknown");
            assert_eq!(harness.state()["conditions"][FAULT]["active"], true);
            assert!(
                !intents(&report)
                    .iter()
                    .any(|(_, _, action)| action == "resolve")
            );
        }
    }
}

#[test]
fn repeated_markers_cannot_extend_grace_without_recovery() {
    let mut harness = metric_alerts_harness();
    harness.raw("warming_bound = 2000\n");
    write_metric_alerts(&harness, T0, |doc| value_code_rule(doc, "inactive", "1"));
    harness.evaluate(T0);
    let at = T0 + 3600;
    for offset in [0, 600, 899, 900] {
        write_reconfiguration(&harness, at + offset);
        write_metric_alerts(&harness, at + offset, |doc| {
            value_code_rule(doc, "firing", "3")
        });
        let report = harness.evaluate(at + offset);
        assert_eq!(report["exit_code"], if offset < 900 { 0 } else { 3 });
    }
    // A qualified recovery allows a new grace inside the rate-limit window.
    write_metric_alerts(&harness, at + 901, |doc| {
        value_code_rule(doc, "inactive", "1")
    });
    harness.evaluate(at + 901);
    write_reconfiguration(&harness, at + 902);
    write_metric_alerts(&harness, at + 902, |doc| {
        value_code_rule(doc, "firing", "3")
    });
    assert_eq!(harness.evaluate(at + 902)["exit_code"], 0);
}

#[test]
fn missing_and_unreadable_observation_stores_warm_only_at_startup() {
    for unreadable in [false, true] {
        let mut harness = Harness::new();
        let store = harness.path("nightshift.db");
        if unreadable {
            fs::write(&store, b"not a sqlite database").unwrap();
        }
        harness.raw(&format!(
            "[inputs.nightshift]\nlabel = \"observation\"\nstore_path = {store:?}\n"
        ));
        for offset in [0, 899, 900] {
            let report = harness.evaluate(T0 + offset);
            let input = &report["inputs"][0];
            assert_eq!(report["exit_code"], if offset < 900 { 0 } else { 3 });
            assert_eq!(
                causes(input),
                [if offset < 900 {
                    "warming"
                } else {
                    "unreadable"
                }]
            );
        }
        write_reconfiguration(&harness, T0 + 901);
        assert_eq!(harness.evaluate(T0 + 901)["exit_code"], 3);
    }
}

#[test]
fn new_metric_sidecar_loads_with_the_release_struct() {
    // Exact f60ed56 field set and deny_unknown_fields behavior, including history.
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ReleaseMetricAlertsState {
        schema: String,
        site: String,
        #[serde(default)]
        updated_at: i64,
        #[serde(deserialize_with = "Option::deserialize")]
        history: Option<ReleaseMetricAlertsHistory>,
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ReleaseMetricAlertsHistory {
        first_seen: i64,
        warming_since: std::collections::BTreeMap<String, i64>,
    }
    let harness = metric_alerts_harness();
    write_metric_alerts(&harness, T0, |doc| value_code_rule(doc, "firing", "5"));
    write_reconfiguration(&harness, T0);
    harness.evaluate(T0);
    let saved: ReleaseMetricAlertsState =
        serde_json::from_slice(&fs::read(harness.path("state/state-metric-alerts.json")).unwrap())
            .unwrap();
    assert_eq!(
        saved.schema,
        "constellation.attention_metric_alerts_state.v1"
    );
    assert_eq!(saved.site, "labelwatch");
    assert_eq!(saved.updated_at, T0);
    let history = saved.history.unwrap();
    assert_eq!(history.first_seen, T0);
    assert_eq!(history.warming_since.len(), 1);
}

#[test]
fn lifecycle_refuses_unknown_fields_and_dry_runs_preserve_it() {
    let harness = metric_alerts_harness();
    write_metric_alerts(&harness, T0, |doc| value_code_rule(doc, "inactive", "1"));
    harness.evaluate(T0);
    let path = harness.path("state/state-attention-lifecycle.json");
    let before = fs::read(&path).unwrap();
    write_reconfiguration(&harness, T0 + 60);
    harness.evaluate_at(T0 + 60, &["--dry-run"]);
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let saved: Value = serde_json::from_slice(&before).unwrap();
    for field in ["extra", "schema", "site"] {
        let mut invalid = saved.clone();
        invalid[field] = json!("invalid");
        let bytes = serde_json::to_vec(&invalid).unwrap();
        fs::write(&path, &bytes).unwrap();
        assert_eq!(harness.evaluate_at(T0 + 60, &[]).status.code(), Some(1));
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
}

#[test]
fn previously_rejected_identity_cannot_gain_reconfiguration_grace() {
    let harness = metric_alerts_harness();
    write_metric_alerts(&harness, T0, |doc| {
        value_code_rule(doc, "firing", "invalid")
    });
    assert_eq!(harness.evaluate(T0)["exit_code"], 3);
    write_reconfiguration(&harness, T0 + 3600);
    write_metric_alerts(&harness, T0 + 3600, |doc| {
        value_code_rule(doc, "firing", "3")
    });
    let report = harness.evaluate(T0 + 3600);
    assert_eq!(report["exit_code"], 3);
    assert!(
        metric_input(&report)["identity"]
            .get("warming_rules")
            .is_none()
    );
}

/// Handler changes retire old obligations while the condition and accepted
/// page retain their identities. Retirements themselves never fail delivery.
#[test]
fn active_condition_survives_notice_handler_added_then_removed() {
    for pending in [false, true] {
        let mut harness = Harness::new();
        harness.notice_transport = "local_file";
        harness.host_posture("root");
        if pending {
            harness.fake("command_error-operations", "");
        }
        for offset in [0, 660] {
            set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
            harness.evaluate(T0 + offset);
        }
        let page_event =
            harness.state()["conditions"][UNKNOWN_ROOT]["last_intent"]["page"]["stable_event_id"]
                .clone();
        harness.notice_reference = "my-hook";
        harness.notice_transport = "slack";
        for (offset, retired_route) in [(720, "operations"), (780, "my-hook")] {
            if offset == 780 {
                harness.notice_reference = "operations";
                harness.notice_transport = "local_file";
                if pending {
                    fs::remove_file(harness.path("fake/command_error-operations")).unwrap();
                }
            }
            set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
            let output = harness.evaluate_at(T0 + offset, &[]);
            assert_eq!(output.status.code(), Some(0), "{output:?}");
            let report = harness.report();
            let rows = report["intents"].as_array().unwrap();
            assert_eq!(rows.len(), 2, "{report}");
            assert_eq!(rows[0]["outcome"], "route_retired");
            assert_eq!(rows[0]["route"], retired_route);
            assert_eq!(rows[1]["outcome"], "accepted");
            assert_eq!(rows[1]["route"], harness.notice_reference);
            assert!(
                report["unresolved_deliveries"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                harness.state()["conditions"][UNKNOWN_ROOT]["last_intent"]["page"]["stable_event_id"],
                page_event
            );
            assert_eq!(rows[1]["transition_id"], page_event);
            assert!(report["delivery"].get(retired_route).is_none());
        }
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + 840);
        assert!(
            harness.evaluate(T0 + 840)["intents"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            harness
                .calls()
                .iter()
                .filter(|call| call.starts_with("submit pagerduty-ops "))
                .count(),
            1
        );
        let log = fs::read_to_string(harness.path("state/intents.jsonl")).unwrap();
        assert_eq!(
            log.lines()
                .filter(|line| line.contains("route_retired"))
                .count(),
            2
        );
    }
}

#[test]
fn route_transport_changes_retire_before_using_the_current_nq_entry_point() {
    for (page, initially_local) in [(false, false), (false, true), (true, false), (true, true)] {
        let mut harness = Harness::new();
        if initially_local {
            if page {
                harness.page_transport = "local_file";
            } else {
                harness.notice_transport = "local_file";
            }
        }
        harness.host_posture("root");
        for offset in [0, 660] {
            set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
            harness.evaluate(T0 + offset);
        }
        let (offset, local) = (720, !initially_local);
        let route = if page {
            harness.page_reference
        } else {
            harness.notice_reference
        };
        if page {
            harness.page_transport = if local { "local_file" } else { "pagerduty" };
        } else {
            harness.notice_transport = if local { "local_file" } else { "discord" };
        }
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        let report = harness.evaluate(T0 + offset);
        assert_eq!(report["exit_code"], 0, "{report}");
        let rows = report["intents"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["outcome"], "route_retired");
        assert_eq!(rows[1]["outcome"], "accepted");
        assert_eq!(rows[1]["route"], route);
        let attempts = fs::read_to_string(harness.path("fake/attempts.log")).unwrap();
        assert!(attempts.lines().last().unwrap().starts_with(&format!(
            "{} {route} ",
            if local { "deliver-local" } else { "submit" }
        )));
        let body: Value = serde_json::from_slice(
            &harness.submitted_intent(rows[1]["notification_id"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(
            body["destination_identity"],
            format!(
                "{}:{route}",
                if local {
                    "local-inbox"
                } else if page {
                    "pagerduty"
                } else {
                    "discord"
                }
            )
        );
    }
}

#[test]
fn current_nq_transport_controls_delivery_even_with_old_notice_setting() {
    let mut harness = Harness::new();
    harness.page_route = false;
    harness.host_posture("root");
    for offset in [0, 660] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    harness.nq_routes_override = Some(
        "[[notification_routes]]\nreference = \"operations\"\ntransport = \"local_file\"\n".into(),
    );
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 720);
    let report = harness.evaluate(T0 + 720);
    assert_eq!(report["exit_code"], 0, "{report}");
    assert_eq!(report["intents"][0]["outcome"], "route_retired");
    assert_eq!(report["intents"][1]["outcome"], "accepted");
    assert!(
        harness
            .calls()
            .last()
            .unwrap()
            .starts_with("submit local:operations ")
    );
}

#[test]
fn missing_current_nq_route_keeps_last_and_pending_resolve_as_failures() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    harness.fake("command_error-operations", "");
    for (offset, state) in [
        (0, ProjectedStateV1::Unknown),
        (660, ProjectedStateV1::Unknown),
        (720, ProjectedStateV1::Healthy),
    ] {
        set(&harness, "root", state, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    // Model the persisted pre-submission checkpoint: resolve and its pending
    // trigger both refer to the route removed by the next config apply.
    let mut state = harness.state();
    let condition = &mut state["conditions"][UNKNOWN_ROOT];
    let trigger = condition["last_intent"]["notice"].clone();
    condition["pending_trigger"] = json!({"notice": trigger});
    condition["last_intent"]["notice"]["action"] = json!("resolve");
    condition["active"] = json!(false);
    condition["first_seen"] = Value::Null;
    condition["clear_since"] = Value::Null;
    fs::write(
        harness.path("state/state.json"),
        serde_json::to_vec(&state).unwrap(),
    )
    .unwrap();
    harness.nq_routes_override = Some(
        "[[notification_routes]]\nreference = \"pagerduty-ops\"\ntransport = \"pagerduty\"\n"
            .into(),
    );
    let attempts = fs::read_to_string(harness.path("fake/attempts.log")).unwrap();
    set(&harness, "root", ProjectedStateV1::Healthy, T0 + 780);
    let report = harness.evaluate(T0 + 780);
    assert_eq!(report["exit_code"], 4, "{report}");
    let rows = report["intents"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .all(|row| row["outcome"] == "failed" && row["error"] == "route_not_configured_in_nq")
    );
    assert_eq!(
        fs::read_to_string(harness.path("fake/attempts.log")).unwrap(),
        attempts
    );
    assert!(harness.state()["conditions"][UNKNOWN_ROOT]["pending_trigger"]["notice"].is_object());
    set(&harness, "root", ProjectedStateV1::Healthy, T0 + 840);
    assert_eq!(harness.evaluate(T0 + 840)["exit_code"], 4);
    // Restoring NQ's current route retries the original obligations.
    harness.nq_routes_override = None;
    fs::remove_file(harness.path("fake/command_error-operations")).unwrap();
    set(&harness, "root", ProjectedStateV1::Healthy, T0 + 900);
    assert_eq!(harness.evaluate(T0 + 900)["exit_code"], 0);
}

#[test]
fn digest_acceptance_cannot_move_to_a_new_notice_identity() {
    let mut harness = Harness::new();
    harness.page_route = false;
    harness.raw("[digest]\nat_utc = \"00:40\"\n");
    let accepted = harness.evaluate(T0);
    assert_eq!(accepted["delivery"]["operations"]["outcome"], "accepted");
    // No obligation is due for this identity yet, even though the previous
    // route accepted a digest today. The old digest record has no route field.
    harness.extra_config = "[digest]\nat_utc = \"13:00\"\n".into();
    harness.notice_reference = "my-hook";
    harness.fake("state-my-hook", "failed");
    let report = harness.evaluate(T0 + 60);
    assert_eq!(report["exit_code"], 0);
    assert_eq!(
        report["delivery"]["my-hook"],
        json!({"outcome": "skipped", "last_attempt_at": null})
    );
    assert_eq!(report["intents"][0]["outcome"], "route_retired");
    let report = harness.evaluate(T0 + 3600);
    assert_eq!(report["exit_code"], 4);
    assert_eq!(
        report["delivery"]["my-hook"],
        json!({"outcome": "failed", "last_attempt_at": rfc3339(T0 + 3600)})
    );
    assert_eq!(harness.calls().len(), 2);
}

#[test]
fn repeated_fatal_passes_preserve_the_last_completed_report() {
    let mut harness = Harness::new();
    harness.raw("[digest]\nat_utc = \"13:00\"\n");
    assert_eq!(harness.evaluate(T0)["exit_code"], 0);
    let prior = fs::read(harness.path("state/report.json")).unwrap();
    fs::create_dir(harness.path("state/digest-intent.json")).unwrap();
    for offset in [3600, 3660] {
        let output = harness.evaluate_at(T0 + offset, &[]);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert_eq!(fs::read(harness.path("state/report.json")).unwrap(), prior);
    }
    // Consume the actual retained report through both status readers. A newer
    // state.json or filesystem mtime cannot make evaluated_at current.
    let script = r#"
import importlib.util, pathlib, sys
root, report, now = pathlib.Path(sys.argv[1]), sys.argv[2], int(sys.argv[3])
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result
m = module('monitored', root / 'monitored/constellation-monitored.py')
f = root / 'monitored/fixtures'
argv = []
for flag, filename in [('registry','registry.json'), ('estate','estate.json'), ('services-dir','services.d'), ('attention-config','attention.toml'), ('policy','policy.json'), ('metric-alerts','metrics.json'), ('receipts-index','receipts/index.json')]:
    argv += ['--' + flag, str(f / filename)]
args = m.parser().parse_args(argv + ['--attention-report', report, 'list'])
doc = m.build(args, now)
row = next(row for row in doc['components'] if row['service'] == 'constellation-attention.timer')
assert 'stale' in row['state'], row
assert 'output current' not in row['state'], row
d = module('diagnostic', root / 'diagnostic/constellation-diagnostic.py')
from types import SimpleNamespace
reader = d.Investigation(SimpleNamespace(max_age=300), now)
assert reader.document('attention', report, 'constellation.attention_report.v1', 'evaluated_at') is None
assert any('stale' in str(row) for row in reader.bins['unknown']), reader.bins
"#;
    let output = Command::new("python3")
        .args(["-B", "-c", script])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .arg(harness.path("state/report.json"))
        .arg((T0 + 3660).to_string())
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn a_fatal_pass_before_any_completed_report_writes_none() {
    let harness = Harness::new();
    fs::write(harness.path("state/state.json"), b"broken").unwrap();
    for offset in [0, 60] {
        let output = harness.evaluate_at(T0 + offset, &[]);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(!harness.path("state/report.json").exists());
    }
}

#[test]
fn active_condition_acquires_and_retires_page_roles_without_repeating_notices() {
    let mut harness = Harness::new();
    harness.page_route = false;
    harness.host_posture("root");
    for offset in [0, 660] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    harness.page_route = true;
    for (offset, reference) in [(720, "pagerduty-ops"), (780, "new-pager")] {
        harness.page_reference = reference;
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        let report = harness.evaluate(T0 + offset);
        assert_eq!(report["exit_code"], 0);
        let rows = report["intents"].as_array().unwrap();
        assert_eq!(rows.len(), if offset == 720 { 1 } else { 2 });
        let fresh = rows.last().unwrap();
        assert_eq!(fresh["route"], reference);
        assert_eq!(fresh["route_role"], "page");
        assert_eq!(fresh["outcome"], "accepted");
        assert_eq!(
            report["delivery"]["operations"]["last_attempt_at"],
            rfc3339(T0 + 660)
        );
    }
    harness.page_route = false;
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 840);
    let report = harness.evaluate(T0 + 840);
    assert_eq!(report["exit_code"], 0);
    assert!(
        report["intents"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["outcome"] == "route_retired")
    );
    assert!(
        report["intents"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["action"] == "resolve"
                && row["route"] == "new-pager"
                && row["outcome"] == "accepted")
    );
    assert_eq!(
        report["abandoned_open_incident"][0]["route"],
        "pagerduty-ops"
    );
    assert_eq!(harness.calls().len(), 5);
}

#[test]
fn failed_replacement_route_does_not_blame_retirement_or_inherit_acceptance() {
    let mut harness = Harness::new();
    harness.page_route = false;
    harness.host_posture("root");
    for offset in [0, 660] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    harness.notice_transport = "local_file";
    harness.fake("command_error-operations", "");
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 720);
    let report = harness.evaluate(T0 + 720);
    assert_eq!(report["exit_code"], 4);
    assert_eq!(report["intents"][0]["outcome"], "route_retired");
    assert_eq!(
        report["delivery"]["operations"],
        json!({"outcome": "failed", "last_attempt_at": rfc3339(T0 + 720)})
    );
    let error = report["first_error"].as_str().unwrap();
    assert!(
        error.contains("notification condition target_class is refused"),
        "{error}"
    );
    assert!(!error.contains("route removed"), "{error}");
}

#[test]
fn readding_an_accepted_page_identity_does_not_reach_the_provider_again() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    for offset in [0, 660] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    let original = harness.state()["conditions"][UNKNOWN_ROOT]["last_intent"]["page"].clone();
    // A temporary transport change still preserves provider acceptance.
    {
        let offset = 720;
        let local = true;
        harness.page_transport = if local { "local_file" } else { "pagerduty" };
        harness.page_route = local;
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        let report = harness.evaluate(T0 + offset);
        assert_eq!(report["exit_code"], 0);
        assert_eq!(report["intents"][0]["outcome"], "route_retired");
        harness.page_route = true;
        harness.page_transport = "pagerduty";
        set(
            &harness,
            "root",
            ProjectedStateV1::Unknown,
            T0 + offset + 60,
        );
        let report = harness.evaluate(T0 + offset + 60);
        assert_eq!(report["exit_code"], 0);
        assert!(
            report["intents"]
                .as_array()
                .unwrap()
                .iter()
                .all(|item| item["outcome"] == "route_retired")
        );
        assert_eq!(
            report["delivery"]["pagerduty-ops"],
            json!({"outcome": "accepted", "last_attempt_at": rfc3339(T0 + 660)})
        );
        assert_eq!(
            harness.state()["conditions"][UNKNOWN_ROOT]["last_intent"]["page"],
            original
        );
    }
    assert_eq!(
        harness.calls().len(),
        3,
        "notice, original provider page, local copy"
    );
    for offset in [960, 1080] {
        set(&harness, "root", ProjectedStateV1::Healthy, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    let saved: Value =
        serde_json::from_slice(&fs::read(harness.path("state/accepted-pages.json")).unwrap())
            .unwrap();
    assert_eq!(saved, json!({}), "closed incidents forget accepted pages");
    for offset in [1140, 1800] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    assert_eq!(
        harness
            .calls()
            .iter()
            .filter(|call| call.starts_with("submit pagerduty-ops ") && call.contains("-trigger-"))
            .count(),
        2,
        "a new incident must page again"
    );
}

#[test]
fn reviewers_missing_operations_probe_fails_notice_and_digest() {
    for network in [true, false] {
        let mut harness = Harness::new();
        harness.page_route = false;
        harness.network = network;
        harness.host_posture("root");
        harness.raw("[digest]\nat_utc = \"00:00\"\n");
        harness.nq_routes_override = Some(String::new());
        set(&harness, "root", ProjectedStateV1::Unknown, T0);
        let report = harness.evaluate(T0);
        assert_eq!(report["exit_code"], 4);
        assert_eq!(report["digest"]["outcome"], "failed");
        assert_eq!(report["digest"]["error"], "route_not_configured_in_nq");
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + 660);
        let report = harness.evaluate(T0 + 660);
        assert_eq!(report["exit_code"], 4);
        assert_eq!(report["delivery"]["operations"]["outcome"], "failed");
        assert_eq!(
            report["delivery"]["operations"]["error"],
            "route_not_configured_in_nq"
        );
        assert!(report["delivery"]["operations"]["last_attempt_at"].is_null());
        assert!(
            report["intents"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row["outcome"] == "failed"
                    && row["error"] == "route_not_configured_in_nq")
        );
        assert!(!report["intents"].as_array().unwrap().is_empty());
        let output = harness.command(&[
            "check-config",
            "--config",
            harness.config_path().to_str().unwrap(),
        ]);
        assert_eq!(output.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("route_not_configured_in_nq: operations")
        );
    }
}

#[test]
fn missing_current_page_route_is_failed_and_rejected_by_check_config() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    harness.nq_routes_override =
        Some("[[notification_routes]]\nreference = \"operations\"\ntransport = \"slack\"\n".into());
    for offset in [0, 660] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    let report = harness.report();
    assert_eq!(report["exit_code"], 4);
    assert_eq!(report["delivery"]["operations"]["outcome"], "accepted");
    assert_eq!(report["delivery"]["pagerduty-ops"]["outcome"], "failed");
    assert_eq!(report["intents"][1]["error"], "route_not_configured_in_nq");
    let output = harness.command(&[
        "check-config",
        "--config",
        harness.config_path().to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn an_accepted_digest_cannot_hide_a_missing_current_nq_route() {
    let mut harness = Harness::new();
    harness.page_route = false;
    harness.raw("[digest]\nat_utc = \"00:00\"\n");
    assert_eq!(harness.evaluate(T0)["exit_code"], 0);
    harness.nq_routes_override = Some(String::new());
    let report = harness.evaluate(T0 + 60);
    assert_eq!(report["exit_code"], 4);
    assert_eq!(report["delivery"]["operations"]["outcome"], "failed");
    assert!(report["intents"].as_array().unwrap().is_empty());
    assert!(
        report["first_error"]
            .as_str()
            .unwrap()
            .contains("route_not_configured_in_nq")
    );
}

#[test]
fn idle_notice_only_passes_and_offline_check_config_skip_unreadable_nq() {
    let mut harness = Harness::new();
    harness.page_route = false;
    let config_path = harness.config_path();
    fs::remove_file(harness.path("nq.toml")).unwrap();
    let config = constellation_attention::config::Config::load(&config_path).unwrap();
    for offset in [0, 60] {
        let result = constellation_attention::engine::evaluate(
            &config,
            &constellation_attention::engine::PassOptions {
                dry_run: false,
                now: T0 + offset,
                now_ms: (T0 + offset) * 1000,
            },
        )
        .unwrap();
        assert_eq!(result.exit_code, 0);
    }
    let output = harness.command(&["check-config", "--config", config_path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0));
    assert!(harness.calls().is_empty());
}

#[test]
fn removing_page_role_resolves_the_accepted_provider_incident() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    for offset in [0, 660] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    let page = harness.state()["conditions"][UNKNOWN_ROOT]["last_intent"]["page"].clone();
    let original: Value = serde_json::from_slice(
        &harness.submitted_intent(page["notification_id"].as_str().unwrap()),
    )
    .unwrap();
    harness.page_route = false;
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 720);
    let report = harness.evaluate(T0 + 720);
    assert_eq!(report["exit_code"], 0);
    let rows = report["intents"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["action"], "resolve");
    assert_eq!(rows[0]["outcome"], "accepted");
    let resolve: Value = serde_json::from_slice(
        &harness.submitted_intent(rows[0]["notification_id"].as_str().unwrap()),
    )
    .unwrap();
    assert_eq!(resolve["condition"], original["condition"]);
    assert_eq!(
        resolve["destination_identity"],
        original["destination_identity"]
    );
    assert_eq!(resolve["action"], "resolve");
    assert_eq!(rows[1]["outcome"], "route_retired");
    assert!(report["abandoned_open_incident"].is_null());
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 780);
    assert!(
        harness.evaluate(T0 + 780)["intents"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    harness.page_route = true;
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 840);
    let report = harness.evaluate(T0 + 840);
    assert_eq!(report["intents"][0]["action"], "trigger");
    assert_eq!(harness.calls().len(), 4, "notice, page, resolve, new page");
}

#[test]
fn removing_an_unavailable_page_identity_reports_and_notices_manual_resolution() {
    for replacement in [
        "",
        "[[notification_routes]]\nreference = \"pagerduty-ops\"\ntransport = \"local_file\"\n",
    ] {
        let mut harness = Harness::new();
        harness.host_posture("root");
        for offset in [0, 660] {
            set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
            harness.evaluate(T0 + offset);
        }
        harness.page_route = false;
        harness.nq_routes_override = Some(format!(
            "{replacement}[[notification_routes]]\nreference = \"operations\"\ntransport = \"slack\"\n"
        ));
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + 720);
        let report = harness.evaluate(T0 + 720);
        assert_eq!(report["exit_code"], 0);
        assert_eq!(
            report["abandoned_open_incident"],
            json!([{"route": "pagerduty-ops", "dedup_key": UNKNOWN_ROOT}])
        );
        let notice = &report["intents"][0];
        assert_eq!(notice["route"], "operations");
        assert_eq!(notice["outcome"], "accepted");
        let body: Value = serde_json::from_slice(
            &harness.submitted_intent(notice["notification_id"].as_str().unwrap()),
        )
        .unwrap();
        let summary = body["summary"].as_str().unwrap();
        assert!(summary.contains("provider incident must be resolved by hand"));
        assert!(summary.contains("pagerduty-ops"));
        assert!(summary.contains(UNKNOWN_ROOT));
        assert_eq!(harness.calls().len(), 3);
    }
}

#[test]
fn removed_page_resolve_failure_keeps_the_obligation_until_accepted() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    for offset in [0, 660] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    harness.page_route = false;
    harness.fake("command_error-pagerduty-ops", "");
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 720);
    let report = harness.evaluate(T0 + 720);
    assert_eq!(report["exit_code"], 4);
    assert!(
        report["intents"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["outcome"] != "route_retired")
    );
    assert!(harness.state()["conditions"][UNKNOWN_ROOT]["last_intent"]["page"].is_object());
    fs::remove_file(harness.path("fake/command_error-pagerduty-ops")).unwrap();
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 780);
    let report = harness.evaluate(T0 + 780);
    assert_eq!(report["exit_code"], 0);
    assert_eq!(report["intents"][0]["action"], "resolve");
    assert_eq!(report["intents"][0]["outcome"], "accepted");
    assert_eq!(report["intents"][1]["outcome"], "route_retired");
}

#[test]
fn damaged_accepted_pages_are_repaired_without_blocking_evaluation() {
    for malformed in [true, false] {
        let mut harness = Harness::new();
        harness.host_posture("root");
        for offset in [0, 660] {
            set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
            harness.evaluate(T0 + offset);
        }
        let path = harness.path("state/accepted-pages.json");
        if malformed {
            fs::write(&path, b"broken").unwrap();
        } else {
            let mut saved: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            saved[UNKNOWN_ROOT]["pagerduty-ops"]["last"]["route"] = json!("wrong-route");
            fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
        }
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + 720);
        let output = harness.evaluate_at(T0 + 720, &[]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("accepted_pages: repaired"));
        assert_eq!(harness.report()["accepted_pages"], "repaired");
        assert_eq!(
            harness.calls().len(),
            2,
            "live state still holds acceptance"
        );
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + 780);
        assert!(harness.evaluate(T0 + 780)["accepted_pages"].is_null());
    }
}

#[test]
fn removed_page_resolve_recovers_a_crash_after_provider_acceptance() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    for offset in [0, 660] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    harness.page_route = false;
    harness.fake("crash_after", "");
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 720);
    let output = harness.evaluate_at(T0 + 720, &[]);
    assert!(!output.status.success());
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 780);
    let report = harness.evaluate(T0 + 780);
    assert_eq!(report["exit_code"], 0);
    assert_eq!(report["intents"][0]["action"], "resolve");
    assert_eq!(report["intents"][0]["outcome"], "accepted");
    assert_eq!(report["intents"][1]["outcome"], "route_retired");
    let calls = harness.calls();
    assert_eq!(calls.len(), 4);
    assert!(calls.last().unwrap().ends_with("existing"));
    assert_eq!(
        calls[2].split_whitespace().nth(2),
        calls[3].split_whitespace().nth(2)
    );
}

#[test]
fn removed_page_retry_pause_preserves_the_actual_attempt_time() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    for offset in [0, 660] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    harness.page_route = false;
    harness.fake("state-pagerduty-ops", "failed");
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 720);
    assert_eq!(harness.evaluate(T0 + 720)["exit_code"], 4);
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 780);
    let report = harness.evaluate(T0 + 780);
    assert_eq!(report["exit_code"], 4);
    assert_eq!(
        report["delivery"]["pagerduty-ops"]["last_attempt_at"],
        rfc3339(T0 + 720)
    );
    assert!(report["intents"].as_array().unwrap().is_empty());
    harness.fake("state-pagerduty-ops", "accepted");
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 1020);
    let report = harness.evaluate(T0 + 1020);
    assert_eq!(report["exit_code"], 0);
    assert_eq!(report["intents"][0]["operation"], "resubmit");
    assert_eq!(report["intents"][1]["outcome"], "route_retired");
}

#[test]
fn removed_page_becomes_manual_if_nq_identity_disappears_during_cleanup() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    for offset in [0, 660] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    harness.page_route = false;
    harness.fake("command_error-pagerduty-ops", "");
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 720);
    assert_eq!(harness.evaluate(T0 + 720)["exit_code"], 4);
    harness.nq_routes_override =
        Some("[[notification_routes]]\nreference = \"operations\"\ntransport = \"slack\"\n".into());
    harness.fake("command_error-operations", "");
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 780);
    let report = harness.evaluate(T0 + 780);
    assert_eq!(report["exit_code"], 4);
    assert_eq!(
        report["abandoned_open_incident"][0]["dedup_key"],
        UNKNOWN_ROOT
    );
    fs::remove_file(harness.path("fake/command_error-operations")).unwrap();
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 840);
    let report = harness.evaluate(T0 + 840);
    assert_eq!(report["exit_code"], 0);
    assert_eq!(report["intents"][0]["route"], "operations");
    assert_eq!(report["intents"][0]["outcome"], "accepted");
    assert_eq!(report["intents"][1]["outcome"], "route_retired");
}

#[test]
fn readding_page_role_finishes_pending_cleanup_before_retriggering() {
    let mut harness = Harness::new();
    harness.host_posture("root");
    for offset in [0, 660] {
        set(&harness, "root", ProjectedStateV1::Unknown, T0 + offset);
        harness.evaluate(T0 + offset);
    }
    harness.page_route = false;
    harness.fake("command_error-pagerduty-ops", "");
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 720);
    assert_eq!(harness.evaluate(T0 + 720)["exit_code"], 4);
    fs::remove_file(harness.path("fake/command_error-pagerduty-ops")).unwrap();
    harness.page_route = true;
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 780);
    let report = harness.evaluate(T0 + 780);
    assert_eq!(report["exit_code"], 0);
    assert_eq!(report["intents"][0]["action"], "resolve");
    assert_eq!(report["intents"][0]["outcome"], "accepted");
    assert_eq!(report["intents"][1]["outcome"], "route_retired");
    assert_eq!(report["intents"][2]["action"], "trigger");
    assert_eq!(report["intents"][2]["outcome"], "accepted");
    set(&harness, "root", ProjectedStateV1::Unknown, T0 + 840);
    let report = harness.evaluate(T0 + 840);
    assert_eq!(report["exit_code"], 0);
    assert!(report["intents"].as_array().unwrap().is_empty());
    assert_eq!(harness.calls().len(), 4);
}
