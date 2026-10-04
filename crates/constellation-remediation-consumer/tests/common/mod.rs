//! Shared harness: fakes for ag-loopctl, the Docket grant resolver, the
//! observation resolvers, nq, systemctl, ag-effectd, la_inference and the
//! provider endpoint.
#![allow(dead_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use constellation_remediation_consumer::Config;
use serde_json::{Value, json};

pub mod provider;

pub const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
pub const MACHINE: &str = "1853ff04ff7a42679bf212ec9a569c4f";
pub const UNIT: &str = "attention-canary.service";
pub const INSTANCE: &str = "svc-attention-canary";
pub const CONDITION: &str = "constellation:reference:service:service-down:attention-canary.service";
pub const SUBJECT: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub const SCOPE: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

pub fn now_s() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

pub fn rfc3339(seconds: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(seconds)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

pub struct Harness {
    pub dir: tempfile::TempDir,
    /// The model decider's loopback endpoint, when the harness runs it.
    pub endpoint: Option<String>,
    /// PID of the pass being run, for the fake provider's kill hook.
    pub child: Arc<AtomicU32>,
    /// The dev-mode store of a real `la_inference`, when one replaces the fake.
    pub la_store: Option<PathBuf>,
}

/// The milestone the real-LA enrollment below belongs to.
pub const LA_MILESTONE: &str = "agentic-remediation-v2";

/// The API key the fake env file holds; it must never appear in any record.
pub const API_KEY: &str = "sk-or-v1-test-0123456789abcdef";

impl Harness {
    pub fn new() -> Self {
        Self::build(None)
    }

    /// A harness running `--decider model` against `provider`, with a window
    /// long enough for the model decider.
    pub fn model(provider: &provider::FakeProvider) -> Self {
        let harness = Self::build(Some(provider.endpoint()));
        provider.watch(harness.child.clone());
        let key = harness.path("etc/openrouter.env");
        fs::write(
            &key,
            format!("# owner-installed\nOPENROUTER_API_KEY={API_KEY}\n"),
        )
        .unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        harness.write_report(&Report {
            window_left: 280,
            ..Report::default()
        });
        harness
    }

    fn build(endpoint: Option<String>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let harness = Self {
            dir,
            endpoint,
            child: Arc::new(AtomicU32::new(0)),
            la_store: None,
        };
        for sub in ["fake", "etc", "campaign"] {
            fs::create_dir_all(harness.path(sub)).unwrap();
        }
        let fake = harness.path("fake");
        let wrap = |name: &str, script: &str, argument: &str| {
            let path = harness.path("etc").join(name);
            fs::write(
                &path,
                format!(
                    "#!/bin/sh\nFAKE_DIR={} exec {FIXTURES}/{script} {argument} \"$@\"\n",
                    fake.display()
                ),
            )
            .unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        };
        wrap("ag-loopctl", "fake-ag-loopctl.sh", "");
        wrap("pre-resolver", "fake-resolver.sh", "pre");
        wrap("post-resolver", "fake-resolver.sh", "post");
        wrap("grant-resolver", "fake-grant-resolver.sh", "");
        wrap("nq", "fake-tool.sh", "nq");
        wrap("systemctl", "fake-tool.sh", "systemctl");
        wrap("ag-effectd", "fake-tool.sh", "effectd");
        wrap("la_inference", "fake-la-inference.sh", "");
        harness.write_plan("plan-inactive.json", UNIT, "inactive");
        harness.write_config(&["inactive"]);
        harness.write_report(&Report::default());
        harness
    }

    /// Replace the fake with a real `la_inference` binary over a dev-mode
    /// store holding the DESIGN envelope's enrollment.
    pub fn use_real_la(&mut self, binary: &Path) {
        let wrapper = self.path("etc/la_inference");
        fs::write(
            &wrapper,
            format!("#!/bin/sh\nexec {} \"$@\"\n", binary.display()),
        )
        .unwrap();
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
        let store = self.path("la-books/inference.sqlite");
        self.la_store = Some(store.clone());
        self.write_config(&["inactive"]);
        let enrollment = self.path("etc/la-enroll.json");
        fs::write(
            &enrollment,
            serde_json::to_vec(&json!({
                "v": 1, "cmd": "enroll",
                "admission_id": "adm-bar-v2-vm",
                "admission_ref": "owner-grant:bar-v2",
                "basis_kind": "owner_grant",
                "actor": "constellation-remediation-consumer",
                "scope": "agentic-v2/vm",
                "milestone_id": LA_MILESTONE,
                "host_allocation_micro_usd": 1_000_000,
                "valid_from_unix_ms": 0,
                "valid_until_unix_ms": 9_000_000_000_000u64,
                "models": [{"provider": "openrouter/google-vertex",
                    "model_class": "google/gemini-2.5-flash-lite"}],
                "episode_ceilings": {"max_calls": 2, "retry_ceiling": 1, "max_input_tokens": 8192,
                    "max_output_tokens": 512, "max_cost_micro_usd": 5000, "max_wall_ms": 35000},
                "call_ceilings": {"max_input_tokens": 4096, "max_output_tokens": 256,
                    "max_cost_micro_usd": 2500, "max_wall_ms": 15000},
            }))
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(&enrollment, fs::Permissions::from_mode(0o644)).unwrap();
        let output = Command::new(binary)
            .args(["--dev", "--store"])
            .arg(&store)
            .args(["enroll", "--file"])
            .arg(&enrollment)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    /// `la_inference reconcile` over the real store: (exit code, result).
    pub fn la_reconcile(&self, binary: &Path) -> (Option<i32>, Value) {
        let output = Command::new(binary)
            .args(["--dev", "--store"])
            .arg(self.la_store.as_ref().unwrap())
            .args(["reconcile", "--milestone", LA_MILESTONE])
            .output()
            .unwrap();
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        (output.status.code(), value["result"].clone())
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    pub fn etc(&self, name: &str) -> String {
        self.path("etc").join(name).display().to_string()
    }

    pub fn control(&self, name: &str, value: &str) {
        fs::write(self.path("fake").join(name), value).unwrap();
    }

    pub fn write_plan(&self, name: &str, unit: &str, prestate: &str) {
        fs::write(
            self.path("etc").join(name),
            serde_json::to_vec(&json!({
                "schema": "ag-effectd.docket-executor-systemd-plan/v2",
                "subject": SUBJECT,
                "scope": SCOPE,
                "effect": {
                    "kind": "systemd_unit",
                    "unit": unit,
                    "action": "start",
                    "expected_active_state": prestate,
                    "expected_unit_file_state": "enabled",
                },
                "systemd_machine_identity": MACHINE,
            }))
            .unwrap(),
        )
        .unwrap();
    }

    pub fn write_config(&self, prestates: &[&str]) {
        let plans: String = prestates
            .iter()
            .map(|prestate| {
                format!(
                    "[[ag.plans]]\nprestate = \"{prestate}\"\npath = \"{}\"\n",
                    self.etc(&format!("plan-{prestate}.json"))
                )
            })
            .collect();
        let config = format!(
            r#"
[enrollment]
site = "reference"
unit = "{UNIT}"
instance_id = "{INSTANCE}"
machine_id = "{MACHINE}"

[consumer]
state_dir = "{state}"
report = "{report}"
poll_attempts = 2
poll_interval_ms = 10
postcondition_attempts = 2
postcondition_interval_ms = 10
postcondition_dwell_seconds = 5
command_timeout_seconds = 20

[ag]
loopctl = "{loopctl}"
database = "{database}"
runtime_profile = "{etc}/runtime-profile.json"
catalog = "{etc}/catalog.json"
observation_resolver = "{pre}"
observation_resolver_id = "pre-resolver/v1"
standing_resolver = "{etc}/ag-standing-resolver"
standing_resolver_id = "ag-standing/v1"
max_standing_ttl_ms = 60000
postcondition_resolver = "{post}"
postcondition_resolver_id = "post-resolver/v1"
{plans}
[docket]
program = "/usr/bin/docket"
state_dir = "{dir}/docket"
trust = "{etc}/trust.json"
standing_resolver = "{grant}"
executor = "{effectd}"
issuer_principal = "remediation-owner"
issuer_key_id = "k1"
issuer_key = "{etc}/issuer.pk8"

[nq]
program = "{nq}"
config = "/etc/nq/nqd-ops.toml"

[evaluator]
systemctl = "{systemctl}"
{model}"#,
            state = self.path("state").display(),
            report = self.path("report.json").display(),
            loopctl = self.etc("ag-loopctl"),
            database = self.path("campaign/active.sqlite").display(),
            etc = self.path("etc").display(),
            dir = self.dir.path().display(),
            pre = self.etc("pre-resolver"),
            post = self.etc("post-resolver"),
            grant = self.etc("grant-resolver"),
            effectd = self.etc("ag-effectd"),
            nq = self.etc("nq"),
            systemctl = self.etc("systemctl"),
            model = self
                .endpoint
                .as_ref()
                .map_or_else(String::new, |endpoint| format!(
                    r#"
[model]
la_program = "{la}"
la_arguments = {la_arguments}
la_admission_id = "adm-bar-v2-vm"
la_eligibility_ref = "owner-grant:bar-canary/test"
endpoint = "{endpoint}"
key_file = "{etc}/openrouter.env"
total_timeout_ms = 1000
connect_timeout_ms = 500
retry_backoff_ms = 0
"#,
                    la = self.etc("la_inference"),
                    la_arguments = self.la_store.as_ref().map_or_else(
                        || r#"["--store", "/var/lib/linear-accountant/inference.sqlite"]"#
                            .to_owned(),
                        |store| format!(r#"["--dev", "--store", "{}"]"#, store.display()),
                    ),
                    etc = self.path("etc").display(),
                )),
        );
        fs::write(self.path("consumer.toml"), config).unwrap();
    }

    pub fn write_report(&self, report: &Report) {
        let now = now_s();
        fs::write(
            self.path("report.json"),
            serde_json::to_vec(&json!({
                "schema": "constellation.attention_report.v1",
                "site": "reference",
                "evaluated_at": rfc3339(now - report.age),
                "inputs": [
                    {"label": "nq-ops", "kind": "nq_status", "status": report.nq_status},
                    {"label": "posture", "kind": "host_posture", "status": "ok"},
                ],
                "conditions": [{
                    "id": CONDITION,
                    "rule": "service-down",
                    "observation": report.observation,
                    "reference": {"instance_id": INSTANCE},
                    "first_seen": rfc3339(report.first_seen.unwrap_or(now - 200)),
                    "persisted_seconds": 200,
                    "active": true,
                    "transition": null,
                    "response_policy": report.policy,
                    "remediation_window_until": now + report.window_left,
                    "page_deferred": report.page_deferred,
                    "summary": report.summary,
                }],
            }))
            .unwrap(),
        )
        .unwrap();
    }

    pub fn config(&self) -> Config {
        Config::load(&self.path("consumer.toml")).unwrap()
    }

    /// Run one pass of the binary; the summary, or None if it was killed.
    pub fn run(&self) -> Option<Value> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_constellation-remediation-consumer"));
        command.args([
            "--config",
            &self.path("consumer.toml").display().to_string(),
        ]);
        if self.endpoint.is_some() {
            command.args(["--decider", "model"]);
        }
        let child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        self.child.store(child.id(), Ordering::SeqCst);
        let output = child.wait_with_output().unwrap();
        self.child.store(0, Ordering::SeqCst);
        // Killed by a signal: no exit code.
        output.status.code()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Some(serde_json::from_slice(&output.stdout).unwrap())
    }

    pub fn result(&self) -> String {
        self.run().expect("pass was killed")["result"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    pub fn calls(&self) -> Vec<String> {
        lines(&self.path("fake/calls.log"))
    }

    pub fn count(&self, call: &str) -> usize {
        self.calls().iter().filter(|line| *line == call).count()
    }

    pub fn effects(&self) -> usize {
        lines(&self.path("fake/effects.log")).len()
    }

    pub fn journal(&self) -> Vec<Value> {
        lines(&self.path("state/journal.jsonl"))
            .iter()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    pub fn events(&self, event: &str) -> Vec<Value> {
        self.journal()
            .into_iter()
            .filter(|line| line["event"] == event)
            .collect()
    }

    pub fn abstentions(&self) -> Vec<String> {
        self.events("abstained")
            .iter()
            .map(|line| line["detail"]["reason"].as_str().unwrap().to_owned())
            .collect()
    }

    pub fn state(&self) -> Value {
        serde_json::from_slice(&fs::read(self.path("state/state.json")).unwrap()).unwrap()
    }

    pub fn closed_outcomes(&self) -> Vec<String> {
        self.state()["closed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|episode| episode["outcome"].as_str().unwrap().to_owned())
            .collect()
    }
}

pub fn lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

pub struct Report {
    pub age: i64,
    pub nq_status: &'static str,
    pub observation: &'static str,
    pub policy: &'static str,
    pub window_left: i64,
    pub first_seen: Option<i64>,
    pub page_deferred: bool,
    /// The condition's untrusted narration, if any.
    pub summary: Option<&'static str>,
}

impl Default for Report {
    fn default() -> Self {
        Self {
            age: 10,
            nq_status: "ok",
            observation: "present",
            policy: "auto_remediate_then_page",
            window_left: 200,
            first_seen: None,
            page_deferred: true,
            summary: None,
        }
    }
}
