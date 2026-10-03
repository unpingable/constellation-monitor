//! The consumer binary (and, for clock-dependent cases, the library) against
//! fakes for ag-loopctl, the Docket grant resolver, the observation
//! resolvers, nq, systemctl and ag-effectd.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use constellation_remediation_consumer::{Config, run_pass};
use serde_json::{Value, json};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
const MACHINE: &str = "1853ff04ff7a42679bf212ec9a569c4f";
const UNIT: &str = "attention-canary.service";
const INSTANCE: &str = "svc-attention-canary";
const CONDITION: &str = "constellation:labelwatch:service:service-down:attention-canary.service";
const SUBJECT: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SCOPE: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn now_s() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

fn rfc3339(seconds: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(seconds)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

struct Harness {
    dir: tempfile::TempDir,
}

impl Harness {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let harness = Self { dir };
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
        harness.write_plan("plan-inactive.json", UNIT, "inactive");
        harness.write_config(&["inactive"]);
        harness.write_report(&Report::default());
        harness
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn etc(&self, name: &str) -> String {
        self.path("etc").join(name).display().to_string()
    }

    fn control(&self, name: &str, value: &str) {
        fs::write(self.path("fake").join(name), value).unwrap();
    }

    fn write_plan(&self, name: &str, unit: &str, prestate: &str) {
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

    fn write_config(&self, prestates: &[&str]) {
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
site = "labelwatch"
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
"#,
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
        );
        fs::write(self.path("consumer.toml"), config).unwrap();
    }

    fn write_report(&self, report: &Report) {
        let now = now_s();
        fs::write(
            self.path("report.json"),
            serde_json::to_vec(&json!({
                "schema": "constellation.attention_report.v1",
                "site": "labelwatch",
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
                    "page_deferred": true,
                }],
            }))
            .unwrap(),
        )
        .unwrap();
    }

    fn config(&self) -> Config {
        Config::load(&self.path("consumer.toml")).unwrap()
    }

    /// Run one pass of the binary; the summary, or None if it was killed.
    fn run(&self) -> Option<Value> {
        let output = Command::new(env!("CARGO_BIN_EXE_constellation-remediation-consumer"))
            .args([
                "--config",
                &self.path("consumer.toml").display().to_string(),
            ])
            .output()
            .unwrap();
        // Killed by a signal: no exit code.
        output.status.code()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Some(serde_json::from_slice(&output.stdout).unwrap())
    }

    fn result(&self) -> String {
        self.run().expect("pass was killed")["result"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn calls(&self) -> Vec<String> {
        lines(&self.path("fake/calls.log"))
    }

    fn count(&self, call: &str) -> usize {
        self.calls().iter().filter(|line| *line == call).count()
    }

    fn effects(&self) -> usize {
        lines(&self.path("fake/effects.log")).len()
    }

    fn journal(&self) -> Vec<Value> {
        lines(&self.path("state/journal.jsonl"))
            .iter()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn events(&self, event: &str) -> Vec<Value> {
        self.journal()
            .into_iter()
            .filter(|line| line["event"] == event)
            .collect()
    }

    fn abstentions(&self) -> Vec<String> {
        self.events("abstained")
            .iter()
            .map(|line| line["detail"]["reason"].as_str().unwrap().to_owned())
            .collect()
    }

    fn state(&self) -> Value {
        serde_json::from_slice(&fs::read(self.path("state/state.json")).unwrap()).unwrap()
    }

    fn closed_outcomes(&self) -> Vec<String> {
        self.state()["closed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|episode| episode["outcome"].as_str().unwrap().to_owned())
            .collect()
    }
}

fn lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

struct Report {
    age: i64,
    nq_status: &'static str,
    observation: &'static str,
    policy: &'static str,
    window_left: i64,
    first_seen: Option<i64>,
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
        }
    }
}

const AG_HAPPY: [&str; 11] = [
    "ag init",
    "ag record-proposal",
    "ag require-standing",
    "ag decide",
    "ag authorize",
    "ag recover",
    "ag dispatch",
    "ag poll",
    "ag continue",
    "ag complete",
    "systemctl start constellation-attention.service",
];

fn ag_and_trigger_calls(harness: &Harness) -> Vec<String> {
    harness
        .calls()
        .into_iter()
        .filter(|line| {
            (line.starts_with("ag ") && line != "ag status") || line.starts_with("systemctl")
        })
        .collect()
}

#[test]
fn happy_path_drives_one_occurrence_to_completion() {
    let harness = Harness::new();
    let summary = harness.run().unwrap();
    assert_eq!(summary["result"], "completed", "{:#?}", harness.journal());
    assert_eq!(
        summary["schema"],
        "constellation.remediation-consumer.pass/v1"
    );
    assert_eq!(ag_and_trigger_calls(&harness), AG_HAPPY);
    assert_eq!(harness.effects(), 1);
    let calls = harness.calls();
    let position = |call: &str| calls.iter().position(|line| line == call).unwrap();
    assert!(position("resolve pre current") < position("ag init"));
    assert!(
        position("ag poll")
            < position("nq --config /etc/nq/nqd-ops.toml collect svc-attention-canary")
    );
    assert!(
        position("nq --config /etc/nq/nqd-ops.toml collect svc-attention-canary")
            < position("resolve post current")
    );
    assert!(position("resolve post current") < position("ag complete"));
    // Only the enrolled unit and the evaluator's own service are ever named.
    assert!(
        calls
            .iter()
            .filter(|line| line.starts_with("systemctl"))
            .all(|line| line == "systemctl start constellation-attention.service")
    );
    assert_eq!(harness.closed_outcomes(), ["completed"]);
    let closed = &harness.state()["closed"][0];
    // Every plan-gated AG step names the one chosen owner plan.
    let plan = closed["plan"].as_str().unwrap();
    assert_eq!(
        lines(&harness.path("fake/plans.log")),
        ["init", "decide", "authorize", "continue", "complete"]
            .iter()
            .map(|step| format!("{step} {plan}"))
            .collect::<Vec<_>>()
    );
    assert_eq!(closed["dispatch_started"], true);
    assert_eq!(closed["condition_id"], CONDITION);
    assert_eq!(closed["prestate"], "inactive");
    assert!(closed["continuation_occurrence"].is_string());
    assert_ne!(closed["continuation_occurrence"], closed["occurrence"]);
    let events: Vec<String> = harness
        .journal()
        .iter()
        .map(|line| line["event"].as_str().unwrap().to_owned())
        .collect();
    for expected in [
        "pass_started",
        "precondition",
        "episode_opened",
        "dispatch_started",
        "settled",
        "collect_requested",
        "postcondition",
        "episode_closed",
        "evaluator_triggered",
        "pass_finished",
    ] {
        assert!(
            events.contains(&expected.to_owned()),
            "{expected}: {events:?}"
        );
    }
    for line in harness.journal() {
        assert_eq!(
            line["schema"],
            "constellation.remediation-consumer.journal/v1"
        );
    }
    // The genesis carries a zero retry budget and the plan's identity.
    let episode = closed["episode"].as_str().unwrap();
    let dir = harness
        .path("state/episodes")
        .join(&episode["sha256:".len().."sha256:".len() + 32]);
    let genesis: Value =
        serde_json::from_slice(&fs::read(dir.join("genesis.json")).unwrap()).unwrap();
    assert_eq!(genesis["budget"]["retry_limit"], 0);
    assert_eq!(genesis["expected_ag_work"], closed["work"]);
    assert_eq!(genesis["campaign"], closed["campaign"]);
    // State directory is private.
    let mode = fs::metadata(harness.path("state"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700);

    // The next pass sees the same (still reported) episode and does nothing.
    assert_eq!(harness.result(), "abstained");
    assert_eq!(harness.abstentions(), ["episode_already_attempted"]);
    assert_eq!(harness.effects(), 1);
}

#[test]
fn contradictory_precondition_abstains_without_touching_ag() {
    let harness = Harness::new();
    harness.control("pre_status", "contradictory");
    assert_eq!(harness.result(), "abstained");
    assert_eq!(harness.abstentions(), ["precondition_contradictory"]);
    assert!(harness.calls().iter().all(|line| !line.starts_with("ag ")));
    assert!(!harness.path("campaign/active.sqlite").exists());
    let precondition = &harness.events("precondition")[0]["detail"];
    assert_eq!(precondition["status"], "contradictory");
    assert_eq!(precondition["note"], "fake resolver: contradictory");

    // Stale and absent abstain too; an abstention never consumes the episode.
    for status in ["stale", "absent"] {
        harness.control("pre_status", status);
        assert_eq!(harness.result(), "abstained");
    }
    harness.control("pre_status", "current");
    assert_eq!(harness.result(), "completed");
    assert_eq!(harness.effects(), 1);
}

#[test]
fn stale_or_not_ok_input_abstains_before_any_resolution() {
    let cases = [
        (
            Report {
                age: 130,
                ..Report::default()
            },
            "report_stale",
        ),
        (
            Report {
                nq_status: "not_current",
                ..Report::default()
            },
            "nq_input_not_ok",
        ),
        (
            Report {
                window_left: 80,
                ..Report::default()
            },
            "window_too_short",
        ),
        (
            Report {
                observation: "unknown",
                ..Report::default()
            },
            "observation_not_present",
        ),
        (
            Report {
                policy: "observe_only",
                ..Report::default()
            },
            "policy_not_auto_remediate",
        ),
    ];
    for (report, reason) in cases {
        let harness = Harness::new();
        harness.write_report(&report);
        assert_eq!(harness.result(), "abstained");
        assert_eq!(harness.abstentions(), [reason]);
        assert!(
            harness.calls().is_empty(),
            "{reason}: {:?}",
            harness.calls()
        );
    }
}

#[test]
fn second_episode_within_the_window_gets_no_second_attempt() {
    let harness = Harness::new();
    let now = now_s();
    harness.write_report(&Report {
        first_seen: Some(now - 200),
        ..Report::default()
    });
    assert_eq!(harness.result(), "completed");
    // The canary dies again: a new episode, inside the first one's window.
    harness.write_report(&Report {
        first_seen: Some(now - 5),
        ..Report::default()
    });
    assert_eq!(harness.result(), "abstained");
    assert_eq!(harness.abstentions(), ["attempt_within_previous_window"]);
    assert_eq!(harness.count("ag init"), 1);
    assert_eq!(harness.effects(), 1);
}

#[test]
fn ag_refusal_is_recorded_and_never_retried() {
    let harness = Harness::new();
    harness.control(
        "refuse_decide",
        "exact-work catalog does not admit work for another unit",
    );
    assert_eq!(harness.result(), "refused_at_decide");
    let refused = &harness.events("ag_refused")[0]["detail"];
    assert_eq!(refused["step"], "decide");
    assert!(
        refused["failure"]["message"]
            .as_str()
            .unwrap()
            .contains("another unit")
    );
    assert_eq!(harness.count("ag authorize"), 0);
    assert_eq!(harness.effects(), 0);
    // Same episode next pass: no retry even though AG would now admit.
    fs::remove_file(harness.path("fake/refuse_decide")).unwrap();
    assert_eq!(harness.result(), "abstained");
    assert_eq!(harness.abstentions(), ["episode_already_attempted"]);
    assert_eq!(harness.count("ag decide"), 1);
}

#[test]
fn exhausted_grant_refuses_dispatch_without_retry() {
    let harness = Harness::new();
    harness.control("grant_max", "0");
    assert_eq!(harness.result(), "dispatch_refused");
    assert_eq!(harness.count("ag dispatch"), 1);
    assert_eq!(harness.count("grant 0/0"), 1);
    assert_eq!(harness.effects(), 0);
    assert_eq!(harness.closed_outcomes(), ["dispatch_refused"]);
    let closed = &harness.events("episode_closed")[0]["detail"];
    assert_eq!(closed["detail"]["refusal"], "grant_exhausted");
    // A later episode is blocked while that spent issuance stays unresolved.
    let mut state = harness.state();
    state["last_window_until"] = json!(0);
    fs::write(
        harness.path("state/state.json"),
        serde_json::to_vec(&state).unwrap(),
    )
    .unwrap();
    harness.write_report(&Report {
        first_seen: Some(now_s() - 3),
        ..Report::default()
    });
    assert_eq!(harness.result(), "abstained");
    assert_eq!(harness.abstentions(), ["prior_campaign_unresolved"]);
    assert_eq!(harness.count("ag dispatch"), 1);
    assert_eq!(harness.count("ag init"), 1);
}

#[test]
fn revoked_grant_refuses_dispatch_with_its_reason() {
    let harness = Harness::new();
    harness.control("grant_revoked", "");
    assert_eq!(harness.result(), "dispatch_refused");
    assert_eq!(harness.count("ag dispatch"), 1);
    assert_eq!(harness.effects(), 0);
    let closed = &harness.events("episode_closed")[0]["detail"];
    assert_eq!(closed["detail"]["refusal"], "grant_revoked");
    assert_eq!(
        constellation_remediation_consumer::pass::docket_refusal("executor failed"),
        "docket_refused"
    );
}

#[test]
fn plan_for_another_unit_is_never_presented() {
    let harness = Harness::new();
    harness.write_plan("plan-inactive.json", "sshd.service", "inactive");
    assert_eq!(harness.result(), "abstained");
    assert_eq!(harness.abstentions(), ["plan_not_enrolled"]);
    assert!(harness.calls().iter().all(|line| !line.starts_with("ag ")));
}

#[test]
fn prestate_selects_the_enrolled_plan() {
    let harness = Harness::new();
    harness.write_plan("plan-failed.json", UNIT, "failed");
    harness.write_config(&["inactive", "failed"]);
    harness.control("active_state", "failed");
    assert_eq!(harness.result(), "completed");
    assert_eq!(harness.state()["closed"][0]["prestate"], "failed");
    assert!(harness.calls().contains(&format!(
        "systemctl show --property=ActiveState --value {UNIT}"
    )));
    // A unit that is already active has no enrolled plan: abstain.
    let harness = Harness::new();
    harness.write_plan("plan-failed.json", UNIT, "failed");
    harness.write_config(&["inactive", "failed"]);
    harness.control("active_state", "active");
    assert_eq!(harness.result(), "abstained");
    assert_eq!(harness.abstentions(), ["prestate_not_enrolled"]);
}

#[test]
fn indeterminate_dispatch_is_never_retried() {
    let harness = Harness::new();
    harness.control("dispatch_outcome", "indeterminate");
    assert_eq!(harness.result(), "indeterminate");
    assert_eq!(harness.count("ag continue"), 0);
    assert_eq!(harness.count("ag complete"), 0);
    assert_eq!(
        harness.count("systemctl start constellation-attention.service"),
        0
    );
    assert_eq!(harness.result(), "abstained");
    assert_eq!(harness.abstentions(), ["episode_already_attempted"]);
    assert_eq!(harness.count("ag dispatch"), 1);
    assert_eq!(harness.effects(), 1);
}

#[test]
fn settled_failure_claims_nothing() {
    let harness = Harness::new();
    harness.control("dispatch_outcome", "failure");
    assert_eq!(harness.result(), "settled_failure");
    assert_eq!(harness.count("ag continue"), 0);
    assert_eq!(
        harness.count("systemctl start constellation-attention.service"),
        0
    );
}

#[test]
fn crash_between_authorize_and_dispatch_reconciles_once() {
    let harness = Harness::new();
    harness.control("crash_after_authorize", "");
    assert!(harness.run().is_none(), "the pass should have been killed");
    let state = harness.state();
    assert_eq!(state["active"]["phase"], "driving");
    assert_eq!(state["active"]["dispatch_started"], false);
    assert_eq!(harness.effects(), 0);

    assert_eq!(harness.result(), "completed");
    assert_eq!(harness.count("ag authorize"), 1);
    assert_eq!(harness.count("ag dispatch"), 1);
    assert_eq!(harness.effects(), 1);
    assert_eq!(harness.events("episode_resumed").len(), 1);
}

#[test]
fn crash_after_dispatch_never_dispatches_again() {
    let harness = Harness::new();
    harness.control("crash_in_dispatch", "");
    assert!(harness.run().is_none(), "the pass should have been killed");
    assert_eq!(harness.state()["active"]["dispatch_started"], true);
    assert_eq!(harness.effects(), 1);

    assert_eq!(harness.result(), "completed");
    assert_eq!(harness.count("ag dispatch"), 1);
    assert_eq!(harness.effects(), 1);
}

#[test]
fn crash_after_dispatch_with_lost_custody_reply_closes_without_dispatch() {
    // The fence is set but Docket never accepted: recover reports the
    // issuance absent, and the consumer still does not dispatch again.
    let harness = Harness::new();
    harness.control("crash_after_authorize", "");
    assert!(harness.run().is_none());
    let mut state = harness.state();
    state["active"]["dispatch_started"] = json!(true);
    fs::write(
        harness.path("state/state.json"),
        serde_json::to_vec(&state).unwrap(),
    )
    .unwrap();
    assert_eq!(harness.result(), "dispatch_not_accepted");
    assert_eq!(harness.count("ag dispatch"), 0);
    assert_eq!(harness.effects(), 0);
}

#[test]
fn unproven_postcondition_is_never_claimed() {
    let harness = Harness::new();
    harness.control("post_status", "contradictory");
    assert_eq!(harness.result(), "awaiting_postcondition");
    assert_eq!(harness.count("ag complete"), 0);
    assert_eq!(
        harness.count("systemctl start constellation-attention.service"),
        0
    );
    assert_eq!(harness.count("resolve post contradictory"), 2);
    assert!(harness.events("episode_closed").is_empty());
    assert_eq!(harness.state()["active"]["phase"], "awaiting_postcondition");

    // Still unproven at window expiry: closed without a completion claim.
    let config = harness.config();
    let window_until = harness.state()["active"]["window_until"].as_i64().unwrap();
    let after = u64::try_from(window_until + 1).unwrap() * 1000;
    let summary = run_pass(&config, &|| after).unwrap();
    assert_eq!(summary.result, "postcondition_not_proven");
    assert_eq!(harness.closed_outcomes(), ["postcondition_not_proven"]);
    assert_eq!(harness.count("ag complete"), 0);
    assert_eq!(harness.count("ag continue"), 1);
    assert_eq!(harness.count("ag dispatch"), 1);
}

#[test]
fn postcondition_proven_on_a_later_pass_completes() {
    let harness = Harness::new();
    harness.control("post_status", "stale");
    assert_eq!(harness.result(), "awaiting_postcondition");
    harness.control("post_status", "current");
    assert_eq!(harness.result(), "completed");
    assert_eq!(harness.count("ag continue"), 1);
    assert_eq!(harness.count("ag dispatch"), 1);
    // nq collect is requested once per episode.
    assert_eq!(
        harness.count("nq --config /etc/nq/nqd-ops.toml collect svc-attention-canary"),
        1
    );
}

#[test]
fn a_held_lock_makes_the_pass_busy() {
    let harness = Harness::new();
    assert_eq!(harness.result(), "completed");
    let lock = fs::OpenOptions::new()
        .write(true)
        .open(harness.path("state/lock"))
        .unwrap();
    lock.try_lock().unwrap();
    assert_eq!(harness.result(), "busy");
}

#[test]
fn configuration_refuses_foreign_or_loose_enrolment() {
    let harness = Harness::new();
    let text = fs::read_to_string(harness.path("consumer.toml")).unwrap();
    for (from, to) in [
        ("prestate = \"inactive\"", "prestate = \"active\""),
        (&format!("unit = \"{UNIT}\""), "unit = \"../evil.service\""),
        (
            "postcondition_resolver_id = \"post-resolver/v1\"",
            "postcondition_resolver_id = \"pre-resolver/v1\"",
        ),
    ] {
        fs::write(harness.path("bad.toml"), text.replace(from, to)).unwrap();
        assert!(
            Config::load(&harness.path("bad.toml")).is_err(),
            "{from} -> {to}"
        );
    }
}
