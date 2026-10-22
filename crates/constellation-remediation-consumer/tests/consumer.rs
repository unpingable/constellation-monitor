//! The consumer binary (and, for clock-dependent cases, the library) against
//! fakes for ag-loopctl, the Docket grant resolver, the observation
//! resolvers, nq, systemctl and ag-effectd.

mod common;

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use common::*;
use constellation_remediation_consumer::{Config, run_pass};
use serde_json::{Value, json};

/// Pad the live journal to the production bound without allocating it.
fn fill_journal_sparsely(state_dir: &std::path::Path) {
    use constellation_remediation_consumer::store::MAX_JOURNAL_BYTES;
    fs::OpenOptions::new()
        .write(true)
        .open(state_dir.join("journal.jsonl"))
        .unwrap()
        .set_len(MAX_JOURNAL_BYTES)
        .unwrap();
}

fn listing(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn full_journal_seals_then_the_pass_honours_the_dispatch_fence() {
    use constellation_remediation_consumer::store::MAX_JOURNAL_BYTES;
    let harness = Harness::new();
    harness.control("crash_in_dispatch", "");
    assert!(harness.run().is_none(), "the pass should have been killed");
    let state_dir = harness.path("state");
    let fenced = harness.state()["active"].clone();
    assert_eq!(fenced["dispatch_started"], true);
    assert_eq!(harness.effects(), 1);
    let history = fs::read(state_dir.join("journal.jsonl")).unwrap();
    fill_journal_sparsely(&state_dir);
    let state_before = fs::read(state_dir.join("state.json")).unwrap();
    let episodes_before = listing(&state_dir.join("episodes"));

    assert_eq!(harness.result(), "completed");
    let sealed = state_dir.join("journal.sealed.0001.jsonl");
    assert_eq!(fs::metadata(&sealed).unwrap().len(), MAX_JOURNAL_BYTES);
    let mut prefix = vec![0; history.len()];
    std::io::Read::read_exact(&mut fs::File::open(&sealed).unwrap(), &mut prefix).unwrap();
    assert_eq!(prefix, history);
    let sidecar: Value =
        serde_json::from_slice(&fs::read(state_dir.join("journal.sealed.0001.json")).unwrap())
            .unwrap();
    assert_eq!(sidecar["bytes"], MAX_JOURNAL_BYTES);
    let journal = harness.journal();
    assert_eq!(journal[0]["event"], "journal_sealed");
    assert_eq!(
        journal[0]["detail"]["predecessor"],
        "journal.sealed.0001.jsonl"
    );
    assert_eq!(journal[0]["detail"]["sha256"], sidecar["sha256"]);
    assert_eq!(journal[0]["detail"]["trigger"], "open");
    assert_eq!(journal[1]["event"], "pass_started");
    // The sealing record precedes the pass: the pass read the state the crash
    // left, and its fence held. Only the pass itself changed state.json.
    assert_eq!(journal[1]["episode"], fenced["episode"]);
    assert_ne!(
        fs::read(state_dir.join("state.json")).unwrap(),
        state_before
    );
    assert_eq!(harness.count("ag dispatch"), 1);
    assert_eq!(harness.count("ag authorize"), 1);
    assert_eq!(harness.effects(), 1);
    let closed = &harness.state()["closed"][0];
    assert_eq!(closed["episode"], fenced["episode"]);
    assert_eq!(closed["dispatch_started"], true);
    assert!(listing(&state_dir.join("episodes")).starts_with(&episodes_before));
}

#[test]
fn production_shaped_full_journal_seals_on_an_idle_pass() {
    // 2026-10-21: 67,108,673 bytes, closed episodes only, no active one; the
    // first record of a pass no longer fits under the 64 MiB bound.
    let harness = Harness::new();
    assert_eq!(harness.result(), "completed");
    let state_dir = harness.path("state");
    fs::OpenOptions::new()
        .write(true)
        .open(state_dir.join("journal.jsonl"))
        .unwrap()
        .set_len(67_108_673)
        .unwrap();
    let state_before = fs::read(state_dir.join("state.json")).unwrap();
    let calls_before = harness.calls().len();
    let result = harness.result();
    assert_eq!(
        fs::metadata(state_dir.join("journal.sealed.0001.jsonl"))
            .unwrap()
            .len(),
        67_108_673
    );
    let journal = harness.journal();
    assert_eq!(journal[0]["event"], "journal_sealed");
    assert_eq!(journal[0]["detail"]["bytes"], 67_108_673);
    assert_eq!(journal[1]["event"], "pass_started");
    assert_eq!(journal.last().unwrap()["event"], "pass_finished");
    assert_eq!(journal.last().unwrap()["detail"]["result"], result);
    assert_eq!(harness.effects(), 1);
    assert!(
        harness.calls()[calls_before..]
            .iter()
            .all(|line| line != "ag dispatch" && line != "ag authorize")
    );
    let state: Value = serde_json::from_slice(&state_before).unwrap();
    assert!(state["active"].is_null());
    assert_eq!(harness.state()["closed"], state["closed"]);
}

#[test]
fn exhausted_sealed_generations_refuse_before_external_commands() {
    use constellation_remediation_consumer::store::{
        Episode, MAX_JOURNAL_BYTES, MAX_SEALED_JOURNALS, State,
    };
    let harness = Harness::new();
    let state_dir = harness.path("state");
    // Written directly: holding the Store lock in this process would race the
    // pass's own lock against children forked by concurrent tests.
    fs::create_dir(&state_dir).unwrap();
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let state = State {
        active: Some(Episode {
            episode: "retained-episode".into(),
            campaign: "retained-campaign".into(),
            dispatch_started: true,
            attempt: Some("retained-attempt".into()),
            ..Episode::default()
        }),
        ..State::default()
    };
    fs::write(
        state_dir.join("state.json"),
        serde_json::to_vec_pretty(&state).unwrap(),
    )
    .unwrap();
    fs::write(state_dir.join("journal.jsonl"), b"").unwrap();
    fs::write(state_dir.join("lock"), b"").unwrap();
    for sequence in 1..=MAX_SEALED_JOURNALS {
        fs::write(
            state_dir.join(format!("journal.sealed.{sequence:04}.jsonl")),
            b"",
        )
        .unwrap();
    }
    fill_journal_sparsely(&state_dir);
    let state_before = fs::read(state_dir.join("state.json")).unwrap();
    let names_before = listing(&state_dir);
    let inode = fs::metadata(state_dir.join("journal.jsonl")).unwrap().ino();
    let error = run_pass(&harness.config(), &|| 0).unwrap_err();
    assert!(error.contains("journal capacity exhausted"), "{error}");
    assert!(
        error.contains("sealed journal generations exhausted"),
        "{error}"
    );
    assert!(harness.calls().is_empty());
    assert_eq!(
        fs::read(state_dir.join("state.json")).unwrap(),
        state_before
    );
    assert_eq!(
        fs::metadata(state_dir.join("journal.jsonl")).unwrap().len(),
        MAX_JOURNAL_BYTES
    );
    assert_eq!(listing(&state_dir), names_before);
    assert_eq!(
        fs::metadata(state_dir.join("journal.jsonl")).unwrap().ino(),
        inode
    );
}

#[test]
fn config_check_reports_journal_bound_without_opening_state() {
    let harness = Harness::new();
    assert!(!harness.path("state").exists());
    let output =
        std::process::Command::new(env!("CARGO_BIN_EXE_constellation-remediation-consumer"))
            .arg("--config")
            .arg(harness.path("consumer.toml"))
            .arg("--check-config")
            .output()
            .unwrap();
    assert!(output.status.success(), "{output:?}");
    let checked: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(checked["journal_max_bytes"], 64 * 1024 * 1024);
    assert_eq!(checked["journal_max_sealed"], 16);
    assert_eq!(checked["journal_sealed_present"], 0);
    assert!(!harness.path("state").exists());
    assert!(harness.calls().is_empty());
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

fn report_revision(harness: &Harness, version: u32, digest: char) -> Value {
    let path = harness.path("report.json");
    let mut report: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    report["rules"] = json!([{"id":"service-down", "version":version}]);
    report["attention_policy_digest"] = json!(format!("sha256:{}", digest.to_string().repeat(64)));
    fs::write(path, serde_json::to_vec(&report).unwrap()).unwrap();
    json!({"rule":"service-down", "version":version, "attention_policy_digest":report["attention_policy_digest"]})
}

#[test]
fn opening_revision_survives_resume_under_a_changed_report() {
    let harness = Harness::new();
    let opening = report_revision(&harness, 2, 'a');
    let golden: Value =
        serde_json::from_slice(include_bytes!("fixtures/rule-revision-v1.json")).unwrap();
    assert_eq!(opening, golden);
    harness.control("crash_after_authorize", "");
    assert!(harness.run().is_none());
    assert!(harness.state()["active"].get("rule_revision").is_none());
    assert_eq!(
        harness.events("episode_opened")[0]["detail"]["rule_revision"],
        opening
    );
    report_revision(&harness, 3, 'b');
    assert_eq!(harness.result(), "completed");
    assert!(harness.state()["closed"][0].get("rule_revision").is_none());
    assert_eq!(
        harness.events("episode_opened")[0]["detail"]["rule_revision"],
        opening
    );
    assert_eq!(harness.effects(), 1);
}

#[test]
fn legacy_episode_is_not_backfilled_from_a_current_report() {
    let harness = Harness::new();
    harness.control("crash_after_authorize", "");
    assert!(harness.run().is_none());
    let mut journal = harness.journal();
    for record in &mut journal {
        if record["event"] == "episode_opened" {
            record["detail"]
                .as_object_mut()
                .unwrap()
                .remove("rule_revision");
        }
    }
    let bytes = journal
        .iter()
        .map(|r| serde_json::to_string(r).unwrap() + "\n")
        .collect::<String>();
    fs::write(harness.path("state/journal.jsonl"), bytes).unwrap();
    report_revision(&harness, 7, 'c');
    assert_eq!(harness.result(), "completed");
    assert!(harness.state()["closed"][0].get("rule_revision").is_none());
    assert!(
        harness.events("episode_opened")[0]["detail"]
            .get("rule_revision")
            .is_none()
    );
    assert_eq!(harness.effects(), 1);
}

#[test]
fn missing_or_ambiguous_revision_does_not_change_execution_admission() {
    for variant in ["missing", "duplicate", "bad_digest", "zero"] {
        let harness = Harness::new();
        report_revision(&harness, 2, 'a');
        let path = harness.path("report.json");
        let mut report: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        match variant {
            "missing" => {
                report.as_object_mut().unwrap().remove("rules");
            }
            "duplicate" => {
                report["rules"] =
                    json!([{"id":"service-down","version":2},{"id":"service-down","version":3}]);
            }
            "bad_digest" => {
                report["attention_policy_digest"] = json!("unknown");
            }
            _ => {
                report["rules"][0]["version"] = json!(0);
            }
        }
        fs::write(path, serde_json::to_vec(&report).unwrap()).unwrap();
        assert_eq!(harness.result(), "completed", "{variant}");
        assert!(harness.state()["closed"][0].get("rule_revision").is_none());
        assert!(harness.events("episode_opened")[0]["detail"]["rule_revision"].is_null());
        assert_eq!(ag_and_trigger_calls(&harness), AG_HAPPY);
        assert_eq!(harness.effects(), 1);
    }
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
        // Below the rule's bound (or after the page was sent) the evaluator
        // holds no page: there is nothing to remediate before a human sees it.
        (
            Report {
                page_deferred: false,
                ..Report::default()
            },
            "page_not_deferred",
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
    // Inside the window it keeps asking AG's recover, never dispatching.
    assert_eq!(harness.result(), "pending");
    assert_eq!(harness.count("ag dispatch"), 0);
    // At window end it closes without a claim.
    let config = harness.config();
    let window_until = harness.state()["active"]["window_until"].as_i64().unwrap();
    let after = u64::try_from(window_until + 1).unwrap() * 1000;
    assert_eq!(
        run_pass(&config, &|| after).unwrap().result,
        "dispatch_not_accepted"
    );
    assert_eq!(harness.count("ag dispatch"), 0);
    assert_eq!(harness.effects(), 0);
}

/// Review F4: a dispatch error that is not Docket's refusal (a timeout, an
/// unreachable boundary) never closes the episode as refused; the next
/// passes keep asking AG's recover and never dispatch again.
#[test]
fn unconfirmed_dispatch_error_keeps_driving() {
    let harness = Harness::new();
    harness.control("dispatch_unavailable", "");
    assert_eq!(harness.result(), "pending");
    assert!(!harness.events("dispatch_unconfirmed").is_empty());
    assert!(harness.closed_outcomes().is_empty());
    assert_eq!(harness.result(), "pending");
    assert_eq!(harness.count("ag dispatch"), 1);
    assert_eq!(harness.effects(), 0);
}

/// Review F4: a timed-out command's whole process group is killed, so no
/// descendant can complete an effect after the consumer gave up on it.
#[test]
fn timeout_kills_the_whole_process_group() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("late-effect");
    let script = dir.path().join("slow.sh");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\n( sleep 2; touch '{}' ) &\nsleep 30\n",
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    let failure = constellation_remediation_consumer::external::run(
        &script,
        &[],
        None,
        std::time::Duration::from_secs(1),
    )
    .unwrap_err();
    assert!(failure.message.contains("timed out"), "{}", failure.message);
    std::thread::sleep(std::time::Duration::from_secs(3));
    assert!(!marker.exists(), "a descendant survived the timeout");
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

/// Review F2: a current "active" answer from a sample taken before the dwell
/// after Docket's settlement never completes.
#[test]
fn postcondition_sample_before_the_dwell_is_never_claimed() {
    let harness = Harness::new();
    // Settled 60 s ago; dwell 15 s; the newest sample is 100 s old.
    harness.control("sample_offset_s", "-100");
    assert_eq!(harness.result(), "awaiting_postcondition");
    assert_eq!(harness.count("ag complete"), 0);
    assert!(!harness.events("postcondition_before_dwell").is_empty());
    // A fresh sample after the dwell completes.
    fs::remove_file(harness.path("fake/sample_offset_s")).unwrap();
    assert_eq!(harness.result(), "completed");
    assert_eq!(harness.count("ag complete"), 1);
}

/// The consumer waits out the dwell after a settlement it has just seen.
#[test]
fn postcondition_waits_for_the_dwell_after_settlement() {
    let harness = Harness::new();
    harness.control("settled_ago_ms", "0");
    let started = std::time::Instant::now();
    assert_eq!(harness.result(), "completed");
    assert!(started.elapsed() >= std::time::Duration::from_secs(5));
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

fn last_pass(harness: &Harness) -> Value {
    serde_json::from_slice(&fs::read(harness.path("state/last-pass.json")).unwrap()).unwrap()
}

fn clear(harness: &Harness) {
    harness.write_report(&Report {
        observation: "clear",
        page_deferred: false,
        ..Report::default()
    });
}

#[test]
fn idle_pass_journals_nothing_and_rewrites_last_pass() {
    let harness = Harness::new();
    clear(&harness);
    assert_eq!(harness.result(), "abstained");
    assert!(harness.journal().is_empty(), "{:#?}", harness.journal());
    assert!(harness.calls().is_empty(), "{:?}", harness.calls());
    let first = last_pass(&harness);
    assert_eq!(
        first["schema"],
        "constellation.remediation-consumer.last-pass/v1"
    );
    assert_eq!(first["result"], "abstained");
    assert_eq!(first["abstain_reason"], "observation_not_present");
    assert_eq!(first["idle"], true);
    assert_eq!(first["consecutive_idle_passes"], 1);
    assert_eq!(first["idle_since"], first["at"]);
    assert_eq!(first["idle_unsummarized"]["count"], 1);
    assert_eq!(first["journal_bytes"], 0);
    assert_eq!(first["sealed_segments"], 0);
    assert_eq!(first["journal_max_bytes"], 64 * 1024 * 1024);
    assert_eq!(first["max_sealed_journals"], 16);
    let mode = fs::metadata(harness.path("state/last-pass.json"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);

    assert_eq!(harness.result(), "abstained");
    assert!(harness.journal().is_empty());
    let second = last_pass(&harness);
    assert_ne!(second["pass"], first["pass"]);
    assert_eq!(second["consecutive_idle_passes"], 2);
    assert_eq!(second["idle_since"], first["at"]);
    assert_eq!(second["idle_unsummarized"]["count"], 2);
    assert_eq!(
        second["idle_unsummarized"]["first_at"],
        first["idle_unsummarized"]["first_at"]
    );
    // state.json is neither created nor changed by idle passes.
    assert!(!harness.path("state/state.json").exists());
}

#[test]
fn condition_present_pass_journals_and_ends_the_idle_streak_with_a_summary() {
    let harness = Harness::new();
    clear(&harness);
    assert_eq!(harness.result(), "abstained");
    assert_eq!(harness.result(), "abstained");
    let idle = last_pass(&harness);
    harness.write_report(&Report::default());
    assert_eq!(harness.result(), "completed");
    let journal = harness.journal();
    assert_eq!(journal[0]["event"], "idle_summary");
    let summary = &journal[0]["detail"];
    assert_eq!(summary["trigger"], "streak_ended");
    assert_eq!(summary["count"], 2);
    assert_eq!(summary["first_at"], idle["idle_unsummarized"]["first_at"]);
    assert_eq!(summary["last_at"], idle["at"]);
    assert_eq!(summary["last_reason"], "observation_not_present");
    assert_eq!(summary["consecutive_idle_passes"], 2);
    assert_eq!(summary["idle_since"], idle["idle_since"]);
    assert_eq!(journal[1]["event"], "pass_started");
    assert!(
        journal
            .iter()
            .any(|record| record["event"] == "episode_opened")
    );
    assert_eq!(journal.last().unwrap()["event"], "pass_finished");
    assert_eq!(harness.events("idle_summary").len(), 1);
    let after = last_pass(&harness);
    assert_eq!(after["result"], "completed");
    assert_eq!(after["idle"], false);
    assert!(after["abstain_reason"].is_null());
    assert_eq!(after["consecutive_idle_passes"], 0);
    assert!(after["idle_since"].is_null());
    assert!(after["idle_unsummarized"].is_null());
    assert_eq!(
        after["journal_bytes"],
        fs::metadata(harness.path("state/journal.jsonl"))
            .unwrap()
            .len()
    );

    // A later streak starts afresh; the condition is clear again.
    clear(&harness);
    let length = harness.journal().len();
    assert_eq!(harness.result(), "abstained");
    assert_eq!(harness.journal().len(), length);
    assert_eq!(last_pass(&harness)["consecutive_idle_passes"], 1);
}

#[test]
fn idle_streak_is_summarized_at_most_hourly() {
    let harness = Harness::new();
    clear(&harness);
    assert_eq!(harness.result(), "abstained");
    // Backdate the unsummarized window: its first pass an hour and a second
    // ago, five passes in it.
    let path = harness.path("state/last-pass.json");
    let mut record = last_pass(&harness);
    let first_ms = record["at_unix_ms"].as_u64().unwrap() - 3_601_000;
    let first_at = rfc3339(i64::try_from(first_ms / 1000).unwrap());
    record["consecutive_idle_passes"] = json!(5);
    record["idle_since"] = json!(first_at);
    record["idle_since_unix_ms"] = json!(first_ms);
    record["idle_unsummarized"]["count"] = json!(5);
    record["idle_unsummarized"]["first_at"] = json!(first_at);
    record["idle_unsummarized"]["first_at_unix_ms"] = json!(first_ms);
    fs::write(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();

    assert_eq!(harness.result(), "abstained");
    let journal = harness.journal();
    assert_eq!(journal.len(), 1, "{journal:#?}");
    assert_eq!(journal[0]["event"], "idle_summary");
    let summary = &journal[0]["detail"];
    assert_eq!(summary["trigger"], "hourly");
    assert_eq!(summary["count"], 6);
    assert_eq!(summary["first_at"], first_at);
    assert_eq!(summary["consecutive_idle_passes"], 6);
    assert_eq!(summary["idle_since"], first_at);
    assert_eq!(summary["last_reason"], "observation_not_present");
    let after = last_pass(&harness);
    assert_eq!(after["consecutive_idle_passes"], 6);
    assert_eq!(after["idle_since"], first_at);
    assert!(after["idle_unsummarized"].is_null());

    // Within the hour after a summary nothing more is journaled.
    assert_eq!(harness.result(), "abstained");
    assert_eq!(harness.journal().len(), 1);
    let next = last_pass(&harness);
    assert_eq!(next["consecutive_idle_passes"], 7);
    assert_eq!(next["idle_unsummarized"]["count"], 1);
}

#[test]
fn abstentions_that_are_not_a_clear_condition_are_journaled() {
    let cases = [
        (
            Report {
                observation: "clear",
                nq_status: "not_current",
                ..Report::default()
            },
            "nq_input_not_ok",
        ),
        (
            Report {
                observation: "clear",
                age: 130,
                ..Report::default()
            },
            "report_stale",
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
                observation: "removed",
                ..Report::default()
            },
            "observation_not_present",
        ),
        (
            Report {
                page_deferred: false,
                ..Report::default()
            },
            "page_not_deferred",
        ),
    ];
    for (report, reason) in cases {
        let harness = Harness::new();
        clear(&harness);
        assert_eq!(harness.result(), "abstained");
        harness.write_report(&report);
        assert_eq!(harness.result(), "abstained");
        let events: Vec<String> = harness
            .journal()
            .iter()
            .map(|record| record["event"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            events,
            ["idle_summary", "pass_started", "abstained", "pass_finished"],
            "{reason}"
        );
        assert_eq!(harness.abstentions(), [reason]);
        let record = last_pass(&harness);
        assert_eq!(record["idle"], false, "{reason}");
        assert_eq!(record["abstain_reason"], reason);
        assert_eq!(record["consecutive_idle_passes"], 0);
    }
    // An unreadable report is not idle either.
    let harness = Harness::new();
    fs::remove_file(harness.path("report.json")).unwrap();
    assert_eq!(harness.result(), "abstained");
    assert_eq!(harness.abstentions(), ["report_unreadable"]);
    assert_eq!(last_pass(&harness)["idle"], false);
}

#[test]
fn a_store_fault_is_recorded_as_a_fault_in_last_pass() {
    let harness = Harness::new();
    clear(&harness);
    assert_eq!(harness.result(), "abstained");
    fs::write(harness.path("state/state.json"), b"{not json").unwrap();
    let error = run_pass(&harness.config(), &|| 1_792_597_797_140).unwrap_err();
    assert!(error.contains("state.json"), "{error}");
    let record = last_pass(&harness);
    assert_eq!(record["result"], "fault");
    assert!(record["error"].as_str().unwrap().contains("state.json"));
    assert_eq!(record["idle"], false);
    assert_eq!(record["consecutive_idle_passes"], 0);
    // The idle pass not yet summarized is kept for the next journaled pass.
    assert_eq!(record["idle_unsummarized"]["count"], 1);
    assert!(harness.journal().is_empty());
}

fn status(harness: &Harness) -> Value {
    let output =
        std::process::Command::new(env!("CARGO_BIN_EXE_constellation-remediation-consumer"))
            .arg("--config")
            .arg(harness.path("consumer.toml"))
            .arg("--status")
            .output()
            .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

/// `(local_state, reason)` per concern id, in document order.
fn concerns(document: &Value) -> Vec<(String, String, String)> {
    document["concerns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|concern| {
            assert_eq!(concern["required"], true);
            assert_eq!(concern["observation"]["observation_present"], true);
            (
                concern["id"].as_str().unwrap().to_owned(),
                concern["observation"]["local_state"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
                concern["observation"]["reason"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            )
        })
        .collect()
}

fn states(document: &Value) -> Vec<String> {
    concerns(document)
        .into_iter()
        .map(|(_, state, _)| state)
        .collect()
}

/// Every name in the state directory with its length and modification time.
fn snapshot(dir: &std::path::Path) -> Vec<(String, u64, std::time::SystemTime)> {
    listing(dir)
        .into_iter()
        .map(|name| {
            let metadata = fs::symlink_metadata(dir.join(&name)).unwrap();
            (name, metadata.len(), metadata.modified().unwrap())
        })
        .collect()
}

#[test]
fn status_without_any_pass_reports_the_pass_concerns_absent() {
    let harness = Harness::new();
    let document = status(&harness);
    assert_eq!(document["schema"], "project.ops.status/v1");
    assert_eq!(document["project"], "constellation-remediation-consumer");
    let found = concerns(&document);
    let ids: Vec<&str> = found.iter().map(|(id, _, _)| id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "remediation.consumer.pass-fresh",
            "remediation.consumer.pass-succeeding",
            "remediation.journal.generations-headroom",
            "remediation.journal.generations-critical",
            "remediation.consumer.inputs-ok",
        ]
    );
    assert_eq!(
        states(&document),
        ["ABSENT", "ABSENT", "PRESENT", "PRESENT", "ABSENT"]
    );
    assert!(found[0].2.contains("last-pass.json"), "{}", found[0].2);
    // Nothing is created.
    assert!(!harness.path("state").exists());

    fs::create_dir(harness.path("state")).unwrap();
    fs::set_permissions(harness.path("state"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(harness.path("state/last-pass.json"), b"{\"schema\":").unwrap();
    let document = status(&harness);
    assert_eq!(&states(&document)[..2], ["ABSENT", "ABSENT"]);
    assert!(concerns(&document)[1].2.contains("last-pass.json"));
}

#[test]
fn status_after_an_idle_pass_is_present_and_changes_nothing() {
    let harness = Harness::new();
    clear(&harness);
    assert_eq!(harness.result(), "abstained");
    assert_eq!(harness.result(), "abstained");
    let state_dir = harness.path("state");
    let before = snapshot(&state_dir);
    // No lock is taken: a pass holding it does not stop the status.
    let lock = fs::OpenOptions::new()
        .write(true)
        .open(state_dir.join("lock"))
        .unwrap();
    lock.try_lock().unwrap();
    let document = status(&harness);
    drop(lock);
    assert_eq!(states(&document), ["PRESENT"; 5]);
    let record = last_pass(&harness);
    let extension = &document["extensions"]["constellation.remediation-consumer"];
    assert_eq!(extension["idle_since"], record["idle_since"]);
    assert_eq!(extension["consecutive_idle_passes"], 2);
    assert_eq!(extension["sealed_segments"], 0);
    assert_eq!(extension["journal_bytes"], 0);
    assert_eq!(extension["last_result"], "abstained");
    let succeeding = &document["concerns"][1]["observation"];
    assert_eq!(succeeding["observed_at"], record["at"]);
    assert_eq!(succeeding["valid_for_seconds"], 120);
    assert_eq!(succeeding["facts"]["idle"], true);
    assert_eq!(snapshot(&state_dir), before);
}

#[test]
fn status_reports_a_stale_or_failed_last_pass() {
    let harness = Harness::new();
    clear(&harness);
    assert_eq!(harness.result(), "abstained");
    let path = harness.path("state/last-pass.json");
    let mut record = last_pass(&harness);
    let old = record["at_unix_ms"].as_u64().unwrap() - 200_000;
    record["at_unix_ms"] = json!(old);
    record["at"] = json!(rfc3339(i64::try_from(old / 1000).unwrap()));
    fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
    let document = status(&harness);
    assert_eq!(
        states(&document),
        ["ABSENT", "PRESENT", "PRESENT", "PRESENT", "PRESENT"]
    );
    assert!(concerns(&document)[0].2.contains("s ago"));

    fs::write(harness.path("state/state.json"), b"{not json").unwrap();
    run_pass(&harness.config(), &|| now_ms()).unwrap_err();
    let document = status(&harness);
    assert_eq!(
        states(&document),
        ["PRESENT", "ABSENT", "PRESENT", "PRESENT", "UNKNOWN"]
    );
    assert!(
        concerns(&document)[1].2.contains("state.json"),
        "{:?}",
        concerns(&document)[1]
    );
}

fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

#[test]
fn status_counts_sealed_generations_against_custody_and_critical_thresholds() {
    let harness = Harness::new();
    clear(&harness);
    assert_eq!(harness.result(), "abstained");
    let state_dir = harness.path("state");
    let seal = |sequence: usize| {
        fs::write(
            state_dir.join(format!("journal.sealed.{sequence:04}.jsonl")),
            b"",
        )
        .unwrap();
        fs::write(
            state_dir.join(format!("journal.sealed.{sequence:04}.json")),
            b"{}",
        )
        .unwrap();
    };
    for sequence in 1..=11 {
        seal(sequence);
    }
    assert_eq!(states(&status(&harness))[2..4], ["PRESENT", "PRESENT"]);
    seal(12);
    let document = status(&harness);
    assert_eq!(states(&document)[2..4], ["ABSENT", "PRESENT"]);
    assert!(concerns(&document)[2].2.contains("12 sealed segments"));
    seal(13);
    seal(14);
    assert_eq!(states(&status(&harness))[2..4], ["ABSENT", "PRESENT"]);
    seal(15);
    let document = status(&harness);
    assert_eq!(states(&document)[2..4], ["ABSENT", "ABSENT"]);
    assert_eq!(
        document["extensions"]["constellation.remediation-consumer"]["sealed_segments"],
        15
    );
}

fn events(harness: &Harness) -> Vec<String> {
    harness
        .journal()
        .iter()
        .map(|record| record["event"].as_str().unwrap().to_owned())
        .collect()
}

fn failing_inputs(harness: &Harness, status: &'static str) {
    harness.write_report(&Report {
        nq_status: status,
        ..Report::default()
    });
}

#[test]
fn a_streak_of_identical_input_failures_journals_once_then_summarizes() {
    let harness = Harness::new();
    failing_inputs(&harness, "not_current");
    for _ in 0..3 {
        assert_eq!(harness.result(), "abstained");
    }
    // The onset is journaled in full; the repeats only rewrite last-pass.json.
    assert_eq!(
        events(&harness),
        ["pass_started", "abstained", "pass_finished"]
    );
    assert!(harness.calls().is_empty(), "{:?}", harness.calls());
    let record = last_pass(&harness);
    assert_eq!(record["abstain_reason"], "nq_input_not_ok");
    assert_eq!(record["idle"], false);
    assert_eq!(record["repeat_reason"], "nq_input_not_ok");
    assert_eq!(record["repeat_count"], 3);
    assert_eq!(
        record["repeat_detail"]["not_ok"],
        json!([{"label": "nq-ops", "status": "not_current"}])
    );
    assert_eq!(record["repeat_unsummarized"]["count"], 2);
    let since = record["repeat_since"].as_str().unwrap().to_owned();

    // The judged abstention still succeeds; the inputs concern does not.
    let document = status(&harness);
    assert_eq!(
        states(&document),
        ["PRESENT", "PRESENT", "PRESENT", "PRESENT", "ABSENT"]
    );
    let extension = &document["extensions"]["constellation.remediation-consumer"];
    assert_eq!(extension["repeat_reason"], "nq_input_not_ok");
    assert_eq!(extension["repeat_count"], 3);
    assert_eq!(extension["repeat_since"], since);
    assert!(concerns(&document)[4].2.contains("nq_input_not_ok"));
    assert!(concerns(&document)[1].2.contains("3 passes since"));

    // At most hourly, a summary of the repeats.
    let path = harness.path("state/last-pass.json");
    let mut record = last_pass(&harness);
    let old = record["at_unix_ms"].as_u64().unwrap() - 3_601_000;
    record["repeat_unsummarized"]["first_at_unix_ms"] = json!(old);
    fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
    assert_eq!(harness.result(), "abstained");
    let journal = harness.journal();
    assert_eq!(journal.len(), 4);
    let summary = &journal[3];
    assert_eq!(summary["event"], "abstention_summary");
    assert!(summary["episode"].is_null());
    assert_eq!(summary["detail"]["trigger"], "hourly");
    assert_eq!(summary["detail"]["reason"], "nq_input_not_ok");
    assert_eq!(summary["detail"]["count"], 3);
    assert_eq!(summary["detail"]["repeat_count"], 4);
    assert_eq!(summary["detail"]["repeat_since"], since);
    assert_eq!(summary["detail"]["detail"], record["repeat_detail"]);
    assert!(last_pass(&harness)["repeat_unsummarized"].is_null());
    assert_eq!(harness.result(), "abstained");
    assert_eq!(harness.journal().len(), 4);

    // The condition clears: the streak ends with a summary, the idle streak
    // starts, and the inputs concern recovers.
    clear(&harness);
    assert_eq!(harness.result(), "abstained");
    let journal = harness.journal();
    assert_eq!(journal.len(), 5);
    assert_eq!(journal[4]["event"], "abstention_summary");
    assert_eq!(journal[4]["detail"]["trigger"], "streak_ended");
    assert_eq!(journal[4]["detail"]["count"], 1);
    assert_eq!(journal[4]["detail"]["repeat_count"], 5);
    let record = last_pass(&harness);
    assert_eq!(record["idle"], true);
    assert_eq!(record["consecutive_idle_passes"], 1);
    assert!(record["repeat_reason"].is_null());
    assert_eq!(record["repeat_count"], 0);
    assert!(record["repeat_unsummarized"].is_null());
    assert_eq!(states(&status(&harness)), ["PRESENT"; 5]);

    // Back to failing inputs: the idle streak ends with its summary and the
    // new abstention streak starts with a full record.
    failing_inputs(&harness, "not_current");
    assert_eq!(harness.result(), "abstained");
    assert_eq!(
        events(&harness)[5..],
        ["idle_summary", "pass_started", "abstained", "pass_finished"]
    );
    assert_eq!(last_pass(&harness)["repeat_count"], 1);
}

#[test]
fn a_changed_cause_starts_a_new_streak_with_a_full_record() {
    let harness = Harness::new();
    failing_inputs(&harness, "not_current");
    assert_eq!(harness.result(), "abstained");
    assert_eq!(harness.result(), "abstained");
    failing_inputs(&harness, "failed");
    assert_eq!(harness.result(), "abstained");
    assert_eq!(
        events(&harness),
        [
            "pass_started",
            "abstained",
            "pass_finished",
            "abstention_summary",
            "pass_started",
            "abstained",
            "pass_finished"
        ]
    );
    let journal = harness.journal();
    assert_eq!(journal[3]["detail"]["trigger"], "streak_ended");
    assert_eq!(journal[3]["detail"]["count"], 1);
    assert_eq!(
        journal[5]["detail"]["detail"]["not_ok"],
        json!([{"label": "nq-ops", "status": "failed"}])
    );
    let record = last_pass(&harness);
    assert_eq!(record["repeat_count"], 1);
    assert_eq!(
        record["repeat_detail"]["not_ok"],
        json!([{"label": "nq-ops", "status": "failed"}])
    );
    assert!(record["repeat_unsummarized"].is_null());

    // Another reason is another cause; a growing report age is not.
    harness.write_report(&Report {
        age: 130,
        ..Report::default()
    });
    assert_eq!(harness.result(), "abstained");
    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert_eq!(harness.result(), "abstained");
    assert_eq!(harness.abstentions().len(), 3);
    assert_eq!(harness.abstentions()[2], "report_stale");
    let record = last_pass(&harness);
    assert_eq!(record["repeat_reason"], "report_stale");
    assert_eq!(record["repeat_count"], 2);
    assert!(record["repeat_detail"].get("age_seconds").is_none());
    assert!(record["repeat_detail"]["evaluated_at"].is_string());
    assert_eq!(states(&status(&harness))[4], "ABSENT");
}

#[test]
fn an_opened_episode_ends_a_repeated_abstention_streak() {
    let harness = Harness::new();
    failing_inputs(&harness, "not_current");
    assert_eq!(harness.result(), "abstained");
    assert_eq!(harness.result(), "abstained");
    harness.write_report(&Report::default());
    assert_eq!(harness.result(), "completed");
    let journal = harness.journal();
    assert_eq!(journal[3]["event"], "abstention_summary");
    assert_eq!(journal[3]["detail"]["trigger"], "streak_ended");
    assert_eq!(journal[4]["event"], "pass_started");
    let record = last_pass(&harness);
    assert!(record["repeat_reason"].is_null());
    assert_eq!(record["result"], "completed");
}
