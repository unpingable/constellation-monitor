//! The consumer binary (and, for clock-dependent cases, the library) against
//! fakes for ag-loopctl, the Docket grant resolver, the observation
//! resolvers, nq, systemctl and ag-effectd.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt as _;

use common::*;
use constellation_remediation_consumer::{Config, run_pass};
use serde_json::{Value, json};

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
