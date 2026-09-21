use pulse_replay::{ReplayReportV1, run_jsonl};
use pulse_types::{
    CoverageDimensionV1, FreshnessDimensionV1, INCOMPLETE_COVERAGE_EXPLANATION, JudgmentCategoryV1,
    ObserverAvailabilityDimensionV1, SequenceContinuityDimensionV1,
    SubjectSignalConsistencyDimensionV1, TransportDimensionV1,
};

const HOSTILE: &[(&str, &str)] = &[
    (
        "packet-loss",
        include_str!("../../../traces/packet-loss.jsonl"),
    ),
    (
        "duplication",
        include_str!("../../../traces/duplication.jsonl"),
    ),
    (
        "reordering",
        include_str!("../../../traces/reordering.jsonl"),
    ),
    (
        "delayed-stale-delivery",
        include_str!("../../../traces/delayed-stale-delivery.jsonl"),
    ),
    (
        "sequence-gap",
        include_str!("../../../traces/sequence-gap.jsonl"),
    ),
    (
        "observer-restart",
        include_str!("../../../traces/observer-restart.jsonl"),
    ),
    (
        "subject-restart",
        include_str!("../../../traces/subject-restart.jsonl"),
    ),
    (
        "clock-discontinuity",
        include_str!("../../../traces/clock-discontinuity.jsonl"),
    ),
    (
        "network-partition",
        include_str!("../../../traces/network-partition.jsonl"),
    ),
    (
        "observer-disagreement",
        include_str!("../../../traces/observer-disagreement.jsonl"),
    ),
    (
        "stale-replay",
        include_str!("../../../traces/stale-replay.jsonl"),
    ),
    (
        "common-cause-failure",
        include_str!("../../../traces/common-cause-failure.jsonl"),
    ),
    (
        "monitor-overload",
        include_str!("../../../traces/monitor-overload.jsonl"),
    ),
    (
        "coverage-collapse",
        include_str!("../../../traces/coverage-collapse.jsonl"),
    ),
    (
        "lying-self-report",
        include_str!("../../../traces/lying-self-report.jsonl"),
    ),
    (
        "escalation-storm",
        include_str!("../../../traces/escalation-storm.jsonl"),
    ),
];

fn report(name: &str) -> ReplayReportV1 {
    let (_, trace) = HOSTILE
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .expect("named hostile trace exists");
    run_jsonl(trace).unwrap_or_else(|error| panic!("{name} replay failed: {error}"))
}

#[test]
fn previously_positive_judgment_expires_after_pulse_loss() {
    let report = report("packet-loss");
    assert!(
        report
            .transitions
            .iter()
            .any(|transition| transition.category == JudgmentCategoryV1::Current)
    );
    assert_eq!(report.final_judgment.category, JudgmentCategoryV1::Unknown);
    assert_eq!(report.metrics.failure_to_unknown_latency_ms, Some(50));
    assert_eq!(report.metrics.failure_to_escalation_latency_ms, Some(50));
}

#[test]
fn delayed_and_duplicate_packets_never_refresh_expiry() {
    let delayed = report("delayed-stale-delivery");
    assert_eq!(delayed.final_judgment.category, JudgmentCategoryV1::Unknown);
    assert_eq!(delayed.metrics.dropped_stale_pulse_count, 1);

    let duplicate = report("duplication");
    assert_eq!(
        duplicate.final_judgment.category,
        JudgmentCategoryV1::Unknown
    );
    assert_eq!(duplicate.metrics.duplicate_count, 1);
}

#[test]
fn reorder_cannot_erase_newer_contradiction() {
    let report = report("reordering");
    assert_eq!(
        report.final_judgment.category,
        JudgmentCategoryV1::Contradicted
    );
    assert_eq!(report.metrics.dropped_stale_pulse_count, 1);
}

#[test]
fn observer_restart_has_a_distinct_noninherited_lineage() {
    let report = report("observer-restart");
    assert!(report.transitions.iter().any(|transition| {
        transition.category == JudgmentCategoryV1::Degraded
            && transition.dimensions.sequence_continuity == SequenceContinuityDimensionV1::Restarted
    }));
    assert_eq!(report.final_judgment.category, JudgmentCategoryV1::Current);
}

#[test]
fn sequence_gap_and_subject_restart_remain_explicit() {
    let gap = report("sequence-gap");
    assert_eq!(gap.final_judgment.category, JudgmentCategoryV1::Degraded);
    assert_eq!(gap.metrics.sequence_gap_count, 1);
    assert_eq!(
        gap.final_judgment.dimensions.sequence_continuity,
        SequenceContinuityDimensionV1::Gapped
    );

    let restart = report("subject-restart");
    assert_eq!(
        restart.final_judgment.category,
        JudgmentCategoryV1::Contradicted
    );
    assert!(
        restart
            .final_judgment
            .explanation
            .reasons
            .iter()
            .any(|reason| { reason.code == "contradiction_retained" })
    );
    assert_eq!(restart.metrics.dropped_stale_pulse_count, 1);
}

#[test]
fn majority_does_not_erase_grounded_disagreement() {
    let report = report("observer-disagreement");
    assert_eq!(
        report.final_judgment.category,
        JudgmentCategoryV1::Contradicted
    );
    assert!(
        report
            .final_judgment
            .explanation
            .reasons
            .iter()
            .any(|reason| { reason.code == "contradiction_retained" })
    );
}

#[test]
fn incomplete_coverage_is_exactly_unknown() {
    let report = report("coverage-collapse");
    assert_eq!(report.final_judgment.category, JudgmentCategoryV1::Unknown);
    assert_eq!(
        report.final_judgment.explanation.summary,
        INCOMPLETE_COVERAGE_EXPLANATION
    );
    assert_eq!(report.final_judgment.coverage.missing, vec!["memory"]);
}

#[test]
fn monitor_overload_reports_blindness() {
    let report = report("monitor-overload");
    assert_eq!(report.final_judgment.category, JudgmentCategoryV1::Unknown);
    assert_eq!(
        report.final_judgment.dimensions.transport,
        TransportDimensionV1::Blind
    );
    assert_eq!(report.metrics.monitor_input_drop_count, 5);
}

#[test]
fn clock_loss_and_network_partition_withdraw_reliance() {
    let clock = report("clock-discontinuity");
    assert_eq!(clock.final_judgment.category, JudgmentCategoryV1::Unknown);
    assert_eq!(
        clock.final_judgment.dimensions.transport,
        TransportDimensionV1::Blind
    );

    let partition = report("network-partition");
    assert!(
        partition
            .transitions
            .iter()
            .any(|transition| transition.category == JudgmentCategoryV1::Current)
    );
    assert_eq!(
        partition.final_judgment.category,
        JudgmentCategoryV1::Unknown
    );
    assert_eq!(partition.metrics.failure_to_unknown_latency_ms, Some(75));
}

#[test]
fn equivalent_escalation_storm_is_deduplicated() {
    let report = report("escalation-storm");
    assert_eq!(report.metrics.escalation_deduplication_count, 1);
    let request_events = report
        .sparse_events
        .iter()
        .filter(|event| {
            matches!(
                event.event,
                pulse_types::SparseDurableEventKindV1::EscalationRequested { .. }
            )
        })
        .count();
    assert_eq!(request_events, 1);
}

#[test]
fn diagnostic_completion_is_correlated_but_not_health() {
    let report = run_jsonl(pulse_replay::DEMO_TRACE).expect("demo replay");
    assert_eq!(report.diagnostic_receipts.len(), 1);
    assert_eq!(
        report.final_judgment.category,
        JudgmentCategoryV1::Contradicted
    );
    assert!(
        report
            .final_judgment
            .explanation
            .reasons
            .iter()
            .any(|reason| { reason.code == "diagnostic_receipt_correlated" })
    );
    assert!(!report.final_judgment.grants_mutation_authority());

    let after_receipt_expiry = run_jsonl(&format!(
        "{}\n{{\"event\":\"tick\",\"at_ms\":400}}\n",
        pulse_replay::DEMO_TRACE
    ))
    .expect("demo replays through diagnostic applicability expiry");
    assert_eq!(
        after_receipt_expiry.final_judgment.category,
        JudgmentCategoryV1::Contradicted
    );
    assert!(
        after_receipt_expiry
            .final_judgment
            .explanation
            .reasons
            .iter()
            .all(|reason| reason.code != "diagnostic_receipt_correlated")
    );
}

#[test]
fn checked_in_demo_report_is_the_exact_replay_artifact() {
    let checked_in: ReplayReportV1 =
        serde_json::from_str(include_str!("../../../artifacts/demo-report.json"))
            .expect("checked-in demo report is valid");
    let replayed = run_jsonl(pulse_replay::DEMO_TRACE).expect("demo replay");
    assert_eq!(checked_in, replayed);
}

#[test]
fn negative_observation_requires_named_supersession_or_expiry() {
    let trace = r#"
{"event":"config","minimum_observers":1,"auto_bridge":false}
{"event":"pulse","at_ms":0,"observer":"observer:a","observer_incarnation":"a:1","sequence":1,"validity_ms":100,"load":"outside","load_value":1.25}
{"event":"pulse","at_ms":10,"observer":"observer:a","observer_incarnation":"a:1","sequence":2,"validity_ms":100,"load":"within","load_value":0.25}
"#;
    let report = run_jsonl(trace).expect("negative supersession trace replays");
    assert_eq!(report.final_judgment.category, JudgmentCategoryV1::Current);
    assert!(report.sparse_events.iter().any(|event| {
        matches!(
            &event.event,
            pulse_types::SparseDurableEventKindV1::AdverseObservationSuperseded {
                rule,
                adverse_signals,
                ..
            } if rule == "same_observer_newer_sequence/v1"
                && adverse_signals == &["load_ratio"]
        )
    }));
}

#[test]
fn common_cause_ids_do_not_count_as_independent_observers() {
    let report = report("common-cause-failure");
    assert_eq!(report.final_judgment.category, JudgmentCategoryV1::Unknown);
    assert_eq!(report.final_judgment.coverage.active_observers, 1);
    assert_eq!(report.final_judgment.coverage.required_observers, 2);
}

#[test]
fn stale_incarnation_replay_and_reassuring_self_report_do_not_restore_reliance() {
    let stale = report("stale-replay");
    assert_eq!(stale.final_judgment.category, JudgmentCategoryV1::Unknown);
    assert_eq!(stale.metrics.dropped_stale_pulse_count, 1);

    let self_report = report("lying-self-report");
    assert_eq!(
        self_report.final_judgment.category,
        JudgmentCategoryV1::Contradicted
    );
    assert_eq!(
        self_report.metrics.failure_to_contradicted_latency_ms,
        Some(0)
    );
}

#[test]
fn normal_control_has_no_false_escalation() {
    let report =
        run_jsonl(include_str!("../../../traces/normal.jsonl")).expect("normal trace replays");
    assert_eq!(report.final_judgment.category, JudgmentCategoryV1::Current);
    assert_eq!(report.metrics.false_escalation_count, 0);
    assert_eq!(report.metrics.escalation_deduplication_count, 0);
}

#[test]
fn ineligible_provenance_cannot_create_a_grounded_contradiction() {
    let trace = r#"
{"event":"config","minimum_observers":1,"require_verified_authentication":true,"auto_bridge":false}
{"event":"pulse","at_ms":0,"observer":"observer:a","observer_incarnation":"a:1","sequence":1,"validity_ms":100,"load":"within","load_value":0.25}
{"event":"pulse","at_ms":10,"observer":"observer:untrusted","observer_incarnation":"u:1","sequence":1,"validity_ms":100,"load":"outside","load_value":1.25,"authentication":"failed"}
"#;
    let report = run_jsonl(trace).expect("failed-provenance trace replays");
    assert_eq!(report.final_judgment.category, JudgmentCategoryV1::Unknown);
    assert_eq!(
        report.final_judgment.dimensions.provenance,
        pulse_types::ProvenanceDimensionV1::Failed
    );
    assert!(
        report
            .final_judgment
            .explanation
            .reasons
            .iter()
            .all(|reason| reason.code != "contradiction_retained")
    );
}

#[test]
fn every_hostile_trace_is_deterministic_and_never_grants_a_stronger_claim() {
    for (name, trace) in HOSTILE {
        let first = run_jsonl(trace).unwrap_or_else(|error| panic!("{name}: {error}"));
        let second = run_jsonl(trace).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(first, second, "{name} replay is not deterministic");

        let serialized = serde_json::to_string(&first).expect("report serializes");
        assert!(
            !serialized.contains("\"healthy\":true"),
            "{name} emitted a forbidden global health claim"
        );
        assert!(
            serialized.contains("\"mutation_authority\":\"none\""),
            "{name} omitted the structural no-mutation statement"
        );
        assert!(!first.final_judgment.grants_mutation_authority());

        for transition in &first.transitions {
            if transition.category == JudgmentCategoryV1::Current {
                assert!(transition.missing_coverage.is_empty(), "{name}");
                assert_eq!(
                    transition.dimensions.coverage,
                    CoverageDimensionV1::Complete
                );
                assert_eq!(
                    transition.dimensions.observer_availability,
                    ObserverAvailabilityDimensionV1::Available,
                    "{name}"
                );
                assert!(
                    matches!(
                        transition.dimensions.freshness,
                        FreshnessDimensionV1::Current | FreshnessDimensionV1::Mixed
                    ),
                    "{name}"
                );
                assert_ne!(transition.dimensions.transport, TransportDimensionV1::Blind);
                assert_eq!(
                    transition.dimensions.subject_signal_consistency,
                    SubjectSignalConsistencyDimensionV1::Consistent,
                    "{name}"
                );
            }
        }
    }
}
