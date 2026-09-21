use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use pulse_evaluator::{EscalationPolicyV1, ReliancePolicyV1};
use pulse_l3_bridge::stub_profile_identity;
use pulse_runtime::{
    ConsumerActivationV1, ConsumerRegistrationV1, HistoricalJournal, JournalBoundsV1,
    JournalConfigV1, LocalCrashReactor, MonotonicEpochV1, PulseIngressV1, ReactorConditionV1,
    ReactorConfigV1, ReceiverSchedulerRuntime, RuntimeBoundsV1, RuntimeConfigV1, RuntimeInputV1,
    qualification_fixture_inputs,
};
use pulse_types::{
    AuthenticationFieldV1, AuthenticationResultV1, BoundedSignalValueV1, ClockId, ConsumerId,
    ConsumerProfileGenerationId, ContextActivationId, CoverageDescriptorV1, DiagnosticBoundsV1,
    EvaluatorSemanticGenerationId, GenerationTransitionCauseV1, IncarnationId, JudgmentCategoryV1,
    ObservationPolicyGenerationId, ObservationProfileIdV1, ObserverId, ObserverSetGenerationId,
    PolicyGenerationId, PulseFrameV1, ReceiverId, RelianceContextV1, SCHEMA_VERSION_V1,
    SignalAssessmentV1, SubjectId, digest_parts,
};

const SUBJECT: &str = "subject:reactor-test";
const SUBJECT_INCAR: &str = "subject-incarnation:reactor-one";
const OBSERVATION_GENERATION: &str = "observation-policy:reactor-one";
static NEXT_PATH: AtomicU64 = AtomicU64::new(1);
static REACTOR_TEST_SERIALIZER: Mutex<()> = Mutex::new(());

fn serial_reactor_test() -> MutexGuard<'static, ()> {
    REACTOR_TEST_SERIALIZER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn temp_path(label: &str) -> PathBuf {
    let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "monitor-reactor-{label}-{}-{sequence}.journal",
        std::process::id()
    ))
}

fn profile() -> ObservationProfileIdV1 {
    ObservationProfileIdV1 {
        name: "profile:reactor-test".to_owned(),
        version: 1,
        semantic_digest: digest_parts("reactor.test.profile", &[b"load"]),
    }
}

fn policy(consumer: &str, generation: &str, validity_ms: u64) -> ReliancePolicyV1 {
    ReliancePolicyV1 {
        schema_version: SCHEMA_VERSION_V1,
        subject: SubjectId::new(SUBJECT),
        scope: "host".to_owned(),
        consumer: ConsumerId::new(consumer),
        generation: PolicyGenerationId::new(generation),
        observation_policy_generation: ObservationPolicyGenerationId::new(OBSERVATION_GENERATION),
        observation_profile: profile(),
        required_coverage: vec!["load".to_owned()],
        minimum_observers: 1,
        maximum_validity_ms: validity_ms,
        require_verified_authentication: true,
        coherence_tolerances: BTreeMap::new(),
        observer_failure_domains: BTreeMap::new(),
        escalation: Some(EscalationPolicyV1 {
            triggers: [pulse_types::EscalationTriggerClassV1::FreshnessLost]
                .into_iter()
                .collect::<BTreeSet<_>>(),
            diagnostic_profile: stub_profile_identity(),
            bounds: DiagnosticBoundsV1 {
                maximum_runtime_ms: 25,
                maximum_output_bytes: 1_024,
                maximum_observations: 4,
            },
            request_ttl_ms: 250,
        }),
    }
}

fn context(policy: &ReliancePolicyV1, activation: &str) -> RelianceContextV1 {
    RelianceContextV1 {
        schema_version: SCHEMA_VERSION_V1,
        activation_id: ContextActivationId::new(activation),
        reliance_policy_generation: policy.generation.clone(),
        reliance_policy_semantic_digest: policy.semantic_digest(),
        consumer_profile_generation: ConsumerProfileGenerationId::new("consumer-profile:reactor"),
        evaluator_semantic_generation: EvaluatorSemanticGenerationId::new("evaluator:reactor"),
        observer_set_generation: ObserverSetGenerationId::new("observer-set:reactor"),
        observation_policy_generation: policy.observation_policy_generation.clone(),
    }
}

fn registration(policy: ReliancePolicyV1, activation: &str) -> ConsumerRegistrationV1 {
    ConsumerRegistrationV1 {
        context: context(&policy, activation),
        policy,
        subject_incarnation: IncarnationId::new(SUBJECT_INCAR),
    }
}

fn activation(policy: ReliancePolicyV1, activation: &str) -> ConsumerActivationV1 {
    ConsumerActivationV1 {
        context: context(&policy, activation),
        policy,
        cause: GenerationTransitionCauseV1::EquivalentBodyNewGeneration,
    }
}

fn runtime_config(incarnation: &str, clock: &str) -> RuntimeConfigV1 {
    RuntimeConfigV1 {
        schema_version: SCHEMA_VERSION_V1,
        receiver: ReceiverId::new("receiver:reactor-test"),
        receiver_incarnation: IncarnationId::new(incarnation),
        clock_id: ClockId::new(clock),
        transport_custody_policy: None,
        bounds: RuntimeBoundsV1::qualification(),
    }
}

fn epoch(config: &RuntimeConfigV1, id: &str, origin: u64) -> MonotonicEpochV1 {
    MonotonicEpochV1 {
        schema_version: SCHEMA_VERSION_V1,
        epoch_id: IncarnationId::new(id),
        receiver: config.receiver.clone(),
        receiver_incarnation: config.receiver_incarnation.clone(),
        clock_id: config.clock_id.clone(),
        origin_runtime_monotonic_ms: origin,
        clock_source: "std::time::Instant/process-local".to_owned(),
    }
}

fn journal_config(id: &str) -> JournalConfigV1 {
    JournalConfigV1 {
        schema_version: SCHEMA_VERSION_V1,
        journal_id: id.to_owned(),
        bounds: JournalBoundsV1 {
            maximum_records: 512,
            maximum_record_payload_bytes: 256 * 1_024,
            maximum_file_bytes: 16 * 1_024 * 1_024,
        },
    }
}

fn registered_runtime(
    consumer: &str,
    validity_ms: u64,
    config: RuntimeConfigV1,
) -> ReceiverSchedulerRuntime {
    let mut runtime = ReceiverSchedulerRuntime::new(config).expect("runtime");
    let registration = registration(
        policy(consumer, "policy:reactor-one", validity_ms),
        "activation:one",
    );
    runtime
        .qualify_and_activate_local_binding(
            &registration,
            qualification_fixture_inputs("3cd15b7a1e7f424f6fd57c09b30fa4790947eca2", 97),
            0,
        )
        .expect("local exact binding activates");
    runtime
        .register_consumer(registration, 0)
        .expect("consumer registers");
    runtime
}

fn pulse(sequence: u64, validity_ms: u64) -> PulseFrameV1 {
    PulseFrameV1 {
        schema_version: SCHEMA_VERSION_V1,
        subject: SubjectId::new(SUBJECT),
        subject_incarnation: IncarnationId::new(SUBJECT_INCAR),
        observer: ObserverId::new("observer:reactor"),
        observer_incarnation: IncarnationId::new("observer-incarnation:reactor-one"),
        sequence,
        observer_monotonic_ns: sequence.saturating_mul(1_000_000),
        validity_ms,
        profile: profile(),
        observation_policy_generation: ObservationPolicyGenerationId::new(OBSERVATION_GENERATION),
        coverage: CoverageDescriptorV1 {
            expected: vec!["load".to_owned()],
            observed: vec!["load".to_owned()],
        },
        signals: vec![BoundedSignalValueV1 {
            name: "load_ratio".to_owned(),
            value: 0.2,
            unit: "ratio".to_owned(),
            assessment: SignalAssessmentV1::WithinDeclaredBound,
        }],
        observation_digest: digest_parts("unsealed", &[]),
        authentication: AuthenticationFieldV1::Placeholder {
            disclosure: "reactor fixture".to_owned(),
        },
    }
    .seal()
}

fn ingress(sequence: u64, validity_ms: u64) -> RuntimeInputV1 {
    RuntimeInputV1::Pulse(PulseIngressV1 {
        frame: pulse(sequence, validity_ms),
        transport_path: "local:reactor-test".to_owned(),
        transport_observed_delay_ms: Some(0),
        authentication: AuthenticationResultV1::Verified {
            method: "fixture".to_owned(),
            principal: "observer:reactor".to_owned(),
        },
    })
}

fn start_reactor(
    label: &str,
    consumer: &str,
    validity_ms: u64,
    reactor_config: ReactorConfigV1,
) -> (LocalCrashReactor, PathBuf, JournalConfigV1, RuntimeConfigV1) {
    let path = temp_path(label);
    let runtime_config = runtime_config(
        &format!("receiver-incarnation:{label}"),
        &format!("clock:{label}"),
    );
    let runtime = registered_runtime(consumer, validity_ms, runtime_config.clone());
    let journal_config = journal_config(&format!("journal:{label}"));
    let journal = HistoricalJournal::create_new(&path, journal_config.clone()).expect("journal");
    let reactor = LocalCrashReactor::start(
        runtime,
        journal,
        epoch(&runtime_config, &format!("epoch:{label}"), 0),
        reactor_config,
    )
    .expect("reactor starts");
    reactor
        .wait_until(Duration::from_secs(2), |snapshot| {
            snapshot.condition == ReactorConditionV1::Operational
        })
        .expect("reactor becomes operational");
    (reactor, path, journal_config, runtime_config)
}

fn judgment(snapshot: &pulse_runtime::ReactorSnapshotV1, consumer: &str) -> JudgmentCategoryV1 {
    snapshot
        .certificates
        .iter()
        .find(|certificate| certificate.consumer == ConsumerId::new(consumer))
        .expect("consumer certificate")
        .judgment
}

#[test]
fn real_actor_withdraws_current_without_external_run_until() {
    let _serial = serial_reactor_test();
    let (reactor, path, journal_config, _) = start_reactor(
        "real-expiry",
        "consumer:one",
        40,
        ReactorConfigV1::qualification(),
    );
    reactor
        .submit_input(ingress(1, 40))
        .expect("pulse evaluates");
    let current = reactor.snapshot();
    assert_eq!(
        judgment(&current, "consumer:one"),
        JudgmentCategoryV1::Current
    );
    let deadline = current
        .earliest_deadline_monotonic_ms
        .expect("deadline is armed");
    let expired = reactor
        .wait_until(Duration::from_secs(2), |snapshot| {
            snapshot.live_standing_available
                && snapshot.certificates.iter().any(|certificate| {
                    certificate.consumer == ConsumerId::new("consumer:one")
                        && certificate.judgment == JudgmentCategoryV1::Unknown
                })
        })
        .expect("actor withdraws current");
    assert!(expired.observed_at_epoch_monotonic_ms >= deadline);
    assert_eq!(expired.active_deadline_count, 0);
    assert_eq!(expired.reactor_metrics.deadline_withdrawal_count, 1);
    reactor.shutdown().expect("clean shutdown");
    let report = HistoricalJournal::scan(&path, &journal_config).expect("scan journal");
    assert!(report.records.iter().any(|record| matches!(
        record.body,
        pulse_runtime::JournalRecordBodyV1::SparseEvent {
            event: pulse_types::SparseDurableEventV1 {
                event: pulse_types::SparseDurableEventKindV1::SchedulerReevaluated { .. },
                ..
            }
        }
    )));
    fs::remove_file(path).expect("remove fixture");
}

#[test]
fn delayed_wakeup_reports_lateness_without_extending_encoded_deadline() {
    let _serial = serial_reactor_test();
    let mut config = ReactorConfigV1::qualification();
    config.deliberate_deadline_delay_ms = 25;
    let (reactor, path, _, _) = start_reactor("late", "consumer:one", 35, config);
    reactor
        .submit_input(ingress(1, 35))
        .expect("pulse evaluates");
    let deadline = reactor
        .snapshot()
        .earliest_deadline_monotonic_ms
        .expect("deadline");
    let expired = reactor
        .wait_until(Duration::from_secs(2), |snapshot| {
            snapshot.reactor_metrics.deadline_withdrawal_count == 1
        })
        .expect("late deadline processed");
    assert!(expired.observed_at_epoch_monotonic_ms >= deadline + 20);
    assert_eq!(expired.condition, ReactorConditionV1::Operational);
    assert!(expired.reactor_metrics.last_wakeup_lateness_ms >= 20);
    assert!(expired.runtime_metrics.maximum_stale_positive_duration_ms >= 20);
    reactor.shutdown().expect("shutdown");
    fs::remove_file(path).expect("remove fixture");
}

#[test]
fn required_journal_exhaustion_is_a_distinct_fail_closed_condition() {
    let _serial = serial_reactor_test();
    // This case qualifies journal exhaustion, not sub-second scheduling. Keep
    // enough separation between startup and expiry that a loaded test host can
    // observe the initial durable state before the deadline transition.
    const JOURNAL_EXHAUSTION_VALIDITY_MS: u64 = 500;
    let path = temp_path("journal-failure");
    let runtime_config = runtime_config(
        "receiver-incarnation:journal-failure",
        "clock:journal-failure",
    );
    let mut runtime = registered_runtime(
        "consumer:one",
        JOURNAL_EXHAUSTION_VALIDITY_MS,
        runtime_config.clone(),
    );
    runtime
        .enqueue(0, ingress(1, JOURNAL_EXHAUSTION_VALIDITY_MS))
        .expect("current pulse enqueues");
    runtime.run_until(0).expect("current pulse evaluates");
    let baseline_records = runtime.export_history().sparse_events.len();
    assert!(baseline_records > 0);
    let journal_config = JournalConfigV1 {
        schema_version: SCHEMA_VERSION_V1,
        journal_id: "journal:journal-failure".to_owned(),
        bounds: JournalBoundsV1 {
            maximum_records: baseline_records,
            maximum_record_payload_bytes: 256 * 1_024,
            maximum_file_bytes: 16 * 1_024 * 1_024,
        },
    };
    let journal = HistoricalJournal::create_new(&path, journal_config).expect("journal");
    let reactor = LocalCrashReactor::start(
        runtime,
        journal,
        epoch(&runtime_config, "epoch:journal-failure", 0),
        ReactorConfigV1::qualification(),
    )
    .expect("reactor");
    reactor
        .wait_until(Duration::from_secs(5), |snapshot| {
            snapshot.condition == ReactorConditionV1::Operational
        })
        .expect("initial history fits exactly");
    let failed = reactor
        .wait_until(Duration::from_secs(5), |snapshot| {
            snapshot.condition == ReactorConditionV1::JournalFailure
        })
        .expect("deadline history exceeds journal bound");
    assert_eq!(failed.reactor_metrics.journal_failure_count, 1);
    assert!(!failed.live_standing_available);
    assert!(failed.certificates.is_empty());
    assert_eq!(failed.active_deadline_count, 0);
    drop(reactor);
    fs::remove_file(path).expect("remove fixture");
}

#[test]
fn nearer_deadline_inserted_while_sleeping_is_rearmed() {
    let _serial = serial_reactor_test();
    let (reactor, path, _, _) = start_reactor(
        "rearm",
        "consumer:one",
        250,
        ReactorConfigV1::qualification(),
    );
    reactor.submit_input(ingress(1, 250)).expect("first pulse");
    let first_deadline = reactor
        .snapshot()
        .earliest_deadline_monotonic_ms
        .expect("first deadline");
    std::thread::sleep(Duration::from_millis(10));
    reactor.submit_input(ingress(2, 40)).expect("nearer pulse");
    let second_deadline = reactor
        .snapshot()
        .earliest_deadline_monotonic_ms
        .expect("second deadline");
    assert!(second_deadline < first_deadline);
    let expired = reactor
        .wait_until(Duration::from_secs(2), |snapshot| {
            snapshot.reactor_metrics.deadline_withdrawal_count == 1
        })
        .expect("nearer deadline wakes");
    assert!(expired.observed_at_epoch_monotonic_ms < first_deadline);
    reactor.shutdown().expect("shutdown");
    fs::remove_file(path).expect("remove fixture");
}

#[test]
fn generation_transition_removes_old_deadline_before_expiry() {
    let _serial = serial_reactor_test();
    let (reactor, path, _, _) = start_reactor(
        "generation",
        "consumer:one",
        500,
        ReactorConfigV1::qualification(),
    );
    reactor.submit_input(ingress(1, 500)).expect("pulse");
    assert_eq!(reactor.snapshot().active_deadline_count, 1);
    let next_policy = policy("consumer:one", "policy:reactor-two", 500);
    reactor
        .submit_input(RuntimeInputV1::ActivateConsumer(activation(
            next_policy,
            "activation:two",
        )))
        .expect("generation transition");
    let snapshot = reactor.snapshot();
    assert_eq!(
        judgment(&snapshot, "consumer:one"),
        JudgmentCategoryV1::Unknown
    );
    assert_eq!(snapshot.active_deadline_count, 0);
    assert_eq!(
        snapshot.certificates[0].context.activation_id.as_str(),
        "activation:two"
    );
    reactor.shutdown().expect("shutdown");
    fs::remove_file(path).expect("remove fixture");
}

#[test]
fn two_deadlines_are_serviced_earliest_first() {
    let _serial = serial_reactor_test();
    let path = temp_path("two-deadlines");
    let runtime_config = runtime_config("receiver-incarnation:two", "clock:two");
    let mut runtime = ReceiverSchedulerRuntime::new(runtime_config.clone()).expect("runtime");
    let fast = registration(
        policy("consumer:fast", "policy:fast", 40),
        "activation:fast",
    );
    runtime
        .qualify_and_activate_local_binding(
            &fast,
            qualification_fixture_inputs("3cd15b7a1e7f424f6fd57c09b30fa4790947eca2", 97),
            0,
        )
        .expect("fast binding activates");
    runtime.register_consumer(fast, 0).expect("fast registers");
    let slow = registration(
        policy("consumer:slow", "policy:slow", 150),
        "activation:slow",
    );
    runtime
        .qualify_and_activate_local_binding(
            &slow,
            qualification_fixture_inputs("3cd15b7a1e7f424f6fd57c09b30fa4790947eca2", 97),
            0,
        )
        .expect("slow binding activates");
    runtime.register_consumer(slow, 0).expect("slow registers");
    let journal_config = journal_config("journal:two-deadlines");
    let journal = HistoricalJournal::create_new(&path, journal_config).expect("journal");
    let reactor = LocalCrashReactor::start(
        runtime,
        journal,
        epoch(&runtime_config, "epoch:two-deadlines", 0),
        ReactorConfigV1::qualification(),
    )
    .expect("reactor");
    reactor
        .wait_until(Duration::from_secs(2), |snapshot| {
            snapshot.condition == ReactorConditionV1::Operational
        })
        .expect("operational");
    reactor.submit_input(ingress(1, 200)).expect("pulse");
    assert_eq!(reactor.snapshot().active_deadline_count, 2);
    let first = reactor
        .wait_until(Duration::from_secs(2), |snapshot| {
            snapshot.certificates.iter().any(|certificate| {
                certificate.consumer == ConsumerId::new("consumer:fast")
                    && certificate.judgment == JudgmentCategoryV1::Unknown
            })
        })
        .expect("first deadline");
    assert_eq!(
        judgment(&first, "consumer:slow"),
        JudgmentCategoryV1::Current
    );
    let second = reactor
        .wait_until(Duration::from_secs(2), |snapshot| {
            snapshot.reactor_metrics.deadline_withdrawal_count == 2
        })
        .expect("second deadline");
    assert_eq!(
        judgment(&second, "consumer:slow"),
        JudgmentCategoryV1::Unknown
    );
    reactor.shutdown().expect("shutdown");
    fs::remove_file(path).expect("remove fixture");
}

#[test]
fn journal_recovery_starts_new_epoch_unknown_without_support_or_deadlines() {
    let _serial = serial_reactor_test();
    let (reactor, path, journal_config, _) = start_reactor(
        "restart",
        "consumer:one",
        500,
        ReactorConfigV1::qualification(),
    );
    reactor.submit_input(ingress(1, 500)).expect("pulse");
    assert_eq!(
        judgment(&reactor.snapshot(), "consumer:one"),
        JudgmentCategoryV1::Current
    );
    reactor.shutdown().expect("shutdown");
    let report = HistoricalJournal::scan(&path, &journal_config).expect("scan");
    assert!(report.historical_current_record_count() > 0);
    let projection = report.project_history().expect("project history");
    assert!(!projection.current_standing_reconstructed);
    assert!(!projection.active_escalation_suppression_restored);

    let next_config = runtime_config("receiver-incarnation:restart-two", "clock:restart-two");
    let (restarted, _) = ReceiverSchedulerRuntime::recover(
        next_config,
        vec![registration(
            policy("consumer:one", "policy:reactor-one", 500),
            "activation:restart-two",
        )],
        projection.history,
        0,
    )
    .expect("runtime history recovers");
    let certificate = restarted
        .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new("consumer:one"))
        .expect("restart certificate");
    assert_eq!(certificate.judgment, JudgmentCategoryV1::Unknown);
    assert!(certificate.supporting_evidence_ids.is_empty());
    assert_eq!(restarted.scheduled_deadline_count(), 0);
    fs::remove_file(path).expect("remove fixture");
}

#[test]
fn clean_shutdown_terminates_with_no_live_standing_surface() {
    let _serial = serial_reactor_test();
    let (reactor, path, _, _) = start_reactor(
        "shutdown",
        "consumer:one",
        500,
        ReactorConfigV1::qualification(),
    );
    reactor.submit_input(ingress(1, 500)).expect("pulse");
    let final_snapshot = reactor.shutdown().expect("clean shutdown");
    assert_eq!(final_snapshot.condition, ReactorConditionV1::Terminated);
    assert!(final_snapshot.clean_shutdown);
    assert!(!final_snapshot.live_standing_available);
    assert!(final_snapshot.certificates.is_empty());
    assert_eq!(final_snapshot.active_deadline_count, 0);
    fs::remove_file(path).expect("remove fixture");
}

#[test]
fn abandoned_command_channel_withdraws_and_journals_temporal_custody() {
    let _serial = serial_reactor_test();
    let (reactor, path, journal_config, _) = start_reactor(
        "abandoned",
        "consumer:one",
        500,
        ReactorConfigV1::qualification(),
    );
    reactor.submit_input(ingress(1, 500)).expect("pulse");
    assert_eq!(
        judgment(&reactor.snapshot(), "consumer:one"),
        JudgmentCategoryV1::Current
    );

    drop(reactor);

    let report = HistoricalJournal::scan(&path, &journal_config).expect("scan abandoned journal");
    assert_eq!(
        report.outcome,
        pulse_runtime::JournalRecoveryOutcomeV1::Clean
    );
    assert!(report.records.iter().any(|record| matches!(
        &record.body,
        pulse_runtime::JournalRecordBodyV1::SparseEvent {
            event: pulse_types::SparseDurableEventV1 {
                event: pulse_types::SparseDurableEventKindV1::MonitorCapabilityChanged {
                    state,
                    ..
                },
                ..
            }
        } if state == "reactor_terminated"
    )));
    fs::remove_file(path).expect("remove fixture");
}
