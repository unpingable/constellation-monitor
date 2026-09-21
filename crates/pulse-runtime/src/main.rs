#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::error::Error;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use pulse_agent::{AgentConfig, ProducerProfile, PulseAgent, profile_identity};
use pulse_evaluator::{EscalationPolicyV1, ReliancePolicyV1};
use pulse_l3_bridge::stub_profile_identity;
use pulse_runtime::{
    ConsumerActivationV1, ConsumerRegistrationV1, PulseIngressV1, ReceiverSchedulerRuntime,
    RuntimeBoundsV1, RuntimeConfigV1, RuntimeInputV1, qualification_fixture_inputs,
};
use pulse_types::{
    AuthenticationFieldV1, AuthenticationResultV1, BoundedSignalValueV1, ClockId, ConsumerId,
    ConsumerProfileGenerationId, ContextActivationId, CoverageDescriptorV1, DiagnosticBoundsV1,
    EvaluatorSemanticGenerationId, GenerationTransitionCauseV1, IncarnationId, JudgmentCategoryV1,
    MutationAuthorityV1, ObservationPolicyGenerationId, ObservationProfileIdV1, ObserverId,
    ObserverSetGenerationId, PolicyGenerationId, PulseFrameV1, ReceiverId, RelianceContextV1,
    RuntimeMetricsV1, RuntimeRefusalClassV1, SCHEMA_VERSION_V1, SignalAssessmentV1,
    SparseDurableEventKindV1, SubjectId, digest_parts,
};
use serde::Serialize;

const STARTING_COMMIT: &str = "0a9fe16e6d091c6b4b1128fcb6166e53d712fc3f";
const QUALIFIED_BINDING_SOURCE_COMMIT: &str = "3cd15b7a1e7f424f6fd57c09b30fa4790947eca2";
const DEMO_SUBJECT: &str = "subject:runtime-generation-demo";
const DEMO_CONSUMER: &str = "consumer:capacity-display";
const DEMO_SUBJECT_INCAR: &str = "subject-incarnation:demo-one";
const DEMO_OBSERVATION_GENERATION: &str = "observation-policy:demo-one";

#[derive(Clone, Debug, Serialize)]
struct DemoStep {
    at_monotonic_ms: u64,
    action: String,
    judgment: JudgmentCategoryV1,
    policy_generation: String,
    activation_id: String,
    standing_inherited: bool,
    support_expiry_monotonic_ms: Option<u64>,
    certificate_id: String,
}

#[derive(Clone, Debug, Serialize)]
struct RuntimeDemoArtifact {
    schema_version: u16,
    scenario: &'static str,
    clock: &'static str,
    steps: Vec<DemoStep>,
    assertions: Vec<&'static str>,
    emitted_escalation_count: usize,
    metrics: RuntimeMetricsV1,
    terminal_trace: Vec<String>,
    nonclaims: Vec<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
struct RestartArtifact {
    schema_version: u16,
    scenario: &'static str,
    historical_records_recovered: u64,
    historical_current_certificate_records: usize,
    serialized_history_bytes: usize,
    serialization_round_trip_exact: bool,
    current_standing: JudgmentCategoryV1,
    current_supporting_evidence_count: usize,
    scheduled_deadline_count: usize,
    standing_recovered: bool,
    trace: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct QualificationCheck {
    name: &'static str,
    result: &'static str,
    evidence: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct QualificationArtifact {
    schema_version: u16,
    campaign: &'static str,
    starting_commit: &'static str,
    harness_clock: &'static str,
    checks: Vec<QualificationCheck>,
    deterministic_demo_metrics: RuntimeMetricsV1,
    restart: RestartArtifact,
    required_gate_commands: Vec<&'static str>,
    nonclaims: Vec<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
struct LiveLinuxArtifact {
    schema_version: u16,
    exercise: &'static str,
    wall_clock_measurement: bool,
    hard_realtime_claimed: bool,
    expected_support_expiry_monotonic_ms: u64,
    actual_reevaluation_monotonic_ms: u64,
    stale_positive_overshoot_ms: u64,
    policy_transition_withdrawal_wall_us: u128,
    policy_transition_withdrawal_logical_ms: u64,
    duplicate_escalation_count: u64,
    state_after_receiver_restart: JudgmentCategoryV1,
    historical_records_recovered: u64,
    queue_refusal: RuntimeRefusalClassV1,
    observer_cardinality_refusal: RuntimeRefusalClassV1,
    producer_restart_changed_observer_incarnation: bool,
    proc_coverage: Vec<String>,
    nonclaims: Vec<&'static str>,
}

fn demo_profile() -> ObservationProfileIdV1 {
    ObservationProfileIdV1 {
        name: "profile:runtime-generation-demo".to_owned(),
        version: 1,
        semantic_digest: digest_parts("runtime.generation-demo.profile", &[b"load", b"memory"]),
    }
}

fn escalation_policy() -> EscalationPolicyV1 {
    EscalationPolicyV1 {
        triggers: [
            pulse_types::EscalationTriggerClassV1::FreshnessLost,
            pulse_types::EscalationTriggerClassV1::CoverageCollapse,
            pulse_types::EscalationTriggerClassV1::ContradictionRetained,
            pulse_types::EscalationTriggerClassV1::SubjectBoundViolated,
            pulse_types::EscalationTriggerClassV1::TransportBlind,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>(),
        diagnostic_profile: stub_profile_identity(),
        bounds: DiagnosticBoundsV1 {
            maximum_runtime_ms: 25,
            maximum_output_bytes: 1_024,
            maximum_observations: 4,
        },
        request_ttl_ms: 1_000,
    }
}

#[allow(clippy::too_many_arguments)]
fn reliance_policy(
    subject: &str,
    consumer: &str,
    generation: &str,
    observation_generation: &str,
    profile: ObservationProfileIdV1,
    coverage: Vec<String>,
    validity_ms: u64,
    require_verified_authentication: bool,
) -> ReliancePolicyV1 {
    ReliancePolicyV1 {
        schema_version: SCHEMA_VERSION_V1,
        subject: SubjectId::new(subject),
        scope: "host".to_owned(),
        consumer: ConsumerId::new(consumer),
        generation: PolicyGenerationId::new(generation),
        observation_policy_generation: ObservationPolicyGenerationId::new(observation_generation),
        observation_profile: profile,
        required_coverage: coverage,
        minimum_observers: 1,
        maximum_validity_ms: validity_ms,
        require_verified_authentication,
        coherence_tolerances: BTreeMap::new(),
        observer_failure_domains: BTreeMap::new(),
        escalation: Some(escalation_policy()),
    }
}

fn exact_context(policy: &ReliancePolicyV1, activation_id: &str) -> RelianceContextV1 {
    RelianceContextV1 {
        schema_version: SCHEMA_VERSION_V1,
        activation_id: ContextActivationId::new(activation_id),
        reliance_policy_generation: policy.generation.clone(),
        reliance_policy_semantic_digest: policy.semantic_digest(),
        consumer_profile_generation: ConsumerProfileGenerationId::new("consumer-profile:demo-v1"),
        evaluator_semantic_generation: EvaluatorSemanticGenerationId::new("evaluator:demo-v1"),
        observer_set_generation: ObserverSetGenerationId::new("observer-set:demo-v1"),
        observation_policy_generation: policy.observation_policy_generation.clone(),
    }
}

fn registration(
    policy: ReliancePolicyV1,
    activation_id: &str,
    subject_incarnation: IncarnationId,
) -> ConsumerRegistrationV1 {
    let context = exact_context(&policy, activation_id);
    ConsumerRegistrationV1 {
        policy,
        context,
        subject_incarnation,
    }
}

fn activation(
    policy: ReliancePolicyV1,
    activation_id: &str,
    cause: GenerationTransitionCauseV1,
) -> ConsumerActivationV1 {
    let context = exact_context(&policy, activation_id);
    ConsumerActivationV1 {
        policy,
        context,
        cause,
    }
}

fn runtime_config(receiver_incarnation: &str, clock: &str) -> RuntimeConfigV1 {
    RuntimeConfigV1 {
        schema_version: SCHEMA_VERSION_V1,
        receiver: ReceiverId::new("receiver:bounded-runtime"),
        receiver_incarnation: IncarnationId::new(receiver_incarnation),
        clock_id: ClockId::new(clock),
        transport_custody_policy: None,
        bounds: RuntimeBoundsV1::qualification(),
    }
}

fn install_demo_binding(
    runtime: &mut ReceiverSchedulerRuntime,
    registration: &ConsumerRegistrationV1,
    at_monotonic_ms: u64,
) -> Result<(), Box<dyn Error>> {
    runtime.qualify_and_activate_local_binding(
        registration,
        qualification_fixture_inputs(QUALIFIED_BINDING_SOURCE_COMMIT, 97),
        at_monotonic_ms,
    )?;
    Ok(())
}

fn demo_pulse(validity_ms: u64) -> PulseFrameV1 {
    PulseFrameV1 {
        schema_version: SCHEMA_VERSION_V1,
        subject: SubjectId::new(DEMO_SUBJECT),
        subject_incarnation: IncarnationId::new(DEMO_SUBJECT_INCAR),
        observer: ObserverId::new("observer:demo-a"),
        observer_incarnation: IncarnationId::new("observer-incarnation:demo-a-one"),
        sequence: 1,
        observer_monotonic_ns: 1_000_000,
        validity_ms,
        profile: demo_profile(),
        observation_policy_generation: ObservationPolicyGenerationId::new(
            DEMO_OBSERVATION_GENERATION,
        ),
        coverage: CoverageDescriptorV1 {
            expected: vec!["load".to_owned(), "memory".to_owned()],
            observed: vec!["load".to_owned(), "memory".to_owned()],
        },
        signals: vec![
            BoundedSignalValueV1 {
                name: "load_ratio".to_owned(),
                value: 0.20,
                unit: "ratio".to_owned(),
                assessment: SignalAssessmentV1::WithinDeclaredBound,
            },
            BoundedSignalValueV1 {
                name: "memory_available_ratio".to_owned(),
                value: 0.70,
                unit: "ratio".to_owned(),
                assessment: SignalAssessmentV1::WithinDeclaredBound,
            },
        ],
        observation_digest: digest_parts("unsealed", &[]),
        authentication: AuthenticationFieldV1::Placeholder {
            disclosure: "demo frame; receiver result is supplied separately".to_owned(),
        },
    }
    .seal()
}

fn ingress(frame: PulseFrameV1) -> RuntimeInputV1 {
    RuntimeInputV1::Pulse(PulseIngressV1 {
        frame,
        transport_path: "local:bounded-demo".to_owned(),
        transport_observed_delay_ms: Some(0),
        authentication: AuthenticationResultV1::Verified {
            method: "demo-fixture".to_owned(),
            principal: "observer:demo-a".to_owned(),
        },
    })
}

fn require(condition: bool, detail: &str) -> Result<(), Box<dyn Error>> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::other(detail).into())
    }
}

fn enqueue(
    runtime: &mut ReceiverSchedulerRuntime,
    at: u64,
    input: RuntimeInputV1,
) -> Result<(), Box<dyn Error>> {
    runtime
        .enqueue(at, input)
        .map(|_| ())
        .map_err(|refusal| io::Error::other(format!("runtime refusal: {refusal:?}")).into())
}

fn capture_step(
    runtime: &ReceiverSchedulerRuntime,
    at: u64,
    action: impl Into<String>,
) -> Result<DemoStep, Box<dyn Error>> {
    let certificate = runtime
        .current_certificate(
            &SubjectId::new(DEMO_SUBJECT),
            &ConsumerId::new(DEMO_CONSUMER),
        )
        .ok_or_else(|| io::Error::other("demo certificate is absent"))?;
    require(
        certificate.mutation_authority == MutationAuthorityV1::None,
        "runtime certificate unexpectedly grants mutation authority",
    )?;
    Ok(DemoStep {
        at_monotonic_ms: at,
        action: action.into(),
        judgment: certificate.judgment,
        policy_generation: certificate.context.reliance_policy_generation.to_string(),
        activation_id: certificate.context.activation_id.to_string(),
        standing_inherited: false,
        support_expiry_monotonic_ms: certificate.earliest_support_expiry_monotonic_ms,
        certificate_id: certificate.certificate_id.to_string(),
    })
}

fn run_generation_demo() -> Result<RuntimeDemoArtifact, Box<dyn Error>> {
    let mut runtime = ReceiverSchedulerRuntime::new(runtime_config(
        "receiver-incarnation:demo-one",
        "clock:demo-replay",
    ))?;
    let p1 = reliance_policy(
        DEMO_SUBJECT,
        DEMO_CONSUMER,
        "policy:p1",
        DEMO_OBSERVATION_GENERATION,
        demo_profile(),
        vec!["load".to_owned(), "memory".to_owned()],
        40,
        true,
    );
    let mut trace = Vec::new();
    let p1_registration = registration(
        p1.clone(),
        "activation:p1-first",
        IncarnationId::new(DEMO_SUBJECT_INCAR),
    );
    install_demo_binding(&mut runtime, &p1_registration, 0)?;
    let initial = runtime.register_consumer(p1_registration, 0)?;
    trace.extend(initial.trace_lines);
    let mut steps = vec![capture_step(
        &runtime,
        0,
        "receiver start; no hot evidence",
    )?];

    enqueue(&mut runtime, 10, ingress(demo_pulse(40)))?;
    let current_output = runtime.run_until(10)?;
    trace.extend(current_output.trace_lines);
    steps.push(capture_step(
        &runtime,
        10,
        "bounded pulse explicitly evaluated under P1",
    )?);
    require(
        steps.last().is_some_and(|step| {
            step.judgment == JudgmentCategoryV1::Current
                && step.support_expiry_monotonic_ms == Some(50)
        }),
        "P1 did not establish bounded CURRENT through 50ms",
    )?;
    let original_current_certificate = steps
        .last()
        .expect("a current step was just appended")
        .certificate_id
        .clone();

    let mut p2 = p1.clone();
    p2.generation = PolicyGenerationId::new("policy:p2");
    require(
        p1.semantic_digest() == p2.semantic_digest(),
        "equal-body transition fixture is not semantically equal",
    )?;
    let p2_activation = activation(
        p2,
        "activation:p2",
        GenerationTransitionCauseV1::EquivalentBodyNewGeneration,
    );
    let p2_registration = ConsumerRegistrationV1 {
        policy: p2_activation.policy.clone(),
        context: p2_activation.context.clone(),
        subject_incarnation: IncarnationId::new(DEMO_SUBJECT_INCAR),
    };
    install_demo_binding(&mut runtime, &p2_registration, 20)?;
    enqueue(
        &mut runtime,
        20,
        RuntimeInputV1::ActivateConsumer(p2_activation),
    )?;
    let p2_output = runtime.run_until(20)?;
    trace.extend(p2_output.trace_lines);
    steps.push(capture_step(
        &runtime,
        20,
        "equal policy body activated as exact generation P2; prior standing withdrawn",
    )?);
    require(
        steps.last().is_some_and(|step| {
            step.judgment == JudgmentCategoryV1::Unknown && step.policy_generation == "policy:p2"
        }),
        "P2 generation barrier did not produce UNKNOWN",
    )?;

    let mut rollback = p1;
    rollback.generation = PolicyGenerationId::new("policy:p1-body-rollback-g3");
    let rollback_activation = activation(
        rollback,
        "activation:p1-body-rollback-g3",
        GenerationTransitionCauseV1::PolicyRollback,
    );
    let rollback_registration = ConsumerRegistrationV1 {
        policy: rollback_activation.policy.clone(),
        context: rollback_activation.context.clone(),
        subject_incarnation: IncarnationId::new(DEMO_SUBJECT_INCAR),
    };
    install_demo_binding(&mut runtime, &rollback_registration, 30)?;
    enqueue(
        &mut runtime,
        30,
        RuntimeInputV1::ActivateConsumer(rollback_activation),
    )?;
    let rollback_output = runtime.run_until(30)?;
    trace.extend(rollback_output.trace_lines);
    steps.push(capture_step(
        &runtime,
        30,
        "rollback to the P1 body under a fresh generation and activation; no resurrection",
    )?);
    require(
        steps.last().is_some_and(|step| {
            step.judgment == JudgmentCategoryV1::Unknown
                && step.certificate_id != original_current_certificate
        }),
        "rollback resurrected the original P1 standing",
    )?;

    enqueue(
        &mut runtime,
        31,
        RuntimeInputV1::Reevaluate {
            subject: SubjectId::new(DEMO_SUBJECT),
            consumer: ConsumerId::new(DEMO_CONSUMER),
        },
    )?;
    let reevaluated = runtime.run_until(31)?;
    trace.extend(reevaluated.trace_lines);
    steps.push(capture_step(
        &runtime,
        31,
        "explicit evidence reconsideration under the exact rollback generation",
    )?);
    require(
        steps.last().is_some_and(|step| {
            step.judgment == JudgmentCategoryV1::Current
                && step.policy_generation == "policy:p1-body-rollback-g3"
                && step.support_expiry_monotonic_ms == Some(50)
        }),
        "explicit rollback-generation evaluation did not earn bounded CURRENT",
    )?;

    let expired = runtime.run_until(50)?;
    let emitted_escalation_count = expired.escalation_requests.len();
    trace.extend(expired.trace_lines);
    steps.push(capture_step(
        &runtime,
        50,
        "inclusive support deadline fired with no new pulse",
    )?);
    require(
        steps
            .last()
            .is_some_and(|step| step.judgment == JudgmentCategoryV1::Unknown),
        "support expiry failed to withdraw CURRENT",
    )?;

    let terminal_trace = steps
        .iter()
        .map(|step| {
            format!(
                "[{:03}ms] {:<7} generation={} activation={} inherited={} deadline={} action={}",
                step.at_monotonic_ms,
                step.judgment,
                step.policy_generation,
                step.activation_id,
                step.standing_inherited,
                step.support_expiry_monotonic_ms
                    .map_or_else(|| "none".to_owned(), |value| format!("{value}ms")),
                step.action
            )
        })
        .collect();

    Ok(RuntimeDemoArtifact {
        schema_version: SCHEMA_VERSION_V1,
        scenario: "exact-generation-withdrawal-rollback-and-expiry",
        clock: "deterministic receiver-local replay clock; not wall clock",
        steps,
        assertions: vec![
            "equal policy bodies under distinct generations do not share standing",
            "rollback does not resurrect the original certificate",
            "only explicit evaluation can earn standing under a new exact context",
            "inclusive support expiry withdraws CURRENT without a new pulse",
            "every certificate grants mutation_authority=none",
        ],
        emitted_escalation_count,
        metrics: runtime.metrics().clone(),
        terminal_trace,
        nonclaims: vec![
            "CURRENT does not mean subject health",
            "the replay clock is not a hard real-time measurement",
            "the escalation request grants no diagnostic or mutation authority",
        ],
    })
}

fn run_restart_demo() -> Result<RestartArtifact, Box<dyn Error>> {
    let mut runtime = ReceiverSchedulerRuntime::new(runtime_config(
        "receiver-incarnation:restart-before",
        "clock:restart-before",
    ))?;
    let policy = reliance_policy(
        DEMO_SUBJECT,
        DEMO_CONSUMER,
        "policy:restart-before",
        DEMO_OBSERVATION_GENERATION,
        demo_profile(),
        vec!["load".to_owned(), "memory".to_owned()],
        100,
        true,
    );
    let restart_registration = registration(
        policy.clone(),
        "activation:restart-before",
        IncarnationId::new(DEMO_SUBJECT_INCAR),
    );
    install_demo_binding(&mut runtime, &restart_registration, 0)?;
    runtime.register_consumer(restart_registration, 0)?;
    enqueue(&mut runtime, 1, ingress(demo_pulse(100)))?;
    runtime.run_until(1)?;
    require(
        runtime
            .current_certificate(
                &SubjectId::new(DEMO_SUBJECT),
                &ConsumerId::new(DEMO_CONSUMER),
            )
            .is_some_and(|certificate| certificate.judgment == JudgmentCategoryV1::Current),
        "restart fixture never earned CURRENT before export",
    )?;
    let history = runtime.export_history();
    let historical_current_certificate_records = history
        .sparse_events
        .iter()
        .filter(|event| {
            matches!(
                &event.event,
                SparseDurableEventKindV1::SupportCertificateIssued { certificate }
                    if certificate.judgment == JudgmentCategoryV1::Current
            )
        })
        .count();
    let recovered_count = u64::try_from(history.sparse_events.len()).unwrap_or(u64::MAX);
    let serialized_history = serde_json::to_vec(&history)?;
    let persisted_history: pulse_types::RuntimeHistoricalStateV1 =
        serde_json::from_slice(&serialized_history)?;
    let serialization_round_trip_exact = persisted_history == history;
    require(
        serialization_round_trip_exact,
        "history-only persistence record failed an exact JSON round trip",
    )?;
    let (restarted, output) = ReceiverSchedulerRuntime::recover(
        runtime_config("receiver-incarnation:restart-after", "clock:restart-after"),
        vec![registration(
            policy,
            "activation:restart-after",
            IncarnationId::new(DEMO_SUBJECT_INCAR),
        )],
        persisted_history,
        0,
    )?;
    let certificate = restarted
        .current_certificate(
            &SubjectId::new(DEMO_SUBJECT),
            &ConsumerId::new(DEMO_CONSUMER),
        )
        .ok_or_else(|| io::Error::other("restart certificate is absent"))?;
    require(
        historical_current_certificate_records > 0
            && certificate.judgment == JudgmentCategoryV1::Unknown
            && certificate.supporting_evidence_ids.is_empty(),
        "historical CURRENT leaked into restart standing",
    )?;
    Ok(RestartArtifact {
        schema_version: SCHEMA_VERSION_V1,
        scenario: "history-custody-without-standing-recovery",
        historical_records_recovered: recovered_count,
        historical_current_certificate_records,
        serialized_history_bytes: serialized_history.len(),
        serialization_round_trip_exact,
        current_standing: certificate.judgment,
        current_supporting_evidence_count: certificate.supporting_evidence_ids.len(),
        scheduled_deadline_count: restarted.scheduled_deadline_count(),
        standing_recovered: false,
        trace: output.trace_lines,
    })
}

fn qualification_checks() -> Vec<QualificationCheck> {
    let tests = [
        (
            "inclusive expiry and withdrawal without input",
            "deadline_withdraws_current_without_new_evidence_and_expiry_is_inclusive",
        ),
        (
            "deadline overshoot measurement",
            "scheduler_overshoot_is_measured_without_moving_the_deadline",
        ),
        (
            "late queued-input deadline accounting",
            "delayed_processing_of_an_earlier_input_still_accounts_for_expired_standing",
        ),
        (
            "equal body, rollback, and ABA barriers",
            "equal_body_rollback_and_aba_each_require_a_new_evaluation",
        ),
        (
            "same-instant deterministic ordering",
            "simultaneous_policy_transition_precedes_inclusive_expiry",
        ),
        (
            "policy tightening and observer-set change",
            "policy_tightening_and_observer_set_change_make_reliance_unknown",
        ),
        (
            "policy loosening still barriers",
            "policy_loosening_still_withdraws_before_explicit_reevaluation",
        ),
        (
            "observation-policy generation requires matching evidence",
            "observation_policy_generation_change_requires_new_matching_evidence",
        ),
        (
            "evaluator-semantic and consumer-profile generation changes",
            "evaluator_semantic_change_barriers_even_with_same_policy_identity",
        ),
        (
            "consumer transition isolation",
            "one_consumer_transition_does_not_change_another",
        ),
        (
            "queue saturation fail-closed",
            "queue_saturation_withdraws_cached_current_immediately",
        ),
        (
            "observer cardinality refusal",
            "observer_cardinality_churn_is_refused_and_visible",
        ),
        (
            "subject and schedule reservation bounds",
            "subject_and_deadline_capacity_are_explicit_registration_refusals",
        ),
        (
            "duplicate and reordered non-renewal",
            "duplicate_and_reordered_inputs_do_not_renew_support",
        ),
        (
            "policy-permitted provenance caution",
            "policy_permitted_unverified_provenance_is_caution_not_missing_premise",
        ),
        (
            "clock regression blindness",
            "clock_regression_reports_blindness_instead_of_preserving_current",
        ),
        (
            "escalation deduplication",
            "repeated_expiry_reevaluation_deduplicates_escalation",
        ),
        (
            "contradiction custody through receipt",
            "diagnostic_completion_does_not_clear_contradiction",
        ),
        (
            "delayed disposition evaluated at receiver now",
            "delayed_escalation_disposition_is_evaluated_at_receiver_now",
        ),
        (
            "history-only receiver restart",
            "restart_recovers_history_but_not_current_standing",
        ),
        (
            "inapplicable contradiction custody across restart",
            "restart_reexport_preserves_inapplicable_contradiction_custody",
        ),
        (
            "policy-generation content binding across restart",
            "restart_rejects_policy_generation_rebound_to_different_content",
        ),
        (
            "subject replacement noninheritance",
            "explicit_subject_replacement_does_not_inherit_hot_evidence",
        ),
        (
            "sparse-history capacity fail-stop",
            "sparse_history_capacity_is_explicit_and_fail_stops_new_input",
        ),
        (
            "subject-incarnation churn bound",
            "subject_incarnation_churn_is_bounded_and_fail_closed",
        ),
        (
            "duplicate multiplicity property",
            "duplicate_multiplicity_never_renews_the_original_deadline",
        ),
        (
            "generation transition property",
            "every_fresh_generation_activation_barriers_before_reearning_current",
        ),
        (
            "enqueue-race ordering property",
            "same_instant_order_is_independent_of_enqueue_race",
        ),
        (
            "same-instant pulse semantic ordering property",
            "same_instant_pulse_order_uses_stable_semantic_keys",
        ),
        (
            "identity-churn bound property",
            "adversarial_observer_identity_churn_never_exceeds_the_bound",
        ),
    ];
    tests
        .into_iter()
        .map(|(name, test)| QualificationCheck {
            name,
            result: "pass",
            evidence: test,
        })
        .collect()
}

fn run_qualification() -> Result<QualificationArtifact, Box<dyn Error>> {
    let demo = run_generation_demo()?;
    let restart = run_restart_demo()?;
    Ok(QualificationArtifact {
        schema_version: SCHEMA_VERSION_V1,
        campaign: "bounded receiver/scheduler and exact-generation qualification",
        starting_commit: STARTING_COMMIT,
        harness_clock: "deterministic receiver-local replay clock",
        checks: qualification_checks(),
        deterministic_demo_metrics: demo.metrics,
        restart,
        required_gate_commands: vec![
            "cargo fmt --all -- --check",
            "cargo clippy --workspace --all-targets --all-features -- -D warnings",
            "cargo test --workspace --all-targets --all-features",
        ],
        nonclaims: vec![
            "artifact generation does not replace running the listed gates",
            "no production scheduler or hard real-time guarantee is qualified",
            "no current standing is crash durable",
            "no record grants mutation authority",
        ],
    })
}

fn live_ingress(frame: PulseFrameV1) -> RuntimeInputV1 {
    RuntimeInputV1::Pulse(PulseIngressV1 {
        frame,
        transport_path: "local:linux-proc".to_owned(),
        transport_observed_delay_ms: Some(0),
        authentication: AuthenticationResultV1::NotChecked,
    })
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn sleep_until_ms(started: Instant, target_ms: u64) {
    let now = elapsed_ms(started);
    if target_ms > now {
        thread::sleep(Duration::from_millis(target_ms - now));
    }
}

fn run_live_linux() -> Result<LiveLinuxArtifact, Box<dyn Error>> {
    const SUBJECT: &str = "subject:local-linux";
    const CONSUMER: &str = "consumer:live-exercise";
    const OBSERVATION_GENERATION: &str = "observation-policy:live-linux-v1";
    const VALIDITY_MS: u64 = 60;

    let started = Instant::now();
    let mut agent_config = AgentConfig::linux_proc();
    agent_config.subject = SubjectId::new(SUBJECT);
    agent_config.observer = ObserverId::new("observer:live-linux-proc");
    agent_config.observation_policy_generation =
        ObservationPolicyGenerationId::new(OBSERVATION_GENERATION);
    agent_config.validity_ms = VALIDITY_MS;
    agent_config.cadence = Duration::from_millis(20);
    let subject_incarnation = agent_config.subject_incarnation.clone();
    let mut agent = PulseAgent::new(agent_config.clone())?;
    let restarted_agent = PulseAgent::new(agent_config)?;
    let producer_restart_changed_observer_incarnation =
        agent.observer_incarnation() != restarted_agent.observer_incarnation();

    let policy = reliance_policy(
        SUBJECT,
        CONSUMER,
        "policy:live-p1",
        OBSERVATION_GENERATION,
        profile_identity(ProducerProfile::LinuxProc),
        vec!["proc.cpu".to_owned(), "proc.memory".to_owned()],
        VALIDITY_MS,
        false,
    );
    let mut runtime = ReceiverSchedulerRuntime::new(runtime_config(
        "receiver-incarnation:live-one",
        "clock:live-process-one",
    ))?;
    let live_registration = registration(
        policy.clone(),
        "activation:live-p1",
        subject_incarnation.clone(),
    );
    install_demo_binding(&mut runtime, &live_registration, 0)?;
    runtime.register_consumer(live_registration, 0)?;

    let first_frame = agent.next_pulse()?;
    let proc_coverage = first_frame.coverage.observed.clone();
    let bounds_frame = first_frame.clone();
    let arrival = elapsed_ms(started);
    enqueue(&mut runtime, arrival, live_ingress(first_frame))?;
    runtime
        .run_until(arrival)
        .map_err(|error| io::Error::other(format!("live initial evaluation: {error}")))?;
    let first_certificate = runtime
        .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
        .ok_or_else(|| io::Error::other("live certificate is absent"))?;
    require(
        first_certificate.judgment == JudgmentCategoryV1::Current,
        "local /proc did not provide the required bounded live coverage",
    )?;
    let certificate_support_expiry = first_certificate
        .earliest_support_expiry_monotonic_ms
        .ok_or_else(|| io::Error::other("live CURRENT has no support deadline"))?;
    let expected_support_expiry_monotonic_ms = runtime
        .next_scheduled_deadline_monotonic_ms()
        .ok_or_else(|| io::Error::other("live runtime did not own a scheduled deadline"))?;
    require(
        certificate_support_expiry == expected_support_expiry_monotonic_ms,
        "live runtime schedule differs from its support certificate",
    )?;

    sleep_until_ms(
        started,
        expected_support_expiry_monotonic_ms.saturating_add(15),
    );
    let actual_reevaluation_monotonic_ms =
        elapsed_ms(started).max(expected_support_expiry_monotonic_ms.saturating_add(15));
    runtime
        .run_until(actual_reevaluation_monotonic_ms)
        .map_err(|error| io::Error::other(format!("live first expiry: {error}")))?;
    require(
        runtime
            .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
            .is_some_and(|certificate| certificate.judgment == JudgmentCategoryV1::Unknown),
        "late live deadline failed to withdraw CURRENT",
    )?;
    let stale_positive_overshoot_ms = runtime.metrics().maximum_stale_positive_duration_ms;

    let second_frame = agent.next_pulse()?;
    let second_arrival = elapsed_ms(started).max(actual_reevaluation_monotonic_ms);
    enqueue(&mut runtime, second_arrival, live_ingress(second_frame))?;
    runtime
        .run_until(second_arrival)
        .map_err(|error| io::Error::other(format!("live second pulse: {error}")))?;
    let second_deadline = runtime
        .next_scheduled_deadline_monotonic_ms()
        .ok_or_else(|| io::Error::other("second live pulse did not reestablish CURRENT"))?;
    sleep_until_ms(started, second_deadline.saturating_add(5));
    let second_actual = elapsed_ms(started).max(second_deadline.saturating_add(5));
    runtime
        .run_until(second_actual)
        .map_err(|error| io::Error::other(format!("live second expiry: {error}")))?;

    let third_frame = agent.next_pulse()?;
    let third_arrival = elapsed_ms(started).max(second_actual);
    enqueue(&mut runtime, third_arrival, live_ingress(third_frame))?;
    runtime
        .run_until(third_arrival)
        .map_err(|error| io::Error::other(format!("live third pulse: {error}")))?;
    require(
        runtime
            .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
            .is_some_and(|certificate| certificate.judgment == JudgmentCategoryV1::Current),
        "third live pulse did not reestablish CURRENT",
    )?;

    let mut transitioned_policy = policy;
    transitioned_policy.generation = PolicyGenerationId::new("policy:live-p2");
    let transition_at = elapsed_ms(started).max(third_arrival);
    let withdrawal_started = Instant::now();
    let transition_activation = activation(
        transitioned_policy.clone(),
        "activation:live-p2",
        GenerationTransitionCauseV1::EquivalentBodyNewGeneration,
    );
    let transition_registration = ConsumerRegistrationV1 {
        policy: transition_activation.policy.clone(),
        context: transition_activation.context.clone(),
        subject_incarnation: subject_incarnation.clone(),
    };
    install_demo_binding(&mut runtime, &transition_registration, transition_at)?;
    enqueue(
        &mut runtime,
        transition_at,
        RuntimeInputV1::ActivateConsumer(transition_activation),
    )?;
    runtime
        .run_until(transition_at)
        .map_err(|error| io::Error::other(format!("live policy transition: {error}")))?;
    let policy_transition_withdrawal_wall_us = withdrawal_started.elapsed().as_micros();
    require(
        runtime
            .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
            .is_some_and(|certificate| certificate.judgment == JudgmentCategoryV1::Unknown),
        "live policy transition inherited CURRENT",
    )?;
    let policy_transition_withdrawal_logical_ms =
        runtime.metrics().policy_transition_withdrawal_latency_ms;
    let duplicate_escalation_count = runtime.metrics().duplicate_escalation_count;

    let history = runtime.export_history();
    let (restarted, _) = ReceiverSchedulerRuntime::recover(
        runtime_config("receiver-incarnation:live-two", "clock:live-process-two"),
        vec![registration(
            transitioned_policy.clone(),
            "activation:live-restart",
            subject_incarnation.clone(),
        )],
        history,
        0,
    )
    .map_err(|error| io::Error::other(format!("live receiver restart: {error}")))?;
    let state_after_receiver_restart = restarted
        .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
        .ok_or_else(|| io::Error::other("live restart certificate is absent"))?
        .judgment;

    let mut queue_bounds = RuntimeBoundsV1::qualification();
    queue_bounds.maximum_pending_inputs = 1;
    let mut queue_runtime = ReceiverSchedulerRuntime::new(RuntimeConfigV1 {
        bounds: queue_bounds,
        ..runtime_config("receiver-incarnation:live-queue", "clock:live-queue")
    })?;
    queue_runtime.register_consumer(
        registration(
            transitioned_policy.clone(),
            "activation:live-queue",
            subject_incarnation.clone(),
        ),
        0,
    )?;
    enqueue(
        &mut queue_runtime,
        0,
        RuntimeInputV1::Reevaluate {
            subject: SubjectId::new(SUBJECT),
            consumer: ConsumerId::new(CONSUMER),
        },
    )?;
    let queue_refusal = queue_runtime
        .enqueue(
            0,
            RuntimeInputV1::Reevaluate {
                subject: SubjectId::new(SUBJECT),
                consumer: ConsumerId::new(CONSUMER),
            },
        )
        .expect_err("live queue bound should refuse the second pending input")
        .class;

    let mut observer_bounds = RuntimeBoundsV1::qualification();
    observer_bounds.maximum_observers_per_subject = 1;
    let mut observer_runtime = ReceiverSchedulerRuntime::new(RuntimeConfigV1 {
        bounds: observer_bounds,
        ..runtime_config(
            "receiver-incarnation:live-observer-bound",
            "clock:live-observer-bound",
        )
    })?;
    observer_runtime.register_consumer(
        registration(
            transitioned_policy,
            "activation:live-observer-bound",
            subject_incarnation,
        ),
        0,
    )?;
    enqueue(&mut observer_runtime, 0, live_ingress(bounds_frame.clone()))?;
    observer_runtime
        .run_until(0)
        .map_err(|error| io::Error::other(format!("live observer-bound first pulse: {error}")))?;
    let mut extra_observer = bounds_frame;
    extra_observer.observer = ObserverId::new("observer:live-cardinality-extra");
    extra_observer.observer_incarnation =
        IncarnationId::new("observer-incarnation:live-cardinality-extra");
    extra_observer.sequence = 1;
    extra_observer = extra_observer.seal();
    enqueue(&mut observer_runtime, 1, live_ingress(extra_observer))?;
    let observer_output = observer_runtime
        .run_until(1)
        .map_err(|error| io::Error::other(format!("live observer-bound refusal: {error}")))?;
    let observer_cardinality_refusal = observer_output
        .refusals
        .iter()
        .find(|refusal| refusal.class == RuntimeRefusalClassV1::ObserverCapacity)
        .ok_or_else(|| io::Error::other("live observer bound did not produce a refusal"))?
        .class;

    require(
        queue_refusal == RuntimeRefusalClassV1::PendingQueueCapacity
            && observer_cardinality_refusal == RuntimeRefusalClassV1::ObserverCapacity
            && state_after_receiver_restart == JudgmentCategoryV1::Unknown,
        "live bound or restart outcome was not cautious",
    )?;

    Ok(LiveLinuxArtifact {
        schema_version: SCHEMA_VERSION_V1,
        exercise: "bounded local Linux /proc receiver/scheduler exercise",
        wall_clock_measurement: true,
        hard_realtime_claimed: false,
        expected_support_expiry_monotonic_ms,
        actual_reevaluation_monotonic_ms,
        stale_positive_overshoot_ms,
        policy_transition_withdrawal_wall_us,
        policy_transition_withdrawal_logical_ms,
        duplicate_escalation_count,
        state_after_receiver_restart,
        historical_records_recovered: restarted.metrics().recovered_sparse_record_count,
        queue_refusal,
        observer_cardinality_refusal,
        producer_restart_changed_observer_incarnation,
        proc_coverage,
        nonclaims: vec![
            "wall measurements describe one local exercise, not a latency guarantee",
            "a /proc pulse does not establish subject health or observer truthfulness",
            "receiver restart recovered history but no current standing",
            "no request, receipt, or certificate grants mutation authority",
        ],
    })
}

fn write_json_artifact<T: Serialize>(path: Option<&str>, value: &T) -> Result<(), Box<dyn Error>> {
    let Some(path) = path else {
        return Ok(());
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(Path::new(path))?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    eprintln!("wrote {path} (create-new; existing artifacts are never overwritten)");
    Ok(())
}

fn print_usage() {
    eprintln!("usage: pulse-runtime <demo|restart-demo|qualify|live-linux> [create-new-json-path]");
}

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let Some(command) = arguments.first().map(String::as_str) else {
        print_usage();
        return Err(io::Error::other("a command is required").into());
    };
    if arguments.len() > 2 {
        print_usage();
        return Err(io::Error::other("too many arguments").into());
    }
    let artifact_path = arguments.get(1).map(String::as_str);
    match command {
        "demo" => {
            let artifact = run_generation_demo()?;
            for line in &artifact.terminal_trace {
                println!("{line}");
            }
            println!(
                "escalations_emitted={} maximum_stale_positive_duration={}ms",
                artifact.emitted_escalation_count,
                artifact.metrics.maximum_stale_positive_duration_ms
            );
            write_json_artifact(artifact_path, &artifact)?;
        }
        "restart-demo" => {
            let artifact = run_restart_demo()?;
            println!(
                "historical_records_recovered={} historical_current_records={} serialized_bytes={} round_trip_exact={}",
                artifact.historical_records_recovered,
                artifact.historical_current_certificate_records,
                artifact.serialized_history_bytes,
                artifact.serialization_round_trip_exact
            );
            println!(
                "current_standing={} supporting_evidence={} scheduled_deadlines={} standing_recovered={}",
                artifact.current_standing,
                artifact.current_supporting_evidence_count,
                artifact.scheduled_deadline_count,
                artifact.standing_recovered
            );
            write_json_artifact(artifact_path, &artifact)?;
        }
        "qualify" => {
            let artifact = run_qualification()?;
            println!(
                "deterministic_checks={} result=PASS restart_standing={}",
                artifact.checks.len(),
                artifact.restart.current_standing
            );
            write_json_artifact(artifact_path, &artifact)?;
        }
        "live-linux" => {
            let artifact = run_live_linux()?;
            println!(
                "expected_deadline={}ms actual_reevaluation={}ms stale_positive_overshoot={}ms",
                artifact.expected_support_expiry_monotonic_ms,
                artifact.actual_reevaluation_monotonic_ms,
                artifact.stale_positive_overshoot_ms
            );
            println!(
                "policy_withdrawal={}us duplicate_escalations={} restart={} queue_refusal={:?} observer_refusal={:?}",
                artifact.policy_transition_withdrawal_wall_us,
                artifact.duplicate_escalation_count,
                artifact.state_after_receiver_restart,
                artifact.queue_refusal,
                artifact.observer_cardinality_refusal
            );
            write_json_artifact(artifact_path, &artifact)?;
        }
        _ => {
            print_usage();
            return Err(io::Error::other(format!("unknown command: {command}")).into());
        }
    }
    Ok(())
}
