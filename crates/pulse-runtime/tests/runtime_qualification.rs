use std::collections::{BTreeMap, BTreeSet};

use proptest::prelude::*;
use pulse_evaluator::{EscalationPolicyV1, ReliancePolicyV1};
use pulse_l3_bridge::{StubL3Bridge, stub_profile_identity};
use pulse_runtime::{
    ConsumerActivationV1, ConsumerRegistrationV1, PulseIngressV1, ReceiverSchedulerRuntime,
    RuntimeBoundsV1, RuntimeConfigV1, RuntimeInputV1, qualification_fixture_inputs,
};
use pulse_types::{
    AuthenticationFieldV1, AuthenticationResultV1, BoundedSignalValueV1, BridgeId, ClockId,
    ConsumerId, ConsumerProfileGenerationId, ContextActivationId, CoverageDescriptorV1,
    DiagnosticBoundsV1, EvaluatorSemanticGenerationId, GenerationTransitionCauseV1, IncarnationId,
    JudgmentCategoryV1, MutationAuthorityV1, ObservationPolicyGenerationId, ObservationProfileIdV1,
    ObserverId, ObserverSetGenerationId, PolicyGenerationId, PulseFrameV1, ReceiverId,
    RelianceContextV1, SCHEMA_VERSION_V1, SignalAssessmentV1, SubjectId, digest_parts,
};

const SUBJECT: &str = "subject:runtime-test";
const CONSUMER: &str = "consumer:display";
const SUBJECT_INCAR: &str = "subject-incarnation:one";

fn profile() -> ObservationProfileIdV1 {
    ObservationProfileIdV1 {
        name: "profile:runtime-test".to_owned(),
        version: 1,
        semantic_digest: digest_parts("runtime.test.profile", &[b"load", b"memory"]),
    }
}

fn policy(
    subject: &str,
    consumer: &str,
    generation: &str,
    minimum_observers: u32,
    validity_ms: u64,
) -> ReliancePolicyV1 {
    ReliancePolicyV1 {
        schema_version: SCHEMA_VERSION_V1,
        subject: SubjectId::new(subject),
        scope: "host".to_owned(),
        consumer: ConsumerId::new(consumer),
        generation: PolicyGenerationId::new(generation),
        observation_policy_generation: ObservationPolicyGenerationId::new(
            "observation-policy:runtime-v1",
        ),
        observation_profile: profile(),
        required_coverage: vec!["load".to_owned(), "memory".to_owned()],
        minimum_observers,
        maximum_validity_ms: validity_ms,
        require_verified_authentication: true,
        coherence_tolerances: BTreeMap::from([("load_ratio".to_owned(), 0.10)]),
        observer_failure_domains: BTreeMap::new(),
        escalation: Some(EscalationPolicyV1 {
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
            request_ttl_ms: 250,
        }),
    }
}

fn context(
    policy: &ReliancePolicyV1,
    activation: &str,
    consumer_generation: &str,
    evaluator_generation: &str,
    observer_set_generation: &str,
) -> RelianceContextV1 {
    RelianceContextV1 {
        schema_version: SCHEMA_VERSION_V1,
        activation_id: ContextActivationId::new(activation),
        reliance_policy_generation: policy.generation.clone(),
        reliance_policy_semantic_digest: policy.semantic_digest(),
        consumer_profile_generation: ConsumerProfileGenerationId::new(consumer_generation),
        evaluator_semantic_generation: EvaluatorSemanticGenerationId::new(evaluator_generation),
        observer_set_generation: ObserverSetGenerationId::new(observer_set_generation),
        observation_policy_generation: policy.observation_policy_generation.clone(),
    }
}

fn config_with(bounds: RuntimeBoundsV1, incarnation: &str, clock: &str) -> RuntimeConfigV1 {
    RuntimeConfigV1 {
        schema_version: SCHEMA_VERSION_V1,
        receiver: ReceiverId::new("receiver:runtime-test"),
        receiver_incarnation: IncarnationId::new(incarnation),
        clock_id: ClockId::new(clock),
        transport_custody_policy: None,
        bounds,
    }
}

fn config() -> RuntimeConfigV1 {
    config_with(
        RuntimeBoundsV1::qualification(),
        "receiver-incarnation:one",
        "clock:one",
    )
}

fn registration(
    policy: ReliancePolicyV1,
    activation: &str,
    subject_incarnation: &str,
) -> ConsumerRegistrationV1 {
    let context = context(
        &policy,
        activation,
        "consumer-profile:one",
        "evaluator:one",
        "observer-set:one",
    );
    ConsumerRegistrationV1 {
        policy,
        context,
        subject_incarnation: IncarnationId::new(subject_incarnation),
    }
}

fn activation(
    policy: ReliancePolicyV1,
    activation: &str,
    cause: GenerationTransitionCauseV1,
) -> ConsumerActivationV1 {
    let context = context(
        &policy,
        activation,
        "consumer-profile:one",
        "evaluator:one",
        "observer-set:one",
    );
    ConsumerActivationV1 {
        policy,
        context,
        cause,
    }
}

fn install_binding(
    runtime: &mut ReceiverSchedulerRuntime,
    registration: &ConsumerRegistrationV1,
    at_monotonic_ms: u64,
) {
    runtime
        .qualify_and_activate_local_binding(
            registration,
            qualification_fixture_inputs("3cd15b7a1e7f424f6fd57c09b30fa4790947eca2", 97),
            at_monotonic_ms,
        )
        .expect("local exact binding activates");
}

fn register_qualified(
    runtime: &mut ReceiverSchedulerRuntime,
    registration: ConsumerRegistrationV1,
    at_monotonic_ms: u64,
) {
    install_binding(runtime, &registration, at_monotonic_ms);
    runtime
        .register_consumer(registration, at_monotonic_ms)
        .expect("consumer registers");
}

fn install_activation_binding(
    runtime: &mut ReceiverSchedulerRuntime,
    activation: &ConsumerActivationV1,
    subject_incarnation: &str,
    at_monotonic_ms: u64,
) {
    install_binding(
        runtime,
        &ConsumerRegistrationV1 {
            policy: activation.policy.clone(),
            context: activation.context.clone(),
            subject_incarnation: IncarnationId::new(subject_incarnation),
        },
        at_monotonic_ms,
    );
}

#[allow(clippy::too_many_arguments)]
fn pulse(
    subject: &str,
    subject_incarnation: &str,
    observer: &str,
    observer_incarnation: &str,
    sequence: u64,
    validity_ms: u64,
    load: SignalAssessmentV1,
    load_value: f64,
) -> PulseFrameV1 {
    PulseFrameV1 {
        schema_version: SCHEMA_VERSION_V1,
        subject: SubjectId::new(subject),
        subject_incarnation: IncarnationId::new(subject_incarnation),
        observer: ObserverId::new(observer),
        observer_incarnation: IncarnationId::new(observer_incarnation),
        sequence,
        observer_monotonic_ns: sequence.saturating_mul(1_000_000),
        validity_ms,
        profile: profile(),
        observation_policy_generation: ObservationPolicyGenerationId::new(
            "observation-policy:runtime-v1",
        ),
        coverage: CoverageDescriptorV1 {
            expected: vec!["load".to_owned(), "memory".to_owned()],
            observed: vec!["load".to_owned(), "memory".to_owned()],
        },
        signals: vec![
            BoundedSignalValueV1 {
                name: "load_ratio".to_owned(),
                value: load_value,
                unit: "ratio".to_owned(),
                assessment: load,
            },
            BoundedSignalValueV1 {
                name: "memory_ratio".to_owned(),
                value: 0.70,
                unit: "ratio".to_owned(),
                assessment: SignalAssessmentV1::WithinDeclaredBound,
            },
        ],
        observation_digest: digest_parts("unsealed", &[]),
        authentication: AuthenticationFieldV1::Mac {
            scheme: "fixture".to_owned(),
            key_id: "fixture-key".to_owned(),
            tag: "not-cryptographic".to_owned(),
        },
    }
    .seal()
}

fn ingress(frame: PulseFrameV1) -> RuntimeInputV1 {
    RuntimeInputV1::Pulse(PulseIngressV1 {
        frame,
        transport_path: "test:loopback".to_owned(),
        transport_observed_delay_ms: Some(0),
        authentication: AuthenticationResultV1::Verified {
            method: "fixture".to_owned(),
            principal: "observer-fixture".to_owned(),
        },
    })
}

fn one_consumer_runtime(validity_ms: u64) -> ReceiverSchedulerRuntime {
    let mut runtime = ReceiverSchedulerRuntime::new(config()).expect("runtime config");
    register_qualified(
        &mut runtime,
        registration(
            policy(SUBJECT, CONSUMER, "policy:p1", 1, validity_ms),
            "activation:p1",
            SUBJECT_INCAR,
        ),
        0,
    );
    runtime
}

fn establish_current(runtime: &mut ReceiverSchedulerRuntime, at: u64, validity_ms: u64) {
    runtime
        .enqueue(
            at,
            ingress(pulse(
                SUBJECT,
                SUBJECT_INCAR,
                "observer:a",
                "observer-incarnation:a1",
                1,
                validity_ms,
                SignalAssessmentV1::WithinDeclaredBound,
                0.20,
            )),
        )
        .expect("pulse enqueues");
    runtime.run_until(at).expect("pulse evaluates");
    assert_eq!(
        runtime
            .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
            .expect("certificate")
            .judgment,
        JudgmentCategoryV1::Current
    );
}

#[test]
fn deadline_withdraws_current_without_new_evidence_and_expiry_is_inclusive() {
    let mut runtime = one_consumer_runtime(100);
    establish_current(&mut runtime, 0, 100);
    assert_eq!(runtime.scheduled_deadline_count(), 1);

    let output = runtime.run_until(100).expect("deadline evaluates");
    assert!(
        output
            .trace_lines
            .iter()
            .any(|line| line.contains("DEADLINE"))
    );
    let current = runtime
        .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
        .expect("certificate");
    assert_eq!(current.judgment, JudgmentCategoryV1::Unknown);
    assert_eq!(runtime.metrics().maximum_stale_positive_duration_ms, 0);
    assert_eq!(runtime.scheduled_deadline_count(), 0);
}

#[test]
fn scheduler_overshoot_is_measured_without_moving_the_deadline() {
    let mut runtime = one_consumer_runtime(100);
    establish_current(&mut runtime, 0, 100);
    runtime.run_until(123).expect("late scheduler evaluates");
    assert_eq!(
        runtime.metrics().expected_support_expiry_monotonic_ms,
        Some(100)
    );
    assert_eq!(
        runtime.metrics().actual_reevaluation_monotonic_ms,
        Some(123)
    );
    assert_eq!(runtime.metrics().scheduler_lateness_ms, 23);
    assert_eq!(runtime.metrics().maximum_stale_positive_duration_ms, 23);
}

#[test]
fn delayed_processing_of_an_earlier_input_still_accounts_for_expired_standing() {
    let mut runtime = one_consumer_runtime(100);
    establish_current(&mut runtime, 0, 100);
    runtime
        .enqueue(
            50,
            ingress(pulse(
                SUBJECT,
                SUBJECT_INCAR,
                "observer:a",
                "observer-incarnation:a1",
                2,
                100,
                SignalAssessmentV1::WithinDeclaredBound,
                0.20,
            )),
        )
        .expect("earlier pulse enqueues");
    runtime.run_until(200).expect("late batch evaluates");
    assert_eq!(
        runtime.metrics().expected_support_expiry_monotonic_ms,
        Some(100)
    );
    assert_eq!(
        runtime.metrics().actual_reevaluation_monotonic_ms,
        Some(200)
    );
    assert_eq!(runtime.metrics().maximum_stale_positive_duration_ms, 100);
    assert_eq!(
        runtime
            .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
            .expect("expired certificate")
            .judgment,
        JudgmentCategoryV1::Unknown
    );
}

#[test]
fn equal_body_rollback_and_aba_each_require_a_new_evaluation() {
    let mut runtime = one_consumer_runtime(200);
    establish_current(&mut runtime, 0, 200);
    let original = runtime
        .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
        .expect("original")
        .clone();

    let p1 = policy(SUBJECT, CONSUMER, "policy:p1", 1, 200);
    let mut p2 = p1.clone();
    p2.generation = PolicyGenerationId::new("policy:p2");
    assert_eq!(p1.semantic_digest(), p2.semantic_digest());
    let p2_activation = activation(
        p2.clone(),
        "activation:p2",
        GenerationTransitionCauseV1::EquivalentBodyNewGeneration,
    );
    install_activation_binding(&mut runtime, &p2_activation, SUBJECT_INCAR, 10);
    runtime
        .enqueue(10, RuntimeInputV1::ActivateConsumer(p2_activation))
        .expect("transition enqueues");
    runtime.run_until(10).expect("barrier evaluates");
    let p2_barrier = runtime
        .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
        .expect("p2 barrier")
        .clone();
    assert_eq!(p2_barrier.judgment, JudgmentCategoryV1::Unknown);
    assert_ne!(p2_barrier.certificate_id, original.certificate_id);

    runtime
        .enqueue(
            10,
            RuntimeInputV1::Reevaluate {
                subject: SubjectId::new(SUBJECT),
                consumer: ConsumerId::new(CONSUMER),
            },
        )
        .expect("reevaluation enqueues");
    runtime.run_until(10).expect("explicit p2 evaluation");
    assert_eq!(
        runtime
            .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
            .expect("p2 current")
            .judgment,
        JudgmentCategoryV1::Current
    );

    let mut p3 = p1.clone();
    p3.generation = PolicyGenerationId::new("policy:p3-rollback-body");
    let p3_activation = activation(
        p3,
        "activation:p3",
        GenerationTransitionCauseV1::PolicyRollback,
    );
    install_activation_binding(&mut runtime, &p3_activation, SUBJECT_INCAR, 20);
    runtime
        .enqueue(20, RuntimeInputV1::ActivateConsumer(p3_activation))
        .expect("rollback enqueues");
    runtime.run_until(20).expect("rollback barrier");
    assert_eq!(
        runtime
            .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
            .expect("rollback barrier")
            .judgment,
        JudgmentCategoryV1::Unknown
    );

    let aba_activation = activation(
        p1,
        "activation:p1-aba-return",
        GenerationTransitionCauseV1::AbaReactivation,
    );
    install_activation_binding(&mut runtime, &aba_activation, SUBJECT_INCAR, 30);
    runtime
        .enqueue(30, RuntimeInputV1::ActivateConsumer(aba_activation))
        .expect("ABA enqueues");
    runtime.run_until(30).expect("ABA barrier");
    let aba = runtime
        .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
        .expect("ABA certificate");
    assert_eq!(aba.judgment, JudgmentCategoryV1::Unknown);
    assert_eq!(aba.context.reliance_policy_generation.as_str(), "policy:p1");
    assert_eq!(
        aba.context.activation_id.as_str(),
        "activation:p1-aba-return"
    );
    assert_ne!(aba.certificate_id, original.certificate_id);
}

#[test]
fn simultaneous_policy_transition_precedes_inclusive_expiry() {
    let mut runtime = one_consumer_runtime(100);
    establish_current(&mut runtime, 0, 100);
    let mut p2 = policy(SUBJECT, CONSUMER, "policy:p1", 1, 100);
    p2.generation = PolicyGenerationId::new("policy:p2");
    runtime
        .enqueue(
            100,
            RuntimeInputV1::Reevaluate {
                subject: SubjectId::new(SUBJECT),
                consumer: ConsumerId::new(CONSUMER),
            },
        )
        .expect("reevaluation enqueues first");
    runtime
        .enqueue(
            100,
            RuntimeInputV1::ActivateConsumer(activation(
                p2,
                "activation:p2",
                GenerationTransitionCauseV1::ReliancePolicyChanged,
            )),
        )
        .expect("transition enqueues second");
    let output = runtime.run_until(100).expect("same-instant batch");
    let p2_certificates = output
        .certificates
        .iter()
        .filter(|certificate| certificate.context.activation_id.as_str() == "activation:p2")
        .collect::<Vec<_>>();
    assert!(!p2_certificates.is_empty());
    assert!(
        p2_certificates
            .iter()
            .all(|certificate| certificate.judgment != JudgmentCategoryV1::Current)
    );
}

#[test]
fn policy_tightening_and_observer_set_change_make_reliance_unknown() {
    let mut runtime = one_consumer_runtime(200);
    establish_current(&mut runtime, 0, 200);
    let tightened = policy(SUBJECT, CONSUMER, "policy:tight", 2, 200);
    let mut next = activation(
        tightened,
        "activation:tight",
        GenerationTransitionCauseV1::ObserverSetChanged,
    );
    next.context.observer_set_generation = ObserverSetGenerationId::new("observer-set:two");
    runtime
        .enqueue(10, RuntimeInputV1::ActivateConsumer(next))
        .expect("tightening enqueues");
    runtime
        .enqueue(
            10,
            RuntimeInputV1::Reevaluate {
                subject: SubjectId::new(SUBJECT),
                consumer: ConsumerId::new(CONSUMER),
            },
        )
        .expect("reevaluation enqueues");
    runtime.run_until(10).expect("tight policy evaluates");
    assert_eq!(
        runtime
            .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
            .expect("tight certificate")
            .judgment,
        JudgmentCategoryV1::Unknown
    );
}

#[test]
fn policy_loosening_still_withdraws_before_explicit_reevaluation() {
    let mut runtime = ReceiverSchedulerRuntime::new(config()).expect("runtime");
    register_qualified(
        &mut runtime,
        registration(
            policy(SUBJECT, CONSUMER, "policy:tight-first", 2, 200),
            "activation:tight-first",
            SUBJECT_INCAR,
        ),
        0,
    );
    for observer in ["observer:a", "observer:b"] {
        runtime
            .enqueue(
                0,
                ingress(pulse(
                    SUBJECT,
                    SUBJECT_INCAR,
                    observer,
                    &format!("{observer}:incarnation"),
                    1,
                    200,
                    SignalAssessmentV1::WithinDeclaredBound,
                    0.20,
                )),
            )
            .expect("pulse enqueues");
    }
    runtime.run_until(0).expect("tight policy becomes current");
    assert_eq!(
        runtime
            .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
            .expect("tight certificate")
            .judgment,
        JudgmentCategoryV1::Current
    );
    let loosened = activation(
        policy(SUBJECT, CONSUMER, "policy:loosened", 1, 200),
        "activation:loosened",
        GenerationTransitionCauseV1::ReliancePolicyChanged,
    );
    install_activation_binding(&mut runtime, &loosened, SUBJECT_INCAR, 10);
    runtime
        .enqueue(10, RuntimeInputV1::ActivateConsumer(loosened))
        .expect("looser policy enqueues");
    runtime
        .run_until(10)
        .expect("looser policy barrier evaluates");
    assert_eq!(
        runtime
            .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
            .expect("looser barrier")
            .judgment,
        JudgmentCategoryV1::Unknown
    );
    runtime
        .enqueue(
            10,
            RuntimeInputV1::Reevaluate {
                subject: SubjectId::new(SUBJECT),
                consumer: ConsumerId::new(CONSUMER),
            },
        )
        .expect("explicit reevaluation enqueues");
    runtime.run_until(10).expect("looser policy reevaluates");
    assert_eq!(
        runtime
            .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
            .expect("looser exact certificate")
            .judgment,
        JudgmentCategoryV1::Current
    );
}

#[test]
fn observation_policy_generation_change_requires_new_matching_evidence() {
    let mut runtime = one_consumer_runtime(200);
    establish_current(&mut runtime, 0, 200);
    let mut next_policy = policy(SUBJECT, CONSUMER, "policy:observation-two", 1, 200);
    next_policy.observation_policy_generation =
        ObservationPolicyGenerationId::new("observation-policy:runtime-v2");
    let next_activation = activation(
        next_policy,
        "activation:observation-two",
        GenerationTransitionCauseV1::ObservationPolicyChanged,
    );
    install_activation_binding(&mut runtime, &next_activation, SUBJECT_INCAR, 10);
    runtime
        .enqueue(10, RuntimeInputV1::ActivateConsumer(next_activation))
        .expect("observation-policy transition enqueues");
    runtime
        .enqueue(
            10,
            RuntimeInputV1::Reevaluate {
                subject: SubjectId::new(SUBJECT),
                consumer: ConsumerId::new(CONSUMER),
            },
        )
        .expect("reevaluation enqueues");
    runtime.run_until(10).expect("new collection law evaluates");
    assert_eq!(
        runtime
            .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
            .expect("new observation-policy certificate")
            .judgment,
        JudgmentCategoryV1::Unknown
    );

    let mut matching = pulse(
        SUBJECT,
        SUBJECT_INCAR,
        "observer:a",
        "observer-incarnation:a1",
        1,
        200,
        SignalAssessmentV1::WithinDeclaredBound,
        0.20,
    );
    matching.observation_policy_generation =
        ObservationPolicyGenerationId::new("observation-policy:runtime-v2");
    matching = matching.seal();
    runtime
        .enqueue(11, ingress(matching))
        .expect("matching new-generation evidence enqueues");
    runtime
        .run_until(11)
        .expect("matching new-generation evidence evaluates");
    assert_eq!(
        runtime
            .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
            .expect("new-generation current certificate")
            .judgment,
        JudgmentCategoryV1::Current
    );
}

#[test]
fn evaluator_semantic_change_barriers_even_with_same_policy_identity() {
    let mut runtime = one_consumer_runtime(200);
    establish_current(&mut runtime, 0, 200);
    let same_policy = policy(SUBJECT, CONSUMER, "policy:p1", 1, 200);
    let mut next = activation(
        same_policy,
        "activation:evaluator-two",
        GenerationTransitionCauseV1::EvaluatorSemanticsChanged,
    );
    next.context.evaluator_semantic_generation =
        EvaluatorSemanticGenerationId::new("evaluator:two");
    install_activation_binding(&mut runtime, &next, SUBJECT_INCAR, 10);
    runtime
        .enqueue(10, RuntimeInputV1::ActivateConsumer(next))
        .expect("semantic transition enqueues");
    runtime.run_until(10).expect("semantic barrier");
    let certificate = runtime
        .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
        .expect("certificate");
    assert_eq!(certificate.judgment, JudgmentCategoryV1::Unknown);
    assert_eq!(
        certificate.context.evaluator_semantic_generation.as_str(),
        "evaluator:two"
    );
    runtime
        .enqueue(
            10,
            RuntimeInputV1::Reevaluate {
                subject: SubjectId::new(SUBJECT),
                consumer: ConsumerId::new(CONSUMER),
            },
        )
        .expect("semantic reevaluation enqueues");
    runtime.run_until(10).expect("semantic context reearns");
    assert_eq!(
        runtime
            .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
            .expect("semantic current")
            .judgment,
        JudgmentCategoryV1::Current
    );

    let mut consumer_change = activation(
        policy(SUBJECT, CONSUMER, "policy:p1", 1, 200),
        "activation:consumer-profile-two",
        GenerationTransitionCauseV1::ConsumerProfileChanged,
    );
    consumer_change.context.evaluator_semantic_generation =
        EvaluatorSemanticGenerationId::new("evaluator:two");
    consumer_change.context.consumer_profile_generation =
        ConsumerProfileGenerationId::new("consumer-profile:two");
    install_activation_binding(&mut runtime, &consumer_change, SUBJECT_INCAR, 20);
    runtime
        .enqueue(20, RuntimeInputV1::ActivateConsumer(consumer_change))
        .expect("consumer-profile transition enqueues");
    runtime.run_until(20).expect("consumer-profile barrier");
    let certificate = runtime
        .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
        .expect("consumer-profile certificate");
    assert_eq!(certificate.judgment, JudgmentCategoryV1::Unknown);
    assert_eq!(
        certificate.context.consumer_profile_generation.as_str(),
        "consumer-profile:two"
    );
}

#[test]
fn one_consumer_transition_does_not_change_another() {
    let mut runtime = ReceiverSchedulerRuntime::new(config()).expect("runtime");
    let consumer_a = "consumer:a";
    let consumer_b = "consumer:b";
    register_qualified(
        &mut runtime,
        registration(
            policy(SUBJECT, consumer_a, "policy:a1", 1, 200),
            "activation:a1",
            SUBJECT_INCAR,
        ),
        0,
    );
    register_qualified(
        &mut runtime,
        registration(
            policy(SUBJECT, consumer_b, "policy:b1", 1, 200),
            "activation:b1",
            SUBJECT_INCAR,
        ),
        0,
    );
    runtime
        .enqueue(
            0,
            ingress(pulse(
                SUBJECT,
                SUBJECT_INCAR,
                "observer:a",
                "observer-incarnation:a1",
                1,
                200,
                SignalAssessmentV1::WithinDeclaredBound,
                0.20,
            )),
        )
        .expect("pulse enqueues");
    runtime.run_until(0).expect("both evaluate");
    let b_before = runtime
        .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(consumer_b))
        .expect("B certificate")
        .clone();
    let next_a = policy(SUBJECT, consumer_a, "policy:a2", 2, 200);
    let next_a = activation(
        next_a,
        "activation:a2",
        GenerationTransitionCauseV1::ReliancePolicyChanged,
    );
    install_activation_binding(&mut runtime, &next_a, SUBJECT_INCAR, 10);
    runtime
        .enqueue(10, RuntimeInputV1::ActivateConsumer(next_a))
        .expect("A transition enqueues");
    runtime.run_until(10).expect("A transitions");
    let b_after = runtime
        .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(consumer_b))
        .expect("B remains");
    assert_eq!(b_after, &b_before);
    assert_eq!(b_after.judgment, JudgmentCategoryV1::Current);
}

#[test]
fn queue_saturation_withdraws_cached_current_immediately() {
    let mut bounds = RuntimeBoundsV1::qualification();
    bounds.maximum_pending_inputs = 1;
    let mut runtime = ReceiverSchedulerRuntime::new(config_with(
        bounds,
        "receiver-incarnation:queue",
        "clock:queue",
    ))
    .expect("runtime");
    register_qualified(
        &mut runtime,
        registration(
            policy(SUBJECT, CONSUMER, "policy:p1", 1, 200),
            "activation:p1",
            SUBJECT_INCAR,
        ),
        0,
    );
    establish_current(&mut runtime, 0, 200);
    runtime
        .enqueue(
            10,
            RuntimeInputV1::Reevaluate {
                subject: SubjectId::new(SUBJECT),
                consumer: ConsumerId::new(CONSUMER),
            },
        )
        .expect("queue fills");
    let refusal = runtime
        .enqueue(
            10,
            RuntimeInputV1::Reevaluate {
                subject: SubjectId::new(SUBJECT),
                consumer: ConsumerId::new(CONSUMER),
            },
        )
        .expect_err("second item is refused");
    assert_eq!(
        refusal.class,
        pulse_types::RuntimeRefusalClassV1::PendingQueueCapacity
    );
    assert!(!refusal.current_preserved);
    assert_eq!(
        runtime
            .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
            .expect("blind certificate")
            .judgment,
        JudgmentCategoryV1::Unknown
    );
    runtime
        .run_until(10)
        .expect("admitted item drains cautiously");
    runtime
        .enqueue(
            11,
            RuntimeInputV1::RestoreMonitorCapability {
                subject: Some(SubjectId::new(SUBJECT)),
                detail: "operator verified receiver capacity".to_owned(),
            },
        )
        .expect("restore transition enqueues");
    runtime.run_until(11).expect("restore barrier evaluates");
    assert_eq!(
        runtime
            .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
            .expect("restore barrier certificate")
            .judgment,
        JudgmentCategoryV1::Unknown
    );
    runtime
        .enqueue(
            11,
            RuntimeInputV1::Reevaluate {
                subject: SubjectId::new(SUBJECT),
                consumer: ConsumerId::new(CONSUMER),
            },
        )
        .expect("separate reevaluation enqueues");
    runtime
        .run_until(11)
        .expect("separate reevaluation can reconsider evidence");
    assert_eq!(
        runtime
            .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
            .expect("reestablished certificate")
            .judgment,
        JudgmentCategoryV1::Current
    );
}

#[test]
fn observer_cardinality_churn_is_refused_and_visible() {
    let mut bounds = RuntimeBoundsV1::qualification();
    bounds.maximum_observers_per_subject = 1;
    let mut runtime = ReceiverSchedulerRuntime::new(config_with(
        bounds,
        "receiver-incarnation:observer-bound",
        "clock:observer-bound",
    ))
    .expect("runtime");
    register_qualified(
        &mut runtime,
        registration(
            policy(SUBJECT, CONSUMER, "policy:p1", 1, 200),
            "activation:p1",
            SUBJECT_INCAR,
        ),
        0,
    );
    establish_current(&mut runtime, 0, 200);
    runtime
        .enqueue(
            1,
            ingress(pulse(
                SUBJECT,
                SUBJECT_INCAR,
                "observer:churn",
                "observer-incarnation:churn",
                1,
                200,
                SignalAssessmentV1::WithinDeclaredBound,
                0.20,
            )),
        )
        .expect("churn input reaches bounded queue");
    let output = runtime.run_until(1).expect("churn is refused");
    assert!(output.refusals.iter().any(|refusal| {
        refusal.class == pulse_types::RuntimeRefusalClassV1::ObserverCapacity
            && !refusal.current_preserved
    }));
    assert_eq!(runtime.metrics().observer_refusal_count, 1);
    assert_eq!(
        runtime
            .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
            .expect("blind certificate")
            .judgment,
        JudgmentCategoryV1::Unknown
    );
}

#[test]
fn subject_and_deadline_capacity_are_explicit_registration_refusals() {
    let mut bounds = RuntimeBoundsV1::qualification();
    bounds.maximum_subjects = 1;
    bounds.maximum_scheduled_deadlines = 1;
    let mut runtime = ReceiverSchedulerRuntime::new(config_with(
        bounds,
        "receiver-incarnation:registration-bound",
        "clock:registration-bound",
    ))
    .expect("runtime");
    runtime
        .register_consumer(
            registration(
                policy(SUBJECT, CONSUMER, "policy:p1", 1, 100),
                "activation:p1",
                SUBJECT_INCAR,
            ),
            0,
        )
        .expect("first subject registers");
    let subject_error = runtime
        .register_consumer(
            registration(
                policy("subject:two", "consumer:two", "policy:two", 1, 100),
                "activation:two",
                "subject-incarnation:two",
            ),
            0,
        )
        .expect_err("second subject is refused");
    assert_eq!(subject_error.code, "subject_capacity");

    let deadline_error = runtime
        .register_consumer(
            registration(
                policy(SUBJECT, "consumer:second", "policy:second", 1, 100),
                "activation:second",
                SUBJECT_INCAR,
            ),
            0,
        )
        .expect_err("unreservable deadline slot is refused");
    assert_eq!(deadline_error.code, "scheduled_deadline_capacity");
}

#[test]
fn duplicate_and_reordered_inputs_do_not_renew_support() {
    let mut runtime = one_consumer_runtime(100);
    establish_current(&mut runtime, 0, 100);
    for at in [10, 20] {
        runtime
            .enqueue(
                at,
                ingress(pulse(
                    SUBJECT,
                    SUBJECT_INCAR,
                    "observer:a",
                    "observer-incarnation:a1",
                    1,
                    100,
                    SignalAssessmentV1::WithinDeclaredBound,
                    0.20,
                )),
            )
            .expect("duplicate enqueues");
    }
    runtime.run_until(20).expect("duplicates process");
    assert_eq!(
        runtime
            .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
            .expect("still current")
            .earliest_support_expiry_monotonic_ms,
        Some(100)
    );
    runtime.run_until(100).expect("original deadline fires");
    assert_eq!(
        runtime
            .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
            .expect("expired")
            .judgment,
        JudgmentCategoryV1::Unknown
    );
}

#[test]
fn policy_permitted_unverified_provenance_is_caution_not_missing_premise() {
    let mut runtime = ReceiverSchedulerRuntime::new(config()).expect("runtime");
    let mut permissive = policy(SUBJECT, CONSUMER, "policy:permissive-auth", 1, 100);
    permissive.require_verified_authentication = false;
    register_qualified(
        &mut runtime,
        registration(permissive, "activation:permissive-auth", SUBJECT_INCAR),
        0,
    );
    let mut pulse = match ingress(pulse(
        SUBJECT,
        SUBJECT_INCAR,
        "observer:a",
        "observer-incarnation:a1",
        1,
        100,
        SignalAssessmentV1::WithinDeclaredBound,
        0.20,
    )) {
        RuntimeInputV1::Pulse(pulse) => pulse,
        _ => unreachable!("ingress helper always produces a pulse"),
    };
    pulse.authentication = AuthenticationResultV1::NotChecked;
    runtime
        .enqueue(0, RuntimeInputV1::Pulse(pulse))
        .expect("pulse enqueues");
    runtime.run_until(0).expect("pulse evaluates");
    let certificate = runtime
        .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
        .expect("certificate");
    assert_eq!(certificate.judgment, JudgmentCategoryV1::Current);
    assert!(certificate.missing_premises.is_empty());
}

#[test]
fn clock_regression_reports_blindness_instead_of_preserving_current() {
    let mut runtime = one_consumer_runtime(100);
    establish_current(&mut runtime, 10, 100);
    let output = runtime
        .run_until(9)
        .expect("regression is a cautious output");
    assert!(
        output.refusals.iter().any(|refusal| {
            refusal.class == pulse_types::RuntimeRefusalClassV1::ClockRegression
        })
    );
    assert_eq!(
        runtime
            .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
            .expect("blind certificate")
            .judgment,
        JudgmentCategoryV1::Unknown
    );
}

#[test]
fn repeated_expiry_reevaluation_deduplicates_escalation() {
    let mut runtime = one_consumer_runtime(50);
    establish_current(&mut runtime, 0, 50);
    let first = runtime.run_until(50).expect("first expiry");
    assert_eq!(first.escalation_requests.len(), 1);
    runtime
        .enqueue(
            60,
            ingress(pulse(
                SUBJECT,
                SUBJECT_INCAR,
                "observer:a",
                "observer-incarnation:a1",
                2,
                50,
                SignalAssessmentV1::WithinDeclaredBound,
                0.20,
            )),
        )
        .expect("fresh pulse enqueues");
    runtime.run_until(60).expect("current is re-earned");
    let second = runtime.run_until(110).expect("second expiry");
    assert!(second.escalation_requests.is_empty());
    assert_eq!(runtime.metrics().duplicate_escalation_count, 1);
}

#[test]
fn diagnostic_completion_does_not_clear_contradiction() {
    let mut runtime = ReceiverSchedulerRuntime::new(config()).expect("runtime");
    register_qualified(
        &mut runtime,
        registration(
            policy(SUBJECT, CONSUMER, "policy:p1", 2, 200),
            "activation:p1",
            SUBJECT_INCAR,
        ),
        0,
    );
    for observer in ["observer:a", "observer:b"] {
        runtime
            .enqueue(
                0,
                ingress(pulse(
                    SUBJECT,
                    SUBJECT_INCAR,
                    observer,
                    &format!("{observer}:incarnation"),
                    1,
                    200,
                    SignalAssessmentV1::WithinDeclaredBound,
                    0.20,
                )),
            )
            .expect("pulse enqueues");
    }
    runtime.run_until(0).expect("current is established");
    assert_eq!(
        runtime
            .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
            .expect("current certificate")
            .judgment,
        JudgmentCategoryV1::Current
    );
    runtime
        .enqueue(
            10,
            ingress(pulse(
                SUBJECT,
                SUBJECT_INCAR,
                "observer:b",
                "observer:b:incarnation",
                2,
                200,
                SignalAssessmentV1::OutsideDeclaredBound,
                1.20,
            )),
        )
        .expect("contradicting pulse enqueues");
    let contradicted = runtime.run_until(10).expect("contradiction evaluates");
    let request = contradicted
        .escalation_requests
        .first()
        .expect("contradiction escalates")
        .clone();
    assert_eq!(
        runtime
            .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
            .expect("contradicted")
            .judgment,
        JudgmentCategoryV1::Contradicted
    );
    let mut bridge = StubL3Bridge::new(BridgeId::new("bridge:test"), ClockId::new("clock:one"));
    let outcome = bridge.handle(&request, 11);
    runtime
        .enqueue(
            11,
            RuntimeInputV1::EscalationDisposition(outcome.disposition),
        )
        .expect("disposition enqueues");
    runtime.run_until(11).expect("disposition records");
    let receipt = outcome.receipt.expect("accepted stub receipt");
    runtime
        .enqueue(12, RuntimeInputV1::DiagnosticReceipt(receipt))
        .expect("receipt enqueues");
    runtime.run_until(12).expect("receipt records");
    let certificate = runtime
        .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
        .expect("final certificate");
    assert_eq!(certificate.judgment, JudgmentCategoryV1::Contradicted);
    assert!(!certificate.applicable_contradictions.is_empty());
    assert_eq!(certificate.mutation_authority, MutationAuthorityV1::None);

    let history = runtime.export_history();
    assert_eq!(history.diagnostic_receipts.len(), 1);
    let (restarted, _) = ReceiverSchedulerRuntime::recover(
        config_with(
            RuntimeBoundsV1::qualification(),
            "receiver-incarnation:receipt-restart",
            "clock:receipt-restart",
        ),
        vec![registration(
            policy(SUBJECT, CONSUMER, "policy:p1", 2, 200),
            "activation:receipt-restart",
            SUBJECT_INCAR,
        )],
        history,
        0,
    )
    .expect("historical receipt custody recovers");
    let restarted_certificate = restarted
        .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
        .expect("restart certificate");
    assert_eq!(restarted_certificate.judgment, JudgmentCategoryV1::Unknown);
    assert!(!restarted_certificate.applicable_contradictions.is_empty());
    assert_eq!(restarted.metrics().recovered_receipt_count, 1);
    assert_eq!(restarted.export_history().diagnostic_receipts.len(), 1);
}

#[test]
fn delayed_escalation_disposition_is_evaluated_at_receiver_now() {
    let mut runtime = one_consumer_runtime(50);
    establish_current(&mut runtime, 0, 50);
    runtime
        .enqueue(
            10,
            ingress(pulse(
                SUBJECT,
                SUBJECT_INCAR,
                "observer:a",
                "observer-incarnation:a1",
                2,
                50,
                SignalAssessmentV1::OutsideDeclaredBound,
                1.20,
            )),
        )
        .expect("violating pulse enqueues");
    let suspect = runtime.run_until(10).expect("violation evaluates");
    let request = suspect
        .escalation_requests
        .first()
        .expect("loss of current escalates");
    let mut bridge = StubL3Bridge::new(BridgeId::new("bridge:delay"), ClockId::new("clock:one"));
    let outcome = bridge.handle(request, 11);
    runtime
        .enqueue(
            11,
            RuntimeInputV1::EscalationDisposition(outcome.disposition),
        )
        .expect("disposition enqueues");
    runtime
        .run_until(70)
        .expect("delayed disposition evaluates at receiver now");
    let certificate = runtime
        .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
        .expect("certificate");
    assert_eq!(certificate.evaluated_at_monotonic_ms, 70);
    assert_eq!(certificate.judgment, JudgmentCategoryV1::Unknown);
    assert_eq!(certificate.earliest_support_expiry_monotonic_ms, None);
}

#[test]
fn restart_recovers_history_but_not_current_standing() {
    let mut runtime = one_consumer_runtime(200);
    establish_current(&mut runtime, 0, 200);
    let history = runtime.export_history();
    assert!(history.sparse_events.iter().any(|event| {
        matches!(
            event.event,
            pulse_types::SparseDurableEventKindV1::SupportCertificateIssued { .. }
        )
    }));
    let restart_policy = policy(SUBJECT, CONSUMER, "policy:p1", 1, 200);
    let (restarted, output) = ReceiverSchedulerRuntime::recover(
        config_with(
            RuntimeBoundsV1::qualification(),
            "receiver-incarnation:restart",
            "clock:restart",
        ),
        vec![registration(
            restart_policy,
            "activation:restart",
            SUBJECT_INCAR,
        )],
        history,
        0,
    )
    .expect("history reopens");
    assert!(output.trace_lines.iter().any(|line| {
        line.contains("historical_records=") && line.contains("current_standing=UNKNOWN")
    }));
    let certificate = restarted
        .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
        .expect("restart certificate");
    assert_eq!(certificate.judgment, JudgmentCategoryV1::Unknown);
    assert!(certificate.supporting_evidence_ids.is_empty());
    assert_eq!(restarted.scheduled_deadline_count(), 0);
    assert!(restarted.metrics().recovered_sparse_record_count > 0);
}

#[test]
fn restart_reexport_preserves_inapplicable_contradiction_custody() {
    let mut runtime = ReceiverSchedulerRuntime::new(config()).expect("runtime");
    register_qualified(
        &mut runtime,
        registration(
            policy(SUBJECT, CONSUMER, "policy:custody-one", 2, 200),
            "activation:custody-one",
            SUBJECT_INCAR,
        ),
        0,
    );
    for observer in ["observer:a", "observer:b"] {
        runtime
            .enqueue(
                0,
                ingress(pulse(
                    SUBJECT,
                    SUBJECT_INCAR,
                    observer,
                    &format!("{observer}:incarnation"),
                    1,
                    200,
                    SignalAssessmentV1::WithinDeclaredBound,
                    0.20,
                )),
            )
            .expect("pulse enqueues");
    }
    runtime.run_until(0).expect("current establishes");
    runtime
        .enqueue(
            10,
            ingress(pulse(
                SUBJECT,
                SUBJECT_INCAR,
                "observer:b",
                "observer:b:incarnation",
                2,
                200,
                SignalAssessmentV1::OutsideDeclaredBound,
                1.20,
            )),
        )
        .expect("contradiction enqueues");
    runtime.run_until(10).expect("contradiction records");
    let replacement_policy = policy(SUBJECT, CONSUMER, "policy:custody-two", 2, 200);
    runtime
        .enqueue(
            20,
            RuntimeInputV1::ReplaceSubjectIncarnation {
                subject: SubjectId::new(SUBJECT),
                replacement: IncarnationId::new("subject-incarnation:two"),
                activations: vec![activation(
                    replacement_policy.clone(),
                    "activation:custody-two",
                    GenerationTransitionCauseV1::SubjectIncarnationChanged,
                )],
            },
        )
        .expect("replacement enqueues");
    runtime.run_until(20).expect("replacement evaluates");
    let history = runtime.export_history();
    assert!(history.contradictions.iter().any(|custody| matches!(
        custody.applicability,
        pulse_types::ContradictionApplicabilityV1::InapplicableBySubjectReplacement { .. }
    )));

    let (restarted, _) = ReceiverSchedulerRuntime::recover(
        config_with(
            RuntimeBoundsV1::qualification(),
            "receiver-incarnation:custody-restart",
            "clock:custody-restart",
        ),
        vec![registration(
            replacement_policy,
            "activation:custody-restart",
            "subject-incarnation:two",
        )],
        history,
        0,
    )
    .expect("history recovers");
    let reexported = restarted.export_history();
    assert!(reexported.contradictions.iter().any(|custody| matches!(
        custody.applicability,
        pulse_types::ContradictionApplicabilityV1::InapplicableBySubjectReplacement { .. }
    )));
    assert_eq!(
        restarted
            .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
            .expect("restart certificate")
            .judgment,
        JudgmentCategoryV1::Unknown
    );
}

#[test]
fn restart_rejects_policy_generation_rebound_to_different_content() {
    let runtime = one_consumer_runtime(100);
    let history = runtime.export_history();
    let mut rebound = policy(SUBJECT, CONSUMER, "policy:p1", 1, 100);
    rebound.maximum_validity_ms = 99;
    let error = ReceiverSchedulerRuntime::recover(
        config_with(
            RuntimeBoundsV1::qualification(),
            "receiver-incarnation:rebound-restart",
            "clock:rebound-restart",
        ),
        vec![registration(
            rebound,
            "activation:rebound-restart",
            SUBJECT_INCAR,
        )],
        history,
        0,
    )
    .err()
    .expect("one historical policy generation cannot be rebound to new content");
    assert_eq!(error.code, "policy_generation_rebound");
}

#[test]
fn explicit_subject_replacement_does_not_inherit_hot_evidence() {
    let mut runtime = one_consumer_runtime(200);
    establish_current(&mut runtime, 0, 200);
    let next_policy = policy(SUBJECT, CONSUMER, "policy:subject-two", 1, 200);
    runtime
        .enqueue(
            10,
            RuntimeInputV1::ReplaceSubjectIncarnation {
                subject: SubjectId::new(SUBJECT),
                replacement: IncarnationId::new("subject-incarnation:two"),
                activations: vec![activation(
                    next_policy,
                    "activation:subject-two",
                    GenerationTransitionCauseV1::SubjectIncarnationChanged,
                )],
            },
        )
        .expect("replacement enqueues");
    runtime.run_until(10).expect("replacement evaluates");
    let certificate = runtime
        .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
        .expect("replacement certificate");
    assert_eq!(certificate.judgment, JudgmentCategoryV1::Unknown);
    assert_eq!(
        certificate.subject_scope.subject_incarnation.as_str(),
        "subject-incarnation:two"
    );
    assert!(certificate.supporting_evidence_ids.is_empty());
}

#[test]
fn sparse_history_capacity_is_explicit_and_fail_stops_new_input() {
    let mut bounds = RuntimeBoundsV1::qualification();
    bounds.maximum_sparse_events = 1;
    let mut runtime = ReceiverSchedulerRuntime::new(config_with(
        bounds,
        "receiver-incarnation:sparse-bound",
        "clock:sparse-bound",
    ))
    .expect("runtime");
    let registration_output = runtime
        .register_consumer(
            registration(
                policy(SUBJECT, CONSUMER, "policy:sparse-bound", 1, 100),
                "activation:sparse-bound",
                SUBJECT_INCAR,
            ),
            0,
        )
        .expect("registration returns an explicit bounded output");
    assert!(registration_output.refusals.iter().any(|refusal| {
        refusal.class == pulse_types::RuntimeRefusalClassV1::SparseHistoryCapacity
            && !refusal.current_preserved
    }));
    runtime.run_until(0).expect("blindness latches");
    let refusal = runtime
        .enqueue(
            1,
            RuntimeInputV1::Reevaluate {
                subject: SubjectId::new(SUBJECT),
                consumer: ConsumerId::new(CONSUMER),
            },
        )
        .expect_err("new input is fail-stopped after history exhaustion");
    assert_eq!(
        refusal.class,
        pulse_types::RuntimeRefusalClassV1::RuntimeBlind
    );
    assert_eq!(
        runtime
            .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
            .expect("blind certificate")
            .judgment,
        JudgmentCategoryV1::Unknown
    );
}

#[test]
fn subject_incarnation_churn_is_bounded_and_fail_closed() {
    let mut bounds = RuntimeBoundsV1::qualification();
    bounds.maximum_subject_incarnations_per_subject = 2;
    let mut runtime = ReceiverSchedulerRuntime::new(config_with(
        bounds,
        "receiver-incarnation:subject-churn",
        "clock:subject-churn",
    ))
    .expect("runtime");
    runtime
        .register_consumer(
            registration(
                policy(SUBJECT, CONSUMER, "policy:subject-one", 1, 200),
                "activation:subject-one",
                SUBJECT_INCAR,
            ),
            0,
        )
        .expect("registers");
    runtime
        .enqueue(
            1,
            RuntimeInputV1::ReplaceSubjectIncarnation {
                subject: SubjectId::new(SUBJECT),
                replacement: IncarnationId::new("subject-incarnation:two"),
                activations: vec![activation(
                    policy(SUBJECT, CONSUMER, "policy:subject-two", 1, 200),
                    "activation:subject-two",
                    GenerationTransitionCauseV1::SubjectIncarnationChanged,
                )],
            },
        )
        .expect("second incarnation enqueues");
    runtime.run_until(1).expect("second incarnation activates");
    runtime
        .enqueue(
            2,
            RuntimeInputV1::ReplaceSubjectIncarnation {
                subject: SubjectId::new(SUBJECT),
                replacement: IncarnationId::new("subject-incarnation:three"),
                activations: vec![activation(
                    policy(SUBJECT, CONSUMER, "policy:subject-three", 1, 200),
                    "activation:subject-three",
                    GenerationTransitionCauseV1::SubjectIncarnationChanged,
                )],
            },
        )
        .expect("bounded queue admits attempted replacement");
    let output = runtime.run_until(2).expect("third incarnation is refused");
    assert!(output.refusals.iter().any(|refusal| {
        refusal.class == pulse_types::RuntimeRefusalClassV1::IncarnationHistoryCapacity
            && !refusal.current_preserved
    }));
    let certificate = runtime
        .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
        .expect("blind certificate");
    assert_eq!(certificate.judgment, JudgmentCategoryV1::Unknown);
    assert_eq!(
        certificate.subject_scope.subject_incarnation.as_str(),
        "subject-incarnation:two"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn duplicate_multiplicity_never_renews_the_original_deadline(copies in 1usize..17) {
        let mut runtime = one_consumer_runtime(100);
        for _ in 0..copies {
            runtime
                .enqueue(
                    0,
                    ingress(pulse(
                        SUBJECT,
                        SUBJECT_INCAR,
                        "observer:a",
                        "observer-incarnation:a1",
                        1,
                        100,
                        SignalAssessmentV1::WithinDeclaredBound,
                        0.20,
                    )),
                )
                .expect("bounded duplicate enqueues");
        }
        runtime.run_until(0).expect("duplicates evaluate");
        let certificate = runtime
            .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
            .expect("certificate");
        prop_assert_eq!(certificate.judgment, JudgmentCategoryV1::Current);
        prop_assert_eq!(certificate.earliest_support_expiry_monotonic_ms, Some(100));
        runtime.run_until(100).expect("inclusive deadline evaluates");
        prop_assert_eq!(
            runtime
                .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
                .expect("expired certificate")
                .judgment,
            JudgmentCategoryV1::Unknown
        );
    }

    #[test]
    fn every_fresh_generation_activation_barriers_before_reearning_current(
        transitions in 1usize..9,
    ) {
        let mut runtime = one_consumer_runtime(1_000);
        establish_current(&mut runtime, 0, 1_000);
        for index in 1..=transitions {
            let at = u64::try_from(index).expect("small generated index");
            let generation = format!("policy:generated-{index}");
            let activation_id = format!("activation:generated-{index}");
            let next = policy(SUBJECT, CONSUMER, &generation, 1, 1_000);
            let next_activation = activation(
                next,
                &activation_id,
                GenerationTransitionCauseV1::EquivalentBodyNewGeneration,
            );
            install_activation_binding(&mut runtime, &next_activation, SUBJECT_INCAR, at);
            runtime
                .enqueue(
                    at,
                    RuntimeInputV1::ActivateConsumer(next_activation),
                )
                .expect("generated activation enqueues");
            runtime.run_until(at).expect("generated barrier evaluates");
            let barrier = runtime
                .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
                .expect("barrier certificate");
            prop_assert_eq!(barrier.judgment, JudgmentCategoryV1::Unknown);
            prop_assert_eq!(barrier.context.activation_id.as_str(), activation_id.as_str());
            prop_assert_eq!(barrier.context.reliance_policy_generation.as_str(), generation.as_str());

            runtime
                .enqueue(
                    at,
                    RuntimeInputV1::Reevaluate {
                        subject: SubjectId::new(SUBJECT),
                        consumer: ConsumerId::new(CONSUMER),
                    },
                )
                .expect("explicit reevaluation enqueues");
            runtime.run_until(at).expect("exact context reevaluates");
            let reearned = runtime
                .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
                .expect("reearned certificate");
            prop_assert_eq!(reearned.judgment, JudgmentCategoryV1::Current);
            prop_assert_eq!(reearned.context.activation_id.as_str(), activation_id.as_str());
        }
    }

    #[test]
    fn same_instant_order_is_independent_of_enqueue_race(transition_first in any::<bool>()) {
        let mut runtime = one_consumer_runtime(100);
        establish_current(&mut runtime, 0, 100);
        let next = RuntimeInputV1::ActivateConsumer(activation(
            policy(SUBJECT, CONSUMER, "policy:ordered", 1, 100),
            "activation:ordered",
            GenerationTransitionCauseV1::ReliancePolicyChanged,
        ));
        let reevaluate = RuntimeInputV1::Reevaluate {
            subject: SubjectId::new(SUBJECT),
            consumer: ConsumerId::new(CONSUMER),
        };
        if transition_first {
            runtime.enqueue(100, next).expect("transition enqueues");
            runtime.enqueue(100, reevaluate).expect("reevaluation enqueues");
        } else {
            runtime.enqueue(100, reevaluate).expect("reevaluation enqueues");
            runtime.enqueue(100, next).expect("transition enqueues");
        }
        runtime.run_until(100).expect("same instant evaluates");
        let certificate = runtime
            .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
            .expect("ordered certificate");
        prop_assert_eq!(certificate.judgment, JudgmentCategoryV1::Unknown);
        prop_assert_eq!(certificate.context.activation_id.as_str(), "activation:ordered");
        prop_assert_eq!(certificate.earliest_support_expiry_monotonic_ms, None);
    }

    #[test]
    fn same_instant_pulse_order_uses_stable_semantic_keys(newer_first in any::<bool>()) {
        let mut runtime = one_consumer_runtime(100);
        let first = ingress(pulse(
            SUBJECT,
            SUBJECT_INCAR,
            "observer:a",
            "observer-incarnation:a1",
            1,
            100,
            SignalAssessmentV1::WithinDeclaredBound,
            0.20,
        ));
        let second = ingress(pulse(
            SUBJECT,
            SUBJECT_INCAR,
            "observer:a",
            "observer-incarnation:a1",
            2,
            100,
            SignalAssessmentV1::WithinDeclaredBound,
            0.20,
        ));
        if newer_first {
            runtime.enqueue(0, second).expect("newer pulse enqueues");
            runtime.enqueue(0, first).expect("older pulse enqueues");
        } else {
            runtime.enqueue(0, first).expect("older pulse enqueues");
            runtime.enqueue(0, second).expect("newer pulse enqueues");
        }
        runtime.run_until(0).expect("same-instant pulses evaluate");
        let certificate = runtime
            .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
            .expect("certificate");
        prop_assert_eq!(certificate.judgment, JudgmentCategoryV1::Current);
        prop_assert_eq!(certificate.earliest_support_expiry_monotonic_ms, Some(100));
        prop_assert!(certificate
            .supporting_evidence_ids
            .iter()
            .any(|reference| reference.contains("observer:a/observer-incarnation:a1/seq=2/")));
    }

    #[test]
    fn adversarial_observer_identity_churn_never_exceeds_the_bound(attempts in 1usize..13) {
        let mut bounds = RuntimeBoundsV1::qualification();
        bounds.maximum_observers_per_subject = 3;
        let mut runtime = ReceiverSchedulerRuntime::new(config_with(
            bounds,
            "receiver-incarnation:property-bound",
            "clock:property-bound",
        ))
        .expect("runtime");
        runtime
            .register_consumer(
                registration(
                    policy(SUBJECT, CONSUMER, "policy:property-bound", 1, 100),
                    "activation:property-bound",
                    SUBJECT_INCAR,
                ),
                0,
            )
            .expect("registers");
        for index in 0..attempts {
            let observer = format!("observer:generated-{index}");
            let observer_incarnation = format!("observer-incarnation:generated-{index}");
            runtime
                .enqueue(
                    0,
                    ingress(pulse(
                        SUBJECT,
                        SUBJECT_INCAR,
                        &observer,
                        &observer_incarnation,
                        1,
                        100,
                        SignalAssessmentV1::WithinDeclaredBound,
                        0.20,
                    )),
                )
                .expect("bounded queue admits generated identity");
        }
        let output = runtime.run_until(0).expect("identity churn evaluates");
        let expected_refusals = attempts.saturating_sub(3);
        prop_assert_eq!(
            output
                .refusals
                .iter()
                .filter(|refusal| refusal.class == pulse_types::RuntimeRefusalClassV1::ObserverCapacity)
                .count(),
            expected_refusals
        );
        prop_assert_eq!(
            runtime.metrics().observer_refusal_count,
            u64::try_from(expected_refusals).expect("small generated count")
        );
        if expected_refusals > 0 {
            prop_assert_eq!(
                runtime
                    .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
                    .expect("blind certificate")
                    .judgment,
                JudgmentCategoryV1::Unknown
            );
        }
    }
}
