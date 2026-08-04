#![forbid(unsafe_code)]

//! Narrow local qualification harness for exact runtime-generation binding.
//!
//! This crate is deliberately not a build system or an attestation service. It
//! assembles checked local package records, drives the runtime activation gate,
//! and produces deterministic refusal/demonstration artifacts.

use std::collections::{BTreeMap, BTreeSet};

use pulse_evaluator::{EscalationPolicyV1, ReliancePolicyV1};
use pulse_l3_bridge::stub_profile_identity;
use pulse_runtime::{
    ConsumerRegistrationV1, LocalQualificationPackageV1, PulseIngressV1, ReceiverSchedulerRuntime,
    RuntimeConfigV1, RuntimeInputV1, qualification_fixture_inputs,
};
use pulse_types::{
    ActivationReceiptV1, ArtifactRoleV1, AuthenticationFieldV1, AuthenticationResultV1,
    AuthorityGrantsV1, BoundedSignalValueV1, ClockId, ConsumerId, ConsumerProfileGenerationId,
    ContextActivationId, CoverageDescriptorV1, DiagnosticBoundsV1, DigestV1,
    EvaluatorSemanticGenerationId, GenerationLifecycleFactBodyV1, GenerationLifecycleFactV1,
    GenerationLifecycleKindV1, IncarnationId, JudgmentCategoryV1, LocalActivationAcceptanceV1,
    LocalCertificateStatusV1, MutationAuthorityV1, ObservationPolicyGenerationId,
    ObservationProfileIdV1, ObserverId, ObserverSetGenerationId, PolicyGenerationId, PulseFrameV1,
    QualificationCertificateV1, QualificationEvidenceReportV1, QualifiedArtifactManifestV1,
    ReceiverId, RelianceContextV1, SCHEMA_VERSION_V1, SignalAssessmentV1, SourceIdentityV1,
    SparseDurableEventKindV1, SubjectId, artifact_content_digest, digest_parts,
};
use serde::{Deserialize, Serialize};

pub const CAMPAIGN_STARTING_COMMIT: &str = "3cd15b7a1e7f424f6fd57c09b30fa4790947eca2";
pub const FIXTURE_SUBJECT: &str = "subject:qualified-binding";
pub const FIXTURE_CONSUMER: &str = "consumer:qualified-display";
pub const FIXTURE_SUBJECT_INCAR: &str = "subject-incarnation:qualified-one";
pub const FIXTURE_POLICY_GENERATION: &str = "policy:qualified-one";
pub const FIXTURE_ACTIVATION: &str = "activation:qualified-one";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DemoStepV1 {
    pub sequence: u16,
    pub action: String,
    pub binding_state: pulse_types::RuntimeBindingStateV1,
    pub judgment: JudgmentCategoryV1,
    pub supporting_evidence_count: usize,
    pub active_deadlines: usize,
    pub activation_receipt_digest: Option<DigestV1>,
    pub qualified_generation_digest: Option<DigestV1>,
    pub qualified_manifest_digest: Option<DigestV1>,
    pub qualified_certificate_digest: Option<DigestV1>,
    pub qualified_activation_receipt_digest: Option<DigestV1>,
    pub mutation_authority: MutationAuthorityV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeterministicBindingDemoV1 {
    pub schema_version: u16,
    pub scenario: String,
    pub steps: Vec<DemoStepV1>,
    pub assertions: Vec<String>,
    pub terminal_trace: Vec<String>,
    pub nonclaims: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostileCheckV1 {
    pub scenario: String,
    pub expected_binding_state: pulse_types::RuntimeBindingStateV1,
    pub observed_binding_state: pulse_types::RuntimeBindingStateV1,
    pub observed_judgment: JudgmentCategoryV1,
    pub active_deadlines: usize,
    pub current_permitted: bool,
    pub authority_granted: bool,
    pub passed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostileCorpusArtifactV1 {
    pub schema_version: u16,
    pub corpus: String,
    pub checks: Vec<HostileCheckV1>,
    pub all_passed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RestartActivationArtifactV1 {
    pub schema_version: u16,
    pub historical_activation_receipts_recovered: usize,
    pub prior_process_binding_state: pulse_types::RuntimeBindingStateV1,
    pub restarted_binding_state: pulse_types::RuntimeBindingStateV1,
    pub restarted_judgment: JudgmentCategoryV1,
    pub restarted_supporting_evidence_count: usize,
    pub restarted_active_deadlines: usize,
    pub new_measurement_required: bool,
    pub prior_receipt_reused: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleArtifactV1 {
    pub schema_version: u16,
    pub lifecycle_kind: GenerationLifecycleKindV1,
    pub before_state: pulse_types::RuntimeBindingStateV1,
    pub after_state: pulse_types::RuntimeBindingStateV1,
    pub before_judgment: JudgmentCategoryV1,
    pub after_judgment: JudgmentCategoryV1,
    pub active_deadlines_after: usize,
    pub historical_receipt_preserved: bool,
    pub standing_preserved: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationCrashPointV1 {
    pub point: String,
    pub process_killed: bool,
    pub technically_executed: bool,
    pub journal_records_recovered: usize,
    pub journal_recovery: String,
    pub journal_damage: Option<String>,
    pub historical_activation_receipts: usize,
    pub historical_current_records: usize,
    pub restarted_binding_state: pulse_types::RuntimeBindingStateV1,
    pub restarted_judgment: JudgmentCategoryV1,
    pub restarted_supporting_evidence_count: usize,
    pub restarted_active_deadlines: usize,
    pub standing_reconstructed: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationCrashCorpusV1 {
    pub schema_version: u16,
    pub platform: String,
    pub points: Vec<ActivationCrashPointV1>,
    pub all_executed_restart_checks_passed: bool,
    pub refused_point_count: usize,
    pub nonclaims: Vec<String>,
}

#[must_use]
pub fn fixture_profile() -> ObservationProfileIdV1 {
    ObservationProfileIdV1 {
        name: "profile:qualified-binding".to_owned(),
        version: 1,
        semantic_digest: digest_parts("qualified.fixture.profile.v1", &[b"load", b"memory"]),
    }
}

#[must_use]
pub fn fixture_policy() -> ReliancePolicyV1 {
    ReliancePolicyV1 {
        schema_version: SCHEMA_VERSION_V1,
        subject: SubjectId::new(FIXTURE_SUBJECT),
        scope: "host".to_owned(),
        consumer: ConsumerId::new(FIXTURE_CONSUMER),
        generation: PolicyGenerationId::new(FIXTURE_POLICY_GENERATION),
        observation_policy_generation: ObservationPolicyGenerationId::new(
            "observation-policy:qualified-one",
        ),
        observation_profile: fixture_profile(),
        required_coverage: vec!["load".to_owned(), "memory".to_owned()],
        minimum_observers: 1,
        maximum_validity_ms: 100,
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

#[must_use]
pub fn fixture_context(policy: &ReliancePolicyV1) -> RelianceContextV1 {
    RelianceContextV1 {
        schema_version: SCHEMA_VERSION_V1,
        activation_id: ContextActivationId::new(FIXTURE_ACTIVATION),
        reliance_policy_generation: policy.generation.clone(),
        reliance_policy_semantic_digest: policy.semantic_digest(),
        consumer_profile_generation: ConsumerProfileGenerationId::new(
            "consumer-profile:qualified-one",
        ),
        evaluator_semantic_generation: EvaluatorSemanticGenerationId::new(
            "evaluator:qualified-one",
        ),
        observer_set_generation: ObserverSetGenerationId::new("observer-set:qualified-one"),
        observation_policy_generation: policy.observation_policy_generation.clone(),
    }
}

#[must_use]
pub fn fixture_registration() -> ConsumerRegistrationV1 {
    let policy = fixture_policy();
    ConsumerRegistrationV1 {
        context: fixture_context(&policy),
        policy,
        subject_incarnation: IncarnationId::new(FIXTURE_SUBJECT_INCAR),
    }
}

#[must_use]
pub fn fixture_config(receiver_incarnation: &str, clock: &str) -> RuntimeConfigV1 {
    RuntimeConfigV1 {
        schema_version: SCHEMA_VERSION_V1,
        receiver: ReceiverId::new("receiver:qualified-binding"),
        receiver_incarnation: IncarnationId::new(receiver_incarnation),
        clock_id: ClockId::new(clock),
        transport_custody_policy: None,
        bounds: pulse_runtime::RuntimeBoundsV1::qualification(),
    }
}

#[must_use]
pub fn fixture_pulse(sequence: u64, validity_ms: u64) -> PulseFrameV1 {
    PulseFrameV1 {
        schema_version: SCHEMA_VERSION_V1,
        subject: SubjectId::new(FIXTURE_SUBJECT),
        subject_incarnation: IncarnationId::new(FIXTURE_SUBJECT_INCAR),
        observer: ObserverId::new("observer:qualified-binding"),
        observer_incarnation: IncarnationId::new("observer-incarnation:qualified-one"),
        sequence,
        observer_monotonic_ns: sequence.saturating_mul(1_000_000),
        validity_ms,
        profile: fixture_profile(),
        observation_policy_generation: ObservationPolicyGenerationId::new(
            "observation-policy:qualified-one",
        ),
        coverage: CoverageDescriptorV1 {
            expected: vec!["load".to_owned(), "memory".to_owned()],
            observed: vec!["load".to_owned(), "memory".to_owned()],
        },
        signals: vec![
            BoundedSignalValueV1 {
                name: "load_ratio".to_owned(),
                value: 0.2,
                unit: "ratio".to_owned(),
                assessment: SignalAssessmentV1::WithinDeclaredBound,
            },
            BoundedSignalValueV1 {
                name: "memory_ratio".to_owned(),
                value: 0.7,
                unit: "ratio".to_owned(),
                assessment: SignalAssessmentV1::WithinDeclaredBound,
            },
        ],
        observation_digest: digest_parts("unsealed", &[]),
        authentication: AuthenticationFieldV1::Placeholder {
            disclosure: "qualification fixture; authentication result is receiver annotation"
                .to_owned(),
        },
    }
    .seal()
}

#[must_use]
pub fn fixture_ingress(sequence: u64, validity_ms: u64) -> RuntimeInputV1 {
    RuntimeInputV1::Pulse(PulseIngressV1 {
        frame: fixture_pulse(sequence, validity_ms),
        transport_path: "local:qualification-fixture".to_owned(),
        transport_observed_delay_ms: Some(0),
        authentication: AuthenticationResultV1::Verified {
            method: "fixture".to_owned(),
            principal: "observer-fixture".to_owned(),
        },
    })
}

pub fn build_fixture_package(
    config: &RuntimeConfigV1,
    registration: &ConsumerRegistrationV1,
) -> Result<LocalQualificationPackageV1, pulse_types::QualificationError> {
    pulse_runtime::build_local_qualification_package(
        config,
        registration,
        qualification_fixture_inputs(CAMPAIGN_STARTING_COMMIT, 97),
    )
}

pub fn retarget_artifact(
    package: &LocalQualificationPackageV1,
    role: ArtifactRoleV1,
    replacement_bytes: &[u8],
) -> Result<LocalQualificationPackageV1, pulse_types::QualificationError> {
    let mut body = package.manifest.body.clone();
    let artifact = body
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.role == role)
        .ok_or_else(|| {
            pulse_types::QualificationError::new(
                "artifact_inventory_incomplete",
                "retargeted role is absent",
            )
        })?;
    artifact.byte_length = replacement_bytes.len() as u64;
    artifact.content_digest = artifact_content_digest(replacement_bytes);
    if role == ArtifactRoleV1::QualificationCorpus {
        body.qualification_corpus_identities = vec![artifact.content_digest.clone()];
    }
    let manifest = QualifiedArtifactManifestV1::new(body)?;

    let mut report_body = package.report.body.clone();
    report_body.manifest_digest = manifest.manifest_digest.clone();
    report_body.artifact_digests = manifest.body.artifact_digests();
    report_body.qualification_corpus_identities =
        manifest.body.qualification_corpus_identities.clone();
    let report = QualificationEvidenceReportV1::new(report_body)?;
    let certificate = QualificationCertificateV1::issue(
        &manifest,
        &report,
        package.certificate.body.provenance.clone(),
    )?;
    let acceptance = LocalActivationAcceptanceV1 {
        schema_version: SCHEMA_VERSION_V1,
        accepted_certificate_digest: certificate.certificate_digest.clone(),
        lifecycle_authority_id: manifest.body.lifecycle_authority_id.clone(),
        certificate_status: LocalCertificateStatusV1::Accepted {
            observed_through_sequence: 0,
        },
        pinned_superseded_activation_allowed: false,
        authority_grants: AuthorityGrantsV1::none(),
    };
    acceptance.validate()?;
    Ok(LocalQualificationPackageV1 {
        manifest,
        report,
        certificate,
        acceptance,
    })
}

fn activate_package(
    runtime: &mut ReceiverSchedulerRuntime,
    registration: &ConsumerRegistrationV1,
    package: &LocalQualificationPackageV1,
    at_monotonic_ms: u64,
) -> Result<ActivationReceiptV1, pulse_runtime::RuntimeError> {
    let manifest = package
        .manifest_bytes()
        .map_err(|error| pulse_runtime::RuntimeError::new(error.code, error.detail))?;
    let certificate = package
        .certificate_bytes()
        .map_err(|error| pulse_runtime::RuntimeError::new(error.code, error.detail))?;
    let report = package
        .report_bytes()
        .map_err(|error| pulse_runtime::RuntimeError::new(error.code, error.detail))?;
    Ok(runtime
        .activate_qualified_binding(
            registration,
            Some(&manifest),
            Some(&certificate),
            Some(&report),
            package.acceptance.clone(),
            at_monotonic_ms,
        )?
        .receipt)
}

fn current_certificate(
    runtime: &ReceiverSchedulerRuntime,
) -> &pulse_types::RelianceSupportCertificateV1 {
    runtime
        .current_certificate(
            &SubjectId::new(FIXTURE_SUBJECT),
            &ConsumerId::new(FIXTURE_CONSUMER),
        )
        .expect("qualification fixture always registers the consumer")
}

fn capture_step(runtime: &ReceiverSchedulerRuntime, sequence: u16, action: &str) -> DemoStepV1 {
    let certificate = current_certificate(runtime);
    DemoStepV1 {
        sequence,
        action: action.to_owned(),
        binding_state: runtime.binding_state(
            &SubjectId::new(FIXTURE_SUBJECT),
            &ConsumerId::new(FIXTURE_CONSUMER),
        ),
        judgment: certificate.judgment,
        supporting_evidence_count: certificate.supporting_evidence_ids.len(),
        active_deadlines: runtime.scheduled_deadline_count(),
        activation_receipt_digest: runtime
            .activation_receipt(
                &SubjectId::new(FIXTURE_SUBJECT),
                &ConsumerId::new(FIXTURE_CONSUMER),
            )
            .map(|receipt| receipt.receipt_digest.clone()),
        qualified_generation_digest: certificate
            .qualified_generation
            .as_ref()
            .map(|binding| binding.generation_set.identity_digest()),
        qualified_manifest_digest: certificate
            .qualified_generation
            .as_ref()
            .map(|binding| binding.manifest_digest.clone()),
        qualified_certificate_digest: certificate
            .qualified_generation
            .as_ref()
            .map(|binding| binding.qualification_certificate_digest.clone()),
        qualified_activation_receipt_digest: certificate
            .qualified_generation
            .as_ref()
            .map(|binding| binding.activation_receipt_digest.clone()),
        mutation_authority: certificate.mutation_authority,
    }
}

pub fn run_matched_activation_demo() -> Result<
    (
        DeterministicBindingDemoV1,
        LocalQualificationPackageV1,
        ActivationReceiptV1,
    ),
    String,
> {
    let config = fixture_config("receiver-incarnation:matched", "clock:matched");
    let registration = fixture_registration();
    let package =
        build_fixture_package(&config, &registration).map_err(|error| error.to_string())?;
    let (demo, receipt) = run_matched_package_activation_demo(&config, &registration, &package)?;
    Ok((demo, package, receipt))
}

pub fn run_matched_package_activation_demo(
    config: &RuntimeConfigV1,
    registration: &ConsumerRegistrationV1,
    package: &LocalQualificationPackageV1,
) -> Result<(DeterministicBindingDemoV1, ActivationReceiptV1), String> {
    let mut runtime =
        ReceiverSchedulerRuntime::new(config.clone()).map_err(|error| error.to_string())?;
    let unbound_state = runtime.binding_state(
        &SubjectId::new(FIXTURE_SUBJECT),
        &ConsumerId::new(FIXTURE_CONSUMER),
    );
    let receipt = activate_package(&mut runtime, registration, package, 0)
        .map_err(|error| error.to_string())?;
    let registered = runtime
        .register_consumer(registration.clone(), 0)
        .map_err(|error| error.to_string())?;
    let mut trace = registered.trace_lines;
    let mut steps = vec![capture_step(
        &runtime,
        1,
        "certificate and manifest verified; exact local artifacts activated; no evidence yet",
    )];
    runtime
        .enqueue(1, fixture_ingress(1, 100))
        .map_err(|error| format!("{:?}: {}", error.class, error.detail))?;
    let evaluated = runtime.run_until(1).map_err(|error| error.to_string())?;
    trace.extend(evaluated.trace_lines);
    steps.push(capture_step(
        &runtime,
        2,
        "fresh evidence evaluated under the exact accepted activation",
    ));
    if unbound_state != pulse_types::RuntimeBindingStateV1::Unbound
        || receipt.body.state != pulse_types::RuntimeBindingStateV1::QualifiedAndMatched
        || steps[0].judgment != JudgmentCategoryV1::Unknown
        || steps[1].judgment != JudgmentCategoryV1::Current
        || steps[1].qualified_generation_digest.is_none()
        || steps[1].mutation_authority != MutationAuthorityV1::None
    {
        return Err("matched activation demo did not satisfy its exact assertions".to_owned());
    }
    Ok((
        DeterministicBindingDemoV1 {
            schema_version: SCHEMA_VERSION_V1,
            scenario: "exact-matched-local-activation".to_owned(),
            steps,
            assertions: vec![
                "runtime began Unbound".to_owned(),
                "activation receipt was QualifiedAndMatched".to_owned(),
                "no evidence meant UNKNOWN after activation".to_owned(),
                "fresh evidence earned CURRENT naming the exact qualified generation".to_owned(),
                "no emitted object granted mutation authority".to_owned(),
            ],
            terminal_trace: trace,
            nonclaims: binding_nonclaims(),
        },
        receipt,
    ))
}

pub fn run_mismatch_demo(
    role: ArtifactRoleV1,
    expected_state: pulse_types::RuntimeBindingStateV1,
    scenario: &str,
) -> Result<DeterministicBindingDemoV1, String> {
    let config = fixture_config("receiver-incarnation:mismatch", "clock:mismatch");
    let registration = fixture_registration();
    let base = build_fixture_package(&config, &registration).map_err(|error| error.to_string())?;
    run_mismatch_package_demo(
        &config,
        &registration,
        &base,
        role,
        expected_state,
        scenario,
    )
}

pub fn run_mismatch_package_demo(
    config: &RuntimeConfigV1,
    registration: &ConsumerRegistrationV1,
    base: &LocalQualificationPackageV1,
    role: ArtifactRoleV1,
    expected_state: pulse_types::RuntimeBindingStateV1,
    scenario: &str,
) -> Result<DeterministicBindingDemoV1, String> {
    let package = retarget_artifact(
        base,
        role,
        format!("hostile replacement:{role:?}").as_bytes(),
    )
    .map_err(|error| error.to_string())?;
    let mut runtime =
        ReceiverSchedulerRuntime::new(config.clone()).map_err(|error| error.to_string())?;
    let receipt = activate_package(&mut runtime, registration, &package, 0)
        .map_err(|error| error.to_string())?;
    let output = runtime
        .register_consumer(registration.clone(), 0)
        .map_err(|error| error.to_string())?;
    runtime
        .enqueue(1, fixture_ingress(1, 100))
        .map_err(|error| format!("{:?}: {}", error.class, error.detail))?;
    let evaluated = runtime.run_until(1).map_err(|error| error.to_string())?;
    let step = capture_step(&runtime, 1, scenario);
    if receipt.body.state != expected_state
        || step.judgment == JudgmentCategoryV1::Current
        || step.active_deadlines != 0
    {
        return Err(format!(
            "{scenario} did not fail closed as {expected_state:?}"
        ));
    }
    let mut terminal_trace = output.trace_lines;
    terminal_trace.extend(evaluated.trace_lines);
    Ok(DeterministicBindingDemoV1 {
        schema_version: SCHEMA_VERSION_V1,
        scenario: scenario.to_owned(),
        steps: vec![step],
        assertions: vec![
            format!("activation state is {expected_state:?}"),
            "current standing remains UNKNOWN".to_owned(),
            "no active support deadline exists".to_owned(),
        ],
        terminal_trace,
        nonclaims: binding_nonclaims(),
    })
}

pub fn run_restart_demo() -> Result<RestartActivationArtifactV1, String> {
    let config = fixture_config(
        "receiver-incarnation:restart-before",
        "clock:restart-before",
    );
    let registration = fixture_registration();
    let package =
        build_fixture_package(&config, &registration).map_err(|error| error.to_string())?;
    let mut runtime = ReceiverSchedulerRuntime::new(config).map_err(|error| error.to_string())?;
    activate_package(&mut runtime, &registration, &package, 0)
        .map_err(|error| error.to_string())?;
    runtime
        .register_consumer(registration.clone(), 0)
        .map_err(|error| error.to_string())?;
    runtime
        .enqueue(1, fixture_ingress(1, 100))
        .map_err(|error| format!("{:?}: {}", error.class, error.detail))?;
    runtime.run_until(1).map_err(|error| error.to_string())?;
    let prior_process_binding_state = runtime.binding_state(
        &SubjectId::new(FIXTURE_SUBJECT),
        &ConsumerId::new(FIXTURE_CONSUMER),
    );
    let history = runtime.export_history();
    let historical_activation_receipts_recovered = history
        .sparse_events
        .iter()
        .filter(|event| {
            matches!(
                event.event,
                SparseDurableEventKindV1::QualifiedGenerationBindingChanged { .. }
            )
        })
        .count();
    let mut restart_registration = registration;
    restart_registration.context.activation_id =
        ContextActivationId::new("activation:qualified-restart");
    let (restarted, _) = ReceiverSchedulerRuntime::recover(
        fixture_config("receiver-incarnation:restart-after", "clock:restart-after"),
        vec![restart_registration],
        history,
        0,
    )
    .map_err(|error| error.to_string())?;
    let certificate = current_certificate(&restarted);
    let artifact = RestartActivationArtifactV1 {
        schema_version: SCHEMA_VERSION_V1,
        historical_activation_receipts_recovered,
        prior_process_binding_state,
        restarted_binding_state: restarted.binding_state(
            &SubjectId::new(FIXTURE_SUBJECT),
            &ConsumerId::new(FIXTURE_CONSUMER),
        ),
        restarted_judgment: certificate.judgment,
        restarted_supporting_evidence_count: certificate.supporting_evidence_ids.len(),
        restarted_active_deadlines: restarted.scheduled_deadline_count(),
        new_measurement_required: true,
        prior_receipt_reused: false,
    };
    if artifact.historical_activation_receipts_recovered == 0
        || artifact.restarted_binding_state != pulse_types::RuntimeBindingStateV1::Unbound
        || artifact.restarted_judgment != JudgmentCategoryV1::Unknown
        || artifact.restarted_supporting_evidence_count != 0
        || artifact.restarted_active_deadlines != 0
    {
        return Err("restart reconstructed activation or reliance".to_owned());
    }
    Ok(artifact)
}

pub fn run_lifecycle_demo(kind: GenerationLifecycleKindV1) -> Result<LifecycleArtifactV1, String> {
    let config = fixture_config("receiver-incarnation:lifecycle", "clock:lifecycle");
    let registration = fixture_registration();
    let package =
        build_fixture_package(&config, &registration).map_err(|error| error.to_string())?;
    let mut runtime = ReceiverSchedulerRuntime::new(config).map_err(|error| error.to_string())?;
    activate_package(&mut runtime, &registration, &package, 0)
        .map_err(|error| error.to_string())?;
    runtime
        .register_consumer(registration, 0)
        .map_err(|error| error.to_string())?;
    runtime
        .enqueue(1, fixture_ingress(1, 100))
        .map_err(|error| format!("{:?}: {}", error.class, error.detail))?;
    runtime.run_until(1).map_err(|error| error.to_string())?;
    let before_state = runtime.binding_state(
        &SubjectId::new(FIXTURE_SUBJECT),
        &ConsumerId::new(FIXTURE_CONSUMER),
    );
    let before_judgment = current_certificate(&runtime).judgment;
    let (successor_manifest_digest, successor_certificate_digest) = match kind {
        GenerationLifecycleKindV1::Superseded => (
            Some(digest_parts(
                "fixture.successor.manifest.v1",
                &[b"successor"],
            )),
            Some(digest_parts(
                "fixture.successor.certificate.v1",
                &[b"successor"],
            )),
        ),
        GenerationLifecycleKindV1::Revoked => (None, None),
    };
    let fact = GenerationLifecycleFactV1::new(GenerationLifecycleFactBodyV1 {
        schema_version: SCHEMA_VERSION_V1,
        authority_id: package.manifest.body.lifecycle_authority_id.clone(),
        fact_sequence: 1,
        certificate_digest: package.certificate.certificate_digest.clone(),
        kind,
        successor_manifest_digest,
        successor_certificate_digest,
        reason: "qualified local hostile fixture".to_owned(),
        authority_grants: AuthorityGrantsV1::none(),
    })
    .map_err(|error| error.to_string())?;
    runtime
        .apply_generation_lifecycle_fact(
            &SubjectId::new(FIXTURE_SUBJECT),
            &ConsumerId::new(FIXTURE_CONSUMER),
            fact,
            2,
        )
        .map_err(|error| error.to_string())?;
    let after_state = runtime.binding_state(
        &SubjectId::new(FIXTURE_SUBJECT),
        &ConsumerId::new(FIXTURE_CONSUMER),
    );
    let expected = match kind {
        GenerationLifecycleKindV1::Superseded => pulse_types::RuntimeBindingStateV1::Superseded,
        GenerationLifecycleKindV1::Revoked => pulse_types::RuntimeBindingStateV1::Revoked,
    };
    let historical_receipt_preserved = runtime.export_history().sparse_events.iter().any(|event| {
        matches!(
            event.event,
            SparseDurableEventKindV1::QualifiedGenerationBindingChanged { .. }
        )
    });
    let artifact = LifecycleArtifactV1 {
        schema_version: SCHEMA_VERSION_V1,
        lifecycle_kind: kind,
        before_state,
        after_state,
        before_judgment,
        after_judgment: current_certificate(&runtime).judgment,
        active_deadlines_after: runtime.scheduled_deadline_count(),
        historical_receipt_preserved,
        standing_preserved: false,
    };
    if artifact.before_judgment != JudgmentCategoryV1::Current
        || artifact.after_state != expected
        || artifact.after_judgment == JudgmentCategoryV1::Current
        || artifact.active_deadlines_after != 0
        || !artifact.historical_receipt_preserved
    {
        return Err("lifecycle demo silently preserved positive standing".to_owned());
    }
    Ok(artifact)
}

pub fn run_load_bearing_mismatch_corpus() -> Result<HostileCorpusArtifactV1, String> {
    let scenarios = [
        (
            ArtifactRoleV1::RunningExecutable,
            pulse_types::RuntimeBindingStateV1::ExecutableMismatch,
            "same labels; different executable bytes",
        ),
        (
            ArtifactRoleV1::EvaluatorImplementation,
            pulse_types::RuntimeBindingStateV1::EvaluatorMismatch,
            "exact policy; different evaluator bytes",
        ),
        (
            ArtifactRoleV1::ReliancePolicy,
            pulse_types::RuntimeBindingStateV1::PolicyMismatch,
            "same policy name and generation; different policy bytes",
        ),
        (
            ArtifactRoleV1::ConsumerProfile,
            pulse_types::RuntimeBindingStateV1::ProfileMismatch,
            "same profile generation; different profile bytes",
        ),
        (
            ArtifactRoleV1::ObserverSet,
            pulse_types::RuntimeBindingStateV1::ObserverSetMismatch,
            "same observer-set generation; different observer-set bytes",
        ),
        (
            ArtifactRoleV1::ObservationPolicy,
            pulse_types::RuntimeBindingStateV1::ObservationPolicyMismatch,
            "same observation-policy generation; different bytes",
        ),
        (
            ArtifactRoleV1::RuntimeConfiguration,
            pulse_types::RuntimeBindingStateV1::ConfigurationMismatch,
            "same configuration label; different canonical configuration",
        ),
        (
            ArtifactRoleV1::SemanticContracts,
            pulse_types::RuntimeBindingStateV1::ContractMismatch,
            "unsupported semantic contract bytes",
        ),
    ];
    let mut checks = Vec::new();
    for (role, expected, scenario) in scenarios {
        let demo = run_mismatch_demo(role, expected, scenario)?;
        let step = &demo.steps[0];
        checks.push(HostileCheckV1 {
            scenario: scenario.to_owned(),
            expected_binding_state: expected,
            observed_binding_state: step.binding_state,
            observed_judgment: step.judgment,
            active_deadlines: step.active_deadlines,
            current_permitted: step.judgment == JudgmentCategoryV1::Current,
            authority_granted: step.mutation_authority != MutationAuthorityV1::None,
            passed: step.binding_state == expected
                && step.judgment != JudgmentCategoryV1::Current
                && step.active_deadlines == 0
                && step.mutation_authority == MutationAuthorityV1::None,
        });
    }
    let all_passed = checks.iter().all(|check| check.passed);
    Ok(HostileCorpusArtifactV1 {
        schema_version: SCHEMA_VERSION_V1,
        corpus: "load-bearing-identity-substitution".to_owned(),
        checks,
        all_passed,
    })
}

pub fn run_authority_laundering_corpus() -> Result<HostileCorpusArtifactV1, String> {
    let mut checks = Vec::new();
    for scenario in [
        "caller-supplied generation label alone",
        "artifact digest alone",
        "manifest digest alone",
        "exact source commit alone",
        "passing test result without exact package binding",
        "historical CURRENT record alone",
    ] {
        checks.push(unbound_authority_check(scenario)?);
    }
    checks.push(partial_package_check(
        "valid canonical manifest without certificate",
        true,
        false,
        true,
        pulse_types::RuntimeBindingStateV1::MissingCertificate,
    )?);
    checks.push(partial_package_check(
        "qualification certificate without manifest",
        false,
        true,
        true,
        pulse_types::RuntimeBindingStateV1::ManifestMismatch,
    )?);
    checks.push(partial_package_check(
        "manifest and certificate without checked qualification report",
        true,
        true,
        false,
        pulse_types::RuntimeBindingStateV1::QualificationEvidenceMissing,
    )?);

    let mismatches = run_load_bearing_mismatch_corpus()?;
    for mismatch in mismatches.checks.into_iter().filter(|check| {
        matches!(
            check.expected_binding_state,
            pulse_types::RuntimeBindingStateV1::PolicyMismatch
                | pulse_types::RuntimeBindingStateV1::EvaluatorMismatch
        )
    }) {
        checks.push(mismatch);
    }

    for kind in [
        GenerationLifecycleKindV1::Superseded,
        GenerationLifecycleKindV1::Revoked,
    ] {
        let lifecycle = run_lifecycle_demo(kind)?;
        checks.push(HostileCheckV1 {
            scenario: format!("{kind:?} certificate"),
            expected_binding_state: lifecycle.after_state,
            observed_binding_state: lifecycle.after_state,
            observed_judgment: lifecycle.after_judgment,
            active_deadlines: lifecycle.active_deadlines_after,
            current_permitted: lifecycle.after_judgment == JudgmentCategoryV1::Current,
            authority_granted: false,
            passed: lifecycle.after_judgment != JudgmentCategoryV1::Current
                && lifecycle.active_deadlines_after == 0
                && !lifecycle.standing_preserved,
        });
    }

    let restart = run_restart_demo()?;
    checks.push(HostileCheckV1 {
        scenario: "successful prior activation receipt after process restart".to_owned(),
        expected_binding_state: pulse_types::RuntimeBindingStateV1::Unbound,
        observed_binding_state: restart.restarted_binding_state,
        observed_judgment: restart.restarted_judgment,
        active_deadlines: restart.restarted_active_deadlines,
        current_permitted: restart.restarted_judgment == JudgmentCategoryV1::Current,
        authority_granted: false,
        passed: restart.restarted_binding_state == pulse_types::RuntimeBindingStateV1::Unbound
            && restart.restarted_judgment == JudgmentCategoryV1::Unknown
            && restart.restarted_active_deadlines == 0
            && !restart.prior_receipt_reused,
    });

    let all_passed = checks.iter().all(|check| check.passed);
    Ok(HostileCorpusArtifactV1 {
        schema_version: SCHEMA_VERSION_V1,
        corpus: "authority-laundering-refusals".to_owned(),
        checks,
        all_passed,
    })
}

fn unbound_authority_check(scenario: &str) -> Result<HostileCheckV1, String> {
    let mut runtime = ReceiverSchedulerRuntime::new(fixture_config(
        "receiver-incarnation:authority-unbound",
        "clock:authority-unbound",
    ))
    .map_err(|error| error.to_string())?;
    runtime
        .register_consumer(fixture_registration(), 0)
        .map_err(|error| error.to_string())?;
    runtime
        .enqueue(1, fixture_ingress(1, 100))
        .map_err(|error| format!("{:?}: {}", error.class, error.detail))?;
    runtime.run_until(1).map_err(|error| error.to_string())?;
    let certificate = current_certificate(&runtime);
    let observed_binding_state = runtime.binding_state(
        &SubjectId::new(FIXTURE_SUBJECT),
        &ConsumerId::new(FIXTURE_CONSUMER),
    );
    Ok(HostileCheckV1 {
        scenario: scenario.to_owned(),
        expected_binding_state: pulse_types::RuntimeBindingStateV1::Unbound,
        observed_binding_state,
        observed_judgment: certificate.judgment,
        active_deadlines: runtime.scheduled_deadline_count(),
        current_permitted: certificate.judgment == JudgmentCategoryV1::Current,
        authority_granted: certificate.mutation_authority != MutationAuthorityV1::None,
        passed: observed_binding_state == pulse_types::RuntimeBindingStateV1::Unbound
            && certificate.judgment == JudgmentCategoryV1::Unknown
            && runtime.scheduled_deadline_count() == 0
            && certificate.mutation_authority == MutationAuthorityV1::None,
    })
}

fn partial_package_check(
    scenario: &str,
    include_manifest: bool,
    include_certificate: bool,
    include_report: bool,
    expected: pulse_types::RuntimeBindingStateV1,
) -> Result<HostileCheckV1, String> {
    let config = fixture_config(
        "receiver-incarnation:authority-partial",
        "clock:authority-partial",
    );
    let registration = fixture_registration();
    let package =
        build_fixture_package(&config, &registration).map_err(|error| error.to_string())?;
    let manifest = package
        .manifest_bytes()
        .map_err(|error| error.to_string())?;
    let certificate = package
        .certificate_bytes()
        .map_err(|error| error.to_string())?;
    let report = package.report_bytes().map_err(|error| error.to_string())?;
    let mut runtime = ReceiverSchedulerRuntime::new(config).map_err(|error| error.to_string())?;
    let activation = runtime
        .activate_qualified_binding(
            &registration,
            include_manifest.then_some(manifest.as_slice()),
            include_certificate.then_some(certificate.as_slice()),
            include_report.then_some(report.as_slice()),
            package.acceptance,
            0,
        )
        .map_err(|error| error.to_string())?;
    runtime
        .register_consumer(registration, 0)
        .map_err(|error| error.to_string())?;
    runtime
        .enqueue(1, fixture_ingress(1, 100))
        .map_err(|error| format!("{:?}: {}", error.class, error.detail))?;
    runtime.run_until(1).map_err(|error| error.to_string())?;
    let current = current_certificate(&runtime);
    Ok(HostileCheckV1 {
        scenario: scenario.to_owned(),
        expected_binding_state: expected,
        observed_binding_state: activation.receipt.body.state,
        observed_judgment: current.judgment,
        active_deadlines: runtime.scheduled_deadline_count(),
        current_permitted: current.judgment == JudgmentCategoryV1::Current,
        authority_granted: current.mutation_authority != MutationAuthorityV1::None,
        passed: activation.receipt.body.state == expected
            && current.judgment == JudgmentCategoryV1::Unknown
            && runtime.scheduled_deadline_count() == 0
            && current.mutation_authority == MutationAuthorityV1::None,
    })
}

#[must_use]
pub fn binding_nonclaims() -> Vec<String> {
    vec![
        "digest identity is not authorship, authority, freshness, or qualification".to_owned(),
        "local self-measurement is not independent attestation".to_owned(),
        "source-to-binary correspondence is not established".to_owned(),
        "compiler, toolchain, kernel, loader, and host integrity are not established".to_owned(),
        "no continuation, diagnostic-execution, deployment, signing, revocation, or mutation authority is granted".to_owned(),
        "no subject-health, complete-coverage, production, or product-plane claim is made".to_owned(),
    ]
}

#[must_use]
pub fn package_source_identity(package: &LocalQualificationPackageV1) -> &SourceIdentityV1 {
    &package.manifest.body.source
}
