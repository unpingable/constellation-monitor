#![forbid(unsafe_code)]
//! Bounded receiver/scheduler owner for exact consumer reliance contexts.

mod binding;
mod campaign;
mod crash;
mod custody;
mod journal;
mod reactor;

pub use campaign::{
    CrashFaultQualificationArtifactV1, DistributionU64V1, DistributionU128V1,
    JournalCorruptionCorpusV1, JournalScenarioV1, LiveLinuxArtifactV1, QualificationCheckV1,
    ReactorDemoArtifactV1, RestartDemoArtifactV1, TimerSampleV1, TruncationSweepV1,
    qualification_manifest, run_journal_corruption_corpus, run_live_linux_exercise,
    run_reactor_demo, run_restart_demo,
};
pub use crash::{
    CrashHarnessArtifactV1, CrashScenarioResultV1, run_crash_child, run_crash_harness,
};
pub use custody::*;
pub use journal::{
    HistoricalJournal, HistoricalJournalRecordV1, JournalAppendAckV1, JournalBoundsV1,
    JournalConfigV1, JournalCreationAckV1, JournalDamageClassV1, JournalDurabilityModeV1,
    JournalError, JournalErrorClassV1, JournalHistoryProjectionV1, JournalRecordBodyV1,
    JournalRecordKindV1, JournalRecoveryOutcomeV1, JournalRecoveryReportV1, JournalWriteStageV1,
    MonotonicEpochV1,
};
pub use reactor::{
    LocalCrashReactor, ReactorCommandError, ReactorCommandErrorClassV1, ReactorConditionV1,
    ReactorConfigV1, ReactorMetricsV1, ReactorSnapshotV1,
};

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use pulse_evaluator::{
    EvaluationOutput, Evaluator, ReceiverTracker, ReevaluationBarrierV1, ReliancePolicyV1,
};
use pulse_types::{
    ActivationReceiptV1, AuthenticationResultV1, ClockId, ConsumerId, ContextActivationId,
    ContradictionApplicabilityV1, ContradictionCustodyV1, DiagnosticEscalationRequestV1,
    EscalationDispositionV1, GenerationLifecycleFactV1, GenerationLifecycleKindV1,
    GenerationTransitionCauseV1, IncarnationId, JudgmentCategoryV1, LocalActivationAcceptanceV1,
    LocalActivationContextV1, LocalCertificateStatusV1, MockDiagnosticReceiptV1,
    MutationAuthorityV1, ObservationPolicyGenerationId, ObservationProfileIdV1, ObserverId,
    PulseFrameV1, QualifiedGenerationBindingV1, QualifiedGenerationSetV1, ReceivedPulseV1,
    ReceiverAcceptanceReceiptV1, ReceiverId, RelianceContextTransitionV1, RelianceContextV1,
    RelianceSupportCertificateV1, RemoteObservationCustodyReferenceV1, RuntimeBindingStateV1,
    RuntimeHistoricalStateV1, RuntimeMetricsV1, RuntimeRefusalClassV1, RuntimeRefusalId,
    RuntimeRefusalV1, SCHEMA_VERSION_V1, SparseDurableEventKindV1, SparseDurableEventV1,
    SparseEventId, SubjectId, SubjectScopeV1, TransportCustodyFindingV1,
    TransportCustodyPolicyBindingV1, VerifiedActivationV1, digest_parts, verify_local_activation,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBoundsV1 {
    pub maximum_subjects: usize,
    pub maximum_consumers_per_subject: usize,
    pub maximum_observers_per_subject: usize,
    pub maximum_receiver_streams: usize,
    pub maximum_incarnations_per_observer: usize,
    pub maximum_subject_incarnations_per_subject: usize,
    pub maximum_pending_inputs: usize,
    pub maximum_scheduled_deadlines: usize,
    pub maximum_context_activations_per_consumer: usize,
    pub maximum_active_escalations: usize,
    pub maximum_supporting_evidence_refs: usize,
    pub maximum_sparse_events: usize,
    pub maximum_diagnostic_receipts: usize,
}

impl RuntimeBoundsV1 {
    #[must_use]
    pub const fn qualification() -> Self {
        Self {
            maximum_subjects: 4,
            maximum_consumers_per_subject: 4,
            maximum_observers_per_subject: 8,
            maximum_receiver_streams: 32,
            maximum_incarnations_per_observer: 8,
            maximum_subject_incarnations_per_subject: 8,
            maximum_pending_inputs: 32,
            maximum_scheduled_deadlines: 16,
            maximum_context_activations_per_consumer: 32,
            maximum_active_escalations: 16,
            maximum_supporting_evidence_refs: 16,
            maximum_sparse_events: 2_048,
            maximum_diagnostic_receipts: 64,
        }
    }

    pub fn validate(self) -> Result<(), RuntimeError> {
        let values = [
            self.maximum_subjects,
            self.maximum_consumers_per_subject,
            self.maximum_observers_per_subject,
            self.maximum_receiver_streams,
            self.maximum_incarnations_per_observer,
            self.maximum_subject_incarnations_per_subject,
            self.maximum_pending_inputs,
            self.maximum_scheduled_deadlines,
            self.maximum_context_activations_per_consumer,
            self.maximum_active_escalations,
            self.maximum_supporting_evidence_refs,
            self.maximum_sparse_events,
            self.maximum_diagnostic_receipts,
        ];
        if values.contains(&0) {
            return Err(RuntimeError::new(
                "invalid_bounds",
                "every runtime bound must be nonzero",
            ));
        }
        if self.maximum_supporting_evidence_refs < self.maximum_observers_per_subject
            || self.maximum_supporting_evidence_refs > pulse_types::MAX_CERTIFICATE_EVIDENCE_REFS
        {
            return Err(RuntimeError::new(
                "invalid_bounds",
                "certificate evidence bound must cover observer capacity and fit v1",
            ));
        }
        Ok(())
    }
}

impl Default for RuntimeBoundsV1 {
    fn default() -> Self {
        Self::qualification()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfigV1 {
    pub schema_version: u16,
    pub receiver: ReceiverId,
    pub receiver_incarnation: IncarnationId,
    pub clock_id: ClockId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_custody_policy: Option<TransportCustodyPolicyBindingV1>,
    pub bounds: RuntimeBoundsV1,
}

impl RuntimeConfigV1 {
    pub fn validate(&self) -> Result<(), RuntimeError> {
        if self.schema_version != SCHEMA_VERSION_V1 {
            return Err(RuntimeError::new(
                "unsupported_schema",
                "runtime config schema is unsupported",
            ));
        }
        self.receiver
            .validate()
            .map_err(|_| RuntimeError::new("invalid_identity", "invalid receiver identity"))?;
        self.receiver_incarnation
            .validate()
            .map_err(|_| RuntimeError::new("invalid_identity", "invalid receiver incarnation"))?;
        self.clock_id
            .validate()
            .map_err(|_| RuntimeError::new("invalid_identity", "invalid clock identity"))?;
        if let Some(binding) = &self.transport_custody_policy {
            binding
                .validate()
                .map_err(|error| RuntimeError::new(error.code, error.detail.clone()))?;
        }
        self.bounds.validate()
    }
}

#[derive(Clone, Debug)]
pub struct ConsumerRegistrationV1 {
    pub policy: ReliancePolicyV1,
    pub context: RelianceContextV1,
    pub subject_incarnation: IncarnationId,
}

#[derive(Clone, Debug)]
pub struct ConsumerActivationV1 {
    pub policy: ReliancePolicyV1,
    pub context: RelianceContextV1,
    pub cause: GenerationTransitionCauseV1,
}

#[derive(Clone, Debug)]
pub struct PulseIngressV1 {
    pub frame: PulseFrameV1,
    pub transport_path: String,
    pub transport_observed_delay_ms: Option<u64>,
    pub authentication: AuthenticationResultV1,
}

#[derive(Debug)]
pub enum RuntimeInputV1 {
    ActivateConsumer(ConsumerActivationV1),
    ReplaceSubjectIncarnation {
        subject: SubjectId,
        replacement: IncarnationId,
        activations: Vec<ConsumerActivationV1>,
    },
    Pulse(PulseIngressV1),
    RemotePulse(Box<VerifiedRemoteObservationV1>),
    EscalationDisposition(EscalationDispositionV1),
    DiagnosticReceipt(MockDiagnosticReceiptV1),
    Reevaluate {
        subject: SubjectId,
        consumer: ConsumerId,
    },
    RevalidateTransportActivation {
        subject: SubjectId,
        consumer: ConsumerId,
        expected_policy: TransportCustodyPolicyBindingV1,
    },
    ReceiverBoundaryCondition {
        subject: Option<SubjectId>,
        finding: TransportCustodyFindingV1,
        session_binding_digest: Option<pulse_types::DigestV1>,
        detail: String,
        withdraw: bool,
    },
    RestoreMonitorCapability {
        subject: Option<SubjectId>,
        detail: String,
    },
}

impl RuntimeInputV1 {
    fn priority(&self) -> u8 {
        match self {
            Self::ActivateConsumer(_)
            | Self::ReplaceSubjectIncarnation { .. }
            | Self::ReceiverBoundaryCondition { .. } => 0,
            Self::Pulse(_) | Self::RemotePulse(_) => 2,
            Self::RevalidateTransportActivation { .. } => 1,
            Self::EscalationDisposition(_) | Self::DiagnosticReceipt(_) => 3,
            Self::RestoreMonitorCapability { .. } => 4,
            Self::Reevaluate { .. } => 5,
        }
    }

    fn ordering_subject(&self) -> String {
        match self {
            Self::ActivateConsumer(activation) => activation.policy.subject.to_string(),
            Self::ReplaceSubjectIncarnation { subject, .. }
            | Self::Reevaluate { subject, .. }
            | Self::RevalidateTransportActivation { subject, .. } => subject.to_string(),
            Self::Pulse(pulse) => pulse.frame.subject.to_string(),
            Self::RemotePulse(pulse) => pulse.frame().subject.to_string(),
            Self::RestoreMonitorCapability {
                subject: Some(subject),
                ..
            }
            | Self::ReceiverBoundaryCondition {
                subject: Some(subject),
                ..
            } => subject.to_string(),
            Self::EscalationDisposition(_)
            | Self::DiagnosticReceipt(_)
            | Self::ReceiverBoundaryCondition { subject: None, .. }
            | Self::RestoreMonitorCapability { subject: None, .. } => String::new(),
        }
    }

    fn ordering_discriminator(&self) -> String {
        match self {
            Self::ActivateConsumer(activation) => format!(
                "activation:{}:{}",
                activation.policy.consumer, activation.context.activation_id
            ),
            Self::ReplaceSubjectIncarnation { replacement, .. } => {
                format!("subject-replacement:{replacement}")
            }
            Self::Pulse(pulse) => format!(
                "pulse:{}:{}:{}:{}:{:05}:{}:{:020}:{}",
                pulse.frame.subject_incarnation,
                pulse.frame.observer,
                pulse.frame.observer_incarnation,
                pulse.frame.profile.name,
                pulse.frame.profile.version,
                pulse.frame.observation_policy_generation,
                pulse.frame.sequence,
                pulse.frame.observation_digest
            ),
            Self::RemotePulse(pulse) => format!(
                "remote-pulse:{}:{}:{}:{}:{:05}:{}:{:020}:{}",
                pulse.frame().subject_incarnation,
                pulse.frame().observer,
                pulse.frame().observer_incarnation,
                pulse.frame().profile.name,
                pulse.frame().profile.version,
                pulse.frame().observation_policy_generation,
                pulse.frame().sequence,
                pulse.frame().observation_digest
            ),
            Self::EscalationDisposition(disposition) => {
                format!("disposition:{}", disposition.request_id)
            }
            Self::DiagnosticReceipt(receipt) => {
                format!("receipt:{}:{}", receipt.request_id, receipt.receipt_id)
            }
            Self::Reevaluate { consumer, .. } => format!("reevaluate:{consumer}"),
            Self::RevalidateTransportActivation {
                consumer,
                expected_policy,
                ..
            } => format!(
                "transport-activation-revalidation:{consumer}:{}:{}",
                expected_policy.policy_generation, expected_policy.policy_digest
            ),
            Self::ReceiverBoundaryCondition {
                finding, detail, ..
            } => format!("receiver-boundary:{finding:?}:{detail}"),
            Self::RestoreMonitorCapability { detail, .. } => format!("restore:{detail}"),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCycleOutputV1 {
    pub certificates: Vec<RelianceSupportCertificateV1>,
    pub escalation_requests: Vec<DiagnosticEscalationRequestV1>,
    pub refusals: Vec<RuntimeRefusalV1>,
    pub sparse_events: Vec<SparseDurableEventV1>,
    pub trace_lines: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct RuntimeBindingActivationOutputV1 {
    pub receipt: ActivationReceiptV1,
    pub runtime_output: RuntimeCycleOutputV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationQualificationPointV1 {
    BeforeArtifactMeasurement,
    DuringArtifactMeasurement,
    AfterArtifactMeasurementBeforeBindingCommit,
    AfterBindingCommitBeforeReturn,
}

impl RuntimeCycleOutputV1 {
    fn append(&mut self, mut other: Self) {
        self.certificates.append(&mut other.certificates);
        self.escalation_requests
            .append(&mut other.escalation_requests);
        self.refusals.append(&mut other.refusals);
        self.sparse_events.append(&mut other.sparse_events);
        self.trace_lines.append(&mut other.trace_lines);
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ConsumerKey {
    subject: SubjectId,
    consumer: ConsumerId,
}

impl ConsumerKey {
    fn new(subject: SubjectId, consumer: ConsumerId) -> Self {
        Self { subject, consumer }
    }
}

struct ConsumerState {
    evaluator: Evaluator,
    context: RelianceContextV1,
    seen_activations: BTreeSet<ContextActivationId>,
    certificate: Option<RelianceSupportCertificateV1>,
}

struct QualifiedBindingSlot {
    state: RuntimeBindingStateV1,
    receipt: ActivationReceiptV1,
    acceptance: LocalActivationAcceptanceV1,
    accepted: Option<VerifiedActivationV1>,
}

#[derive(Default)]
struct SubjectState {
    consumers: BTreeSet<ConsumerId>,
    observers: BTreeSet<ObserverId>,
    subject_incarnations: BTreeSet<IncarnationId>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ReceiverStreamIdentity {
    subject: SubjectId,
    subject_incarnation: IncarnationId,
    observer: ObserverId,
    profile: ObservationProfileIdV1,
    observation_policy_generation: ObservationPolicyGenerationId,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PendingKey {
    at_monotonic_ms: u64,
    priority: u8,
    subject: String,
    discriminator: String,
    ingress_ordinal: u64,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ScheduleKey {
    deadline_monotonic_ms: u64,
    subject: SubjectId,
    consumer: ConsumerId,
    activation_id: ContextActivationId,
}

pub struct ReceiverSchedulerRuntime {
    config: RuntimeConfigV1,
    receiver: ReceiverTracker,
    subjects: BTreeMap<SubjectId, SubjectState>,
    consumers: BTreeMap<ConsumerKey, ConsumerState>,
    qualified_bindings: BTreeMap<ConsumerKey, QualifiedBindingSlot>,
    receiver_streams: BTreeSet<ReceiverStreamIdentity>,
    observer_incarnations: BTreeMap<(SubjectId, ObserverId), BTreeSet<IncarnationId>>,
    remote_observation_custody:
        BTreeMap<(SubjectId, ObserverId), RemoteObservationCustodyReferenceV1>,
    pending: BTreeMap<PendingKey, RuntimeInputV1>,
    schedules: BTreeSet<ScheduleKey>,
    request_owners: BTreeMap<pulse_types::EscalationRequestId, (ConsumerKey, u64)>,
    sparse_history: Vec<SparseDurableEventV1>,
    historical_contradictions: Vec<ContradictionCustodyV1>,
    diagnostic_receipts: Vec<MockDiagnosticReceiptV1>,
    historical_activation_ids: BTreeSet<ContextActivationId>,
    historical_policy_bodies:
        BTreeMap<(SubjectId, ConsumerId, pulse_types::PolicyGenerationId), pulse_types::DigestV1>,
    metrics: RuntimeMetricsV1,
    current_monotonic_ms: u64,
    ingress_counter: u64,
    event_counter: u64,
    refusal_counter: u64,
    history_exhausted: bool,
    history_exhaustion_reported: bool,
    history_blindness_latched: bool,
    pending_output: RuntimeCycleOutputV1,
}

impl ReceiverSchedulerRuntime {
    pub fn new(config: RuntimeConfigV1) -> Result<Self, RuntimeError> {
        config.validate()?;
        Ok(Self {
            receiver: ReceiverTracker::new(
                config.receiver.clone(),
                config.receiver_incarnation.clone(),
                config.clock_id.clone(),
            ),
            config,
            subjects: BTreeMap::new(),
            consumers: BTreeMap::new(),
            qualified_bindings: BTreeMap::new(),
            receiver_streams: BTreeSet::new(),
            observer_incarnations: BTreeMap::new(),
            remote_observation_custody: BTreeMap::new(),
            pending: BTreeMap::new(),
            schedules: BTreeSet::new(),
            request_owners: BTreeMap::new(),
            sparse_history: Vec::new(),
            historical_contradictions: Vec::new(),
            diagnostic_receipts: Vec::new(),
            historical_activation_ids: BTreeSet::new(),
            historical_policy_bodies: BTreeMap::new(),
            metrics: RuntimeMetricsV1::empty(),
            current_monotonic_ms: 0,
            ingress_counter: 0,
            event_counter: 0,
            refusal_counter: 0,
            history_exhausted: false,
            history_exhaustion_reported: false,
            history_blindness_latched: false,
            pending_output: RuntimeCycleOutputV1::default(),
        })
    }

    #[must_use]
    pub const fn config(&self) -> &RuntimeConfigV1 {
        &self.config
    }

    #[must_use]
    pub const fn metrics(&self) -> &RuntimeMetricsV1 {
        &self.metrics
    }

    #[must_use]
    pub fn current_certificate(
        &self,
        subject: &SubjectId,
        consumer: &ConsumerId,
    ) -> Option<&RelianceSupportCertificateV1> {
        self.consumers
            .get(&ConsumerKey::new(subject.clone(), consumer.clone()))
            .and_then(|state| state.certificate.as_ref())
    }

    #[must_use]
    pub fn pending_input_count(&self) -> usize {
        self.pending.len()
    }

    #[must_use]
    pub fn scheduled_deadline_count(&self) -> usize {
        self.schedules.len()
    }

    #[must_use]
    pub fn next_scheduled_deadline_monotonic_ms(&self) -> Option<u64> {
        self.schedules
            .first()
            .map(|schedule| schedule.deadline_monotonic_ms)
    }

    #[must_use]
    pub const fn current_monotonic_ms(&self) -> u64 {
        self.current_monotonic_ms
    }

    #[must_use]
    pub fn current_certificates(&self) -> Vec<RelianceSupportCertificateV1> {
        self.consumers
            .values()
            .filter_map(|state| state.certificate.clone())
            .collect()
    }

    #[must_use]
    pub fn binding_state(
        &self,
        subject: &SubjectId,
        consumer: &ConsumerId,
    ) -> RuntimeBindingStateV1 {
        self.qualified_bindings
            .get(&ConsumerKey::new(subject.clone(), consumer.clone()))
            .map_or(RuntimeBindingStateV1::Unbound, |slot| slot.state)
    }

    #[must_use]
    pub fn activation_receipt(
        &self,
        subject: &SubjectId,
        consumer: &ConsumerId,
    ) -> Option<&ActivationReceiptV1> {
        self.qualified_bindings
            .get(&ConsumerKey::new(subject.clone(), consumer.clone()))
            .map(|slot| &slot.receipt)
    }

    /// Verify and install one exact subject/consumer qualified-generation
    /// binding. The returned live activation cannot be deserialized or reused
    /// after restart. Installing any binding result is an immediate barrier for
    /// an already registered consumer; fresh evidence reevaluation remains a
    /// separate step.
    #[allow(clippy::too_many_arguments)]
    pub fn activate_qualified_binding(
        &mut self,
        registration: &ConsumerRegistrationV1,
        manifest_bytes: Option<&[u8]>,
        certificate_bytes: Option<&[u8]>,
        report_bytes: Option<&[u8]>,
        acceptance: LocalActivationAcceptanceV1,
        at_monotonic_ms: u64,
    ) -> Result<RuntimeBindingActivationOutputV1, RuntimeError> {
        self.activate_qualified_binding_with_qualification_hook(
            registration,
            manifest_bytes,
            certificate_bytes,
            report_bytes,
            acceptance,
            at_monotonic_ms,
            &mut |_| {},
        )
    }

    /// Deterministic crash-injection seam. Production callers use
    /// [`Self::activate_qualified_binding`]; this hook cannot alter a binding
    /// value and exists only to stop a child process at named custody points.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn activate_qualified_binding_with_qualification_hook(
        &mut self,
        registration: &ConsumerRegistrationV1,
        manifest_bytes: Option<&[u8]>,
        certificate_bytes: Option<&[u8]>,
        report_bytes: Option<&[u8]>,
        acceptance: LocalActivationAcceptanceV1,
        at_monotonic_ms: u64,
        hook: &mut dyn FnMut(ActivationQualificationPointV1),
    ) -> Result<RuntimeBindingActivationOutputV1, RuntimeError> {
        if self.history_exhausted {
            return Err(RuntimeError::new(
                "sparse_history_capacity",
                "sparse historical custody is exhausted; binding is fail-stopped",
            ));
        }
        self.ensure_time_not_regressed(at_monotonic_ms)?;
        self.validate_registration(registration)?;
        let key = ConsumerKey::new(
            registration.policy.subject.clone(),
            registration.policy.consumer.clone(),
        );
        let maximum_binding_slots = self
            .config
            .bounds
            .maximum_subjects
            .checked_mul(self.config.bounds.maximum_consumers_per_subject)
            .ok_or_else(|| RuntimeError::new("invalid_bounds", "binding slot bound overflow"))?;
        if !self.qualified_bindings.contains_key(&key)
            && self.qualified_bindings.len() >= maximum_binding_slots
        {
            return Err(RuntimeError::new(
                "qualified_binding_capacity",
                "qualified binding slot bound is full; no entry was evicted",
            ));
        }
        hook(ActivationQualificationPointV1::BeforeArtifactMeasurement);
        let semantic_measurements = active_runtime_measurements(&self.config, registration)
            .map_err(|error| RuntimeError::new(error.code, error.detail))?;
        hook(ActivationQualificationPointV1::DuringArtifactMeasurement);
        let expected_generation_set = QualifiedGenerationSetV1::from_context(
            registration.policy.subject.clone(),
            registration.policy.consumer.clone(),
            &registration.context,
        );
        let attempt = verify_local_activation(
            manifest_bytes,
            certificate_bytes,
            report_bytes,
            &acceptance,
            LocalActivationContextV1 {
                expected_generation_set,
                receiver_incarnation: self.config.receiver_incarnation.clone(),
                receiver_clock_id: self.config.clock_id.clone(),
                activated_at_monotonic_ms: at_monotonic_ms,
                runtime_version: env!("CARGO_PKG_VERSION").to_owned(),
                target_platform: format!(
                    "{}-unknown-{}",
                    std::env::consts::ARCH,
                    std::env::consts::OS
                ),
                semantic_measurements,
            },
        )
        .map_err(|error| RuntimeError::new(error.code, error.detail))?;
        hook(ActivationQualificationPointV1::AfterArtifactMeasurementBeforeBindingCommit);
        let receipt = attempt.receipt;
        let state = receipt.body.state;
        self.qualified_bindings.insert(
            key.clone(),
            QualifiedBindingSlot {
                state,
                receipt: receipt.clone(),
                acceptance,
                accepted: attempt.accepted,
            },
        );

        let mut output = std::mem::take(&mut self.pending_output);
        self.record_sparse(
            at_monotonic_ms,
            SparseDurableEventKindV1::QualifiedGenerationBindingChanged {
                receipt: Box::new(receipt.clone()),
            },
            &mut output,
        );
        self.cancel_schedule(&key);
        if let Some(mut consumer_state) = self.consumers.remove(&key) {
            let evaluation = consumer_state
                .evaluator
                .install_reevaluation_barrier(
                    ReevaluationBarrierV1::QualifiedGenerationBinding {
                        detail: format!(
                            "qualified-generation activation result is {state:?}; prior standing is not inherited"
                        ),
                    },
                    at_monotonic_ms,
                )
                .map_err(RuntimeError::from_evaluator)?;
            self.consumers.insert(key.clone(), consumer_state);
            self.apply_evaluation(&key, evaluation, at_monotonic_ms, &mut output)?;
        }
        output.trace_lines.push(format!(
            "[{at_monotonic_ms:06}ms] BINDING consumer={} state={state:?} receipt={} standing_inherited=false",
            key.consumer, receipt.receipt_digest
        ));
        output.append(std::mem::take(&mut self.pending_output));
        hook(ActivationQualificationPointV1::AfterBindingCommitBeforeReturn);
        Ok(RuntimeBindingActivationOutputV1 {
            receipt,
            runtime_output: output,
        })
    }

    /// Assemble a narrow local package from already-recorded exact
    /// qualification results, verify it through the same activation gate, and
    /// return both historical package objects and the live activation result.
    /// This function executes no command and trusts no generation label.
    pub fn qualify_and_activate_local_binding(
        &mut self,
        registration: &ConsumerRegistrationV1,
        inputs: LocalQualificationInputsV1,
        at_monotonic_ms: u64,
    ) -> Result<
        (
            LocalQualificationPackageV1,
            RuntimeBindingActivationOutputV1,
        ),
        RuntimeError,
    > {
        let package = build_local_qualification_package(&self.config, registration, inputs)
            .map_err(|error| RuntimeError::new(error.code, error.detail))?;
        let manifest = package
            .manifest_bytes()
            .map_err(|error| RuntimeError::new(error.code, error.detail))?;
        let certificate = package
            .certificate_bytes()
            .map_err(|error| RuntimeError::new(error.code, error.detail))?;
        let report = package
            .report_bytes()
            .map_err(|error| RuntimeError::new(error.code, error.detail))?;
        let activation = self.activate_qualified_binding(
            registration,
            Some(&manifest),
            Some(&certificate),
            Some(&report),
            package.acceptance.clone(),
            at_monotonic_ms,
        )?;
        Ok((package, activation))
    }

    pub fn apply_generation_lifecycle_fact(
        &mut self,
        subject: &SubjectId,
        consumer: &ConsumerId,
        fact: GenerationLifecycleFactV1,
        at_monotonic_ms: u64,
    ) -> Result<RuntimeCycleOutputV1, RuntimeError> {
        if self.history_exhausted {
            return Err(RuntimeError::new(
                "sparse_history_capacity",
                "sparse historical custody is exhausted; lifecycle change is fail-stopped",
            ));
        }
        self.ensure_time_not_regressed(at_monotonic_ms)?;
        fact.validate()
            .map_err(|error| RuntimeError::new(error.code, error.detail))?;
        let key = ConsumerKey::new(subject.clone(), consumer.clone());
        let slot = self.qualified_bindings.get_mut(&key).ok_or_else(|| {
            RuntimeError::new(
                "unbound_generation",
                "no active local binding exists for this lifecycle fact",
            )
        })?;
        let observed_through = match &slot.acceptance.certificate_status {
            LocalCertificateStatusV1::Accepted {
                observed_through_sequence,
            } => *observed_through_sequence,
            _ => {
                return Err(RuntimeError::new(
                    "lifecycle_already_terminal",
                    "binding lifecycle is already superseded, revoked, or unknown",
                ));
            }
        };
        if fact.body.authority_id != slot.acceptance.lifecycle_authority_id
            || fact.body.certificate_digest != slot.acceptance.accepted_certificate_digest
            || fact.body.fact_sequence <= observed_through
        {
            return Err(RuntimeError::new(
                "lifecycle_authority_mismatch",
                "fact authority, certificate, or sequence is not accepted by local policy",
            ));
        }
        let state = match fact.body.kind {
            GenerationLifecycleKindV1::Superseded => RuntimeBindingStateV1::Superseded,
            GenerationLifecycleKindV1::Revoked => RuntimeBindingStateV1::Revoked,
        };
        slot.state = state;
        slot.accepted = None;
        slot.acceptance.certificate_status = match fact.body.kind {
            GenerationLifecycleKindV1::Superseded => {
                LocalCertificateStatusV1::Superseded { fact: fact.clone() }
            }
            GenerationLifecycleKindV1::Revoked => {
                LocalCertificateStatusV1::Revoked { fact: fact.clone() }
            }
        };
        self.cancel_schedule(&key);
        let mut output = std::mem::take(&mut self.pending_output);
        self.record_sparse(
            at_monotonic_ms,
            SparseDurableEventKindV1::QualifiedGenerationLifecycleApplied {
                consumer: consumer.clone(),
                fact: Box::new(fact),
                state,
                standing_preserved: false,
            },
            &mut output,
        );
        if let Some(mut consumer_state) = self.consumers.remove(&key) {
            let evaluation = consumer_state
                .evaluator
                .install_reevaluation_barrier(
                    ReevaluationBarrierV1::QualifiedGenerationBinding {
                        detail: format!(
                            "accepted local lifecycle fact changed binding to {state:?}"
                        ),
                    },
                    at_monotonic_ms,
                )
                .map_err(RuntimeError::from_evaluator)?;
            self.consumers.insert(key.clone(), consumer_state);
            self.apply_evaluation(&key, evaluation, at_monotonic_ms, &mut output)?;
        }
        output.trace_lines.push(format!(
            "[{at_monotonic_ms:06}ms] LIFECYCLE consumer={consumer} state={state:?} standing_preserved=false"
        ));
        output.append(std::mem::take(&mut self.pending_output));
        Ok(output)
    }

    /// Withdraw positive standing when an enclosing local actor can no longer
    /// maintain a named observation premise. This bypasses the bounded input
    /// queue deliberately: queue saturation must not require adding one more
    /// item to the queue it just saturated.
    pub fn declare_external_monitor_blindness(
        &mut self,
        at_monotonic_ms: u64,
        state: impl Into<String>,
        detail: impl Into<String>,
    ) -> Result<RuntimeCycleOutputV1, RuntimeError> {
        self.ensure_time_not_regressed(at_monotonic_ms)?;
        let state = state.into();
        let detail = detail.into();
        let mut output = std::mem::take(&mut self.pending_output);
        self.record_sparse(
            at_monotonic_ms,
            SparseDurableEventKindV1::MonitorCapabilityChanged {
                state,
                detail: detail.clone(),
            },
            &mut output,
        );
        self.latch_blind_all(at_monotonic_ms, &detail);
        output.append(std::mem::take(&mut self.pending_output));
        Ok(output)
    }

    pub fn register_consumer(
        &mut self,
        registration: ConsumerRegistrationV1,
        at_monotonic_ms: u64,
    ) -> Result<RuntimeCycleOutputV1, RuntimeError> {
        if self.history_exhausted {
            return Err(RuntimeError::new(
                "sparse_history_capacity",
                "sparse historical custody is exhausted; registration is fail-stopped",
            ));
        }
        self.ensure_time_not_regressed(at_monotonic_ms)?;
        self.validate_registration(&registration)?;
        let subject = registration.policy.subject.clone();
        let consumer = registration.policy.consumer.clone();
        let key = ConsumerKey::new(subject.clone(), consumer.clone());
        if self.consumers.contains_key(&key) {
            return Err(RuntimeError::new(
                "consumer_exists",
                "consumer is already registered for the subject",
            ));
        }
        if !self.subjects.contains_key(&subject)
            && self.subjects.len() >= self.config.bounds.maximum_subjects
        {
            self.metrics.subject_refusal_count =
                self.metrics.subject_refusal_count.saturating_add(1);
            return Err(RuntimeError::new(
                "subject_capacity",
                "subject cardinality bound is full",
            ));
        }
        let subject_consumer_count = self
            .subjects
            .get(&subject)
            .map_or(0, |state| state.consumers.len());
        if subject_consumer_count >= self.config.bounds.maximum_consumers_per_subject {
            return Err(RuntimeError::new(
                "consumer_capacity",
                "consumer cardinality bound is full for the subject",
            ));
        }
        if self.consumers.len() >= self.config.bounds.maximum_scheduled_deadlines {
            self.metrics.deadline_refusal_count =
                self.metrics.deadline_refusal_count.saturating_add(1);
            return Err(RuntimeError::new(
                "scheduled_deadline_capacity",
                "no deadline slot can be reserved for another consumer",
            ));
        }
        if self
            .historical_activation_ids
            .contains(&registration.context.activation_id)
        {
            return Err(RuntimeError::new(
                "reused_activation",
                "historical context activation identity cannot be reactivated",
            ));
        }
        let policy_key = (
            subject.clone(),
            consumer.clone(),
            registration.policy.generation.clone(),
        );
        if self
            .historical_policy_bodies
            .get(&policy_key)
            .is_some_and(|digest| digest != &registration.policy.semantic_digest())
        {
            return Err(RuntimeError::new(
                "policy_generation_rebound",
                "historical reliance-policy generation identity names different semantic content",
            ));
        }

        let mut evaluator = Evaluator::new(
            registration.policy.clone(),
            self.config.receiver.clone(),
            self.config.receiver_incarnation.clone(),
            self.config.clock_id.clone(),
            registration.subject_incarnation.clone(),
        )
        .map_err(RuntimeError::from_evaluator)?;
        let evaluation = evaluator
            .install_reevaluation_barrier(
                ReevaluationBarrierV1::GenerationTransition {
                    detail: "initial exact reliance context activated; no prior standing exists"
                        .to_owned(),
                },
                at_monotonic_ms,
            )
            .map_err(RuntimeError::from_evaluator)?;
        let mut seen_activations = BTreeSet::new();
        seen_activations.insert(registration.context.activation_id.clone());
        self.consumers.insert(
            key.clone(),
            ConsumerState {
                evaluator,
                context: registration.context.clone(),
                seen_activations,
                certificate: None,
            },
        );
        let subject_state = self.subjects.entry(subject.clone()).or_default();
        subject_state.consumers.insert(consumer.clone());
        subject_state
            .subject_incarnations
            .insert(registration.subject_incarnation.clone());
        self.historical_activation_ids
            .insert(registration.context.activation_id.clone());
        self.historical_policy_bodies
            .insert(policy_key, registration.policy.semantic_digest());

        let mut output = RuntimeCycleOutputV1::default();
        self.record_context_transition(
            &key,
            None,
            registration.context,
            GenerationTransitionCauseV1::InitialActivation,
            registration.subject_incarnation,
            at_monotonic_ms,
            &mut output,
        );
        self.apply_evaluation(&key, evaluation, at_monotonic_ms, &mut output)?;
        Ok(output)
    }

    // The complete typed refusal is returned synchronously so overload cannot
    // be reduced to a lossy status code at the admission boundary.
    #[allow(clippy::result_large_err)]
    pub fn enqueue(
        &mut self,
        at_monotonic_ms: u64,
        input: RuntimeInputV1,
    ) -> Result<u64, RuntimeRefusalV1> {
        if self.history_exhausted {
            let refusal = self.refusal(
                RuntimeRefusalClassV1::RuntimeBlind,
                self.current_monotonic_ms,
                None,
                None,
                u64::try_from(self.config.bounds.maximum_sparse_events).unwrap_or(u64::MAX),
                u64::try_from(self.sparse_history.len().saturating_add(1)).unwrap_or(u64::MAX),
                "sparse historical custody is exhausted; new runtime input is fail-stopped",
            );
            self.stage_refusal(refusal.clone());
            self.latch_history_blindness(self.current_monotonic_ms);
            return Err(refusal);
        }
        if at_monotonic_ms < self.current_monotonic_ms {
            let refusal = self.refusal(
                RuntimeRefusalClassV1::ClockRegression,
                self.current_monotonic_ms,
                None,
                None,
                self.current_monotonic_ms,
                at_monotonic_ms,
                "input time regressed within one receiver clock generation",
            );
            self.stage_refusal(refusal.clone());
            self.latch_blind_all(
                self.current_monotonic_ms,
                "input time regressed within one receiver clock generation",
            );
            return Err(refusal);
        }
        if self.pending.len() >= self.config.bounds.maximum_pending_inputs {
            self.metrics.queue_refusal_count = self.metrics.queue_refusal_count.saturating_add(1);
            let refusal = self.refusal(
                RuntimeRefusalClassV1::PendingQueueCapacity,
                at_monotonic_ms,
                None,
                None,
                u64::try_from(self.config.bounds.maximum_pending_inputs).unwrap_or(u64::MAX),
                u64::try_from(self.pending.len().saturating_add(1)).unwrap_or(u64::MAX),
                "pending input queue is full; the new input was refused and monitor blindness latched",
            );
            self.stage_refusal(refusal.clone());
            self.latch_blind_all(
                at_monotonic_ms,
                "pending input queue saturated; at least one receiver input was not admitted",
            );
            return Err(refusal);
        }
        if self.ingress_counter == u64::MAX {
            let refusal = self.refusal(
                RuntimeRefusalClassV1::RuntimeBlind,
                at_monotonic_ms,
                None,
                None,
                u64::MAX,
                u64::MAX,
                "receiver ingress ordinal space is exhausted; input was refused",
            );
            self.stage_refusal(refusal.clone());
            self.latch_blind_all(
                at_monotonic_ms,
                "receiver ingress ordinal space is exhausted",
            );
            return Err(refusal);
        }
        self.ingress_counter += 1;
        let ordinal = self.ingress_counter;
        let key = PendingKey {
            at_monotonic_ms,
            priority: input.priority(),
            subject: input.ordering_subject(),
            discriminator: input.ordering_discriminator(),
            ingress_ordinal: ordinal,
        };
        self.pending.insert(key, input);
        Ok(ordinal)
    }

    pub fn run_until(
        &mut self,
        now_monotonic_ms: u64,
    ) -> Result<RuntimeCycleOutputV1, RuntimeError> {
        if now_monotonic_ms < self.current_monotonic_ms {
            let at = self.current_monotonic_ms;
            let refusal = self.refusal(
                RuntimeRefusalClassV1::ClockRegression,
                at,
                None,
                None,
                self.current_monotonic_ms,
                now_monotonic_ms,
                "scheduler time regressed within one receiver clock generation",
            );
            self.stage_refusal(refusal);
            self.latch_blind_all(at, "scheduler monotonic clock regressed");
            return Ok(std::mem::take(&mut self.pending_output));
        }
        self.current_monotonic_ms = now_monotonic_ms;
        self.request_owners
            .retain(|_, (_, expiry)| now_monotonic_ms < *expiry);
        let mut output = std::mem::take(&mut self.pending_output);

        loop {
            let next_pending = self
                .pending
                .first_key_value()
                .filter(|(key, _)| key.at_monotonic_ms <= now_monotonic_ms)
                .map(|(key, _)| key.clone());
            let next_schedule = self
                .schedules
                .first()
                .filter(|key| key.deadline_monotonic_ms <= now_monotonic_ms)
                .cloned();
            let take_pending = match (&next_pending, &next_schedule) {
                (None, None) => break,
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (Some(pending), Some(schedule)) => {
                    (
                        pending.at_monotonic_ms,
                        pending.priority,
                        pending.subject.as_str(),
                        pending.discriminator.as_str(),
                    ) <= (
                        schedule.deadline_monotonic_ms,
                        1,
                        schedule.subject.as_str(),
                        schedule.consumer.as_str(),
                    )
                }
            };
            if take_pending {
                let key = next_pending.expect("selected pending key exists");
                let input = self.pending.remove(&key).expect("pending input exists");
                self.process_input(
                    key.at_monotonic_ms,
                    key.ingress_ordinal,
                    input,
                    now_monotonic_ms,
                    &mut output,
                )?;
            } else {
                let schedule = next_schedule.expect("selected schedule exists");
                self.schedules.remove(&schedule);
                self.process_deadline(schedule, now_monotonic_ms, &mut output)?;
            }
        }

        if self.history_exhausted {
            self.latch_history_blindness(now_monotonic_ms);
            output.append(std::mem::take(&mut self.pending_output));
        }
        Ok(output)
    }

    #[must_use]
    pub fn export_history(&self) -> RuntimeHistoricalStateV1 {
        let mut contradictions = self
            .historical_contradictions
            .iter()
            .cloned()
            .map(|custody| {
                (
                    (
                        custody.contradiction.subject_scope.subject.clone(),
                        custody.consumer.clone(),
                        custody.contradiction.contradiction_id.clone(),
                    ),
                    custody,
                )
            })
            .collect::<BTreeMap<_, _>>();
        for (key, state) in &self.consumers {
            for record in state.evaluator.contradictions() {
                let applicability = match &record.status {
                    pulse_types::ContradictionStatusV1::InapplicableBySubjectReplacement {
                        prior_subject_incarnation,
                        replacement_subject_incarnation,
                        at_monotonic_ms,
                        rule,
                    } => ContradictionApplicabilityV1::InapplicableBySubjectReplacement {
                        prior_subject_incarnation: prior_subject_incarnation.clone(),
                        replacement_subject_incarnation: replacement_subject_incarnation.clone(),
                        at_monotonic_ms: *at_monotonic_ms,
                        rule: rule.clone(),
                    },
                    _ => ContradictionApplicabilityV1::Applicable {
                        subject_incarnation: record.subject_scope.subject_incarnation.clone(),
                        blocks_reliance: record.is_active()
                            && record.subject_scope.subject_incarnation
                                == *state.evaluator.current_subject_incarnation(),
                    },
                };
                let custody = ContradictionCustodyV1 {
                    schema_version: SCHEMA_VERSION_V1,
                    consumer: key.consumer.clone(),
                    contradiction: record.clone(),
                    applicability,
                };
                contradictions.insert(
                    (
                        custody.contradiction.subject_scope.subject.clone(),
                        custody.consumer.clone(),
                        custody.contradiction.contradiction_id.clone(),
                    ),
                    custody,
                );
            }
        }
        RuntimeHistoricalStateV1 {
            schema_version: SCHEMA_VERSION_V1,
            sparse_events: self.sparse_history.clone(),
            contradictions: contradictions.into_values().collect(),
            diagnostic_receipts: self.diagnostic_receipts.clone(),
            nonclaims: pulse_types::history_nonclaims(),
        }
    }

    pub fn recover(
        config: RuntimeConfigV1,
        registrations: Vec<ConsumerRegistrationV1>,
        history: RuntimeHistoricalStateV1,
        at_monotonic_ms: u64,
    ) -> Result<(Self, RuntimeCycleOutputV1), RuntimeError> {
        history
            .validate()
            .map_err(|error| RuntimeError::new(error.code, error.detail))?;
        config.validate()?;
        if history.sparse_events.len() > config.bounds.maximum_sparse_events
            || history.contradictions.len() > config.bounds.maximum_sparse_events
            || history.diagnostic_receipts.len() > config.bounds.maximum_diagnostic_receipts
        {
            return Err(RuntimeError::new(
                "historical_capacity",
                "historical state exceeds configured runtime bounds",
            ));
        }
        let mut runtime = Self::new(config)?;
        runtime.sparse_history = history.sparse_events;
        runtime.historical_contradictions = history.contradictions.clone();
        runtime.diagnostic_receipts = history.diagnostic_receipts;
        runtime.event_counter = u64::try_from(runtime.sparse_history.len()).unwrap_or(u64::MAX);
        runtime.metrics.recovered_sparse_record_count =
            u64::try_from(runtime.sparse_history.len()).unwrap_or(u64::MAX);
        runtime.metrics.recovered_receipt_count =
            u64::try_from(runtime.diagnostic_receipts.len()).unwrap_or(u64::MAX);
        for event in &runtime.sparse_history {
            if let SparseDurableEventKindV1::RelianceContextTransition { transition } = &event.event
            {
                runtime
                    .historical_activation_ids
                    .insert(transition.new_context.activation_id.clone());
                let policy_key = (
                    transition.subject_scope.subject.clone(),
                    transition.consumer.clone(),
                    transition.new_context.reliance_policy_generation.clone(),
                );
                if runtime
                    .historical_policy_bodies
                    .get(&policy_key)
                    .is_some_and(|digest| {
                        digest != &transition.new_context.reliance_policy_semantic_digest
                    })
                {
                    return Err(RuntimeError::new(
                        "historical_generation_rebound",
                        "historical context transitions bind one policy generation to different bodies",
                    ));
                }
                runtime.historical_policy_bodies.insert(
                    policy_key,
                    transition
                        .new_context
                        .reliance_policy_semantic_digest
                        .clone(),
                );
            }
        }

        let prior_activations = runtime.historical_activation_ids.clone();
        let mut output = RuntimeCycleOutputV1::default();
        for registration in registrations {
            if prior_activations.contains(&registration.context.activation_id) {
                return Err(RuntimeError::new(
                    "reused_activation",
                    "restart requires a new context activation identity",
                ));
            }
            output.append(runtime.register_consumer(registration, at_monotonic_ms)?);
        }

        let mut grouped: BTreeMap<ConsumerKey, Vec<pulse_types::ContradictionRecordV1>> =
            BTreeMap::new();
        for custody in history.contradictions {
            if matches!(
                custody.applicability,
                ContradictionApplicabilityV1::Applicable {
                    blocks_reliance: true,
                    ..
                }
            ) && custody.contradiction.is_active()
            {
                grouped
                    .entry(ConsumerKey::new(
                        custody.contradiction.subject_scope.subject.clone(),
                        custody.consumer,
                    ))
                    .or_default()
                    .push(custody.contradiction);
            }
        }
        for (key, records) in grouped {
            let Some(mut state) = runtime.consumers.remove(&key) else {
                return Err(RuntimeError::new(
                    "historical_binding",
                    "contradiction history has no registered consumer",
                ));
            };
            state
                .evaluator
                .import_contradictions(records)
                .map_err(RuntimeError::from_evaluator)?;
            runtime.consumers.insert(key, state);
        }
        for key in runtime.consumer_keys(None) {
            let mut state = runtime
                .consumers
                .remove(&key)
                .expect("registered recovery consumer exists");
            let evaluation = state
                .evaluator
                .install_reevaluation_barrier(
                    ReevaluationBarrierV1::ReceiverRestart {
                        detail: "historical custody was recovered without hot evidence or current standing"
                            .to_owned(),
                    },
                    at_monotonic_ms,
                )
                .map_err(RuntimeError::from_evaluator)?;
            runtime.consumers.insert(key.clone(), state);
            runtime.apply_evaluation(&key, evaluation, at_monotonic_ms, &mut output)?;
        }
        let restart_event = SparseDurableEventKindV1::RuntimeRestarted {
            receiver_incarnation: runtime.config.receiver_incarnation.clone(),
            clock_id: runtime.config.clock_id.clone(),
            recovered_sparse_records: runtime.metrics.recovered_sparse_record_count,
            recovered_receipts: runtime.metrics.recovered_receipt_count,
            standing_recovered: false,
        };
        runtime.record_sparse(at_monotonic_ms, restart_event, &mut output);
        output.trace_lines.push(format!(
            "[{at_monotonic_ms:06}ms] RESTART historical_records={} receipts={} current_standing=UNKNOWN",
            runtime.metrics.recovered_sparse_record_count,
            runtime.metrics.recovered_receipt_count,
        ));
        Ok((runtime, output))
    }

    fn process_input(
        &mut self,
        logical_at: u64,
        ingress_ordinal: u64,
        input: RuntimeInputV1,
        evaluated_at: u64,
        output: &mut RuntimeCycleOutputV1,
    ) -> Result<(), RuntimeError> {
        match input {
            RuntimeInputV1::ActivateConsumer(activation) => {
                self.activate_consumer(logical_at, activation, evaluated_at, output)?;
            }
            RuntimeInputV1::ReplaceSubjectIncarnation {
                subject,
                replacement,
                activations,
            } => self.replace_subject_incarnation(
                logical_at,
                subject,
                replacement,
                activations,
                evaluated_at,
                output,
            )?,
            RuntimeInputV1::Pulse(pulse) => {
                self.process_pulse(
                    logical_at,
                    ingress_ordinal,
                    pulse,
                    None,
                    evaluated_at,
                    output,
                )?;
            }
            RuntimeInputV1::RemotePulse(verified) => {
                let (frame, custody, receipt) = verified.into_parts();
                let principal = custody.sender_key_identity_digest.to_string();
                let receiver_arrival_monotonic_ms = custody.receiver_arrival_monotonic_ms;
                self.process_pulse(
                    receiver_arrival_monotonic_ms,
                    ingress_ordinal,
                    PulseIngressV1 {
                        frame,
                        transport_path: "udp-authenticated-custody/v1".to_owned(),
                        transport_observed_delay_ms: None,
                        authentication: AuthenticationResultV1::Verified {
                            method: "ed25519-pinned-custody/v1".to_owned(),
                            principal,
                        },
                    },
                    Some((custody, receipt)),
                    evaluated_at,
                    output,
                )?;
            }
            RuntimeInputV1::EscalationDisposition(disposition) => {
                let Some((owner, _)) = self.request_owners.get(&disposition.request_id).cloned()
                else {
                    self.push_refusal(
                        RuntimeRefusalClassV1::InvalidBinding,
                        evaluated_at,
                        None,
                        None,
                        0,
                        1,
                        "escalation disposition references no active runtime request",
                        output,
                    );
                    return Ok(());
                };
                let mut state = self
                    .consumers
                    .remove(&owner)
                    .expect("request owner consumer exists");
                let evaluation = state
                    .evaluator
                    .record_escalation_disposition(disposition, evaluated_at)
                    .map_err(RuntimeError::from_evaluator)?;
                self.consumers.insert(owner.clone(), state);
                self.apply_evaluation(&owner, evaluation, evaluated_at, output)?;
            }
            RuntimeInputV1::DiagnosticReceipt(receipt) => {
                if self.diagnostic_receipts.len() >= self.config.bounds.maximum_diagnostic_receipts
                {
                    self.push_refusal(
                        RuntimeRefusalClassV1::ReceiptHistoryCapacity,
                        evaluated_at,
                        Some(receipt.subject_scope.subject.clone()),
                        Some(receipt.consumer.clone()),
                        u64::try_from(self.config.bounds.maximum_diagnostic_receipts)
                            .unwrap_or(u64::MAX),
                        u64::try_from(self.diagnostic_receipts.len().saturating_add(1))
                            .unwrap_or(u64::MAX),
                        "diagnostic receipt custody bound is full",
                        output,
                    );
                    self.latch_blind_subject(
                        &receipt.subject_scope.subject,
                        evaluated_at,
                        "diagnostic receipt custody was refused at capacity",
                    );
                    return Ok(());
                }
                let Some((owner, _)) = self.request_owners.get(&receipt.request_id).cloned() else {
                    self.push_refusal(
                        RuntimeRefusalClassV1::InvalidBinding,
                        evaluated_at,
                        Some(receipt.subject_scope.subject.clone()),
                        Some(receipt.consumer.clone()),
                        0,
                        1,
                        "diagnostic receipt references no active runtime request",
                        output,
                    );
                    return Ok(());
                };
                let mut state = self
                    .consumers
                    .remove(&owner)
                    .expect("request owner consumer exists");
                let evaluation = state
                    .evaluator
                    .record_diagnostic_receipt(receipt.clone(), evaluated_at)
                    .map_err(RuntimeError::from_evaluator)?;
                self.diagnostic_receipts.push(receipt);
                self.consumers.insert(owner.clone(), state);
                self.apply_evaluation(&owner, evaluation, evaluated_at, output)?;
            }
            RuntimeInputV1::Reevaluate { subject, consumer } => {
                let key = ConsumerKey::new(subject, consumer);
                let mut state = self.consumers.remove(&key).ok_or_else(|| {
                    RuntimeError::new("unknown_consumer", "reevaluation consumer is unknown")
                })?;
                let evaluation = state
                    .evaluator
                    .tick(evaluated_at)
                    .map_err(RuntimeError::from_evaluator)?;
                self.consumers.insert(key.clone(), state);
                self.apply_evaluation(&key, evaluation, evaluated_at, output)?;
            }
            RuntimeInputV1::RevalidateTransportActivation {
                subject,
                consumer,
                expected_policy,
            } => {
                if self.config.transport_custody_policy.as_ref() != Some(&expected_policy) {
                    return Err(RuntimeError::new(
                        "transport_policy_mismatch",
                        "transport revalidation policy differs from the activated runtime configuration",
                    ));
                }
                let key = ConsumerKey::new(subject, consumer);
                let mut state = self.consumers.remove(&key).ok_or_else(|| {
                    RuntimeError::new(
                        "unknown_consumer",
                        "transport activation consumer is unknown",
                    )
                })?;
                let _ = self.revalidated_qualified_binding(&key, &state, evaluated_at, output)?;
                let evaluation = state
                    .evaluator
                    .tick(evaluated_at)
                    .map_err(RuntimeError::from_evaluator)?;
                self.consumers.insert(key.clone(), state);
                self.apply_evaluation(&key, evaluation, evaluated_at, output)?;
            }
            RuntimeInputV1::ReceiverBoundaryCondition {
                subject,
                finding,
                session_binding_digest,
                detail,
                withdraw,
            } => {
                if detail.is_empty() || detail.len() > 256 || detail.chars().any(char::is_control) {
                    return Err(RuntimeError::new(
                        "invalid_receiver_boundary_condition",
                        "receiver-boundary condition detail is empty, over-bound, or contains control characters",
                    ));
                }
                self.record_sparse(
                    evaluated_at,
                    SparseDurableEventKindV1::ReceiverBoundaryCustodyChanged {
                        state: finding,
                        session_binding_digest,
                        detail: detail.clone(),
                    },
                    output,
                );
                output.trace_lines.push(format!(
                    "[{evaluated_at:06}ms] RECEIVER_BOUNDARY state={finding:?} detail={detail}"
                ));
                if withdraw {
                    if let Some(subject) = &subject {
                        self.latch_blind_subject(subject, evaluated_at, &detail);
                    } else {
                        self.latch_blind_all(evaluated_at, &detail);
                    }
                    output.append(std::mem::take(&mut self.pending_output));
                }
            }
            RuntimeInputV1::RestoreMonitorCapability { subject, detail } => {
                let keys = self.consumer_keys(subject.as_ref());
                for key in keys {
                    let mut state = self.consumers.remove(&key).expect("consumer exists");
                    let evaluation = state
                        .evaluator
                        .restore_monitor_capability(evaluated_at, detail.clone())
                        .map_err(RuntimeError::from_evaluator)?;
                    self.consumers.insert(key.clone(), state);
                    self.apply_evaluation(&key, evaluation, evaluated_at, output)?;
                }
                output.trace_lines.push(format!(
                    "[{evaluated_at:06}ms] MONITOR operational detail={detail}; explicit reevaluation still governs standing"
                ));
            }
        }
        Ok(())
    }

    fn process_deadline(
        &mut self,
        schedule: ScheduleKey,
        evaluated_at: u64,
        output: &mut RuntimeCycleOutputV1,
    ) -> Result<(), RuntimeError> {
        let key = ConsumerKey::new(schedule.subject.clone(), schedule.consumer.clone());
        let Some(mut state) = self.consumers.remove(&key) else {
            return Ok(());
        };
        if state.context.activation_id != schedule.activation_id {
            self.consumers.insert(key, state);
            return Ok(());
        }
        let evaluation = state
            .evaluator
            .tick(evaluated_at)
            .map_err(RuntimeError::from_evaluator)?;
        self.metrics.expected_support_expiry_monotonic_ms = Some(schedule.deadline_monotonic_ms);
        self.metrics.actual_reevaluation_monotonic_ms = Some(evaluated_at);
        let overshoot = evaluated_at.saturating_sub(schedule.deadline_monotonic_ms);
        self.metrics.scheduler_lateness_ms = self.metrics.scheduler_lateness_ms.max(overshoot);
        self.metrics.maximum_stale_positive_duration_ms = self
            .metrics
            .maximum_stale_positive_duration_ms
            .max(overshoot);
        self.consumers.insert(key.clone(), state);
        self.record_sparse(
            evaluated_at,
            SparseDurableEventKindV1::SchedulerReevaluated {
                consumer: key.consumer.clone(),
                activation_id: schedule.activation_id,
                expected_deadline_monotonic_ms: schedule.deadline_monotonic_ms,
                actual_reevaluation_monotonic_ms: evaluated_at,
                stale_positive_overshoot_ms: overshoot,
            },
            output,
        );
        output.trace_lines.push(format!(
            "[{evaluated_at:06}ms] DEADLINE consumer={} expected={}ms actual={}ms overshoot={}ms",
            key.consumer, schedule.deadline_monotonic_ms, evaluated_at, overshoot
        ));
        self.apply_evaluation(&key, evaluation, evaluated_at, output)
    }

    fn process_pulse(
        &mut self,
        arrival_at: u64,
        ingress_ordinal: u64,
        pulse: PulseIngressV1,
        remote: Option<(
            RemoteObservationCustodyReferenceV1,
            ReceiverAcceptanceReceiptV1,
        )>,
        evaluated_at: u64,
        output: &mut RuntimeCycleOutputV1,
    ) -> Result<(), RuntimeError> {
        let subject = pulse.frame.subject.clone();
        let observer = pulse.frame.observer.clone();
        let Some(subject_state) = self.subjects.get(&subject) else {
            self.push_refusal(
                RuntimeRefusalClassV1::InvalidBinding,
                evaluated_at,
                Some(subject),
                None,
                u64::try_from(self.config.bounds.maximum_subjects).unwrap_or(u64::MAX),
                u64::try_from(self.subjects.len().saturating_add(1)).unwrap_or(u64::MAX),
                "pulse subject has no registered consumer",
                output,
            );
            return Ok(());
        };
        let new_observer = !subject_state.observers.contains(&observer);
        if new_observer
            && subject_state.observers.len() >= self.config.bounds.maximum_observers_per_subject
        {
            self.metrics.observer_refusal_count =
                self.metrics.observer_refusal_count.saturating_add(1);
            self.push_refusal(
                RuntimeRefusalClassV1::ObserverCapacity,
                evaluated_at,
                Some(subject.clone()),
                None,
                u64::try_from(self.config.bounds.maximum_observers_per_subject).unwrap_or(u64::MAX),
                u64::try_from(subject_state.observers.len().saturating_add(1)).unwrap_or(u64::MAX),
                "new observer identity refused at subject cardinality bound",
                output,
            );
            self.latch_blind_subject(
                &subject,
                evaluated_at,
                "observer identity capacity was exceeded",
            );
            return Ok(());
        }

        let stream = ReceiverStreamIdentity {
            subject: subject.clone(),
            subject_incarnation: pulse.frame.subject_incarnation.clone(),
            observer: observer.clone(),
            profile: pulse.frame.profile.clone(),
            observation_policy_generation: pulse.frame.observation_policy_generation.clone(),
        };
        if !self.receiver_streams.contains(&stream)
            && self.receiver_streams.len() >= self.config.bounds.maximum_receiver_streams
        {
            self.metrics.receiver_stream_refusal_count =
                self.metrics.receiver_stream_refusal_count.saturating_add(1);
            self.push_refusal(
                RuntimeRefusalClassV1::ReceiverStreamCapacity,
                evaluated_at,
                Some(subject.clone()),
                None,
                u64::try_from(self.config.bounds.maximum_receiver_streams).unwrap_or(u64::MAX),
                u64::try_from(self.receiver_streams.len().saturating_add(1)).unwrap_or(u64::MAX),
                "new receiver stream identity refused at capacity",
                output,
            );
            self.latch_blind_subject(
                &subject,
                evaluated_at,
                "receiver stream identity capacity was exceeded",
            );
            return Ok(());
        }
        let lineage_key = (subject.clone(), observer.clone());
        let incarnation_count = self
            .observer_incarnations
            .get(&lineage_key)
            .map_or(0, BTreeSet::len);
        let new_incarnation = self
            .observer_incarnations
            .get(&lineage_key)
            .is_none_or(|items| !items.contains(&pulse.frame.observer_incarnation));
        if new_incarnation
            && incarnation_count >= self.config.bounds.maximum_incarnations_per_observer
        {
            self.push_refusal(
                RuntimeRefusalClassV1::IncarnationHistoryCapacity,
                evaluated_at,
                Some(subject.clone()),
                None,
                u64::try_from(self.config.bounds.maximum_incarnations_per_observer)
                    .unwrap_or(u64::MAX),
                u64::try_from(incarnation_count.saturating_add(1)).unwrap_or(u64::MAX),
                "observer incarnation churn exceeded the receiver history bound",
                output,
            );
            self.latch_blind_subject(
                &subject,
                evaluated_at,
                "observer incarnation history capacity was exceeded",
            );
            return Ok(());
        }

        self.subjects
            .get_mut(&subject)
            .expect("subject exists")
            .observers
            .insert(observer.clone());
        self.receiver_streams.insert(stream);
        self.observer_incarnations
            .entry(lineage_key)
            .or_default()
            .insert(pulse.frame.observer_incarnation.clone());
        if let Some((custody, receipt)) = &remote {
            custody
                .validate()
                .map_err(|error| RuntimeError::new(error.code, error.detail.clone()))?;
            receipt
                .validate()
                .map_err(|error| RuntimeError::new(error.code, error.detail.clone()))?;
            if custody.subject_scope.subject != pulse.frame.subject
                || custody.subject_scope.subject_incarnation != pulse.frame.subject_incarnation
                || custody.observer != pulse.frame.observer
                || custody.observation_sequence != pulse.frame.sequence
                || custody.observation_identity != pulse.frame.observation_digest
                || receipt.accepted_evidence_identity.as_ref()
                    != Some(&custody.accepted_evidence_identity)
                || receipt.envelope_digest.as_ref() != Some(&custody.envelope_digest)
            {
                return Err(RuntimeError::new(
                    "remote_custody_mismatch",
                    "verified remote custody no longer matches the admitted pulse",
                ));
            }
            self.record_sparse(
                evaluated_at,
                SparseDurableEventKindV1::ReceiverBoundaryAcceptanceRecorded {
                    receipt: Box::new(receipt.clone()),
                },
                output,
            );
            self.remote_observation_custody
                .insert((subject.clone(), observer.clone()), custody.clone());
        } else {
            self.remote_observation_custody
                .remove(&(subject.clone(), observer.clone()));
        }
        let annotation = self
            .receiver
            .annotate(
                &pulse.frame,
                arrival_at,
                pulse.transport_path,
                pulse.transport_observed_delay_ms,
                pulse.authentication,
            )
            .map_err(|error| RuntimeError::new("receiver_refusal", error.to_string()))?;
        let received = ReceivedPulseV1 {
            frame: pulse.frame,
            receiver: annotation,
        };
        let keys = self.consumer_keys(Some(&subject));
        for key in keys {
            let compatible = self.consumers.get(&key).is_some_and(|state| {
                state.evaluator.policy().observation_profile == received.frame.profile
                    && state.evaluator.policy().observation_policy_generation
                        == received.frame.observation_policy_generation
            });
            if !compatible {
                continue;
            }
            let mut state = self.consumers.remove(&key).expect("consumer exists");
            let evaluation = state
                .evaluator
                .ingest(received.clone(), evaluated_at)
                .map_err(RuntimeError::from_evaluator)?;
            self.consumers.insert(key.clone(), state);
            output.trace_lines.push(format!(
                "[{evaluated_at:06}ms] PULSE ordinal={ingress_ordinal} observer={} sequence={} arrival={}ms",
                received.frame.observer, received.frame.sequence, arrival_at
            ));
            self.apply_evaluation(&key, evaluation, evaluated_at, output)?;
        }
        Ok(())
    }

    fn activate_consumer(
        &mut self,
        logical_at: u64,
        activation: ConsumerActivationV1,
        evaluated_at: u64,
        output: &mut RuntimeCycleOutputV1,
    ) -> Result<(), RuntimeError> {
        self.validate_activation(&activation)?;
        let key = ConsumerKey::new(
            activation.policy.subject.clone(),
            activation.policy.consumer.clone(),
        );
        let mut state = self.consumers.remove(&key).ok_or_else(|| {
            RuntimeError::new("unknown_consumer", "activation consumer is not registered")
        })?;
        if state
            .seen_activations
            .contains(&activation.context.activation_id)
            || self
                .historical_activation_ids
                .contains(&activation.context.activation_id)
        {
            self.consumers.insert(key.clone(), state);
            self.metrics.context_refusal_count =
                self.metrics.context_refusal_count.saturating_add(1);
            self.push_refusal(
                RuntimeRefusalClassV1::ReusedActivation,
                evaluated_at,
                Some(key.subject.clone()),
                Some(key.consumer.clone()),
                u64::try_from(self.config.bounds.maximum_context_activations_per_consumer)
                    .unwrap_or(u64::MAX),
                u64::try_from(
                    self.consumers
                        .get(&key)
                        .map_or(0, |item| item.seen_activations.len()),
                )
                .unwrap_or(u64::MAX),
                "context activation identity was already used; standing was withdrawn",
                output,
            );
            self.latch_blind_consumer(
                &key,
                evaluated_at,
                "reused context activation identity was refused",
            );
            return Ok(());
        }
        if state.seen_activations.len()
            >= self.config.bounds.maximum_context_activations_per_consumer
        {
            self.consumers.insert(key.clone(), state);
            self.metrics.context_refusal_count =
                self.metrics.context_refusal_count.saturating_add(1);
            self.push_refusal(
                RuntimeRefusalClassV1::ContextHistoryCapacity,
                evaluated_at,
                Some(key.subject.clone()),
                Some(key.consumer.clone()),
                u64::try_from(self.config.bounds.maximum_context_activations_per_consumer)
                    .unwrap_or(u64::MAX),
                u64::try_from(self.config.bounds.maximum_context_activations_per_consumer + 1)
                    .unwrap_or(u64::MAX),
                "consumer context activation history is full",
                output,
            );
            self.latch_blind_consumer(
                &key,
                evaluated_at,
                "consumer context history capacity was exceeded",
            );
            return Ok(());
        }
        let policy_key = (
            key.subject.clone(),
            key.consumer.clone(),
            activation.policy.generation.clone(),
        );
        let policy_digest = activation.policy.semantic_digest();
        if let Some(existing) = self.historical_policy_bodies.get(&policy_key)
            && existing != &policy_digest
        {
            self.consumers.insert(key.clone(), state);
            self.push_refusal(
                RuntimeRefusalClassV1::InvalidBinding,
                evaluated_at,
                Some(key.subject.clone()),
                Some(key.consumer.clone()),
                1,
                2,
                "one reliance-policy generation identity was rebound to different semantic content",
                output,
            );
            self.latch_blind_consumer(
                &key,
                evaluated_at,
                "reliance-policy generation identity was rebound",
            );
            return Ok(());
        }
        self.invalidate_binding_for_context_change(&key, &activation.context, evaluated_at, output);
        let prior_context = state.context.clone();
        let prior_was_current = state
            .certificate
            .as_ref()
            .is_some_and(|certificate| certificate.judgment == JudgmentCategoryV1::Current);
        state
            .seen_activations
            .insert(activation.context.activation_id.clone());
        state.context = activation.context.clone();
        let evaluation = state
            .evaluator
            .replace_policy(
                activation.policy,
                ReevaluationBarrierV1::GenerationTransition {
                    detail: format!(
                        "exact reliance context changed from {} to {}; prior CURRENT was not inherited",
                        prior_context.activation_id, activation.context.activation_id
                    ),
                },
                evaluated_at,
            )
            .map_err(RuntimeError::from_evaluator)?;
        self.consumers.insert(key.clone(), state);
        self.historical_activation_ids
            .insert(activation.context.activation_id.clone());
        self.historical_policy_bodies
            .insert(policy_key, policy_digest);
        self.cancel_schedule(&key);
        let withdrawal_latency = evaluated_at.saturating_sub(logical_at);
        if prior_was_current {
            self.metrics.policy_transition_withdrawal_latency_ms = self
                .metrics
                .policy_transition_withdrawal_latency_ms
                .max(withdrawal_latency);
            self.metrics.maximum_stale_positive_duration_ms = self
                .metrics
                .maximum_stale_positive_duration_ms
                .max(withdrawal_latency);
        }
        let subject_incarnation = self
            .consumers
            .get(&key)
            .expect("consumer exists")
            .evaluator
            .current_subject_incarnation()
            .clone();
        self.record_context_transition(
            &key,
            Some(prior_context),
            activation.context,
            activation.cause,
            subject_incarnation,
            evaluated_at,
            output,
        );
        output.trace_lines.push(format!(
            "[{evaluated_at:06}ms] CONTEXT consumer={} cause={:?} standing_inherited=false",
            key.consumer, activation.cause
        ));
        self.apply_evaluation(&key, evaluation, evaluated_at, output)
    }

    fn replace_subject_incarnation(
        &mut self,
        logical_at: u64,
        subject: SubjectId,
        replacement: IncarnationId,
        mut activations: Vec<ConsumerActivationV1>,
        evaluated_at: u64,
        output: &mut RuntimeCycleOutputV1,
    ) -> Result<(), RuntimeError> {
        replacement
            .validate()
            .map_err(|_| RuntimeError::new("invalid_identity", "invalid subject incarnation"))?;
        let subject_state = self.subjects.get(&subject).ok_or_else(|| {
            RuntimeError::new("unknown_subject", "subject replacement target is unknown")
        })?;
        if !subject_state.subject_incarnations.contains(&replacement)
            && subject_state.subject_incarnations.len()
                >= self.config.bounds.maximum_subject_incarnations_per_subject
        {
            self.push_refusal(
                RuntimeRefusalClassV1::IncarnationHistoryCapacity,
                evaluated_at,
                Some(subject.clone()),
                None,
                u64::try_from(self.config.bounds.maximum_subject_incarnations_per_subject)
                    .unwrap_or(u64::MAX),
                u64::try_from(subject_state.subject_incarnations.len().saturating_add(1))
                    .unwrap_or(u64::MAX),
                "subject incarnation history bound is full",
                output,
            );
            self.latch_blind_subject(
                &subject,
                evaluated_at,
                "subject incarnation history capacity was exceeded",
            );
            return Ok(());
        }
        activations.sort_by(|left, right| left.policy.consumer.cmp(&right.policy.consumer));
        let expected = subject_state.consumers.iter().cloned().collect::<Vec<_>>();
        let supplied = activations
            .iter()
            .map(|activation| activation.policy.consumer.clone())
            .collect::<Vec<_>>();
        if expected != supplied || supplied.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(RuntimeError::new(
                "incomplete_subject_transition",
                "subject replacement must activate every registered consumer exactly once",
            ));
        }
        for activation in &activations {
            self.validate_activation(activation)?;
            if activation.policy.subject != subject {
                return Err(RuntimeError::new(
                    "subject_mismatch",
                    "subject replacement activation names another subject",
                ));
            }
        }
        self.receiver
            .activate_subject_incarnation(&subject, replacement.clone())
            .map_err(|error| RuntimeError::new("receiver_refusal", error.to_string()))?;
        for activation in activations {
            let key = ConsumerKey::new(subject.clone(), activation.policy.consumer.clone());
            let mut state = self.consumers.remove(&key).expect("consumer exists");
            let prior_context = state.context.clone();
            let subject_barrier = state
                .evaluator
                .replace_subject_incarnation(replacement.clone(), evaluated_at)
                .map_err(RuntimeError::from_evaluator)?;
            self.consumers.insert(key.clone(), state);
            self.cancel_schedule(&key);
            self.apply_evaluation(&key, subject_barrier, evaluated_at, output)?;
            self.activate_consumer(logical_at, activation, evaluated_at, output)?;
            output.trace_lines.push(format!(
                "[{evaluated_at:06}ms] SUBJECT consumer={} prior_activation={} replacement={} standing_inherited=false",
                key.consumer, prior_context.activation_id, replacement
            ));
        }
        self.subjects
            .get_mut(&subject)
            .expect("subject exists")
            .subject_incarnations
            .insert(replacement);
        Ok(())
    }

    fn apply_evaluation(
        &mut self,
        key: &ConsumerKey,
        evaluation: EvaluationOutput,
        evaluated_at: u64,
        output: &mut RuntimeCycleOutputV1,
    ) -> Result<(), RuntimeError> {
        let prior_runtime_current = self
            .consumers
            .get(key)
            .and_then(|state| state.certificate.as_ref())
            .is_some_and(|certificate| certificate.judgment == JudgmentCategoryV1::Current);
        for event in evaluation.sparse_events {
            self.record_sparse(event.at_monotonic_ms, event.event, output);
        }
        if let Some(request) = evaluation.escalation_request {
            if !prior_runtime_current {
                output.trace_lines.push(format!(
                    "[{evaluated_at:06}ms] ESCALATION_SUPPRESSED consumer={} reason=no_prior_runtime_supported_current",
                    key.consumer
                ));
            } else if self.request_owners.len() >= self.config.bounds.maximum_active_escalations {
                self.push_refusal(
                    RuntimeRefusalClassV1::EscalationCapacity,
                    evaluated_at,
                    Some(key.subject.clone()),
                    Some(key.consumer.clone()),
                    u64::try_from(self.config.bounds.maximum_active_escalations)
                        .unwrap_or(u64::MAX),
                    u64::try_from(self.request_owners.len().saturating_add(1)).unwrap_or(u64::MAX),
                    "active escalation request bound is full; request was not dispatched",
                    output,
                );
            } else {
                self.request_owners.insert(
                    request.request_id.clone(),
                    (key.clone(), request.expires_at_monotonic_ms),
                );
                output.escalation_requests.push(request);
            }
        }
        self.account_due_schedule_before_cancellation(key, evaluated_at);
        self.cancel_schedule(key);
        let mut state = self.consumers.remove(key).ok_or_else(|| {
            RuntimeError::new("unknown_consumer", "evaluation consumer disappeared")
        })?;
        let mut evidence = state.evaluator.supporting_evidence_refs(evaluated_at);
        evidence.sort();
        evidence.dedup();
        let mut contradictions = state.evaluator.active_contradiction_ids();
        contradictions.sort();
        contradictions.dedup();
        let evidence_set = evidence.iter().collect::<BTreeSet<_>>();
        let mut remote_observation_custody = self
            .remote_observation_custody
            .values()
            .filter(|custody| {
                custody.subject_scope == evaluation.judgment.subject_scope
                    && evidence_set.contains(&custody.supporting_evidence_id)
            })
            .cloned()
            .collect::<Vec<_>>();
        remote_observation_custody.sort_by_key(|custody| custody.identity_digest());
        remote_observation_custody.dedup_by_key(|custody| custody.identity_digest());
        if evidence.len() > self.config.bounds.maximum_supporting_evidence_refs
            || contradictions.len() > pulse_types::MAX_CERTIFICATE_CONTRADICTIONS
        {
            state.certificate = None;
            self.consumers.insert(key.clone(), state);
            self.push_refusal(
                RuntimeRefusalClassV1::CertificateCapacity,
                evaluated_at,
                Some(key.subject.clone()),
                Some(key.consumer.clone()),
                u64::try_from(self.config.bounds.maximum_supporting_evidence_refs)
                    .unwrap_or(u64::MAX),
                u64::try_from(evidence.len().max(contradictions.len())).unwrap_or(u64::MAX),
                "support certificate references exceed their exact bound; no positive certificate was issued",
                output,
            );
            return Ok(());
        }
        let evaluator_requested_current =
            evaluation.judgment.category == JudgmentCategoryV1::Current;
        let qualified_generation = if evaluator_requested_current {
            self.revalidated_qualified_binding(key, &state, evaluated_at, output)?
        } else {
            self.descriptive_qualified_binding(key, &state)
        };
        let judgment = if evaluator_requested_current && qualified_generation.is_none() {
            JudgmentCategoryV1::Unknown
        } else {
            evaluation.judgment.category
        };
        // An evaluator can truthfully retain a nonblocking caution (for
        // example, unverified provenance when this exact policy does not
        // require verification) while still satisfying every named premise.
        // Such cautions remain in the judgment explanation; they are not
        // mislabeled as missing certificate premises.
        let mut missing = if judgment == JudgmentCategoryV1::Current {
            Vec::new()
        } else {
            evaluation
                .judgment
                .explanation
                .reasons
                .iter()
                .filter(|reason| reason.code != "named_reliance_conditions_satisfied")
                .map(|reason| reason.code.clone())
                .collect::<Vec<_>>()
        };
        if evaluator_requested_current && qualified_generation.is_none() {
            let binding_state = self
                .qualified_bindings
                .get(key)
                .map_or(RuntimeBindingStateV1::Unbound, |slot| slot.state);
            missing.push(format!("qualified_generation_binding:{binding_state:?}"));
        }
        missing.extend(
            evaluation
                .judgment
                .coverage
                .missing
                .iter()
                .map(|tag| format!("coverage:{tag}")),
        );
        missing.sort();
        missing.dedup();
        let deadline = if judgment == JudgmentCategoryV1::Current {
            evaluation.judgment.positive_support_expires_at_monotonic_ms
        } else {
            None
        };
        let mut certificate = RelianceSupportCertificateV1 {
            schema_version: SCHEMA_VERSION_V1,
            certificate_id: pulse_types::SupportCertificateId::new("pending"),
            consumer: key.consumer.clone(),
            subject_scope: evaluation.judgment.subject_scope.clone(),
            context: state.context.clone(),
            qualified_generation,
            evaluated_at_monotonic_ms: evaluated_at,
            receiver_clock_id: self.config.clock_id.to_string(),
            judgment,
            evidence_window_id: evaluation.judgment.evidence_window_id.clone(),
            supporting_evidence_ids: evidence,
            remote_observation_custody,
            missing_premises: missing,
            applicable_contradictions: contradictions,
            coverage: evaluation.judgment.coverage.clone(),
            earliest_support_expiry_monotonic_ms: deadline,
            next_scheduled_reevaluation_monotonic_ms: deadline,
            escalation: evaluation.judgment.escalation.clone(),
            mutation_authority: MutationAuthorityV1::None,
        };
        certificate.certificate_id = certificate.compute_id();
        certificate
            .validate()
            .map_err(|error| RuntimeError::new(error.code, error.detail))?;
        if let Some(deadline) = deadline {
            self.schedules.insert(ScheduleKey {
                deadline_monotonic_ms: deadline,
                subject: key.subject.clone(),
                consumer: key.consumer.clone(),
                activation_id: state.context.activation_id.clone(),
            });
            self.metrics.expected_support_expiry_monotonic_ms = Some(deadline);
        }
        let changed = state.certificate.as_ref() != Some(&certificate);
        state.certificate = Some(certificate.clone());
        self.consumers.insert(key.clone(), state);
        output.certificates.push(certificate.clone());
        if changed {
            self.record_sparse(
                evaluated_at,
                SparseDurableEventKindV1::SupportCertificateIssued {
                    certificate: Box::new(certificate.clone()),
                },
                output,
            );
        }
        output.trace_lines.push(format!(
            "[{evaluated_at:06}ms] CERTIFICATE consumer={} activation={} judgment={} support_expires={} standing_inherited=false",
            key.consumer,
            certificate.context.activation_id,
            certificate.judgment,
            certificate
                .earliest_support_expiry_monotonic_ms
                .map_or_else(|| "none".to_owned(), |value| format!("{value}ms")),
        ));
        self.metrics.duplicate_escalation_count = self
            .consumers
            .values()
            .map(|consumer| consumer.evaluator.metrics().escalation_deduplication_count)
            .sum();
        Ok(())
    }

    fn descriptive_qualified_binding(
        &self,
        key: &ConsumerKey,
        state: &ConsumerState,
    ) -> Option<QualifiedGenerationBindingV1> {
        let slot = self.qualified_bindings.get(key)?;
        if slot.state != RuntimeBindingStateV1::QualifiedAndMatched {
            return None;
        }
        let accepted = slot.accepted.as_ref()?;
        let binding = accepted.binding();
        if binding.generation_set.subject != key.subject
            || binding.generation_set.consumer != key.consumer
            || !binding.generation_set.matches_context(&state.context)
        {
            return None;
        }
        Some(binding.clone())
    }

    fn invalidate_binding_for_context_change(
        &mut self,
        key: &ConsumerKey,
        context: &RelianceContextV1,
        evaluated_at: u64,
        output: &mut RuntimeCycleOutputV1,
    ) {
        let invalidation = self.qualified_bindings.get(key).and_then(|slot| {
            slot.accepted.as_ref().and_then(|accepted| {
                (!accepted.binding().generation_set.matches_context(context)).then(|| {
                    (
                        accepted.receipt().receipt_digest.clone(),
                        "reliance context changed without a matching fresh qualified activation"
                            .to_owned(),
                    )
                })
            })
        });
        if let Some((prior_receipt, detail)) = invalidation {
            if let Some(slot) = self.qualified_bindings.get_mut(key) {
                slot.state = RuntimeBindingStateV1::Unbound;
                slot.accepted = None;
            }
            self.record_sparse(
                evaluated_at,
                SparseDurableEventKindV1::QualifiedGenerationBindingInvalidated {
                    consumer: key.consumer.clone(),
                    prior_activation_receipt_digest: prior_receipt,
                    state: RuntimeBindingStateV1::Unbound,
                    detail: detail.clone(),
                    standing_preserved: false,
                },
                output,
            );
            output.trace_lines.push(format!(
                "[{evaluated_at:06}ms] BINDING_INVALIDATED consumer={} state=Unbound detail={detail}",
                key.consumer
            ));
        }
    }

    fn revalidated_qualified_binding(
        &mut self,
        key: &ConsumerKey,
        state: &ConsumerState,
        evaluated_at: u64,
        output: &mut RuntimeCycleOutputV1,
    ) -> Result<Option<QualifiedGenerationBindingV1>, RuntimeError> {
        let registration = ConsumerRegistrationV1 {
            policy: state.evaluator.policy().clone(),
            context: state.context.clone(),
            subject_incarnation: state.evaluator.current_subject_incarnation().clone(),
        };
        let observed = active_runtime_measurements(&self.config, &registration)
            .map_err(|error| RuntimeError::new(error.code, error.detail))?;
        let mut invalidation = None;
        let binding = if let Some(slot) = self.qualified_bindings.get_mut(key) {
            if slot.state != RuntimeBindingStateV1::QualifiedAndMatched {
                None
            } else if let Some(accepted) = slot.accepted.as_mut() {
                let generation_matches = accepted.binding().generation_set.subject == key.subject
                    && accepted.binding().generation_set.consumer == key.consumer
                    && accepted
                        .binding()
                        .generation_set
                        .matches_context(&state.context);
                if !generation_matches {
                    invalidation = Some((
                        RuntimeBindingStateV1::Ambiguous,
                        "active qualified generation does not match the evaluator context"
                            .to_owned(),
                        accepted.receipt().receipt_digest.clone(),
                    ));
                    None
                } else if let Err(error) = accepted.revalidate_executable() {
                    invalidation = Some((
                        RuntimeBindingStateV1::MutableAfterActivation,
                        error.to_string(),
                        accepted.receipt().receipt_digest.clone(),
                    ));
                    None
                } else {
                    let mismatch = observed.iter().find(|observed_measurement| {
                        accepted
                            .measurements()
                            .iter()
                            .find(|qualified| qualified.role == observed_measurement.role)
                            .is_none_or(|qualified| {
                                qualified.content_digest != observed_measurement.content_digest
                                    || qualified.byte_length != observed_measurement.byte_length
                                    || qualified.caller_supplied
                            })
                    });
                    if let Some(mismatch) = mismatch {
                        invalidation = Some((
                            mismatch.role.mismatch_state(),
                            format!(
                                "owned active artifact {:?} changed after qualification activation",
                                mismatch.role
                            ),
                            accepted.receipt().receipt_digest.clone(),
                        ));
                        None
                    } else {
                        Some(accepted.binding().clone())
                    }
                }
            } else {
                None
            }
        } else {
            None
        };
        if let Some((binding_state, detail, prior_receipt)) = invalidation {
            if let Some(slot) = self.qualified_bindings.get_mut(key) {
                slot.state = binding_state;
                slot.accepted = None;
            }
            self.cancel_schedule(key);
            self.record_sparse(
                evaluated_at,
                SparseDurableEventKindV1::QualifiedGenerationBindingInvalidated {
                    consumer: key.consumer.clone(),
                    prior_activation_receipt_digest: prior_receipt,
                    state: binding_state,
                    detail: detail.clone(),
                    standing_preserved: false,
                },
                output,
            );
            output.trace_lines.push(format!(
                "[{evaluated_at:06}ms] BINDING_INVALIDATED consumer={} state={binding_state:?} detail={detail}",
                key.consumer
            ));
        }
        Ok(binding)
    }

    fn validate_registration(
        &self,
        registration: &ConsumerRegistrationV1,
    ) -> Result<(), RuntimeError> {
        registration
            .policy
            .validate()
            .map_err(|error| RuntimeError::new("invalid_policy", error.to_string()))?;
        registration
            .subject_incarnation
            .validate()
            .map_err(|_| RuntimeError::new("invalid_identity", "invalid subject incarnation"))?;
        validate_policy_context(&registration.policy, &registration.context)
    }

    fn validate_activation(&self, activation: &ConsumerActivationV1) -> Result<(), RuntimeError> {
        activation
            .policy
            .validate()
            .map_err(|error| RuntimeError::new("invalid_policy", error.to_string()))?;
        validate_policy_context(&activation.policy, &activation.context)
    }

    fn ensure_time_not_regressed(&mut self, at: u64) -> Result<(), RuntimeError> {
        if at < self.current_monotonic_ms {
            self.latch_blind_all(
                self.current_monotonic_ms,
                "runtime management time regressed within one clock generation",
            );
            return Err(RuntimeError::new(
                "clock_regression",
                "runtime operation time regressed",
            ));
        }
        self.current_monotonic_ms = at;
        Ok(())
    }

    fn consumer_keys(&self, subject: Option<&SubjectId>) -> Vec<ConsumerKey> {
        self.consumers
            .keys()
            .filter(|key| subject.is_none_or(|subject| &key.subject == subject))
            .cloned()
            .collect()
    }

    fn cancel_schedule(&mut self, key: &ConsumerKey) {
        self.schedules.retain(|schedule| {
            schedule.subject != key.subject || schedule.consumer != key.consumer
        });
    }

    fn account_due_schedule_before_cancellation(&mut self, key: &ConsumerKey, evaluated_at: u64) {
        let due = self
            .schedules
            .iter()
            .filter(|schedule| {
                schedule.subject == key.subject
                    && schedule.consumer == key.consumer
                    && schedule.deadline_monotonic_ms <= evaluated_at
            })
            .map(|schedule| schedule.deadline_monotonic_ms)
            .min();
        if let Some(deadline) = due {
            let overshoot = evaluated_at.saturating_sub(deadline);
            self.metrics.expected_support_expiry_monotonic_ms = Some(deadline);
            self.metrics.actual_reevaluation_monotonic_ms = Some(evaluated_at);
            self.metrics.scheduler_lateness_ms = self.metrics.scheduler_lateness_ms.max(overshoot);
            self.metrics.maximum_stale_positive_duration_ms = self
                .metrics
                .maximum_stale_positive_duration_ms
                .max(overshoot);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn record_context_transition(
        &mut self,
        key: &ConsumerKey,
        prior_context: Option<RelianceContextV1>,
        new_context: RelianceContextV1,
        cause: GenerationTransitionCauseV1,
        subject_incarnation: IncarnationId,
        at: u64,
        output: &mut RuntimeCycleOutputV1,
    ) {
        self.record_sparse(
            at,
            SparseDurableEventKindV1::RelianceContextTransition {
                transition: Box::new(RelianceContextTransitionV1 {
                    schema_version: SCHEMA_VERSION_V1,
                    subject_scope: SubjectScopeV1 {
                        subject: key.subject.clone(),
                        subject_incarnation,
                        scope: self.consumers.get(key).map_or_else(
                            || "unknown".to_owned(),
                            |state| state.evaluator.policy().scope.clone(),
                        ),
                    },
                    consumer: key.consumer.clone(),
                    prior_context,
                    new_context,
                    cause,
                    at_monotonic_ms: at,
                    standing_inherited: false,
                }),
            },
            output,
        );
    }

    fn record_sparse(
        &mut self,
        at: u64,
        event: SparseDurableEventKindV1,
        output: &mut RuntimeCycleOutputV1,
    ) {
        if self.sparse_history.len() >= self.config.bounds.maximum_sparse_events {
            self.history_exhausted = true;
            self.metrics.sparse_history_refusal_count =
                self.metrics.sparse_history_refusal_count.saturating_add(1);
            if !self.history_exhaustion_reported {
                self.history_exhaustion_reported = true;
                let refusal = self.refusal(
                    RuntimeRefusalClassV1::SparseHistoryCapacity,
                    at,
                    None,
                    None,
                    u64::try_from(self.config.bounds.maximum_sparse_events).unwrap_or(u64::MAX),
                    u64::try_from(self.sparse_history.len().saturating_add(1))
                        .unwrap_or(u64::MAX),
                    "sparse historical custody capacity is exhausted; the event was refused and monitor blindness latched",
                );
                output.trace_lines.push(format!(
                    "[{at:06}ms] REFUSAL class={:?} detail={}",
                    refusal.class, refusal.detail
                ));
                output.refusals.push(refusal);
            }
            return;
        }
        self.event_counter = self.event_counter.saturating_add(1);
        let event_lineage = digest_parts(
            "runtime.event-lineage.v1",
            &[
                self.config.receiver_incarnation.as_str().as_bytes(),
                self.config.clock_id.as_str().as_bytes(),
            ],
        );
        let record = SparseDurableEventV1 {
            schema_version: SCHEMA_VERSION_V1,
            event_id: SparseEventId::new(format!(
                "runtime-event:{}:{:016x}",
                event_lineage.as_str().trim_start_matches("sha256:"),
                self.event_counter
            )),
            at_monotonic_ms: at,
            event,
        };
        self.sparse_history.push(record.clone());
        output.sparse_events.push(record);
    }

    #[allow(clippy::too_many_arguments)]
    fn push_refusal(
        &mut self,
        class: RuntimeRefusalClassV1,
        at: u64,
        subject: Option<SubjectId>,
        consumer: Option<ConsumerId>,
        configured_bound: u64,
        observed_count: u64,
        detail: &str,
        output: &mut RuntimeCycleOutputV1,
    ) {
        let refusal = self.refusal(
            class,
            at,
            subject,
            consumer,
            configured_bound,
            observed_count,
            detail,
        );
        self.record_sparse(
            at,
            SparseDurableEventKindV1::RuntimeRefusal {
                refusal: Box::new(refusal.clone()),
            },
            output,
        );
        output.trace_lines.push(format!(
            "[{at:06}ms] REFUSAL class={:?} detail={}",
            refusal.class, refusal.detail
        ));
        output.refusals.push(refusal);
    }

    fn stage_refusal(&mut self, refusal: RuntimeRefusalV1) {
        let at = refusal.at_monotonic_ms;
        let mut output = RuntimeCycleOutputV1::default();
        self.record_sparse(
            at,
            SparseDurableEventKindV1::RuntimeRefusal {
                refusal: Box::new(refusal.clone()),
            },
            &mut output,
        );
        output.trace_lines.push(format!(
            "[{at:06}ms] REFUSAL class={:?} detail={}",
            refusal.class, refusal.detail
        ));
        output.refusals.push(refusal);
        self.pending_output.append(output);
    }

    #[allow(clippy::too_many_arguments)]
    fn refusal(
        &mut self,
        class: RuntimeRefusalClassV1,
        at: u64,
        subject: Option<SubjectId>,
        consumer: Option<ConsumerId>,
        configured_bound: u64,
        observed_count: u64,
        detail: &str,
    ) -> RuntimeRefusalV1 {
        self.refusal_counter = self.refusal_counter.saturating_add(1);
        RuntimeRefusalV1 {
            schema_version: SCHEMA_VERSION_V1,
            refusal_id: RuntimeRefusalId::new(format!(
                "runtime-refusal:{:016x}",
                self.refusal_counter
            )),
            class,
            at_monotonic_ms: at,
            subject,
            consumer,
            configured_bound,
            observed_count,
            detail: detail.to_owned(),
            current_preserved: false,
            mutation_authority: MutationAuthorityV1::None,
        }
    }

    fn latch_blind_all(&mut self, at: u64, detail: &str) {
        let keys = self.consumer_keys(None);
        for key in keys {
            self.latch_blind_consumer(&key, at, detail);
        }
    }

    fn latch_history_blindness(&mut self, at: u64) {
        if self.history_blindness_latched {
            return;
        }
        self.history_blindness_latched = true;
        self.latch_blind_all(at, "sparse historical custody capacity is exhausted");
    }

    fn latch_blind_subject(&mut self, subject: &SubjectId, at: u64, detail: &str) {
        let keys = self.consumer_keys(Some(subject));
        for key in keys {
            self.latch_blind_consumer(&key, at, detail);
        }
    }

    fn latch_blind_consumer(&mut self, key: &ConsumerKey, at: u64, detail: &str) {
        let Some(mut state) = self.consumers.remove(key) else {
            return;
        };
        let evaluation = state.evaluator.record_monitor_input_drop(1, at, detail);
        self.consumers.insert(key.clone(), state);
        if let Ok(evaluation) = evaluation {
            let mut output = RuntimeCycleOutputV1::default();
            if self
                .apply_evaluation(
                    key,
                    evaluation,
                    at.max(self.current_monotonic_ms),
                    &mut output,
                )
                .is_ok()
            {
                self.pending_output.append(output);
            }
        }
    }
}

fn validate_policy_context(
    policy: &ReliancePolicyV1,
    context: &RelianceContextV1,
) -> Result<(), RuntimeError> {
    context
        .validate()
        .map_err(|error| RuntimeError::new(error.code, error.detail))?;
    if context.reliance_policy_generation != policy.generation
        || context.reliance_policy_semantic_digest != policy.semantic_digest()
        || context.observation_policy_generation != policy.observation_policy_generation
    {
        return Err(RuntimeError::new(
            "context_binding_mismatch",
            "reliance context does not exactly bind the policy generation, body, and admitted observation generation",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeError {
    pub code: &'static str,
    pub detail: String,
}

impl RuntimeError {
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    fn from_evaluator(error: pulse_evaluator::EvaluatorError) -> Self {
        Self::new(error.code, error.detail)
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for RuntimeError {}

#[must_use]
pub fn policy_body_equality_marker(
    left: &ReliancePolicyV1,
    right: &ReliancePolicyV1,
) -> pulse_types::DigestV1 {
    digest_parts(
        "runtime.policy-body-equality.v1",
        &[
            left.semantic_digest().as_str().as_bytes(),
            right.semantic_digest().as_str().as_bytes(),
        ],
    )
}
pub use binding::{
    CanonicalEscalationPolicyV1, CanonicalFailureDomainV1, CanonicalReliancePolicyArtifactV1,
    CanonicalToleranceV1, ConsumerProfileArtifactV1, EvaluatorImplementationArtifactV1,
    LocalQualificationInputsV1, LocalQualificationPackageV1, ObservationPolicyArtifactV1,
    ObserverSetArtifactV1, QualificationCorpusArtifactV1, QualificationResultsArtifactV1,
    RuntimeArtifactPayloadV1, RuntimeConfigurationArtifactV1, SemanticContractsArtifactV1,
    active_runtime_artifact_payloads, active_runtime_measurements,
    build_local_qualification_package, package_artifact_digests, qualification_fixture_inputs,
    runtime_semantic_contracts,
};
