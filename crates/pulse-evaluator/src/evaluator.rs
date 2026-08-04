use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use pulse_types::{
    ArrivalDispositionV1, AuthenticationResultV1, ConfidenceDimensionsV1, ContradictionId,
    ContradictionRecordV1, ContradictionStatusV1, CoverageCountV1, CoverageDimensionV1,
    CoverageSummaryV1, CrossObserverCoherenceDimensionV1, DiagnosticEscalationRequestV1,
    DiagnosticEvidenceReferenceV1, DigestV1, ESCALATION_NONCLAIMS, EscalationDispositionKindV1,
    EscalationDispositionV1, EscalationRequestId, EscalationStateV1, EscalationTriggerClassV1,
    EvidenceWindowId, ExperimentalMetricsV1, FreshnessDimensionV1, INCOMPLETE_COVERAGE_EXPLANATION,
    IncarnationId, JudgmentCategoryV1, JudgmentExplanationV1, JudgmentReasonV1,
    JudgmentTransitionV1, MockDiagnosticReceiptV1, MutationAuthorityV1, NO_MUTATION_NONCLAIM,
    ObserverAvailabilityDimensionV1, ObserverId, PresentStateJudgmentV1, ProvenanceDimensionV1,
    PulseFrameV1, ReceivedPulseV1, SCHEMA_VERSION_V1, SequenceContinuityDimensionV1,
    SignalAssessmentV1, SparseDurableEventKindV1, SparseDurableEventV1, SparseEventId,
    SubjectScopeV1, SubjectSignalConsistencyDimensionV1, TransitionId, TransportDimensionV1,
    digest_parts,
};
use serde::{Deserialize, Serialize};

use crate::{PolicyError, ReliancePolicyV1};

const JUDGMENT_NONCLAIMS: [&str; 7] = [
    "Pulse receipt does not establish subject health.",
    "The runtime does not establish that observations are truthful.",
    "The runtime does not establish complete distributed-world coverage.",
    "Observer identity does not establish observer independence.",
    "A present-state judgment is consumer-, policy-, coverage-, and time-indexed.",
    "Diagnostic completion does not establish indefinite reliance.",
    NO_MUTATION_NONCLAIM,
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum MonitorCapabilityV1 {
    Operational,
    Degraded { detail: String },
    Blind { detail: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReevaluationBarrierV1 {
    GenerationTransition { detail: String },
    QualifiedGenerationBinding { detail: String },
    SubjectIncarnationTransition { detail: String },
    ReceiverRestart { detail: String },
    MonitorCapabilityRestored { detail: String },
}

impl ReevaluationBarrierV1 {
    const fn code(&self) -> &'static str {
        match self {
            Self::GenerationTransition { .. } => "generation_transition_requires_reevaluation",
            Self::QualifiedGenerationBinding { .. } => {
                "qualified_generation_binding_requires_reevaluation"
            }
            Self::SubjectIncarnationTransition { .. } => {
                "subject_incarnation_transition_requires_reevaluation"
            }
            Self::ReceiverRestart { .. } => "receiver_restart_requires_reevaluation",
            Self::MonitorCapabilityRestored { .. } => {
                "monitor_capability_restored_requires_reevaluation"
            }
        }
    }

    fn detail(&self) -> &str {
        match self {
            Self::GenerationTransition { detail }
            | Self::QualifiedGenerationBinding { detail }
            | Self::SubjectIncarnationTransition { detail }
            | Self::ReceiverRestart { detail }
            | Self::MonitorCapabilityRestored { detail } => detail,
        }
    }
}

#[derive(Clone, Debug)]
struct ObserverEvidence {
    received: ReceivedPulseV1,
    expires_at_ms: u64,
    continuity: SequenceContinuityDimensionV1,
}

#[derive(Clone, Debug)]
struct ObserverLineage {
    incarnation: IncarnationId,
    sequence: u64,
}

#[derive(Clone, Debug)]
struct ActiveEscalation {
    request_id: EscalationRequestId,
    expires_at_ms: u64,
}

#[derive(Clone, Debug)]
pub struct EvaluationOutput {
    pub judgment: PresentStateJudgmentV1,
    pub transition: Option<JudgmentTransitionV1>,
    pub escalation_request: Option<DiagnosticEscalationRequestV1>,
    pub sparse_events: Vec<SparseDurableEventV1>,
}

#[derive(Clone, Debug)]
pub struct ContradictionResolutionV1 {
    pub resolver: String,
    pub rule: String,
    pub explanation: String,
}

/// Purely in-memory deterministic evaluator for one policy/consumer.
pub struct Evaluator {
    policy: ReliancePolicyV1,
    receiver: pulse_types::ReceiverId,
    receiver_incarnation: IncarnationId,
    clock_id: pulse_types::ClockId,
    current_subject_incarnation: IncarnationId,
    retired_subject_incarnations: BTreeSet<IncarnationId>,
    observer_lineages: BTreeMap<ObserverId, ObserverLineage>,
    retired_observer_incarnations: BTreeSet<(ObserverId, IncarnationId)>,
    observers: BTreeMap<ObserverId, ObserverEvidence>,
    contradictions: BTreeMap<ContradictionId, ContradictionRecordV1>,
    diagnostic_evidence: Vec<DiagnosticEvidenceReferenceV1>,
    issued_requests: BTreeMap<EscalationRequestId, DiagnosticEscalationRequestV1>,
    active_escalations: BTreeMap<DigestV1, ActiveEscalation>,
    monitor_capability: MonitorCapabilityV1,
    escalation_state: EscalationStateV1,
    reevaluation_barrier: Option<ReevaluationBarrierV1>,
    last_judgment: Option<PresentStateJudgmentV1>,
    last_positive_support_deadline_ms: Option<u64>,
    last_receiver_arrival_ms: Option<u64>,
    last_evaluation_ms: Option<u64>,
    transition_counter: u64,
    request_counter: u64,
    event_counter: u64,
    metrics: ExperimentalMetricsV1,
    fault_started_at_ms: Option<u64>,
    normal_trace: bool,
    event_log: Vec<SparseDurableEventV1>,
}

impl Evaluator {
    pub fn new(
        policy: ReliancePolicyV1,
        receiver: pulse_types::ReceiverId,
        receiver_incarnation: IncarnationId,
        clock_id: pulse_types::ClockId,
        initial_subject_incarnation: IncarnationId,
    ) -> Result<Self, EvaluatorError> {
        policy.validate().map_err(EvaluatorError::from_policy)?;
        receiver
            .validate()
            .map_err(|_| EvaluatorError::new("invalid_receiver", "invalid receiver identity"))?;
        receiver_incarnation
            .validate()
            .map_err(|_| EvaluatorError::new("invalid_receiver", "invalid receiver incarnation"))?;
        clock_id
            .validate()
            .map_err(|_| EvaluatorError::new("invalid_clock", "invalid receiver clock identity"))?;
        initial_subject_incarnation
            .validate()
            .map_err(|_| EvaluatorError::new("invalid_subject", "invalid subject incarnation"))?;
        Ok(Self {
            policy,
            receiver,
            receiver_incarnation,
            clock_id,
            current_subject_incarnation: initial_subject_incarnation,
            retired_subject_incarnations: BTreeSet::new(),
            observer_lineages: BTreeMap::new(),
            retired_observer_incarnations: BTreeSet::new(),
            observers: BTreeMap::new(),
            contradictions: BTreeMap::new(),
            diagnostic_evidence: Vec::new(),
            issued_requests: BTreeMap::new(),
            active_escalations: BTreeMap::new(),
            monitor_capability: MonitorCapabilityV1::Operational,
            escalation_state: EscalationStateV1::NotRequested,
            reevaluation_barrier: None,
            last_judgment: None,
            last_positive_support_deadline_ms: None,
            last_receiver_arrival_ms: None,
            last_evaluation_ms: None,
            transition_counter: 0,
            request_counter: 0,
            event_counter: 0,
            metrics: ExperimentalMetricsV1::empty(),
            fault_started_at_ms: None,
            normal_trace: false,
            event_log: Vec::new(),
        })
    }

    #[must_use]
    pub const fn policy(&self) -> &ReliancePolicyV1 {
        &self.policy
    }

    #[must_use]
    pub const fn metrics(&self) -> &ExperimentalMetricsV1 {
        &self.metrics
    }

    #[must_use]
    pub fn contradictions(&self) -> Vec<&ContradictionRecordV1> {
        self.contradictions.values().collect()
    }

    #[must_use]
    pub fn event_log(&self) -> &[SparseDurableEventV1] {
        &self.event_log
    }

    #[must_use]
    pub const fn current_subject_incarnation(&self) -> &IncarnationId {
        &self.current_subject_incarnation
    }

    #[must_use]
    pub fn active_contradiction_ids(&self) -> Vec<ContradictionId> {
        self.contradictions
            .values()
            .filter(|record| record.is_active())
            .map(|record| record.contradiction_id.clone())
            .collect()
    }

    #[must_use]
    pub fn supporting_evidence_refs(&self, now_monotonic_ms: u64) -> Vec<String> {
        self.observers
            .values()
            .filter(|evidence| {
                evidence.received.frame.subject_incarnation == self.current_subject_incarnation
                    && now_monotonic_ms < evidence.expires_at_ms
                    && self.provenance_is_eligible(evidence)
            })
            .map(|evidence| evidence_ref(&evidence.received.frame))
            .collect()
    }

    /// Replace the exact consumer policy and install a non-inheriting barrier.
    /// Existing compatible hot evidence may be reconsidered only by a later
    /// explicit evaluation. Active contradictions remain in custody.
    pub fn replace_policy(
        &mut self,
        policy: ReliancePolicyV1,
        barrier: ReevaluationBarrierV1,
        at_monotonic_ms: u64,
    ) -> Result<EvaluationOutput, EvaluatorError> {
        policy.validate().map_err(EvaluatorError::from_policy)?;
        if policy.subject != self.policy.subject
            || policy.scope != self.policy.scope
            || policy.consumer != self.policy.consumer
        {
            return Err(EvaluatorError::new(
                "policy_binding_mismatch",
                "replacement policy changes evaluator subject, scope, or consumer",
            ));
        }
        if policy.observation_profile != self.policy.observation_profile
            || policy.observation_policy_generation != self.policy.observation_policy_generation
        {
            self.observers.clear();
            self.observer_lineages.clear();
            self.retired_observer_incarnations.clear();
        }
        self.policy = policy;
        self.escalation_state = EscalationStateV1::NotRequested;
        self.reevaluation_barrier = Some(barrier);
        self.evaluate(at_monotonic_ms)
    }

    /// Install a barrier when a non-policy member of the reliance context
    /// changes while keeping the policy body exact.
    pub fn install_reevaluation_barrier(
        &mut self,
        barrier: ReevaluationBarrierV1,
        at_monotonic_ms: u64,
    ) -> Result<EvaluationOutput, EvaluatorError> {
        self.escalation_state = EscalationStateV1::NotRequested;
        self.reevaluation_barrier = Some(barrier);
        self.evaluate(at_monotonic_ms)
    }

    /// Apply an explicitly configured subject replacement. Old-incarnation
    /// contradictions remain historical but become inapplicable under exactly
    /// one named rule. Merely receiving a disagreeing pulse does not call this.
    pub fn replace_subject_incarnation(
        &mut self,
        replacement: IncarnationId,
        at_monotonic_ms: u64,
    ) -> Result<EvaluationOutput, EvaluatorError> {
        replacement.validate().map_err(|_| {
            EvaluatorError::new("invalid_subject", "invalid replacement incarnation")
        })?;
        if replacement == self.current_subject_incarnation {
            return Err(EvaluatorError::new(
                "duplicate_subject_incarnation",
                "replacement incarnation is already active",
            ));
        }
        let prior = self.current_subject_incarnation.clone();
        let mut changed = Vec::new();
        for record in self.contradictions.values_mut().filter(|record| {
            record.is_active() && record.subject_scope.subject_incarnation == prior
        }) {
            record.status = ContradictionStatusV1::InapplicableBySubjectReplacement {
                prior_subject_incarnation: prior.clone(),
                replacement_subject_incarnation: replacement.clone(),
                at_monotonic_ms,
                rule: "subject_incarnation_replacement/v1".to_owned(),
            };
            changed.push(record.clone());
        }
        for contradiction in changed {
            self.sparse_event(
                at_monotonic_ms,
                SparseDurableEventKindV1::ContradictionLifecycleChanged {
                    contradiction: Box::new(contradiction),
                },
            );
        }
        self.retired_subject_incarnations.insert(prior.clone());
        self.current_subject_incarnation = replacement.clone();
        self.observers.clear();
        self.observer_lineages.clear();
        self.retired_observer_incarnations.clear();
        self.diagnostic_evidence.clear();
        self.escalation_state = EscalationStateV1::NotRequested;
        self.reevaluation_barrier = Some(ReevaluationBarrierV1::SubjectIncarnationTransition {
            detail: format!(
                "configured subject incarnation changed from {prior} to {replacement}; old standing and hot evidence were not inherited"
            ),
        });
        self.evaluate(at_monotonic_ms)
    }

    /// Restore contradiction custody only. This does not restore hot evidence,
    /// a prior judgment, escalation state, or a schedule.
    pub fn import_contradictions(
        &mut self,
        records: impl IntoIterator<Item = ContradictionRecordV1>,
    ) -> Result<(), EvaluatorError> {
        for record in records {
            if record.schema_version != SCHEMA_VERSION_V1
                || record.subject_scope.subject != self.policy.subject
            {
                return Err(EvaluatorError::new(
                    "invalid_contradiction_history",
                    "historical contradiction does not bind this evaluator subject",
                ));
            }
            if let Some(existing) = self.contradictions.get(&record.contradiction_id)
                && existing != &record
            {
                return Err(EvaluatorError::new(
                    "contradiction_identity_rebound",
                    "one contradiction identity names different historical content",
                ));
            }
            self.contradictions
                .insert(record.contradiction_id.clone(), record);
        }
        Ok(())
    }

    pub const fn set_normal_trace(&mut self, normal: bool) {
        self.normal_trace = normal;
    }

    pub const fn mark_failure_start(&mut self, at_monotonic_ms: u64) {
        self.fault_started_at_ms = Some(at_monotonic_ms);
    }

    pub fn ingest(
        &mut self,
        received: ReceivedPulseV1,
        evaluated_at_monotonic_ms: u64,
    ) -> Result<EvaluationOutput, EvaluatorError> {
        let event_log_start = self.event_log.len();
        received
            .validate()
            .map_err(|error| EvaluatorError::new("invalid_pulse", error.to_string()))?;
        self.validate_binding(&received)?;
        if evaluated_at_monotonic_ms < received.receiver.arrival_monotonic_ms {
            return Err(EvaluatorError::new(
                "evaluation_before_arrival",
                "evaluation time precedes receiver-observed arrival",
            ));
        }
        self.metrics.pulse_to_evaluation_latency_ms =
            evaluated_at_monotonic_ms.saturating_sub(received.receiver.arrival_monotonic_ms);

        if self
            .last_receiver_arrival_ms
            .is_some_and(|prior| received.receiver.arrival_monotonic_ms < prior)
        {
            self.monitor_capability = MonitorCapabilityV1::Blind {
                detail: "receiver monotonic arrival regressed within one clock generation"
                    .to_owned(),
            };
            self.monitor_event(
                evaluated_at_monotonic_ms,
                "blind",
                "receiver monotonic arrival regressed within one clock generation",
            );
            return self.evaluate_since(evaluated_at_monotonic_ms, event_log_start);
        }
        self.last_receiver_arrival_ms = Some(
            self.last_receiver_arrival_ms
                .map_or(received.receiver.arrival_monotonic_ms, |prior| {
                    prior.max(received.receiver.arrival_monotonic_ms)
                }),
        );

        let expected = self.classify_arrival(&received.frame, &received.receiver);
        if expected.0 != received.receiver.disposition
            || expected.1 != received.receiver.sequence_gap
        {
            let detail = format!(
                "receiver annotation mismatch: expected {:?}, received {:?}",
                expected.0, received.receiver.disposition
            );
            self.monitor_capability = MonitorCapabilityV1::Blind {
                detail: detail.clone(),
            };
            self.monitor_event(evaluated_at_monotonic_ms, "blind", &detail);
            return self.evaluate_since(evaluated_at_monotonic_ms, event_log_start);
        }

        match received.receiver.disposition {
            ArrivalDispositionV1::Duplicate => {
                self.metrics.duplicate_count = self.metrics.duplicate_count.saturating_add(1);
                return self.evaluate_since(evaluated_at_monotonic_ms, event_log_start);
            }
            ArrivalDispositionV1::Replay => {
                self.metrics.dropped_stale_pulse_count =
                    self.metrics.dropped_stale_pulse_count.saturating_add(1);
                return self.evaluate_since(evaluated_at_monotonic_ms, event_log_start);
            }
            ArrivalDispositionV1::Stale => {
                self.metrics.dropped_stale_pulse_count =
                    self.metrics.dropped_stale_pulse_count.saturating_add(1);
                return self.evaluate_since(evaluated_at_monotonic_ms, event_log_start);
            }
            ArrivalDispositionV1::Gap => {
                self.metrics.sequence_gap_count = self.metrics.sequence_gap_count.saturating_add(1);
            }
            ArrivalDispositionV1::First
            | ArrivalDispositionV1::Continuous
            | ArrivalDispositionV1::Restarted => {}
        }

        let effective_validity = received
            .frame
            .validity_ms
            .min(self.policy.maximum_validity_ms);
        let receiver_observed_delay = received.receiver.transport_observed_delay_ms.unwrap_or(0);
        if receiver_observed_delay >= effective_validity {
            // The receiver's sequence fact remains valid even when this
            // consumer's narrower freshness policy cannot use the occurrence.
            // Advancing the evaluator's receiver lineage keeps later receiver
            // annotations comparable without admitting this pulse as evidence.
            self.update_lineage(&received.frame, &received.receiver.disposition);
            self.metrics.dropped_stale_pulse_count =
                self.metrics.dropped_stale_pulse_count.saturating_add(1);
            return self.evaluate_since(evaluated_at_monotonic_ms, event_log_start);
        }

        if received.frame.subject_incarnation != self.current_subject_incarnation {
            if self
                .retired_subject_incarnations
                .contains(&received.frame.subject_incarnation)
            {
                self.metrics.dropped_stale_pulse_count =
                    self.metrics.dropped_stale_pulse_count.saturating_add(1);
                return self.evaluate_since(evaluated_at_monotonic_ms, event_log_start);
            }
            self.record_subject_incarnation_change(&received, evaluated_at_monotonic_ms);
        }

        self.update_lineage(&received.frame, &received.receiver.disposition);
        self.detect_signal_contradictions(&received, evaluated_at_monotonic_ms);
        self.record_adverse_supersession(&received, evaluated_at_monotonic_ms);
        let continuity = match received.receiver.disposition {
            ArrivalDispositionV1::Gap => SequenceContinuityDimensionV1::Gapped,
            ArrivalDispositionV1::Restarted => SequenceContinuityDimensionV1::Restarted,
            ArrivalDispositionV1::First => SequenceContinuityDimensionV1::FirstSeen,
            ArrivalDispositionV1::Continuous => SequenceContinuityDimensionV1::Continuous,
            ArrivalDispositionV1::Duplicate
            | ArrivalDispositionV1::Replay
            | ArrivalDispositionV1::Stale => unreachable!("returned before evidence update"),
        };
        let remaining_validity = effective_validity - receiver_observed_delay;
        let expires_at_ms = received
            .receiver
            .arrival_monotonic_ms
            .saturating_add(remaining_validity);
        self.observers.insert(
            received.frame.observer.clone(),
            ObserverEvidence {
                received,
                expires_at_ms,
                continuity,
            },
        );
        self.evaluate_since(evaluated_at_monotonic_ms, event_log_start)
    }

    pub fn tick(
        &mut self,
        evaluated_at_monotonic_ms: u64,
    ) -> Result<EvaluationOutput, EvaluatorError> {
        self.evaluate(evaluated_at_monotonic_ms)
    }

    pub fn set_monitor_capability(
        &mut self,
        state: MonitorCapabilityV1,
        at_monotonic_ms: u64,
    ) -> Result<EvaluationOutput, EvaluatorError> {
        let (label, detail) = match &state {
            MonitorCapabilityV1::Operational => (
                "operational",
                "monitor observation capability restored".to_owned(),
            ),
            MonitorCapabilityV1::Degraded { detail } => ("degraded", detail.clone()),
            MonitorCapabilityV1::Blind { detail } => ("blind", detail.clone()),
        };
        self.monitor_capability = state;
        let event = self.monitor_event(at_monotonic_ms, label, &detail);
        let mut output = self.evaluate(at_monotonic_ms)?;
        output.sparse_events.insert(0, event);
        Ok(output)
    }

    pub fn record_monitor_input_drop(
        &mut self,
        count: u64,
        at_monotonic_ms: u64,
        detail: impl Into<String>,
    ) -> Result<EvaluationOutput, EvaluatorError> {
        self.metrics.monitor_input_drop_count =
            self.metrics.monitor_input_drop_count.saturating_add(count);
        self.set_monitor_capability(
            MonitorCapabilityV1::Blind {
                detail: detail.into(),
            },
            at_monotonic_ms,
        )
    }

    /// Restore observation capability but retain a one-evaluation barrier so
    /// cached evidence cannot become CURRENT in the restoration operation.
    pub fn restore_monitor_capability(
        &mut self,
        at_monotonic_ms: u64,
        detail: impl Into<String>,
    ) -> Result<EvaluationOutput, EvaluatorError> {
        let detail = detail.into();
        self.monitor_capability = MonitorCapabilityV1::Operational;
        let event = self.monitor_event(at_monotonic_ms, "operational", &detail);
        self.reevaluation_barrier = Some(ReevaluationBarrierV1::MonitorCapabilityRestored {
            detail: format!(
                "monitor capability was explicitly restored ({detail}); a separate evaluation is required"
            ),
        });
        let mut output = self.evaluate(at_monotonic_ms)?;
        output.sparse_events.insert(0, event);
        Ok(output)
    }

    pub fn resolve_contradiction(
        &mut self,
        contradiction_id: &ContradictionId,
        resolution: ContradictionResolutionV1,
        at_monotonic_ms: u64,
    ) -> Result<EvaluationOutput, EvaluatorError> {
        if resolution.resolver.is_empty()
            || resolution.rule.is_empty()
            || resolution.explanation.is_empty()
        {
            return Err(EvaluatorError::new(
                "invalid_resolution",
                "resolution identity, rule, and explanation are required",
            ));
        }
        let changed = {
            let record = self
                .contradictions
                .get_mut(contradiction_id)
                .ok_or_else(|| {
                    EvaluatorError::new("unknown_contradiction", "contradiction does not exist")
                })?;
            if !record.is_active() {
                return Err(EvaluatorError::new(
                    "contradiction_not_active",
                    "only an active contradiction can be resolved",
                ));
            }
            record.status = ContradictionStatusV1::Resolved {
                resolver: resolution.resolver,
                resolved_at_monotonic_ms: at_monotonic_ms,
                rule: resolution.rule,
                explanation: resolution.explanation,
            };
            record.clone()
        };
        let event = self.sparse_event(
            at_monotonic_ms,
            SparseDurableEventKindV1::ContradictionLifecycleChanged {
                contradiction: Box::new(changed),
            },
        );
        let mut output = self.evaluate(at_monotonic_ms)?;
        output.sparse_events.insert(0, event);
        Ok(output)
    }

    pub fn record_escalation_disposition(
        &mut self,
        disposition: EscalationDispositionV1,
        evaluated_at_monotonic_ms: u64,
    ) -> Result<EvaluationOutput, EvaluatorError> {
        if disposition.schema_version != SCHEMA_VERSION_V1
            || disposition.bridge_id.as_str().is_empty()
            || disposition.clock_id != self.clock_id
        {
            return Err(EvaluatorError::new(
                "invalid_disposition",
                "disposition schema, bridge, or clock binding is invalid",
            ));
        }
        if !self.issued_requests.contains_key(&disposition.request_id) {
            return Err(EvaluatorError::new(
                "unknown_request",
                "disposition references an unknown request",
            ));
        }
        if evaluated_at_monotonic_ms < disposition.decided_at_monotonic_ms {
            return Err(EvaluatorError::new(
                "evaluation_before_disposition",
                "evaluation time precedes the bridge disposition occurrence",
            ));
        }
        self.escalation_state = match &disposition.kind {
            EscalationDispositionKindV1::Accept { .. } => EscalationStateV1::Accepted {
                request_id: disposition.request_id.to_string(),
            },
            EscalationDispositionKindV1::Refuse { detail, .. } => EscalationStateV1::Refused {
                request_id: disposition.request_id.to_string(),
                reason: detail.clone(),
            },
            EscalationDispositionKindV1::Narrow { .. } => EscalationStateV1::Narrowed {
                request_id: disposition.request_id.to_string(),
            },
            EscalationDispositionKindV1::Defer { .. } => EscalationStateV1::Deferred {
                request_id: disposition.request_id.to_string(),
            },
        };
        let at = disposition.decided_at_monotonic_ms;
        let event = self.sparse_event(
            at,
            SparseDurableEventKindV1::EscalationDisposition {
                disposition: disposition.clone(),
            },
        );
        let mut output = self.evaluate(evaluated_at_monotonic_ms)?;
        output.sparse_events.insert(0, event);
        Ok(output)
    }

    pub fn record_diagnostic_receipt(
        &mut self,
        receipt: MockDiagnosticReceiptV1,
        at_monotonic_ms: u64,
    ) -> Result<EvaluationOutput, EvaluatorError> {
        let request = self
            .issued_requests
            .get(&receipt.request_id)
            .ok_or_else(|| {
                EvaluatorError::new("unknown_request", "receipt references an unknown request")
            })?;
        if receipt.schema_version != SCHEMA_VERSION_V1
            || receipt.request_id != request.request_id
            || receipt.causal_transition_id != request.causal_transition_id
            || receipt.deduplication_key != request.deduplication_key
            || receipt.evidence_window_digest != request.evidence_window_digest
            || receipt.subject_scope != request.subject_scope
            || receipt.consumer != request.consumer
            || receipt.policy_generation != request.policy_generation
            || receipt.observation_policy_generation != request.observation_policy_generation
            || receipt.diagnostic_profile != request.diagnostic_profile
            || receipt.clock_id != self.clock_id
            || receipt.completed_at_monotonic_ms < receipt.started_at_monotonic_ms
            || at_monotonic_ms < receipt.completed_at_monotonic_ms
        {
            return Err(EvaluatorError::new(
                "receipt_binding_mismatch",
                "diagnostic receipt does not exactly bind its request",
            ));
        }
        let evidence_reference = DiagnosticEvidenceReferenceV1 {
            receipt_id: receipt.receipt_id.clone(),
            result_digest: receipt.result_digest.clone(),
            recorded_at_monotonic_ms: at_monotonic_ms,
            applicable_until_monotonic_ms: receipt.applicable_until_monotonic_ms,
            nonclaims: receipt.nonclaims.clone(),
        };
        self.diagnostic_evidence.push(evidence_reference.clone());
        self.escalation_state = EscalationStateV1::Completed {
            request_id: receipt.request_id.to_string(),
            receipt_id: receipt.receipt_id.clone(),
        };
        let event = self.sparse_event(
            at_monotonic_ms,
            SparseDurableEventKindV1::DiagnosticReceiptCorrelated {
                receipt: Box::new(receipt),
                evidence_reference: Box::new(evidence_reference),
            },
        );
        let mut output = self.evaluate(at_monotonic_ms)?;
        output.sparse_events.insert(0, event);
        Ok(output)
    }

    fn validate_binding(&self, received: &ReceivedPulseV1) -> Result<(), EvaluatorError> {
        if received.receiver.receiver != self.receiver
            || received.receiver.receiver_incarnation != self.receiver_incarnation
            || received.receiver.clock_id != self.clock_id
        {
            return Err(EvaluatorError::new(
                "receiver_binding_mismatch",
                "receiver identity, incarnation, or clock differs from evaluator",
            ));
        }
        if received.frame.subject != self.policy.subject {
            return Err(EvaluatorError::new(
                "subject_mismatch",
                "pulse subject differs from policy subject",
            ));
        }
        if received.frame.observation_policy_generation != self.policy.observation_policy_generation
        {
            return Err(EvaluatorError::new(
                "observation_policy_generation_mismatch",
                "pulse observation-policy generation is not admitted by the reliance policy",
            ));
        }
        if received.frame.profile != self.policy.observation_profile {
            return Err(EvaluatorError::new(
                "profile_mismatch",
                "pulse profile differs from evaluator policy",
            ));
        }
        Ok(())
    }

    fn classify_arrival(
        &self,
        frame: &PulseFrameV1,
        annotation: &pulse_types::ReceiverAnnotationV1,
    ) -> (ArrivalDispositionV1, Option<pulse_types::SequenceGapV1>) {
        if annotation
            .transport_observed_delay_ms
            .is_some_and(|delay| delay >= frame.validity_ms)
        {
            return (ArrivalDispositionV1::Stale, None);
        }
        if self
            .retired_subject_incarnations
            .contains(&frame.subject_incarnation)
        {
            return (ArrivalDispositionV1::Replay, None);
        }
        if let Some(lineage) = self.observer_lineages.get(&frame.observer) {
            if lineage.incarnation == frame.observer_incarnation {
                if frame.sequence == lineage.sequence {
                    (ArrivalDispositionV1::Duplicate, None)
                } else if frame.sequence < lineage.sequence {
                    (ArrivalDispositionV1::Replay, None)
                } else if frame.sequence == lineage.sequence.saturating_add(1) {
                    (ArrivalDispositionV1::Continuous, None)
                } else {
                    let expected_next = lineage.sequence.saturating_add(1);
                    (
                        ArrivalDispositionV1::Gap,
                        Some(pulse_types::SequenceGapV1 {
                            expected_next,
                            received: frame.sequence,
                            missing_count: frame.sequence - expected_next,
                        }),
                    )
                }
            } else if self
                .retired_observer_incarnations
                .contains(&(frame.observer.clone(), frame.observer_incarnation.clone()))
            {
                (ArrivalDispositionV1::Replay, None)
            } else {
                (ArrivalDispositionV1::Restarted, None)
            }
        } else {
            (ArrivalDispositionV1::First, None)
        }
    }

    fn update_lineage(&mut self, frame: &PulseFrameV1, disposition: &ArrivalDispositionV1) {
        if matches!(disposition, ArrivalDispositionV1::Restarted)
            && let Some(old) = self.observer_lineages.get(&frame.observer)
        {
            self.retired_observer_incarnations
                .insert((frame.observer.clone(), old.incarnation.clone()));
        }
        self.observer_lineages.insert(
            frame.observer.clone(),
            ObserverLineage {
                incarnation: frame.observer_incarnation.clone(),
                sequence: frame.sequence,
            },
        );
    }

    fn record_subject_incarnation_change(
        &mut self,
        received: &ReceivedPulseV1,
        at_monotonic_ms: u64,
    ) {
        let old = self.current_subject_incarnation.clone();
        let new = received.frame.subject_incarnation.clone();
        let mut references: Vec<String> = self
            .observers
            .values()
            .filter(|evidence| evidence.received.frame.subject_incarnation == old)
            .map(|evidence| evidence_ref(&evidence.received.frame))
            .collect();
        references.push(evidence_ref(&received.frame));
        let statements = vec![
            format!("subject incarnation observed as {old}"),
            format!("subject incarnation observed as {new}"),
        ];
        self.retired_subject_incarnations.insert(old);
        self.current_subject_incarnation = new;
        self.create_contradiction(
            "subject_incarnation",
            references,
            statements,
            at_monotonic_ms,
        );
    }

    fn detect_signal_contradictions(&mut self, received: &ReceivedPulseV1, at_monotonic_ms: u64) {
        if !self.received_provenance_is_eligible(received) {
            return;
        }
        let mut candidates = Vec::new();
        for evidence in self.observers.values() {
            if evidence.received.frame.observer == received.frame.observer
                || evidence.received.frame.subject_incarnation != received.frame.subject_incarnation
                || at_monotonic_ms >= evidence.expires_at_ms
                || !self.provenance_is_eligible(evidence)
            {
                continue;
            }
            for incoming in &received.frame.signals {
                let Some(existing) = evidence
                    .received
                    .frame
                    .signals
                    .iter()
                    .find(|signal| signal.name == incoming.name)
                else {
                    continue;
                };
                if signals_are_incompatible(
                    incoming,
                    existing,
                    self.policy
                        .coherence_tolerances
                        .get(&incoming.name)
                        .copied(),
                ) {
                    candidates.push((
                        incoming.name.clone(),
                        vec![
                            evidence_ref(&received.frame),
                            evidence_ref(&evidence.received.frame),
                        ],
                        vec![
                            signal_statement(&received.frame.observer, incoming),
                            signal_statement(&evidence.received.frame.observer, existing),
                        ],
                    ));
                }
            }
        }
        for (signal, references, statements) in candidates {
            self.create_contradiction(&signal, references, statements, at_monotonic_ms);
        }
    }

    fn record_adverse_supersession(&mut self, received: &ReceivedPulseV1, at_monotonic_ms: u64) {
        let supersession = self
            .observers
            .get(&received.frame.observer)
            .and_then(|prior| {
                let mut adverse_signals = prior
                    .received
                    .frame
                    .signals
                    .iter()
                    .filter(|signal| signal.assessment == SignalAssessmentV1::OutsideDeclaredBound)
                    .map(|signal| signal.name.clone())
                    .collect::<Vec<_>>();
                if adverse_signals.is_empty() {
                    return None;
                }
                adverse_signals.sort();
                let rule = if prior.received.frame.observer_incarnation
                    == received.frame.observer_incarnation
                {
                    "same_observer_newer_sequence/v1"
                } else {
                    "observer_incarnation_replacement/v1"
                };
                Some((
                    evidence_ref(&prior.received.frame),
                    evidence_ref(&received.frame),
                    adverse_signals,
                    rule.to_owned(),
                ))
            });
        if let Some((prior_evidence_ref, superseding_evidence_ref, adverse_signals, rule)) =
            supersession
        {
            self.sparse_event(
                at_monotonic_ms,
                SparseDurableEventKindV1::AdverseObservationSuperseded {
                    observer: received.frame.observer.clone(),
                    prior_evidence_ref,
                    superseding_evidence_ref,
                    adverse_signals,
                    rule,
                },
            );
        }
    }

    fn create_contradiction(
        &mut self,
        signal: &str,
        mut evidence_refs: Vec<String>,
        mut statements: Vec<String>,
        at_monotonic_ms: u64,
    ) {
        evidence_refs.sort();
        evidence_refs.dedup();
        statements.sort();
        statements.dedup();
        let mut parts: Vec<Vec<u8>> = vec![
            self.policy.subject.as_str().as_bytes().to_vec(),
            self.current_subject_incarnation
                .as_str()
                .as_bytes()
                .to_vec(),
            self.policy.generation.as_str().as_bytes().to_vec(),
            signal.as_bytes().to_vec(),
        ];
        parts.extend(evidence_refs.iter().map(|value| value.as_bytes().to_vec()));
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        let digest = digest_parts("contradiction.record.v1", &refs);
        let contradiction_id = ContradictionId::new(format!(
            "contradiction:{}",
            digest.as_str().trim_start_matches("sha256:")
        ));
        if self.contradictions.contains_key(&contradiction_id) {
            return;
        }
        let record = ContradictionRecordV1 {
            schema_version: SCHEMA_VERSION_V1,
            contradiction_id: contradiction_id.clone(),
            subject_scope: self.subject_scope(),
            policy_generation: self.policy.generation.clone(),
            signal: signal.to_owned(),
            first_observed_at_monotonic_ms: at_monotonic_ms,
            evidence_refs,
            incompatible_statements: statements,
            status: ContradictionStatusV1::Active,
        };
        self.contradictions.insert(contradiction_id, record.clone());
        self.sparse_event(
            at_monotonic_ms,
            SparseDurableEventKindV1::ContradictionCreated {
                contradiction: Box::new(record),
            },
        );
    }

    fn evaluate_since(
        &mut self,
        now: u64,
        event_log_start: usize,
    ) -> Result<EvaluationOutput, EvaluatorError> {
        let mut output = self.evaluate(now)?;
        output.sparse_events = self.event_log[event_log_start..].to_vec();
        Ok(output)
    }

    fn evaluate(&mut self, requested_now: u64) -> Result<EvaluationOutput, EvaluatorError> {
        let event_log_start = self.event_log.len();
        let now = if let Some(prior) = self.last_evaluation_ms {
            if requested_now < prior {
                let detail = format!(
                    "evaluation monotonic time regressed from {prior}ms to {requested_now}ms within one clock generation"
                );
                self.monitor_capability = MonitorCapabilityV1::Blind {
                    detail: detail.clone(),
                };
                self.monitor_event(prior, "blind", &detail);
                prior
            } else {
                requested_now
            }
        } else {
            requested_now
        };
        self.last_evaluation_ms = Some(now);
        self.active_escalations
            .retain(|_, active| now < active.expires_at_ms);
        self.diagnostic_evidence
            .retain(|evidence| now < evidence.applicable_until_monotonic_ms);

        let barrier = self.reevaluation_barrier.clone();
        let mut derived = self.derive(now);
        if barrier.is_some() {
            derived.category = JudgmentCategoryV1::Unknown;
            derived.support_deadline_ms = None;
        }
        self.metrics.active_coverage =
            u32::try_from(derived.coverage.active.len()).unwrap_or(u32::MAX);
        self.metrics.expired_coverage =
            u32::try_from(derived.coverage.expired.len()).unwrap_or(u32::MAX);

        let evidence_window_id = self.evidence_window_id(now);
        let explanation = explanation_for(
            derived.category,
            &derived.dimensions,
            &derived.coverage,
            &derived.active_contradictions,
            &derived.violation_evidence_refs,
            &self.monitor_capability,
            u64::try_from(self.diagnostic_evidence.len()).unwrap_or(u64::MAX),
            barrier.as_ref(),
        );
        let mut judgment = PresentStateJudgmentV1 {
            schema_version: SCHEMA_VERSION_V1,
            subject_scope: self.subject_scope(),
            consumer: self.policy.consumer.clone(),
            policy_generation: self.policy.generation.clone(),
            coverage: derived.coverage,
            evaluated_at_monotonic_ms: now,
            positive_support_expires_at_monotonic_ms: derived.support_deadline_ms,
            receiver_clock_id: self.clock_id.to_string(),
            evidence_window_id,
            category: derived.category,
            dimensions: derived.dimensions,
            explanation,
            escalation: self.escalation_state.clone(),
            mutation_authority: MutationAuthorityV1::None,
        };

        let semantic_transition = self
            .last_judgment
            .as_ref()
            .is_none_or(|prior| judgment_semantically_changed(prior, &judgment));
        let transition = if semantic_transition {
            Some(self.build_transition(&judgment, now))
        } else {
            None
        };
        if let Some(transition) = &transition {
            self.sparse_event(
                now,
                SparseDurableEventKindV1::JudgmentTransition {
                    transition: transition.clone(),
                },
            );
        }

        self.update_failure_metrics(judgment.category, now);
        self.update_stale_positive_metric(&judgment, now, derived.support_deadline_ms);

        let escalation_request = if barrier.is_none() {
            transition
                .as_ref()
                .and_then(|transition| self.maybe_escalate(transition, &judgment, now))
        } else {
            None
        };
        judgment.escalation = self.escalation_state.clone();
        self.last_judgment = Some(judgment.clone());
        self.reevaluation_barrier = None;
        let sparse_events = self.event_log[event_log_start..].to_vec();
        Ok(EvaluationOutput {
            judgment,
            transition,
            escalation_request,
            sparse_events,
        })
    }

    fn derive(&self, now: u64) -> DerivedState {
        let relevant: Vec<&ObserverEvidence> = self
            .observers
            .values()
            .filter(|evidence| {
                evidence.received.frame.subject_incarnation == self.current_subject_incarnation
            })
            .collect();
        let fresh: Vec<_> = relevant
            .iter()
            .copied()
            .filter(|evidence| now < evidence.expires_at_ms)
            .collect();
        let expired: Vec<_> = relevant
            .iter()
            .copied()
            .filter(|evidence| now >= evidence.expires_at_ms)
            .collect();
        let eligible_fresh: Vec<_> = fresh
            .iter()
            .copied()
            .filter(|evidence| self.provenance_is_eligible(evidence))
            .collect();

        let active_domains = unique_domains(&eligible_fresh, &self.policy.observer_failure_domains);
        let coverage = self.coverage_summary(&eligible_fresh, &expired);
        let active_contradictions: Vec<&ContradictionRecordV1> = self
            .contradictions
            .values()
            .filter(|record| record.is_active())
            .collect();
        let violation_evidence_refs = eligible_fresh
            .iter()
            .filter(|evidence| {
                evidence
                    .received
                    .frame
                    .signals
                    .iter()
                    .any(|signal| signal.assessment == SignalAssessmentV1::OutsideDeclaredBound)
            })
            .map(|evidence| evidence_ref(&evidence.received.frame))
            .collect::<Vec<_>>();
        let has_violation = !violation_evidence_refs.is_empty();

        let freshness = if relevant.is_empty() {
            FreshnessDimensionV1::NoEvidence
        } else if fresh.is_empty() {
            FreshnessDimensionV1::Expired
        } else if expired.is_empty() {
            FreshnessDimensionV1::Current
        } else {
            FreshnessDimensionV1::Mixed
        };
        let sequence_continuity = if fresh.is_empty() {
            SequenceContinuityDimensionV1::Unknown
        } else if fresh
            .iter()
            .any(|evidence| evidence.continuity == SequenceContinuityDimensionV1::Gapped)
        {
            SequenceContinuityDimensionV1::Gapped
        } else if fresh
            .iter()
            .any(|evidence| evidence.continuity == SequenceContinuityDimensionV1::Restarted)
        {
            SequenceContinuityDimensionV1::Restarted
        } else if fresh
            .iter()
            .any(|evidence| evidence.continuity == SequenceContinuityDimensionV1::FirstSeen)
        {
            SequenceContinuityDimensionV1::FirstSeen
        } else {
            SequenceContinuityDimensionV1::Continuous
        };
        let observer_availability = if active_domains.len()
            >= usize::try_from(self.policy.minimum_observers).unwrap_or(usize::MAX)
        {
            ObserverAvailabilityDimensionV1::Available
        } else if active_domains.is_empty() {
            ObserverAvailabilityDimensionV1::Unavailable
        } else {
            ObserverAvailabilityDimensionV1::Partial
        };
        let coherence = if !active_contradictions.is_empty() {
            CrossObserverCoherenceDimensionV1::Disagreement
        } else if active_domains.len() >= 2 {
            CrossObserverCoherenceDimensionV1::Coherent
        } else {
            CrossObserverCoherenceDimensionV1::Insufficient
        };
        let provenance = provenance_dimension(&fresh);
        let transport = match self.monitor_capability {
            MonitorCapabilityV1::Operational => TransportDimensionV1::Normal,
            MonitorCapabilityV1::Degraded { .. } => TransportDimensionV1::Degraded,
            MonitorCapabilityV1::Blind { .. } => TransportDimensionV1::Blind,
        };
        let subject_signal_consistency = if !active_contradictions.is_empty() {
            SubjectSignalConsistencyDimensionV1::Contradictory
        } else if has_violation {
            SubjectSignalConsistencyDimensionV1::Violation
        } else if eligible_fresh.is_empty() {
            SubjectSignalConsistencyDimensionV1::Unknown
        } else {
            SubjectSignalConsistencyDimensionV1::Consistent
        };
        let dimensions = ConfidenceDimensionsV1 {
            freshness,
            sequence_continuity,
            observer_availability,
            cross_observer_coherence: coherence,
            coverage: if coverage.missing.is_empty() {
                CoverageDimensionV1::Complete
            } else if coverage.active.is_empty() {
                CoverageDimensionV1::Absent
            } else {
                CoverageDimensionV1::Partial
            },
            provenance,
            transport,
            subject_signal_consistency,
        };

        let reliance_unknown = !coverage.missing.is_empty()
            || observer_availability != ObserverAvailabilityDimensionV1::Available
            || matches!(
                freshness,
                FreshnessDimensionV1::Expired | FreshnessDimensionV1::NoEvidence
            )
            || (self.policy.require_verified_authentication
                && provenance != ProvenanceDimensionV1::Verified)
            || transport == TransportDimensionV1::Blind;
        let category = if !active_contradictions.is_empty() {
            JudgmentCategoryV1::Contradicted
        } else if has_violation {
            JudgmentCategoryV1::Suspect
        } else if reliance_unknown {
            JudgmentCategoryV1::Unknown
        } else if matches!(
            sequence_continuity,
            SequenceContinuityDimensionV1::Gapped
                | SequenceContinuityDimensionV1::Restarted
                | SequenceContinuityDimensionV1::Unknown
        ) || transport == TransportDimensionV1::Degraded
        {
            JudgmentCategoryV1::Degraded
        } else {
            JudgmentCategoryV1::Current
        };
        let support_deadline_ms = if category == JudgmentCategoryV1::Current {
            self.support_deadline(&eligible_fresh)
        } else {
            None
        };
        DerivedState {
            category,
            dimensions,
            coverage,
            active_contradictions: active_contradictions
                .iter()
                .map(|record| record.contradiction_id.to_string())
                .collect(),
            violation_evidence_refs,
            support_deadline_ms,
        }
    }

    fn provenance_is_eligible(&self, evidence: &ObserverEvidence) -> bool {
        self.received_provenance_is_eligible(&evidence.received)
    }

    fn received_provenance_is_eligible(&self, received: &ReceivedPulseV1) -> bool {
        if !self.policy.require_verified_authentication {
            return !matches!(
                received.receiver.authentication,
                AuthenticationResultV1::Failed { .. }
            );
        }
        matches!(
            received.receiver.authentication,
            AuthenticationResultV1::Verified { .. }
        )
    }

    fn coverage_summary(
        &self,
        fresh: &[&ObserverEvidence],
        expired: &[&ObserverEvidence],
    ) -> CoverageSummaryV1 {
        let required_observers = self.policy.minimum_observers;
        let mut per_tag = Vec::with_capacity(self.policy.required_coverage.len());
        let mut active = Vec::new();
        let mut missing = Vec::new();
        let mut expired_tags = Vec::new();
        for tag in &self.policy.required_coverage {
            let active_count =
                domain_count_for_tag(fresh, tag, &self.policy.observer_failure_domains);
            let expired_count =
                domain_count_for_tag(expired, tag, &self.policy.observer_failure_domains);
            if active_count >= required_observers {
                active.push(tag.clone());
            } else {
                missing.push(tag.clone());
            }
            if expired_count > 0 {
                expired_tags.push(tag.clone());
            }
            per_tag.push(CoverageCountV1 {
                tag: tag.clone(),
                active_observers: active_count,
                expired_observers: expired_count,
                required_observers,
            });
        }
        CoverageSummaryV1 {
            required: self.policy.required_coverage.clone(),
            active,
            missing,
            expired: expired_tags,
            active_observers: u32::try_from(
                unique_domains(fresh, &self.policy.observer_failure_domains).len(),
            )
            .unwrap_or(u32::MAX),
            required_observers,
            per_tag,
        }
    }

    fn support_deadline(&self, fresh: &[&ObserverEvidence]) -> Option<u64> {
        let required = usize::try_from(self.policy.minimum_observers).ok()?;
        let mut overall = u64::MAX;
        for tag in &self.policy.required_coverage {
            let mut by_domain: BTreeMap<String, u64> = BTreeMap::new();
            for evidence in fresh {
                if evidence
                    .received
                    .frame
                    .coverage
                    .observed
                    .binary_search(tag)
                    .is_ok()
                {
                    let domain = failure_domain(
                        &evidence.received.frame.observer,
                        &self.policy.observer_failure_domains,
                    );
                    by_domain
                        .entry(domain)
                        .and_modify(|expiry| *expiry = (*expiry).max(evidence.expires_at_ms))
                        .or_insert(evidence.expires_at_ms);
                }
            }
            let mut expiries: Vec<u64> = by_domain.into_values().collect();
            expiries.sort_unstable_by(|left, right| right.cmp(left));
            let deadline = *expiries.get(required.saturating_sub(1))?;
            overall = overall.min(deadline);
        }
        (overall != u64::MAX).then_some(overall)
    }

    fn evidence_window_id(&self, now: u64) -> EvidenceWindowId {
        let mut owned = vec![
            self.policy.subject.as_str().as_bytes().to_vec(),
            self.current_subject_incarnation
                .as_str()
                .as_bytes()
                .to_vec(),
            self.policy.consumer.as_str().as_bytes().to_vec(),
            self.policy.generation.as_str().as_bytes().to_vec(),
            self.clock_id.as_str().as_bytes().to_vec(),
            now.to_be_bytes().to_vec(),
            monitor_state_name(&self.monitor_capability)
                .as_bytes()
                .to_vec(),
        ];
        for evidence in self.observers.values() {
            owned.push(
                evidence
                    .received
                    .frame
                    .observer
                    .as_str()
                    .as_bytes()
                    .to_vec(),
            );
            owned.push(
                evidence
                    .received
                    .frame
                    .observer_incarnation
                    .as_str()
                    .as_bytes()
                    .to_vec(),
            );
            owned.push(evidence.received.frame.sequence.to_be_bytes().to_vec());
            owned.push(
                evidence
                    .received
                    .frame
                    .observation_digest
                    .as_str()
                    .as_bytes()
                    .to_vec(),
            );
            owned.push(evidence.expires_at_ms.to_be_bytes().to_vec());
        }
        for record in self
            .contradictions
            .values()
            .filter(|record| record.is_active())
        {
            owned.push(record.contradiction_id.as_str().as_bytes().to_vec());
        }
        for evidence in &self.diagnostic_evidence {
            owned.push(evidence.receipt_id.as_str().as_bytes().to_vec());
            owned.push(evidence.result_digest.as_str().as_bytes().to_vec());
            owned.push(
                evidence
                    .applicable_until_monotonic_ms
                    .to_be_bytes()
                    .to_vec(),
            );
        }
        let parts: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
        EvidenceWindowId::new(digest_parts("evidence.window.v1", &parts).to_string())
    }

    fn build_transition(
        &mut self,
        judgment: &PresentStateJudgmentV1,
        now: u64,
    ) -> JudgmentTransitionV1 {
        self.transition_counter = self.transition_counter.saturating_add(1);
        let digest = digest_parts(
            "judgment.transition.v1",
            &[
                self.policy.subject.as_str().as_bytes(),
                self.policy.consumer.as_str().as_bytes(),
                self.policy.generation.as_str().as_bytes(),
                &self.transition_counter.to_be_bytes(),
                &now.to_be_bytes(),
                judgment.evidence_window_id.as_str().as_bytes(),
            ],
        );
        JudgmentTransitionV1 {
            schema_version: SCHEMA_VERSION_V1,
            transition_id: TransitionId::new(format!(
                "transition:{}",
                digest.as_str().trim_start_matches("sha256:")
            )),
            subject_scope: judgment.subject_scope.clone(),
            consumer: judgment.consumer.clone(),
            policy_generation: judgment.policy_generation.clone(),
            at_monotonic_ms: now,
            from: self.last_judgment.as_ref().map(|prior| prior.category),
            to: judgment.category,
            prior_evidence_window: self
                .last_judgment
                .as_ref()
                .map(|prior| prior.evidence_window_id.clone()),
            evidence_window: judgment.evidence_window_id.clone(),
            reason_codes: judgment
                .explanation
                .reasons
                .iter()
                .map(|reason| reason.code.clone())
                .collect(),
        }
    }

    fn maybe_escalate(
        &mut self,
        transition: &JudgmentTransitionV1,
        judgment: &PresentStateJudgmentV1,
        now: u64,
    ) -> Option<DiagnosticEscalationRequestV1> {
        if transition.from != Some(JudgmentCategoryV1::Current)
            || transition.to == JudgmentCategoryV1::Current
        {
            return None;
        }
        let trigger = select_trigger(judgment);
        let escalation = self.policy.escalation.as_ref()?;
        if !escalation.triggers.contains(&trigger) {
            return None;
        }
        let mut request = DiagnosticEscalationRequestV1 {
            schema_version: SCHEMA_VERSION_V1,
            request_id: EscalationRequestId::new("pending"),
            subject_scope: judgment.subject_scope.clone(),
            consumer: self.policy.consumer.clone(),
            trigger_class: trigger,
            evidence_window_digest: DigestV1(judgment.evidence_window_id.to_string()),
            policy_generation: self.policy.generation.clone(),
            observation_policy_generation: self.policy.observation_policy_generation.clone(),
            diagnostic_profile: escalation.diagnostic_profile.clone(),
            bounds: escalation.bounds,
            clock_id: self.clock_id.clone(),
            created_at_monotonic_ms: now,
            expires_at_monotonic_ms: now.saturating_add(escalation.request_ttl_ms),
            deduplication_key: digest_parts("pending", &[]),
            causal_transition_id: transition.transition_id.clone(),
            nonclaims: ESCALATION_NONCLAIMS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        };
        request.deduplication_key = request.compute_deduplication_key();
        if let Some(active) = self.active_escalations.get(&request.deduplication_key) {
            self.metrics.escalation_deduplication_count = self
                .metrics
                .escalation_deduplication_count
                .saturating_add(1);
            self.escalation_state = EscalationStateV1::Requested {
                request_id: active.request_id.to_string(),
            };
            self.sparse_event(
                now,
                SparseDurableEventKindV1::EscalationDeduplicated {
                    deduplication_key: request.deduplication_key,
                    active_request_id: active.request_id.clone(),
                },
            );
            return None;
        }
        self.request_counter = self.request_counter.saturating_add(1);
        request.request_id =
            EscalationRequestId::new(format!("escalation:{:016x}", self.request_counter));
        if request.validate().is_err() {
            return None;
        }
        self.active_escalations.insert(
            request.deduplication_key.clone(),
            ActiveEscalation {
                request_id: request.request_id.clone(),
                expires_at_ms: request.expires_at_monotonic_ms,
            },
        );
        self.issued_requests
            .insert(request.request_id.clone(), request.clone());
        self.escalation_state = EscalationStateV1::Requested {
            request_id: request.request_id.to_string(),
        };
        if self.normal_trace {
            self.metrics.false_escalation_count =
                self.metrics.false_escalation_count.saturating_add(1);
        }
        if let Some(start) = self.fault_started_at_ms
            && self.metrics.failure_to_escalation_latency_ms.is_none()
        {
            self.metrics.failure_to_escalation_latency_ms = Some(now.saturating_sub(start));
        }
        self.sparse_event(
            now,
            SparseDurableEventKindV1::EscalationRequested {
                request: Box::new(request.clone()),
            },
        );
        Some(request)
    }

    fn update_failure_metrics(&mut self, category: JudgmentCategoryV1, now: u64) {
        let Some(start) = self.fault_started_at_ms else {
            return;
        };
        let latency = now.saturating_sub(start);
        if category == JudgmentCategoryV1::Unknown
            && self.metrics.failure_to_unknown_latency_ms.is_none()
        {
            self.metrics.failure_to_unknown_latency_ms = Some(latency);
        }
        if category == JudgmentCategoryV1::Contradicted
            && self.metrics.failure_to_contradicted_latency_ms.is_none()
        {
            self.metrics.failure_to_contradicted_latency_ms = Some(latency);
        }
    }

    fn update_stale_positive_metric(
        &mut self,
        judgment: &PresentStateJudgmentV1,
        now: u64,
        support_deadline_ms: Option<u64>,
    ) {
        let was_current = self
            .last_judgment
            .as_ref()
            .is_some_and(|prior| prior.category == JudgmentCategoryV1::Current);
        if judgment.category == JudgmentCategoryV1::Current {
            self.last_positive_support_deadline_ms = support_deadline_ms;
        } else if was_current {
            if let Some(deadline) = self.last_positive_support_deadline_ms {
                self.metrics.maximum_stale_positive_duration_ms = self
                    .metrics
                    .maximum_stale_positive_duration_ms
                    .max(now.saturating_sub(deadline));
            }
            self.last_positive_support_deadline_ms = None;
        }
    }

    fn monitor_event(
        &mut self,
        at_monotonic_ms: u64,
        state: &str,
        detail: &str,
    ) -> SparseDurableEventV1 {
        self.sparse_event(
            at_monotonic_ms,
            SparseDurableEventKindV1::MonitorCapabilityChanged {
                state: state.to_owned(),
                detail: detail.to_owned(),
            },
        )
    }

    fn sparse_event(
        &mut self,
        at_monotonic_ms: u64,
        event: SparseDurableEventKindV1,
    ) -> SparseDurableEventV1 {
        self.event_counter = self.event_counter.saturating_add(1);
        let item = SparseDurableEventV1 {
            schema_version: SCHEMA_VERSION_V1,
            event_id: SparseEventId::new(format!("event:{:016x}", self.event_counter)),
            at_monotonic_ms,
            event,
        };
        self.event_log.push(item.clone());
        item
    }

    fn subject_scope(&self) -> SubjectScopeV1 {
        SubjectScopeV1 {
            subject: self.policy.subject.clone(),
            subject_incarnation: self.current_subject_incarnation.clone(),
            scope: self.policy.scope.clone(),
        }
    }
}

struct DerivedState {
    category: JudgmentCategoryV1,
    dimensions: ConfidenceDimensionsV1,
    coverage: CoverageSummaryV1,
    active_contradictions: Vec<String>,
    violation_evidence_refs: Vec<String>,
    support_deadline_ms: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluatorError {
    pub code: &'static str,
    pub detail: String,
}

impl EvaluatorError {
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    fn from_policy(error: PolicyError) -> Self {
        Self::new("invalid_policy", error.to_string())
    }
}

impl fmt::Display for EvaluatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for EvaluatorError {}

fn signals_are_incompatible(
    left: &pulse_types::BoundedSignalValueV1,
    right: &pulse_types::BoundedSignalValueV1,
    tolerance: Option<f64>,
) -> bool {
    let opposing_assessments = matches!(
        (left.assessment, right.assessment),
        (
            SignalAssessmentV1::WithinDeclaredBound,
            SignalAssessmentV1::OutsideDeclaredBound
        ) | (
            SignalAssessmentV1::OutsideDeclaredBound,
            SignalAssessmentV1::WithinDeclaredBound
        )
    );
    if opposing_assessments {
        return true;
    }
    tolerance.is_some_and(|maximum| {
        left.assessment != SignalAssessmentV1::Unavailable
            && right.assessment != SignalAssessmentV1::Unavailable
            && (left.value - right.value).abs() > maximum
    })
}

fn signal_statement(observer: &ObserverId, signal: &pulse_types::BoundedSignalValueV1) -> String {
    format!(
        "observer={} signal={} value={} unit={} assessment={:?}",
        observer, signal.name, signal.value, signal.unit, signal.assessment
    )
}

fn evidence_ref(frame: &PulseFrameV1) -> String {
    format!(
        "{}/{}/seq={}/{}",
        frame.observer, frame.observer_incarnation, frame.sequence, frame.observation_digest
    )
}

fn failure_domain(observer: &ObserverId, declared: &BTreeMap<String, String>) -> String {
    declared
        .get(observer.as_str())
        .cloned()
        .unwrap_or_else(|| format!("observer:{}", observer.as_str()))
}

fn unique_domains(
    evidence: &[&ObserverEvidence],
    declared: &BTreeMap<String, String>,
) -> BTreeSet<String> {
    evidence
        .iter()
        .map(|item| failure_domain(&item.received.frame.observer, declared))
        .collect()
}

fn domain_count_for_tag(
    evidence: &[&ObserverEvidence],
    tag: &str,
    declared: &BTreeMap<String, String>,
) -> u32 {
    let domains: BTreeSet<_> = evidence
        .iter()
        .filter(|item| {
            item.received
                .frame
                .coverage
                .observed
                .binary_search_by(|candidate| candidate.as_str().cmp(tag))
                .is_ok()
        })
        .map(|item| failure_domain(&item.received.frame.observer, declared))
        .collect();
    u32::try_from(domains.len()).unwrap_or(u32::MAX)
}

fn provenance_dimension(evidence: &[&ObserverEvidence]) -> ProvenanceDimensionV1 {
    if evidence.is_empty() {
        ProvenanceDimensionV1::Unknown
    } else if evidence.iter().any(|item| {
        matches!(
            item.received.receiver.authentication,
            AuthenticationResultV1::Failed { .. }
        )
    }) {
        ProvenanceDimensionV1::Failed
    } else if evidence.iter().all(|item| {
        matches!(
            item.received.receiver.authentication,
            AuthenticationResultV1::Verified { .. }
        )
    }) {
        ProvenanceDimensionV1::Verified
    } else {
        ProvenanceDimensionV1::Degraded
    }
}

#[allow(clippy::too_many_arguments)]
fn explanation_for(
    category: JudgmentCategoryV1,
    dimensions: &ConfidenceDimensionsV1,
    coverage: &CoverageSummaryV1,
    active_contradictions: &[String],
    violation_evidence_refs: &[String],
    monitor: &MonitorCapabilityV1,
    receipt_count: u64,
    barrier: Option<&ReevaluationBarrierV1>,
) -> JudgmentExplanationV1 {
    let mut reasons = Vec::new();
    if let Some(barrier) = barrier {
        reasons.push(JudgmentReasonV1 {
            code: barrier.code().to_owned(),
            detail: barrier.detail().to_owned(),
            evidence_refs: Vec::new(),
        });
    }
    let has_violation = !violation_evidence_refs.is_empty();
    if !active_contradictions.is_empty() {
        reasons.push(JudgmentReasonV1 {
            code: "contradiction_retained".to_owned(),
            detail: format!(
                "{} independently grounded contradiction record(s) remain unresolved",
                active_contradictions.len()
            ),
            evidence_refs: active_contradictions.to_vec(),
        });
    }
    if has_violation {
        reasons.push(JudgmentReasonV1 {
            code: "subject_bound_violated".to_owned(),
            detail: "current admitted evidence contains an outside-declared-bound observation"
                .to_owned(),
            evidence_refs: violation_evidence_refs.to_vec(),
        });
    }
    match dimensions.freshness {
        FreshnessDimensionV1::Expired => reasons.push(JudgmentReasonV1 {
            code: "freshness_expired".to_owned(),
            detail: "all applicable pulse evidence has reached receiver-owned expiry".to_owned(),
            evidence_refs: Vec::new(),
        }),
        FreshnessDimensionV1::Mixed => reasons.push(JudgmentReasonV1 {
            code: "freshness_mixed".to_owned(),
            detail: "the evidence window contains both current and expired contributions"
                .to_owned(),
            evidence_refs: Vec::new(),
        }),
        FreshnessDimensionV1::NoEvidence => reasons.push(JudgmentReasonV1 {
            code: "no_evidence".to_owned(),
            detail: "no applicable pulse evidence has been admitted".to_owned(),
            evidence_refs: Vec::new(),
        }),
        FreshnessDimensionV1::Current => {}
    }
    if !coverage.missing.is_empty() {
        reasons.push(JudgmentReasonV1 {
            code: "coverage_incomplete".to_owned(),
            detail: format!("required coverage missing: {}", coverage.missing.join(",")),
            evidence_refs: Vec::new(),
        });
    }
    if dimensions.observer_availability != ObserverAvailabilityDimensionV1::Available {
        reasons.push(JudgmentReasonV1 {
            code: "observer_availability_insufficient".to_owned(),
            detail: format!(
                "{} independent configured failure domain(s) are active; {} required",
                coverage.active_observers, coverage.required_observers
            ),
            evidence_refs: Vec::new(),
        });
    }
    match dimensions.provenance {
        ProvenanceDimensionV1::Failed => reasons.push(JudgmentReasonV1 {
            code: "provenance_failed".to_owned(),
            detail: "at least one current receiver authentication result failed".to_owned(),
            evidence_refs: Vec::new(),
        }),
        ProvenanceDimensionV1::Degraded => reasons.push(JudgmentReasonV1 {
            code: "provenance_unverified".to_owned(),
            detail: "current evidence includes an unauthenticated or unchecked observation"
                .to_owned(),
            evidence_refs: Vec::new(),
        }),
        ProvenanceDimensionV1::Verified | ProvenanceDimensionV1::Unknown => {}
    }
    match dimensions.sequence_continuity {
        SequenceContinuityDimensionV1::Gapped => reasons.push(JudgmentReasonV1 {
            code: "sequence_gap".to_owned(),
            detail: "a current observer lineage contains a receiver-observed sequence gap"
                .to_owned(),
            evidence_refs: Vec::new(),
        }),
        SequenceContinuityDimensionV1::Restarted => reasons.push(JudgmentReasonV1 {
            code: "observer_restarted".to_owned(),
            detail: "a current observer began a new incarnation and did not inherit continuity"
                .to_owned(),
            evidence_refs: Vec::new(),
        }),
        SequenceContinuityDimensionV1::FirstSeen
        | SequenceContinuityDimensionV1::Continuous
        | SequenceContinuityDimensionV1::Unknown => {}
    }
    match monitor {
        MonitorCapabilityV1::Degraded { detail } => reasons.push(JudgmentReasonV1 {
            code: "monitor_degraded".to_owned(),
            detail: detail.clone(),
            evidence_refs: Vec::new(),
        }),
        MonitorCapabilityV1::Blind { detail } => reasons.push(JudgmentReasonV1 {
            code: "monitor_blind".to_owned(),
            detail: detail.clone(),
            evidence_refs: Vec::new(),
        }),
        MonitorCapabilityV1::Operational => {}
    }
    if receipt_count > 0 {
        reasons.push(JudgmentReasonV1 {
            code: "diagnostic_receipt_correlated".to_owned(),
            detail: format!(
                "{receipt_count} bounded diagnostic receipt(s) were correlated; they do not refresh pulse evidence"
            ),
            evidence_refs: Vec::new(),
        });
    }
    if reasons.is_empty() {
        reasons.push(JudgmentReasonV1 {
            code: "named_reliance_conditions_satisfied".to_owned(),
            detail: "all conditions named by this consumer policy are satisfied at evaluation time"
                .to_owned(),
            evidence_refs: Vec::new(),
        });
    }
    let summary = if barrier.is_some() {
        "UNKNOWN: an explicit runtime transition requires reevaluation; prior standing was not inherited."
            .to_owned()
    } else if category == JudgmentCategoryV1::Unknown
        && !coverage.missing.is_empty()
        && !has_violation
        && active_contradictions.is_empty()
    {
        INCOMPLETE_COVERAGE_EXPLANATION.to_owned()
    } else {
        match category {
            JudgmentCategoryV1::Current => {
                "CURRENT: named reliance conditions are satisfied for this consumer at this evaluation time."
            }
            JudgmentCategoryV1::Degraded => {
                "DEGRADED: current evidence exists, but a named observation-quality condition is degraded."
            }
            JudgmentCategoryV1::Suspect => {
                "SUSPECT: current admitted evidence contains a declared bound violation."
            }
            JudgmentCategoryV1::Unknown => {
                "UNKNOWN: available evidence does not support this consumer's present reliance conditions."
            }
            JudgmentCategoryV1::Contradicted => {
                "CONTRADICTED: incompatible grounded evidence remains unresolved."
            }
        }
        .to_owned()
    };
    let claims = match category {
        JudgmentCategoryV1::Current => vec![
            "The named consumer reliance conditions are satisfied for this exact evidence window and evaluation time."
                .to_owned(),
        ],
        JudgmentCategoryV1::Degraded => vec![
            "Current observation evidence exists and at least one named quality condition is degraded."
                .to_owned(),
        ],
        JudgmentCategoryV1::Suspect => vec![
            "At least one current admitted observation is outside a declared profile bound."
                .to_owned(),
        ],
        JudgmentCategoryV1::Unknown => vec![
            "The available evidence is insufficient for this consumer's present reliance judgment."
                .to_owned(),
        ],
        JudgmentCategoryV1::Contradicted => vec![
            "Incompatible admitted observation statements remain visible and unresolved."
                .to_owned(),
        ],
    };
    JudgmentExplanationV1 {
        summary,
        reasons,
        claims,
        nonclaims: JUDGMENT_NONCLAIMS
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
    }
}

fn judgment_semantically_changed(
    prior: &PresentStateJudgmentV1,
    current: &PresentStateJudgmentV1,
) -> bool {
    prior.subject_scope != current.subject_scope
        || prior.consumer != current.consumer
        || prior.policy_generation != current.policy_generation
        || prior.category != current.category
        || prior.dimensions != current.dimensions
        || prior.coverage != current.coverage
        || prior
            .explanation
            .reasons
            .iter()
            .map(|reason| reason.code.as_str())
            .collect::<Vec<_>>()
            != current
                .explanation
                .reasons
                .iter()
                .map(|reason| reason.code.as_str())
                .collect::<Vec<_>>()
}

fn select_trigger(judgment: &PresentStateJudgmentV1) -> EscalationTriggerClassV1 {
    if judgment.category == JudgmentCategoryV1::Contradicted {
        EscalationTriggerClassV1::ContradictionRetained
    } else if judgment.category == JudgmentCategoryV1::Suspect {
        EscalationTriggerClassV1::SubjectBoundViolated
    } else if judgment.dimensions.transport == TransportDimensionV1::Blind {
        EscalationTriggerClassV1::TransportBlind
    } else if judgment.dimensions.provenance == ProvenanceDimensionV1::Failed {
        EscalationTriggerClassV1::ProvenanceFailed
    } else if !judgment.coverage.missing.is_empty() {
        EscalationTriggerClassV1::CoverageCollapse
    } else if matches!(
        judgment.dimensions.sequence_continuity,
        SequenceContinuityDimensionV1::Gapped | SequenceContinuityDimensionV1::Restarted
    ) {
        EscalationTriggerClassV1::SequenceDiscontinuity
    } else if matches!(
        judgment.dimensions.freshness,
        FreshnessDimensionV1::Expired | FreshnessDimensionV1::NoEvidence
    ) {
        EscalationTriggerClassV1::FreshnessLost
    } else {
        EscalationTriggerClassV1::ObserverDisagreement
    }
}

fn monitor_state_name(state: &MonitorCapabilityV1) -> &'static str {
    match state {
        MonitorCapabilityV1::Operational => "operational",
        MonitorCapabilityV1::Degraded { .. } => "degraded",
        MonitorCapabilityV1::Blind { .. } => "blind",
    }
}
