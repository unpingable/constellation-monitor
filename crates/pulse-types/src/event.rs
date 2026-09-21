use serde::{Deserialize, Serialize};

use crate::{
    ActivationReceiptV1, ContradictionRecordV1, DiagnosticEscalationRequestV1,
    DiagnosticEvidenceReferenceV1, EscalationDispositionV1, ExperimentalMetricsV1,
    GenerationLifecycleFactV1, JudgmentTransitionV1, MockDiagnosticReceiptV1, ObserverId,
    ReceiverAcceptanceReceiptV1, RelianceContextTransitionV1, RelianceSupportCertificateV1,
    RuntimeBindingStateV1, RuntimeRefusalV1, SCHEMA_VERSION_V1, SparseEventId,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SparseDurableEventKindV1 {
    JudgmentTransition {
        transition: JudgmentTransitionV1,
    },
    ContradictionCreated {
        contradiction: Box<ContradictionRecordV1>,
    },
    ContradictionLifecycleChanged {
        contradiction: Box<ContradictionRecordV1>,
    },
    AdverseObservationSuperseded {
        observer: ObserverId,
        prior_evidence_ref: String,
        superseding_evidence_ref: String,
        adverse_signals: Vec<String>,
        rule: String,
    },
    EscalationRequested {
        request: Box<DiagnosticEscalationRequestV1>,
    },
    EscalationDeduplicated {
        deduplication_key: crate::DigestV1,
        active_request_id: crate::EscalationRequestId,
    },
    EscalationDisposition {
        disposition: EscalationDispositionV1,
    },
    DiagnosticReceiptCorrelated {
        receipt: Box<MockDiagnosticReceiptV1>,
        evidence_reference: Box<DiagnosticEvidenceReferenceV1>,
    },
    MonitorCapabilityChanged {
        state: String,
        detail: String,
    },
    RelianceContextTransition {
        transition: Box<RelianceContextTransitionV1>,
    },
    SupportCertificateIssued {
        certificate: Box<RelianceSupportCertificateV1>,
    },
    RuntimeRefusal {
        refusal: Box<RuntimeRefusalV1>,
    },
    SchedulerReevaluated {
        consumer: crate::ConsumerId,
        activation_id: crate::ContextActivationId,
        expected_deadline_monotonic_ms: u64,
        actual_reevaluation_monotonic_ms: u64,
        stale_positive_overshoot_ms: u64,
    },
    RuntimeRestarted {
        receiver_incarnation: crate::IncarnationId,
        clock_id: crate::ClockId,
        recovered_sparse_records: u64,
        recovered_receipts: u64,
        standing_recovered: bool,
    },
    ContradictionApplicabilityChanged {
        custody: Box<crate::ContradictionCustodyV1>,
    },
    QualifiedGenerationBindingChanged {
        receipt: Box<ActivationReceiptV1>,
    },
    QualifiedGenerationLifecycleApplied {
        consumer: crate::ConsumerId,
        fact: Box<GenerationLifecycleFactV1>,
        state: RuntimeBindingStateV1,
        standing_preserved: bool,
    },
    QualifiedGenerationBindingInvalidated {
        consumer: crate::ConsumerId,
        prior_activation_receipt_digest: crate::DigestV1,
        state: RuntimeBindingStateV1,
        detail: String,
        standing_preserved: bool,
    },
    ReceiverBoundaryAcceptanceRecorded {
        receipt: Box<ReceiverAcceptanceReceiptV1>,
    },
    ReceiverBoundaryCustodyChanged {
        state: crate::TransportCustodyFindingV1,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_binding_digest: Option<crate::DigestV1>,
        detail: String,
    },
    MetricsSnapshot {
        metrics: ExperimentalMetricsV1,
    },
}

/// Sparse, auditable semantic event. High-rate pulses are not embedded here.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SparseDurableEventV1 {
    pub schema_version: u16,
    pub event_id: SparseEventId,
    pub at_monotonic_ms: u64,
    pub event: SparseDurableEventKindV1,
}

impl SparseDurableEventV1 {
    #[must_use]
    pub const fn is_v1(&self) -> bool {
        self.schema_version == SCHEMA_VERSION_V1
    }
}
