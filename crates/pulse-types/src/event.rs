use serde::{Deserialize, Serialize};

use crate::{
    ContradictionRecordV1, DiagnosticEscalationRequestV1, DiagnosticEvidenceReferenceV1,
    EscalationDispositionV1, ExperimentalMetricsV1, JudgmentTransitionV1, MockDiagnosticReceiptV1,
    ObserverId, SCHEMA_VERSION_V1, SparseEventId,
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
