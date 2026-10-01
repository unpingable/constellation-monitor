//! The only value that may feed a projection.
//!
//! `VerifiedCorrespondenceV1` is created solely by [`crate::Coproducer`] after
//! every co-production check passed within one process. It implements neither
//! `Clone` nor `Serialize`, holds a process-local `Instant`, and cannot be
//! rebuilt from a persisted record.

use std::time::Instant;

use pulse_types::{IncarnationId, SubjectId};

use crate::{DeliveryMeasurementV1, NqDetectorStateV1, OwnerFailureV1, QuestionV1};

#[derive(Debug)]
pub struct VerifiedCorrespondenceV1 {
    question: QuestionV1,
    owner_failure: Option<OwnerFailureV1>,
    correspondence_id: String,
    acquisition_id: String,
    evidence_ref: String,
    artifact_id: String,
    certificate_id: String,
    profile_digest: String,
    subject: SubjectId,
    subject_incarnation: IncarnationId,
    nq_detector_state: NqDetectorStateV1,
    delivery: DeliveryMeasurementV1,
    sealed_at: Instant,
}

impl VerifiedCorrespondenceV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        question: QuestionV1,
        owner_failure: Option<OwnerFailureV1>,
        correspondence_id: String,
        acquisition_id: String,
        evidence_ref: String,
        artifact_id: String,
        certificate_id: String,
        profile_digest: String,
        subject: SubjectId,
        subject_incarnation: IncarnationId,
        nq_detector_state: NqDetectorStateV1,
        delivery: DeliveryMeasurementV1,
        sealed_at: Instant,
    ) -> Self {
        Self {
            question,
            owner_failure,
            correspondence_id,
            acquisition_id,
            evidence_ref,
            artifact_id,
            certificate_id,
            profile_digest,
            subject,
            subject_incarnation,
            nq_detector_state,
            delivery,
            sealed_at,
        }
    }

    /// The question this correspondence was co-produced for. A consumer that
    /// maps one question must refuse any other.
    #[must_use]
    pub fn question(&self) -> QuestionV1 {
        self.question
    }

    #[must_use]
    pub fn correspondence_id(&self) -> &str {
        &self.correspondence_id
    }

    #[must_use]
    pub fn acquisition_id(&self) -> &str {
        &self.acquisition_id
    }

    /// The exact Pulse supporting-evidence reference of the sealed frame.
    #[must_use]
    pub fn evidence_ref(&self) -> &str {
        &self.evidence_ref
    }

    #[must_use]
    pub fn artifact_id(&self) -> &str {
        &self.artifact_id
    }

    /// The certificate observed immediately after delivery. A later
    /// certificate for the same consumer may name a later frame; consumers
    /// must check the live certificate, not this value alone.
    #[must_use]
    pub fn certificate_id(&self) -> &str {
        &self.certificate_id
    }

    #[must_use]
    pub fn profile_digest(&self) -> &str {
        &self.profile_digest
    }

    #[must_use]
    pub fn subject(&self) -> &SubjectId {
        &self.subject
    }

    #[must_use]
    pub fn subject_incarnation(&self) -> &IncarnationId {
        &self.subject_incarnation
    }

    /// NQ's detector outcome, carried unchanged.
    #[must_use]
    pub fn nq_detector_state(&self) -> NqDetectorStateV1 {
        self.nq_detector_state
    }

    /// The owner's typed reason for a `cannot_evaluate`, when NQ carried one.
    /// `None` for every other state and for a malformed detail. The owning
    /// profile is this correspondence's question. It explains why the
    /// condition could not be evaluated and never changes the state.
    #[must_use]
    pub fn owner_failure(&self) -> Option<&OwnerFailureV1> {
        self.owner_failure.as_ref()
    }

    #[must_use]
    pub fn delivery(&self) -> DeliveryMeasurementV1 {
        self.delivery
    }

    /// Process-local seal instant. It is not a wall-clock time and never
    /// crosses a process boundary.
    #[must_use]
    pub fn sealed_at(&self) -> Instant {
        self.sealed_at
    }
}
