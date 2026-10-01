//! Lifetime law, reactor ingress, and the V11 certificate binding.
//!
//! The co-producer measures the frame's holding delay `d` from the seal
//! instant to the moment the frame enters the reactor, and the ingress fence
//! `f` from that moment to the reactor's return. Pulse subtracts `d` from the
//! frame validity `V`, so the certificate can never outlive `t0 + V + F + 1 =
//! t0 + R`, NQ's own reliance window measured from before the acquisition.

use std::time::Instant;

use pulse_runtime::{LocalCrashReactor, PulseIngressV1, RuntimeInputV1};
use pulse_types::{
    AuthenticationResultV1, IncarnationId, JudgmentCategoryV1, PulseFrameV1,
    RelianceSupportCertificateV1,
};

use crate::{
    CorrespondenceError, CorrespondenceProfileV1, INGRESS_DISCLOSURE, INGRESS_FENCE_MS, QuestionV1,
    SealedOccurrenceV1,
};

/// Measured delivery intervals for one occurrence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryMeasurementV1 {
    pub holding_delay_ms: u64,
    pub ingress_fence_ms: u64,
}

/// Ceiling of an elapsed interval in milliseconds. Rounding up shortens the
/// window Pulse grants; it never lengthens it.
#[must_use]
pub fn elapsed_ceil_ms(from: Instant, to: Instant) -> u64 {
    let nanos = to.saturating_duration_since(from).as_nanos();
    u64::try_from(nanos.saturating_add(999_999) / 1_000_000).unwrap_or(u64::MAX)
}

/// `d < V` for load v1 only; every other caller uses
/// [`check_holding_delay_for`].
pub fn check_holding_delay(holding_delay_ms: u64) -> Result<(), CorrespondenceError> {
    check_holding_delay_for(QuestionV1::HostLoadPressureV1, holding_delay_ms)
}

/// `d < V`: a frame held for its whole validity is not delivered.
pub fn check_holding_delay_for(
    question: QuestionV1,
    holding_delay_ms: u64,
) -> Result<(), CorrespondenceError> {
    let validity_ms = question.frame_validity_ms();
    if holding_delay_ms >= validity_ms {
        return Err(CorrespondenceError::new(
            "holding_delay_exceeds_validity",
            format!("frame was held {holding_delay_ms} ms, not below {validity_ms} ms"),
        ));
    }
    Ok(())
}

/// `f <= F`: a reactor return slower than the fence yields audit only.
pub fn check_ingress_fence(ingress_fence_ms: u64) -> Result<(), CorrespondenceError> {
    if ingress_fence_ms > INGRESS_FENCE_MS {
        return Err(CorrespondenceError::new(
            "ingress_fence_exceeded",
            format!("reactor ingress took {ingress_fence_ms} ms, above {INGRESS_FENCE_MS} ms"),
        ));
    }
    Ok(())
}

/// The load v1 ingress record only; every other caller uses
/// [`frame_ingress_for`]. Submitting another question's frame through this
/// path would name the load transport path.
#[must_use]
pub fn frame_ingress(frame: PulseFrameV1, holding_delay_ms: u64) -> RuntimeInputV1 {
    frame_ingress_for(QuestionV1::HostLoadPressureV1, frame, holding_delay_ms)
}

/// The exact ingress record: the question's fixed transport path, measured
/// holding delay, and an unauthenticated disclosure. Nothing here is a Pulse
/// assessment.
#[must_use]
pub fn frame_ingress_for(
    question: QuestionV1,
    frame: PulseFrameV1,
    holding_delay_ms: u64,
) -> RuntimeInputV1 {
    RuntimeInputV1::Pulse(PulseIngressV1 {
        frame,
        transport_path: question.spec().transport_path.to_owned(),
        transport_observed_delay_ms: Some(holding_delay_ms),
        authentication: AuthenticationResultV1::Unauthenticated {
            disclosure: INGRESS_DISCLOSURE.to_owned(),
        },
    })
}

/// V11 (certificate part): the consumer's certificate is `CURRENT`, lists
/// exactly the frame's evidence reference, carries the frame's subject
/// incarnation, and leaves no more than `V - d` of support after evaluation.
pub fn verify_certificate_binding(
    certificate: &RelianceSupportCertificateV1,
    profile: &CorrespondenceProfileV1,
    evidence_ref: &str,
    subject_incarnation: &IncarnationId,
    holding_delay_ms: u64,
) -> Result<(), CorrespondenceError> {
    certificate
        .validate()
        .map_err(|error| CorrespondenceError::new("invalid_certificate", error.to_string()))?;
    let question = profile.question()?;
    if certificate.consumer != profile.consumer()
        || certificate.subject_scope.subject != profile.subject()
        || certificate.subject_scope.scope != question.spec().pulse_scope
    {
        return Err(CorrespondenceError::new(
            "certificate_binding_mismatch",
            "certificate consumer, subject, or scope differs from the profile",
        ));
    }
    if &certificate.subject_scope.subject_incarnation != subject_incarnation {
        return Err(CorrespondenceError::new(
            "certificate_incarnation_mismatch",
            "certificate subject incarnation differs from the sealed frame",
        ));
    }
    if certificate.supporting_evidence_ids != [evidence_ref.to_owned()] {
        return Err(CorrespondenceError::new(
            "certificate_evidence_mismatch",
            "certificate does not list exactly the sealed frame as supporting evidence",
        ));
    }
    if certificate.judgment != JudgmentCategoryV1::Current
        || !certificate.missing_premises.is_empty()
        || !certificate.applicable_contradictions.is_empty()
    {
        return Err(CorrespondenceError::new(
            "certificate_not_current",
            "certificate is not contradiction-free CURRENT support",
        ));
    }
    let Some(expiry) = certificate.earliest_support_expiry_monotonic_ms else {
        return Err(CorrespondenceError::new(
            "certificate_not_current",
            "CURRENT certificate has no support expiry",
        ));
    };
    let remaining = expiry.saturating_sub(certificate.evaluated_at_monotonic_ms);
    let permitted = question
        .frame_validity_ms()
        .saturating_sub(holding_delay_ms);
    if remaining == 0 || remaining > permitted {
        return Err(CorrespondenceError::new(
            "certificate_window_exceeds_law",
            format!(
                "certificate leaves {remaining} ms but the lifetime law permits at most {permitted} ms"
            ),
        ));
    }
    Ok(())
}

/// Deliver one sealed frame to the in-process reactor and measure both
/// intervals. Returns the measurement and the certificate observed after
/// ingress; the caller applies [`verify_certificate_binding`].
pub(crate) fn deliver(
    reactor: &LocalCrashReactor,
    question: QuestionV1,
    occurrence: &SealedOccurrenceV1,
) -> Result<DeliveryMeasurementV1, CorrespondenceError> {
    let delivered_at = Instant::now();
    let holding_delay_ms = elapsed_ceil_ms(occurrence.sealed_at, delivered_at);
    check_holding_delay_for(question, holding_delay_ms)?;
    reactor
        .submit_input(frame_ingress_for(
            question,
            occurrence.frame.clone(),
            holding_delay_ms,
        ))
        .map_err(|error| CorrespondenceError::new("reactor_refused", error.to_string()))?;
    let returned_at = Instant::now();
    Ok(DeliveryMeasurementV1 {
        holding_delay_ms,
        ingress_fence_ms: elapsed_ceil_ms(delivered_at, returned_at),
    })
}

/// Find the certificate for the profile's consumer, subject, and scope in a
/// reactor snapshot.
pub(crate) fn consumer_certificate(
    reactor: &LocalCrashReactor,
    profile: &CorrespondenceProfileV1,
) -> Result<RelianceSupportCertificateV1, CorrespondenceError> {
    let scope = profile.question()?.spec().pulse_scope;
    let snapshot = reactor.snapshot();
    if !snapshot.condition.exposes_live_standing() {
        return Err(CorrespondenceError::new(
            "reactor_not_operational",
            format!("reactor condition is {:?}", snapshot.condition),
        ));
    }
    snapshot
        .certificates
        .into_iter()
        .find(|certificate| {
            certificate.consumer == profile.consumer()
                && certificate.subject_scope.subject == profile.subject()
                && certificate.subject_scope.scope == scope
        })
        .ok_or_else(|| {
            CorrespondenceError::new(
                "certificate_missing",
                "reactor holds no certificate for the correspondence consumer",
            )
        })
}
