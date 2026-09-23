use std::time::{Duration, Instant};

use pulse_types::{
    JudgmentCategoryV1, LivePresentSupportDispositionV1, LivePresentSupportRequestV1,
    LivePresentSupportResponseV1, RelianceSupportCertificateV1,
};

use crate::{LiveSupportSelectorV1, ProjectionError};

/// Process-local timing custody for one exact live query. Create it before
/// transmission and consume it exactly once when admitting the response.
#[derive(Debug)]
pub struct LiveQueryAnchorV1 {
    request_digest: String,
    started_at: Instant,
}

impl LiveQueryAnchorV1 {
    pub fn begin(request: &LivePresentSupportRequestV1) -> Result<Self, ProjectionError> {
        request
            .validate()
            .map_err(|error| ProjectionError::new("invalid_live_request", error.to_string()))?;
        Ok(Self {
            request_digest: request.identity_digest().as_str().to_owned(),
            started_at: Instant::now(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn admit(
        self,
        request: &LivePresentSupportRequestV1,
        response: &LivePresentSupportResponseV1,
        certificate: &RelianceSupportCertificateV1,
        evidence_id: &str,
        maximum_trusted_lifetime_ms: u64,
    ) -> Result<LiveSupportObservationV1, ProjectionError> {
        if self.request_digest != request.identity_digest().as_str() {
            return Err(ProjectionError::new(
                "request_substitution",
                "live-query anchor belongs to a different request",
            ));
        }
        let admitted_at = Instant::now();
        let elapsed_nanos = admitted_at.duration_since(self.started_at).as_nanos();
        let elapsed_since_send_ms =
            u64::try_from(elapsed_nanos.saturating_add(999_999) / 1_000_000).unwrap_or(u64::MAX);
        LiveSupportObservationV1::from_live_exchange_at(
            request,
            response,
            certificate,
            evidence_id,
            elapsed_since_send_ms,
            maximum_trusted_lifetime_ms,
            admitted_at,
        )
    }
}

/// One exact Pulse result admitted for a single process-local projection
/// timeline. This type deliberately implements neither serialization nor
/// cloning. Its deadline is an `Instant`, not a durable or cross-host time.
#[derive(Debug)]
pub struct LiveSupportObservationV1 {
    evidence_id: String,
    certificate_id: String,
    response_digest: String,
    selector: LiveSupportSelectorV1,
    expires_at: Instant,
}

impl LiveSupportObservationV1 {
    /// Validate an exact live exchange at the caller's process-local admission
    /// instant. `elapsed_since_send_ms` starts before transmission and includes
    /// source processing, response transit, decoding, and all delay through
    /// `admitted_at`.
    #[allow(clippy::too_many_arguments)]
    fn from_live_exchange_at(
        request: &LivePresentSupportRequestV1,
        response: &LivePresentSupportResponseV1,
        certificate: &RelianceSupportCertificateV1,
        evidence_id: &str,
        elapsed_since_send_ms: u64,
        maximum_trusted_lifetime_ms: u64,
        admitted_at: Instant,
    ) -> Result<Self, ProjectionError> {
        request
            .validate()
            .map_err(|error| ProjectionError::new("invalid_live_request", error.to_string()))?;
        response
            .validate_against(request)
            .map_err(|error| ProjectionError::new("invalid_live_response", error.to_string()))?;
        certificate
            .validate()
            .map_err(|error| ProjectionError::new("invalid_certificate", error.to_string()))?;
        if certificate.certificate_id != certificate.compute_id()
            || certificate.certificate_id != request.support_certificate_id
            || certificate.consumer != request.consumer
            || certificate.subject_scope != request.subject_scope
            || certificate.context != request.reliance_context
            || certificate.context.identity_digest() != request.reliance_context_digest
            || certificate.evidence_window_id != request.evidence_window_id
            || certificate.receiver_clock_id != request.receiver_clock_id.as_str()
        {
            return Err(ProjectionError::new(
                "live_binding_mismatch",
                "certificate does not match the exact live request",
            ));
        }
        let Some(qualified_generation) = certificate.qualified_generation.as_ref() else {
            return Err(ProjectionError::new(
                "missing_qualification",
                "live certificate has no qualified generation",
            ));
        };
        if qualified_generation.identity_digest() != request.qualified_generation_digest {
            return Err(ProjectionError::new(
                "qualified_generation_mismatch",
                "certificate qualification does not match the request",
            ));
        }
        if response.disposition != LivePresentSupportDispositionV1::SupportedCurrent
            || certificate.judgment != JudgmentCategoryV1::Current
            || !certificate.missing_premises.is_empty()
            || !certificate.applicable_contradictions.is_empty()
        {
            return Err(ProjectionError::new(
                "no_present_support",
                "only exact contradiction-free CURRENT support can establish a bounded interval",
            ));
        }
        if response.measured_at_receiver_monotonic_ms < certificate.evaluated_at_monotonic_ms {
            return Err(ProjectionError::new(
                "invalid_source_window",
                "response measurement precedes certificate evaluation",
            ));
        }
        let source_remaining_ms = certificate
            .earliest_support_expiry_monotonic_ms
            .and_then(|deadline| deadline.checked_sub(response.measured_at_receiver_monotonic_ms))
            .filter(|remaining| *remaining > 0)
            .ok_or_else(|| {
                ProjectionError::new(
                    "invalid_source_window",
                    "certificate expiry does not leave positive support at response time",
                )
            })?;
        if response
            .remaining_lifetime_ms_at_response
            .is_none_or(|remaining| remaining > source_remaining_ms)
        {
            return Err(ProjectionError::new(
                "invalid_source_window",
                "response lifetime exceeds the exact certificate support window",
            ));
        }
        if evidence_id.is_empty()
            || !certificate
                .supporting_evidence_ids
                .iter()
                .any(|candidate| candidate == evidence_id)
        {
            return Err(ProjectionError::new(
                "evidence_mismatch",
                "fact evidence is not included in the exact support certificate",
            ));
        }
        if maximum_trusted_lifetime_ms == 0 {
            return Err(ProjectionError::new(
                "invalid_lifetime_bound",
                "maximum trusted lifetime must be positive",
            ));
        }
        let usable_remaining_ms = response
            .conservative_remaining_lifetime_ms(elapsed_since_send_ms)
            .map(|remaining| remaining.min(maximum_trusted_lifetime_ms))
            .filter(|remaining| *remaining > 0)
            .ok_or_else(|| {
                ProjectionError::new(
                    "support_expired",
                    "no positive source-owned lifetime remains after caller elapsed time",
                )
            })?;
        let expires_at = admitted_at
            .checked_add(Duration::from_millis(usable_remaining_ms))
            .ok_or_else(|| ProjectionError::new("clock_overflow", "live deadline overflow"))?;
        Ok(Self {
            evidence_id: evidence_id.to_owned(),
            certificate_id: certificate.certificate_id.as_str().to_owned(),
            response_digest: response.response_digest.as_str().to_owned(),
            selector: selector_from_request(request),
            expires_at,
        })
    }

    #[must_use]
    pub fn evidence_id(&self) -> &str {
        &self.evidence_id
    }

    #[must_use]
    pub fn usable_remaining_ms_at(&self, moment: Instant) -> Option<u64> {
        self.expires_at
            .checked_duration_since(moment)
            .and_then(|remaining| u64::try_from(remaining.as_millis()).ok())
            .filter(|remaining| *remaining > 0)
    }

    #[must_use]
    pub fn matches_selector(&self, selector: &LiveSupportSelectorV1) -> bool {
        &self.selector == selector
    }

    #[must_use]
    pub fn certificate_id(&self) -> &str {
        &self.certificate_id
    }

    #[must_use]
    pub fn response_digest(&self) -> &str {
        &self.response_digest
    }
}

fn selector_from_request(request: &LivePresentSupportRequestV1) -> LiveSupportSelectorV1 {
    LiveSupportSelectorV1 {
        consumer: request.consumer.as_str().to_owned(),
        subject: request.subject_scope.subject.as_str().to_owned(),
        subject_incarnation: request
            .subject_scope
            .subject_incarnation
            .as_str()
            .to_owned(),
        scope: request.subject_scope.scope.clone(),
        reliance_context_digest: request.reliance_context_digest.as_str().to_owned(),
        qualified_generation_digest: request.qualified_generation_digest.as_str().to_owned(),
        receiver: request.receiver.as_str().to_owned(),
        receiver_incarnation: request.receiver_incarnation.as_str().to_owned(),
        receiver_epoch_id: request.receiver_epoch_id.as_str().to_owned(),
        receiver_clock_id: request.receiver_clock_id.as_str().to_owned(),
    }
}
