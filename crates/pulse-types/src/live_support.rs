use serde::{Deserialize, Serialize};

use crate::{
    ClockId, ConsumerId, DigestV1, IncarnationId, LivePresentSupportNonce, MutationAuthorityV1,
    ReceiverId, RelianceContextV1, RuntimeTypeError, SubjectScopeV1, SupportCertificateId,
    digest_parts,
};

pub const LIVE_PRESENT_SUPPORT_REQUEST_SCHEMA_V1: &str = "pulse.live_present_support_request.v1";
pub const LIVE_PRESENT_SUPPORT_RESPONSE_SCHEMA_V1: &str = "pulse.live_present_support_response.v1";
pub const LIVE_PRESENT_SUPPORT_NONAUTHORITY_V1: &str = "This response reports one bounded present-reliance measurement. It grants no authority and does not refresh, extend, or persist support.";
pub const MAX_LIVE_PRESENT_SUPPORT_REQUEST_BYTES: usize = 16 * 1_024;
pub const MAX_LIVE_PRESENT_SUPPORT_RESPONSE_BYTES: usize = 32 * 1_024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LivePresentSupportRequestV1 {
    pub schema: String,
    pub request_nonce: LivePresentSupportNonce,
    pub consumer: ConsumerId,
    pub subject_scope: SubjectScopeV1,
    pub reliance_context: RelianceContextV1,
    pub reliance_context_digest: DigestV1,
    pub support_certificate_id: SupportCertificateId,
    pub evidence_window_id: crate::EvidenceWindowId,
    pub qualified_generation_digest: DigestV1,
    pub receiver: ReceiverId,
    pub receiver_incarnation: IncarnationId,
    pub receiver_epoch_id: IncarnationId,
    pub receiver_clock_id: ClockId,
}

impl LivePresentSupportRequestV1 {
    pub fn validate(&self) -> Result<(), RuntimeTypeError> {
        if self.schema != LIVE_PRESENT_SUPPORT_REQUEST_SCHEMA_V1 {
            return Err(RuntimeTypeError::new(
                "unsupported_schema",
                "live present-support request schema is unsupported",
            ));
        }
        self.request_nonce
            .validate()
            .map_err(|_| RuntimeTypeError::new("invalid_identity", "invalid request nonce"))?;
        self.consumer
            .validate()
            .map_err(|_| RuntimeTypeError::new("invalid_identity", "invalid consumer"))?;
        self.subject_scope
            .validate()
            .map_err(|_| RuntimeTypeError::new("invalid_identity", "invalid subject scope"))?;
        self.reliance_context.validate()?;
        self.reliance_context_digest.validate().map_err(|_| {
            RuntimeTypeError::new("invalid_digest", "invalid reliance context digest")
        })?;
        if self.reliance_context_digest != self.reliance_context.identity_digest() {
            return Err(RuntimeTypeError::new(
                "identity_mismatch",
                "reliance context digest does not identify the exact context",
            ));
        }
        self.support_certificate_id.validate().map_err(|_| {
            RuntimeTypeError::new("invalid_identity", "invalid support certificate identity")
        })?;
        self.evidence_window_id.validate().map_err(|_| {
            RuntimeTypeError::new("invalid_identity", "invalid evidence window identity")
        })?;
        self.qualified_generation_digest.validate().map_err(|_| {
            RuntimeTypeError::new("invalid_digest", "invalid qualified generation digest")
        })?;
        self.receiver
            .validate()
            .map_err(|_| RuntimeTypeError::new("invalid_identity", "invalid receiver"))?;
        self.receiver_incarnation.validate().map_err(|_| {
            RuntimeTypeError::new("invalid_identity", "invalid receiver incarnation")
        })?;
        self.receiver_epoch_id.validate().map_err(|_| {
            RuntimeTypeError::new("invalid_identity", "invalid receiver epoch identity")
        })?;
        self.receiver_clock_id.validate().map_err(|_| {
            RuntimeTypeError::new("invalid_identity", "invalid receiver clock identity")
        })?;
        Ok(())
    }

    #[must_use]
    pub fn identity_digest(&self) -> DigestV1 {
        let context_digest = self.reliance_context.identity_digest();
        digest_parts(
            "pulse.live-present-support.request.v1",
            &[
                self.schema.as_bytes(),
                self.request_nonce.as_str().as_bytes(),
                self.consumer.as_str().as_bytes(),
                self.subject_scope.subject.as_str().as_bytes(),
                self.subject_scope.subject_incarnation.as_str().as_bytes(),
                self.subject_scope.scope.as_bytes(),
                context_digest.as_str().as_bytes(),
                self.support_certificate_id.as_str().as_bytes(),
                self.evidence_window_id.as_str().as_bytes(),
                self.qualified_generation_digest.as_str().as_bytes(),
                self.receiver.as_str().as_bytes(),
                self.receiver_incarnation.as_str().as_bytes(),
                self.receiver_epoch_id.as_str().as_bytes(),
                self.receiver_clock_id.as_str().as_bytes(),
            ],
        )
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate().map_err(|error| error.to_string())?;
        serde_jcs::to_vec(self).map_err(|error| error.to_string())
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, String> {
        let value: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        value.validate().map_err(|error| error.to_string())?;
        if value.canonical_bytes()? != bytes {
            return Err("live present-support request is not canonical JSON".to_owned());
        }
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LivePresentSupportDispositionV1 {
    SupportedCurrent,
    Expired,
    Unsupported,
    Indeterminate,
}

impl LivePresentSupportDispositionV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SupportedCurrent => "supported_current",
            Self::Expired => "expired",
            Self::Unsupported => "unsupported",
            Self::Indeterminate => "indeterminate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LivePresentSupportMeasurementV1 {
    ActorSerializedAfterRunUntil,
}

impl LivePresentSupportMeasurementV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ActorSerializedAfterRunUntil => "actor_serialized_after_run_until",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LivePresentSupportResponseV1 {
    pub schema: String,
    pub response_digest: DigestV1,
    pub request_digest: DigestV1,
    pub request: LivePresentSupportRequestV1,
    pub receiver: ReceiverId,
    pub receiver_incarnation: IncarnationId,
    pub receiver_epoch_id: IncarnationId,
    pub receiver_clock_id: ClockId,
    pub receiver_clock_source: String,
    pub measured_at_receiver_monotonic_ms: u64,
    pub measurement: LivePresentSupportMeasurementV1,
    pub disposition: LivePresentSupportDispositionV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining_lifetime_ms_at_response: Option<u64>,
    pub source_rounding_margin_ms: u64,
    pub mutation_authority: MutationAuthorityV1,
    pub non_authorization: String,
}

impl LivePresentSupportResponseV1 {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        request: LivePresentSupportRequestV1,
        receiver: ReceiverId,
        receiver_incarnation: IncarnationId,
        receiver_epoch_id: IncarnationId,
        receiver_clock_id: ClockId,
        receiver_clock_source: String,
        measured_at_receiver_monotonic_ms: u64,
        disposition: LivePresentSupportDispositionV1,
        remaining_lifetime_ms_at_response: Option<u64>,
    ) -> Self {
        let request_digest = request.identity_digest();
        let mut response = Self {
            schema: LIVE_PRESENT_SUPPORT_RESPONSE_SCHEMA_V1.to_owned(),
            response_digest: digest_parts("pulse.live-present-support.pending.v1", &[b"pending"]),
            request_digest,
            request,
            receiver,
            receiver_incarnation,
            receiver_epoch_id,
            receiver_clock_id,
            receiver_clock_source,
            measured_at_receiver_monotonic_ms,
            measurement: LivePresentSupportMeasurementV1::ActorSerializedAfterRunUntil,
            disposition,
            remaining_lifetime_ms_at_response,
            source_rounding_margin_ms: 1,
            mutation_authority: MutationAuthorityV1::None,
            non_authorization: LIVE_PRESENT_SUPPORT_NONAUTHORITY_V1.to_owned(),
        };
        response.response_digest = response.compute_digest();
        response
    }

    #[must_use]
    pub fn compute_digest(&self) -> DigestV1 {
        let remaining = self
            .remaining_lifetime_ms_at_response
            .map_or_else(|| b"none".to_vec(), |value| value.to_be_bytes().to_vec());
        digest_parts(
            "pulse.live-present-support.response.v1",
            &[
                self.schema.as_bytes(),
                self.request_digest.as_str().as_bytes(),
                self.receiver.as_str().as_bytes(),
                self.receiver_incarnation.as_str().as_bytes(),
                self.receiver_epoch_id.as_str().as_bytes(),
                self.receiver_clock_id.as_str().as_bytes(),
                self.receiver_clock_source.as_bytes(),
                &self.measured_at_receiver_monotonic_ms.to_be_bytes(),
                self.measurement.as_str().as_bytes(),
                self.disposition.as_str().as_bytes(),
                &remaining,
                &self.source_rounding_margin_ms.to_be_bytes(),
                b"mutation_authority:none",
                self.non_authorization.as_bytes(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), RuntimeTypeError> {
        if self.schema != LIVE_PRESENT_SUPPORT_RESPONSE_SCHEMA_V1 {
            return Err(RuntimeTypeError::new(
                "unsupported_schema",
                "live present-support response schema is unsupported",
            ));
        }
        self.request.validate()?;
        if self.request_digest != self.request.identity_digest() {
            return Err(RuntimeTypeError::new(
                "request_identity_mismatch",
                "response request digest does not identify its echoed request",
            ));
        }
        for identity in [
            self.receiver.as_str(),
            self.receiver_incarnation.as_str(),
            self.receiver_epoch_id.as_str(),
            self.receiver_clock_id.as_str(),
        ] {
            if identity.is_empty() || identity.len() > crate::MAX_IDENTITY_BYTES {
                return Err(RuntimeTypeError::new(
                    "invalid_identity",
                    "response receiver lineage identity is invalid",
                ));
            }
        }
        if self.receiver_clock_source.is_empty()
            || self.receiver_clock_source.len() > crate::MAX_IDENTITY_BYTES
            || self.receiver_clock_source.chars().any(char::is_control)
        {
            return Err(RuntimeTypeError::new(
                "invalid_clock_source",
                "response receiver clock source is invalid",
            ));
        }
        let lifetime_is_valid = match self.disposition {
            LivePresentSupportDispositionV1::SupportedCurrent => self
                .remaining_lifetime_ms_at_response
                .is_some_and(|value| value > 0),
            _ => self.remaining_lifetime_ms_at_response.is_none(),
        };
        if !lifetime_is_valid {
            return Err(RuntimeTypeError::new(
                "invalid_remaining_lifetime",
                "only supported-current may carry a nonzero remaining lifetime",
            ));
        }
        if self.source_rounding_margin_ms != 1
            || self.mutation_authority != MutationAuthorityV1::None
            || self.non_authorization != LIVE_PRESENT_SUPPORT_NONAUTHORITY_V1
        {
            return Err(RuntimeTypeError::new(
                "invalid_nonclaim",
                "response does not preserve the fixed v1 time margin and authority boundary",
            ));
        }
        if self.response_digest != self.compute_digest() {
            return Err(RuntimeTypeError::new(
                "response_identity_mismatch",
                "response digest does not identify the exact response",
            ));
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        request: &LivePresentSupportRequestV1,
    ) -> Result<(), RuntimeTypeError> {
        self.validate()?;
        request.validate()?;
        if &self.request != request || self.request_digest != request.identity_digest() {
            return Err(RuntimeTypeError::new(
                "request_substitution",
                "response does not bind the exact outstanding request",
            ));
        }
        if self.receiver != request.receiver
            || self.receiver_incarnation != request.receiver_incarnation
            || self.receiver_epoch_id != request.receiver_epoch_id
            || self.receiver_clock_id != request.receiver_clock_id
        {
            return Err(RuntimeTypeError::new(
                "source_lineage_mismatch",
                "response source lineage does not match the requested live receiver",
            ));
        }
        Ok(())
    }

    /// Conservative lifetime on the caller's clock. `elapsed_since_send_ms`
    /// starts before request transmission and therefore includes request
    /// transit, source processing, response transit, and any later local wait.
    #[must_use]
    pub fn conservative_remaining_lifetime_ms(&self, elapsed_since_send_ms: u64) -> Option<u64> {
        if self.disposition != LivePresentSupportDispositionV1::SupportedCurrent {
            return None;
        }
        self.remaining_lifetime_ms_at_response
            .and_then(|remaining| remaining.checked_sub(elapsed_since_send_ms))
            .filter(|remaining| *remaining > 0)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate().map_err(|error| error.to_string())?;
        serde_jcs::to_vec(self).map_err(|error| error.to_string())
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, String> {
        let value: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        value.validate().map_err(|error| error.to_string())?;
        if value.canonical_bytes()? != bytes {
            return Err("live present-support response is not canonical JSON".to_owned());
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ConsumerProfileGenerationId, ContextActivationId, EvaluatorSemanticGenerationId,
        EvidenceWindowId, ObservationPolicyGenerationId, ObserverSetGenerationId,
        PolicyGenerationId, SubjectId,
    };

    fn request(nonce: &str) -> LivePresentSupportRequestV1 {
        let context = RelianceContextV1 {
            schema_version: 1,
            activation_id: ContextActivationId::new("activation:one"),
            reliance_policy_generation: PolicyGenerationId::new("policy:one"),
            reliance_policy_semantic_digest: digest_parts("policy", &[b"one"]),
            consumer_profile_generation: ConsumerProfileGenerationId::new("profile:one"),
            evaluator_semantic_generation: EvaluatorSemanticGenerationId::new("evaluator:one"),
            observer_set_generation: ObserverSetGenerationId::new("observers:one"),
            observation_policy_generation: ObservationPolicyGenerationId::new(
                "observation-policy:one",
            ),
        };
        LivePresentSupportRequestV1 {
            schema: LIVE_PRESENT_SUPPORT_REQUEST_SCHEMA_V1.to_owned(),
            request_nonce: LivePresentSupportNonce::new(nonce),
            consumer: ConsumerId::new("consumer:one"),
            subject_scope: SubjectScopeV1 {
                subject: SubjectId::new("subject:one"),
                subject_incarnation: IncarnationId::new("subject-incarnation:one"),
                scope: "scope:one".to_owned(),
            },
            reliance_context_digest: context.identity_digest(),
            reliance_context: context,
            support_certificate_id: SupportCertificateId::new("support:one"),
            evidence_window_id: EvidenceWindowId::new("evidence-window:one"),
            qualified_generation_digest: digest_parts("binding", &[b"one"]),
            receiver: ReceiverId::new("receiver:one"),
            receiver_incarnation: IncarnationId::new("receiver-incarnation:one"),
            receiver_epoch_id: IncarnationId::new("receiver-epoch:one"),
            receiver_clock_id: ClockId::new("clock:one"),
        }
    }

    fn response(request: LivePresentSupportRequestV1) -> LivePresentSupportResponseV1 {
        LivePresentSupportResponseV1::new(
            request,
            ReceiverId::new("receiver:one"),
            IncarnationId::new("receiver-incarnation:one"),
            IncarnationId::new("receiver-epoch:one"),
            ClockId::new("clock:one"),
            "std::time::Instant/process-local".to_owned(),
            10,
            LivePresentSupportDispositionV1::SupportedCurrent,
            Some(89),
        )
    }

    #[test]
    fn canonical_round_trip_is_exact() {
        let response = response(request("nonce:one"));
        let bytes = response.canonical_bytes().expect("canonical response");
        assert_eq!(
            LivePresentSupportResponseV1::decode_canonical(&bytes).expect("round trip"),
            response
        );
    }

    #[test]
    fn exact_request_binding_rejects_nonce_substitution() {
        let original = request("nonce:one");
        let response = response(original.clone());
        response
            .validate_against(&original)
            .expect("exact request accepted");
        assert!(response.validate_against(&request("nonce:two")).is_err());
    }

    #[test]
    fn elapsed_time_only_reduces_lifetime() {
        let response = response(request("nonce:one"));
        assert_eq!(response.conservative_remaining_lifetime_ms(0), Some(89));
        assert_eq!(response.conservative_remaining_lifetime_ms(88), Some(1));
        assert_eq!(response.conservative_remaining_lifetime_ms(89), None);
        assert_eq!(response.conservative_remaining_lifetime_ms(100), None);
    }

    #[test]
    fn canonical_decoders_reject_extensions_and_noncanonical_bytes() {
        let request = request("nonce:one");
        let mut request_bytes = request.canonical_bytes().expect("canonical request");
        request_bytes.push(b'\n');
        assert!(LivePresentSupportRequestV1::decode_canonical(&request_bytes).is_err());

        let response = response(request);
        let text = String::from_utf8(response.canonical_bytes().expect("canonical response"))
            .expect("json is utf8");
        let extended = text.replacen('{', "{\"unexpected\":true,", 1);
        assert!(LivePresentSupportResponseV1::decode_canonical(extended.as_bytes()).is_err());
    }
}
