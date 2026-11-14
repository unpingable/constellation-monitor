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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AvailabilityV1, ImpactV1, ProjectedStateV1, ProjectionMomentV1, ProjectionPolicyV1,
        SOURCE_FACT_SCHEMA_V1, SourceFactClassV1, SourceFactV1, project,
    };
    use pulse_types::{
        AuthorityGrantsV1, ClockId, ConsumerId, ConsumerProfileGenerationId, ContextActivationId,
        CoverageSummaryV1, EscalationStateV1, EvaluatorSemanticGenerationId, EvidenceWindowId,
        IncarnationId, JudgmentCategoryV1, LIVE_PRESENT_SUPPORT_REQUEST_SCHEMA_V1,
        LivePresentSupportDispositionV1, LivePresentSupportNonce, LivePresentSupportRequestV1,
        LivePresentSupportResponseV1, ObservationPolicyGenerationId, ObserverSetGenerationId,
        PolicyGenerationId, QualifiedGenerationBindingV1, QualifiedGenerationSetV1, ReceiverId,
        RelianceContextV1, RelianceSupportCertificateV1, SCHEMA_VERSION_V1, SubjectId,
        SubjectScopeV1, SupportCertificateId, digest_parts,
    };

    const NOW: u64 = 1_900_000_000_000;

    #[test]
    fn reusing_one_live_observation_never_moves_its_absolute_presentation_deadline() {
        let mut policy: ProjectionPolicyV1 = serde_json::from_str(include_str!(
            "../fixtures/synthetic-public-reduction.policy.json"
        ))
        .unwrap();
        policy.timestamp_granularity_ms = 1;
        policy.admitted_clock_uncertainty_ms = 0;
        let facts = vec![
            fact(
                "fact.synthetic.dependency",
                "synthetic.dependency",
                "evidence:subordinate",
                AvailabilityV1::Available,
                ImpactV1::None,
            ),
            fact(
                "fact.synthetic.service",
                "synthetic.service",
                "evidence:service",
                AvailabilityV1::Available,
                ImpactV1::None,
            ),
        ];
        // The Instant is only an origin: no subsequent real clock reads or
        // sleeps participate in admission, projection or either assertion.
        let admitted_at = Instant::now();
        let moment = |offset_ms| ProjectionMomentV1 {
            generated_at_unix_ms: NOW + offset_ms,
            monotonic_now: admitted_at + Duration::from_millis(offset_ms),
        };
        let support = vec![
            live_support_at("evidence:service", 30_000, admitted_at),
            live_support_at("evidence:subordinate", 30_000, admitted_at),
        ];
        let first = project(&policy, &facts, &support, &[], moment(0)).unwrap();
        let later = project(&policy, &facts, &support, &[], moment(5)).unwrap();
        assert_eq!(first.aggregate_state, ProjectedStateV1::Healthy);
        assert_eq!(later.aggregate_state, ProjectedStateV1::Healthy);
        assert_eq!(first.fresh_until_unix_ms, NOW + 30_000);
        assert_eq!(first.fresh_until_unix_ms, later.fresh_until_unix_ms);

        let short_support = vec![
            live_support_at("evidence:service", 5, admitted_at),
            live_support_at("evidence:subordinate", 5, admitted_at),
        ];
        let initially_live = project(&policy, &facts, &short_support, &[], moment(0)).unwrap();
        assert_eq!(initially_live.aggregate_state, ProjectedStateV1::Healthy);
        assert_eq!(initially_live.fresh_until_unix_ms, NOW + 5);
        for offset_ms in [5, 10] {
            let expired = project(&policy, &facts, &short_support, &[], moment(offset_ms)).unwrap();
            assert_eq!(expired.aggregate_state, ProjectedStateV1::Unknown);
            assert_eq!(expired.generated_at_unix_ms, expired.fresh_until_unix_ms);
        }
    }

    #[test]
    fn faster_new_query_can_extend_local_bound_without_renewing_source_support() {
        // Drop the invalid ordering constraint between independently anchored
        // conservative intervals. Receiver expiry is fixed at relative D = 1000;
        // the fixture's receiver clock starts at 10000. Source responses deduct
        // their existing 1 ms rounding margin; each caller deducts its own RTT.
        let (request, _, certificate) = live_exchange("evidence:service", 999);
        let original_certificate = certificate.clone();
        assert_eq!(
            certificate.earliest_support_expiry_monotonic_ms,
            Some(11_000)
        );
        let origin = Instant::now();
        let response_at = |measured_at, remaining| {
            LivePresentSupportResponseV1::new(
                request.clone(),
                request.receiver.clone(),
                request.receiver_incarnation.clone(),
                request.receiver_epoch_id.clone(),
                request.receiver_clock_id.clone(),
                "std::time::Instant/process-local".to_owned(),
                measured_at,
                LivePresentSupportDispositionV1::SupportedCurrent,
                Some(remaining),
            )
        };
        // First: send 0, source measurement 20, admission 25. Second: send 30,
        // source measurement 31, admission 35. These are two fresh responses
        // for the same certificate, not re-admission of a retained response.
        let first_response = response_at(10_020, 979);
        let second_response = response_at(10_031, 968);
        let first = LiveSupportObservationV1::from_live_exchange_at(
            &request,
            &first_response,
            &certificate,
            "evidence:service",
            25,
            120_000,
            origin + Duration::from_millis(25),
        )
        .unwrap();
        let second = LiveSupportObservationV1::from_live_exchange_at(
            &request,
            &second_response,
            &certificate,
            "evidence:service",
            5,
            120_000,
            origin + Duration::from_millis(35),
        )
        .unwrap();
        let common_now = origin + Duration::from_millis(35);
        assert_eq!(first.usable_remaining_ms_at(common_now), Some(944));
        assert_eq!(second.usable_remaining_ms_at(common_now), Some(963));
        assert_eq!(first.expires_at, origin + Duration::from_millis(979));
        assert_eq!(second.expires_at, origin + Duration::from_millis(998));
        assert_ne!(first.response_digest(), second.response_digest());
        assert_eq!(first.certificate_id(), second.certificate_id());
        assert_eq!(certificate, original_certificate);

        let mut policy: ProjectionPolicyV1 = serde_json::from_str(include_str!(
            "../fixtures/synthetic-public-reduction.policy.json"
        ))
        .unwrap();
        policy.timestamp_granularity_ms = 1;
        policy.admitted_clock_uncertainty_ms = 0;
        policy.dependencies.clear();
        policy
            .components
            .retain(|component| component.key == "synthetic.service");
        let facts = [fact(
            "fact.synthetic.service",
            "synthetic.service",
            "evidence:service",
            AvailabilityV1::Available,
            ImpactV1::None,
        )];
        let moment = |offset_ms| ProjectionMomentV1 {
            generated_at_unix_ms: NOW + offset_ms,
            monotonic_now: origin + Duration::from_millis(offset_ms),
        };
        for (live, deadline_ms) in [(&first, 979), (&second, 998)] {
            assert!(live.expires_at <= origin + Duration::from_millis(1_000));
            let fresh =
                project(&policy, &facts, std::slice::from_ref(live), &[], moment(35)).unwrap();
            assert_eq!(fresh.aggregate_state, ProjectedStateV1::Healthy);
            assert_eq!(fresh.fresh_until_unix_ms, NOW + deadline_ms);
            assert_eq!(
                live.usable_remaining_ms_at(moment(1_000).monotonic_now),
                None
            );
            let expired = project(
                &policy,
                &facts,
                std::slice::from_ref(live),
                &[],
                moment(1_000),
            )
            .unwrap();
            assert_eq!(expired.aggregate_state, ProjectedStateV1::Unknown);
            assert_eq!(expired.generated_at_unix_ms, expired.fresh_until_unix_ms);
        }
    }

    // Same typed synthetic exchange as the integration fixture, admitted
    // through the existing private constructor with controlled timing.
    fn live_support_at(
        evidence: &str,
        remaining_ms: u64,
        admitted_at: Instant,
    ) -> LiveSupportObservationV1 {
        let (request, response, certificate) = live_exchange(evidence, remaining_ms);
        LiveSupportObservationV1::from_live_exchange_at(
            &request,
            &response,
            &certificate,
            evidence,
            0,
            120_000,
            admitted_at,
        )
        .expect("valid synthetic live-support exchange at fixed admission instant")
    }

    fn live_exchange(
        evidence: &str,
        remaining_ms: u64,
    ) -> (
        LivePresentSupportRequestV1,
        LivePresentSupportResponseV1,
        RelianceSupportCertificateV1,
    ) {
        let context = support_context();
        let consumer = support_consumer();
        let subject_scope = support_subject_scope();
        let qualified_generation = support_binding(&context, &consumer, &subject_scope);
        let measured_at = 10_000;
        let mut certificate = RelianceSupportCertificateV1 {
            schema_version: SCHEMA_VERSION_V1,
            certificate_id: SupportCertificateId::new("pending"),
            consumer: consumer.clone(),
            subject_scope: subject_scope.clone(),
            context: context.clone(),
            qualified_generation: Some(qualified_generation.clone()),
            evaluated_at_monotonic_ms: measured_at,
            receiver_clock_id: "clock:status-projection".to_owned(),
            judgment: JudgmentCategoryV1::Current,
            evidence_window_id: EvidenceWindowId::new("window:status-projection"),
            supporting_evidence_ids: vec![evidence.to_owned()],
            remote_observation_custody: Vec::new(),
            missing_premises: Vec::new(),
            applicable_contradictions: Vec::new(),
            coverage: CoverageSummaryV1 {
                required: vec!["service".to_owned()],
                active: vec!["service".to_owned()],
                missing: Vec::new(),
                expired: Vec::new(),
                active_observers: 1,
                required_observers: 1,
                per_tag: Vec::new(),
            },
            earliest_support_expiry_monotonic_ms: Some(measured_at + remaining_ms + 1),
            next_scheduled_reevaluation_monotonic_ms: Some(measured_at + remaining_ms + 1),
            escalation: EscalationStateV1::NotRequested,
            mutation_authority: pulse_types::MutationAuthorityV1::None,
        };
        certificate.certificate_id = certificate.compute_id();
        let request = LivePresentSupportRequestV1 {
            schema: LIVE_PRESENT_SUPPORT_REQUEST_SCHEMA_V1.to_owned(),
            request_nonce: LivePresentSupportNonce::new(format!("nonce:{evidence}")),
            consumer,
            subject_scope,
            reliance_context_digest: context.identity_digest(),
            reliance_context: context,
            support_certificate_id: certificate.certificate_id.clone(),
            evidence_window_id: certificate.evidence_window_id.clone(),
            qualified_generation_digest: qualified_generation.identity_digest(),
            receiver: ReceiverId::new("receiver:status-projection"),
            receiver_incarnation: IncarnationId::new("receiver-incarnation:status-projection"),
            receiver_epoch_id: IncarnationId::new("receiver-epoch:status-projection"),
            receiver_clock_id: ClockId::new("clock:status-projection"),
        };
        let response = LivePresentSupportResponseV1::new(
            request.clone(),
            request.receiver.clone(),
            request.receiver_incarnation.clone(),
            request.receiver_epoch_id.clone(),
            request.receiver_clock_id.clone(),
            "std::time::Instant/process-local".to_owned(),
            measured_at,
            LivePresentSupportDispositionV1::SupportedCurrent,
            Some(remaining_ms),
        );
        (request, response, certificate)
    }

    fn fact(
        id: &str,
        subject: &str,
        evidence: &str,
        availability: AvailabilityV1,
        impact: ImpactV1,
    ) -> SourceFactV1 {
        SourceFactV1 {
            schema: SOURCE_FACT_SCHEMA_V1.to_owned(),
            fact_id: id.to_owned(),
            subject_key: subject.to_owned(),
            owner: "synthetic-fixture".to_owned(),
            native_schema: "synthetic.status_fact.v1".to_owned(),
            native_record_id: format!("native.{id}"),
            class: SourceFactClassV1::DerivedAdmitted,
            evidence_id: evidence.to_owned(),
            availability,
            impact,
            reason_code: "qualified-state".to_owned(),
            basis_digest: format!("sha256:{}", "a".repeat(64)),
            observed_at_unix_ms: Some(1_900_000_000_000),
        }
    }

    fn support_context() -> RelianceContextV1 {
        RelianceContextV1 {
            schema_version: SCHEMA_VERSION_V1,
            activation_id: ContextActivationId::new("activation:status-projection"),
            reliance_policy_generation: PolicyGenerationId::new("policy:status-projection"),
            reliance_policy_semantic_digest: digest_parts("policy", &[b"status-projection"]),
            consumer_profile_generation: ConsumerProfileGenerationId::new(
                "profile:status-projection",
            ),
            evaluator_semantic_generation: EvaluatorSemanticGenerationId::new(
                "evaluator:status-projection",
            ),
            observer_set_generation: ObserverSetGenerationId::new("observers:status-projection"),
            observation_policy_generation: ObservationPolicyGenerationId::new(
                "observation-policy:status-projection",
            ),
        }
    }

    fn support_consumer() -> ConsumerId {
        ConsumerId::new("consumer:status-projector")
    }

    fn support_subject_scope() -> SubjectScopeV1 {
        SubjectScopeV1 {
            subject: SubjectId::new("subject:synthetic-service"),
            subject_incarnation: IncarnationId::new("subject-incarnation:synthetic-1"),
            scope: "status-projection".to_owned(),
        }
    }

    fn support_binding(
        context: &RelianceContextV1,
        consumer: &ConsumerId,
        subject_scope: &SubjectScopeV1,
    ) -> QualifiedGenerationBindingV1 {
        QualifiedGenerationBindingV1 {
            schema_version: SCHEMA_VERSION_V1,
            manifest_digest: digest_parts("manifest", &[b"status-projection"]),
            qualification_certificate_digest: digest_parts(
                "qualification",
                &[b"status-projection"],
            ),
            activation_receipt_digest: digest_parts("activation", &[b"status-projection"]),
            activation_occurrence_id: IncarnationId::new("activation-occurrence:status-projection"),
            process_epoch_id: IncarnationId::new("process-epoch:status-projection"),
            generation_set: QualifiedGenerationSetV1::from_context(
                subject_scope.subject.clone(),
                consumer.clone(),
                context,
            ),
            authority_grants: AuthorityGrantsV1::none(),
        }
    }
}
