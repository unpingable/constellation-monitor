#![forbid(unsafe_code)]
//! Closed-profile, non-authorizing diagnostic bridge stub.

use std::collections::BTreeMap;

use pulse_types::{
    BridgeId, ClockId, DiagnosticBoundsV1, DiagnosticEscalationRequestV1, DiagnosticProfileIdV1,
    DiagnosticReceiptId, DiagnosticReceiptStatusV1, DiagnosticResultEntryV1, DiagnosticRunId,
    DigestV1, EscalationDispositionKindV1, EscalationDispositionV1, EscalationRequestId,
    MockDiagnosticReceiptV1, MutationAuthorityV1, SCHEMA_VERSION_V1, digest_parts,
};

pub const STUB_PROFILE_NAME: &str = "local.readonly.summary";
pub const STUB_PROFILE_VERSION: u16 = 1;
pub const STUB_RECEIPT_VALIDITY_MS: u64 = 250;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeOutcome {
    pub disposition: EscalationDispositionV1,
    pub receipt: Option<MockDiagnosticReceiptV1>,
}

/// The only executable bridge in the initial slice.
///
/// It invokes no subprocess and accepts no program, argument, environment,
/// path, network target, credential, or mutation target from the request.
pub struct StubL3Bridge {
    bridge_id: BridgeId,
    clock_id: ClockId,
    profile: DiagnosticProfileIdV1,
    bounds: DiagnosticBoundsV1,
    available: bool,
    outcomes: BTreeMap<EscalationRequestId, BridgeOutcome>,
    active_deduplication: BTreeMap<DigestV1, (u64, EscalationRequestId)>,
}

impl StubL3Bridge {
    #[must_use]
    pub fn new(bridge_id: BridgeId, clock_id: ClockId) -> Self {
        Self {
            bridge_id,
            clock_id,
            profile: stub_profile_identity(),
            bounds: DiagnosticBoundsV1 {
                maximum_runtime_ms: 50,
                maximum_output_bytes: 4_096,
                maximum_observations: 8,
            },
            available: true,
            outcomes: BTreeMap::new(),
            active_deduplication: BTreeMap::new(),
        }
    }

    pub const fn set_available(&mut self, available: bool) {
        self.available = available;
    }

    #[must_use]
    pub const fn registry_bounds(&self) -> DiagnosticBoundsV1 {
        self.bounds
    }

    #[must_use]
    pub fn registry_profile(&self) -> &DiagnosticProfileIdV1 {
        &self.profile
    }

    #[must_use]
    pub fn handle(
        &mut self,
        request: &DiagnosticEscalationRequestV1,
        now_monotonic_ms: u64,
    ) -> BridgeOutcome {
        if let Some(existing) = self.outcomes.get(&request.request_id) {
            return existing.clone();
        }
        self.active_deduplication
            .retain(|_, (expiry, _)| now_monotonic_ms < *expiry);

        let outcome = if let Err(error) = request.validate() {
            self.refuse(request, now_monotonic_ms, error.code, error.detail)
        } else if request.clock_id != self.clock_id {
            self.refuse(
                request,
                now_monotonic_ms,
                "clock_mismatch",
                "bridge and request monotonic clock generations differ",
            )
        } else if now_monotonic_ms < request.created_at_monotonic_ms {
            self.refuse(
                request,
                now_monotonic_ms,
                "request_from_future",
                "bridge time precedes request creation",
            )
        } else if now_monotonic_ms >= request.expires_at_monotonic_ms {
            self.refuse(
                request,
                now_monotonic_ms,
                "request_expired",
                "diagnostic request reached inclusive expiry before execution",
            )
        } else if request.diagnostic_profile != self.profile {
            self.refuse(
                request,
                now_monotonic_ms,
                "profile_not_registered",
                "requested diagnostic profile is absent from the closed registry",
            )
        } else if let Some((_, active_request)) =
            self.active_deduplication.get(&request.deduplication_key)
        {
            self.defer(
                request,
                now_monotonic_ms,
                "equivalent_request_active",
                &format!("equivalent request {active_request} is already active"),
            )
        } else if !self.available {
            self.defer(
                request,
                now_monotonic_ms,
                "bridge_unavailable",
                "local diagnostic capacity is temporarily unavailable; expiry is unchanged",
            )
        } else if !request.bounds.fits_within(self.bounds) {
            self.narrow(request, now_monotonic_ms)
        } else {
            self.accept(request, now_monotonic_ms)
        };
        self.outcomes
            .insert(request.request_id.clone(), outcome.clone());
        if matches!(
            outcome.disposition.kind,
            EscalationDispositionKindV1::Accept { .. }
        ) {
            self.active_deduplication.insert(
                request.deduplication_key.clone(),
                (request.expires_at_monotonic_ms, request.request_id.clone()),
            );
        }
        outcome
    }

    fn accept(&self, request: &DiagnosticEscalationRequestV1, now: u64) -> BridgeOutcome {
        let completed = now.saturating_add(1);
        let results = vec![
            DiagnosticResultEntryV1 {
                name: "stub_execution".to_owned(),
                value: "completed".to_owned(),
                interpretation: "the compiled harmless local stub returned".to_owned(),
            },
            DiagnosticResultEntryV1 {
                name: "subject_scope_binding".to_owned(),
                value: format!(
                    "{}/{}",
                    request.subject_scope.subject, request.subject_scope.scope
                ),
                interpretation: "request correlation only; no subject condition inferred"
                    .to_owned(),
            },
        ];
        let result_digest = result_digest(request, &results, now, completed);
        let run_digest = digest_parts(
            "diagnostic.stub.run.v1",
            &[
                request.request_id.as_str().as_bytes(),
                &now.to_be_bytes(),
                result_digest.as_str().as_bytes(),
            ],
        );
        let run_id = DiagnosticRunId::new(format!(
            "run:{}",
            run_digest.as_str().trim_start_matches("sha256:")
        ));
        let receipt_digest = digest_parts(
            "diagnostic.stub.receipt.v1",
            &[
                run_id.as_str().as_bytes(),
                request.request_id.as_str().as_bytes(),
                result_digest.as_str().as_bytes(),
            ],
        );
        let receipt = MockDiagnosticReceiptV1 {
            schema_version: SCHEMA_VERSION_V1,
            receipt_id: DiagnosticReceiptId::new(format!(
                "receipt:{}",
                receipt_digest.as_str().trim_start_matches("sha256:")
            )),
            run_id,
            request_id: request.request_id.clone(),
            causal_transition_id: request.causal_transition_id.clone(),
            deduplication_key: request.deduplication_key.clone(),
            evidence_window_digest: request.evidence_window_digest.clone(),
            subject_scope: request.subject_scope.clone(),
            consumer: request.consumer.clone(),
            policy_generation: request.policy_generation.clone(),
            observation_policy_generation: request.observation_policy_generation.clone(),
            diagnostic_profile: request.diagnostic_profile.clone(),
            bridge_id: self.bridge_id.clone(),
            clock_id: self.clock_id.clone(),
            started_at_monotonic_ms: now,
            completed_at_monotonic_ms: completed,
            applicable_until_monotonic_ms: completed
                .saturating_add(STUB_RECEIPT_VALIDITY_MS)
                .min(request.expires_at_monotonic_ms),
            status: DiagnosticReceiptStatusV1::Completed,
            results,
            observed_coverage: vec!["stub.bridge".to_owned(), "stub.profile".to_owned()],
            result_digest,
            nonclaims: vec![
                "This is a mock local diagnostic receipt, not an NQ artifact.".to_owned(),
                "Stub completion does not establish subject health or resolve contradiction."
                    .to_owned(),
                "This receipt grants no execution, repair, or mutation authority.".to_owned(),
            ],
            mutation_authority: MutationAuthorityV1::None,
        };
        BridgeOutcome {
            disposition: self.disposition(
                request,
                now,
                EscalationDispositionKindV1::Accept {
                    admitted_bounds: request.bounds,
                },
            ),
            receipt: Some(receipt),
        }
    }

    fn refuse(
        &self,
        request: &DiagnosticEscalationRequestV1,
        now: u64,
        code: &str,
        detail: &str,
    ) -> BridgeOutcome {
        BridgeOutcome {
            disposition: self.disposition(
                request,
                now,
                EscalationDispositionKindV1::Refuse {
                    code: code.to_owned(),
                    detail: detail.to_owned(),
                },
            ),
            receipt: None,
        }
    }

    fn defer(
        &self,
        request: &DiagnosticEscalationRequestV1,
        now: u64,
        code: &str,
        detail: &str,
    ) -> BridgeOutcome {
        BridgeOutcome {
            disposition: self.disposition(
                request,
                now,
                EscalationDispositionKindV1::Defer {
                    code: code.to_owned(),
                    detail: detail.to_owned(),
                },
            ),
            receipt: None,
        }
    }

    fn narrow(&self, request: &DiagnosticEscalationRequestV1, now: u64) -> BridgeOutcome {
        BridgeOutcome {
            disposition: self.disposition(
                request,
                now,
                EscalationDispositionKindV1::Narrow {
                    allowed_profile: self.profile.clone(),
                    allowed_bounds: request.bounds.narrowed_to(self.bounds),
                    detail: "requested bounds exceed the compiled local profile limits; explicit resubmission required"
                        .to_owned(),
                },
            ),
            receipt: None,
        }
    }

    fn disposition(
        &self,
        request: &DiagnosticEscalationRequestV1,
        now: u64,
        kind: EscalationDispositionKindV1,
    ) -> EscalationDispositionV1 {
        EscalationDispositionV1 {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id.clone(),
            bridge_id: self.bridge_id.clone(),
            clock_id: self.clock_id.clone(),
            decided_at_monotonic_ms: now,
            kind,
            mutation_authority: MutationAuthorityV1::None,
        }
    }
}

#[must_use]
pub fn stub_profile_identity() -> DiagnosticProfileIdV1 {
    DiagnosticProfileIdV1 {
        name: STUB_PROFILE_NAME.to_owned(),
        version: STUB_PROFILE_VERSION,
        semantic_digest: digest_parts(
            "diagnostic.profile.v1",
            &[
                STUB_PROFILE_NAME.as_bytes(),
                &STUB_PROFILE_VERSION.to_be_bytes(),
            ],
        ),
    }
}

fn result_digest(
    request: &DiagnosticEscalationRequestV1,
    results: &[DiagnosticResultEntryV1],
    started: u64,
    completed: u64,
) -> DigestV1 {
    let mut owned = vec![
        request.request_id.as_str().as_bytes().to_vec(),
        request.subject_scope.subject.as_str().as_bytes().to_vec(),
        request.subject_scope.scope.as_bytes().to_vec(),
        started.to_be_bytes().to_vec(),
        completed.to_be_bytes().to_vec(),
    ];
    for result in results {
        owned.push(result.name.as_bytes().to_vec());
        owned.push(result.value.as_bytes().to_vec());
        owned.push(result.interpretation.as_bytes().to_vec());
    }
    let parts: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
    digest_parts("diagnostic.stub.result.v1", &parts)
}

#[cfg(test)]
mod tests {
    use pulse_types::{
        ConsumerId, ESCALATION_NONCLAIMS, EscalationTriggerClassV1, IncarnationId,
        ObservationPolicyGenerationId, PolicyGenerationId, SubjectId, SubjectScopeV1, TransitionId,
    };

    use super::*;

    fn request(now: u64) -> DiagnosticEscalationRequestV1 {
        let mut request = DiagnosticEscalationRequestV1 {
            schema_version: SCHEMA_VERSION_V1,
            request_id: EscalationRequestId::new(format!("request:{now}")),
            subject_scope: SubjectScopeV1 {
                subject: SubjectId::new("subject:a"),
                subject_incarnation: IncarnationId::new("boot:1"),
                scope: "host".to_owned(),
            },
            consumer: ConsumerId::new("consumer:display"),
            trigger_class: EscalationTriggerClassV1::CoverageCollapse,
            evidence_window_digest: digest_parts("window", &[b"one"]),
            policy_generation: PolicyGenerationId::new("policy:1"),
            observation_policy_generation: ObservationPolicyGenerationId::new(
                "observation-policy:1",
            ),
            diagnostic_profile: stub_profile_identity(),
            bounds: DiagnosticBoundsV1 {
                maximum_runtime_ms: 25,
                maximum_output_bytes: 1_024,
                maximum_observations: 4,
            },
            clock_id: ClockId::new("clock:1"),
            created_at_monotonic_ms: now,
            expires_at_monotonic_ms: now + 100,
            deduplication_key: digest_parts("pending", &[]),
            causal_transition_id: TransitionId::new("transition:1"),
            nonclaims: ESCALATION_NONCLAIMS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        };
        request.deduplication_key = request.compute_deduplication_key();
        request
    }

    #[test]
    fn accepted_request_runs_only_the_stub_and_returns_bound_receipt() {
        let mut bridge = StubL3Bridge::new(BridgeId::new("bridge:1"), ClockId::new("clock:1"));
        let request = request(10);
        let outcome = bridge.handle(&request, 11);
        assert!(matches!(
            outcome.disposition.kind,
            EscalationDispositionKindV1::Accept { .. }
        ));
        let receipt = outcome.receipt.expect("accepted request has receipt");
        assert_eq!(receipt.request_id, request.request_id);
        assert_eq!(receipt.mutation_authority, MutationAuthorityV1::None);
    }

    #[test]
    fn expiry_refuses_without_execution() {
        let mut bridge = StubL3Bridge::new(BridgeId::new("bridge:1"), ClockId::new("clock:1"));
        let request = request(10);
        let outcome = bridge.handle(&request, request.expires_at_monotonic_ms);
        assert!(matches!(
            outcome.disposition.kind,
            EscalationDispositionKindV1::Refuse { ref code, .. } if code == "request_expired"
        ));
        assert!(outcome.receipt.is_none());
    }

    #[test]
    fn broader_bounds_are_narrowed_not_executed() {
        let mut bridge = StubL3Bridge::new(BridgeId::new("bridge:1"), ClockId::new("clock:1"));
        let mut request = request(10);
        request.bounds.maximum_runtime_ms = 1_000;
        let outcome = bridge.handle(&request, 11);
        assert!(matches!(
            outcome.disposition.kind,
            EscalationDispositionKindV1::Narrow { .. }
        ));
        assert!(outcome.receipt.is_none());
    }

    #[test]
    fn unknown_profile_is_refused() {
        let mut bridge = StubL3Bridge::new(BridgeId::new("bridge:1"), ClockId::new("clock:1"));
        let mut request = request(10);
        request.diagnostic_profile.name = "arbitrary.shell".to_owned();
        request.diagnostic_profile.semantic_digest = digest_parts("profile", &[b"arbitrary"]);
        request.deduplication_key = request.compute_deduplication_key();
        let outcome = bridge.handle(&request, 11);
        assert!(matches!(
            outcome.disposition.kind,
            EscalationDispositionKindV1::Refuse { ref code, .. } if code == "profile_not_registered"
        ));
        assert!(outcome.receipt.is_none());
    }
}
