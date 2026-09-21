use std::collections::{BTreeMap, BTreeSet};

use pulse_types::{
    ConsumerId, DiagnosticBoundsV1, DiagnosticProfileIdV1, DigestV1, EscalationTriggerClassV1,
    ObservationPolicyGenerationId, ObservationProfileIdV1, PolicyGenerationId, SCHEMA_VERSION_V1,
    SubjectId, digest_parts,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EscalationPolicyV1 {
    pub triggers: BTreeSet<EscalationTriggerClassV1>,
    pub diagnostic_profile: DiagnosticProfileIdV1,
    pub bounds: DiagnosticBoundsV1,
    pub request_ttl_ms: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReliancePolicyV1 {
    pub schema_version: u16,
    pub subject: SubjectId,
    pub scope: String,
    pub consumer: ConsumerId,
    pub generation: PolicyGenerationId,
    pub observation_policy_generation: ObservationPolicyGenerationId,
    pub observation_profile: ObservationProfileIdV1,
    pub required_coverage: Vec<String>,
    pub minimum_observers: u32,
    pub maximum_validity_ms: u64,
    pub require_verified_authentication: bool,
    pub coherence_tolerances: BTreeMap<String, f64>,
    pub observer_failure_domains: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escalation: Option<EscalationPolicyV1>,
}

impl ReliancePolicyV1 {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.schema_version != SCHEMA_VERSION_V1 {
            return Err(PolicyError("unsupported policy schema"));
        }
        self.subject
            .validate()
            .map_err(|_| PolicyError("invalid subject identity"))?;
        self.consumer
            .validate()
            .map_err(|_| PolicyError("invalid consumer identity"))?;
        self.generation
            .validate()
            .map_err(|_| PolicyError("invalid policy generation"))?;
        self.observation_policy_generation
            .validate()
            .map_err(|_| PolicyError("invalid observation policy generation"))?;
        self.observation_profile
            .validate()
            .map_err(|_| PolicyError("invalid observation profile"))?;
        if self.scope.is_empty() {
            return Err(PolicyError("scope is empty"));
        }
        if self.minimum_observers == 0 {
            return Err(PolicyError("minimum observers must be nonzero"));
        }
        if self.maximum_validity_ms == 0 {
            return Err(PolicyError("maximum validity must be nonzero"));
        }
        if self.required_coverage.is_empty() {
            return Err(PolicyError("required coverage is empty"));
        }
        if self
            .required_coverage
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(PolicyError("required coverage must be unique and sorted"));
        }
        if self
            .coherence_tolerances
            .values()
            .any(|value| !value.is_finite() || *value < 0.0)
        {
            return Err(PolicyError(
                "coherence tolerances must be finite and non-negative",
            ));
        }
        if let Some(escalation) = &self.escalation {
            if escalation.triggers.is_empty()
                || !escalation.bounds.is_nonzero()
                || escalation.request_ttl_ms == 0
            {
                return Err(PolicyError("escalation policy is incomplete"));
            }
        }
        Ok(())
    }

    /// Exact digest of the consumer reliance-policy body. The generation is
    /// deliberately excluded so equal bodies under distinct generations have
    /// equal body digests but remain distinct reliance contexts.
    #[must_use]
    pub fn semantic_digest(&self) -> DigestV1 {
        let mut parts = vec![
            self.schema_version.to_be_bytes().to_vec(),
            self.subject.as_str().as_bytes().to_vec(),
            self.scope.as_bytes().to_vec(),
            self.consumer.as_str().as_bytes().to_vec(),
            self.observation_policy_generation
                .as_str()
                .as_bytes()
                .to_vec(),
            self.observation_profile.name.as_bytes().to_vec(),
            self.observation_profile.version.to_be_bytes().to_vec(),
            self.observation_profile
                .semantic_digest
                .as_str()
                .as_bytes()
                .to_vec(),
            self.minimum_observers.to_be_bytes().to_vec(),
            self.maximum_validity_ms.to_be_bytes().to_vec(),
            vec![u8::from(self.require_verified_authentication)],
        ];
        for tag in &self.required_coverage {
            parts.push(b"coverage".to_vec());
            parts.push(tag.as_bytes().to_vec());
        }
        for (signal, tolerance) in &self.coherence_tolerances {
            parts.push(b"coherence".to_vec());
            parts.push(signal.as_bytes().to_vec());
            parts.push(tolerance.to_bits().to_be_bytes().to_vec());
        }
        for (observer, domain) in &self.observer_failure_domains {
            parts.push(b"failure-domain".to_vec());
            parts.push(observer.as_bytes().to_vec());
            parts.push(domain.as_bytes().to_vec());
        }
        if let Some(escalation) = &self.escalation {
            parts.push(b"escalation".to_vec());
            for trigger in &escalation.triggers {
                parts.push(trigger.as_str().as_bytes().to_vec());
            }
            parts.push(escalation.diagnostic_profile.name.as_bytes().to_vec());
            parts.push(escalation.diagnostic_profile.version.to_be_bytes().to_vec());
            parts.push(
                escalation
                    .diagnostic_profile
                    .semantic_digest
                    .as_str()
                    .as_bytes()
                    .to_vec(),
            );
            parts.push(escalation.bounds.maximum_runtime_ms.to_be_bytes().to_vec());
            parts.push(
                escalation
                    .bounds
                    .maximum_output_bytes
                    .to_be_bytes()
                    .to_vec(),
            );
            parts.push(
                escalation
                    .bounds
                    .maximum_observations
                    .to_be_bytes()
                    .to_vec(),
            );
            parts.push(escalation.request_ttl_ms.to_be_bytes().to_vec());
        }
        let references = parts.iter().map(Vec::as_slice).collect::<Vec<_>>();
        digest_parts("reliance.policy.body.v1", &references)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyError(pub &'static str);

impl std::fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for PolicyError {}
