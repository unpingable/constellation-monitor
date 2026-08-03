use std::collections::{BTreeMap, BTreeSet};

use pulse_types::{
    ConsumerId, DiagnosticBoundsV1, DiagnosticProfileIdV1, EscalationTriggerClassV1,
    ObservationProfileIdV1, PolicyGenerationId, SCHEMA_VERSION_V1, SubjectId,
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyError(pub &'static str);

impl std::fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for PolicyError {}
