//! Correspondence profile: compiled constants plus deployment enrollment.
//!
//! The profile digest `P` binds every fixed constant and every enrolled NQ and
//! Pulse identity. It is the only policy input to the acquisition identity, the
//! Pulse observation profile, and the audit record.

use std::collections::BTreeMap;
use std::path::PathBuf;

use pulse_evaluator::ReliancePolicyV1;
use pulse_runtime::ConsumerRegistrationV1;
use pulse_types::{
    ConsumerId, ConsumerProfileGenerationId, ContextActivationId, DigestV1,
    EvaluatorSemanticGenerationId, IncarnationId, ObservationPolicyGenerationId,
    ObservationProfileIdV1, ObserverId, ObserverSetGenerationId, PolicyGenerationId,
    RelianceContextV1, SCHEMA_VERSION_V1, SubjectId, digest_parts,
};
use serde::{Deserialize, Serialize};

use crate::{CorrespondenceError, object_id, require_digest, require_token};

pub const PROFILE_SCHEMA_V1: &str = "constellation.nq_host_load_pressure_correspondence_profile.v1";
pub const OCCURRENCE_SCHEMA_V1: &str =
    "constellation.nq_host_load_pressure_correspondence_occurrence.v1";
pub const INTENT_SCHEMA_V1: &str = "constellation.nq_host_load_pressure_correspondence_intent.v1";
pub const RECORD_SCHEMA_V1: &str = "constellation.nq_host_load_pressure_correspondence.v1";
pub const PULSE_PROFILE_NAME: &str = "constellation.nq_host_load_pressure_correspondence";
pub const PULSE_PROFILE_VERSION: u16 = 1;
pub const PULSE_PROFILE_DOMAIN: &str =
    "constellation.nq_host_load_pressure_correspondence.pulse_profile.v1";
pub const PULSE_SCOPE: &str = "nq.host.load_pressure/v1";
pub const COVERAGE_TAG: &str = "nq_host_load_pressure_v1_terminal_artifact";
pub const TRANSPORT_PATH: &str = "in-process:nq-load-correspondence/v1";
pub const FRAME_DISCLOSURE: &str =
    "unauthenticated in-process correspondence frame; it carries no NQ value or assessment";
pub const INGRESS_DISCLOSURE: &str =
    "in-process co-producer delivery; no transport authentication is claimed";
pub const ACQUISITION_ID_PREFIX: &str = "constellation-nq-load:v1:";
/// NQ's own source reliance window for `nq.host/1` (`reliance_seconds: 300`).
pub const NQ_RELIANCE_WINDOW_MS: u64 = 300_000;
/// Bound on the measured interval between frame delivery and reactor return.
pub const INGRESS_FENCE_MS: u64 = 1_000;
/// Frame validity: strictly below NQ's window by the fence and one millisecond.
pub const FRAME_VALIDITY_MS: u64 = NQ_RELIANCE_WINDOW_MS - INGRESS_FENCE_MS - 1;

pub const NQ_ARTIFACT_SCHEMA: &str = "nq.diagnostic_execution.v2";
pub const NQ_PROVENANCE_SCHEMA: &str = "nq.diagnostic_admission_provenance.v1";
pub const NQ_REFUSAL_SCHEMA: &str = "nq.governed_refusal.v1";
pub const NQ_JUDGMENT_SCHEMA: &str = "nq-ng.judgment.v1";
pub const NQ_SOURCE_KIND: &str = "local_nq_store";
pub const NQ_QUESTION_ID: &str = "nq.host.load_pressure";
pub const NQ_QUESTION_VERSION: &str = "1";
pub const NQ_QUESTION_DIGEST: &str =
    "sha256:7de797da3d9d3a6ae8e21e5d77b95095453336cd38f606ffb3eb29ff6a32e2cf";
pub const NQ_PROFILE_ID: &str = "nq.host";
pub const NQ_PROFILE_VERSION: &str = "1";
pub const NQ_PROFILE_DIGEST: &str =
    "sha256:c8c10fed1cc5598d953b4defbc98e8c106fc59e035c249d43681698a5c7b4ff9";
pub const NQ_CONDITION: &str = "host_load_pressure";
pub const NQ_CLAIM_ID: &str = "claim:host_load_pressure";
pub const NQ_SELECTION_RULE_ID: &str = "nq.deliberate_successor_single_admitted_report";
pub const NQ_REFUSAL_BOUNDARY: &str = "detector";
pub const NQ_REFUSAL_CODE: &str = "cannot_evaluate";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticIdentityV1 {
    pub id: String,
    pub version: String,
    pub digest: String,
}

impl SemanticIdentityV1 {
    #[must_use]
    pub fn new(id: &str, version: &str, digest: &str) -> Self {
        Self {
            id: id.to_owned(),
            version: version.to_owned(),
            digest: digest.to_owned(),
        }
    }

    fn validate(&self, name: &str) -> Result<(), CorrespondenceError> {
        require_token(&format!("{name}.id"), &self.id)?;
        require_token(&format!("{name}.version"), &self.version)?;
        require_digest(&format!("{name}.digest"), &self.digest)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NqProducerV1 {
    pub node_id: String,
    pub build: SemanticIdentityV1,
    pub cohort: SemanticIdentityV1,
}

/// Runtime-derived NQ identities enrolled from a real run of the pinned build.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NqEnrollmentV1 {
    pub instance_id: String,
    pub subject_id: String,
    pub subject_scope: SemanticIdentityV1,
    pub vantage: SemanticIdentityV1,
    pub profile_semantic_id: String,
    pub threshold_policy: SemanticIdentityV1,
    pub evaluator: SemanticIdentityV1,
    pub state_model: SemanticIdentityV1,
    pub producer: NqProducerV1,
    pub executable_path: PathBuf,
    pub executable_sha256: String,
    pub config_path: PathBuf,
    pub config_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PulseEnrollmentV1 {
    pub observer_id: String,
    pub consumer_id: String,
    pub policy_generation: String,
    pub observation_policy_generation: String,
}

/// Compiled constants carried in the profile so `P` covers them and a
/// verifier can refuse a profile whose constants drifted from this build.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorrespondenceConstantsV1 {
    pub reliance_window_ms: u64,
    pub ingress_fence_ms: u64,
    pub frame_validity_ms: u64,
    pub coverage_tag: String,
    pub transport_path: String,
    pub frame_disclosure: String,
    pub ingress_disclosure: String,
    pub pulse_scope: String,
    pub claim_id: String,
    pub condition: String,
    pub selection_rule_id: String,
    pub question: SemanticIdentityV1,
    pub profile: SemanticIdentityV1,
}

impl CorrespondenceConstantsV1 {
    #[must_use]
    pub fn compiled() -> Self {
        Self {
            reliance_window_ms: NQ_RELIANCE_WINDOW_MS,
            ingress_fence_ms: INGRESS_FENCE_MS,
            frame_validity_ms: FRAME_VALIDITY_MS,
            coverage_tag: COVERAGE_TAG.to_owned(),
            transport_path: TRANSPORT_PATH.to_owned(),
            frame_disclosure: FRAME_DISCLOSURE.to_owned(),
            ingress_disclosure: INGRESS_DISCLOSURE.to_owned(),
            pulse_scope: PULSE_SCOPE.to_owned(),
            claim_id: NQ_CLAIM_ID.to_owned(),
            condition: NQ_CONDITION.to_owned(),
            selection_rule_id: NQ_SELECTION_RULE_ID.to_owned(),
            question: SemanticIdentityV1::new(
                NQ_QUESTION_ID,
                NQ_QUESTION_VERSION,
                NQ_QUESTION_DIGEST,
            ),
            profile: SemanticIdentityV1::new(NQ_PROFILE_ID, NQ_PROFILE_VERSION, NQ_PROFILE_DIGEST),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorrespondenceProfileV1 {
    pub schema: String,
    pub profile_digest: String,
    pub constants: CorrespondenceConstantsV1,
    pub nq: NqEnrollmentV1,
    pub pulse: PulseEnrollmentV1,
}

impl CorrespondenceProfileV1 {
    /// Build and seal a profile from enrollment. Constants are always the
    /// compiled ones.
    pub fn seal(nq: NqEnrollmentV1, pulse: PulseEnrollmentV1) -> Result<Self, CorrespondenceError> {
        let mut profile = Self {
            schema: PROFILE_SCHEMA_V1.to_owned(),
            profile_digest: String::new(),
            constants: CorrespondenceConstantsV1::compiled(),
            nq,
            pulse,
        };
        profile.profile_digest = object_id(&profile, "profile_digest")?;
        profile.validate()?;
        Ok(profile)
    }

    /// V2: the profile matches the compiled constants and is well formed.
    pub fn validate(&self) -> Result<(), CorrespondenceError> {
        if self.schema != PROFILE_SCHEMA_V1 {
            return Err(CorrespondenceError::new(
                "unsupported_schema",
                "correspondence profile schema is unsupported",
            ));
        }
        if self.constants != CorrespondenceConstantsV1::compiled() {
            return Err(CorrespondenceError::new(
                "profile_constant_drift",
                "profile constants differ from the compiled correspondence constants",
            ));
        }
        require_token("nq.instance_id", &self.nq.instance_id)?;
        require_token("nq.subject_id", &self.nq.subject_id)?;
        if self.nq.subject_id.len() > pulse_types::MAX_IDENTITY_BYTES
            || !self.nq.subject_id.starts_with("host:")
        {
            return Err(CorrespondenceError::new(
                "invalid_subject",
                "NQ subject must be a bounded host: identity",
            ));
        }
        self.nq.subject_scope.validate("nq.subject_scope")?;
        self.nq.vantage.validate("nq.vantage")?;
        require_digest("nq.profile_semantic_id", &self.nq.profile_semantic_id)?;
        self.nq.threshold_policy.validate("nq.threshold_policy")?;
        self.nq.evaluator.validate("nq.evaluator")?;
        self.nq.state_model.validate("nq.state_model")?;
        require_token("nq.producer.node_id", &self.nq.producer.node_id)?;
        self.nq.producer.build.validate("nq.producer.build")?;
        self.nq.producer.cohort.validate("nq.producer.cohort")?;
        require_digest("nq.executable_sha256", &self.nq.executable_sha256)?;
        require_digest("nq.config_sha256", &self.nq.config_sha256)?;
        if !self.nq.executable_path.is_absolute() || !self.nq.config_path.is_absolute() {
            return Err(CorrespondenceError::new(
                "relative_path",
                "NQ executable and configuration paths must be absolute",
            ));
        }
        for (name, value) in [
            ("pulse.observer_id", &self.pulse.observer_id),
            ("pulse.consumer_id", &self.pulse.consumer_id),
            ("pulse.policy_generation", &self.pulse.policy_generation),
            (
                "pulse.observation_policy_generation",
                &self.pulse.observation_policy_generation,
            ),
        ] {
            require_token(name, value)?;
            if value.len() > pulse_types::MAX_IDENTITY_BYTES || value.contains(char::is_whitespace)
            {
                return Err(CorrespondenceError::new(
                    "invalid_token",
                    format!("{name} exceeds the Pulse identity bound or contains whitespace"),
                ));
            }
        }
        if self.pulse.observer_id.contains('/') {
            return Err(CorrespondenceError::new(
                "invalid_observer",
                "observer identity must not contain '/', which delimits the evidence reference",
            ));
        }
        if self.profile_digest != object_id(self, "profile_digest")? {
            return Err(CorrespondenceError::new(
                "identity_mismatch",
                "profile_digest does not match the canonical profile",
            ));
        }
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CorrespondenceError> {
        if bytes.len() > 64 * 1_024 {
            return Err(CorrespondenceError::new(
                "bound_exceeded",
                "profile exceeds its byte bound",
            ));
        }
        let profile: Self = serde_json::from_slice(bytes)
            .map_err(|error| CorrespondenceError::new("decode", error.to_string()))?;
        profile.validate()?;
        Ok(profile)
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.profile_digest
    }

    #[must_use]
    pub fn subject(&self) -> SubjectId {
        SubjectId::new(self.nq.subject_id.clone())
    }

    #[must_use]
    pub fn observer(&self) -> ObserverId {
        ObserverId::new(self.pulse.observer_id.clone())
    }

    #[must_use]
    pub fn consumer(&self) -> ConsumerId {
        ConsumerId::new(self.pulse.consumer_id.clone())
    }

    #[must_use]
    pub fn observation_policy_generation(&self) -> ObservationPolicyGenerationId {
        ObservationPolicyGenerationId::new(self.pulse.observation_policy_generation.clone())
    }

    /// Pulse observation profile whose semantic digest is bound to `P`.
    #[must_use]
    pub fn pulse_observation_profile(&self) -> ObservationProfileIdV1 {
        ObservationProfileIdV1 {
            name: PULSE_PROFILE_NAME.to_owned(),
            version: PULSE_PROFILE_VERSION,
            semantic_digest: pulse_profile_digest(&self.profile_digest),
        }
    }

    /// The exact reliance policy for this correspondence: one observer, one
    /// coverage tag, one failure domain, validity `V`, no escalation, and no
    /// verified-authentication requirement (the frame is in-process and
    /// unauthenticated by disclosure).
    #[must_use]
    pub fn reliance_policy(&self) -> ReliancePolicyV1 {
        let mut observer_failure_domains = BTreeMap::new();
        observer_failure_domains.insert(
            self.pulse.observer_id.clone(),
            "domain:nq-load-correspondence".to_owned(),
        );
        ReliancePolicyV1 {
            schema_version: SCHEMA_VERSION_V1,
            subject: self.subject(),
            scope: PULSE_SCOPE.to_owned(),
            consumer: self.consumer(),
            generation: PolicyGenerationId::new(self.pulse.policy_generation.clone()),
            observation_policy_generation: self.observation_policy_generation(),
            observation_profile: self.pulse_observation_profile(),
            required_coverage: vec![COVERAGE_TAG.to_owned()],
            minimum_observers: 1,
            maximum_validity_ms: FRAME_VALIDITY_MS,
            require_verified_authentication: false,
            coherence_tolerances: BTreeMap::new(),
            observer_failure_domains,
            escalation: None,
        }
    }

    #[must_use]
    pub fn reliance_context(&self, activation_id: &str) -> RelianceContextV1 {
        let policy = self.reliance_policy();
        RelianceContextV1 {
            schema_version: SCHEMA_VERSION_V1,
            activation_id: ContextActivationId::new(activation_id),
            reliance_policy_generation: policy.generation.clone(),
            reliance_policy_semantic_digest: policy.semantic_digest(),
            consumer_profile_generation: ConsumerProfileGenerationId::new(format!(
                "consumer-profile:{}",
                short_digest(&self.profile_digest)
            )),
            evaluator_semantic_generation: EvaluatorSemanticGenerationId::new(format!(
                "evaluator:{}",
                short_digest(&self.profile_digest)
            )),
            observer_set_generation: ObserverSetGenerationId::new(format!(
                "observer-set:{}",
                short_digest(&self.profile_digest)
            )),
            observation_policy_generation: policy.observation_policy_generation,
        }
    }

    #[must_use]
    pub fn consumer_registration(
        &self,
        subject_incarnation: IncarnationId,
        activation_id: &str,
    ) -> ConsumerRegistrationV1 {
        ConsumerRegistrationV1 {
            policy: self.reliance_policy(),
            context: self.reliance_context(activation_id),
            subject_incarnation,
        }
    }
}

#[must_use]
pub fn pulse_profile_digest(profile_digest: &str) -> DigestV1 {
    digest_parts(PULSE_PROFILE_DOMAIN, &[profile_digest.as_bytes()])
}

fn short_digest(digest: &str) -> &str {
    digest
        .strip_prefix("sha256:")
        .map_or(digest, |hex| &hex[..hex.len().min(16)])
}
