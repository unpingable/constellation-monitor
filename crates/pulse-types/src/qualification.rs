//! Closed local qualified-generation records and canonical package validation.
//!
//! These records distinguish declared generation labels, checked qualification
//! evidence, and one process-local activation occurrence. None is an authority
//! carrier and a serialized activation receipt cannot recreate the live token.

use std::fmt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::{
    ClockId, ConsumerId, ConsumerProfileGenerationId, DigestV1, EvaluatorSemanticGenerationId,
    IncarnationId, MutationAuthorityV1, ObservationPolicyGenerationId, ObserverSetGenerationId,
    PolicyGenerationId, RelianceContextV1, SCHEMA_VERSION_V1, SubjectId, digest_parts,
};

pub const MAX_QUALIFICATION_PACKAGE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_QUALIFICATION_ARTIFACTS: usize = 16;
pub const MAX_QUALIFICATION_COMMANDS: usize = 16;
pub const MAX_QUALIFICATION_COMMAND_ARGUMENTS: usize = 32;
pub const MAX_QUALIFICATION_CLAIMS: usize = 64;
pub const MAX_QUALIFICATION_ASSUMPTIONS: usize = 64;
pub const MAX_QUALIFICATION_DEPENDENCIES: usize = 128;
pub const MAX_QUALIFICATION_STRING_BYTES: usize = 1_024;
pub const MAX_EXECUTABLE_MEASUREMENT_BYTES: u64 = 128 * 1024 * 1024;

static NEXT_ACTIVATION_OCCURRENCE: AtomicU64 = AtomicU64::new(1);
static EXECUTABLE_CONTENT_CACHE: OnceLock<Mutex<Option<ExecutableContentCache>>> = OnceLock::new();

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRoleV1 {
    RunningExecutable,
    EvaluatorImplementation,
    ReliancePolicy,
    ConsumerProfile,
    ObserverSet,
    ObservationPolicy,
    RuntimeConfiguration,
    SemanticContracts,
    QualificationCorpus,
    QualificationResults,
}

impl ArtifactRoleV1 {
    #[must_use]
    pub const fn all() -> [Self; 10] {
        [
            Self::RunningExecutable,
            Self::EvaluatorImplementation,
            Self::ReliancePolicy,
            Self::ConsumerProfile,
            Self::ObserverSet,
            Self::ObservationPolicy,
            Self::RuntimeConfiguration,
            Self::SemanticContracts,
            Self::QualificationCorpus,
            Self::QualificationResults,
        ]
    }

    #[must_use]
    pub const fn activation_required(self) -> bool {
        !matches!(self, Self::QualificationCorpus | Self::QualificationResults)
    }

    #[must_use]
    pub const fn mismatch_state(self) -> RuntimeBindingStateV1 {
        match self {
            Self::RunningExecutable => RuntimeBindingStateV1::ExecutableMismatch,
            Self::EvaluatorImplementation => RuntimeBindingStateV1::EvaluatorMismatch,
            Self::ReliancePolicy => RuntimeBindingStateV1::PolicyMismatch,
            Self::ConsumerProfile => RuntimeBindingStateV1::ProfileMismatch,
            Self::ObserverSet => RuntimeBindingStateV1::ObserverSetMismatch,
            Self::ObservationPolicy => RuntimeBindingStateV1::ObservationPolicyMismatch,
            Self::RuntimeConfiguration => RuntimeBindingStateV1::ConfigurationMismatch,
            Self::SemanticContracts => RuntimeBindingStateV1::ContractMismatch,
            Self::QualificationCorpus | Self::QualificationResults => {
                RuntimeBindingStateV1::QualificationEvidenceMissing
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityGrantV1 {
    None,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityGrantsV1 {
    pub continuation: AuthorityGrantV1,
    pub diagnostic_execution: AuthorityGrantV1,
    pub deployment: AuthorityGrantV1,
    pub signing: AuthorityGrantV1,
    pub revocation: AuthorityGrantV1,
    pub mutation: MutationAuthorityV1,
}

impl AuthorityGrantsV1 {
    #[must_use]
    pub const fn none() -> Self {
        Self {
            continuation: AuthorityGrantV1::None,
            diagnostic_execution: AuthorityGrantV1::None,
            deployment: AuthorityGrantV1::None,
            signing: AuthorityGrantV1::None,
            revocation: AuthorityGrantV1::None,
            mutation: MutationAuthorityV1::None,
        }
    }

    #[must_use]
    pub const fn grants_nothing(self) -> bool {
        matches!(self.continuation, AuthorityGrantV1::None)
            && matches!(self.diagnostic_execution, AuthorityGrantV1::None)
            && matches!(self.deployment, AuthorityGrantV1::None)
            && matches!(self.signing, AuthorityGrantV1::None)
            && matches!(self.revocation, AuthorityGrantV1::None)
            && matches!(self.mutation, MutationAuthorityV1::None)
    }
}

impl Default for AuthorityGrantsV1 {
    fn default() -> Self {
        Self::none()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDigestBindingV1 {
    pub role: ArtifactRoleV1,
    pub content_digest: DigestV1,
}

impl ArtifactDigestBindingV1 {
    fn validate(&self) -> Result<(), QualificationError> {
        self.content_digest
            .validate()
            .map_err(|error| QualificationError::new("invalid_digest", error.to_string()))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactIdentityV1 {
    pub role: ArtifactRoleV1,
    pub logical_name: String,
    pub logical_path: String,
    pub media_type: String,
    pub byte_length: u64,
    pub content_digest: DigestV1,
    pub activation_required: bool,
}

impl ArtifactIdentityV1 {
    pub fn validate(&self) -> Result<(), QualificationError> {
        validate_text("artifact.logical_name", &self.logical_name)?;
        validate_logical_path(&self.logical_path)?;
        validate_text("artifact.media_type", &self.media_type)?;
        if self.byte_length == 0 {
            return Err(QualificationError::new(
                "invalid_artifact",
                "artifact byte length must be nonzero",
            ));
        }
        self.content_digest
            .validate()
            .map_err(|error| QualificationError::new("invalid_digest", error.to_string()))?;
        if self.activation_required != self.role.activation_required() {
            return Err(QualificationError::new(
                "ambiguous_artifact_role",
                "artifact activation posture does not match its closed role",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn digest_binding(&self) -> ArtifactDigestBindingV1 {
        ArtifactDigestBindingV1 {
            role: self.role,
            content_digest: self.content_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedGenerationSetV1 {
    pub subject: SubjectId,
    pub consumer: ConsumerId,
    pub reliance_policy_generation: PolicyGenerationId,
    pub reliance_policy_semantic_digest: DigestV1,
    pub consumer_profile_generation: ConsumerProfileGenerationId,
    pub evaluator_semantic_generation: EvaluatorSemanticGenerationId,
    pub observer_set_generation: ObserverSetGenerationId,
    pub observation_policy_generation: ObservationPolicyGenerationId,
}

impl QualifiedGenerationSetV1 {
    #[must_use]
    pub fn from_context(
        subject: SubjectId,
        consumer: ConsumerId,
        context: &RelianceContextV1,
    ) -> Self {
        Self {
            subject,
            consumer,
            reliance_policy_generation: context.reliance_policy_generation.clone(),
            reliance_policy_semantic_digest: context.reliance_policy_semantic_digest.clone(),
            consumer_profile_generation: context.consumer_profile_generation.clone(),
            evaluator_semantic_generation: context.evaluator_semantic_generation.clone(),
            observer_set_generation: context.observer_set_generation.clone(),
            observation_policy_generation: context.observation_policy_generation.clone(),
        }
    }

    pub fn validate(&self) -> Result<(), QualificationError> {
        self.subject
            .validate()
            .map_err(|error| QualificationError::new("invalid_identity", error.to_string()))?;
        self.consumer
            .validate()
            .map_err(|error| QualificationError::new("invalid_identity", error.to_string()))?;
        self.reliance_policy_generation
            .validate()
            .map_err(|error| QualificationError::new("invalid_identity", error.to_string()))?;
        self.reliance_policy_semantic_digest
            .validate()
            .map_err(|error| QualificationError::new("invalid_digest", error.to_string()))?;
        self.consumer_profile_generation
            .validate()
            .map_err(|error| QualificationError::new("invalid_identity", error.to_string()))?;
        self.evaluator_semantic_generation
            .validate()
            .map_err(|error| QualificationError::new("invalid_identity", error.to_string()))?;
        self.observer_set_generation
            .validate()
            .map_err(|error| QualificationError::new("invalid_identity", error.to_string()))?;
        self.observation_policy_generation
            .validate()
            .map_err(|error| QualificationError::new("invalid_identity", error.to_string()))
    }

    #[must_use]
    pub fn matches_context(&self, context: &RelianceContextV1) -> bool {
        self.reliance_policy_generation == context.reliance_policy_generation
            && self.reliance_policy_semantic_digest == context.reliance_policy_semantic_digest
            && self.consumer_profile_generation == context.consumer_profile_generation
            && self.evaluator_semantic_generation == context.evaluator_semantic_generation
            && self.observer_set_generation == context.observer_set_generation
            && self.observation_policy_generation == context.observation_policy_generation
    }

    #[must_use]
    pub fn identity_digest(&self) -> DigestV1 {
        digest_parts(
            "qualified.generation-set.v1",
            &[
                self.subject.as_str().as_bytes(),
                self.consumer.as_str().as_bytes(),
                self.reliance_policy_generation.as_str().as_bytes(),
                self.reliance_policy_semantic_digest.as_str().as_bytes(),
                self.consumer_profile_generation.as_str().as_bytes(),
                self.evaluator_semantic_generation.as_str().as_bytes(),
                self.observer_set_generation.as_str().as_bytes(),
                self.observation_policy_generation.as_str().as_bytes(),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticContractIdentityV1 {
    pub name: String,
    pub version: u16,
    pub digest: DigestV1,
}

impl SemanticContractIdentityV1 {
    fn validate(&self) -> Result<(), QualificationError> {
        validate_text("semantic_contract.name", &self.name)?;
        if self.version == 0 {
            return Err(QualificationError::new(
                "unsupported_contract",
                "semantic contract version zero is unsupported",
            ));
        }
        self.digest
            .validate()
            .map_err(|error| QualificationError::new("invalid_digest", error.to_string()))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeDependencyIdentityV1 {
    pub name: String,
    pub version: String,
    pub source_digest: DigestV1,
}

impl RuntimeDependencyIdentityV1 {
    fn validate(&self) -> Result<(), QualificationError> {
        validate_text("dependency.name", &self.name)?;
        validate_text("dependency.version", &self.version)?;
        self.source_digest
            .validate()
            .map_err(|error| QualificationError::new("invalid_digest", error.to_string()))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentityV1 {
    pub repository_identity: String,
    pub commit: String,
    pub source_tree_digest: DigestV1,
    pub dirty: bool,
}

impl SourceIdentityV1 {
    fn validate(&self) -> Result<(), QualificationError> {
        validate_text("source.repository_identity", &self.repository_identity)?;
        if self.commit.len() != 40
            || !self
                .commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(QualificationError::new(
                "invalid_source_identity",
                "source commit must be a lowercase forty-hex identity",
            ));
        }
        self.source_tree_digest
            .validate()
            .map_err(|error| QualificationError::new("invalid_digest", error.to_string()))?;
        if self.dirty {
            return Err(QualificationError::new(
                "ambiguous_source_identity",
                "a qualified source identity cannot be marked dirty",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildIdentityV1 {
    pub toolchain_identity: String,
    pub target_triple: String,
    pub build_profile: String,
    pub enabled_features: Vec<String>,
    pub runtime_dependencies: Vec<RuntimeDependencyIdentityV1>,
}

impl BuildIdentityV1 {
    fn validate(&self) -> Result<(), QualificationError> {
        validate_text("build.toolchain_identity", &self.toolchain_identity)?;
        validate_text("build.target_triple", &self.target_triple)?;
        validate_text("build.build_profile", &self.build_profile)?;
        validate_sorted_texts(
            "build.enabled_features",
            &self.enabled_features,
            MAX_QUALIFICATION_DEPENDENCIES,
        )?;
        validate_sorted(
            "build.runtime_dependencies",
            &self.runtime_dependencies,
            MAX_QUALIFICATION_DEPENDENCIES,
        )?;
        for dependency in &self.runtime_dependencies {
            dependency.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactManifestBodyV1 {
    pub schema_version: u16,
    pub generation_set: QualifiedGenerationSetV1,
    pub artifacts: Vec<ArtifactIdentityV1>,
    pub source: SourceIdentityV1,
    pub build: BuildIdentityV1,
    pub semantic_contracts: Vec<SemanticContractIdentityV1>,
    pub platform_assumptions: Vec<String>,
    pub qualification_corpus_identities: Vec<DigestV1>,
    pub declared_claims: Vec<String>,
    pub nonclaims: Vec<String>,
    pub supersedes_manifest_digests: Vec<DigestV1>,
    pub lifecycle_authority_id: String,
    pub authority_grants: AuthorityGrantsV1,
}

impl ArtifactManifestBodyV1 {
    pub fn validate(&self) -> Result<(), QualificationError> {
        validate_schema(self.schema_version, "artifact manifest body")?;
        self.generation_set.validate()?;
        if self.artifacts.len() != ArtifactRoleV1::all().len()
            || self.artifacts.len() > MAX_QUALIFICATION_ARTIFACTS
        {
            return Err(QualificationError::new(
                "artifact_inventory_incomplete",
                "manifest must contain every closed v1 artifact role exactly once",
            ));
        }
        for (artifact, expected_role) in self.artifacts.iter().zip(ArtifactRoleV1::all()) {
            if artifact.role != expected_role {
                return Err(QualificationError::new(
                    "artifact_role_order",
                    "artifact roles must be complete, unique, and in canonical order",
                ));
            }
            artifact.validate()?;
        }
        self.source.validate()?;
        self.build.validate()?;
        validate_sorted(
            "manifest.semantic_contracts",
            &self.semantic_contracts,
            MAX_QUALIFICATION_ASSUMPTIONS,
        )?;
        for contract in &self.semantic_contracts {
            contract.validate()?;
        }
        validate_sorted_texts(
            "manifest.platform_assumptions",
            &self.platform_assumptions,
            MAX_QUALIFICATION_ASSUMPTIONS,
        )?;
        validate_sorted(
            "manifest.qualification_corpus_identities",
            &self.qualification_corpus_identities,
            MAX_QUALIFICATION_ASSUMPTIONS,
        )?;
        for digest in &self.qualification_corpus_identities {
            digest
                .validate()
                .map_err(|error| QualificationError::new("invalid_digest", error.to_string()))?;
        }
        let corpus_artifact = self
            .artifacts
            .iter()
            .find(|artifact| artifact.role == ArtifactRoleV1::QualificationCorpus)
            .expect("complete ordered artifact inventory contains the corpus role");
        if self.qualification_corpus_identities != vec![corpus_artifact.content_digest.clone()] {
            return Err(QualificationError::new(
                "qualification_corpus_mismatch",
                "manifest corpus identity must exactly name its corpus artifact bytes",
            ));
        }
        validate_sorted_texts(
            "manifest.declared_claims",
            &self.declared_claims,
            MAX_QUALIFICATION_CLAIMS,
        )?;
        validate_sorted_texts(
            "manifest.nonclaims",
            &self.nonclaims,
            MAX_QUALIFICATION_CLAIMS,
        )?;
        validate_sorted(
            "manifest.supersedes_manifest_digests",
            &self.supersedes_manifest_digests,
            MAX_QUALIFICATION_ASSUMPTIONS,
        )?;
        for digest in &self.supersedes_manifest_digests {
            digest
                .validate()
                .map_err(|error| QualificationError::new("invalid_digest", error.to_string()))?;
        }
        validate_text(
            "manifest.lifecycle_authority_id",
            &self.lifecycle_authority_id,
        )?;
        if !self.authority_grants.grants_nothing() {
            return Err(QualificationError::new(
                "authority_laundering",
                "manifest cannot carry an authority grant",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn artifact_digests(&self) -> Vec<ArtifactDigestBindingV1> {
        self.artifacts
            .iter()
            .map(ArtifactIdentityV1::digest_binding)
            .collect()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedArtifactManifestV1 {
    pub schema_version: u16,
    pub manifest_digest: DigestV1,
    pub body: ArtifactManifestBodyV1,
}

impl QualifiedArtifactManifestV1 {
    pub fn new(body: ArtifactManifestBodyV1) -> Result<Self, QualificationError> {
        body.validate()?;
        let manifest_digest = body_digest("qualified.artifact-manifest.body.v1", &body)?;
        Ok(Self {
            schema_version: SCHEMA_VERSION_V1,
            manifest_digest,
            body,
        })
    }

    pub fn validate(&self) -> Result<(), QualificationError> {
        validate_schema(self.schema_version, "artifact manifest")?;
        self.body.validate()?;
        let expected = body_digest("qualified.artifact-manifest.body.v1", &self.body)?;
        if self.manifest_digest != expected {
            return Err(QualificationError::new(
                "manifest_identity_mismatch",
                "manifest digest does not identify its canonical body",
            ));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, QualificationError> {
        self.validate()?;
        canonical_encode(self)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, QualificationError> {
        let value: Self = canonical_decode(bytes, "artifact manifest")?;
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationCommandResultV1 {
    pub sequence: u16,
    pub argv: Vec<String>,
    pub exit_code: i32,
    pub stdout_digest: DigestV1,
    pub stderr_digest: DigestV1,
    pub observed_test_count: Option<u32>,
}

impl QualificationCommandResultV1 {
    pub fn validate(&self) -> Result<(), QualificationError> {
        if self.sequence == 0
            || self.argv.is_empty()
            || self.argv.len() > MAX_QUALIFICATION_COMMAND_ARGUMENTS
        {
            return Err(QualificationError::new(
                "invalid_qualification_command",
                "qualification command sequence and argument bounds are invalid",
            ));
        }
        for argument in &self.argv {
            validate_text("qualification_command.argv", argument)?;
        }
        self.stdout_digest
            .validate()
            .map_err(|error| QualificationError::new("invalid_digest", error.to_string()))?;
        self.stderr_digest
            .validate()
            .map_err(|error| QualificationError::new("invalid_digest", error.to_string()))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationEvidenceBodyV1 {
    pub schema_version: u16,
    pub manifest_digest: DigestV1,
    pub artifact_digests: Vec<ArtifactDigestBindingV1>,
    pub source: SourceIdentityV1,
    pub build: BuildIdentityV1,
    pub semantic_contracts: Vec<SemanticContractIdentityV1>,
    pub command_results: Vec<QualificationCommandResultV1>,
    pub qualification_corpus_identities: Vec<DigestV1>,
    pub hostile_scenarios: Vec<String>,
    pub earned_claims: Vec<String>,
    pub nonclaims: Vec<String>,
    pub total_tests_passed: u32,
    pub all_required_commands_passed: bool,
    pub authority_grants: AuthorityGrantsV1,
}

impl QualificationEvidenceBodyV1 {
    pub fn validate(&self) -> Result<(), QualificationError> {
        validate_schema(self.schema_version, "qualification evidence body")?;
        self.manifest_digest
            .validate()
            .map_err(|error| QualificationError::new("invalid_digest", error.to_string()))?;
        validate_sorted(
            "qualification.artifact_digests",
            &self.artifact_digests,
            MAX_QUALIFICATION_ARTIFACTS,
        )?;
        for binding in &self.artifact_digests {
            binding.validate()?;
        }
        self.source.validate()?;
        self.build.validate()?;
        validate_sorted(
            "qualification.semantic_contracts",
            &self.semantic_contracts,
            MAX_QUALIFICATION_ASSUMPTIONS,
        )?;
        for contract in &self.semantic_contracts {
            contract.validate()?;
        }
        if self.command_results.is_empty()
            || self.command_results.len() > MAX_QUALIFICATION_COMMANDS
        {
            return Err(QualificationError::new(
                "qualification_evidence_missing",
                "qualification command results are absent or exceed their bound",
            ));
        }
        for (index, command) in self.command_results.iter().enumerate() {
            command.validate()?;
            let expected = u16::try_from(index + 1).map_err(|_| {
                QualificationError::new("bound_exceeded", "command sequence exceeds u16")
            })?;
            if command.sequence != expected {
                return Err(QualificationError::new(
                    "qualification_command_sequence",
                    "qualification command results must have a contiguous canonical sequence",
                ));
            }
        }
        validate_sorted(
            "qualification.corpus",
            &self.qualification_corpus_identities,
            MAX_QUALIFICATION_ASSUMPTIONS,
        )?;
        for digest in &self.qualification_corpus_identities {
            digest
                .validate()
                .map_err(|error| QualificationError::new("invalid_digest", error.to_string()))?;
        }
        validate_sorted_texts(
            "qualification.hostile_scenarios",
            &self.hostile_scenarios,
            MAX_QUALIFICATION_CLAIMS,
        )?;
        validate_sorted_texts(
            "qualification.earned_claims",
            &self.earned_claims,
            MAX_QUALIFICATION_CLAIMS,
        )?;
        validate_sorted_texts(
            "qualification.nonclaims",
            &self.nonclaims,
            MAX_QUALIFICATION_CLAIMS,
        )?;
        let summed_tests = self
            .command_results
            .iter()
            .filter_map(|command| command.observed_test_count)
            .fold(0_u32, u32::saturating_add);
        if !self.all_required_commands_passed
            || self
                .command_results
                .iter()
                .any(|command| command.exit_code != 0)
            || summed_tests != self.total_tests_passed
        {
            return Err(QualificationError::new(
                "qualification_command_failed",
                "qualification success and exact test count are not supported by command results",
            ));
        }
        if !self.authority_grants.grants_nothing() {
            return Err(QualificationError::new(
                "authority_laundering",
                "qualification evidence cannot carry authority",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationEvidenceReportV1 {
    pub schema_version: u16,
    pub report_digest: DigestV1,
    pub body: QualificationEvidenceBodyV1,
}

impl QualificationEvidenceReportV1 {
    pub fn new(body: QualificationEvidenceBodyV1) -> Result<Self, QualificationError> {
        body.validate()?;
        let report_digest = body_digest("qualified.evidence-report.body.v1", &body)?;
        Ok(Self {
            schema_version: SCHEMA_VERSION_V1,
            report_digest,
            body,
        })
    }

    pub fn validate(&self) -> Result<(), QualificationError> {
        validate_schema(self.schema_version, "qualification evidence report")?;
        self.body.validate()?;
        if self.report_digest != body_digest("qualified.evidence-report.body.v1", &self.body)? {
            return Err(QualificationError::new(
                "qualification_report_identity_mismatch",
                "qualification report digest does not identify its canonical body",
            ));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, QualificationError> {
        self.validate()?;
        canonical_encode(self)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, QualificationError> {
        let value: Self = canonical_decode(bytes, "qualification evidence report")?;
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateProvenanceMethodV1 {
    LocalUnsignedExactBytes,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateProvenanceV1 {
    pub issuance_id: String,
    pub issuer_id: String,
    pub method: CertificateProvenanceMethodV1,
}

impl CertificateProvenanceV1 {
    fn validate(&self) -> Result<(), QualificationError> {
        validate_text("certificate.issuance_id", &self.issuance_id)?;
        validate_text("certificate.issuer_id", &self.issuer_id)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationCertificateBodyV1 {
    pub schema_version: u16,
    pub manifest_digest: DigestV1,
    pub qualification_report_digest: DigestV1,
    pub artifact_digests: Vec<ArtifactDigestBindingV1>,
    pub source: SourceIdentityV1,
    pub build: BuildIdentityV1,
    pub semantic_contracts: Vec<SemanticContractIdentityV1>,
    pub qualification_commands: Vec<QualificationCommandResultV1>,
    pub qualification_corpus_identities: Vec<DigestV1>,
    pub hostile_coverage: Vec<String>,
    pub earned_claims: Vec<String>,
    pub nonclaims: Vec<String>,
    pub provenance: CertificateProvenanceV1,
    pub lifecycle_authority_id: String,
    pub authority_grants: AuthorityGrantsV1,
}

impl QualificationCertificateBodyV1 {
    fn validate(&self) -> Result<(), QualificationError> {
        validate_schema(self.schema_version, "qualification certificate body")?;
        self.manifest_digest
            .validate()
            .map_err(|error| QualificationError::new("invalid_digest", error.to_string()))?;
        self.qualification_report_digest
            .validate()
            .map_err(|error| QualificationError::new("invalid_digest", error.to_string()))?;
        validate_sorted(
            "certificate.artifact_digests",
            &self.artifact_digests,
            MAX_QUALIFICATION_ARTIFACTS,
        )?;
        for binding in &self.artifact_digests {
            binding.validate()?;
        }
        self.source.validate()?;
        self.build.validate()?;
        validate_sorted(
            "certificate.semantic_contracts",
            &self.semantic_contracts,
            MAX_QUALIFICATION_ASSUMPTIONS,
        )?;
        for contract in &self.semantic_contracts {
            contract.validate()?;
        }
        if self.qualification_commands.is_empty()
            || self.qualification_commands.len() > MAX_QUALIFICATION_COMMANDS
        {
            return Err(QualificationError::new(
                "qualification_evidence_missing",
                "certificate contains no bounded qualification command evidence",
            ));
        }
        for (index, command) in self.qualification_commands.iter().enumerate() {
            command.validate()?;
            if command.sequence as usize != index + 1 || command.exit_code != 0 {
                return Err(QualificationError::new(
                    "qualification_command_failed",
                    "certificate command evidence is not contiguous and successful",
                ));
            }
        }
        validate_sorted(
            "certificate.corpus",
            &self.qualification_corpus_identities,
            MAX_QUALIFICATION_ASSUMPTIONS,
        )?;
        validate_sorted_texts(
            "certificate.hostile_coverage",
            &self.hostile_coverage,
            MAX_QUALIFICATION_CLAIMS,
        )?;
        validate_sorted_texts(
            "certificate.earned_claims",
            &self.earned_claims,
            MAX_QUALIFICATION_CLAIMS,
        )?;
        validate_sorted_texts(
            "certificate.nonclaims",
            &self.nonclaims,
            MAX_QUALIFICATION_CLAIMS,
        )?;
        self.provenance.validate()?;
        validate_text(
            "certificate.lifecycle_authority_id",
            &self.lifecycle_authority_id,
        )?;
        if !self.authority_grants.grants_nothing() {
            return Err(QualificationError::new(
                "authority_laundering",
                "qualification certificate cannot carry authority",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationCertificateV1 {
    pub schema_version: u16,
    pub certificate_digest: DigestV1,
    pub body: QualificationCertificateBodyV1,
}

impl QualificationCertificateV1 {
    pub fn issue(
        manifest: &QualifiedArtifactManifestV1,
        report: &QualificationEvidenceReportV1,
        provenance: CertificateProvenanceV1,
    ) -> Result<Self, QualificationError> {
        verify_manifest_report(manifest, report)?;
        let body = QualificationCertificateBodyV1 {
            schema_version: SCHEMA_VERSION_V1,
            manifest_digest: manifest.manifest_digest.clone(),
            qualification_report_digest: report.report_digest.clone(),
            artifact_digests: report.body.artifact_digests.clone(),
            source: report.body.source.clone(),
            build: report.body.build.clone(),
            semantic_contracts: report.body.semantic_contracts.clone(),
            qualification_commands: report.body.command_results.clone(),
            qualification_corpus_identities: report.body.qualification_corpus_identities.clone(),
            hostile_coverage: report.body.hostile_scenarios.clone(),
            earned_claims: report.body.earned_claims.clone(),
            nonclaims: report.body.nonclaims.clone(),
            provenance,
            lifecycle_authority_id: manifest.body.lifecycle_authority_id.clone(),
            authority_grants: AuthorityGrantsV1::none(),
        };
        body.validate()?;
        let certificate_digest = body_digest("qualified.certificate.body.v1", &body)?;
        Ok(Self {
            schema_version: SCHEMA_VERSION_V1,
            certificate_digest,
            body,
        })
    }

    pub fn validate(&self) -> Result<(), QualificationError> {
        validate_schema(self.schema_version, "qualification certificate")?;
        self.body.validate()?;
        if self.certificate_digest != body_digest("qualified.certificate.body.v1", &self.body)? {
            return Err(QualificationError::new(
                "certificate_identity_mismatch",
                "certificate digest does not identify its canonical body",
            ));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, QualificationError> {
        self.validate()?;
        canonical_encode(self)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, QualificationError> {
        let value: Self = canonical_decode(bytes, "qualification certificate")?;
        value.validate()?;
        Ok(value)
    }
}

pub fn verify_qualification_package(
    manifest: &QualifiedArtifactManifestV1,
    report: &QualificationEvidenceReportV1,
    certificate: &QualificationCertificateV1,
) -> Result<(), QualificationError> {
    verify_manifest_report(manifest, report)?;
    certificate.validate()?;
    if certificate.body.manifest_digest != manifest.manifest_digest
        || certificate.body.qualification_report_digest != report.report_digest
        || certificate.body.artifact_digests != report.body.artifact_digests
        || certificate.body.source != report.body.source
        || certificate.body.build != report.body.build
        || certificate.body.semantic_contracts != report.body.semantic_contracts
        || certificate.body.qualification_commands != report.body.command_results
        || certificate.body.qualification_corpus_identities
            != report.body.qualification_corpus_identities
        || certificate.body.hostile_coverage != report.body.hostile_scenarios
        || certificate.body.earned_claims != report.body.earned_claims
        || certificate.body.nonclaims != report.body.nonclaims
        || certificate.body.lifecycle_authority_id != manifest.body.lifecycle_authority_id
    {
        return Err(QualificationError::new(
            "certificate_package_mismatch",
            "certificate does not exactly bind the checked manifest and report",
        ));
    }
    Ok(())
}

fn verify_manifest_report(
    manifest: &QualifiedArtifactManifestV1,
    report: &QualificationEvidenceReportV1,
) -> Result<(), QualificationError> {
    manifest.validate()?;
    report.validate()?;
    if report.body.manifest_digest != manifest.manifest_digest
        || report.body.artifact_digests != manifest.body.artifact_digests()
        || report.body.source != manifest.body.source
        || report.body.build != manifest.body.build
        || report.body.semantic_contracts != manifest.body.semantic_contracts
        || report.body.qualification_corpus_identities
            != manifest.body.qualification_corpus_identities
        || !is_subset(&report.body.earned_claims, &manifest.body.declared_claims)
        || report.body.nonclaims != manifest.body.nonclaims
    {
        return Err(QualificationError::new(
            "qualification_evidence_mismatch",
            "checked qualification evidence does not exactly support the manifest",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GenerationLifecycleKindV1 {
    Superseded,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationLifecycleFactBodyV1 {
    pub schema_version: u16,
    pub authority_id: String,
    pub fact_sequence: u64,
    pub certificate_digest: DigestV1,
    pub kind: GenerationLifecycleKindV1,
    pub successor_manifest_digest: Option<DigestV1>,
    pub successor_certificate_digest: Option<DigestV1>,
    pub reason: String,
    pub authority_grants: AuthorityGrantsV1,
}

impl GenerationLifecycleFactBodyV1 {
    fn validate(&self) -> Result<(), QualificationError> {
        validate_schema(self.schema_version, "generation lifecycle fact body")?;
        validate_text("lifecycle.authority_id", &self.authority_id)?;
        if self.fact_sequence == 0 {
            return Err(QualificationError::new(
                "invalid_lifecycle_fact",
                "lifecycle fact sequence must be nonzero",
            ));
        }
        self.certificate_digest
            .validate()
            .map_err(|error| QualificationError::new("invalid_digest", error.to_string()))?;
        match self.kind {
            GenerationLifecycleKindV1::Superseded => {
                let Some(manifest) = &self.successor_manifest_digest else {
                    return Err(QualificationError::new(
                        "invalid_lifecycle_fact",
                        "supersession requires exact successor manifest and certificate",
                    ));
                };
                let Some(certificate) = &self.successor_certificate_digest else {
                    return Err(QualificationError::new(
                        "invalid_lifecycle_fact",
                        "supersession requires exact successor manifest and certificate",
                    ));
                };
                manifest.validate().map_err(|error| {
                    QualificationError::new("invalid_digest", error.to_string())
                })?;
                certificate.validate().map_err(|error| {
                    QualificationError::new("invalid_digest", error.to_string())
                })?;
            }
            GenerationLifecycleKindV1::Revoked => {
                if self.successor_manifest_digest.is_some()
                    || self.successor_certificate_digest.is_some()
                {
                    return Err(QualificationError::new(
                        "invalid_lifecycle_fact",
                        "revocation cannot imply a successor activation",
                    ));
                }
            }
        }
        validate_text("lifecycle.reason", &self.reason)?;
        if !self.authority_grants.grants_nothing() {
            return Err(QualificationError::new(
                "authority_laundering",
                "lifecycle fact cannot grant revocation or any other authority",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationLifecycleFactV1 {
    pub schema_version: u16,
    pub fact_digest: DigestV1,
    pub body: GenerationLifecycleFactBodyV1,
}

impl GenerationLifecycleFactV1 {
    pub fn new(body: GenerationLifecycleFactBodyV1) -> Result<Self, QualificationError> {
        body.validate()?;
        let fact_digest = body_digest("qualified.lifecycle-fact.body.v1", &body)?;
        Ok(Self {
            schema_version: SCHEMA_VERSION_V1,
            fact_digest,
            body,
        })
    }

    pub fn validate(&self) -> Result<(), QualificationError> {
        validate_schema(self.schema_version, "generation lifecycle fact")?;
        self.body.validate()?;
        if self.fact_digest != body_digest("qualified.lifecycle-fact.body.v1", &self.body)? {
            return Err(QualificationError::new(
                "lifecycle_fact_identity_mismatch",
                "lifecycle fact digest does not identify its body",
            ));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, QualificationError> {
        self.validate()?;
        canonical_encode(self)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, QualificationError> {
        let value: Self = canonical_decode(bytes, "generation lifecycle fact")?;
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum LocalCertificateStatusV1 {
    Accepted { observed_through_sequence: u64 },
    Unknown,
    Superseded { fact: GenerationLifecycleFactV1 },
    Revoked { fact: GenerationLifecycleFactV1 },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalActivationAcceptanceV1 {
    pub schema_version: u16,
    pub accepted_certificate_digest: DigestV1,
    pub lifecycle_authority_id: String,
    pub certificate_status: LocalCertificateStatusV1,
    pub pinned_superseded_activation_allowed: bool,
    pub authority_grants: AuthorityGrantsV1,
}

impl LocalActivationAcceptanceV1 {
    pub fn validate(&self) -> Result<(), QualificationError> {
        validate_schema(self.schema_version, "local activation acceptance")?;
        self.accepted_certificate_digest
            .validate()
            .map_err(|error| QualificationError::new("invalid_digest", error.to_string()))?;
        validate_text(
            "acceptance.lifecycle_authority_id",
            &self.lifecycle_authority_id,
        )?;
        if self.pinned_superseded_activation_allowed {
            return Err(QualificationError::new(
                "unsupported_acceptance_policy",
                "v1 deliberately does not support pinned superseded activation",
            ));
        }
        match &self.certificate_status {
            LocalCertificateStatusV1::Accepted { .. } | LocalCertificateStatusV1::Unknown => {}
            LocalCertificateStatusV1::Superseded { fact } => {
                fact.validate()?;
                if fact.body.kind != GenerationLifecycleKindV1::Superseded {
                    return Err(QualificationError::new(
                        "invalid_lifecycle_fact",
                        "superseded status carries another lifecycle fact kind",
                    ));
                }
            }
            LocalCertificateStatusV1::Revoked { fact } => {
                fact.validate()?;
                if fact.body.kind != GenerationLifecycleKindV1::Revoked {
                    return Err(QualificationError::new(
                        "invalid_lifecycle_fact",
                        "revoked status carries another lifecycle fact kind",
                    ));
                }
            }
        }
        if let LocalCertificateStatusV1::Superseded { fact }
        | LocalCertificateStatusV1::Revoked { fact } = &self.certificate_status
        {
            if fact.body.authority_id != self.lifecycle_authority_id
                || fact.body.certificate_digest != self.accepted_certificate_digest
            {
                return Err(QualificationError::new(
                    "lifecycle_authority_mismatch",
                    "lifecycle fact is not from the configured local authority for this certificate",
                ));
            }
        }
        if !self.authority_grants.grants_nothing() {
            return Err(QualificationError::new(
                "authority_laundering",
                "local acceptance policy cannot emit authority",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeBindingStateV1 {
    Unbound,
    BindingPending,
    QualifiedAndMatched,
    MissingCertificate,
    UnsupportedCertificate,
    ManifestMismatch,
    ExecutableMismatch,
    EvaluatorMismatch,
    PolicyMismatch,
    ProfileMismatch,
    ObserverSetMismatch,
    ObservationPolicyMismatch,
    ConfigurationMismatch,
    ContractMismatch,
    QualificationEvidenceMissing,
    Superseded,
    Revoked,
    MutableAfterActivation,
    MeasurementUnavailable,
    Ambiguous,
}

impl RuntimeBindingStateV1 {
    #[must_use]
    pub const fn permits_current(self) -> bool {
        matches!(self, Self::QualifiedAndMatched)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BindingMismatchV1 {
    pub code: String,
    pub role: Option<ArtifactRoleV1>,
    pub expected: Option<DigestV1>,
    pub observed: Option<DigestV1>,
    pub detail: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum MeasurementProvenanceV1 {
    ProcSelfExeOpenedHandle {
        link_label: String,
        device: u64,
        inode: u64,
    },
    EmbeddedArtifact {
        name: String,
    },
    OwnedCanonicalValue {
        type_name: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactMeasurementV1 {
    pub role: ArtifactRoleV1,
    pub content_digest: DigestV1,
    pub byte_length: u64,
    pub provenance: MeasurementProvenanceV1,
    pub caller_supplied: bool,
}

impl ArtifactMeasurementV1 {
    pub fn validate(&self) -> Result<(), QualificationError> {
        self.content_digest
            .validate()
            .map_err(|error| QualificationError::new("invalid_digest", error.to_string()))?;
        if self.byte_length == 0 {
            return Err(QualificationError::new(
                "invalid_measurement",
                "artifact measurement byte length must be nonzero",
            ));
        }
        match &self.provenance {
            MeasurementProvenanceV1::ProcSelfExeOpenedHandle { link_label, .. } => {
                validate_text("measurement.link_label", link_label)?;
                if self.role != ArtifactRoleV1::RunningExecutable {
                    return Err(QualificationError::new(
                        "ambiguous_measurement",
                        "proc executable provenance is valid only for executable role",
                    ));
                }
            }
            MeasurementProvenanceV1::EmbeddedArtifact { name } => {
                validate_text("measurement.embedded_name", name)?;
            }
            MeasurementProvenanceV1::OwnedCanonicalValue { type_name } => {
                validate_text("measurement.type_name", type_name)?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalProcessIdentityV1 {
    pub process_epoch_id: IncarnationId,
    pub process_id: u32,
    pub linux_boot_id_digest: DigestV1,
    pub process_start_ticks: u64,
}

impl LocalProcessIdentityV1 {
    fn validate(&self) -> Result<(), QualificationError> {
        self.process_epoch_id
            .validate()
            .map_err(|error| QualificationError::new("invalid_identity", error.to_string()))?;
        if self.process_id == 0 {
            return Err(QualificationError::new(
                "measurement_unavailable",
                "process identity has process id zero",
            ));
        }
        self.linux_boot_id_digest
            .validate()
            .map_err(|error| QualificationError::new("invalid_digest", error.to_string()))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationReceiptBodyV1 {
    pub schema_version: u16,
    pub manifest_digest: Option<DigestV1>,
    pub qualification_certificate_digest: Option<DigestV1>,
    pub qualification_report_digest: Option<DigestV1>,
    pub generation_set: Option<QualifiedGenerationSetV1>,
    pub process: Option<LocalProcessIdentityV1>,
    pub activation_occurrence_id: IncarnationId,
    pub activation_sequence: u64,
    pub receiver_incarnation: IncarnationId,
    pub receiver_clock_id: ClockId,
    pub activated_at_monotonic_ms: u64,
    pub runtime_version: String,
    pub target_platform: String,
    pub measurements: Vec<ArtifactMeasurementV1>,
    pub state: RuntimeBindingStateV1,
    pub mismatches: Vec<BindingMismatchV1>,
    pub all_required_artifacts_measured: bool,
    pub any_measurement_caller_supplied: bool,
    pub mutable_after_activation: bool,
    pub independent_attestation_claimed: bool,
    pub authority_grants: AuthorityGrantsV1,
}

impl ActivationReceiptBodyV1 {
    fn validate(&self) -> Result<(), QualificationError> {
        validate_schema(self.schema_version, "activation receipt body")?;
        for digest in [
            self.manifest_digest.as_ref(),
            self.qualification_certificate_digest.as_ref(),
            self.qualification_report_digest.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            digest
                .validate()
                .map_err(|error| QualificationError::new("invalid_digest", error.to_string()))?;
        }
        if let Some(generation_set) = &self.generation_set {
            generation_set.validate()?;
        }
        if let Some(process) = &self.process {
            process.validate()?;
        }
        self.activation_occurrence_id
            .validate()
            .map_err(|error| QualificationError::new("invalid_identity", error.to_string()))?;
        if self.activation_sequence == 0 {
            return Err(QualificationError::new(
                "invalid_activation_receipt",
                "activation occurrence sequence must be nonzero",
            ));
        }
        self.receiver_incarnation
            .validate()
            .map_err(|error| QualificationError::new("invalid_identity", error.to_string()))?;
        self.receiver_clock_id
            .validate()
            .map_err(|error| QualificationError::new("invalid_identity", error.to_string()))?;
        validate_text("activation.runtime_version", &self.runtime_version)?;
        validate_text("activation.target_platform", &self.target_platform)?;
        validate_measurements(&self.measurements, false)?;
        if self.mismatches.len() > MAX_QUALIFICATION_ARTIFACTS {
            return Err(QualificationError::new(
                "bound_exceeded",
                "activation mismatch collection exceeds its bound",
            ));
        }
        for mismatch in &self.mismatches {
            validate_text("activation.mismatch.code", &mismatch.code)?;
            validate_text("activation.mismatch.detail", &mismatch.detail)?;
            for digest in [mismatch.expected.as_ref(), mismatch.observed.as_ref()]
                .into_iter()
                .flatten()
            {
                digest.validate().map_err(|error| {
                    QualificationError::new("invalid_digest", error.to_string())
                })?;
            }
        }
        if self.state == RuntimeBindingStateV1::QualifiedAndMatched
            && (!self.all_required_artifacts_measured
                || self.any_measurement_caller_supplied
                || self.mutable_after_activation
                || !self.mismatches.is_empty()
                || self.process.is_none()
                || self.manifest_digest.is_none()
                || self.qualification_certificate_digest.is_none()
                || self.qualification_report_digest.is_none()
                || self.generation_set.is_none())
        {
            return Err(QualificationError::new(
                "invalid_matched_activation",
                "matched activation receipt lacks an exact non-caller-supplied premise",
            ));
        }
        if self.independent_attestation_claimed || !self.authority_grants.grants_nothing() {
            return Err(QualificationError::new(
                "authority_laundering",
                "local activation receipt cannot claim attestation or authority",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationReceiptV1 {
    pub schema_version: u16,
    pub receipt_digest: DigestV1,
    pub body: ActivationReceiptBodyV1,
}

impl ActivationReceiptV1 {
    fn new(body: ActivationReceiptBodyV1) -> Result<Self, QualificationError> {
        body.validate()?;
        let receipt_digest = body_digest("qualified.activation-receipt.body.v1", &body)?;
        Ok(Self {
            schema_version: SCHEMA_VERSION_V1,
            receipt_digest,
            body,
        })
    }

    pub fn validate(&self) -> Result<(), QualificationError> {
        validate_schema(self.schema_version, "activation receipt")?;
        self.body.validate()?;
        if self.receipt_digest != body_digest("qualified.activation-receipt.body.v1", &self.body)? {
            return Err(QualificationError::new(
                "activation_receipt_identity_mismatch",
                "activation receipt digest does not identify its canonical body",
            ));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, QualificationError> {
        self.validate()?;
        canonical_encode(self)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, QualificationError> {
        let value: Self = canonical_decode(bytes, "activation receipt")?;
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedGenerationBindingV1 {
    pub schema_version: u16,
    pub manifest_digest: DigestV1,
    pub qualification_certificate_digest: DigestV1,
    pub activation_receipt_digest: DigestV1,
    pub activation_occurrence_id: IncarnationId,
    pub process_epoch_id: IncarnationId,
    pub generation_set: QualifiedGenerationSetV1,
    pub authority_grants: AuthorityGrantsV1,
}

impl QualifiedGenerationBindingV1 {
    pub fn validate(&self) -> Result<(), QualificationError> {
        validate_schema(self.schema_version, "qualified generation binding")?;
        for digest in [
            &self.manifest_digest,
            &self.qualification_certificate_digest,
            &self.activation_receipt_digest,
        ] {
            digest
                .validate()
                .map_err(|error| QualificationError::new("invalid_digest", error.to_string()))?;
        }
        self.activation_occurrence_id
            .validate()
            .map_err(|error| QualificationError::new("invalid_identity", error.to_string()))?;
        self.process_epoch_id
            .validate()
            .map_err(|error| QualificationError::new("invalid_identity", error.to_string()))?;
        self.generation_set.validate()?;
        if !self.authority_grants.grants_nothing() {
            return Err(QualificationError::new(
                "authority_laundering",
                "qualified binding cannot grant authority",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn identity_digest(&self) -> DigestV1 {
        digest_parts(
            "qualified.generation-binding.v1",
            &[
                self.manifest_digest.as_str().as_bytes(),
                self.qualification_certificate_digest.as_str().as_bytes(),
                self.activation_receipt_digest.as_str().as_bytes(),
                self.activation_occurrence_id.as_str().as_bytes(),
                self.process_epoch_id.as_str().as_bytes(),
                self.generation_set.identity_digest().as_str().as_bytes(),
            ],
        )
    }
}

struct ExecutableMeasurementGuard {
    file: File,
    expected: ArtifactMeasurementV1,
    metadata: ExecutableMetadataSnapshot,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecutableMetadataSnapshot {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[derive(Clone, Debug)]
struct ExecutableContentCache {
    metadata: ExecutableMetadataSnapshot,
    content_digest: DigestV1,
}

#[cfg(target_os = "linux")]
impl ExecutableMetadataSnapshot {
    fn observe(file: &File) -> Result<Self, QualificationError> {
        let metadata = file.metadata().map_err(|error| {
            QualificationError::new(
                "measurement_unavailable",
                format!("cannot inspect retained executable: {error}"),
            )
        })?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }
}

#[cfg(not(target_os = "linux"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecutableMetadataSnapshot;

#[cfg(not(target_os = "linux"))]
impl ExecutableMetadataSnapshot {
    fn observe(_file: &File) -> Result<Self, QualificationError> {
        Err(QualificationError::new(
            "measurement_unavailable",
            "v1 executable measurement is qualified only on Linux",
        ))
    }
}

/// A live accepted activation. Private fields, no `Clone`, and no serde are
/// deliberate: historical bytes cannot reconstruct the activation premise.
pub struct VerifiedActivationV1 {
    binding: QualifiedGenerationBindingV1,
    receipt: ActivationReceiptV1,
    measurements: Vec<ArtifactMeasurementV1>,
    executable: ExecutableMeasurementGuard,
}

impl fmt::Debug for VerifiedActivationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedActivationV1")
            .field("binding", &self.binding)
            .field("receipt", &self.receipt)
            .field("measurements", &self.measurements)
            .field("executable_handle_retained", &true)
            .finish()
    }
}

impl VerifiedActivationV1 {
    #[must_use]
    pub const fn binding(&self) -> &QualifiedGenerationBindingV1 {
        &self.binding
    }

    #[must_use]
    pub const fn receipt(&self) -> &ActivationReceiptV1 {
        &self.receipt
    }

    #[must_use]
    pub fn measurements(&self) -> &[ArtifactMeasurementV1] {
        &self.measurements
    }

    pub fn revalidate_executable(&mut self) -> Result<(), QualificationError> {
        let metadata = ExecutableMetadataSnapshot::observe(&self.executable.file)?;
        if metadata == self.executable.metadata {
            return Ok(());
        }
        let observed = measure_open_executable(&mut self.executable.file)?;
        if observed.content_digest != self.executable.expected.content_digest
            || observed.byte_length != self.executable.expected.byte_length
        {
            return Err(QualificationError::new(
                "mutable_after_activation",
                "retained executable object no longer matches its activation measurement",
            ));
        }
        self.executable.metadata = metadata;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct LocalActivationContextV1 {
    pub expected_generation_set: QualifiedGenerationSetV1,
    pub receiver_incarnation: IncarnationId,
    pub receiver_clock_id: ClockId,
    pub activated_at_monotonic_ms: u64,
    pub runtime_version: String,
    pub target_platform: String,
    pub semantic_measurements: Vec<ArtifactMeasurementV1>,
}

#[derive(Debug)]
pub struct LocalActivationAttemptV1 {
    pub receipt: ActivationReceiptV1,
    pub accepted: Option<VerifiedActivationV1>,
}

#[allow(clippy::too_many_lines)]
pub fn verify_local_activation(
    manifest_bytes: Option<&[u8]>,
    certificate_bytes: Option<&[u8]>,
    report_bytes: Option<&[u8]>,
    acceptance: &LocalActivationAcceptanceV1,
    context: LocalActivationContextV1,
) -> Result<LocalActivationAttemptV1, QualificationError> {
    context.expected_generation_set.validate()?;
    context
        .receiver_incarnation
        .validate()
        .map_err(|error| QualificationError::new("invalid_identity", error.to_string()))?;
    context
        .receiver_clock_id
        .validate()
        .map_err(|error| QualificationError::new("invalid_identity", error.to_string()))?;
    validate_text("activation.runtime_version", &context.runtime_version)?;
    validate_text("activation.target_platform", &context.target_platform)?;
    validate_measurements(&context.semantic_measurements, true)?;
    acceptance.validate()?;

    let activation_sequence = NEXT_ACTIVATION_OCCURRENCE.fetch_add(1, Ordering::Relaxed);
    let process = observe_local_process_identity().ok();
    let activation_occurrence_id = activation_occurrence_id(process.as_ref(), activation_sequence);

    let mut state = RuntimeBindingStateV1::BindingPending;
    let mut mismatches = Vec::new();
    let manifest = match manifest_bytes {
        Some(bytes) => match QualifiedArtifactManifestV1::decode_canonical(bytes) {
            Ok(value) => Some(value),
            Err(error) => {
                state = RuntimeBindingStateV1::ManifestMismatch;
                mismatches.push(mismatch("manifest_invalid", None, error.to_string()));
                None
            }
        },
        None => {
            state = RuntimeBindingStateV1::ManifestMismatch;
            mismatches.push(mismatch(
                "manifest_missing",
                None,
                "qualified artifact manifest is missing",
            ));
            None
        }
    };
    let certificate = match certificate_bytes {
        Some(bytes) => match QualificationCertificateV1::decode_canonical(bytes) {
            Ok(value) => Some(value),
            Err(error) => {
                if state == RuntimeBindingStateV1::BindingPending {
                    state = RuntimeBindingStateV1::UnsupportedCertificate;
                }
                mismatches.push(mismatch("certificate_invalid", None, error.to_string()));
                None
            }
        },
        None => {
            if state == RuntimeBindingStateV1::BindingPending {
                state = RuntimeBindingStateV1::MissingCertificate;
            }
            mismatches.push(mismatch(
                "certificate_missing",
                None,
                "qualification certificate is missing",
            ));
            None
        }
    };
    let report = match report_bytes {
        Some(bytes) => match QualificationEvidenceReportV1::decode_canonical(bytes) {
            Ok(value) => Some(value),
            Err(error) => {
                if state == RuntimeBindingStateV1::BindingPending {
                    state = RuntimeBindingStateV1::QualificationEvidenceMissing;
                }
                mismatches.push(mismatch(
                    "qualification_report_invalid",
                    None,
                    error.to_string(),
                ));
                None
            }
        },
        None => {
            if state == RuntimeBindingStateV1::BindingPending {
                state = RuntimeBindingStateV1::QualificationEvidenceMissing;
            }
            mismatches.push(mismatch(
                "qualification_report_missing",
                None,
                "checked qualification report is missing",
            ));
            None
        }
    };

    if let (Some(manifest), Some(report), Some(certificate)) = (&manifest, &report, &certificate) {
        if let Err(error) = verify_qualification_package(manifest, report, certificate) {
            state = RuntimeBindingStateV1::ManifestMismatch;
            mismatches.push(mismatch("package_cross_binding", None, error.to_string()));
        }
        if certificate.certificate_digest != acceptance.accepted_certificate_digest
            || certificate.body.lifecycle_authority_id != acceptance.lifecycle_authority_id
        {
            state = RuntimeBindingStateV1::Ambiguous;
            mismatches.push(mismatch(
                "local_acceptance_mismatch",
                None,
                "local acceptance policy does not name this exact certificate and authority",
            ));
        }
        match &acceptance.certificate_status {
            LocalCertificateStatusV1::Accepted { .. } => {}
            LocalCertificateStatusV1::Unknown => {
                state = RuntimeBindingStateV1::Ambiguous;
                mismatches.push(mismatch(
                    "lifecycle_status_unknown",
                    None,
                    "local revocation status is not known",
                ));
            }
            LocalCertificateStatusV1::Superseded { .. } => {
                state = RuntimeBindingStateV1::Superseded;
                mismatches.push(mismatch(
                    "certificate_superseded",
                    None,
                    "local accepted supersession prevents activation",
                ));
            }
            LocalCertificateStatusV1::Revoked { .. } => {
                state = RuntimeBindingStateV1::Revoked;
                mismatches.push(mismatch(
                    "certificate_revoked",
                    None,
                    "local accepted revocation prevents activation",
                ));
            }
        }
        if manifest.body.generation_set != context.expected_generation_set {
            state = RuntimeBindingStateV1::Ambiguous;
            mismatches.push(mismatch(
                "generation_set_mismatch",
                None,
                "manifest generation set does not match the runtime context",
            ));
        }
    }

    let executable_result = open_and_measure_executable();
    let mut executable_guard = None;
    let mut measurements = context.semantic_measurements;
    match executable_result {
        Ok((file, measurement)) => {
            let metadata = ExecutableMetadataSnapshot::observe(&file)?;
            measurements.push(measurement.clone());
            measurements.sort_by_key(|measurement| measurement.role);
            executable_guard = Some(ExecutableMeasurementGuard {
                file,
                expected: measurement,
                metadata,
            });
        }
        Err(error) => {
            if state == RuntimeBindingStateV1::BindingPending {
                state = RuntimeBindingStateV1::MeasurementUnavailable;
            }
            mismatches.push(mismatch(
                "executable_measurement",
                Some(ArtifactRoleV1::RunningExecutable),
                error.to_string(),
            ));
        }
    }

    if let Some(manifest) = &manifest {
        for artifact in manifest
            .body
            .artifacts
            .iter()
            .filter(|artifact| artifact.activation_required)
        {
            match measurements
                .iter()
                .find(|measurement| measurement.role == artifact.role)
            {
                Some(measurement)
                    if measurement.content_digest == artifact.content_digest
                        && measurement.byte_length == artifact.byte_length
                        && !measurement.caller_supplied => {}
                Some(measurement) => {
                    if state == RuntimeBindingStateV1::BindingPending {
                        state = artifact.role.mismatch_state();
                    }
                    mismatches.push(BindingMismatchV1 {
                        code: "artifact_identity_mismatch".to_owned(),
                        role: Some(artifact.role),
                        expected: Some(artifact.content_digest.clone()),
                        observed: Some(measurement.content_digest.clone()),
                        detail: "active artifact does not exactly match qualified identity"
                            .to_owned(),
                    });
                }
                None => {
                    if state == RuntimeBindingStateV1::BindingPending {
                        state = RuntimeBindingStateV1::MeasurementUnavailable;
                    }
                    mismatches.push(mismatch(
                        "artifact_measurement_missing",
                        Some(artifact.role),
                        "required active artifact was not measured",
                    ));
                }
            }
        }
    }

    let all_required_artifacts_measured = manifest.as_ref().is_some_and(|manifest| {
        manifest
            .body
            .artifacts
            .iter()
            .filter(|artifact| artifact.activation_required)
            .all(|artifact| {
                measurements.iter().any(|measurement| {
                    measurement.role == artifact.role
                        && measurement.content_digest == artifact.content_digest
                        && measurement.byte_length == artifact.byte_length
                        && !measurement.caller_supplied
                })
            })
    });
    let any_measurement_caller_supplied = measurements
        .iter()
        .any(|measurement| measurement.caller_supplied);
    if state == RuntimeBindingStateV1::BindingPending
        && process.is_some()
        && all_required_artifacts_measured
        && !any_measurement_caller_supplied
        && mismatches.is_empty()
    {
        state = RuntimeBindingStateV1::QualifiedAndMatched;
    } else if state == RuntimeBindingStateV1::BindingPending {
        state = RuntimeBindingStateV1::MeasurementUnavailable;
    }

    let receipt_body = ActivationReceiptBodyV1 {
        schema_version: SCHEMA_VERSION_V1,
        manifest_digest: manifest.as_ref().map(|value| value.manifest_digest.clone()),
        qualification_certificate_digest: certificate
            .as_ref()
            .map(|value| value.certificate_digest.clone()),
        qualification_report_digest: report.as_ref().map(|value| value.report_digest.clone()),
        generation_set: manifest
            .as_ref()
            .map(|value| value.body.generation_set.clone()),
        process: process.clone(),
        activation_occurrence_id: activation_occurrence_id.clone(),
        activation_sequence,
        receiver_incarnation: context.receiver_incarnation,
        receiver_clock_id: context.receiver_clock_id,
        activated_at_monotonic_ms: context.activated_at_monotonic_ms,
        runtime_version: context.runtime_version,
        target_platform: context.target_platform,
        measurements: measurements.clone(),
        state,
        mismatches,
        all_required_artifacts_measured,
        any_measurement_caller_supplied,
        mutable_after_activation: false,
        independent_attestation_claimed: false,
        authority_grants: AuthorityGrantsV1::none(),
    };
    let receipt = ActivationReceiptV1::new(receipt_body)?;
    let accepted = if state == RuntimeBindingStateV1::QualifiedAndMatched {
        let manifest = manifest.expect("matched state has manifest");
        let certificate = certificate.expect("matched state has certificate");
        let process = process.expect("matched state has process identity");
        let executable = executable_guard.expect("matched state has executable measurement");
        let binding = QualifiedGenerationBindingV1 {
            schema_version: SCHEMA_VERSION_V1,
            manifest_digest: manifest.manifest_digest,
            qualification_certificate_digest: certificate.certificate_digest,
            activation_receipt_digest: receipt.receipt_digest.clone(),
            activation_occurrence_id,
            process_epoch_id: process.process_epoch_id,
            generation_set: manifest.body.generation_set,
            authority_grants: AuthorityGrantsV1::none(),
        };
        binding.validate()?;
        Some(VerifiedActivationV1 {
            binding,
            receipt: receipt.clone(),
            measurements,
            executable,
        })
    } else {
        None
    };
    Ok(LocalActivationAttemptV1 { receipt, accepted })
}

/// Measure the exact bytes exposed by one newly opened `/proc/self/exe`
/// handle. This is content identity, not proof of loader or kernel integrity.
pub fn observe_running_executable() -> Result<ArtifactMeasurementV1, QualificationError> {
    let (_, measurement) = open_and_measure_executable()?;
    Ok(measurement)
}

#[cfg(target_os = "linux")]
fn open_and_measure_executable() -> Result<(File, ArtifactMeasurementV1), QualificationError> {
    let mut file = File::open("/proc/self/exe").map_err(|error| {
        QualificationError::new(
            "measurement_unavailable",
            format!("cannot open /proc/self/exe: {error}"),
        )
    })?;
    let before = ExecutableMetadataSnapshot::observe(&file)?;
    let cache = EXECUTABLE_CONTENT_CACHE.get_or_init(|| Mutex::new(None));
    let cached_digest = cache
        .lock()
        .map_err(|_| {
            QualificationError::new(
                "measurement_unavailable",
                "process-local executable measurement cache is poisoned",
            )
        })?
        .as_ref()
        .filter(|entry| entry.metadata == before)
        .map(|entry| entry.content_digest.clone());
    let measurement = if let Some(content_digest) = cached_digest {
        let after = ExecutableMetadataSnapshot::observe(&file)?;
        if before != after {
            return Err(QualificationError::new(
                "ambiguous_measurement",
                "opened executable metadata changed while cached content identity was checked",
            ));
        }
        executable_measurement_from_identity(content_digest, before)?
    } else {
        let measurement = measure_open_executable(&mut file)?;
        let after = ExecutableMetadataSnapshot::observe(&file)?;
        let mut cache = cache.lock().map_err(|_| {
            QualificationError::new(
                "measurement_unavailable",
                "process-local executable measurement cache is poisoned",
            )
        })?;
        *cache = Some(ExecutableContentCache {
            metadata: after,
            content_digest: measurement.content_digest.clone(),
        });
        measurement
    };
    Ok((file, measurement))
}

#[cfg(target_os = "linux")]
fn executable_measurement_from_identity(
    content_digest: DigestV1,
    metadata: ExecutableMetadataSnapshot,
) -> Result<ArtifactMeasurementV1, QualificationError> {
    let link_label = std::fs::read_link("/proc/self/exe")
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "/proc/self/exe (link label unavailable)".to_owned());
    validate_text("measurement.link_label", &link_label)?;
    Ok(ArtifactMeasurementV1 {
        role: ArtifactRoleV1::RunningExecutable,
        content_digest,
        byte_length: metadata.length,
        provenance: MeasurementProvenanceV1::ProcSelfExeOpenedHandle {
            link_label,
            device: metadata.device,
            inode: metadata.inode,
        },
        caller_supplied: false,
    })
}

#[cfg(not(target_os = "linux"))]
fn open_and_measure_executable() -> Result<(File, ArtifactMeasurementV1), QualificationError> {
    Err(QualificationError::new(
        "measurement_unavailable",
        "v1 executable measurement is qualified only on Linux",
    ))
}

#[cfg(target_os = "linux")]
fn measure_open_executable(file: &mut File) -> Result<ArtifactMeasurementV1, QualificationError> {
    let before = file.metadata().map_err(|error| {
        QualificationError::new(
            "measurement_unavailable",
            format!("cannot inspect opened executable: {error}"),
        )
    })?;
    if !before.file_type().is_file() || before.len() == 0 {
        return Err(QualificationError::new(
            "measurement_unavailable",
            "opened executable is not a nonempty regular file",
        ));
    }
    if before.len() > MAX_EXECUTABLE_MEASUREMENT_BYTES {
        return Err(QualificationError::new(
            "bound_exceeded",
            "running executable exceeds the v1 measurement bound",
        ));
    }
    file.seek(SeekFrom::Start(0)).map_err(|error| {
        QualificationError::new(
            "measurement_unavailable",
            format!("cannot seek opened executable: {error}"),
        )
    })?;
    let mut bytes = Vec::with_capacity(usize::try_from(before.len()).map_err(|_| {
        QualificationError::new(
            "bound_exceeded",
            "executable length does not fit memory bound",
        )
    })?);
    file.take(MAX_EXECUTABLE_MEASUREMENT_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| {
            QualificationError::new(
                "measurement_unavailable",
                format!("cannot read opened executable: {error}"),
            )
        })?;
    if bytes.len() as u64 != before.len() || bytes.len() as u64 > MAX_EXECUTABLE_MEASUREMENT_BYTES {
        return Err(QualificationError::new(
            "ambiguous_measurement",
            "opened executable length changed or exceeded its bound while measured",
        ));
    }
    let after = file.metadata().map_err(|error| {
        QualificationError::new(
            "measurement_unavailable",
            format!("cannot reinspect opened executable: {error}"),
        )
    })?;
    if before.dev() != after.dev() || before.ino() != after.ino() || before.len() != after.len() {
        return Err(QualificationError::new(
            "ambiguous_measurement",
            "opened executable identity changed during measurement",
        ));
    }
    file.seek(SeekFrom::Start(0)).map_err(|error| {
        QualificationError::new(
            "measurement_unavailable",
            format!("cannot reset opened executable: {error}"),
        )
    })?;
    let link_label = std::fs::read_link("/proc/self/exe")
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "/proc/self/exe (link label unavailable)".to_owned());
    validate_text("measurement.link_label", &link_label)?;
    Ok(ArtifactMeasurementV1 {
        role: ArtifactRoleV1::RunningExecutable,
        content_digest: artifact_content_digest(&bytes),
        byte_length: bytes.len() as u64,
        provenance: MeasurementProvenanceV1::ProcSelfExeOpenedHandle {
            link_label,
            device: before.dev(),
            inode: before.ino(),
        },
        caller_supplied: false,
    })
}

#[cfg(not(target_os = "linux"))]
fn measure_open_executable(_file: &mut File) -> Result<ArtifactMeasurementV1, QualificationError> {
    Err(QualificationError::new(
        "measurement_unavailable",
        "v1 executable measurement is qualified only on Linux",
    ))
}

#[cfg(target_os = "linux")]
fn observe_local_process_identity() -> Result<LocalProcessIdentityV1, QualificationError> {
    let boot_id = std::fs::read("/proc/sys/kernel/random/boot_id").map_err(|error| {
        QualificationError::new(
            "measurement_unavailable",
            format!("cannot read Linux boot identity: {error}"),
        )
    })?;
    if boot_id.is_empty() || boot_id.len() > 256 {
        return Err(QualificationError::new(
            "ambiguous_measurement",
            "Linux boot identity has an invalid bound",
        ));
    }
    let stat = std::fs::read_to_string("/proc/self/stat").map_err(|error| {
        QualificationError::new(
            "measurement_unavailable",
            format!("cannot read process start identity: {error}"),
        )
    })?;
    let close = stat.rfind(')').ok_or_else(|| {
        QualificationError::new(
            "ambiguous_measurement",
            "process stat has no command terminator",
        )
    })?;
    let fields = stat[close + 1..].split_whitespace().collect::<Vec<_>>();
    let start_ticks = fields
        .get(19)
        .ok_or_else(|| {
            QualificationError::new(
                "ambiguous_measurement",
                "process stat has no start-time field",
            )
        })?
        .parse::<u64>()
        .map_err(|_| {
            QualificationError::new(
                "ambiguous_measurement",
                "process start-time field is not an integer",
            )
        })?;
    let process_id = std::process::id();
    let boot_digest = digest_parts("qualified.linux-boot-id.v1", &[&boot_id]);
    let epoch_digest = digest_parts(
        "qualified.process-epoch.v1",
        &[
            boot_digest.as_str().as_bytes(),
            &process_id.to_be_bytes(),
            &start_ticks.to_be_bytes(),
        ],
    );
    let process_epoch_id = IncarnationId::new(format!(
        "process-epoch:{}",
        epoch_digest.as_str().trim_start_matches("sha256:")
    ));
    let identity = LocalProcessIdentityV1 {
        process_epoch_id,
        process_id,
        linux_boot_id_digest: boot_digest,
        process_start_ticks: start_ticks,
    };
    identity.validate()?;
    Ok(identity)
}

#[cfg(not(target_os = "linux"))]
fn observe_local_process_identity() -> Result<LocalProcessIdentityV1, QualificationError> {
    Err(QualificationError::new(
        "measurement_unavailable",
        "v1 process epoch observation is qualified only on Linux",
    ))
}

fn activation_occurrence_id(
    process: Option<&LocalProcessIdentityV1>,
    sequence: u64,
) -> IncarnationId {
    let process_identity = process.map_or("process-unavailable", |value| {
        value.process_epoch_id.as_str()
    });
    let digest = digest_parts(
        "qualified.activation-occurrence.v1",
        &[process_identity.as_bytes(), &sequence.to_be_bytes()],
    );
    IncarnationId::new(format!(
        "activation-occurrence:{}",
        digest.as_str().trim_start_matches("sha256:")
    ))
}

#[must_use]
pub fn artifact_content_digest(bytes: &[u8]) -> DigestV1 {
    digest_parts("qualified.artifact-content.v1", &[bytes])
}

pub fn canonical_artifact_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, QualificationError> {
    canonical_encode(value)
}

fn canonical_encode<T: Serialize>(value: &T) -> Result<Vec<u8>, QualificationError> {
    let bytes = serde_json::to_vec(value).map_err(|error| {
        QualificationError::new(
            "canonical_encoding_failed",
            format!("canonical JSON encoding failed: {error}"),
        )
    })?;
    if bytes.len() > MAX_QUALIFICATION_PACKAGE_BYTES {
        return Err(QualificationError::new(
            "bound_exceeded",
            "canonical object exceeds the package byte bound",
        ));
    }
    Ok(bytes)
}

fn canonical_decode<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    label: &str,
) -> Result<T, QualificationError> {
    if bytes.is_empty() || bytes.len() > MAX_QUALIFICATION_PACKAGE_BYTES {
        return Err(QualificationError::new(
            "bound_exceeded",
            format!("{label} is empty or exceeds its byte bound"),
        ));
    }
    let value = serde_json::from_slice::<T>(bytes).map_err(|error| {
        QualificationError::new(
            "malformed_canonical_encoding",
            format!("{label} does not decode as its closed schema: {error}"),
        )
    })?;
    let canonical = canonical_encode(&value)?;
    if canonical != bytes {
        return Err(QualificationError::new(
            "noncanonical_encoding",
            format!("{label} bytes are not the unique canonical encoding"),
        ));
    }
    Ok(value)
}

fn body_digest<T: Serialize>(domain: &str, value: &T) -> Result<DigestV1, QualificationError> {
    let bytes = canonical_encode(value)?;
    Ok(digest_parts(domain, &[&bytes]))
}

fn validate_schema(version: u16, label: &str) -> Result<(), QualificationError> {
    if version != SCHEMA_VERSION_V1 {
        return Err(QualificationError::new(
            "unsupported_version",
            format!("{label} schema version is unsupported"),
        ));
    }
    Ok(())
}

fn validate_text(field: &str, value: &str) -> Result<(), QualificationError> {
    if value.is_empty()
        || value.len() > MAX_QUALIFICATION_STRING_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(QualificationError::new(
            "invalid_text",
            format!("{field} is empty, over its bound, or contains control characters"),
        ));
    }
    Ok(())
}

fn validate_logical_path(path: &str) -> Result<(), QualificationError> {
    validate_text("artifact.logical_path", path)?;
    if path.starts_with('/')
        || path.contains('\\')
        || path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(QualificationError::new(
            "ambiguous_path",
            "logical path must be normalized, relative, and traversal-free",
        ));
    }
    Ok(())
}

fn validate_sorted<T: Ord>(
    field: &str,
    values: &[T],
    maximum: usize,
) -> Result<(), QualificationError> {
    if values.len() > maximum || values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(QualificationError::new(
            "noncanonical_collection",
            format!("{field} exceeds its bound or is not sorted and unique"),
        ));
    }
    Ok(())
}

fn validate_sorted_texts(
    field: &str,
    values: &[String],
    maximum: usize,
) -> Result<(), QualificationError> {
    validate_sorted(field, values, maximum)?;
    for value in values {
        validate_text(field, value)?;
    }
    Ok(())
}

fn validate_measurements(
    measurements: &[ArtifactMeasurementV1],
    executable_must_be_absent: bool,
) -> Result<(), QualificationError> {
    if measurements.len() > MAX_QUALIFICATION_ARTIFACTS
        || measurements
            .windows(2)
            .any(|pair| pair[0].role >= pair[1].role)
    {
        return Err(QualificationError::new(
            "ambiguous_measurement",
            "artifact measurements exceed their bound or are not role-sorted and unique",
        ));
    }
    if executable_must_be_absent
        && measurements
            .iter()
            .any(|measurement| measurement.role == ArtifactRoleV1::RunningExecutable)
    {
        return Err(QualificationError::new(
            "ambiguous_measurement",
            "caller cannot supply the running executable measurement",
        ));
    }
    for measurement in measurements {
        measurement.validate()?;
    }
    Ok(())
}

fn is_subset<T: Ord>(subset: &[T], superset: &[T]) -> bool {
    subset
        .iter()
        .all(|item| superset.binary_search(item).is_ok())
}

fn mismatch(
    code: &str,
    role: Option<ArtifactRoleV1>,
    detail: impl Into<String>,
) -> BindingMismatchV1 {
    BindingMismatchV1 {
        code: code.to_owned(),
        role,
        expected: None,
        observed: None,
        detail: detail.into(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualificationError {
    pub code: &'static str,
    pub detail: String,
}

impl QualificationError {
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for QualificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for QualificationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ContextActivationId, digest_parts};

    fn generation_set() -> QualifiedGenerationSetV1 {
        let context = RelianceContextV1 {
            schema_version: SCHEMA_VERSION_V1,
            activation_id: ContextActivationId::new("activation:test"),
            reliance_policy_generation: PolicyGenerationId::new("policy:test"),
            reliance_policy_semantic_digest: digest_parts("test-policy", &[b"body"]),
            consumer_profile_generation: ConsumerProfileGenerationId::new("profile:test"),
            evaluator_semantic_generation: EvaluatorSemanticGenerationId::new("evaluator:test"),
            observer_set_generation: ObserverSetGenerationId::new("observer-set:test"),
            observation_policy_generation: ObservationPolicyGenerationId::new(
                "observation-policy:test",
            ),
        };
        QualifiedGenerationSetV1::from_context(
            SubjectId::new("subject:test"),
            ConsumerId::new("consumer:test"),
            &context,
        )
    }

    fn artifact(role: ArtifactRoleV1) -> ArtifactIdentityV1 {
        let name = format!("{role:?}").to_lowercase();
        ArtifactIdentityV1 {
            role,
            logical_name: name.clone(),
            logical_path: format!("artifacts/{name}"),
            media_type: "application/octet-stream".to_owned(),
            byte_length: 4,
            content_digest: artifact_content_digest(name.as_bytes()),
            activation_required: role.activation_required(),
        }
    }

    fn source() -> SourceIdentityV1 {
        SourceIdentityV1 {
            repository_identity: "monitor-skunkworks".to_owned(),
            commit: "3cd15b7a1e7f424f6fd57c09b30fa4790947eca2".to_owned(),
            source_tree_digest: digest_parts("source-tree", &[b"fixture"]),
            dirty: false,
        }
    }

    fn build() -> BuildIdentityV1 {
        BuildIdentityV1 {
            toolchain_identity: "rustc fixture".to_owned(),
            target_triple: "x86_64-unknown-linux-gnu".to_owned(),
            build_profile: "test".to_owned(),
            enabled_features: vec!["default".to_owned()],
            runtime_dependencies: Vec::new(),
        }
    }

    fn manifest() -> QualifiedArtifactManifestV1 {
        let artifacts = ArtifactRoleV1::all()
            .into_iter()
            .map(artifact)
            .collect::<Vec<_>>();
        let corpus_digest = artifacts
            .iter()
            .find(|artifact| artifact.role == ArtifactRoleV1::QualificationCorpus)
            .expect("fixture corpus role")
            .content_digest
            .clone();
        QualifiedArtifactManifestV1::new(ArtifactManifestBodyV1 {
            schema_version: SCHEMA_VERSION_V1,
            generation_set: generation_set(),
            artifacts,
            source: source(),
            build: build(),
            semantic_contracts: Vec::new(),
            platform_assumptions: vec!["linux-proc-self-exe/v1".to_owned()],
            qualification_corpus_identities: vec![corpus_digest],
            declared_claims: vec!["canonical_manifest/v1".to_owned()],
            nonclaims: vec!["not_remote_attestation".to_owned()],
            supersedes_manifest_digests: Vec::new(),
            lifecycle_authority_id: "local-authority:test".to_owned(),
            authority_grants: AuthorityGrantsV1::none(),
        })
        .expect("manifest")
    }

    fn report(manifest: &QualifiedArtifactManifestV1) -> QualificationEvidenceReportV1 {
        QualificationEvidenceReportV1::new(QualificationEvidenceBodyV1 {
            schema_version: SCHEMA_VERSION_V1,
            manifest_digest: manifest.manifest_digest.clone(),
            artifact_digests: manifest.body.artifact_digests(),
            source: manifest.body.source.clone(),
            build: manifest.body.build.clone(),
            semantic_contracts: manifest.body.semantic_contracts.clone(),
            command_results: vec![QualificationCommandResultV1 {
                sequence: 1,
                argv: vec!["cargo".to_owned(), "test".to_owned()],
                exit_code: 0,
                stdout_digest: digest_parts("stdout", &[b"ok"]),
                stderr_digest: digest_parts("stderr", &[b"empty"]),
                observed_test_count: Some(1),
            }],
            qualification_corpus_identities: manifest.body.qualification_corpus_identities.clone(),
            hostile_scenarios: vec!["manifest_truncation".to_owned()],
            earned_claims: vec!["canonical_manifest/v1".to_owned()],
            nonclaims: manifest.body.nonclaims.clone(),
            total_tests_passed: 1,
            all_required_commands_passed: true,
            authority_grants: AuthorityGrantsV1::none(),
        })
        .expect("report")
    }

    #[test]
    fn canonical_manifest_has_one_encoding_and_rejects_reordered_json() {
        let manifest = manifest();
        let bytes = manifest.canonical_bytes().expect("canonical bytes");
        assert_eq!(
            QualifiedArtifactManifestV1::decode_canonical(&bytes).expect("round trip"),
            manifest
        );
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        let object = value.as_object_mut().expect("object");
        let schema = object.remove("schema_version").expect("schema");
        object.insert("schema_version".to_owned(), schema);
        let reordered = serde_json::to_vec(&value).expect("json bytes");
        assert_ne!(reordered, bytes);
        assert!(QualifiedArtifactManifestV1::decode_canonical(&reordered).is_err());
    }

    #[test]
    fn duplicate_role_path_traversal_and_claim_broadening_are_refused() {
        let mut body = manifest().body;
        body.artifacts[1].role = ArtifactRoleV1::RunningExecutable;
        assert!(QualifiedArtifactManifestV1::new(body).is_err());

        let mut body = manifest().body;
        body.artifacts[0].logical_path = "../runtime".to_owned();
        assert!(QualifiedArtifactManifestV1::new(body).is_err());

        let manifest = manifest();
        let mut report_body = report(&manifest).body;
        report_body.earned_claims = vec!["unearned_claim".to_owned()];
        let report = QualificationEvidenceReportV1::new(report_body).expect("internal report");
        assert!(
            QualificationCertificateV1::issue(
                &manifest,
                &report,
                CertificateProvenanceV1 {
                    issuance_id: "issuance:test".to_owned(),
                    issuer_id: "issuer:test".to_owned(),
                    method: CertificateProvenanceMethodV1::LocalUnsignedExactBytes,
                }
            )
            .is_err()
        );
    }

    #[test]
    fn certificate_is_distinct_from_manifest_and_checked_report() {
        let manifest = manifest();
        let report = report(&manifest);
        let certificate = QualificationCertificateV1::issue(
            &manifest,
            &report,
            CertificateProvenanceV1 {
                issuance_id: "issuance:test".to_owned(),
                issuer_id: "issuer:test".to_owned(),
                method: CertificateProvenanceMethodV1::LocalUnsignedExactBytes,
            },
        )
        .expect("certificate");
        verify_qualification_package(&manifest, &report, &certificate).expect("package");
        assert_ne!(manifest.manifest_digest, certificate.certificate_digest);
        assert_ne!(report.report_digest, certificate.certificate_digest);
    }

    #[test]
    fn activation_receipt_bytes_cannot_construct_live_activation() {
        let receipt = ActivationReceiptV1::new(ActivationReceiptBodyV1 {
            schema_version: SCHEMA_VERSION_V1,
            manifest_digest: None,
            qualification_certificate_digest: None,
            qualification_report_digest: None,
            generation_set: None,
            process: None,
            activation_occurrence_id: IncarnationId::new("activation-occurrence:test"),
            activation_sequence: 1,
            receiver_incarnation: IncarnationId::new("receiver-incarnation:test"),
            receiver_clock_id: ClockId::new("clock:test"),
            activated_at_monotonic_ms: 0,
            runtime_version: "test".to_owned(),
            target_platform: "linux-test".to_owned(),
            measurements: Vec::new(),
            state: RuntimeBindingStateV1::Unbound,
            mismatches: Vec::new(),
            all_required_artifacts_measured: false,
            any_measurement_caller_supplied: false,
            mutable_after_activation: false,
            independent_attestation_claimed: false,
            authority_grants: AuthorityGrantsV1::none(),
        })
        .expect("receipt");
        let bytes = receipt.canonical_bytes().expect("bytes");
        assert_eq!(
            ActivationReceiptV1::decode_canonical(&bytes).expect("historical receipt"),
            receipt
        );
        // There is deliberately no conversion from ActivationReceiptV1 to
        // VerifiedActivationV1; the latter owns a live executable handle.
        assert!(!receipt.body.state.permits_current());
    }
}
