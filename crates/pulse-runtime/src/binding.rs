//! Exact owned-value artifacts and narrow local qualification-package assembly.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use pulse_evaluator::{EscalationPolicyV1, ReliancePolicyV1};
use pulse_types::{
    ArtifactDigestBindingV1, ArtifactIdentityV1, ArtifactManifestBodyV1, ArtifactMeasurementV1,
    ArtifactRoleV1, AuthorityGrantsV1, BuildIdentityV1, CertificateProvenanceMethodV1,
    CertificateProvenanceV1, LocalActivationAcceptanceV1, LocalCertificateStatusV1,
    MAX_QUALIFICATION_CLAIMS, MAX_QUALIFICATION_COMMANDS, MAX_QUALIFICATION_PACKAGE_BYTES,
    MAX_QUALIFICATION_STRING_BYTES, MeasurementProvenanceV1, QualificationCertificateV1,
    QualificationCommandResultV1, QualificationError, QualificationEvidenceBodyV1,
    QualificationEvidenceReportV1, QualifiedArtifactManifestV1, QualifiedGenerationSetV1,
    RuntimeDependencyIdentityV1, SCHEMA_VERSION_V1, SemanticContractIdentityV1, SourceIdentityV1,
    artifact_content_digest, canonical_artifact_bytes, digest_parts, observe_running_executable,
};

use crate::{ConsumerRegistrationV1, RuntimeBoundsV1, RuntimeConfigV1};

const EVALUATOR_IMPLEMENTATION_MARKER: &[u8] = b"monitor-skunkworks/pulse-evaluator/consumer-indexed-evaluator/v1\ncategory-precedence=contradicted,suspect,unknown,degraded,current\nreceiver-owned-freshness=true\nscalar-confidence=false\n";
const RUNTIME_BINDING_CONTRACT: &[u8] = b"monitor-skunkworks/qualified-generation-binding/v1\ndeclared!=qualified!=activated\ncurrent-requires-qualified-and-matched=true\n";
const SUPPORT_CERTIFICATE_CONTRACT: &[u8] = b"monitor-skunkworks/reliance-support-certificate/v2\nqualified-generation-binding-required-for-current=true\nmutation-authority=none\n";
const REMOTE_SUPPORT_CERTIFICATE_CONTRACT: &[u8] = b"monitor-skunkworks/reliance-support-certificate/v3\nqualified-generation-binding-required-for-current=true\nremote-custody-is-exact-and-receiver-anchored=true\nmutation-authority=none\n";
const RECEIVER_BOUNDARY_CONTRACT: &[u8] = b"monitor-skunkworks/receiver-boundary-custody/v1\nauthenticated-transport!=sender-activation!=receiver-admission!=reliance\nreceiver-owned-arrival-freshness=true\n";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalToleranceV1 {
    pub signal: String,
    pub value_bits: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalFailureDomainV1 {
    pub observer: String,
    pub failure_domain: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalEscalationPolicyV1 {
    pub triggers: Vec<String>,
    pub diagnostic_profile_name: String,
    pub diagnostic_profile_version: u16,
    pub diagnostic_profile_digest: pulse_types::DigestV1,
    pub maximum_runtime_ms: u64,
    pub maximum_output_bytes: u64,
    pub maximum_observations: u32,
    pub request_ttl_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalReliancePolicyArtifactV1 {
    pub schema_version: u16,
    pub subject: pulse_types::SubjectId,
    pub scope: String,
    pub consumer: pulse_types::ConsumerId,
    pub generation: pulse_types::PolicyGenerationId,
    pub observation_policy_generation: pulse_types::ObservationPolicyGenerationId,
    pub observation_profile: pulse_types::ObservationProfileIdV1,
    pub required_coverage: Vec<String>,
    pub minimum_observers: u32,
    pub maximum_validity_ms: u64,
    pub require_verified_authentication: bool,
    pub coherence_tolerances: Vec<CanonicalToleranceV1>,
    pub observer_failure_domains: Vec<CanonicalFailureDomainV1>,
    pub escalation: Option<CanonicalEscalationPolicyV1>,
}

impl From<&ReliancePolicyV1> for CanonicalReliancePolicyArtifactV1 {
    fn from(policy: &ReliancePolicyV1) -> Self {
        Self {
            schema_version: policy.schema_version,
            subject: policy.subject.clone(),
            scope: policy.scope.clone(),
            consumer: policy.consumer.clone(),
            generation: policy.generation.clone(),
            observation_policy_generation: policy.observation_policy_generation.clone(),
            observation_profile: policy.observation_profile.clone(),
            required_coverage: policy.required_coverage.clone(),
            minimum_observers: policy.minimum_observers,
            maximum_validity_ms: policy.maximum_validity_ms,
            require_verified_authentication: policy.require_verified_authentication,
            coherence_tolerances: policy
                .coherence_tolerances
                .iter()
                .map(|(signal, value)| CanonicalToleranceV1 {
                    signal: signal.clone(),
                    value_bits: value.to_bits(),
                })
                .collect(),
            observer_failure_domains: policy
                .observer_failure_domains
                .iter()
                .map(|(observer, failure_domain)| CanonicalFailureDomainV1 {
                    observer: observer.clone(),
                    failure_domain: failure_domain.clone(),
                })
                .collect(),
            escalation: policy.escalation.as_ref().map(canonical_escalation),
        }
    }
}

fn canonical_escalation(policy: &EscalationPolicyV1) -> CanonicalEscalationPolicyV1 {
    CanonicalEscalationPolicyV1 {
        triggers: policy
            .triggers
            .iter()
            .map(|trigger| trigger.as_str().to_owned())
            .collect(),
        diagnostic_profile_name: policy.diagnostic_profile.name.clone(),
        diagnostic_profile_version: policy.diagnostic_profile.version,
        diagnostic_profile_digest: policy.diagnostic_profile.semantic_digest.clone(),
        maximum_runtime_ms: policy.bounds.maximum_runtime_ms,
        maximum_output_bytes: policy.bounds.maximum_output_bytes,
        maximum_observations: policy.bounds.maximum_observations,
        request_ttl_ms: policy.request_ttl_ms,
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluatorImplementationArtifactV1 {
    pub schema_version: u16,
    pub evaluator_generation: pulse_types::EvaluatorSemanticGenerationId,
    pub embedded_implementation_marker_digest: pulse_types::DigestV1,
    pub executable_contains_implementation: bool,
    pub source_to_binary_correspondence_claimed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumerProfileArtifactV1 {
    pub schema_version: u16,
    pub generation: pulse_types::ConsumerProfileGenerationId,
    pub consumer: pulse_types::ConsumerId,
    pub subject: pulse_types::SubjectId,
    pub scope: String,
    pub reliance_contract: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverSetArtifactV1 {
    pub schema_version: u16,
    pub generation: pulse_types::ObserverSetGenerationId,
    pub minimum_observers: u32,
    pub failure_domains: Vec<CanonicalFailureDomainV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationPolicyArtifactV1 {
    pub schema_version: u16,
    pub generation: pulse_types::ObservationPolicyGenerationId,
    pub profile: pulse_types::ObservationProfileIdV1,
    pub admitted_coverage: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfigurationArtifactV1 {
    pub schema_version: u16,
    pub receiver: pulse_types::ReceiverId,
    pub bounds: RuntimeBoundsV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_custody_policy: Option<pulse_types::TransportCustodyPolicyBindingV1>,
    pub receiver_incarnation_is_process_occurrence: bool,
    pub receiver_clock_is_process_occurrence: bool,
    pub deadline_custody_contract: String,
    pub history_restarts_unknown: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticContractsArtifactV1 {
    pub schema_version: u16,
    pub contracts: Vec<SemanticContractIdentityV1>,
}

#[derive(Clone, Debug)]
pub struct RuntimeArtifactPayloadV1 {
    pub role: ArtifactRoleV1,
    pub logical_name: String,
    pub logical_path: String,
    pub media_type: String,
    pub bytes: Vec<u8>,
    pub provenance: MeasurementProvenanceV1,
}

impl RuntimeArtifactPayloadV1 {
    #[must_use]
    pub fn identity(&self) -> ArtifactIdentityV1 {
        ArtifactIdentityV1 {
            role: self.role,
            logical_name: self.logical_name.clone(),
            logical_path: self.logical_path.clone(),
            media_type: self.media_type.clone(),
            byte_length: self.bytes.len() as u64,
            content_digest: artifact_content_digest(&self.bytes),
            activation_required: self.role.activation_required(),
        }
    }

    #[must_use]
    pub fn measurement(&self) -> ArtifactMeasurementV1 {
        ArtifactMeasurementV1 {
            role: self.role,
            content_digest: artifact_content_digest(&self.bytes),
            byte_length: self.bytes.len() as u64,
            provenance: self.provenance.clone(),
            caller_supplied: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct LocalQualificationInputsV1 {
    pub source: SourceIdentityV1,
    pub build: BuildIdentityV1,
    pub platform_assumptions: Vec<String>,
    pub declared_claims: Vec<String>,
    pub nonclaims: Vec<String>,
    pub supersedes_manifest_digests: Vec<pulse_types::DigestV1>,
    pub lifecycle_authority_id: String,
    pub corpus_bytes: Vec<u8>,
    pub results_bytes: Vec<u8>,
    pub command_results: Vec<QualificationCommandResultV1>,
    pub hostile_scenarios: Vec<String>,
    pub total_tests_passed: u32,
    pub issuance_id: String,
    pub issuer_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationCorpusArtifactV1 {
    pub schema_version: u16,
    pub corpus_id: String,
    pub hostile_scenarios: Vec<String>,
    pub property_families: Vec<String>,
}

impl QualificationCorpusArtifactV1 {
    pub fn validate(&self) -> Result<(), QualificationError> {
        if self.schema_version != SCHEMA_VERSION_V1 {
            return Err(QualificationError::new(
                "unsupported_version",
                "qualification corpus schema version is unsupported",
            ));
        }
        validate_local_text("corpus_id", &self.corpus_id)?;
        validate_local_sorted_texts("hostile_scenarios", &self.hostile_scenarios)?;
        validate_local_sorted_texts("property_families", &self.property_families)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, QualificationError> {
        self.validate()?;
        canonical_artifact_bytes(self)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, QualificationError> {
        let value: Self = decode_exact_artifact(bytes, "qualification corpus")?;
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationResultsArtifactV1 {
    pub schema_version: u16,
    pub command_results: Vec<QualificationCommandResultV1>,
    pub total_tests_passed: u32,
    pub all_required_commands_passed: bool,
}

impl QualificationResultsArtifactV1 {
    pub fn validate(&self) -> Result<(), QualificationError> {
        if self.schema_version != SCHEMA_VERSION_V1 {
            return Err(QualificationError::new(
                "unsupported_version",
                "qualification results schema version is unsupported",
            ));
        }
        if self.command_results.is_empty()
            || self.command_results.len() > MAX_QUALIFICATION_COMMANDS
        {
            return Err(QualificationError::new(
                "qualification_evidence_missing",
                "qualification results command inventory is absent or exceeds its bound",
            ));
        }
        for (index, command) in self.command_results.iter().enumerate() {
            command.validate()?;
            if command.sequence as usize != index + 1 || command.exit_code != 0 {
                return Err(QualificationError::new(
                    "qualification_command_failed",
                    "qualification results contain a failed or discontinuous command",
                ));
            }
        }
        let observed_tests = self
            .command_results
            .iter()
            .filter_map(|command| command.observed_test_count)
            .fold(0_u32, u32::saturating_add);
        if !self.all_required_commands_passed || observed_tests != self.total_tests_passed {
            return Err(QualificationError::new(
                "qualification_result_mismatch",
                "qualification results do not support their declared command or test outcome",
            ));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, QualificationError> {
        self.validate()?;
        canonical_artifact_bytes(self)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, QualificationError> {
        let value: Self = decode_exact_artifact(bytes, "qualification results")?;
        value.validate()?;
        Ok(value)
    }
}

fn decode_exact_artifact<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    name: &str,
) -> Result<T, QualificationError> {
    if bytes.is_empty() || bytes.len() > MAX_QUALIFICATION_PACKAGE_BYTES {
        return Err(QualificationError::new(
            "bound_exceeded",
            format!("{name} bytes are empty or exceed their bound"),
        ));
    }
    let value: T = serde_json::from_slice(bytes).map_err(|error| {
        QualificationError::new("malformed_canonical_encoding", format!("{name}: {error}"))
    })?;
    let encoded = canonical_artifact_bytes(&value)?;
    if encoded != bytes {
        return Err(QualificationError::new(
            "noncanonical_encoding",
            format!("{name} bytes are not their unique canonical encoding"),
        ));
    }
    Ok(value)
}

fn validate_local_text(field: &str, value: &str) -> Result<(), QualificationError> {
    if value.is_empty()
        || value.len() > MAX_QUALIFICATION_STRING_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(QualificationError::new(
            "invalid_text",
            format!("{field} is empty, contains control text, or exceeds its bound"),
        ));
    }
    Ok(())
}

fn validate_local_sorted_texts(field: &str, values: &[String]) -> Result<(), QualificationError> {
    if values.is_empty() || values.len() > MAX_QUALIFICATION_CLAIMS {
        return Err(QualificationError::new(
            "bound_exceeded",
            format!("{field} is empty or exceeds its bound"),
        ));
    }
    for value in values {
        validate_local_text(field, value)?;
    }
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(QualificationError::new(
            "noncanonical_order",
            format!("{field} must be strictly sorted and unique"),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct LocalQualificationPackageV1 {
    pub manifest: QualifiedArtifactManifestV1,
    pub report: QualificationEvidenceReportV1,
    pub certificate: QualificationCertificateV1,
    pub acceptance: LocalActivationAcceptanceV1,
}

impl LocalQualificationPackageV1 {
    pub fn manifest_bytes(&self) -> Result<Vec<u8>, QualificationError> {
        self.manifest.canonical_bytes()
    }

    pub fn report_bytes(&self) -> Result<Vec<u8>, QualificationError> {
        self.report.canonical_bytes()
    }

    pub fn certificate_bytes(&self) -> Result<Vec<u8>, QualificationError> {
        self.certificate.canonical_bytes()
    }
}

pub fn runtime_semantic_contracts() -> Vec<SemanticContractIdentityV1> {
    vec![
        SemanticContractIdentityV1 {
            name: "monitor.qualified_generation_binding".to_owned(),
            version: 1,
            digest: artifact_content_digest(RUNTIME_BINDING_CONTRACT),
        },
        SemanticContractIdentityV1 {
            name: "monitor.reliance_support_certificate".to_owned(),
            version: 2,
            digest: artifact_content_digest(SUPPORT_CERTIFICATE_CONTRACT),
        },
        SemanticContractIdentityV1 {
            name: "monitor.runtime_evaluator".to_owned(),
            version: 1,
            digest: artifact_content_digest(EVALUATOR_IMPLEMENTATION_MARKER),
        },
    ]
}

fn runtime_semantic_contracts_for_config(
    config: &RuntimeConfigV1,
) -> Vec<SemanticContractIdentityV1> {
    if config.transport_custody_policy.is_none() {
        return runtime_semantic_contracts();
    }
    let mut contracts = vec![
        SemanticContractIdentityV1 {
            name: "monitor.qualified_generation_binding".to_owned(),
            version: 1,
            digest: artifact_content_digest(RUNTIME_BINDING_CONTRACT),
        },
        SemanticContractIdentityV1 {
            name: "monitor.receiver_boundary_custody".to_owned(),
            version: 1,
            digest: artifact_content_digest(RECEIVER_BOUNDARY_CONTRACT),
        },
        SemanticContractIdentityV1 {
            name: "monitor.reliance_support_certificate".to_owned(),
            version: 3,
            digest: artifact_content_digest(REMOTE_SUPPORT_CERTIFICATE_CONTRACT),
        },
        SemanticContractIdentityV1 {
            name: "monitor.runtime_evaluator".to_owned(),
            version: 1,
            digest: artifact_content_digest(EVALUATOR_IMPLEMENTATION_MARKER),
        },
    ];
    contracts.sort_by(|left, right| left.name.cmp(&right.name));
    contracts
}

pub fn active_runtime_artifact_payloads(
    config: &RuntimeConfigV1,
    registration: &ConsumerRegistrationV1,
) -> Result<Vec<RuntimeArtifactPayloadV1>, QualificationError> {
    let contracts = runtime_semantic_contracts_for_config(config);
    let policy = CanonicalReliancePolicyArtifactV1::from(&registration.policy);
    let evaluator = EvaluatorImplementationArtifactV1 {
        schema_version: SCHEMA_VERSION_V1,
        evaluator_generation: registration.context.evaluator_semantic_generation.clone(),
        embedded_implementation_marker_digest: artifact_content_digest(
            EVALUATOR_IMPLEMENTATION_MARKER,
        ),
        executable_contains_implementation: true,
        source_to_binary_correspondence_claimed: false,
    };
    let profile = ConsumerProfileArtifactV1 {
        schema_version: SCHEMA_VERSION_V1,
        generation: registration.context.consumer_profile_generation.clone(),
        consumer: registration.policy.consumer.clone(),
        subject: registration.policy.subject.clone(),
        scope: registration.policy.scope.clone(),
        reliance_contract: "consumer-indexed-present-reliance/v1".to_owned(),
    };
    let observer_set = ObserverSetArtifactV1 {
        schema_version: SCHEMA_VERSION_V1,
        generation: registration.context.observer_set_generation.clone(),
        minimum_observers: registration.policy.minimum_observers,
        failure_domains: registration
            .policy
            .observer_failure_domains
            .iter()
            .map(|(observer, failure_domain)| CanonicalFailureDomainV1 {
                observer: observer.clone(),
                failure_domain: failure_domain.clone(),
            })
            .collect(),
    };
    let observation_policy = ObservationPolicyArtifactV1 {
        schema_version: SCHEMA_VERSION_V1,
        generation: registration.context.observation_policy_generation.clone(),
        profile: registration.policy.observation_profile.clone(),
        admitted_coverage: registration.policy.required_coverage.clone(),
    };
    let runtime_config = RuntimeConfigurationArtifactV1 {
        schema_version: SCHEMA_VERSION_V1,
        receiver: config.receiver.clone(),
        bounds: config.bounds,
        transport_custody_policy: config.transport_custody_policy.clone(),
        receiver_incarnation_is_process_occurrence: true,
        receiver_clock_is_process_occurrence: true,
        deadline_custody_contract: "receiver-owned-inclusive-support-expiry/v1".to_owned(),
        history_restarts_unknown: true,
    };
    let contract_artifact = SemanticContractsArtifactV1 {
        schema_version: SCHEMA_VERSION_V1,
        contracts,
    };
    let mut payloads = vec![
        typed_payload(
            ArtifactRoleV1::EvaluatorImplementation,
            "evaluator-implementation",
            "typed/evaluator-implementation.json",
            &evaluator,
            "EvaluatorImplementationArtifactV1",
        )?,
        typed_payload(
            ArtifactRoleV1::ReliancePolicy,
            "reliance-policy",
            "typed/reliance-policy.json",
            &policy,
            "CanonicalReliancePolicyArtifactV1",
        )?,
        typed_payload(
            ArtifactRoleV1::ConsumerProfile,
            "consumer-profile",
            "typed/consumer-profile.json",
            &profile,
            "ConsumerProfileArtifactV1",
        )?,
        typed_payload(
            ArtifactRoleV1::ObserverSet,
            "observer-set",
            "typed/observer-set.json",
            &observer_set,
            "ObserverSetArtifactV1",
        )?,
        typed_payload(
            ArtifactRoleV1::ObservationPolicy,
            "observation-policy",
            "typed/observation-policy.json",
            &observation_policy,
            "ObservationPolicyArtifactV1",
        )?,
        typed_payload(
            ArtifactRoleV1::RuntimeConfiguration,
            "runtime-configuration",
            "typed/runtime-configuration.json",
            &runtime_config,
            "RuntimeConfigurationArtifactV1",
        )?,
        RuntimeArtifactPayloadV1 {
            role: ArtifactRoleV1::SemanticContracts,
            logical_name: "semantic-contracts".to_owned(),
            logical_path: "embedded/semantic-contracts.json".to_owned(),
            media_type: "application/json".to_owned(),
            bytes: canonical_artifact_bytes(&contract_artifact)?,
            provenance: MeasurementProvenanceV1::EmbeddedArtifact {
                name: "pulse-runtime semantic contract inventory".to_owned(),
            },
        },
    ];
    payloads.sort_by_key(|payload| payload.role);
    Ok(payloads)
}

pub fn active_runtime_measurements(
    config: &RuntimeConfigV1,
    registration: &ConsumerRegistrationV1,
) -> Result<Vec<ArtifactMeasurementV1>, QualificationError> {
    Ok(active_runtime_artifact_payloads(config, registration)?
        .iter()
        .map(RuntimeArtifactPayloadV1::measurement)
        .collect())
}

pub fn build_local_qualification_package(
    config: &RuntimeConfigV1,
    registration: &ConsumerRegistrationV1,
    inputs: LocalQualificationInputsV1,
) -> Result<LocalQualificationPackageV1, QualificationError> {
    let corpus = QualificationCorpusArtifactV1::decode_canonical(&inputs.corpus_bytes)?;
    let results = QualificationResultsArtifactV1::decode_canonical(&inputs.results_bytes)?;
    if corpus.hostile_scenarios != inputs.hostile_scenarios
        || results.command_results != inputs.command_results
        || results.total_tests_passed != inputs.total_tests_passed
        || !results.all_required_commands_passed
    {
        return Err(QualificationError::new(
            "qualification_artifact_mismatch",
            "checked corpus/results bytes do not exactly match the report inputs",
        ));
    }
    let executable = observe_running_executable()?;
    let mut artifacts = Vec::new();
    artifacts.push(ArtifactIdentityV1 {
        role: ArtifactRoleV1::RunningExecutable,
        logical_name: "running-executable".to_owned(),
        logical_path: "runtime/running-executable".to_owned(),
        media_type: "application/x-executable".to_owned(),
        byte_length: executable.byte_length,
        content_digest: executable.content_digest,
        activation_required: true,
    });
    artifacts.extend(
        active_runtime_artifact_payloads(config, registration)?
            .iter()
            .map(RuntimeArtifactPayloadV1::identity),
    );
    artifacts.push(external_payload_identity(
        ArtifactRoleV1::QualificationCorpus,
        "qualification-corpus",
        "qualification/hostile-corpus.json",
        &inputs.corpus_bytes,
    )?);
    artifacts.push(external_payload_identity(
        ArtifactRoleV1::QualificationResults,
        "qualification-results",
        "qualification/results.json",
        &inputs.results_bytes,
    )?);
    artifacts.sort_by_key(|artifact| artifact.role);

    let corpus_digest = artifact_content_digest(&inputs.corpus_bytes);
    let manifest = QualifiedArtifactManifestV1::new(ArtifactManifestBodyV1 {
        schema_version: SCHEMA_VERSION_V1,
        generation_set: QualifiedGenerationSetV1::from_context(
            registration.policy.subject.clone(),
            registration.policy.consumer.clone(),
            &registration.context,
        ),
        artifacts,
        source: inputs.source,
        build: inputs.build,
        semantic_contracts: runtime_semantic_contracts_for_config(config),
        platform_assumptions: inputs.platform_assumptions,
        qualification_corpus_identities: vec![corpus_digest],
        declared_claims: inputs.declared_claims.clone(),
        nonclaims: inputs.nonclaims.clone(),
        supersedes_manifest_digests: inputs.supersedes_manifest_digests,
        lifecycle_authority_id: inputs.lifecycle_authority_id.clone(),
        authority_grants: AuthorityGrantsV1::none(),
    })?;
    let report = QualificationEvidenceReportV1::new(QualificationEvidenceBodyV1 {
        schema_version: SCHEMA_VERSION_V1,
        manifest_digest: manifest.manifest_digest.clone(),
        artifact_digests: manifest.body.artifact_digests(),
        source: manifest.body.source.clone(),
        build: manifest.body.build.clone(),
        semantic_contracts: manifest.body.semantic_contracts.clone(),
        command_results: inputs.command_results,
        qualification_corpus_identities: manifest.body.qualification_corpus_identities.clone(),
        hostile_scenarios: inputs.hostile_scenarios,
        earned_claims: inputs.declared_claims,
        nonclaims: inputs.nonclaims,
        total_tests_passed: inputs.total_tests_passed,
        all_required_commands_passed: true,
        authority_grants: AuthorityGrantsV1::none(),
    })?;
    let certificate = QualificationCertificateV1::issue(
        &manifest,
        &report,
        CertificateProvenanceV1 {
            issuance_id: inputs.issuance_id,
            issuer_id: inputs.issuer_id,
            method: CertificateProvenanceMethodV1::LocalUnsignedExactBytes,
        },
    )?;
    let acceptance = LocalActivationAcceptanceV1 {
        schema_version: SCHEMA_VERSION_V1,
        accepted_certificate_digest: certificate.certificate_digest.clone(),
        lifecycle_authority_id: inputs.lifecycle_authority_id,
        certificate_status: LocalCertificateStatusV1::Accepted {
            observed_through_sequence: 0,
        },
        pinned_superseded_activation_allowed: false,
        authority_grants: AuthorityGrantsV1::none(),
    };
    acceptance.validate()?;
    Ok(LocalQualificationPackageV1 {
        manifest,
        report,
        certificate,
        acceptance,
    })
}

fn typed_payload<T: Serialize>(
    role: ArtifactRoleV1,
    logical_name: &str,
    logical_path: &str,
    value: &T,
    type_name: &str,
) -> Result<RuntimeArtifactPayloadV1, QualificationError> {
    Ok(RuntimeArtifactPayloadV1 {
        role,
        logical_name: logical_name.to_owned(),
        logical_path: logical_path.to_owned(),
        media_type: "application/json".to_owned(),
        bytes: canonical_artifact_bytes(value)?,
        provenance: MeasurementProvenanceV1::OwnedCanonicalValue {
            type_name: type_name.to_owned(),
        },
    })
}

fn external_payload_identity(
    role: ArtifactRoleV1,
    logical_name: &str,
    logical_path: &str,
    bytes: &[u8],
) -> Result<ArtifactIdentityV1, QualificationError> {
    if bytes.is_empty() {
        return Err(QualificationError::new(
            "qualification_evidence_missing",
            "qualification corpus and results artifacts must be nonempty",
        ));
    }
    Ok(ArtifactIdentityV1 {
        role,
        logical_name: logical_name.to_owned(),
        logical_path: logical_path.to_owned(),
        media_type: "application/json".to_owned(),
        byte_length: bytes.len() as u64,
        content_digest: artifact_content_digest(bytes),
        activation_required: false,
    })
}

#[must_use]
pub fn qualification_fixture_inputs(
    starting_commit: &str,
    total_tests_passed: u32,
) -> LocalQualificationInputsV1 {
    let claims = vec![
        "exact_active_artifact_binding/v1".to_owned(),
        "restart_requires_new_activation/v1".to_owned(),
    ];
    let nonclaims = vec![
        "no_continuation_or_mutation_authority".to_owned(),
        "not_independent_attestation".to_owned(),
        "not_source_to_binary_correspondence".to_owned(),
    ];
    let command_stdout = format!("{total_tests_passed} fixture tests passed");
    let command_results = vec![QualificationCommandResultV1 {
        sequence: 1,
        argv: vec![
            "cargo".to_owned(),
            "test".to_owned(),
            "--fixture".to_owned(),
        ],
        exit_code: 0,
        stdout_digest: digest_parts(
            "qualified.fixture.command.stdout.v1",
            &[command_stdout.as_bytes()],
        ),
        stderr_digest: digest_parts("qualified.fixture.command.stderr.v1", &[b"empty"]),
        observed_test_count: Some(total_tests_passed),
    }];
    let hostile_scenarios = vec![
        "activation_receipt_replay".to_owned(),
        "generation_label_without_binding".to_owned(),
    ];
    let corpus_bytes = QualificationCorpusArtifactV1 {
        schema_version: SCHEMA_VERSION_V1,
        corpus_id: "qualification-fixture".to_owned(),
        hostile_scenarios: hostile_scenarios.clone(),
        property_families: vec!["exact-package-pairing".to_owned()],
    }
    .canonical_bytes()
    .expect("static qualification corpus fixture is valid");
    let results_bytes = QualificationResultsArtifactV1 {
        schema_version: SCHEMA_VERSION_V1,
        command_results: command_results.clone(),
        total_tests_passed,
        all_required_commands_passed: true,
    }
    .canonical_bytes()
    .expect("static qualification results fixture is valid");
    LocalQualificationInputsV1 {
        source: SourceIdentityV1 {
            repository_identity: "monitor-skunkworks".to_owned(),
            commit: starting_commit.to_owned(),
            source_tree_digest: digest_parts(
                "qualified.fixture.source-tree.v1",
                &[starting_commit.as_bytes()],
            ),
            dirty: false,
        },
        build: BuildIdentityV1 {
            toolchain_identity: "rustc stable; fixture identity only".to_owned(),
            target_triple: format!(
                "{}-unknown-{}",
                std::env::consts::ARCH,
                std::env::consts::OS
            ),
            build_profile: "test-or-demo".to_owned(),
            enabled_features: vec!["default".to_owned()],
            runtime_dependencies: vec![RuntimeDependencyIdentityV1 {
                name: "workspace-cargo-lock".to_owned(),
                version: "v4".to_owned(),
                source_digest: digest_parts("qualified.fixture.cargo-lock.v1", &[b"fixture"]),
            }],
        },
        platform_assumptions: vec![
            "linux-proc-self-exe-opened-handle/v1".to_owned(),
            "owned-runtime-values-immutable-after-activation/v1".to_owned(),
        ],
        declared_claims: claims,
        nonclaims,
        supersedes_manifest_digests: Vec::new(),
        lifecycle_authority_id: "local-lifecycle-authority:qualification-fixture".to_owned(),
        corpus_bytes,
        results_bytes,
        command_results,
        hostile_scenarios,
        total_tests_passed,
        issuance_id: "local-issuance:qualification-fixture".to_owned(),
        issuer_id: "local-issuer:qualification-fixture".to_owned(),
    }
}

#[must_use]
pub fn package_artifact_digests(
    package: &LocalQualificationPackageV1,
) -> Vec<ArtifactDigestBindingV1> {
    package.manifest.body.artifact_digests()
}
