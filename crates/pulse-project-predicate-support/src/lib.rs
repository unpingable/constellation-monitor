#![forbid(unsafe_code)]
//! Closed generic Pulse support for an NQ-admitted project predicate.
//!
//! NQ is invoked to replay the exact primary admission and to recompute its
//! content-bound predicate over separately signed support facts. Pulse owns
//! signature/source-policy matching, occurrence-relative currentness, skew,
//! and the resulting support disposition. It does not establish world truth.

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const POLICY_SCHEMA: &str = "pulse.project-predicate-support-policy/v1";
pub const EVIDENCE_SCHEMA: &str = "pulse.project-predicate-support-evidence/v1";
pub const ENVELOPE_SCHEMA: &str = "pulse.project-predicate-support-envelope/v1";
pub const RECEIPT_SCHEMA: &str = "pulse.project-predicate-qualified-support/v1";
pub const REPLAY_SCHEMA: &str = "pulse.project-predicate-support-replay/v1";
pub const NQ_EVALUATION_SCHEMA: &str = "nq.bounded-predicate-support-evaluation/v1";
const SIGNATURE_DOMAIN: &[u8] = b"pulse/project-predicate-support/evidence/v1\0";
const MAX_ARTIFACT_BYTES: usize = 2 * 1024 * 1024;
// Public NQ debug builds retain the documented local same-identity fixture path
// and can exceed 128 MiB. Keep executable hashing bounded while admitting that
// supported build product; installed release binaries remain preferable.
const MAX_EXECUTABLE_BYTES: usize = 256 * 1024 * 1024;
const MAX_VERIFIER_OUTPUT_BYTES: usize = 256 * 1024;
const VERIFIER_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupportPolicyV1 {
    pub schema: String,
    pub policy_id: String,
    pub policy_digest: String,
    pub target: TargetBindingV1,
    pub support_source: SupportSourceBindingV1,
    pub currentness: CurrentnessPolicyV1,
    pub nq_verifier_executable_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetBindingV1 {
    pub project: String,
    pub concern: String,
    pub question: String,
    pub declaration_profile: String,
    pub predicate_profile: String,
    pub catalog_digest: String,
    pub profile_digest: String,
    pub input_schema_digest: String,
    pub primary_producer: String,
    /// Operator-owned binding of the project predicate to the governed
    /// instance. This is not inferred from repository HEAD or a path string.
    pub subject_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupportSourceBindingV1 {
    pub producer_id: String,
    pub producer_key_id: String,
    pub producer_public_key_hex: String,
    pub source_id: String,
    pub vantage_id: String,
    /// Exact declared input closure for the separately administered producer.
    pub dependency_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentnessPolicyV1 {
    pub maximum_primary_age_seconds: u64,
    pub maximum_support_age_seconds: u64,
    pub maximum_primary_support_skew_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupportEvidenceV1 {
    pub schema: String,
    pub evidence_id: String,
    pub acquisition_id: String,
    pub producer_id: String,
    pub producer_key_id: String,
    pub source_id: String,
    pub dependency_ids: Vec<String>,
    pub subject_id: String,
    pub vantage_id: String,
    pub observed_at: String,
    pub valid_for_seconds: Option<u64>,
    pub facts: Value,
    /// Opaque producer testimony. It is retained but never used by the
    /// support predicate or currentness calculation.
    pub local_state: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSupportEvidenceV1 {
    pub schema: String,
    pub evidence: SupportEvidenceV1,
    pub signature_hex: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SupportDispositionV1 {
    SupportedCurrent,
    NqReceiptInvalid,
    MissingSupport,
    SupportProducerFailed,
    SupportEvidenceInvalid,
    IdentityMismatch,
    IndependenceNotQualified,
    PrimaryStale,
    SupportStale,
    SkewExceeded,
    Contradictory,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedSupportReceiptV1 {
    pub schema: String,
    pub receipt_digest: String,
    pub policy_id: String,
    pub policy_digest: String,
    pub project: String,
    pub concern: String,
    pub question: String,
    pub declaration_profile: String,
    pub predicate_profile: String,
    pub nq_catalog_digest: String,
    pub nq_profile_digest: String,
    pub nq_input_schema_digest: String,
    pub nq_receipt_digest: String,
    pub nq_verifier_executable_digest: String,
    pub primary_observed_at: Option<String>,
    pub support_evidence_id: Option<String>,
    pub support_evidence_digest: Option<String>,
    pub support_observed_at: Option<String>,
    pub support_producer_id: Option<String>,
    pub support_source_id: Option<String>,
    pub support_vantage_id: Option<String>,
    pub subject_id: String,
    pub qualification_at: String,
    /// Exclusive Unix-millisecond reliance boundary. The wire type is i64 so
    /// canonical JSON remains valid and interoperable; supported RFC3339
    /// occurrences already fit this range.
    pub current_until_unix_ms: Option<i64>,
    /// Absolute primary/support skew in milliseconds. Bounded to u64 before
    /// sealing so JCS never receives a JSON-incompatible u128.
    pub primary_support_skew_ms: Option<u64>,
    pub independence_basis: String,
    pub disposition: SupportDispositionV1,
    pub detail: String,
    pub validated: Vec<String>,
    pub not_validated: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayResultV1 {
    pub schema: String,
    pub matches: bool,
    pub expected_receipt_digest: String,
    pub recomputed_receipt_digest: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NqSupportEvaluation {
    schema: String,
    admission_replay_matches: bool,
    admission_receipt_digest: String,
    catalog_digest: String,
    predicate_profile: String,
    profile_digest: String,
    input_schema_digest: String,
    semantic_conclusion: bool,
    trace: Value,
}

pub struct NqArtifacts<'a> {
    pub executable: &'a Path,
    pub receipt: &'a Path,
    pub inventory: &'a Path,
    pub catalog: &'a Path,
}

impl SupportPolicyV1 {
    pub fn seal(&mut self) -> Result<(), String> {
        self.policy_digest = digest_without_field(self, "policy_digest")?;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != POLICY_SCHEMA {
            return Err("unsupported support policy schema".into());
        }
        for (name, value) in [
            ("policy_id", self.policy_id.as_str()),
            ("project", self.target.project.as_str()),
            ("concern", self.target.concern.as_str()),
            ("question", self.target.question.as_str()),
            (
                "declaration_profile",
                self.target.declaration_profile.as_str(),
            ),
            ("predicate_profile", self.target.predicate_profile.as_str()),
            ("primary_producer", self.target.primary_producer.as_str()),
            ("subject_id", self.target.subject_id.as_str()),
            ("support producer", self.support_source.producer_id.as_str()),
            ("support source", self.support_source.source_id.as_str()),
            ("support vantage", self.support_source.vantage_id.as_str()),
        ] {
            require_token(name, value)?;
        }
        for (name, value) in [
            ("policy_digest", self.policy_digest.as_str()),
            ("catalog_digest", self.target.catalog_digest.as_str()),
            ("profile_digest", self.target.profile_digest.as_str()),
            (
                "input_schema_digest",
                self.target.input_schema_digest.as_str(),
            ),
            (
                "verifier digest",
                self.nq_verifier_executable_digest.as_str(),
            ),
        ] {
            require_digest(name, value)?;
        }
        require_token("producer_key_id", &self.support_source.producer_key_id)?;
        require_hex(&self.support_source.producer_public_key_hex, 32)?;
        validate_dependencies(&self.support_source.dependency_ids)?;
        if self.support_source.producer_id == self.target.primary_producer {
            return Err("support and primary producer identities must differ".into());
        }
        if self.support_source.dependency_ids.iter().any(|dependency| {
            dependency == &self.target.primary_producer
                || matches!(
                    dependency.as_str(),
                    "monitor_inventory" | "nq_receipt" | "project_status_output"
                )
        }) {
            return Err("support dependency closure contains a disallowed primary artifact".into());
        }
        if self.currentness.maximum_primary_age_seconds == 0
            || self.currentness.maximum_support_age_seconds == 0
        {
            return Err("currentness age bounds must be nonzero".into());
        }
        if digest_without_field(self, "policy_digest")? != self.policy_digest {
            return Err("support policy digest does not bind its exact content".into());
        }
        Ok(())
    }
}

pub fn sign_evidence(
    mut evidence: SupportEvidenceV1,
    signing_key: &SigningKey,
) -> Result<SignedSupportEvidenceV1, String> {
    evidence.schema = EVIDENCE_SCHEMA.to_owned();
    evidence.evidence_id.clear();
    validate_evidence_shape(&evidence, false)?;
    evidence.evidence_id = digest_without_field(&evidence, "evidence_id")?;
    let mut message = SIGNATURE_DOMAIN.to_vec();
    message.extend(canonical_bytes(&evidence)?);
    Ok(SignedSupportEvidenceV1 {
        schema: ENVELOPE_SCHEMA.to_owned(),
        evidence,
        signature_hex: encode_hex(&signing_key.sign(&message).to_bytes()),
    })
}

pub fn qualify(
    policy: &SupportPolicyV1,
    nq: &NqArtifacts<'_>,
    evidence: Option<&SignedSupportEvidenceV1>,
    qualification_at: &str,
) -> Result<QualifiedSupportReceiptV1, String> {
    policy.validate()?;
    let qualification_time = parse_time(qualification_at)?;
    let nq_receipt_value: Value = serde_json::from_slice(&read_bounded(nq.receipt)?)
        .map_err(|error| format!("NQ receipt JSON: {error}"))?;
    let nq_receipt_digest = json_string(&nq_receipt_value, "receipt_digest")?.to_owned();
    let mut receipt = base_receipt(policy, qualification_at, nq_receipt_digest);

    let executable_digest = file_digest(nq.executable)?;
    if executable_digest != policy.nq_verifier_executable_digest {
        receipt.disposition = SupportDispositionV1::NqReceiptInvalid;
        receipt.detail = "NQ verifier executable digest does not match policy".into();
        return seal_receipt(receipt);
    }
    let Some(evidence) = evidence else {
        receipt.disposition = SupportDispositionV1::MissingSupport;
        receipt.detail = "no independent support observation was supplied".into();
        return seal_receipt(receipt);
    };
    receipt.support_evidence_id = Some(evidence.evidence.evidence_id.clone());
    receipt.support_evidence_digest = Some(canonical_digest(evidence)?);
    receipt.support_observed_at = Some(evidence.evidence.observed_at.clone());
    receipt.support_producer_id = Some(evidence.evidence.producer_id.clone());
    receipt.support_source_id = Some(evidence.evidence.source_id.clone());
    receipt.support_vantage_id = Some(evidence.evidence.vantage_id.clone());

    if let Err(error) = verify_evidence(policy, evidence) {
        receipt.disposition =
            if error.contains("dependency") || error.contains("producer identities") {
                SupportDispositionV1::IndependenceNotQualified
            } else if error.contains("match the support policy") {
                SupportDispositionV1::IdentityMismatch
            } else {
                SupportDispositionV1::SupportEvidenceInvalid
            };
        receipt.detail = error;
        return seal_receipt(receipt);
    }

    let evaluation = match invoke_nq(nq, &evidence.evidence.facts) {
        Ok(value) => value,
        Err(error) => {
            receipt.disposition = SupportDispositionV1::NqReceiptInvalid;
            receipt.detail = error;
            return seal_receipt(receipt);
        }
    };
    if !evaluation.admission_replay_matches
        || evaluation.admission_receipt_digest != receipt.nq_receipt_digest
        || evaluation.catalog_digest != policy.target.catalog_digest
        || evaluation.predicate_profile != policy.target.predicate_profile
        || evaluation.profile_digest != policy.target.profile_digest
        || evaluation.input_schema_digest != policy.target.input_schema_digest
    {
        receipt.disposition = SupportDispositionV1::NqReceiptInvalid;
        receipt.detail = "NQ replay/evaluation custody does not match support policy".into();
        return seal_receipt(receipt);
    }
    let witness = nq_receipt_value
        .get("witness")
        .and_then(Value::as_object)
        .ok_or_else(|| "verified NQ receipt has no witness object".to_owned())?;
    for (field, expected) in [
        ("project", policy.target.project.as_str()),
        ("concern", policy.target.concern.as_str()),
        ("question", policy.target.question.as_str()),
        (
            "declaration_profile",
            policy.target.declaration_profile.as_str(),
        ),
        (
            "predicate_profile",
            policy.target.predicate_profile.as_str(),
        ),
        ("profile_digest", policy.target.profile_digest.as_str()),
        (
            "input_schema_digest",
            policy.target.input_schema_digest.as_str(),
        ),
        ("producer", policy.target.primary_producer.as_str()),
    ] {
        if witness.get(field).and_then(Value::as_str) != Some(expected) {
            receipt.disposition = SupportDispositionV1::IdentityMismatch;
            receipt.detail = format!("verified NQ witness {field} does not match support policy");
            return seal_receipt(receipt);
        }
    }
    let primary_at = witness
        .get("observed_at")
        .and_then(Value::as_str)
        .ok_or_else(|| "verified NQ witness has no observed_at".to_owned())?;
    receipt.primary_observed_at = Some(primary_at.to_owned());
    let primary_time = parse_time(primary_at)?;
    let support_time = parse_time(&evidence.evidence.observed_at)?;
    if qualification_time < primary_time || qualification_time < support_time {
        receipt.disposition = SupportDispositionV1::IdentityMismatch;
        receipt.detail = "qualification occurrence precedes an observation occurrence".into();
        return seal_receipt(receipt);
    }
    let producer_primary_validity = witness.get("valid_for_seconds").and_then(Value::as_u64);
    let primary_bound = producer_primary_validity
        .map_or(policy.currentness.maximum_primary_age_seconds, |value| {
            value.min(policy.currentness.maximum_primary_age_seconds)
        });
    let support_bound = evidence
        .evidence
        .valid_for_seconds
        .map_or(policy.currentness.maximum_support_age_seconds, |value| {
            value.min(policy.currentness.maximum_support_age_seconds)
        });
    let primary_deadline = add_seconds(primary_time, primary_bound)?;
    let support_deadline = add_seconds(support_time, support_bound)?;
    receipt.current_until_unix_ms = Some(to_unix_ms(primary_deadline.min(support_deadline))?);
    let skew = u64::try_from(
        (primary_time - support_time)
            .whole_milliseconds()
            .unsigned_abs(),
    )
    .map_err(|_| "primary/support skew exceeds u64 milliseconds")?;
    receipt.primary_support_skew_ms = Some(skew);
    if qualification_time >= primary_deadline {
        receipt.disposition = SupportDispositionV1::PrimaryStale;
        receipt.detail = "primary observation is outside the exclusive Pulse age bound".into();
    } else if qualification_time >= support_deadline {
        receipt.disposition = SupportDispositionV1::SupportStale;
        receipt.detail = "support observation is outside the exclusive Pulse age bound".into();
    } else if skew
        > policy
            .currentness
            .maximum_primary_support_skew_seconds
            .checked_mul(1_000)
            .ok_or("primary/support skew policy overflows milliseconds")?
    {
        receipt.disposition = SupportDispositionV1::SkewExceeded;
        receipt.detail = "primary/support occurrence skew exceeds policy".into();
    } else if !evaluation.semantic_conclusion {
        receipt.disposition = SupportDispositionV1::Contradictory;
        receipt.detail = "independent support facts make the governed predicate false".into();
    } else {
        receipt.disposition = SupportDispositionV1::SupportedCurrent;
        receipt.detail = "independent support facts establish the same bounded predicate at a distinct governed occurrence".into();
        receipt.validated = vec![
            "exact NQ admission replayed by the policy-pinned NQ verifier".into(),
            "same content-bound predicate recomputed over signed support facts".into(),
            "operator-bound source topology, subject, producer, and vantage matched".into(),
            "primary/support age and occurrence skew satisfied exact policy bounds".into(),
        ];
    }
    seal_receipt(receipt)
}

/// Record an explicitly known support-producer failure without manufacturing
/// support evidence or evaluating a project proposition.
pub fn qualify_support_failure(
    policy: &SupportPolicyV1,
    nq_receipt: &Path,
    qualification_at: &str,
    failure_detail: &str,
) -> Result<QualifiedSupportReceiptV1, String> {
    policy.validate()?;
    parse_time(qualification_at)?;
    if failure_detail.trim().is_empty() {
        return Err("support producer failure detail must not be empty".into());
    }
    let nq_receipt_value: Value = serde_json::from_slice(&read_bounded(nq_receipt)?)
        .map_err(|error| format!("NQ receipt JSON: {error}"))?;
    let mut receipt = base_receipt(
        policy,
        qualification_at,
        json_string(&nq_receipt_value, "receipt_digest")?.to_owned(),
    );
    receipt.disposition = SupportDispositionV1::SupportProducerFailed;
    receipt.detail = failure_detail.to_owned();
    seal_receipt(receipt)
}

pub fn replay(
    prior: &QualifiedSupportReceiptV1,
    policy: &SupportPolicyV1,
    nq: &NqArtifacts<'_>,
    evidence: Option<&SignedSupportEvidenceV1>,
) -> Result<ReplayResultV1, String> {
    let recomputed = qualify(policy, nq, evidence, &prior.qualification_at)?;
    Ok(ReplayResultV1 {
        schema: REPLAY_SCHEMA.into(),
        matches: prior == &recomputed,
        expected_receipt_digest: prior.receipt_digest.clone(),
        recomputed_receipt_digest: recomputed.receipt_digest,
    })
}

fn base_receipt(
    policy: &SupportPolicyV1,
    at: &str,
    nq_receipt_digest: String,
) -> QualifiedSupportReceiptV1 {
    QualifiedSupportReceiptV1 {
        schema: RECEIPT_SCHEMA.into(), receipt_digest: String::new(),
        policy_id: policy.policy_id.clone(), policy_digest: policy.policy_digest.clone(),
        project: policy.target.project.clone(), concern: policy.target.concern.clone(),
        question: policy.target.question.clone(), declaration_profile: policy.target.declaration_profile.clone(),
        predicate_profile: policy.target.predicate_profile.clone(), nq_catalog_digest: policy.target.catalog_digest.clone(),
        nq_profile_digest: policy.target.profile_digest.clone(), nq_input_schema_digest: policy.target.input_schema_digest.clone(),
        nq_receipt_digest, nq_verifier_executable_digest: policy.nq_verifier_executable_digest.clone(),
        primary_observed_at: None, support_evidence_id: None, support_evidence_digest: None,
        support_observed_at: None, support_producer_id: None, support_source_id: None, support_vantage_id: None,
        subject_id: policy.target.subject_id.clone(), qualification_at: at.into(), current_until_unix_ms: None,
        primary_support_skew_ms: None,
        independence_basis: "operator_bound_distinct_signed_producer_and_exact_dependency_closure/v1".into(),
        disposition: SupportDispositionV1::NqReceiptInvalid, detail: String::new(), validated: vec![],
        not_validated: vec![
            "uninterrupted truth between primary and support occurrences".into(),
            "producer correctness or independence beyond signed identity and operator-governed topology".into(),
            "whole-project health, causality, remediation authority, or attention policy".into(),
            "current support at any occurrence after qualification_at".into(),
        ],
    }
}

fn seal_receipt(
    mut receipt: QualifiedSupportReceiptV1,
) -> Result<QualifiedSupportReceiptV1, String> {
    receipt.receipt_digest = digest_without_field(&receipt, "receipt_digest")?;
    Ok(receipt)
}

fn verify_evidence(
    policy: &SupportPolicyV1,
    envelope: &SignedSupportEvidenceV1,
) -> Result<(), String> {
    if envelope.schema != ENVELOPE_SCHEMA {
        return Err("unsupported support evidence envelope".into());
    }
    validate_evidence_shape(&envelope.evidence, true)?;
    let evidence = &envelope.evidence;
    if evidence.producer_id != policy.support_source.producer_id
        || evidence.producer_key_id != policy.support_source.producer_key_id
        || evidence.source_id != policy.support_source.source_id
        || evidence.vantage_id != policy.support_source.vantage_id
        || evidence.subject_id != policy.target.subject_id
    {
        return Err("support evidence identities do not match the support policy".into());
    }
    if evidence.producer_id == policy.target.primary_producer {
        return Err("support and primary producer identities are not independent".into());
    }
    if evidence.dependency_ids != policy.support_source.dependency_ids
        || evidence.dependency_ids.iter().any(|item| {
            item == &policy.target.primary_producer
                || matches!(
                    item.as_str(),
                    "monitor_inventory" | "nq_receipt" | "project_status_output"
                )
        })
    {
        return Err("support dependency closure is not independently qualified".into());
    }
    if digest_without_field(evidence, "evidence_id")? != evidence.evidence_id {
        return Err("support evidence content digest is invalid".into());
    }
    require_hex(&envelope.signature_hex, 64)?;
    let key_bytes = decode_hex(&policy.support_source.producer_public_key_hex, 32)?;
    let key = VerifyingKey::from_bytes(key_bytes.as_slice().try_into().map_err(|_| "key length")?)
        .map_err(|error| error.to_string())?;
    let signature_bytes = decode_hex(&envelope.signature_hex, 64)?;
    let signature = Signature::from_bytes(
        signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "signature length")?,
    );
    let mut message = SIGNATURE_DOMAIN.to_vec();
    message.extend(canonical_bytes(evidence)?);
    key.verify(&message, &signature)
        .map_err(|_| "support evidence signature verification failed".to_owned())
}

fn validate_evidence_shape(evidence: &SupportEvidenceV1, require_id: bool) -> Result<(), String> {
    if evidence.schema != EVIDENCE_SCHEMA {
        return Err("unsupported support evidence schema".into());
    }
    for (name, value) in [
        ("acquisition_id", evidence.acquisition_id.as_str()),
        ("producer_id", evidence.producer_id.as_str()),
        ("producer_key_id", evidence.producer_key_id.as_str()),
        ("source_id", evidence.source_id.as_str()),
        ("subject_id", evidence.subject_id.as_str()),
        ("vantage_id", evidence.vantage_id.as_str()),
        ("local_state", evidence.local_state.as_str()),
    ] {
        require_token(name, value)?;
    }
    if require_id {
        require_digest("evidence_id", &evidence.evidence_id)?;
    }
    validate_dependencies(&evidence.dependency_ids)?;
    parse_time(&evidence.observed_at)?;
    if !evidence.facts.is_object() {
        return Err("support facts must be a JSON object".into());
    }
    Ok(())
}

fn invoke_nq(nq: &NqArtifacts<'_>, facts: &Value) -> Result<NqSupportEvaluation, String> {
    let mut facts_file = tempfile::NamedTempFile::new().map_err(|error| error.to_string())?;
    facts_file
        .write_all(&canonical_bytes(facts)?)
        .map_err(|error| error.to_string())?;
    facts_file.flush().map_err(|error| error.to_string())?;
    let mut child = Command::new(nq.executable)
        // The public NQ successor owns this compiled, finite-profile boundary.
        // Matching JSON transport is not compatibility with the older catalog
        // interpreter; never fall back to that predecessor command or schema.
        .args(["bounded-predicate", "support-evaluate", "--receipt"])
        .arg(nq.receipt)
        .args(["--inventory"])
        .arg(nq.inventory)
        .args(["--profiles"])
        .arg(nq.catalog)
        .args(["--facts"])
        .arg(facts_file.path())
        .args(["--output", "-"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("starting NQ verifier: {error}"))?;
    let started = Instant::now();
    loop {
        if child
            .try_wait()
            .map_err(|error| error.to_string())?
            .is_some()
        {
            break;
        }
        if started.elapsed() >= VERIFIER_TIMEOUT {
            child.kill().map_err(|error| error.to_string())?;
            let _ = child.wait();
            return Err("NQ verifier exceeded its bounded runtime".into());
        }
        thread::sleep(Duration::from_millis(5));
    }
    let output = child
        .wait_with_output()
        .map_err(|error| error.to_string())?;
    if output.stdout.len() > MAX_VERIFIER_OUTPUT_BYTES
        || output.stderr.len() > MAX_VERIFIER_OUTPUT_BYTES
    {
        return Err("NQ verifier output exceeded its byte bound".into());
    }
    if !output.status.success() {
        return Err(format!(
            "NQ verifier refused replay/evaluation: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let value: NqSupportEvaluation = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("NQ verifier output: {error}"))?;
    if value.schema != NQ_EVALUATION_SCHEMA || !value.admission_replay_matches {
        return Err("NQ verifier returned an unsupported or non-replay result".into());
    }
    let _ = &value.trace;
    Ok(value)
}

fn parse_time(value: &str) -> Result<OffsetDateTime, String> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|error| format!("invalid RFC3339 occurrence {value:?}: {error}"))
}
fn add_seconds(value: OffsetDateTime, seconds: u64) -> Result<OffsetDateTime, String> {
    value
        .checked_add(time::Duration::seconds(
            i64::try_from(seconds).map_err(|_| "duration exceeds i64")?,
        ))
        .ok_or_else(|| "currentness deadline overflow".into())
}
fn to_unix_ms(value: OffsetDateTime) -> Result<i64, String> {
    i64::try_from(value.unix_timestamp_nanos() / 1_000_000)
        .map_err(|_| "currentness deadline exceeds i64 Unix milliseconds".into())
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "{} must be a regular non-symlink file",
            path.display()
        ));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|error| error.to_string())?
        .take((MAX_ARTIFACT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > MAX_ARTIFACT_BYTES {
        return Err(format!("{} exceeds artifact byte bound", path.display()));
    }
    Ok(bytes)
}
fn file_digest(path: &Path) -> Result<String, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "{} must be a regular non-symlink executable",
            path.display()
        ));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|error| error.to_string())?
        .take((MAX_EXECUTABLE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > MAX_EXECUTABLE_BYTES {
        return Err(format!("{} exceeds executable byte bound", path.display()));
    }
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}
pub fn canonical_digest<T: Serialize>(value: &T) -> Result<String, String> {
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(canonical_bytes(value)?)
    ))
}
fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    serde_jcs::to_vec(value).map_err(|error| error.to_string())
}
fn digest_without_field<T: Serialize>(value: &T, field: &str) -> Result<String, String> {
    let mut value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    value
        .as_object_mut()
        .ok_or_else(|| "digest subject must be an object".to_owned())?
        .remove(field);
    canonical_digest(&value)
}
fn json_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("NQ receipt has no string {field}"))
}
fn validate_dependencies(values: &[String]) -> Result<(), String> {
    if values.is_empty() {
        return Err("support dependency closure must not be empty".into());
    }
    let mut prior: Option<&str> = None;
    for value in values {
        require_token("dependency_id", value)?;
        if prior.is_some_and(|p| p >= value) {
            return Err("dependency IDs must be sorted and unique".into());
        }
        prior = Some(value);
    }
    Ok(())
}
fn require_token(name: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 1024 || value.chars().any(char::is_whitespace) {
        return Err(format!("{name} must be a bounded token"));
    }
    Ok(())
}
fn require_digest(name: &str, value: &str) -> Result<(), String> {
    if value.len() != 71
        || !value.starts_with("sha256:")
        || !value[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(format!("{name} must be sha256:<lowercase hex>"));
    }
    Ok(())
}
fn require_hex(value: &str, bytes: usize) -> Result<(), String> {
    if value.len() != bytes * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("value is not exact lowercase hex".into());
    }
    Ok(())
}
fn decode_hex(value: &str, bytes: usize) -> Result<Vec<u8>, String> {
    require_hex(value, bytes)?;
    (0..bytes)
        .map(|i| {
            u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|error| error.to_string())
        })
        .collect()
}
fn encode_hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn verifier_executable_digest(path: &Path) -> Result<String, String> {
    file_digest(path)
}
pub fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    serde_json::from_slice(&read_bounded(path)?).map_err(|error| error.to_string())
}
pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    std::fs::write(path, bytes).map_err(|error| error.to_string())
}
