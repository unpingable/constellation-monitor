#![forbid(unsafe_code)]
//! Closed production support family for `nq.host.load_pressure/v1`.
//!
//! This crate deliberately has no NQ client, command runner, arbitrary source
//! path, proposition registry, or currentness authority. The producer reads
//! only the fixed Linux sources used by the qualified proposition. A separate
//! intake stamps receiver-owned boot-clock custody. The resolver only matches
//! retained support to one deployment-pinned Nightshift query.

use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const CONFIG_SCHEMA: &str = "pulse.nq_host_load_pressure_support_config.v1";
pub const EVIDENCE_SCHEMA: &str = "pulse.nq_host_load_pressure_support_evidence.v1";
pub const ENVELOPE_SCHEMA: &str = "pulse.nq_host_load_pressure_support_envelope.v1";
pub const RECEIPT_SCHEMA: &str = "pulse.nq_host_load_pressure_support_receipt.v1";
pub const SUPPORT_FAMILY: &str = "pulse.nq_host_load_pressure.v1";
pub const SUPPORT_QUERY_SCHEMA: &str = "nightshift.present_evidence_query.v1";
pub const QUALIFIED_SUPPORT_SCHEMA: &str = "nightshift.qualified_support.v1";
pub const QUESTION_ID: &str = "nq.host.load_pressure";
pub const QUESTION_VERSION: &str = "1";
pub const QUESTION_DIGEST: &str =
    "sha256:7de797da3d9d3a6ae8e21e5d77b95095453336cd38f606ffb3eb29ff6a32e2cf";
pub const PROFILE_ID: &str = "nq.host";
pub const PROFILE_VERSION: &str = "1";
pub const PROFILE_DIGEST: &str =
    "sha256:c8c10fed1cc5598d953b4defbc98e8c106fc59e035c249d43681698a5c7b4ff9";
pub const PROFILE_SEMANTIC_ID: &str =
    "sha256:382b8dac14ef9353a3603757d60fc8fbc727e1bcaf088c9aab4bdf895d3f6ab1";
pub const THRESHOLD_POLICY_ID: &str = "nq.host.load_pressure.threshold_policy";
pub const THRESHOLD_POLICY_VERSION: &str = "1";
pub const THRESHOLD_POLICY_DIGEST: &str =
    "sha256:52b815509d26878fad1f88c6352bcd17537452f704072e56664e18434fee855e";
pub const NORMALIZED_LOAD_THRESHOLD_MILLIS: u32 = 2_000;
pub const SUPPORT_VALIDITY_MS: u64 = 300_000;
pub const SOURCE_BASIS: &str = "linux_proc_loadavg_plus_rust_available_parallelism_v1";

const PROC_LOADAVG: &str = "/proc/loadavg";
const PROC_UPTIME: &str = "/proc/uptime";
const PROC_BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";
const MAX_SOURCE_BYTES: usize = 4_096;
const MAX_RECORDS: usize = 1_024;
const SIGNATURE_DOMAIN: &[u8] = b"pulse/nq-host-load-pressure-support/evidence/v1\0";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticIdentityV1 {
    pub id: String,
    pub version: String,
    pub digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadPressureStateV1 {
    Present,
    ExplicitlyAbsent,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedDiagnosticV1 {
    pub diagnostic_inputs_id: String,
    pub artifact_ids: Vec<String>,
    pub expected_state: LoadPressureStateV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadSupportConfigV1 {
    pub schema: String,
    pub authority_id: String,
    pub support_family: String,
    pub producer_id: String,
    pub producer_key_id: String,
    pub producer_public_key_hex: String,
    pub producer_private_key_path: PathBuf,
    pub subject_id: String,
    pub scope_id: String,
    pub vantage_id: String,
    pub question: SemanticIdentityV1,
    pub profile: SemanticIdentityV1,
    pub profile_semantic_id: String,
    pub threshold_policy: SemanticIdentityV1,
    pub outgoing_directory: PathBuf,
    pub receipt_directory: PathBuf,
    pub expected_diagnostic: ExpectedDiagnosticV1,
}

impl LoadSupportConfigV1 {
    pub fn from_path(path: &Path) -> Result<Self, String> {
        let bytes = read_regular_bounded(path, 64 * 1_024)?;
        let value: Self = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != CONFIG_SCHEMA || self.support_family != SUPPORT_FAMILY {
            return Err("unsupported exact load-support configuration".into());
        }
        for (name, value) in [
            ("authority_id", self.authority_id.as_str()),
            ("producer_id", self.producer_id.as_str()),
            ("producer_key_id", self.producer_key_id.as_str()),
            ("subject_id", self.subject_id.as_str()),
            ("vantage_id", self.vantage_id.as_str()),
        ] {
            require_token(name, value)?;
        }
        require_digest("scope_id", &self.scope_id)?;
        require_digest("profile_semantic_id", &self.profile_semantic_id)?;
        require_hex("producer_public_key_hex", &self.producer_public_key_hex, 32)?;
        require_identity(
            "question",
            &self.question,
            QUESTION_ID,
            QUESTION_VERSION,
            QUESTION_DIGEST,
        )?;
        require_identity(
            "profile",
            &self.profile,
            PROFILE_ID,
            PROFILE_VERSION,
            PROFILE_DIGEST,
        )?;
        if self.profile_semantic_id != PROFILE_SEMANTIC_ID {
            return Err("profile_semantic_id is not the qualified NQ host v1 identity".into());
        }
        require_identity(
            "threshold_policy",
            &self.threshold_policy,
            THRESHOLD_POLICY_ID,
            THRESHOLD_POLICY_VERSION,
            THRESHOLD_POLICY_DIGEST,
        )?;
        require_digest(
            "expected_diagnostic.diagnostic_inputs_id",
            &self.expected_diagnostic.diagnostic_inputs_id,
        )?;
        strictly_ordered_digests(
            "expected_diagnostic.artifact_ids",
            &self.expected_diagnostic.artifact_ids,
        )?;
        if self.outgoing_directory == self.receipt_directory {
            return Err("producer outgoing and receiver receipt directories must differ".into());
        }
        if !self.outgoing_directory.is_absolute()
            || !self.receipt_directory.is_absolute()
            || !self.producer_private_key_path.is_absolute()
        {
            return Err("all production custody paths must be absolute".into());
        }
        Ok(())
    }

    fn verifying_key(&self) -> Result<VerifyingKey, String> {
        let bytes = decode_hex_exact(&self.producer_public_key_hex, 32)?;
        VerifyingKey::from_bytes(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| "producer public key length changed".to_owned())?,
        )
        .map_err(|error| error.to_string())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverInstantV1 {
    pub clock_id: String,
    pub tick_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadPressureEvidenceV1 {
    pub schema: String,
    pub evidence_id: String,
    pub acquisition_id: String,
    pub support_family: String,
    pub producer_id: String,
    pub producer_key_id: String,
    pub subject_id: String,
    pub vantage_id: String,
    pub question: SemanticIdentityV1,
    pub profile: SemanticIdentityV1,
    pub profile_semantic_id: String,
    pub threshold_policy: SemanticIdentityV1,
    pub source_basis: String,
    pub load_1m_token: String,
    pub logical_cpu_count: u32,
    pub normalized_load_threshold_millis: u32,
    pub state: LoadPressureStateV1,
    pub observed_at: ReceiverInstantV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedLoadPressureEvidenceV1 {
    pub schema: String,
    pub evidence: LoadPressureEvidenceV1,
    pub signature_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceivedLoadPressureSupportV1 {
    pub schema: String,
    pub receipt_id: String,
    pub evidence: SignedLoadPressureEvidenceV1,
    pub received_at: ReceiverInstantV1,
    pub expiry_tick_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PresentEvidenceQueryV1 {
    pub schema: String,
    pub query_id: String,
    pub observation_cycle_id: String,
    pub request_nonce: String,
    pub observation_id: String,
    pub diagnostic_inputs_id: String,
    pub subject_id: String,
    pub scope_id: String,
    pub artifact_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupportInstantV1 {
    pub clock_id: String,
    pub tick: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupportExpiryV1 {
    pub clock_id: String,
    pub tick: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QualifiedStandingV1 {
    Current,
    Expired,
    Unknown,
    Unsupported,
    Contradictory,
    Blind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedSupportV1 {
    pub schema: String,
    pub support_id: String,
    pub authority_id: String,
    pub query_id: String,
    pub observation_cycle_id: String,
    pub request_nonce: String,
    pub observation_id: String,
    pub diagnostic_inputs_id: String,
    pub subject_id: String,
    pub scope_id: String,
    pub artifact_ids: Vec<String>,
    pub evaluated_at: SupportInstantV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry: Option<SupportExpiryV1>,
    pub standing: QualifiedStandingV1,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contradiction_refs: Vec<String>,
}

trait HostSource {
    fn load_1m_token(&self) -> Result<String, String>;
    fn logical_cpu_count(&self) -> Result<u32, String>;
}

struct LinuxHostSource;

impl HostSource for LinuxHostSource {
    fn load_1m_token(&self) -> Result<String, String> {
        let text = read_fixed_source(PROC_LOADAVG)?;
        text.split_ascii_whitespace()
            .next()
            .map(str::to_owned)
            .ok_or_else(|| "/proc/loadavg is empty".to_owned())
    }

    fn logical_cpu_count(&self) -> Result<u32, String> {
        u32::try_from(
            std::thread::available_parallelism()
                .map_err(|error| error.to_string())?
                .get(),
        )
        .map_err(|_| "logical CPU count exceeds u32".to_owned())
    }
}

trait AuthorityClock {
    fn now(&self) -> Result<ReceiverInstantV1, String>;
}

struct LinuxBootClock;

impl AuthorityClock for LinuxBootClock {
    fn now(&self) -> Result<ReceiverInstantV1, String> {
        let boot_id = read_fixed_source(PROC_BOOT_ID)?;
        let boot_id = boot_id.trim();
        if boot_id.is_empty() || boot_id.chars().any(char::is_whitespace) {
            return Err("Linux boot ID is empty or malformed".into());
        }
        let uptime = read_fixed_source(PROC_UPTIME)?;
        let token = uptime
            .split_ascii_whitespace()
            .next()
            .ok_or_else(|| "/proc/uptime is empty".to_owned())?;
        Ok(ReceiverInstantV1 {
            clock_id: format!("pulse-linux-boottime:sha256:{:x}", Sha256::digest(boot_id)),
            tick_ms: decimal_seconds_to_millis(token)?,
        })
    }
}

pub fn produce(config: &LoadSupportConfigV1, acquisition_id: &str) -> Result<String, String> {
    produce_with(config, acquisition_id, &LinuxHostSource, &LinuxBootClock)
}

fn produce_with(
    config: &LoadSupportConfigV1,
    acquisition_id: &str,
    source: &impl HostSource,
    clock: &impl AuthorityClock,
) -> Result<String, String> {
    config.validate()?;
    require_token("acquisition_id", acquisition_id)?;
    fs::create_dir_all(&config.outgoing_directory).map_err(|error| error.to_string())?;
    let output = occurrence_path(&config.outgoing_directory, acquisition_id);
    if output.exists() {
        let existing = read_envelope(&output)?;
        verify_envelope(config, &existing)?;
        if existing.evidence.acquisition_id != acquisition_id {
            return Err("existing producer occurrence has a substituted acquisition ID".into());
        }
        return Ok(existing.evidence.evidence_id);
    }

    let load_1m_token = source.load_1m_token()?;
    let load = parse_load(&load_1m_token)?;
    let logical_cpu_count = source.logical_cpu_count()?;
    if logical_cpu_count == 0 {
        return Err("logical CPU count must be nonzero".into());
    }
    let state = derive_state(load, logical_cpu_count);
    let mut evidence = LoadPressureEvidenceV1 {
        schema: EVIDENCE_SCHEMA.into(),
        evidence_id: String::new(),
        acquisition_id: acquisition_id.into(),
        support_family: SUPPORT_FAMILY.into(),
        producer_id: config.producer_id.clone(),
        producer_key_id: config.producer_key_id.clone(),
        subject_id: config.subject_id.clone(),
        vantage_id: config.vantage_id.clone(),
        question: config.question.clone(),
        profile: config.profile.clone(),
        profile_semantic_id: config.profile_semantic_id.clone(),
        threshold_policy: config.threshold_policy.clone(),
        source_basis: SOURCE_BASIS.into(),
        load_1m_token,
        logical_cpu_count,
        normalized_load_threshold_millis: NORMALIZED_LOAD_THRESHOLD_MILLIS,
        state,
        observed_at: clock.now()?,
    };
    evidence.evidence_id = object_id(&evidence, "evidence_id")?;
    let signing_key = read_signing_key(&config.producer_private_key_path)?;
    if signing_key.verifying_key() != config.verifying_key()? {
        return Err("producer private key does not match the configured public key".into());
    }
    let mut signing_bytes = SIGNATURE_DOMAIN.to_vec();
    signing_bytes.extend(canonical_bytes(&evidence)?);
    let envelope = SignedLoadPressureEvidenceV1 {
        schema: ENVELOPE_SCHEMA.into(),
        signature_hex: encode_hex(&signing_key.sign(&signing_bytes).to_bytes()),
        evidence,
    };
    write_create_new(&output, &canonical_bytes(&envelope)?, 0o640)?;
    Ok(envelope.evidence.evidence_id)
}

pub fn ingest(config: &LoadSupportConfigV1, acquisition_id: &str) -> Result<String, String> {
    ingest_with(config, acquisition_id, &LinuxBootClock)
}

fn ingest_with(
    config: &LoadSupportConfigV1,
    acquisition_id: &str,
    clock: &impl AuthorityClock,
) -> Result<String, String> {
    config.validate()?;
    require_token("acquisition_id", acquisition_id)?;
    fs::create_dir_all(&config.receipt_directory).map_err(|error| error.to_string())?;
    let output = occurrence_path(&config.outgoing_directory, acquisition_id);
    let envelope = read_envelope(&output)?;
    verify_envelope(config, &envelope)?;
    if envelope.evidence.acquisition_id != acquisition_id {
        return Err("producer occurrence does not match requested acquisition ID".into());
    }
    let receipt_path = occurrence_path(&config.receipt_directory, acquisition_id);
    if receipt_path.exists() {
        let existing = read_receipt(&receipt_path)?;
        verify_receipt(config, &existing)?;
        if existing.evidence != envelope {
            return Err("replayed acquisition conflicts with the retained exact envelope".into());
        }
        return Ok(existing.receipt_id);
    }
    let received_at = clock.now()?;
    if received_at.clock_id != envelope.evidence.observed_at.clock_id
        || received_at.tick_ms < envelope.evidence.observed_at.tick_ms
    {
        return Err("producer evidence is not ordered on the receiver's current boot clock".into());
    }
    let expiry_tick_ms = received_at
        .tick_ms
        .checked_add(SUPPORT_VALIDITY_MS)
        .ok_or_else(|| "support expiry overflow".to_owned())?;
    let mut receipt = ReceivedLoadPressureSupportV1 {
        schema: RECEIPT_SCHEMA.into(),
        receipt_id: String::new(),
        evidence: envelope,
        received_at,
        expiry_tick_ms,
    };
    receipt.receipt_id = object_id(&receipt, "receipt_id")?;
    write_create_new(&receipt_path, &canonical_bytes(&receipt)?, 0o640)?;
    Ok(receipt.receipt_id)
}

pub fn resolve(
    config: &LoadSupportConfigV1,
    query: &PresentEvidenceQueryV1,
) -> Result<QualifiedSupportV1, String> {
    resolve_with(config, query, &LinuxBootClock)
}

fn resolve_with(
    config: &LoadSupportConfigV1,
    query: &PresentEvidenceQueryV1,
    clock: &impl AuthorityClock,
) -> Result<QualifiedSupportV1, String> {
    config.validate()?;
    validate_query(config, query)?;
    let now = clock.now()?;
    let mut receipts = load_receipts(config)?;
    receipts.sort_by(|left, right| {
        (left.received_at.tick_ms, left.receipt_id.as_str())
            .cmp(&(right.received_at.tick_ms, right.receipt_id.as_str()))
    });
    let latest = receipts
        .into_iter()
        .rfind(|receipt| receipt.received_at.clock_id == now.clock_id);
    let (standing, expiry, evidence_refs, contradiction_refs) = match latest {
        None => (QualifiedStandingV1::Unknown, None, vec![], vec![]),
        Some(receipt) if now.tick_ms >= receipt.expiry_tick_ms => (
            QualifiedStandingV1::Expired,
            Some(SupportExpiryV1 {
                clock_id: now.clock_id.clone(),
                tick: receipt.expiry_tick_ms,
            }),
            vec![receipt.evidence.evidence.evidence_id],
            vec![],
        ),
        Some(receipt)
            if receipt.evidence.evidence.state != config.expected_diagnostic.expected_state =>
        {
            (
                QualifiedStandingV1::Contradictory,
                None,
                vec![],
                vec![receipt.evidence.evidence.evidence_id],
            )
        }
        Some(receipt) => (
            QualifiedStandingV1::Current,
            Some(SupportExpiryV1 {
                clock_id: now.clock_id.clone(),
                tick: receipt.expiry_tick_ms,
            }),
            vec![receipt.evidence.evidence.evidence_id],
            vec![],
        ),
    };
    let mut support = QualifiedSupportV1 {
        schema: QUALIFIED_SUPPORT_SCHEMA.into(),
        support_id: String::new(),
        authority_id: config.authority_id.clone(),
        query_id: query.query_id.clone(),
        observation_cycle_id: query.observation_cycle_id.clone(),
        request_nonce: query.request_nonce.clone(),
        observation_id: query.observation_id.clone(),
        diagnostic_inputs_id: query.diagnostic_inputs_id.clone(),
        subject_id: query.subject_id.clone(),
        scope_id: query.scope_id.clone(),
        artifact_ids: query.artifact_ids.clone(),
        evaluated_at: SupportInstantV1 {
            clock_id: now.clock_id,
            tick: now.tick_ms,
        },
        expiry,
        standing,
        evidence_refs,
        contradiction_refs,
    };
    support.support_id = object_id(&support, "support_id")?;
    Ok(support)
}

fn validate_query(
    config: &LoadSupportConfigV1,
    query: &PresentEvidenceQueryV1,
) -> Result<(), String> {
    if query.schema != SUPPORT_QUERY_SCHEMA {
        return Err("unsupported Nightshift present-evidence query schema".into());
    }
    for (name, value) in [
        ("query_id", query.query_id.as_str()),
        ("observation_id", query.observation_id.as_str()),
        ("diagnostic_inputs_id", query.diagnostic_inputs_id.as_str()),
        ("scope_id", query.scope_id.as_str()),
    ] {
        require_digest(name, value)?;
    }
    for (name, value) in [
        ("observation_cycle_id", query.observation_cycle_id.as_str()),
        ("request_nonce", query.request_nonce.as_str()),
        ("subject_id", query.subject_id.as_str()),
    ] {
        require_token(name, value)?;
    }
    strictly_ordered_digests("artifact_ids", &query.artifact_ids)?;
    if object_id(query, "query_id")? != query.query_id {
        return Err("query_id does not match the canonical query preimage".into());
    }
    if query.subject_id != config.subject_id
        || query.scope_id != config.scope_id
        || query.diagnostic_inputs_id != config.expected_diagnostic.diagnostic_inputs_id
        || query.artifact_ids != config.expected_diagnostic.artifact_ids
    {
        return Err("query does not match the one configured diagnostic basis".into());
    }
    Ok(())
}

fn load_receipts(
    config: &LoadSupportConfigV1,
) -> Result<Vec<ReceivedLoadPressureSupportV1>, String> {
    let mut paths = Vec::new();
    match fs::read_dir(&config.receipt_directory) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.map_err(|error| error.to_string())?;
                if entry
                    .file_type()
                    .map_err(|error| error.to_string())?
                    .is_file()
                    && entry
                        .path()
                        .extension()
                        .is_some_and(|extension| extension == "json")
                {
                    paths.push(entry.path());
                    if paths.len() > MAX_RECORDS {
                        return Err("support receipt store exceeds its closed record bound".into());
                    }
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.to_string()),
    }
    paths.sort();
    paths
        .iter()
        .map(|path| {
            let receipt = read_receipt(path)?;
            verify_receipt(config, &receipt)?;
            Ok(receipt)
        })
        .collect()
}

fn verify_envelope(
    config: &LoadSupportConfigV1,
    envelope: &SignedLoadPressureEvidenceV1,
) -> Result<(), String> {
    if envelope.schema != ENVELOPE_SCHEMA {
        return Err("unsupported load-support envelope schema".into());
    }
    let evidence = &envelope.evidence;
    if evidence.schema != EVIDENCE_SCHEMA
        || evidence.support_family != SUPPORT_FAMILY
        || evidence.producer_id != config.producer_id
        || evidence.producer_key_id != config.producer_key_id
        || evidence.subject_id != config.subject_id
        || evidence.vantage_id != config.vantage_id
        || evidence.question != config.question
        || evidence.profile != config.profile
        || evidence.profile_semantic_id != config.profile_semantic_id
        || evidence.threshold_policy != config.threshold_policy
        || evidence.source_basis != SOURCE_BASIS
        || evidence.normalized_load_threshold_millis != NORMALIZED_LOAD_THRESHOLD_MILLIS
    {
        return Err("load-support evidence does not match the closed family configuration".into());
    }
    require_token("acquisition_id", &evidence.acquisition_id)?;
    require_digest("evidence_id", &evidence.evidence_id)?;
    require_token("observed_at.clock_id", &evidence.observed_at.clock_id)?;
    if object_id(evidence, "evidence_id")? != evidence.evidence_id {
        return Err("evidence_id does not match its canonical preimage".into());
    }
    let load = parse_load(&evidence.load_1m_token)?;
    if evidence.logical_cpu_count == 0
        || derive_state(load, evidence.logical_cpu_count) != evidence.state
    {
        return Err("derived load-pressure state does not match the retained raw basis".into());
    }
    require_hex("signature_hex", &envelope.signature_hex, 64)?;
    let signature_bytes = decode_hex_exact(&envelope.signature_hex, 64)?;
    let signature = Signature::from_bytes(
        signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "signature length changed".to_owned())?,
    );
    let mut signing_bytes = SIGNATURE_DOMAIN.to_vec();
    signing_bytes.extend(canonical_bytes(evidence)?);
    config
        .verifying_key()?
        .verify(&signing_bytes, &signature)
        .map_err(|_| "producer signature verification failed".to_owned())
}

fn verify_receipt(
    config: &LoadSupportConfigV1,
    receipt: &ReceivedLoadPressureSupportV1,
) -> Result<(), String> {
    if receipt.schema != RECEIPT_SCHEMA {
        return Err("unsupported support receipt schema".into());
    }
    verify_envelope(config, &receipt.evidence)?;
    require_digest("receipt_id", &receipt.receipt_id)?;
    require_token("received_at.clock_id", &receipt.received_at.clock_id)?;
    if receipt.received_at.clock_id != receipt.evidence.evidence.observed_at.clock_id
        || receipt.received_at.tick_ms < receipt.evidence.evidence.observed_at.tick_ms
        || receipt.expiry_tick_ms
            != receipt
                .received_at
                .tick_ms
                .checked_add(SUPPORT_VALIDITY_MS)
                .ok_or_else(|| "support expiry overflow".to_owned())?
        || object_id(receipt, "receipt_id")? != receipt.receipt_id
    {
        return Err("support receipt custody or receiver-clock binding is invalid".into());
    }
    Ok(())
}

fn derive_state(load_1m: f64, cpu_count: u32) -> LoadPressureStateV1 {
    if load_1m / f64::from(cpu_count) >= f64::from(NORMALIZED_LOAD_THRESHOLD_MILLIS) / 1_000.0 {
        LoadPressureStateV1::Present
    } else {
        LoadPressureStateV1::ExplicitlyAbsent
    }
}

fn parse_load(token: &str) -> Result<f64, String> {
    if token.is_empty() || token.len() > 64 || token.chars().any(char::is_whitespace) {
        return Err("one-minute load token is empty, oversized, or contains whitespace".into());
    }
    let value = token.parse::<f64>().map_err(|error| error.to_string())?;
    if !value.is_finite() || value.is_sign_negative() {
        return Err("one-minute load must be finite and non-negative".into());
    }
    Ok(value)
}

fn decimal_seconds_to_millis(token: &str) -> Result<u64, String> {
    let (seconds, fraction) = token.split_once('.').unwrap_or((token, ""));
    if seconds.is_empty()
        || !seconds.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("boot-clock source is not a non-negative decimal".into());
    }
    let seconds = seconds.parse::<u64>().map_err(|error| error.to_string())?;
    let mut millis = 0_u64;
    for (index, byte) in fraction.bytes().take(3).enumerate() {
        let digit = u64::from(byte - b'0');
        millis += digit * [100, 10, 1][index];
    }
    seconds
        .checked_mul(1_000)
        .and_then(|value| value.checked_add(millis))
        .ok_or_else(|| "boot-clock milliseconds overflow".to_owned())
}

fn occurrence_path(directory: &Path, acquisition_id: &str) -> PathBuf {
    directory.join(format!("sha256-{:x}.json", Sha256::digest(acquisition_id)))
}

fn read_envelope(path: &Path) -> Result<SignedLoadPressureEvidenceV1, String> {
    let bytes = read_regular_bounded(path, 64 * 1_024)?;
    let value = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if canonical_bytes(&value)? != bytes {
        return Err("producer evidence is not exact canonical JSON".into());
    }
    Ok(value)
}

fn read_receipt(path: &Path) -> Result<ReceivedLoadPressureSupportV1, String> {
    let bytes = read_regular_bounded(path, 128 * 1_024)?;
    let value = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if canonical_bytes(&value)? != bytes {
        return Err("support receipt is not exact canonical JSON".into());
    }
    Ok(value)
}

fn read_signing_key(path: &Path) -> Result<SigningKey, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err("producer signing key must be a non-symlink regular file".into());
    }
    if metadata.mode() & 0o077 != 0 {
        return Err("producer signing key must not be accessible by group or others".into());
    }
    let text = String::from_utf8(read_regular_bounded(path, 256)?)
        .map_err(|_| "producer signing key is not UTF-8 hex".to_owned())?;
    let bytes = decode_hex_exact(text.trim(), 32)?;
    Ok(SigningKey::from_bytes(
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| "producer signing key length changed".to_owned())?,
    ))
}

fn read_fixed_source(path: &str) -> Result<String, String> {
    String::from_utf8(read_regular_bounded(Path::new(path), MAX_SOURCE_BYTES)?)
        .map_err(|_| format!("{path} is not UTF-8"))
}

fn read_regular_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "{} must be a non-symlink regular file",
            path.display()
        ));
    }
    let limit = u64::try_from(maximum)
        .map_err(|error| error.to_string())?
        .saturating_add(1);
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|error| error.to_string())?
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > maximum {
        return Err(format!("{} exceeds its byte bound", path.display()));
    }
    Ok(bytes)
}

fn write_create_new(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    serde_jcs::to_vec(value).map_err(|error| error.to_string())
}

fn object_id<T: Serialize>(value: &T, identity_field: &str) -> Result<String, String> {
    let mut value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    value
        .as_object_mut()
        .ok_or_else(|| "identity-bearing value must be an object".to_owned())?
        .remove(identity_field);
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(canonical_bytes(&value)?)
    ))
}

fn require_identity(
    name: &str,
    actual: &SemanticIdentityV1,
    id: &str,
    version: &str,
    digest: &str,
) -> Result<(), String> {
    if actual.id != id || actual.version != version || actual.digest != digest {
        return Err(format!("{name} is not the exact qualified identity"));
    }
    Ok(())
}

fn require_token(name: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_whitespace) {
        return Err(format!("{name} must be a bounded non-whitespace token"));
    }
    Ok(())
}

fn require_digest(name: &str, value: &str) -> Result<(), String> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(format!("{name} must use sha256:<64 lowercase hex>"));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{name} must use sha256:<64 lowercase hex>"));
    }
    Ok(())
}

fn strictly_ordered_digests(name: &str, values: &[String]) -> Result<(), String> {
    if values.is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    let mut prior: Option<&str> = None;
    for value in values {
        require_digest(name, value)?;
        if prior.is_some_and(|item| item >= value.as_str()) {
            return Err(format!("{name} must be strictly ordered and unique"));
        }
        prior = Some(value);
    }
    Ok(())
}

fn require_hex(name: &str, value: &str, bytes: usize) -> Result<(), String> {
    if value.len() != bytes * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{name} must be exact lowercase hex"));
    }
    Ok(())
}

fn decode_hex_exact(value: &str, bytes: usize) -> Result<Vec<u8>, String> {
    require_hex("hex value", value, bytes)?;
    (0..bytes)
        .map(|index| {
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                .map_err(|error| error.to_string())
        })
        .collect()
}

fn encode_hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use tempfile::TempDir;

    use super::*;

    struct FixedSource<'a> {
        load: &'a str,
        cpus: u32,
        reads: &'a Cell<u32>,
    }

    impl HostSource for FixedSource<'_> {
        fn load_1m_token(&self) -> Result<String, String> {
            self.reads.set(self.reads.get() + 1);
            Ok(self.load.into())
        }

        fn logical_cpu_count(&self) -> Result<u32, String> {
            self.reads.set(self.reads.get() + 1);
            Ok(self.cpus)
        }
    }

    #[derive(Clone)]
    struct FixedClock {
        clock_id: &'static str,
        tick_ms: Cell<u64>,
    }

    impl AuthorityClock for FixedClock {
        fn now(&self) -> Result<ReceiverInstantV1, String> {
            Ok(ReceiverInstantV1 {
                clock_id: self.clock_id.into(),
                tick_ms: self.tick_ms.get(),
            })
        }
    }

    fn fixture() -> (TempDir, LoadSupportConfigV1) {
        let root = TempDir::new().expect("tempdir");
        let outgoing = root.path().join("outgoing");
        let receipts = root.path().join("receipts");
        fs::create_dir_all(&outgoing).expect("outgoing");
        fs::create_dir_all(&receipts).expect("receipts");
        let signing = SigningKey::from_bytes(&[7_u8; 32]);
        let key_path = root.path().join("key.hex");
        write_create_new(&key_path, encode_hex(&signing.to_bytes()).as_bytes(), 0o600)
            .expect("key");
        (
            root,
            LoadSupportConfigV1 {
                schema: CONFIG_SCHEMA.into(),
                authority_id: "pulse-authority:load-pressure-v1".into(),
                support_family: SUPPORT_FAMILY.into(),
                producer_id: "pulse-producer:load-pressure-local-v1".into(),
                producer_key_id: format!(
                    "pulse-key:sha256:{:x}",
                    Sha256::digest(signing.verifying_key().as_bytes())
                ),
                producer_public_key_hex: encode_hex(signing.verifying_key().as_bytes()),
                producer_private_key_path: key_path,
                subject_id: "host:labelwatch-host".into(),
                scope_id: "sha256:41841f4aad87f73aea2a2be3926020ce4edb3a833190ab0d71115f7549e961d6".into(),
                vantage_id: "nq.vantage.local.nq-store-genesis:bf0ab251-7ff1-4337-aafa-c7a98832d666.labelwatch-host-local".into(),
                question: SemanticIdentityV1 {
                    id: QUESTION_ID.into(),
                    version: QUESTION_VERSION.into(),
                    digest: QUESTION_DIGEST.into(),
                },
                profile: SemanticIdentityV1 {
                    id: PROFILE_ID.into(),
                    version: PROFILE_VERSION.into(),
                    digest: PROFILE_DIGEST.into(),
                },
                profile_semantic_id: PROFILE_SEMANTIC_ID.into(),
                threshold_policy: SemanticIdentityV1 {
                    id: THRESHOLD_POLICY_ID.into(),
                    version: THRESHOLD_POLICY_VERSION.into(),
                    digest: THRESHOLD_POLICY_DIGEST.into(),
                },
                outgoing_directory: outgoing,
                receipt_directory: receipts,
                expected_diagnostic: ExpectedDiagnosticV1 {
                    diagnostic_inputs_id: "sha256:bf913b508824ba94fdbceda4376d5bfe0f269f036db173c9aa936a988ad0ec9b".into(),
                    artifact_ids: vec!["sha256:54c50dfca0acfaf369d7e800d585b35a26768ffefbad5741cea62c04b63bfad3".into()],
                    expected_state: LoadPressureStateV1::ExplicitlyAbsent,
                },
            },
        )
    }

    fn query(config: &LoadSupportConfigV1) -> PresentEvidenceQueryV1 {
        let mut query = PresentEvidenceQueryV1 {
            schema: SUPPORT_QUERY_SCHEMA.into(),
            query_id: String::new(),
            observation_cycle_id: "cycle:test".into(),
            request_nonce: "support-query:test".into(),
            observation_id:
                "sha256:11dd56509e57e8f094aa03e1ace29889b92e014a1d3262b65b53a8762fce5ba2".into(),
            diagnostic_inputs_id: config.expected_diagnostic.diagnostic_inputs_id.clone(),
            subject_id: config.subject_id.clone(),
            scope_id: config.scope_id.clone(),
            artifact_ids: config.expected_diagnostic.artifact_ids.clone(),
        };
        query.query_id = object_id(&query, "query_id").expect("query ID");
        query
    }

    fn acquire(
        config: &LoadSupportConfigV1,
        acquisition_id: &str,
        load: &str,
        tick: u64,
        reads: &Cell<u32>,
    ) -> String {
        let source = FixedSource {
            load,
            cpus: 2,
            reads,
        };
        let producer_clock = FixedClock {
            clock_id: "clock:boot-one",
            tick_ms: Cell::new(tick),
        };
        produce_with(config, acquisition_id, &source, &producer_clock).expect("produce");
        let receiver_clock = FixedClock {
            clock_id: "clock:boot-one",
            tick_ms: Cell::new(tick + 1),
        };
        ingest_with(config, acquisition_id, &receiver_clock).expect("ingest")
    }

    #[test]
    fn exact_nq_semantics_and_threshold_equality_are_preserved() {
        assert_eq!(
            derive_state(3.999, 2),
            LoadPressureStateV1::ExplicitlyAbsent
        );
        assert_eq!(derive_state(4.0, 2), LoadPressureStateV1::Present);
        assert_eq!(derive_state(8.0, 4), LoadPressureStateV1::Present);
    }

    #[test]
    fn replay_converges_without_rereading_host_state() {
        let (_root, config) = fixture();
        let reads = Cell::new(0);
        let first = acquire(&config, "support:a1", "0.50", 100, &reads);
        assert_eq!(reads.get(), 2);
        let source = FixedSource {
            load: "99.0",
            cpus: 1,
            reads: &reads,
        };
        let clock = FixedClock {
            clock_id: "clock:boot-one",
            tick_ms: Cell::new(200),
        };
        produce_with(&config, "support:a1", &source, &clock).expect("exact replay");
        assert_eq!(reads.get(), 2, "replay must not reacquire host state");
        assert_eq!(
            ingest_with(&config, "support:a1", &clock).expect("replay"),
            first
        );
    }

    #[test]
    fn same_proposition_supports_and_contradiction_is_explicit() {
        let (_root, config) = fixture();
        let reads = Cell::new(0);
        acquire(&config, "support:a1", "0.50", 100, &reads);
        let clock = FixedClock {
            clock_id: "clock:boot-one",
            tick_ms: Cell::new(200),
        };
        let current = resolve_with(&config, &query(&config), &clock).expect("current");
        assert_eq!(current.standing, QualifiedStandingV1::Current);
        assert_eq!(current.evidence_refs.len(), 1);

        acquire(&config, "support:a2", "4.00", 300, &reads);
        clock.tick_ms.set(400);
        let contradictory = resolve_with(&config, &query(&config), &clock).expect("contradiction");
        assert_eq!(contradictory.standing, QualifiedStandingV1::Contradictory);
        assert_eq!(contradictory.contradiction_refs.len(), 1);
    }

    #[test]
    fn stale_support_stays_same_evidence_and_fresh_successor_is_distinct() {
        let (_root, config) = fixture();
        let reads = Cell::new(0);
        acquire(&config, "support:a1", "0.50", 100, &reads);
        let clock = FixedClock {
            clock_id: "clock:boot-one",
            tick_ms: Cell::new(300_101),
        };
        let stale = resolve_with(&config, &query(&config), &clock).expect("stale");
        assert_eq!(stale.standing, QualifiedStandingV1::Expired);
        let old = stale.evidence_refs[0].clone();
        acquire(&config, "support:a2", "0.75", 300_200, &reads);
        clock.tick_ms.set(300_300);
        let fresh = resolve_with(&config, &query(&config), &clock).expect("fresh");
        assert_eq!(fresh.standing, QualifiedStandingV1::Current);
        assert_ne!(fresh.evidence_refs[0], old);
    }

    #[test]
    fn subject_vantage_policy_query_and_signature_substitution_refuse() {
        let (_root, config) = fixture();
        let reads = Cell::new(0);
        acquire(&config, "support:a1", "0.50", 100, &reads);
        let clock = FixedClock {
            clock_id: "clock:boot-one",
            tick_ms: Cell::new(200),
        };
        for mutate in 0..4 {
            let mut wrong = query(&config);
            match mutate {
                0 => wrong.subject_id = "host:other".into(),
                1 => {
                    wrong.scope_id =
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .into()
                }
                2 => {
                    wrong.diagnostic_inputs_id =
                        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                            .into()
                }
                _ => {
                    wrong.artifact_ids[0] =
                        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                            .into()
                }
            }
            wrong.query_id = object_id(&wrong, "query_id").expect("reseal");
            assert!(resolve_with(&config, &wrong, &clock).is_err());
        }

        let path = occurrence_path(&config.outgoing_directory, "support:a1");
        let mut envelope = read_envelope(&path).expect("envelope");
        envelope.evidence.vantage_id = "nq.vantage.local.other".into();
        fs::write(&path, canonical_bytes(&envelope).expect("bytes")).expect("hostile write");
        assert!(ingest_with(&config, "support:a1", &clock).is_err());
    }

    #[test]
    fn unrelated_candidate_schemas_are_not_support_evidence() {
        for candidate in [
            r#"{"schema":"nq.liveness_snapshot.v1"}"#,
            r#"{"schema":"nq.diagnostic_execution.v2"}"#,
            r#"{"schema":"nq.substrate_origin_evidence.v1"}"#,
            r#"{"schema":"pulse.frame.v1","signal":"cpu_idle_fraction"}"#,
        ] {
            assert!(serde_json::from_str::<SignedLoadPressureEvidenceV1>(candidate).is_err());
        }
    }
}
