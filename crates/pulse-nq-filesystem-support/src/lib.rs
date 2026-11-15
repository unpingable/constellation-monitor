//! Present support for one exact native filesystem-capacity proposition.
//!
//! NQ's pinned helper owns observation/identity, and its profile owns the law.
//! This adapter owns signed custody and conservative current-boot expiry for
//! a separately named Nightshift consumer. It never reads status CURRENT,
//! opens an NQ store, admits a diagnostic, or authorizes an effect.

#![forbid(unsafe_code)]

#[path = "../../../build-support/host-posture-helper/build_info.rs"]
pub mod build_info;
mod custody;
mod prepare;
mod realization;
use custody::*;
use ed25519_dalek::{Signature, Signer as _, Verifier as _, VerifyingKey};
use nq_host_resource_helper::{LinuxSource, observe};
use nq_profiles::{
    DetectorState, EvidenceBasis, ProfileModule, ScopeGrant, VantageGrant,
    host_filesystem as native,
};
pub use prepare::prepare;
use pulse_nq_load_support::{
    LoadPressureStateV1, PresentEvidenceQueryV1, QUALIFIED_SUPPORT_SCHEMA, QualifiedStandingV1,
    QualifiedSupportV1, ReceiverInstantV1, SUPPORT_QUERY_SCHEMA, SupportExpiryV1, SupportInstantV1,
};
pub use realization::{AdapterRealizationV1, NQ_SOURCE_COMMIT, REALIZATION_SCHEMA};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};

pub const CONFIG_SCHEMA: &str = "pulse.nq_filesystem_capacity_support_config.v1";
const EVIDENCE_SCHEMA: &str = "pulse.nq_filesystem_capacity_support_evidence.v1";
const ENVELOPE_SCHEMA: &str = "pulse.nq_filesystem_capacity_support_envelope.v1";
const RECEIPT_SCHEMA: &str = "pulse.nq_filesystem_capacity_support_receipt.v1";
const SIGNATURE_DOMAIN: &[u8] = b"pulse/nq-filesystem-capacity-support/evidence/v1\0";
const VALIDITY_MS: u64 = 300_000;
const MAX_ACQUISITION_MS: u64 = 5_000;
// /proc/uptime has centisecond resolution. Subtract this margin at reliance.
const CLOCK_MARGIN_MS: u64 = 10;
const MAX_BYTES: usize = 128 * 1_024;

/// Create one new deployment-owned producer key; never overwrite or export it.
pub fn create_producer_key(path: &Path) -> Result<String, String> {
    if !path.is_absolute() {
        return Err("absolute producer key path required".into());
    }
    let mut bytes = [0u8; 32];
    fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|e| e.to_string())?;
    let key = ed25519_dalek::SigningKey::from_bytes(&bytes);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| e.to_string())?;
    f.write_all(encode_hex(&bytes).as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|e| e.to_string())?;
    fs::File::open(path.parent().ok_or("producer key has no parent")?)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    Ok(encode_hex(key.verifying_key().as_bytes()))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemSupportConfigV1 {
    pub schema: String,
    pub authority_id: String,
    pub consumer_id: String,
    pub producer_id: String,
    pub producer_key_id: String,
    pub producer_public_key_hex: String,
    pub producer_private_key_path: PathBuf,
    pub subject_id: String,
    pub scope_id: String,
    pub scope: native::HostFilesystemScope,
    pub vantage: VantageGrant,
    pub profile_semantic_id: String,
    pub realization: AdapterRealizationV1,
    pub outgoing_directory: PathBuf,
    pub receipt_directory: PathBuf,
    pub expected_diagnostic: pulse_nq_load_support::ExpectedDiagnosticV1,
}

impl FilesystemSupportConfigV1 {
    pub fn from_path(path: &Path) -> Result<Self, String> {
        let x: Self = serde_json::from_slice(&read_regular_bounded(path, MAX_BYTES)?)
            .map_err(|e| e.to_string())?;
        x.validate()?;
        Ok(x)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != CONFIG_SCHEMA {
            return Err("not the closed filesystem support schema".into());
        }
        for (name, x) in [
            ("consumer_id", &self.consumer_id),
            ("authority_id", &self.authority_id),
            ("producer_id", &self.producer_id),
            ("producer_key_id", &self.producer_key_id),
        ] {
            require_token(name, x)?;
        }
        // Namespace is an explicit enrollment distinction, not authentication.
        if !self.consumer_id.starts_with("nightshift:")
            || self.authority_id != format!("filesystem-support:{}", self.consumer_id)
        {
            return Err(
                "filesystem support requires its own Nightshift consumer/authority enrollment"
                    .into(),
            );
        }
        native::validate_scope_value(
            &serde_json::to_value(&self.scope).map_err(|e| e.to_string())?,
            &self.subject_id,
        )?;
        require_digest("scope_id", &self.scope_id)?;
        let semantic = nq_profiles::profile_semantic_id(native::CAPACITY_MODULE.descriptor())
            .map_err(|e| e.to_string())?;
        if self.profile_semantic_id != semantic.as_str() {
            return Err(
                "filesystem support is not bound to this exact native profile semantic identity"
                    .into(),
            );
        }
        if self.vantage.kind != "local" || self.vantage.value != serde_json::json!({}) {
            return Err(
                "filesystem support admits only the native local empty-value vantage".into(),
            );
        }
        self.realization.validate()?;
        if self.realization.configuration_digest != self.configuration_digest()? {
            return Err(
                "filesystem configuration differs from accepted realization enrollment".into(),
            );
        }
        let expected_scope = native_scope_digest(&self.subject_id, &self.scope)?;
        if self.scope_id != expected_scope {
            return Err("native filesystem scope digest differs from diagnostic scope".into());
        }
        require_hex("producer_public_key_hex", &self.producer_public_key_hex, 32)?;
        require_digest(
            "diagnostic_inputs_id",
            &self.expected_diagnostic.diagnostic_inputs_id,
        )?;
        strictly_ordered_digests("artifact_ids", &self.expected_diagnostic.artifact_ids)?;
        if self.expected_diagnostic.artifact_ids.len() != 1 {
            return Err("one filesystem diagnostic only".into());
        }
        if self.outgoing_directory == self.receipt_directory
            || !self.outgoing_directory.is_absolute()
            || !self.receipt_directory.is_absolute()
            || !self.producer_private_key_path.is_absolute()
        {
            return Err("separate absolute producer/receiver custody paths required".into());
        }
        Ok(())
    }

    /// Operator-accepted static configuration. Excluding realization avoids a
    /// digest cycle; the signed enrollment below binds the accepted realization.
    pub fn configuration_digest(&self) -> Result<String, String> {
        let mut value = serde_json::to_value(self).map_err(|e| e.to_string())?;
        let object = value
            .as_object_mut()
            .ok_or("configuration must be an object")?;
        object.remove("realization");
        object.remove("expected_diagnostic");
        object_id(&value, "configuration_digest")
    }

    /// Stable deployment enrollment, excluding the per-query diagnostic basis.
    /// Prior diagnostic testimony must remain Unsupported, not be rebound.
    pub fn enrollment_id(&self) -> Result<String, String> {
        let mut value = serde_json::to_value(self).map_err(|e| e.to_string())?;
        value
            .as_object_mut()
            .ok_or("configuration must be an object")?
            .remove("expected_diagnostic");
        object_id(&value, "enrollment_id")
    }

    fn validate_running(&self) -> Result<(), String> {
        self.validate()?;
        self.realization.validate_current_process()
    }
}

fn native_scope_digest(
    subject: &str,
    scope: &native::HostFilesystemScope,
) -> Result<String, String> {
    let descriptor = native::CAPACITY_MODULE.descriptor();
    let preimage = serde_json::json!({"schema":"nq.diagnostic_scope.v1","subject":subject,
        "scope":{"kind":native::SCOPE_KIND,"value":scope},
        "profile":{"id":descriptor.profile.id,"version":descriptor.profile.version.to_string(),
            "digest":descriptor.digest().map_err(|e|e.to_string())?}});
    nq_protocol::semantic_digest(&preimage)
        .map(|d| d.into_string())
        .map_err(|e| e.to_string())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct FilesystemEvidenceV1 {
    schema: String,
    evidence_id: String,
    acquisition_id: String,
    authority_id: String,
    consumer_id: String,
    producer_id: String,
    producer_key_id: String,
    subject_id: String,
    scope_id: String,
    profile_semantic_id: String,
    realization_id: String,
    enrollment_id: String,
    diagnostic_inputs_id: String,
    artifact_ids: Vec<String>,
    observation_started: ReceiverInstantV1,
    observation_ended: ReceiverInstantV1,
    payload: native::FilesystemSnapshotPayload,
    state: LoadPressureStateV1,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct FilesystemEnvelopeV1 {
    schema: String,
    evidence: FilesystemEvidenceV1,
    signature_hex: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct FilesystemReceiptV1 {
    schema: String,
    receipt_id: String,
    envelope: FilesystemEnvelopeV1,
    received_at: ReceiverInstantV1,
    expiry_tick_ms: u64,
}

fn classify(
    scope: &native::HostFilesystemScope,
    payload: &native::FilesystemSnapshotPayload,
) -> Result<LoadPressureStateV1, String> {
    native::validate_payload_against_scope(payload, scope)?;
    match native::capacity_pressure_state(payload, native::USED_THRESHOLD_PERMILLE) {
        Some(DetectorState::Present) => Ok(LoadPressureStateV1::Present),
        Some(DetectorState::ExplicitlyAbsent) => Ok(LoadPressureStateV1::ExplicitlyAbsent),
        _ => Err("native filesystem capacity cannot establish present or absent".into()),
    }
}

fn acquire_native(
    config: &FilesystemSupportConfigV1,
) -> Result<native::FilesystemSnapshotPayload, String> {
    let x = observe(&config.scope, &LinuxSource)
        .map_err(|e| format!("native filesystem observation refused: {e:?}"))?;
    Ok(native::FilesystemSnapshotPayload {
        evidence_basis: EvidenceBasis {
            scope: ScopeGrant {
                kind: native::SCOPE_KIND.into(),
                value: serde_json::to_value(&config.scope).map_err(|e| e.to_string())?,
            },
            vantage: config.vantage.clone(),
            access_path: native::ACCESS_PATH.into(),
            basis: "kernel_snapshot".into(),
            regime: "normal".into(),
            capabilities_used: native::CAPABILITIES
                .iter()
                .map(|x| (*x).to_owned())
                .collect(),
        },
        machine_id: config.scope.machine_id.clone(),
        filesystem_uuid: config.scope.filesystem_uuid.clone(),
        filesystem_type: config.scope.filesystem_type.clone(),
        mountpoint: config.scope.mountpoint.clone(),
        mount_id: x.mount.mount_id,
        device_major: x.mount.major,
        device_minor: x.mount.minor,
        fsid_hex: format!("{:016x}", x.cut.fsid),
        fragment_size: x.cut.fragment_size,
        blocks_total: x.cut.blocks_total,
        blocks_free: x.cut.blocks_free,
        blocks_available: x.cut.blocks_available,
        inodes_total: x.cut.inodes_total,
        inodes_free: x.cut.inodes_free,
    })
}

/// Acquire actual native filesystem testimony. This does not receive it.
pub fn produce(config: &FilesystemSupportConfigV1, acquisition_id: &str) -> Result<String, String> {
    config.validate_running()?;
    require_token("acquisition_id", acquisition_id)?;
    let key = read_signing_key(&config.producer_private_key_path)?;
    if encode_hex(key.verifying_key().as_bytes()) != config.producer_public_key_hex {
        return Err("filesystem producer key differs from enrollment".into());
    }
    let started = LinuxBootClock.now()?;
    let payload = acquire_native(config)?;
    let ended = LinuxBootClock.now()?;
    if started.clock_id != ended.clock_id
        || ended.tick_ms < started.tick_ms
        || ended.tick_ms - started.tick_ms > MAX_ACQUISITION_MS
    {
        return Err("filesystem acquisition lost its bounded boot-clock interval".into());
    }
    let state = classify(&config.scope, &payload)?;
    let mut e = FilesystemEvidenceV1 {
        schema: EVIDENCE_SCHEMA.into(),
        evidence_id: String::new(),
        acquisition_id: acquisition_id.into(),
        authority_id: config.authority_id.clone(),
        consumer_id: config.consumer_id.clone(),
        producer_id: config.producer_id.clone(),
        producer_key_id: config.producer_key_id.clone(),
        subject_id: config.subject_id.clone(),
        scope_id: config.scope_id.clone(),
        profile_semantic_id: config.profile_semantic_id.clone(),
        realization_id: config.realization.realization_id.clone(),
        enrollment_id: config.enrollment_id()?,
        diagnostic_inputs_id: config.expected_diagnostic.diagnostic_inputs_id.clone(),
        artifact_ids: config.expected_diagnostic.artifact_ids.clone(),
        observation_started: started,
        observation_ended: ended,
        payload,
        state,
    };
    e.evidence_id = object_id(&e, "evidence_id")?;
    let mut message = SIGNATURE_DOMAIN.to_vec();
    message.extend(canonical_bytes(&e)?);
    let envelope = FilesystemEnvelopeV1 {
        schema: ENVELOPE_SCHEMA.into(),
        signature_hex: encode_hex(&key.sign(&message).to_bytes()),
        evidence: e,
    };
    replace_latest(
        &config.outgoing_directory,
        "current-envelope.json",
        &canonical_bytes(&envelope)?,
    )?;
    Ok(envelope.evidence.evidence_id)
}

fn verify_envelope(
    config: &FilesystemSupportConfigV1,
    x: &FilesystemEnvelopeV1,
    exact_basis: bool,
) -> Result<(), String> {
    let e = &x.evidence;
    if x.schema != ENVELOPE_SCHEMA
        || e.schema != EVIDENCE_SCHEMA
        || e.authority_id != config.authority_id
        || e.consumer_id != config.consumer_id
        || e.producer_id != config.producer_id
        || e.producer_key_id != config.producer_key_id
        || e.subject_id != config.subject_id
        || e.scope_id != config.scope_id
        || e.profile_semantic_id != config.profile_semantic_id
        || e.realization_id != config.realization.realization_id
        || e.enrollment_id != config.enrollment_id()?
        || e.payload.evidence_basis.vantage != config.vantage
        || e.payload.evidence_basis.scope
            != (ScopeGrant {
                kind: native::SCOPE_KIND.into(),
                value: serde_json::to_value(&config.scope).map_err(|e| e.to_string())?,
            })
    {
        return Err(
            "filesystem envelope differs from exact consumer/native scope enrollment".into(),
        );
    }
    if exact_basis
        && (e.diagnostic_inputs_id != config.expected_diagnostic.diagnostic_inputs_id
            || e.artifact_ids != config.expected_diagnostic.artifact_ids)
    {
        return Err("filesystem envelope differs from exact diagnostic basis".into());
    }
    require_token("acquisition_id", &e.acquisition_id)?;
    if object_id(e, "evidence_id")? != e.evidence_id
        || classify(&config.scope, &e.payload)? != e.state
    {
        return Err("filesystem evidence identity/native law mismatch".into());
    }
    if e.observation_started.clock_id != e.observation_ended.clock_id
        || e.observation_ended.tick_ms < e.observation_started.tick_ms
        || e.observation_ended.tick_ms - e.observation_started.tick_ms > MAX_ACQUISITION_MS
    {
        return Err("invalid filesystem observation interval".into());
    }
    let bytes = decode_hex_exact(&config.producer_public_key_hex, 32)?;
    let key = VerifyingKey::from_bytes(
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| "public key length")?,
    )
    .map_err(|e| e.to_string())?;
    let bytes = decode_hex_exact(&x.signature_hex, 64)?;
    let signature = Signature::from_bytes(
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| "signature length")?,
    );
    let mut message = SIGNATURE_DOMAIN.to_vec();
    message.extend(canonical_bytes(e)?);
    key.verify(&message, &signature).map_err(|e| e.to_string())
}

/// Separately receive the latest exact signed acquisition. Replay never renews it.
pub fn ingest(config: &FilesystemSupportConfigV1, acquisition_id: &str) -> Result<String, String> {
    config.validate_running()?;
    let x: FilesystemEnvelopeV1 =
        read_canonical(&config.outgoing_directory.join("current-envelope.json"))?;
    verify_envelope(config, &x, true)?;
    if x.evidence.acquisition_id != acquisition_id {
        return Err("wrong filesystem acquisition occurrence".into());
    }
    let now = LinuxBootClock.now()?;
    let start = &x.evidence.observation_started;
    let expiry = start
        .tick_ms
        .checked_add(VALIDITY_MS)
        .ok_or("filesystem expiry overflow")?;
    if now.clock_id != start.clock_id
        || now.tick_ms < x.evidence.observation_ended.tick_ms
        || now.tick_ms.saturating_add(CLOCK_MARGIN_MS) >= expiry
    {
        return Err("filesystem observation is unordered or expired at intake".into());
    }
    let path = config.receipt_directory.join("current-receipt.json");
    if fs::symlink_metadata(&path)
        .map(|_| true)
        .or_else(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Ok(false)
            } else {
                Err(e)
            }
        })
        .map_err(|e| e.to_string())?
    {
        let previous: FilesystemReceiptV1 = read_canonical(&path)?;
        verify_receipt(config, &previous, false)?;
        if previous.envelope == x {
            return Ok(previous.receipt_id);
        }
        if previous.received_at.clock_id == now.clock_id
            && previous.envelope.evidence.observation_started.tick_ms >= start.tick_ms
        {
            return Err("filesystem support cannot replace a newer/equal acquisition".into());
        }
    }
    let mut receipt = FilesystemReceiptV1 {
        schema: RECEIPT_SCHEMA.into(),
        receipt_id: String::new(),
        envelope: x,
        received_at: now,
        expiry_tick_ms: expiry,
    };
    receipt.receipt_id = object_id(&receipt, "receipt_id")?;
    replace_latest(
        &config.receipt_directory,
        "current-receipt.json",
        &canonical_bytes(&receipt)?,
    )?;
    Ok(receipt.receipt_id)
}

fn verify_receipt(
    config: &FilesystemSupportConfigV1,
    x: &FilesystemReceiptV1,
    exact_basis: bool,
) -> Result<(), String> {
    verify_envelope(config, &x.envelope, exact_basis)?;
    let e = &x.envelope.evidence;
    if x.schema != RECEIPT_SCHEMA
        || object_id(x, "receipt_id")? != x.receipt_id
        || x.received_at.clock_id != e.observation_started.clock_id
        || x.received_at.tick_ms < e.observation_ended.tick_ms
        || x.expiry_tick_ms
            != e.observation_started
                .tick_ms
                .checked_add(VALIDITY_MS)
                .ok_or("filesystem expiry overflow")?
    {
        return Err("filesystem receiver custody mismatch".into());
    }
    Ok(())
}

fn standing_at(
    x: Option<&FilesystemReceiptV1>,
    now: &ReceiverInstantV1,
    expected: LoadPressureStateV1,
) -> QualifiedStandingV1 {
    match x {
        None => QualifiedStandingV1::Unknown,
        Some(x) if x.received_at.clock_id != now.clock_id => QualifiedStandingV1::Unknown,
        Some(x) if now.tick_ms < x.received_at.tick_ms => QualifiedStandingV1::Blind,
        Some(x) if now.tick_ms.saturating_add(CLOCK_MARGIN_MS) >= x.expiry_tick_ms => {
            QualifiedStandingV1::Expired
        }
        Some(x) if x.envelope.evidence.state != expected => QualifiedStandingV1::Contradictory,
        Some(_) => QualifiedStandingV1::Current,
    }
}

fn validate_filesystem_query(
    config: &FilesystemSupportConfigV1,
    q: &PresentEvidenceQueryV1,
) -> Result<(), String> {
    if q.schema != SUPPORT_QUERY_SCHEMA
        || object_id(q, "query_id")? != q.query_id
        || q.subject_id != config.subject_id
        || q.scope_id != config.scope_id
        || q.diagnostic_inputs_id != config.expected_diagnostic.diagnostic_inputs_id
        || q.artifact_ids != config.expected_diagnostic.artifact_ids
    {
        return Err(
            "Nightshift query differs from the one enrolled filesystem diagnostic basis".into(),
        );
    }
    for (k, v) in [
        ("cycle", &q.observation_cycle_id),
        ("nonce", &q.request_nonce),
        ("observation", &q.observation_id),
    ] {
        require_token(k, v)?;
    }
    Ok(())
}

/// Read-only current support. Missing custody stays Unknown; no source is acquired here.
pub fn resolve(
    config: &FilesystemSupportConfigV1,
    q: &PresentEvidenceQueryV1,
) -> Result<QualifiedSupportV1, String> {
    config.validate_running()?;
    validate_filesystem_query(config, q)?;
    let now = LinuxBootClock.now()?;
    let path = config.receipt_directory.join("current-receipt.json");
    let receipt: Option<FilesystemReceiptV1> = match fs::symlink_metadata(&path) {
        Ok(_) => {
            let x = read_canonical(&path)?;
            verify_receipt(config, &x, false)?;
            Some(x)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.to_string()),
    };
    let basis_matches = receipt.as_ref().is_none_or(|r| {
        r.envelope.evidence.diagnostic_inputs_id == q.diagnostic_inputs_id
            && r.envelope.evidence.artifact_ids == q.artifact_ids
    });
    let standing = if basis_matches {
        standing_at(
            receipt.as_ref(),
            &now,
            config.expected_diagnostic.expected_state,
        )
    } else {
        QualifiedStandingV1::Unsupported
    };
    let mut out = QualifiedSupportV1 {
        schema: QUALIFIED_SUPPORT_SCHEMA.into(),
        support_id: String::new(),
        authority_id: config.authority_id.clone(),
        query_id: q.query_id.clone(),
        observation_cycle_id: q.observation_cycle_id.clone(),
        request_nonce: q.request_nonce.clone(),
        observation_id: q.observation_id.clone(),
        diagnostic_inputs_id: q.diagnostic_inputs_id.clone(),
        subject_id: q.subject_id.clone(),
        scope_id: q.scope_id.clone(),
        artifact_ids: q.artifact_ids.clone(),
        evaluated_at: SupportInstantV1 {
            clock_id: now.clock_id.clone(),
            tick: now.tick_ms,
        },
        expiry: None,
        standing,
        evidence_refs: vec![],
        contradiction_refs: vec![],
    };
    if let Some(x) = receipt {
        if x.received_at.clock_id == now.clock_id {
            out.expiry = Some(SupportExpiryV1 {
                clock_id: now.clock_id,
                tick: x.expiry_tick_ms.saturating_sub(CLOCK_MARGIN_MS),
            });
        }
        if standing == QualifiedStandingV1::Contradictory {
            out.contradiction_refs.push(x.envelope.evidence.evidence_id);
        } else if standing == QualifiedStandingV1::Current
            || standing == QualifiedStandingV1::Expired
        {
            out.evidence_refs.push(x.envelope.evidence.evidence_id);
        }
    }
    out.support_id = object_id(&out, "support_id")?;
    Ok(out)
}

fn read_canonical<T: serde::de::DeserializeOwned + Serialize>(path: &Path) -> Result<T, String> {
    let b = read_regular_bounded(path, MAX_BYTES)?;
    let x = serde_json::from_slice(&b).map_err(|e| e.to_string())?;
    if canonical_bytes(&x)? != b {
        return Err("filesystem custody must be exact canonical JSON".into());
    }
    Ok(x)
}
fn replace_latest(directory: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    let m = fs::symlink_metadata(directory).map_err(|e| e.to_string())?;
    if !m.is_dir() || m.file_type().is_symlink() || m.mode() & 0o7777 != 0o2750 {
        return Err("filesystem publication requires an existing non-symlink 02750 writer-owned setgid reader directory".into());
    }
    let next = directory.join(format!(".{name}.next-{}", std::process::id()));
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&next)
        .map_err(|e| e.to_string())?;
    f.write_all(bytes).map_err(|e| e.to_string())?;
    // The directory's setgid group is the separately enrolled next reader.
    // Establish the final reader mode on this new inode before it is current.
    let created = f.metadata().map_err(|e| e.to_string())?;
    if created.uid() != m.uid() || created.gid() != m.gid() {
        return Err("filesystem publication writer/group differs from directory custody".into());
    }
    f.set_permissions(fs::Permissions::from_mode(0o640))
        .map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    if f.metadata().map_err(|e| e.to_string())?.mode() & 0o7777 != 0o640 {
        return Err("filesystem reader handoff mode was not established".into());
    }
    fs::rename(next, directory.join(name)).map_err(|e| e.to_string())?;
    fs::File::open(directory)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
