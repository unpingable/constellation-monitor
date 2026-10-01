#![forbid(unsafe_code)]
//! Deliberately co-produced correspondence between one exact NQ
//! local-successor acquisition and one precommitted Pulse frame, for each
//! question in the closed [`QuestionV1`] table (`nq.host.load_pressure/v1`,
//! `nq.host_filesystem_capacity.pressure/v1`, `nq.host_memory.pressure_stall/v1`).
//!
//! This crate owns only the pairing. It seals an empty-signal Pulse frame,
//! derives the NQ acquisition identity from that frame, asks NQ to acquire and
//! evaluate under that identity through one closed port, verifies NQ's exact
//! artifact, replay, and admission provenance, and delivers the same frame to
//! the in-process Pulse reactor with its measured holding delay.
//!
//! It never reads host sources, applies a threshold, assesses a signal,
//! classifies health, issues support, or grants authority. NQ keeps the
//! judgment; Pulse keeps currentness. The persisted record is an audit copy;
//! only the process-local [`VerifiedCorrespondenceV1`] built during
//! co-production may feed a projection.

mod coproducer;
mod custody;
mod deliver;
mod nq_artifact;
mod nq_cli;
mod occurrence;
mod profile;
mod provenance;
mod question;
mod record;
mod verified;

#[cfg(feature = "synthetic-fixtures")]
pub mod fixture;

pub use coproducer::{Coproducer, OccurrenceOutcomeV1, OccurrenceResultV1, occurrence_path};
pub use custody::{read_regular_bounded, sha256_hex_of_file, write_create_new};
pub use deliver::{
    DeliveryMeasurementV1, check_holding_delay, check_holding_delay_for, check_ingress_fence,
    elapsed_ceil_ms, frame_ingress, frame_ingress_for, verify_certificate_binding,
};
pub use nq_artifact::{
    NqDetectorStateV1, OwnerFailureV1, VerifiedNqArtifactV1, classify_outcome,
    classify_outcome_for, verify_artifact,
};
pub use nq_cli::{
    MAX_NQ_OUTPUT_BYTES, NQ_ACQUIRE_TIMEOUT, NQ_READ_TIMEOUT, NqPort, PinnedNqExecutable,
};
pub use occurrence::{
    FixedSubjectIncarnation, ObserverLineage, SealedOccurrenceV1, SubjectIncarnationWitness,
    acquisition_id, build_frame, evidence_ref, verify_frame,
};
pub use profile::*;
pub use provenance::verify_provenance;
pub use question::{QuestionSpecV1, QuestionV1};
pub use record::{
    AuditVerdictV1, CorrespondenceRecordV1, DeliveryV1, MAX_RECORD_BYTES, NqSideV1, PulseSideV1,
    RECORD_NONCLAIMS, verify_audit_record,
};
pub use verified::VerifiedCorrespondenceV1;

/// Closed error carrier. `code` is stable and machine-comparable; `detail` is
/// bounded operator text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorrespondenceError {
    pub code: &'static str,
    pub detail: String,
}

impl CorrespondenceError {
    #[must_use]
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for CorrespondenceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for CorrespondenceError {}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

pub(crate) fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

pub(crate) fn canonical_bytes<T: serde::Serialize>(
    value: &T,
) -> Result<Vec<u8>, CorrespondenceError> {
    let value = serde_json::to_value(value)
        .map_err(|error| CorrespondenceError::new("encode", error.to_string()))?;
    validate_i_json_numbers(&value)?;
    serde_jcs::to_vec(&value).map_err(|error| CorrespondenceError::new("encode", error.to_string()))
}

/// SHA-256 over canonical JSON with one identity field removed. This is the
/// same rule NQ uses for `artifact_id` and `provenance_id`.
pub(crate) fn object_id<T: serde::Serialize>(
    value: &T,
    identity_field: &str,
) -> Result<String, CorrespondenceError> {
    let mut value = serde_json::to_value(value)
        .map_err(|error| CorrespondenceError::new("encode", error.to_string()))?;
    value
        .as_object_mut()
        .ok_or_else(|| CorrespondenceError::new("encode", "identity subject is not an object"))?
        .remove(identity_field);
    Ok(sha256_prefixed(&canonical_bytes(&value)?))
}

fn validate_i_json_numbers(value: &serde_json::Value) -> Result<(), CorrespondenceError> {
    const LIMIT: u64 = 9_007_199_254_740_991;
    match value {
        serde_json::Value::Number(number) => {
            let unsafe_integer = match (number.as_u64(), number.as_i64()) {
                (Some(unsigned), _) => unsigned > LIMIT,
                (None, Some(signed)) => signed.unsigned_abs() > LIMIT,
                (None, None) => false,
            };
            if unsafe_integer {
                return Err(CorrespondenceError::new(
                    "unsafe_integer",
                    format!("{number} exceeds the I-JSON safe integer range"),
                ));
            }
            Ok(())
        }
        serde_json::Value::Array(values) => values.iter().try_for_each(validate_i_json_numbers),
        serde_json::Value::Object(object) => object.values().try_for_each(validate_i_json_numbers),
        _ => Ok(()),
    }
}

pub(crate) fn require_token(name: &str, value: &str) -> Result<(), CorrespondenceError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(CorrespondenceError::new(
            "invalid_token",
            format!("{name} must contain 1..=256 non-control bytes"),
        ));
    }
    Ok(())
}

pub(crate) fn require_digest(name: &str, value: &str) -> Result<(), CorrespondenceError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(CorrespondenceError::new(
            "invalid_digest",
            format!("{name} must use sha256:<64 lowercase hex>"),
        ));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CorrespondenceError::new(
            "invalid_digest",
            format!("{name} must use sha256:<64 lowercase hex>"),
        ));
    }
    Ok(())
}
