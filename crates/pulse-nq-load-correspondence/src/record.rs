//! The canonical correspondence record and its audit verifier.
//!
//! A persisted record is audit evidence. It binds the exact frame wire bytes,
//! NQ artifact, and admission provenance under one content identity. Verifying
//! it establishes that the pairing was well formed; it never restores present
//! support and cannot become a [`crate::VerifiedCorrespondenceV1`].

use pulse_types::PulseFrameV1;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::nq_artifact::verify_artifact_value;
use crate::provenance::verify_provenance_value;
use crate::{
    CorrespondenceError, CorrespondenceProfileV1, NqDetectorStateV1, QuestionV1, acquisition_id,
    canonical_bytes, check_holding_delay_for, check_ingress_fence, evidence_ref, object_id,
    require_digest, verify_frame,
};

pub const MAX_RECORD_BYTES: usize = 256 * 1_024;

pub const RECORD_NONCLAIMS: [&str; 6] = [
    "this record binds one NQ occurrence to one Pulse frame and adds no meaning to either",
    "the judgment is NQ's and the currentness is Pulse's; neither is health",
    "the frame carries no domain value or assessment",
    "the boot binding is a co-production claim within one process lifetime; NQ does not establish boot generation",
    "a retained record is historical and never restores present support",
    "this record grants no authority",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PulseSideV1 {
    pub evidence_ref: String,
    /// The exact v1 wire encoding, hex encoded so 64-bit frame fields never
    /// enter JSON number space.
    pub frame_wire_hex: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NqSideV1 {
    pub artifact: Value,
    pub admission_provenance: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryV1 {
    pub transport_path: String,
    pub holding_delay_ms: u64,
    pub ingress_fence_ms: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorrespondenceRecordV1 {
    pub schema: String,
    pub correspondence_id: String,
    pub profile_digest: String,
    pub acquisition_id: String,
    pub pulse: PulseSideV1,
    pub nq: NqSideV1,
    pub nq_detector_state: NqDetectorStateV1,
    pub delivery: DeliveryV1,
    pub nonclaims: Vec<String>,
    pub mutation_authority: String,
}

impl CorrespondenceRecordV1 {
    pub(crate) fn seal(mut self, question: QuestionV1) -> Result<Self, CorrespondenceError> {
        question.spec().record_schema.clone_into(&mut self.schema);
        self.nonclaims = RECORD_NONCLAIMS
            .iter()
            .map(|text| (*text).to_owned())
            .collect();
        "none".clone_into(&mut self.mutation_authority);
        self.correspondence_id = String::new();
        self.correspondence_id = self.compute_id()?;
        Ok(self)
    }

    pub fn compute_id(&self) -> Result<String, CorrespondenceError> {
        object_id(self, "correspondence_id")
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CorrespondenceError> {
        let bytes = canonical_bytes(self)?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(CorrespondenceError::new(
                "bound_exceeded",
                "correspondence record exceeds its byte bound",
            ));
        }
        Ok(bytes)
    }

    /// The question this record names through its schema. Crate-private:
    /// a record's schema is compared with a profile's question, never used
    /// to choose one.
    pub(crate) fn question(&self) -> Result<QuestionV1, CorrespondenceError> {
        QuestionV1::from_record_schema(&self.schema).ok_or_else(|| {
            CorrespondenceError::new(
                "unsupported_schema",
                "correspondence record schema is unsupported",
            )
        })
    }

    /// V1: bound, closed fields, a schema of the closed question table,
    /// canonical bytes, identity. Decoding is not verification: a decoded
    /// record has not been checked against any profile and may name any
    /// question of the table.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, CorrespondenceError> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(CorrespondenceError::new(
                "bound_exceeded",
                "correspondence record exceeds its byte bound",
            ));
        }
        let record: Self = serde_json::from_slice(bytes)
            .map_err(|error| CorrespondenceError::new("record_decode", error.to_string()))?;
        record.question()?;
        if canonical_bytes(&record)? != bytes {
            return Err(CorrespondenceError::new(
                "record_noncanonical",
                "correspondence record bytes are not canonical JSON",
            ));
        }
        require_digest("correspondence_id", &record.correspondence_id)?;
        if record.compute_id()? != record.correspondence_id {
            return Err(CorrespondenceError::new(
                "record_identity_mismatch",
                "correspondence_id does not match the canonical record",
            ));
        }
        if record.mutation_authority != "none"
            || record.nonclaims != RECORD_NONCLAIMS.map(str::to_owned)
        {
            return Err(CorrespondenceError::new(
                "authority_boundary",
                "record nonclaims or authority statement changed",
            ));
        }
        Ok(record)
    }

    pub fn frame(&self) -> Result<PulseFrameV1, CorrespondenceError> {
        let bytes = decode_hex(&self.pulse.frame_wire_hex)?;
        PulseFrameV1::decode_wire(&bytes)
            .map_err(|error| CorrespondenceError::new("invalid_frame", error.to_string()))
    }
}

/// The result of verifying an audit record. It is a verification report, not
/// reliance input: it carries no clock anchor and cannot be admitted for
/// projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditVerdictV1 {
    pub correspondence_id: String,
    pub acquisition_id: String,
    pub evidence_ref: String,
    pub artifact_id: String,
    pub nq_detector_state: NqDetectorStateV1,
}

/// V1 through V9 over a persisted record. V10 (replay equality) and V11 (live
/// support) exist only at co-production.
pub fn verify_audit_record(
    bytes: &[u8],
    profile: &CorrespondenceProfileV1,
) -> Result<AuditVerdictV1, CorrespondenceError> {
    profile.validate()?;
    let question = profile.question()?;
    let record = CorrespondenceRecordV1::decode_canonical(bytes)?;
    if record.question()? != question {
        return Err(CorrespondenceError::new(
            "record_question_mismatch",
            "record was produced for a different question than the profile names",
        ));
    }
    if record.profile_digest != profile.digest() {
        return Err(CorrespondenceError::new(
            "profile_mismatch",
            "record was produced under a different correspondence profile",
        ));
    }
    let frame = record.frame()?;
    verify_frame(&frame, profile)?;
    if evidence_ref(&frame) != record.pulse.evidence_ref {
        return Err(CorrespondenceError::new(
            "evidence_ref_mismatch",
            "recorded evidence reference does not match the frame",
        ));
    }
    let expected_acquisition = acquisition_id(
        question,
        profile.digest(),
        &profile.nq.instance_id,
        &record.pulse.evidence_ref,
    )?;
    if expected_acquisition != record.acquisition_id {
        return Err(CorrespondenceError::new(
            "acquisition_id_mismatch",
            "acquisition identity was not derived from this frame under this profile",
        ));
    }
    let mut artifact = verify_artifact_value(&record.nq.artifact, profile)?;
    artifact.bytes = canonical_bytes(&record.nq.artifact)?;
    verify_provenance_value(&record.nq.admission_provenance, &artifact, profile)?;
    if artifact.state != record.nq_detector_state {
        return Err(CorrespondenceError::new(
            "state_mismatch",
            "recorded detector state differs from the state recomputed from the artifact",
        ));
    }
    if record.delivery.transport_path != question.spec().transport_path {
        return Err(CorrespondenceError::new(
            "transport_path_mismatch",
            "record names a transport path other than the in-process co-producer",
        ));
    }
    check_holding_delay_for(question, record.delivery.holding_delay_ms)?;
    check_ingress_fence(record.delivery.ingress_fence_ms)?;
    Ok(AuditVerdictV1 {
        correspondence_id: record.correspondence_id,
        acquisition_id: record.acquisition_id,
        evidence_ref: record.pulse.evidence_ref,
        artifact_id: artifact.artifact_id,
        nq_detector_state: artifact.state,
    })
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(value: &str) -> Result<Vec<u8>, CorrespondenceError> {
    if value.len() % 2 != 0
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CorrespondenceError::new(
            "invalid_hex",
            "frame wire hex is not exact lowercase hex",
        ));
    }
    (0..value.len() / 2)
        .map(|index| {
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                .map_err(|error| CorrespondenceError::new("invalid_hex", error.to_string()))
        })
        .collect()
}
