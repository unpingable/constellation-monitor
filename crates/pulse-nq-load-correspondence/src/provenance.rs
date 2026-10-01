//! V7: NQ admission provenance verification.
//!
//! `nq diagnostics qualify` reopens the local store history and emits
//! `nq.diagnostic_admission_provenance.v1`. The correspondence requires that
//! carrier to bind the exact artifact bytes, run, provider intake, raw digest,
//! profile semantics, and disposition consistent with the artifact's state.

use serde_json::Value;

use crate::nq_artifact::{field, string};
use crate::{
    CorrespondenceError, CorrespondenceProfileV1, NQ_ARTIFACT_SCHEMA, NQ_JUDGMENT_SCHEMA,
    NQ_PROVENANCE_SCHEMA, NQ_SOURCE_KIND, NqDetectorStateV1, VerifiedNqArtifactV1, object_id,
    require_digest, sha256_prefixed,
};

/// Parse and verify provenance bytes against one verified artifact. The
/// returned value is the parsed provenance (NQ's `--json` output is not
/// canonical; the audit record re-canonicalizes it).
pub fn verify_provenance(
    bytes: &[u8],
    artifact: &VerifiedNqArtifactV1,
    profile: &CorrespondenceProfileV1,
) -> Result<Value, CorrespondenceError> {
    if bytes.len() > crate::MAX_NQ_OUTPUT_BYTES {
        return Err(CorrespondenceError::new(
            "bound_exceeded",
            "NQ provenance exceeds its byte bound",
        ));
    }
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| CorrespondenceError::new("provenance_decode", error.to_string()))?;
    verify_provenance_value(&value, artifact, profile)?;
    Ok(value)
}

pub(crate) fn verify_provenance_value(
    value: &Value,
    artifact: &VerifiedNqArtifactV1,
    profile: &CorrespondenceProfileV1,
) -> Result<(), CorrespondenceError> {
    let mismatch = |detail: &str| CorrespondenceError::new("provenance_mismatch", detail);
    if string(value, "schema")? != NQ_PROVENANCE_SCHEMA {
        return Err(CorrespondenceError::new(
            "provenance_schema",
            "provenance is not nq.diagnostic_admission_provenance.v1",
        ));
    }
    let provenance_id = string(value, "provenance_id")?;
    require_digest("provenance_id", provenance_id)?;
    if object_id(value, "provenance_id")? != provenance_id {
        return Err(CorrespondenceError::new(
            "provenance_identity_mismatch",
            "provenance_id does not match the canonical provenance preimage",
        ));
    }
    let source = field(value, "source")?;
    if string(source, "kind")? != NQ_SOURCE_KIND
        || string(source, "source_id")? != profile.nq.producer.node_id
    {
        return Err(mismatch(
            "provenance source is not the enrolled local NQ store",
        ));
    }
    let bound = field(value, "artifact")?;
    if artifact.bytes.is_empty() {
        return Err(CorrespondenceError::new(
            "artifact_bytes_missing",
            "provenance verification requires the exact artifact bytes",
        ));
    }
    let length = u64::try_from(artifact.bytes.len())
        .map_err(|error| CorrespondenceError::new("bound", error.to_string()))?;
    if string(bound, "artifact_id")? != artifact.artifact_id
        || string(bound, "contract_schema")? != NQ_ARTIFACT_SCHEMA
        || string(bound, "canonical_bytes_sha256")? != sha256_prefixed(&artifact.bytes)
        || field(bound, "canonical_bytes_length")?.as_u64() != Some(length)
    {
        return Err(mismatch(
            "provenance does not bind the exact artifact identity and bytes",
        ));
    }
    let origin = field(value, "origin")?;
    if string(origin, "run_id")? != artifact.run_id {
        return Err(mismatch("provenance run differs from the artifact run"));
    }
    let provider = field(value, "provider")?;
    if string(provider, "provider_intake_id")? != artifact.provider_intake_id
        || string(provider, "raw_sha256")? != artifact.raw_sha256
        || string(provider, "profile_semantic_id")? != artifact.profile_semantic_id
    {
        return Err(mismatch(
            "provenance provider intake, raw digest, or profile semantics differ from the artifact",
        ));
    }
    let disposition = string(value, "disposition")?;
    let evaluation_id = origin.get("evaluation_id").and_then(Value::as_str);
    let judgment = value.get("judgment").filter(|judgment| !judgment.is_null());
    match artifact.state {
        NqDetectorStateV1::Present
        | NqDetectorStateV1::ExplicitlyAbsent
        | NqDetectorStateV1::CannotEvaluate => {
            let Some(judgment) = judgment else {
                return Err(mismatch(
                    "evaluated outcome requires an admitted-report judgment",
                ));
            };
            if disposition != "admitted_report"
                || evaluation_id.is_none_or(str::is_empty)
                || string(judgment, "report_id")?.is_empty()
                || string(judgment, "judgment_schema")? != NQ_JUDGMENT_SCHEMA
            {
                return Err(mismatch(
                    "evaluated outcome requires admitted_report disposition, evaluation, and judgment",
                ));
            }
            require_digest("judgment_digest", string(judgment, "judgment_digest")?)?;
        }
        NqDetectorStateV1::NotEvaluated => {
            if !matches!(disposition, "governed_refusal" | "acquisition_failure")
                || evaluation_id.is_some()
                || judgment.is_some()
            {
                return Err(mismatch(
                    "non-evaluated outcome cannot carry an admitted-report disposition or judgment",
                ));
            }
        }
    }
    Ok(())
}
