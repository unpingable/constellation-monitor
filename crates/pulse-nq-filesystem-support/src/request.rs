//! Per-invocation diagnostic context, never operator enrollment or NQ admission.
use super::*;
use pulse_nq_load_correspondence::{NqDetectorStateV1, QuestionV1, classify_outcome_for};
use pulse_nq_load_support::ExpectedDiagnosticV1;
use serde_json::Value;

/// A bounded canonical request decoded once by each role. Fields are private:
/// callers cannot substitute an arbitrary expected boolean for the diagnostic.
#[derive(Clone, Debug)]
pub struct FilesystemRequestContext {
    pub(crate) expected: ExpectedDiagnosticV1,
    pub(crate) observation_id: String,
    enrollment_id: String,
}
impl FilesystemRequestContext {
    pub fn from_path(config: &FilesystemSupportConfigV1, path: &Path) -> Result<Self, String> {
        if !path.is_absolute() {
            return Err("absolute per-invocation canonical request required".into());
        }
        Self::from_bytes(config, &read_regular_bounded(path, 2 * 1024 * 1024)?)
    }

    /// Verify just this adapter's closed diagnostic binding. Nightshift retains
    /// full request/policy/recurrence validation and native diagnostic admission.
    pub fn from_bytes(config: &FilesystemSupportConfigV1, bytes: &[u8]) -> Result<Self, String> {
        config.validate()?;
        if bytes.len() > 2 * 1024 * 1024 {
            return Err("canonical request exceeds byte bound".into());
        }
        let request: Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if canonical_bytes(&request)? != bytes
            || request["schema"] != "nightshift.canonical_cycle_request.v1"
            || request["request_id"].as_str() != Some(object_id(&request, "request_id")?.as_str())
        {
            return Err("exact canonical Nightshift request/preimage required".into());
        }
        let inputs = &request["inputs"];
        if inputs["schema"] != "nightshift.diagnostic_inputs.v2"
            || inputs["inputs_id"].as_str() != Some(object_id(inputs, "inputs_id")?.as_str())
        {
            return Err("exact native diagnostic inputs v2/preimage required".into());
        }
        let rows = inputs["inputs"]
            .as_array()
            .ok_or("missing diagnostic inputs")?;
        let [input] = rows.as_slice() else {
            return Err("one native filesystem input required".into());
        };
        let artifact = &input["artifact"];
        let question = QuestionV1::HostFilesystemCapacityPressureV1;
        if input["status"] != "delivered"
            || artifact["schema"] != "nq.diagnostic_execution.v2"
            || artifact["question"]
                != serde_json::to_value(question.question_identity()).map_err(|e| e.to_string())?
            || artifact["profile"]
                != serde_json::to_value(question.nq_profile_identity())
                    .map_err(|e| e.to_string())?
            || artifact["profile_semantic_id"] != config.profile_semantic_id
            || artifact["subject"]["id"] != config.subject_id
            || artifact["subject"]["scope"]["digest"] != config.scope_id
            || request["policy"]["subject"] != artifact["subject"]
            || artifact["artifact_id"].as_str() != Some(native_artifact_id(artifact)?.as_str())
        {
            return Err(
                "request differs from exact enrolled filesystem diagnostic/profile/subject/scope"
                    .into(),
            );
        }
        let expected_state =
            match classify_outcome_for(artifact, question, Some(question.spec().claim_id))
                .map_err(|e| e.to_string())?
            {
                NqDetectorStateV1::Present => LoadPressureStateV1::Present,
                NqDetectorStateV1::ExplicitlyAbsent => LoadPressureStateV1::ExplicitlyAbsent,
                _ => {
                    return Err(
                        "unresolved diagnostic cannot request positive filesystem support".into(),
                    );
                }
            };
        let text = |v: &Value| {
            v.as_str()
                .map(str::to_owned)
                .ok_or_else(|| "missing exact request binding string".to_owned())
        };
        let result = Self {
            expected: ExpectedDiagnosticV1 {
                diagnostic_inputs_id: text(&inputs["inputs_id"])?,
                artifact_ids: vec![text(&artifact["artifact_id"])?],
                expected_state,
            },
            observation_id: text(&request["observation_id"])?,
            enrollment_id: config.enrollment_id()?,
        };
        result.validate_for(config)?;
        Ok(result)
    }
    pub(crate) fn validate_for(&self, config: &FilesystemSupportConfigV1) -> Result<(), String> {
        if self.enrollment_id != config.enrollment_id()? {
            return Err("request context belongs to another static enrollment".into());
        }
        require_digest("observation_id", &self.observation_id)?;
        require_digest("diagnostic_inputs_id", &self.expected.diagnostic_inputs_id)?;
        strictly_ordered_digests("artifact_ids", &self.expected.artifact_ids)?;
        if self.expected.artifact_ids.len() != 1 {
            return Err("one filesystem diagnostic only".into());
        }
        Ok(())
    }
}

// NQ owns the canonicalization of its diagnostic artifact preimage.
pub(crate) fn native_artifact_id(artifact: &Value) -> Result<String, String> {
    let mut preimage = artifact.clone();
    preimage
        .as_object_mut()
        .ok_or("diagnostic artifact must be an object")?
        .remove("artifact_id");
    nq_protocol::semantic_digest(&preimage)
        .map(|x| x.into_string())
        .map_err(|e| e.to_string())
}
