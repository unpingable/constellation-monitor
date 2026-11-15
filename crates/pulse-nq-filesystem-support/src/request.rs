//! Per-invocation diagnostic context, never operator enrollment or NQ admission.
use super::*;
use pulse_nq_load_correspondence::{NqDetectorStateV1, QuestionV1, classify_outcome_for};
use serde_json::Value;

/// A bounded canonical request decoded once by each role. Fields are private:
/// callers cannot substitute an arbitrary expected boolean for the diagnostic.
#[derive(Clone, Debug)]
pub struct FilesystemRequestContext {
    pub(crate) expected: FilesystemDiagnosticBasis,
    pub(crate) observation_id: String,
    enrollment_id: String,
}
#[derive(Clone, Debug)]
pub(crate) struct FilesystemDiagnosticBasis {
    pub(crate) diagnostic_inputs_id: String,
    pub(crate) artifact_ids: Vec<String>,
    pub(crate) expected_state: Option<LoadPressureStateV1>,
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
        let question = QuestionV1::HostFilesystemCapacityPressureV1;
        let expected_key = serde_json::json!({"question_id":question.spec().question_id,"profile_id":question.spec().nq_profile_id,"subject_id":config.subject_id,"vantage_id":config.diagnostic_vantage_id});
        if input["key"] != expected_key
            || request["policy"]["subject"]["id"] != config.subject_id
            || request["policy"]["subject"]["scope"]["digest"] != config.scope_id
        {
            return Err(
                "request differs from the statically enrolled diagnostic key/subject/scope".into(),
            );
        }
        let inventory = request["policy"]["inventory"]
            .as_array()
            .ok_or("missing enrolled diagnostic inventory")?;
        let bindings:Vec<_>=inventory.iter().filter_map(|entry| {
            let b=&entry["binding"];
            let key=serde_json::json!({"question_id":b["question"]["id"],"profile_id":b["profile"]["id"],"subject_id":b["subject"]["id"],"vantage_id":b["vantage"]["id"]});
            (key==expected_key).then_some(b)
        }).collect();
        let [binding] = bindings.as_slice() else {
            return Err("one fixed enrolled native diagnostic binding required".into());
        };
        if binding["question"]
            != serde_json::to_value(question.question_identity()).map_err(|e| e.to_string())?
            || binding["profile"]
                != serde_json::to_value(question.nq_profile_identity())
                    .map_err(|e| e.to_string())?
            || binding["profile_semantic_id"] != config.profile_semantic_id
            || binding["subject"] != request["policy"]["subject"]
            || binding["claim_id"] != question.spec().claim_id
        {
            return Err(
                "policy inventory differs from enrolled native meaning/subject/scope".into(),
            );
        }
        let object = input
            .as_object()
            .ok_or("diagnostic input must be an object")?;
        let (expected_state, artifact_ids) = match input["status"].as_str() {
            Some("no_response") if object.len() == 2 => (None, vec![]),
            Some("acquisition_failed") if object.len() == 3 && object.contains_key("reason") => {
                let reason = input["reason"]
                    .as_str()
                    .ok_or("acquisition failure reason must be a string")?;
                if reason.is_empty() || reason.len() > 256 || reason.chars().any(char::is_control) {
                    return Err("malformed acquisition failure reason".into());
                }
                (None, vec![])
            }
            Some("delivered") if object.len() == 3 && object.contains_key("artifact") => {
                let artifact = &input["artifact"];
                if artifact["schema"] != "nq.diagnostic_execution.v2"
                    || artifact["question"] != binding["question"]
                    || artifact["profile"] != binding["profile"]
                    || artifact["profile_semantic_id"] != config.profile_semantic_id
                    || artifact["subject"] != binding["subject"]
                    || artifact["vantage"] != binding["vantage"]
                    || artifact["artifact_id"].as_str()
                        != Some(native_artifact_id(artifact)?.as_str())
                {
                    return Err("delivered artifact differs from enrolled native diagnostic binding/preimage".into());
                }
                let state =
                    match classify_outcome_for(artifact, question, Some(question.spec().claim_id))
                        .map_err(|e| e.to_string())?
                    {
                        NqDetectorStateV1::Present => Some(LoadPressureStateV1::Present),
                        NqDetectorStateV1::ExplicitlyAbsent => {
                            Some(LoadPressureStateV1::ExplicitlyAbsent)
                        }
                        NqDetectorStateV1::CannotEvaluate => None,
                        NqDetectorStateV1::NotEvaluated
                            if artifact.get("primary_claim_id").is_none_or(Value::is_null)
                                && artifact["claims"].as_array().is_some_and(Vec::is_empty) =>
                        {
                            None
                        }
                        _ => return Err("malformed indeterminate native diagnostic".into()),
                    };
                let id = artifact["artifact_id"]
                    .as_str()
                    .ok_or("missing delivered artifact ID")?
                    .to_owned();
                (state, vec![id])
            }
            _ => return Err("unsupported or malformed native diagnostic input status".into()),
        };
        let text = |v: &Value| {
            v.as_str()
                .map(str::to_owned)
                .ok_or_else(|| "missing exact request binding string".to_owned())
        };
        let result = Self {
            expected: FilesystemDiagnosticBasis {
                diagnostic_inputs_id: text(&inputs["inputs_id"])?,
                artifact_ids,
                expected_state,
            },
            observation_id: text(&request["observation_id"])?,
            enrollment_id: config.enrollment_id()?,
        };
        result.validate_for(config)?;
        Ok(result)
    }
    pub(crate) fn require_delivered(&self) -> Result<(), String> {
        if self.expected.expected_state.is_none() {
            return Err("no eligible delivered diagnostic for native acquisition/intake".into());
        }
        Ok(())
    }
    pub(crate) fn validate_for(&self, config: &FilesystemSupportConfigV1) -> Result<(), String> {
        if self.enrollment_id != config.enrollment_id()? {
            return Err("request context belongs to another static enrollment".into());
        }
        require_digest("observation_id", &self.observation_id)?;
        require_digest("diagnostic_inputs_id", &self.expected.diagnostic_inputs_id)?;
        if !self.expected.artifact_ids.is_empty() {
            strictly_ordered_digests("artifact_ids", &self.expected.artifact_ids)?;
        }
        if self.expected.artifact_ids.len() > 1
            || (self.expected.expected_state.is_some() && self.expected.artifact_ids.len() != 1)
        {
            return Err("one filesystem diagnostic or exact artifactless negative only".into());
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
