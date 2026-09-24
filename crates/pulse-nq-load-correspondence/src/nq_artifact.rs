//! V5/V6: exact NQ v2 artifact verification and the outcome ladder.
//!
//! The artifact is read as canonical JSON, never re-evaluated. The ladder only
//! reverses NQ's own mapping from detector state to outcome fields; it adds no
//! availability, impact, or health meaning.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    CorrespondenceError, CorrespondenceProfileV1, NQ_ARTIFACT_SCHEMA, NQ_REFUSAL_BOUNDARY,
    NQ_REFUSAL_CODE, NQ_REFUSAL_SCHEMA, NQ_SELECTION_RULE_ID, QuestionSpecV1, QuestionV1,
    SemanticIdentityV1, canonical_bytes, object_id, require_digest, require_token,
};

/// NQ's detector outcome, carried unchanged, plus one bucket for every other
/// valid NQ outcome (no response, acquisition failure, input refusal,
/// unsupported, partial). Only the first three arise from an evaluated report.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NqDetectorStateV1 {
    Present,
    ExplicitlyAbsent,
    CannotEvaluate,
    NotEvaluated,
}

impl NqDetectorStateV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::ExplicitlyAbsent => "explicitly_absent",
            Self::CannotEvaluate => "cannot_evaluate",
            Self::NotEvaluated => "not_evaluated",
        }
    }

    /// Whether NQ admitted and evaluated a report for this outcome.
    #[must_use]
    pub const fn is_evaluated(self) -> bool {
        !matches!(self, Self::NotEvaluated)
    }
}

/// The owner's typed reason for a `cannot_evaluate`, copied from the
/// detector refusal's details when NQ carried one. The code is the owning
/// profile's own vocabulary; the owning profile is the question's NQ profile,
/// already pinned by the ladder, never re-read from artifact text. The seam
/// carries this identity in process only and interprets nothing: it is not
/// persisted in the record, never enters a Pulse frame, and never changes the
/// detector state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerFailureV1 {
    /// Helper code exactly as NQ carried it (a token: `[a-z][a-z0-9_]*`).
    pub code: String,
    /// The owner's own retriable statement when NQ carried one.
    pub retriable: Option<bool>,
}

/// Bound on an owner failure code.
const MAX_OWNER_FAILURE_CODE_BYTES: usize = 64;

/// Strictly parse the two optional detail keys of a detector refusal.
/// Anything not exactly a token code with an optional `"true"`/`"false"`
/// retriable is `None`: a malformed detail never becomes a reason.
fn owner_failure(refusal: &Value) -> Option<OwnerFailureV1> {
    let details = refusal
        .get("origin")?
        .get("payload")?
        .get("refusal")?
        .get("details")?;
    let code = details.get("failure_code")?.as_str()?;
    let is_token = !code.is_empty()
        && code.len() <= MAX_OWNER_FAILURE_CODE_BYTES
        && code
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
    if !is_token {
        return None;
    }
    let retriable = match details.get("failure_retriable").and_then(Value::as_str) {
        None => None,
        Some("true") => Some(true),
        Some("false") => Some(false),
        Some(_) => return None,
    };
    Some(OwnerFailureV1 {
        code: code.to_owned(),
        retriable,
    })
}

/// One exact artifact that passed V5 and V6 against a profile.
#[derive(Clone, Debug)]
pub struct VerifiedNqArtifactV1 {
    pub value: Value,
    pub bytes: Vec<u8>,
    pub artifact_id: String,
    pub run_id: String,
    pub provider_intake_id: String,
    /// Raw artifact digest of the single received input, or the digest of
    /// empty bytes when nothing entered custody.
    pub raw_sha256: String,
    pub profile_semantic_id: String,
    pub state: NqDetectorStateV1,
    /// The owner's typed reason, only for a detector `cannot_evaluate` that
    /// carried one.
    pub owner_failure: Option<OwnerFailureV1>,
}

const EMPTY_SHA256: &str =
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// V5 + V6: canonical bytes, recomputed identity, exact pins, single
/// acquisition, and the outcome ladder.
pub fn verify_artifact(
    bytes: &[u8],
    profile: &CorrespondenceProfileV1,
) -> Result<VerifiedNqArtifactV1, CorrespondenceError> {
    if bytes.len() > crate::MAX_NQ_OUTPUT_BYTES {
        return Err(CorrespondenceError::new(
            "bound_exceeded",
            "NQ artifact exceeds its byte bound",
        ));
    }
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| CorrespondenceError::new("artifact_decode", error.to_string()))?;
    if canonical_bytes(&value)? != bytes {
        return Err(CorrespondenceError::new(
            "artifact_noncanonical",
            "NQ artifact bytes are not canonical JSON",
        ));
    }
    verify_artifact_value(&value, profile).map(|mut verified| {
        verified.bytes = bytes.to_vec();
        verified
    })
}

/// Verify an artifact already held as a JSON value (for example, embedded in
/// an audit record). `bytes` is left empty; callers that need it use
/// [`verify_artifact`].
pub(crate) fn verify_artifact_value(
    value: &Value,
    profile: &CorrespondenceProfileV1,
) -> Result<VerifiedNqArtifactV1, CorrespondenceError> {
    let artifact_id = string(value, "artifact_id")?;
    require_digest("artifact_id", artifact_id)?;
    if object_id(value, "artifact_id")? != artifact_id {
        return Err(CorrespondenceError::new(
            "artifact_identity_mismatch",
            "artifact_id does not match the canonical artifact preimage",
        ));
    }
    if string(value, "schema")? != NQ_ARTIFACT_SCHEMA {
        return Err(CorrespondenceError::new(
            "artifact_schema",
            "artifact is not nq.diagnostic_execution.v2",
        ));
    }
    let question = profile.question()?;
    let constants = &profile.constants;
    let nq = &profile.nq;
    require_identity(value, "question", &constants.question)?;
    require_identity(value, "profile", &constants.profile)?;
    require_identity(value, "threshold_policy", &nq.threshold_policy)?;
    require_identity(value, "evaluator", &nq.evaluator)?;
    require_identity(value, "vantage", &nq.vantage)?;
    require_identity(value, "state_model", &nq.state_model)?;
    if string(value, "profile_semantic_id")? != nq.profile_semantic_id {
        return Err(CorrespondenceError::new(
            "artifact_pin_mismatch",
            "profile_semantic_id differs from the enrolled identity",
        ));
    }
    let subject = field(value, "subject")?;
    if string(subject, "id")? != nq.subject_id {
        return Err(CorrespondenceError::new(
            "artifact_pin_mismatch",
            "artifact subject differs from the enrolled subject",
        ));
    }
    require_identity(subject, "scope", &nq.subject_scope)?;
    let producer = field(value, "producer")?;
    if string(producer, "node_id")? != nq.producer.node_id {
        return Err(CorrespondenceError::new(
            "artifact_pin_mismatch",
            "producer node differs from the enrolled NQ node",
        ));
    }
    require_identity(producer, "build", &nq.producer.build)?;
    require_identity(producer, "cohort", &nq.producer.cohort)?;
    let inputs = field(value, "inputs")?;
    let selection_rule = field(inputs, "selection_rule")?;
    if string(selection_rule, "id")? != NQ_SELECTION_RULE_ID {
        return Err(CorrespondenceError::new(
            "artifact_selection_rule",
            "artifact was not produced by the deliberate local-successor selection rule",
        ));
    }
    let run_id = string(value, "run_id")?;
    require_token("run_id", run_id)?;

    let state = classify_outcome_for(value, question, Some(question.spec().claim_id))?;
    let mut owner_failure_value = None;
    if state == NqDetectorStateV1::CannotEvaluate {
        let [refusal] = array(field(value, "outcome")?, "refusals")?.as_slice() else {
            return Err(CorrespondenceError::new(
                "artifact_ladder",
                "cannot-evaluate outcome must carry exactly one detector refusal",
            ));
        };
        let instance = field(field(field(refusal, "origin")?, "payload")?, "refusal")?
            .get("instance_id")
            .and_then(Value::as_str);
        if instance != Some(nq.instance_id.as_str()) {
            return Err(CorrespondenceError::new(
                "artifact_pin_mismatch",
                "detector refusal names a different enrolled NQ instance",
            ));
        }
        owner_failure_value = owner_failure(refusal);
    }
    let (provider_intake_id, raw_sha256) = single_acquisition(inputs, state)?;
    Ok(VerifiedNqArtifactV1 {
        value: value.clone(),
        bytes: Vec::new(),
        artifact_id: artifact_id.to_owned(),
        run_id: run_id.to_owned(),
        provider_intake_id,
        raw_sha256,
        profile_semantic_id: nq.profile_semantic_id.clone(),
        state,
        owner_failure: owner_failure_value,
    })
}

/// The load v1 outcome ladder only: [`classify_outcome_for`] under
/// [`QuestionV1::HostLoadPressureV1`]. Another question's detector refusal
/// does not name `nq.host` and is refused here rather than classified.
pub fn classify_outcome(
    value: &Value,
    expected_claim_id: Option<&str>,
) -> Result<NqDetectorStateV1, CorrespondenceError> {
    classify_outcome_for(value, QuestionV1::HostLoadPressureV1, expected_claim_id)
}

/// The accepted outcome ladder. `expected_claim_id` pins the primary claim
/// for production; `None` classifies an artifact under its own claim id (used
/// only for NQ's cross-repository fixture mirror, whose fixtures predate the
/// production claim identity). A detector refusal must name the question's
/// NQ profile.
pub fn classify_outcome_for(
    value: &Value,
    question: QuestionV1,
    expected_claim_id: Option<&str>,
) -> Result<NqDetectorStateV1, CorrespondenceError> {
    let outcome = field(value, "outcome")?;
    let derivation = string(outcome, "derivation")?;
    let condition = string(outcome, "condition")?;
    let coherence = string(outcome, "coherence")?;
    let coverage = string(outcome, "coverage")?;
    let refusals = array(outcome, "refusals")?;
    let unsupported = array(outcome, "unsupported")?;
    let claims = array(value, "claims")?;
    let primary_claim_id = value.get("primary_claim_id").and_then(Value::as_str);
    let inputs = field(value, "inputs")?;
    let selected = array(inputs, "selected")?;

    let determinate = derivation == "completed"
        && coherence == "jointly_established"
        && coverage == "complete"
        && refusals.is_empty()
        && unsupported.is_empty()
        && matches!(condition, "present" | "explicitly_absent");
    if determinate {
        let Some(primary) = primary_claim_id else {
            return Err(CorrespondenceError::new(
                "artifact_ladder",
                "determinate outcome has no primary claim",
            ));
        };
        if expected_claim_id.is_some_and(|expected| expected != primary) {
            return Err(CorrespondenceError::new(
                "artifact_claim_mismatch",
                "primary claim is not the enrolled claim for the question",
            ));
        }
        let [claim] = claims.as_slice() else {
            return Err(CorrespondenceError::new(
                "artifact_ladder",
                "determinate outcome must export exactly one claim",
            ));
        };
        let [selected_input] = selected.as_slice() else {
            return Err(CorrespondenceError::new(
                "artifact_single_acquisition",
                "determinate outcome must select exactly one input",
            ));
        };
        let selected_id = string(selected_input, "input_id")?;
        if string(claim, "claim_id")? != primary
            || string(claim, "status")? != "established"
            || claim.get("condition_effect").and_then(Value::as_str) != Some(condition)
            || array(claim, "dependency_input_ids")? != &[Value::String(selected_id.to_owned())]
            || !array(claim, "dependency_refusal_ids")?.is_empty()
            || !array(claim, "dependency_failure_ids")?.is_empty()
        {
            return Err(CorrespondenceError::new(
                "artifact_ladder",
                "primary claim does not depend on exactly the single selected input",
            ));
        }
        return Ok(if condition == "present" {
            NqDetectorStateV1::Present
        } else {
            NqDetectorStateV1::ExplicitlyAbsent
        });
    }

    let cannot_evaluate = derivation == "refused"
        && condition == "unresolved"
        && coherence == "not_evaluated"
        && coverage == "partial"
        && claims.is_empty()
        && primary_claim_id.is_none()
        && unsupported.is_empty()
        && refusals.len() == 1
        && selected.len() == 1
        && is_detector_cannot_evaluate(&refusals[0], question.spec());
    if cannot_evaluate {
        return Ok(NqDetectorStateV1::CannotEvaluate);
    }
    // A detector cannot_evaluate refusal that names another NQ profile is
    // another question's judgment, never this question's undetermined
    // outcome.
    if refusals
        .iter()
        .any(|refusal| is_foreign_detector_refusal(refusal, question.spec()))
    {
        return Err(CorrespondenceError::new(
            "artifact_ladder",
            "detector refusal names an NQ profile other than the question's",
        ));
    }

    // Any other NQ outcome in which no determinate condition was derived:
    // provider no response, acquisition failure, received-input refusal,
    // unsupported, or partial derivation. A determinate condition that failed
    // the strict ladder above is an unexpected shape and is refused, never
    // downgraded.
    if !matches!(derivation, "partial" | "refused" | "unsupported")
        || !matches!(condition, "unresolved" | "not_applicable")
    {
        return Err(CorrespondenceError::new(
            "artifact_ladder",
            "outcome is neither an exact determinate result, an exact detector refusal, nor an undetermined NQ outcome",
        ));
    }
    Ok(NqDetectorStateV1::NotEvaluated)
}

/// A profile-origin detector `cannot_evaluate` refusal whose profile is not
/// the question's.
fn is_foreign_detector_refusal(refusal: &Value, spec: &QuestionSpecV1) -> bool {
    let Ok(origin) = field(refusal, "origin") else {
        return false;
    };
    let profile_refusal = origin
        .get("payload")
        .and_then(|payload| payload.get("refusal"));
    let profile = profile_refusal.and_then(|refusal| refusal.get("profile"));
    let named = (
        profile
            .and_then(|profile| profile.get("id"))
            .and_then(Value::as_str),
        profile
            .and_then(|profile| profile.get("version"))
            .and_then(Value::as_u64),
    );
    origin.get("kind").and_then(Value::as_str) == Some("profile")
        && profile_refusal
            .and_then(|refusal| refusal.get("boundary"))
            .and_then(Value::as_str)
            == Some(NQ_REFUSAL_BOUNDARY)
        && profile_refusal
            .and_then(|refusal| refusal.get("code"))
            .and_then(Value::as_str)
            == Some(NQ_REFUSAL_CODE)
        && named.0.is_some()
        && named != (Some(spec.nq_profile_id), Some(spec.refusal_profile_version))
}

fn is_detector_cannot_evaluate(refusal: &Value, spec: &QuestionSpecV1) -> bool {
    let Ok(origin) = field(refusal, "origin") else {
        return false;
    };
    let payload = origin.get("payload");
    let profile_refusal = payload.and_then(|payload| payload.get("refusal"));
    let profile = profile_refusal.and_then(|refusal| refusal.get("profile"));
    refusal.get("schema").and_then(Value::as_str) == Some(NQ_REFUSAL_SCHEMA)
        && origin.get("kind").and_then(Value::as_str) == Some("profile")
        && profile_refusal
            .and_then(|refusal| refusal.get("boundary"))
            .and_then(Value::as_str)
            == Some(NQ_REFUSAL_BOUNDARY)
        && profile_refusal
            .and_then(|refusal| refusal.get("code"))
            .and_then(Value::as_str)
            == Some(NQ_REFUSAL_CODE)
        && profile
            .and_then(|profile| profile.get("id"))
            .and_then(Value::as_str)
            == Some(spec.nq_profile_id)
        && profile
            .and_then(|profile| profile.get("version"))
            .and_then(Value::as_u64)
            == Some(spec.refusal_profile_version)
}

/// V6: exactly one provider-intake occurrence, and for evaluated outcomes the
/// single selected input is an exact-source received input.
fn single_acquisition(
    inputs: &Value,
    state: NqDetectorStateV1,
) -> Result<(String, String), CorrespondenceError> {
    let received = array(inputs, "received")?;
    let failed = array(inputs, "failed")?;
    let selected = array(inputs, "selected")?;
    if state.is_evaluated() {
        let [selected_input] = selected.as_slice() else {
            return Err(CorrespondenceError::new(
                "artifact_single_acquisition",
                "evaluated outcome must select exactly one input",
            ));
        };
        let selected_id = string(selected_input, "input_id")?;
        if selected
            .iter()
            .any(|input| string(input, "role").is_ok_and(|role| role.is_empty()))
        {
            return Err(CorrespondenceError::new(
                "artifact_single_acquisition",
                "selected input role is empty",
            ));
        }
        let [received_input] = received.as_slice() else {
            return Err(CorrespondenceError::new(
                "artifact_single_acquisition",
                "evaluated outcome must have exactly one received input",
            ));
        };
        if string(received_input, "input_id")? != selected_id
            || string(received_input, "capture_mode")? != "exact_source"
        {
            return Err(CorrespondenceError::new(
                "artifact_single_acquisition",
                "the selected input is not the single exact-source received input",
            ));
        }
        if !failed.is_empty() {
            return Err(CorrespondenceError::new(
                "artifact_single_acquisition",
                "evaluated outcome cannot also carry failed inputs",
            ));
        }
        let intake = string(received_input, "provider_intake_id")?;
        let raw = string(received_input, "raw_artifact_id")?;
        require_token("provider_intake_id", intake)?;
        require_digest("raw_artifact_id", raw)?;
        return Ok((intake.to_owned(), raw.to_owned()));
    }
    // Not evaluated: exactly one provider-intake occurrence, received or failed.
    let mut intakes = Vec::new();
    for input in received {
        intakes.push((
            string(input, "provider_intake_id")?.to_owned(),
            string(input, "raw_artifact_id")?.to_owned(),
        ));
    }
    for input in failed {
        let cause = field(input, "cause")?;
        if let Some(intake) = cause.get("provider_intake_id").and_then(Value::as_str) {
            intakes.push((intake.to_owned(), EMPTY_SHA256.to_owned()));
        }
    }
    match intakes.as_slice() {
        [(intake, raw)] => {
            require_token("provider_intake_id", intake)?;
            require_digest("raw_artifact_id", raw)?;
            Ok((intake.clone(), raw.clone()))
        }
        _ => Err(CorrespondenceError::new(
            "artifact_single_acquisition",
            "artifact does not record exactly one provider-intake occurrence",
        )),
    }
}

fn require_identity(
    parent: &Value,
    name: &str,
    expected: &SemanticIdentityV1,
) -> Result<(), CorrespondenceError> {
    let actual = field(parent, name)?;
    let matches = string(actual, "id")? == expected.id
        && string(actual, "version")? == expected.version
        && string(actual, "digest")? == expected.digest;
    if !matches {
        return Err(CorrespondenceError::new(
            "artifact_pin_mismatch",
            format!("{name} differs from the enrolled identity"),
        ));
    }
    Ok(())
}

pub(crate) fn field<'a>(parent: &'a Value, name: &str) -> Result<&'a Value, CorrespondenceError> {
    parent
        .get(name)
        .ok_or_else(|| CorrespondenceError::new("artifact_shape", format!("missing field {name}")))
}

pub(crate) fn string<'a>(parent: &'a Value, name: &str) -> Result<&'a str, CorrespondenceError> {
    field(parent, name)?.as_str().ok_or_else(|| {
        CorrespondenceError::new("artifact_shape", format!("field {name} is not a string"))
    })
}

pub(crate) fn array<'a>(
    parent: &'a Value,
    name: &str,
) -> Result<&'a Vec<Value>, CorrespondenceError> {
    field(parent, name)?.as_array().ok_or_else(|| {
        CorrespondenceError::new("artifact_shape", format!("field {name} is not an array"))
    })
}
