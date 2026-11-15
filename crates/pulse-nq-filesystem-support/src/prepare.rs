//! Deployment binding for the existing canonical request, not NQ admission.
use super::*;
use pulse_nq_load_correspondence::{NqDetectorStateV1, QuestionV1, classify_outcome_for};
use serde_json::Value;

/// Prepare one exact filesystem support configuration from the ordinary
/// Nightshift request and the operator's real NQ watcher declaration.
/// Nightshift still owns native admission qualification of the diagnostic.
pub fn prepare(
    request_path: &Path,
    nq_config: &Path,
    instance: &str,
    state: &Path,
    realization_path: &Path,
) -> Result<String, String> {
    if !request_path.is_absolute()
        || !nq_config.is_absolute()
        || !state.is_absolute()
        || !realization_path.is_absolute()
    {
        return Err("absolute request/NQ configuration/support state paths required".into());
    }
    if realization_path.starts_with(state) {
        return Err("accepted realization must be outside producer/receiver support state".into());
    }
    let realization: AdapterRealizationV1 =
        serde_json::from_slice(&read_regular_bounded(realization_path, MAX_BYTES)?)
            .map_err(|e| e.to_string())?;
    realization.validate_current_process()?;
    let request: Value =
        serde_json::from_slice(&read_regular_bounded(request_path, 2 * 1024 * 1024)?)
            .map_err(|e| e.to_string())?;
    if request["schema"] != "nightshift.canonical_cycle_request.v1" {
        return Err("not a canonical Nightshift cycle request".into());
    }
    let inputs = request
        .pointer("/inputs/inputs")
        .and_then(Value::as_array)
        .ok_or("missing diagnostic inputs")?;
    let [input] = inputs.as_slice() else {
        return Err("one native filesystem input required".into());
    };
    let artifact = input
        .get("artifact")
        .ok_or("missing native diagnostic artifact")?;
    let question = QuestionV1::HostFilesystemCapacityPressureV1;
    if artifact["schema"] != "nq.diagnostic_execution.v2"
        || artifact["question"]
            != serde_json::to_value(question.question_identity()).map_err(|e| e.to_string())?
        || artifact["profile"]
            != serde_json::to_value(question.nq_profile_identity()).map_err(|e| e.to_string())?
    {
        return Err("only the exact native filesystem-capacity diagnostic is supported".into());
    }
    let expected = match classify_outcome_for(artifact, question, Some(question.spec().claim_id))
        .map_err(|e| e.to_string())?
    {
        NqDetectorStateV1::Present => LoadPressureStateV1::Present,
        NqDetectorStateV1::ExplicitlyAbsent => LoadPressureStateV1::ExplicitlyAbsent,
        _ => {
            return Err(
                "an unresolved diagnostic cannot request positive filesystem support".into(),
            );
        }
    };
    let config: Value = toml::from_str(
        std::str::from_utf8(&read_regular_bounded(nq_config, 1024 * 1024)?)
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let watchers = config["watchers"]
        .as_array()
        .ok_or("missing native watcher declaration")?;
    let selected: Vec<_> = watchers
        .iter()
        .filter(|w| w["instance_id"].as_str() == Some(instance))
        .collect();
    let [watcher] = selected.as_slice() else {
        return Err("exactly one selected native watcher required".into());
    };
    if watcher["profile"]["id"] != native::CAPACITY_PROFILE_ID
        || watcher["profile"]["version"] != 1
        || watcher["scope"]["kind"] != native::SCOPE_KIND
        || watcher["subject"] != artifact["subject"]["id"]
    {
        return Err(
            "native watcher does not match the diagnostic filesystem profile/subject".into(),
        );
    }
    let text = |v: &Value| {
        v.as_str()
            .map(str::to_owned)
            .ok_or_else(|| "missing exact binding string".to_owned())
    };
    let scope_id = text(&artifact["subject"]["scope"]["digest"])?;
    let consumer = format!(
        "nightshift:filesystem:{}",
        scope_id
            .strip_prefix("sha256:")
            .ok_or("invalid native scope digest")?
    );
    let key = read_signing_key(&state.join("producer.key"))?;
    let result = FilesystemSupportConfigV1 {
        schema: CONFIG_SCHEMA.into(),
        authority_id: format!("filesystem-support:{consumer}"),
        consumer_id: consumer.clone(),
        producer_id: format!("producer:{consumer}"),
        producer_key_id: format!("key:{consumer}"),
        producer_public_key_hex: encode_hex(key.verifying_key().as_bytes()),
        producer_private_key_path: state.join("producer.key"),
        subject_id: text(&artifact["subject"]["id"])?,
        scope_id,
        scope: serde_json::from_value(watcher["scope"]["value"].clone())
            .map_err(|e| e.to_string())?,
        vantage: serde_json::from_value(watcher["vantage"].clone()).map_err(|e| e.to_string())?,
        profile_semantic_id: text(&artifact["profile_semantic_id"])?,
        realization,
        outgoing_directory: state.join("outgoing"),
        receipt_directory: state.join("receiver"),
        expected_diagnostic: pulse_nq_load_support::ExpectedDiagnosticV1 {
            diagnostic_inputs_id: text(&request["inputs"]["inputs_id"])?,
            artifact_ids: vec![text(&artifact["artifact_id"])?],
            expected_state: expected,
        },
    };
    result.validate()?;
    replace_latest(state, "filesystem-support.json", &canonical_bytes(&result)?)?;
    text(&request["request_id"])
}
