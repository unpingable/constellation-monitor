//! Seal one deployment profile from an initial real NQ diagnostic artifact.
//!
//! This qualification helper copies NQ-owned runtime identities from the
//! artifact, hashes the exact executable and configuration bytes, and writes a
//! create-new canonical profile. It does not acquire evidence or infer an NQ
//! identity from configuration text. `NQ_CORRESPONDENCE_QUESTION` names the
//! question by its NQ question id and must match the artifact exactly.

use std::env;
use std::error::Error;
use std::path::{Path, PathBuf};

use pulse_nq_load_correspondence::{
    CorrespondenceProfileV1, NQ_ARTIFACT_SCHEMA, NqEnrollmentV1, NqProducerV1, PulseEnrollmentV1,
    QuestionV1, SemanticIdentityV1, sha256_hex_of_file, write_create_new,
};
use serde_json::Value;

const MAX_ARTIFACT_BYTES: usize = 2 * 1_024 * 1_024;
const MAX_EXECUTABLE_BYTES: usize = 128 * 1_024 * 1_024;
const MAX_CONFIG_BYTES: usize = 256 * 1_024;

fn required_path(name: &str) -> PathBuf {
    let path = PathBuf::from(env::var_os(name).unwrap_or_else(|| panic!("{name} is required")));
    assert!(path.is_absolute(), "{name} must be absolute");
    path
}

fn required_string(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
}

fn field<'a>(value: &'a Value, pointer: &str) -> &'a Value {
    value
        .pointer(pointer)
        .unwrap_or_else(|| panic!("initial NQ artifact has no {pointer}"))
}

fn identity(value: &Value, pointer: &str) -> SemanticIdentityV1 {
    serde_json::from_value(field(value, pointer).clone())
        .unwrap_or_else(|error| panic!("initial NQ artifact {pointer} is invalid: {error}"))
}

fn string(value: &Value, pointer: &str) -> String {
    field(value, pointer)
        .as_str()
        .unwrap_or_else(|| panic!("initial NQ artifact {pointer} is not a string"))
        .to_owned()
}

fn main() -> Result<(), Box<dyn Error>> {
    let question_id = required_string("NQ_CORRESPONDENCE_QUESTION");
    let question = QuestionV1::ALL
        .into_iter()
        .find(|question| question.spec().question_id == question_id)
        .unwrap_or_else(|| panic!("NQ_CORRESPONDENCE_QUESTION names no question: {question_id}"));
    let artifact_path = required_path("NQ_CORRESPONDENCE_INITIAL_ARTIFACT");
    let executable_path = required_path("NQ_CORRESPONDENCE_NQ_EXECUTABLE");
    let config_path = required_path("NQ_CORRESPONDENCE_NQ_CONFIG");
    let output_path = required_path("NQ_CORRESPONDENCE_PROFILE_OUT");
    let artifact_bytes =
        pulse_nq_load_correspondence::read_regular_bounded(&artifact_path, MAX_ARTIFACT_BYTES)?;
    let artifact: Value = serde_json::from_slice(&artifact_bytes)?;

    assert_eq!(
        string(&artifact, "/schema"),
        NQ_ARTIFACT_SCHEMA,
        "initial artifact has the wrong schema"
    );
    assert_eq!(
        identity(&artifact, "/profile"),
        question.nq_profile_identity(),
        "initial artifact has the wrong NQ profile identity"
    );
    assert_eq!(
        identity(&artifact, "/question"),
        question.question_identity(),
        "initial artifact has the wrong NQ question identity"
    );

    let profile = CorrespondenceProfileV1::seal_for(
        question,
        NqEnrollmentV1 {
            instance_id: required_string("NQ_CORRESPONDENCE_INSTANCE_ID"),
            subject_id: string(&artifact, "/subject/id"),
            subject_scope: identity(&artifact, "/subject/scope"),
            vantage: identity(&artifact, "/vantage"),
            profile_semantic_id: string(&artifact, "/profile_semantic_id"),
            threshold_policy: identity(&artifact, "/threshold_policy"),
            evaluator: identity(&artifact, "/evaluator"),
            state_model: identity(&artifact, "/state_model"),
            producer: serde_json::from_value::<NqProducerV1>(
                field(&artifact, "/producer").clone(),
            )?,
            executable_sha256: sha256_hex_of_file(
                Path::new(&executable_path),
                MAX_EXECUTABLE_BYTES,
            )?,
            executable_path,
            config_sha256: sha256_hex_of_file(Path::new(&config_path), MAX_CONFIG_BYTES)?,
            config_path,
        },
        PulseEnrollmentV1 {
            observer_id: required_string("NQ_CORRESPONDENCE_OBSERVER_ID"),
            consumer_id: required_string("NQ_CORRESPONDENCE_CONSUMER_ID"),
            policy_generation: required_string("NQ_CORRESPONDENCE_POLICY_GENERATION"),
            observation_policy_generation: required_string(
                "NQ_CORRESPONDENCE_OBSERVATION_POLICY_GENERATION",
            ),
        },
    )?;
    let bytes = serde_jcs::to_vec(&profile)?;
    write_create_new(&output_path, &bytes, 0o640)?;
    println!("{} {}", profile.digest(), output_path.display());
    Ok(())
}
