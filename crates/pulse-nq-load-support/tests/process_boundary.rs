use std::fs;
use std::io::Write as _;
use std::os::unix::fs::symlink;
use std::process::{Command, Stdio};

use ed25519_dalek::SigningKey;
use pulse_nq_load_support::{
    CONFIG_SCHEMA, ExpectedDiagnosticV1, LoadPressureStateV1, LoadSupportConfigV1, PROFILE_DIGEST,
    PROFILE_ID, PROFILE_SEMANTIC_ID, PROFILE_VERSION, PresentEvidenceQueryV1,
    QUALIFIED_SUPPORT_SCHEMA, QUESTION_DIGEST, QUESTION_ID, QUESTION_VERSION, QualifiedStandingV1,
    QualifiedSupportV1, SUPPORT_FAMILY, SemanticIdentityV1, THRESHOLD_POLICY_DIGEST,
    THRESHOLD_POLICY_ID, THRESHOLD_POLICY_VERSION,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn object_id<T: Serialize>(value: &T, identity_field: &str) -> String {
    let mut value = serde_json::to_value(value).expect("value");
    value
        .as_object_mut()
        .expect("object")
        .remove(identity_field);
    format!(
        "sha256:{:x}",
        Sha256::digest(serde_jcs::to_vec(&value).expect("canonical bytes"))
    )
}

fn fixture(root: &TempDir) -> (LoadSupportConfigV1, std::path::PathBuf) {
    let signing = SigningKey::from_bytes(&[19_u8; 32]);
    let key_path = root.path().join("producer-key.hex");
    fs::write(&key_path, hex(&signing.to_bytes())).expect("key");
    let mut permissions = fs::metadata(&key_path).expect("key metadata").permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o600);
    fs::set_permissions(&key_path, permissions).expect("key mode");
    let config = LoadSupportConfigV1 {
        schema: CONFIG_SCHEMA.into(),
        authority_id: "pulse-authority:load-pressure-v1".into(),
        support_family: SUPPORT_FAMILY.into(),
        producer_id: "pulse-producer:process-boundary-v1".into(),
        producer_key_id: format!(
            "pulse-key:sha256:{:x}",
            Sha256::digest(signing.verifying_key().as_bytes())
        ),
        producer_public_key_hex: hex(signing.verifying_key().as_bytes()),
        producer_private_key_path: key_path,
        subject_id: "host:labelwatch-host".into(),
        scope_id: "sha256:41841f4aad87f73aea2a2be3926020ce4edb3a833190ab0d71115f7549e961d6"
            .into(),
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
        outgoing_directory: root.path().join("outgoing"),
        receipt_directory: root.path().join("receipts"),
        expected_diagnostic: ExpectedDiagnosticV1 {
            diagnostic_inputs_id:
                "sha256:bf913b508824ba94fdbceda4376d5bfe0f269f036db173c9aa936a988ad0ec9b"
                    .into(),
            artifact_ids: vec![
                "sha256:54c50dfca0acfaf369d7e800d585b35a26768ffefbad5741cea62c04b63bfad3"
                    .into(),
            ],
            expected_state: LoadPressureStateV1::ExplicitlyAbsent,
        },
    };
    fs::create_dir_all(&config.outgoing_directory).expect("outgoing");
    fs::create_dir_all(&config.receipt_directory).expect("receipts");
    let config_path = root.path().join("config.json");
    fs::write(
        &config_path,
        serde_jcs::to_vec(&config).expect("canonical config"),
    )
    .expect("write config");
    (config, config_path)
}

#[test]
fn real_roles_cross_the_process_boundary_without_resolver_generation() {
    let root = TempDir::new().expect("tempdir");
    let (config, config_path) = fixture(&root);
    let binary = env!("CARGO_BIN_EXE_pulse-nq-load-support");
    let acquisition_id = "support:process-boundary-1";

    let produce = Command::new(binary)
        .args([
            "produce",
            "--config",
            config_path.to_str().expect("config path"),
            "--acquisition-id",
            acquisition_id,
        ])
        .output()
        .expect("producer process");
    assert!(
        produce.status.success(),
        "{}",
        String::from_utf8_lossy(&produce.stderr)
    );
    assert_eq!(
        fs::read_dir(&config.outgoing_directory)
            .expect("outgoing")
            .count(),
        1
    );
    assert_eq!(
        fs::read_dir(&config.receipt_directory)
            .expect("receipts")
            .count(),
        0
    );

    let intake = Command::new(binary)
        .args([
            "ingest",
            "--config",
            config_path.to_str().expect("config path"),
            "--acquisition-id",
            acquisition_id,
        ])
        .output()
        .expect("intake process");
    assert!(
        intake.status.success(),
        "{}",
        String::from_utf8_lossy(&intake.stderr)
    );
    assert_eq!(
        fs::read_dir(&config.receipt_directory)
            .expect("receipts")
            .count(),
        1
    );

    let resolver = root.path().join("pulse-support-resolver");
    symlink(binary, &resolver).expect("resolver role link");
    let mut query = PresentEvidenceQueryV1 {
        schema: "nightshift.present_evidence_query.v1".into(),
        query_id: String::new(),
        observation_cycle_id: "cycle:process-boundary".into(),
        request_nonce: "support-query:process-boundary".into(),
        observation_id: "sha256:11dd56509e57e8f094aa03e1ace29889b92e014a1d3262b65b53a8762fce5ba2"
            .into(),
        diagnostic_inputs_id: config.expected_diagnostic.diagnostic_inputs_id.clone(),
        subject_id: config.subject_id,
        scope_id: config.scope_id,
        artifact_ids: config.expected_diagnostic.artifact_ids,
    };
    query.query_id = object_id(&query, "query_id");
    let receipt_count = fs::read_dir(&config.receipt_directory)
        .expect("receipts")
        .count();
    let mut child = Command::new(&resolver)
        .env("PULSE_LOAD_SUPPORT_CONFIG", &config_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("resolver process");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(&serde_jcs::to_vec(&query).expect("query"))
        .expect("write query");
    let output = child.wait_with_output().expect("resolver output");
    assert!(output.status.success());
    let support: QualifiedSupportV1 = serde_json::from_slice(&output.stdout).expect("support");
    assert_eq!(support.schema, QUALIFIED_SUPPORT_SCHEMA);
    assert_eq!(support.standing, QualifiedStandingV1::Current);
    assert_eq!(support.query_id, query.query_id);
    assert_eq!(
        fs::read_dir(&config.receipt_directory)
            .expect("receipts")
            .count(),
        receipt_count,
        "resolver must not manufacture support custody"
    );
    assert_eq!(
        fs::read_dir(&config.outgoing_directory)
            .expect("outgoing")
            .count(),
        1,
        "resolver must not invoke a producer"
    );
}
