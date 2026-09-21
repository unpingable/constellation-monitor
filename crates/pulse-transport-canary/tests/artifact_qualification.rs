use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use pulse_runtime::{
    decode_observation_envelope_datagram, decode_receiver_challenge_datagram,
    decode_receiver_session_acceptance_datagram, decode_sender_session_binding_datagram,
    decode_sender_session_offer_datagram,
};
use pulse_transport_canary::{GeneratedArtifactSetV1, write_campaign_artifacts};
use pulse_types::{
    PeerKeyIdentityV1, QualificationCertificateV1, QualificationEvidenceReportV1,
    QualifiedArtifactManifestV1, ReceiverAcceptancePolicyV1, SenderEmissionPolicyV1,
    verify_qualification_package,
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

fn temporary_directory() -> PathBuf {
    std::env::temp_dir().join(format!(
        "monitor-custody-artifacts-{}-{}",
        std::process::id(),
        NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
    ))
}

fn read(path: &Path, name: &str) -> Vec<u8> {
    fs::read(path.join(name)).unwrap_or_else(|error| panic!("read {name}: {error}"))
}

fn corpus_wire(path: &Path, name: &str) -> Vec<u8> {
    let value: serde_json::Value = serde_json::from_slice(&read(path, name)).expect("corpus JSON");
    let hex = value["datagram_hex"].as_str().expect("datagram hex");
    assert_eq!(hex.len() % 2, 0);
    (0..hex.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&hex[offset..offset + 2], 16).expect("lower hex"))
        .collect()
}

fn verify_package(path: &Path, prefix: &str) {
    let manifest = QualifiedArtifactManifestV1::decode_canonical(&read(
        path,
        &format!("{prefix}-qualified-manifest.json"),
    ))
    .expect("manifest");
    let report = QualificationEvidenceReportV1::decode_canonical(&read(
        path,
        &format!("{prefix}-qualification-report.json"),
    ))
    .expect("report");
    let certificate = QualificationCertificateV1::decode_canonical(&read(
        path,
        &format!("{prefix}-qualification-certificate.json"),
    ))
    .expect("certificate");
    verify_qualification_package(&manifest, &report, &certificate).expect("exact package");
}

#[test]
fn generated_campaign_artifacts_are_bounded_parseable_public_and_exactly_paired() {
    let directory = temporary_directory();
    let generated = write_campaign_artifacts(&directory).expect("generate artifacts");
    assert!(!generated.private_key_material_written);
    assert!(generated.files.len() >= 25);
    for name in &generated.files {
        let bytes = read(&directory, name);
        assert!(bytes.len() <= 2 * 1024 * 1024, "oversized artifact: {name}");
        let _: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or_else(|error| panic!("parse {name}: {error}"));
        let text = String::from_utf8(bytes).expect("artifact UTF-8");
        for forbidden in ["private_key_hex", "secret_key", "signing_seed"] {
            assert!(!text.contains(forbidden), "{name} contains {forbidden}");
        }
    }
    let index: GeneratedArtifactSetV1 =
        serde_json::from_slice(&read(&directory, "artifact-index.json")).expect("index");
    assert!(!index.private_key_material_written);

    ReceiverAcceptancePolicyV1::decode_canonical(&read(
        &directory,
        "receiver-acceptance-policy.json",
    ))
    .expect("receiver policy");
    SenderEmissionPolicyV1::decode_canonical(&read(&directory, "sender-emission-policy.json"))
        .expect("sender policy");
    for prefix in ["sender", "receiver-consumer-a", "receiver-consumer-b"] {
        verify_package(&directory, prefix);
    }

    let keys: serde_json::Value =
        serde_json::from_slice(&read(&directory, "peer-public-key-identities.json"))
            .expect("key identities");
    let sender_key: PeerKeyIdentityV1 =
        serde_json::from_value(keys["sender"].clone()).expect("sender key");
    let receiver_key: PeerKeyIdentityV1 =
        serde_json::from_value(keys["receiver"].clone()).expect("receiver key");
    decode_sender_session_offer_datagram(
        &corpus_wire(&directory, "sender-session-offer-corpus.json"),
        &sender_key,
    )
    .expect("offer");
    decode_receiver_challenge_datagram(
        &corpus_wire(&directory, "receiver-challenge-corpus.json"),
        &receiver_key,
    )
    .expect("challenge");
    decode_sender_session_binding_datagram(
        &corpus_wire(&directory, "sender-session-binding-corpus.json"),
        &sender_key,
    )
    .expect("binding");
    decode_receiver_session_acceptance_datagram(
        &corpus_wire(&directory, "receiver-session-acceptance-corpus.json"),
        &receiver_key,
    )
    .expect("session acceptance");
    decode_observation_envelope_datagram(
        &corpus_wire(&directory, "observation-envelope-corpus.json"),
        &sender_key,
    )
    .expect("envelope");

    fs::remove_dir_all(directory).expect("remove test artifacts");
}
