use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::Command;

use ed25519_dalek::SigningKey;
use pulse_project_predicate_support::{
    CurrentnessPolicyV1, EVIDENCE_SCHEMA, NqArtifacts, POLICY_SCHEMA, SignedSupportEvidenceV1,
    SupportDispositionV1, SupportEvidenceV1, SupportPolicyV1, SupportSourceBindingV1,
    TargetBindingV1, canonical_digest, qualify, qualify_support_failure, read_json, replay,
    sign_evidence, verifier_executable_digest, write_json,
};
use serde_json::{Value, json};
use tempfile::TempDir;

const R: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const C: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const P: &str = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
const I: &str = "sha256:4444444444444444444444444444444444444444444444444444444444444444";

struct Fixture {
    _root: TempDir,
    verifier: PathBuf,
    receipt: PathBuf,
    inventory: PathBuf,
    catalog: PathBuf,
    policy: SupportPolicyV1,
    key: SigningKey,
}

impl Fixture {
    fn new(conclusion: bool) -> Self {
        let root = TempDir::new().unwrap();
        let verifier = root.path().join("nq-verifier");
        let result = json!({"schema":"nq.bounded-predicate-support-evaluation/v1","admission_replay_matches":true,"admission_receipt_digest":R,"catalog_digest":C,"predicate_profile":"nq.profile.sprocket-queue-bounded-17/v1","profile_digest":P,"input_schema_digest":I,"semantic_conclusion":conclusion,"trace":{"compiled_semantics":"nq.bounded-predicate-compiled/v1","result":conclusion}});
        fs::write(
            &verifier,
            format!("#!/bin/sh\ntest \"$1\" = bounded-predicate && test \"$2\" = support-evaluate || exit 64\nprintf '%s\\n' '{}'\n", result),
        )
        .unwrap();
        let mut mode = fs::metadata(&verifier).unwrap().permissions();
        mode.set_mode(0o700);
        fs::set_permissions(&verifier, mode).unwrap();
        let receipt = root.path().join("receipt.json");
        fs::write(&receipt, serde_json::to_vec(&json!({"receipt_digest":R,"witness":{"project":"sprocket-fixture","concern":"sprocket.queue.bounded","question":"sprocket.question.queue-bounded/v1","declaration_profile":"sprocket.profile.queue-bounded-17/v1","predicate_profile":"nq.profile.sprocket-queue-bounded-17/v1","profile_digest":P,"input_schema_digest":I,"producer":"sprocket-fixture.status","observed_at":"2026-08-25T12:00:00Z","valid_for_seconds":300}})).unwrap()).unwrap();
        let inventory = root.path().join("inventory.json");
        let catalog = root.path().join("catalog.json");
        fs::write(&inventory, "{}").unwrap();
        fs::write(&catalog, "{}").unwrap();
        let key = SigningKey::from_bytes(&[42; 32]);
        let mut policy = SupportPolicyV1 {
            schema: POLICY_SCHEMA.into(),
            policy_id: "pulse.policy.unfamiliar-queue/v1".into(),
            policy_digest: String::new(),
            target: TargetBindingV1 {
                project: "sprocket-fixture".into(),
                concern: "sprocket.queue.bounded".into(),
                question: "sprocket.question.queue-bounded/v1".into(),
                declaration_profile: "sprocket.profile.queue-bounded-17/v1".into(),
                predicate_profile: "nq.profile.sprocket-queue-bounded-17/v1".into(),
                catalog_digest: C.into(),
                profile_digest: P.into(),
                input_schema_digest: I.into(),
                primary_producer: "sprocket-fixture.status".into(),
                subject_id: "deployment:sprocket-test".into(),
            },
            support_source: SupportSourceBindingV1 {
                producer_id: "pulse-producer:sprocket-independent".into(),
                producer_key_id: "pulse-key:sprocket-independent".into(),
                producer_public_key_hex: hex(key.verifying_key().as_bytes()),
                source_id: "source:sprocket-direct-queue-api".into(),
                vantage_id: "vantage:pulse-sidecar".into(),
                dependency_ids: vec!["direct:sprocket-queue-api".into()],
            },
            currentness: CurrentnessPolicyV1 {
                maximum_primary_age_seconds: 300,
                maximum_support_age_seconds: 120,
                maximum_primary_support_skew_seconds: 30,
            },
            nq_verifier_executable_digest: verifier_executable_digest(&verifier).unwrap(),
        };
        policy.seal().unwrap();
        Self {
            _root: root,
            verifier,
            receipt,
            inventory,
            catalog,
            policy,
            key,
        }
    }
    fn nq(&self) -> NqArtifacts<'_> {
        NqArtifacts {
            executable: &self.verifier,
            receipt: &self.receipt,
            inventory: &self.inventory,
            catalog: &self.catalog,
        }
    }
    fn evidence(&self, depth: u64, at: &str, state: &str) -> SignedSupportEvidenceV1 {
        sign_evidence(
            SupportEvidenceV1 {
                schema: EVIDENCE_SCHEMA.into(),
                evidence_id: String::new(),
                acquisition_id: "support-occurrence:1".into(),
                producer_id: self.policy.support_source.producer_id.clone(),
                producer_key_id: self.policy.support_source.producer_key_id.clone(),
                source_id: self.policy.support_source.source_id.clone(),
                dependency_ids: self.policy.support_source.dependency_ids.clone(),
                subject_id: self.policy.target.subject_id.clone(),
                vantage_id: self.policy.support_source.vantage_id.clone(),
                observed_at: at.into(),
                valid_for_seconds: Some(120),
                facts: json!({"queue":{"depth":depth}}),
                local_state: state.into(),
            },
            &self.key,
        )
        .unwrap()
    }
}

#[test]
fn unfamiliar_project_qualifies_and_opaque_state_is_inert() {
    let f = Fixture::new(true);
    let a = f.evidence(12, "2026-08-25T12:00:10Z", "FROBNICATED");
    let b = f.evidence(12, "2026-08-25T12:00:10Z", "UNKNOWN");
    let first = qualify(&f.policy, &f.nq(), Some(&a), "2026-08-25T12:01:00Z").unwrap();
    let second = qualify(&f.policy, &f.nq(), Some(&b), "2026-08-25T12:01:00Z").unwrap();
    assert_eq!(first.disposition, SupportDispositionV1::SupportedCurrent);
    assert_eq!(first.disposition, second.disposition);
    assert_ne!(
        first.support_evidence_digest,
        second.support_evidence_digest
    );
    assert!(
        replay(&first, &f.policy, &f.nq(), Some(&a))
            .unwrap()
            .matches
    );
}

#[test]
fn predecessor_schema_is_not_accepted_as_native_support() {
    let mut fixture = Fixture::new(true);
    let script = fs::read_to_string(&fixture.verifier).unwrap().replace(
        "nq.bounded-predicate-support-evaluation/v1",
        "nq.project-predicate-support-evaluation/v1",
    );
    fs::write(&fixture.verifier, script).unwrap();
    fixture.policy.nq_verifier_executable_digest =
        verifier_executable_digest(&fixture.verifier).unwrap();
    fixture.policy.seal().unwrap();
    let evidence = fixture.evidence(12, "2026-08-25T12:00:10Z", "observed");
    let receipt = qualify(
        &fixture.policy,
        &fixture.nq(),
        Some(&evidence),
        "2026-08-25T12:01:00Z",
    )
    .unwrap();
    assert_eq!(receipt.disposition, SupportDispositionV1::NqReceiptInvalid);
}

#[test]
fn qualified_receipt_round_trips_as_valid_canonical_json() {
    let fixture = Fixture::new(true);
    let evidence = fixture.evidence(12, "2026-08-25T12:00:10Z", "FROBNICATED");
    let receipt = qualify(
        &fixture.policy,
        &fixture.nq(),
        Some(&evidence),
        "2026-08-25T12:01:00Z",
    )
    .unwrap();
    let path = fixture._root.path().join("qualified-support.json");
    write_json(&path, &receipt).unwrap();
    let decoded: pulse_project_predicate_support::QualifiedSupportReceiptV1 =
        read_json(&path).unwrap();
    assert_eq!(decoded, receipt);
}

#[test]
fn contradiction_stale_skew_and_missing_are_distinct() {
    let false_f = Fixture::new(false);
    let result = qualify(
        &false_f.policy,
        &false_f.nq(),
        Some(&false_f.evidence(18, "2026-08-25T12:00:10Z", "PRESENT")),
        "2026-08-25T12:01:00Z",
    )
    .unwrap();
    assert_eq!(result.disposition, SupportDispositionV1::Contradictory);
    let f = Fixture::new(true);
    assert_eq!(
        qualify(
            &f.policy,
            &f.nq(),
            Some(&f.evidence(12, "2026-08-25T12:04:50Z", "PRESENT")),
            "2026-08-25T12:05:00Z"
        )
        .unwrap()
        .disposition,
        SupportDispositionV1::PrimaryStale
    );
    assert_eq!(
        qualify(
            &f.policy,
            &f.nq(),
            Some(&f.evidence(12, "2026-08-25T12:00:10Z", "PRESENT")),
            "2026-08-25T12:02:10Z"
        )
        .unwrap()
        .disposition,
        SupportDispositionV1::SupportStale
    );
    assert_eq!(
        qualify(
            &f.policy,
            &f.nq(),
            Some(&f.evidence(12, "2026-08-25T12:01:00Z", "PRESENT")),
            "2026-08-25T12:01:01Z"
        )
        .unwrap()
        .disposition,
        SupportDispositionV1::SkewExceeded
    );
    assert_eq!(
        qualify(&f.policy, &f.nq(), None, "2026-08-25T12:01:00Z")
            .unwrap()
            .disposition,
        SupportDispositionV1::MissingSupport
    );
    assert_eq!(
        qualify_support_failure(
            &f.policy,
            &f.receipt,
            "2026-08-25T12:01:00Z",
            "independent producer exited nonzero",
        )
        .unwrap()
        .disposition,
        SupportDispositionV1::SupportProducerFailed
    );
}

#[test]
fn same_source_subject_signature_and_replay_substitution_refuse() {
    let f = Fixture::new(true);
    let mut policy = f.policy.clone();
    policy.support_source.dependency_ids = vec!["nq_receipt".into()];
    policy.seal().unwrap();
    assert!(
        qualify(
            &policy,
            &f.nq(),
            Some(&f.evidence(12, "2026-08-25T12:00:10Z", "PRESENT")),
            "2026-08-25T12:01:00Z"
        )
        .is_err()
    );
    let mut wrong = f.evidence(12, "2026-08-25T12:00:10Z", "PRESENT");
    wrong.evidence.subject_id = "deployment:other".into();
    assert_ne!(
        qualify(&f.policy, &f.nq(), Some(&wrong), "2026-08-25T12:01:00Z")
            .unwrap()
            .disposition,
        SupportDispositionV1::SupportedCurrent
    );
    let evidence = f.evidence(12, "2026-08-25T12:00:10Z", "PRESENT");
    let receipt = qualify(&f.policy, &f.nq(), Some(&evidence), "2026-08-25T12:01:00Z").unwrap();
    let mutated = f.evidence(13, "2026-08-25T12:00:10Z", "PRESENT");
    assert!(
        !replay(&receipt, &f.policy, &f.nq(), Some(&mutated))
            .unwrap()
            .matches
    );
}

#[test]
fn checked_in_schemas_are_parseable_and_version_exact() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas");
    for (file, identity) in [
        (
            "pulse.project-predicate-support-policy.v1.schema.json",
            "pulse.project-predicate-support-policy/v1",
        ),
        (
            "pulse.project-predicate-support-evidence.v1.schema.json",
            "pulse.project-predicate-support-envelope/v1",
        ),
        (
            "pulse.project-predicate-qualified-support.v1.schema.json",
            "pulse.project-predicate-qualified-support/v1",
        ),
    ] {
        let schema: Value = serde_json::from_slice(&fs::read(root.join(file)).unwrap()).unwrap();
        assert_eq!(schema["$id"], identity);
        assert_eq!(schema["additionalProperties"], false);
    }
}

#[test]
#[ignore = "requires NQ_MONITOR_BIN pointing to the public native nq executable"]
fn real_nq_sprocket_support_and_contradiction() {
    let bin = PathBuf::from(std::env::var_os("NQ_MONITOR_BIN").expect("NQ_MONITOR_BIN"));
    let root = TempDir::new().unwrap();
    let inventory = root.path().join("inventory.json");
    let catalog = root.path().join("catalog.json");
    let receipt = root.path().join("receipt.json");
    let cat = sprocket_catalog();
    fs::write(
        &inventory,
        serde_json::to_vec(&sprocket_inventory()).unwrap(),
    )
    .unwrap();
    fs::write(&catalog, serde_json::to_vec(&cat).unwrap()).unwrap();
    let cat_digest = canonical_digest(&cat).unwrap();
    let output = Command::new(&bin)
        .args(["bounded-predicate", "admit", "--inventory"])
        .arg(&inventory)
        .arg("--profiles")
        .arg(&catalog)
        .args([
            "--catalog-digest",
            &cat_digest,
            "--concern",
            "sprocket.queue.bounded",
            "--evaluated-at",
            "2026-08-25T12:01:00Z",
            "--output",
        ])
        .arg(&receipt)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let profile = &cat["profiles"][0];
    let key = SigningKey::from_bytes(&[99; 32]);
    let mut policy = SupportPolicyV1 {
        schema: POLICY_SCHEMA.into(),
        policy_id: "pulse.policy.real-sprocket/v1".into(),
        policy_digest: String::new(),
        target: TargetBindingV1 {
            project: "sprocket-fixture".into(),
            concern: "sprocket.queue.bounded".into(),
            question: "sprocket.question.queue-bounded/v1".into(),
            declaration_profile: "sprocket.profile.queue-bounded-17/v1".into(),
            predicate_profile: "nq.profile.sprocket-queue-bounded-17/v1".into(),
            catalog_digest: cat_digest,
            profile_digest: canonical_digest(profile).unwrap(),
            input_schema_digest: canonical_digest(&profile["input_schema"]).unwrap(),
            primary_producer: "sprocket-fixture.status".into(),
            subject_id: "deployment:sprocket-real".into(),
        },
        support_source: SupportSourceBindingV1 {
            producer_id: "pulse-producer:real-sprocket".into(),
            producer_key_id: "pulse-key:real-sprocket".into(),
            producer_public_key_hex: hex(key.verifying_key().as_bytes()),
            source_id: "source:direct-sprocket-queue-api".into(),
            vantage_id: "vantage:pulse-real".into(),
            dependency_ids: vec!["direct:sprocket-queue-api".into()],
        },
        currentness: CurrentnessPolicyV1 {
            maximum_primary_age_seconds: 300,
            maximum_support_age_seconds: 120,
            maximum_primary_support_skew_seconds: 30,
        },
        nq_verifier_executable_digest: verifier_executable_digest(&bin).unwrap(),
    };
    policy.seal().unwrap();
    let nq = NqArtifacts {
        executable: &bin,
        receipt: &receipt,
        inventory: &inventory,
        catalog: &catalog,
    };
    let make = |depth, id: &str| {
        sign_evidence(
            SupportEvidenceV1 {
                schema: EVIDENCE_SCHEMA.into(),
                evidence_id: String::new(),
                acquisition_id: id.into(),
                producer_id: policy.support_source.producer_id.clone(),
                producer_key_id: policy.support_source.producer_key_id.clone(),
                source_id: policy.support_source.source_id.clone(),
                dependency_ids: policy.support_source.dependency_ids.clone(),
                subject_id: policy.target.subject_id.clone(),
                vantage_id: policy.support_source.vantage_id.clone(),
                observed_at: "2026-08-25T12:00:10Z".into(),
                valid_for_seconds: Some(120),
                facts: json!({"queue":{"depth":depth}}),
                local_state: "FROBNICATED".into(),
            },
            &key,
        )
        .unwrap()
    };
    let positive = make(12, "support:real-1");
    let qualified = qualify(&policy, &nq, Some(&positive), "2026-08-25T12:01:00Z").unwrap();
    assert_eq!(
        qualified.disposition,
        SupportDispositionV1::SupportedCurrent
    );
    assert!(
        replay(&qualified, &policy, &nq, Some(&positive))
            .unwrap()
            .matches
    );
    assert_eq!(
        qualify(
            &policy,
            &nq,
            Some(&make(18, "support:real-2")),
            "2026-08-25T12:01:00Z"
        )
        .unwrap()
        .disposition,
        SupportDispositionV1::Contradictory
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn sprocket_catalog() -> Value {
    json!({"schema":"nq.project-predicate-profile-catalog/v1","profiles":[{"schema":"nq.project-predicate-profile/v1","id":"nq.profile.sprocket-queue-bounded-17/v1","question":"sprocket.question.queue-bounded/v1","declaration_profile":"sprocket.profile.queue-bounded-17/v1","subject":{"project":"sprocket-fixture","concern":"sprocket.queue.bounded"},"accepted_producers":["sprocket-fixture.status"],"accepted_manifest_digests":["sha256:8e81b1be2f274e4be29a992fa69ceae81cf337a1323ab319fc06c416afed505c"],"input_schema":[{"path":"queue.depth","type":"u64"}],"predicate":{"operator":"compare","fact":"queue.depth","comparator":"le","value":{"type":"u64","value":17}},"max_observation_age_seconds":300}]})
}
fn sprocket_inventory() -> Value {
    json!({"schema":"monitor.project-observation.inventory/v1","project":"sprocket-fixture","repository":"/fixture/sprocket","acquisition":{"disposition":"ACQUIRED_AND_VALIDATED","acquired_at_unix_ms":1787704334277_u64,"producer":"sprocket-fixture.status","binding_schema":"project.observation-binding/v1","manifest_digest":"sha256:8e81b1be2f274e4be29a992fa69ceae81cf337a1323ab319fc06c416afed505c","status_digest":"sha256:298fdab15972fc2a8df2ac6b3f0468083977fd8e1c235236fa7a628d9fc7ae16","exit_code":0,"stdout_bytes":849,"stderr_bytes":0,"repository_revision_context":"context-only","repository_revision_is_deployment_provenance":false},"validation_issues":[],"concerns":[{"declaration":{"id":"sprocket.queue.bounded","question":"sprocket.question.queue-bounded/v1","profile":"sprocket.profile.queue-bounded-17/v1","required":true,"description":"queue bounded"},"monitor_state":"OBSERVED","observation":{"observation_present":true,"local_state":"FROBNICATED","domain_state":"SPROCKET_PAUSED","observed_at":"2026-08-25T12:00:00Z","valid_for_seconds":300,"reason":"opaque","facts":{"queue":{"depth":12}}}}]})
}
