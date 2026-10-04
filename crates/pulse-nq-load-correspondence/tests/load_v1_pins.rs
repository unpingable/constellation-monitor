//! Golden pins for load v1 identities that the shared vectors do not cover:
//! the reliance policy and context digests (failure domain, scope, coverage
//! tag, and validity inside the policy), the intent bytes, one literal
//! acquisition identity, the ingress strings, and every compiled constant.
//! Values were captured on the qualified load-only implementation; a
//! generalization of the seam must leave all of them unchanged.

use std::fs;

use pulse_nq_load_correspondence::fixture::{
    FakeNq, SYNTHETIC_OBSERVER_INCARNATION, SYNTHETIC_SUBJECT_INCARNATION, SyntheticOutcome,
    start_reactor, synthetic_profile,
};
use pulse_nq_load_correspondence::{
    ACQUISITION_ID_PREFIX, COVERAGE_TAG, Coproducer, CorrespondenceConstantsV1, FRAME_DISCLOSURE,
    FRAME_VALIDITY_MS, FixedSubjectIncarnation, INGRESS_DISCLOSURE, INGRESS_FENCE_MS,
    INTENT_SCHEMA_V1, NQ_CLAIM_ID, NQ_CONDITION, NQ_PROFILE_DIGEST, NQ_PROFILE_ID,
    NQ_PROFILE_VERSION, NQ_QUESTION_DIGEST, NQ_QUESTION_ID, NQ_QUESTION_VERSION,
    NQ_RELIANCE_WINDOW_MS, NQ_SELECTION_RULE_ID, OCCURRENCE_SCHEMA_V1, ObserverLineage,
    PROFILE_SCHEMA_V1, PULSE_PROFILE_DOMAIN, PULSE_PROFILE_NAME, PULSE_PROFILE_VERSION,
    PULSE_SCOPE, QuestionV1, RECORD_SCHEMA_V1, TRANSPORT_PATH, acquisition_id, build_frame,
    evidence_ref, frame_ingress, occurrence_path, pulse_profile_digest,
};
use pulse_runtime::RuntimeInputV1;
use pulse_types::{AuthenticationResultV1, IncarnationId};

fn print_or_assert(name: &str, actual: &str, pinned: &str) {
    if std::env::var_os("PIN_PRINT").is_some() {
        println!("PIN {name} = {actual}");
    } else {
        assert_eq!(actual, pinned, "{name} changed");
    }
}

#[test]
fn compiled_load_row_is_literal() {
    for (name, actual, pinned) in [
        (
            "PROFILE_SCHEMA_V1",
            PROFILE_SCHEMA_V1,
            "constellation.nq_host_load_pressure_correspondence_profile.v1",
        ),
        (
            "OCCURRENCE_SCHEMA_V1",
            OCCURRENCE_SCHEMA_V1,
            "constellation.nq_host_load_pressure_correspondence_occurrence.v1",
        ),
        (
            "INTENT_SCHEMA_V1",
            INTENT_SCHEMA_V1,
            "constellation.nq_host_load_pressure_correspondence_intent.v1",
        ),
        (
            "RECORD_SCHEMA_V1",
            RECORD_SCHEMA_V1,
            "constellation.nq_host_load_pressure_correspondence.v1",
        ),
        (
            "PULSE_PROFILE_NAME",
            PULSE_PROFILE_NAME,
            "constellation.nq_host_load_pressure_correspondence",
        ),
        (
            "PULSE_PROFILE_DOMAIN",
            PULSE_PROFILE_DOMAIN,
            "constellation.nq_host_load_pressure_correspondence.pulse_profile.v1",
        ),
        ("PULSE_SCOPE", PULSE_SCOPE, "nq.host.load_pressure/v1"),
        (
            "COVERAGE_TAG",
            COVERAGE_TAG,
            "nq_host_load_pressure_v1_terminal_artifact",
        ),
        (
            "TRANSPORT_PATH",
            TRANSPORT_PATH,
            "in-process:nq-load-correspondence/v1",
        ),
        (
            "ACQUISITION_ID_PREFIX",
            ACQUISITION_ID_PREFIX,
            "constellation-nq-load:v1:",
        ),
        ("NQ_QUESTION_ID", NQ_QUESTION_ID, "nq.host.load_pressure"),
        ("NQ_QUESTION_VERSION", NQ_QUESTION_VERSION, "1"),
        (
            "NQ_QUESTION_DIGEST",
            NQ_QUESTION_DIGEST,
            "sha256:7de797da3d9d3a6ae8e21e5d77b95095453336cd38f606ffb3eb29ff6a32e2cf",
        ),
        ("NQ_PROFILE_ID", NQ_PROFILE_ID, "nq.host"),
        ("NQ_PROFILE_VERSION", NQ_PROFILE_VERSION, "1"),
        (
            "NQ_PROFILE_DIGEST",
            NQ_PROFILE_DIGEST,
            "sha256:c8c10fed1cc5598d953b4defbc98e8c106fc59e035c249d43681698a5c7b4ff9",
        ),
        ("NQ_CLAIM_ID", NQ_CLAIM_ID, "claim:host_load_pressure"),
        ("NQ_CONDITION", NQ_CONDITION, "host_load_pressure"),
        (
            "NQ_SELECTION_RULE_ID",
            NQ_SELECTION_RULE_ID,
            "nq.deliberate_successor_single_admitted_report",
        ),
        (
            "FRAME_DISCLOSURE",
            FRAME_DISCLOSURE,
            "unauthenticated in-process correspondence frame; it carries no NQ value or assessment",
        ),
        (
            "INGRESS_DISCLOSURE",
            INGRESS_DISCLOSURE,
            "in-process co-producer delivery; no transport authentication is claimed",
        ),
    ] {
        assert_eq!(actual, pinned, "{name}");
    }
    assert_eq!(NQ_RELIANCE_WINDOW_MS, 300_000);
    assert_eq!(INGRESS_FENCE_MS, 1_000);
    assert_eq!(FRAME_VALIDITY_MS, 298_999);
    assert_eq!(PULSE_PROFILE_VERSION, 1);
    assert_eq!(
        QuestionV1::from_profile_schema(PROFILE_SCHEMA_V1),
        Some(QuestionV1::HostLoadPressureV1)
    );
    assert_eq!(
        QuestionV1::HostLoadPressureV1.frame_validity_ms(),
        FRAME_VALIDITY_MS
    );
    let row = QuestionV1::HostLoadPressureV1.spec();
    assert_eq!(row.question_id, "nq.host.load_pressure");
    assert_eq!(row.question_version, "1");
    assert_eq!(
        row.question_digest,
        "sha256:7de797da3d9d3a6ae8e21e5d77b95095453336cd38f606ffb3eb29ff6a32e2cf"
    );
    assert_eq!(row.nq_profile_id, "nq.host");
    assert_eq!(row.nq_profile_version, "1");
    assert_eq!(
        row.nq_profile_digest,
        "sha256:c8c10fed1cc5598d953b4defbc98e8c106fc59e035c249d43681698a5c7b4ff9"
    );
    assert_eq!(row.refusal_profile_version, 1);
    assert_eq!(row.claim_id, "claim:host_load_pressure");
    assert_eq!(row.condition, "host_load_pressure");
    assert_eq!(row.subject_prefix, "host:");
    assert_eq!(row.reliance_window_ms, 300_000);
    assert_eq!(row.pulse_scope, "nq.host.load_pressure/v1");
    assert_eq!(
        row.coverage_tag,
        "nq_host_load_pressure_v1_terminal_artifact"
    );
    assert_eq!(row.acquisition_id_prefix, "constellation-nq-load:v1:");
    assert_eq!(row.transport_path, "in-process:nq-load-correspondence/v1");
    assert_eq!(row.failure_domain, "domain:nq-load-correspondence");
    assert_eq!(
        row.profile_schema,
        "constellation.nq_host_load_pressure_correspondence_profile.v1"
    );
    assert_eq!(
        row.occurrence_schema,
        "constellation.nq_host_load_pressure_correspondence_occurrence.v1"
    );
    assert_eq!(
        row.intent_schema,
        "constellation.nq_host_load_pressure_correspondence_intent.v1"
    );
    assert_eq!(
        row.record_schema,
        "constellation.nq_host_load_pressure_correspondence.v1"
    );
    assert_eq!(
        row.pulse_profile_name,
        "constellation.nq_host_load_pressure_correspondence"
    );
    assert_eq!(
        row.pulse_profile_domain,
        "constellation.nq_host_load_pressure_correspondence.pulse_profile.v1"
    );
    let compiled = CorrespondenceConstantsV1::compiled();
    assert_eq!(
        compiled,
        CorrespondenceConstantsV1::compiled_for(QuestionV1::HostLoadPressureV1)
    );
    assert_eq!(compiled.reliance_window_ms, 300_000);
    assert_eq!(compiled.frame_validity_ms, 298_999);
    assert_eq!(compiled.coverage_tag, COVERAGE_TAG);
    assert_eq!(compiled.pulse_scope, PULSE_SCOPE);
    assert_eq!(compiled.claim_id, NQ_CLAIM_ID);
    assert_eq!(compiled.question.id, NQ_QUESTION_ID);
    assert_eq!(compiled.profile.digest, NQ_PROFILE_DIGEST);
}

#[test]
fn load_v1_digests_intent_bytes_and_acquisition_identity_are_pinned() {
    let profile = synthetic_profile().expect("synthetic profile");
    print_or_assert(
        "profile_digest",
        profile.digest(),
        "sha256:b790d13eb385f2c805ed7fe9003a0a8a83171aadca1a178465e931a20dfeb610",
    );
    print_or_assert(
        "reliance_policy_semantic_digest",
        profile
            .reliance_policy()
            .expect("policy")
            .semantic_digest()
            .as_str(),
        "sha256:c573daa13c3a7469bd108200fdf7004a599af1c9740fe7072eac7eea52e065bb",
    );
    print_or_assert(
        "reliance_context_identity_digest",
        profile
            .reliance_context("a")
            .expect("context")
            .identity_digest()
            .as_str(),
        "sha256:f67656f7efeb2071c5152179f622da02195e0bcd15afe261bc3cd9bd0991c78c",
    );
    print_or_assert(
        "pulse_profile_digest",
        pulse_profile_digest(QuestionV1::HostLoadPressureV1, profile.digest()).as_str(),
        "sha256:46d745ffd47650d7abad02cab92b8ffae961a980d61c8897199eb6f80b53abe3",
    );
    let frame = build_frame(
        &profile,
        IncarnationId::new(SYNTHETIC_SUBJECT_INCARNATION),
        IncarnationId::new(SYNTHETIC_OBSERVER_INCARNATION),
        1,
        0,
    )
    .expect("frame");
    let reference = evidence_ref(&frame);
    print_or_assert(
        "evidence_ref",
        &reference,
        "observer:nq-load-correspondence/observer-incarnation:synthetic:1/seq=1/sha256:7f3bbc4e0f448d15becf1e93a1263521a83e2c5206b8fc8b0181e2ed73632192",
    );
    let acquisition = acquisition_id(
        QuestionV1::HostLoadPressureV1,
        profile.digest(),
        "host-local",
        &reference,
    )
    .expect("id");
    print_or_assert(
        "acquisition_id",
        &acquisition,
        "constellation-nq-load:v1:sha256:4df7d9bfec38c9facc40e0b6a7b065ab22322fd15614016129a9f567f2c44122",
    );
    match frame_ingress(frame, 7) {
        RuntimeInputV1::Pulse(ingress) => {
            assert_eq!(ingress.transport_path, TRANSPORT_PATH);
            assert_eq!(ingress.transport_observed_delay_ms, Some(7));
            assert_eq!(
                ingress.authentication,
                AuthenticationResultV1::Unauthenticated {
                    disclosure: INGRESS_DISCLOSURE.to_owned()
                }
            );
        }
        other => panic!("unexpected ingress {other:?}"),
    }

    // Intent bytes for one fixed occurrence, read back from custody.
    let root = tempfile::tempdir().expect("tempdir");
    let journal = root.path().join("pins.journal");
    let reactor = start_reactor(
        &profile,
        IncarnationId::new(SYNTHETIC_SUBJECT_INCARNATION),
        "pins",
        &journal,
    )
    .expect("reactor");
    let nq = FakeNq::new(profile.clone(), SyntheticOutcome::Present);
    let witness = FixedSubjectIncarnation(IncarnationId::new(SYNTHETIC_SUBJECT_INCARNATION));
    let lineage = ObserverLineage::with_incarnation(
        &profile,
        IncarnationId::new(SYNTHETIC_OBSERVER_INCARNATION),
    );
    let intent_dir = root.path().join("intent");
    let audit_dir = root.path().join("audit");
    let mut coproducer =
        Coproducer::with_lineage(&profile, &nq, &witness, lineage, &intent_dir, &audit_dir)
            .expect("coproducer");
    let result = coproducer.run_occurrence(&reactor).expect("occurrence");
    reactor.shutdown().expect("shutdown");
    let intent_bytes =
        fs::read(occurrence_path(&intent_dir, &result.acquisition_id)).expect("intent");
    let intent: serde_json::Value = serde_json::from_slice(&intent_bytes).expect("intent json");
    // The evidence reference carries the frame digest, which covers real
    // issue times, so the bytes are pinned by shape (key-sorted canonical
    // JSON on both sides) with the two derived fields taken from the
    // occurrence itself.
    assert_eq!(
        intent,
        serde_json::json!({
            "schema": INTENT_SCHEMA_V1,
            "profile_digest": profile.digest(),
            "acquisition_id": result.acquisition_id,
            "pulse_evidence_ref": result.evidence_ref,
            "sequence": 1,
        })
    );
    assert_eq!(
        intent_bytes,
        serde_json::to_vec(&intent).expect("canonical intent"),
        "intent bytes must be the compact key-sorted serialization"
    );
    assert_eq!(
        result.acquisition_id,
        acquisition_id(
            QuestionV1::HostLoadPressureV1,
            profile.digest(),
            "host-local",
            &result.evidence_ref
        )
        .expect("id"),
        "occurrence acquisition identity must be the pure derivation"
    );
    assert!(result.acquisition_id.starts_with(ACQUISITION_ID_PREFIX));
}
