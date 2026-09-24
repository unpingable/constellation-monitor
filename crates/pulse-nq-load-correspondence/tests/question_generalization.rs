//! The seam holds for the second question of the closed table and refuses
//! every cross-question substitution.
//!
//! The filesystem-capacity profile seals under its own schema and constants,
//! co-produces through a real local reactor with the synthetic NQ port,
//! verifies its audit record, and carries its question on the verified value.
//! A load record, frame, artifact, or certificate never satisfies the
//! filesystem profile and the reverse never holds either.

use std::fs;

use pulse_nq_load_correspondence::fixture::{
    FakeNq, SYNTHETIC_FILESYSTEM_SUBJECT, SYNTHETIC_OBSERVER_INCARNATION,
    SYNTHETIC_SUBJECT_INCARNATION, SyntheticOutcome, Tamper, reseal, start_reactor,
    synthetic_enrollment_for, synthetic_profile, synthetic_profile_for, synthetic_record,
};
use pulse_nq_load_correspondence::{
    Coproducer, CorrespondenceConstantsV1, CorrespondenceProfileV1, CorrespondenceRecordV1,
    FRAME_VALIDITY_MS, FixedSubjectIncarnation, NqDetectorStateV1, OccurrenceOutcomeV1, QuestionV1,
    acquisition_id, build_frame, check_holding_delay_for, classify_outcome_for, evidence_ref,
    frame_ingress_for, verify_artifact, verify_audit_record, verify_certificate_binding,
    verify_frame,
};
use pulse_runtime::RuntimeInputV1;
use pulse_types::IncarnationId;

const FS: QuestionV1 = QuestionV1::HostFilesystemCapacityPressureV1;
const LOAD: QuestionV1 = QuestionV1::HostLoadPressureV1;

fn incarnation() -> IncarnationId {
    IncarnationId::new(SYNTHETIC_SUBJECT_INCARNATION)
}

#[test]
fn the_filesystem_profile_seals_under_its_own_row_and_the_load_profile_is_unchanged() {
    let fs_profile = synthetic_profile_for(FS).expect("filesystem profile");
    let load_profile = synthetic_profile().expect("load profile");
    assert_eq!(fs_profile.question().expect("question"), FS);
    assert_eq!(load_profile.question().expect("question"), LOAD);
    assert_eq!(fs_profile.schema, FS.spec().profile_schema);
    assert_eq!(
        fs_profile.constants,
        CorrespondenceConstantsV1::compiled_for(FS)
    );
    assert_ne!(fs_profile.digest(), load_profile.digest());
    assert_eq!(
        fs_profile.reliance_policy().expect("policy").scope,
        FS.spec().pulse_scope
    );
    assert_eq!(
        fs_profile
            .reliance_policy()
            .expect("policy")
            .maximum_validity_ms,
        FS.frame_validity_ms()
    );
    assert_eq!(FS.frame_validity_ms(), FRAME_VALIDITY_MS);
    assert_ne!(
        fs_profile.pulse_observation_profile().expect("profile"),
        load_profile.pulse_observation_profile().expect("profile")
    );
    // Decoding the canonical bytes reproduces the same profile.
    let bytes = serde_jcs::to_vec(&fs_profile).expect("canonical");
    assert_eq!(
        CorrespondenceProfileV1::decode(&bytes).expect("decodes"),
        fs_profile
    );
}

#[test]
fn a_profile_cannot_mix_one_question_schema_with_another_question_constants() {
    let fs_profile = synthetic_profile_for(FS).expect("filesystem profile");
    let mut mixed = fs_profile.clone();
    mixed.schema = LOAD.spec().profile_schema.to_owned();
    assert_eq!(mixed.validate().unwrap_err().code, "profile_constant_drift");
    let mut unknown = fs_profile.clone();
    unknown.schema = "constellation.nq_host_memory_correspondence_profile.v1".to_owned();
    assert_eq!(unknown.validate().unwrap_err().code, "unsupported_schema");
    // The subject rule follows the question: a host: subject is not a
    // filesystem subject and the reverse does not hold either.
    let (mut nq, pulse) = synthetic_enrollment_for(FS);
    nq.subject_id = "host:synthetic-correspondence".to_owned();
    assert_eq!(
        CorrespondenceProfileV1::seal_for(FS, nq.clone(), pulse.clone())
            .unwrap_err()
            .code,
        "invalid_subject"
    );
    nq.subject_id = "host-filesystem:".to_owned();
    assert_eq!(
        CorrespondenceProfileV1::seal_for(FS, nq, pulse)
            .unwrap_err()
            .code,
        "invalid_subject"
    );
    let (mut load_nq, load_pulse) = synthetic_enrollment_for(LOAD);
    load_nq.subject_id = SYNTHETIC_FILESYSTEM_SUBJECT.to_owned();
    assert_eq!(
        CorrespondenceProfileV1::seal_for(LOAD, load_nq, load_pulse)
            .unwrap_err()
            .code,
        "invalid_subject"
    );
}

#[test]
fn filesystem_identities_use_the_filesystem_row() {
    let profile = synthetic_profile_for(FS).expect("filesystem profile");
    let frame = build_frame(
        &profile,
        incarnation(),
        IncarnationId::new(SYNTHETIC_OBSERVER_INCARNATION),
        1,
        0,
    )
    .expect("frame");
    assert_eq!(frame.coverage.expected, [FS.spec().coverage_tag.to_owned()]);
    assert_eq!(frame.profile.name, FS.spec().pulse_profile_name);
    assert_eq!(frame.validity_ms, FS.frame_validity_ms());
    let reference = evidence_ref(&frame);
    let fs_id =
        acquisition_id(FS, profile.digest(), &profile.nq.instance_id, &reference).expect("id");
    let load_id =
        acquisition_id(LOAD, profile.digest(), &profile.nq.instance_id, &reference).expect("id");
    assert!(fs_id.starts_with(FS.spec().acquisition_id_prefix));
    assert_ne!(
        fs_id[FS.spec().acquisition_id_prefix.len()..],
        load_id[LOAD.spec().acquisition_id_prefix.len()..],
        "the occurrence schema is part of the preimage"
    );
    match frame_ingress_for(FS, frame.clone(), 3) {
        RuntimeInputV1::Pulse(ingress) => {
            assert_eq!(ingress.transport_path, FS.spec().transport_path);
        }
        other => panic!("unexpected ingress {other:?}"),
    }
    assert!(check_holding_delay_for(FS, FS.frame_validity_ms() - 1).is_ok());
    assert_eq!(
        check_holding_delay_for(FS, FS.frame_validity_ms())
            .unwrap_err()
            .code,
        "holding_delay_exceeds_validity"
    );
    // The frame verifies only against its own profile.
    let load_profile = synthetic_profile().expect("load profile");
    assert!(verify_frame(&frame, &profile).is_ok());
    assert_eq!(
        verify_frame(&frame, &load_profile).unwrap_err().code,
        "frame_binding_mismatch"
    );
}

#[test]
fn the_ladder_pins_the_filesystem_claim_and_refusal_profile() {
    let profile = synthetic_profile_for(FS).expect("filesystem profile");
    let present = synthetic_record(&profile, SyntheticOutcome::Present, 1, 7, 3).expect("record");
    let artifact = &present.nq.artifact;
    assert_eq!(
        classify_outcome_for(artifact, FS, Some(FS.spec().claim_id)).expect("present"),
        NqDetectorStateV1::Present
    );
    assert_eq!(
        classify_outcome_for(artifact, FS, Some(LOAD.spec().claim_id))
            .unwrap_err()
            .code,
        "artifact_claim_mismatch"
    );
    let refused =
        synthetic_record(&profile, SyntheticOutcome::CannotEvaluate, 2, 7, 3).expect("record");
    assert_eq!(
        classify_outcome_for(&refused.nq.artifact, FS, None).expect("classifies"),
        NqDetectorStateV1::CannotEvaluate
    );
    // Under the load row the same refusal names the wrong NQ profile, so it
    // is not a detector refusal and falls to the undetermined bucket, as any
    // foreign refusal does for load v1. The artifact verifier refuses the
    // profile pin before the ladder is ever consulted.
    assert_eq!(
        classify_outcome_for(&refused.nq.artifact, LOAD, None).expect("classifies"),
        NqDetectorStateV1::NotEvaluated
    );
    let canonical = serde_jcs::to_vec(artifact).expect("canonical");
    assert!(verify_artifact(&canonical, &profile).is_ok());
    let load_profile = synthetic_profile().expect("load profile");
    assert_eq!(
        verify_artifact(&canonical, &load_profile).unwrap_err().code,
        "artifact_pin_mismatch"
    );
}

#[test]
fn filesystem_records_verify_only_under_the_filesystem_profile() {
    let fs_profile = synthetic_profile_for(FS).expect("filesystem profile");
    let load_profile = synthetic_profile().expect("load profile");
    for (outcome, state) in [
        (SyntheticOutcome::Present, NqDetectorStateV1::Present),
        (
            SyntheticOutcome::ExplicitlyAbsent,
            NqDetectorStateV1::ExplicitlyAbsent,
        ),
        (
            SyntheticOutcome::CannotEvaluate,
            NqDetectorStateV1::CannotEvaluate,
        ),
        (
            SyntheticOutcome::InputRefusal,
            NqDetectorStateV1::NotEvaluated,
        ),
        (
            SyntheticOutcome::ProviderNoResponse,
            NqDetectorStateV1::NotEvaluated,
        ),
    ] {
        let record = synthetic_record(&fs_profile, outcome, 1, 7, 3).expect("record");
        assert_eq!(record.schema, FS.spec().record_schema);
        assert_eq!(record.delivery.transport_path, FS.spec().transport_path);
        let bytes = record.canonical_bytes().expect("bytes");
        let verdict = verify_audit_record(&bytes, &fs_profile).expect("verifies");
        assert_eq!(verdict.nq_detector_state, state);
        assert_eq!(
            verify_audit_record(&bytes, &load_profile).unwrap_err().code,
            "record_question_mismatch"
        );
    }
    let load_record =
        synthetic_record(&load_profile, SyntheticOutcome::Present, 1, 7, 3).expect("record");
    let load_bytes = load_record.canonical_bytes().expect("bytes");
    assert_eq!(
        verify_audit_record(&load_bytes, &fs_profile)
            .unwrap_err()
            .code,
        "record_question_mismatch"
    );
    // A record whose schema is rewritten to the other question fails on its
    // identity, and after re-sealing on the profile digest: the question is
    // never inferred from the payload.
    let mut relabelled = load_record.clone();
    relabelled.schema = FS.spec().record_schema.to_owned();
    assert_eq!(
        CorrespondenceRecordV1::decode_canonical(&relabelled.canonical_bytes().expect("bytes"))
            .unwrap_err()
            .code,
        "record_identity_mismatch"
    );
    let resealed = reseal(relabelled).expect("reseal");
    assert_eq!(
        verify_audit_record(&resealed.canonical_bytes().expect("bytes"), &fs_profile)
            .unwrap_err()
            .code,
        "profile_mismatch"
    );
    let mut unknown = load_record;
    unknown.schema = "constellation.nq_host_memory_correspondence.v1".to_owned();
    unknown.correspondence_id = unknown.compute_id().expect("id");
    assert_eq!(
        CorrespondenceRecordV1::decode_canonical(&unknown.canonical_bytes().expect("bytes"))
            .unwrap_err()
            .code,
        "unsupported_schema"
    );
}

#[test]
fn filesystem_co_production_verifies_end_to_end_and_carries_its_question() {
    let profile = synthetic_profile_for(FS).expect("filesystem profile");
    let root = tempfile::tempdir().expect("tempdir");
    let journal = root.path().join("fs.journal");
    let reactor = start_reactor(&profile, incarnation(), "fs-capacity", &journal).expect("reactor");
    let nq = FakeNq::new(profile.clone(), SyntheticOutcome::Present);
    let witness = FixedSubjectIncarnation(incarnation());
    let intent_dir = root.path().join("intent");
    let audit_dir = root.path().join("audit");
    let mut coproducer =
        Coproducer::begin(&profile, &nq, &witness, &intent_dir, &audit_dir).expect("coproducer");
    assert_eq!(coproducer.question(), FS);
    for (outcome, state) in [
        (SyntheticOutcome::Present, NqDetectorStateV1::Present),
        (
            SyntheticOutcome::ExplicitlyAbsent,
            NqDetectorStateV1::ExplicitlyAbsent,
        ),
        (
            SyntheticOutcome::CannotEvaluate,
            NqDetectorStateV1::CannotEvaluate,
        ),
        (
            SyntheticOutcome::InputRefusal,
            NqDetectorStateV1::NotEvaluated,
        ),
    ] {
        nq.set_outcome(outcome);
        let result = coproducer.run_occurrence(&reactor).expect("occurrence");
        assert!(
            result
                .acquisition_id
                .starts_with(FS.spec().acquisition_id_prefix)
        );
        assert_eq!(result.nq_detector_state, state);
        let bytes = fs::read(&result.record_path).expect("record");
        let verdict = verify_audit_record(&bytes, &profile).expect("audit verifies");
        assert_eq!(verdict.acquisition_id, result.acquisition_id);
        let intent: serde_json::Value = serde_json::from_slice(
            &fs::read(pulse_nq_load_correspondence::occurrence_path(
                &intent_dir,
                &result.acquisition_id,
            ))
            .expect("intent"),
        )
        .expect("intent json");
        assert_eq!(intent["schema"], FS.spec().intent_schema);
        match result.outcome {
            OccurrenceOutcomeV1::Verified(verified) => {
                assert_eq!(verified.question(), FS);
                assert_eq!(verified.subject().as_str(), SYNTHETIC_FILESYSTEM_SUBJECT);
                assert_eq!(verified.nq_detector_state(), state);
                let snapshot = reactor.snapshot();
                let certificate = snapshot
                    .certificates
                    .iter()
                    .find(|certificate| certificate.consumer == profile.consumer())
                    .expect("certificate");
                assert_eq!(certificate.subject_scope.scope, FS.spec().pulse_scope);
                assert_eq!(
                    certificate.supporting_evidence_ids,
                    [verified.evidence_ref().to_owned()]
                );
                verify_certificate_binding(
                    certificate,
                    &profile,
                    verified.evidence_ref(),
                    verified.subject_incarnation(),
                    verified.delivery().holding_delay_ms,
                )
                .expect("binding");
                // The same certificate never binds under the load profile.
                let load_profile = synthetic_profile().expect("load profile");
                assert_eq!(
                    verify_certificate_binding(
                        certificate,
                        &load_profile,
                        verified.evidence_ref(),
                        verified.subject_incarnation(),
                        verified.delivery().holding_delay_ms,
                    )
                    .unwrap_err()
                    .code,
                    "certificate_binding_mismatch"
                );
            }
            OccurrenceOutcomeV1::AuditOnly { refusal } => panic!("audit only: {refusal}"),
        }
    }
    // Tampered NQ output is refused for the filesystem question exactly as
    // for load, before delivery; each refusal burns a sequence.
    nq.set_outcome(SyntheticOutcome::Present);
    for (tamper, code) in [
        (Tamper::ArtifactOtherQuestionDigest, "artifact_pin_mismatch"),
        (Tamper::ArtifactOtherSubject, "artifact_pin_mismatch"),
        (
            Tamper::ArtifactFreshSelectionRule,
            "artifact_selection_rule",
        ),
        (
            Tamper::ArtifactOtherProfileSemantic,
            "artifact_pin_mismatch",
        ),
        (Tamper::ReplayDiffers, "replay_mismatch"),
    ] {
        nq.set_tamper(tamper);
        let error = coproducer
            .run_occurrence(&reactor)
            .expect_err("tampered occurrence must refuse");
        assert_eq!(error.code, code, "{tamper:?}: {error}");
    }
    // A helper-origin refusal labelled as a detector refusal is a valid
    // not-evaluated outcome; it is delivered and recorded, and after the
    // burned sequences Pulse's gap keeps it audit-only.
    nq.set_outcome(SyntheticOutcome::CannotEvaluate);
    nq.set_tamper(Tamper::ArtifactHelperRefusalLabelledCannotEvaluate);
    let result = coproducer.run_occurrence(&reactor).expect("valid outcome");
    assert_eq!(result.nq_detector_state, NqDetectorStateV1::NotEvaluated);
    reactor.shutdown().expect("shutdown");
}

#[test]
fn a_port_enrolled_for_the_other_question_is_refused_before_custody() {
    let fs_profile = synthetic_profile_for(FS).expect("filesystem profile");
    let load_profile = synthetic_profile().expect("load profile");
    let root = tempfile::tempdir().expect("tempdir");
    let load_port = FakeNq::new(load_profile, SyntheticOutcome::Present);
    let witness = FixedSubjectIncarnation(incarnation());
    let refusal = Coproducer::begin(
        &fs_profile,
        &load_port,
        &witness,
        &root.path().join("intent"),
        &root.path().join("audit"),
    )
    .err()
    .expect("a load-enrolled port is refused");
    assert_eq!(refusal.code, "nq_enrollment_mismatch");
}

/// Decode a sealed real profile named by `NQ_CORRESPONDENCE_PROFILE_CHECK`
/// and print its digest and question, for the regression gate.
#[test]
#[ignore = "reads a profile path from the environment"]
fn decode_real_profile_from_env() {
    let path = std::env::var("NQ_CORRESPONDENCE_PROFILE_CHECK").expect("profile path");
    let bytes = fs::read(&path).expect("profile bytes");
    let profile = CorrespondenceProfileV1::decode(&bytes).expect("profile decodes");
    println!(
        "PROFILE {} question={:?} subject={}",
        profile.digest(),
        profile.question().expect("question"),
        profile.nq.subject_id
    );
}

/// Cross-verify two real audit record sets: every record verifies under its
/// own profile and is refused under the other question's profile. Reads
/// `NQ_CORRESPONDENCE_REAL_{A,B}_PROFILE` and `_RECORD_DIR` from the
/// environment and prints one line per record.
#[test]
#[ignore = "reads real profiles and audit records from the environment"]
fn cross_verify_real_records_from_env() {
    let side = |name: &str| {
        let profile_path =
            std::env::var(format!("NQ_CORRESPONDENCE_REAL_{name}_PROFILE")).expect("profile path");
        let record_dir =
            std::env::var(format!("NQ_CORRESPONDENCE_REAL_{name}_RECORD_DIR")).expect("record dir");
        let profile =
            CorrespondenceProfileV1::decode(&fs::read(&profile_path).expect("profile bytes"))
                .expect("profile decodes");
        let mut records = fs::read_dir(&record_dir)
            .expect("record dir")
            .map(|entry| entry.expect("entry").path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .collect::<Vec<_>>();
        records.sort();
        assert!(!records.is_empty(), "{record_dir} holds no records");
        (profile, records)
    };
    let (profile_a, records_a) = side("A");
    let (profile_b, records_b) = side("B");
    for (own, other, records) in [
        (&profile_a, &profile_b, &records_a),
        (&profile_b, &profile_a, &records_b),
    ] {
        for record in records {
            let bytes = fs::read(record).expect("record bytes");
            let verdict = verify_audit_record(&bytes, own).expect("own profile verifies");
            let refusal =
                verify_audit_record(&bytes, other).expect_err("other profile must refuse");
            assert!(
                refusal.code == "record_question_mismatch" || refusal.code == "profile_mismatch",
                "{}: {refusal}",
                record.display()
            );
            println!(
                "RECORD {} question={:?} state={} own=verified other={}",
                record.file_name().unwrap_or_default().to_string_lossy(),
                own.question().expect("question"),
                verdict.nq_detector_state.as_str(),
                refusal.code
            );
        }
    }
}
