//! The memory row exercises what the first two rows could not: a subject
//! prefix shared with another row (`host:`), and a frame validity that
//! differs from load's (118 999 ms against 298 999 ms). The seam must key on
//! the question, never on the prefix, and every validity check must read the
//! row, never a load constant.

use pulse_nq_load_correspondence::fixture::{
    FakeNq, SYNTHETIC_MEMORY_SUBJECT, SYNTHETIC_OBSERVER_INCARNATION,
    SYNTHETIC_SUBJECT_INCARNATION, SyntheticOutcome, reseal, start_reactor,
    synthetic_enrollment_for, synthetic_profile_for, synthetic_record,
};
use pulse_nq_load_correspondence::{
    Coproducer, CorrespondenceProfileV1, FixedSubjectIncarnation, INGRESS_FENCE_MS,
    NqDetectorStateV1, OccurrenceOutcomeV1, QuestionV1, build_frame, check_holding_delay,
    check_holding_delay_for, classify_outcome_for, verify_artifact, verify_audit_record,
    verify_certificate_binding, verify_frame,
};
use pulse_types::IncarnationId;

const MEMORY: QuestionV1 = QuestionV1::HostMemoryPressureStallV1;
const LOAD: QuestionV1 = QuestionV1::HostLoadPressureV1;
const FS: QuestionV1 = QuestionV1::HostFilesystemCapacityPressureV1;

fn incarnation() -> IncarnationId {
    IncarnationId::new(SYNTHETIC_SUBJECT_INCARNATION)
}

/// A load-row profile enrolled with the memory enrollment: the shared `host:`
/// prefix lets it seal, so every later check must refuse on the question.
fn load_profile_over_memory_enrollment() -> CorrespondenceProfileV1 {
    let (nq, pulse) = synthetic_enrollment_for(MEMORY);
    assert_eq!(nq.subject_id, SYNTHETIC_MEMORY_SUBJECT);
    CorrespondenceProfileV1::seal_for(LOAD, nq, pulse).expect("shared prefix seals")
}

#[test]
fn the_memory_row_derives_its_own_validity_through_the_shared_law() {
    assert_eq!(MEMORY.spec().reliance_window_ms, 120_000);
    assert_eq!(MEMORY.frame_validity_ms(), 120_000 - INGRESS_FENCE_MS - 1);
    assert_eq!(MEMORY.frame_validity_ms(), 118_999);
    assert_eq!(LOAD.frame_validity_ms(), 298_999);
    let profile = synthetic_profile_for(MEMORY).expect("memory profile");
    assert_eq!(profile.constants.reliance_window_ms, 120_000);
    assert_eq!(profile.constants.frame_validity_ms, 118_999);
    let policy = profile.reliance_policy().expect("policy");
    assert_eq!(policy.maximum_validity_ms, 118_999);
    let frame = build_frame(
        &profile,
        incarnation(),
        IncarnationId::new(SYNTHETIC_OBSERVER_INCARNATION),
        1,
        0,
    )
    .expect("frame");
    assert_eq!(frame.validity_ms, 118_999);
    // Boundaries of the row's own law.
    assert!(check_holding_delay_for(MEMORY, 118_998).is_ok());
    assert_eq!(
        check_holding_delay_for(MEMORY, 118_999).unwrap_err().code,
        "holding_delay_exceeds_validity"
    );
    // The load-default wrapper is the load row's law and would accept a
    // delay the memory row refuses; production code never calls it (the
    // structural script forbids it).
    assert!(check_holding_delay(200_000).is_ok());
    assert_eq!(
        check_holding_delay_for(MEMORY, 200_000).unwrap_err().code,
        "holding_delay_exceeds_validity"
    );
    // A frame carrying the load row's validity is not a memory frame.
    let mut load_validity = frame.clone();
    load_validity.validity_ms = LOAD.frame_validity_ms();
    let load_validity = load_validity.seal();
    assert_eq!(
        verify_frame(&load_validity, &profile).unwrap_err().code,
        "frame_validity_mismatch"
    );
    // A record held for a delay lawful under load only is refused.
    let mut held =
        synthetic_record(&profile, SyntheticOutcome::ExplicitlyAbsent, 1, 7, 3).expect("record");
    held.delivery.holding_delay_ms = 200_000;
    let held = reseal(held).expect("reseal");
    assert_eq!(
        verify_audit_record(&held.canonical_bytes().expect("bytes"), &profile)
            .unwrap_err()
            .code,
        "holding_delay_exceeds_validity"
    );
    // The boundary record at d = V - 1 with the fence at its bound verifies.
    let boundary = synthetic_record(
        &profile,
        SyntheticOutcome::ExplicitlyAbsent,
        2,
        118_998,
        INGRESS_FENCE_MS,
    )
    .expect("record");
    verify_audit_record(&boundary.canonical_bytes().expect("bytes"), &profile)
        .expect("boundary verifies");
}

#[test]
fn a_shared_subject_prefix_never_lets_one_row_accept_the_other_rows_judgment() {
    let memory = synthetic_profile_for(MEMORY).expect("memory profile");
    let load_over_memory = load_profile_over_memory_enrollment();
    assert_eq!(load_over_memory.nq.subject_id, memory.nq.subject_id);
    assert_eq!(load_over_memory.question().expect("question"), LOAD);

    // The first memory artifact under the load-row profile: question pin.
    let present = synthetic_record(&memory, SyntheticOutcome::Present, 1, 7, 3).expect("record");
    let artifact = serde_jcs::to_vec(&present.nq.artifact).expect("canonical");
    assert!(verify_artifact(&artifact, &memory).is_ok());
    assert_eq!(
        verify_artifact(&artifact, &load_over_memory)
            .unwrap_err()
            .code,
        "artifact_pin_mismatch"
    );
    // The memory audit record under the load-row profile: record schema.
    assert_eq!(
        verify_audit_record(
            &present.canonical_bytes().expect("bytes"),
            &load_over_memory
        )
        .unwrap_err()
        .code,
        "record_question_mismatch"
    );
    // A load-row record over the memory enrollment under the memory profile.
    let load_record = synthetic_record(&load_over_memory, SyntheticOutcome::Present, 1, 7, 3)
        .expect("load record");
    assert_eq!(
        verify_audit_record(&load_record.canonical_bytes().expect("bytes"), &memory)
            .unwrap_err()
            .code,
        "record_question_mismatch"
    );
    // The memory frame under the load-row profile: the observation profile
    // digest differs even with the same subject and observer.
    let frame = present.frame().expect("frame");
    assert!(verify_frame(&frame, &memory).is_ok());
    assert_eq!(
        verify_frame(&frame, &load_over_memory).unwrap_err().code,
        "frame_binding_mismatch"
    );
    // Claims and refusals: the memory claim under the load row, and a memory
    // detector refusal naming `nq.host` v1.
    assert_eq!(
        classify_outcome_for(&present.nq.artifact, LOAD, Some(LOAD.spec().claim_id))
            .unwrap_err()
            .code,
        "artifact_claim_mismatch"
    );
    let refused =
        synthetic_record(&memory, SyntheticOutcome::CannotEvaluate, 2, 7, 3).expect("record");
    assert_eq!(
        classify_outcome_for(&refused.nq.artifact, MEMORY, None).expect("classifies"),
        NqDetectorStateV1::CannotEvaluate
    );
    assert_eq!(
        classify_outcome_for(&refused.nq.artifact, LOAD, None)
            .unwrap_err()
            .code,
        "artifact_ladder"
    );
    let mut foreign = refused.nq.artifact.clone();
    foreign["outcome"]["refusals"][0]["origin"]["payload"]["refusal"]["profile"] =
        serde_json::json!({"id": LOAD.spec().nq_profile_id, "version": 1});
    assert_eq!(
        classify_outcome_for(&foreign, MEMORY, None)
            .unwrap_err()
            .code,
        "artifact_ladder"
    );
    // The filesystem row cannot even seal the memory enrollment.
    let (nq, pulse) = synthetic_enrollment_for(MEMORY);
    assert_eq!(
        CorrespondenceProfileV1::seal_for(FS, nq, pulse)
            .unwrap_err()
            .code,
        "invalid_subject"
    );
}

#[test]
fn a_port_enrolled_for_the_load_row_over_the_same_subject_is_refused_before_custody() {
    let memory = synthetic_profile_for(MEMORY).expect("memory profile");
    let load_over_memory = load_profile_over_memory_enrollment();
    let root = tempfile::tempdir().expect("tempdir");
    // The port's enrollment equals the memory profile's NQ enrollment; the
    // co-producer for the load-row profile accepts the port, then the first
    // acquisition is refused on the question pin before any delivery.
    let journal = root.path().join("shared-prefix.journal");
    let reactor = start_reactor(&load_over_memory, incarnation(), "shared-prefix", &journal)
        .expect("reactor");
    let memory_port = FakeNq::new(memory.clone(), SyntheticOutcome::Present);
    let witness = FixedSubjectIncarnation(incarnation());
    let mut coproducer = Coproducer::begin(
        &load_over_memory,
        &memory_port,
        &witness,
        &root.path().join("intent"),
        &root.path().join("audit"),
    )
    .expect("same enrollment binds");
    let refusal = coproducer
        .run_occurrence(&reactor)
        .expect_err("a memory judgment never verifies under the load row");
    assert_eq!(refusal.code, "artifact_pin_mismatch");
    let certificate = reactor
        .snapshot()
        .certificates
        .into_iter()
        .find(|certificate| certificate.consumer == load_over_memory.consumer())
        .expect("certificate");
    assert!(
        certificate.supporting_evidence_ids.is_empty(),
        "nothing was delivered"
    );
    reactor.shutdown().expect("shutdown");
}

#[test]
fn memory_co_production_verifies_with_the_120_s_window_and_its_question() {
    let profile = synthetic_profile_for(MEMORY).expect("memory profile");
    let root = tempfile::tempdir().expect("tempdir");
    let journal = root.path().join("memory.journal");
    let reactor = start_reactor(&profile, incarnation(), "memory", &journal).expect("reactor");
    let nq = FakeNq::new(profile.clone(), SyntheticOutcome::ExplicitlyAbsent);
    let witness = FixedSubjectIncarnation(incarnation());
    let mut coproducer = Coproducer::begin(
        &profile,
        &nq,
        &witness,
        &root.path().join("intent"),
        &root.path().join("audit"),
    )
    .expect("coproducer");
    assert_eq!(coproducer.question(), MEMORY);
    for (outcome, state) in [
        (
            SyntheticOutcome::ExplicitlyAbsent,
            NqDetectorStateV1::ExplicitlyAbsent,
        ),
        (SyntheticOutcome::Present, NqDetectorStateV1::Present),
        (
            SyntheticOutcome::CannotEvaluate,
            NqDetectorStateV1::CannotEvaluate,
        ),
    ] {
        nq.set_outcome(outcome);
        let result = coproducer.run_occurrence(&reactor).expect("occurrence");
        assert!(
            result
                .acquisition_id
                .starts_with(MEMORY.spec().acquisition_id_prefix)
        );
        assert_eq!(result.nq_detector_state, state);
        let OccurrenceOutcomeV1::Verified(verified) = result.outcome else {
            panic!("audit only")
        };
        assert_eq!(verified.question(), MEMORY);
        assert_eq!(verified.subject().as_str(), SYNTHETIC_MEMORY_SUBJECT);
        let certificate = reactor
            .snapshot()
            .certificates
            .into_iter()
            .find(|certificate| certificate.consumer == profile.consumer())
            .expect("certificate");
        assert_eq!(certificate.subject_scope.scope, MEMORY.spec().pulse_scope);
        let remaining = certificate
            .earliest_support_expiry_monotonic_ms
            .expect("expiry")
            .saturating_sub(certificate.evaluated_at_monotonic_ms);
        assert!(remaining > 0);
        assert!(
            remaining <= MEMORY.frame_validity_ms() - verified.delivery().holding_delay_ms,
            "support {remaining} ms exceeds the 120 s row's lifetime law"
        );
        assert!(remaining < LOAD.frame_validity_ms());
        verify_certificate_binding(
            &certificate,
            &profile,
            verified.evidence_ref(),
            verified.subject_incarnation(),
            verified.delivery().holding_delay_ms,
        )
        .expect("binding under the memory row");
        // The same certificate, same subject and consumer id, never binds
        // under a load-row profile sealed over this enrollment: the scope is
        // the memory row's.
        let (nq_enrollment, pulse_enrollment) = synthetic_enrollment_for(MEMORY);
        let load_over_memory =
            CorrespondenceProfileV1::seal_for(LOAD, nq_enrollment, pulse_enrollment)
                .expect("shared prefix seals");
        assert_eq!(
            verify_certificate_binding(
                &certificate,
                &load_over_memory,
                verified.evidence_ref(),
                verified.subject_incarnation(),
                verified.delivery().holding_delay_ms,
            )
            .unwrap_err()
            .code,
            "certificate_binding_mismatch"
        );
        let bytes = std::fs::read(&result.record_path).expect("record");
        assert_eq!(
            verify_audit_record(&bytes, &profile)
                .expect("verifies")
                .nq_detector_state,
            state
        );
    }
    reactor.shutdown().expect("shutdown");
}
