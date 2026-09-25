//! The inode row exercises what no earlier row could: it shares the capacity
//! row's subject prefix (`host-filesystem:`) *and* its frame validity
//! (298 999 ms), and its synthetic enrollment names the exact capacity
//! subject, because NQ asks both questions of one filesystem. Neither the
//! subject nor the validity separates the two rows; only the question does.
//! A capacity-row profile therefore seals over the inode enrollment (and the
//! reverse), and every later check must refuse on the question alone.

use pulse_nq_load_correspondence::fixture::{
    FakeNq, SYNTHETIC_FILESYSTEM_INODES_SUBJECT, SYNTHETIC_FILESYSTEM_SUBJECT,
    SYNTHETIC_OBSERVER_INCARNATION, SYNTHETIC_SUBJECT_INCARNATION, SyntheticOutcome, reseal,
    start_reactor, synthetic_enrollment_for, synthetic_profile_for, synthetic_record,
};
use pulse_nq_load_correspondence::{
    Coproducer, CorrespondenceProfileV1, FixedSubjectIncarnation, INGRESS_FENCE_MS,
    NqDetectorStateV1, OccurrenceOutcomeV1, QuestionV1, build_frame, check_disjoint_enrollment,
    check_holding_delay_for, classify_outcome_for, verify_artifact, verify_audit_record,
    verify_certificate_binding, verify_frame,
};
use pulse_types::IncarnationId;

const INODES: QuestionV1 = QuestionV1::HostFilesystemInodePressureV1;
const CAPACITY: QuestionV1 = QuestionV1::HostFilesystemCapacityPressureV1;
/// The rows whose prefix differs: none of them can even seal over the
/// filesystem subject.
const DISJOINT: [QuestionV1; 3] = [
    QuestionV1::HostLoadPressureV1,
    QuestionV1::HostMemoryPressureStallV1,
    QuestionV1::SystemdUnitRequiredActiveV1,
];

fn incarnation() -> IncarnationId {
    IncarnationId::new(SYNTHETIC_SUBJECT_INCARNATION)
}

/// A profile of `row` sealed over the other filesystem row's enrollment: the
/// shared prefix lets it seal, so every later check must refuse on the
/// question.
fn profile_over_enrollment_of(row: QuestionV1, enrolled: QuestionV1) -> CorrespondenceProfileV1 {
    let (nq, pulse) = synthetic_enrollment_for(enrolled);
    assert_eq!(nq.subject_id, SYNTHETIC_FILESYSTEM_SUBJECT);
    CorrespondenceProfileV1::seal_for(row, nq, pulse).expect("shared prefix seals")
}

#[test]
fn the_inode_row_shares_the_capacity_subject_and_validity_and_differs_only_by_question() {
    assert_eq!(
        SYNTHETIC_FILESYSTEM_INODES_SUBJECT,
        SYNTHETIC_FILESYSTEM_SUBJECT
    );
    assert_eq!(INODES.spec().subject_prefix, CAPACITY.spec().subject_prefix);
    assert_eq!(INODES.spec().reliance_window_ms, 300_000);
    assert_eq!(INODES.frame_validity_ms(), 300_000 - INGRESS_FENCE_MS - 1);
    assert_eq!(INODES.frame_validity_ms(), 298_999);
    assert_eq!(INODES.frame_validity_ms(), CAPACITY.frame_validity_ms());
    let inodes = synthetic_profile_for(INODES).expect("inode profile");
    let capacity = synthetic_profile_for(CAPACITY).expect("capacity profile");
    assert_eq!(inodes.nq.subject_id, capacity.nq.subject_id);
    assert_eq!(inodes.constants.frame_validity_ms, 298_999);
    assert_eq!(
        inodes
            .reliance_policy()
            .expect("policy")
            .maximum_validity_ms,
        capacity
            .reliance_policy()
            .expect("policy")
            .maximum_validity_ms
    );
    // What does differ: the question, its scope and observer/consumer, the
    // observation profile, and therefore the profile digest.
    assert_eq!(inodes.question().expect("question"), INODES);
    assert_eq!(capacity.question().expect("question"), CAPACITY);
    assert_ne!(inodes.digest(), capacity.digest());
    assert_ne!(inodes.consumer(), capacity.consumer());
    assert_ne!(
        inodes.pulse_observation_profile().expect("profile"),
        capacity.pulse_observation_profile().expect("profile")
    );
    assert_ne!(
        inodes.reliance_policy().expect("policy").scope,
        capacity.reliance_policy().expect("policy").scope
    );
    // Both profiles may share one reactor: the same subject under different
    // questions is not an overlap, while a reused consumer identity is.
    check_disjoint_enrollment(&[&capacity, &inodes]).expect("disjoint by question");
    let mut reused_consumer = inodes.clone();
    reused_consumer.pulse.consumer_id = capacity.pulse.consumer_id.clone();
    assert_eq!(
        check_disjoint_enrollment(&[&capacity, &reused_consumer])
            .unwrap_err()
            .code,
        "enrollment_overlap"
    );
    // The lifetime law is the same law: a delay lawful under one row is
    // lawful under the other, and the boundary is shared.
    let frame = build_frame(
        &inodes,
        incarnation(),
        IncarnationId::new(SYNTHETIC_OBSERVER_INCARNATION),
        1,
        0,
    )
    .expect("frame");
    assert_eq!(frame.validity_ms, 298_999);
    for row in [INODES, CAPACITY] {
        assert!(check_holding_delay_for(row, 298_998).is_ok());
        assert_eq!(
            check_holding_delay_for(row, 298_999).unwrap_err().code,
            "holding_delay_exceeds_validity"
        );
    }
    // A frame carrying the capacity validity is not a validity mismatch under
    // the inode row (the validities are equal); it is still refused, on the
    // observation profile binding, when it was sealed for the other row.
    let mut capacity_validity = frame.clone();
    capacity_validity.validity_ms = CAPACITY.frame_validity_ms();
    verify_frame(&capacity_validity.seal(), &inodes).expect("equal validity is this row's");
    let mut held =
        synthetic_record(&inodes, SyntheticOutcome::ExplicitlyAbsent, 1, 7, 3).expect("record");
    held.delivery.holding_delay_ms = 298_999;
    let held = reseal(held).expect("reseal");
    assert_eq!(
        verify_audit_record(&held.canonical_bytes().expect("bytes"), &inodes)
            .unwrap_err()
            .code,
        "holding_delay_exceeds_validity"
    );
    let boundary = synthetic_record(
        &inodes,
        SyntheticOutcome::ExplicitlyAbsent,
        2,
        298_998,
        INGRESS_FENCE_MS,
    )
    .expect("record");
    verify_audit_record(&boundary.canonical_bytes().expect("bytes"), &inodes)
        .expect("boundary verifies");
}

#[test]
fn a_capacity_profile_seals_over_the_inode_enrollment_and_every_check_refuses_on_the_question() {
    for (own, other) in [(INODES, CAPACITY), (CAPACITY, INODES)] {
        let profile = synthetic_profile_for(own).expect("profile");
        let foreign = profile_over_enrollment_of(other, own);
        assert_eq!(foreign.nq, profile.nq, "{own:?}: the same enrollment");
        assert_eq!(foreign.question().expect("question"), other);
        assert_eq!(
            foreign.constants.frame_validity_ms,
            profile.constants.frame_validity_ms
        );
        assert_ne!(foreign.digest(), profile.digest());

        // The first artifact under the other row's profile: the question pin.
        let present =
            synthetic_record(&profile, SyntheticOutcome::Present, 1, 7, 3).expect("record");
        let artifact = serde_jcs::to_vec(&present.nq.artifact).expect("canonical");
        assert!(verify_artifact(&artifact, &profile).is_ok());
        assert_eq!(
            verify_artifact(&artifact, &foreign).unwrap_err().code,
            "artifact_pin_mismatch",
            "{own:?} artifact under {other:?}"
        );
        // The audit record under the other row's profile: the record schema.
        assert_eq!(
            verify_audit_record(&present.canonical_bytes().expect("bytes"), &foreign)
                .unwrap_err()
                .code,
            "record_question_mismatch",
            "{own:?} record under {other:?}"
        );
        // A record of the other row over this enrollment under this profile.
        let foreign_record =
            synthetic_record(&foreign, SyntheticOutcome::Present, 1, 7, 3).expect("record");
        assert_eq!(
            verify_audit_record(&foreign_record.canonical_bytes().expect("bytes"), &profile)
                .unwrap_err()
                .code,
            "record_question_mismatch",
            "{other:?} record under {own:?}"
        );
        // The frame: same subject, same observer, same validity, different
        // observation profile digest.
        let frame = present.frame().expect("frame");
        assert!(verify_frame(&frame, &profile).is_ok());
        assert_eq!(
            verify_frame(&frame, &foreign).unwrap_err().code,
            "frame_binding_mismatch",
            "{own:?} frame under {other:?}"
        );
        // The claim under the other row.
        assert_eq!(
            classify_outcome_for(&present.nq.artifact, other, Some(other.spec().claim_id))
                .unwrap_err()
                .code,
            "artifact_claim_mismatch",
            "{own:?} claim under {other:?}"
        );
        // A detector refusal naming this row's profile is not the other row's
        // refusal, and one naming the other row's profile is not this row's.
        let refused =
            synthetic_record(&profile, SyntheticOutcome::CannotEvaluate, 2, 7, 3).expect("record");
        assert_eq!(
            classify_outcome_for(&refused.nq.artifact, own, None).expect("classifies"),
            NqDetectorStateV1::CannotEvaluate
        );
        assert_eq!(
            classify_outcome_for(&refused.nq.artifact, other, None)
                .unwrap_err()
                .code,
            "artifact_ladder",
            "{own:?} refusal under {other:?}"
        );
        let mut renamed = refused.nq.artifact.clone();
        renamed["outcome"]["refusals"][0]["origin"]["payload"]["refusal"]["profile"] = serde_json::json!({
            "id": other.spec().nq_profile_id,
            "version": other.spec().refusal_profile_version
        });
        assert_eq!(
            classify_outcome_for(&renamed, own, None).unwrap_err().code,
            "artifact_ladder",
            "refusal naming {other:?} under {own:?}"
        );
    }
    // The rows whose prefix differs cannot seal over the filesystem subject
    // at all, in either direction.
    for row in DISJOINT {
        let (nq, pulse) = synthetic_enrollment_for(INODES);
        assert_eq!(
            CorrespondenceProfileV1::seal_for(row, nq, pulse)
                .unwrap_err()
                .code,
            "invalid_subject",
            "{row:?} sealed over the filesystem subject"
        );
        let (nq, pulse) = synthetic_enrollment_for(row);
        assert_eq!(
            CorrespondenceProfileV1::seal_for(INODES, nq, pulse)
                .unwrap_err()
                .code,
            "invalid_subject",
            "the inode row sealed over a {row:?} subject"
        );
    }
}

#[test]
fn a_port_enrolled_for_the_other_filesystem_row_over_the_same_subject_is_refused_before_custody() {
    for (own, other) in [(INODES, CAPACITY), (CAPACITY, INODES)] {
        let profile = synthetic_profile_for(own).expect("profile");
        let foreign = profile_over_enrollment_of(other, own);
        let root = tempfile::tempdir().expect("tempdir");
        // The port's enrollment equals the foreign profile's NQ enrollment;
        // the co-producer for the other row's profile accepts the port, then
        // the first acquisition is refused on the question pin before any
        // delivery.
        let journal = root.path().join("shared-subject.journal");
        let reactor =
            start_reactor(&foreign, incarnation(), "shared-subject", &journal).expect("reactor");
        let port = FakeNq::new(profile.clone(), SyntheticOutcome::Present);
        let witness = FixedSubjectIncarnation(incarnation());
        let mut coproducer = Coproducer::begin(
            &foreign,
            &port,
            &witness,
            &root.path().join("intent"),
            &root.path().join("audit"),
        )
        .expect("same enrollment binds");
        assert_eq!(coproducer.question(), other);
        let refusal = coproducer
            .run_occurrence(&reactor)
            .expect_err("a judgment of one filesystem question never verifies under the other");
        assert_eq!(
            refusal.code, "artifact_pin_mismatch",
            "{own:?} port under {other:?}"
        );
        let certificate = reactor
            .snapshot()
            .certificates
            .into_iter()
            .find(|certificate| certificate.consumer == foreign.consumer())
            .expect("certificate");
        assert!(
            certificate.supporting_evidence_ids.is_empty(),
            "nothing was delivered"
        );
        reactor.shutdown().expect("shutdown");
    }
}

#[test]
fn inode_co_production_verifies_with_its_own_scope_and_never_binds_under_the_capacity_row() {
    let profile = synthetic_profile_for(INODES).expect("inode profile");
    let root = tempfile::tempdir().expect("tempdir");
    let journal = root.path().join("inodes.journal");
    let reactor = start_reactor(&profile, incarnation(), "inodes", &journal).expect("reactor");
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
    assert_eq!(coproducer.question(), INODES);
    let capacity_over_inodes = profile_over_enrollment_of(CAPACITY, INODES);
    for (outcome, state) in [
        (
            SyntheticOutcome::ExplicitlyAbsent,
            NqDetectorStateV1::ExplicitlyAbsent,
        ),
        (SyntheticOutcome::Present, NqDetectorStateV1::Present),
        (
            SyntheticOutcome::CannotEvaluateTyped,
            NqDetectorStateV1::CannotEvaluate,
        ),
    ] {
        nq.set_outcome(outcome);
        let result = coproducer.run_occurrence(&reactor).expect("occurrence");
        assert!(
            result
                .acquisition_id
                .starts_with(INODES.spec().acquisition_id_prefix)
        );
        assert_eq!(result.nq_detector_state, state);
        let OccurrenceOutcomeV1::Verified(verified) = result.outcome else {
            panic!("audit only")
        };
        assert_eq!(verified.question(), INODES);
        assert_eq!(
            verified.subject().as_str(),
            SYNTHETIC_FILESYSTEM_INODES_SUBJECT
        );
        assert_eq!(verified.subject().as_str(), SYNTHETIC_FILESYSTEM_SUBJECT);
        if state == NqDetectorStateV1::CannotEvaluate {
            assert_eq!(
                verified
                    .owner_failure()
                    .map(|failure| failure.code.as_str()),
                Some("filesystem_identity_mismatch")
            );
        }
        let certificate = reactor
            .snapshot()
            .certificates
            .into_iter()
            .find(|certificate| certificate.consumer == profile.consumer())
            .expect("certificate");
        assert_eq!(certificate.subject_scope.scope, INODES.spec().pulse_scope);
        assert_ne!(certificate.subject_scope.scope, CAPACITY.spec().pulse_scope);
        assert_eq!(
            certificate.subject_scope.subject.as_str(),
            SYNTHETIC_FILESYSTEM_SUBJECT
        );
        let remaining = certificate
            .earliest_support_expiry_monotonic_ms
            .expect("expiry")
            .saturating_sub(certificate.evaluated_at_monotonic_ms);
        assert!(remaining > 0);
        assert!(
            remaining <= INODES.frame_validity_ms() - verified.delivery().holding_delay_ms,
            "support {remaining} ms exceeds the row's lifetime law"
        );
        verify_certificate_binding(
            &certificate,
            &profile,
            verified.evidence_ref(),
            verified.subject_incarnation(),
            verified.delivery().holding_delay_ms,
        )
        .expect("binding under the inode row");
        // The same certificate, same subject and same validity, never binds
        // under a capacity-row profile sealed over this enrollment: the scope
        // is the inode row's.
        assert_eq!(
            verify_certificate_binding(
                &certificate,
                &capacity_over_inodes,
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
        for other in [CAPACITY, DISJOINT[0], DISJOINT[1], DISJOINT[2]] {
            let other_profile = synthetic_profile_for(other).expect("other");
            assert_eq!(
                verify_audit_record(&bytes, &other_profile)
                    .unwrap_err()
                    .code,
                "record_question_mismatch",
                "{other:?}"
            );
        }
    }
    reactor.shutdown().expect("shutdown");
}
