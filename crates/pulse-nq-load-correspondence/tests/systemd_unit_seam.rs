//! The systemd unit row is the first categorical (unit lifecycle) condition
//! and the first whose NQ profile is a second revision of an existing profile
//! id (`nq.systemd_unit` v1 is the operator-beta fixture contract). The seam
//! must carry it with no new field: its own 60 s reliance through the shared
//! validity law, its own `systemd-unit:` prefix, and a refusal pin that names
//! profile version 2 so a v1 detector refusal is never taken for its own.

use pulse_nq_load_correspondence::fixture::{
    FakeNq, SYNTHETIC_OBSERVER_INCARNATION, SYNTHETIC_SUBJECT_INCARNATION,
    SYNTHETIC_SYSTEMD_UNIT_SUBJECT, SyntheticOutcome, Tamper, reidentify_artifact, reseal,
    start_reactor, synthetic_artifact_with_code, synthetic_enrollment_for, synthetic_profile_for,
    synthetic_record,
};
use pulse_nq_load_correspondence::{
    Coproducer, CorrespondenceProfileV1, FixedSubjectIncarnation, INGRESS_FENCE_MS,
    NqDetectorStateV1, OccurrenceOutcomeV1, QuestionV1, build_frame, check_holding_delay_for,
    classify_outcome_for, verify_artifact, verify_audit_record, verify_certificate_binding,
    verify_frame,
};
use pulse_types::IncarnationId;

const UNIT: QuestionV1 = QuestionV1::SystemdUnitRequiredActiveV1;
const OTHERS: [QuestionV1; 4] = [
    QuestionV1::HostLoadPressureV1,
    QuestionV1::HostFilesystemCapacityPressureV1,
    QuestionV1::HostMemoryPressureStallV1,
    QuestionV1::HostFilesystemInodePressureV1,
];

fn incarnation() -> IncarnationId {
    IncarnationId::new(SYNTHETIC_SUBJECT_INCARNATION)
}

#[test]
fn the_unit_row_derives_its_own_validity_through_the_shared_law() {
    assert_eq!(UNIT.spec().reliance_window_ms, 60_000);
    assert_eq!(UNIT.frame_validity_ms(), 60_000 - INGRESS_FENCE_MS - 1);
    assert_eq!(UNIT.frame_validity_ms(), 58_999);
    let profile = synthetic_profile_for(UNIT).expect("unit profile");
    assert_eq!(profile.constants.frame_validity_ms, 58_999);
    assert_eq!(
        profile
            .reliance_policy()
            .expect("policy")
            .maximum_validity_ms,
        58_999
    );
    let frame = build_frame(
        &profile,
        incarnation(),
        IncarnationId::new(SYNTHETIC_OBSERVER_INCARNATION),
        1,
        0,
    )
    .expect("frame");
    assert_eq!(frame.validity_ms, 58_999);
    assert!(check_holding_delay_for(UNIT, 58_998).is_ok());
    assert_eq!(
        check_holding_delay_for(UNIT, 58_999).unwrap_err().code,
        "holding_delay_exceeds_validity"
    );
    for other in OTHERS {
        let mut other_validity = frame.clone();
        other_validity.validity_ms = other.frame_validity_ms();
        assert_eq!(
            verify_frame(&other_validity.seal(), &profile)
                .unwrap_err()
                .code,
            "frame_validity_mismatch"
        );
        // Every other row's window is longer: a delay lawful there is not here.
        assert!(check_holding_delay_for(other, 100_000).is_ok());
    }
    let mut held =
        synthetic_record(&profile, SyntheticOutcome::ExplicitlyAbsent, 1, 7, 3).expect("record");
    held.delivery.holding_delay_ms = 100_000;
    let held = reseal(held).expect("reseal");
    assert_eq!(
        verify_audit_record(&held.canonical_bytes().expect("bytes"), &profile)
            .unwrap_err()
            .code,
        "holding_delay_exceeds_validity"
    );
    let boundary = synthetic_record(
        &profile,
        SyntheticOutcome::ExplicitlyAbsent,
        2,
        58_998,
        INGRESS_FENCE_MS,
    )
    .expect("record");
    verify_audit_record(&boundary.canonical_bytes().expect("bytes"), &profile)
        .expect("boundary verifies");
}

#[test]
fn the_unit_prefix_is_its_own_and_no_other_row_seals_over_it() {
    let (unit_nq, unit_pulse) = synthetic_enrollment_for(UNIT);
    assert_eq!(unit_nq.subject_id, SYNTHETIC_SYSTEMD_UNIT_SUBJECT);
    for other in OTHERS {
        assert_eq!(
            CorrespondenceProfileV1::seal_for(other, unit_nq.clone(), unit_pulse.clone())
                .unwrap_err()
                .code,
            "invalid_subject",
            "{other:?} sealed over a systemd-unit subject"
        );
        let (other_nq, other_pulse) = synthetic_enrollment_for(other);
        assert_eq!(
            CorrespondenceProfileV1::seal_for(UNIT, other_nq, other_pulse)
                .unwrap_err()
                .code,
            "invalid_subject",
            "the unit row sealed over a {other:?} subject"
        );
    }
    let mut bare = unit_nq;
    bare.subject_id = "systemd-unit:".to_owned();
    assert_eq!(
        CorrespondenceProfileV1::seal_for(UNIT, bare, unit_pulse)
            .unwrap_err()
            .code,
        "invalid_subject"
    );
}

#[test]
fn a_detector_refusal_naming_the_fixture_revision_is_not_the_unit_rows_refusal() {
    let profile = synthetic_profile_for(UNIT).expect("unit profile");
    let bytes = synthetic_artifact_with_code(
        &profile,
        "constellation-nq-systemd-unit:v1:refusal",
        SyntheticOutcome::CannotEvaluateTyped,
        Tamper::None,
        None,
    )
    .expect("artifact");
    let verified = verify_artifact(&bytes, &profile).expect("the v2 refusal verifies");
    assert_eq!(verified.state, NqDetectorStateV1::CannotEvaluate);
    assert_eq!(
        verified
            .owner_failure
            .as_ref()
            .map(|failure| failure.code.as_str()),
        Some("unit_name_not_canonical")
    );
    let artifact: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    let pointer = "/outcome/refusals/0/origin/payload/refusal/profile";
    assert_eq!(
        artifact.pointer(pointer),
        Some(&serde_json::json!({"id": "nq.systemd_unit", "version": 2}))
    );
    for version in [
        serde_json::json!(1),
        serde_json::json!("2"),
        serde_json::json!(3),
    ] {
        let mut other_revision = artifact.clone();
        *other_revision.pointer_mut(pointer).expect("profile") =
            serde_json::json!({"id": "nq.systemd_unit", "version": version});
        reidentify_artifact(&mut other_revision).expect("reidentify");
        assert_eq!(
            classify_outcome_for(&other_revision, UNIT, None)
                .unwrap_err()
                .code,
            "artifact_ladder",
            "refusal naming nq.systemd_unit version {version}"
        );
    }
}

#[test]
fn unit_co_production_verifies_with_the_60_s_window_and_its_question() {
    let profile = synthetic_profile_for(UNIT).expect("unit profile");
    let root = tempfile::tempdir().expect("tempdir");
    let journal = root.path().join("unit.journal");
    let reactor = start_reactor(&profile, incarnation(), "unit", &journal).expect("reactor");
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
    assert_eq!(coproducer.question(), UNIT);
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
                .starts_with(UNIT.spec().acquisition_id_prefix)
        );
        assert_eq!(result.nq_detector_state, state);
        let OccurrenceOutcomeV1::Verified(verified) = &result.outcome else {
            let OccurrenceOutcomeV1::AuditOnly { refusal } = &result.outcome else {
                unreachable!()
            };
            let snapshot = reactor.snapshot();
            panic!(
                "{outcome:?}: audit only: {refusal}; holding_delay_ms={}; ingress_fence_ms={}; reactor_condition={:?}; reactor_detail={}",
                result.delivery.holding_delay_ms,
                result.delivery.ingress_fence_ms,
                snapshot.condition,
                snapshot.condition_detail
            )
        };
        assert_eq!(verified.question(), UNIT);
        assert_eq!(verified.subject().as_str(), SYNTHETIC_SYSTEMD_UNIT_SUBJECT);
        let certificate = reactor
            .snapshot()
            .certificates
            .into_iter()
            .find(|certificate| certificate.consumer == profile.consumer())
            .expect("certificate");
        assert_eq!(certificate.subject_scope.scope, UNIT.spec().pulse_scope);
        let remaining = certificate
            .earliest_support_expiry_monotonic_ms
            .expect("expiry")
            .saturating_sub(certificate.evaluated_at_monotonic_ms);
        assert!(remaining > 0);
        assert!(
            remaining <= UNIT.frame_validity_ms() - verified.delivery().holding_delay_ms,
            "support {remaining} ms exceeds the 60 s row's lifetime law"
        );
        verify_certificate_binding(
            &certificate,
            &profile,
            verified.evidence_ref(),
            verified.subject_incarnation(),
            verified.delivery().holding_delay_ms,
        )
        .expect("binding under the unit row");
        let bytes = std::fs::read(&result.record_path).expect("record");
        assert_eq!(
            verify_audit_record(&bytes, &profile)
                .expect("verifies")
                .nq_detector_state,
            state
        );
        for other in OTHERS {
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
