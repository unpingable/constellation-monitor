//! Co-production against a real local Pulse reactor with an in-process NQ
//! double. These tests prove the evidence-reference format, the lifetime law,
//! delivery boundaries, replay non-refresh, and every pre-delivery refusal.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use pulse_nq_load_correspondence::fixture::{
    FakeNq, SYNTHETIC_SUBJECT_INCARNATION, SyntheticOutcome, Tamper, start_reactor,
    synthetic_enrollment, synthetic_profile,
};
use pulse_nq_load_correspondence::{
    Coproducer, CorrespondenceProfileV1, FRAME_VALIDITY_MS, FixedSubjectIncarnation,
    INGRESS_FENCE_MS, NqDetectorStateV1, OccurrenceOutcomeV1, SubjectIncarnationWitness,
    check_holding_delay, check_ingress_fence, frame_ingress, occurrence_path, verify_audit_record,
    verify_certificate_binding,
};
use pulse_runtime::LocalCrashReactor;
use pulse_types::{IncarnationId, JudgmentCategoryV1, RelianceSupportCertificateV1};

static SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct Harness {
    profile: CorrespondenceProfileV1,
    reactor: LocalCrashReactor,
    journal: PathBuf,
    intent_dir: PathBuf,
    audit_dir: PathBuf,
    _root: tempfile::TempDir,
}

fn harness(label: &str) -> Harness {
    let profile = synthetic_profile().expect("synthetic profile");
    let root = tempfile::tempdir().expect("tempdir");
    let unique = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let journal = root.path().join(format!("{label}-{unique}.journal"));
    let reactor = start_reactor(
        &profile,
        IncarnationId::new(SYNTHETIC_SUBJECT_INCARNATION),
        &format!("{label}-{unique}"),
        &journal,
    )
    .expect("reactor");
    Harness {
        profile,
        reactor,
        journal,
        intent_dir: root.path().join("intent"),
        audit_dir: root.path().join("audit"),
        _root: root,
    }
}

impl Harness {
    fn witness(&self) -> FixedSubjectIncarnation {
        FixedSubjectIncarnation(IncarnationId::new(SYNTHETIC_SUBJECT_INCARNATION))
    }

    fn certificate(&self) -> Option<RelianceSupportCertificateV1> {
        self.reactor
            .snapshot()
            .certificates
            .into_iter()
            .find(|certificate| certificate.consumer == self.profile.consumer())
    }

    fn finish(self) {
        self.reactor.shutdown().expect("shutdown");
        let _ = fs::remove_file(self.journal);
    }
}

#[test]
fn co_production_binds_the_frame_pulse_certifies_and_the_record_verifies() {
    let harness = harness("positive");
    let nq = FakeNq::new(harness.profile.clone(), SyntheticOutcome::Present);
    let witness = harness.witness();
    let mut coproducer = Coproducer::begin(
        &harness.profile,
        &nq,
        &witness,
        &harness.intent_dir,
        &harness.audit_dir,
    )
    .expect("coproducer");
    let result = coproducer
        .run_occurrence(&harness.reactor)
        .expect("occurrence");
    let OccurrenceOutcomeV1::Verified(verified) = &result.outcome else {
        panic!("expected verified outcome, got {:?}", result.outcome);
    };
    assert_eq!(verified.nq_detector_state(), NqDetectorStateV1::Present);
    assert_eq!(verified.evidence_ref(), result.evidence_ref);
    assert!(
        result
            .acquisition_id
            .starts_with("constellation-nq-load:v1:sha256:")
    );
    assert_eq!(result.acquisition_id.len(), 96);

    // The reproduced evidence-reference format equals Pulse's own.
    let certificate = harness.certificate().expect("certificate");
    assert_eq!(certificate.judgment, JudgmentCategoryV1::Current);
    assert_eq!(
        certificate.supporting_evidence_ids,
        vec![result.evidence_ref.clone()]
    );
    assert_eq!(
        certificate.certificate_id.as_str(),
        verified.certificate_id()
    );

    // Lifetime law: the certificate never leaves more than V - d.
    let remaining = certificate.earliest_support_expiry_monotonic_ms.unwrap()
        - certificate.evaluated_at_monotonic_ms;
    assert!(remaining > 0);
    assert!(remaining <= FRAME_VALIDITY_MS - result.delivery.holding_delay_ms);
    assert!(result.delivery.ingress_fence_ms <= INGRESS_FENCE_MS);

    // Intent and audit custody exist and the audit record verifies offline.
    assert!(occurrence_path(&harness.intent_dir, &result.acquisition_id).is_file());
    let bytes = fs::read(&result.record_path).expect("record");
    let verdict = verify_audit_record(&bytes, &harness.profile).expect("audit verifies");
    assert_eq!(verdict.correspondence_id, result.correspondence_id);
    assert_eq!(verdict.nq_detector_state, NqDetectorStateV1::Present);
    assert_eq!(verdict.artifact_id, verified.artifact_id());
    assert_eq!(nq.acquisition_count(), 1);
    harness.finish();
}

#[test]
fn an_alternate_coherent_port_enrollment_refuses_before_occurrence_custody() {
    let harness = harness("enrollment-mismatch");
    let (mut alternate_nq, alternate_pulse) = synthetic_enrollment();
    alternate_nq.instance_id = "host-local-alternate".to_owned();
    let alternate_profile = CorrespondenceProfileV1::seal(alternate_nq, alternate_pulse)
        .expect("coherent alternate profile");
    let alternate_port = FakeNq::new(alternate_profile, SyntheticOutcome::Present);
    let witness = harness.witness();

    let result = Coproducer::begin(
        &harness.profile,
        &alternate_port,
        &witness,
        &harness.intent_dir,
        &harness.audit_dir,
    );
    let error = match result {
        Ok(_) => panic!("a port for another sealed enrollment cannot enter this occurrence"),
        Err(error) => error,
    };
    assert_eq!(error.code, "nq_enrollment_mismatch");
    assert!(
        !harness.intent_dir.exists() && !harness.audit_dir.exists(),
        "the mismatch is refused before custody paths are created"
    );
    assert_eq!(alternate_port.acquire_attempt_count(), 0);
    assert_eq!(alternate_port.replay_attempt_count(), 0);
    harness.finish();
}

#[test]
fn a_lost_acquire_response_reconciles_once_without_a_replacement_effect_or_frame() {
    let harness = harness("response-loss");
    let nq = FakeNq::new(harness.profile.clone(), SyntheticOutcome::Present);
    nq.set_tamper(Tamper::AcquireResponseLost);
    let witness = harness.witness();
    let mut coproducer = Coproducer::begin(
        &harness.profile,
        &nq,
        &witness,
        &harness.intent_dir,
        &harness.audit_dir,
    )
    .expect("coproducer");

    let result = coproducer
        .run_occurrence(&harness.reactor)
        .expect("same-process replay reconciles the lost response");
    assert!(matches!(result.outcome, OccurrenceOutcomeV1::Verified(_)));
    assert_eq!(result.sequence, 1);
    assert_eq!(nq.acquire_attempt_count(), 1, "never acquire twice");
    assert_eq!(nq.acquisition_count(), 1, "one durable NQ acquisition");
    assert_eq!(
        nq.replay_attempt_count(),
        2,
        "one reconciliation replay plus the ordinary byte-equality replay"
    );
    assert_eq!(
        fs::read_dir(&harness.intent_dir)
            .expect("intent directory")
            .count(),
        1,
        "no replacement intent or frame"
    );
    assert_eq!(
        fs::read_dir(&harness.audit_dir)
            .expect("audit directory")
            .count(),
        1,
        "one effect yields one audit record"
    );
    let record = pulse_nq_load_correspondence::CorrespondenceRecordV1::decode_canonical(
        &fs::read(&result.record_path).expect("record"),
    )
    .expect("record decodes");
    assert_eq!(record.acquisition_id, result.acquisition_id);
    assert_eq!(record.pulse.evidence_ref, result.evidence_ref);
    let certificate = harness.certificate().expect("certificate");
    assert_eq!(
        certificate.supporting_evidence_ids,
        vec![result.evidence_ref],
        "Pulse received only the original precommitted frame"
    );
    harness.finish();
}

#[test]
fn every_synthetic_outcome_delivers_and_carries_nq_state_unchanged() {
    let harness = harness("outcomes");
    let nq = FakeNq::new(harness.profile.clone(), SyntheticOutcome::ExplicitlyAbsent);
    let witness = harness.witness();
    let mut coproducer = Coproducer::begin(
        &harness.profile,
        &nq,
        &witness,
        &harness.intent_dir,
        &harness.audit_dir,
    )
    .expect("coproducer");
    for outcome in [
        SyntheticOutcome::ExplicitlyAbsent,
        SyntheticOutcome::CannotEvaluate,
        SyntheticOutcome::InputRefusal,
        SyntheticOutcome::ProviderNoResponse,
        SyntheticOutcome::Present,
    ] {
        nq.set_outcome(outcome);
        let result = coproducer
            .run_occurrence(&harness.reactor)
            .expect("occurrence");
        assert_eq!(result.nq_detector_state, outcome.expected_state());
        let OccurrenceOutcomeV1::Verified(verified) = &result.outcome else {
            let OccurrenceOutcomeV1::AuditOnly { refusal } = &result.outcome else {
                unreachable!()
            };
            let snapshot = harness.reactor.snapshot();
            panic!(
                "{outcome:?}: audit only: {refusal}; holding_delay_ms={}; ingress_fence_ms={}; reactor_condition={:?}; reactor_detail={}",
                result.delivery.holding_delay_ms,
                result.delivery.ingress_fence_ms,
                snapshot.condition,
                snapshot.condition_detail
            )
        };
        assert_eq!(verified.nq_detector_state(), outcome.expected_state());
        let certificate = harness.certificate().expect("certificate");
        assert_eq!(
            certificate.supporting_evidence_ids,
            vec![result.evidence_ref.clone()],
            "the newest frame replaces the previous supporting evidence"
        );
    }
    harness.finish();
}

#[test]
fn holding_delay_and_ingress_fence_boundaries_are_exact() {
    assert!(check_holding_delay(FRAME_VALIDITY_MS - 1).is_ok());
    assert_eq!(
        check_holding_delay(FRAME_VALIDITY_MS).unwrap_err().code,
        "holding_delay_exceeds_validity"
    );
    assert!(check_ingress_fence(INGRESS_FENCE_MS).is_ok());
    assert_eq!(
        check_ingress_fence(INGRESS_FENCE_MS + 1).unwrap_err().code,
        "ingress_fence_exceeded"
    );
    assert_eq!(FRAME_VALIDITY_MS + INGRESS_FENCE_MS + 1, 300_000);
}

#[test]
fn a_frame_held_for_its_whole_validity_is_stale_to_pulse_and_never_current() {
    let harness = harness("stale");
    let mut lineage =
        pulse_nq_load_correspondence::ObserverLineage::begin(&harness.profile).expect("lineage");
    let sealed = lineage
        .seal_next(
            &harness.profile,
            IncarnationId::new(SYNTHETIC_SUBJECT_INCARNATION),
        )
        .expect("seal");
    // Bypass the co-producer's own check to observe Pulse's law directly.
    harness
        .reactor
        .submit_input(frame_ingress(sealed.frame.clone(), FRAME_VALIDITY_MS))
        .expect("submit");
    let certificate = harness.certificate().expect("certificate");
    assert_ne!(certificate.judgment, JudgmentCategoryV1::Current);
    assert!(certificate.supporting_evidence_ids.is_empty());

    // One millisecond below validity is admitted with a one-millisecond window.
    let sealed = lineage
        .seal_next(
            &harness.profile,
            IncarnationId::new(SYNTHETIC_SUBJECT_INCARNATION),
        )
        .expect("seal");
    harness
        .reactor
        .submit_input(frame_ingress(sealed.frame.clone(), FRAME_VALIDITY_MS - 1))
        .expect("submit");
    let certificate = harness.certificate().expect("certificate");
    if certificate.judgment == JudgmentCategoryV1::Current {
        verify_certificate_binding(
            &certificate,
            &harness.profile,
            &sealed.evidence_ref,
            &sealed.subject_incarnation,
            FRAME_VALIDITY_MS - 1,
        )
        .expect("one millisecond of support satisfies the law");
        let remaining = certificate.earliest_support_expiry_monotonic_ms.unwrap()
            - certificate.evaluated_at_monotonic_ms;
        assert_eq!(remaining, 1);
    }
    harness.finish();
}

#[test]
fn resubmitting_the_same_frame_never_refreshes_support() {
    let harness = harness("duplicate");
    let nq = FakeNq::new(harness.profile.clone(), SyntheticOutcome::ExplicitlyAbsent);
    let witness = harness.witness();
    let mut coproducer = Coproducer::begin(
        &harness.profile,
        &nq,
        &witness,
        &harness.intent_dir,
        &harness.audit_dir,
    )
    .expect("coproducer");
    let result = coproducer
        .run_occurrence(&harness.reactor)
        .expect("occurrence");
    let before = harness.certificate().expect("certificate");
    let record = pulse_nq_load_correspondence::CorrespondenceRecordV1::decode_canonical(
        &fs::read(&result.record_path).expect("record"),
    )
    .expect("decode");
    std::thread::sleep(std::time::Duration::from_millis(5));
    harness
        .reactor
        .submit_input(frame_ingress(record.frame().expect("frame"), 0))
        .expect("duplicate submit is accepted as input");
    let after = harness.certificate().expect("certificate");
    // Pulse may re-evaluate on the duplicate (a new evaluation occurrence and
    // therefore a new certificate identity), but the supporting evidence and
    // its expiry are not refreshed.
    assert_eq!(
        before.supporting_evidence_ids,
        after.supporting_evidence_ids
    );
    assert_eq!(
        before.earliest_support_expiry_monotonic_ms,
        after.earliest_support_expiry_monotonic_ms
    );
    assert!(after.evaluated_at_monotonic_ms >= before.evaluated_at_monotonic_ms);
    harness.finish();
}

#[test]
fn pre_delivery_refusals_burn_the_sequence_and_deliver_nothing() {
    let harness = harness("refusals");
    let nq = FakeNq::new(harness.profile.clone(), SyntheticOutcome::Present);
    let witness = harness.witness();
    let mut coproducer = Coproducer::begin(
        &harness.profile,
        &nq,
        &witness,
        &harness.intent_dir,
        &harness.audit_dir,
    )
    .expect("coproducer");
    let cases = [
        (Tamper::AcquirePreLaunchFails, "nq_spawn"),
        (Tamper::AcquireFails, "acquire_reconciliation_failed"),
        (Tamper::ReplayDiffers, "replay_mismatch"),
        (Tamper::QualifyFails, "nq_refused"),
        (Tamper::ProvenanceRawMismatch, "provenance_mismatch"),
        (Tamper::ProvenanceOtherArtifact, "provenance_mismatch"),
        (Tamper::ProvenanceOtherRun, "provenance_mismatch"),
        (Tamper::ArtifactOtherSubject, "artifact_pin_mismatch"),
        (
            Tamper::ArtifactFreshSelectionRule,
            "artifact_selection_rule",
        ),
        (Tamper::ArtifactOtherQuestionDigest, "artifact_pin_mismatch"),
        (
            Tamper::ArtifactOtherProfileSemantic,
            "artifact_pin_mismatch",
        ),
        (Tamper::ArtifactOtherEvaluator, "artifact_pin_mismatch"),
        (Tamper::ArtifactOtherNode, "artifact_pin_mismatch"),
        (
            Tamper::ArtifactTwoSelectedInputs,
            "artifact_single_acquisition",
        ),
        (Tamper::ArtifactClaimDependsOnOtherInput, "artifact_ladder"),
        (
            Tamper::ArtifactPresentWithPartialCoverage,
            "artifact_ladder",
        ),
    ];
    let mut expected_sequence = 1;
    for (tamper, code) in cases {
        let replay_attempts_before = nq.replay_attempt_count();
        nq.set_tamper(tamper);
        let error = coproducer
            .run_occurrence(&harness.reactor)
            .expect_err("tampered occurrence must refuse");
        assert_eq!(error.code, code, "{tamper:?}: {error}");
        match tamper {
            Tamper::AcquirePreLaunchFails => assert_eq!(
                nq.replay_attempt_count(),
                replay_attempts_before,
                "a clear pre-launch failure must not attempt replay"
            ),
            Tamper::AcquireFails => assert_eq!(
                nq.replay_attempt_count(),
                replay_attempts_before + 1,
                "a post-launch refusal is reconciled only by one read-only replay"
            ),
            _ => {}
        }
        if tamper == Tamper::AcquireFails {
            assert!(error.detail.contains("original_acquire=nq_refused"));
            assert!(error.detail.len() <= 512, "reconciliation error is bounded");
        }
        expected_sequence += 1;
        assert_eq!(coproducer.lineage().next_sequence(), expected_sequence);
        let certificate = harness.certificate().expect("certificate");
        assert!(
            certificate.supporting_evidence_ids.is_empty(),
            "{tamper:?} must not deliver a frame"
        );
    }
    // A helper-origin refusal is not a detector cannot_evaluate.
    nq.set_outcome(SyntheticOutcome::CannotEvaluate);
    nq.set_tamper(Tamper::ArtifactHelperRefusalLabelledCannotEvaluate);
    let result = coproducer
        .run_occurrence(&harness.reactor)
        .expect("helper refusal is a valid not-evaluated outcome");
    assert_eq!(result.nq_detector_state, NqDetectorStateV1::NotEvaluated);

    // After the failures, an untampered occurrence still succeeds on the same
    // lineage; the burned sequences remain gaps.
    nq.set_tamper(Tamper::None);
    nq.set_outcome(SyntheticOutcome::Present);
    let result = coproducer
        .run_occurrence(&harness.reactor)
        .expect("occurrence");
    assert!(matches!(result.outcome, OccurrenceOutcomeV1::Verified(_)));
    assert_eq!(result.sequence, expected_sequence + 1);
    harness.finish();
}

#[test]
fn nq_command_errors_name_the_exact_post_intent_stage_and_acquisition() {
    let harness = harness("stage-errors");
    let nq = FakeNq::new(harness.profile.clone(), SyntheticOutcome::Present);
    let witness = harness.witness();
    let mut coproducer = Coproducer::begin(
        &harness.profile,
        &nq,
        &witness,
        &harness.intent_dir,
        &harness.audit_dir,
    )
    .expect("coproducer");
    let mut expected_sequence = 1;
    for (tamper, stage, code) in [
        (Tamper::AcquirePreLaunchFails, "acquire", "nq_spawn"),
        (
            Tamper::AcquireFails,
            "reconciliation_replay",
            "acquire_reconciliation_failed",
        ),
        (Tamper::ReplayDiffers, "mandatory_replay", "replay_mismatch"),
        (Tamper::QualifyFails, "qualify", "nq_refused"),
    ] {
        nq.set_tamper(tamper);
        let error = coproducer
            .run_occurrence(&harness.reactor)
            .expect_err("negative stage case must refuse");
        assert_eq!(error.code, code, "{tamper:?}: {error}");
        let matching_intents: Vec<serde_json::Value> = fs::read_dir(&harness.intent_dir)
            .expect("intent directory")
            .map(|entry| {
                let path = entry.expect("intent entry").path();
                serde_json::from_slice(&fs::read(path).expect("intent bytes")).expect("intent JSON")
            })
            .filter(|intent: &serde_json::Value| {
                intent["sequence"].as_u64() == Some(expected_sequence)
            })
            .collect();
        assert_eq!(matching_intents.len(), 1, "one exact intent sequence");
        let acquisition_id = matching_intents[0]["acquisition_id"]
            .as_str()
            .expect("intent acquisition identity");
        assert!(
            error.detail.contains(&format!("stage={stage};")),
            "{tamper:?}: {error}"
        );
        assert!(
            error
                .detail
                .contains(&format!("acquisition_id={acquisition_id};")),
            "{tamper:?}: {error}"
        );
        assert!(error.detail.len() <= 512, "stage detail is bounded");
        if tamper == Tamper::AcquireFails {
            assert!(error.detail.contains("original_acquire=nq_refused"));
            assert!(error.detail.contains("replay=nq_refused"));
            assert!(error.detail.contains("replacement_acquisition=false"));
            assert!(
                error
                    .detail
                    .contains("replay_detail=fixture: no such local successor")
            );
        }
        expected_sequence += 1;
    }
    harness.finish();
}

#[test]
fn certificate_binding_refuses_extra_evidence_wrong_incarnation_and_long_windows() {
    let harness = harness("binding");
    let nq = FakeNq::new(harness.profile.clone(), SyntheticOutcome::Present);
    let witness = harness.witness();
    let mut coproducer = Coproducer::begin(
        &harness.profile,
        &nq,
        &witness,
        &harness.intent_dir,
        &harness.audit_dir,
    )
    .expect("coproducer");
    let result = coproducer
        .run_occurrence(&harness.reactor)
        .expect("occurrence");
    let certificate = harness.certificate().expect("certificate");
    let incarnation = IncarnationId::new(SYNTHETIC_SUBJECT_INCARNATION);
    let delay = result.delivery.holding_delay_ms;
    verify_certificate_binding(
        &certificate,
        &harness.profile,
        &result.evidence_ref,
        &incarnation,
        delay,
    )
    .expect("exact binding holds");

    let mut extra = certificate.clone();
    extra
        .supporting_evidence_ids
        .push(format!("{}z", result.evidence_ref));
    extra.certificate_id = extra.compute_id();
    assert_eq!(
        verify_certificate_binding(
            &extra,
            &harness.profile,
            &result.evidence_ref,
            &incarnation,
            delay
        )
        .unwrap_err()
        .code,
        "certificate_evidence_mismatch"
    );

    assert_eq!(
        verify_certificate_binding(
            &certificate,
            &harness.profile,
            &result.evidence_ref,
            &IncarnationId::new("linux-boot:other"),
            delay
        )
        .unwrap_err()
        .code,
        "certificate_incarnation_mismatch"
    );

    assert_eq!(
        verify_certificate_binding(
            &certificate,
            &harness.profile,
            &result.evidence_ref,
            &incarnation,
            FRAME_VALIDITY_MS - 1
        )
        .unwrap_err()
        .code,
        "certificate_window_exceeds_law",
        "claiming a larger holding delay than measured shrinks the permitted window below the certificate's"
    );

    let mut other_incarnation = certificate.clone();
    other_incarnation.subject_scope.subject_incarnation = IncarnationId::new("linux-boot:other");
    other_incarnation.certificate_id = other_incarnation.compute_id();
    assert!(
        verify_certificate_binding(
            &other_incarnation,
            &harness.profile,
            &result.evidence_ref,
            &incarnation,
            delay
        )
        .is_err()
    );
    harness.finish();
}

struct ChangingWitness {
    calls: std::cell::Cell<u32>,
}

impl SubjectIncarnationWitness for ChangingWitness {
    fn current(&self) -> Result<IncarnationId, pulse_nq_load_correspondence::CorrespondenceError> {
        let call = self.calls.get();
        self.calls.set(call + 1);
        Ok(IncarnationId::new(if call == 0 {
            SYNTHETIC_SUBJECT_INCARNATION.to_owned()
        } else {
            "linux-boot:rebooted".to_owned()
        }))
    }
}

#[test]
fn a_changed_subject_incarnation_stops_before_sealing() {
    let harness = harness("reboot");
    let nq = FakeNq::new(harness.profile.clone(), SyntheticOutcome::Present);
    let witness = ChangingWitness {
        calls: std::cell::Cell::new(0),
    };
    let mut coproducer = Coproducer::begin(
        &harness.profile,
        &nq,
        &witness,
        &harness.intent_dir,
        &harness.audit_dir,
    )
    .expect("coproducer");
    let error = coproducer
        .run_occurrence(&harness.reactor)
        .expect_err("changed incarnation refuses");
    assert_eq!(error.code, "subject_incarnation_changed");
    assert_eq!(nq.acquisition_count(), 0);
    harness.finish();
}

#[test]
fn a_restarted_lineage_starts_a_new_incarnation_and_never_reuses_an_identity() {
    let harness = harness("restart");
    let nq = FakeNq::new(harness.profile.clone(), SyntheticOutcome::ExplicitlyAbsent);
    let witness = harness.witness();
    let first_result = {
        let mut first = Coproducer::begin(
            &harness.profile,
            &nq,
            &witness,
            &harness.intent_dir,
            &harness.audit_dir,
        )
        .expect("coproducer");
        first.run_occurrence(&harness.reactor).expect("occurrence")
    };
    let mut second = Coproducer::begin(
        &harness.profile,
        &nq,
        &witness,
        &harness.intent_dir,
        &harness.audit_dir,
    )
    .expect("second coproducer");
    let second_result = second
        .run_occurrence(&harness.reactor)
        .expect("second occurrence");
    assert_ne!(first_result.acquisition_id, second_result.acquisition_id);
    assert_ne!(first_result.evidence_ref, second_result.evidence_ref);
    assert_eq!(
        second_result.sequence, 1,
        "a new lineage restarts its sequence"
    );
    let certificate = harness.certificate().expect("certificate");
    // Pulse decides how a restarted observer stream is judged. Whatever it
    // decides, the earlier correspondence can no longer be the supporting
    // evidence, and the co-producer reported that exactly.
    assert_ne!(
        certificate.supporting_evidence_ids,
        vec![first_result.evidence_ref.clone()]
    );
    match &second_result.outcome {
        OccurrenceOutcomeV1::Verified(verified) => {
            assert_eq!(certificate.judgment, JudgmentCategoryV1::Current);
            assert_eq!(
                certificate.supporting_evidence_ids,
                vec![verified.evidence_ref().to_owned()]
            );
        }
        OccurrenceOutcomeV1::AuditOnly { refusal } => {
            assert!(
                refusal.code.starts_with("certificate_"),
                "restart refusal must come from the certificate binding: {refusal}"
            );
        }
    }
    // The first record still verifies as history; it is not present support.
    let bytes = fs::read(&first_result.record_path).expect("first record");
    verify_audit_record(&bytes, &harness.profile).expect("historical record verifies");
    harness.finish();
}

#[test]
fn an_acquisition_identity_is_never_written_twice() {
    let harness = harness("reuse");
    let nq = FakeNq::new(harness.profile.clone(), SyntheticOutcome::Present);
    let witness = harness.witness();
    let mut coproducer = Coproducer::begin(
        &harness.profile,
        &nq,
        &witness,
        &harness.intent_dir,
        &harness.audit_dir,
    )
    .expect("coproducer");
    let result = coproducer
        .run_occurrence(&harness.reactor)
        .expect("occurrence");
    let intent = occurrence_path(&harness.intent_dir, &result.acquisition_id);
    let error = pulse_nq_load_correspondence::write_create_new(&intent, b"{}", 0o640)
        .expect_err("second intent write refuses");
    assert_eq!(error.code, "already_exists");
    let error = pulse_nq_load_correspondence::write_create_new(&result.record_path, b"{}", 0o640)
        .expect_err("second record write refuses");
    assert_eq!(error.code, "already_exists");
    harness.finish();
}
