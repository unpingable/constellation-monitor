use pulse_runtime::{
    CanarySigningIdentityV1, decode_receiver_challenge_datagram,
    decode_sender_session_offer_datagram, sign_observation_envelope, sign_sender_session_offer,
};
use pulse_transport_canary::{
    CANARY_CONSUMER_A, CANARY_CONSUMER_B, CANARY_SESSION_DURATION_MS, CANARY_SUBJECT,
    CANARY_VALIDITY_MS, CanaryHarnessV1, run_matched_custody_demo, run_restart_custody_demo,
};
use pulse_types::{
    AuthorityGrantsV1, CustodyPeerRoleV1, GenerationLifecycleFactBodyV1, GenerationLifecycleFactV1,
    GenerationLifecycleKindV1, IncarnationId, JudgmentCategoryV1, ReceiverAcceptancePolicyV1,
    SCHEMA_VERSION_V1, TransportCustodyFindingV1, digest_parts,
};

const LOADED_HOST_SESSION_MS: u64 = 5_000;

fn qualification_harness() -> Result<CanaryHarnessV1, String> {
    CanaryHarnessV1::with_qualification_session(false, 16, 16, LOADED_HOST_SESSION_MS)
}

fn strict_qualification_harness() -> Result<CanaryHarnessV1, String> {
    CanaryHarnessV1::with_qualification_session(true, 16, 16, LOADED_HOST_SESSION_MS)
}

fn bounded_qualification_harness(
    maximum_messages_per_session: u32,
    maximum_messages_per_second: u32,
) -> Result<CanaryHarnessV1, String> {
    CanaryHarnessV1::with_qualification_session(
        false,
        maximum_messages_per_session,
        maximum_messages_per_second,
        LOADED_HOST_SESSION_MS,
    )
}

#[test]
fn restart_recovers_acceptance_history_but_no_session_evidence_deadline_or_current() {
    let artifact = run_restart_custody_demo().expect("restart custody demo");
    assert!(artifact.historical_sparse_records_recovered > 0);
    assert_eq!(artifact.historical_acceptance_receipts_recovered, 1);
    assert!(artifact.historical_current_certificates_recovered > 0);
    assert!(artifact.history_complete);
    assert_eq!(
        artifact.restarted_binding_state,
        pulse_types::RuntimeBindingStateV1::Unbound
    );
    assert_eq!(artifact.restarted_judgment, JudgmentCategoryV1::Unknown);
    assert_eq!(artifact.restarted_supporting_evidence_count, 0);
    assert_eq!(artifact.restarted_active_deadlines, 0);
    assert_eq!(artifact.restarted_live_sessions, 0);
    assert_eq!(artifact.restarted_accepted_remote_activations, 0);
    assert!(!artifact.current_standing_reconstructed);
    assert!(!artifact.prior_acceptance_receipt_reused_as_evidence);
    assert!(artifact.fresh_local_activation_required);
    assert!(artifact.fresh_challenge_required);
}

fn emit_without_delivery(harness: &mut CanaryHarnessV1, sequence: u64) -> Vec<u8> {
    let datagram = harness
        .sender
        .emit_pulse(
            harness.sender_reactor.as_ref().expect("sender reactor"),
            &pulse_types::SubjectId::new(CANARY_SUBJECT),
            &pulse_types::ConsumerId::new(CANARY_CONSUMER_A),
            &pulse_transport_canary::canary_pulse(sequence),
        )
        .expect("emit exact envelope");
    assert_eq!(
        harness.sender.pop_queued_datagram().as_ref(),
        Some(&datagram)
    );
    datagram
}

#[test]
fn matched_custody_admits_exact_evidence_but_consumers_decide_independently() {
    let artifact = run_matched_custody_demo().expect("matched custody demo");
    assert_eq!(artifact.consumer_a_judgment, JudgmentCategoryV1::Current);
    assert_eq!(artifact.consumer_b_judgment, JudgmentCategoryV1::Unknown);
    assert!(artifact.support_names_exact_remote_custody);
    assert!(artifact.consumer_a_deadline_monotonic_ms.is_some());
    assert_eq!(artifact.consumer_b_deadline_monotonic_ms, None);
    assert!(artifact.envelope_bytes <= 1_232);
}

#[test]
fn silence_expires_remote_current_without_a_new_envelope() {
    let mut harness = qualification_harness().expect("harness");
    harness.establish_session().expect("session");
    harness.emit_and_admit(1).expect("admission");
    let deadline = harness
        .receiver_certificate(CANARY_CONSUMER_A)
        .earliest_support_expiry_monotonic_ms
        .expect("current has a deadline");
    let snapshot = harness
        .receiver_reactor
        .as_ref()
        .expect("receiver")
        .wait_until(std::time::Duration::from_secs(2), |snapshot| {
            snapshot.observed_at_epoch_monotonic_ms >= deadline
                && snapshot.certificates.iter().any(|certificate| {
                    certificate.consumer == pulse_types::ConsumerId::new(CANARY_CONSUMER_A)
                        && certificate.judgment == JudgmentCategoryV1::Unknown
                })
        })
        .expect("reactor withdraws at expiry");
    let consumer_b = snapshot
        .certificates
        .iter()
        .find(|certificate| certificate.consumer == pulse_types::ConsumerId::new(CANARY_CONSUMER_B))
        .expect("consumer B");
    assert_eq!(consumer_b.judgment, JudgmentCategoryV1::Unknown);
    let consumer_a = snapshot
        .certificates
        .iter()
        .find(|certificate| certificate.consumer == pulse_types::ConsumerId::new(CANARY_CONSUMER_A))
        .expect("consumer A");
    assert!(consumer_a.applicable_contradictions.is_empty());
    let transport_output = harness
        .receiver
        .report_transport_unavailable(
            harness.receiver_reactor.as_ref().unwrap(),
            "qualification-injected network partition",
        )
        .expect("typed transport condition");
    assert!(transport_output.sparse_events.iter().any(|event| matches!(
        event.event,
        pulse_types::SparseDurableEventKindV1::ReceiverBoundaryCustodyChanged {
            state: TransportCustodyFindingV1::TransportUnavailable,
            ..
        }
    )));
    harness.shutdown().expect("shutdown");
}

#[test]
fn first_seen_prearrival_delay_cannot_be_promoted_to_observation_time_freshness() {
    let mut harness = qualification_harness().expect("harness");
    harness.establish_session().expect("session");
    let datagram = emit_without_delivery(&mut harness, 1);
    std::thread::sleep(std::time::Duration::from_millis(20));
    let admission = harness
        .enqueue_and_admit_raw(&datagram)
        .expect("arrival-anchored admission");
    let receipt = admission.receipt.clone();
    harness
        .receiver_reactor
        .as_ref()
        .unwrap()
        .submit_input(admission.into_runtime_input().expect("verified token"))
        .expect("runtime evidence admission");
    let certificate = harness.receiver_certificate(CANARY_CONSUMER_A);
    assert_eq!(
        certificate.earliest_support_expiry_monotonic_ms,
        Some(
            receipt
                .receiver_arrival_monotonic_ms
                .saturating_add(CANARY_VALIDITY_MS)
        )
    );
    assert_eq!(
        certificate.remote_observation_custody[0].freshness_mode,
        pulse_types::RemoteFreshnessModeV1::ArrivalAnchored
    );
    harness.shutdown().expect("shutdown");

    let mut strict = strict_qualification_harness().expect("strict harness");
    strict.establish_session().expect("strict session");
    let strict_datagram = emit_without_delivery(&mut strict, 1);
    let refusal = strict
        .enqueue_and_admit_raw(&strict_datagram)
        .expect("complete refusal receipt");
    assert!(!refusal.admitted());
    assert_eq!(
        refusal.receipt.finding,
        TransportCustodyFindingV1::ObservationRejected
    );
    assert_eq!(
        strict
            .receiver_reactor
            .as_ref()
            .unwrap()
            .snapshot()
            .active_deadline_count,
        0
    );
    strict.shutdown().expect("shutdown");
}

#[test]
fn wrong_key_signature_is_an_authenticated_refusal_not_evidence() {
    let mut harness = qualification_harness().expect("harness");
    harness.establish_session().expect("session");
    let accepted = emit_without_delivery(&mut harness, 1);
    let accepted_envelope =
        pulse_runtime::decode_observation_envelope_datagram(&accepted, &harness.sender_key)
            .expect("accepted envelope decodes");
    let wrong = CanarySigningIdentityV1::generate(
        CustodyPeerRoleV1::Sender,
        vec!["host".to_owned()],
        "sender-local-policy:wrong-key",
    )
    .expect("wrong key");
    let mut wrong_body = accepted_envelope.body;
    wrong_body.sender_key_identity_digest = wrong.key_identity().identity_digest();
    let (_, wrong_datagram) = sign_observation_envelope(&wrong, wrong_body).expect("signed bytes");
    let admission = harness
        .enqueue_and_admit_raw(&wrong_datagram)
        .expect("refusal receipt");
    assert!(!admission.admitted());
    assert_eq!(
        admission.receipt.finding,
        TransportCustodyFindingV1::SenderKeyMismatch
    );
    let snapshot = harness.receiver_reactor.as_ref().unwrap().snapshot();
    assert_eq!(snapshot.supporting_evidence_count, 0);
    assert_eq!(snapshot.active_deadline_count, 0);
    harness.shutdown().expect("shutdown");
}

#[test]
fn accepted_key_with_substituted_manifest_is_refused_before_evidence() {
    let mut harness = qualification_harness().expect("harness");
    harness.establish_session().expect("session");
    let datagram = emit_without_delivery(&mut harness, 1);
    let envelope =
        pulse_runtime::decode_observation_envelope_datagram(&datagram, &harness.sender_key)
            .expect("envelope");
    let mut body = envelope.body;
    body.sender_manifest_digest = digest_parts("hostile.substituted-manifest.v1", &[b"other"]);
    let (_, substituted) = sign_observation_envelope(&harness.qualification_sender_key_copy, body)
        .expect("accepted key signs substituted assertion");
    let admission = harness
        .enqueue_and_admit_raw(&substituted)
        .expect("refusal receipt");
    assert!(!admission.admitted());
    assert_eq!(
        admission.receipt.finding,
        TransportCustodyFindingV1::QualifiedIdentityMismatch
    );
    assert_eq!(
        harness
            .receiver_reactor
            .as_ref()
            .unwrap()
            .snapshot()
            .active_deadline_count,
        0
    );
    harness.shutdown().expect("shutdown");
}

#[test]
fn same_label_receiver_policy_substitution_is_refused_by_exact_anchor() {
    let mut harness = qualification_harness().expect("harness");
    let subject = pulse_types::SubjectId::new(CANARY_SUBJECT);
    let consumer = pulse_types::ConsumerId::new(CANARY_CONSUMER_A);
    let sender_reactor = harness.sender_reactor.as_ref().unwrap();
    let receiver_reactor = harness.receiver_reactor.as_ref().unwrap();
    let offer = harness
        .sender
        .create_session_offer(sender_reactor, &subject, &consumer)
        .expect("sender offer");
    let valid_challenge = harness
        .receiver
        .accept_session_offer_and_issue_challenge(receiver_reactor, &subject, &consumer, &offer)
        .expect("valid challenge");
    let challenge = decode_receiver_challenge_datagram(&valid_challenge, &harness.receiver_key)
        .expect("decode challenge");
    let mut body = challenge.body;
    assert_eq!(
        body.receiver_acceptance_policy_generation,
        harness.sender_policy.accepted_receiver_policy_generation
    );
    body.receiver_acceptance_policy_anchor_digest = digest_parts(
        "hostile.receiver-policy-anchor.v1",
        &[b"same-label-other-policy"],
    );
    body.receiver_acceptance_policy_digest = ReceiverAcceptancePolicyV1::identity_digest_from_parts(
        &body.receiver_acceptance_policy_anchor_digest,
        &body.accepted_sender_manifest_digest,
        &body.accepted_sender_certificate_digest,
    );
    let hostile = harness
        .sign_receiver_challenge_for_qualification(body)
        .expect("accepted receiver key signs hostile policy assertion");
    let error = harness
        .sender
        .accept_receiver_challenge(sender_reactor, &subject, &consumer, &hostile)
        .expect_err("same-label policy substitution must be refused");
    assert_eq!(
        error.finding,
        TransportCustodyFindingV1::ReceiverChallengeInvalid
    );
    assert_eq!(harness.sender.live_session_count(), 0);
    harness.shutdown().expect("shutdown");
}

#[test]
fn every_load_bearing_envelope_identity_is_checked_before_evidence_admission() {
    let mut harness = qualification_harness().expect("harness");
    harness.establish_session().expect("session");
    let datagram = emit_without_delivery(&mut harness, 1);
    let base = pulse_runtime::decode_observation_envelope_datagram(&datagram, &harness.sender_key)
        .expect("envelope")
        .body;
    let hostile_digest = || digest_parts("hostile.identity-substitution.v1", &[b"other"]);
    let mut cases = Vec::new();

    let mut body = base.clone();
    body.sender_qualification_certificate_digest = hostile_digest();
    cases.push((body, TransportCustodyFindingV1::QualifiedIdentityMismatch));
    let mut body = base.clone();
    body.sender_activation_receipt_digest = hostile_digest();
    cases.push((body, TransportCustodyFindingV1::QualifiedIdentityMismatch));
    let mut body = base.clone();
    body.sender_process_occurrence = IncarnationId::new("sender-process:substituted");
    cases.push((body, TransportCustodyFindingV1::QualifiedIdentityMismatch));
    let mut body = base.clone();
    body.sender_monotonic_epoch = IncarnationId::new("sender-epoch:substituted");
    cases.push((body, TransportCustodyFindingV1::QualifiedIdentityMismatch));
    let mut body = base.clone();
    body.failure_domain_claim = "configured-failure-domain:substituted".to_owned();
    cases.push((body, TransportCustodyFindingV1::QualifiedIdentityMismatch));
    let mut body = base.clone();
    body.observer = pulse_types::ObserverId::new("observer:substituted");
    cases.push((body, TransportCustodyFindingV1::ObserverRoleMismatch));
    let mut body = base.clone();
    body.subject_scope.subject = pulse_types::SubjectId::new("subject:substituted");
    cases.push((body, TransportCustodyFindingV1::SubjectScopeMismatch));
    let mut body = base.clone();
    body.subject_scope.subject_incarnation = IncarnationId::new("subject-incarnation:substituted");
    cases.push((body, TransportCustodyFindingV1::SubjectScopeMismatch));
    let mut body = base.clone();
    body.observation_identity = hostile_digest();
    cases.push((body, TransportCustodyFindingV1::SubjectScopeMismatch));
    let mut body = base.clone();
    body.receiver_key_identity_digest = hostile_digest();
    cases.push((body, TransportCustodyFindingV1::ReceiverChallengeInvalid));
    let mut body = base.clone();
    body.receiver_challenge_digest = hostile_digest();
    cases.push((body, TransportCustodyFindingV1::SessionUnknown));
    let mut body = base;
    body.session_binding_digest = hostile_digest();
    cases.push((body, TransportCustodyFindingV1::SessionUnknown));

    for (body, expected) in cases {
        let (_, hostile) = sign_observation_envelope(&harness.qualification_sender_key_copy, body)
            .expect("accepted key can make a hostile assertion");
        let admission = harness
            .enqueue_and_admit_raw(&hostile)
            .expect("complete refusal receipt");
        assert!(!admission.admitted());
        assert_eq!(admission.receipt.finding, expected);
        assert!(admission.receipt.accepted_evidence_identity.is_none());
    }
    let snapshot = harness.receiver_reactor.as_ref().unwrap().snapshot();
    assert_eq!(snapshot.supporting_evidence_count, 0);
    assert_eq!(snapshot.active_deadline_count, 0);
    assert_eq!(
        harness.receiver_certificate(CANARY_CONSUMER_A).judgment,
        JudgmentCategoryV1::Unknown
    );
    harness.shutdown().expect("shutdown");
}

#[test]
fn duplicate_replay_does_not_renew_receiver_freshness() {
    let mut harness = qualification_harness().expect("harness");
    harness.establish_session().expect("session");
    let (_, _, _, datagram) = harness.emit_and_admit(1).expect("first admission");
    let prior = harness.receiver_certificate(CANARY_CONSUMER_A);
    let prior_deadline = prior.earliest_support_expiry_monotonic_ms;
    let prior_evidence = prior.supporting_evidence_ids;
    let replay = harness
        .enqueue_and_admit_raw(&datagram)
        .expect("replay refusal receipt");
    assert!(!replay.admitted());
    assert_eq!(
        replay.receipt.finding,
        TransportCustodyFindingV1::DuplicateDetected
    );
    let after = harness.receiver_certificate(CANARY_CONSUMER_A);
    assert_eq!(after.earliest_support_expiry_monotonic_ms, prior_deadline);
    assert_eq!(after.supporting_evidence_ids, prior_evidence);
    assert_eq!(harness.receiver.duplicate_refusals(), 1);
    harness.shutdown().expect("shutdown");
}

#[test]
fn duplicate_observation_in_new_envelopes_and_repeated_duplicates_never_renew() {
    let mut harness = qualification_harness().expect("harness");
    harness.establish_session().expect("session");
    let (_, _, _, admitted_datagram) = harness.emit_and_admit(1).expect("first admission");
    let original = harness.receiver_certificate(CANARY_CONSUMER_A);
    let original_deadline = original.earliest_support_expiry_monotonic_ms;

    let new_envelope_same_observation = emit_without_delivery(&mut harness, 1);
    let reset = harness
        .enqueue_and_admit_raw(&new_envelope_same_observation)
        .expect("observation-sequence refusal receipt");
    assert!(!reset.admitted());
    assert_eq!(
        reset.receipt.finding,
        TransportCustodyFindingV1::ReplayDetected
    );

    for _ in 0..4 {
        let duplicate = harness
            .enqueue_and_admit_raw(&admitted_datagram)
            .expect("bounded duplicate refusal receipt");
        assert!(!duplicate.admitted());
        assert!(matches!(
            duplicate.receipt.finding,
            TransportCustodyFindingV1::DuplicateDetected
                | TransportCustodyFindingV1::ReplayDetected
        ));
    }
    let after = harness.receiver_certificate(CANARY_CONSUMER_A);
    assert!(
        after.earliest_support_expiry_monotonic_ms.is_none()
            || after.earliest_support_expiry_monotonic_ms == original_deadline
    );
    assert!(harness.receiver.replay_refusals() >= 1);
    harness.shutdown().expect("shutdown");
}

#[test]
fn session_message_and_receiver_rate_bounds_refuse_without_eviction() {
    let mut message_bound = bounded_qualification_harness(2, 16).expect("bounded harness");
    message_bound.establish_session().expect("session");
    for sequence in 1..=2 {
        let _ = emit_without_delivery(&mut message_bound, sequence);
    }
    let sender_error = message_bound
        .sender
        .emit_pulse(
            message_bound.sender_reactor.as_ref().unwrap(),
            &pulse_types::SubjectId::new(CANARY_SUBJECT),
            &pulse_types::ConsumerId::new(CANARY_CONSUMER_A),
            &pulse_transport_canary::canary_pulse(3),
        )
        .expect_err("third envelope exceeds exact session message bound");
    assert_eq!(
        sender_error.finding,
        TransportCustodyFindingV1::TransportOverloaded
    );
    assert_eq!(message_bound.sender.live_session_count(), 0);
    message_bound.shutdown().expect("shutdown");

    let mut rate_bound = bounded_qualification_harness(16, 1).expect("rate harness");
    rate_bound.establish_session().expect("session");
    rate_bound
        .emit_and_admit(1)
        .expect("first admitted message");
    let second = emit_without_delivery(&mut rate_bound, 2);
    let refusal = rate_bound
        .enqueue_and_admit_raw(&second)
        .expect("rate refusal receipt");
    assert!(!refusal.admitted());
    assert_eq!(
        refusal.receipt.finding,
        TransportCustodyFindingV1::TransportOverloaded
    );
    assert_eq!(rate_bound.receiver.live_session_count(), 0);
    assert!(
        !rate_bound
            .receiver_reactor
            .as_ref()
            .unwrap()
            .snapshot()
            .live_standing_available
    );
    assert_eq!(
        rate_bound
            .receiver_reactor
            .as_ref()
            .unwrap()
            .snapshot()
            .active_deadline_count,
        0
    );
    rate_bound.shutdown().expect("shutdown");
}

#[test]
fn replay_window_gap_bound_is_explicit_before_payload_admission() {
    let mut harness = qualification_harness().expect("harness");
    harness.establish_session().expect("session");
    let datagram = emit_without_delivery(&mut harness, 1);
    let envelope =
        pulse_runtime::decode_observation_envelope_datagram(&datagram, &harness.sender_key)
            .expect("envelope");
    let mut body = envelope.body;
    body.session_sequence = 10;
    let (_, hostile_gap) = sign_observation_envelope(&harness.qualification_sender_key_copy, body)
        .expect("accepted key signs over-bound sequence assertion");
    let refusal = harness
        .enqueue_and_admit_raw(&hostile_gap)
        .expect("bounded gap refusal receipt");
    assert!(!refusal.admitted());
    assert_eq!(
        refusal.receipt.finding,
        TransportCustodyFindingV1::ReplayDetected
    );
    assert_eq!(
        refusal.receipt.replay_window_result,
        pulse_types::ReplayWindowResultV1::BoundExceeded
    );
    assert!(refusal.receipt.accepted_evidence_identity.is_none());
    assert_eq!(
        harness
            .receiver_reactor
            .as_ref()
            .unwrap()
            .snapshot()
            .active_deadline_count,
        0
    );
    harness.shutdown().expect("shutdown");
}

#[test]
fn reordered_envelope_is_refused_without_replacing_newer_admitted_evidence() {
    let mut harness = qualification_harness().expect("harness");
    harness.establish_session().expect("session");
    let older = emit_without_delivery(&mut harness, 1);
    let newer = emit_without_delivery(&mut harness, 2);
    let admitted = harness
        .enqueue_and_admit_raw(&newer)
        .expect("gap-bearing admission");
    assert!(admitted.admitted());
    assert_eq!(
        admitted
            .receipt
            .sequence_gap
            .as_ref()
            .map(|gap| gap.missing_count),
        Some(1)
    );
    harness
        .receiver_reactor
        .as_ref()
        .unwrap()
        .submit_input(admitted.into_runtime_input().expect("verified token"))
        .expect("evaluate newer evidence");
    let before = harness.receiver_reactor.as_ref().unwrap().snapshot();
    let refusal = harness
        .enqueue_and_admit_raw(&older)
        .expect("reordered refusal");
    assert!(!refusal.admitted());
    assert_eq!(
        refusal.receipt.finding,
        TransportCustodyFindingV1::ReplayDetected
    );
    let after = harness.receiver_reactor.as_ref().unwrap().snapshot();
    // The autonomous reactor may lawfully expire the 120 ms support while
    // this refusal is checked under host load. Reorder must never increase or
    // renew either surface; inclusive expiry may only reduce it.
    assert!(after.supporting_evidence_count <= before.supporting_evidence_count);
    assert!(after.active_deadline_count <= before.active_deadline_count);
    assert_eq!(harness.receiver.sequence_gap_count(), 1);
    assert_eq!(harness.receiver.replay_refusals(), 1);
    harness.shutdown().expect("shutdown");
}

#[test]
fn receiver_session_expiry_is_inclusive_and_delayed_first_delivery_is_refused() {
    // This case intentionally exercises the canonical 750 ms session profile.
    let mut harness = CanaryHarnessV1::deterministic().expect("harness");
    harness.establish_session().expect("session");
    let delayed = emit_without_delivery(&mut harness, 1);
    std::thread::sleep(std::time::Duration::from_millis(
        CANARY_SESSION_DURATION_MS + 25,
    ));
    let refusal = harness
        .enqueue_and_admit_raw(&delayed)
        .expect("expired-session refusal");
    assert!(!refusal.admitted());
    assert_eq!(
        refusal.receipt.finding,
        TransportCustodyFindingV1::SessionExpired
    );
    assert_eq!(harness.receiver.live_session_count(), 0);
    let snapshot = harness.receiver_reactor.as_ref().unwrap().snapshot();
    assert_eq!(snapshot.supporting_evidence_count, 0);
    assert_eq!(snapshot.active_deadline_count, 0);
    harness.shutdown().expect("shutdown");
}

#[test]
fn transport_partition_is_recorded_separately_and_never_invents_contradiction() {
    let mut harness = qualification_harness().expect("harness");
    harness.establish_session().expect("session");
    harness.emit_and_admit(1).expect("current evidence");
    assert_eq!(
        harness.receiver_certificate(CANARY_CONSUMER_A).judgment,
        JudgmentCategoryV1::Current
    );
    harness
        .receiver
        .report_transport_unavailable(
            harness.receiver_reactor.as_ref().unwrap(),
            "qualification partition injection",
        )
        .expect("typed partition condition");
    let snapshot = harness.receiver_reactor.as_ref().unwrap().snapshot();
    assert_eq!(harness.receiver.live_session_count(), 0);
    assert!(!snapshot.live_standing_available);
    assert_eq!(snapshot.active_deadline_count, 0);
    assert!(
        snapshot
            .certificates
            .iter()
            .all(|certificate| certificate.judgment != JudgmentCategoryV1::Contradicted)
    );
    harness.shutdown().expect("shutdown");
}

#[test]
fn skipped_session_sequence_is_admitted_only_with_explicit_missingness() {
    let mut harness = qualification_harness().expect("harness");
    harness.establish_session().expect("session");
    let _dropped = emit_without_delivery(&mut harness, 1);
    let received = emit_without_delivery(&mut harness, 2);
    let admission = harness
        .enqueue_and_admit_raw(&received)
        .expect("gap admission receipt");
    assert!(admission.admitted());
    assert_eq!(
        admission.receipt.finding,
        TransportCustodyFindingV1::EvidenceAdmitted
    );
    let gap = admission
        .receipt
        .sequence_gap
        .as_ref()
        .expect("gap is explicit");
    assert_eq!(gap.expected_next, 1);
    assert_eq!(gap.received, 2);
    assert_eq!(gap.missing_count, 1);
    harness
        .receiver_reactor
        .as_ref()
        .unwrap()
        .submit_input(admission.into_runtime_input().expect("verified token"))
        .expect("runtime admission");
    assert_eq!(harness.receiver.sequence_gap_count(), 1);
    harness.shutdown().expect("shutdown");
}

#[test]
fn receiver_queue_saturation_invalidates_session_and_withdraws_positive_surface() {
    let mut harness = qualification_harness().expect("harness");
    harness.establish_session().expect("session");
    let datagram = emit_without_delivery(&mut harness, 1);
    let reactor = harness.receiver_reactor.as_ref().unwrap();
    for _ in 0..8 {
        harness
            .receiver
            .enqueue_envelope(reactor, datagram.clone(), "loopback:metadata")
            .expect("bounded queue slot");
    }
    let error = harness
        .receiver
        .enqueue_envelope(reactor, datagram, "loopback:metadata")
        .expect_err("ninth message saturates the exact queue bound");
    assert_eq!(
        error.finding,
        TransportCustodyFindingV1::TransportOverloaded
    );
    assert_eq!(harness.receiver.live_session_count(), 0);
    assert!(!reactor.snapshot().live_standing_available);
    assert_eq!(reactor.snapshot().active_deadline_count, 0);
    harness.shutdown().expect("shutdown");
}

#[test]
fn sender_queue_saturation_stops_emission_and_latches_local_blindness() {
    let mut harness = qualification_harness().expect("harness");
    harness.establish_session().expect("session");
    for sequence in 1..=8 {
        harness
            .sender
            .emit_pulse(
                harness.sender_reactor.as_ref().unwrap(),
                &pulse_types::SubjectId::new(CANARY_SUBJECT),
                &pulse_types::ConsumerId::new(CANARY_CONSUMER_A),
                &pulse_transport_canary::canary_pulse(sequence),
            )
            .expect("bounded sender queue slot");
    }
    let error = harness
        .sender
        .emit_pulse(
            harness.sender_reactor.as_ref().unwrap(),
            &pulse_types::SubjectId::new(CANARY_SUBJECT),
            &pulse_types::ConsumerId::new(CANARY_CONSUMER_A),
            &pulse_transport_canary::canary_pulse(9),
        )
        .expect_err("ninth unsent envelope saturates sender queue");
    assert_eq!(
        error.finding,
        TransportCustodyFindingV1::TransportOverloaded
    );
    assert_eq!(harness.sender.live_session_count(), 0);
    assert_eq!(harness.sender.queue_refusals(), 1);
    assert!(
        !harness
            .sender_reactor
            .as_ref()
            .unwrap()
            .snapshot()
            .live_standing_available
    );
    harness.shutdown().expect("shutdown");
}

#[test]
fn competing_authenticated_sender_occurrence_never_wins_by_last_arrival() {
    let mut harness = qualification_harness().expect("harness");
    let first_offer = harness.establish_session().expect("first session").offer;
    let receiver_reactor = harness.receiver_reactor.as_ref().unwrap();
    let mut body = first_offer.body;
    body.sender_process_occurrence = IncarnationId::new("sender-process:competing-two");
    body.sender_monotonic_epoch = IncarnationId::new("sender-epoch:competing-two");
    body.sender_nonce_hex = "33".repeat(32);
    let (_, competing) = sign_sender_session_offer(&harness.qualification_sender_key_copy, body)
        .expect("authenticated competing assertion");
    let error = harness
        .receiver
        .accept_session_offer_and_issue_challenge(
            receiver_reactor,
            &pulse_types::SubjectId::new(CANARY_SUBJECT),
            &pulse_types::ConsumerId::new(CANARY_CONSUMER_A),
            &competing,
        )
        .expect_err("competing occurrence is ambiguous");
    assert_eq!(
        error.finding,
        TransportCustodyFindingV1::SenderOccurrenceConflict
    );
    assert_eq!(harness.receiver.competing_occurrences(), 1);
    assert_eq!(harness.receiver.live_session_count(), 0);
    assert!(!receiver_reactor.snapshot().live_standing_available);
    harness.shutdown().expect("shutdown");
}

#[test]
fn prior_receiver_challenge_cannot_recreate_sender_session_after_live_state_loss() {
    let mut harness = qualification_harness().expect("harness");
    let prior_session = harness.establish_session().expect("first session");
    let old_challenge = prior_session.challenge;
    let old_challenge_wire = prior_session.challenge_wire;
    assert_eq!(harness.sender.live_session_count(), 1);

    harness.sender.invalidate();
    let sender_reactor = harness.sender_reactor.as_ref().unwrap();
    let new_offer_wire = harness
        .sender
        .create_session_offer(
            sender_reactor,
            &pulse_types::SubjectId::new(CANARY_SUBJECT),
            &pulse_types::ConsumerId::new(CANARY_CONSUMER_A),
        )
        .expect("new process-local offer");
    let new_offer = decode_sender_session_offer_datagram(&new_offer_wire, &harness.sender_key)
        .expect("new exact offer");
    let error = harness
        .sender
        .accept_receiver_challenge(
            sender_reactor,
            &pulse_types::SubjectId::new(CANARY_SUBJECT),
            &pulse_types::ConsumerId::new(CANARY_CONSUMER_A),
            &old_challenge_wire,
        )
        .expect_err("old challenge must not bind a new sender offer");
    assert_eq!(
        error.finding,
        TransportCustodyFindingV1::ReceiverChallengeInvalid
    );
    assert_eq!(harness.sender.live_session_count(), 0);
    assert_ne!(
        old_challenge.body.sender_session_offer_digest,
        new_offer.offer_digest
    );
    harness.shutdown().expect("shutdown");
}

#[test]
fn exact_local_revocation_fact_withdraws_session_but_grants_no_revocation_authority() {
    let mut harness = qualification_harness().expect("harness");
    harness.establish_session().expect("session");
    harness.emit_and_admit(1).expect("current evidence");
    let fact = GenerationLifecycleFactV1::new(GenerationLifecycleFactBodyV1 {
        schema_version: SCHEMA_VERSION_V1,
        authority_id: "local-custody-lifecycle-authority:canary".to_owned(),
        fact_sequence: 1,
        certificate_digest: harness
            .sender_package
            .certificate
            .certificate_digest
            .clone(),
        kind: GenerationLifecycleKindV1::Revoked,
        successor_manifest_digest: None,
        successor_certificate_digest: None,
        reason: "hostile qualification finding".to_owned(),
        authority_grants: AuthorityGrantsV1::none(),
    })
    .expect("exact local fact");
    harness
        .receiver
        .apply_sender_lifecycle_fact(harness.receiver_reactor.as_ref().unwrap(), &fact)
        .expect("configured local lifecycle boundary accepts exact fact");
    let snapshot = harness.receiver_reactor.as_ref().unwrap().snapshot();
    assert_eq!(harness.receiver.live_session_count(), 0);
    assert!(!snapshot.live_standing_available);
    assert_eq!(snapshot.active_deadline_count, 0);
    assert!(fact.body.authority_grants.grants_nothing());
    harness.shutdown().expect("shutdown");
}

#[test]
fn exact_local_supersession_fact_withdraws_session_without_inheriting_successor_custody() {
    let mut harness = qualification_harness().expect("harness");
    harness.establish_session().expect("session");
    harness.emit_and_admit(1).expect("current evidence");
    let fact = GenerationLifecycleFactV1::new(GenerationLifecycleFactBodyV1 {
        schema_version: SCHEMA_VERSION_V1,
        authority_id: "local-custody-lifecycle-authority:canary".to_owned(),
        fact_sequence: 1,
        certificate_digest: harness
            .sender_package
            .certificate
            .certificate_digest
            .clone(),
        kind: GenerationLifecycleKindV1::Superseded,
        successor_manifest_digest: Some(digest_parts(
            "transport.successor.manifest.v1",
            &[b"successor"],
        )),
        successor_certificate_digest: Some(digest_parts(
            "transport.successor.certificate.v1",
            &[b"successor"],
        )),
        reason: "qualified successor configured".to_owned(),
        authority_grants: AuthorityGrantsV1::none(),
    })
    .expect("exact local supersession fact");
    harness
        .receiver
        .apply_sender_lifecycle_fact(harness.receiver_reactor.as_ref().unwrap(), &fact)
        .expect("configured local lifecycle boundary accepts exact fact");
    let snapshot = harness.receiver_reactor.as_ref().unwrap().snapshot();
    assert_eq!(harness.receiver.live_session_count(), 0);
    assert!(!snapshot.live_standing_available);
    assert_eq!(snapshot.active_deadline_count, 0);
    assert!(snapshot.certificates.iter().all(|certificate| {
        certificate.remote_observation_custody.is_empty()
            && certificate.judgment != JudgmentCategoryV1::Current
    }));
    assert!(fact.body.authority_grants.grants_nothing());
    harness.shutdown().expect("shutdown");
}

#[test]
fn arbitrary_revocation_authority_string_is_refused_without_session_change() {
    let mut harness = qualification_harness().expect("harness");
    harness.establish_session().expect("session");
    let fact = GenerationLifecycleFactV1::new(GenerationLifecycleFactBodyV1 {
        schema_version: SCHEMA_VERSION_V1,
        authority_id: "attacker-asserted-revocation".to_owned(),
        fact_sequence: 1,
        certificate_digest: harness
            .sender_package
            .certificate
            .certificate_digest
            .clone(),
        kind: GenerationLifecycleKindV1::Revoked,
        successor_manifest_digest: None,
        successor_certificate_digest: None,
        reason: "unauthorized assertion".to_owned(),
        authority_grants: AuthorityGrantsV1::none(),
    })
    .expect("structurally valid fact");
    let error = harness
        .receiver
        .apply_sender_lifecycle_fact(harness.receiver_reactor.as_ref().unwrap(), &fact)
        .expect_err("unconfigured authority is refused");
    assert_eq!(
        error.finding,
        TransportCustodyFindingV1::QualifiedIdentityMismatch
    );
    assert_eq!(harness.receiver.live_session_count(), 1);
    harness.shutdown().expect("shutdown");
}
