use proptest::prelude::*;
use pulse_runtime::{
    decode_observation_envelope_datagram, decode_receiver_challenge_datagram,
    decode_receiver_session_acceptance_datagram, decode_sender_session_binding_datagram,
    decode_sender_session_offer_datagram,
};
use pulse_transport_canary::CanaryHarnessV1;
use pulse_types::{ReceiverAcceptancePolicyV1, SenderEmissionPolicyV1};

#[test]
fn every_truncation_and_single_byte_corruption_of_small_corpus_is_refused() {
    let mut harness = CanaryHarnessV1::deterministic().expect("harness");
    let session = harness.establish_session().expect("session");
    let offer = session.offer_wire;
    let challenge = session.challenge_wire;
    let binding = session.binding_wire;
    let acceptance = session.receiver_acceptance_wire;
    let (_, _, _, envelope) = harness.emit_and_admit(1).expect("envelope");

    for split in 0..offer.len() {
        assert!(
            decode_sender_session_offer_datagram(&offer[..split], &harness.sender_key).is_err()
        );
    }
    for split in 0..challenge.len() {
        assert!(
            decode_receiver_challenge_datagram(&challenge[..split], &harness.receiver_key).is_err()
        );
    }
    for split in 0..binding.len() {
        assert!(
            decode_sender_session_binding_datagram(&binding[..split], &harness.sender_key).is_err()
        );
    }
    for split in 0..acceptance.len() {
        assert!(
            decode_receiver_session_acceptance_datagram(
                &acceptance[..split],
                &harness.receiver_key
            )
            .is_err()
        );
    }
    for split in 0..envelope.len() {
        assert!(
            decode_observation_envelope_datagram(&envelope[..split], &harness.sender_key).is_err()
        );
    }

    for offset in 0..offer.len() {
        let mut corrupted = offer.clone();
        corrupted[offset] ^= 0x01;
        assert!(decode_sender_session_offer_datagram(&corrupted, &harness.sender_key).is_err());
    }
    for offset in 0..challenge.len() {
        let mut corrupted = challenge.clone();
        corrupted[offset] ^= 0x01;
        assert!(decode_receiver_challenge_datagram(&corrupted, &harness.receiver_key).is_err());
    }
    for offset in 0..binding.len() {
        let mut corrupted = binding.clone();
        corrupted[offset] ^= 0x01;
        assert!(decode_sender_session_binding_datagram(&corrupted, &harness.sender_key).is_err());
    }
    for offset in 0..acceptance.len() {
        let mut corrupted = acceptance.clone();
        corrupted[offset] ^= 0x01;
        assert!(
            decode_receiver_session_acceptance_datagram(&corrupted, &harness.receiver_key).is_err()
        );
    }
    for offset in 0..envelope.len() {
        let mut corrupted = envelope.clone();
        corrupted[offset] ^= 0x01;
        assert!(decode_observation_envelope_datagram(&corrupted, &harness.sender_key).is_err());
    }
    let mut trailing = envelope;
    trailing.push(0);
    assert!(decode_observation_envelope_datagram(&trailing, &harness.sender_key).is_err());
    harness.shutdown().expect("shutdown");
}

#[test]
fn canonical_policy_decoders_refuse_unknown_duplicate_and_reordered_json() {
    let harness = CanaryHarnessV1::deterministic().expect("harness");
    let receiver = harness
        .receiver_policy
        .canonical_bytes()
        .expect("receiver policy canonical bytes");
    let sender = harness
        .sender_policy
        .canonical_bytes()
        .expect("sender policy canonical bytes");
    assert_eq!(
        ReceiverAcceptancePolicyV1::decode_canonical(&receiver).expect("canonical receiver"),
        harness.receiver_policy
    );
    assert_eq!(
        SenderEmissionPolicyV1::decode_canonical(&sender).expect("canonical sender"),
        harness.sender_policy
    );
    assert_eq!(
        harness.sender_policy.accepted_receiver_policy_anchor_digest,
        harness.receiver_policy.anchor_digest()
    );
    let original_anchor = harness.receiver_policy.anchor_digest();
    let original_identity = harness.receiver_policy.identity_digest();
    let mut different_sender_package = harness.receiver_policy.clone();
    different_sender_package.accepted_sender_manifest_digest =
        pulse_types::digest_parts("hostile.other-manifest.v1", &[b"other"]);
    assert_eq!(different_sender_package.anchor_digest(), original_anchor);
    assert_ne!(
        different_sender_package.identity_digest(),
        original_identity
    );
    let mut different_policy_semantics = harness.receiver_policy.clone();
    different_policy_semantics.maximum_sequence_gap += 1;
    assert_ne!(different_policy_semantics.anchor_digest(), original_anchor);
    assert_ne!(
        different_policy_semantics.identity_digest(),
        original_identity
    );

    let mut receiver_value: serde_json::Value =
        serde_json::from_slice(&receiver).expect("receiver JSON");
    receiver_value
        .as_object_mut()
        .expect("object")
        .insert("unknown_mandatory".to_owned(), serde_json::json!(true));
    assert!(
        ReceiverAcceptancePolicyV1::decode_canonical(
            &serde_json::to_vec(&receiver_value).expect("altered JSON")
        )
        .is_err()
    );

    let text = String::from_utf8(sender).expect("sender UTF-8");
    let duplicate = text.replacen(
        "\"schema_version\":1,",
        "\"schema_version\":1,\"schema_version\":1,",
        1,
    );
    assert!(SenderEmissionPolicyV1::decode_canonical(duplicate.as_bytes()).is_err());

    let mut fields = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&text)
        .expect("sender object")
        .into_iter()
        .collect::<Vec<_>>();
    fields.reverse();
    let reordered = format!(
        "{{{}}}",
        fields
            .iter()
            .map(|(key, value)| format!(
                "{}:{}",
                serde_json::to_string(key).expect("key"),
                serde_json::to_string(value).expect("value")
            ))
            .collect::<Vec<_>>()
            .join(",")
    );
    assert!(SenderEmissionPolicyV1::decode_canonical(reordered.as_bytes()).is_err());
    harness.shutdown().expect("shutdown");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn bounded_arbitrary_datagrams_never_decode_without_an_exact_signature(
        bytes in proptest::collection::vec(any::<u8>(), 0..=1_300),
    ) {
        let key = pulse_runtime::CanarySigningIdentityV1::generate(
            pulse_types::CustodyPeerRoleV1::Sender,
            vec!["host".to_owned()],
            "sender-local-policy:canary",
        )
        .expect("key")
        .key_identity()
        .clone();
        prop_assert!(decode_observation_envelope_datagram(&bytes, &key).is_err());
    }
}
