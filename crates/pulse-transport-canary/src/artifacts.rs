use std::fs;
use std::path::Path;
use std::time::Instant;

use pulse_runtime::{
    CanarySigningIdentityV1, sign_observation_envelope, sign_sender_session_offer,
};
use pulse_types::{
    CustodyPeerRoleV1, IncarnationId, JudgmentCategoryV1, SCHEMA_VERSION_V1, digest_parts,
    encode_lower_hex,
};
use serde::{Deserialize, Serialize};

use crate::{
    CAMPAIGN_STARTING_COMMIT, CANARY_CONSUMER_A, CANARY_CONSUMER_B, CANARY_SUBJECT,
    CanaryHarnessV1, run_restart_custody_demo, run_udp_loopback_probe,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedArtifactSetV1 {
    pub schema_version: u16,
    pub campaign: String,
    pub files: Vec<String>,
    pub private_key_material_written: bool,
}

fn write_json(
    directory: &Path,
    name: &str,
    value: &impl Serialize,
    files: &mut Vec<String>,
) -> Result<(), String> {
    fs::write(
        directory.join(name),
        serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    files.push(name.to_owned());
    Ok(())
}

fn write_bytes(
    directory: &Path,
    name: &str,
    bytes: &[u8],
    files: &mut Vec<String>,
) -> Result<(), String> {
    fs::write(directory.join(name), bytes).map_err(|error| error.to_string())?;
    files.push(name.to_owned());
    Ok(())
}

fn protocol_schema() -> serde_json::Value {
    serde_json::json!({
        "schema_version": SCHEMA_VERSION_V1,
        "protocol_version": pulse_types::CUSTODY_PROTOCOL_VERSION_V1,
        "transport": "one bounded UDP datagram path",
        "maximum_datagram_bytes": pulse_types::MAX_CANARY_DATAGRAM_BYTES,
        "framing": [
            "magic PCN1",
            "closed message-kind byte",
            "big-endian exact body length",
            "canonical bounded body bytes",
            "64-byte Ed25519 signature",
            "trailing bytes refused"
        ],
        "signature_algorithm": "Ed25519 through ed25519-dalek verify_strict",
        "signature_domains": [
            pulse_types::SENDER_SESSION_OFFER_SIGNATURE_DOMAIN_V1,
            pulse_types::RECEIVER_CHALLENGE_SIGNATURE_DOMAIN_V1,
            pulse_types::SENDER_BINDING_SIGNATURE_DOMAIN_V1,
            pulse_types::RECEIVER_SESSION_ACCEPTANCE_SIGNATURE_DOMAIN_V1,
            pulse_types::OBSERVATION_ENVELOPE_SIGNATURE_DOMAIN_V1
        ],
        "objects": {
            "peer_key_identity_v1": ["algorithm", "exact public key bytes and digest", "closed role", "scope", "local policy identity"],
            "sender_session_offer_v1": ["sender process and monotonic epoch", "random offer nonce", "exact sender package and activation assertion", "intended receiver key", "observer/failure-domain/scope claims", "signature"],
            "receiver_session_challenge_v1": ["exact sender offer digest and process occurrence", "receiver process and monotonic epoch", "random nonce", "acceptance policy identity", "intended sender key", "accepted sender package", "receiver expiry and message bounds", "signature"],
            "sender_session_binding_v1": ["challenge digest", "sender process and monotonic epoch", "exact sender package and activation", "observer/failure-domain/scope claims", "signature"],
            "receiver_session_acceptance_v1": ["challenge and binding digests", "both process occurrences", "receiver policy digest", "receiver expiry and message bound", "signature"],
            "observation_custody_envelope_v1": ["challenge and session digests", "peer/process/package/activation identities", "observer/subject/incarnation/sequences", "exact pulse payload and digest", "sender times as provenance", "signature"],
            "receiver_acceptance_receipt_v1": ["receiver process/epoch/policy/arrival", "ordered admission checks", "accepted evidence identity or refusal", "receipt and journal sequences"]
        },
        "session_flow": ["sender offer", "receiver challenge", "sender binding", "receiver acceptance", "observation envelope"],
        "sender_emission_requires_receiver_acceptance": true,
        "receiver_admission_order": [
            "bounded framing",
            "canonical decode and protocol version",
            "challenge/session/receiver identities",
            "pinned sender key identity",
            "strict signature verification",
            "sender occurrence and exact package identities",
            "observer/failure-domain/subject/kind scope",
            "session and observation sequence/replay",
            "queue/capacity/payload/lifecycle",
            "receiver-owned arrival admission"
        ],
        "receiver_local_fields": ["arrival", "replay result", "gap", "queue result", "accepted evidence identity", "receipt sequence"],
        "sender_times_are_provenance_only": true,
        "first_seen_prearrival_delay_bounded": false
    })
}

fn write_packages(
    directory: &Path,
    harness: &CanaryHarnessV1,
    files: &mut Vec<String>,
) -> Result<(), String> {
    for (prefix, package) in [
        ("sender", &harness.sender_package),
        ("receiver-consumer-a", &harness.receiver_package_a),
        ("receiver-consumer-b", &harness.receiver_package_b),
    ] {
        write_bytes(
            directory,
            &format!("{prefix}-qualified-manifest.json"),
            &package
                .manifest_bytes()
                .map_err(|error| error.to_string())?,
            files,
        )?;
        write_bytes(
            directory,
            &format!("{prefix}-qualification-report.json"),
            &package.report_bytes().map_err(|error| error.to_string())?,
            files,
        )?;
        write_bytes(
            directory,
            &format!("{prefix}-qualification-certificate.json"),
            &package
                .certificate_bytes()
                .map_err(|error| error.to_string())?,
            files,
        )?;
    }
    write_json(
        directory,
        "exact-canary-package-identities.json",
        &serde_json::json!({
            "schema_version": SCHEMA_VERSION_V1,
            "sender": {
                "manifest_digest": harness.sender_package.manifest.manifest_digest,
                "qualification_report_digest": harness.sender_package.report.report_digest,
                "qualification_certificate_digest": harness.sender_package.certificate.certificate_digest,
                "accepted_certificate_digest": harness.sender_package.acceptance.accepted_certificate_digest
            },
            "receiver_consumer_a": {
                "manifest_digest": harness.receiver_package_a.manifest.manifest_digest,
                "qualification_report_digest": harness.receiver_package_a.report.report_digest,
                "qualification_certificate_digest": harness.receiver_package_a.certificate.certificate_digest,
                "accepted_certificate_digest": harness.receiver_package_a.acceptance.accepted_certificate_digest
            },
            "receiver_consumer_b": {
                "manifest_digest": harness.receiver_package_b.manifest.manifest_digest,
                "qualification_report_digest": harness.receiver_package_b.report.report_digest,
                "qualification_certificate_digest": harness.receiver_package_b.certificate.certificate_digest,
                "accepted_certificate_digest": harness.receiver_package_b.acceptance.accepted_certificate_digest
            },
            "packages_contain_private_key_material": false,
            "source_to_binary_correspondence_claimed": false,
            "remote_attestation_claimed": false
        }),
        files,
    )
}

fn resident_memory_kib() -> Option<u64> {
    fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| {
            let value = line.strip_prefix("VmRSS:")?;
            value.split_whitespace().next()?.parse().ok()
        })
}

fn local_host_facts() -> serde_json::Value {
    let hostname = fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|value| value.trim().to_owned());
    let kernel = fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|value| value.trim().to_owned());
    let default_route_interface = fs::read_to_string("/proc/net/route")
        .ok()
        .and_then(|routes| {
            routes.lines().skip(1).find_map(|line| {
                let mut fields = line.split_whitespace();
                let interface = fields.next()?;
                let destination = fields.next()?;
                (destination == "00000000").then(|| interface.to_owned())
            })
        });
    serde_json::json!({
        "hostname": hostname,
        "kernel": kernel,
        "architecture": std::env::consts::ARCH,
        "operating_system": std::env::consts::OS,
        "default_route_interface": default_route_interface
    })
}

fn write_qualification_summary(directory: &Path, files: &mut Vec<String>) -> Result<(), String> {
    write_json(
        directory,
        "live-two-host-measurements.json",
        &serde_json::json!({
            "schema_version": SCHEMA_VERSION_V1,
            "executed": false,
            "two_linux_hosts_qualified": false,
            "local_host": local_host_facts(),
            "reachable_candidate": {
                "ssh_alias": "mac",
                "observed_operating_system": "Darwin 24.6.0",
                "observed_architecture": "arm64",
                "selected_for_canary": false
            },
            "refusal": "no second explicitly authorized reachable Linux host was available; loopback is not reported as a two-host result",
            "live_timing_samples": [],
            "private_key_cleanup": "no two-host private keys were created"
        }),
        files,
    )?;
    write_json(
        directory,
        "qualification-summary.json",
        &serde_json::json!({
            "schema_version": SCHEMA_VERSION_V1,
            "campaign": "receiver-boundary-custody",
            "starting_commit": CAMPAIGN_STARTING_COMMIT,
            "transport": "bounded UDP datagrams",
            "authentication": "Ed25519 / ed25519-dalek verify_strict / pinned exact public keys",
            "freshness": "ArrivalAnchored at receiver-owned monotonic arrival time",
            "deterministic_harness_executed": true,
            "actual_udp_loopback_executed_separately": true,
            "actual_two_host_linux_canary_executed": false,
            "private_key_material_in_artifacts": false,
            "authority_granted": false,
            "first_seen_prearrival_delay_bounded": false,
            "hard_realtime_claimed": false,
            "final_commands_pending_at_generation": [
                "cargo fmt --all -- --check",
                "cargo clippy --workspace --all-targets --all-features -- -D warnings",
                "cargo test --workspace --all-targets --all-features"
            ]
        }),
        files,
    )
}

#[allow(clippy::too_many_lines)]
pub fn write_campaign_artifacts(
    directory: impl AsRef<Path>,
) -> Result<GeneratedArtifactSetV1, String> {
    let directory = directory.as_ref();
    fs::create_dir_all(directory).map_err(|error| error.to_string())?;
    let mut files = Vec::new();
    write_json(
        directory,
        "transport-protocol-schemas.json",
        &protocol_schema(),
        &mut files,
    )?;

    let mut harness = CanaryHarnessV1::deterministic()?;
    let session_started = Instant::now();
    let session = harness.establish_session()?;
    let offer = session.offer;
    let challenge = session.challenge;
    let binding = session.binding;
    let session_acceptance = session.receiver_acceptance;
    let offer_wire = session.offer_wire;
    let challenge_wire = session.challenge_wire;
    let binding_wire = session.binding_wire;
    let session_acceptance_wire = session.receiver_acceptance_wire;
    let session_establishment_us = session_started.elapsed().as_micros();
    let admission_started = Instant::now();
    let (envelope, receipt, output, envelope_wire) = harness.emit_and_admit(1)?;
    let emission_through_evaluation_us = admission_started.elapsed().as_micros();
    let certificate_a = harness.receiver_certificate(CANARY_CONSUMER_A);
    let certificate_b = harness.receiver_certificate(CANARY_CONSUMER_B);
    let deadline = certificate_a
        .earliest_support_expiry_monotonic_ms
        .ok_or("CURRENT certificate has no receiver deadline")?;

    write_bytes(
        directory,
        "receiver-acceptance-policy.json",
        &harness
            .receiver_policy
            .canonical_bytes()
            .map_err(|error| error.to_string())?,
        &mut files,
    )?;
    write_bytes(
        directory,
        "sender-emission-policy.json",
        &harness
            .sender_policy
            .canonical_bytes()
            .map_err(|error| error.to_string())?,
        &mut files,
    )?;
    write_json(
        directory,
        "peer-public-key-identities.json",
        &serde_json::json!({
            "schema_version": SCHEMA_VERSION_V1,
            "sender": harness.sender_key,
            "receiver": harness.receiver_key,
            "valid_signature_claim": "possession of one configured key over exact domain-separated bytes",
            "private_keys_included": false,
            "exclusive_key_custody_claimed": false
        }),
        &mut files,
    )?;
    for (name, kind, object, wire) in [
        (
            "sender-session-offer-corpus.json",
            "sender_session_offer_v1",
            serde_json::to_value(&offer).map_err(|error| error.to_string())?,
            &offer_wire,
        ),
        (
            "receiver-challenge-corpus.json",
            "receiver_session_challenge_v1",
            serde_json::to_value(&challenge).map_err(|error| error.to_string())?,
            &challenge_wire,
        ),
        (
            "sender-session-binding-corpus.json",
            "sender_session_binding_v1",
            serde_json::to_value(&binding).map_err(|error| error.to_string())?,
            &binding_wire,
        ),
        (
            "receiver-session-acceptance-corpus.json",
            "receiver_session_acceptance_v1",
            serde_json::to_value(&session_acceptance).map_err(|error| error.to_string())?,
            &session_acceptance_wire,
        ),
        (
            "observation-envelope-corpus.json",
            "observation_custody_envelope_v1",
            serde_json::to_value(&envelope).map_err(|error| error.to_string())?,
            &envelope_wire,
        ),
    ] {
        write_json(
            directory,
            name,
            &serde_json::json!({
                "schema_version": SCHEMA_VERSION_V1,
                "object_kind": kind,
                "canonical_wire_encoding": "PCN1 bounded binary v1",
                "diagnostic_projection": object,
                "datagram_hex": encode_lower_hex(wire),
                "datagram_bytes": wire.len(),
                "private_key_included": false
            }),
            &mut files,
        )?;
    }
    write_json(
        directory,
        "receiver-acceptance-corpus.json",
        &serde_json::json!({
            "schema_version": SCHEMA_VERSION_V1,
            "receipt": receipt,
            "consumer_a_certificate": certificate_a,
            "consumer_b_certificate": certificate_b,
            "trace": output.trace_lines,
            "acceptance_is_reliance": false
        }),
        &mut files,
    )?;

    let replay = harness.enqueue_and_admit_raw(&envelope_wire)?;
    let after_replay = harness.receiver_certificate(CANARY_CONSUMER_A);
    write_json(
        directory,
        "replay-and-sequence-corpus.json",
        &serde_json::json!({
            "schema_version": SCHEMA_VERSION_V1,
            "first_envelope_digest": envelope.envelope_digest,
            "first_arrival_monotonic_ms": receipt.receiver_arrival_monotonic_ms,
            "encoded_support_deadline_monotonic_ms": deadline,
            "replay_finding": replay.receipt.finding,
            "deadline_after_replay_monotonic_ms": after_replay.earliest_support_expiry_monotonic_ms,
            "freshness_renewed": after_replay.earliest_support_expiry_monotonic_ms != certificate_a.earliest_support_expiry_monotonic_ms,
            "duplicate_refusal_count": harness.receiver.duplicate_refusals(),
            "replay_refusal_count": harness.receiver.replay_refusals(),
            "sequence_gap_count": harness.receiver.sequence_gap_count()
        }),
        &mut files,
    )?;

    let mut substituted_body = envelope.body.clone();
    substituted_body.sender_manifest_digest =
        digest_parts("transport.hostile.substituted-manifest.v1", &[b"other"]);
    let (_, substituted_wire) =
        sign_observation_envelope(&harness.qualification_sender_key_copy, substituted_body)
            .map_err(|error| error.to_string())?;
    let substituted = harness.enqueue_and_admit_raw(&substituted_wire)?;
    let wrong_key = CanarySigningIdentityV1::generate(
        CustodyPeerRoleV1::Sender,
        vec!["host".to_owned()],
        "hostile-wrong-key-policy",
    )
    .map_err(|error| error.to_string())?;
    let mut wrong_body = envelope.body.clone();
    wrong_body.sender_key_identity_digest = wrong_key.key_identity().identity_digest();
    let (_, wrong_wire) =
        sign_observation_envelope(&wrong_key, wrong_body).map_err(|error| error.to_string())?;
    let wrong = harness.enqueue_and_admit_raw(&wrong_wire)?;
    write_json(
        directory,
        "authentication-mismatch-corpus.json",
        &serde_json::json!({
            "schema_version": SCHEMA_VERSION_V1,
            "checks": [
                {"scenario": "accepted key with substituted manifest", "finding": substituted.receipt.finding, "admitted": substituted.admitted()},
                {"scenario": "unaccepted sender key", "finding": wrong.receipt.finding, "admitted": wrong.admitted()}
            ],
            "all_refused": !substituted.admitted() && !wrong.admitted(),
            "freshness_renewed": false
        }),
        &mut files,
    )?;

    write_packages(directory, &harness, &mut files)?;
    write_json(
        directory,
        "authority-laundering-refusal-corpus.json",
        &serde_json::json!({
            "schema_version": SCHEMA_VERSION_V1,
            "objects_checked": ["peer key", "sender offer", "challenge", "session binding", "receiver session acceptance", "envelope", "acceptance receipt", "remote support reference"],
            "continuation": false,
            "transport_administration": false,
            "diagnostic_execution": false,
            "deployment": false,
            "signing": false,
            "revocation": false,
            "mutation": false
        }),
        &mut files,
    )?;

    let withdrawal = harness
        .receiver_reactor
        .as_ref()
        .ok_or("receiver stopped")?
        .wait_until(std::time::Duration::from_secs(2), |snapshot| {
            snapshot.observed_at_epoch_monotonic_ms >= deadline
                && !snapshot
                    .certificates
                    .iter()
                    .any(|certificate| certificate.judgment == JudgmentCategoryV1::Current)
        })
        .map_err(|error| error.to_string())?;
    write_json(
        directory,
        "live-local-linux-measurements.json",
        &serde_json::json!({
            "schema_version": SCHEMA_VERSION_V1,
            "exercise": "local deterministic custody; real UDP probe separately identified",
            "wall_clock_measurement": true,
            "session_establishment_us": session_establishment_us,
            "emission_through_evaluation_us": emission_through_evaluation_us,
            "expected_support_deadline_monotonic_ms": deadline,
            "actual_withdrawal_monotonic_ms": withdrawal.observed_at_epoch_monotonic_ms,
            "stale_positive_overshoot_ms": withdrawal.observed_at_epoch_monotonic_ms.saturating_sub(deadline),
            "envelope_bytes": envelope_wire.len(),
            "resident_memory_kib": resident_memory_kib(),
            "udp_loopback_probe": run_udp_loopback_probe(&envelope_wire),
            "hard_realtime_claimed": false,
            "two_host_claimed": false
        }),
        &mut files,
    )?;

    let mut competing_body = offer.body.clone();
    let competing_occurrence = IncarnationId::new("sender-process:artifact-competing-two");
    competing_body.sender_process_occurrence = competing_occurrence.clone();
    competing_body.sender_monotonic_epoch =
        IncarnationId::new("sender-epoch:artifact-competing-two");
    competing_body.sender_nonce_hex = "22".repeat(32);
    let (_, competing_wire) =
        sign_sender_session_offer(&harness.qualification_sender_key_copy, competing_body)
            .map_err(|error| error.to_string())?;
    let conflict = harness
        .receiver
        .accept_session_offer_and_issue_challenge(
            harness
                .receiver_reactor
                .as_ref()
                .ok_or("receiver stopped")?,
            &pulse_types::SubjectId::new(CANARY_SUBJECT),
            &pulse_types::ConsumerId::new(CANARY_CONSUMER_A),
            &competing_wire,
        )
        .expect_err("competing occurrence must be refused");
    write_json(
        directory,
        "competing-occurrence-corpus.json",
        &serde_json::json!({
            "schema_version": SCHEMA_VERSION_V1,
            "first_sender_process_occurrence": binding.body.sender_process_occurrence,
            "competing_sender_process_occurrence": competing_occurrence,
            "finding": conflict.finding,
            "live_sessions_after": harness.receiver.live_session_count(),
            "last_arrival_won": false,
            "positive_surface_after": harness.receiver_reactor.as_ref().unwrap().snapshot().certificates.iter().any(|certificate| certificate.judgment == JudgmentCategoryV1::Current)
        }),
        &mut files,
    )?;

    harness.shutdown()?;

    write_json(
        directory,
        "crash-restart-corpus.json",
        &serde_json::json!({
            "schema_version": SCHEMA_VERSION_V1,
            "deterministic_restart": run_restart_custody_demo()?,
            "real_sigkill_tests": [
                {"point": "sender_qualified", "test": "sigkill_before_session_during_session_and_after_signing_restores_no_live_custody"},
                {"point": "session_active", "test": "sigkill_before_session_during_session_and_after_signing_restores_no_live_custody"},
                {"point": "envelope_signed", "test": "sigkill_before_session_during_session_and_after_signing_restores_no_live_custody"},
                {"point": "receiver_current", "test": "sigkill_while_remote_current_recovers_history_but_no_session_evidence_or_standing"}
            ],
            "unexposed_atomic_injection_points": [
                "receipt journaled before evaluator admission",
                "evidence admission before support-certificate journaling"
            ]
        }),
        &mut files,
    )?;
    write_qualification_summary(directory, &mut files)?;
    files.sort();
    let set = GeneratedArtifactSetV1 {
        schema_version: SCHEMA_VERSION_V1,
        campaign: "receiver-boundary-custody".to_owned(),
        files: files.clone(),
        private_key_material_written: false,
    };
    write_json(directory, "artifact-index.json", &set, &mut files)?;
    Ok(set)
}
