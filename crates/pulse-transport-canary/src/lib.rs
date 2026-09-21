#![forbid(unsafe_code)]

//! Narrow two-peer custody canary and deterministic qualification fixture.
//! It is intentionally one sender, one receiver, one UDP-shaped message path,
//! and not a reusable RPC or peer-discovery framework.

mod artifacts;
pub use artifacts::*;

use std::collections::BTreeMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use pulse_evaluator::ReliancePolicyV1;
use pulse_runtime::{
    BoundedUdpCanarySocketV1, CanarySigningIdentityV1, ConsumerRegistrationV1, HistoricalJournal,
    JournalBoundsV1, JournalConfigV1, LocalCrashReactor, LocalQualificationPackageV1,
    MonotonicEpochV1, ReactorConfigV1, ReceiverCustodyV1, ReceiverEnvelopeAdmissionV1,
    ReceiverSchedulerRuntime, RuntimeBoundsV1, RuntimeConfigV1, RuntimeCycleOutputV1,
    SenderCustodyV1, build_local_qualification_package, decode_observation_envelope_datagram,
    decode_receiver_challenge_datagram, decode_receiver_session_acceptance_datagram,
    decode_sender_session_binding_datagram, decode_sender_session_offer_datagram,
    qualification_fixture_inputs, sign_receiver_challenge,
};
use pulse_types::{
    AuthenticationFieldV1, BoundedSignalValueV1, ClockId, ConsumerId, ConsumerProfileGenerationId,
    ContextActivationId, CoverageDescriptorV1, CustodyAuthorityGrantsV1,
    CustodyCertificateStatusV1, CustodyPeerRoleV1, DigestV1, EvaluatorSemanticGenerationId,
    IncarnationId, JudgmentCategoryV1, ObservationCustodyEnvelopeV1, ObservationCustodyKindV1,
    ObservationPolicyGenerationId, ObservationProfileIdV1, ObserverId, ObserverSetGenerationId,
    PeerKeyIdentityV1, PolicyGenerationId, PulseFrameV1, ReceiverAcceptancePolicyV1,
    ReceiverAcceptanceReceiptV1, ReceiverId, ReceiverSessionAcceptanceV1,
    ReceiverSessionChallengeBodyV1, ReceiverSessionChallengeV1, RelianceContextV1,
    RelianceSupportCertificateV1, RemoteFreshnessModeV1, RuntimeBindingStateV1, SCHEMA_VERSION_V1,
    SenderEmissionPolicyV1, SenderSessionBindingV1, SenderSessionOfferV1, SignalAssessmentV1,
    SubjectId, SubjectScopeV1, TransportCustodyFindingV1, digest_parts,
};
use serde::{Deserialize, Serialize};

pub const CAMPAIGN_STARTING_COMMIT: &str = "94c4c8ee8e7de89edee212abc823e97c809fc26a";
pub const CANARY_SUBJECT: &str = "subject:remote-canary";
pub const CANARY_SUBJECT_INCAR: &str = "subject-incarnation:remote-one";
pub const CANARY_OBSERVER: &str = "observer:remote-canary";
pub const CANARY_OBSERVER_INCAR: &str = "observer-incarnation:remote-one";
pub const CANARY_CONSUMER_A: &str = "consumer:capacity-display";
pub const CANARY_CONSUMER_B: &str = "consumer:destructive-automation";
pub const CANARY_FAILURE_DOMAIN: &str = "configured-failure-domain:rack-a";
pub const CANARY_VALIDITY_MS: u64 = 120;
pub const CANARY_SESSION_DURATION_MS: u64 = 750;
pub const CANARY_MAX_DATAGRAM: u16 = 1_232;
const CRASH_CURRENT_VALIDITY_MS: u64 = 5_000;

static NEXT_PATH: AtomicU64 = AtomicU64::new(1);
// The local custody canary has deliberately short session bounds. Running many
// harnesses concurrently in one qualification binary can consume that bound
// in scheduler delay instead of exercising the named case. Serialize harness
// instances within a process; this is test-fixture coordination, not transport
// or authority state.
static CANARY_HARNESS_SERIALIZER: Mutex<()> = Mutex::new(());

fn temp_journal_path(role: &str) -> PathBuf {
    let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "monitor-custody-{role}-{}-{sequence}.journal",
        std::process::id()
    ))
}

fn deterministic_datagram_transfer(bytes: &[u8]) -> (Vec<u8>, String) {
    (
        bytes.to_vec(),
        "deterministic-direct-datagram-harness".to_owned(),
    )
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UdpLoopbackProbeV1 {
    pub schema_version: u16,
    pub actual_udp_socket_executed: bool,
    pub exact_bytes_preserved: bool,
    pub datagram_bytes: usize,
    pub sender_endpoint: Option<String>,
    pub receiver_endpoint: Option<String>,
    pub refusal: Option<String>,
    pub two_host_claimed: bool,
}

pub fn run_udp_loopback_probe(bytes: &[u8]) -> UdpLoopbackProbeV1 {
    match udp_loopback_transfer(bytes) {
        Ok((received, sender_endpoint, receiver_endpoint)) => UdpLoopbackProbeV1 {
            schema_version: SCHEMA_VERSION_V1,
            actual_udp_socket_executed: true,
            exact_bytes_preserved: received == bytes,
            datagram_bytes: bytes.len(),
            sender_endpoint: Some(sender_endpoint.to_string()),
            receiver_endpoint: Some(receiver_endpoint.to_string()),
            refusal: None,
            two_host_claimed: false,
        },
        Err(error) => UdpLoopbackProbeV1 {
            schema_version: SCHEMA_VERSION_V1,
            actual_udp_socket_executed: false,
            exact_bytes_preserved: false,
            datagram_bytes: bytes.len(),
            sender_endpoint: None,
            receiver_endpoint: None,
            refusal: Some(error),
            two_host_claimed: false,
        },
    }
}

fn udp_loopback_transfer(bytes: &[u8]) -> Result<(Vec<u8>, SocketAddr, SocketAddr), String> {
    let sender = BoundedUdpCanarySocketV1::bind(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        usize::from(CANARY_MAX_DATAGRAM),
    )
    .map_err(|error| error.to_string())?;
    let receiver = BoundedUdpCanarySocketV1::bind(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        usize::from(CANARY_MAX_DATAGRAM),
    )
    .map_err(|error| error.to_string())?;
    sender
        .send_to(
            bytes,
            receiver.local_addr().map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
    let received = receiver.receive().map_err(|error| error.to_string())?;
    if received.bytes != bytes {
        return Err("UDP canary did not preserve exact datagram bytes".to_owned());
    }
    Ok((
        received.bytes,
        received.remote_endpoint,
        receiver.local_addr().map_err(|error| error.to_string())?,
    ))
}

#[must_use]
pub fn canary_scope() -> SubjectScopeV1 {
    SubjectScopeV1 {
        subject: SubjectId::new(CANARY_SUBJECT),
        subject_incarnation: IncarnationId::new(CANARY_SUBJECT_INCAR),
        scope: "host".to_owned(),
    }
}

#[must_use]
pub fn canary_profile() -> ObservationProfileIdV1 {
    ObservationProfileIdV1 {
        name: "profile:remote-canary".to_owned(),
        version: 1,
        semantic_digest: digest_parts("transport.canary.profile.v1", &[b"load"]),
    }
}

#[must_use]
pub fn canary_registration(consumer: &str, minimum_observers: u32) -> ConsumerRegistrationV1 {
    canary_registration_with_validity(consumer, minimum_observers, CANARY_VALIDITY_MS)
}

fn canary_registration_with_validity(
    consumer: &str,
    minimum_observers: u32,
    maximum_validity_ms: u64,
) -> ConsumerRegistrationV1 {
    let policy = ReliancePolicyV1 {
        schema_version: SCHEMA_VERSION_V1,
        subject: SubjectId::new(CANARY_SUBJECT),
        scope: "host".to_owned(),
        consumer: ConsumerId::new(consumer),
        generation: PolicyGenerationId::new(format!("policy:remote-canary:{consumer}")),
        observation_policy_generation: ObservationPolicyGenerationId::new(
            "observation-policy:remote-canary-one",
        ),
        observation_profile: canary_profile(),
        required_coverage: vec!["load".to_owned()],
        minimum_observers,
        maximum_validity_ms,
        require_verified_authentication: true,
        coherence_tolerances: BTreeMap::new(),
        observer_failure_domains: [(CANARY_OBSERVER.to_owned(), CANARY_FAILURE_DOMAIN.to_owned())]
            .into_iter()
            .collect(),
        escalation: None,
    };
    ConsumerRegistrationV1 {
        context: RelianceContextV1 {
            schema_version: SCHEMA_VERSION_V1,
            activation_id: ContextActivationId::new(format!("activation:remote-canary:{consumer}")),
            reliance_policy_generation: policy.generation.clone(),
            reliance_policy_semantic_digest: policy.semantic_digest(),
            consumer_profile_generation: ConsumerProfileGenerationId::new(format!(
                "consumer-profile:remote-canary:{consumer}"
            )),
            evaluator_semantic_generation: EvaluatorSemanticGenerationId::new(
                "evaluator:remote-canary-one",
            ),
            observer_set_generation: ObserverSetGenerationId::new(format!(
                "observer-set:remote-canary:{minimum_observers}"
            )),
            observation_policy_generation: policy.observation_policy_generation.clone(),
        },
        policy,
        subject_incarnation: IncarnationId::new(CANARY_SUBJECT_INCAR),
    }
}

#[must_use]
pub fn canary_pulse(sequence: u64) -> PulseFrameV1 {
    canary_pulse_with_validity(sequence, CANARY_VALIDITY_MS)
}

fn canary_pulse_with_validity(sequence: u64, validity_ms: u64) -> PulseFrameV1 {
    PulseFrameV1 {
        schema_version: SCHEMA_VERSION_V1,
        subject: SubjectId::new(CANARY_SUBJECT),
        subject_incarnation: IncarnationId::new(CANARY_SUBJECT_INCAR),
        observer: ObserverId::new(CANARY_OBSERVER),
        observer_incarnation: IncarnationId::new(CANARY_OBSERVER_INCAR),
        sequence,
        observer_monotonic_ns: sequence.saturating_mul(1_000_000),
        validity_ms,
        profile: canary_profile(),
        observation_policy_generation: ObservationPolicyGenerationId::new(
            "observation-policy:remote-canary-one",
        ),
        coverage: CoverageDescriptorV1 {
            expected: vec!["load".to_owned()],
            observed: vec!["load".to_owned()],
        },
        signals: vec![BoundedSignalValueV1 {
            name: "load_ratio".to_owned(),
            value: 0.25,
            unit: "ratio".to_owned(),
            assessment: SignalAssessmentV1::WithinDeclaredBound,
        }],
        observation_digest: digest_parts("transport.canary.unsealed.v1", &[]),
        authentication: AuthenticationFieldV1::Placeholder {
            disclosure: "message signature is verified at the receiver boundary".to_owned(),
        },
    }
    .seal()
}

fn sender_policy(
    sender_key: &PeerKeyIdentityV1,
    receiver_key: &PeerKeyIdentityV1,
    receiver_policy_anchor_digest: DigestV1,
) -> SenderEmissionPolicyV1 {
    SenderEmissionPolicyV1 {
        schema_version: SCHEMA_VERSION_V1,
        policy_generation: "sender-emission-policy:canary-one".to_owned(),
        sender_key: sender_key.clone(),
        accepted_receiver_key: receiver_key.clone(),
        accepted_receiver_policy_generation: "receiver-acceptance-policy:canary-one".to_owned(),
        accepted_receiver_policy_anchor_digest: receiver_policy_anchor_digest,
        observer: ObserverId::new(CANARY_OBSERVER),
        failure_domain_claim: CANARY_FAILURE_DOMAIN.to_owned(),
        permitted_subject_scopes: vec![canary_scope()],
        permitted_observation_kinds: vec![ObservationCustodyKindV1::PulseV1],
        maximum_datagram_bytes: CANARY_MAX_DATAGRAM,
        sender_queue_bound: 8,
        authority_grants: CustodyAuthorityGrantsV1::none(),
    }
}

fn receiver_policy(
    receiver_key: &PeerKeyIdentityV1,
    sender_key: &PeerKeyIdentityV1,
    sender_package: &LocalQualificationPackageV1,
    observation_time_freshness_required: bool,
    maximum_messages_per_session: u32,
    maximum_messages_per_second: u32,
    maximum_session_duration_ms: u64,
) -> ReceiverAcceptancePolicyV1 {
    receiver_policy_with_digests(
        receiver_key,
        sender_key,
        sender_package.manifest.manifest_digest.clone(),
        sender_package.certificate.certificate_digest.clone(),
        observation_time_freshness_required,
        maximum_messages_per_session,
        maximum_messages_per_second,
        maximum_session_duration_ms,
    )
}

#[allow(clippy::too_many_arguments)]
fn receiver_policy_with_digests(
    receiver_key: &PeerKeyIdentityV1,
    sender_key: &PeerKeyIdentityV1,
    sender_manifest_digest: DigestV1,
    sender_certificate_digest: DigestV1,
    observation_time_freshness_required: bool,
    maximum_messages_per_session: u32,
    maximum_messages_per_second: u32,
    maximum_session_duration_ms: u64,
) -> ReceiverAcceptancePolicyV1 {
    ReceiverAcceptancePolicyV1 {
        schema_version: SCHEMA_VERSION_V1,
        policy_generation: "receiver-acceptance-policy:canary-one".to_owned(),
        receiver_key: receiver_key.clone(),
        accepted_sender_key: sender_key.clone(),
        accepted_sender_manifest_digest: sender_manifest_digest,
        accepted_sender_certificate_digest: sender_certificate_digest,
        accepted_protocol_version: pulse_types::CUSTODY_PROTOCOL_VERSION_V1,
        accepted_pulse_schema_version: SCHEMA_VERSION_V1,
        accepted_observer: ObserverId::new(CANARY_OBSERVER),
        accepted_failure_domain_claim: CANARY_FAILURE_DOMAIN.to_owned(),
        permitted_subject_scopes: vec![canary_scope()],
        permitted_observation_kinds: vec![ObservationCustodyKindV1::PulseV1],
        maximum_datagram_bytes: CANARY_MAX_DATAGRAM,
        maximum_session_duration_ms,
        maximum_messages_per_session,
        maximum_messages_per_second,
        receiver_queue_bound: 8,
        replay_window_size: 16,
        maximum_sequence_gap: 8,
        certificate_status: CustodyCertificateStatusV1::Accepted,
        lifecycle_authority_id: "local-custody-lifecycle-authority:canary".to_owned(),
        freshness_mode: RemoteFreshnessModeV1::ArrivalAnchored,
        arrival_anchored_evidence_may_support_reliance: !observation_time_freshness_required,
        observation_time_freshness_required,
        journal_id: "journal:receiver-custody-canary".to_owned(),
        authority_grants: CustodyAuthorityGrantsV1::none(),
    }
}

fn runtime_config(
    role: &str,
    binding: pulse_types::TransportCustodyPolicyBindingV1,
) -> RuntimeConfigV1 {
    RuntimeConfigV1 {
        schema_version: SCHEMA_VERSION_V1,
        receiver: ReceiverId::new(format!("receiver:{role}:custody-canary")),
        receiver_incarnation: IncarnationId::new(format!("receiver-incarnation:{role}:one")),
        clock_id: ClockId::new(format!("clock:{role}:one")),
        transport_custody_policy: Some(binding),
        bounds: RuntimeBoundsV1::qualification(),
    }
}

fn qualification_package(
    config: &RuntimeConfigV1,
    registration: &ConsumerRegistrationV1,
) -> Result<LocalQualificationPackageV1, String> {
    let mut inputs = qualification_fixture_inputs(CAMPAIGN_STARTING_COMMIT, 1);
    inputs.declared_claims = vec![
        "exact_active_artifact_binding/v1".to_owned(),
        "restart_requires_new_activation/v1".to_owned(),
        "transport_custody_semantic_fixture/v1".to_owned(),
    ];
    inputs.nonclaims.push("not_remote_attestation".to_owned());
    inputs
        .nonclaims
        .push("not_transport_delay_bound".to_owned());
    inputs
        .nonclaims
        .push("not_campaign_qualification_evidence".to_owned());
    inputs.nonclaims.sort();
    inputs.nonclaims.dedup();
    build_local_qualification_package(config, registration, inputs)
        .map_err(|error| error.to_string())
}

fn activate_runtime(
    config: RuntimeConfigV1,
    registrations_and_packages: &[(&ConsumerRegistrationV1, &LocalQualificationPackageV1)],
) -> Result<ReceiverSchedulerRuntime, String> {
    let mut runtime = ReceiverSchedulerRuntime::new(config).map_err(|error| error.to_string())?;
    for (registration, _) in registrations_and_packages {
        runtime
            .register_consumer((*registration).clone(), 0)
            .map_err(|error| error.to_string())?;
    }
    for (registration, package) in registrations_and_packages {
        runtime
            .activate_qualified_binding(
                registration,
                Some(
                    &package
                        .manifest_bytes()
                        .map_err(|error| error.to_string())?,
                ),
                Some(
                    &package
                        .certificate_bytes()
                        .map_err(|error| error.to_string())?,
                ),
                Some(&package.report_bytes().map_err(|error| error.to_string())?),
                package.acceptance.clone(),
                0,
            )
            .map_err(|error| error.to_string())?;
    }
    Ok(runtime)
}

fn journal_config(role: &str) -> JournalConfigV1 {
    JournalConfigV1 {
        schema_version: SCHEMA_VERSION_V1,
        journal_id: format!("journal:transport-canary:{role}"),
        bounds: JournalBoundsV1 {
            maximum_records: 512,
            maximum_record_payload_bytes: 256 * 1_024,
            maximum_file_bytes: 16 * 1_024 * 1_024,
        },
    }
}

#[must_use]
pub fn receiver_journal_config() -> JournalConfigV1 {
    journal_config("receiver")
}

#[must_use]
pub fn sender_journal_config() -> JournalConfigV1 {
    journal_config("sender")
}

fn start_reactor(
    role: &str,
    runtime: ReceiverSchedulerRuntime,
) -> Result<(LocalCrashReactor, PathBuf), String> {
    let path = temp_journal_path(role);
    let journal = HistoricalJournal::create_new(&path, journal_config(role))
        .map_err(|error| error.to_string())?;
    let config = runtime.config().clone();
    let epoch = MonotonicEpochV1 {
        schema_version: SCHEMA_VERSION_V1,
        epoch_id: IncarnationId::new(format!("monotonic-epoch:{role}:one")),
        receiver: config.receiver.clone(),
        receiver_incarnation: config.receiver_incarnation.clone(),
        clock_id: config.clock_id.clone(),
        origin_runtime_monotonic_ms: runtime.current_monotonic_ms(),
        clock_source: "std::time::Instant/process-local".to_owned(),
    };
    let reactor =
        LocalCrashReactor::start(runtime, journal, epoch, ReactorConfigV1::qualification())
            .map_err(|error| error.to_string())?;
    reactor
        .wait_until(Duration::from_secs(2), |snapshot| {
            snapshot.condition == pulse_runtime::ReactorConditionV1::Operational
        })
        .map_err(|error| error.to_string())?;
    Ok((reactor, path))
}

pub struct CanaryHarnessV1 {
    pub sender: SenderCustodyV1,
    pub receiver: ReceiverCustodyV1,
    pub sender_reactor: Option<LocalCrashReactor>,
    pub receiver_reactor: Option<LocalCrashReactor>,
    pub sender_package: LocalQualificationPackageV1,
    pub receiver_package_a: LocalQualificationPackageV1,
    pub receiver_package_b: LocalQualificationPackageV1,
    pub sender_key: PeerKeyIdentityV1,
    pub receiver_key: PeerKeyIdentityV1,
    pub sender_policy: SenderEmissionPolicyV1,
    pub receiver_policy: ReceiverAcceptancePolicyV1,
    pub qualification_sender_key_copy: CanarySigningIdentityV1,
    receiver_restart_key_copy: Option<CanarySigningIdentityV1>,
    journal_paths: Vec<PathBuf>,
    pulse_validity_ms: u64,
    _serial_guard: MutexGuard<'static, ()>,
}

#[derive(Debug)]
pub struct EstablishedCanarySessionV1 {
    pub offer: SenderSessionOfferV1,
    pub challenge: ReceiverSessionChallengeV1,
    pub binding: SenderSessionBindingV1,
    pub receiver_acceptance: ReceiverSessionAcceptanceV1,
    pub offer_wire: Vec<u8>,
    pub challenge_wire: Vec<u8>,
    pub binding_wire: Vec<u8>,
    pub receiver_acceptance_wire: Vec<u8>,
}

impl CanaryHarnessV1 {
    pub fn deterministic() -> Result<Self, String> {
        Self::deterministic_with_options(false, 16, 16)
    }

    pub fn observation_time_freshness_required() -> Result<Self, String> {
        Self::deterministic_with_options(true, 16, 16)
    }

    pub fn with_transport_limits(
        maximum_messages_per_session: u32,
        maximum_messages_per_second: u32,
    ) -> Result<Self, String> {
        Self::deterministic_with_options(
            false,
            maximum_messages_per_session,
            maximum_messages_per_second,
        )
    }

    /// Construct the same deterministic canary with a longer session window
    /// for loaded local qualification hosts. This changes only the fixture
    /// policy bound; it does not change the canonical 750 ms artifact profile.
    pub fn with_qualification_session(
        observation_time_freshness_required: bool,
        maximum_messages_per_session: u32,
        maximum_messages_per_second: u32,
        maximum_session_duration_ms: u64,
    ) -> Result<Self, String> {
        if maximum_session_duration_ms == 0 || maximum_session_duration_ms > 60_000 {
            return Err("qualification session duration is outside its bounded range".to_owned());
        }
        Self::deterministic_with_options_and_validity(
            observation_time_freshness_required,
            maximum_messages_per_session,
            maximum_messages_per_second,
            CANARY_VALIDITY_MS,
            maximum_session_duration_ms,
        )
    }

    fn deterministic_with_options(
        observation_time_freshness_required: bool,
        maximum_messages_per_session: u32,
        maximum_messages_per_second: u32,
    ) -> Result<Self, String> {
        Self::deterministic_with_options_and_validity(
            observation_time_freshness_required,
            maximum_messages_per_session,
            maximum_messages_per_second,
            CANARY_VALIDITY_MS,
            CANARY_SESSION_DURATION_MS,
        )
    }

    fn deterministic_with_options_and_validity(
        observation_time_freshness_required: bool,
        maximum_messages_per_session: u32,
        maximum_messages_per_second: u32,
        pulse_validity_ms: u64,
        maximum_session_duration_ms: u64,
    ) -> Result<Self, String> {
        let serial_guard = CANARY_HARNESS_SERIALIZER
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (sender_signing, qualification_sender_key_copy) =
            CanarySigningIdentityV1::generate_qualification_pair(
                CustodyPeerRoleV1::Sender,
                vec!["host".to_owned()],
                "sender-local-policy:canary",
            )
            .map_err(|error| error.to_string())?;
        let (receiver_signing, receiver_restart_key_copy) =
            CanarySigningIdentityV1::generate_qualification_pair(
                CustodyPeerRoleV1::Receiver,
                vec!["host".to_owned()],
                "receiver-local-policy:canary",
            )
            .map_err(|error| error.to_string())?;
        let sender_key = sender_signing.key_identity().clone();
        let receiver_key = receiver_signing.key_identity().clone();
        let receiver_policy_template = receiver_policy_with_digests(
            &receiver_key,
            &sender_key,
            digest_parts("transport.canary.pending-sender-manifest.v1", &[b"pending"]),
            digest_parts(
                "transport.canary.pending-sender-certificate.v1",
                &[b"pending"],
            ),
            observation_time_freshness_required,
            maximum_messages_per_session,
            maximum_messages_per_second,
            maximum_session_duration_ms,
        );
        let receiver_policy_anchor_digest = receiver_policy_template.anchor_digest();
        let sender_policy = sender_policy(
            &sender_key,
            &receiver_key,
            receiver_policy_anchor_digest.clone(),
        );
        sender_policy
            .validate()
            .map_err(|error| error.to_string())?;
        let sender_config = runtime_config("sender", sender_policy.binding());
        let sender_registration =
            canary_registration_with_validity(CANARY_CONSUMER_A, 1, pulse_validity_ms);
        let sender_package = qualification_package(&sender_config, &sender_registration)?;

        let receiver_policy = receiver_policy(
            &receiver_key,
            &sender_key,
            &sender_package,
            observation_time_freshness_required,
            maximum_messages_per_session,
            maximum_messages_per_second,
            maximum_session_duration_ms,
        );
        receiver_policy
            .validate()
            .map_err(|error| error.to_string())?;
        if receiver_policy.anchor_digest() != receiver_policy_anchor_digest {
            return Err(
                "receiver policy anchor changed while binding the exact sender package".to_owned(),
            );
        }
        let receiver_config = runtime_config("receiver", receiver_policy.binding());
        let receiver_registration_a =
            canary_registration_with_validity(CANARY_CONSUMER_A, 1, pulse_validity_ms);
        let receiver_registration_b =
            canary_registration_with_validity(CANARY_CONSUMER_B, 2, pulse_validity_ms);
        let receiver_package_a = qualification_package(&receiver_config, &receiver_registration_a)?;
        let receiver_package_b = qualification_package(&receiver_config, &receiver_registration_b)?;

        let sender_runtime =
            activate_runtime(sender_config, &[(&sender_registration, &sender_package)])?;
        let receiver_runtime = activate_runtime(
            receiver_config,
            &[
                (&receiver_registration_a, &receiver_package_a),
                (&receiver_registration_b, &receiver_package_b),
            ],
        )?;
        let (sender_reactor, sender_path) = start_reactor("sender", sender_runtime)?;
        let (receiver_reactor, receiver_path) = start_reactor("receiver", receiver_runtime)?;

        let sender = SenderCustodyV1::new(sender_signing, sender_policy.clone())
            .map_err(|error| error.to_string())?;
        let receiver = ReceiverCustodyV1::new(
            receiver_signing,
            receiver_policy.clone(),
            &sender_package
                .manifest_bytes()
                .map_err(|error| error.to_string())?,
            &sender_package
                .report_bytes()
                .map_err(|error| error.to_string())?,
            &sender_package
                .certificate_bytes()
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        Ok(Self {
            sender,
            receiver,
            sender_reactor: Some(sender_reactor),
            receiver_reactor: Some(receiver_reactor),
            sender_package,
            receiver_package_a,
            receiver_package_b,
            sender_key,
            receiver_key,
            sender_policy,
            receiver_policy,
            qualification_sender_key_copy,
            receiver_restart_key_copy: Some(receiver_restart_key_copy),
            journal_paths: vec![sender_path, receiver_path],
            pulse_validity_ms,
            _serial_guard: serial_guard,
        })
    }

    #[must_use]
    pub fn sender_journal_path(&self) -> &std::path::Path {
        &self.journal_paths[0]
    }

    #[must_use]
    pub fn receiver_journal_path(&self) -> &std::path::Path {
        &self.journal_paths[1]
    }

    pub fn establish_session(&mut self) -> Result<EstablishedCanarySessionV1, String> {
        let subject = SubjectId::new(CANARY_SUBJECT);
        let consumer = ConsumerId::new(CANARY_CONSUMER_A);
        let receiver_reactor = self.receiver_reactor.as_ref().ok_or("receiver stopped")?;
        let sender_reactor = self.sender_reactor.as_ref().ok_or("sender stopped")?;
        let offer_bytes = self
            .sender
            .create_session_offer(sender_reactor, &subject, &consumer)
            .map_err(|error| error.to_string())?;
        let (received_offer, _) = deterministic_datagram_transfer(&offer_bytes);
        let offer = decode_sender_session_offer_datagram(&received_offer, &self.sender_key)
            .map_err(|error| error.to_string())?;
        let challenge_bytes = self
            .receiver
            .accept_session_offer_and_issue_challenge(
                receiver_reactor,
                &subject,
                &consumer,
                &received_offer,
            )
            .map_err(|error| error.to_string())?;
        let (received_challenge, _) = deterministic_datagram_transfer(&challenge_bytes);
        let challenge = decode_receiver_challenge_datagram(&received_challenge, &self.receiver_key)
            .map_err(|error| error.to_string())?;
        let binding_bytes = self
            .sender
            .accept_receiver_challenge(sender_reactor, &subject, &consumer, &received_challenge)
            .map_err(|error| error.to_string())?;
        let (received_binding, _) = deterministic_datagram_transfer(&binding_bytes);
        let binding = decode_sender_session_binding_datagram(&received_binding, &self.sender_key)
            .map_err(|error| error.to_string())?;
        let acceptance_bytes = self
            .receiver
            .accept_session_binding(receiver_reactor, &subject, &consumer, &received_binding)
            .map_err(|error| error.to_string())?;
        let (received_acceptance, _) = deterministic_datagram_transfer(&acceptance_bytes);
        let acceptance =
            decode_receiver_session_acceptance_datagram(&received_acceptance, &self.receiver_key)
                .map_err(|error| error.to_string())?;
        self.sender
            .accept_receiver_session_acceptance(
                sender_reactor,
                &subject,
                &consumer,
                &received_acceptance,
            )
            .map_err(|error| error.to_string())?;
        Ok(EstablishedCanarySessionV1 {
            offer,
            challenge,
            binding,
            receiver_acceptance: acceptance,
            offer_wire: offer_bytes,
            challenge_wire: challenge_bytes,
            binding_wire: binding_bytes,
            receiver_acceptance_wire: acceptance_bytes,
        })
    }

    /// Sign a receiver challenge with the harness-only duplicate key holder so
    /// hostile authenticated receiver assertions can be tested. This helper
    /// deliberately demonstrates no exclusive-key-custody claim.
    pub fn sign_receiver_challenge_for_qualification(
        &self,
        body: ReceiverSessionChallengeBodyV1,
    ) -> Result<Vec<u8>, String> {
        let signing = self
            .receiver_restart_key_copy
            .as_ref()
            .ok_or("receiver qualification key holder is unavailable")?;
        let (_, datagram) =
            sign_receiver_challenge(signing, body).map_err(|error| error.to_string())?;
        Ok(datagram)
    }

    pub fn emit_and_admit(
        &mut self,
        sequence: u64,
    ) -> Result<
        (
            ObservationCustodyEnvelopeV1,
            ReceiverAcceptanceReceiptV1,
            RuntimeCycleOutputV1,
            Vec<u8>,
        ),
        String,
    > {
        let subject = SubjectId::new(CANARY_SUBJECT);
        let consumer = ConsumerId::new(CANARY_CONSUMER_A);
        let sender_reactor = self.sender_reactor.as_ref().ok_or("sender stopped")?;
        let receiver_reactor = self.receiver_reactor.as_ref().ok_or("receiver stopped")?;
        let datagram = self
            .sender
            .emit_pulse(
                sender_reactor,
                &subject,
                &consumer,
                &canary_pulse_with_validity(sequence, self.pulse_validity_ms),
            )
            .map_err(|error| error.to_string())?;
        let queued = self
            .sender
            .pop_queued_datagram()
            .ok_or("sender did not retain the bounded datagram")?;
        if queued != datagram {
            return Err("sender queue altered exact envelope bytes".to_owned());
        }
        let (received_datagram, remote_endpoint) = deterministic_datagram_transfer(&datagram);
        let envelope = decode_observation_envelope_datagram(&received_datagram, &self.sender_key)
            .map_err(|error| error.to_string())?;
        self.receiver
            .enqueue_envelope(receiver_reactor, received_datagram, remote_endpoint)
            .map_err(|error| error.to_string())?;
        let admission = self
            .receiver
            .admit_next(receiver_reactor, &subject, &consumer)
            .map_err(|error| error.to_string())?;
        let receipt = admission.receipt.clone();
        let output = receiver_reactor
            .submit_input(
                admission
                    .into_runtime_input()
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        Ok((envelope, receipt, output, datagram))
    }

    pub fn enqueue_and_admit_raw(
        &mut self,
        datagram: &[u8],
    ) -> Result<ReceiverEnvelopeAdmissionV1, String> {
        let subject = SubjectId::new(CANARY_SUBJECT);
        let consumer = ConsumerId::new(CANARY_CONSUMER_A);
        let receiver_reactor = self.receiver_reactor.as_ref().ok_or("receiver stopped")?;
        let (received, remote_endpoint) = deterministic_datagram_transfer(datagram);
        self.receiver
            .enqueue_envelope(receiver_reactor, received, remote_endpoint)
            .map_err(|error| error.to_string())?;
        self.receiver
            .admit_next(receiver_reactor, &subject, &consumer)
            .map_err(|error| error.to_string())
    }

    #[must_use]
    pub fn receiver_certificate(&self, consumer: &str) -> RelianceSupportCertificateV1 {
        self.receiver_reactor
            .as_ref()
            .expect("receiver reactor is live")
            .snapshot()
            .certificates
            .into_iter()
            .find(|certificate| certificate.consumer == ConsumerId::new(consumer))
            .expect("registered consumer has a certificate")
    }

    pub fn shutdown(mut self) -> Result<(), String> {
        if let Some(reactor) = self.sender_reactor.take() {
            reactor.shutdown().map_err(|error| error.to_string())?;
        }
        if let Some(reactor) = self.receiver_reactor.take() {
            reactor.shutdown().map_err(|error| error.to_string())?;
        }
        for path in &self.journal_paths {
            fs::remove_file(path).map_err(|error| error.to_string())?;
        }
        self.journal_paths.clear();
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrashChildReadyV1 {
    pub schema_version: u16,
    pub point: String,
    pub process_id: u32,
    pub sender_journal_path: String,
    pub receiver_journal_path: String,
    pub receiver_policy_binding: pulse_types::TransportCustodyPolicyBindingV1,
    pub sender_live_sessions_before_kill: usize,
    pub receiver_live_sessions_before_kill: usize,
    pub receiver_judgment_before_kill: JudgmentCategoryV1,
    pub pulse_validity_ms: u64,
    pub private_key_material_serialized: bool,
}

pub fn run_crash_child(point: &str, ready_path: &std::path::Path) -> Result<(), String> {
    // The receiver-current qualification kills the child after a separate
    // process observes its create-only ready marker. Give that coordination
    // window a distinct bound so host scheduling pressure cannot turn the
    // intended CURRENT kill point into an expiry-write race. Other canary
    // profiles retain the public 120 ms validity.
    let mut harness = if point == "receiver_current" {
        CanaryHarnessV1::deterministic_with_options_and_validity(
            false,
            16,
            16,
            CRASH_CURRENT_VALIDITY_MS,
            CANARY_SESSION_DURATION_MS,
        )?
    } else {
        CanaryHarnessV1::deterministic()?
    };
    match point {
        "sender_qualified" => {}
        "session_active" => {
            harness.establish_session()?;
        }
        "envelope_signed" => {
            harness.establish_session()?;
            let datagram = harness
                .sender
                .emit_pulse(
                    harness.sender_reactor.as_ref().ok_or("sender stopped")?,
                    &SubjectId::new(CANARY_SUBJECT),
                    &ConsumerId::new(CANARY_CONSUMER_A),
                    &canary_pulse(1),
                )
                .map_err(|error| error.to_string())?;
            if datagram.is_empty() {
                return Err("signed envelope is unexpectedly empty".to_owned());
            }
        }
        "receiver_current" => {
            harness.establish_session()?;
            harness.emit_and_admit(1)?;
        }
        _ => return Err(format!("unsupported crash child point: {point}")),
    }
    let ready = CrashChildReadyV1 {
        schema_version: SCHEMA_VERSION_V1,
        point: point.to_owned(),
        process_id: std::process::id(),
        sender_journal_path: harness.sender_journal_path().display().to_string(),
        receiver_journal_path: harness.receiver_journal_path().display().to_string(),
        receiver_policy_binding: harness.receiver_policy.binding(),
        sender_live_sessions_before_kill: harness.sender.live_session_count(),
        receiver_live_sessions_before_kill: harness.receiver.live_session_count(),
        receiver_judgment_before_kill: harness.receiver_certificate(CANARY_CONSUMER_A).judgment,
        pulse_validity_ms: harness.pulse_validity_ms,
        private_key_material_serialized: false,
    };
    let bytes = serde_json::to_vec_pretty(&ready).map_err(|error| error.to_string())?;
    fs::write(ready_path, bytes).map_err(|error| error.to_string())?;
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

impl Drop for CanaryHarnessV1 {
    fn drop(&mut self) {
        if let Some(reactor) = self.sender_reactor.take() {
            let _ = reactor.shutdown();
        }
        if let Some(reactor) = self.receiver_reactor.take() {
            let _ = reactor.shutdown();
        }
        for path in &self.journal_paths {
            let _ = fs::remove_file(path);
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyDemoArtifactV1 {
    pub schema_version: u16,
    pub scenario: String,
    pub transport: String,
    pub authentication: String,
    pub sender_offer_digest: DigestV1,
    pub challenge_digest: DigestV1,
    pub session_binding_digest: DigestV1,
    pub receiver_session_acceptance_digest: DigestV1,
    pub envelope_digest: DigestV1,
    pub acceptance_receipt_digest: DigestV1,
    pub consumer_a_judgment: JudgmentCategoryV1,
    pub consumer_b_judgment: JudgmentCategoryV1,
    pub consumer_a_deadline_monotonic_ms: Option<u64>,
    pub consumer_b_deadline_monotonic_ms: Option<u64>,
    pub support_names_exact_remote_custody: bool,
    pub envelope_bytes: usize,
    pub trace: Vec<String>,
    pub nonclaims: Vec<String>,
}

pub fn run_matched_custody_demo() -> Result<CustodyDemoArtifactV1, String> {
    let mut harness = CanaryHarnessV1::deterministic()?;
    let session = harness.establish_session()?;
    let (envelope, receipt, output, datagram) = harness.emit_and_admit(1)?;
    let certificate_a = harness.receiver_certificate(CANARY_CONSUMER_A);
    let certificate_b = harness.receiver_certificate(CANARY_CONSUMER_B);
    let support_names_exact_remote_custody = certificate_a
        .remote_observation_custody
        .first()
        .is_some_and(|custody| {
            custody.sender_session_offer_digest == session.offer.offer_digest
                && custody.receiver_session_acceptance_digest
                    == session.receiver_acceptance.acceptance_digest
                && custody.envelope_digest == envelope.envelope_digest
                && custody.acceptance_receipt_digest == receipt.receipt_digest
                && custody.sender_manifest_digest == harness.sender_package.manifest.manifest_digest
                && custody.receiver_manifest_digest
                    == harness.receiver_package_a.manifest.manifest_digest
                && custody.authority_grants.grants_nothing()
        });
    let mut trace = vec![
        "receiver UNBOUND -> QualifiedAndMatched (local semantic fixture)".to_owned(),
        "sender UNBOUND -> QualifiedAndMatched (local semantic fixture)".to_owned(),
        format!("signed sender offer {}", session.offer.offer_digest),
        format!(
            "signed receiver challenge {}",
            session.challenge.challenge_digest
        ),
        format!("signed sender binding {}", session.binding.binding_digest),
        format!(
            "signed receiver session acceptance {}",
            session.receiver_acceptance.acceptance_digest
        ),
        format!("exact observation envelope {}", envelope.envelope_digest),
        format!("receiver admission receipt {}", receipt.receipt_digest),
    ];
    trace.extend(output.trace_lines);
    let artifact = CustodyDemoArtifactV1 {
        schema_version: SCHEMA_VERSION_V1,
        scenario: "matched_local_two-process-shaped_custody".to_owned(),
        transport: "bounded UDP datagram codec; deterministic harness uses loopback metadata"
            .to_owned(),
        authentication:
            "Ed25519 pinned public keys; key possession over domain-separated exact bytes only"
                .to_owned(),
        sender_offer_digest: session.offer.offer_digest,
        challenge_digest: session.challenge.challenge_digest,
        session_binding_digest: session.binding.binding_digest,
        receiver_session_acceptance_digest: session.receiver_acceptance.acceptance_digest,
        envelope_digest: envelope.envelope_digest,
        acceptance_receipt_digest: receipt.receipt_digest,
        consumer_a_judgment: certificate_a.judgment,
        consumer_b_judgment: certificate_b.judgment,
        consumer_a_deadline_monotonic_ms: certificate_a.earliest_support_expiry_monotonic_ms,
        consumer_b_deadline_monotonic_ms: certificate_b.earliest_support_expiry_monotonic_ms,
        support_names_exact_remote_custody,
        envelope_bytes: datagram.len(),
        trace,
        nonclaims: vec![
            "not a two-host result".to_owned(),
            "not remote attestation".to_owned(),
            "not observation-time freshness".to_owned(),
            "not subject health".to_owned(),
            "no continuation or mutation authority".to_owned(),
        ],
    };
    harness.shutdown()?;
    Ok(artifact)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyRestartArtifactV1 {
    pub schema_version: u16,
    pub historical_sparse_records_recovered: usize,
    pub historical_acceptance_receipts_recovered: usize,
    pub historical_current_certificates_recovered: usize,
    pub history_complete: bool,
    pub restarted_binding_state: RuntimeBindingStateV1,
    pub restarted_judgment: JudgmentCategoryV1,
    pub restarted_supporting_evidence_count: usize,
    pub restarted_active_deadlines: usize,
    pub restarted_live_sessions: usize,
    pub restarted_accepted_remote_activations: usize,
    pub current_standing_reconstructed: bool,
    pub prior_acceptance_receipt_reused_as_evidence: bool,
    pub fresh_local_activation_required: bool,
    pub fresh_challenge_required: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyExpiryDemoArtifactV1 {
    pub schema_version: u16,
    pub initial_judgment: JudgmentCategoryV1,
    pub expected_support_deadline_monotonic_ms: u64,
    pub actual_withdrawal_monotonic_ms: u64,
    pub stale_positive_overshoot_ms: u64,
    pub final_judgment: JudgmentCategoryV1,
    pub final_supporting_evidence_count: usize,
    pub final_active_deadlines: usize,
    pub new_envelope_arrived: bool,
    pub subject_contradiction_invented: bool,
    pub trace: Vec<String>,
}

pub fn run_silence_expiry_demo() -> Result<CustodyExpiryDemoArtifactV1, String> {
    let mut harness = CanaryHarnessV1::deterministic()?;
    harness.establish_session()?;
    harness.emit_and_admit(1)?;
    let initial = harness.receiver_certificate(CANARY_CONSUMER_A);
    let deadline = initial
        .earliest_support_expiry_monotonic_ms
        .ok_or("CURRENT remote support has no deadline")?;
    let withdrawn = harness
        .receiver_reactor
        .as_ref()
        .ok_or("receiver stopped")?
        .wait_until(Duration::from_secs(2), |snapshot| {
            snapshot.observed_at_epoch_monotonic_ms >= deadline
                && snapshot.certificates.iter().any(|certificate| {
                    certificate.consumer == ConsumerId::new(CANARY_CONSUMER_A)
                        && certificate.judgment == JudgmentCategoryV1::Unknown
                })
        })
        .map_err(|error| error.to_string())?;
    let final_certificate = withdrawn
        .certificates
        .iter()
        .find(|certificate| certificate.consumer == ConsumerId::new(CANARY_CONSUMER_A))
        .ok_or("withdrawal snapshot lacks Consumer A")?;
    let artifact = CustodyExpiryDemoArtifactV1 {
        schema_version: SCHEMA_VERSION_V1,
        initial_judgment: initial.judgment,
        expected_support_deadline_monotonic_ms: deadline,
        actual_withdrawal_monotonic_ms: withdrawn.observed_at_epoch_monotonic_ms,
        stale_positive_overshoot_ms: withdrawn
            .observed_at_epoch_monotonic_ms
            .saturating_sub(deadline),
        final_judgment: final_certificate.judgment,
        final_supporting_evidence_count: withdrawn.supporting_evidence_count,
        final_active_deadlines: withdrawn.active_deadline_count,
        new_envelope_arrived: false,
        subject_contradiction_invented: final_certificate.judgment
            == JudgmentCategoryV1::Contradicted,
        trace: vec![
            "exact remote evidence admitted -> Consumer A CURRENT".to_owned(),
            format!("receiver-owned support deadline armed at {deadline}ms"),
            "network silence; no retry, replay, or sender time update".to_owned(),
            format!(
                "reactor withdrew CURRENT at {}ms",
                withdrawn.observed_at_epoch_monotonic_ms
            ),
            "Consumer A UNKNOWN; no subject contradiction invented".to_owned(),
        ],
    };
    harness.shutdown()?;
    Ok(artifact)
}

pub fn run_restart_custody_demo() -> Result<CustodyRestartArtifactV1, String> {
    let mut harness = CanaryHarnessV1::deterministic()?;
    harness.establish_session()?;
    harness.emit_and_admit(1)?;
    let receiver_path = harness.journal_paths[1].clone();
    let receiver_reactor = harness
        .receiver_reactor
        .take()
        .ok_or("receiver reactor is absent")?;
    receiver_reactor
        .shutdown()
        .map_err(|error| error.to_string())?;
    let report = HistoricalJournal::scan(&receiver_path, &journal_config("receiver"))
        .map_err(|error| error.to_string())?;
    let projection = report
        .project_history()
        .map_err(|error| error.to_string())?;
    let historical_sparse_records_recovered = projection.history.sparse_events.len();
    let historical_acceptance_receipts_recovered = projection
        .history
        .sparse_events
        .iter()
        .filter(|event| {
            matches!(
                event.event,
                pulse_types::SparseDurableEventKindV1::ReceiverBoundaryAcceptanceRecorded { .. }
            )
        })
        .count();
    let historical_current_certificates_recovered = projection
        .history
        .sparse_events
        .iter()
        .filter(|event| {
            matches!(
                &event.event,
                pulse_types::SparseDurableEventKindV1::SupportCertificateIssued { certificate }
                    if certificate.judgment == JudgmentCategoryV1::Current
            )
        })
        .count();

    let mut registration_a = canary_registration(CANARY_CONSUMER_A, 1);
    registration_a.context.activation_id =
        ContextActivationId::new("activation:remote-canary:consumer-a:restart");
    let mut registration_b = canary_registration(CANARY_CONSUMER_B, 2);
    registration_b.context.activation_id =
        ContextActivationId::new("activation:remote-canary:consumer-b:restart");
    let restart_config = RuntimeConfigV1 {
        schema_version: SCHEMA_VERSION_V1,
        receiver: ReceiverId::new("receiver:receiver:custody-canary"),
        receiver_incarnation: IncarnationId::new("receiver-incarnation:receiver:restart"),
        clock_id: ClockId::new("clock:receiver:restart"),
        transport_custody_policy: Some(harness.receiver_policy.binding()),
        bounds: RuntimeBoundsV1::qualification(),
    };
    let (runtime, _) = ReceiverSchedulerRuntime::recover(
        restart_config,
        vec![registration_a, registration_b],
        projection.history,
        0,
    )
    .map_err(|error| error.to_string())?;
    let certificate = runtime
        .current_certificate(
            &SubjectId::new(CANARY_SUBJECT),
            &ConsumerId::new(CANARY_CONSUMER_A),
        )
        .ok_or("restarted consumer has no UNKNOWN certificate")?;

    let fresh_receiver_signing = harness
        .receiver_restart_key_copy
        .take()
        .ok_or("restart receiver key copy is absent")?;
    let fresh_receiver = ReceiverCustodyV1::new(
        fresh_receiver_signing,
        harness.receiver_policy.clone(),
        &harness
            .sender_package
            .manifest_bytes()
            .map_err(|error| error.to_string())?,
        &harness
            .sender_package
            .report_bytes()
            .map_err(|error| error.to_string())?,
        &harness
            .sender_package
            .certificate_bytes()
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let artifact = CustodyRestartArtifactV1 {
        schema_version: SCHEMA_VERSION_V1,
        historical_sparse_records_recovered,
        historical_acceptance_receipts_recovered,
        historical_current_certificates_recovered,
        history_complete: projection.history_complete,
        restarted_binding_state: runtime.binding_state(
            &SubjectId::new(CANARY_SUBJECT),
            &ConsumerId::new(CANARY_CONSUMER_A),
        ),
        restarted_judgment: certificate.judgment,
        restarted_supporting_evidence_count: certificate.supporting_evidence_ids.len(),
        restarted_active_deadlines: runtime.scheduled_deadline_count(),
        restarted_live_sessions: fresh_receiver.live_session_count(),
        restarted_accepted_remote_activations: fresh_receiver.accepted_remote_activation_count(),
        current_standing_reconstructed: projection.current_standing_reconstructed,
        prior_acceptance_receipt_reused_as_evidence: false,
        fresh_local_activation_required: true,
        fresh_challenge_required: true,
    };
    harness.shutdown()?;
    Ok(artifact)
}

#[must_use]
pub fn udp_socket_type_marker() -> &'static str {
    // Keep the concrete transport adapter load-bearing in this narrow crate.
    std::any::type_name::<BoundedUdpCanarySocketV1>()
}

#[must_use]
pub fn admission_is_refusal(admission: &ReceiverEnvelopeAdmissionV1) -> bool {
    !admission.admitted()
        && admission.receipt.finding != TransportCustodyFindingV1::EvidenceAdmitted
}
