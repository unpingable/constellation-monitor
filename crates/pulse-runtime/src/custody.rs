//! One bounded pinned-key UDP custody path. This is deliberately not a
//! general transport or RPC framework.

use std::collections::VecDeque;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::{SocketAddr, UdpSocket};
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use pulse_types::{
    CUSTODY_PROTOCOL_VERSION_V1, CustodyAuthorityGrantsV1, CustodyCertificateStatusV1,
    CustodyCheckResultV1, CustodyKeyAlgorithmV1, CustodyPeerRoleV1, CustodySequenceGapV1,
    CustodySignatureDomainV1, CustodyTypeError, DigestV1, GenerationLifecycleFactV1,
    GenerationLifecycleKindV1, IncarnationId, MAX_CANARY_DATAGRAM_BYTES, MAX_CUSTODY_PAYLOAD_BYTES,
    MutationAuthorityV1, ObservationCustodyEnvelopeBodyV1, ObservationCustodyEnvelopeV1,
    ObservationCustodyKindV1, ObserverId, PeerKeyIdentityV1, PulseFrameV1,
    QualificationCertificateV1, QualificationEvidenceReportV1, QualifiedArtifactManifestV1,
    QualifiedGenerationBindingV1, ReceiverAcceptancePolicyV1, ReceiverAcceptanceReceiptV1,
    ReceiverSessionAcceptanceBodyV1, ReceiverSessionAcceptanceV1, ReceiverSessionChallengeBodyV1,
    ReceiverSessionChallengeV1, RemoteFreshnessModeV1, RemoteObservationCustodyReferenceV1,
    ReplayWindowResultV1, SCHEMA_VERSION_V1, SenderEmissionPolicyV1, SenderSessionBindingBodyV1,
    SenderSessionBindingV1, SenderSessionOfferBodyV1, SenderSessionOfferV1, SessionBindingResultV1,
    SubjectScopeV1, TransportCustodyFindingV1, decode_hex_exact, digest_parts, encode_lower_hex,
    verify_qualification_package,
};
use rand_core::{OsRng, RngCore};

use crate::{LocalCrashReactor, RuntimeInputV1};

const DATAGRAM_MAGIC: &[u8; 4] = b"PCN1";
const DATAGRAM_HEADER_BYTES: usize = 9;
const SIGNATURE_BYTES: usize = 64;
const SENDER_SESSION_OFFER_KIND: u8 = 1;
const CHALLENGE_KIND: u8 = 2;
const SESSION_BINDING_KIND: u8 = 3;
const RECEIVER_SESSION_ACCEPTANCE_KIND: u8 = 4;
const OBSERVATION_ENVELOPE_KIND: u8 = 5;

/// An in-memory Ed25519 signing identity. Its `Debug` implementation never
/// emits private material and the dalek default zeroizes the signing key.
pub struct CanarySigningIdentityV1 {
    signing_key: SigningKey,
    key_identity: PeerKeyIdentityV1,
}

impl fmt::Debug for CanarySigningIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanarySigningIdentityV1")
            .field("key_identity", &self.key_identity)
            .field("private_key", &"redacted")
            .finish()
    }
}

impl CanarySigningIdentityV1 {
    pub fn generate(
        role: CustodyPeerRoleV1,
        accepted_scopes: Vec<String>,
        local_acceptance_policy_id: impl Into<String>,
    ) -> Result<Self, CustodyError> {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self::from_signing_key(
            signing_key,
            role,
            accepted_scopes,
            local_acceptance_policy_id,
        )
    }

    /// Generate two in-memory holders of one ephemeral qualification key.
    /// This is used only to exercise hostile authenticated assertions and is
    /// explicit evidence that the canary does not establish exclusive key
    /// custody. No private bytes leave this function.
    pub fn generate_qualification_pair(
        role: CustodyPeerRoleV1,
        accepted_scopes: Vec<String>,
        local_acceptance_policy_id: impl Into<String>,
    ) -> Result<(Self, Self), CustodyError> {
        let first_key = SigningKey::generate(&mut OsRng);
        let mut duplicate_seed = first_key.to_bytes();
        let second_key = SigningKey::from_bytes(&duplicate_seed);
        duplicate_seed.fill(0);
        let policy_id = local_acceptance_policy_id.into();
        let first =
            Self::from_signing_key(first_key, role, accepted_scopes.clone(), policy_id.clone())?;
        let second = Self::from_signing_key(second_key, role, accepted_scopes, policy_id)?;
        Ok((first, second))
    }

    fn from_seed(
        seed: [u8; 32],
        role: CustodyPeerRoleV1,
        accepted_scopes: Vec<String>,
        local_acceptance_policy_id: impl Into<String>,
    ) -> Result<Self, CustodyError> {
        Self::from_signing_key(
            SigningKey::from_bytes(&seed),
            role,
            accepted_scopes,
            local_acceptance_policy_id,
        )
    }

    fn from_signing_key(
        signing_key: SigningKey,
        role: CustodyPeerRoleV1,
        accepted_scopes: Vec<String>,
        local_acceptance_policy_id: impl Into<String>,
    ) -> Result<Self, CustodyError> {
        let public = signing_key.verifying_key().to_bytes();
        let key_identity = PeerKeyIdentityV1 {
            schema_version: SCHEMA_VERSION_V1,
            protocol_version: CUSTODY_PROTOCOL_VERSION_V1,
            algorithm: CustodyKeyAlgorithmV1::Ed25519,
            role,
            intended_peer_role: match role {
                CustodyPeerRoleV1::Sender => CustodyPeerRoleV1::Receiver,
                CustodyPeerRoleV1::Receiver => CustodyPeerRoleV1::Sender,
            },
            public_key_hex: encode_lower_hex(&public),
            public_key_digest: digest_parts("transport.ed25519.public-key.v1", &[&public]),
            accepted_scopes,
            local_acceptance_policy_id: local_acceptance_policy_id.into(),
        };
        key_identity.validate().map_err(CustodyError::from_type)?;
        Ok(Self {
            signing_key,
            key_identity,
        })
    }

    #[must_use]
    pub const fn key_identity(&self) -> &PeerKeyIdentityV1 {
        &self.key_identity
    }

    fn sign(&self, domain: CustodySignatureDomainV1, body: &[u8]) -> [u8; 64] {
        self.signing_key
            .sign(&signature_transcript(domain, body))
            .to_bytes()
    }
}

/// A live key plus a temporary mode-0600 seed file. The seed file is removed
/// on drop. No API exposes its bytes or serializes the object.
pub struct EphemeralPrivateKeyFileV1 {
    path: PathBuf,
    identity: CanarySigningIdentityV1,
}

impl fmt::Debug for EphemeralPrivateKeyFileV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EphemeralPrivateKeyFileV1")
            .field("path", &self.path)
            .field("public_identity", self.identity.key_identity())
            .field("private_key", &"redacted")
            .finish()
    }
}

impl EphemeralPrivateKeyFileV1 {
    #[cfg(target_os = "linux")]
    pub fn create_new(
        path: impl AsRef<Path>,
        role: CustodyPeerRoleV1,
        accepted_scopes: Vec<String>,
        local_acceptance_policy_id: impl Into<String>,
    ) -> Result<Self, CustodyError> {
        let mut seed = [0_u8; 32];
        OsRng.fill_bytes(&mut seed);
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path.as_ref())
            .map_err(|error| CustodyError::io("create private-key file", &error))?;
        file.write_all(&seed)
            .map_err(|error| CustodyError::io("write private-key file", &error))?;
        file.sync_all()
            .map_err(|error| CustodyError::io("sync private-key file", &error))?;
        let identity = CanarySigningIdentityV1::from_seed(
            seed,
            role,
            accepted_scopes,
            local_acceptance_policy_id,
        )?;
        seed.fill(0);
        Ok(Self {
            path: path.as_ref().to_path_buf(),
            identity,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn create_new(
        _path: impl AsRef<Path>,
        _role: CustodyPeerRoleV1,
        _accepted_scopes: Vec<String>,
        _local_acceptance_policy_id: impl Into<String>,
    ) -> Result<Self, CustodyError> {
        Err(CustodyError::new(
            TransportCustodyFindingV1::TransportUnavailable,
            "ephemeral key-file qualification is Linux-only",
        ))
    }

    #[must_use]
    pub const fn identity(&self) -> &CanarySigningIdentityV1 {
        &self.identity
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for EphemeralPrivateKeyFileV1 {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[derive(Clone, Debug)]
pub struct AcceptedSenderQualificationPackageV1 {
    manifest: QualifiedArtifactManifestV1,
    certificate: QualificationCertificateV1,
}

impl AcceptedSenderQualificationPackageV1 {
    pub fn verify(
        manifest_bytes: &[u8],
        report_bytes: &[u8],
        certificate_bytes: &[u8],
        policy: &ReceiverAcceptancePolicyV1,
    ) -> Result<Self, CustodyError> {
        let manifest = QualifiedArtifactManifestV1::decode_canonical(manifest_bytes)
            .map_err(CustodyError::from_qualification)?;
        let report = QualificationEvidenceReportV1::decode_canonical(report_bytes)
            .map_err(CustodyError::from_qualification)?;
        let certificate = QualificationCertificateV1::decode_canonical(certificate_bytes)
            .map_err(CustodyError::from_qualification)?;
        verify_qualification_package(&manifest, &report, &certificate)
            .map_err(CustodyError::from_qualification)?;
        if manifest.manifest_digest != policy.accepted_sender_manifest_digest
            || certificate.certificate_digest != policy.accepted_sender_certificate_digest
        {
            return Err(CustodyError::new(
                TransportCustodyFindingV1::QualifiedIdentityMismatch,
                "checked sender qualification package does not match receiver policy",
            ));
        }
        Ok(Self {
            manifest,
            certificate,
        })
    }

    #[must_use]
    pub fn manifest_digest(&self) -> &DigestV1 {
        &self.manifest.manifest_digest
    }

    #[must_use]
    pub fn certificate_digest(&self) -> &DigestV1 {
        &self.certificate.certificate_digest
    }
}

#[derive(Clone, Debug)]
pub struct ReceivedCanaryDatagramV1 {
    pub bytes: Vec<u8>,
    pub remote_endpoint: SocketAddr,
}

pub struct BoundedUdpCanarySocketV1 {
    socket: UdpSocket,
    maximum_datagram_bytes: usize,
}

impl fmt::Debug for BoundedUdpCanarySocketV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedUdpCanarySocketV1")
            .field("local_addr", &self.socket.local_addr().ok())
            .field("maximum_datagram_bytes", &self.maximum_datagram_bytes)
            .finish()
    }
}

impl BoundedUdpCanarySocketV1 {
    pub fn bind(address: SocketAddr, maximum_datagram_bytes: usize) -> Result<Self, CustodyError> {
        if maximum_datagram_bytes == 0 || maximum_datagram_bytes > MAX_CANARY_DATAGRAM_BYTES {
            return Err(CustodyError::new(
                TransportCustodyFindingV1::TransportMalformed,
                "UDP datagram bound is zero or exceeds the canary ceiling",
            ));
        }
        let socket = UdpSocket::bind(address)
            .map_err(|error| CustodyError::io("bind UDP canary socket", &error))?;
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|error| CustodyError::io("set UDP receive timeout", &error))?;
        Ok(Self {
            socket,
            maximum_datagram_bytes,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, CustodyError> {
        self.socket
            .local_addr()
            .map_err(|error| CustodyError::io("observe UDP local address", &error))
    }

    pub fn send_to(&self, bytes: &[u8], peer: SocketAddr) -> Result<usize, CustodyError> {
        if bytes.is_empty() || bytes.len() > self.maximum_datagram_bytes {
            return Err(CustodyError::new(
                TransportCustodyFindingV1::TransportMalformed,
                "outbound datagram is empty or exceeds the qualified bound",
            ));
        }
        let sent = self
            .socket
            .send_to(bytes, peer)
            .map_err(|error| CustodyError::io("send UDP canary datagram", &error))?;
        if sent != bytes.len() {
            return Err(CustodyError::new(
                TransportCustodyFindingV1::TransportUnavailable,
                "UDP send did not report the complete bounded datagram",
            ));
        }
        Ok(sent)
    }

    pub fn receive(&self) -> Result<ReceivedCanaryDatagramV1, CustodyError> {
        let mut buffer = [0_u8; MAX_CANARY_DATAGRAM_BYTES + 1];
        let (received, remote_endpoint) = self
            .socket
            .recv_from(&mut buffer)
            .map_err(|error| CustodyError::io("receive UDP canary datagram", &error))?;
        if received == 0 || received > self.maximum_datagram_bytes {
            return Err(CustodyError::new(
                TransportCustodyFindingV1::TransportMalformed,
                "received datagram is empty, oversized, or observably truncated",
            ));
        }
        Ok(ReceivedCanaryDatagramV1 {
            bytes: buffer[..received].to_vec(),
            remote_endpoint,
        })
    }
}

/// Move-only evidence token. Only the receiver admission gate in this module
/// can construct it; historical bytes and public schema values cannot.
pub struct VerifiedRemoteObservationV1 {
    frame: PulseFrameV1,
    custody: RemoteObservationCustodyReferenceV1,
    receipt: ReceiverAcceptanceReceiptV1,
}

impl fmt::Debug for VerifiedRemoteObservationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedRemoteObservationV1")
            .field("observation_digest", &self.frame.observation_digest)
            .field("custody", &self.custody)
            .field("acceptance_receipt_digest", &self.receipt.receipt_digest)
            .finish()
    }
}

impl VerifiedRemoteObservationV1 {
    pub(crate) const fn frame(&self) -> &PulseFrameV1 {
        &self.frame
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        PulseFrameV1,
        RemoteObservationCustodyReferenceV1,
        ReceiverAcceptanceReceiptV1,
    ) {
        (self.frame, self.custody, self.receipt)
    }
}

pub struct ReceiverEnvelopeAdmissionV1 {
    pub receipt: ReceiverAcceptanceReceiptV1,
    verified: Option<VerifiedRemoteObservationV1>,
}

impl fmt::Debug for ReceiverEnvelopeAdmissionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReceiverEnvelopeAdmissionV1")
            .field("receipt", &self.receipt)
            .field("verified_remote_observation", &self.verified.is_some())
            .finish()
    }
}

impl ReceiverEnvelopeAdmissionV1 {
    #[must_use]
    pub fn admitted(&self) -> bool {
        self.verified.is_some()
    }

    pub fn into_runtime_input(self) -> Result<RuntimeInputV1, CustodyError> {
        self.verified
            .map(|verified| RuntimeInputV1::RemotePulse(Box::new(verified)))
            .ok_or_else(|| {
                CustodyError::new(
                    self.receipt.finding,
                    "receiver refusal has no verified remote evidence token",
                )
            })
    }
}

#[derive(Clone, Debug)]
struct SenderLiveSession {
    offer: SenderSessionOfferV1,
    challenge: ReceiverSessionChallengeV1,
    binding: SenderSessionBindingV1,
    receiver_acceptance: Option<ReceiverSessionAcceptanceV1>,
    local_expires_at_monotonic_ms: u64,
    next_session_sequence: u64,
    emitted_messages: u32,
    exact_activation: QualifiedGenerationBindingV1,
}

pub struct SenderCustodyV1 {
    signing: CanarySigningIdentityV1,
    policy: SenderEmissionPolicyV1,
    pending_offer: Option<SenderSessionOfferV1>,
    session: Option<SenderLiveSession>,
    outbound: VecDeque<Vec<u8>>,
    successful_emissions: u64,
    queue_refusals: u64,
}

impl fmt::Debug for SenderCustodyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SenderCustodyV1")
            .field("key", self.signing.key_identity())
            .field("policy_digest", &self.policy.identity_digest())
            .field("pending_offer", &self.pending_offer.is_some())
            .field(
                "live_session",
                &self
                    .session
                    .as_ref()
                    .is_some_and(|session| session.receiver_acceptance.is_some()),
            )
            .field("queued", &self.outbound.len())
            .finish()
    }
}

impl SenderCustodyV1 {
    pub fn new(
        signing: CanarySigningIdentityV1,
        policy: SenderEmissionPolicyV1,
    ) -> Result<Self, CustodyError> {
        policy.validate().map_err(CustodyError::from_type)?;
        if signing.key_identity() != &policy.sender_key {
            return Err(CustodyError::new(
                TransportCustodyFindingV1::QualifiedIdentityMismatch,
                "sender signing key does not match its exact emission policy",
            ));
        }
        Ok(Self {
            signing,
            policy,
            pending_offer: None,
            session: None,
            outbound: VecDeque::new(),
            successful_emissions: 0,
            queue_refusals: 0,
        })
    }

    #[must_use]
    pub fn live_session_count(&self) -> usize {
        usize::from(
            self.session
                .as_ref()
                .is_some_and(|session| session.receiver_acceptance.is_some()),
        )
    }

    #[must_use]
    pub const fn successful_emissions(&self) -> u64 {
        self.successful_emissions
    }

    #[must_use]
    pub const fn queue_refusals(&self) -> u64 {
        self.queue_refusals
    }

    pub fn invalidate(&mut self) {
        self.pending_offer = None;
        self.session = None;
        self.outbound.clear();
    }

    pub fn create_session_offer(
        &mut self,
        reactor: &LocalCrashReactor,
        subject: &pulse_types::SubjectId,
        consumer: &pulse_types::ConsumerId,
    ) -> Result<Vec<u8>, CustodyError> {
        let exact_activation =
            reactor.revalidate_transport_activation(subject, consumer, &self.policy.binding())?;
        let snapshot = reactor.snapshot();
        if !snapshot.condition.exposes_live_standing() {
            self.invalidate();
            return Err(CustodyError::new(
                TransportCustodyFindingV1::TransportUnavailable,
                "sender reactor does not expose live temporal custody",
            ));
        }
        let mut nonce = [0_u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let body = SenderSessionOfferBodyV1 {
            schema_version: SCHEMA_VERSION_V1,
            protocol_version: CUSTODY_PROTOCOL_VERSION_V1,
            receiver_key_identity_digest: self.policy.accepted_receiver_key.identity_digest(),
            sender_key_identity_digest: self.policy.sender_key.identity_digest(),
            sender_process_occurrence: exact_activation.process_epoch_id.clone(),
            sender_monotonic_epoch: snapshot.monotonic_epoch.epoch_id,
            sender_nonce_hex: encode_lower_hex(&nonce),
            sender_manifest_digest: exact_activation.manifest_digest,
            sender_qualification_certificate_digest: exact_activation
                .qualification_certificate_digest,
            sender_activation_receipt_digest: exact_activation.activation_receipt_digest,
            sender_runtime_generation_set_digest: exact_activation.generation_set.identity_digest(),
            observer: self.policy.observer.clone(),
            failure_domain_claim: self.policy.failure_domain_claim.clone(),
            permitted_subject_scopes: self.policy.permitted_subject_scopes.clone(),
        };
        let (offer, datagram) = sign_sender_session_offer(&self.signing, body)?;
        self.session = None;
        self.pending_offer = Some(offer);
        Ok(datagram)
    }

    pub fn accept_receiver_challenge(
        &mut self,
        reactor: &LocalCrashReactor,
        subject: &pulse_types::SubjectId,
        consumer: &pulse_types::ConsumerId,
        challenge_datagram: &[u8],
    ) -> Result<Vec<u8>, CustodyError> {
        let challenge = decode_receiver_challenge_datagram(
            challenge_datagram,
            &self.policy.accepted_receiver_key,
        )?;
        if challenge.body.intended_sender_key_identity_digest
            != self.policy.sender_key.identity_digest()
            || challenge.body.receiver_key_identity_digest
                != self.policy.accepted_receiver_key.identity_digest()
            || challenge.body.receiver_acceptance_policy_generation
                != self.policy.accepted_receiver_policy_generation
            || challenge.body.receiver_acceptance_policy_anchor_digest
                != self.policy.accepted_receiver_policy_anchor_digest
        {
            return Err(CustodyError::new(
                TransportCustodyFindingV1::ReceiverChallengeInvalid,
                "challenge does not match the sender's exact pinned peer policy",
            ));
        }
        let expected_receiver_policy_digest =
            ReceiverAcceptancePolicyV1::identity_digest_from_parts(
                &challenge.body.receiver_acceptance_policy_anchor_digest,
                &challenge.body.accepted_sender_manifest_digest,
                &challenge.body.accepted_sender_certificate_digest,
            );
        if challenge.body.receiver_acceptance_policy_digest != expected_receiver_policy_digest {
            return Err(CustodyError::new(
                TransportCustodyFindingV1::ReceiverChallengeInvalid,
                "challenge receiver-policy identity is not the exact anchored policy",
            ));
        }
        let exact_activation =
            reactor.revalidate_transport_activation(subject, consumer, &self.policy.binding())?;
        let offer = self.pending_offer.as_ref().ok_or_else(|| {
            CustodyError::new(
                TransportCustodyFindingV1::ReceiverChallengeInvalid,
                "sender has no live process-local offer for this challenge",
            )
        })?;
        if challenge.body.sender_session_offer_digest != offer.offer_digest
            || challenge.body.intended_sender_process_occurrence
                != exact_activation.process_epoch_id
            || offer.body.sender_process_occurrence != exact_activation.process_epoch_id
            || offer.body.sender_manifest_digest != exact_activation.manifest_digest
            || offer.body.sender_qualification_certificate_digest
                != exact_activation.qualification_certificate_digest
            || offer.body.sender_activation_receipt_digest
                != exact_activation.activation_receipt_digest
        {
            self.invalidate();
            return Err(CustodyError::new(
                TransportCustodyFindingV1::ReceiverChallengeInvalid,
                "challenge is not bound to this live sender offer and process occurrence",
            ));
        }
        if challenge.body.accepted_sender_manifest_digest != exact_activation.manifest_digest
            || challenge.body.accepted_sender_certificate_digest
                != exact_activation.qualification_certificate_digest
        {
            return Err(CustodyError::new(
                TransportCustodyFindingV1::QualifiedIdentityMismatch,
                "receiver challenge does not accept the sender's live exact package",
            ));
        }
        let snapshot = reactor.snapshot();
        if !snapshot.condition.exposes_live_standing() {
            return Err(CustodyError::new(
                TransportCustodyFindingV1::TransportUnavailable,
                "sender reactor does not expose live temporal custody",
            ));
        }
        let duration = challenge
            .body
            .expires_at_receiver_monotonic_ms
            .saturating_sub(challenge.body.issued_at_receiver_monotonic_ms);
        let body = SenderSessionBindingBodyV1 {
            schema_version: SCHEMA_VERSION_V1,
            protocol_version: CUSTODY_PROTOCOL_VERSION_V1,
            receiver_challenge_digest: challenge.challenge_digest.clone(),
            receiver_key_identity_digest: challenge.body.receiver_key_identity_digest.clone(),
            sender_key_identity_digest: self.policy.sender_key.identity_digest(),
            sender_process_occurrence: exact_activation.process_epoch_id.clone(),
            sender_monotonic_epoch: snapshot.monotonic_epoch.epoch_id.clone(),
            sender_manifest_digest: exact_activation.manifest_digest.clone(),
            sender_qualification_certificate_digest: exact_activation
                .qualification_certificate_digest
                .clone(),
            sender_activation_receipt_digest: exact_activation.activation_receipt_digest.clone(),
            sender_runtime_generation_set_digest: exact_activation.generation_set.identity_digest(),
            observer: self.policy.observer.clone(),
            failure_domain_claim: self.policy.failure_domain_claim.clone(),
            permitted_subject_scopes: self.policy.permitted_subject_scopes.clone(),
            observation_protocol_version: CUSTODY_PROTOCOL_VERSION_V1,
            session_sequence_origin: 1,
            binding_result: SessionBindingResultV1::QualifiedAndMatchedAssertion,
        };
        let (binding, datagram) = sign_sender_session_binding(&self.signing, body)?;
        self.session = Some(SenderLiveSession {
            offer: offer.clone(),
            challenge,
            binding: binding.clone(),
            receiver_acceptance: None,
            local_expires_at_monotonic_ms: snapshot
                .observed_at_epoch_monotonic_ms
                .saturating_add(duration),
            next_session_sequence: 1,
            emitted_messages: 0,
            exact_activation,
        });
        self.pending_offer = None;
        Ok(datagram)
    }

    pub fn accept_receiver_session_acceptance(
        &mut self,
        reactor: &LocalCrashReactor,
        subject: &pulse_types::SubjectId,
        consumer: &pulse_types::ConsumerId,
        datagram: &[u8],
    ) -> Result<DigestV1, CustodyError> {
        let exact_activation =
            reactor.revalidate_transport_activation(subject, consumer, &self.policy.binding())?;
        let acceptance = decode_receiver_session_acceptance_datagram(
            datagram,
            &self.policy.accepted_receiver_key,
        )?;
        let now_monotonic_ms = reactor.receiver_monotonic_now()?;
        let session = self.session.as_mut().ok_or_else(|| {
            CustodyError::new(
                TransportCustodyFindingV1::SessionUnknown,
                "sender has no provisional session awaiting receiver acceptance",
            )
        })?;
        if session.receiver_acceptance.is_some() {
            return Err(CustodyError::new(
                TransportCustodyFindingV1::ReplayDetected,
                "receiver session acceptance was already consumed",
            ));
        }
        if now_monotonic_ms >= session.local_expires_at_monotonic_ms {
            self.session = None;
            return Err(CustodyError::new(
                TransportCustodyFindingV1::SessionExpired,
                "provisional sender session expired before receiver acceptance",
            ));
        }
        if exact_activation != session.exact_activation
            || acceptance.body.receiver_challenge_digest != session.challenge.challenge_digest
            || acceptance.body.sender_session_binding_digest != session.binding.binding_digest
            || acceptance.body.receiver_key_identity_digest
                != self.policy.accepted_receiver_key.identity_digest()
            || acceptance.body.sender_key_identity_digest
                != self.policy.sender_key.identity_digest()
            || acceptance.body.receiver_process_occurrence
                != session.challenge.body.receiver_process_occurrence
            || acceptance.body.receiver_monotonic_epoch
                != session.challenge.body.receiver_monotonic_epoch
            || acceptance.body.sender_process_occurrence
                != session.binding.body.sender_process_occurrence
            || acceptance.body.receiver_acceptance_policy_digest
                != session.challenge.body.receiver_acceptance_policy_digest
            || acceptance.body.accepted_at_receiver_monotonic_ms
                < session.challenge.body.issued_at_receiver_monotonic_ms
            || acceptance.body.expires_at_receiver_monotonic_ms
                != session.challenge.body.expires_at_receiver_monotonic_ms
            || acceptance.body.maximum_messages != session.challenge.body.maximum_messages
            || session.offer.offer_digest != session.challenge.body.sender_session_offer_digest
        {
            self.invalidate();
            return Err(CustodyError::new(
                TransportCustodyFindingV1::SessionConflict,
                "receiver acceptance does not confirm this exact provisional session",
            ));
        }
        let digest = acceptance.acceptance_digest.clone();
        session.receiver_acceptance = Some(acceptance);
        Ok(digest)
    }

    pub fn emit_pulse(
        &mut self,
        reactor: &LocalCrashReactor,
        subject: &pulse_types::SubjectId,
        consumer: &pulse_types::ConsumerId,
        frame: &PulseFrameV1,
    ) -> Result<Vec<u8>, CustodyError> {
        let exact_activation =
            reactor.revalidate_transport_activation(subject, consumer, &self.policy.binding())?;
        let snapshot = reactor.snapshot();
        if !snapshot.condition.exposes_live_standing() {
            self.invalidate();
            return Err(CustodyError::new(
                TransportCustodyFindingV1::TransportUnavailable,
                "sender reactor is not operational",
            ));
        }
        let session = self.session.as_mut().ok_or_else(|| {
            CustodyError::new(
                TransportCustodyFindingV1::SessionUnknown,
                "sender has no live receiver session",
            )
        })?;
        if session.receiver_acceptance.is_none() {
            return Err(CustodyError::new(
                TransportCustodyFindingV1::SessionUnknown,
                "sender binding is provisional until a signed receiver acceptance arrives",
            ));
        }
        if snapshot.observed_at_epoch_monotonic_ms >= session.local_expires_at_monotonic_ms {
            self.session = None;
            return Err(CustodyError::new(
                TransportCustodyFindingV1::SessionExpired,
                "sender's conservative local session lifetime has expired",
            ));
        }
        if session.emitted_messages >= session.challenge.body.maximum_messages {
            self.session = None;
            return Err(CustodyError::new(
                TransportCustodyFindingV1::TransportOverloaded,
                "sender session message bound is exhausted",
            ));
        }
        if exact_activation != session.exact_activation {
            self.session = None;
            return Err(CustodyError::new(
                TransportCustodyFindingV1::QualifiedIdentityMismatch,
                "sender activation changed after session binding",
            ));
        }
        frame.validate().map_err(|error| {
            CustodyError::new(
                TransportCustodyFindingV1::PayloadMalformed,
                error.to_string(),
            )
        })?;
        let scope = SubjectScopeV1 {
            subject: frame.subject.clone(),
            subject_incarnation: frame.subject_incarnation.clone(),
            scope: self
                .policy
                .permitted_subject_scopes
                .iter()
                .find(|scope| {
                    scope.subject == frame.subject
                        && scope.subject_incarnation == frame.subject_incarnation
                })
                .map(|scope| scope.scope.clone())
                .ok_or_else(|| {
                    CustodyError::new(
                        TransportCustodyFindingV1::SubjectScopeMismatch,
                        "pulse subject/incarnation is outside sender scope",
                    )
                })?,
        };
        if frame.observer != self.policy.observer {
            return Err(CustodyError::new(
                TransportCustodyFindingV1::ObserverRoleMismatch,
                "pulse observer differs from sender policy",
            ));
        }
        let payload = frame.encode_wire().map_err(|error| {
            CustodyError::new(
                TransportCustodyFindingV1::PayloadMalformed,
                error.to_string(),
            )
        })?;
        if payload.len() > MAX_CUSTODY_PAYLOAD_BYTES {
            return Err(CustodyError::new(
                TransportCustodyFindingV1::TransportMalformed,
                "pulse payload exceeds the custody-envelope bound",
            ));
        }
        if self.outbound.len() >= usize::from(self.policy.sender_queue_bound) {
            self.queue_refusals = self.queue_refusals.saturating_add(1);
            self.invalidate();
            let _ = reactor.declare_blindness(
                "sender-boundary emission queue saturated; successful emission stopped",
            );
            return Err(CustodyError::new(
                TransportCustodyFindingV1::TransportOverloaded,
                "sender bounded emission queue is full; session invalidated",
            ));
        }
        let body = ObservationCustodyEnvelopeBodyV1 {
            schema_version: SCHEMA_VERSION_V1,
            protocol_version: CUSTODY_PROTOCOL_VERSION_V1,
            receiver_challenge_digest: session.challenge.challenge_digest.clone(),
            session_binding_digest: session.binding.binding_digest.clone(),
            receiver_key_identity_digest: session
                .challenge
                .body
                .receiver_key_identity_digest
                .clone(),
            sender_key_identity_digest: self.policy.sender_key.identity_digest(),
            sender_process_occurrence: exact_activation.process_epoch_id.clone(),
            sender_monotonic_epoch: snapshot.monotonic_epoch.epoch_id,
            sender_manifest_digest: exact_activation.manifest_digest.clone(),
            sender_qualification_certificate_digest: exact_activation
                .qualification_certificate_digest
                .clone(),
            sender_activation_receipt_digest: exact_activation.activation_receipt_digest.clone(),
            observer: frame.observer.clone(),
            failure_domain_claim: self.policy.failure_domain_claim.clone(),
            subject_scope: scope,
            observation_identity: frame.observation_digest.clone(),
            observation_sequence: frame.sequence,
            session_sequence: session.next_session_sequence,
            observation_kind: ObservationCustodyKindV1::PulseV1,
            payload_hex: encode_lower_hex(&payload),
            payload_digest: digest_parts("transport.observation-payload.v1", &[&payload]),
            sender_observation_monotonic_ns: frame.observer_monotonic_ns,
            sender_emission_monotonic_ns: snapshot
                .observed_at_epoch_monotonic_ms
                .saturating_mul(1_000_000),
        };
        let (_, datagram) = sign_observation_envelope(&self.signing, body)?;
        if datagram.len() > usize::from(self.policy.maximum_datagram_bytes)
            || datagram.len() > usize::from(session.challenge.body.maximum_envelope_bytes)
        {
            return Err(CustodyError::new(
                TransportCustodyFindingV1::TransportMalformed,
                "canonical observation envelope exceeds a signed datagram bound",
            ));
        }
        session.next_session_sequence =
            session
                .next_session_sequence
                .checked_add(1)
                .ok_or_else(|| {
                    CustodyError::new(
                        TransportCustodyFindingV1::ObservationRejected,
                        "sender session sequence exhausted",
                    )
                })?;
        session.emitted_messages = session.emitted_messages.saturating_add(1);
        self.successful_emissions = self.successful_emissions.saturating_add(1);
        self.outbound.push_back(datagram.clone());
        Ok(datagram)
    }

    pub fn pop_queued_datagram(&mut self) -> Option<Vec<u8>> {
        self.outbound.pop_front()
    }
}

#[derive(Clone, Debug)]
struct QueuedEnvelope {
    bytes: Vec<u8>,
    remote_endpoint: String,
    arrival_monotonic_ms: u64,
}

#[derive(Clone, Debug)]
struct ReceiverLiveSession {
    challenge: ReceiverSessionChallengeV1,
    binding: SenderSessionBindingV1,
    receiver_session_acceptance_digest: DigestV1,
    receiver_activation: QualifiedGenerationBindingV1,
    high_session_sequence: Option<u64>,
    replay_bitmap: u64,
    high_observation_sequence: Option<u64>,
    accepted_messages: u32,
    rate_window_started_ms: u64,
    rate_window_messages: u32,
}

pub struct ReceiverCustodyV1 {
    signing: CanarySigningIdentityV1,
    policy: ReceiverAcceptancePolicyV1,
    accepted_sender_package: AcceptedSenderQualificationPackageV1,
    pending_challenge: Option<(
        ReceiverSessionChallengeV1,
        QualifiedGenerationBindingV1,
        SenderSessionOfferV1,
    )>,
    session: Option<ReceiverLiveSession>,
    inbound: VecDeque<QueuedEnvelope>,
    receipts: Vec<ReceiverAcceptanceReceiptV1>,
    receipt_sequence: u64,
    duplicate_refusals: u64,
    replay_refusals: u64,
    sequence_gaps: u64,
    queue_refusals: u64,
    competing_occurrences: u64,
    lifecycle_status: CustodyCertificateStatusV1,
}

impl fmt::Debug for ReceiverCustodyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReceiverCustodyV1")
            .field("key", self.signing.key_identity())
            .field("policy_digest", &self.policy.identity_digest())
            .field("live_session", &self.session.is_some())
            .field("pending_challenge", &self.pending_challenge.is_some())
            .field("queued", &self.inbound.len())
            .finish()
    }
}

impl ReceiverCustodyV1 {
    pub fn new(
        signing: CanarySigningIdentityV1,
        policy: ReceiverAcceptancePolicyV1,
        sender_manifest_bytes: &[u8],
        sender_report_bytes: &[u8],
        sender_certificate_bytes: &[u8],
    ) -> Result<Self, CustodyError> {
        policy.validate().map_err(CustodyError::from_type)?;
        if signing.key_identity() != &policy.receiver_key {
            return Err(CustodyError::new(
                TransportCustodyFindingV1::QualifiedIdentityMismatch,
                "receiver signing key does not match its exact acceptance policy",
            ));
        }
        let accepted_sender_package = AcceptedSenderQualificationPackageV1::verify(
            sender_manifest_bytes,
            sender_report_bytes,
            sender_certificate_bytes,
            &policy,
        )?;
        let lifecycle_status = policy.certificate_status;
        Ok(Self {
            signing,
            policy,
            accepted_sender_package,
            pending_challenge: None,
            session: None,
            inbound: VecDeque::new(),
            receipts: Vec::new(),
            receipt_sequence: 0,
            duplicate_refusals: 0,
            replay_refusals: 0,
            sequence_gaps: 0,
            queue_refusals: 0,
            competing_occurrences: 0,
            lifecycle_status,
        })
    }

    #[must_use]
    pub fn live_session_count(&self) -> usize {
        usize::from(self.session.is_some())
    }

    #[must_use]
    pub fn accepted_remote_activation_count(&self) -> usize {
        usize::from(self.session.is_some())
    }

    #[must_use]
    pub fn receipts(&self) -> &[ReceiverAcceptanceReceiptV1] {
        &self.receipts
    }

    #[must_use]
    pub const fn duplicate_refusals(&self) -> u64 {
        self.duplicate_refusals
    }

    #[must_use]
    pub const fn replay_refusals(&self) -> u64 {
        self.replay_refusals
    }

    #[must_use]
    pub const fn sequence_gap_count(&self) -> u64 {
        self.sequence_gaps
    }

    #[must_use]
    pub const fn queue_refusals(&self) -> u64 {
        self.queue_refusals
    }

    #[must_use]
    pub const fn competing_occurrences(&self) -> u64 {
        self.competing_occurrences
    }

    pub fn accept_session_offer_and_issue_challenge(
        &mut self,
        reactor: &LocalCrashReactor,
        subject: &pulse_types::SubjectId,
        consumer: &pulse_types::ConsumerId,
        offer_datagram: &[u8],
    ) -> Result<Vec<u8>, CustodyError> {
        match self.lifecycle_status {
            CustodyCertificateStatusV1::Accepted => {}
            CustodyCertificateStatusV1::Superseded => {
                return Err(CustodyError::new(
                    TransportCustodyFindingV1::CertificateSuperseded,
                    "receiver policy marks the sender certificate superseded",
                ));
            }
            CustodyCertificateStatusV1::Revoked => {
                return Err(CustodyError::new(
                    TransportCustodyFindingV1::CertificateRevoked,
                    "receiver policy marks the sender certificate revoked",
                ));
            }
            CustodyCertificateStatusV1::Unknown => {
                return Err(CustodyError::new(
                    TransportCustodyFindingV1::QualifiedIdentityMismatch,
                    "receiver policy cannot establish sender certificate lifecycle",
                ));
            }
        }
        let activation =
            reactor.revalidate_transport_activation(subject, consumer, &self.policy.binding())?;
        let offer =
            decode_sender_session_offer_datagram(offer_datagram, &self.policy.accepted_sender_key)?;
        if offer.body.receiver_key_identity_digest != self.policy.receiver_key.identity_digest()
            || offer.body.sender_key_identity_digest
                != self.policy.accepted_sender_key.identity_digest()
            || offer.body.sender_manifest_digest != self.policy.accepted_sender_manifest_digest
            || offer.body.sender_qualification_certificate_digest
                != self.policy.accepted_sender_certificate_digest
            || offer.body.observer != self.policy.accepted_observer
            || offer.body.failure_domain_claim != self.policy.accepted_failure_domain_claim
            || offer.body.permitted_subject_scopes != self.policy.permitted_subject_scopes
        {
            return Err(CustodyError::new(
                TransportCustodyFindingV1::QualifiedIdentityMismatch,
                "sender offer does not match the receiver's exact package/scope policy",
            ));
        }
        if let Some(active) = &self.session {
            if active.binding.body.observer == offer.body.observer
                && active.binding.body.sender_key_identity_digest
                    == offer.body.sender_key_identity_digest
                && active.binding.body.sender_process_occurrence
                    != offer.body.sender_process_occurrence
            {
                self.competing_occurrences = self.competing_occurrences.saturating_add(1);
                let session_digest = Some(active.binding.binding_digest.clone());
                self.session = None;
                self.pending_challenge = None;
                let _ = reactor.report_receiver_boundary_condition(
                    Some(subject.clone()),
                    TransportCustodyFindingV1::SenderOccurrenceConflict,
                    session_digest,
                    "competing sender process occurrences claimed one observer/key/scope",
                    true,
                );
                return Err(CustodyError::new(
                    TransportCustodyFindingV1::SenderOccurrenceConflict,
                    "competing sender occurrence refused; last arrival did not win",
                ));
            }
            return Err(CustodyError::new(
                TransportCustodyFindingV1::SessionConflict,
                "receiver already has a live session for this sender occurrence",
            ));
        }
        if self.pending_challenge.is_some() {
            return Err(CustodyError::new(
                TransportCustodyFindingV1::SessionConflict,
                "receiver already has one bounded pending challenge",
            ));
        }
        let snapshot = reactor.snapshot();
        if !snapshot.condition.exposes_live_standing() {
            return Err(CustodyError::new(
                TransportCustodyFindingV1::ReceiverBlind,
                "receiver reactor does not expose live temporal custody",
            ));
        }
        let now_monotonic_ms = snapshot.observed_at_epoch_monotonic_ms;
        let mut nonce = [0_u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let body = ReceiverSessionChallengeBodyV1 {
            schema_version: SCHEMA_VERSION_V1,
            protocol_version: CUSTODY_PROTOCOL_VERSION_V1,
            receiver_key_identity_digest: self.policy.receiver_key.identity_digest(),
            sender_session_offer_digest: offer.offer_digest.clone(),
            receiver_process_occurrence: activation.process_epoch_id.clone(),
            receiver_monotonic_epoch: snapshot.monotonic_epoch.epoch_id,
            session_nonce_hex: encode_lower_hex(&nonce),
            receiver_acceptance_policy_generation: self.policy.policy_generation.clone(),
            receiver_acceptance_policy_anchor_digest: self.policy.anchor_digest(),
            receiver_acceptance_policy_digest: self.policy.identity_digest(),
            intended_sender_key_identity_digest: self.policy.accepted_sender_key.identity_digest(),
            intended_sender_process_occurrence: offer.body.sender_process_occurrence.clone(),
            accepted_sender_manifest_digest: self.accepted_sender_package.manifest_digest().clone(),
            accepted_sender_certificate_digest: self
                .accepted_sender_package
                .certificate_digest()
                .clone(),
            issued_at_receiver_monotonic_ms: now_monotonic_ms,
            expires_at_receiver_monotonic_ms: now_monotonic_ms
                .saturating_add(self.policy.maximum_session_duration_ms),
            maximum_envelope_bytes: self.policy.maximum_datagram_bytes,
            maximum_messages: self.policy.maximum_messages_per_session,
        };
        let (challenge, datagram) = sign_receiver_challenge(&self.signing, body)?;
        self.pending_challenge = Some((challenge, activation, offer));
        Ok(datagram)
    }

    pub fn accept_session_binding(
        &mut self,
        reactor: &LocalCrashReactor,
        subject: &pulse_types::SubjectId,
        consumer: &pulse_types::ConsumerId,
        datagram: &[u8],
    ) -> Result<Vec<u8>, CustodyError> {
        let receiver_activation =
            reactor.revalidate_transport_activation(subject, consumer, &self.policy.binding())?;
        let now_monotonic_ms = reactor.receiver_monotonic_now()?;
        let (challenge, challenge_activation, offer) =
            self.pending_challenge.as_ref().ok_or_else(|| {
                CustodyError::new(
                    TransportCustodyFindingV1::SessionUnknown,
                    "receiver has no live pending challenge",
                )
            })?;
        if now_monotonic_ms >= challenge.body.expires_at_receiver_monotonic_ms {
            self.pending_challenge = None;
            return Err(CustodyError::new(
                TransportCustodyFindingV1::SessionExpired,
                "receiver challenge expired inclusively",
            ));
        }
        if &receiver_activation != challenge_activation {
            self.pending_challenge = None;
            return Err(CustodyError::new(
                TransportCustodyFindingV1::QualifiedIdentityMismatch,
                "receiver activation changed after challenge issuance",
            ));
        }
        let binding =
            decode_sender_session_binding_datagram(datagram, &self.policy.accepted_sender_key)?;
        self.verify_session_binding(challenge, offer, &binding)?;
        if let Some(active) = &self.session
            && active.binding.body.observer == binding.body.observer
            && active.binding.body.sender_key_identity_digest
                == binding.body.sender_key_identity_digest
            && active.binding.body.sender_process_occurrence
                != binding.body.sender_process_occurrence
        {
            self.competing_occurrences = self.competing_occurrences.saturating_add(1);
            let session_digest = Some(active.binding.binding_digest.clone());
            self.session = None;
            self.pending_challenge = None;
            let _ = reactor.report_receiver_boundary_condition(
                Some(subject.clone()),
                TransportCustodyFindingV1::SenderOccurrenceConflict,
                session_digest,
                "competing sender process occurrences claimed one observer/key/scope",
                true,
            );
            return Err(CustodyError::new(
                TransportCustodyFindingV1::SenderOccurrenceConflict,
                "competing sender occurrence refused; last arrival did not win",
            ));
        }
        let acceptance_body = ReceiverSessionAcceptanceBodyV1 {
            schema_version: SCHEMA_VERSION_V1,
            protocol_version: CUSTODY_PROTOCOL_VERSION_V1,
            receiver_challenge_digest: challenge.challenge_digest.clone(),
            sender_session_binding_digest: binding.binding_digest.clone(),
            receiver_key_identity_digest: self.policy.receiver_key.identity_digest(),
            sender_key_identity_digest: self.policy.accepted_sender_key.identity_digest(),
            receiver_process_occurrence: challenge.body.receiver_process_occurrence.clone(),
            receiver_monotonic_epoch: challenge.body.receiver_monotonic_epoch.clone(),
            sender_process_occurrence: binding.body.sender_process_occurrence.clone(),
            receiver_acceptance_policy_digest: self.policy.identity_digest(),
            accepted_at_receiver_monotonic_ms: now_monotonic_ms,
            expires_at_receiver_monotonic_ms: challenge.body.expires_at_receiver_monotonic_ms,
            maximum_messages: challenge.body.maximum_messages,
        };
        let (acceptance, acceptance_datagram) =
            sign_receiver_session_acceptance(&self.signing, acceptance_body)?;
        self.session = Some(ReceiverLiveSession {
            challenge: challenge.clone(),
            high_session_sequence: Some(binding.body.session_sequence_origin - 1),
            binding,
            receiver_session_acceptance_digest: acceptance.acceptance_digest,
            receiver_activation,
            replay_bitmap: 0,
            high_observation_sequence: None,
            accepted_messages: 0,
            rate_window_started_ms: now_monotonic_ms,
            rate_window_messages: 0,
        });
        self.pending_challenge = None;
        Ok(acceptance_datagram)
    }

    fn verify_session_binding(
        &self,
        challenge: &ReceiverSessionChallengeV1,
        offer: &SenderSessionOfferV1,
        binding: &SenderSessionBindingV1,
    ) -> Result<(), CustodyError> {
        if binding.body.receiver_challenge_digest != challenge.challenge_digest
            || challenge.body.sender_session_offer_digest != offer.offer_digest
            || binding.body.receiver_key_identity_digest
                != self.policy.receiver_key.identity_digest()
            || binding.body.sender_key_identity_digest
                != self.policy.accepted_sender_key.identity_digest()
            || binding.body.sender_process_occurrence
                != challenge.body.intended_sender_process_occurrence
            || binding.body.sender_process_occurrence != offer.body.sender_process_occurrence
            || binding.body.sender_monotonic_epoch != offer.body.sender_monotonic_epoch
            || binding.body.sender_manifest_digest != self.policy.accepted_sender_manifest_digest
            || binding.body.sender_qualification_certificate_digest
                != self.policy.accepted_sender_certificate_digest
            || binding.body.sender_activation_receipt_digest
                != offer.body.sender_activation_receipt_digest
            || binding.body.sender_runtime_generation_set_digest
                != offer.body.sender_runtime_generation_set_digest
            || binding.body.observer != self.policy.accepted_observer
            || binding.body.failure_domain_claim != self.policy.accepted_failure_domain_claim
            || binding.body.permitted_subject_scopes != self.policy.permitted_subject_scopes
            || binding.body.session_sequence_origin != 1
        {
            return Err(CustodyError::new(
                TransportCustodyFindingV1::QualifiedIdentityMismatch,
                "sender binding does not match the receiver's exact accepted package/scope",
            ));
        }
        Ok(())
    }

    pub fn enqueue_envelope(
        &mut self,
        reactor: &LocalCrashReactor,
        bytes: Vec<u8>,
        remote_endpoint: impl Into<String>,
    ) -> Result<(), CustodyError> {
        let arrival_monotonic_ms = reactor.receiver_monotonic_now()?;
        if bytes.is_empty() || bytes.len() > usize::from(self.policy.maximum_datagram_bytes) {
            return Err(CustodyError::new(
                TransportCustodyFindingV1::TransportMalformed,
                "inbound envelope is empty or exceeds the qualified datagram bound",
            ));
        }
        if self.inbound.len() >= usize::from(self.policy.receiver_queue_bound) {
            self.queue_refusals = self.queue_refusals.saturating_add(1);
            let session_digest = self
                .session
                .as_ref()
                .map(|session| session.binding.binding_digest.clone());
            self.session = None;
            let _ = reactor.report_receiver_boundary_condition(
                None,
                TransportCustodyFindingV1::TransportOverloaded,
                session_digest,
                "receiver-boundary queue saturated; remote evidence custody is blind",
                true,
            );
            return Err(CustodyError::new(
                TransportCustodyFindingV1::TransportOverloaded,
                "receiver bounded envelope queue is full; session invalidated",
            ));
        }
        self.inbound.push_back(QueuedEnvelope {
            bytes,
            remote_endpoint: remote_endpoint.into(),
            arrival_monotonic_ms,
        });
        Ok(())
    }

    pub fn admit_next(
        &mut self,
        reactor: &LocalCrashReactor,
        subject: &pulse_types::SubjectId,
        consumer: &pulse_types::ConsumerId,
    ) -> Result<ReceiverEnvelopeAdmissionV1, CustodyError> {
        let queued = self.inbound.pop_front().ok_or_else(|| {
            CustodyError::new(
                TransportCustodyFindingV1::TransportUnavailable,
                "receiver envelope queue is empty",
            )
        })?;
        let result = self.admit_envelope_inner(reactor, subject, consumer, &queued);
        match result {
            Ok((receipt, verified)) => {
                self.retain_receipt(receipt.clone())?;
                Ok(ReceiverEnvelopeAdmissionV1 {
                    receipt,
                    verified: Some(verified),
                })
            }
            Err(error) => {
                let receipt = self.refusal_receipt(&queued, &error)?;
                self.retain_receipt(receipt.clone())?;
                Ok(ReceiverEnvelopeAdmissionV1 {
                    receipt,
                    verified: None,
                })
            }
        }
    }

    fn admit_envelope_inner(
        &mut self,
        reactor: &LocalCrashReactor,
        subject: &pulse_types::SubjectId,
        consumer: &pulse_types::ConsumerId,
        queued: &QueuedEnvelope,
    ) -> Result<(ReceiverAcceptanceReceiptV1, VerifiedRemoteObservationV1), CustodyError> {
        let session = self.session.as_mut().ok_or_else(|| {
            CustodyError::new(
                TransportCustodyFindingV1::SessionUnknown,
                "receiver has no live sender session",
            )
        })?;
        if queued.arrival_monotonic_ms >= session.challenge.body.expires_at_receiver_monotonic_ms {
            self.session = None;
            return Err(CustodyError::new(
                TransportCustodyFindingV1::SessionExpired,
                "receiver session expired inclusively before envelope arrival",
            ));
        }
        if self.lifecycle_status != CustodyCertificateStatusV1::Accepted {
            self.session = None;
            return Err(CustodyError::new(
                match self.lifecycle_status {
                    CustodyCertificateStatusV1::Superseded => {
                        TransportCustodyFindingV1::CertificateSuperseded
                    }
                    CustodyCertificateStatusV1::Revoked => {
                        TransportCustodyFindingV1::CertificateRevoked
                    }
                    CustodyCertificateStatusV1::Accepted | CustodyCertificateStatusV1::Unknown => {
                        TransportCustodyFindingV1::QualifiedIdentityMismatch
                    }
                },
                "sender certificate lifecycle no longer permits admission",
            ));
        }
        if queued.arrival_monotonic_ms >= session.rate_window_started_ms.saturating_add(1_000) {
            session.rate_window_started_ms = queued.arrival_monotonic_ms;
            session.rate_window_messages = 0;
        }
        if session.rate_window_messages >= self.policy.maximum_messages_per_second
            || session.accepted_messages >= self.policy.maximum_messages_per_session
        {
            let session_digest = Some(session.binding.binding_digest.clone());
            self.session = None;
            let _ = reactor.report_receiver_boundary_condition(
                Some(subject.clone()),
                TransportCustodyFindingV1::TransportOverloaded,
                session_digest,
                "receiver-boundary rate or session-message capacity was exceeded",
                true,
            );
            return Err(CustodyError::new(
                TransportCustodyFindingV1::TransportOverloaded,
                "receiver rate or session-message bound is exhausted",
            ));
        }
        let envelope =
            decode_observation_envelope_for_admission(&queued.bytes, &self.policy, session)?;
        verify_envelope_session_identity(&self.policy, session, &envelope)?;
        let replay = classify_sequence(
            session.high_session_sequence,
            session.replay_bitmap,
            envelope.body.session_sequence,
            self.policy.replay_window_size,
            self.policy.maximum_sequence_gap,
        )?;
        if matches!(
            replay.result,
            ReplayWindowResultV1::Duplicate
                | ReplayWindowResultV1::Replay
                | ReplayWindowResultV1::Reordered
                | ReplayWindowResultV1::BoundExceeded
        ) {
            if replay.result == ReplayWindowResultV1::Duplicate {
                self.duplicate_refusals = self.duplicate_refusals.saturating_add(1);
            } else {
                self.replay_refusals = self.replay_refusals.saturating_add(1);
            }
            return Err(CustodyError::new(
                if replay.result == ReplayWindowResultV1::Duplicate {
                    TransportCustodyFindingV1::DuplicateDetected
                } else {
                    TransportCustodyFindingV1::ReplayDetected
                },
                "duplicate, replayed, reordered, or over-window session sequence refused",
            )
            .with_replay_window_result(replay.result));
        }
        if let Some(prior_observation) = session.high_observation_sequence
            && envelope.body.observation_sequence <= prior_observation
        {
            self.replay_refusals = self.replay_refusals.saturating_add(1);
            return Err(CustodyError::new(
                TransportCustodyFindingV1::ReplayDetected,
                "observation sequence reset/replay is not admitted within a session",
            )
            .with_replay_window_result(ReplayWindowResultV1::Replay));
        }
        let payload = envelope
            .body
            .payload_bytes()
            .map_err(CustodyError::from_type)?;
        let frame = PulseFrameV1::decode_wire(&payload).map_err(|error| {
            CustodyError::new(
                TransportCustodyFindingV1::PayloadMalformed,
                error.to_string(),
            )
        })?;
        verify_frame_identity(&self.policy, &envelope, &frame)?;
        if self.policy.observation_time_freshness_required
            || !self.policy.arrival_anchored_evidence_may_support_reliance
        {
            return Err(CustodyError::new(
                TransportCustodyFindingV1::ObservationRejected,
                "policy requires unproved observation-time freshness; ArrivalAnchored evidence withheld",
            ));
        }
        let receiver_activation =
            reactor.revalidate_transport_activation(subject, consumer, &self.policy.binding())?;
        if receiver_activation != session.receiver_activation {
            self.session = None;
            return Err(CustodyError::new(
                TransportCustodyFindingV1::QualifiedIdentityMismatch,
                "receiver qualified activation changed during the session",
            ));
        }
        session.high_session_sequence = Some(replay.new_high);
        session.replay_bitmap = replay.new_bitmap;
        session.high_observation_sequence = Some(envelope.body.observation_sequence);
        session.accepted_messages = session.accepted_messages.saturating_add(1);
        session.rate_window_messages = session.rate_window_messages.saturating_add(1);
        let sequence_gap = replay.gap.clone();
        if sequence_gap.is_some() {
            self.sequence_gaps = self.sequence_gaps.saturating_add(1);
        }
        let receiver_monotonic_epoch = session.challenge.body.receiver_monotonic_epoch.clone();
        let sender_session_offer_digest =
            session.challenge.body.sender_session_offer_digest.clone();
        let receiver_challenge_digest = session.challenge.challenge_digest.clone();
        let session_binding_digest = session.binding.binding_digest.clone();
        let receiver_session_acceptance_digest = session.receiver_session_acceptance_digest.clone();
        let arrival_bytes = queued.arrival_monotonic_ms.to_be_bytes();
        let evidence_identity = digest_parts(
            "transport.admitted-evidence.v1",
            &[
                envelope.envelope_digest.as_str().as_bytes(),
                session_binding_digest.as_str().as_bytes(),
                arrival_bytes.as_slice(),
                receiver_activation
                    .activation_receipt_digest
                    .as_str()
                    .as_bytes(),
            ],
        );
        let receipt = self.acceptance_receipt(
            queued,
            &envelope,
            sequence_gap,
            replay.result,
            evidence_identity.clone(),
        )?;
        let supporting_evidence_id = evidence_ref(&frame);
        let custody = RemoteObservationCustodyReferenceV1 {
            schema_version: SCHEMA_VERSION_V1,
            receiver_process_occurrence: receiver_activation.process_epoch_id.clone(),
            receiver_monotonic_epoch,
            receiver_manifest_digest: receiver_activation.manifest_digest.clone(),
            receiver_qualification_certificate_digest: receiver_activation
                .qualification_certificate_digest
                .clone(),
            receiver_activation_receipt_digest: receiver_activation
                .activation_receipt_digest
                .clone(),
            receiver_acceptance_policy_generation: self.policy.policy_generation.clone(),
            receiver_acceptance_policy_digest: self.policy.identity_digest(),
            receiver_key_identity_digest: self.policy.receiver_key.identity_digest(),
            sender_key_identity_digest: self.policy.accepted_sender_key.identity_digest(),
            sender_process_occurrence: envelope.body.sender_process_occurrence.clone(),
            sender_monotonic_epoch: envelope.body.sender_monotonic_epoch.clone(),
            sender_manifest_digest: envelope.body.sender_manifest_digest.clone(),
            sender_qualification_certificate_digest: envelope
                .body
                .sender_qualification_certificate_digest
                .clone(),
            sender_activation_receipt_digest: envelope
                .body
                .sender_activation_receipt_digest
                .clone(),
            sender_session_offer_digest,
            receiver_challenge_digest,
            session_binding_digest,
            receiver_session_acceptance_digest,
            envelope_digest: envelope.envelope_digest.clone(),
            acceptance_receipt_digest: receipt.receipt_digest.clone(),
            observer: frame.observer.clone(),
            failure_domain_claim: envelope.body.failure_domain_claim.clone(),
            subject_scope: envelope.body.subject_scope.clone(),
            observation_sequence: envelope.body.observation_sequence,
            session_sequence: envelope.body.session_sequence,
            payload_digest: envelope.body.payload_digest.clone(),
            observation_identity: envelope.body.observation_identity.clone(),
            supporting_evidence_id,
            receiver_arrival_monotonic_ms: queued.arrival_monotonic_ms,
            accepted_evidence_identity: evidence_identity,
            freshness_mode: RemoteFreshnessModeV1::ArrivalAnchored,
            authority_grants: CustodyAuthorityGrantsV1::none(),
        };
        custody.validate().map_err(CustodyError::from_type)?;
        Ok((
            receipt.clone(),
            VerifiedRemoteObservationV1 {
                frame,
                custody,
                receipt,
            },
        ))
    }

    fn acceptance_receipt(
        &mut self,
        queued: &QueuedEnvelope,
        envelope: &ObservationCustodyEnvelopeV1,
        sequence_gap: Option<CustodySequenceGapV1>,
        replay: ReplayWindowResultV1,
        evidence_identity: DigestV1,
    ) -> Result<ReceiverAcceptanceReceiptV1, CustodyError> {
        let sequence = self.next_receipt_sequence()?;
        let session = self.session.as_ref().expect("admission has a live session");
        let receipt = ReceiverAcceptanceReceiptV1 {
            schema_version: SCHEMA_VERSION_V1,
            receipt_digest: digest_parts("transport.receipt.pending.v1", &[b"pending"]),
            receiver_process_occurrence: session.receiver_activation.process_epoch_id.clone(),
            receiver_monotonic_epoch: session.challenge.body.receiver_monotonic_epoch.clone(),
            receiver_acceptance_policy_generation: self.policy.policy_generation.clone(),
            receiver_acceptance_policy_digest: self.policy.identity_digest(),
            session_binding_digest: Some(session.binding.binding_digest.clone()),
            envelope_digest: Some(envelope.envelope_digest.clone()),
            receiver_arrival_monotonic_ms: queued.arrival_monotonic_ms,
            remote_network_endpoint: queued.remote_endpoint.clone(),
            sender_key_verification: CustodyCheckResultV1::Accepted,
            receiver_challenge_verification: CustodyCheckResultV1::Accepted,
            session_binding_verification: CustodyCheckResultV1::Accepted,
            sender_qualification_package_acceptance: CustodyCheckResultV1::Accepted,
            exact_identity_match: CustodyCheckResultV1::Accepted,
            replay_window_result: replay,
            sequence_gap,
            queue_and_capacity_result: CustodyCheckResultV1::Accepted,
            subject_scope_result: CustodyCheckResultV1::Accepted,
            observer_role_result: CustodyCheckResultV1::Accepted,
            payload_decoding_result: CustodyCheckResultV1::Accepted,
            finding: TransportCustodyFindingV1::EvidenceAdmitted,
            accepted_evidence_identity: Some(evidence_identity),
            refusal_reason: None,
            complete: true,
            receipt_sequence: sequence,
            journal_identity: self.policy.journal_id.clone(),
            mutation_authority: MutationAuthorityV1::None,
            authority_grants: CustodyAuthorityGrantsV1::none(),
        }
        .seal();
        receipt.validate().map_err(CustodyError::from_type)?;
        Ok(receipt)
    }

    fn refusal_receipt(
        &mut self,
        queued: &QueuedEnvelope,
        error: &CustodyError,
    ) -> Result<ReceiverAcceptanceReceiptV1, CustodyError> {
        let sequence = self.next_receipt_sequence()?;
        let (receiver_process_occurrence, receiver_epoch, session_digest) =
            self.session.as_ref().map_or_else(
                || {
                    (
                        IncarnationId::new("receiver-process:unavailable"),
                        IncarnationId::new("receiver-epoch:unavailable"),
                        None,
                    )
                },
                |session| {
                    (
                        session.receiver_activation.process_epoch_id.clone(),
                        session.challenge.body.receiver_monotonic_epoch.clone(),
                        Some(session.binding.binding_digest.clone()),
                    )
                },
            );
        let receipt = ReceiverAcceptanceReceiptV1 {
            schema_version: SCHEMA_VERSION_V1,
            receipt_digest: digest_parts("transport.receipt.pending.v1", &[b"pending"]),
            receiver_process_occurrence,
            receiver_monotonic_epoch: receiver_epoch,
            receiver_acceptance_policy_generation: self.policy.policy_generation.clone(),
            receiver_acceptance_policy_digest: self.policy.identity_digest(),
            session_binding_digest: session_digest,
            envelope_digest: decode_envelope_digest_without_auth(&queued.bytes),
            receiver_arrival_monotonic_ms: queued.arrival_monotonic_ms,
            remote_network_endpoint: queued.remote_endpoint.clone(),
            sender_key_verification: if matches!(
                error.finding,
                TransportCustodyFindingV1::AuthenticationFailed
                    | TransportCustodyFindingV1::SenderKeyMismatch
                    | TransportCustodyFindingV1::SignatureInvalid
            ) {
                CustodyCheckResultV1::Rejected
            } else {
                CustodyCheckResultV1::NotChecked
            },
            receiver_challenge_verification: CustodyCheckResultV1::NotChecked,
            session_binding_verification: CustodyCheckResultV1::NotChecked,
            sender_qualification_package_acceptance: CustodyCheckResultV1::NotChecked,
            exact_identity_match: CustodyCheckResultV1::NotChecked,
            replay_window_result: error
                .replay_window_result
                .unwrap_or_else(|| replay_for_finding(error.finding)),
            sequence_gap: None,
            queue_and_capacity_result: if error.finding
                == TransportCustodyFindingV1::TransportOverloaded
            {
                CustodyCheckResultV1::Rejected
            } else {
                CustodyCheckResultV1::NotChecked
            },
            subject_scope_result: CustodyCheckResultV1::NotChecked,
            observer_role_result: CustodyCheckResultV1::NotChecked,
            payload_decoding_result: CustodyCheckResultV1::NotChecked,
            finding: error.finding,
            accepted_evidence_identity: None,
            refusal_reason: Some(error.detail.clone()),
            complete: true,
            receipt_sequence: sequence,
            journal_identity: self.policy.journal_id.clone(),
            mutation_authority: MutationAuthorityV1::None,
            authority_grants: CustodyAuthorityGrantsV1::none(),
        }
        .seal();
        receipt.validate().map_err(CustodyError::from_type)?;
        Ok(receipt)
    }

    fn next_receipt_sequence(&mut self) -> Result<u64, CustodyError> {
        self.receipt_sequence = self.receipt_sequence.checked_add(1).ok_or_else(|| {
            CustodyError::new(
                TransportCustodyFindingV1::TransportOverloaded,
                "receiver acceptance receipt sequence exhausted",
            )
        })?;
        Ok(self.receipt_sequence)
    }

    fn retain_receipt(&mut self, receipt: ReceiverAcceptanceReceiptV1) -> Result<(), CustodyError> {
        if self.receipts.len() >= pulse_types::MAX_CUSTODY_RECEIPTS {
            self.session = None;
            return Err(CustodyError::new(
                TransportCustodyFindingV1::TransportOverloaded,
                "bounded receiver acceptance-receipt custody is exhausted",
            ));
        }
        self.receipts.push(receipt);
        Ok(())
    }

    pub fn apply_sender_lifecycle_fact(
        &mut self,
        reactor: &LocalCrashReactor,
        fact: &GenerationLifecycleFactV1,
    ) -> Result<(), CustodyError> {
        fact.validate().map_err(CustodyError::from_qualification)?;
        if fact.body.authority_id != self.policy.lifecycle_authority_id
            || fact.body.certificate_digest != self.policy.accepted_sender_certificate_digest
        {
            return Err(CustodyError::new(
                TransportCustodyFindingV1::QualifiedIdentityMismatch,
                "sender lifecycle fact is not accepted by the exact local authority policy",
            ));
        }
        self.lifecycle_status = match fact.body.kind {
            GenerationLifecycleKindV1::Superseded => CustodyCertificateStatusV1::Superseded,
            GenerationLifecycleKindV1::Revoked => CustodyCertificateStatusV1::Revoked,
        };
        let session_digest = self
            .session
            .as_ref()
            .map(|session| session.binding.binding_digest.clone());
        self.session = None;
        self.pending_challenge = None;
        self.inbound.clear();
        let _ = reactor.report_receiver_boundary_condition(
            None,
            match fact.body.kind {
                GenerationLifecycleKindV1::Superseded => {
                    TransportCustodyFindingV1::CertificateSuperseded
                }
                GenerationLifecycleKindV1::Revoked => TransportCustodyFindingV1::CertificateRevoked,
            },
            session_digest,
            "accepted sender certificate lifecycle fact invalidated remote custody",
            true,
        );
        Ok(())
    }

    pub fn invalidate_for_policy_change(&mut self, reactor: &LocalCrashReactor) {
        let session_digest = self
            .session
            .as_ref()
            .map(|session| session.binding.binding_digest.clone());
        self.session = None;
        self.pending_challenge = None;
        self.inbound.clear();
        let _ = reactor.report_receiver_boundary_condition(
            None,
            TransportCustodyFindingV1::QualifiedIdentityMismatch,
            session_digest,
            "receiver acceptance policy changed; new qualified activation/session required",
            true,
        );
    }

    pub fn report_transport_unavailable(
        &mut self,
        reactor: &LocalCrashReactor,
        detail: impl Into<String>,
    ) -> Result<crate::RuntimeCycleOutputV1, CustodyError> {
        let session_digest = self
            .session
            .as_ref()
            .map(|session| session.binding.binding_digest.clone());
        self.session = None;
        self.pending_challenge = None;
        self.inbound.clear();
        let output = reactor.report_receiver_boundary_condition(
            None,
            TransportCustodyFindingV1::TransportUnavailable,
            session_digest,
            detail,
            true,
        )?;
        Ok(output)
    }
}

#[derive(Clone, Debug)]
struct SequenceClassification {
    result: ReplayWindowResultV1,
    gap: Option<CustodySequenceGapV1>,
    new_high: u64,
    new_bitmap: u64,
}

fn classify_sequence(
    high: Option<u64>,
    bitmap: u64,
    received: u64,
    window_size: u16,
    maximum_gap: u64,
) -> Result<SequenceClassification, CustodyError> {
    if received == 0 {
        return Err(CustodyError::new(
            TransportCustodyFindingV1::ReplayDetected,
            "session sequence zero is invalid",
        ));
    }
    let Some(high) = high else {
        return Ok(SequenceClassification {
            result: ReplayWindowResultV1::First,
            gap: None,
            new_high: received,
            new_bitmap: 1,
        });
    };
    if received > high {
        let delta = received - high;
        if delta > maximum_gap.saturating_add(1) {
            return Ok(SequenceClassification {
                result: ReplayWindowResultV1::BoundExceeded,
                gap: None,
                new_high: high,
                new_bitmap: bitmap,
            });
        }
        let new_bitmap = if delta >= u64::from(window_size) {
            1
        } else {
            (bitmap << u32::try_from(delta).unwrap_or(u32::MAX)) | 1
        };
        let gap = (delta > 1).then(|| CustodySequenceGapV1 {
            expected_next: high.saturating_add(1),
            received,
            missing_count: delta - 1,
        });
        return Ok(SequenceClassification {
            result: if gap.is_some() {
                ReplayWindowResultV1::Gap
            } else {
                ReplayWindowResultV1::Continuous
            },
            gap,
            new_high: received,
            new_bitmap,
        });
    }
    let distance = high - received;
    if distance >= u64::from(window_size) {
        return Ok(SequenceClassification {
            result: ReplayWindowResultV1::Replay,
            gap: None,
            new_high: high,
            new_bitmap: bitmap,
        });
    }
    let mask = 1_u64 << u32::try_from(distance).unwrap_or(u32::MAX);
    Ok(SequenceClassification {
        result: if bitmap & mask != 0 {
            ReplayWindowResultV1::Duplicate
        } else {
            ReplayWindowResultV1::Reordered
        },
        gap: None,
        new_high: high,
        new_bitmap: bitmap,
    })
}

pub fn sign_sender_session_offer(
    signing: &CanarySigningIdentityV1,
    body: SenderSessionOfferBodyV1,
) -> Result<(SenderSessionOfferV1, Vec<u8>), CustodyError> {
    body.validate().map_err(CustodyError::from_type)?;
    let body_bytes = encode_sender_offer_body(&body)?;
    let signature = signing.sign(CustodySignatureDomainV1::SenderSessionOfferV1, &body_bytes);
    let value = SenderSessionOfferV1 {
        schema_version: SCHEMA_VERSION_V1,
        offer_digest: signed_object_digest(
            CustodySignatureDomainV1::SenderSessionOfferV1,
            &body_bytes,
            &signature,
        ),
        body,
        signature_domain: CustodySignatureDomainV1::SenderSessionOfferV1,
        signer_key_identity_digest: signing.key_identity().identity_digest(),
        signature_hex: encode_lower_hex(&signature),
        authority_grants: CustodyAuthorityGrantsV1::none(),
    };
    value
        .validate_structure()
        .map_err(CustodyError::from_type)?;
    let datagram = encode_signed_datagram(SENDER_SESSION_OFFER_KIND, &body_bytes, &signature)?;
    Ok((value, datagram))
}

pub fn decode_sender_session_offer_datagram(
    datagram: &[u8],
    expected_key: &PeerKeyIdentityV1,
) -> Result<SenderSessionOfferV1, CustodyError> {
    let (body_bytes, signature) = decode_signed_datagram(datagram, SENDER_SESSION_OFFER_KIND)?;
    let body = decode_sender_offer_body(&body_bytes)?;
    verify_signature(
        expected_key,
        CustodySignatureDomainV1::SenderSessionOfferV1,
        &body_bytes,
        &signature,
    )?;
    let value = SenderSessionOfferV1 {
        schema_version: SCHEMA_VERSION_V1,
        offer_digest: signed_object_digest(
            CustodySignatureDomainV1::SenderSessionOfferV1,
            &body_bytes,
            &signature,
        ),
        body,
        signature_domain: CustodySignatureDomainV1::SenderSessionOfferV1,
        signer_key_identity_digest: expected_key.identity_digest(),
        signature_hex: encode_lower_hex(&signature),
        authority_grants: CustodyAuthorityGrantsV1::none(),
    };
    value
        .validate_structure()
        .map_err(CustodyError::from_type)?;
    Ok(value)
}

pub fn sign_receiver_challenge(
    signing: &CanarySigningIdentityV1,
    body: ReceiverSessionChallengeBodyV1,
) -> Result<(ReceiverSessionChallengeV1, Vec<u8>), CustodyError> {
    body.validate().map_err(CustodyError::from_type)?;
    let body_bytes = encode_challenge_body(&body)?;
    let signature = signing.sign(
        CustodySignatureDomainV1::ReceiverSessionChallengeV1,
        &body_bytes,
    );
    let challenge_digest = signed_object_digest(
        CustodySignatureDomainV1::ReceiverSessionChallengeV1,
        &body_bytes,
        &signature,
    );
    let value = ReceiverSessionChallengeV1 {
        schema_version: SCHEMA_VERSION_V1,
        challenge_digest,
        body,
        signature_domain: CustodySignatureDomainV1::ReceiverSessionChallengeV1,
        signer_key_identity_digest: signing.key_identity().identity_digest(),
        signature_hex: encode_lower_hex(&signature),
        authority_grants: CustodyAuthorityGrantsV1::none(),
    };
    value
        .validate_structure()
        .map_err(CustodyError::from_type)?;
    let datagram = encode_signed_datagram(CHALLENGE_KIND, &body_bytes, &signature)?;
    Ok((value, datagram))
}

pub fn decode_receiver_challenge_datagram(
    datagram: &[u8],
    expected_key: &PeerKeyIdentityV1,
) -> Result<ReceiverSessionChallengeV1, CustodyError> {
    let (body_bytes, signature) = decode_signed_datagram(datagram, CHALLENGE_KIND)?;
    let body = decode_challenge_body(&body_bytes)?;
    verify_signature(
        expected_key,
        CustodySignatureDomainV1::ReceiverSessionChallengeV1,
        &body_bytes,
        &signature,
    )?;
    let value = ReceiverSessionChallengeV1 {
        schema_version: SCHEMA_VERSION_V1,
        challenge_digest: signed_object_digest(
            CustodySignatureDomainV1::ReceiverSessionChallengeV1,
            &body_bytes,
            &signature,
        ),
        body,
        signature_domain: CustodySignatureDomainV1::ReceiverSessionChallengeV1,
        signer_key_identity_digest: expected_key.identity_digest(),
        signature_hex: encode_lower_hex(&signature),
        authority_grants: CustodyAuthorityGrantsV1::none(),
    };
    value
        .validate_structure()
        .map_err(CustodyError::from_type)?;
    Ok(value)
}

pub fn sign_sender_session_binding(
    signing: &CanarySigningIdentityV1,
    body: SenderSessionBindingBodyV1,
) -> Result<(SenderSessionBindingV1, Vec<u8>), CustodyError> {
    body.validate().map_err(CustodyError::from_type)?;
    let body_bytes = encode_binding_body(&body)?;
    let signature = signing.sign(
        CustodySignatureDomainV1::SenderSessionBindingV1,
        &body_bytes,
    );
    let value = SenderSessionBindingV1 {
        schema_version: SCHEMA_VERSION_V1,
        binding_digest: signed_object_digest(
            CustodySignatureDomainV1::SenderSessionBindingV1,
            &body_bytes,
            &signature,
        ),
        body,
        signature_domain: CustodySignatureDomainV1::SenderSessionBindingV1,
        signer_key_identity_digest: signing.key_identity().identity_digest(),
        signature_hex: encode_lower_hex(&signature),
        authority_grants: CustodyAuthorityGrantsV1::none(),
    };
    value
        .validate_structure()
        .map_err(CustodyError::from_type)?;
    let datagram = encode_signed_datagram(SESSION_BINDING_KIND, &body_bytes, &signature)?;
    Ok((value, datagram))
}

pub fn decode_sender_session_binding_datagram(
    datagram: &[u8],
    expected_key: &PeerKeyIdentityV1,
) -> Result<SenderSessionBindingV1, CustodyError> {
    let (body_bytes, signature) = decode_signed_datagram(datagram, SESSION_BINDING_KIND)?;
    let body = decode_binding_body(&body_bytes)?;
    verify_signature(
        expected_key,
        CustodySignatureDomainV1::SenderSessionBindingV1,
        &body_bytes,
        &signature,
    )?;
    let value = SenderSessionBindingV1 {
        schema_version: SCHEMA_VERSION_V1,
        binding_digest: signed_object_digest(
            CustodySignatureDomainV1::SenderSessionBindingV1,
            &body_bytes,
            &signature,
        ),
        body,
        signature_domain: CustodySignatureDomainV1::SenderSessionBindingV1,
        signer_key_identity_digest: expected_key.identity_digest(),
        signature_hex: encode_lower_hex(&signature),
        authority_grants: CustodyAuthorityGrantsV1::none(),
    };
    value
        .validate_structure()
        .map_err(CustodyError::from_type)?;
    Ok(value)
}

pub fn sign_receiver_session_acceptance(
    signing: &CanarySigningIdentityV1,
    body: ReceiverSessionAcceptanceBodyV1,
) -> Result<(ReceiverSessionAcceptanceV1, Vec<u8>), CustodyError> {
    body.validate().map_err(CustodyError::from_type)?;
    let body_bytes = encode_receiver_session_acceptance_body(&body)?;
    let signature = signing.sign(
        CustodySignatureDomainV1::ReceiverSessionAcceptanceV1,
        &body_bytes,
    );
    let value = ReceiverSessionAcceptanceV1 {
        schema_version: SCHEMA_VERSION_V1,
        acceptance_digest: signed_object_digest(
            CustodySignatureDomainV1::ReceiverSessionAcceptanceV1,
            &body_bytes,
            &signature,
        ),
        body,
        signature_domain: CustodySignatureDomainV1::ReceiverSessionAcceptanceV1,
        signer_key_identity_digest: signing.key_identity().identity_digest(),
        signature_hex: encode_lower_hex(&signature),
        authority_grants: CustodyAuthorityGrantsV1::none(),
    };
    value
        .validate_structure()
        .map_err(CustodyError::from_type)?;
    let datagram =
        encode_signed_datagram(RECEIVER_SESSION_ACCEPTANCE_KIND, &body_bytes, &signature)?;
    Ok((value, datagram))
}

pub fn decode_receiver_session_acceptance_datagram(
    datagram: &[u8],
    expected_key: &PeerKeyIdentityV1,
) -> Result<ReceiverSessionAcceptanceV1, CustodyError> {
    let (body_bytes, signature) =
        decode_signed_datagram(datagram, RECEIVER_SESSION_ACCEPTANCE_KIND)?;
    let body = decode_receiver_session_acceptance_body(&body_bytes)?;
    verify_signature(
        expected_key,
        CustodySignatureDomainV1::ReceiverSessionAcceptanceV1,
        &body_bytes,
        &signature,
    )?;
    let value = ReceiverSessionAcceptanceV1 {
        schema_version: SCHEMA_VERSION_V1,
        acceptance_digest: signed_object_digest(
            CustodySignatureDomainV1::ReceiverSessionAcceptanceV1,
            &body_bytes,
            &signature,
        ),
        body,
        signature_domain: CustodySignatureDomainV1::ReceiverSessionAcceptanceV1,
        signer_key_identity_digest: expected_key.identity_digest(),
        signature_hex: encode_lower_hex(&signature),
        authority_grants: CustodyAuthorityGrantsV1::none(),
    };
    value
        .validate_structure()
        .map_err(CustodyError::from_type)?;
    Ok(value)
}

pub fn sign_observation_envelope(
    signing: &CanarySigningIdentityV1,
    body: ObservationCustodyEnvelopeBodyV1,
) -> Result<(ObservationCustodyEnvelopeV1, Vec<u8>), CustodyError> {
    body.validate().map_err(CustodyError::from_type)?;
    let body_bytes = encode_envelope_body(&body)?;
    let signature = signing.sign(
        CustodySignatureDomainV1::ObservationCustodyEnvelopeV1,
        &body_bytes,
    );
    let value = ObservationCustodyEnvelopeV1 {
        schema_version: SCHEMA_VERSION_V1,
        envelope_digest: signed_object_digest(
            CustodySignatureDomainV1::ObservationCustodyEnvelopeV1,
            &body_bytes,
            &signature,
        ),
        body,
        signature_domain: CustodySignatureDomainV1::ObservationCustodyEnvelopeV1,
        signer_key_identity_digest: signing.key_identity().identity_digest(),
        signature_hex: encode_lower_hex(&signature),
        authority_grants: CustodyAuthorityGrantsV1::none(),
    };
    value
        .validate_structure()
        .map_err(CustodyError::from_type)?;
    let datagram = encode_signed_datagram(OBSERVATION_ENVELOPE_KIND, &body_bytes, &signature)?;
    Ok((value, datagram))
}

pub fn decode_observation_envelope_datagram(
    datagram: &[u8],
    expected_key: &PeerKeyIdentityV1,
) -> Result<ObservationCustodyEnvelopeV1, CustodyError> {
    let (body_bytes, signature) = decode_signed_datagram(datagram, OBSERVATION_ENVELOPE_KIND)?;
    let body = decode_envelope_body(&body_bytes)?;
    verify_signature(
        expected_key,
        CustodySignatureDomainV1::ObservationCustodyEnvelopeV1,
        &body_bytes,
        &signature,
    )?;
    let value = ObservationCustodyEnvelopeV1 {
        schema_version: SCHEMA_VERSION_V1,
        envelope_digest: signed_object_digest(
            CustodySignatureDomainV1::ObservationCustodyEnvelopeV1,
            &body_bytes,
            &signature,
        ),
        body,
        signature_domain: CustodySignatureDomainV1::ObservationCustodyEnvelopeV1,
        signer_key_identity_digest: expected_key.identity_digest(),
        signature_hex: encode_lower_hex(&signature),
        authority_grants: CustodyAuthorityGrantsV1::none(),
    };
    value
        .validate_structure()
        .map_err(CustodyError::from_type)?;
    Ok(value)
}

pub fn verify_signature_in_domain(
    key: &PeerKeyIdentityV1,
    domain: CustodySignatureDomainV1,
    body: &[u8],
    signature_hex: &str,
) -> Result<(), CustodyError> {
    let signature =
        decode_hex_exact(signature_hex, 64, "signature").map_err(CustodyError::from_type)?;
    let signature: [u8; 64] = signature.try_into().map_err(|_| {
        CustodyError::new(
            TransportCustodyFindingV1::SignatureInvalid,
            "signature byte count is invalid",
        )
    })?;
    verify_signature(key, domain, body, &signature)
}

fn verify_signature(
    key: &PeerKeyIdentityV1,
    domain: CustodySignatureDomainV1,
    body: &[u8],
    signature: &[u8; 64],
) -> Result<(), CustodyError> {
    key.validate().map_err(CustodyError::from_type)?;
    let public =
        decode_hex_exact(&key.public_key_hex, 32, "public key").map_err(CustodyError::from_type)?;
    let public: [u8; 32] = public.try_into().map_err(|_| {
        CustodyError::new(
            TransportCustodyFindingV1::AuthenticationFailed,
            "public key byte count is invalid",
        )
    })?;
    let verifying = VerifyingKey::from_bytes(&public).map_err(|error| {
        CustodyError::new(
            TransportCustodyFindingV1::AuthenticationFailed,
            format!("invalid Ed25519 public key: {error}"),
        )
    })?;
    verifying
        .verify_strict(
            &signature_transcript(domain, body),
            &Signature::from_bytes(signature),
        )
        .map_err(|_| {
            CustodyError::new(
                TransportCustodyFindingV1::SignatureInvalid,
                "strict Ed25519 signature verification failed",
            )
        })
}

fn signature_transcript(domain: CustodySignatureDomainV1, body: &[u8]) -> Vec<u8> {
    let domain = domain.as_str().as_bytes();
    let mut transcript = Vec::with_capacity(domain.len() + body.len() + 10);
    transcript.extend_from_slice(&(domain.len() as u16).to_be_bytes());
    transcript.extend_from_slice(domain);
    transcript.extend_from_slice(&(body.len() as u64).to_be_bytes());
    transcript.extend_from_slice(body);
    transcript
}

fn signed_object_digest(
    domain: CustodySignatureDomainV1,
    body: &[u8],
    signature: &[u8; 64],
) -> DigestV1 {
    digest_parts(
        "transport.signed-object.v1",
        &[domain.as_str().as_bytes(), body, signature],
    )
}

fn encode_signed_datagram(
    kind: u8,
    body: &[u8],
    signature: &[u8; 64],
) -> Result<Vec<u8>, CustodyError> {
    let body_length = u16::try_from(body.len()).map_err(|_| {
        CustodyError::new(
            TransportCustodyFindingV1::TransportMalformed,
            "canonical signed body length exceeds u16",
        )
    })?;
    let mut output = Vec::with_capacity(DATAGRAM_HEADER_BYTES + body.len() + SIGNATURE_BYTES);
    output.extend_from_slice(DATAGRAM_MAGIC);
    output.extend_from_slice(&CUSTODY_PROTOCOL_VERSION_V1.to_be_bytes());
    output.push(kind);
    output.extend_from_slice(&body_length.to_be_bytes());
    output.extend_from_slice(body);
    output.extend_from_slice(signature);
    if output.len() > MAX_CANARY_DATAGRAM_BYTES {
        return Err(CustodyError::new(
            TransportCustodyFindingV1::TransportMalformed,
            "canonical signed datagram exceeds 1,232 bytes",
        ));
    }
    Ok(output)
}

fn decode_signed_datagram(
    datagram: &[u8],
    expected_kind: u8,
) -> Result<(Vec<u8>, [u8; 64]), CustodyError> {
    if datagram.is_empty() || datagram.len() > MAX_CANARY_DATAGRAM_BYTES {
        return Err(CustodyError::new(
            TransportCustodyFindingV1::TransportMalformed,
            "datagram is empty or exceeds the fixed bound",
        ));
    }
    if datagram.len() < DATAGRAM_HEADER_BYTES + SIGNATURE_BYTES
        || &datagram[..4] != DATAGRAM_MAGIC
        || u16::from_be_bytes([datagram[4], datagram[5]]) != CUSTODY_PROTOCOL_VERSION_V1
        || datagram[6] != expected_kind
    {
        return Err(CustodyError::new(
            TransportCustodyFindingV1::TransportMalformed,
            "datagram header, version, or message kind is invalid",
        ));
    }
    let body_length = usize::from(u16::from_be_bytes([datagram[7], datagram[8]]));
    let expected_length = DATAGRAM_HEADER_BYTES
        .checked_add(body_length)
        .and_then(|length| length.checked_add(SIGNATURE_BYTES))
        .ok_or_else(|| {
            CustodyError::new(
                TransportCustodyFindingV1::TransportMalformed,
                "datagram length arithmetic overflowed",
            )
        })?;
    if datagram.len() != expected_length {
        return Err(CustodyError::new(
            TransportCustodyFindingV1::TransportMalformed,
            "datagram body length disagrees or trailing bytes are present",
        ));
    }
    let body = datagram[DATAGRAM_HEADER_BYTES..DATAGRAM_HEADER_BYTES + body_length].to_vec();
    let signature: [u8; 64] = datagram[DATAGRAM_HEADER_BYTES + body_length..]
        .try_into()
        .expect("exact signature suffix length was checked");
    Ok((body, signature))
}

fn encode_sender_offer_body(body: &SenderSessionOfferBodyV1) -> Result<Vec<u8>, CustodyError> {
    let mut writer = WireWriter::new();
    writer.u16(body.schema_version);
    writer.u16(body.protocol_version);
    writer.digest(&body.receiver_key_identity_digest)?;
    writer.digest(&body.sender_key_identity_digest)?;
    writer.text(body.sender_process_occurrence.as_str())?;
    writer.text(body.sender_monotonic_epoch.as_str())?;
    writer.fixed_hex(&body.sender_nonce_hex, 32, "sender offer nonce")?;
    writer.digest(&body.sender_manifest_digest)?;
    writer.digest(&body.sender_qualification_certificate_digest)?;
    writer.digest(&body.sender_activation_receipt_digest)?;
    writer.digest(&body.sender_runtime_generation_set_digest)?;
    writer.text(body.observer.as_str())?;
    writer.text(&body.failure_domain_claim)?;
    writer.scopes(&body.permitted_subject_scopes)?;
    Ok(writer.finish())
}

fn decode_sender_offer_body(bytes: &[u8]) -> Result<SenderSessionOfferBodyV1, CustodyError> {
    let mut reader = WireReader::new(bytes);
    let body = SenderSessionOfferBodyV1 {
        schema_version: reader.u16()?,
        protocol_version: reader.u16()?,
        receiver_key_identity_digest: reader.digest()?,
        sender_key_identity_digest: reader.digest()?,
        sender_process_occurrence: IncarnationId::new(reader.text()?),
        sender_monotonic_epoch: IncarnationId::new(reader.text()?),
        sender_nonce_hex: encode_lower_hex(reader.fixed(32)?),
        sender_manifest_digest: reader.digest()?,
        sender_qualification_certificate_digest: reader.digest()?,
        sender_activation_receipt_digest: reader.digest()?,
        sender_runtime_generation_set_digest: reader.digest()?,
        observer: ObserverId::new(reader.text()?),
        failure_domain_claim: reader.text()?,
        permitted_subject_scopes: reader.scopes()?,
    };
    reader.finish()?;
    body.validate().map_err(CustodyError::from_type)?;
    Ok(body)
}

fn encode_challenge_body(body: &ReceiverSessionChallengeBodyV1) -> Result<Vec<u8>, CustodyError> {
    let mut writer = WireWriter::new();
    writer.u16(body.schema_version);
    writer.u16(body.protocol_version);
    writer.digest(&body.receiver_key_identity_digest)?;
    writer.digest(&body.sender_session_offer_digest)?;
    writer.text(body.receiver_process_occurrence.as_str())?;
    writer.text(body.receiver_monotonic_epoch.as_str())?;
    writer.fixed_hex(&body.session_nonce_hex, 32, "session nonce")?;
    writer.text(&body.receiver_acceptance_policy_generation)?;
    writer.digest(&body.receiver_acceptance_policy_anchor_digest)?;
    writer.digest(&body.receiver_acceptance_policy_digest)?;
    writer.digest(&body.intended_sender_key_identity_digest)?;
    writer.text(body.intended_sender_process_occurrence.as_str())?;
    writer.digest(&body.accepted_sender_manifest_digest)?;
    writer.digest(&body.accepted_sender_certificate_digest)?;
    writer.u64(body.issued_at_receiver_monotonic_ms);
    writer.u64(body.expires_at_receiver_monotonic_ms);
    writer.u16(body.maximum_envelope_bytes);
    writer.u32(body.maximum_messages);
    Ok(writer.finish())
}

fn decode_challenge_body(bytes: &[u8]) -> Result<ReceiverSessionChallengeBodyV1, CustodyError> {
    let mut reader = WireReader::new(bytes);
    let body = ReceiverSessionChallengeBodyV1 {
        schema_version: reader.u16()?,
        protocol_version: reader.u16()?,
        receiver_key_identity_digest: reader.digest()?,
        sender_session_offer_digest: reader.digest()?,
        receiver_process_occurrence: IncarnationId::new(reader.text()?),
        receiver_monotonic_epoch: IncarnationId::new(reader.text()?),
        session_nonce_hex: encode_lower_hex(reader.fixed(32)?),
        receiver_acceptance_policy_generation: reader.text()?,
        receiver_acceptance_policy_anchor_digest: reader.digest()?,
        receiver_acceptance_policy_digest: reader.digest()?,
        intended_sender_key_identity_digest: reader.digest()?,
        intended_sender_process_occurrence: IncarnationId::new(reader.text()?),
        accepted_sender_manifest_digest: reader.digest()?,
        accepted_sender_certificate_digest: reader.digest()?,
        issued_at_receiver_monotonic_ms: reader.u64()?,
        expires_at_receiver_monotonic_ms: reader.u64()?,
        maximum_envelope_bytes: reader.u16()?,
        maximum_messages: reader.u32()?,
    };
    reader.finish()?;
    body.validate().map_err(CustodyError::from_type)?;
    Ok(body)
}

fn encode_binding_body(body: &SenderSessionBindingBodyV1) -> Result<Vec<u8>, CustodyError> {
    let mut writer = WireWriter::new();
    writer.u16(body.schema_version);
    writer.u16(body.protocol_version);
    writer.digest(&body.receiver_challenge_digest)?;
    writer.digest(&body.receiver_key_identity_digest)?;
    writer.digest(&body.sender_key_identity_digest)?;
    writer.text(body.sender_process_occurrence.as_str())?;
    writer.text(body.sender_monotonic_epoch.as_str())?;
    writer.digest(&body.sender_manifest_digest)?;
    writer.digest(&body.sender_qualification_certificate_digest)?;
    writer.digest(&body.sender_activation_receipt_digest)?;
    writer.digest(&body.sender_runtime_generation_set_digest)?;
    writer.text(body.observer.as_str())?;
    writer.text(&body.failure_domain_claim)?;
    writer.scopes(&body.permitted_subject_scopes)?;
    writer.u16(body.observation_protocol_version);
    writer.u64(body.session_sequence_origin);
    writer.u8(1);
    Ok(writer.finish())
}

fn decode_binding_body(bytes: &[u8]) -> Result<SenderSessionBindingBodyV1, CustodyError> {
    let mut reader = WireReader::new(bytes);
    let body = SenderSessionBindingBodyV1 {
        schema_version: reader.u16()?,
        protocol_version: reader.u16()?,
        receiver_challenge_digest: reader.digest()?,
        receiver_key_identity_digest: reader.digest()?,
        sender_key_identity_digest: reader.digest()?,
        sender_process_occurrence: IncarnationId::new(reader.text()?),
        sender_monotonic_epoch: IncarnationId::new(reader.text()?),
        sender_manifest_digest: reader.digest()?,
        sender_qualification_certificate_digest: reader.digest()?,
        sender_activation_receipt_digest: reader.digest()?,
        sender_runtime_generation_set_digest: reader.digest()?,
        observer: ObserverId::new(reader.text()?),
        failure_domain_claim: reader.text()?,
        permitted_subject_scopes: reader.scopes()?,
        observation_protocol_version: reader.u16()?,
        session_sequence_origin: reader.u64()?,
        binding_result: match reader.u8()? {
            1 => SessionBindingResultV1::QualifiedAndMatchedAssertion,
            _ => {
                return Err(CustodyError::new(
                    TransportCustodyFindingV1::TransportMalformed,
                    "unknown sender binding-result tag",
                ));
            }
        },
    };
    reader.finish()?;
    body.validate().map_err(CustodyError::from_type)?;
    Ok(body)
}

fn encode_receiver_session_acceptance_body(
    body: &ReceiverSessionAcceptanceBodyV1,
) -> Result<Vec<u8>, CustodyError> {
    let mut writer = WireWriter::new();
    writer.u16(body.schema_version);
    writer.u16(body.protocol_version);
    writer.digest(&body.receiver_challenge_digest)?;
    writer.digest(&body.sender_session_binding_digest)?;
    writer.digest(&body.receiver_key_identity_digest)?;
    writer.digest(&body.sender_key_identity_digest)?;
    writer.text(body.receiver_process_occurrence.as_str())?;
    writer.text(body.receiver_monotonic_epoch.as_str())?;
    writer.text(body.sender_process_occurrence.as_str())?;
    writer.digest(&body.receiver_acceptance_policy_digest)?;
    writer.u64(body.accepted_at_receiver_monotonic_ms);
    writer.u64(body.expires_at_receiver_monotonic_ms);
    writer.u32(body.maximum_messages);
    Ok(writer.finish())
}

fn decode_receiver_session_acceptance_body(
    bytes: &[u8],
) -> Result<ReceiverSessionAcceptanceBodyV1, CustodyError> {
    let mut reader = WireReader::new(bytes);
    let body = ReceiverSessionAcceptanceBodyV1 {
        schema_version: reader.u16()?,
        protocol_version: reader.u16()?,
        receiver_challenge_digest: reader.digest()?,
        sender_session_binding_digest: reader.digest()?,
        receiver_key_identity_digest: reader.digest()?,
        sender_key_identity_digest: reader.digest()?,
        receiver_process_occurrence: IncarnationId::new(reader.text()?),
        receiver_monotonic_epoch: IncarnationId::new(reader.text()?),
        sender_process_occurrence: IncarnationId::new(reader.text()?),
        receiver_acceptance_policy_digest: reader.digest()?,
        accepted_at_receiver_monotonic_ms: reader.u64()?,
        expires_at_receiver_monotonic_ms: reader.u64()?,
        maximum_messages: reader.u32()?,
    };
    reader.finish()?;
    body.validate().map_err(CustodyError::from_type)?;
    Ok(body)
}

fn encode_envelope_body(body: &ObservationCustodyEnvelopeBodyV1) -> Result<Vec<u8>, CustodyError> {
    let mut writer = WireWriter::new();
    writer.u16(body.schema_version);
    writer.u16(body.protocol_version);
    writer.digest(&body.receiver_challenge_digest)?;
    writer.digest(&body.session_binding_digest)?;
    writer.digest(&body.receiver_key_identity_digest)?;
    writer.digest(&body.sender_key_identity_digest)?;
    writer.text(body.sender_process_occurrence.as_str())?;
    writer.text(body.sender_monotonic_epoch.as_str())?;
    writer.digest(&body.sender_manifest_digest)?;
    writer.digest(&body.sender_qualification_certificate_digest)?;
    writer.digest(&body.sender_activation_receipt_digest)?;
    writer.text(body.observer.as_str())?;
    writer.text(&body.failure_domain_claim)?;
    writer.scope(&body.subject_scope)?;
    writer.digest(&body.observation_identity)?;
    writer.u64(body.observation_sequence);
    writer.u64(body.session_sequence);
    writer.u8(1);
    let payload = body.payload_bytes().map_err(CustodyError::from_type)?;
    writer.bytes(&payload)?;
    writer.digest(&body.payload_digest)?;
    writer.u64(body.sender_observation_monotonic_ns);
    writer.u64(body.sender_emission_monotonic_ns);
    Ok(writer.finish())
}

fn decode_envelope_body(bytes: &[u8]) -> Result<ObservationCustodyEnvelopeBodyV1, CustodyError> {
    let mut reader = WireReader::new(bytes);
    let schema_version = reader.u16()?;
    let protocol_version = reader.u16()?;
    let receiver_challenge_digest = reader.digest()?;
    let session_binding_digest = reader.digest()?;
    let receiver_key_identity_digest = reader.digest()?;
    let sender_key_identity_digest = reader.digest()?;
    let sender_process_occurrence = IncarnationId::new(reader.text()?);
    let sender_monotonic_epoch = IncarnationId::new(reader.text()?);
    let sender_manifest_digest = reader.digest()?;
    let sender_qualification_certificate_digest = reader.digest()?;
    let sender_activation_receipt_digest = reader.digest()?;
    let observer = ObserverId::new(reader.text()?);
    let failure_domain_claim = reader.text()?;
    let subject_scope = reader.scope()?;
    let observation_identity = reader.digest()?;
    let observation_sequence = reader.u64()?;
    let session_sequence = reader.u64()?;
    let observation_kind = match reader.u8()? {
        1 => ObservationCustodyKindV1::PulseV1,
        _ => {
            return Err(CustodyError::new(
                TransportCustodyFindingV1::TransportMalformed,
                "unknown observation-kind tag",
            ));
        }
    };
    let payload = reader.bytes(MAX_CUSTODY_PAYLOAD_BYTES)?;
    let payload_digest = reader.digest()?;
    let sender_observation_monotonic_ns = reader.u64()?;
    let sender_emission_monotonic_ns = reader.u64()?;
    reader.finish()?;
    let body = ObservationCustodyEnvelopeBodyV1 {
        schema_version,
        protocol_version,
        receiver_challenge_digest,
        session_binding_digest,
        receiver_key_identity_digest,
        sender_key_identity_digest,
        sender_process_occurrence,
        sender_monotonic_epoch,
        sender_manifest_digest,
        sender_qualification_certificate_digest,
        sender_activation_receipt_digest,
        observer,
        failure_domain_claim,
        subject_scope,
        observation_identity,
        observation_sequence,
        session_sequence,
        observation_kind,
        payload_hex: encode_lower_hex(&payload),
        payload_digest,
        sender_observation_monotonic_ns,
        sender_emission_monotonic_ns,
    };
    body.validate().map_err(CustodyError::from_type)?;
    Ok(body)
}

fn decode_observation_envelope_for_admission(
    datagram: &[u8],
    policy: &ReceiverAcceptancePolicyV1,
    session: &ReceiverLiveSession,
) -> Result<ObservationCustodyEnvelopeV1, CustodyError> {
    // Admission deliberately parses only the bounded canonical body before
    // authentication. No field is trusted or admitted at this point.
    let (body_bytes, signature) = decode_signed_datagram(datagram, OBSERVATION_ENVELOPE_KIND)?;
    let body = decode_envelope_body(&body_bytes)?;
    if body.receiver_challenge_digest != session.challenge.challenge_digest
        || body.session_binding_digest != session.binding.binding_digest
    {
        return Err(CustodyError::new(
            TransportCustodyFindingV1::SessionUnknown,
            "envelope does not identify the live receiver challenge/session",
        ));
    }
    if body.receiver_key_identity_digest != policy.receiver_key.identity_digest() {
        return Err(CustodyError::new(
            TransportCustodyFindingV1::ReceiverChallengeInvalid,
            "envelope names a different intended receiver key",
        ));
    }
    if body.sender_key_identity_digest != policy.accepted_sender_key.identity_digest() {
        return Err(CustodyError::new(
            TransportCustodyFindingV1::SenderKeyMismatch,
            "envelope names a sender key outside the pinned acceptance policy",
        ));
    }
    verify_signature(
        &policy.accepted_sender_key,
        CustodySignatureDomainV1::ObservationCustodyEnvelopeV1,
        &body_bytes,
        &signature,
    )?;
    let value = ObservationCustodyEnvelopeV1 {
        schema_version: SCHEMA_VERSION_V1,
        envelope_digest: signed_object_digest(
            CustodySignatureDomainV1::ObservationCustodyEnvelopeV1,
            &body_bytes,
            &signature,
        ),
        body,
        signature_domain: CustodySignatureDomainV1::ObservationCustodyEnvelopeV1,
        signer_key_identity_digest: policy.accepted_sender_key.identity_digest(),
        signature_hex: encode_lower_hex(&signature),
        authority_grants: CustodyAuthorityGrantsV1::none(),
    };
    value
        .validate_structure()
        .map_err(CustodyError::from_type)?;
    Ok(value)
}

fn verify_envelope_session_identity(
    policy: &ReceiverAcceptancePolicyV1,
    session: &ReceiverLiveSession,
    envelope: &ObservationCustodyEnvelopeV1,
) -> Result<(), CustodyError> {
    if envelope.body.receiver_challenge_digest != session.challenge.challenge_digest
        || envelope.body.session_binding_digest != session.binding.binding_digest
        || envelope.body.receiver_key_identity_digest != policy.receiver_key.identity_digest()
        || envelope.body.sender_key_identity_digest != policy.accepted_sender_key.identity_digest()
        || envelope.body.sender_process_occurrence != session.binding.body.sender_process_occurrence
        || envelope.body.sender_monotonic_epoch != session.binding.body.sender_monotonic_epoch
        || envelope.body.sender_manifest_digest != policy.accepted_sender_manifest_digest
        || envelope.body.sender_qualification_certificate_digest
            != policy.accepted_sender_certificate_digest
        || envelope.body.sender_activation_receipt_digest
            != session.binding.body.sender_activation_receipt_digest
        || envelope.body.failure_domain_claim != policy.accepted_failure_domain_claim
    {
        return Err(CustodyError::new(
            TransportCustodyFindingV1::QualifiedIdentityMismatch,
            "signed envelope does not match its exact live session/package/observer identities",
        ));
    }
    if envelope.body.observer != policy.accepted_observer {
        return Err(CustodyError::new(
            TransportCustodyFindingV1::ObserverRoleMismatch,
            "signed envelope observer differs from the exact accepted observer role",
        ));
    }
    Ok(())
}

fn verify_frame_identity(
    policy: &ReceiverAcceptancePolicyV1,
    envelope: &ObservationCustodyEnvelopeV1,
    frame: &PulseFrameV1,
) -> Result<(), CustodyError> {
    if frame.observer != envelope.body.observer {
        return Err(CustodyError::new(
            TransportCustodyFindingV1::ObserverRoleMismatch,
            "pulse payload observer differs from its signed envelope",
        ));
    }
    if frame.subject != envelope.body.subject_scope.subject
        || frame.subject_incarnation != envelope.body.subject_scope.subject_incarnation
        || frame.sequence != envelope.body.observation_sequence
        || frame.observation_digest != envelope.body.observation_identity
        || !policy
            .permitted_subject_scopes
            .contains(&envelope.body.subject_scope)
    {
        return Err(CustodyError::new(
            TransportCustodyFindingV1::SubjectScopeMismatch,
            "pulse payload identity differs from its signed envelope or accepted scope",
        ));
    }
    Ok(())
}

fn evidence_ref(frame: &PulseFrameV1) -> String {
    format!(
        "{}/{}/seq={}/{}",
        frame.observer, frame.observer_incarnation, frame.sequence, frame.observation_digest
    )
}

fn decode_envelope_digest_without_auth(bytes: &[u8]) -> Option<DigestV1> {
    let (body, signature) = decode_signed_datagram(bytes, OBSERVATION_ENVELOPE_KIND).ok()?;
    Some(signed_object_digest(
        CustodySignatureDomainV1::ObservationCustodyEnvelopeV1,
        &body,
        &signature,
    ))
}

fn replay_for_finding(finding: TransportCustodyFindingV1) -> ReplayWindowResultV1 {
    match finding {
        TransportCustodyFindingV1::DuplicateDetected => ReplayWindowResultV1::Duplicate,
        TransportCustodyFindingV1::ReplayDetected => ReplayWindowResultV1::Replay,
        _ => ReplayWindowResultV1::NotChecked,
    }
}

struct WireWriter {
    bytes: Vec<u8>,
}

impl WireWriter {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn text(&mut self, value: &str) -> Result<(), CustodyError> {
        let length = u16::try_from(value.len()).map_err(|_| {
            CustodyError::new(
                TransportCustodyFindingV1::TransportMalformed,
                "wire text length exceeds u16",
            )
        })?;
        if value.is_empty()
            || value.len() > pulse_types::MAX_CUSTODY_TEXT_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(CustodyError::new(
                TransportCustodyFindingV1::TransportMalformed,
                "wire text is empty, oversized, or contains control characters",
            ));
        }
        self.u16(length);
        self.bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }

    fn digest(&mut self, value: &DigestV1) -> Result<(), CustodyError> {
        value.validate().map_err(|error| {
            CustodyError::new(
                TransportCustodyFindingV1::TransportMalformed,
                error.to_string(),
            )
        })?;
        let raw = decode_hex_exact(value.as_str().trim_start_matches("sha256:"), 32, "digest")
            .map_err(CustodyError::from_type)?;
        self.bytes.extend_from_slice(&raw);
        Ok(())
    }

    fn fixed_hex(
        &mut self,
        value: &str,
        exact: usize,
        field: &'static str,
    ) -> Result<(), CustodyError> {
        let raw = decode_hex_exact(value, exact, field).map_err(CustodyError::from_type)?;
        self.bytes.extend_from_slice(&raw);
        Ok(())
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), CustodyError> {
        let length = u16::try_from(value.len()).map_err(|_| {
            CustodyError::new(
                TransportCustodyFindingV1::TransportMalformed,
                "wire byte string length exceeds u16",
            )
        })?;
        self.u16(length);
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn scope(&mut self, scope: &SubjectScopeV1) -> Result<(), CustodyError> {
        self.text(scope.subject.as_str())?;
        self.text(scope.subject_incarnation.as_str())?;
        self.text(&scope.scope)
    }

    fn scopes(&mut self, scopes: &[SubjectScopeV1]) -> Result<(), CustodyError> {
        let count = u8::try_from(scopes.len()).map_err(|_| {
            CustodyError::new(
                TransportCustodyFindingV1::TransportMalformed,
                "wire subject-scope count exceeds u8",
            )
        })?;
        self.u8(count);
        for scope in scopes {
            self.scope(scope)?;
        }
        Ok(())
    }
}

struct WireReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> WireReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn fixed(&mut self, count: usize) -> Result<&'a [u8], CustodyError> {
        let end = self.offset.checked_add(count).ok_or_else(|| {
            CustodyError::new(
                TransportCustodyFindingV1::TransportMalformed,
                "wire offset overflow",
            )
        })?;
        let value = self.bytes.get(self.offset..end).ok_or_else(|| {
            CustodyError::new(
                TransportCustodyFindingV1::TransportMalformed,
                "canonical datagram body is truncated",
            )
        })?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, CustodyError> {
        Ok(self.fixed(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, CustodyError> {
        let bytes: [u8; 2] = self.fixed(2)?.try_into().expect("fixed length");
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, CustodyError> {
        let bytes: [u8; 4] = self.fixed(4)?.try_into().expect("fixed length");
        Ok(u32::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, CustodyError> {
        let bytes: [u8; 8] = self.fixed(8)?.try_into().expect("fixed length");
        Ok(u64::from_be_bytes(bytes))
    }

    fn text(&mut self) -> Result<String, CustodyError> {
        let length = usize::from(self.u16()?);
        if length == 0 || length > pulse_types::MAX_CUSTODY_TEXT_BYTES {
            return Err(CustodyError::new(
                TransportCustodyFindingV1::TransportMalformed,
                "canonical wire text length is outside its bound",
            ));
        }
        let bytes = self.fixed(length)?;
        let text = std::str::from_utf8(bytes).map_err(|_| {
            CustodyError::new(
                TransportCustodyFindingV1::TransportMalformed,
                "canonical wire text is not valid UTF-8",
            )
        })?;
        if text.chars().any(char::is_control) {
            return Err(CustodyError::new(
                TransportCustodyFindingV1::TransportMalformed,
                "canonical wire text contains a control character",
            ));
        }
        Ok(text.to_owned())
    }

    fn digest(&mut self) -> Result<DigestV1, CustodyError> {
        let raw = self.fixed(32)?;
        let digest = DigestV1(format!("sha256:{}", encode_lower_hex(raw)));
        digest.validate().map_err(|error| {
            CustodyError::new(
                TransportCustodyFindingV1::TransportMalformed,
                error.to_string(),
            )
        })?;
        Ok(digest)
    }

    fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, CustodyError> {
        let length = usize::from(self.u16()?);
        if length > maximum {
            return Err(CustodyError::new(
                TransportCustodyFindingV1::TransportMalformed,
                "canonical wire byte string exceeds its bound",
            ));
        }
        Ok(self.fixed(length)?.to_vec())
    }

    fn scope(&mut self) -> Result<SubjectScopeV1, CustodyError> {
        Ok(SubjectScopeV1 {
            subject: pulse_types::SubjectId::new(self.text()?),
            subject_incarnation: IncarnationId::new(self.text()?),
            scope: self.text()?,
        })
    }

    fn scopes(&mut self) -> Result<Vec<SubjectScopeV1>, CustodyError> {
        let count = usize::from(self.u8()?);
        if count == 0 || count > pulse_types::MAX_CUSTODY_SCOPES {
            return Err(CustodyError::new(
                TransportCustodyFindingV1::TransportMalformed,
                "canonical scope count is outside its bound",
            ));
        }
        let mut scopes = Vec::with_capacity(count);
        for _ in 0..count {
            scopes.push(self.scope()?);
        }
        Ok(scopes)
    }

    fn finish(self) -> Result<(), CustodyError> {
        if self.offset != self.bytes.len() {
            return Err(CustodyError::new(
                TransportCustodyFindingV1::TransportMalformed,
                "canonical datagram body contains trailing bytes",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustodyError {
    pub finding: TransportCustodyFindingV1,
    pub detail: String,
    pub replay_window_result: Option<ReplayWindowResultV1>,
}

impl CustodyError {
    pub fn new(finding: TransportCustodyFindingV1, detail: impl Into<String>) -> Self {
        Self {
            finding,
            detail: detail.into(),
            replay_window_result: None,
        }
    }

    fn with_replay_window_result(mut self, result: ReplayWindowResultV1) -> Self {
        self.replay_window_result = Some(result);
        self
    }

    fn from_type(error: CustodyTypeError) -> Self {
        Self::new(
            TransportCustodyFindingV1::TransportMalformed,
            error.to_string(),
        )
    }

    fn from_qualification(error: pulse_types::QualificationError) -> Self {
        Self::new(
            TransportCustodyFindingV1::QualifiedIdentityMismatch,
            error.to_string(),
        )
    }

    fn io(operation: &'static str, error: &io::Error) -> Self {
        Self::new(
            TransportCustodyFindingV1::TransportUnavailable,
            format!("{operation}: {error}"),
        )
    }
}

impl fmt::Display for CustodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.finding, self.detail)
    }
}

impl std::error::Error for CustodyError {}

impl From<crate::ReactorCommandError> for CustodyError {
    fn from(error: crate::ReactorCommandError) -> Self {
        Self::new(
            TransportCustodyFindingV1::TransportUnavailable,
            error.to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_domains_do_not_interoperate() {
        let signing = CanarySigningIdentityV1::generate(
            CustodyPeerRoleV1::Sender,
            vec!["scope:test".to_owned()],
            "sender-policy:test",
        )
        .unwrap();
        let body = b"canonical-body";
        let domains = [
            CustodySignatureDomainV1::SenderSessionOfferV1,
            CustodySignatureDomainV1::ReceiverSessionChallengeV1,
            CustodySignatureDomainV1::SenderSessionBindingV1,
            CustodySignatureDomainV1::ReceiverSessionAcceptanceV1,
            CustodySignatureDomainV1::ObservationCustodyEnvelopeV1,
        ];
        for signing_domain in domains {
            let signature = encode_lower_hex(&signing.sign(signing_domain, body));
            for verification_domain in domains {
                assert_eq!(
                    verify_signature_in_domain(
                        signing.key_identity(),
                        verification_domain,
                        body,
                        &signature,
                    )
                    .is_ok(),
                    signing_domain == verification_domain,
                );
            }
        }
    }

    #[test]
    fn arbitrary_truncation_and_trailing_bytes_are_refused() {
        let signing = CanarySigningIdentityV1::generate(
            CustodyPeerRoleV1::Receiver,
            vec!["scope:test".to_owned()],
            "receiver-policy:test",
        )
        .unwrap();
        let digest = digest_parts("fixture", &[b"identity"]);
        let body = ReceiverSessionChallengeBodyV1 {
            schema_version: SCHEMA_VERSION_V1,
            protocol_version: CUSTODY_PROTOCOL_VERSION_V1,
            receiver_key_identity_digest: signing.key_identity().identity_digest(),
            sender_session_offer_digest: digest.clone(),
            receiver_process_occurrence: IncarnationId::new("receiver-process:test"),
            receiver_monotonic_epoch: IncarnationId::new("receiver-epoch:test"),
            session_nonce_hex: encode_lower_hex(&[3; 32]),
            receiver_acceptance_policy_generation: "receiver-policy:test".to_owned(),
            receiver_acceptance_policy_anchor_digest: digest.clone(),
            receiver_acceptance_policy_digest: digest.clone(),
            intended_sender_key_identity_digest: digest.clone(),
            intended_sender_process_occurrence: IncarnationId::new("sender-process:test"),
            accepted_sender_manifest_digest: digest.clone(),
            accepted_sender_certificate_digest: digest,
            issued_at_receiver_monotonic_ms: 1,
            expires_at_receiver_monotonic_ms: 101,
            maximum_envelope_bytes: 1_232,
            maximum_messages: 4,
        };
        let (_, datagram) = sign_receiver_challenge(&signing, body).unwrap();
        for split in 0..datagram.len() {
            assert!(
                decode_receiver_challenge_datagram(&datagram[..split], signing.key_identity())
                    .is_err()
            );
        }
        let mut trailing = datagram.clone();
        trailing.push(0);
        assert!(decode_receiver_challenge_datagram(&trailing, signing.key_identity()).is_err());
    }

    #[test]
    fn bounded_replay_window_never_renews_duplicate_or_reorder() {
        let first = classify_sequence(None, 0, 10, 8, 4).unwrap();
        let next = classify_sequence(Some(first.new_high), first.new_bitmap, 11, 8, 4).unwrap();
        let duplicate = classify_sequence(Some(next.new_high), next.new_bitmap, 11, 8, 4).unwrap();
        let reordered = classify_sequence(Some(next.new_high), next.new_bitmap, 9, 8, 4).unwrap();
        assert_eq!(duplicate.result, ReplayWindowResultV1::Duplicate);
        assert_eq!(reordered.result, ReplayWindowResultV1::Reordered);
        assert_eq!(duplicate.new_high, 11);
        assert_eq!(reordered.new_high, 11);
    }
}
