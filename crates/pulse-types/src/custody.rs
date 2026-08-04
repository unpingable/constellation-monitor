use std::fmt;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::{
    AuthorityGrantV1, DigestV1, IncarnationId, MutationAuthorityV1, ObserverId, SCHEMA_VERSION_V1,
    SubjectScopeV1, artifact_content_digest, digest_parts,
};

pub const CUSTODY_PROTOCOL_VERSION_V1: u16 = 1;
pub const MAX_CANARY_DATAGRAM_BYTES: usize = 1_232;
pub const MAX_CUSTODY_PAYLOAD_BYTES: usize = 640;
pub const MAX_CUSTODY_TEXT_BYTES: usize = 256;
pub const MAX_CUSTODY_SCOPES: usize = 8;
pub const MAX_CUSTODY_QUEUE_DEPTH: usize = 64;
pub const MAX_CUSTODY_REPLAY_WINDOW: u16 = 64;
pub const MAX_CUSTODY_RECEIPTS: usize = 256;

pub const RECEIVER_CHALLENGE_SIGNATURE_DOMAIN_V1: &str = "monitor.receiver-session-challenge.v1";
pub const SENDER_SESSION_OFFER_SIGNATURE_DOMAIN_V1: &str = "monitor.sender-session-offer.v1";
pub const SENDER_BINDING_SIGNATURE_DOMAIN_V1: &str = "monitor.sender-session-binding.v1";
pub const RECEIVER_SESSION_ACCEPTANCE_SIGNATURE_DOMAIN_V1: &str =
    "monitor.receiver-session-acceptance.v1";
pub const OBSERVATION_ENVELOPE_SIGNATURE_DOMAIN_V1: &str =
    "monitor.observation-custody-envelope.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyPeerRoleV1 {
    Sender,
    Receiver,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyKeyAlgorithmV1 {
    Ed25519,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodySignatureDomainV1 {
    SenderSessionOfferV1,
    ReceiverSessionChallengeV1,
    SenderSessionBindingV1,
    ReceiverSessionAcceptanceV1,
    ObservationCustodyEnvelopeV1,
}

impl CustodySignatureDomainV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SenderSessionOfferV1 => SENDER_SESSION_OFFER_SIGNATURE_DOMAIN_V1,
            Self::ReceiverSessionChallengeV1 => RECEIVER_CHALLENGE_SIGNATURE_DOMAIN_V1,
            Self::SenderSessionBindingV1 => SENDER_BINDING_SIGNATURE_DOMAIN_V1,
            Self::ReceiverSessionAcceptanceV1 => RECEIVER_SESSION_ACCEPTANCE_SIGNATURE_DOMAIN_V1,
            Self::ObservationCustodyEnvelopeV1 => OBSERVATION_ENVELOPE_SIGNATURE_DOMAIN_V1,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationCustodyKindV1 {
    PulseV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteFreshnessModeV1 {
    ArrivalAnchored,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyCertificateStatusV1 {
    Accepted,
    Superseded,
    Revoked,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionBindingResultV1 {
    QualifiedAndMatchedAssertion,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyCheckResultV1 {
    NotChecked,
    Accepted,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayWindowResultV1 {
    NotChecked,
    First,
    Continuous,
    Gap,
    Duplicate,
    Replay,
    Reordered,
    BoundExceeded,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportCustodyFindingV1 {
    TransportUnavailable,
    TransportOverloaded,
    TransportMalformed,
    AuthenticationFailed,
    SenderKeyMismatch,
    ReceiverChallengeInvalid,
    SessionExpired,
    SessionUnknown,
    SessionConflict,
    SenderOccurrenceConflict,
    SignatureInvalid,
    QualifiedIdentityMismatch,
    CertificateSuperseded,
    CertificateRevoked,
    ReplayDetected,
    DuplicateDetected,
    SequenceGap,
    ObservationRejected,
    PayloadMalformed,
    SubjectScopeMismatch,
    ObserverRoleMismatch,
    ReceiverBlind,
    EvidenceAdmitted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyAuthorityGrantsV1 {
    pub continuation: AuthorityGrantV1,
    pub transport_administration: AuthorityGrantV1,
    pub diagnostic_execution: AuthorityGrantV1,
    pub deployment: AuthorityGrantV1,
    pub signing: AuthorityGrantV1,
    pub revocation: AuthorityGrantV1,
    pub mutation: AuthorityGrantV1,
}

impl CustodyAuthorityGrantsV1 {
    #[must_use]
    pub const fn none() -> Self {
        Self {
            continuation: AuthorityGrantV1::None,
            transport_administration: AuthorityGrantV1::None,
            diagnostic_execution: AuthorityGrantV1::None,
            deployment: AuthorityGrantV1::None,
            signing: AuthorityGrantV1::None,
            revocation: AuthorityGrantV1::None,
            mutation: AuthorityGrantV1::None,
        }
    }

    #[must_use]
    pub const fn grants_nothing(self) -> bool {
        matches!(self.continuation, AuthorityGrantV1::None)
            && matches!(self.transport_administration, AuthorityGrantV1::None)
            && matches!(self.diagnostic_execution, AuthorityGrantV1::None)
            && matches!(self.deployment, AuthorityGrantV1::None)
            && matches!(self.signing, AuthorityGrantV1::None)
            && matches!(self.revocation, AuthorityGrantV1::None)
            && matches!(self.mutation, AuthorityGrantV1::None)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransportCustodyPolicyBindingV1 {
    pub schema_version: u16,
    pub role: CustodyPeerRoleV1,
    pub policy_generation: String,
    pub policy_digest: DigestV1,
}

impl TransportCustodyPolicyBindingV1 {
    pub fn validate(&self) -> Result<(), CustodyTypeError> {
        validate_schema(self.schema_version)?;
        validate_text("transport policy generation", &self.policy_generation)?;
        self.policy_digest
            .validate()
            .map_err(|error| CustodyTypeError::new("invalid_digest", error.to_string()))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PeerKeyIdentityV1 {
    pub schema_version: u16,
    pub protocol_version: u16,
    pub algorithm: CustodyKeyAlgorithmV1,
    pub role: CustodyPeerRoleV1,
    pub intended_peer_role: CustodyPeerRoleV1,
    pub public_key_hex: String,
    pub public_key_digest: DigestV1,
    pub accepted_scopes: Vec<String>,
    pub local_acceptance_policy_id: String,
}

impl PeerKeyIdentityV1 {
    pub fn validate(&self) -> Result<(), CustodyTypeError> {
        validate_schema(self.schema_version)?;
        if self.protocol_version != CUSTODY_PROTOCOL_VERSION_V1 {
            return Err(CustodyTypeError::new(
                "unsupported_protocol",
                "peer key protocol version is unsupported",
            ));
        }
        if self.role == self.intended_peer_role {
            return Err(CustodyTypeError::new(
                "invalid_peer_role",
                "peer key role and intended peer role must differ",
            ));
        }
        let public_key = decode_hex_exact(&self.public_key_hex, 32, "public key")?;
        let expected = digest_parts("transport.ed25519.public-key.v1", &[&public_key]);
        if self.public_key_digest != expected {
            return Err(CustodyTypeError::new(
                "key_identity_mismatch",
                "public key digest does not identify the exact public key bytes",
            ));
        }
        validate_sorted_texts("accepted scopes", &self.accepted_scopes, MAX_CUSTODY_SCOPES)?;
        validate_text(
            "local acceptance policy identity",
            &self.local_acceptance_policy_id,
        )
    }

    #[must_use]
    pub fn identity_digest(&self) -> DigestV1 {
        let bytes = serde_json::to_vec(self).expect("validated schema serializes");
        digest_parts("transport.peer-key-identity.v1", &[&bytes])
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CustodyTypeError> {
        self.validate()?;
        canonical_encode(self)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, CustodyTypeError> {
        canonical_decode(bytes, "peer key identity")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverAcceptancePolicyV1 {
    pub schema_version: u16,
    pub policy_generation: String,
    pub receiver_key: PeerKeyIdentityV1,
    pub accepted_sender_key: PeerKeyIdentityV1,
    pub accepted_sender_manifest_digest: DigestV1,
    pub accepted_sender_certificate_digest: DigestV1,
    pub accepted_protocol_version: u16,
    pub accepted_pulse_schema_version: u16,
    pub accepted_observer: ObserverId,
    pub accepted_failure_domain_claim: String,
    pub permitted_subject_scopes: Vec<SubjectScopeV1>,
    pub permitted_observation_kinds: Vec<ObservationCustodyKindV1>,
    pub maximum_datagram_bytes: u16,
    pub maximum_session_duration_ms: u64,
    pub maximum_messages_per_session: u32,
    pub maximum_messages_per_second: u32,
    pub receiver_queue_bound: u16,
    pub replay_window_size: u16,
    pub maximum_sequence_gap: u64,
    pub certificate_status: CustodyCertificateStatusV1,
    pub lifecycle_authority_id: String,
    pub freshness_mode: RemoteFreshnessModeV1,
    pub arrival_anchored_evidence_may_support_reliance: bool,
    pub observation_time_freshness_required: bool,
    pub journal_id: String,
    pub authority_grants: CustodyAuthorityGrantsV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverAcceptancePolicyAnchorV1 {
    pub schema_version: u16,
    pub policy_generation: String,
    pub receiver_key: PeerKeyIdentityV1,
    pub accepted_sender_key: PeerKeyIdentityV1,
    pub accepted_protocol_version: u16,
    pub accepted_pulse_schema_version: u16,
    pub accepted_observer: ObserverId,
    pub accepted_failure_domain_claim: String,
    pub permitted_subject_scopes: Vec<SubjectScopeV1>,
    pub permitted_observation_kinds: Vec<ObservationCustodyKindV1>,
    pub maximum_datagram_bytes: u16,
    pub maximum_session_duration_ms: u64,
    pub maximum_messages_per_session: u32,
    pub maximum_messages_per_second: u32,
    pub receiver_queue_bound: u16,
    pub replay_window_size: u16,
    pub maximum_sequence_gap: u64,
    pub certificate_status: CustodyCertificateStatusV1,
    pub lifecycle_authority_id: String,
    pub freshness_mode: RemoteFreshnessModeV1,
    pub arrival_anchored_evidence_may_support_reliance: bool,
    pub observation_time_freshness_required: bool,
    pub journal_id: String,
    pub authority_grants: CustodyAuthorityGrantsV1,
}

impl ReceiverAcceptancePolicyV1 {
    pub fn validate(&self) -> Result<(), CustodyTypeError> {
        validate_schema(self.schema_version)?;
        validate_text("receiver policy generation", &self.policy_generation)?;
        self.receiver_key.validate()?;
        self.accepted_sender_key.validate()?;
        if self.receiver_key.role != CustodyPeerRoleV1::Receiver
            || self.accepted_sender_key.role != CustodyPeerRoleV1::Sender
        {
            return Err(CustodyTypeError::new(
                "invalid_peer_role",
                "receiver policy key roles are invalid",
            ));
        }
        validate_digest(&self.accepted_sender_manifest_digest)?;
        validate_digest(&self.accepted_sender_certificate_digest)?;
        if self.accepted_protocol_version != CUSTODY_PROTOCOL_VERSION_V1
            || self.accepted_pulse_schema_version != SCHEMA_VERSION_V1
        {
            return Err(CustodyTypeError::new(
                "unsupported_protocol",
                "receiver policy protocol or pulse schema is unsupported",
            ));
        }
        self.accepted_observer
            .validate()
            .map_err(|error| CustodyTypeError::new("invalid_identity", error.to_string()))?;
        validate_text(
            "accepted failure-domain claim",
            &self.accepted_failure_domain_claim,
        )?;
        validate_scopes(&self.permitted_subject_scopes)?;
        if self.permitted_observation_kinds != [ObservationCustodyKindV1::PulseV1] {
            return Err(CustodyTypeError::new(
                "unsupported_observation_kind",
                "v1 receiver policy must admit only pulse_v1",
            ));
        }
        validate_transport_bounds(
            self.maximum_datagram_bytes,
            self.maximum_session_duration_ms,
            self.maximum_messages_per_session,
            self.maximum_messages_per_second,
            self.receiver_queue_bound,
            self.replay_window_size,
        )?;
        if self.maximum_sequence_gap == 0 {
            return Err(CustodyTypeError::new(
                "invalid_bound",
                "maximum sequence gap must be nonzero",
            ));
        }
        validate_text("lifecycle authority", &self.lifecycle_authority_id)?;
        validate_text("custody journal identity", &self.journal_id)?;
        if !self.authority_grants.grants_nothing() {
            return Err(CustodyTypeError::new(
                "authority_laundering",
                "receiver policy cannot grant operational authority",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn identity_digest(&self) -> DigestV1 {
        let anchor = self.anchor_digest();
        Self::identity_digest_from_parts(
            &anchor,
            &self.accepted_sender_manifest_digest,
            &self.accepted_sender_certificate_digest,
        )
    }

    /// Compute the exact policy identity from the cycle-free receiver-policy
    /// anchor and the exact sender package admitted by that policy.
    #[must_use]
    pub fn identity_digest_from_parts(
        anchor: &DigestV1,
        sender_manifest: &DigestV1,
        sender_certificate: &DigestV1,
    ) -> DigestV1 {
        digest_parts(
            "transport.receiver-acceptance-policy.v1",
            &[
                anchor.as_str().as_bytes(),
                sender_manifest.as_str().as_bytes(),
                sender_certificate.as_str().as_bytes(),
            ],
        )
    }

    #[must_use]
    pub fn anchor_digest(&self) -> DigestV1 {
        let anchor = ReceiverAcceptancePolicyAnchorV1 {
            schema_version: self.schema_version,
            policy_generation: self.policy_generation.clone(),
            receiver_key: self.receiver_key.clone(),
            accepted_sender_key: self.accepted_sender_key.clone(),
            accepted_protocol_version: self.accepted_protocol_version,
            accepted_pulse_schema_version: self.accepted_pulse_schema_version,
            accepted_observer: self.accepted_observer.clone(),
            accepted_failure_domain_claim: self.accepted_failure_domain_claim.clone(),
            permitted_subject_scopes: self.permitted_subject_scopes.clone(),
            permitted_observation_kinds: self.permitted_observation_kinds.clone(),
            maximum_datagram_bytes: self.maximum_datagram_bytes,
            maximum_session_duration_ms: self.maximum_session_duration_ms,
            maximum_messages_per_session: self.maximum_messages_per_session,
            maximum_messages_per_second: self.maximum_messages_per_second,
            receiver_queue_bound: self.receiver_queue_bound,
            replay_window_size: self.replay_window_size,
            maximum_sequence_gap: self.maximum_sequence_gap,
            certificate_status: self.certificate_status,
            lifecycle_authority_id: self.lifecycle_authority_id.clone(),
            freshness_mode: self.freshness_mode,
            arrival_anchored_evidence_may_support_reliance: self
                .arrival_anchored_evidence_may_support_reliance,
            observation_time_freshness_required: self.observation_time_freshness_required,
            journal_id: self.journal_id.clone(),
            authority_grants: self.authority_grants,
        };
        let bytes = serde_json::to_vec(&anchor).expect("receiver policy anchor serializes");
        digest_parts("transport.receiver-acceptance-policy-anchor.v1", &[&bytes])
    }

    #[must_use]
    pub fn binding(&self) -> TransportCustodyPolicyBindingV1 {
        TransportCustodyPolicyBindingV1 {
            schema_version: SCHEMA_VERSION_V1,
            role: CustodyPeerRoleV1::Receiver,
            policy_generation: self.policy_generation.clone(),
            policy_digest: self.identity_digest(),
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CustodyTypeError> {
        self.validate()?;
        canonical_encode(self)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, CustodyTypeError> {
        canonical_decode(bytes, "receiver acceptance policy")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SenderEmissionPolicyV1 {
    pub schema_version: u16,
    pub policy_generation: String,
    pub sender_key: PeerKeyIdentityV1,
    pub accepted_receiver_key: PeerKeyIdentityV1,
    pub accepted_receiver_policy_generation: String,
    pub accepted_receiver_policy_anchor_digest: DigestV1,
    pub observer: ObserverId,
    pub failure_domain_claim: String,
    pub permitted_subject_scopes: Vec<SubjectScopeV1>,
    pub permitted_observation_kinds: Vec<ObservationCustodyKindV1>,
    pub maximum_datagram_bytes: u16,
    pub sender_queue_bound: u16,
    pub authority_grants: CustodyAuthorityGrantsV1,
}

impl SenderEmissionPolicyV1 {
    pub fn validate(&self) -> Result<(), CustodyTypeError> {
        validate_schema(self.schema_version)?;
        validate_text("sender policy generation", &self.policy_generation)?;
        self.sender_key.validate()?;
        self.accepted_receiver_key.validate()?;
        if self.sender_key.role != CustodyPeerRoleV1::Sender
            || self.accepted_receiver_key.role != CustodyPeerRoleV1::Receiver
        {
            return Err(CustodyTypeError::new(
                "invalid_peer_role",
                "sender policy key roles are invalid",
            ));
        }
        validate_text(
            "accepted receiver policy generation",
            &self.accepted_receiver_policy_generation,
        )?;
        validate_digest(&self.accepted_receiver_policy_anchor_digest)?;
        self.observer
            .validate()
            .map_err(|error| CustodyTypeError::new("invalid_identity", error.to_string()))?;
        validate_text("failure-domain claim", &self.failure_domain_claim)?;
        validate_scopes(&self.permitted_subject_scopes)?;
        if self.permitted_observation_kinds != [ObservationCustodyKindV1::PulseV1]
            || self.maximum_datagram_bytes == 0
            || usize::from(self.maximum_datagram_bytes) > MAX_CANARY_DATAGRAM_BYTES
            || self.sender_queue_bound == 0
            || usize::from(self.sender_queue_bound) > MAX_CUSTODY_QUEUE_DEPTH
        {
            return Err(CustodyTypeError::new(
                "invalid_bound",
                "sender policy kind or bound is unsupported",
            ));
        }
        if !self.authority_grants.grants_nothing() {
            return Err(CustodyTypeError::new(
                "authority_laundering",
                "sender policy cannot grant operational authority",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn identity_digest(&self) -> DigestV1 {
        let bytes = serde_json::to_vec(self).expect("validated schema serializes");
        digest_parts("transport.sender-emission-policy.v1", &[&bytes])
    }

    #[must_use]
    pub fn binding(&self) -> TransportCustodyPolicyBindingV1 {
        TransportCustodyPolicyBindingV1 {
            schema_version: SCHEMA_VERSION_V1,
            role: CustodyPeerRoleV1::Sender,
            policy_generation: self.policy_generation.clone(),
            policy_digest: self.identity_digest(),
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CustodyTypeError> {
        self.validate()?;
        canonical_encode(self)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, CustodyTypeError> {
        canonical_decode(bytes, "sender emission policy")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SenderSessionOfferBodyV1 {
    pub schema_version: u16,
    pub protocol_version: u16,
    pub receiver_key_identity_digest: DigestV1,
    pub sender_key_identity_digest: DigestV1,
    pub sender_process_occurrence: IncarnationId,
    pub sender_monotonic_epoch: IncarnationId,
    pub sender_nonce_hex: String,
    pub sender_manifest_digest: DigestV1,
    pub sender_qualification_certificate_digest: DigestV1,
    pub sender_activation_receipt_digest: DigestV1,
    pub sender_runtime_generation_set_digest: DigestV1,
    pub observer: ObserverId,
    pub failure_domain_claim: String,
    pub permitted_subject_scopes: Vec<SubjectScopeV1>,
}

impl SenderSessionOfferBodyV1 {
    pub fn validate(&self) -> Result<(), CustodyTypeError> {
        validate_schema(self.schema_version)?;
        validate_protocol(self.protocol_version)?;
        for digest in [
            &self.receiver_key_identity_digest,
            &self.sender_key_identity_digest,
            &self.sender_manifest_digest,
            &self.sender_qualification_certificate_digest,
            &self.sender_activation_receipt_digest,
            &self.sender_runtime_generation_set_digest,
        ] {
            validate_digest(digest)?;
        }
        self.sender_process_occurrence
            .validate()
            .map_err(|error| CustodyTypeError::new("invalid_identity", error.to_string()))?;
        self.sender_monotonic_epoch
            .validate()
            .map_err(|error| CustodyTypeError::new("invalid_identity", error.to_string()))?;
        decode_hex_exact(&self.sender_nonce_hex, 32, "sender offer nonce")?;
        self.observer
            .validate()
            .map_err(|error| CustodyTypeError::new("invalid_identity", error.to_string()))?;
        validate_text("failure-domain claim", &self.failure_domain_claim)?;
        validate_scopes(&self.permitted_subject_scopes)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SenderSessionOfferV1 {
    pub schema_version: u16,
    pub offer_digest: DigestV1,
    pub body: SenderSessionOfferBodyV1,
    pub signature_domain: CustodySignatureDomainV1,
    pub signer_key_identity_digest: DigestV1,
    pub signature_hex: String,
    pub authority_grants: CustodyAuthorityGrantsV1,
}

impl SenderSessionOfferV1 {
    pub fn validate_structure(&self) -> Result<(), CustodyTypeError> {
        validate_schema(self.schema_version)?;
        self.body.validate()?;
        validate_digest(&self.offer_digest)?;
        validate_digest(&self.signer_key_identity_digest)?;
        decode_hex_exact(&self.signature_hex, 64, "sender-offer signature")?;
        if self.signature_domain != CustodySignatureDomainV1::SenderSessionOfferV1
            || self.signer_key_identity_digest != self.body.sender_key_identity_digest
            || !self.authority_grants.grants_nothing()
        {
            return Err(CustodyTypeError::new(
                "invalid_sender_offer",
                "sender offer domain, signer, or authority posture is invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverSessionChallengeBodyV1 {
    pub schema_version: u16,
    pub protocol_version: u16,
    pub receiver_key_identity_digest: DigestV1,
    pub sender_session_offer_digest: DigestV1,
    pub receiver_process_occurrence: IncarnationId,
    pub receiver_monotonic_epoch: IncarnationId,
    pub session_nonce_hex: String,
    pub receiver_acceptance_policy_generation: String,
    pub receiver_acceptance_policy_anchor_digest: DigestV1,
    pub receiver_acceptance_policy_digest: DigestV1,
    pub intended_sender_key_identity_digest: DigestV1,
    pub intended_sender_process_occurrence: IncarnationId,
    pub accepted_sender_manifest_digest: DigestV1,
    pub accepted_sender_certificate_digest: DigestV1,
    pub issued_at_receiver_monotonic_ms: u64,
    pub expires_at_receiver_monotonic_ms: u64,
    pub maximum_envelope_bytes: u16,
    pub maximum_messages: u32,
}

impl ReceiverSessionChallengeBodyV1 {
    pub fn validate(&self) -> Result<(), CustodyTypeError> {
        validate_schema(self.schema_version)?;
        validate_protocol(self.protocol_version)?;
        for digest in [
            &self.receiver_key_identity_digest,
            &self.sender_session_offer_digest,
            &self.receiver_acceptance_policy_anchor_digest,
            &self.receiver_acceptance_policy_digest,
            &self.intended_sender_key_identity_digest,
            &self.accepted_sender_manifest_digest,
            &self.accepted_sender_certificate_digest,
        ] {
            validate_digest(digest)?;
        }
        self.receiver_process_occurrence
            .validate()
            .map_err(|error| CustodyTypeError::new("invalid_identity", error.to_string()))?;
        self.receiver_monotonic_epoch
            .validate()
            .map_err(|error| CustodyTypeError::new("invalid_identity", error.to_string()))?;
        self.intended_sender_process_occurrence
            .validate()
            .map_err(|error| CustodyTypeError::new("invalid_identity", error.to_string()))?;
        decode_hex_exact(&self.session_nonce_hex, 32, "session nonce")?;
        validate_text(
            "receiver acceptance policy generation",
            &self.receiver_acceptance_policy_generation,
        )?;
        if self.expires_at_receiver_monotonic_ms <= self.issued_at_receiver_monotonic_ms
            || self.maximum_envelope_bytes == 0
            || usize::from(self.maximum_envelope_bytes) > MAX_CANARY_DATAGRAM_BYTES
            || self.maximum_messages == 0
        {
            return Err(CustodyTypeError::new(
                "invalid_challenge_bound",
                "receiver challenge expiry or message bound is invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverSessionChallengeV1 {
    pub schema_version: u16,
    pub challenge_digest: DigestV1,
    pub body: ReceiverSessionChallengeBodyV1,
    pub signature_domain: CustodySignatureDomainV1,
    pub signer_key_identity_digest: DigestV1,
    pub signature_hex: String,
    pub authority_grants: CustodyAuthorityGrantsV1,
}

impl ReceiverSessionChallengeV1 {
    pub fn validate_structure(&self) -> Result<(), CustodyTypeError> {
        validate_schema(self.schema_version)?;
        self.body.validate()?;
        validate_digest(&self.challenge_digest)?;
        validate_digest(&self.signer_key_identity_digest)?;
        decode_hex_exact(&self.signature_hex, 64, "challenge signature")?;
        if self.signature_domain != CustodySignatureDomainV1::ReceiverSessionChallengeV1
            || self.signer_key_identity_digest != self.body.receiver_key_identity_digest
            || !self.authority_grants.grants_nothing()
        {
            return Err(CustodyTypeError::new(
                "invalid_challenge",
                "challenge domain, signer, or authority posture is invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SenderSessionBindingBodyV1 {
    pub schema_version: u16,
    pub protocol_version: u16,
    pub receiver_challenge_digest: DigestV1,
    pub receiver_key_identity_digest: DigestV1,
    pub sender_key_identity_digest: DigestV1,
    pub sender_process_occurrence: IncarnationId,
    pub sender_monotonic_epoch: IncarnationId,
    pub sender_manifest_digest: DigestV1,
    pub sender_qualification_certificate_digest: DigestV1,
    pub sender_activation_receipt_digest: DigestV1,
    pub sender_runtime_generation_set_digest: DigestV1,
    pub observer: ObserverId,
    pub failure_domain_claim: String,
    pub permitted_subject_scopes: Vec<SubjectScopeV1>,
    pub observation_protocol_version: u16,
    pub session_sequence_origin: u64,
    pub binding_result: SessionBindingResultV1,
}

impl SenderSessionBindingBodyV1 {
    pub fn validate(&self) -> Result<(), CustodyTypeError> {
        validate_schema(self.schema_version)?;
        validate_protocol(self.protocol_version)?;
        for digest in [
            &self.receiver_challenge_digest,
            &self.receiver_key_identity_digest,
            &self.sender_key_identity_digest,
            &self.sender_manifest_digest,
            &self.sender_qualification_certificate_digest,
            &self.sender_activation_receipt_digest,
            &self.sender_runtime_generation_set_digest,
        ] {
            validate_digest(digest)?;
        }
        self.sender_process_occurrence
            .validate()
            .map_err(|error| CustodyTypeError::new("invalid_identity", error.to_string()))?;
        self.sender_monotonic_epoch
            .validate()
            .map_err(|error| CustodyTypeError::new("invalid_identity", error.to_string()))?;
        self.observer
            .validate()
            .map_err(|error| CustodyTypeError::new("invalid_identity", error.to_string()))?;
        validate_text("failure-domain claim", &self.failure_domain_claim)?;
        validate_scopes(&self.permitted_subject_scopes)?;
        validate_protocol(self.observation_protocol_version)?;
        if self.session_sequence_origin == 0 {
            return Err(CustodyTypeError::new(
                "invalid_sequence",
                "session sequence origin must be nonzero",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SenderSessionBindingV1 {
    pub schema_version: u16,
    pub binding_digest: DigestV1,
    pub body: SenderSessionBindingBodyV1,
    pub signature_domain: CustodySignatureDomainV1,
    pub signer_key_identity_digest: DigestV1,
    pub signature_hex: String,
    pub authority_grants: CustodyAuthorityGrantsV1,
}

impl SenderSessionBindingV1 {
    pub fn validate_structure(&self) -> Result<(), CustodyTypeError> {
        validate_schema(self.schema_version)?;
        self.body.validate()?;
        validate_digest(&self.binding_digest)?;
        validate_digest(&self.signer_key_identity_digest)?;
        decode_hex_exact(&self.signature_hex, 64, "session-binding signature")?;
        if self.signature_domain != CustodySignatureDomainV1::SenderSessionBindingV1
            || self.signer_key_identity_digest != self.body.sender_key_identity_digest
            || !self.authority_grants.grants_nothing()
        {
            return Err(CustodyTypeError::new(
                "invalid_session_binding",
                "session binding domain, signer, or authority posture is invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverSessionAcceptanceBodyV1 {
    pub schema_version: u16,
    pub protocol_version: u16,
    pub receiver_challenge_digest: DigestV1,
    pub sender_session_binding_digest: DigestV1,
    pub receiver_key_identity_digest: DigestV1,
    pub sender_key_identity_digest: DigestV1,
    pub receiver_process_occurrence: IncarnationId,
    pub receiver_monotonic_epoch: IncarnationId,
    pub sender_process_occurrence: IncarnationId,
    pub receiver_acceptance_policy_digest: DigestV1,
    pub accepted_at_receiver_monotonic_ms: u64,
    pub expires_at_receiver_monotonic_ms: u64,
    pub maximum_messages: u32,
}

impl ReceiverSessionAcceptanceBodyV1 {
    pub fn validate(&self) -> Result<(), CustodyTypeError> {
        validate_schema(self.schema_version)?;
        validate_protocol(self.protocol_version)?;
        for digest in [
            &self.receiver_challenge_digest,
            &self.sender_session_binding_digest,
            &self.receiver_key_identity_digest,
            &self.sender_key_identity_digest,
            &self.receiver_acceptance_policy_digest,
        ] {
            validate_digest(digest)?;
        }
        for occurrence in [
            &self.receiver_process_occurrence,
            &self.receiver_monotonic_epoch,
            &self.sender_process_occurrence,
        ] {
            occurrence
                .validate()
                .map_err(|error| CustodyTypeError::new("invalid_identity", error.to_string()))?;
        }
        if self.accepted_at_receiver_monotonic_ms >= self.expires_at_receiver_monotonic_ms
            || self.maximum_messages == 0
        {
            return Err(CustodyTypeError::new(
                "invalid_session_acceptance",
                "receiver session acceptance is expired or has an empty message bound",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverSessionAcceptanceV1 {
    pub schema_version: u16,
    pub acceptance_digest: DigestV1,
    pub body: ReceiverSessionAcceptanceBodyV1,
    pub signature_domain: CustodySignatureDomainV1,
    pub signer_key_identity_digest: DigestV1,
    pub signature_hex: String,
    pub authority_grants: CustodyAuthorityGrantsV1,
}

impl ReceiverSessionAcceptanceV1 {
    pub fn validate_structure(&self) -> Result<(), CustodyTypeError> {
        validate_schema(self.schema_version)?;
        self.body.validate()?;
        validate_digest(&self.acceptance_digest)?;
        validate_digest(&self.signer_key_identity_digest)?;
        decode_hex_exact(&self.signature_hex, 64, "session-acceptance signature")?;
        if self.signature_domain != CustodySignatureDomainV1::ReceiverSessionAcceptanceV1
            || self.signer_key_identity_digest != self.body.receiver_key_identity_digest
            || !self.authority_grants.grants_nothing()
        {
            return Err(CustodyTypeError::new(
                "invalid_session_acceptance",
                "session acceptance domain, signer, or authority posture is invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationCustodyEnvelopeBodyV1 {
    pub schema_version: u16,
    pub protocol_version: u16,
    pub receiver_challenge_digest: DigestV1,
    pub session_binding_digest: DigestV1,
    pub receiver_key_identity_digest: DigestV1,
    pub sender_key_identity_digest: DigestV1,
    pub sender_process_occurrence: IncarnationId,
    pub sender_monotonic_epoch: IncarnationId,
    pub sender_manifest_digest: DigestV1,
    pub sender_qualification_certificate_digest: DigestV1,
    pub sender_activation_receipt_digest: DigestV1,
    pub observer: ObserverId,
    pub failure_domain_claim: String,
    pub subject_scope: SubjectScopeV1,
    pub observation_identity: DigestV1,
    pub observation_sequence: u64,
    pub session_sequence: u64,
    pub observation_kind: ObservationCustodyKindV1,
    pub payload_hex: String,
    pub payload_digest: DigestV1,
    pub sender_observation_monotonic_ns: u64,
    pub sender_emission_monotonic_ns: u64,
}

impl ObservationCustodyEnvelopeBodyV1 {
    pub fn validate(&self) -> Result<(), CustodyTypeError> {
        validate_schema(self.schema_version)?;
        validate_protocol(self.protocol_version)?;
        for digest in [
            &self.receiver_challenge_digest,
            &self.session_binding_digest,
            &self.receiver_key_identity_digest,
            &self.sender_key_identity_digest,
            &self.sender_manifest_digest,
            &self.sender_qualification_certificate_digest,
            &self.sender_activation_receipt_digest,
            &self.observation_identity,
            &self.payload_digest,
        ] {
            validate_digest(digest)?;
        }
        self.sender_process_occurrence
            .validate()
            .map_err(|error| CustodyTypeError::new("invalid_identity", error.to_string()))?;
        self.sender_monotonic_epoch
            .validate()
            .map_err(|error| CustodyTypeError::new("invalid_identity", error.to_string()))?;
        self.observer
            .validate()
            .map_err(|error| CustodyTypeError::new("invalid_identity", error.to_string()))?;
        validate_text("failure-domain claim", &self.failure_domain_claim)?;
        self.subject_scope
            .validate()
            .map_err(|error| CustodyTypeError::new("invalid_identity", error.to_string()))?;
        if self.observation_sequence == 0 || self.session_sequence == 0 {
            return Err(CustodyTypeError::new(
                "invalid_sequence",
                "observation and session sequences must be nonzero",
            ));
        }
        let payload = decode_hex_bounded(
            &self.payload_hex,
            MAX_CUSTODY_PAYLOAD_BYTES,
            "observation payload",
        )?;
        if self.payload_digest != digest_parts("transport.observation-payload.v1", &[&payload]) {
            return Err(CustodyTypeError::new(
                "payload_digest_mismatch",
                "payload digest does not identify the exact payload bytes",
            ));
        }
        Ok(())
    }

    pub fn payload_bytes(&self) -> Result<Vec<u8>, CustodyTypeError> {
        decode_hex_bounded(
            &self.payload_hex,
            MAX_CUSTODY_PAYLOAD_BYTES,
            "observation payload",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationCustodyEnvelopeV1 {
    pub schema_version: u16,
    pub envelope_digest: DigestV1,
    pub body: ObservationCustodyEnvelopeBodyV1,
    pub signature_domain: CustodySignatureDomainV1,
    pub signer_key_identity_digest: DigestV1,
    pub signature_hex: String,
    pub authority_grants: CustodyAuthorityGrantsV1,
}

impl ObservationCustodyEnvelopeV1 {
    pub fn validate_structure(&self) -> Result<(), CustodyTypeError> {
        validate_schema(self.schema_version)?;
        self.body.validate()?;
        validate_digest(&self.envelope_digest)?;
        validate_digest(&self.signer_key_identity_digest)?;
        decode_hex_exact(&self.signature_hex, 64, "observation-envelope signature")?;
        if self.signature_domain != CustodySignatureDomainV1::ObservationCustodyEnvelopeV1
            || self.signer_key_identity_digest != self.body.sender_key_identity_digest
            || !self.authority_grants.grants_nothing()
        {
            return Err(CustodyTypeError::new(
                "invalid_observation_envelope",
                "envelope domain, signer, or authority posture is invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustodySequenceGapV1 {
    pub expected_next: u64,
    pub received: u64,
    pub missing_count: u64,
}

impl CustodySequenceGapV1 {
    pub fn validate(&self) -> Result<(), CustodyTypeError> {
        if self.received <= self.expected_next
            || self.missing_count != self.received - self.expected_next
        {
            return Err(CustodyTypeError::new(
                "invalid_sequence_gap",
                "custody sequence gap arithmetic is inconsistent",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverAcceptanceReceiptV1 {
    pub schema_version: u16,
    pub receipt_digest: DigestV1,
    pub receiver_process_occurrence: IncarnationId,
    pub receiver_monotonic_epoch: IncarnationId,
    pub receiver_acceptance_policy_generation: String,
    pub receiver_acceptance_policy_digest: DigestV1,
    pub session_binding_digest: Option<DigestV1>,
    pub envelope_digest: Option<DigestV1>,
    pub receiver_arrival_monotonic_ms: u64,
    pub remote_network_endpoint: String,
    pub sender_key_verification: CustodyCheckResultV1,
    pub receiver_challenge_verification: CustodyCheckResultV1,
    pub session_binding_verification: CustodyCheckResultV1,
    pub sender_qualification_package_acceptance: CustodyCheckResultV1,
    pub exact_identity_match: CustodyCheckResultV1,
    pub replay_window_result: ReplayWindowResultV1,
    pub sequence_gap: Option<CustodySequenceGapV1>,
    pub queue_and_capacity_result: CustodyCheckResultV1,
    pub subject_scope_result: CustodyCheckResultV1,
    pub observer_role_result: CustodyCheckResultV1,
    pub payload_decoding_result: CustodyCheckResultV1,
    pub finding: TransportCustodyFindingV1,
    pub accepted_evidence_identity: Option<DigestV1>,
    pub refusal_reason: Option<String>,
    pub complete: bool,
    pub receipt_sequence: u64,
    pub journal_identity: String,
    pub mutation_authority: MutationAuthorityV1,
    pub authority_grants: CustodyAuthorityGrantsV1,
}

impl ReceiverAcceptanceReceiptV1 {
    #[must_use]
    pub fn compute_digest(&self) -> DigestV1 {
        let mut transcript = self.clone();
        transcript.receipt_digest =
            artifact_content_digest(b"receiver-acceptance-receipt-digest-field/v1");
        let bytes = serde_json::to_vec(&transcript).expect("receipt transcript serializes");
        digest_parts("transport.receiver-acceptance-receipt.v1", &[&bytes])
    }

    pub fn seal(mut self) -> Self {
        self.receipt_digest = self.compute_digest();
        self
    }

    pub fn validate(&self) -> Result<(), CustodyTypeError> {
        validate_schema(self.schema_version)?;
        validate_digest(&self.receipt_digest)?;
        self.receiver_process_occurrence
            .validate()
            .map_err(|error| CustodyTypeError::new("invalid_identity", error.to_string()))?;
        self.receiver_monotonic_epoch
            .validate()
            .map_err(|error| CustodyTypeError::new("invalid_identity", error.to_string()))?;
        validate_text(
            "receiver acceptance policy generation",
            &self.receiver_acceptance_policy_generation,
        )?;
        validate_digest(&self.receiver_acceptance_policy_digest)?;
        for digest in [
            self.session_binding_digest.as_ref(),
            self.envelope_digest.as_ref(),
            self.accepted_evidence_identity.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_digest(digest)?;
        }
        validate_text("remote endpoint metadata", &self.remote_network_endpoint)?;
        if let Some(gap) = &self.sequence_gap {
            gap.validate()?;
        }
        if let Some(reason) = &self.refusal_reason {
            validate_text("receiver refusal reason", reason)?;
        }
        validate_text("receipt journal identity", &self.journal_identity)?;
        if self.receipt_sequence == 0
            || !self.complete
            || self.mutation_authority != MutationAuthorityV1::None
            || !self.authority_grants.grants_nothing()
        {
            return Err(CustodyTypeError::new(
                "invalid_acceptance_receipt",
                "receipt is incomplete, unsequenced, or carries authority",
            ));
        }
        if self.receipt_digest != self.compute_digest() {
            return Err(CustodyTypeError::new(
                "receipt_identity_mismatch",
                "acceptance receipt digest does not identify its exact contents",
            ));
        }
        if self.finding == TransportCustodyFindingV1::EvidenceAdmitted {
            if self.accepted_evidence_identity.is_none()
                || self.refusal_reason.is_some()
                || self.sender_key_verification != CustodyCheckResultV1::Accepted
                || self.receiver_challenge_verification != CustodyCheckResultV1::Accepted
                || self.session_binding_verification != CustodyCheckResultV1::Accepted
                || self.sender_qualification_package_acceptance != CustodyCheckResultV1::Accepted
                || self.exact_identity_match != CustodyCheckResultV1::Accepted
                || self.queue_and_capacity_result != CustodyCheckResultV1::Accepted
                || self.subject_scope_result != CustodyCheckResultV1::Accepted
                || self.observer_role_result != CustodyCheckResultV1::Accepted
                || self.payload_decoding_result != CustodyCheckResultV1::Accepted
            {
                return Err(CustodyTypeError::new(
                    "invalid_admission",
                    "admitted receipt lacks every accepted admission premise",
                ));
            }
        } else if self.accepted_evidence_identity.is_some() {
            return Err(CustodyTypeError::new(
                "authority_laundering",
                "non-admitted receipt cannot name accepted evidence",
            ));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CustodyTypeError> {
        self.validate()?;
        canonical_encode(self)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, CustodyTypeError> {
        canonical_decode(bytes, "receiver acceptance receipt")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteObservationCustodyReferenceV1 {
    pub schema_version: u16,
    pub receiver_process_occurrence: IncarnationId,
    pub receiver_monotonic_epoch: IncarnationId,
    pub receiver_manifest_digest: DigestV1,
    pub receiver_qualification_certificate_digest: DigestV1,
    pub receiver_activation_receipt_digest: DigestV1,
    pub receiver_acceptance_policy_generation: String,
    pub receiver_acceptance_policy_digest: DigestV1,
    pub receiver_key_identity_digest: DigestV1,
    pub sender_key_identity_digest: DigestV1,
    pub sender_process_occurrence: IncarnationId,
    pub sender_monotonic_epoch: IncarnationId,
    pub sender_manifest_digest: DigestV1,
    pub sender_qualification_certificate_digest: DigestV1,
    pub sender_activation_receipt_digest: DigestV1,
    pub sender_session_offer_digest: DigestV1,
    pub receiver_challenge_digest: DigestV1,
    pub session_binding_digest: DigestV1,
    pub receiver_session_acceptance_digest: DigestV1,
    pub envelope_digest: DigestV1,
    pub acceptance_receipt_digest: DigestV1,
    pub observer: ObserverId,
    pub failure_domain_claim: String,
    pub subject_scope: SubjectScopeV1,
    pub observation_sequence: u64,
    pub session_sequence: u64,
    pub payload_digest: DigestV1,
    pub observation_identity: DigestV1,
    pub supporting_evidence_id: String,
    pub receiver_arrival_monotonic_ms: u64,
    pub accepted_evidence_identity: DigestV1,
    pub freshness_mode: RemoteFreshnessModeV1,
    pub authority_grants: CustodyAuthorityGrantsV1,
}

impl RemoteObservationCustodyReferenceV1 {
    pub fn validate(&self) -> Result<(), CustodyTypeError> {
        validate_schema(self.schema_version)?;
        for identity in [
            &self.receiver_process_occurrence,
            &self.receiver_monotonic_epoch,
            &self.sender_process_occurrence,
            &self.sender_monotonic_epoch,
        ] {
            identity
                .validate()
                .map_err(|error| CustodyTypeError::new("invalid_identity", error.to_string()))?;
        }
        for digest in [
            &self.receiver_manifest_digest,
            &self.receiver_qualification_certificate_digest,
            &self.receiver_activation_receipt_digest,
            &self.receiver_acceptance_policy_digest,
            &self.receiver_key_identity_digest,
            &self.sender_key_identity_digest,
            &self.sender_manifest_digest,
            &self.sender_qualification_certificate_digest,
            &self.sender_activation_receipt_digest,
            &self.sender_session_offer_digest,
            &self.receiver_challenge_digest,
            &self.session_binding_digest,
            &self.receiver_session_acceptance_digest,
            &self.envelope_digest,
            &self.acceptance_receipt_digest,
            &self.payload_digest,
            &self.observation_identity,
            &self.accepted_evidence_identity,
        ] {
            validate_digest(digest)?;
        }
        validate_text(
            "receiver acceptance policy generation",
            &self.receiver_acceptance_policy_generation,
        )?;
        self.observer
            .validate()
            .map_err(|error| CustodyTypeError::new("invalid_identity", error.to_string()))?;
        validate_text("failure-domain claim", &self.failure_domain_claim)?;
        self.subject_scope
            .validate()
            .map_err(|error| CustodyTypeError::new("invalid_identity", error.to_string()))?;
        validate_text("supporting evidence identity", &self.supporting_evidence_id)?;
        if self.observation_sequence == 0
            || self.session_sequence == 0
            || !self.authority_grants.grants_nothing()
        {
            return Err(CustodyTypeError::new(
                "invalid_custody_reference",
                "custody reference sequence or authority posture is invalid",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn identity_digest(&self) -> DigestV1 {
        let bytes = serde_json::to_vec(self).expect("validated schema serializes");
        digest_parts("transport.remote-observation-custody.v1", &[&bytes])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustodyTypeError {
    pub code: &'static str,
    pub detail: String,
}

impl CustodyTypeError {
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for CustodyTypeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for CustodyTypeError {}

#[must_use]
pub fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

pub fn decode_hex_exact(
    text: &str,
    expected_bytes: usize,
    field: &'static str,
) -> Result<Vec<u8>, CustodyTypeError> {
    let bytes = decode_hex_bounded(text, expected_bytes, field)?;
    if bytes.len() != expected_bytes {
        return Err(CustodyTypeError::new(
            "invalid_hex_length",
            format!("{field} must contain exactly {expected_bytes} bytes"),
        ));
    }
    Ok(bytes)
}

pub fn decode_hex_bounded(
    text: &str,
    maximum_bytes: usize,
    field: &'static str,
) -> Result<Vec<u8>, CustodyTypeError> {
    if text.len() % 2 != 0 || text.len() / 2 > maximum_bytes {
        return Err(CustodyTypeError::new(
            "invalid_hex_length",
            format!("{field} has an invalid bounded hex length"),
        ));
    }
    let mut output = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0]).ok_or_else(|| {
            CustodyTypeError::new("invalid_hex", format!("{field} is not lowercase hex"))
        })?;
        let low = hex_nibble(pair[1]).ok_or_else(|| {
            CustodyTypeError::new("invalid_hex", format!("{field} is not lowercase hex"))
        })?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn validate_schema(version: u16) -> Result<(), CustodyTypeError> {
    if version != SCHEMA_VERSION_V1 {
        return Err(CustodyTypeError::new(
            "unsupported_schema",
            "custody schema version is unsupported",
        ));
    }
    Ok(())
}

fn validate_protocol(version: u16) -> Result<(), CustodyTypeError> {
    if version != CUSTODY_PROTOCOL_VERSION_V1 {
        return Err(CustodyTypeError::new(
            "unsupported_protocol",
            "custody protocol version is unsupported",
        ));
    }
    Ok(())
}

fn validate_digest(digest: &DigestV1) -> Result<(), CustodyTypeError> {
    digest
        .validate()
        .map_err(|error| CustodyTypeError::new("invalid_digest", error.to_string()))
}

fn validate_text(field: &'static str, value: &str) -> Result<(), CustodyTypeError> {
    if value.is_empty()
        || value.len() > MAX_CUSTODY_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(CustodyTypeError::new(
            "invalid_text",
            format!("{field} is empty, oversized, or contains control characters"),
        ));
    }
    Ok(())
}

fn validate_sorted_texts(
    field: &'static str,
    values: &[String],
    maximum: usize,
) -> Result<(), CustodyTypeError> {
    if values.is_empty() || values.len() > maximum {
        return Err(CustodyTypeError::new(
            "bound_exceeded",
            format!("{field} count is outside its bound"),
        ));
    }
    for value in values {
        validate_text(field, value)?;
    }
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(CustodyTypeError::new(
            "noncanonical_collection",
            format!("{field} must be sorted and unique"),
        ));
    }
    Ok(())
}

fn validate_scopes(scopes: &[SubjectScopeV1]) -> Result<(), CustodyTypeError> {
    if scopes.is_empty() || scopes.len() > MAX_CUSTODY_SCOPES {
        return Err(CustodyTypeError::new(
            "bound_exceeded",
            "subject scope count is outside its bound",
        ));
    }
    for scope in scopes {
        scope
            .validate()
            .map_err(|error| CustodyTypeError::new("invalid_identity", error.to_string()))?;
    }
    if scopes
        .windows(2)
        .any(|pair| scope_key(&pair[0]) >= scope_key(&pair[1]))
    {
        return Err(CustodyTypeError::new(
            "noncanonical_collection",
            "subject scopes must be sorted and unique",
        ));
    }
    Ok(())
}

fn scope_key(scope: &SubjectScopeV1) -> (&str, &str, &str) {
    (
        scope.subject.as_str(),
        scope.subject_incarnation.as_str(),
        scope.scope.as_str(),
    )
}

fn validate_transport_bounds(
    maximum_datagram_bytes: u16,
    maximum_session_duration_ms: u64,
    maximum_messages_per_session: u32,
    maximum_messages_per_second: u32,
    queue_bound: u16,
    replay_window_size: u16,
) -> Result<(), CustodyTypeError> {
    if maximum_datagram_bytes == 0
        || usize::from(maximum_datagram_bytes) > MAX_CANARY_DATAGRAM_BYTES
        || maximum_session_duration_ms == 0
        || maximum_messages_per_session == 0
        || maximum_messages_per_second == 0
        || queue_bound == 0
        || usize::from(queue_bound) > MAX_CUSTODY_QUEUE_DEPTH
        || replay_window_size == 0
        || replay_window_size > MAX_CUSTODY_REPLAY_WINDOW
    {
        return Err(CustodyTypeError::new(
            "invalid_bound",
            "transport policy contains an unsupported zero or oversized bound",
        ));
    }
    Ok(())
}

fn canonical_encode<T: Serialize>(value: &T) -> Result<Vec<u8>, CustodyTypeError> {
    serde_json::to_vec(value).map_err(|error| {
        CustodyTypeError::new(
            "canonical_encoding_failed",
            format!("cannot encode canonical custody object: {error}"),
        )
    })
}

fn canonical_decode<T>(bytes: &[u8], label: &'static str) -> Result<T, CustodyTypeError>
where
    T: DeserializeOwned + Serialize,
    T: CustodyValidate,
{
    if bytes.len() > MAX_CANARY_DATAGRAM_BYTES * 8 {
        return Err(CustodyTypeError::new(
            "bound_exceeded",
            format!("{label} exceeds its canonical artifact byte bound"),
        ));
    }
    let value: T = serde_json::from_slice(bytes).map_err(|error| {
        CustodyTypeError::new(
            "canonical_decoding_failed",
            format!("cannot decode {label}: {error}"),
        )
    })?;
    value.custody_validate()?;
    let encoded = canonical_encode(&value)?;
    if encoded != bytes {
        return Err(CustodyTypeError::new(
            "noncanonical_encoding",
            format!("{label} bytes are valid JSON but not the exact canonical encoding"),
        ));
    }
    Ok(value)
}

trait CustodyValidate {
    fn custody_validate(&self) -> Result<(), CustodyTypeError>;
}

impl CustodyValidate for PeerKeyIdentityV1 {
    fn custody_validate(&self) -> Result<(), CustodyTypeError> {
        self.validate()
    }
}

impl CustodyValidate for ReceiverAcceptancePolicyV1 {
    fn custody_validate(&self) -> Result<(), CustodyTypeError> {
        self.validate()
    }
}

impl CustodyValidate for SenderEmissionPolicyV1 {
    fn custody_validate(&self) -> Result<(), CustodyTypeError> {
        self.validate()
    }
}

impl CustodyValidate for ReceiverAcceptanceReceiptV1 {
    fn custody_validate(&self) -> Result<(), CustodyTypeError> {
        self.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowercase_hex_is_exact_and_bounded() {
        let bytes = [0x00, 0x1f, 0xa5, 0xff];
        let encoded = encode_lower_hex(&bytes);
        assert_eq!(encoded, "001fa5ff");
        assert_eq!(decode_hex_exact(&encoded, 4, "fixture").unwrap(), bytes);
        assert!(decode_hex_exact("001FA5FF", 4, "fixture").is_err());
        assert!(decode_hex_exact("001fa5", 4, "fixture").is_err());
    }
}
