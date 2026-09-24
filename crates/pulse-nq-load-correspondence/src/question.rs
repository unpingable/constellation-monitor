//! The closed table of NQ questions this correspondence can pair with Pulse.
//!
//! Each row is the complete identity set of one qualified question: its NQ
//! question and profile identities, the claim NQ exports, the subject rule,
//! the Pulse scope and coverage tag, the schemas of every persisted carrier,
//! and NQ's own reliance window. The seam does no more with a row than it
//! did with the load constants: it pins identities, derives the frame
//! validity, names carriers, and never interprets what the question means.
//!
//! The load row reproduces the qualified load-only constants byte for byte.
//! Adding a row is a source change reviewed like any other identity pin.

use serde::{Deserialize, Serialize};

use crate::{
    ACQUISITION_ID_PREFIX, COVERAGE_TAG, INGRESS_FENCE_MS, INTENT_SCHEMA_V1, NQ_CLAIM_ID,
    NQ_CONDITION, NQ_PROFILE_DIGEST, NQ_PROFILE_ID, NQ_PROFILE_VERSION, NQ_QUESTION_DIGEST,
    NQ_QUESTION_ID, NQ_QUESTION_VERSION, NQ_RELIANCE_WINDOW_MS, OCCURRENCE_SCHEMA_V1,
    PROFILE_SCHEMA_V1, PULSE_PROFILE_DOMAIN, PULSE_PROFILE_NAME, PULSE_SCOPE, RECORD_SCHEMA_V1,
    SemanticIdentityV1, TRANSPORT_PATH,
};

/// One qualified NQ question. The variant is carried in memory only; on disk
/// every carrier names its question through its schema string.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuestionV1 {
    /// `nq.host.load_pressure/1` against `nq.host/1`; subject `host:<id>`.
    HostLoadPressureV1,
    /// `nq.host_filesystem_capacity.pressure/1` against
    /// `nq.host_filesystem_capacity/1`; subject
    /// `host-filesystem:<machine-id>/<filesystem-uuid>`.
    HostFilesystemCapacityPressureV1,
}

/// The identity row of one question. Every field is a compiled literal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuestionSpecV1 {
    pub question_id: &'static str,
    pub question_version: &'static str,
    pub question_digest: &'static str,
    pub nq_profile_id: &'static str,
    pub nq_profile_version: &'static str,
    pub nq_profile_digest: &'static str,
    /// The NQ profile a detector refusal names, as NQ writes it (numeric
    /// version).
    pub refusal_profile_version: u64,
    pub claim_id: &'static str,
    pub condition: &'static str,
    /// Every enrolled subject must start with this prefix. The seam checks
    /// the prefix only; the subject's meaning belongs to NQ's scope.
    pub subject_prefix: &'static str,
    /// NQ's own source reliance window for the profile.
    pub reliance_window_ms: u64,
    pub pulse_scope: &'static str,
    pub coverage_tag: &'static str,
    pub acquisition_id_prefix: &'static str,
    pub transport_path: &'static str,
    pub failure_domain: &'static str,
    pub profile_schema: &'static str,
    pub occurrence_schema: &'static str,
    pub intent_schema: &'static str,
    pub record_schema: &'static str,
    pub pulse_profile_name: &'static str,
    pub pulse_profile_domain: &'static str,
}

const HOST_LOAD_PRESSURE_V1: QuestionSpecV1 = QuestionSpecV1 {
    question_id: NQ_QUESTION_ID,
    question_version: NQ_QUESTION_VERSION,
    question_digest: NQ_QUESTION_DIGEST,
    nq_profile_id: NQ_PROFILE_ID,
    nq_profile_version: NQ_PROFILE_VERSION,
    nq_profile_digest: NQ_PROFILE_DIGEST,
    refusal_profile_version: 1,
    claim_id: NQ_CLAIM_ID,
    condition: NQ_CONDITION,
    subject_prefix: "host:",
    reliance_window_ms: NQ_RELIANCE_WINDOW_MS,
    pulse_scope: PULSE_SCOPE,
    coverage_tag: COVERAGE_TAG,
    acquisition_id_prefix: ACQUISITION_ID_PREFIX,
    transport_path: TRANSPORT_PATH,
    failure_domain: "domain:nq-load-correspondence",
    profile_schema: PROFILE_SCHEMA_V1,
    occurrence_schema: OCCURRENCE_SCHEMA_V1,
    intent_schema: INTENT_SCHEMA_V1,
    record_schema: RECORD_SCHEMA_V1,
    pulse_profile_name: PULSE_PROFILE_NAME,
    pulse_profile_domain: PULSE_PROFILE_DOMAIN,
};

const HOST_FILESYSTEM_CAPACITY_PRESSURE_V1: QuestionSpecV1 = QuestionSpecV1 {
    question_id: "nq.host_filesystem_capacity.pressure",
    question_version: "1",
    question_digest: "sha256:a95ea6b087bbb82c30e3430114d20a084e7d18b384a6bc1676c2291bd05ec81b",
    nq_profile_id: "nq.host_filesystem_capacity",
    nq_profile_version: "1",
    nq_profile_digest: "sha256:48d23e2e27fa47f591455c27a3d994b6409eb57a52dabf08d92607332d215636",
    refusal_profile_version: 1,
    claim_id: "claim:filesystem_capacity_pressure",
    condition: "filesystem_capacity_pressure",
    subject_prefix: "host-filesystem:",
    reliance_window_ms: 300_000,
    pulse_scope: "nq.host_filesystem_capacity.pressure/v1",
    coverage_tag: "nq_host_filesystem_capacity_pressure_v1_terminal_artifact",
    acquisition_id_prefix: "constellation-nq-fs-capacity:v1:",
    transport_path: "in-process:nq-filesystem-capacity-correspondence/v1",
    failure_domain: "domain:nq-filesystem-capacity-correspondence",
    profile_schema: "constellation.nq_host_filesystem_capacity_correspondence_profile.v1",
    occurrence_schema: "constellation.nq_host_filesystem_capacity_correspondence_occurrence.v1",
    intent_schema: "constellation.nq_host_filesystem_capacity_correspondence_intent.v1",
    record_schema: "constellation.nq_host_filesystem_capacity_correspondence.v1",
    pulse_profile_name: "constellation.nq_host_filesystem_capacity_correspondence",
    pulse_profile_domain: "constellation.nq_host_filesystem_capacity_correspondence.pulse_profile.v1",
};

impl QuestionV1 {
    /// Every question in the closed table, in declaration order.
    pub const ALL: [Self; 2] = [
        Self::HostLoadPressureV1,
        Self::HostFilesystemCapacityPressureV1,
    ];

    #[must_use]
    pub const fn spec(self) -> &'static QuestionSpecV1 {
        match self {
            Self::HostLoadPressureV1 => &HOST_LOAD_PRESSURE_V1,
            Self::HostFilesystemCapacityPressureV1 => &HOST_FILESYSTEM_CAPACITY_PRESSURE_V1,
        }
    }

    /// Exact lookup by correspondence profile schema. Unknown schemas resolve
    /// to nothing; there is no default question.
    #[must_use]
    pub fn from_profile_schema(schema: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|question| question.spec().profile_schema == schema)
    }

    /// Exact lookup by correspondence record schema.
    #[must_use]
    pub fn from_record_schema(schema: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|question| question.spec().record_schema == schema)
    }

    /// Frame validity: strictly below NQ's window by the fence and one
    /// millisecond, so a certificate can never outlive NQ's own reliance.
    #[must_use]
    pub const fn frame_validity_ms(self) -> u64 {
        self.spec().reliance_window_ms - INGRESS_FENCE_MS - 1
    }

    #[must_use]
    pub fn question_identity(self) -> SemanticIdentityV1 {
        let spec = self.spec();
        SemanticIdentityV1::new(
            spec.question_id,
            spec.question_version,
            spec.question_digest,
        )
    }

    #[must_use]
    pub fn nq_profile_identity(self) -> SemanticIdentityV1 {
        let spec = self.spec();
        SemanticIdentityV1::new(
            spec.nq_profile_id,
            spec.nq_profile_version,
            spec.nq_profile_digest,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_row_identity_is_distinct_and_schemas_resolve_exactly() {
        let mut seen = BTreeSet::new();
        for question in QuestionV1::ALL {
            let spec = question.spec();
            for value in [
                spec.question_digest,
                spec.nq_profile_digest,
                spec.claim_id,
                spec.pulse_scope,
                spec.coverage_tag,
                spec.acquisition_id_prefix,
                spec.transport_path,
                spec.failure_domain,
                spec.profile_schema,
                spec.occurrence_schema,
                spec.intent_schema,
                spec.record_schema,
                spec.pulse_profile_name,
                spec.pulse_profile_domain,
            ] {
                assert!(seen.insert(value), "{value} is shared between questions");
            }
            assert_eq!(
                QuestionV1::from_profile_schema(spec.profile_schema),
                Some(question)
            );
            assert_eq!(
                QuestionV1::from_record_schema(spec.record_schema),
                Some(question)
            );
            assert!(spec.reliance_window_ms > INGRESS_FENCE_MS + 1);
        }
        assert_eq!(QuestionV1::from_profile_schema("other"), None);
        assert_eq!(QuestionV1::from_record_schema(""), None);
    }
}
