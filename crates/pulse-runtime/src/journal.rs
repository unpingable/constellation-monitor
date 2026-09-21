//! Narrow append-only custody for history that cannot restore current standing.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use pulse_types::{
    ClockId, ConsumerId, ContradictionCustodyV1, DigestV1, IncarnationId, MockDiagnosticReceiptV1,
    MutationAuthorityV1, ReceiverId, RuntimeHistoricalStateV1, SCHEMA_VERSION_V1,
    SparseDurableEventKindV1, SparseDurableEventV1, SubjectId, digest_parts, history_nonclaims,
};
use serde::{Deserialize, Serialize};

pub(crate) const JOURNAL_FORMAT_VERSION_V1: u16 = 1;
const DATA_MAGIC: &[u8; 8] = b"PCJDATA1";
const TRAILER_MAGIC: &[u8; 8] = b"PCJEND01";
const COMMIT_MAGIC: &[u8; 8] = b"PCJCOM01";
const DIGEST_BYTES: usize = 71;
pub(crate) const HEADER_BYTES: usize = 8 + 2 + 1 + 1 + 8 + 4 + DIGEST_BYTES;
const TRAILER_BYTES: usize = 8 + DIGEST_BYTES;
const COMMIT_BYTES: usize = 8 + 8 + DIGEST_BYTES + DIGEST_BYTES;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JournalBoundsV1 {
    pub maximum_records: usize,
    pub maximum_record_payload_bytes: usize,
    pub maximum_file_bytes: u64,
}

impl JournalBoundsV1 {
    #[must_use]
    pub const fn qualification() -> Self {
        Self {
            maximum_records: 4_096,
            maximum_record_payload_bytes: 256 * 1_024,
            maximum_file_bytes: 64 * 1_024 * 1_024,
        }
    }

    pub fn validate(self) -> Result<(), JournalError> {
        if self.maximum_records == 0
            || self.maximum_record_payload_bytes == 0
            || self.maximum_file_bytes == 0
        {
            return Err(JournalError::new(
                JournalErrorClassV1::InvalidConfig,
                "every journal bound must be nonzero",
            ));
        }
        if self.maximum_record_payload_bytes > u32::MAX as usize {
            return Err(JournalError::new(
                JournalErrorClassV1::InvalidConfig,
                "record payload bound does not fit the v1 length field",
            ));
        }
        let minimum_record_bytes = u64::try_from(HEADER_BYTES + TRAILER_BYTES + COMMIT_BYTES)
            .expect("fixed journal frame size fits u64");
        if self.maximum_file_bytes < minimum_record_bytes {
            return Err(JournalError::new(
                JournalErrorClassV1::InvalidConfig,
                "file bound cannot contain one v1 record frame",
            ));
        }
        Ok(())
    }
}

impl Default for JournalBoundsV1 {
    fn default() -> Self {
        Self::qualification()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JournalConfigV1 {
    pub schema_version: u16,
    pub journal_id: String,
    pub bounds: JournalBoundsV1,
}

impl JournalConfigV1 {
    pub fn validate(&self) -> Result<(), JournalError> {
        if self.schema_version != SCHEMA_VERSION_V1 {
            return Err(JournalError::new(
                JournalErrorClassV1::UnsupportedVersion,
                "journal config schema is unsupported",
            ));
        }
        if self.journal_id.is_empty()
            || self.journal_id.len() > pulse_types::MAX_IDENTITY_BYTES
            || self.journal_id.chars().any(char::is_control)
        {
            return Err(JournalError::new(
                JournalErrorClassV1::InvalidConfig,
                "journal identity is empty, over its bound, or contains control characters",
            ));
        }
        self.bounds.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MonotonicEpochV1 {
    pub schema_version: u16,
    pub epoch_id: IncarnationId,
    pub receiver: ReceiverId,
    pub receiver_incarnation: IncarnationId,
    pub clock_id: ClockId,
    pub origin_runtime_monotonic_ms: u64,
    pub clock_source: String,
}

impl MonotonicEpochV1 {
    pub fn validate(&self) -> Result<(), JournalError> {
        if self.schema_version != SCHEMA_VERSION_V1 {
            return Err(JournalError::new(
                JournalErrorClassV1::UnsupportedVersion,
                "monotonic epoch schema is unsupported",
            ));
        }
        self.epoch_id
            .validate()
            .map_err(|error| JournalError::invalid_record(error.to_string()))?;
        self.receiver
            .validate()
            .map_err(|error| JournalError::invalid_record(error.to_string()))?;
        self.receiver_incarnation
            .validate()
            .map_err(|error| JournalError::invalid_record(error.to_string()))?;
        self.clock_id
            .validate()
            .map_err(|error| JournalError::invalid_record(error.to_string()))?;
        if self.clock_source != "std::time::Instant/process-local" {
            return Err(JournalError::invalid_record(
                "v1 monotonic epoch must name the process-local Instant source",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn identity_digest(&self) -> DigestV1 {
        digest_parts(
            "runtime.monotonic-epoch.v1",
            &[
                self.epoch_id.as_str().as_bytes(),
                self.receiver.as_str().as_bytes(),
                self.receiver_incarnation.as_str().as_bytes(),
                self.clock_id.as_str().as_bytes(),
                &self.origin_runtime_monotonic_ms.to_be_bytes(),
                self.clock_source.as_bytes(),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalRecordKindV1 {
    SparseEvent,
    ContradictionCustody,
    DiagnosticReceipt,
}

impl JournalRecordKindV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::SparseEvent => 1,
            Self::ContradictionCustody => 2,
            Self::DiagnosticReceipt => 3,
        }
    }

    const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::SparseEvent),
            2 => Some(Self::ContradictionCustody),
            3 => Some(Self::DiagnosticReceipt),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum JournalRecordBodyV1 {
    SparseEvent { event: SparseDurableEventV1 },
    ContradictionCustody { custody: ContradictionCustodyV1 },
    DiagnosticReceipt { receipt: MockDiagnosticReceiptV1 },
}

impl JournalRecordBodyV1 {
    #[must_use]
    pub const fn kind(&self) -> JournalRecordKindV1 {
        match self {
            Self::SparseEvent { .. } => JournalRecordKindV1::SparseEvent,
            Self::ContradictionCustody { .. } => JournalRecordKindV1::ContradictionCustody,
            Self::DiagnosticReceipt { .. } => JournalRecordKindV1::DiagnosticReceipt,
        }
    }

    fn immutable_identity(&self) -> Option<String> {
        match self {
            Self::SparseEvent { event } => Some(format!("event:{}", event.event_id)),
            Self::DiagnosticReceipt { receipt } => Some(format!("receipt:{}", receipt.receipt_id)),
            Self::ContradictionCustody { .. } => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalJournalRecordV1 {
    pub schema_version: u16,
    pub journal_id: String,
    pub record_sequence: u64,
    pub record_kind: JournalRecordKindV1,
    pub monotonic_epoch: MonotonicEpochV1,
    pub journaled_at_epoch_monotonic_ms: u64,
    pub declared_durability: JournalDurabilityModeV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reliance_context_digest: Option<DigestV1>,
    pub body: JournalRecordBodyV1,
    pub mutation_authority: MutationAuthorityV1,
}

impl HistoricalJournalRecordV1 {
    fn validate(&self, config: &JournalConfigV1) -> Result<(), JournalError> {
        if self.schema_version != SCHEMA_VERSION_V1 {
            return Err(JournalError::new(
                JournalErrorClassV1::UnsupportedVersion,
                "journal payload schema is unsupported",
            ));
        }
        if self.journal_id != config.journal_id {
            return Err(JournalError::invalid_record(
                "journal payload names another journal identity",
            ));
        }
        if self.record_sequence == 0 || self.record_kind != self.body.kind() {
            return Err(JournalError::invalid_record(
                "journal payload sequence or record-kind binding is invalid",
            ));
        }
        self.monotonic_epoch.validate()?;
        if let Some(digest) = &self.reliance_context_digest {
            digest
                .validate()
                .map_err(|error| JournalError::invalid_record(error.to_string()))?;
        }
        if self.mutation_authority != MutationAuthorityV1::None {
            return Err(JournalError::invalid_record(
                "journal record cannot carry mutation authority",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalDurabilityModeV1 {
    Written,
    DataSynced,
    FileSynced,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JournalCreationAckV1 {
    pub schema_version: u16,
    pub journal_id: String,
    pub empty_file_synced: bool,
    pub parent_directory_synced: bool,
    pub physical_media_durability_claimed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JournalAppendAckV1 {
    pub schema_version: u16,
    pub journal_id: String,
    pub record_sequence: u64,
    pub frame_digest: DigestV1,
    pub durability: JournalDurabilityModeV1,
    pub data_frame_written: bool,
    pub data_sync_completed: bool,
    pub commit_marker_written: bool,
    pub commit_sync_completed: bool,
    pub acknowledgement_returned: bool,
    pub file_bytes_after_append: u64,
    pub append_latency_us: u128,
    pub sync_latency_us: u128,
    pub physical_media_durability_claimed: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalRecoveryOutcomeV1 {
    Clean,
    RecoveredThroughValidPrefix,
    Refused,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalDamageClassV1 {
    TruncatedHeader,
    TruncatedPayload,
    TruncatedTrailer,
    UncommittedSuffix,
    TruncatedCommitMarker,
    UnexpectedTrailingBytes,
    InteriorCorruption,
    UnsupportedVersion,
    UnsupportedRecordKind,
    SequenceDiscontinuity,
    DuplicateRecord,
    PriorLinkMismatch,
    OversizedDeclaredLength,
    BoundExceeded,
    PayloadInvalid,
    IoFailure,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JournalRecoveryReportV1 {
    pub schema_version: u16,
    pub outcome: JournalRecoveryOutcomeV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub damage: Option<JournalDamageClassV1>,
    pub records_recovered: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_damaged_offset: Option<u64>,
    pub valid_prefix_bytes: u64,
    pub observed_file_bytes: u64,
    pub history_complete: bool,
    pub operator_action_required: bool,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_committed_frame_digest: Option<DigestV1>,
    pub records: Vec<HistoricalJournalRecordV1>,
}

impl JournalRecoveryReportV1 {
    #[must_use]
    pub fn historical_current_record_count(&self) -> usize {
        self.records
            .iter()
            .filter(|record| {
                matches!(
                    &record.body,
                    JournalRecordBodyV1::SparseEvent {
                        event: SparseDurableEventV1 {
                            event: SparseDurableEventKindV1::SupportCertificateIssued {
                                certificate
                            },
                            ..
                        }
                    } if certificate.judgment == pulse_types::JudgmentCategoryV1::Current
                )
            })
            .count()
    }

    pub fn project_history(&self) -> Result<JournalHistoryProjectionV1, JournalError> {
        if self.outcome == JournalRecoveryOutcomeV1::Refused {
            return Err(JournalError::new(
                JournalErrorClassV1::DamagedJournal,
                format!(
                    "journal recovery was refused; damaged history cannot be projected: damage={:?} offset={:?}",
                    self.damage, self.first_damaged_offset
                ),
            ));
        }
        let mut sparse_events = Vec::new();
        let mut event_ids = BTreeSet::new();
        let mut contradictions: BTreeMap<
            (SubjectId, ConsumerId, pulse_types::ContradictionId),
            ContradictionCustodyV1,
        > = BTreeMap::new();
        let mut receipts = BTreeMap::new();
        let mut historical_deduplication_keys = BTreeSet::new();
        for record in &self.records {
            match &record.body {
                JournalRecordBodyV1::SparseEvent { event } => {
                    if !event_ids.insert(event.event_id.clone()) {
                        return Err(JournalError::new(
                            JournalErrorClassV1::InvalidRecord,
                            "duplicate sparse event identity in recovered prefix",
                        ));
                    }
                    match &event.event {
                        SparseDurableEventKindV1::EscalationRequested { request } => {
                            historical_deduplication_keys.insert(request.deduplication_key.clone());
                        }
                        SparseDurableEventKindV1::EscalationDeduplicated {
                            deduplication_key,
                            ..
                        } => {
                            historical_deduplication_keys.insert(deduplication_key.clone());
                        }
                        _ => {}
                    }
                    sparse_events.push(event.clone());
                }
                JournalRecordBodyV1::ContradictionCustody { custody } => {
                    contradictions.insert(
                        (
                            custody.contradiction.subject_scope.subject.clone(),
                            custody.consumer.clone(),
                            custody.contradiction.contradiction_id.clone(),
                        ),
                        custody.clone(),
                    );
                }
                JournalRecordBodyV1::DiagnosticReceipt { receipt } => {
                    if receipts
                        .insert(receipt.receipt_id.clone(), receipt.clone())
                        .is_some()
                    {
                        return Err(JournalError::new(
                            JournalErrorClassV1::InvalidRecord,
                            "duplicate diagnostic receipt identity in recovered prefix",
                        ));
                    }
                }
            }
        }
        let history = RuntimeHistoricalStateV1 {
            schema_version: SCHEMA_VERSION_V1,
            sparse_events,
            contradictions: contradictions.into_values().collect(),
            diagnostic_receipts: receipts.into_values().collect(),
            nonclaims: history_nonclaims(),
        };
        history
            .validate()
            .map_err(|error| JournalError::invalid_record(error.to_string()))?;
        Ok(JournalHistoryProjectionV1 {
            schema_version: SCHEMA_VERSION_V1,
            recovery_outcome: self.outcome,
            recovery_damage: self.damage,
            history_complete: self.history_complete,
            operator_action_required: self.operator_action_required,
            history,
            historical_escalation_deduplication_keys: historical_deduplication_keys
                .into_iter()
                .collect(),
            active_escalation_suppression_restored: false,
            current_standing_reconstructed: false,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JournalHistoryProjectionV1 {
    pub schema_version: u16,
    pub recovery_outcome: JournalRecoveryOutcomeV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_damage: Option<JournalDamageClassV1>,
    pub history_complete: bool,
    pub operator_action_required: bool,
    pub history: RuntimeHistoricalStateV1,
    pub historical_escalation_deduplication_keys: Vec<DigestV1>,
    pub active_escalation_suppression_restored: bool,
    pub current_standing_reconstructed: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalWriteStageV1 {
    HeaderPartiallyWritten,
    PayloadPartiallyWritten,
    TrailerPartiallyWritten,
    FrameWrittenBeforeSync,
    DataFrameSynced,
    CommitMarkerPartiallyWritten,
    CommitMarkerSyncedBeforeAcknowledgement,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalErrorClassV1 {
    InvalidConfig,
    InvalidRecord,
    UnsupportedVersion,
    BoundExceeded,
    DamagedJournal,
    IoFailure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalError {
    pub class: JournalErrorClassV1,
    pub detail: String,
}

impl JournalError {
    fn new(class: JournalErrorClassV1, detail: impl Into<String>) -> Self {
        Self {
            class,
            detail: detail.into(),
        }
    }

    fn invalid_record(detail: impl Into<String>) -> Self {
        Self::new(JournalErrorClassV1::InvalidRecord, detail)
    }

    fn io(stage: &str, error: &io::Error) -> Self {
        Self::new(
            JournalErrorClassV1::IoFailure,
            format!("journal I/O failed at {stage}: {error}"),
        )
    }
}

impl fmt::Display for JournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.class, self.detail)
    }
}

impl std::error::Error for JournalError {}

pub struct HistoricalJournal {
    path: PathBuf,
    file: File,
    config: JournalConfigV1,
    creation_ack: Option<JournalCreationAckV1>,
    next_sequence: u64,
    prior_frame_digest: DigestV1,
    file_bytes: u64,
    committed_records: Vec<HistoricalJournalRecordV1>,
    immutable_identities: BTreeSet<String>,
    failed: bool,
}

impl HistoricalJournal {
    pub fn create_new(
        path: impl AsRef<Path>,
        config: JournalConfigV1,
    ) -> Result<Self, JournalError> {
        config.validate()?;
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| JournalError::io("create_new", &error))?;
        file.sync_all()
            .map_err(|error| JournalError::io("empty_file_sync_all", &error))?;
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let parent_directory = File::open(parent)
            .map_err(|error| JournalError::io("open_parent_directory", &error))?;
        parent_directory
            .sync_all()
            .map_err(|error| JournalError::io("parent_directory_sync_all", &error))?;
        let creation_ack = JournalCreationAckV1 {
            schema_version: SCHEMA_VERSION_V1,
            journal_id: config.journal_id.clone(),
            empty_file_synced: true,
            parent_directory_synced: true,
            physical_media_durability_claimed: false,
        };
        Ok(Self {
            path,
            file,
            config,
            creation_ack: Some(creation_ack),
            next_sequence: 1,
            prior_frame_digest: genesis_digest(),
            file_bytes: 0,
            committed_records: Vec::new(),
            immutable_identities: BTreeSet::new(),
            failed: false,
        })
    }

    pub fn open_clean(
        path: impl AsRef<Path>,
        config: JournalConfigV1,
    ) -> Result<(Self, JournalRecoveryReportV1), JournalError> {
        let path = path.as_ref().to_path_buf();
        let report = Self::scan(&path, &config)?;
        if report.outcome != JournalRecoveryOutcomeV1::Clean {
            return Err(JournalError::new(
                JournalErrorClassV1::DamagedJournal,
                format!(
                    "journal is not appendable: outcome={:?} damage={:?}",
                    report.outcome, report.damage
                ),
            ));
        }
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(&path)
            .map_err(|error| JournalError::io("open_clean", &error))?;
        let immutable_identities = report
            .records
            .iter()
            .filter_map(|record| record.body.immutable_identity())
            .collect();
        let next_sequence = u64::try_from(report.records.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let prior_frame_digest = report
            .last_committed_frame_digest
            .clone()
            .unwrap_or_else(genesis_digest);
        let journal = Self {
            path,
            file,
            config,
            creation_ack: None,
            next_sequence,
            prior_frame_digest,
            file_bytes: report.observed_file_bytes,
            committed_records: report.records.clone(),
            immutable_identities,
            failed: false,
        };
        Ok((journal, report))
    }

    #[must_use]
    pub const fn config(&self) -> &JournalConfigV1 {
        &self.config
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub const fn creation_ack(&self) -> Option<&JournalCreationAckV1> {
        self.creation_ack.as_ref()
    }

    #[must_use]
    pub fn committed_records(&self) -> &[HistoricalJournalRecordV1] {
        &self.committed_records
    }

    pub fn append(
        &mut self,
        epoch: MonotonicEpochV1,
        journaled_at_epoch_monotonic_ms: u64,
        reliance_context_digest: Option<DigestV1>,
        body: JournalRecordBodyV1,
        durability: JournalDurabilityModeV1,
    ) -> Result<JournalAppendAckV1, JournalError> {
        self.append_with_qualification_hook(
            epoch,
            journaled_at_epoch_monotonic_ms,
            reliance_context_digest,
            body,
            durability,
            &mut |_| Ok(()),
        )
    }

    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn append_with_qualification_hook(
        &mut self,
        epoch: MonotonicEpochV1,
        journaled_at_epoch_monotonic_ms: u64,
        reliance_context_digest: Option<DigestV1>,
        body: JournalRecordBodyV1,
        durability: JournalDurabilityModeV1,
        hook: &mut dyn FnMut(JournalWriteStageV1) -> io::Result<()>,
    ) -> Result<JournalAppendAckV1, JournalError> {
        if self.failed {
            return Err(JournalError::new(
                JournalErrorClassV1::DamagedJournal,
                "journal append was previously interrupted; reopen and scan before reuse",
            ));
        }
        epoch.validate()?;
        if let Some(digest) = &reliance_context_digest {
            digest
                .validate()
                .map_err(|error| JournalError::invalid_record(error.to_string()))?;
        }
        if self.committed_records.len() >= self.config.bounds.maximum_records {
            return Err(JournalError::new(
                JournalErrorClassV1::BoundExceeded,
                "journal record-count bound is exhausted",
            ));
        }
        if let Some(identity) = body.immutable_identity()
            && self.immutable_identities.contains(&identity)
        {
            return Err(JournalError::new(
                JournalErrorClassV1::InvalidRecord,
                format!("immutable journal payload identity is duplicated: {identity}"),
            ));
        }
        let sequence = self.next_sequence;
        let record = HistoricalJournalRecordV1 {
            schema_version: SCHEMA_VERSION_V1,
            journal_id: self.config.journal_id.clone(),
            record_sequence: sequence,
            record_kind: body.kind(),
            monotonic_epoch: epoch,
            journaled_at_epoch_monotonic_ms,
            declared_durability: durability,
            reliance_context_digest,
            body,
            mutation_authority: MutationAuthorityV1::None,
        };
        record.validate(&self.config)?;
        let payload = serde_json::to_vec(&record).map_err(|error| {
            JournalError::new(
                JournalErrorClassV1::InvalidRecord,
                format!("journal payload encoding failed: {error}"),
            )
        })?;
        if payload.len() > self.config.bounds.maximum_record_payload_bytes {
            return Err(JournalError::new(
                JournalErrorClassV1::BoundExceeded,
                "encoded journal payload exceeds the record-size bound",
            ));
        }
        let payload_length = u32::try_from(payload.len()).map_err(|_| {
            JournalError::new(
                JournalErrorClassV1::BoundExceeded,
                "encoded journal payload does not fit the v1 length field",
            )
        })?;
        let encoded_bytes = HEADER_BYTES
            .checked_add(payload.len())
            .and_then(|value| value.checked_add(TRAILER_BYTES + COMMIT_BYTES))
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(|| {
                JournalError::new(
                    JournalErrorClassV1::BoundExceeded,
                    "encoded journal frame size overflowed",
                )
            })?;
        if self.file_bytes.saturating_add(encoded_bytes) > self.config.bounds.maximum_file_bytes {
            return Err(JournalError::new(
                JournalErrorClassV1::BoundExceeded,
                "journal file-size bound is exhausted",
            ));
        }

        let header = encode_header(
            record.record_kind,
            sequence,
            payload_length,
            &self.prior_frame_digest,
        );
        let frame_digest = digest_parts("runtime.history-journal.frame.v1", &[&header, &payload]);
        let trailer = encode_trailer(&frame_digest);
        let commit = encode_commit(sequence, &frame_digest);
        let started = Instant::now();
        let mut sync_latency_us = 0_u128;
        let result = (|| {
            write_split(
                &mut self.file,
                &header,
                JournalWriteStageV1::HeaderPartiallyWritten,
                hook,
            )?;
            write_split(
                &mut self.file,
                &payload,
                JournalWriteStageV1::PayloadPartiallyWritten,
                hook,
            )?;
            write_split(
                &mut self.file,
                &trailer,
                JournalWriteStageV1::TrailerPartiallyWritten,
                hook,
            )?;
            self.file.flush()?;
            hook(JournalWriteStageV1::FrameWrittenBeforeSync)?;
            let sync_started = Instant::now();
            sync_file(&self.file, durability)?;
            sync_latency_us = sync_latency_us.saturating_add(sync_started.elapsed().as_micros());
            hook(JournalWriteStageV1::DataFrameSynced)?;
            write_split(
                &mut self.file,
                &commit,
                JournalWriteStageV1::CommitMarkerPartiallyWritten,
                hook,
            )?;
            self.file.flush()?;
            let sync_started = Instant::now();
            sync_file(&self.file, durability)?;
            sync_latency_us = sync_latency_us.saturating_add(sync_started.elapsed().as_micros());
            hook(JournalWriteStageV1::CommitMarkerSyncedBeforeAcknowledgement)?;
            Ok::<(), io::Error>(())
        })();
        if let Err(error) = result {
            self.failed = true;
            return Err(JournalError::io("append", &error));
        }
        self.file_bytes = self.file_bytes.saturating_add(encoded_bytes);
        self.next_sequence = self.next_sequence.checked_add(1).ok_or_else(|| {
            self.failed = true;
            JournalError::new(
                JournalErrorClassV1::BoundExceeded,
                "journal sequence space is exhausted",
            )
        })?;
        self.prior_frame_digest = frame_digest.clone();
        if let Some(identity) = record.body.immutable_identity() {
            self.immutable_identities.insert(identity);
        }
        self.committed_records.push(record);
        Ok(JournalAppendAckV1 {
            schema_version: SCHEMA_VERSION_V1,
            journal_id: self.config.journal_id.clone(),
            record_sequence: sequence,
            frame_digest,
            durability,
            data_frame_written: true,
            data_sync_completed: durability != JournalDurabilityModeV1::Written,
            commit_marker_written: true,
            commit_sync_completed: durability != JournalDurabilityModeV1::Written,
            acknowledgement_returned: true,
            file_bytes_after_append: self.file_bytes,
            append_latency_us: started.elapsed().as_micros(),
            sync_latency_us,
            physical_media_durability_claimed: false,
        })
    }

    pub fn scan(
        path: impl AsRef<Path>,
        config: &JournalConfigV1,
    ) -> Result<JournalRecoveryReportV1, JournalError> {
        config.validate()?;
        let path = path.as_ref();
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(error) => {
                return Ok(io_failure_report(
                    0,
                    format!("journal open failed: {error}"),
                    Some(config.journal_id.clone()),
                ));
            }
        };
        let observed_file_bytes = match file.metadata() {
            Ok(metadata) => metadata.len(),
            Err(error) => {
                return Ok(io_failure_report(
                    0,
                    format!("journal metadata failed: {error}"),
                    Some(config.journal_id.clone()),
                ));
            }
        };
        if observed_file_bytes > config.bounds.maximum_file_bytes {
            return Ok(damaged_report(
                JournalDamageClassV1::BoundExceeded,
                Vec::new(),
                0,
                0,
                observed_file_bytes,
                "journal exceeds the configured file-size bound",
                Some(config.journal_id.clone()),
                None,
            ));
        }
        let capacity = usize::try_from(observed_file_bytes).map_err(|_| {
            JournalError::new(
                JournalErrorClassV1::BoundExceeded,
                "journal length does not fit this process address space",
            )
        })?;
        let mut bytes = Vec::with_capacity(capacity);
        if let Err(error) = file.read_to_end(&mut bytes) {
            return Ok(io_failure_report(
                observed_file_bytes,
                format!("journal read failed: {error}"),
                Some(config.journal_id.clone()),
            ));
        }
        Ok(scan_bytes(&bytes, config))
    }
}

fn sync_file(file: &File, durability: JournalDurabilityModeV1) -> io::Result<()> {
    match durability {
        JournalDurabilityModeV1::Written => Ok(()),
        JournalDurabilityModeV1::DataSynced => file.sync_data(),
        JournalDurabilityModeV1::FileSynced => file.sync_all(),
    }
}

fn write_split(
    file: &mut File,
    bytes: &[u8],
    stage: JournalWriteStageV1,
    hook: &mut dyn FnMut(JournalWriteStageV1) -> io::Result<()>,
) -> io::Result<()> {
    let split = bytes.len().div_ceil(2);
    file.write_all(&bytes[..split])?;
    file.flush()?;
    hook(stage)?;
    file.write_all(&bytes[split..])?;
    Ok(())
}

fn genesis_digest() -> DigestV1 {
    digest_parts("runtime.history-journal.genesis.v1", &[])
}

fn encode_header(
    kind: JournalRecordKindV1,
    sequence: u64,
    payload_length: u32,
    prior_digest: &DigestV1,
) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_BYTES);
    header.extend_from_slice(DATA_MAGIC);
    header.extend_from_slice(&JOURNAL_FORMAT_VERSION_V1.to_be_bytes());
    header.push(kind.tag());
    header.push(0);
    header.extend_from_slice(&sequence.to_be_bytes());
    header.extend_from_slice(&payload_length.to_be_bytes());
    header.extend_from_slice(prior_digest.as_str().as_bytes());
    debug_assert_eq!(header.len(), HEADER_BYTES);
    header
}

fn encode_trailer(frame_digest: &DigestV1) -> Vec<u8> {
    let mut trailer = Vec::with_capacity(TRAILER_BYTES);
    trailer.extend_from_slice(TRAILER_MAGIC);
    trailer.extend_from_slice(frame_digest.as_str().as_bytes());
    debug_assert_eq!(trailer.len(), TRAILER_BYTES);
    trailer
}

fn encode_commit(sequence: u64, frame_digest: &DigestV1) -> Vec<u8> {
    let sequence_bytes = sequence.to_be_bytes();
    let checksum = digest_parts(
        "runtime.history-journal.commit.v1",
        &[
            COMMIT_MAGIC,
            &sequence_bytes,
            frame_digest.as_str().as_bytes(),
        ],
    );
    let mut commit = Vec::with_capacity(COMMIT_BYTES);
    commit.extend_from_slice(COMMIT_MAGIC);
    commit.extend_from_slice(&sequence_bytes);
    commit.extend_from_slice(frame_digest.as_str().as_bytes());
    commit.extend_from_slice(checksum.as_str().as_bytes());
    debug_assert_eq!(commit.len(), COMMIT_BYTES);
    commit
}

fn scan_bytes(bytes: &[u8], config: &JournalConfigV1) -> JournalRecoveryReportV1 {
    if bytes.is_empty() {
        return clean_report(Vec::new(), 0, Some(config.journal_id.clone()), None);
    }
    let mut offset = 0_usize;
    let mut records = Vec::new();
    let mut expected_sequence = 1_u64;
    let mut expected_prior = genesis_digest();
    let mut last_digest = None;
    let mut immutable_identities = BTreeSet::new();
    while offset < bytes.len() {
        if records.len() >= config.bounds.maximum_records {
            return damaged_at(
                JournalDamageClassV1::BoundExceeded,
                records,
                offset,
                bytes.len(),
                "journal contains more records than the configured bound",
                config,
                last_digest,
            );
        }
        let record_start = offset;
        let remaining = &bytes[offset..];
        if remaining.len() < DATA_MAGIC.len() {
            let damage = if DATA_MAGIC.starts_with(remaining) {
                JournalDamageClassV1::TruncatedHeader
            } else {
                JournalDamageClassV1::UnexpectedTrailingBytes
            };
            return damaged_at(
                damage,
                records,
                record_start,
                bytes.len(),
                "EOF or trailing bytes occurred before a complete data-frame magic",
                config,
                last_digest,
            );
        }
        if &remaining[..DATA_MAGIC.len()] != DATA_MAGIC {
            let damage = if remaining.len() < HEADER_BYTES {
                JournalDamageClassV1::UnexpectedTrailingBytes
            } else {
                JournalDamageClassV1::InteriorCorruption
            };
            return damaged_at(
                damage,
                records,
                record_start,
                bytes.len(),
                "next record does not begin with the exact data-frame magic",
                config,
                last_digest,
            );
        }
        if remaining.len() < HEADER_BYTES {
            return damaged_at(
                JournalDamageClassV1::TruncatedHeader,
                records,
                record_start,
                bytes.len(),
                "data-frame header is incomplete",
                config,
                last_digest,
            );
        }
        let header = &remaining[..HEADER_BYTES];
        let version = u16::from_be_bytes([header[8], header[9]]);
        if version != JOURNAL_FORMAT_VERSION_V1 {
            return damaged_at(
                JournalDamageClassV1::UnsupportedVersion,
                records,
                record_start,
                bytes.len(),
                "journal frame version is unsupported",
                config,
                last_digest,
            );
        }
        let Some(kind) = JournalRecordKindV1::from_tag(header[10]) else {
            return damaged_at(
                JournalDamageClassV1::UnsupportedRecordKind,
                records,
                record_start,
                bytes.len(),
                "journal frame record-kind tag is unsupported",
                config,
                last_digest,
            );
        };
        if header[11] != 0 {
            return damaged_at(
                JournalDamageClassV1::InteriorCorruption,
                records,
                record_start,
                bytes.len(),
                "journal frame reserved byte is nonzero",
                config,
                last_digest,
            );
        }
        let sequence = read_u64(&header[12..20]);
        if sequence != expected_sequence {
            let damage = if sequence < expected_sequence {
                JournalDamageClassV1::DuplicateRecord
            } else {
                JournalDamageClassV1::SequenceDiscontinuity
            };
            return damaged_at(
                damage,
                records,
                record_start,
                bytes.len(),
                "journal sequence is duplicated, reordered, stale, or skipped",
                config,
                last_digest,
            );
        }
        let payload_length = usize::try_from(read_u32(&header[20..24]))
            .expect("u32 payload length fits usize on supported targets");
        if payload_length > config.bounds.maximum_record_payload_bytes {
            return damaged_at(
                JournalDamageClassV1::OversizedDeclaredLength,
                records,
                record_start,
                bytes.len(),
                "journal frame declares a payload over the configured bound",
                config,
                last_digest,
            );
        }
        let prior = match read_digest(&header[24..24 + DIGEST_BYTES]) {
            Some(digest) => digest,
            None => {
                return damaged_at(
                    JournalDamageClassV1::InteriorCorruption,
                    records,
                    record_start,
                    bytes.len(),
                    "prior-frame digest is malformed",
                    config,
                    last_digest,
                );
            }
        };
        if prior != expected_prior {
            return damaged_at(
                JournalDamageClassV1::PriorLinkMismatch,
                records,
                record_start,
                bytes.len(),
                "prior-frame digest does not bind the preceding committed record",
                config,
                last_digest,
            );
        }
        let payload_start = record_start + HEADER_BYTES;
        let payload_end = match payload_start.checked_add(payload_length) {
            Some(end) => end,
            None => {
                return damaged_at(
                    JournalDamageClassV1::OversizedDeclaredLength,
                    records,
                    record_start,
                    bytes.len(),
                    "payload extent overflowed",
                    config,
                    last_digest,
                );
            }
        };
        if payload_end > bytes.len() {
            return damaged_at(
                JournalDamageClassV1::TruncatedPayload,
                records,
                payload_start,
                bytes.len(),
                "journal payload is incomplete",
                config,
                last_digest,
            );
        }
        let trailer_end = match payload_end.checked_add(TRAILER_BYTES) {
            Some(end) => end,
            None => usize::MAX,
        };
        if trailer_end > bytes.len() {
            return damaged_at(
                JournalDamageClassV1::TruncatedTrailer,
                records,
                payload_end,
                bytes.len(),
                "journal frame trailer or checksum is incomplete",
                config,
                last_digest,
            );
        }
        let trailer = &bytes[payload_end..trailer_end];
        if &trailer[..TRAILER_MAGIC.len()] != TRAILER_MAGIC {
            return damaged_at(
                JournalDamageClassV1::InteriorCorruption,
                records,
                payload_end,
                bytes.len(),
                "journal trailer magic is corrupted",
                config,
                last_digest,
            );
        }
        let Some(recorded_digest) = read_digest(&trailer[TRAILER_MAGIC.len()..]) else {
            return damaged_at(
                JournalDamageClassV1::InteriorCorruption,
                records,
                payload_end,
                bytes.len(),
                "journal frame checksum is malformed",
                config,
                last_digest,
            );
        };
        let computed_digest = digest_parts(
            "runtime.history-journal.frame.v1",
            &[header, &bytes[payload_start..payload_end]],
        );
        if recorded_digest != computed_digest {
            return damaged_at(
                JournalDamageClassV1::InteriorCorruption,
                records,
                payload_start,
                bytes.len(),
                "journal frame checksum does not match exact header and payload bytes",
                config,
                last_digest,
            );
        }
        if trailer_end == bytes.len() {
            return damaged_at(
                JournalDamageClassV1::UncommittedSuffix,
                records,
                record_start,
                bytes.len(),
                "complete data frame has no committed marker",
                config,
                last_digest,
            );
        }
        let commit_end = match trailer_end.checked_add(COMMIT_BYTES) {
            Some(end) => end,
            None => usize::MAX,
        };
        if commit_end > bytes.len() {
            return damaged_at(
                JournalDamageClassV1::TruncatedCommitMarker,
                records,
                trailer_end,
                bytes.len(),
                "journal commit marker is incomplete",
                config,
                last_digest,
            );
        }
        let commit = &bytes[trailer_end..commit_end];
        if &commit[..COMMIT_MAGIC.len()] != COMMIT_MAGIC {
            return damaged_at(
                JournalDamageClassV1::InteriorCorruption,
                records,
                trailer_end,
                bytes.len(),
                "journal commit marker magic is corrupted",
                config,
                last_digest,
            );
        }
        let commit_sequence = read_u64(&commit[8..16]);
        let Some(commit_digest) = read_digest(&commit[16..16 + DIGEST_BYTES]) else {
            return damaged_at(
                JournalDamageClassV1::InteriorCorruption,
                records,
                trailer_end,
                bytes.len(),
                "journal commit marker digest is malformed",
                config,
                last_digest,
            );
        };
        let Some(commit_checksum) = read_digest(&commit[16 + DIGEST_BYTES..]) else {
            return damaged_at(
                JournalDamageClassV1::InteriorCorruption,
                records,
                trailer_end,
                bytes.len(),
                "journal commit marker checksum is malformed",
                config,
                last_digest,
            );
        };
        let expected_commit_checksum = digest_parts(
            "runtime.history-journal.commit.v1",
            &[
                COMMIT_MAGIC,
                &commit_sequence.to_be_bytes(),
                commit_digest.as_str().as_bytes(),
            ],
        );
        if commit_sequence != sequence
            || commit_digest != computed_digest
            || commit_checksum != expected_commit_checksum
        {
            return damaged_at(
                JournalDamageClassV1::InteriorCorruption,
                records,
                trailer_end,
                bytes.len(),
                "journal commit marker does not bind the exact data frame",
                config,
                last_digest,
            );
        }
        let record: HistoricalJournalRecordV1 =
            match serde_json::from_slice(&bytes[payload_start..payload_end]) {
                Ok(record) => record,
                Err(error) => {
                    return damaged_at(
                        JournalDamageClassV1::PayloadInvalid,
                        records,
                        payload_start,
                        bytes.len(),
                        &format!("journal JSON payload is invalid: {error}"),
                        config,
                        last_digest,
                    );
                }
            };
        if record.schema_version != SCHEMA_VERSION_V1 {
            return damaged_at(
                JournalDamageClassV1::UnsupportedVersion,
                records,
                payload_start,
                bytes.len(),
                "journal payload schema is unsupported",
                config,
                last_digest,
            );
        }
        if record.record_sequence != sequence || record.record_kind != kind {
            return damaged_at(
                JournalDamageClassV1::PayloadInvalid,
                records,
                payload_start,
                bytes.len(),
                "journal payload does not bind frame sequence and kind",
                config,
                last_digest,
            );
        }
        if let Err(error) = record.validate(config) {
            let damage = if error.class == JournalErrorClassV1::UnsupportedVersion {
                JournalDamageClassV1::UnsupportedVersion
            } else {
                JournalDamageClassV1::PayloadInvalid
            };
            return damaged_at(
                damage,
                records,
                payload_start,
                bytes.len(),
                &error.detail,
                config,
                last_digest,
            );
        }
        if let Some(identity) = record.body.immutable_identity()
            && !immutable_identities.insert(identity)
        {
            return damaged_at(
                JournalDamageClassV1::DuplicateRecord,
                records,
                record_start,
                bytes.len(),
                "immutable payload identity appears more than once",
                config,
                last_digest,
            );
        }
        expected_sequence = match expected_sequence.checked_add(1) {
            Some(value) => value,
            None => {
                return damaged_at(
                    JournalDamageClassV1::BoundExceeded,
                    records,
                    record_start,
                    bytes.len(),
                    "journal sequence space is exhausted",
                    config,
                    last_digest,
                );
            }
        };
        expected_prior = computed_digest.clone();
        last_digest = Some(computed_digest);
        records.push(record);
        offset = commit_end;
    }
    clean_report(
        records,
        u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        Some(config.journal_id.clone()),
        last_digest,
    )
}

fn clean_report(
    records: Vec<HistoricalJournalRecordV1>,
    bytes: u64,
    journal_id: Option<String>,
    last_digest: Option<DigestV1>,
) -> JournalRecoveryReportV1 {
    JournalRecoveryReportV1 {
        schema_version: SCHEMA_VERSION_V1,
        outcome: JournalRecoveryOutcomeV1::Clean,
        damage: None,
        records_recovered: records.len(),
        first_damaged_offset: None,
        valid_prefix_bytes: bytes,
        observed_file_bytes: bytes,
        history_complete: true,
        operator_action_required: false,
        detail: "clean EOF follows the last committed record".to_owned(),
        journal_id,
        last_committed_frame_digest: last_digest,
        records,
    }
}

#[allow(clippy::too_many_arguments)]
fn damaged_at(
    damage: JournalDamageClassV1,
    records: Vec<HistoricalJournalRecordV1>,
    first_damage: usize,
    observed_bytes: usize,
    detail: &str,
    config: &JournalConfigV1,
    last_digest: Option<DigestV1>,
) -> JournalRecoveryReportV1 {
    let valid_prefix_bytes = records
        .iter()
        .filter_map(|record| serde_json::to_vec(record).ok())
        .filter_map(|payload| {
            HEADER_BYTES
                .checked_add(payload.len())?
                .checked_add(TRAILER_BYTES + COMMIT_BYTES)
        })
        .filter_map(|bytes| u64::try_from(bytes).ok())
        .fold(0_u64, u64::saturating_add);
    damaged_report(
        damage,
        records,
        u64::try_from(first_damage).unwrap_or(u64::MAX),
        valid_prefix_bytes,
        u64::try_from(observed_bytes).unwrap_or(u64::MAX),
        detail,
        Some(config.journal_id.clone()),
        last_digest,
    )
}

#[allow(clippy::too_many_arguments)]
fn damaged_report(
    damage: JournalDamageClassV1,
    records: Vec<HistoricalJournalRecordV1>,
    first_damage: u64,
    valid_prefix_bytes: u64,
    observed_file_bytes: u64,
    detail: &str,
    journal_id: Option<String>,
    last_digest: Option<DigestV1>,
) -> JournalRecoveryReportV1 {
    let suffix_recoverable = matches!(
        damage,
        JournalDamageClassV1::TruncatedHeader
            | JournalDamageClassV1::TruncatedPayload
            | JournalDamageClassV1::TruncatedTrailer
            | JournalDamageClassV1::UncommittedSuffix
            | JournalDamageClassV1::TruncatedCommitMarker
            | JournalDamageClassV1::UnexpectedTrailingBytes
    ) && !records.is_empty();
    JournalRecoveryReportV1 {
        schema_version: SCHEMA_VERSION_V1,
        outcome: if suffix_recoverable {
            JournalRecoveryOutcomeV1::RecoveredThroughValidPrefix
        } else {
            JournalRecoveryOutcomeV1::Refused
        },
        damage: Some(damage),
        records_recovered: records.len(),
        first_damaged_offset: Some(first_damage),
        valid_prefix_bytes,
        observed_file_bytes,
        history_complete: false,
        operator_action_required: true,
        detail: detail.to_owned(),
        journal_id,
        last_committed_frame_digest: last_digest,
        records,
    }
}

fn io_failure_report(
    observed_file_bytes: u64,
    detail: String,
    journal_id: Option<String>,
) -> JournalRecoveryReportV1 {
    damaged_report(
        JournalDamageClassV1::IoFailure,
        Vec::new(),
        0,
        0,
        observed_file_bytes,
        &detail,
        journal_id,
        None,
    )
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().expect("bounded u64 slice"))
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().expect("bounded u32 slice"))
}

fn read_digest(bytes: &[u8]) -> Option<DigestV1> {
    let value = std::str::from_utf8(bytes).ok()?;
    let digest = DigestV1(value.to_owned());
    digest.validate().ok()?;
    Some(digest)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use proptest::prelude::*;
    use pulse_l3_bridge::{StubL3Bridge, stub_profile_identity};
    use pulse_types::{
        BridgeId, ConsumerId, DiagnosticBoundsV1, DiagnosticEscalationRequestV1,
        ESCALATION_NONCLAIMS, EscalationRequestId, EscalationTriggerClassV1,
        ObservationPolicyGenerationId, PolicyGenerationId, SparseDurableEventKindV1, SparseEventId,
        SubjectId, SubjectScopeV1, TransitionId,
    };

    static NEXT_PATH: AtomicU64 = AtomicU64::new(1);

    fn temp_path(label: &str) -> PathBuf {
        let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "monitor-journal-{label}-{}-{sequence}.bin",
            std::process::id()
        ))
    }

    fn config(id: &str) -> JournalConfigV1 {
        JournalConfigV1 {
            schema_version: SCHEMA_VERSION_V1,
            journal_id: id.to_owned(),
            bounds: JournalBoundsV1 {
                maximum_records: 16,
                maximum_record_payload_bytes: 16 * 1_024,
                maximum_file_bytes: 256 * 1_024,
            },
        }
    }

    fn epoch(id: &str) -> MonotonicEpochV1 {
        MonotonicEpochV1 {
            schema_version: SCHEMA_VERSION_V1,
            epoch_id: IncarnationId::new(id),
            receiver: ReceiverId::new("receiver:journal-test"),
            receiver_incarnation: IncarnationId::new(format!("receiver-incarnation:{id}")),
            clock_id: ClockId::new(format!("clock:{id}")),
            origin_runtime_monotonic_ms: 0,
            clock_source: "std::time::Instant/process-local".to_owned(),
        }
    }

    fn event(id: &str, at: u64) -> JournalRecordBodyV1 {
        JournalRecordBodyV1::SparseEvent {
            event: SparseDurableEventV1 {
                schema_version: SCHEMA_VERSION_V1,
                event_id: SparseEventId::new(id),
                at_monotonic_ms: at,
                event: SparseDurableEventKindV1::MonitorCapabilityChanged {
                    state: "fixture".to_owned(),
                    detail: format!("event {id}"),
                },
            },
        }
    }

    fn append_event(
        journal: &mut HistoricalJournal,
        epoch: &MonotonicEpochV1,
        id: &str,
        at: u64,
    ) -> JournalAppendAckV1 {
        journal
            .append(
                epoch.clone(),
                at,
                None,
                event(id, at),
                JournalDurabilityModeV1::FileSynced,
            )
            .expect("fixture append succeeds")
    }

    fn receipt() -> MockDiagnosticReceiptV1 {
        let mut request = DiagnosticEscalationRequestV1 {
            schema_version: SCHEMA_VERSION_V1,
            request_id: EscalationRequestId::new("request:journal-receipt"),
            subject_scope: SubjectScopeV1 {
                subject: SubjectId::new("subject:journal-receipt"),
                subject_incarnation: IncarnationId::new("subject-incarnation:journal-receipt"),
                scope: "host".to_owned(),
            },
            consumer: ConsumerId::new("consumer:journal-receipt"),
            trigger_class: EscalationTriggerClassV1::CoverageCollapse,
            evidence_window_digest: digest_parts("journal.receipt.window", &[b"one"]),
            policy_generation: PolicyGenerationId::new("policy:journal-receipt"),
            observation_policy_generation: ObservationPolicyGenerationId::new(
                "observation-policy:journal-receipt",
            ),
            diagnostic_profile: stub_profile_identity(),
            bounds: DiagnosticBoundsV1 {
                maximum_runtime_ms: 25,
                maximum_output_bytes: 1_024,
                maximum_observations: 4,
            },
            clock_id: ClockId::new("clock:journal-receipt"),
            created_at_monotonic_ms: 1,
            expires_at_monotonic_ms: 100,
            deduplication_key: digest_parts("pending", &[]),
            causal_transition_id: TransitionId::new("transition:journal-receipt"),
            nonclaims: ESCALATION_NONCLAIMS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        };
        request.deduplication_key = request.compute_deduplication_key();
        StubL3Bridge::new(
            BridgeId::new("bridge:journal-receipt"),
            ClockId::new("clock:journal-receipt"),
        )
        .handle(&request, 2)
        .receipt
        .expect("stub produces bounded receipt")
    }

    #[test]
    fn empty_and_clean_committed_journals_are_distinctly_clean() {
        let path = temp_path("clean");
        let config = config("journal:clean");
        let mut journal = HistoricalJournal::create_new(&path, config.clone()).expect("create");
        let creation = journal.creation_ack().expect("creation ack");
        assert!(creation.empty_file_synced);
        assert!(creation.parent_directory_synced);
        assert!(!creation.physical_media_durability_claimed);
        let empty = HistoricalJournal::scan(&path, &config).expect("scan empty");
        assert_eq!(empty.outcome, JournalRecoveryOutcomeV1::Clean);
        assert_eq!(empty.records_recovered, 0);

        let ack = append_event(&mut journal, &epoch("epoch:clean"), "event:one", 10);
        assert_eq!(ack.record_sequence, 1);
        assert!(ack.data_sync_completed);
        assert!(ack.commit_sync_completed);
        assert!(ack.acknowledgement_returned);
        assert!(!ack.physical_media_durability_claimed);
        drop(journal);
        let report = HistoricalJournal::scan(&path, &config).expect("scan clean");
        assert_eq!(report.outcome, JournalRecoveryOutcomeV1::Clean);
        assert_eq!(report.records_recovered, 1);
        assert!(report.history_complete);
        fs::remove_file(path).expect("remove fixture");
    }

    #[test]
    fn truncation_at_every_byte_never_turns_a_partial_record_into_history() {
        let source = temp_path("truncate-source");
        let cut_path = temp_path("truncate-cut");
        let config = config("journal:truncate");
        let mut journal = HistoricalJournal::create_new(&source, config.clone()).expect("create");
        let epoch = epoch("epoch:truncate");
        append_event(&mut journal, &epoch, "event:one", 1);
        let first_boundary = fs::metadata(&source).expect("metadata").len() as usize;
        append_event(&mut journal, &epoch, "event:two", 2);
        drop(journal);
        let complete = fs::read(&source).expect("read complete journal");
        for cut in 0..=complete.len() {
            fs::write(&cut_path, &complete[..cut]).expect("write cut fixture");
            let report = HistoricalJournal::scan(&cut_path, &config).expect("scan cut");
            if cut == 0 {
                assert_eq!(report.outcome, JournalRecoveryOutcomeV1::Clean);
                assert_eq!(report.records_recovered, 0);
            } else if cut == first_boundary {
                assert_eq!(report.outcome, JournalRecoveryOutcomeV1::Clean);
                assert_eq!(report.records_recovered, 1);
            } else if cut == complete.len() {
                assert_eq!(report.outcome, JournalRecoveryOutcomeV1::Clean);
                assert_eq!(report.records_recovered, 2);
            } else {
                assert_ne!(report.outcome, JournalRecoveryOutcomeV1::Clean);
                assert!(!report.history_complete);
                assert!(report.operator_action_required);
                assert!(report.records_recovered <= usize::from(cut > first_boundary));
            }
        }
        fs::remove_file(source).expect("remove source");
        fs::remove_file(cut_path).expect("remove cut");
    }

    #[test]
    fn interior_corruption_stops_before_later_valid_looking_bytes() {
        let source = temp_path("interior-source");
        let corrupt = temp_path("interior-corrupt");
        let config = config("journal:interior");
        let mut journal = HistoricalJournal::create_new(&source, config.clone()).expect("create");
        let epoch = epoch("epoch:interior");
        append_event(&mut journal, &epoch, "event:one", 1);
        let first_boundary = fs::metadata(&source).expect("metadata").len() as usize;
        append_event(&mut journal, &epoch, "event:two", 2);
        append_event(&mut journal, &epoch, "event:three", 3);
        drop(journal);
        let mut bytes = fs::read(&source).expect("read journal");
        bytes[first_boundary + HEADER_BYTES + 10] ^= 0x01;
        fs::write(&corrupt, bytes).expect("write corrupt journal");
        let report = HistoricalJournal::scan(&corrupt, &config).expect("scan corrupt");
        assert_eq!(report.outcome, JournalRecoveryOutcomeV1::Refused);
        assert_eq!(
            report.damage,
            Some(JournalDamageClassV1::InteriorCorruption)
        );
        assert_eq!(report.records_recovered, 1);
        assert!(!report.history_complete);
        fs::remove_file(source).expect("remove source");
        fs::remove_file(corrupt).expect("remove corrupt");
    }

    #[test]
    fn duplicated_reordered_skipped_and_stale_frames_are_refused() {
        let source = temp_path("sequence-source");
        let mutated = temp_path("sequence-mutated");
        let config = config("journal:sequence");
        let mut journal = HistoricalJournal::create_new(&source, config.clone()).expect("create");
        let epoch = epoch("epoch:sequence");
        append_event(&mut journal, &epoch, "event:one", 1);
        let first_boundary = fs::metadata(&source).expect("metadata").len() as usize;
        append_event(&mut journal, &epoch, "event:two", 2);
        drop(journal);
        let bytes = fs::read(&source).expect("read journal");

        let mut duplicate = bytes.clone();
        duplicate.extend_from_slice(&bytes[..first_boundary]);
        fs::write(&mutated, duplicate).expect("write duplicate");
        let report = HistoricalJournal::scan(&mutated, &config).expect("scan duplicate");
        assert_eq!(report.damage, Some(JournalDamageClassV1::DuplicateRecord));

        fs::write(&mutated, &bytes[first_boundary..]).expect("write skipped/reordered");
        let report = HistoricalJournal::scan(&mutated, &config).expect("scan skipped");
        assert_eq!(
            report.damage,
            Some(JournalDamageClassV1::SequenceDiscontinuity)
        );

        let mut stale = bytes.clone();
        stale.extend_from_slice(&bytes[..first_boundary]);
        fs::write(&mutated, stale).expect("write stale replay");
        let report = HistoricalJournal::scan(&mutated, &config).expect("scan stale");
        assert_eq!(report.damage, Some(JournalDamageClassV1::DuplicateRecord));
        fs::remove_file(source).expect("remove source");
        fs::remove_file(mutated).expect("remove mutation");
    }

    #[test]
    fn unsupported_version_oversized_length_and_trailing_bytes_are_explicit() {
        let source = temp_path("header-source");
        let mutated = temp_path("header-mutated");
        let config = config("journal:header");
        let mut journal = HistoricalJournal::create_new(&source, config.clone()).expect("create");
        append_event(&mut journal, &epoch("epoch:header"), "event:one", 1);
        drop(journal);
        let bytes = fs::read(&source).expect("read journal");

        let mut unsupported = bytes.clone();
        unsupported[9] = 2;
        fs::write(&mutated, unsupported).expect("write unsupported");
        assert_eq!(
            HistoricalJournal::scan(&mutated, &config)
                .expect("scan")
                .damage,
            Some(JournalDamageClassV1::UnsupportedVersion)
        );

        let mut oversized = bytes.clone();
        oversized[20..24].copy_from_slice(&(u32::MAX).to_be_bytes());
        fs::write(&mutated, oversized).expect("write oversized");
        assert_eq!(
            HistoricalJournal::scan(&mutated, &config)
                .expect("scan")
                .damage,
            Some(JournalDamageClassV1::OversizedDeclaredLength)
        );

        let mut trailing = bytes;
        trailing.extend_from_slice(b"unexpected");
        fs::write(&mutated, trailing).expect("write trailing");
        let trailing_report = HistoricalJournal::scan(&mutated, &config).expect("scan trailing");
        assert_eq!(
            trailing_report.outcome,
            JournalRecoveryOutcomeV1::RecoveredThroughValidPrefix
        );
        assert_eq!(
            trailing_report.damage,
            Some(JournalDamageClassV1::UnexpectedTrailingBytes)
        );
        assert_eq!(trailing_report.records_recovered, 1);
        fs::remove_file(source).expect("remove source");
        fs::remove_file(mutated).expect("remove mutation");
    }

    #[test]
    fn record_and_file_bounds_refuse_before_an_extra_append() {
        let path = temp_path("bounds");
        let mut config = config("journal:bounds");
        config.bounds.maximum_records = 1;
        let mut journal = HistoricalJournal::create_new(&path, config).expect("create");
        let epoch = epoch("epoch:bounds");
        append_event(&mut journal, &epoch, "event:one", 1);
        let error = journal
            .append(
                epoch,
                2,
                None,
                event("event:two", 2),
                JournalDurabilityModeV1::FileSynced,
            )
            .expect_err("record bound refuses");
        assert_eq!(error.class, JournalErrorClassV1::BoundExceeded);
        fs::remove_file(path).expect("remove fixture");
    }

    #[test]
    fn injected_io_failure_latches_append_and_leaves_detectable_damage() {
        let path = temp_path("io-failure");
        let config = config("journal:io-failure");
        let mut journal = HistoricalJournal::create_new(&path, config.clone()).expect("create");
        let mut hook = |stage| {
            if stage == JournalWriteStageV1::PayloadPartiallyWritten {
                Err(io::Error::other("injected payload write failure"))
            } else {
                Ok(())
            }
        };
        let error = journal
            .append_with_qualification_hook(
                epoch("epoch:io-failure"),
                1,
                None,
                event("event:one", 1),
                JournalDurabilityModeV1::FileSynced,
                &mut hook,
            )
            .expect_err("injected failure returns no ack");
        assert_eq!(error.class, JournalErrorClassV1::IoFailure);
        let second = journal
            .append(
                epoch("epoch:io-failure"),
                2,
                None,
                event("event:two", 2),
                JournalDurabilityModeV1::FileSynced,
            )
            .expect_err("failed journal cannot append again");
        assert_eq!(second.class, JournalErrorClassV1::DamagedJournal);
        drop(journal);
        let report = HistoricalJournal::scan(&path, &config).expect("scan damage");
        assert!(!report.history_complete);
        assert_eq!(report.records_recovered, 0);
        fs::remove_file(path).expect("remove fixture");
    }

    #[test]
    fn different_monotonic_epochs_remain_provenance_not_elapsed_time() {
        let path = temp_path("epochs");
        let config = config("journal:epochs");
        let mut journal = HistoricalJournal::create_new(&path, config.clone()).expect("create");
        append_event(&mut journal, &epoch("epoch:one"), "event:one", 900);
        append_event(&mut journal, &epoch("epoch:two"), "event:two", 1);
        let receipt = receipt();
        journal
            .append(
                epoch("epoch:two"),
                2,
                None,
                JournalRecordBodyV1::DiagnosticReceipt {
                    receipt: receipt.clone(),
                },
                JournalDurabilityModeV1::FileSynced,
            )
            .expect("receipt append");
        drop(journal);
        let report = HistoricalJournal::scan(&path, &config).expect("scan");
        assert_eq!(report.outcome, JournalRecoveryOutcomeV1::Clean);
        assert_ne!(
            report.records[0].monotonic_epoch.epoch_id,
            report.records[1].monotonic_epoch.epoch_id
        );
        let projection = report.project_history().expect("project history");
        assert_eq!(projection.history.diagnostic_receipts, vec![receipt]);
        assert!(!projection.current_standing_reconstructed);
        assert!(!projection.active_escalation_suppression_restored);
        fs::remove_file(path).expect("remove fixture");
    }

    proptest! {
        #[test]
        fn bounded_arbitrary_bytes_never_create_unbounded_or_current_state(
            bytes in proptest::collection::vec(any::<u8>(), 0..2_048),
        ) {
            let config = config("journal:arbitrary-bytes");
            let report = scan_bytes(&bytes, &config);
            prop_assert!(report.records_recovered <= config.bounds.maximum_records);
            prop_assert_eq!(report.records_recovered, report.records.len());
            if report.outcome != JournalRecoveryOutcomeV1::Clean {
                prop_assert!(!report.history_complete);
                prop_assert!(report.operator_action_required);
            }
            match report.outcome {
                JournalRecoveryOutcomeV1::Refused => {
                    let error = report.project_history().expect_err("refused damage cannot project");
                    prop_assert_eq!(error.class, JournalErrorClassV1::DamagedJournal);
                }
                JournalRecoveryOutcomeV1::Clean
                | JournalRecoveryOutcomeV1::RecoveredThroughValidPrefix => {
                    let projection = report.project_history().expect("permitted history projects");
                    prop_assert_eq!(projection.recovery_outcome, report.outcome);
                    prop_assert_eq!(projection.history_complete, report.history_complete);
                    prop_assert!(!projection.current_standing_reconstructed);
                    prop_assert!(!projection.active_escalation_suppression_restored);
                }
            }
        }
    }
}
