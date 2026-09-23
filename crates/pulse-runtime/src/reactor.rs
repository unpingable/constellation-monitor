//! One local monotonic actor that owns waking for deterministic runtime deadlines.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
#[cfg(unix)]
use std::io::{Read as _, Write as _};
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::net::UnixStream;

use pulse_types::{
    ConsumerId, DigestV1, JudgmentCategoryV1, LivePresentSupportDispositionV1,
    LivePresentSupportRequestV1, LivePresentSupportResponseV1,
    MAX_LIVE_PRESENT_SUPPORT_REQUEST_BYTES, MAX_LIVE_PRESENT_SUPPORT_RESPONSE_BYTES,
    MutationAuthorityV1, QualifiedGenerationBindingV1, RelianceSupportCertificateV1,
    RuntimeMetricsV1, SCHEMA_VERSION_V1, SparseDurableEventKindV1, SparseDurableEventV1, SubjectId,
    TransportCustodyPolicyBindingV1, digest_parts,
};
use serde::{Deserialize, Serialize};

use crate::{
    HistoricalJournal, JournalAppendAckV1, JournalDurabilityModeV1, JournalError,
    JournalRecordBodyV1, MonotonicEpochV1, ReceiverSchedulerRuntime, RuntimeCycleOutputV1,
    RuntimeInputV1,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReactorConfigV1 {
    pub schema_version: u16,
    pub maximum_pending_commands: usize,
    pub command_response_timeout_ms: u64,
    pub deliberate_deadline_delay_ms: u64,
    pub journal_durability: JournalDurabilityModeV1,
}

impl ReactorConfigV1 {
    #[must_use]
    pub const fn qualification() -> Self {
        Self {
            schema_version: SCHEMA_VERSION_V1,
            maximum_pending_commands: 32,
            command_response_timeout_ms: 5_000,
            deliberate_deadline_delay_ms: 0,
            journal_durability: JournalDurabilityModeV1::FileSynced,
        }
    }

    fn validate(self) -> Result<(), ReactorCommandError> {
        if self.schema_version != SCHEMA_VERSION_V1 {
            return Err(ReactorCommandError::new(
                ReactorCommandErrorClassV1::InvalidConfig,
                "reactor config schema is unsupported",
            ));
        }
        if self.maximum_pending_commands == 0 || self.command_response_timeout_ms == 0 {
            return Err(ReactorCommandError::new(
                ReactorCommandErrorClassV1::InvalidConfig,
                "reactor command and response bounds must be nonzero",
            ));
        }
        if self.deliberate_deadline_delay_ms > 60_000 {
            return Err(ReactorCommandError::new(
                ReactorCommandErrorClassV1::InvalidConfig,
                "qualification delay exceeds its one-minute safety bound",
            ));
        }
        Ok(())
    }
}

impl Default for ReactorConfigV1 {
    fn default() -> Self {
        Self::qualification()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReactorConditionV1 {
    Starting,
    Operational,
    MailboxOverloaded,
    ExplicitBlindness,
    WakeupFailure,
    ActorTerminated,
    JournalFailure,
    CommandChannelClosed,
    ShuttingDown,
    Terminated,
}

impl ReactorConditionV1 {
    #[must_use]
    pub const fn exposes_live_standing(self) -> bool {
        matches!(self, Self::Operational)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReactorMetricsV1 {
    pub schema_version: u16,
    pub wakeup_count: u64,
    pub command_wakeup_count: u64,
    pub deadline_wakeup_count: u64,
    pub early_wakeup_count: u64,
    pub deadline_withdrawal_count: u64,
    pub mailbox_refusal_count: u64,
    pub wakeup_failure_count: u64,
    pub journal_failure_count: u64,
    pub last_wakeup_lateness_ms: u64,
    pub maximum_wakeup_lateness_ms: u64,
    pub last_journal_append_latency_us: u128,
    pub maximum_journal_append_latency_us: u128,
    pub last_journal_sync_latency_us: u128,
    pub maximum_journal_sync_latency_us: u128,
    pub committed_journal_record_count: u64,
}

impl ReactorMetricsV1 {
    const fn empty() -> Self {
        Self {
            schema_version: SCHEMA_VERSION_V1,
            wakeup_count: 0,
            command_wakeup_count: 0,
            deadline_wakeup_count: 0,
            early_wakeup_count: 0,
            deadline_withdrawal_count: 0,
            mailbox_refusal_count: 0,
            wakeup_failure_count: 0,
            journal_failure_count: 0,
            last_wakeup_lateness_ms: 0,
            maximum_wakeup_lateness_ms: 0,
            last_journal_append_latency_us: 0,
            maximum_journal_append_latency_us: 0,
            last_journal_sync_latency_us: 0,
            maximum_journal_sync_latency_us: 0,
            committed_journal_record_count: 0,
        }
    }

    fn observe_append(&mut self, ack: &JournalAppendAckV1) {
        self.last_journal_append_latency_us = ack.append_latency_us;
        self.maximum_journal_append_latency_us = self
            .maximum_journal_append_latency_us
            .max(ack.append_latency_us);
        self.last_journal_sync_latency_us = ack.sync_latency_us;
        self.maximum_journal_sync_latency_us = self
            .maximum_journal_sync_latency_us
            .max(ack.sync_latency_us);
        self.committed_journal_record_count = self.committed_journal_record_count.saturating_add(1);
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReactorSnapshotV1 {
    pub schema_version: u16,
    pub monotonic_epoch: MonotonicEpochV1,
    pub observed_at_epoch_monotonic_ms: u64,
    pub condition: ReactorConditionV1,
    pub condition_detail: String,
    pub live_standing_available: bool,
    pub certificates: Vec<RelianceSupportCertificateV1>,
    pub active_deadline_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub earliest_deadline_monotonic_ms: Option<u64>,
    pub supporting_evidence_count: usize,
    pub runtime_metrics: RuntimeMetricsV1,
    pub reactor_metrics: ReactorMetricsV1,
    pub clean_shutdown: bool,
    pub mutation_authority: MutationAuthorityV1,
}

impl ReactorSnapshotV1 {
    fn unavailable(
        epoch: MonotonicEpochV1,
        observed_at: u64,
        condition: ReactorConditionV1,
        detail: impl Into<String>,
        runtime_metrics: RuntimeMetricsV1,
        reactor_metrics: ReactorMetricsV1,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION_V1,
            monotonic_epoch: epoch,
            observed_at_epoch_monotonic_ms: observed_at,
            condition,
            condition_detail: detail.into(),
            live_standing_available: false,
            certificates: Vec::new(),
            active_deadline_count: 0,
            earliest_deadline_monotonic_ms: None,
            supporting_evidence_count: 0,
            runtime_metrics,
            reactor_metrics,
            clean_shutdown: false,
            mutation_authority: MutationAuthorityV1::None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReactorCommandErrorClassV1 {
    InvalidConfig,
    InvalidRequest,
    QueueSaturated,
    NotOperational,
    ResponseTimeout,
    ActorTerminated,
    RuntimeFailure,
    JournalFailure,
    ThreadSpawnFailure,
    TransportFailure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReactorCommandError {
    pub class: ReactorCommandErrorClassV1,
    pub detail: String,
}

impl ReactorCommandError {
    fn new(class: ReactorCommandErrorClassV1, detail: impl Into<String>) -> Self {
        Self {
            class,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for ReactorCommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.class, self.detail)
    }
}

impl std::error::Error for ReactorCommandError {}

#[derive(Clone)]
struct ReactorClock {
    origin: Instant,
    origin_runtime_monotonic_ms: u64,
}

impl ReactorClock {
    fn now_ms(&self) -> u64 {
        self.origin_runtime_monotonic_ms
            .saturating_add(u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX))
    }
}

enum ActorCommand {
    RuntimeInput {
        admitted_at_monotonic_ms: u64,
        input: Box<RuntimeInputV1>,
        response: SyncSender<Result<RuntimeCycleOutputV1, ReactorCommandError>>,
    },
    DeclareBlindness {
        admitted_at_monotonic_ms: u64,
        detail: String,
        response: SyncSender<Result<RuntimeCycleOutputV1, ReactorCommandError>>,
    },
}

struct LiveSupportQueryCommand {
    request: LivePresentSupportRequestV1,
    response: SyncSender<Result<LivePresentSupportResponseV1, ReactorCommandError>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReactorQualificationPointV1 {
    BeforeDeadlineArming,
    AfterDeadlineArming,
    DeadlineDueBeforeProcessing,
    DeadlineProcessedBeforeJournal,
    CleanShutdownBegan,
}

type ReactorQualificationHook = Box<dyn FnMut(ReactorQualificationPointV1) + Send + 'static>;

struct SharedState {
    queue: VecDeque<ActorCommand>,
    live_support_queries: VecDeque<LiveSupportQueryCommand>,
    accepting_commands: bool,
    overload_latched: bool,
    response_timeout_latched: bool,
    abandoned: bool,
    shutdown_requested: bool,
    snapshot: ReactorSnapshotV1,
}

struct JournalSink {
    journal: HistoricalJournal,
    epoch: MonotonicEpochV1,
    durability: JournalDurabilityModeV1,
    seen_sparse_events: BTreeSet<pulse_types::SparseEventId>,
    seen_receipts: BTreeSet<pulse_types::DiagnosticReceiptId>,
    contradiction_versions: BTreeMap<
        (
            pulse_types::SubjectId,
            pulse_types::ConsumerId,
            pulse_types::ContradictionId,
        ),
        DigestV1,
    >,
}

impl JournalSink {
    fn new(
        journal: HistoricalJournal,
        epoch: MonotonicEpochV1,
        durability: JournalDurabilityModeV1,
    ) -> Result<Self, ReactorCommandError> {
        let mut seen_sparse_events = BTreeSet::new();
        let mut seen_receipts = BTreeSet::new();
        let mut contradiction_versions = BTreeMap::new();
        for record in journal.committed_records() {
            match &record.body {
                JournalRecordBodyV1::SparseEvent { event } => {
                    seen_sparse_events.insert(event.event_id.clone());
                }
                JournalRecordBodyV1::DiagnosticReceipt { receipt } => {
                    seen_receipts.insert(receipt.receipt_id.clone());
                }
                JournalRecordBodyV1::ContradictionCustody { custody } => {
                    let key = (
                        custody.contradiction.subject_scope.subject.clone(),
                        custody.consumer.clone(),
                        custody.contradiction.contradiction_id.clone(),
                    );
                    contradiction_versions.insert(key, custody_digest(custody)?);
                }
            }
        }
        Ok(Self {
            journal,
            epoch,
            durability,
            seen_sparse_events,
            seen_receipts,
            contradiction_versions,
        })
    }

    fn capture(
        &mut self,
        runtime: &ReceiverSchedulerRuntime,
        output: &RuntimeCycleOutputV1,
        now: u64,
        metrics: &mut ReactorMetricsV1,
    ) -> Result<(), ReactorCommandError> {
        for event in &output.sparse_events {
            self.append_sparse(event.clone(), now, metrics)?;
        }
        let history = runtime.export_history();
        for event in history.sparse_events {
            self.append_sparse(event, now, metrics)?;
        }
        for custody in history.contradictions {
            let key = (
                custody.contradiction.subject_scope.subject.clone(),
                custody.consumer.clone(),
                custody.contradiction.contradiction_id.clone(),
            );
            let digest = custody_digest(&custody)?;
            if self.contradiction_versions.get(&key) == Some(&digest) {
                continue;
            }
            let ack = self
                .journal
                .append(
                    self.epoch.clone(),
                    now,
                    None,
                    JournalRecordBodyV1::ContradictionCustody {
                        custody: custody.clone(),
                    },
                    self.durability,
                )
                .map_err(ReactorCommandError::from_journal)?;
            metrics.observe_append(&ack);
            self.contradiction_versions.insert(key, digest);
        }
        for receipt in history.diagnostic_receipts {
            if self.seen_receipts.contains(&receipt.receipt_id) {
                continue;
            }
            let ack = self
                .journal
                .append(
                    self.epoch.clone(),
                    now,
                    None,
                    JournalRecordBodyV1::DiagnosticReceipt {
                        receipt: receipt.clone(),
                    },
                    self.durability,
                )
                .map_err(ReactorCommandError::from_journal)?;
            metrics.observe_append(&ack);
            self.seen_receipts.insert(receipt.receipt_id);
        }
        Ok(())
    }

    fn append_sparse(
        &mut self,
        event: SparseDurableEventV1,
        now: u64,
        metrics: &mut ReactorMetricsV1,
    ) -> Result<(), ReactorCommandError> {
        if self.seen_sparse_events.contains(&event.event_id) {
            return Ok(());
        }
        let context = sparse_context_digest(&event);
        let ack = self
            .journal
            .append(
                self.epoch.clone(),
                now,
                context,
                JournalRecordBodyV1::SparseEvent {
                    event: event.clone(),
                },
                self.durability,
            )
            .map_err(ReactorCommandError::from_journal)?;
        metrics.observe_append(&ack);
        self.seen_sparse_events.insert(event.event_id);
        Ok(())
    }
}

impl ReactorCommandError {
    fn from_journal(error: JournalError) -> Self {
        Self::new(
            ReactorCommandErrorClassV1::JournalFailure,
            error.to_string(),
        )
    }
}

fn custody_digest(
    custody: &pulse_types::ContradictionCustodyV1,
) -> Result<DigestV1, ReactorCommandError> {
    let bytes = serde_json::to_vec(custody).map_err(|error| {
        ReactorCommandError::new(
            ReactorCommandErrorClassV1::JournalFailure,
            format!("contradiction custody encoding failed: {error}"),
        )
    })?;
    Ok(digest_parts("runtime.contradiction-custody.v1", &[&bytes]))
}

fn sparse_context_digest(event: &SparseDurableEventV1) -> Option<DigestV1> {
    match &event.event {
        SparseDurableEventKindV1::RelianceContextTransition { transition } => {
            Some(transition.new_context.identity_digest())
        }
        SparseDurableEventKindV1::SupportCertificateIssued { certificate } => {
            Some(certificate.context.identity_digest())
        }
        _ => None,
    }
}

pub struct LocalCrashReactor {
    shared: Arc<(Mutex<SharedState>, Condvar)>,
    clock: ReactorClock,
    config: ReactorConfigV1,
    journal_path: PathBuf,
    transport_custody_policy: Option<TransportCustodyPolicyBindingV1>,
    join: Option<JoinHandle<()>>,
}

impl LocalCrashReactor {
    pub fn start(
        runtime: ReceiverSchedulerRuntime,
        journal: HistoricalJournal,
        epoch: MonotonicEpochV1,
        config: ReactorConfigV1,
    ) -> Result<Self, ReactorCommandError> {
        Self::start_inner(runtime, journal, epoch, config, None)
    }

    pub(crate) fn start_with_qualification_hook(
        runtime: ReceiverSchedulerRuntime,
        journal: HistoricalJournal,
        epoch: MonotonicEpochV1,
        config: ReactorConfigV1,
        hook: ReactorQualificationHook,
    ) -> Result<Self, ReactorCommandError> {
        Self::start_inner(runtime, journal, epoch, config, Some(hook))
    }

    fn start_inner(
        runtime: ReceiverSchedulerRuntime,
        journal: HistoricalJournal,
        epoch: MonotonicEpochV1,
        config: ReactorConfigV1,
        qualification_hook: Option<ReactorQualificationHook>,
    ) -> Result<Self, ReactorCommandError> {
        config.validate()?;
        let transport_custody_policy = runtime.config().transport_custody_policy.clone();
        epoch
            .validate()
            .map_err(ReactorCommandError::from_journal)?;
        if epoch.receiver != runtime.config().receiver
            || epoch.receiver_incarnation != runtime.config().receiver_incarnation
            || epoch.clock_id != runtime.config().clock_id
            || epoch.origin_runtime_monotonic_ms != runtime.current_monotonic_ms()
        {
            return Err(ReactorCommandError::new(
                ReactorCommandErrorClassV1::InvalidConfig,
                "reactor epoch does not exactly bind runtime receiver lineage and origin",
            ));
        }
        let journal_path = journal.path().to_path_buf();
        let clock = ReactorClock {
            origin: Instant::now(),
            origin_runtime_monotonic_ms: epoch.origin_runtime_monotonic_ms,
        };
        let metrics = ReactorMetricsV1::empty();
        let initial_snapshot = snapshot_from_runtime(
            &runtime,
            epoch.clone(),
            clock.now_ms(),
            ReactorConditionV1::Starting,
            "reactor thread has not entered its wake loop",
            metrics.clone(),
        );
        let shared = Arc::new((
            Mutex::new(SharedState {
                queue: VecDeque::new(),
                live_support_queries: VecDeque::new(),
                accepting_commands: true,
                overload_latched: false,
                response_timeout_latched: false,
                abandoned: false,
                shutdown_requested: false,
                snapshot: initial_snapshot,
            }),
            Condvar::new(),
        ));
        let thread_shared = Arc::clone(&shared);
        let thread_clock = clock.clone();
        let thread_epoch = epoch;
        let guard_epoch = thread_epoch.clone();
        let guard_clock = thread_clock.clone();
        let guard_shared = Arc::clone(&thread_shared);
        let thread_config = config;
        let join = thread::Builder::new()
            .name("pulse-local-crash-reactor".to_owned())
            .spawn(move || {
                guard_actor_unwind(&guard_shared, &guard_epoch, &guard_clock, || {
                    actor_main(
                        runtime,
                        journal,
                        thread_epoch,
                        thread_config,
                        thread_clock,
                        thread_shared,
                        qualification_hook,
                    );
                });
            })
            .map_err(|error| {
                ReactorCommandError::new(
                    ReactorCommandErrorClassV1::ThreadSpawnFailure,
                    format!("reactor thread spawn failed: {error}"),
                )
            })?;
        Ok(Self {
            shared,
            clock,
            config,
            journal_path,
            transport_custody_policy,
            join: Some(join),
        })
    }

    /// Ask the live actor to remeasure and revalidate the exact local
    /// activation used by a transport custody policy. Historical activation
    /// receipts and a caller-provided generation label cannot satisfy this
    /// gate.
    pub fn revalidate_transport_activation(
        &self,
        subject: &SubjectId,
        consumer: &ConsumerId,
        expected_policy: &TransportCustodyPolicyBindingV1,
    ) -> Result<QualifiedGenerationBindingV1, ReactorCommandError> {
        expected_policy.validate().map_err(|error| {
            ReactorCommandError::new(
                ReactorCommandErrorClassV1::InvalidConfig,
                format!("invalid transport custody policy binding: {error}"),
            )
        })?;
        if self.transport_custody_policy.as_ref() != Some(expected_policy) {
            return Err(ReactorCommandError::new(
                ReactorCommandErrorClassV1::InvalidConfig,
                "transport custody policy does not exactly match the activated runtime configuration",
            ));
        }
        if !self.snapshot().condition.exposes_live_standing() {
            return Err(ReactorCommandError::new(
                ReactorCommandErrorClassV1::NotOperational,
                "reactor cannot attest a live local activation while temporal custody is unavailable",
            ));
        }
        let output = self.submit_input(RuntimeInputV1::RevalidateTransportActivation {
            subject: subject.clone(),
            consumer: consumer.clone(),
            expected_policy: expected_policy.clone(),
        })?;
        if !self.snapshot().condition.exposes_live_standing() {
            return Err(ReactorCommandError::new(
                ReactorCommandErrorClassV1::NotOperational,
                "reactor lost temporal custody during activation revalidation",
            ));
        }
        output
            .certificates
            .iter()
            .rev()
            .find(|certificate| {
                &certificate.subject_scope.subject == subject && &certificate.consumer == consumer
            })
            .and_then(|certificate| certificate.qualified_generation.clone())
            .ok_or_else(|| {
                ReactorCommandError::new(
                    ReactorCommandErrorClassV1::NotOperational,
                    "live actor did not establish an exact QualifiedAndMatched activation",
                )
            })
    }

    pub fn submit_input(
        &self,
        input: RuntimeInputV1,
    ) -> Result<RuntimeCycleOutputV1, ReactorCommandError> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let command = ActorCommand::RuntimeInput {
            admitted_at_monotonic_ms: self.clock.now_ms(),
            input: Box::new(input),
            response: sender,
        };
        self.submit_command(command)?;
        match receiver.recv_timeout(Duration::from_millis(
            self.config.command_response_timeout_ms,
        )) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.latch_response_timeout();
                Err(ReactorCommandError::new(
                    ReactorCommandErrorClassV1::ResponseTimeout,
                    "reactor command response exceeded its configured wait bound",
                ))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(ReactorCommandError::new(
                ReactorCommandErrorClassV1::ActorTerminated,
                "reactor terminated before returning the command result",
            )),
        }
    }

    pub fn declare_blindness(
        &self,
        detail: impl Into<String>,
    ) -> Result<RuntimeCycleOutputV1, ReactorCommandError> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let command = ActorCommand::DeclareBlindness {
            admitted_at_monotonic_ms: self.clock.now_ms(),
            detail: detail.into(),
            response: sender,
        };
        self.submit_command(command)?;
        match receiver.recv_timeout(Duration::from_millis(
            self.config.command_response_timeout_ms,
        )) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.latch_response_timeout();
                Err(ReactorCommandError::new(
                    ReactorCommandErrorClassV1::ResponseTimeout,
                    "reactor blindness response exceeded its configured wait bound",
                ))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(ReactorCommandError::new(
                ReactorCommandErrorClassV1::ActorTerminated,
                "reactor terminated before confirming blindness",
            )),
        }
    }

    /// Ask the actor whether one exact support certificate remains current.
    /// This read-only query uses a separate bounded lane: query saturation or
    /// timeout cannot latch reactor blindness or supply a new runtime input.
    /// The actor still applies its ordinary time-driven transitions before it
    /// measures the answer, so an already-due expiry can withdraw support.
    pub fn query_live_present_support(
        &self,
        request: LivePresentSupportRequestV1,
    ) -> Result<LivePresentSupportResponseV1, ReactorCommandError> {
        request.validate().map_err(|error| {
            ReactorCommandError::new(
                ReactorCommandErrorClassV1::InvalidRequest,
                error.to_string(),
            )
        })?;
        let expected_request = request.clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        self.submit_live_support_query(LiveSupportQueryCommand {
            request,
            response: sender,
        })?;
        match receiver.recv_timeout(Duration::from_millis(
            self.config.command_response_timeout_ms,
        )) {
            Ok(result) => result.and_then(|response| {
                response
                    .validate_against(&expected_request)
                    .map_err(|error| {
                        ReactorCommandError::new(
                            ReactorCommandErrorClassV1::RuntimeFailure,
                            error.to_string(),
                        )
                    })?;
                Ok(response)
            }),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(ReactorCommandError::new(
                ReactorCommandErrorClassV1::ResponseTimeout,
                "live present-support response exceeded its wait bound; reactor custody was not changed",
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(ReactorCommandError::new(
                ReactorCommandErrorClassV1::ActorTerminated,
                "reactor terminated before returning the live present-support response",
            )),
        }
    }

    /// Canonical byte boundary for a bounded local process transport. The
    /// caller owns channel authentication, request timing, and conservative
    /// subtraction of elapsed time from the returned duration.
    pub fn query_live_present_support_canonical(
        &self,
        request_bytes: &[u8],
    ) -> Result<Vec<u8>, ReactorCommandError> {
        if request_bytes.len() > MAX_LIVE_PRESENT_SUPPORT_REQUEST_BYTES {
            return Err(ReactorCommandError::new(
                ReactorCommandErrorClassV1::InvalidRequest,
                "live present-support request exceeds its byte bound",
            ));
        }
        let request =
            LivePresentSupportRequestV1::decode_canonical(request_bytes).map_err(|error| {
                ReactorCommandError::new(ReactorCommandErrorClassV1::InvalidRequest, error)
            })?;
        let response = self.query_live_present_support(request)?;
        let bytes = response.canonical_bytes().map_err(|error| {
            ReactorCommandError::new(ReactorCommandErrorClassV1::RuntimeFailure, error)
        })?;
        if bytes.len() > MAX_LIVE_PRESENT_SUPPORT_RESPONSE_BYTES {
            return Err(ReactorCommandError::new(
                ReactorCommandErrorClassV1::RuntimeFailure,
                "live present-support response exceeds its byte bound",
            ));
        }
        Ok(bytes)
    }

    /// Serve exactly one canonical request on an already accepted local Unix
    /// stream. Listener ownership, pathname permissions, and peer identity are
    /// deployment concerns; this method adds no listener or server loop.
    #[cfg(unix)]
    pub fn serve_live_present_support_stream(
        &self,
        stream: &mut UnixStream,
        timeout: Duration,
    ) -> Result<(), ReactorCommandError> {
        with_nonblocking_stream(stream, timeout, |stream, deadline| {
            let request =
                read_live_support_frame(stream, MAX_LIVE_PRESENT_SUPPORT_REQUEST_BYTES, deadline)?;
            let response = self.query_live_present_support_canonical(&request)?;
            write_live_support_frame(
                stream,
                &response,
                MAX_LIVE_PRESENT_SUPPORT_RESPONSE_BYTES,
                deadline,
            )
        })
    }

    fn submit_live_support_query(
        &self,
        query: LiveSupportQueryCommand,
    ) -> Result<(), ReactorCommandError> {
        let (mutex, condvar) = &*self.shared;
        let mut shared = mutex.lock().map_err(|_| {
            ReactorCommandError::new(
                ReactorCommandErrorClassV1::ActorTerminated,
                "reactor shared state is poisoned",
            )
        })?;
        if !shared.accepting_commands {
            return Err(ReactorCommandError::new(
                ReactorCommandErrorClassV1::NotOperational,
                "reactor live-query boundary is closed",
            ));
        }
        if shared.live_support_queries.len() >= self.config.maximum_pending_commands {
            return Err(ReactorCommandError::new(
                ReactorCommandErrorClassV1::QueueSaturated,
                "bounded live-query lane is full; reactor custody was not changed",
            ));
        }
        shared.live_support_queries.push_back(query);
        condvar.notify_one();
        Ok(())
    }

    pub fn report_receiver_boundary_condition(
        &self,
        subject: Option<SubjectId>,
        finding: pulse_types::TransportCustodyFindingV1,
        session_binding_digest: Option<DigestV1>,
        detail: impl Into<String>,
        withdraw: bool,
    ) -> Result<RuntimeCycleOutputV1, ReactorCommandError> {
        let detail = detail.into();
        let mut output = self.submit_input(RuntimeInputV1::ReceiverBoundaryCondition {
            subject,
            finding,
            session_binding_digest,
            detail: detail.clone(),
            withdraw,
        })?;
        if withdraw {
            output.append(
                self.declare_blindness(format!("receiver-boundary {finding:?}: {detail}"))?,
            );
        }
        Ok(output)
    }

    fn submit_command(&self, command: ActorCommand) -> Result<(), ReactorCommandError> {
        let (mutex, condvar) = &*self.shared;
        let mut shared = mutex.lock().map_err(|_| {
            ReactorCommandError::new(
                ReactorCommandErrorClassV1::ActorTerminated,
                "reactor shared state is poisoned",
            )
        })?;
        if !shared.accepting_commands {
            return Err(ReactorCommandError::new(
                ReactorCommandErrorClassV1::NotOperational,
                "reactor command boundary is closed",
            ));
        }
        if shared.queue.len() >= self.config.maximum_pending_commands {
            shared.overload_latched = true;
            shared.snapshot.condition = ReactorConditionV1::MailboxOverloaded;
            shared.snapshot.condition_detail =
                "bounded reactor command mailbox saturated".to_owned();
            shared.snapshot.live_standing_available = false;
            shared.snapshot.certificates.clear();
            shared.snapshot.active_deadline_count = 0;
            shared.snapshot.earliest_deadline_monotonic_ms = None;
            shared.snapshot.supporting_evidence_count = 0;
            shared.snapshot.reactor_metrics.mailbox_refusal_count = shared
                .snapshot
                .reactor_metrics
                .mailbox_refusal_count
                .saturating_add(1);
            condvar.notify_one();
            return Err(ReactorCommandError::new(
                ReactorCommandErrorClassV1::QueueSaturated,
                "bounded reactor command mailbox is full; temporal custody is blind",
            ));
        }
        shared.queue.push_back(command);
        condvar.notify_one();
        Ok(())
    }

    fn latch_response_timeout(&self) {
        let (mutex, condvar) = &*self.shared;
        if let Ok(mut shared) = mutex.lock() {
            shared.response_timeout_latched = true;
            shared.snapshot.condition = ReactorConditionV1::WakeupFailure;
            shared.snapshot.condition_detail =
                "command response timeout made timer custody unavailable".to_owned();
            shared.snapshot.live_standing_available = false;
            shared.snapshot.certificates.clear();
            shared.snapshot.active_deadline_count = 0;
            shared.snapshot.earliest_deadline_monotonic_ms = None;
            shared.snapshot.supporting_evidence_count = 0;
            condvar.notify_one();
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> ReactorSnapshotV1 {
        let (mutex, _) = &*self.shared;
        match mutex.lock() {
            Ok(shared) => shared.snapshot.clone(),
            Err(poisoned) => {
                let shared = poisoned.into_inner();
                let mut snapshot = shared.snapshot.clone();
                snapshot.condition = ReactorConditionV1::WakeupFailure;
                snapshot.condition_detail = "reactor shared-state mutex is poisoned".to_owned();
                snapshot.live_standing_available = false;
                snapshot.certificates.clear();
                snapshot.active_deadline_count = 0;
                snapshot.earliest_deadline_monotonic_ms = None;
                snapshot.supporting_evidence_count = 0;
                snapshot
            }
        }
    }

    /// Receiver-owned process-local monotonic time for transport arrival and
    /// session custody. Sender clocks and network metadata never enter this
    /// clock lineage.
    pub fn receiver_monotonic_now(&self) -> Result<u64, ReactorCommandError> {
        if !self.snapshot().condition.exposes_live_standing() {
            return Err(ReactorCommandError::new(
                ReactorCommandErrorClassV1::NotOperational,
                "reactor monotonic custody is unavailable",
            ));
        }
        Ok(self.clock.now_ms())
    }

    #[must_use]
    pub fn journal_path(&self) -> &Path {
        &self.journal_path
    }

    pub fn wait_until(
        &self,
        timeout: Duration,
        predicate: impl Fn(&ReactorSnapshotV1) -> bool,
    ) -> Result<ReactorSnapshotV1, ReactorCommandError> {
        let started = Instant::now();
        loop {
            let snapshot = self.snapshot();
            if predicate(&snapshot) {
                return Ok(snapshot);
            }
            if started.elapsed() >= timeout {
                return Err(ReactorCommandError::new(
                    ReactorCommandErrorClassV1::ResponseTimeout,
                    "reactor observation predicate did not become true within the wait bound",
                ));
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    pub fn shutdown(mut self) -> Result<ReactorSnapshotV1, ReactorCommandError> {
        {
            let (mutex, condvar) = &*self.shared;
            let mut shared = mutex.lock().map_err(|_| {
                ReactorCommandError::new(
                    ReactorCommandErrorClassV1::ActorTerminated,
                    "reactor shared state is poisoned during shutdown",
                )
            })?;
            shared.accepting_commands = false;
            shared.shutdown_requested = true;
            shared.snapshot.condition = ReactorConditionV1::ShuttingDown;
            shared.snapshot.condition_detail = "clean shutdown requested".to_owned();
            shared.snapshot.live_standing_available = false;
            shared.snapshot.certificates.clear();
            shared.snapshot.active_deadline_count = 0;
            shared.snapshot.earliest_deadline_monotonic_ms = None;
            shared.snapshot.supporting_evidence_count = 0;
            condvar.notify_one();
        }
        if let Some(join) = self.join.take() {
            join.join().map_err(|_| {
                ReactorCommandError::new(
                    ReactorCommandErrorClassV1::ActorTerminated,
                    "reactor thread panicked during shutdown",
                )
            })?;
        }
        Ok(self.snapshot())
    }
}

/// Send one live request through an already connected local Unix stream.
/// Elapsed time is measured from before transmission and rounded upward. The
/// caller must subtract this value, plus any later local wait, from the
/// response's bounded duration.
#[cfg(unix)]
pub fn query_live_present_support_stream(
    stream: &mut UnixStream,
    request: &LivePresentSupportRequestV1,
    timeout: Duration,
) -> Result<(LivePresentSupportResponseV1, u64), ReactorCommandError> {
    request.validate().map_err(|error| {
        ReactorCommandError::new(
            ReactorCommandErrorClassV1::InvalidRequest,
            error.to_string(),
        )
    })?;
    let request_bytes = request.canonical_bytes().map_err(|error| {
        ReactorCommandError::new(ReactorCommandErrorClassV1::InvalidRequest, error)
    })?;
    let started = Instant::now();
    let response_bytes = with_nonblocking_stream(stream, timeout, |stream, deadline| {
        write_live_support_frame(
            stream,
            &request_bytes,
            MAX_LIVE_PRESENT_SUPPORT_REQUEST_BYTES,
            deadline,
        )?;
        read_live_support_frame(stream, MAX_LIVE_PRESENT_SUPPORT_RESPONSE_BYTES, deadline)
    })?;
    let elapsed_nanos = started.elapsed().as_nanos();
    let elapsed_ms =
        u64::try_from(elapsed_nanos.saturating_add(999_999) / 1_000_000).unwrap_or(u64::MAX);
    let response =
        LivePresentSupportResponseV1::decode_canonical(&response_bytes).map_err(|error| {
            ReactorCommandError::new(ReactorCommandErrorClassV1::TransportFailure, error)
        })?;
    response.validate_against(request).map_err(|error| {
        ReactorCommandError::new(
            ReactorCommandErrorClassV1::TransportFailure,
            error.to_string(),
        )
    })?;
    Ok((response, elapsed_ms))
}

#[cfg(unix)]
fn with_nonblocking_stream<T>(
    stream: &mut UnixStream,
    timeout: Duration,
    operation: impl FnOnce(&mut UnixStream, Instant) -> Result<T, ReactorCommandError>,
) -> Result<T, ReactorCommandError> {
    if timeout.is_zero() {
        return Err(ReactorCommandError::new(
            ReactorCommandErrorClassV1::InvalidConfig,
            "live present-support stream timeout must be nonzero",
        ));
    }
    let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
        ReactorCommandError::new(
            ReactorCommandErrorClassV1::InvalidConfig,
            "live present-support stream timeout exceeds Instant range",
        )
    })?;
    stream.set_nonblocking(true).map_err(|error| {
        ReactorCommandError::new(
            ReactorCommandErrorClassV1::TransportFailure,
            format!("enable nonblocking live-query stream: {error}"),
        )
    })?;
    let result = operation(stream, deadline);
    let reset = stream.set_nonblocking(false).map_err(|error| {
        ReactorCommandError::new(
            ReactorCommandErrorClassV1::TransportFailure,
            format!("restore blocking live-query stream: {error}"),
        )
    });
    match (result, reset) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

#[cfg(unix)]
fn read_live_support_frame(
    stream: &mut UnixStream,
    maximum_bytes: usize,
    deadline: Instant,
) -> Result<Vec<u8>, ReactorCommandError> {
    let mut length = [0_u8; 4];
    read_live_support_exact(stream, &mut length, deadline, "frame length")?;
    let length = usize::try_from(u32::from_be_bytes(length)).unwrap_or(usize::MAX);
    if length == 0 || length > maximum_bytes {
        return Err(ReactorCommandError::new(
            ReactorCommandErrorClassV1::InvalidRequest,
            "live-query frame length is zero or exceeds its bound",
        ));
    }
    let mut bytes = vec![0_u8; length];
    read_live_support_exact(stream, &mut bytes, deadline, "frame body")?;
    Ok(bytes)
}

#[cfg(unix)]
fn write_live_support_frame(
    stream: &mut UnixStream,
    bytes: &[u8],
    maximum_bytes: usize,
    deadline: Instant,
) -> Result<(), ReactorCommandError> {
    if bytes.is_empty() || bytes.len() > maximum_bytes {
        return Err(ReactorCommandError::new(
            ReactorCommandErrorClassV1::InvalidRequest,
            "live-query frame is empty or exceeds its bound",
        ));
    }
    let length = u32::try_from(bytes.len()).map_err(|_| {
        ReactorCommandError::new(
            ReactorCommandErrorClassV1::InvalidRequest,
            "live-query frame length exceeds u32",
        )
    })?;
    write_live_support_all(stream, &length.to_be_bytes(), deadline, "frame length")?;
    write_live_support_all(stream, bytes, deadline, "frame body")
}

#[cfg(unix)]
fn read_live_support_exact(
    stream: &mut UnixStream,
    bytes: &mut [u8],
    deadline: Instant,
    part: &str,
) -> Result<(), ReactorCommandError> {
    let mut offset = 0;
    while offset < bytes.len() {
        match stream.read(&mut bytes[offset..]) {
            Ok(0) => {
                return Err(ReactorCommandError::new(
                    ReactorCommandErrorClassV1::TransportFailure,
                    format!("live-query {part} ended before its declared length"),
                ));
            }
            Ok(count) => offset = offset.saturating_add(count),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                wait_for_live_support_io(deadline)?;
            }
            Err(error) => {
                return Err(ReactorCommandError::new(
                    ReactorCommandErrorClassV1::TransportFailure,
                    format!("read live-query {part}: {error}"),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn write_live_support_all(
    stream: &mut UnixStream,
    bytes: &[u8],
    deadline: Instant,
    part: &str,
) -> Result<(), ReactorCommandError> {
    let mut offset = 0;
    while offset < bytes.len() {
        match stream.write(&bytes[offset..]) {
            Ok(0) => {
                return Err(ReactorCommandError::new(
                    ReactorCommandErrorClassV1::TransportFailure,
                    format!("live-query {part} accepted zero bytes"),
                ));
            }
            Ok(count) => offset = offset.saturating_add(count),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                wait_for_live_support_io(deadline)?;
            }
            Err(error) => {
                return Err(ReactorCommandError::new(
                    ReactorCommandErrorClassV1::TransportFailure,
                    format!("write live-query {part}: {error}"),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn wait_for_live_support_io(deadline: Instant) -> Result<(), ReactorCommandError> {
    if Instant::now() >= deadline {
        return Err(ReactorCommandError::new(
            ReactorCommandErrorClassV1::ResponseTimeout,
            "live-query local stream exceeded its bounded exchange time",
        ));
    }
    thread::sleep(Duration::from_millis(1));
    Ok(())
}

fn guard_actor_unwind(
    shared: &Arc<(Mutex<SharedState>, Condvar)>,
    epoch: &MonotonicEpochV1,
    clock: &ReactorClock,
    actor: impl FnOnce(),
) {
    if panic::catch_unwind(AssertUnwindSafe(actor)).is_err() {
        terminate_shared_without_runtime(
            shared,
            epoch,
            clock.now_ms(),
            ReactorConditionV1::ActorTerminated,
            "reactor actor thread terminated by an unwind; temporal custody was withdrawn",
        );
    }
}

impl Drop for LocalCrashReactor {
    fn drop(&mut self) {
        let Some(join) = self.join.take() else {
            return;
        };
        let (mutex, condvar) = &*self.shared;
        match mutex.lock() {
            Ok(mut shared) => {
                shared.accepting_commands = false;
                shared.abandoned = true;
                shared.snapshot.condition = ReactorConditionV1::CommandChannelClosed;
                shared.snapshot.condition_detail =
                    "reactor owner dropped without clean shutdown".to_owned();
                shared.snapshot.live_standing_available = false;
                shared.snapshot.certificates.clear();
                shared.snapshot.active_deadline_count = 0;
                shared.snapshot.earliest_deadline_monotonic_ms = None;
                shared.snapshot.supporting_evidence_count = 0;
                condvar.notify_one();
            }
            Err(poisoned) => {
                let mut shared = poisoned.into_inner();
                shared.accepting_commands = false;
                shared.abandoned = true;
                condvar.notify_one();
            }
        }
        let _ = join.join();
    }
}

fn actor_main(
    mut runtime: ReceiverSchedulerRuntime,
    journal: HistoricalJournal,
    epoch: MonotonicEpochV1,
    config: ReactorConfigV1,
    clock: ReactorClock,
    shared: Arc<(Mutex<SharedState>, Condvar)>,
    mut qualification_hook: Option<ReactorQualificationHook>,
) {
    let mut metrics = ReactorMetricsV1::empty();
    let mut sink = match JournalSink::new(journal, epoch.clone(), config.journal_durability) {
        Ok(sink) => sink,
        Err(error) => {
            terminate_shared(
                &shared,
                &runtime,
                &epoch,
                clock.now_ms(),
                ReactorConditionV1::JournalFailure,
                error.to_string(),
                metrics,
                false,
            );
            return;
        }
    };
    let initial_output = RuntimeCycleOutputV1::default();
    if let Err(error) = sink.capture(&runtime, &initial_output, clock.now_ms(), &mut metrics) {
        metrics.journal_failure_count = metrics.journal_failure_count.saturating_add(1);
        terminate_shared(
            &shared,
            &runtime,
            &epoch,
            clock.now_ms(),
            ReactorConditionV1::JournalFailure,
            error.to_string(),
            metrics,
            false,
        );
        return;
    }
    update_shared_snapshot(
        &shared,
        snapshot_from_runtime(
            &runtime,
            epoch.clone(),
            clock.now_ms(),
            ReactorConditionV1::Operational,
            "reactor owns the earliest active deadline",
            metrics.clone(),
        ),
    );
    let mut custody_failure: Option<(ReactorConditionV1, String)> = None;

    loop {
        if runtime.next_scheduled_deadline_monotonic_ms().is_some() {
            invoke_qualification_hook(
                &mut qualification_hook,
                ReactorQualificationPointV1::BeforeDeadlineArming,
            );
            invoke_qualification_hook(
                &mut qualification_hook,
                ReactorQualificationPointV1::AfterDeadlineArming,
            );
        }
        let wait = wait_for_actor_work(
            &shared,
            runtime.next_scheduled_deadline_monotonic_ms(),
            &clock,
        );
        let (
            mut commands,
            mut live_support_queries,
            overload,
            response_timeout,
            abandoned,
            shutdown,
            timed_out,
        ) = match wait {
            Ok(value) => value,
            Err(detail) => {
                metrics.wakeup_failure_count = metrics.wakeup_failure_count.saturating_add(1);
                let now = clock.now_ms();
                let output = runtime
                    .declare_external_monitor_blindness(
                        now,
                        "reactor_wakeup_failure",
                        detail.clone(),
                    )
                    .unwrap_or_default();
                let _ = sink.capture(&runtime, &output, now, &mut metrics);
                terminate_shared(
                    &shared,
                    &runtime,
                    &epoch,
                    now,
                    ReactorConditionV1::WakeupFailure,
                    detail,
                    metrics,
                    false,
                );
                return;
            }
        };
        metrics.wakeup_count = metrics.wakeup_count.saturating_add(1);
        if timed_out {
            metrics.deadline_wakeup_count = metrics.deadline_wakeup_count.saturating_add(1);
            invoke_qualification_hook(
                &mut qualification_hook,
                ReactorQualificationPointV1::DeadlineDueBeforeProcessing,
            );
        } else if !commands.is_empty() || !live_support_queries.is_empty() {
            metrics.command_wakeup_count = metrics.command_wakeup_count.saturating_add(1);
        } else {
            metrics.early_wakeup_count = metrics.early_wakeup_count.saturating_add(1);
        }
        if timed_out && config.deliberate_deadline_delay_ms > 0 {
            thread::sleep(Duration::from_millis(config.deliberate_deadline_delay_ms));
        }
        let now = clock.now_ms();
        let mut combined = RuntimeCycleOutputV1::default();
        let mut responses = Vec::new();

        if overload || response_timeout {
            let detail = if overload {
                "reactor command mailbox saturated; at least one command was refused"
            } else {
                "reactor command response timed out; temporal custody cannot be relied upon"
            };
            match runtime.declare_external_monitor_blindness(
                now,
                if overload {
                    "reactor_mailbox_overloaded"
                } else {
                    "reactor_response_timeout"
                },
                detail,
            ) {
                Ok(output) => combined.append(output),
                Err(error) => {
                    terminate_shared(
                        &shared,
                        &runtime,
                        &epoch,
                        now,
                        ReactorConditionV1::WakeupFailure,
                        error.to_string(),
                        metrics,
                        false,
                    );
                    return;
                }
            }
            custody_failure = Some((
                if overload {
                    ReactorConditionV1::MailboxOverloaded
                } else {
                    ReactorConditionV1::WakeupFailure
                },
                detail.to_owned(),
            ));
        }

        let mut explicit_blindness = None;
        while let Some(command) = commands.pop_front() {
            match command {
                ActorCommand::RuntimeInput {
                    admitted_at_monotonic_ms,
                    input,
                    response,
                } => match runtime.enqueue(admitted_at_monotonic_ms, *input) {
                    Ok(_) => responses.push((response, None)),
                    Err(refusal) => responses.push((
                        response,
                        Some(ReactorCommandError::new(
                            ReactorCommandErrorClassV1::RuntimeFailure,
                            format!("runtime input refused: {refusal:?}"),
                        )),
                    )),
                },
                ActorCommand::DeclareBlindness {
                    admitted_at_monotonic_ms,
                    detail,
                    response,
                } => {
                    explicit_blindness = Some(detail.clone());
                    match runtime.declare_external_monitor_blindness(
                        admitted_at_monotonic_ms.max(now),
                        "reactor_explicit_blindness",
                        detail,
                    ) {
                        Ok(output) => {
                            combined.append(output);
                            responses.push((response, None));
                        }
                        Err(error) => responses.push((
                            response,
                            Some(ReactorCommandError::new(
                                ReactorCommandErrorClassV1::RuntimeFailure,
                                error.to_string(),
                            )),
                        )),
                    }
                }
            }
        }

        match runtime.run_until(now) {
            Ok(output) => combined.append(output),
            Err(error) => {
                let error = ReactorCommandError::new(
                    ReactorCommandErrorClassV1::RuntimeFailure,
                    error.to_string(),
                );
                for (response, _) in responses {
                    let _ = response.send(Err(error.clone()));
                }
                terminate_shared(
                    &shared,
                    &runtime,
                    &epoch,
                    now,
                    ReactorConditionV1::WakeupFailure,
                    error.to_string(),
                    metrics,
                    false,
                );
                return;
            }
        }
        observe_deadline_output(&combined, &mut metrics);
        if timed_out {
            invoke_qualification_hook(
                &mut qualification_hook,
                ReactorQualificationPointV1::DeadlineProcessedBeforeJournal,
            );
        }
        if let Err(error) = sink.capture(&runtime, &combined, now, &mut metrics) {
            metrics.journal_failure_count = metrics.journal_failure_count.saturating_add(1);
            let blindness = runtime
                .declare_external_monitor_blindness(
                    now,
                    "required_journal_failure",
                    error.to_string(),
                )
                .unwrap_or_default();
            let _ = sink.capture(&runtime, &blindness, now, &mut metrics);
            for (response, _) in responses {
                let _ = response.send(Err(error.clone()));
            }
            terminate_shared(
                &shared,
                &runtime,
                &epoch,
                now,
                ReactorConditionV1::JournalFailure,
                error.to_string(),
                metrics,
                false,
            );
            return;
        }
        if abandoned || shutdown {
            if shutdown {
                invoke_qualification_hook(
                    &mut qualification_hook,
                    ReactorQualificationPointV1::CleanShutdownBegan,
                );
            }
            let condition = if shutdown {
                ReactorConditionV1::ShuttingDown
            } else {
                ReactorConditionV1::CommandChannelClosed
            };
            let detail = if shutdown {
                "clean shutdown withdrew temporal custody"
            } else {
                "reactor command channel closed without a clean shutdown"
            };
            let final_output = runtime
                .declare_external_monitor_blindness(now, "reactor_terminated", detail)
                .unwrap_or_default();
            let query_error = ReactorCommandError::new(
                ReactorCommandErrorClassV1::NotOperational,
                "reactor withdrew temporal custody before answering the live query",
            );
            for query in live_support_queries.drain(..) {
                let _ = query.response.send(Err(query_error.clone()));
            }
            let journal_result = sink.capture(&runtime, &final_output, now, &mut metrics);
            let clean = shutdown && journal_result.is_ok();
            let (final_condition, final_detail) = if let Err(error) = journal_result {
                metrics.journal_failure_count = metrics.journal_failure_count.saturating_add(1);
                (ReactorConditionV1::JournalFailure, error.to_string())
            } else if clean {
                (
                    ReactorConditionV1::Terminated,
                    "clean shutdown completed after withdrawing temporal custody".to_owned(),
                )
            } else {
                (condition, detail.to_owned())
            };
            terminate_shared(
                &shared,
                &runtime,
                &epoch,
                now,
                final_condition,
                final_detail,
                metrics,
                clean,
            );
            return;
        }

        if let Some(detail) = explicit_blindness {
            custody_failure = Some((ReactorConditionV1::ExplicitBlindness, detail));
        }
        let (condition, detail) = custody_failure.clone().unwrap_or((
            ReactorConditionV1::Operational,
            "reactor owns the earliest active deadline".to_owned(),
        ));
        update_shared_snapshot(
            &shared,
            snapshot_from_runtime(
                &runtime,
                epoch.clone(),
                now,
                condition,
                detail,
                metrics.clone(),
            ),
        );
        // Publish the actor's completed state before acknowledging commands.
        // A caller that receives success may therefore immediately inspect the
        // snapshot without racing the actor's state publication.
        for (response, error) in responses {
            let result = error.map_or_else(|| Ok(combined.clone()), Err);
            let _ = response.send(result);
        }
        for query in live_support_queries {
            let measured_at = clock.now_ms();
            let response = live_present_support_response(
                &runtime,
                &epoch,
                condition,
                query.request,
                measured_at,
            );
            let _ = query.response.send(Ok(response));
        }
    }
}

fn invoke_qualification_hook(
    hook: &mut Option<ReactorQualificationHook>,
    point: ReactorQualificationPointV1,
) {
    if let Some(hook) = hook {
        hook(point);
    }
}

type ActorWake = (
    VecDeque<ActorCommand>,
    VecDeque<LiveSupportQueryCommand>,
    bool,
    bool,
    bool,
    bool,
    bool,
);

fn wait_for_actor_work(
    shared: &Arc<(Mutex<SharedState>, Condvar)>,
    deadline: Option<u64>,
    clock: &ReactorClock,
) -> Result<ActorWake, String> {
    let (mutex, condvar) = &**shared;
    let mut state = mutex
        .lock()
        .map_err(|_| "reactor command mutex was poisoned before wait".to_owned())?;
    loop {
        let now = clock.now_ms();
        let deadline_due = deadline.is_some_and(|deadline| now >= deadline);
        if !state.queue.is_empty()
            || !state.live_support_queries.is_empty()
            || state.overload_latched
            || state.response_timeout_latched
            || state.abandoned
            || state.shutdown_requested
            || deadline_due
        {
            let commands = std::mem::take(&mut state.queue);
            let live_support_queries = std::mem::take(&mut state.live_support_queries);
            let overload = std::mem::take(&mut state.overload_latched);
            let response_timeout = std::mem::take(&mut state.response_timeout_latched);
            return Ok((
                commands,
                live_support_queries,
                overload,
                response_timeout,
                state.abandoned,
                state.shutdown_requested,
                deadline_due,
            ));
        }
        state = if let Some(deadline) = deadline {
            let duration = Duration::from_millis(deadline.saturating_sub(now));
            let (mut next, wait_result) = condvar
                .wait_timeout(state, duration)
                .map_err(|_| "reactor condition-variable timed wait was poisoned".to_owned())?;
            if wait_result.timed_out() {
                let commands = std::mem::take(&mut next.queue);
                let live_support_queries = std::mem::take(&mut next.live_support_queries);
                let overload = std::mem::take(&mut next.overload_latched);
                let response_timeout = std::mem::take(&mut next.response_timeout_latched);
                return Ok((
                    commands,
                    live_support_queries,
                    overload,
                    response_timeout,
                    next.abandoned,
                    next.shutdown_requested,
                    true,
                ));
            }
            next
        } else {
            condvar
                .wait(state)
                .map_err(|_| "reactor condition-variable wait was poisoned".to_owned())?
        };
    }
}

fn observe_deadline_output(output: &RuntimeCycleOutputV1, metrics: &mut ReactorMetricsV1) {
    for event in &output.sparse_events {
        if let SparseDurableEventKindV1::SchedulerReevaluated {
            expected_deadline_monotonic_ms,
            actual_reevaluation_monotonic_ms,
            stale_positive_overshoot_ms,
            ..
        } = &event.event
        {
            metrics.deadline_withdrawal_count = metrics.deadline_withdrawal_count.saturating_add(1);
            let lateness = actual_reevaluation_monotonic_ms
                .saturating_sub(*expected_deadline_monotonic_ms)
                .max(*stale_positive_overshoot_ms);
            metrics.last_wakeup_lateness_ms = lateness;
            metrics.maximum_wakeup_lateness_ms = metrics.maximum_wakeup_lateness_ms.max(lateness);
        }
    }
}

fn snapshot_from_runtime(
    runtime: &ReceiverSchedulerRuntime,
    epoch: MonotonicEpochV1,
    observed_at: u64,
    condition: ReactorConditionV1,
    detail: impl Into<String>,
    reactor_metrics: ReactorMetricsV1,
) -> ReactorSnapshotV1 {
    if !condition.exposes_live_standing() {
        return ReactorSnapshotV1::unavailable(
            epoch,
            observed_at,
            condition,
            detail,
            runtime.metrics().clone(),
            reactor_metrics,
        );
    }
    let mut certificates = runtime.current_certificates();
    certificates.sort_by(|left, right| {
        (
            &left.subject_scope.subject,
            &left.consumer,
            &left.context.activation_id,
        )
            .cmp(&(
                &right.subject_scope.subject,
                &right.consumer,
                &right.context.activation_id,
            ))
    });
    let supporting_evidence_count = certificates
        .iter()
        .map(|certificate| certificate.supporting_evidence_ids.len())
        .sum();
    ReactorSnapshotV1 {
        schema_version: SCHEMA_VERSION_V1,
        monotonic_epoch: epoch,
        observed_at_epoch_monotonic_ms: observed_at,
        condition,
        condition_detail: detail.into(),
        live_standing_available: true,
        certificates,
        active_deadline_count: runtime.scheduled_deadline_count(),
        earliest_deadline_monotonic_ms: runtime.next_scheduled_deadline_monotonic_ms(),
        supporting_evidence_count,
        runtime_metrics: runtime.metrics().clone(),
        reactor_metrics,
        clean_shutdown: false,
        mutation_authority: MutationAuthorityV1::None,
    }
}

fn live_present_support_response(
    runtime: &ReceiverSchedulerRuntime,
    epoch: &MonotonicEpochV1,
    condition: ReactorConditionV1,
    request: LivePresentSupportRequestV1,
    measured_at: u64,
) -> LivePresentSupportResponseV1 {
    let lineage_matches = request.receiver == epoch.receiver
        && request.receiver_incarnation == epoch.receiver_incarnation
        && request.receiver_epoch_id == epoch.epoch_id
        && request.receiver_clock_id == epoch.clock_id;
    let certificate =
        runtime.current_certificate(&request.subject_scope.subject, &request.consumer);
    let exact_support = certificate.is_some_and(|certificate| {
        certificate.consumer == request.consumer
            && certificate.subject_scope == request.subject_scope
            && certificate.context == request.reliance_context
            && certificate.context.identity_digest() == request.reliance_context_digest
            && certificate.certificate_id == request.support_certificate_id
            && certificate.evidence_window_id == request.evidence_window_id
            && certificate
                .qualified_generation
                .as_ref()
                .is_some_and(|binding| {
                    binding.identity_digest() == request.qualified_generation_digest
                })
    });
    let (disposition, remaining) = if condition != ReactorConditionV1::Operational {
        (LivePresentSupportDispositionV1::Indeterminate, None)
    } else if !lineage_matches || !exact_support {
        (LivePresentSupportDispositionV1::Unsupported, None)
    } else {
        let certificate = certificate.expect("exact support requires a certificate");
        live_support_remaining(
            certificate.judgment,
            certificate.earliest_support_expiry_monotonic_ms,
            measured_at,
        )
    };
    LivePresentSupportResponseV1::new(
        request,
        epoch.receiver.clone(),
        epoch.receiver_incarnation.clone(),
        epoch.epoch_id.clone(),
        epoch.clock_id.clone(),
        epoch.clock_source.clone(),
        measured_at,
        disposition,
        remaining,
    )
}

fn live_support_remaining(
    judgment: JudgmentCategoryV1,
    expiry: Option<u64>,
    measured_at: u64,
) -> (LivePresentSupportDispositionV1, Option<u64>) {
    match (judgment, expiry) {
        (JudgmentCategoryV1::Current, Some(expiry)) => {
            // `Instant::elapsed().as_millis()` truncates. Subtract one
            // millisecond so a low-rounded source reading cannot overstate
            // the interval available to another process.
            let raw_remaining = expiry.saturating_sub(measured_at);
            if raw_remaining <= 1 {
                (LivePresentSupportDispositionV1::Expired, None)
            } else {
                (
                    LivePresentSupportDispositionV1::SupportedCurrent,
                    Some(raw_remaining - 1),
                )
            }
        }
        _ => (LivePresentSupportDispositionV1::Unsupported, None),
    }
}

fn update_shared_snapshot(
    shared: &Arc<(Mutex<SharedState>, Condvar)>,
    snapshot: ReactorSnapshotV1,
) {
    let (mutex, condvar) = &**shared;
    let mut state = lock_recovering_poison(mutex);
    state.snapshot = snapshot;
    condvar.notify_all();
}

#[allow(clippy::too_many_arguments)]
fn terminate_shared(
    shared: &Arc<(Mutex<SharedState>, Condvar)>,
    runtime: &ReceiverSchedulerRuntime,
    epoch: &MonotonicEpochV1,
    now: u64,
    condition: ReactorConditionV1,
    detail: impl Into<String>,
    metrics: ReactorMetricsV1,
    clean_shutdown: bool,
) {
    let (mutex, condvar) = &**shared;
    let mut state = lock_recovering_poison(mutex);
    state.accepting_commands = false;
    let mut snapshot = ReactorSnapshotV1::unavailable(
        epoch.clone(),
        now,
        condition,
        detail,
        runtime.metrics().clone(),
        metrics,
    );
    snapshot.clean_shutdown = clean_shutdown;
    state.snapshot = snapshot;
    for command in state.queue.drain(..) {
        let response = match command {
            ActorCommand::RuntimeInput { response, .. }
            | ActorCommand::DeclareBlindness { response, .. } => response,
        };
        let _ = response.send(Err(ReactorCommandError::new(
            ReactorCommandErrorClassV1::ActorTerminated,
            "reactor terminated before command processing",
        )));
    }
    for query in state.live_support_queries.drain(..) {
        let _ = query.response.send(Err(ReactorCommandError::new(
            ReactorCommandErrorClassV1::ActorTerminated,
            "reactor terminated before live-query processing",
        )));
    }
    condvar.notify_all();
}

fn terminate_shared_without_runtime(
    shared: &Arc<(Mutex<SharedState>, Condvar)>,
    epoch: &MonotonicEpochV1,
    now: u64,
    condition: ReactorConditionV1,
    detail: impl Into<String>,
) {
    let (mutex, condvar) = &**shared;
    let mut state = lock_recovering_poison(mutex);
    state.accepting_commands = false;
    let mut snapshot = state.snapshot.clone();
    snapshot.monotonic_epoch = epoch.clone();
    snapshot.observed_at_epoch_monotonic_ms = now;
    snapshot.condition = condition;
    snapshot.condition_detail = detail.into();
    snapshot.live_standing_available = false;
    snapshot.certificates.clear();
    snapshot.active_deadline_count = 0;
    snapshot.earliest_deadline_monotonic_ms = None;
    snapshot.supporting_evidence_count = 0;
    snapshot.clean_shutdown = false;
    snapshot.mutation_authority = MutationAuthorityV1::None;
    state.snapshot = snapshot;
    for command in state.queue.drain(..) {
        let response = match command {
            ActorCommand::RuntimeInput { response, .. }
            | ActorCommand::DeclareBlindness { response, .. } => response,
        };
        let _ = response.send(Err(ReactorCommandError::new(
            ReactorCommandErrorClassV1::ActorTerminated,
            "reactor actor thread terminated before command processing",
        )));
    }
    for query in state.live_support_queries.drain(..) {
        let _ = query.response.send(Err(ReactorCommandError::new(
            ReactorCommandErrorClassV1::ActorTerminated,
            "reactor actor thread terminated before live-query processing",
        )));
    }
    condvar.notify_all();
}

fn lock_recovering_poison<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct LiveSupportConformanceVectors {
        schema: String,
        duration_vectors: Vec<DurationVector>,
        caller_decay_vectors: Vec<CallerDecayVector>,
        request_binding_vectors: Vec<RequestBindingVector>,
        qualification_cases: Vec<String>,
    }

    #[derive(Deserialize)]
    struct DurationVector {
        id: String,
        judgment: JudgmentCategoryV1,
        expiry_ms: Option<u64>,
        measured_at_ms: u64,
        expected_disposition: LivePresentSupportDispositionV1,
        expected_remaining_ms: Option<u64>,
    }

    #[derive(Deserialize)]
    struct CallerDecayVector {
        id: String,
        response_remaining_ms: u64,
        elapsed_since_send_ms: u64,
        expected_usable_remaining_ms: Option<u64>,
    }

    #[derive(Deserialize)]
    struct RequestBindingVector {
        id: String,
        mutation: String,
        accepted: bool,
    }

    fn live_query_request(nonce: &str) -> LivePresentSupportRequestV1 {
        let context = pulse_types::RelianceContextV1 {
            schema_version: SCHEMA_VERSION_V1,
            activation_id: pulse_types::ContextActivationId::new("activation:test"),
            reliance_policy_generation: pulse_types::PolicyGenerationId::new("policy:test"),
            reliance_policy_semantic_digest: digest_parts("policy", &[b"test"]),
            consumer_profile_generation: pulse_types::ConsumerProfileGenerationId::new(
                "profile:test",
            ),
            evaluator_semantic_generation: pulse_types::EvaluatorSemanticGenerationId::new(
                "evaluator:test",
            ),
            observer_set_generation: pulse_types::ObserverSetGenerationId::new("observers:test"),
            observation_policy_generation: pulse_types::ObservationPolicyGenerationId::new(
                "observation-policy:test",
            ),
        };
        LivePresentSupportRequestV1 {
            schema: pulse_types::LIVE_PRESENT_SUPPORT_REQUEST_SCHEMA_V1.to_owned(),
            request_nonce: pulse_types::LivePresentSupportNonce::new(nonce),
            consumer: ConsumerId::new("consumer:test"),
            subject_scope: pulse_types::SubjectScopeV1 {
                subject: SubjectId::new("subject:test"),
                subject_incarnation: pulse_types::IncarnationId::new("subject-incarnation:test"),
                scope: "scope:test".to_owned(),
            },
            reliance_context_digest: context.identity_digest(),
            reliance_context: context,
            support_certificate_id: pulse_types::SupportCertificateId::new("support:test"),
            evidence_window_id: pulse_types::EvidenceWindowId::new("window:test"),
            qualified_generation_digest: digest_parts("qualified", &[b"test"]),
            receiver: pulse_types::ReceiverId::new("receiver:test"),
            receiver_incarnation: pulse_types::IncarnationId::new("receiver-incarnation:test"),
            receiver_epoch_id: pulse_types::IncarnationId::new("epoch:test"),
            receiver_clock_id: pulse_types::ClockId::new("clock:test"),
        }
    }

    fn query_test_reactor(
        live_support_queries: VecDeque<LiveSupportQueryCommand>,
        maximum_pending_commands: usize,
    ) -> LocalCrashReactor {
        let epoch = MonotonicEpochV1 {
            schema_version: SCHEMA_VERSION_V1,
            epoch_id: pulse_types::IncarnationId::new("epoch:test"),
            receiver: pulse_types::ReceiverId::new("receiver:test"),
            receiver_incarnation: pulse_types::IncarnationId::new("receiver-incarnation:test"),
            clock_id: pulse_types::ClockId::new("clock:test"),
            origin_runtime_monotonic_ms: 0,
            clock_source: "std::time::Instant/process-local".to_owned(),
        };
        let mut snapshot = ReactorSnapshotV1::unavailable(
            epoch,
            0,
            ReactorConditionV1::Operational,
            "fixture operational",
            RuntimeMetricsV1::empty(),
            ReactorMetricsV1::empty(),
        );
        snapshot.live_standing_available = true;
        LocalCrashReactor {
            shared: Arc::new((
                Mutex::new(SharedState {
                    queue: VecDeque::new(),
                    live_support_queries,
                    accepting_commands: true,
                    overload_latched: false,
                    response_timeout_latched: false,
                    abandoned: false,
                    shutdown_requested: false,
                    snapshot,
                }),
                Condvar::new(),
            )),
            clock: ReactorClock {
                origin: Instant::now(),
                origin_runtime_monotonic_ms: 0,
            },
            config: ReactorConfigV1 {
                maximum_pending_commands,
                command_response_timeout_ms: 1,
                ..ReactorConfigV1::qualification()
            },
            journal_path: PathBuf::from("/tmp/nonexistent-live-query-fixture"),
            transport_custody_policy: None,
            join: None,
        }
    }

    #[test]
    fn non_operational_snapshot_never_exposes_cached_certificates() {
        let epoch = MonotonicEpochV1 {
            schema_version: SCHEMA_VERSION_V1,
            epoch_id: pulse_types::IncarnationId::new("epoch:test"),
            receiver: pulse_types::ReceiverId::new("receiver:test"),
            receiver_incarnation: pulse_types::IncarnationId::new("receiver-incarnation:test"),
            clock_id: pulse_types::ClockId::new("clock:test"),
            origin_runtime_monotonic_ms: 0,
            clock_source: "std::time::Instant/process-local".to_owned(),
        };
        let snapshot = ReactorSnapshotV1::unavailable(
            epoch,
            0,
            ReactorConditionV1::Terminated,
            "fixture",
            RuntimeMetricsV1::empty(),
            ReactorMetricsV1::empty(),
        );
        assert!(!snapshot.live_standing_available);
        assert!(snapshot.certificates.is_empty());
        assert_eq!(snapshot.active_deadline_count, 0);
        assert_eq!(snapshot.mutation_authority, MutationAuthorityV1::None);
    }

    #[test]
    fn bounded_mailbox_refuses_without_eviction_and_latches_blindness() {
        let epoch = MonotonicEpochV1 {
            schema_version: SCHEMA_VERSION_V1,
            epoch_id: pulse_types::IncarnationId::new("epoch:mailbox"),
            receiver: pulse_types::ReceiverId::new("receiver:mailbox"),
            receiver_incarnation: pulse_types::IncarnationId::new("receiver-incarnation:mailbox"),
            clock_id: pulse_types::ClockId::new("clock:mailbox"),
            origin_runtime_monotonic_ms: 0,
            clock_source: "std::time::Instant/process-local".to_owned(),
        };
        let config = ReactorConfigV1 {
            maximum_pending_commands: 1,
            ..ReactorConfigV1::qualification()
        };
        let (existing_sender, _existing_receiver) = mpsc::sync_channel(1);
        let existing = ActorCommand::RuntimeInput {
            admitted_at_monotonic_ms: 0,
            input: Box::new(RuntimeInputV1::RestoreMonitorCapability {
                subject: None,
                detail: "fixture".to_owned(),
            }),
            response: existing_sender,
        };
        let mut queue = VecDeque::new();
        queue.push_back(existing);
        let snapshot = ReactorSnapshotV1 {
            schema_version: SCHEMA_VERSION_V1,
            monotonic_epoch: epoch.clone(),
            observed_at_epoch_monotonic_ms: 0,
            condition: ReactorConditionV1::Operational,
            condition_detail: "fixture".to_owned(),
            live_standing_available: true,
            certificates: Vec::new(),
            active_deadline_count: 1,
            earliest_deadline_monotonic_ms: Some(10),
            supporting_evidence_count: 1,
            runtime_metrics: RuntimeMetricsV1::empty(),
            reactor_metrics: ReactorMetricsV1::empty(),
            clean_shutdown: false,
            mutation_authority: MutationAuthorityV1::None,
        };
        let reactor = LocalCrashReactor {
            shared: Arc::new((
                Mutex::new(SharedState {
                    queue,
                    live_support_queries: VecDeque::new(),
                    accepting_commands: true,
                    overload_latched: false,
                    response_timeout_latched: false,
                    abandoned: false,
                    shutdown_requested: false,
                    snapshot,
                }),
                Condvar::new(),
            )),
            clock: ReactorClock {
                origin: Instant::now(),
                origin_runtime_monotonic_ms: 0,
            },
            config,
            journal_path: PathBuf::from("/tmp/nonexistent-mailbox-fixture"),
            transport_custody_policy: None,
            join: None,
        };
        let error = reactor
            .submit_input(RuntimeInputV1::RestoreMonitorCapability {
                subject: None,
                detail: "refused".to_owned(),
            })
            .expect_err("full mailbox refuses");
        assert_eq!(error.class, ReactorCommandErrorClassV1::QueueSaturated);
        let snapshot = reactor.snapshot();
        assert_eq!(snapshot.condition, ReactorConditionV1::MailboxOverloaded);
        assert!(!snapshot.live_standing_available);
        assert!(snapshot.certificates.is_empty());
        assert_eq!(snapshot.active_deadline_count, 0);
        let state = reactor.shared.0.lock().expect("shared state");
        assert_eq!(state.queue.len(), 1);
        assert!(state.overload_latched);
    }

    #[test]
    fn actor_unwind_immediately_withdraws_shared_temporal_custody() {
        let epoch = MonotonicEpochV1 {
            schema_version: SCHEMA_VERSION_V1,
            epoch_id: pulse_types::IncarnationId::new("epoch:actor-unwind"),
            receiver: pulse_types::ReceiverId::new("receiver:actor-unwind"),
            receiver_incarnation: pulse_types::IncarnationId::new(
                "receiver-incarnation:actor-unwind",
            ),
            clock_id: pulse_types::ClockId::new("clock:actor-unwind"),
            origin_runtime_monotonic_ms: 0,
            clock_source: "std::time::Instant/process-local".to_owned(),
        };
        let mut snapshot = ReactorSnapshotV1::unavailable(
            epoch.clone(),
            0,
            ReactorConditionV1::Operational,
            "fixture current surface",
            RuntimeMetricsV1::empty(),
            ReactorMetricsV1::empty(),
        );
        snapshot.live_standing_available = true;
        snapshot.active_deadline_count = 1;
        snapshot.earliest_deadline_monotonic_ms = Some(10);
        snapshot.supporting_evidence_count = 1;
        let shared = Arc::new((
            Mutex::new(SharedState {
                queue: VecDeque::new(),
                live_support_queries: VecDeque::new(),
                accepting_commands: true,
                overload_latched: false,
                response_timeout_latched: false,
                abandoned: false,
                shutdown_requested: false,
                snapshot,
            }),
            Condvar::new(),
        ));
        let clock = ReactorClock {
            origin: Instant::now(),
            origin_runtime_monotonic_ms: 0,
        };

        guard_actor_unwind(&shared, &epoch, &clock, || panic!("injected actor unwind"));

        let state = shared.0.lock().expect("shared state remains inspectable");
        assert!(!state.accepting_commands);
        assert_eq!(
            state.snapshot.condition,
            ReactorConditionV1::ActorTerminated
        );
        assert!(!state.snapshot.live_standing_available);
        assert!(state.snapshot.certificates.is_empty());
        assert_eq!(state.snapshot.active_deadline_count, 0);
        assert_eq!(state.snapshot.supporting_evidence_count, 0);
    }

    #[test]
    fn live_support_expiry_boundary_is_exclusive_and_low_rounding_is_removed() {
        assert_eq!(
            live_support_remaining(JudgmentCategoryV1::Current, Some(102), 100),
            (LivePresentSupportDispositionV1::SupportedCurrent, Some(1))
        );
        assert_eq!(
            live_support_remaining(JudgmentCategoryV1::Current, Some(101), 100),
            (LivePresentSupportDispositionV1::Expired, None)
        );
        assert_eq!(
            live_support_remaining(JudgmentCategoryV1::Current, Some(100), 100),
            (LivePresentSupportDispositionV1::Expired, None)
        );
        assert_eq!(
            live_support_remaining(JudgmentCategoryV1::Unknown, None, 100),
            (LivePresentSupportDispositionV1::Unsupported, None)
        );
    }

    #[test]
    fn live_query_saturation_and_timeout_do_not_latch_blindness() {
        let (sender, _receiver) = mpsc::sync_channel(1);
        let existing = LiveSupportQueryCommand {
            request: live_query_request("nonce:existing"),
            response: sender,
        };
        let saturated = query_test_reactor(VecDeque::from([existing]), 1);
        let (sender, _receiver) = mpsc::sync_channel(1);
        let error = saturated
            .submit_live_support_query(LiveSupportQueryCommand {
                request: live_query_request("nonce:new"),
                response: sender,
            })
            .expect_err("full query lane refuses");
        assert_eq!(error.class, ReactorCommandErrorClassV1::QueueSaturated);
        let state = saturated.shared.0.lock().expect("shared state");
        assert!(!state.overload_latched);
        assert!(!state.response_timeout_latched);
        assert_eq!(state.snapshot.condition, ReactorConditionV1::Operational);
        drop(state);

        let timed_out = query_test_reactor(VecDeque::new(), 1);
        let error = timed_out
            .query_live_present_support(live_query_request("nonce:timeout"))
            .expect_err("query with no actor times out");
        assert_eq!(error.class, ReactorCommandErrorClassV1::ResponseTimeout);
        let state = timed_out.shared.0.lock().expect("shared state");
        assert!(!state.overload_latched);
        assert!(!state.response_timeout_latched);
        assert_eq!(state.snapshot.condition, ReactorConditionV1::Operational);
    }

    #[test]
    fn checked_in_live_support_conformance_vectors_hold() {
        let vectors: LiveSupportConformanceVectors = serde_json::from_str(include_str!(
            "../../../artifacts/live-present-support-v1/conformance-vectors.json"
        ))
        .expect("conformance vectors parse");
        assert_eq!(vectors.schema, "pulse.live_present_support_conformance.v1");
        assert_eq!(vectors.qualification_cases.len(), 14);

        for vector in vectors.duration_vectors {
            assert_eq!(
                live_support_remaining(vector.judgment, vector.expiry_ms, vector.measured_at_ms),
                (vector.expected_disposition, vector.expected_remaining_ms),
                "{}",
                vector.id
            );
        }

        let base_request = live_query_request("nonce:vector-base");
        for vector in vectors.caller_decay_vectors {
            let response = LivePresentSupportResponseV1::new(
                base_request.clone(),
                base_request.receiver.clone(),
                base_request.receiver_incarnation.clone(),
                base_request.receiver_epoch_id.clone(),
                base_request.receiver_clock_id.clone(),
                "std::time::Instant/process-local".to_owned(),
                100,
                LivePresentSupportDispositionV1::SupportedCurrent,
                Some(vector.response_remaining_ms),
            );
            assert_eq!(
                response.conservative_remaining_lifetime_ms(vector.elapsed_since_send_ms),
                vector.expected_usable_remaining_ms,
                "{}",
                vector.id
            );
        }

        let response = LivePresentSupportResponseV1::new(
            base_request.clone(),
            base_request.receiver.clone(),
            base_request.receiver_incarnation.clone(),
            base_request.receiver_epoch_id.clone(),
            base_request.receiver_clock_id.clone(),
            "std::time::Instant/process-local".to_owned(),
            100,
            LivePresentSupportDispositionV1::SupportedCurrent,
            Some(9),
        );
        for vector in vectors.request_binding_vectors {
            let mut candidate = base_request.clone();
            match vector.mutation.as_str() {
                "none" => {}
                "request_nonce" => {
                    candidate.request_nonce =
                        pulse_types::LivePresentSupportNonce::new("nonce:substituted")
                }
                "consumer" => candidate.consumer = ConsumerId::new("consumer:substituted"),
                "policy_generation" => {
                    candidate.reliance_context.reliance_policy_generation =
                        pulse_types::PolicyGenerationId::new("policy:substituted");
                    candidate.reliance_context_digest =
                        candidate.reliance_context.identity_digest();
                }
                "support_identity" => {
                    candidate.support_certificate_id =
                        pulse_types::SupportCertificateId::new("support:substituted")
                }
                "qualified_generation" => {
                    candidate.qualified_generation_digest =
                        digest_parts("qualified", &[b"substituted"])
                }
                "evidence_window" => {
                    candidate.evidence_window_id =
                        pulse_types::EvidenceWindowId::new("window:substituted")
                }
                "receiver_epoch" => {
                    candidate.receiver_epoch_id =
                        pulse_types::IncarnationId::new("epoch:substituted")
                }
                other => panic!("unknown conformance mutation: {other}"),
            }
            assert_eq!(
                response.validate_against(&candidate).is_ok(),
                vector.accepted,
                "{}",
                vector.id
            );
        }
    }
}
