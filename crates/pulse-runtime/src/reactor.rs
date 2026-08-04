//! One local monotonic actor that owns waking for deterministic runtime deadlines.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use pulse_types::{
    ConsumerId, DigestV1, MutationAuthorityV1, QualifiedGenerationBindingV1,
    RelianceSupportCertificateV1, RuntimeMetricsV1, SCHEMA_VERSION_V1, SparseDurableEventKindV1,
    SparseDurableEventV1, SubjectId, TransportCustodyPolicyBindingV1, digest_parts,
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
    QueueSaturated,
    NotOperational,
    ResponseTimeout,
    ActorTerminated,
    RuntimeFailure,
    JournalFailure,
    ThreadSpawnFailure,
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
        let (mut commands, overload, response_timeout, abandoned, shutdown, timed_out) = match wait
        {
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
        } else if !commands.is_empty() {
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

type ActorWake = (VecDeque<ActorCommand>, bool, bool, bool, bool, bool);

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
            || state.overload_latched
            || state.response_timeout_latched
            || state.abandoned
            || state.shutdown_requested
            || deadline_due
        {
            let commands = std::mem::take(&mut state.queue);
            let overload = std::mem::take(&mut state.overload_latched);
            let response_timeout = std::mem::take(&mut state.response_timeout_latched);
            return Ok((
                commands,
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
                let overload = std::mem::take(&mut next.overload_latched);
                let response_timeout = std::mem::take(&mut next.response_timeout_latched);
                return Ok((
                    commands,
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
}
