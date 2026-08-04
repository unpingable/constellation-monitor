//! Named Linux child-process crash injection for the local custody campaign.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Read as _, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use pulse_evaluator::{EscalationPolicyV1, ReliancePolicyV1};
use pulse_l3_bridge::stub_profile_identity;
use pulse_types::{
    AuthenticationFieldV1, AuthenticationResultV1, BoundedSignalValueV1, ClockId, ConsumerId,
    ConsumerProfileGenerationId, ContextActivationId, ContradictionApplicabilityV1,
    ContradictionCustodyV1, ContradictionId, ContradictionRecordV1, ContradictionStatusV1,
    CoverageDescriptorV1, DiagnosticBoundsV1, DigestV1, EscalationRequestId,
    EvaluatorSemanticGenerationId, IncarnationId, JudgmentCategoryV1, MutationAuthorityV1,
    ObservationPolicyGenerationId, ObservationProfileIdV1, ObserverId, ObserverSetGenerationId,
    PolicyGenerationId, PulseFrameV1, ReceiverId, RelianceContextV1, SCHEMA_VERSION_V1,
    SignalAssessmentV1, SparseDurableEventKindV1, SparseDurableEventV1, SparseEventId, SubjectId,
    SubjectScopeV1, digest_parts,
};
use serde::{Deserialize, Serialize};

use crate::reactor::ReactorQualificationPointV1;
use crate::{
    ConsumerRegistrationV1, HistoricalJournal, JournalBoundsV1, JournalConfigV1,
    JournalDamageClassV1, JournalDurabilityModeV1, JournalRecordBodyV1, JournalRecoveryOutcomeV1,
    JournalWriteStageV1, LocalCrashReactor, MonotonicEpochV1, PulseIngressV1, ReactorConfigV1,
    ReceiverSchedulerRuntime, RuntimeBoundsV1, RuntimeConfigV1, RuntimeInputV1,
};

const SUBJECT: &str = "subject:crash-fixture";
const CONSUMER: &str = "consumer:crash-fixture";
const SUBJECT_INCAR: &str = "subject-incarnation:crash-one";
const POLICY_GENERATION: &str = "policy:crash-one";
const OBSERVATION_GENERATION: &str = "observation-policy:crash-one";
const SUPPORT_MS: u64 = 300;

const SCENARIOS: &[&str] = &[
    "before_deadline_arming",
    "after_deadline_arming",
    "before_expiry",
    "after_expiry_before_withdrawal_journaled",
    "after_withdrawal_written_before_sync",
    "after_sync_before_acknowledgement",
    "during_record_framing",
    "during_payload_write",
    "during_trailer_checksum_write",
    "after_contradiction_custody_persisted",
    "after_escalation_deduplication_persisted",
    "during_clean_shutdown",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrashScenarioResultV1 {
    pub name: String,
    pub marker_observed: bool,
    pub child_killed: bool,
    pub journal_outcome: JournalRecoveryOutcomeV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal_damage: Option<JournalDamageClassV1>,
    pub records_recovered: usize,
    pub history_complete: bool,
    pub historical_current_records: usize,
    pub current_standing_after_restart: JudgmentCategoryV1,
    pub supporting_evidence_after_restart: usize,
    pub active_deadlines_after_restart: usize,
    pub contradiction_custody_recovered: usize,
    pub historical_escalation_deduplication_keys: usize,
    pub active_escalation_suppression_restored: bool,
    pub durability_point_reached_before_kill: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_append_acknowledgement_returned_before_kill: Option<bool>,
    pub acknowledgement_delivery_known_after_restart: bool,
    pub mutation_authority: MutationAuthorityV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrashHarnessArtifactV1 {
    pub schema_version: u16,
    pub harness: String,
    pub platform: String,
    pub kill_mechanism: String,
    pub scenarios: Vec<CrashScenarioResultV1>,
    pub all_restart_invariants_held: bool,
    pub current_standing_reconstructed: bool,
    pub active_escalation_authority_reconstructed: bool,
    pub nonclaims: Vec<String>,
}

pub fn run_crash_harness(executable: &Path) -> Result<CrashHarnessArtifactV1, io::Error> {
    if !cfg!(target_os = "linux") {
        return Err(io::Error::other(
            "the process-kill crash harness is qualified only on Linux",
        ));
    }
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "monitor-crash-harness-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root)?;
    let result = run_harness_in(executable, &root);
    let cleanup = fs::remove_dir_all(&root);
    match (result, cleanup) {
        (Ok(artifact), Ok(())) => Ok(artifact),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

fn run_harness_in(executable: &Path, root: &Path) -> Result<CrashHarnessArtifactV1, io::Error> {
    let mut scenarios = Vec::new();
    for name in SCENARIOS {
        let journal_path = root.join(format!("{name}.journal"));
        let marker_path = root.join(format!("{name}.marker"));
        let mut child = Command::new(executable)
            .arg("crash-child")
            .arg(name)
            .arg(&journal_path)
            .arg(&marker_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        let wait_started = Instant::now();
        loop {
            if marker_path.exists() {
                break;
            }
            if let Some(status) = child.try_wait()? {
                let mut stderr_bytes = Vec::new();
                if let Some(mut stderr) = child.stderr.take() {
                    let _ = stderr.read_to_end(&mut stderr_bytes);
                }
                return Err(io::Error::other(format!(
                    "crash child {name} exited before marker ({status}): {}",
                    String::from_utf8_lossy(&stderr_bytes)
                )));
            }
            if wait_started.elapsed() > Duration::from_secs(10) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::other(format!(
                    "crash child {name} did not reach its injection marker"
                )));
            }
            thread::sleep(Duration::from_millis(2));
        }
        child.kill()?;
        let status = child.wait()?;
        let child_killed = !status.success();
        let journal_config = journal_config(name);
        let report = HistoricalJournal::scan(&journal_path, &journal_config)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let projection = report
            .project_history()
            .map_err(|error| io::Error::other(error.to_string()))?;
        let restart_config = runtime_config(
            &format!("receiver-incarnation:restart-{name}"),
            &format!("clock:restart-{name}"),
        );
        let (restarted, _) = ReceiverSchedulerRuntime::recover(
            restart_config,
            vec![registration(
                policy(),
                &format!("activation:restart-{name}"),
            )],
            projection.history.clone(),
            0,
        )
        .map_err(|error| io::Error::other(error.to_string()))?;
        let certificate = restarted
            .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
            .ok_or_else(|| io::Error::other("restart certificate is absent"))?;
        let durability_point_reached_before_kill = matches!(
            *name,
            "after_sync_before_acknowledgement"
                | "after_contradiction_custody_persisted"
                | "after_escalation_deduplication_persisted"
        );
        let target_append_acknowledgement_returned_before_kill = match *name {
            "after_withdrawal_written_before_sync"
            | "after_sync_before_acknowledgement"
            | "during_record_framing"
            | "during_payload_write"
            | "during_trailer_checksum_write" => Some(false),
            "after_contradiction_custody_persisted"
            | "after_escalation_deduplication_persisted" => Some(true),
            _ => None,
        };
        scenarios.push(CrashScenarioResultV1 {
            name: (*name).to_owned(),
            marker_observed: true,
            child_killed,
            journal_outcome: report.outcome,
            journal_damage: report.damage,
            records_recovered: report.records_recovered,
            history_complete: report.history_complete,
            historical_current_records: report.historical_current_record_count(),
            current_standing_after_restart: certificate.judgment,
            supporting_evidence_after_restart: certificate.supporting_evidence_ids.len(),
            active_deadlines_after_restart: restarted.scheduled_deadline_count(),
            contradiction_custody_recovered: projection.history.contradictions.len(),
            historical_escalation_deduplication_keys: projection
                .historical_escalation_deduplication_keys
                .len(),
            active_escalation_suppression_restored: projection
                .active_escalation_suppression_restored,
            durability_point_reached_before_kill,
            target_append_acknowledgement_returned_before_kill,
            acknowledgement_delivery_known_after_restart: false,
            mutation_authority: MutationAuthorityV1::None,
        });
    }
    let all_restart_invariants_held = scenarios.iter().all(|scenario| {
        scenario.marker_observed
            && scenario.child_killed
            && scenario.current_standing_after_restart == JudgmentCategoryV1::Unknown
            && scenario.supporting_evidence_after_restart == 0
            && scenario.active_deadlines_after_restart == 0
            && !scenario.active_escalation_suppression_restored
            && scenario.mutation_authority == MutationAuthorityV1::None
    });
    Ok(CrashHarnessArtifactV1 {
        schema_version: SCHEMA_VERSION_V1,
        harness: "named child-process crash injection".to_owned(),
        platform: "linux".to_owned(),
        kill_mechanism: "std::process::Child::kill (SIGKILL on qualified Linux host)".to_owned(),
        scenarios,
        all_restart_invariants_held,
        current_standing_reconstructed: false,
        active_escalation_authority_reconstructed: false,
        nonclaims: vec![
            "process-kill recovery is not a host-crash or physical-media durability proof"
                .to_owned(),
            "recovery cannot determine whether a post-sync in-memory acknowledgement reached its caller"
                .to_owned(),
            "historical escalation deduplication evidence restores no active suppression or execution authority"
                .to_owned(),
            "no recovered record grants mutation authority".to_owned(),
        ],
    })
}

#[doc(hidden)]
pub fn run_crash_child(
    scenario: &str,
    journal_path: &Path,
    marker_path: &Path,
) -> Result<(), io::Error> {
    if !SCENARIOS.contains(&scenario) {
        return Err(io::Error::other("unknown crash injection scenario"));
    }
    let config = runtime_config("receiver-incarnation:crash-child", "clock:crash-child");
    let mut runtime = current_runtime(config.clone())?;
    let epoch = epoch(&config, "epoch:crash-child", 0);
    let journal_config = journal_config(scenario);
    let mut journal = HistoricalJournal::create_new(journal_path, journal_config)
        .map_err(|error| io::Error::other(error.to_string()))?;
    persist_full_history(&mut journal, &runtime, &epoch, 0)?;

    match scenario {
        "before_deadline_arming"
        | "after_deadline_arming"
        | "after_expiry_before_withdrawal_journaled"
        | "during_clean_shutdown" => {
            let target = match scenario {
                "before_deadline_arming" => ReactorQualificationPointV1::BeforeDeadlineArming,
                "after_deadline_arming" => ReactorQualificationPointV1::AfterDeadlineArming,
                "after_expiry_before_withdrawal_journaled" => {
                    ReactorQualificationPointV1::DeadlineProcessedBeforeJournal
                }
                "during_clean_shutdown" => ReactorQualificationPointV1::CleanShutdownBegan,
                _ => unreachable!(),
            };
            let marker = marker_path.to_path_buf();
            let hook = Box::new(move |point| {
                if point == target {
                    pause_for_parent(&marker, &format!("{point:?}"));
                }
            });
            let reactor = LocalCrashReactor::start_with_qualification_hook(
                runtime,
                journal,
                epoch,
                ReactorConfigV1::qualification(),
                hook,
            )
            .map_err(|error| io::Error::other(error.to_string()))?;
            if scenario == "during_clean_shutdown" {
                let _ = reactor.shutdown();
            } else {
                park_forever();
            }
        }
        "before_expiry" => {
            let reactor =
                LocalCrashReactor::start(runtime, journal, epoch, ReactorConfigV1::qualification())
                    .map_err(|error| io::Error::other(error.to_string()))?;
            reactor
                .wait_until(Duration::from_secs(2), |snapshot| {
                    snapshot.active_deadline_count == 1
                })
                .map_err(|error| io::Error::other(error.to_string()))?;
            thread::sleep(Duration::from_millis(SUPPORT_MS / 3));
            pause_for_parent(marker_path, "before_expiry");
        }
        "after_withdrawal_written_before_sync" | "after_sync_before_acknowledgement" => {
            let output = runtime
                .run_until(SUPPORT_MS)
                .map_err(|error| io::Error::other(error.to_string()))?;
            let withdrawal = output
                .sparse_events
                .into_iter()
                .find(|event| {
                    matches!(
                        &event.event,
                        SparseDurableEventKindV1::SupportCertificateIssued { certificate }
                            if certificate.judgment == JudgmentCategoryV1::Unknown
                    )
                })
                .ok_or_else(|| io::Error::other("withdrawal event is absent"))?;
            let target = if scenario == "after_withdrawal_written_before_sync" {
                JournalWriteStageV1::FrameWrittenBeforeSync
            } else {
                JournalWriteStageV1::CommitMarkerSyncedBeforeAcknowledgement
            };
            append_and_pause(
                &mut journal,
                epoch,
                SUPPORT_MS,
                JournalRecordBodyV1::SparseEvent { event: withdrawal },
                target,
                marker_path,
            )?;
        }
        "during_record_framing" | "during_payload_write" | "during_trailer_checksum_write" => {
            let target = match scenario {
                "during_record_framing" => JournalWriteStageV1::HeaderPartiallyWritten,
                "during_payload_write" => JournalWriteStageV1::PayloadPartiallyWritten,
                "during_trailer_checksum_write" => JournalWriteStageV1::TrailerPartiallyWritten,
                _ => unreachable!(),
            };
            append_and_pause(
                &mut journal,
                epoch,
                1,
                synthetic_event("crash-final-write"),
                target,
                marker_path,
            )?;
        }
        "after_contradiction_custody_persisted" => {
            journal
                .append(
                    epoch,
                    1,
                    None,
                    JournalRecordBodyV1::ContradictionCustody {
                        custody: contradiction_custody(),
                    },
                    JournalDurabilityModeV1::FileSynced,
                )
                .map_err(|error| io::Error::other(error.to_string()))?;
            pause_for_parent(marker_path, "contradiction_custody_committed");
        }
        "after_escalation_deduplication_persisted" => {
            journal
                .append(
                    epoch,
                    1,
                    None,
                    synthetic_escalation_dedup_event(),
                    JournalDurabilityModeV1::FileSynced,
                )
                .map_err(|error| io::Error::other(error.to_string()))?;
            pause_for_parent(marker_path, "escalation_deduplication_history_committed");
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn append_and_pause(
    journal: &mut HistoricalJournal,
    epoch: MonotonicEpochV1,
    at: u64,
    body: JournalRecordBodyV1,
    target: JournalWriteStageV1,
    marker_path: &Path,
) -> Result<(), io::Error> {
    let marker = marker_path.to_path_buf();
    let mut hook = move |stage| {
        if stage == target {
            pause_for_parent(&marker, &format!("{stage:?}"));
        }
        #[allow(unreachable_code)]
        Ok(())
    };
    journal
        .append_with_qualification_hook(
            epoch,
            at,
            None,
            body,
            JournalDurabilityModeV1::FileSynced,
            &mut hook,
        )
        .map(|_| ())
        .map_err(|error| io::Error::other(error.to_string()))
}

fn pause_for_parent(marker_path: &Path, detail: &str) -> ! {
    let mut marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(marker_path)
        .expect("crash marker create");
    marker
        .write_all(detail.as_bytes())
        .expect("crash marker write");
    marker.sync_all().expect("crash marker sync");
    park_forever()
}

fn park_forever() -> ! {
    loop {
        thread::park_timeout(Duration::from_secs(60));
    }
}

pub(crate) fn journal_config(scenario: &str) -> JournalConfigV1 {
    JournalConfigV1 {
        schema_version: SCHEMA_VERSION_V1,
        journal_id: format!("journal:crash:{scenario}"),
        bounds: JournalBoundsV1 {
            maximum_records: 512,
            maximum_record_payload_bytes: 256 * 1_024,
            maximum_file_bytes: 16 * 1_024 * 1_024,
        },
    }
}

pub(crate) fn runtime_config(receiver_incarnation: &str, clock: &str) -> RuntimeConfigV1 {
    RuntimeConfigV1 {
        schema_version: SCHEMA_VERSION_V1,
        receiver: ReceiverId::new("receiver:crash-fixture"),
        receiver_incarnation: IncarnationId::new(receiver_incarnation),
        clock_id: ClockId::new(clock),
        transport_custody_policy: None,
        bounds: RuntimeBoundsV1::qualification(),
    }
}

pub(crate) fn epoch(config: &RuntimeConfigV1, id: &str, origin: u64) -> MonotonicEpochV1 {
    MonotonicEpochV1 {
        schema_version: SCHEMA_VERSION_V1,
        epoch_id: IncarnationId::new(id),
        receiver: config.receiver.clone(),
        receiver_incarnation: config.receiver_incarnation.clone(),
        clock_id: config.clock_id.clone(),
        origin_runtime_monotonic_ms: origin,
        clock_source: "std::time::Instant/process-local".to_owned(),
    }
}

fn profile() -> ObservationProfileIdV1 {
    ObservationProfileIdV1 {
        name: "profile:crash-fixture".to_owned(),
        version: 1,
        semantic_digest: digest_parts("crash.fixture.profile", &[b"load"]),
    }
}

pub(crate) fn policy() -> ReliancePolicyV1 {
    ReliancePolicyV1 {
        schema_version: SCHEMA_VERSION_V1,
        subject: SubjectId::new(SUBJECT),
        scope: "host".to_owned(),
        consumer: ConsumerId::new(CONSUMER),
        generation: PolicyGenerationId::new(POLICY_GENERATION),
        observation_policy_generation: ObservationPolicyGenerationId::new(OBSERVATION_GENERATION),
        observation_profile: profile(),
        required_coverage: vec!["load".to_owned()],
        minimum_observers: 1,
        maximum_validity_ms: SUPPORT_MS,
        require_verified_authentication: true,
        coherence_tolerances: BTreeMap::new(),
        observer_failure_domains: BTreeMap::new(),
        escalation: Some(EscalationPolicyV1 {
            triggers: [
                pulse_types::EscalationTriggerClassV1::FreshnessLost,
                pulse_types::EscalationTriggerClassV1::CoverageCollapse,
                pulse_types::EscalationTriggerClassV1::ContradictionRetained,
                pulse_types::EscalationTriggerClassV1::SubjectBoundViolated,
                pulse_types::EscalationTriggerClassV1::TransportBlind,
            ]
            .into_iter()
            .collect::<BTreeSet<_>>(),
            diagnostic_profile: stub_profile_identity(),
            bounds: DiagnosticBoundsV1 {
                maximum_runtime_ms: 25,
                maximum_output_bytes: 1_024,
                maximum_observations: 4,
            },
            request_ttl_ms: 250,
        }),
    }
}

pub(crate) fn registration(
    policy: ReliancePolicyV1,
    activation_id: &str,
) -> ConsumerRegistrationV1 {
    let context = RelianceContextV1 {
        schema_version: SCHEMA_VERSION_V1,
        activation_id: ContextActivationId::new(activation_id),
        reliance_policy_generation: policy.generation.clone(),
        reliance_policy_semantic_digest: policy.semantic_digest(),
        consumer_profile_generation: ConsumerProfileGenerationId::new("consumer-profile:crash"),
        evaluator_semantic_generation: EvaluatorSemanticGenerationId::new("evaluator:crash"),
        observer_set_generation: ObserverSetGenerationId::new("observer-set:crash"),
        observation_policy_generation: policy.observation_policy_generation.clone(),
    };
    ConsumerRegistrationV1 {
        policy,
        context,
        subject_incarnation: IncarnationId::new(SUBJECT_INCAR),
    }
}

pub(crate) fn registered_runtime(
    config: RuntimeConfigV1,
) -> Result<ReceiverSchedulerRuntime, io::Error> {
    let mut runtime = ReceiverSchedulerRuntime::new(config)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let registration = registration(policy(), "activation:crash-child");
    runtime
        .qualify_and_activate_local_binding(
            &registration,
            crate::qualification_fixture_inputs("3cd15b7a1e7f424f6fd57c09b30fa4790947eca2", 97),
            0,
        )
        .map_err(|error| io::Error::other(error.to_string()))?;
    runtime
        .register_consumer(registration, 0)
        .map_err(|error| io::Error::other(error.to_string()))?;
    Ok(runtime)
}

fn current_runtime(config: RuntimeConfigV1) -> Result<ReceiverSchedulerRuntime, io::Error> {
    let mut runtime = registered_runtime(config)?;
    runtime
        .enqueue(0, ingress())
        .map_err(|refusal| io::Error::other(format!("{refusal:?}")))?;
    runtime
        .run_until(0)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let current = runtime
        .current_certificate(&SubjectId::new(SUBJECT), &ConsumerId::new(CONSUMER))
        .is_some_and(|certificate| certificate.judgment == JudgmentCategoryV1::Current);
    if !current {
        return Err(io::Error::other(
            "crash fixture did not establish bounded CURRENT",
        ));
    }
    Ok(runtime)
}

pub(crate) fn ingress() -> RuntimeInputV1 {
    ingress_with_sequence(1)
}

pub(crate) fn ingress_with_sequence(sequence: u64) -> RuntimeInputV1 {
    ingress_with_sequence_and_validity(sequence, SUPPORT_MS)
}

pub(crate) fn ingress_with_sequence_and_validity(
    sequence: u64,
    validity_ms: u64,
) -> RuntimeInputV1 {
    let frame = PulseFrameV1 {
        schema_version: SCHEMA_VERSION_V1,
        subject: SubjectId::new(SUBJECT),
        subject_incarnation: IncarnationId::new(SUBJECT_INCAR),
        observer: ObserverId::new("observer:crash-fixture"),
        observer_incarnation: IncarnationId::new("observer-incarnation:crash-one"),
        sequence,
        observer_monotonic_ns: sequence.saturating_mul(1_000_000),
        validity_ms,
        profile: profile(),
        observation_policy_generation: ObservationPolicyGenerationId::new(OBSERVATION_GENERATION),
        coverage: CoverageDescriptorV1 {
            expected: vec!["load".to_owned()],
            observed: vec!["load".to_owned()],
        },
        signals: vec![BoundedSignalValueV1 {
            name: "load_ratio".to_owned(),
            value: 0.2,
            unit: "ratio".to_owned(),
            assessment: SignalAssessmentV1::WithinDeclaredBound,
        }],
        observation_digest: digest_parts("unsealed", &[]),
        authentication: AuthenticationFieldV1::Placeholder {
            disclosure: "crash fixture".to_owned(),
        },
    }
    .seal();
    RuntimeInputV1::Pulse(PulseIngressV1 {
        frame,
        transport_path: "local:crash-fixture".to_owned(),
        transport_observed_delay_ms: Some(0),
        authentication: AuthenticationResultV1::Verified {
            method: "fixture".to_owned(),
            principal: "observer:crash-fixture".to_owned(),
        },
    })
}

fn persist_full_history(
    journal: &mut HistoricalJournal,
    runtime: &ReceiverSchedulerRuntime,
    epoch: &MonotonicEpochV1,
    now: u64,
) -> Result<(), io::Error> {
    let history = runtime.export_history();
    for event in history.sparse_events {
        journal
            .append(
                epoch.clone(),
                now,
                sparse_context_digest(&event),
                JournalRecordBodyV1::SparseEvent { event },
                JournalDurabilityModeV1::FileSynced,
            )
            .map_err(|error| io::Error::other(error.to_string()))?;
    }
    for custody in history.contradictions {
        journal
            .append(
                epoch.clone(),
                now,
                None,
                JournalRecordBodyV1::ContradictionCustody { custody },
                JournalDurabilityModeV1::FileSynced,
            )
            .map_err(|error| io::Error::other(error.to_string()))?;
    }
    for receipt in history.diagnostic_receipts {
        journal
            .append(
                epoch.clone(),
                now,
                None,
                JournalRecordBodyV1::DiagnosticReceipt { receipt },
                JournalDurabilityModeV1::FileSynced,
            )
            .map_err(|error| io::Error::other(error.to_string()))?;
    }
    Ok(())
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

pub(crate) fn synthetic_event(label: &str) -> JournalRecordBodyV1 {
    JournalRecordBodyV1::SparseEvent {
        event: SparseDurableEventV1 {
            schema_version: SCHEMA_VERSION_V1,
            event_id: SparseEventId::new(format!("event:{label}")),
            at_monotonic_ms: 1,
            event: SparseDurableEventKindV1::MonitorCapabilityChanged {
                state: "crash_injection".to_owned(),
                detail: label.to_owned(),
            },
        },
    }
}

fn synthetic_escalation_dedup_event() -> JournalRecordBodyV1 {
    JournalRecordBodyV1::SparseEvent {
        event: SparseDurableEventV1 {
            schema_version: SCHEMA_VERSION_V1,
            event_id: SparseEventId::new("event:historical-escalation-dedup"),
            at_monotonic_ms: 1,
            event: SparseDurableEventKindV1::EscalationDeduplicated {
                deduplication_key: digest_parts("crash.escalation.dedup", &[b"exact-key"]),
                active_request_id: EscalationRequestId::new("escalation:crash-historical"),
            },
        },
    }
}

fn contradiction_custody() -> ContradictionCustodyV1 {
    ContradictionCustodyV1 {
        schema_version: SCHEMA_VERSION_V1,
        consumer: ConsumerId::new(CONSUMER),
        contradiction: ContradictionRecordV1 {
            schema_version: SCHEMA_VERSION_V1,
            contradiction_id: ContradictionId::new("contradiction:crash-custody"),
            subject_scope: SubjectScopeV1 {
                subject: SubjectId::new(SUBJECT),
                subject_incarnation: IncarnationId::new(SUBJECT_INCAR),
                scope: "host".to_owned(),
            },
            policy_generation: PolicyGenerationId::new(POLICY_GENERATION),
            signal: "load_ratio".to_owned(),
            first_observed_at_monotonic_ms: 1,
            evidence_refs: vec!["evidence:a".to_owned(), "evidence:b".to_owned()],
            incompatible_statements: vec!["within".to_owned(), "outside".to_owned()],
            status: ContradictionStatusV1::Active,
        },
        applicability: ContradictionApplicabilityV1::Applicable {
            subject_incarnation: IncarnationId::new(SUBJECT_INCAR),
            blocks_reliance: true,
        },
    }
}
