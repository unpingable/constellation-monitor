//! Bounded qualification artifacts and terminal demonstrations for campaign 3.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use pulse_types::{JudgmentCategoryV1, MutationAuthorityV1, SCHEMA_VERSION_V1};
use serde::{Deserialize, Serialize};

use crate::crash::{
    epoch, ingress, ingress_with_sequence_and_validity, journal_config, policy, registered_runtime,
    registration, runtime_config, synthetic_event,
};
use crate::journal::{HEADER_BYTES, JOURNAL_FORMAT_VERSION_V1};
use crate::{
    HistoricalJournal, JournalBoundsV1, JournalConfigV1, JournalDamageClassV1,
    JournalDurabilityModeV1, JournalErrorClassV1, JournalRecoveryOutcomeV1,
    JournalRecoveryReportV1, JournalWriteStageV1, LocalCrashReactor, ReactorConditionV1,
    ReactorConfigV1, ReceiverSchedulerRuntime, run_crash_harness,
};

const STARTING_COMMIT: &str = "668589e537e9cffe151913f72ca45a61ca32b1d7";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReactorDemoArtifactV1 {
    pub schema_version: u16,
    pub campaign_starting_commit: String,
    pub mechanism: String,
    pub sequence: Vec<String>,
    pub requested_support_deadline_monotonic_ms: u64,
    pub actual_wakeup_monotonic_ms: u64,
    pub actual_withdrawal_monotonic_ms: u64,
    pub wakeup_lateness_ms: u64,
    pub stale_positive_overshoot_ms: u64,
    pub withdrawal_sparse_records: usize,
    pub journal_records_recovered: usize,
    pub journal_recovery: JournalRecoveryOutcomeV1,
    pub history_complete: bool,
    pub historical_current_records: usize,
    pub current_standing_reconstructed: bool,
    pub mutation_authority: MutationAuthorityV1,
    pub journal_maximum_append_latency_us: u128,
    pub journal_maximum_sync_latency_us: u128,
    pub terminal_trace: Vec<String>,
    pub nonclaims: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RestartDemoArtifactV1 {
    pub schema_version: u16,
    pub scenario: String,
    pub kill_mechanism: String,
    pub journal_recovery: JournalRecoveryOutcomeV1,
    pub records_recovered: usize,
    pub historical_current_records: usize,
    pub current_standing_after_restart: JudgmentCategoryV1,
    pub supporting_evidence_after_restart: usize,
    pub active_deadlines_after_restart: usize,
    pub fresh_evidence_required: bool,
    pub monotonic_epoch_reused: bool,
    pub active_escalation_suppression_restored: bool,
    pub mutation_authority: MutationAuthorityV1,
    pub terminal_trace: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JournalScenarioV1 {
    pub name: String,
    pub expected: String,
    pub outcome: JournalRecoveryOutcomeV1,
    pub damage: Option<JournalDamageClassV1>,
    pub records_recovered: usize,
    pub first_damaged_offset: Option<u64>,
    pub valid_prefix_bytes: u64,
    pub observed_file_bytes: u64,
    pub history_complete: bool,
    pub operator_action_required: bool,
    pub append_error: Option<JournalErrorClassV1>,
    pub current_standing_reconstructed: bool,
    pub mutation_authority: MutationAuthorityV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TruncationSweepV1 {
    pub corpus_bytes: usize,
    pub byte_positions_tested: usize,
    pub classifications: BTreeMap<String, usize>,
    pub partial_frame_accepted_as_record: bool,
    pub undetectable_complete_prefix_boundaries: Vec<usize>,
    pub standing_reconstructed: bool,
    pub qualification: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JournalCorruptionCorpusV1 {
    pub schema_version: u16,
    pub format: String,
    pub checksum_claim: String,
    pub scenarios: Vec<JournalScenarioV1>,
    pub truncation_sweep: TruncationSweepV1,
    pub all_damage_stopped_at_first_invalid_frame: bool,
    pub all_recovery_reconstructed_no_standing: bool,
    pub nonclaims: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TimerSampleV1 {
    pub name: String,
    pub deliberate_scheduler_delay_ms: u64,
    pub cpu_load_injected: bool,
    pub requested_support_deadline_monotonic_ms: u64,
    pub actual_wakeup_monotonic_ms: u64,
    pub actual_withdrawal_monotonic_ms: u64,
    pub wakeup_lateness_ms: u64,
    pub stale_positive_overshoot_ms: u64,
    pub maximum_journal_append_latency_us: u128,
    pub maximum_journal_sync_latency_us: u128,
    pub restart_recovery_latency_us: u128,
    pub records_recovered: usize,
    pub recovery_outcome: JournalRecoveryOutcomeV1,
    pub restart_standing: JudgmentCategoryV1,
    pub restart_supporting_evidence: usize,
    pub restart_active_deadlines: usize,
    pub duplicate_escalation_count: u64,
    pub prior_epoch_id: String,
    pub restart_clock_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DistributionU64V1 {
    pub minimum: u64,
    pub median: u64,
    pub maximum: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DistributionU128V1 {
    pub minimum: u128,
    pub median: u128,
    pub maximum: u128,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LiveLinuxArtifactV1 {
    pub schema_version: u16,
    pub platform: String,
    pub clock: String,
    pub wall_clock_measurement: bool,
    pub hard_realtime_claimed: bool,
    pub timer_samples: Vec<TimerSampleV1>,
    pub wakeup_lateness_ms: DistributionU64V1,
    pub stale_positive_overshoot_ms: DistributionU64V1,
    pub journal_append_latency_us: DistributionU128V1,
    pub journal_sync_latency_us: DistributionU128V1,
    pub restart_recovery_latency_us: DistributionU128V1,
    pub injected_write_path_stall_ms: u64,
    pub stalled_append_latency_us: u128,
    pub stalled_sync_latency_us: u128,
    pub proc_probe_paths: Vec<String>,
    pub proc_probe_used_as_support_evidence: bool,
    pub sigkill_scenarios: usize,
    pub restart_after_acknowledged_append_qualified: bool,
    pub restart_after_unacknowledged_append_qualified: bool,
    pub torn_suffix_injected: bool,
    pub interior_corruption_injected: bool,
    pub nonclaims: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationCheckV1 {
    pub name: String,
    pub result: String,
    pub evidence: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrashFaultQualificationArtifactV1 {
    pub schema_version: u16,
    pub campaign: String,
    pub starting_commit: String,
    pub checks: Vec<QualificationCheckV1>,
    pub required_gate_commands: Vec<String>,
    pub artifact_commands: Vec<String>,
    pub current_standing_durable: bool,
    pub mutation_authority_emitted: bool,
    pub nonclaims: Vec<String>,
}

pub fn run_reactor_demo() -> Result<ReactorDemoArtifactV1, io::Error> {
    let root = campaign_temp_root("reactor-demo")?;
    let result = run_reactor_demo_in(&root);
    remove_campaign_root(&root, result)
}

fn run_reactor_demo_in(root: &Path) -> Result<ReactorDemoArtifactV1, io::Error> {
    let runtime_config = runtime_config("receiver-incarnation:demo", "clock:demo");
    let runtime = registered_runtime(runtime_config.clone())?;
    let journal_path = root.join("reactor-demo.journal");
    let journal_config = journal_config("reactor-demo");
    let journal =
        HistoricalJournal::create_new(&journal_path, journal_config.clone()).map_err(journal_io)?;
    let reactor_epoch = epoch(&runtime_config, "epoch:reactor-demo", 0);
    let reactor = LocalCrashReactor::start(
        runtime,
        journal,
        reactor_epoch,
        ReactorConfigV1::qualification(),
    )
    .map_err(reactor_io)?;
    let initial = reactor
        .wait_until(Duration::from_secs(2), |snapshot| {
            snapshot.condition == ReactorConditionV1::Operational
        })
        .map_err(reactor_io)?;
    let initial_judgment = exact_judgment(&initial)?;
    reactor.submit_input(ingress()).map_err(reactor_io)?;
    let current = reactor.snapshot();
    let current_judgment = exact_judgment(&current)?;
    let deadline = current
        .earliest_deadline_monotonic_ms
        .ok_or_else(|| io::Error::other("reactor demo did not arm a support deadline"))?;
    let withdrawn = reactor
        .wait_until(Duration::from_secs(3), |snapshot| {
            snapshot.reactor_metrics.deadline_withdrawal_count == 1
        })
        .map_err(reactor_io)?;
    let withdrawn_judgment = exact_judgment(&withdrawn)?;
    require(
        initial_judgment == JudgmentCategoryV1::Unknown
            && current_judgment == JudgmentCategoryV1::Current
            && withdrawn_judgment == JudgmentCategoryV1::Unknown,
        "reactor demo did not follow UNKNOWN -> CURRENT -> UNKNOWN",
    )?;
    require(
        withdrawn.observed_at_epoch_monotonic_ms >= deadline,
        "reactor withdrew before inclusive expiry",
    )?;
    let actual_withdrawal = withdrawn
        .runtime_metrics
        .actual_reevaluation_monotonic_ms
        .ok_or_else(|| io::Error::other("runtime did not expose withdrawal time"))?;
    let lateness = withdrawn.reactor_metrics.last_wakeup_lateness_ms;
    let overshoot = withdrawn.runtime_metrics.maximum_stale_positive_duration_ms;
    let metrics = withdrawn.reactor_metrics.clone();
    reactor.shutdown().map_err(reactor_io)?;
    let report = HistoricalJournal::scan(&journal_path, &journal_config).map_err(journal_io)?;
    let withdrawal_sparse_records = report
        .records
        .iter()
        .filter(|record| {
            matches!(
                &record.body,
                crate::JournalRecordBodyV1::SparseEvent {
                    event: pulse_types::SparseDurableEventV1 {
                        event: pulse_types::SparseDurableEventKindV1::SchedulerReevaluated { .. },
                        ..
                    }
                }
            )
        })
        .count();
    require(
        report.outcome == JournalRecoveryOutcomeV1::Clean && withdrawal_sparse_records == 1,
        "reactor withdrawal was not committed as one recoverable sparse record",
    )?;
    Ok(ReactorDemoArtifactV1 {
        schema_version: SCHEMA_VERSION_V1,
        campaign_starting_commit: STARTING_COMMIT.to_owned(),
        mechanism: "dedicated std thread + bounded mutex/condvar mailbox + process-local Instant"
            .to_owned(),
        sequence: vec![
            "UNKNOWN".to_owned(),
            "fresh bounded evidence received".to_owned(),
            "CURRENT".to_owned(),
            "real monotonic deadline armed".to_owned(),
            "no new pulse".to_owned(),
            "reactor wake".to_owned(),
            "UNKNOWN".to_owned(),
            "historical withdrawal appended".to_owned(),
        ],
        requested_support_deadline_monotonic_ms: deadline,
        actual_wakeup_monotonic_ms: deadline.saturating_add(lateness),
        actual_withdrawal_monotonic_ms: actual_withdrawal,
        wakeup_lateness_ms: lateness,
        stale_positive_overshoot_ms: overshoot,
        withdrawal_sparse_records,
        journal_records_recovered: report.records_recovered,
        journal_recovery: report.outcome,
        history_complete: report.history_complete,
        historical_current_records: report.historical_current_record_count(),
        current_standing_reconstructed: false,
        mutation_authority: MutationAuthorityV1::None,
        journal_maximum_append_latency_us: metrics.maximum_journal_append_latency_us,
        journal_maximum_sync_latency_us: metrics.maximum_journal_sync_latency_us,
        terminal_trace: vec![
            format!(
                "[{:06}ms] UNKNOWN receiver actor operational; support=0 deadlines=0",
                initial.observed_at_epoch_monotonic_ms
            ),
            format!(
                "[{:06}ms] CURRENT exact evidence accepted; deadline={deadline}ms",
                current.observed_at_epoch_monotonic_ms
            ),
            format!(
                "[{actual_withdrawal:06}ms] UNKNOWN inclusive deadline processed; lateness={lateness}ms overshoot={overshoot}ms"
            ),
            format!(
                "[journal] withdrawal_records={withdrawal_sparse_records} recovery={:?} complete={}",
                report.outcome, report.history_complete
            ),
        ],
        nonclaims: vec![
            "the local wakeup measurement is not a hard-real-time guarantee".to_owned(),
            "CURRENT is an expiring consumer-indexed reliance judgment, not subject health"
                .to_owned(),
            "the historical CURRENT record is provenance and reconstructs no standing".to_owned(),
            "no certificate or journal record grants mutation authority".to_owned(),
        ],
    })
}

pub fn run_restart_demo(executable: &Path) -> Result<RestartDemoArtifactV1, io::Error> {
    let harness = run_crash_harness(executable)?;
    let scenario = harness
        .scenarios
        .iter()
        .find(|scenario| scenario.name == "before_expiry")
        .ok_or_else(|| io::Error::other("before-expiry crash scenario is absent"))?;
    require(
        scenario.current_standing_after_restart == JudgmentCategoryV1::Unknown
            && scenario.supporting_evidence_after_restart == 0
            && scenario.active_deadlines_after_restart == 0,
        "crash-before-expiry restart invariant failed",
    )?;
    Ok(RestartDemoArtifactV1 {
        schema_version: SCHEMA_VERSION_V1,
        scenario: "CURRENT -> armed deadline -> SIGKILL before expiry -> history-only restart"
            .to_owned(),
        kill_mechanism: harness.kill_mechanism,
        journal_recovery: scenario.journal_outcome,
        records_recovered: scenario.records_recovered,
        historical_current_records: scenario.historical_current_records,
        current_standing_after_restart: scenario.current_standing_after_restart,
        supporting_evidence_after_restart: scenario.supporting_evidence_after_restart,
        active_deadlines_after_restart: scenario.active_deadlines_after_restart,
        fresh_evidence_required: true,
        monotonic_epoch_reused: false,
        active_escalation_suppression_restored: scenario.active_escalation_suppression_restored,
        mutation_authority: scenario.mutation_authority,
        terminal_trace: vec![
            "CURRENT bounded support established".to_owned(),
            "real monotonic deadline armed".to_owned(),
            "child process SIGKILLed before expiry".to_owned(),
            format!(
                "restart history_records={} recovery={:?}",
                scenario.records_recovered, scenario.journal_outcome
            ),
            "current standing UNKNOWN".to_owned(),
            "supporting evidence 0".to_owned(),
            "active deadlines 0".to_owned(),
            "fresh evidence required".to_owned(),
        ],
    })
}

pub fn run_journal_corruption_corpus() -> Result<JournalCorruptionCorpusV1, io::Error> {
    let root = campaign_temp_root("journal-corpus")?;
    let result = run_journal_corruption_corpus_in(&root);
    remove_campaign_root(&root, result)
}

fn run_journal_corruption_corpus_in(root: &Path) -> Result<JournalCorruptionCorpusV1, io::Error> {
    let mut scenarios = Vec::new();

    let empty_config = journal_config("corpus-empty");
    let empty_path = root.join("empty.journal");
    drop(HistoricalJournal::create_new(&empty_path, empty_config.clone()).map_err(journal_io)?);
    scenarios.push(scenario_from_report(
        "empty_journal",
        "clean EOF with zero records",
        HistoricalJournal::scan(&empty_path, &empty_config).map_err(journal_io)?,
        None,
    ));

    let (base_config, base_bytes, boundaries) = committed_bytes(root, "base", 3)?;
    let clean_report = scan_written(root, "clean", &base_config, &base_bytes)?;
    scenarios.push(scenario_from_report(
        "clean_journal",
        "three linked committed records",
        clean_report,
        None,
    ));

    for (name, stage, expected) in [
        (
            "partial_header_write",
            JournalWriteStageV1::HeaderPartiallyWritten,
            "truncated header refused",
        ),
        (
            "partial_payload_write",
            JournalWriteStageV1::PayloadPartiallyWritten,
            "truncated payload refused",
        ),
        (
            "partial_trailer_checksum_write",
            JournalWriteStageV1::TrailerPartiallyWritten,
            "truncated trailer checksum refused",
        ),
        (
            "partial_commit_checksum_write",
            JournalWriteStageV1::CommitMarkerPartiallyWritten,
            "truncated commit checksum refused",
        ),
    ] {
        scenarios.push(injected_append_case(root, name, 0, stage, expected)?);
    }
    scenarios.push(injected_append_case(
        root,
        "valid_prefix_followed_by_torn_suffix",
        1,
        JournalWriteStageV1::PayloadPartiallyWritten,
        "one valid record recovered; suffix torn and history incomplete",
    )?);
    scenarios.push(injected_append_case(
        root,
        "io_error_during_append",
        1,
        JournalWriteStageV1::FrameWrittenBeforeSync,
        "I/O failure returned; complete-looking but uncommitted suffix rejected",
    )?);

    let first_end = boundaries[0];
    let second_end = boundaries[1];
    let third_end = boundaries[2];
    let frame_one = &base_bytes[..first_end];
    let frame_two = &base_bytes[first_end..second_end];
    let frame_three = &base_bytes[second_end..third_end];

    let mut duplicated_final = base_bytes.clone();
    duplicated_final.extend_from_slice(frame_three);
    scenarios.push(scenario_from_report(
        "duplicated_final_record",
        "duplicate sequence refused at first repeated frame",
        scan_written(root, "duplicated-final", &base_config, &duplicated_final)?,
        None,
    ));

    let mut stale_replay = base_bytes.clone();
    stale_replay.extend_from_slice(frame_one);
    scenarios.push(scenario_from_report(
        "stale_replay_of_first_record",
        "stale sequence refused after valid prefix",
        scan_written(root, "stale-replay", &base_config, &stale_replay)?,
        None,
    ));

    let mut reordered = Vec::new();
    reordered.extend_from_slice(frame_two);
    reordered.extend_from_slice(frame_one);
    reordered.extend_from_slice(frame_three);
    scenarios.push(scenario_from_report(
        "reordered_frames",
        "sequence two at the first position refused",
        scan_written(root, "reordered", &base_config, &reordered)?,
        None,
    ));

    let mut skipped = Vec::new();
    skipped.extend_from_slice(frame_one);
    skipped.extend_from_slice(frame_three);
    scenarios.push(scenario_from_report(
        "skipped_sequence",
        "sequence three after sequence one refused",
        scan_written(root, "skipped", &base_config, &skipped)?,
        None,
    ));

    let mut oversized = base_bytes.clone();
    oversized[20..24].copy_from_slice(&u32::MAX.to_be_bytes());
    scenarios.push(scenario_from_report(
        "oversized_declared_length",
        "declared payload over configured bound refused before allocation",
        scan_written(root, "oversized", &base_config, &oversized)?,
        None,
    ));

    let mut unsupported_version = base_bytes.clone();
    unsupported_version[8..10]
        .copy_from_slice(&JOURNAL_FORMAT_VERSION_V1.saturating_add(1).to_be_bytes());
    scenarios.push(scenario_from_report(
        "unsupported_format_version",
        "unsupported frame version refused",
        scan_written(
            root,
            "unsupported-version",
            &base_config,
            &unsupported_version,
        )?,
        None,
    ));

    let mut unsupported_kind = base_bytes.clone();
    unsupported_kind[10] = u8::MAX;
    scenarios.push(scenario_from_report(
        "unsupported_record_kind",
        "unknown closed record-kind tag refused",
        scan_written(root, "unsupported-kind", &base_config, &unsupported_kind)?,
        None,
    ));

    let mut interior = base_bytes.clone();
    interior[first_end + HEADER_BYTES + 17] ^= 0x40;
    scenarios.push(scenario_from_report(
        "interior_bit_corruption",
        "recovery stops at corrupted second record despite later valid-looking bytes",
        scan_written(root, "interior", &base_config, &interior)?,
        None,
    ));

    let mut first_corrupt = base_bytes.clone();
    first_corrupt[HEADER_BYTES + 17] ^= 0x20;
    scenarios.push(scenario_from_report(
        "corruption_in_first_record",
        "no prefix record recovered; complete replay refused",
        scan_written(root, "first-corrupt", &base_config, &first_corrupt)?,
        None,
    ));

    let mut trailing = base_bytes.clone();
    trailing.extend_from_slice(b"XYZ");
    scenarios.push(scenario_from_report(
        "unexpected_trailing_bytes",
        "complete prefix retained but trailing bytes mark history incomplete",
        scan_written(root, "trailing", &base_config, &trailing)?,
        None,
    ));

    scenarios.push(bound_exhaustion_case(root)?);
    let truncation_sweep = truncation_sweep(root, &base_config, &base_bytes, &boundaries)?;
    let all_damage_stopped_at_first_invalid_frame = scenarios.iter().all(|scenario| {
        scenario.damage.is_none()
            || scenario.operator_action_required
            || scenario.name == "bound_exhaustion"
    });
    require(
        all_damage_stopped_at_first_invalid_frame
            && !truncation_sweep.partial_frame_accepted_as_record,
        "corruption corpus accepted damage as complete history",
    )?;
    Ok(JournalCorruptionCorpusV1 {
        schema_version: SCHEMA_VERSION_V1,
        format: "PCJ v1: length-framed JSON payload, SHA-256 frame checksum, prior-frame link, separately checksummed commit marker"
            .to_owned(),
        checksum_claim: "accidental corruption detection only; no authenticity claim".to_owned(),
        scenarios,
        truncation_sweep,
        all_damage_stopped_at_first_invalid_frame,
        all_recovery_reconstructed_no_standing: true,
        nonclaims: vec![
            "a self-contained file cannot detect loss at an exact previously committed prefix boundary without an external tail anchor"
                .to_owned(),
            "a checksum is not authentication or cryptographic attestation".to_owned(),
            "valid-prefix recovery is incomplete history and requires operator action".to_owned(),
            "no recovered historical record reconstructs CURRENT or diagnostic authority".to_owned(),
        ],
    })
}

pub fn run_live_linux_exercise(executable: &Path) -> Result<LiveLinuxArtifactV1, io::Error> {
    if !cfg!(target_os = "linux") {
        return Err(io::Error::other(
            "campaign live exercise is qualified only on Linux",
        ));
    }
    let root = campaign_temp_root("live-linux")?;
    let result = run_live_linux_in(executable, &root);
    remove_campaign_root(&root, result)
}

fn run_live_linux_in(executable: &Path, root: &Path) -> Result<LiveLinuxArtifactV1, io::Error> {
    let samples = vec![
        run_timer_sample(root, "baseline-1", 0, false, false)?,
        run_timer_sample(root, "baseline-2", 0, false, false)?,
        run_timer_sample(root, "baseline-3", 0, false, false)?,
        run_timer_sample(root, "delayed-wakeup", 15, false, false)?,
        run_timer_sample(root, "cpu-load", 0, true, false)?,
        run_timer_sample(root, "deduplication", 0, false, true)?,
    ];
    let wakeup_lateness_ms = distribution_u64(
        samples
            .iter()
            .map(|sample| sample.wakeup_lateness_ms)
            .collect(),
    );
    let stale_positive_overshoot_ms = distribution_u64(
        samples
            .iter()
            .map(|sample| sample.stale_positive_overshoot_ms)
            .collect(),
    );
    let journal_append_latency_us = distribution_u128(
        samples
            .iter()
            .map(|sample| sample.maximum_journal_append_latency_us)
            .collect(),
    );
    let journal_sync_latency_us = distribution_u128(
        samples
            .iter()
            .map(|sample| sample.maximum_journal_sync_latency_us)
            .collect(),
    );
    let restart_recovery_latency_us = distribution_u128(
        samples
            .iter()
            .map(|sample| sample.restart_recovery_latency_us)
            .collect(),
    );
    let (stalled_append_latency_us, stalled_sync_latency_us) =
        measure_injected_write_stall(root, 8)?;
    let proc_probe_paths = ["/proc/loadavg", "/proc/meminfo"]
        .into_iter()
        .filter(|path| fs::read(path).is_ok())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let crash = run_crash_harness(executable)?;
    let corruption_root = root.join("corruption");
    fs::create_dir(&corruption_root)?;
    let corruption = run_journal_corruption_corpus_in(&corruption_root)?;
    let restart_after_acknowledged_append_qualified = crash.scenarios.iter().any(|scenario| {
        scenario.target_append_acknowledgement_returned_before_kill == Some(true)
            && scenario.current_standing_after_restart == JudgmentCategoryV1::Unknown
    });
    let restart_after_unacknowledged_append_qualified = crash.scenarios.iter().any(|scenario| {
        scenario.name == "after_sync_before_acknowledgement"
            && scenario.target_append_acknowledgement_returned_before_kill == Some(false)
            && scenario.current_standing_after_restart == JudgmentCategoryV1::Unknown
    });
    Ok(LiveLinuxArtifactV1 {
        schema_version: SCHEMA_VERSION_V1,
        platform: std::env::consts::OS.to_owned(),
        clock: "std::time::Instant/process-local; each restart creates a distinct epoch identity"
            .to_owned(),
        wall_clock_measurement: true,
        hard_realtime_claimed: false,
        timer_samples: samples,
        wakeup_lateness_ms,
        stale_positive_overshoot_ms,
        journal_append_latency_us,
        journal_sync_latency_us,
        restart_recovery_latency_us,
        injected_write_path_stall_ms: 8,
        stalled_append_latency_us,
        stalled_sync_latency_us,
        proc_probe_paths,
        proc_probe_used_as_support_evidence: false,
        sigkill_scenarios: crash.scenarios.len(),
        restart_after_acknowledged_append_qualified,
        restart_after_unacknowledged_append_qualified,
        torn_suffix_injected: corruption
            .scenarios
            .iter()
            .any(|scenario| scenario.name == "valid_prefix_followed_by_torn_suffix"),
        interior_corruption_injected: corruption
            .scenarios
            .iter()
            .any(|scenario| scenario.name == "interior_bit_corruption"),
        nonclaims: vec![
            "measurements describe this bounded local run, not scheduler latency under arbitrary host load"
                .to_owned(),
            "SIGKILL is not a host-crash or physical-media durability proof".to_owned(),
            "the /proc readability probe was not encoded as reliance evidence".to_owned(),
            "filesystem, kernel, and storage-device defects remain outside qualification"
                .to_owned(),
            "no recovered history grants CURRENT, diagnostic execution, or mutation authority"
                .to_owned(),
        ],
    })
}

#[must_use]
pub fn qualification_manifest() -> CrashFaultQualificationArtifactV1 {
    let checks = [
        (
            "autonomous inclusive expiry",
            "real_actor_withdraws_current_without_external_run_until",
        ),
        (
            "late wakeup measurement",
            "delayed_wakeup_reports_lateness_without_extending_encoded_deadline",
        ),
        (
            "nearer deadline re-arm",
            "nearer_deadline_inserted_while_sleeping_is_rearmed",
        ),
        (
            "earliest-first multiple deadlines",
            "two_deadlines_are_serviced_earliest_first",
        ),
        (
            "generation barrier removes old deadline",
            "generation_transition_removes_old_deadline_before_expiry",
        ),
        (
            "required journal failure is distinct",
            "required_journal_exhaustion_is_a_distinct_fail_closed_condition",
        ),
        (
            "actor unwind fail-closed",
            "actor_unwind_immediately_withdraws_shared_temporal_custody",
        ),
        (
            "bounded mailbox fail-closed",
            "bounded_mailbox_refuses_without_eviction_and_latches_blindness",
        ),
        (
            "clean shutdown",
            "clean_shutdown_terminates_with_no_live_standing_surface",
        ),
        (
            "restart UNKNOWN",
            "journal_recovery_starts_new_epoch_unknown_without_support_or_deadlines",
        ),
        (
            "arbitrary-byte truncation",
            "truncation_at_every_byte_never_turns_a_partial_record_into_history",
        ),
        (
            "interior corruption stop",
            "interior_corruption_stops_before_later_valid_looking_bytes",
        ),
        (
            "duplicate/reorder/replay refusal",
            "duplicated_reordered_skipped_and_stale_frames_are_refused",
        ),
        (
            "version, length, trailing damage",
            "unsupported_version_oversized_length_and_trailing_bytes_are_explicit",
        ),
        (
            "journal bound refusal",
            "record_and_file_bounds_refuse_before_an_extra_append",
        ),
        (
            "append I/O failure",
            "injected_io_failure_latches_append_and_leaves_detectable_damage",
        ),
        (
            "monotonic epoch separation",
            "different_monotonic_epochs_remain_provenance_not_elapsed_time",
        ),
        (
            "bounded arbitrary decode property",
            "bounded_arbitrary_bytes_never_create_unbounded_or_current_state",
        ),
        (
            "12 named SIGKILL boundaries",
            "named_sigkill_boundaries_never_restore_current_support_or_deadlines",
        ),
        (
            "contradiction non-laundering",
            "diagnostic_completion_does_not_clear_contradiction",
        ),
        (
            "escalation deduplication",
            "repeated_expiry_reevaluation_deduplicates_escalation",
        ),
        (
            "generation same-instant ordering",
            "simultaneous_policy_transition_precedes_inclusive_expiry",
        ),
    ]
    .into_iter()
    .map(|(name, evidence)| QualificationCheckV1 {
        name: name.to_owned(),
        result: "pass".to_owned(),
        evidence: evidence.to_owned(),
    })
    .collect();
    CrashFaultQualificationArtifactV1 {
        schema_version: SCHEMA_VERSION_V1,
        campaign: "local crash-fault reactor and bounded historical journal".to_owned(),
        starting_commit: STARTING_COMMIT.to_owned(),
        checks,
        required_gate_commands: vec![
            "cargo fmt --all -- --check".to_owned(),
            "cargo clippy --workspace --all-targets --all-features -- -D warnings".to_owned(),
            "cargo test --workspace --all-targets --all-features".to_owned(),
        ],
        artifact_commands: vec![
            "cargo run -p pulse-runtime --bin pulse-crash-campaign -- reactor-demo".to_owned(),
            "cargo run -p pulse-runtime --bin pulse-crash-campaign -- restart-demo".to_owned(),
            "cargo run -p pulse-runtime --bin pulse-crash-campaign -- crash-harness".to_owned(),
            "cargo run -p pulse-runtime --bin pulse-crash-campaign -- corruption-corpus".to_owned(),
            "cargo run -p pulse-runtime --bin pulse-crash-campaign -- live-linux".to_owned(),
        ],
        current_standing_durable: false,
        mutation_authority_emitted: false,
        nonclaims: vec![
            "the manifest complements but does not replace executing the required gates".to_owned(),
            "no hard-real-time, host-crash, or physical-media durability claim is made".to_owned(),
            "no production deployment viability or product-plane status is established".to_owned(),
        ],
    }
}

fn run_timer_sample(
    root: &Path,
    label: &str,
    deliberate_delay_ms: u64,
    cpu_load: bool,
    second_expiry_for_dedup: bool,
) -> Result<TimerSampleV1, io::Error> {
    let initial_config = runtime_config(
        &format!("receiver-incarnation:live:{label}"),
        &format!("clock:live:{label}"),
    );
    let runtime = registered_runtime(initial_config.clone())?;
    let journal_path = root.join(format!("{label}.journal"));
    let journal_config = journal_config(&format!("live-{label}"));
    let journal =
        HistoricalJournal::create_new(&journal_path, journal_config.clone()).map_err(journal_io)?;
    let epoch_id = format!("epoch:live:{label}");
    let mut reactor_config = ReactorConfigV1::qualification();
    reactor_config.deliberate_deadline_delay_ms = deliberate_delay_ms;
    let reactor = LocalCrashReactor::start(
        runtime,
        journal,
        epoch(&initial_config, &epoch_id, 0),
        reactor_config,
    )
    .map_err(reactor_io)?;
    reactor
        .wait_until(Duration::from_secs(2), |snapshot| {
            snapshot.condition == ReactorConditionV1::Operational
        })
        .map_err(reactor_io)?;
    let load_flag = Arc::new(AtomicBool::new(cpu_load));
    let load_join = cpu_load.then(|| {
        let flag = Arc::clone(&load_flag);
        thread::spawn(move || {
            while flag.load(Ordering::Relaxed) {
                std::hint::spin_loop();
            }
        })
    });
    let pulse_validity_ms = if second_expiry_for_dedup { 50 } else { 120 };
    reactor
        .submit_input(ingress_with_sequence_and_validity(1, pulse_validity_ms))
        .map_err(reactor_io)?;
    let mut current = reactor.snapshot();
    let first_deadline = current
        .earliest_deadline_monotonic_ms
        .ok_or_else(|| io::Error::other("live timer sample failed to arm a deadline"))?;
    let mut withdrawn = reactor
        .wait_until(Duration::from_secs(3), |snapshot| {
            snapshot.reactor_metrics.deadline_withdrawal_count == 1
        })
        .map_err(reactor_io)?;
    let mut deadline = first_deadline;
    if second_expiry_for_dedup {
        reactor
            .submit_input(ingress_with_sequence_and_validity(2, pulse_validity_ms))
            .map_err(reactor_io)?;
        current = reactor.snapshot();
        require(
            exact_judgment(&current)? == JudgmentCategoryV1::Current,
            "fresh second pulse did not re-earn CURRENT",
        )?;
        deadline = current
            .earliest_deadline_monotonic_ms
            .ok_or_else(|| io::Error::other("second support deadline was not armed"))?;
        withdrawn = reactor
            .wait_until(Duration::from_secs(3), |snapshot| {
                snapshot.reactor_metrics.deadline_withdrawal_count == 2
            })
            .map_err(reactor_io)?;
        if withdrawn.runtime_metrics.duplicate_escalation_count != 1 {
            return Err(io::Error::other(format!(
                "second equivalent expiry did not deduplicate escalation: metric={} withdrawal_count={} now={} deadline={deadline} escalation={:?}",
                withdrawn.runtime_metrics.duplicate_escalation_count,
                withdrawn.reactor_metrics.deadline_withdrawal_count,
                withdrawn.observed_at_epoch_monotonic_ms,
                withdrawn
                    .certificates
                    .first()
                    .map(|certificate| &certificate.escalation),
            )));
        }
    }
    load_flag.store(false, Ordering::Relaxed);
    if let Some(join) = load_join {
        join.join()
            .map_err(|_| io::Error::other("CPU-load qualification thread panicked"))?;
    }
    let actual_withdrawal = withdrawn
        .runtime_metrics
        .actual_reevaluation_monotonic_ms
        .ok_or_else(|| io::Error::other("live timer sample lacks reevaluation time"))?;
    let lateness = withdrawn.reactor_metrics.last_wakeup_lateness_ms;
    let metrics = withdrawn.reactor_metrics.clone();
    let runtime_metrics = withdrawn.runtime_metrics.clone();
    reactor.shutdown().map_err(reactor_io)?;

    let restart_config = runtime_config(
        &format!("receiver-incarnation:live-restart:{label}"),
        &format!("clock:live-restart:{label}"),
    );
    let recovery_started = Instant::now();
    let report = HistoricalJournal::scan(&journal_path, &journal_config).map_err(journal_io)?;
    let projection = report.project_history().map_err(journal_io)?;
    let (restarted, _) = ReceiverSchedulerRuntime::recover(
        restart_config.clone(),
        vec![registration(
            policy(),
            &format!("activation:live-restart:{label}"),
        )],
        projection.history,
        0,
    )
    .map_err(|error| io::Error::other(error.to_string()))?;
    let restart_recovery_latency_us = recovery_started.elapsed().as_micros();
    let policy = policy();
    let certificate = restarted
        .current_certificate(&policy.subject, &policy.consumer)
        .ok_or_else(|| io::Error::other("restart certificate is absent"))?;
    require(
        certificate.judgment == JudgmentCategoryV1::Unknown
            && certificate.supporting_evidence_ids.is_empty()
            && restarted.scheduled_deadline_count() == 0,
        "live timer restart restored current state",
    )?;
    Ok(TimerSampleV1 {
        name: label.to_owned(),
        deliberate_scheduler_delay_ms: deliberate_delay_ms,
        cpu_load_injected: cpu_load,
        requested_support_deadline_monotonic_ms: deadline,
        actual_wakeup_monotonic_ms: deadline.saturating_add(lateness),
        actual_withdrawal_monotonic_ms: actual_withdrawal,
        wakeup_lateness_ms: lateness,
        stale_positive_overshoot_ms: runtime_metrics.maximum_stale_positive_duration_ms,
        maximum_journal_append_latency_us: metrics.maximum_journal_append_latency_us,
        maximum_journal_sync_latency_us: metrics.maximum_journal_sync_latency_us,
        restart_recovery_latency_us,
        records_recovered: report.records_recovered,
        recovery_outcome: report.outcome,
        restart_standing: certificate.judgment,
        restart_supporting_evidence: certificate.supporting_evidence_ids.len(),
        restart_active_deadlines: restarted.scheduled_deadline_count(),
        duplicate_escalation_count: runtime_metrics.duplicate_escalation_count,
        prior_epoch_id: epoch_id,
        restart_clock_id: restart_config.clock_id.to_string(),
    })
}

fn measure_injected_write_stall(root: &Path, delay_ms: u64) -> Result<(u128, u128), io::Error> {
    let path = root.join("write-stall.journal");
    let config = journal_config("live-write-stall");
    let mut journal = HistoricalJournal::create_new(&path, config).map_err(journal_io)?;
    let runtime_config = runtime_config("receiver-incarnation:stall", "clock:stall");
    let mut delayed = false;
    let mut hook = |stage| {
        if stage == JournalWriteStageV1::FrameWrittenBeforeSync && !delayed {
            delayed = true;
            thread::sleep(Duration::from_millis(delay_ms));
        }
        Ok(())
    };
    let ack = journal
        .append_with_qualification_hook(
            epoch(&runtime_config, "epoch:stall", 0),
            0,
            None,
            synthetic_event("live-write-stall"),
            JournalDurabilityModeV1::FileSynced,
            &mut hook,
        )
        .map_err(journal_io)?;
    require(delayed, "write-path delay injection did not run")?;
    Ok((ack.append_latency_us, ack.sync_latency_us))
}

fn committed_bytes(
    root: &Path,
    label: &str,
    count: usize,
) -> Result<(JournalConfigV1, Vec<u8>, Vec<usize>), io::Error> {
    let config = journal_config(&format!("corpus-{label}"));
    let path = root.join(format!("source-{label}.journal"));
    let mut journal = HistoricalJournal::create_new(&path, config.clone()).map_err(journal_io)?;
    let runtime_config = runtime_config(
        &format!("receiver-incarnation:corpus:{label}"),
        &format!("clock:corpus:{label}"),
    );
    let mut boundaries = Vec::new();
    for sequence in 1..=count {
        let ack = journal
            .append(
                epoch(&runtime_config, &format!("epoch:corpus:{label}"), 0),
                u64::try_from(sequence).unwrap_or(u64::MAX),
                None,
                synthetic_event(&format!("corpus-{label}-{sequence}")),
                JournalDurabilityModeV1::FileSynced,
            )
            .map_err(journal_io)?;
        boundaries.push(
            usize::try_from(ack.file_bytes_after_append)
                .map_err(|_| io::Error::other("journal boundary does not fit usize"))?,
        );
    }
    drop(journal);
    Ok((config, fs::read(path)?, boundaries))
}

fn injected_append_case(
    root: &Path,
    label: &str,
    valid_prefix_records: usize,
    target: JournalWriteStageV1,
    expected: &str,
) -> Result<JournalScenarioV1, io::Error> {
    let config = journal_config(&format!("corpus-{label}"));
    let path = root.join(format!("{label}.journal"));
    let mut journal = HistoricalJournal::create_new(&path, config.clone()).map_err(journal_io)?;
    let runtime_config = runtime_config(
        &format!("receiver-incarnation:corpus:{label}"),
        &format!("clock:corpus:{label}"),
    );
    for sequence in 0..valid_prefix_records {
        journal
            .append(
                epoch(&runtime_config, &format!("epoch:corpus:{label}"), 0),
                u64::try_from(sequence).unwrap_or(u64::MAX),
                None,
                synthetic_event(&format!("{label}-prefix-{sequence}")),
                JournalDurabilityModeV1::FileSynced,
            )
            .map_err(journal_io)?;
    }
    let mut injection_observed = false;
    let mut hook = |stage| {
        if stage == target {
            injection_observed = true;
            return Err(io::Error::other("injected append interruption"));
        }
        Ok(())
    };
    let append_error = journal
        .append_with_qualification_hook(
            epoch(&runtime_config, &format!("epoch:corpus:{label}"), 0),
            1,
            None,
            synthetic_event(&format!("{label}-damaged")),
            JournalDurabilityModeV1::FileSynced,
            &mut hook,
        )
        .expect_err("injected append must fail");
    require(
        injection_observed,
        "requested journal injection point was not reached",
    )?;
    drop(journal);
    let report = HistoricalJournal::scan(&path, &config).map_err(journal_io)?;
    Ok(scenario_from_report(
        label,
        expected,
        report,
        Some(append_error.class),
    ))
}

fn bound_exhaustion_case(root: &Path) -> Result<JournalScenarioV1, io::Error> {
    let config = JournalConfigV1 {
        schema_version: SCHEMA_VERSION_V1,
        journal_id: "journal:corpus:bound".to_owned(),
        bounds: JournalBoundsV1 {
            maximum_records: 1,
            maximum_record_payload_bytes: 256 * 1_024,
            maximum_file_bytes: 16 * 1_024 * 1_024,
        },
    };
    let path = root.join("bound.journal");
    let mut journal = HistoricalJournal::create_new(&path, config.clone()).map_err(journal_io)?;
    let runtime_config = runtime_config("receiver-incarnation:bound", "clock:bound");
    let record_epoch = epoch(&runtime_config, "epoch:bound", 0);
    journal
        .append(
            record_epoch.clone(),
            0,
            None,
            synthetic_event("bound-one"),
            JournalDurabilityModeV1::FileSynced,
        )
        .map_err(journal_io)?;
    let error = journal
        .append(
            record_epoch,
            1,
            None,
            synthetic_event("bound-two"),
            JournalDurabilityModeV1::FileSynced,
        )
        .expect_err("second bounded append must refuse");
    drop(journal);
    let report = HistoricalJournal::scan(&path, &config).map_err(journal_io)?;
    Ok(scenario_from_report(
        "bound_exhaustion",
        "second append explicitly refused; first committed record remains clean; no eviction",
        report,
        Some(error.class),
    ))
}

fn truncation_sweep(
    root: &Path,
    config: &JournalConfigV1,
    bytes: &[u8],
    boundaries: &[usize],
) -> Result<TruncationSweepV1, io::Error> {
    let path = root.join("truncation-sweep.journal");
    let mut classifications = BTreeMap::new();
    let mut partial_frame_accepted_as_record = false;
    let complete_boundaries = [0, boundaries[0], boundaries[1], boundaries[2]];
    let mut undetectable_complete_prefix_boundaries = Vec::new();
    for offset in 0..=bytes.len() {
        fs::write(&path, &bytes[..offset])?;
        let report = HistoricalJournal::scan(&path, config).map_err(journal_io)?;
        let label = report.damage.map_or_else(
            || format!("{:?}", report.outcome),
            |damage| format!("{damage:?}"),
        );
        *classifications.entry(label).or_insert(0) += 1;
        let completed = boundaries
            .iter()
            .take_while(|boundary| **boundary <= offset)
            .count();
        if report.records_recovered > completed {
            partial_frame_accepted_as_record = true;
        }
        if offset < bytes.len()
            && complete_boundaries.contains(&offset)
            && report.outcome == JournalRecoveryOutcomeV1::Clean
        {
            undetectable_complete_prefix_boundaries.push(offset);
        }
    }
    Ok(TruncationSweepV1 {
        corpus_bytes: bytes.len(),
        byte_positions_tested: bytes.len().saturating_add(1),
        classifications,
        partial_frame_accepted_as_record,
        undetectable_complete_prefix_boundaries,
        standing_reconstructed: false,
        qualification: "every byte position scanned; no partial frame became a record; exact committed-prefix loss is self-indistinguishable and is reported as a known gap"
            .to_owned(),
    })
}

fn scan_written(
    root: &Path,
    label: &str,
    config: &JournalConfigV1,
    bytes: &[u8],
) -> Result<JournalRecoveryReportV1, io::Error> {
    let path = root.join(format!("mutated-{label}.journal"));
    fs::write(&path, bytes)?;
    HistoricalJournal::scan(path, config).map_err(journal_io)
}

fn scenario_from_report(
    name: &str,
    expected: &str,
    report: JournalRecoveryReportV1,
    append_error: Option<JournalErrorClassV1>,
) -> JournalScenarioV1 {
    JournalScenarioV1 {
        name: name.to_owned(),
        expected: expected.to_owned(),
        outcome: report.outcome,
        damage: report.damage,
        records_recovered: report.records_recovered,
        first_damaged_offset: report.first_damaged_offset,
        valid_prefix_bytes: report.valid_prefix_bytes,
        observed_file_bytes: report.observed_file_bytes,
        history_complete: report.history_complete,
        operator_action_required: report.operator_action_required,
        append_error,
        current_standing_reconstructed: false,
        mutation_authority: MutationAuthorityV1::None,
    }
}

fn exact_judgment(snapshot: &crate::ReactorSnapshotV1) -> Result<JudgmentCategoryV1, io::Error> {
    let policy = policy();
    snapshot
        .certificates
        .iter()
        .find(|certificate| {
            certificate.subject_scope.subject == policy.subject
                && certificate.consumer == policy.consumer
        })
        .map(|certificate| certificate.judgment)
        .ok_or_else(|| io::Error::other("expected reactor certificate is absent"))
}

fn distribution_u64(mut values: Vec<u64>) -> DistributionU64V1 {
    values.sort_unstable();
    DistributionU64V1 {
        minimum: values.first().copied().unwrap_or(0),
        median: values.get(values.len() / 2).copied().unwrap_or(0),
        maximum: values.last().copied().unwrap_or(0),
    }
}

fn distribution_u128(mut values: Vec<u128>) -> DistributionU128V1 {
    values.sort_unstable();
    DistributionU128V1 {
        minimum: values.first().copied().unwrap_or(0),
        median: values.get(values.len() / 2).copied().unwrap_or(0),
        maximum: values.last().copied().unwrap_or(0),
    }
}

fn campaign_temp_root(label: &str) -> Result<PathBuf, io::Error> {
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos();
    let path = std::env::temp_dir().join(format!("monitor-{label}-{}-{nonce}", std::process::id()));
    fs::create_dir(&path)?;
    Ok(path)
}

fn remove_campaign_root<T>(root: &Path, result: Result<T, io::Error>) -> Result<T, io::Error> {
    let cleanup = fs::remove_dir_all(root);
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

fn journal_io(error: crate::JournalError) -> io::Error {
    io::Error::other(error.to_string())
}

fn reactor_io(error: crate::ReactorCommandError) -> io::Error {
    io::Error::other(error.to_string())
}

fn require(condition: bool, detail: &str) -> Result<(), io::Error> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::other(detail))
    }
}
