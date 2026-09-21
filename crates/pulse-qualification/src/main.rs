#![forbid(unsafe_code)]

use std::env;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant};

use pulse_qualification::{
    ActivationCrashCorpusV1, ActivationCrashPointV1, DeterministicBindingDemoV1,
    HostileCorpusArtifactV1, LifecycleArtifactV1, RestartActivationArtifactV1, binding_nonclaims,
    fixture_config, fixture_ingress, fixture_registration, retarget_artifact,
    run_authority_laundering_corpus, run_lifecycle_demo, run_load_bearing_mismatch_corpus,
    run_matched_activation_demo, run_matched_package_activation_demo, run_mismatch_demo,
    run_mismatch_package_demo, run_restart_demo,
};
use pulse_runtime::{
    ActivationQualificationPointV1, HistoricalJournal, JournalBoundsV1, JournalConfigV1,
    JournalDurabilityModeV1, JournalRecordBodyV1, JournalRecoveryOutcomeV1, JournalWriteStageV1,
    LocalQualificationInputsV1, MonotonicEpochV1, QualificationCorpusArtifactV1,
    QualificationResultsArtifactV1, ReceiverSchedulerRuntime, build_local_qualification_package,
};
use pulse_types::{
    ArtifactRoleV1, BuildIdentityV1, ConsumerId, ContextActivationId, GenerationLifecycleKindV1,
    IncarnationId, JudgmentCategoryV1, QualificationCommandResultV1, RuntimeBindingStateV1,
    RuntimeDependencyIdentityV1, RuntimeHistoricalStateV1, SCHEMA_VERSION_V1, SourceIdentityV1,
    SparseDurableEventKindV1, SubjectId, artifact_content_digest, digest_parts,
};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct QualificationCampaignSummaryV1 {
    schema_version: u16,
    source_commit: String,
    source_tree_object: String,
    source_tree_digest: pulse_types::DigestV1,
    manifest_digest: pulse_types::DigestV1,
    qualification_report_digest: pulse_types::DigestV1,
    qualification_certificate_digest: pulse_types::DigestV1,
    activation_receipt_digest: pulse_types::DigestV1,
    activation_state: RuntimeBindingStateV1,
    qualification_commands: Vec<QualificationCommandResultV1>,
    total_tests_passed: u32,
    all_required_commands_passed: bool,
    cryptographic_signature_present: bool,
    source_to_binary_correspondence_claimed: bool,
    independent_attestation_claimed: bool,
    authority_granted: bool,
    nonclaims: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct DemoBundleV1 {
    schema_version: u16,
    matched: DeterministicBindingDemoV1,
    executable_mismatch: DeterministicBindingDemoV1,
    policy_substitution: DeterministicBindingDemoV1,
    restart: RestartActivationArtifactV1,
    supersession: LifecycleArtifactV1,
    revocation: LifecycleArtifactV1,
    mismatch_corpus: HostileCorpusArtifactV1,
    authority_laundering: HostileCorpusArtifactV1,
}

fn run_checked_command(
    sequence: u16,
    argv: &[&str],
    count_tests: bool,
) -> Result<(QualificationCommandResultV1, Output), Box<dyn Error>> {
    let (program, arguments) = argv
        .split_first()
        .ok_or_else(|| io::Error::other("qualification command is empty"))?;
    let output = Command::new(program).args(arguments).output()?;
    let observed_test_count = count_tests
        .then(|| parse_test_count(&output.stdout).saturating_add(parse_test_count(&output.stderr)));
    let result = QualificationCommandResultV1 {
        sequence,
        argv: argv.iter().map(|argument| (*argument).to_owned()).collect(),
        exit_code: output.status.code().unwrap_or(-1),
        stdout_digest: artifact_content_digest(&output.stdout),
        stderr_digest: artifact_content_digest(&output.stderr),
        observed_test_count,
    };
    Ok((result, output))
}

fn parse_test_count(bytes: &[u8]) -> u32 {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter_map(|line| {
            let marker = "test result: ok. ";
            let remainder = line.trim().strip_prefix(marker)?;
            remainder.split_whitespace().next()?.parse::<u32>().ok()
        })
        .fold(0_u32, u32::saturating_add)
}

fn command_text(argv: &[&str]) -> String {
    argv.join(" ")
}

fn require_clean_source() -> Result<(String, String), Box<dyn Error>> {
    let commit = command_stdout(&["git", "rev-parse", "HEAD"])?;
    let tree = command_stdout(&["git", "rev-parse", "HEAD^{tree}"])?;
    let status = command_stdout(&["git", "status", "--porcelain"])?;
    if !status.is_empty() {
        return Err(io::Error::other(
            "qualification package generation requires a clean source tree",
        )
        .into());
    }
    Ok((commit, tree))
}

fn command_stdout(argv: &[&str]) -> Result<String, Box<dyn Error>> {
    let (program, arguments) = argv
        .split_first()
        .ok_or_else(|| io::Error::other("command is empty"))?;
    let output = Command::new(program).args(arguments).output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!("command failed: {}", command_text(argv))).into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn sorted(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

fn hostile_scenarios() -> Vec<String> {
    sorted(vec![
        "activation-receipt-replay-after-restart".to_owned(),
        "artifact-role-duplication-swapping-and-omission".to_owned(),
        "certificate-and-manifest-cross-pairing".to_owned(),
        "certificate-corruption-and-truncation".to_owned(),
        "configuration-substitution".to_owned(),
        "equal-policy-content-new-generation".to_owned(),
        "evaluator-substitution".to_owned(),
        "executable-substitution-with-equal-label".to_owned(),
        "generation-label-without-binding".to_owned(),
        "manifest-corruption-and-truncation".to_owned(),
        "manifest-without-certificate-or-checked-report".to_owned(),
        "noncanonical-json-and-unknown-mandatory-field".to_owned(),
        "observation-policy-substitution".to_owned(),
        "observer-set-substitution".to_owned(),
        "policy-substitution-with-equal-label".to_owned(),
        "profile-substitution".to_owned(),
        "qualification-results-claim-mismatch".to_owned(),
        "report-single-byte-corruption".to_owned(),
        "restart-does-not-recover-binding-support-or-deadlines".to_owned(),
        "revocation-and-supersession-withdraw-current".to_owned(),
        "semantic-contract-substitution".to_owned(),
        "source-commit-alone-cannot-authorize-current".to_owned(),
    ])
}

fn checked_inputs() -> Result<LocalQualificationInputsV1, Box<dyn Error>> {
    let (source_commit, source_tree_object) = require_clean_source()?;
    let commands: [(&[&str], bool); 3] = [
        ((&["cargo", "fmt", "--all", "--", "--check"]), false),
        (
            (&[
                "cargo",
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ]),
            false,
        ),
        (
            (&[
                "cargo",
                "test",
                "--workspace",
                "--all-targets",
                "--all-features",
            ]),
            true,
        ),
    ];
    let mut command_results = Vec::new();
    for (index, (argv, count_tests)) in commands.iter().enumerate() {
        eprintln!("qualification command: {}", command_text(argv));
        let sequence = u16::try_from(index + 1)?;
        let (result, output) = run_checked_command(sequence, argv, *count_tests)?;
        if !output.status.success() {
            io::stderr().write_all(&output.stderr)?;
            io::stdout().write_all(&output.stdout)?;
            return Err(io::Error::other(format!(
                "qualification command failed: {}",
                command_text(argv)
            ))
            .into());
        }
        command_results.push(result);
    }
    let total_tests_passed = command_results
        .iter()
        .filter_map(|result| result.observed_test_count)
        .fold(0_u32, u32::saturating_add);
    if total_tests_passed == 0 {
        return Err(io::Error::other("qualification test count parser observed zero tests").into());
    }

    let scenarios = hostile_scenarios();
    let corpus = QualificationCorpusArtifactV1 {
        schema_version: SCHEMA_VERSION_V1,
        corpus_id: "qualified-generation-binding-campaign-v1".to_owned(),
        hostile_scenarios: scenarios.clone(),
        property_families: sorted(vec![
            "bounded-canonical-decoding".to_owned(),
            "single-byte-package-corruption".to_owned(),
            "truncation-at-arbitrary-package-offset".to_owned(),
        ]),
    };
    let results = QualificationResultsArtifactV1 {
        schema_version: SCHEMA_VERSION_V1,
        command_results: command_results.clone(),
        total_tests_passed,
        all_required_commands_passed: true,
    };
    let rustc_verbose = command_stdout(&["rustc", "--version", "--verbose"])?;
    let toolchain_identity = rustc_verbose.replace('\n', "; ");
    let target_triple = rustc_verbose
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .unwrap_or("target-unavailable")
        .to_owned();
    let cargo_lock = fs::read("Cargo.lock")?;
    let source_tree_digest = digest_parts(
        "qualified.git-tree-object.v1",
        &[source_tree_object.as_bytes()],
    );
    let claims = sorted(vec![
        "activation-receipt-names-one-process-local-exact-match/v1".to_owned(),
        "current-requires-qualified-and-matched-binding/v1".to_owned(),
        "every-load-bearing-owned-artifact-has-exact-content-identity/v1".to_owned(),
        "restart-requires-new-local-activation/v1".to_owned(),
        "supersession-and-revocation-withdraw-positive-standing/v1".to_owned(),
    ]);
    let mut nonclaims = binding_nonclaims();
    nonclaims.extend([
        "no global certificate or revocation authority".to_owned(),
        "no reproducible-build or source-to-binary correspondence claim".to_owned(),
        "no signer authorization or signature claim".to_owned(),
    ]);
    let nonclaims = sorted(nonclaims);
    Ok(LocalQualificationInputsV1 {
        source: SourceIdentityV1 {
            repository_identity: "monitor-skunkworks/standalone-local".to_owned(),
            commit: source_commit.clone(),
            source_tree_digest,
            dirty: false,
        },
        build: BuildIdentityV1 {
            toolchain_identity,
            target_triple,
            build_profile: "cargo-dev-profile".to_owned(),
            enabled_features: vec!["workspace-all-features".to_owned()],
            runtime_dependencies: vec![RuntimeDependencyIdentityV1 {
                name: "workspace-cargo-lock".to_owned(),
                version: "Cargo.lock-v4".to_owned(),
                source_digest: artifact_content_digest(&cargo_lock),
            }],
        },
        platform_assumptions: sorted(vec![
            "linux-proc-self-exe-opened-handle/v1".to_owned(),
            "ordinary-filesystem-metadata-change-detection/v1".to_owned(),
            "owned-runtime-values-immutable-after-activation/v1".to_owned(),
            "sha-256-collision-resistance-for-content-identity/v1".to_owned(),
        ]),
        declared_claims: claims,
        nonclaims,
        supersedes_manifest_digests: Vec::new(),
        lifecycle_authority_id: "local-policy:monitor-skunkworks-campaign-4".to_owned(),
        corpus_bytes: corpus.canonical_bytes()?,
        results_bytes: results.canonical_bytes()?,
        command_results,
        hostile_scenarios: scenarios,
        total_tests_passed,
        issuance_id: format!("local-qualification-run:{source_commit}"),
        issuer_id: "local-process:self-observed-qualification-run".to_owned(),
    })
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

fn write_json_new<T: Serialize>(path: &Path, value: &T) -> Result<(), Box<dyn Error>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_new(path, &bytes)
}

fn create_output_directory(path: &Path) -> Result<(), Box<dyn Error>> {
    if path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("output directory already exists: {}", path.display()),
        )
        .into());
    }
    fs::create_dir(path)?;
    Ok(())
}

fn crash_journal_config() -> JournalConfigV1 {
    JournalConfigV1 {
        schema_version: SCHEMA_VERSION_V1,
        journal_id: "journal:qualified-activation-crash".to_owned(),
        bounds: JournalBoundsV1 {
            maximum_records: 128,
            maximum_record_payload_bytes: 512 * 1_024,
            maximum_file_bytes: 16 * 1024 * 1024,
        },
    }
}

fn crash_epoch(config: &pulse_runtime::RuntimeConfigV1, label: &str) -> MonotonicEpochV1 {
    MonotonicEpochV1 {
        schema_version: SCHEMA_VERSION_V1,
        epoch_id: IncarnationId::new(label),
        receiver: config.receiver.clone(),
        receiver_incarnation: config.receiver_incarnation.clone(),
        clock_id: config.clock_id.clone(),
        origin_runtime_monotonic_ms: 0,
        clock_source: "std::time::Instant/process-local".to_owned(),
    }
}

fn crash_checkpoint(marker: &Path, point: &str) -> ! {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(marker)
        .expect("crash marker is create-new");
    file.write_all(point.as_bytes())
        .expect("crash marker writes");
    file.sync_all().expect("crash marker syncs");
    loop {
        thread::park_timeout(Duration::from_secs(60));
    }
}

fn append_event_with_crash_point(
    journal: &mut HistoricalJournal,
    epoch: &MonotonicEpochV1,
    event: pulse_types::SparseDurableEventV1,
    phase: &str,
    marker: &Path,
) -> Result<(), Box<dyn Error>> {
    let mut hook = |stage: JournalWriteStageV1| -> io::Result<()> {
        let selected = match phase {
            "during_activation_receipt_framing" => {
                stage == JournalWriteStageV1::PayloadPartiallyWritten
            }
            "after_activation_receipt_write_before_sync" => {
                stage == JournalWriteStageV1::FrameWrittenBeforeSync
            }
            "after_activation_receipt_data_sync_before_commit" => {
                stage == JournalWriteStageV1::DataFrameSynced
            }
            "after_activation_receipt_sync_before_ack" => {
                stage == JournalWriteStageV1::CommitMarkerSyncedBeforeAcknowledgement
            }
            _ => false,
        };
        if selected {
            crash_checkpoint(marker, phase);
        }
        Ok(())
    };
    journal.append_with_qualification_hook(
        epoch.clone(),
        0,
        None,
        JournalRecordBodyV1::SparseEvent { event },
        JournalDurabilityModeV1::FileSynced,
        &mut hook,
    )?;
    Ok(())
}

fn run_crash_child(phase: &str, journal_path: &Path, marker: &Path) -> Result<(), Box<dyn Error>> {
    let config = fixture_config("receiver-incarnation:crash-child", "clock:crash-child");
    let registration = fixture_registration();
    let mut package = build_local_qualification_package(
        &config,
        &registration,
        pulse_runtime::qualification_fixture_inputs(
            pulse_qualification::CAMPAIGN_STARTING_COMMIT,
            97,
        ),
    )?;
    if phase == "after_mismatch_detected" {
        package = retarget_artifact(
            &package,
            ArtifactRoleV1::RunningExecutable,
            b"crash fixture executable mismatch",
        )?;
    }
    let manifest = package.manifest_bytes()?;
    let certificate = package.certificate_bytes()?;
    let report = package.report_bytes()?;
    let mut runtime = ReceiverSchedulerRuntime::new(config.clone())?;
    if phase == "before_artifact_measurement" {
        crash_checkpoint(marker, phase);
    }
    let mut activation_hook = |point: ActivationQualificationPointV1| {
        let selected = matches!(
            (phase, point),
            (
                "during_artifact_measurement",
                ActivationQualificationPointV1::DuringArtifactMeasurement
            ) | (
                "after_artifact_measurement_before_binding_commit",
                ActivationQualificationPointV1::AfterArtifactMeasurementBeforeBindingCommit
            ) | (
                "after_binding_commit_before_receipt_journal",
                ActivationQualificationPointV1::AfterBindingCommitBeforeReturn
            )
        );
        if selected {
            crash_checkpoint(marker, phase);
        }
    };
    let activation = runtime.activate_qualified_binding_with_qualification_hook(
        &registration,
        Some(&manifest),
        Some(&certificate),
        Some(&report),
        package.acceptance,
        0,
        &mut activation_hook,
    )?;
    let binding_event = activation
        .runtime_output
        .sparse_events
        .iter()
        .find(|event| {
            matches!(
                event.event,
                SparseDurableEventKindV1::QualifiedGenerationBindingChanged { .. }
            )
        })
        .cloned()
        .ok_or_else(|| io::Error::other("activation emitted no historical receipt event"))?;
    let binding_event_id = binding_event.event_id.clone();
    let mut journal = HistoricalJournal::create_new(journal_path, crash_journal_config())?;
    let epoch = crash_epoch(&config, "epoch:qualified-activation-crash-child");
    append_event_with_crash_point(&mut journal, &epoch, binding_event, phase, marker)?;
    if phase == "after_synced_activation_receipt" || phase == "after_mismatch_detected" {
        crash_checkpoint(marker, phase);
    }

    runtime.register_consumer(registration, 0)?;
    if phase == "after_binding_before_evidence" {
        crash_checkpoint(marker, phase);
    }
    runtime
        .enqueue(1, fixture_ingress(1, 100))
        .map_err(|error| io::Error::other(format!("{:?}: {}", error.class, error.detail)))?;
    runtime.run_until(1)?;
    for event in runtime
        .export_history()
        .sparse_events
        .into_iter()
        .filter(|event| event.event_id != binding_event_id)
    {
        journal.append(
            epoch.clone(),
            1,
            None,
            JournalRecordBodyV1::SparseEvent { event },
            JournalDurabilityModeV1::FileSynced,
        )?;
    }
    if phase == "while_current" {
        crash_checkpoint(marker, phase);
    }
    Err(io::Error::other(format!("unknown or unreached crash phase: {phase}")).into())
}

fn wait_for_marker(path: &Path, timeout: Duration) -> Result<(), Box<dyn Error>> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if path.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(5));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("child did not reach crash marker {}", path.display()),
    )
    .into())
}

fn run_activation_crash_corpus() -> Result<ActivationCrashCorpusV1, Box<dyn Error>> {
    let executable = env::current_exe()?;
    let phases = [
        "before_artifact_measurement",
        "during_artifact_measurement",
        "after_artifact_measurement_before_binding_commit",
        "after_binding_commit_before_receipt_journal",
        "during_activation_receipt_framing",
        "after_activation_receipt_write_before_sync",
        "after_activation_receipt_data_sync_before_commit",
        "after_activation_receipt_sync_before_ack",
        "after_synced_activation_receipt",
        "after_binding_before_evidence",
        "while_current",
        "after_mismatch_detected",
    ];
    let mut points = Vec::new();
    for (index, phase) in phases.iter().enumerate() {
        let directory = env::temp_dir().join(format!(
            "monitor-qualified-activation-crash-{}-{index}",
            std::process::id()
        ));
        fs::create_dir(&directory)?;
        let journal_path = directory.join("history.journal");
        let marker = directory.join("ready.marker");
        let mut child = Command::new(&executable)
            .arg("crash-child")
            .arg(phase)
            .arg(&journal_path)
            .arg(&marker)
            .spawn()?;
        wait_for_marker(&marker, Duration::from_secs(15))?;
        child.kill()?;
        let status = child.wait()?;
        let process_killed = !status.success();

        let (
            history,
            journal_records_recovered,
            journal_recovery,
            journal_damage,
            historical_current_records,
        ) = if journal_path.exists() {
            let report = HistoricalJournal::scan(&journal_path, &crash_journal_config())?;
            let historical_current_records = report.historical_current_record_count();
            let history = if report.outcome == JournalRecoveryOutcomeV1::Refused {
                RuntimeHistoricalStateV1::empty()
            } else {
                report.project_history()?.history
            };
            (
                history,
                report.records_recovered,
                format!("{:?}", report.outcome),
                report.damage.map(|damage| format!("{damage:?}")),
                historical_current_records,
            )
        } else {
            (
                RuntimeHistoricalStateV1::empty(),
                0,
                "NotCreated".to_owned(),
                None,
                0,
            )
        };
        let historical_activation_receipts = history
            .sparse_events
            .iter()
            .filter(|event| {
                matches!(
                    event.event,
                    SparseDurableEventKindV1::QualifiedGenerationBindingChanged { .. }
                )
            })
            .count();
        let mut restart_registration = fixture_registration();
        restart_registration.context.activation_id =
            ContextActivationId::new(format!("activation:restart-{index}"));
        let (restarted, _) = ReceiverSchedulerRuntime::recover(
            fixture_config(
                &format!("receiver-incarnation:crash-restart-{index}"),
                &format!("clock:crash-restart-{index}"),
            ),
            vec![restart_registration],
            history,
            0,
        )?;
        let certificate = restarted
            .current_certificate(
                &SubjectId::new(pulse_qualification::FIXTURE_SUBJECT),
                &ConsumerId::new(pulse_qualification::FIXTURE_CONSUMER),
            )
            .ok_or_else(|| io::Error::other("restart certificate missing"))?;
        let restarted_binding_state = restarted.binding_state(
            &SubjectId::new(pulse_qualification::FIXTURE_SUBJECT),
            &ConsumerId::new(pulse_qualification::FIXTURE_CONSUMER),
        );
        let standing_reconstructed = certificate.judgment == JudgmentCategoryV1::Current
            || !certificate.supporting_evidence_ids.is_empty()
            || restarted.scheduled_deadline_count() != 0
            || restarted_binding_state != RuntimeBindingStateV1::Unbound;
        points.push(ActivationCrashPointV1 {
            point: (*phase).to_owned(),
            process_killed,
            technically_executed: true,
            journal_records_recovered,
            journal_recovery,
            journal_damage,
            historical_activation_receipts,
            historical_current_records,
            restarted_binding_state,
            restarted_judgment: certificate.judgment,
            restarted_supporting_evidence_count: certificate.supporting_evidence_ids.len(),
            restarted_active_deadlines: restarted.scheduled_deadline_count(),
            standing_reconstructed,
            detail: "SIGKILL child; historical recovery inspected separately from restart standing"
                .to_owned(),
        });
        fs::remove_file(&marker)?;
        if journal_path.exists() {
            fs::remove_file(&journal_path)?;
        }
        fs::remove_dir(&directory)?;
    }
    points.push(ActivationCrashPointV1 {
        point: "after_receipt_sync_before_runtime_binding_activation".to_owned(),
        process_killed: false,
        technically_executed: false,
        journal_records_recovered: 0,
        journal_recovery: "SemanticallyRefused".to_owned(),
        journal_damage: None,
        historical_activation_receipts: 0,
        historical_current_records: 0,
        restarted_binding_state: RuntimeBindingStateV1::Unbound,
        restarted_judgment: JudgmentCategoryV1::Unknown,
        restarted_supporting_evidence_count: 0,
        restarted_active_deadlines: 0,
        standing_reconstructed: false,
        detail: "an activation receipt states what was activated, so v1 commits the ephemeral binding before journaling that receipt; persisting it first would make the receipt false"
            .to_owned(),
    });
    let all_executed_restart_checks_passed = points
        .iter()
        .filter(|point| point.technically_executed)
        .all(|point| {
            point.process_killed
                && point.restarted_binding_state == RuntimeBindingStateV1::Unbound
                && point.restarted_judgment == JudgmentCategoryV1::Unknown
                && point.restarted_supporting_evidence_count == 0
                && point.restarted_active_deadlines == 0
                && !point.standing_reconstructed
        });
    let refused_point_count = points
        .iter()
        .filter(|point| !point.technically_executed)
        .count();
    Ok(ActivationCrashCorpusV1 {
        schema_version: SCHEMA_VERSION_V1,
        platform: format!("{}-unknown-{}", env::consts::ARCH, env::consts::OS),
        points,
        all_executed_restart_checks_passed,
        refused_point_count,
        nonclaims: vec![
            "SIGKILL exercises local process crash boundaries, not host or media failure"
                .to_owned(),
            "a recovered activation receipt remains history and cannot recreate the live token"
                .to_owned(),
        ],
    })
}

fn generate_checked_artifacts(output: &Path) -> Result<(), Box<dyn Error>> {
    let inputs = checked_inputs()?;
    let corpus_bytes = inputs.corpus_bytes.clone();
    let results_bytes = inputs.results_bytes.clone();
    let command_results = inputs.command_results.clone();
    let total_tests_passed = inputs.total_tests_passed;
    let config = fixture_config(
        "receiver-incarnation:checked-package",
        "clock:checked-package",
    );
    let registration = fixture_registration();
    let package = build_local_qualification_package(&config, &registration, inputs)?;
    let (matched, activation_receipt) =
        run_matched_package_activation_demo(&config, &registration, &package)
            .map_err(io::Error::other)?;
    let executable_mismatch = run_mismatch_package_demo(
        &config,
        &registration,
        &package,
        ArtifactRoleV1::RunningExecutable,
        RuntimeBindingStateV1::ExecutableMismatch,
        "valid checked package names different executable bytes",
    )
    .map_err(io::Error::other)?;
    let policy_substitution = run_mismatch_package_demo(
        &config,
        &registration,
        &package,
        ArtifactRoleV1::ReliancePolicy,
        RuntimeBindingStateV1::PolicyMismatch,
        "generation label unchanged while canonical policy bytes differ",
    )
    .map_err(io::Error::other)?;
    let restart = run_restart_demo().map_err(io::Error::other)?;
    let supersession =
        run_lifecycle_demo(GenerationLifecycleKindV1::Superseded).map_err(io::Error::other)?;
    let revocation =
        run_lifecycle_demo(GenerationLifecycleKindV1::Revoked).map_err(io::Error::other)?;
    let mismatch_corpus = run_load_bearing_mismatch_corpus().map_err(io::Error::other)?;
    let authority_laundering = run_authority_laundering_corpus().map_err(io::Error::other)?;
    let crash_corpus = run_activation_crash_corpus()?;
    if !mismatch_corpus.all_passed
        || !authority_laundering.all_passed
        || !crash_corpus.all_executed_restart_checks_passed
    {
        return Err(io::Error::other("a hostile qualification corpus check failed").into());
    }
    let source_commit = package.manifest.body.source.commit.clone();
    let source_tree_digest = package.manifest.body.source.source_tree_digest.clone();
    let source_tree_object = command_stdout(&["git", "rev-parse", "HEAD^{tree}"])?;
    let summary = QualificationCampaignSummaryV1 {
        schema_version: SCHEMA_VERSION_V1,
        source_commit,
        source_tree_object,
        source_tree_digest,
        manifest_digest: package.manifest.manifest_digest.clone(),
        qualification_report_digest: package.report.report_digest.clone(),
        qualification_certificate_digest: package.certificate.certificate_digest.clone(),
        activation_receipt_digest: activation_receipt.receipt_digest.clone(),
        activation_state: activation_receipt.body.state,
        qualification_commands: command_results,
        total_tests_passed,
        all_required_commands_passed: true,
        cryptographic_signature_present: false,
        source_to_binary_correspondence_claimed: false,
        independent_attestation_claimed: false,
        authority_granted: false,
        nonclaims: binding_nonclaims(),
    };
    create_output_directory(output)?;
    write_new(
        &output.join("qualified-manifest.json"),
        &package.manifest.canonical_bytes()?,
    )?;
    write_new(
        &output.join("qualification-certificate.json"),
        &package.certificate.canonical_bytes()?,
    )?;
    write_new(
        &output.join("qualification-report.json"),
        &package.report.canonical_bytes()?,
    )?;
    write_new(&output.join("qualification-corpus.json"), &corpus_bytes)?;
    write_new(&output.join("qualification-results.json"), &results_bytes)?;
    write_new(
        &output.join("activation-receipt.json"),
        &activation_receipt.canonical_bytes()?,
    )?;
    write_json_new(&output.join("matched-activation-demo.json"), &matched)?;
    write_json_new(
        &output.join("executable-mismatch-demo.json"),
        &executable_mismatch,
    )?;
    write_json_new(
        &output.join("policy-substitution-demo.json"),
        &policy_substitution,
    )?;
    write_json_new(&output.join("restart-activation.json"), &restart)?;
    write_json_new(
        &output.join("supersession-qualification.json"),
        &supersession,
    )?;
    write_json_new(&output.join("revocation-qualification.json"), &revocation)?;
    write_json_new(&output.join("mismatch-corpus.json"), &mismatch_corpus)?;
    write_json_new(
        &output.join("authority-laundering-refusals.json"),
        &authority_laundering,
    )?;
    write_json_new(
        &output.join("crash-restart-activation-corpus.json"),
        &crash_corpus,
    )?;
    write_json_new(&output.join("qualification-summary.json"), &summary)?;
    println!(
        "QUALIFIED package manifest={} certificate={} report={} tests={} activation={:?}",
        summary.manifest_digest,
        summary.qualification_certificate_digest,
        summary.qualification_report_digest,
        summary.total_tests_passed,
        summary.activation_state
    );
    for step in &matched.steps {
        println!(
            "MATCHED step={} binding={:?} judgment={} evidence={} deadlines={} action={}",
            step.sequence,
            step.binding_state,
            step.judgment,
            step.supporting_evidence_count,
            step.active_deadlines,
            step.action
        );
    }
    println!(
        "EXECUTABLE_MISMATCH binding={:?} judgment={} deadlines={}",
        executable_mismatch.steps[0].binding_state,
        executable_mismatch.steps[0].judgment,
        executable_mismatch.steps[0].active_deadlines
    );
    println!(
        "POLICY_SUBSTITUTION binding={:?} judgment={} deadlines={}",
        policy_substitution.steps[0].binding_state,
        policy_substitution.steps[0].judgment,
        policy_substitution.steps[0].active_deadlines
    );
    println!(
        "RESTART historical_receipts={} binding={:?} judgment={} evidence={} deadlines={}",
        restart.historical_activation_receipts_recovered,
        restart.restarted_binding_state,
        restart.restarted_judgment,
        restart.restarted_supporting_evidence_count,
        restart.restarted_active_deadlines
    );
    Ok(())
}

fn run_fixture_demos(output: Option<&Path>) -> Result<(), Box<dyn Error>> {
    let (matched, _, _) = run_matched_activation_demo().map_err(io::Error::other)?;
    let executable_mismatch = run_mismatch_demo(
        ArtifactRoleV1::RunningExecutable,
        RuntimeBindingStateV1::ExecutableMismatch,
        "valid certificate names a different executable",
    )
    .map_err(io::Error::other)?;
    let policy_substitution = run_mismatch_demo(
        ArtifactRoleV1::ReliancePolicy,
        RuntimeBindingStateV1::PolicyMismatch,
        "same generation label; different canonical policy bytes",
    )
    .map_err(io::Error::other)?;
    let bundle = DemoBundleV1 {
        schema_version: SCHEMA_VERSION_V1,
        matched,
        executable_mismatch,
        policy_substitution,
        restart: run_restart_demo().map_err(io::Error::other)?,
        supersession: run_lifecycle_demo(GenerationLifecycleKindV1::Superseded)
            .map_err(io::Error::other)?,
        revocation: run_lifecycle_demo(GenerationLifecycleKindV1::Revoked)
            .map_err(io::Error::other)?,
        mismatch_corpus: run_load_bearing_mismatch_corpus().map_err(io::Error::other)?,
        authority_laundering: run_authority_laundering_corpus().map_err(io::Error::other)?,
    };
    for step in &bundle.matched.steps {
        println!(
            "MATCHED step={} binding={:?} judgment={} evidence={} deadlines={} action={}",
            step.sequence,
            step.binding_state,
            step.judgment,
            step.supporting_evidence_count,
            step.active_deadlines,
            step.action
        );
    }
    println!(
        "EXECUTABLE_MISMATCH binding={:?} judgment={} deadlines={}",
        bundle.executable_mismatch.steps[0].binding_state,
        bundle.executable_mismatch.steps[0].judgment,
        bundle.executable_mismatch.steps[0].active_deadlines
    );
    println!(
        "POLICY_SUBSTITUTION binding={:?} judgment={} deadlines={}",
        bundle.policy_substitution.steps[0].binding_state,
        bundle.policy_substitution.steps[0].judgment,
        bundle.policy_substitution.steps[0].active_deadlines
    );
    println!(
        "RESTART historical_receipts={} binding={:?} judgment={} evidence={} deadlines={}",
        bundle.restart.historical_activation_receipts_recovered,
        bundle.restart.restarted_binding_state,
        bundle.restart.restarted_judgment,
        bundle.restart.restarted_supporting_evidence_count,
        bundle.restart.restarted_active_deadlines
    );
    println!(
        "LIFECYCLE superseded={:?}/{} revoked={:?}/{}",
        bundle.supersession.after_state,
        bundle.supersession.after_judgment,
        bundle.revocation.after_state,
        bundle.revocation.after_judgment
    );
    if let Some(output) = output {
        write_json_new(output, &bundle)?;
    }
    Ok(())
}

fn usage() {
    eprintln!(
        "usage: pulse-qualification <demo [create-new-json]|crash-demo [create-new-json]|qualify <create-new-directory>>"
    );
}

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [command, phase, journal, marker] if command == "crash-child" => {
            run_crash_child(phase, Path::new(journal), Path::new(marker))
        }
        [command] if command == "demo" => run_fixture_demos(None),
        [command, output] if command == "demo" => run_fixture_demos(Some(Path::new(output))),
        [command] if command == "crash-demo" => {
            let corpus = run_activation_crash_corpus()?;
            println!(
                "CRASH points={} refused={} restart_checks_passed={}",
                corpus.points.len(),
                corpus.refused_point_count,
                corpus.all_executed_restart_checks_passed
            );
            Ok(())
        }
        [command, output] if command == "crash-demo" => {
            let corpus = run_activation_crash_corpus()?;
            write_json_new(Path::new(output), &corpus)?;
            println!(
                "CRASH points={} refused={} restart_checks_passed={}",
                corpus.points.len(),
                corpus.refused_point_count,
                corpus.all_executed_restart_checks_passed
            );
            Ok(())
        }
        [command, output] if command == "qualify" => {
            generate_checked_artifacts(&PathBuf::from(output))
        }
        _ => {
            usage();
            Err(io::Error::other("invalid command arguments").into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_test_count;

    #[test]
    fn test_count_parser_sums_only_success_summaries() {
        let output =
            b"test result: ok. 12 passed; 0 failed\nnoise\ntest result: ok. 3 passed; 0 failed\n";
        assert_eq!(parse_test_count(output), 15);
        assert_eq!(parse_test_count(b"test result: FAILED. 99 passed"), 0);
    }
}
