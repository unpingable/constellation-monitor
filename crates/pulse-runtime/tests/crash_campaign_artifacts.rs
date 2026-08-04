use pulse_runtime::{
    CrashFaultQualificationArtifactV1, CrashHarnessArtifactV1, JournalCorruptionCorpusV1,
    JournalDamageClassV1, JournalRecoveryOutcomeV1, JournalScenarioV1, LiveLinuxArtifactV1,
    ReactorDemoArtifactV1, RestartDemoArtifactV1, run_journal_corruption_corpus, run_reactor_demo,
};
use pulse_types::MutationAuthorityV1;

#[test]
fn reactor_demo_is_autonomous_and_journals_its_withdrawal() {
    let artifact = run_reactor_demo().expect("reactor demo");
    assert_eq!(
        artifact.sequence.first().map(String::as_str),
        Some("UNKNOWN")
    );
    assert_eq!(
        artifact.sequence.get(2).map(String::as_str),
        Some("CURRENT")
    );
    assert_eq!(
        artifact.sequence.get(6).map(String::as_str),
        Some("UNKNOWN")
    );
    assert!(
        artifact.actual_withdrawal_monotonic_ms >= artifact.requested_support_deadline_monotonic_ms
    );
    assert_eq!(artifact.withdrawal_sparse_records, 1);
    assert_eq!(artifact.journal_recovery, JournalRecoveryOutcomeV1::Clean);
    assert!(!artifact.current_standing_reconstructed);
    assert_eq!(artifact.mutation_authority, MutationAuthorityV1::None);

    let checked: ReactorDemoArtifactV1 =
        serde_json::from_str(include_str!("../../../artifacts/crash-reactor-demo.json"))
            .expect("checked reactor artifact");
    assert_eq!(checked.sequence, artifact.sequence);
    let restart: RestartDemoArtifactV1 =
        serde_json::from_str(include_str!("../../../artifacts/crash-restart-demo.json"))
            .expect("checked restart artifact");
    assert_eq!(
        restart.current_standing_after_restart,
        pulse_types::JudgmentCategoryV1::Unknown
    );
    assert_eq!(restart.supporting_evidence_after_restart, 0);
    assert_eq!(restart.active_deadlines_after_restart, 0);
    let crash: CrashHarnessArtifactV1 =
        serde_json::from_str(include_str!("../../../artifacts/crash-injection.json"))
            .expect("checked crash artifact");
    assert!(crash.all_restart_invariants_held);
    let live: LiveLinuxArtifactV1 = serde_json::from_str(include_str!(
        "../../../artifacts/crash-reactor-live-linux.json"
    ))
    .expect("checked live artifact");
    assert!(!live.hard_realtime_claimed);
    let qualification: CrashFaultQualificationArtifactV1 = serde_json::from_str(include_str!(
        "../../../artifacts/crash-reactor-qualification.json"
    ))
    .expect("checked qualification artifact");
    assert!(!qualification.current_standing_durable);
    assert!(!qualification.mutation_authority_emitted);
}

#[test]
fn corruption_corpus_never_launders_damage_into_standing() {
    let artifact = run_journal_corruption_corpus().expect("corruption corpus");
    let torn = artifact
        .scenarios
        .iter()
        .find(|scenario| scenario.name == "valid_prefix_followed_by_torn_suffix")
        .expect("torn suffix scenario");
    assert_eq!(
        torn.outcome,
        JournalRecoveryOutcomeV1::RecoveredThroughValidPrefix
    );
    assert_eq!(torn.damage, Some(JournalDamageClassV1::TruncatedPayload));
    assert!(!torn.history_complete);
    let interior = artifact
        .scenarios
        .iter()
        .find(|scenario| scenario.name == "interior_bit_corruption")
        .expect("interior corruption scenario");
    assert_eq!(interior.outcome, JournalRecoveryOutcomeV1::Refused);
    assert_eq!(
        interior.damage,
        Some(JournalDamageClassV1::InteriorCorruption)
    );
    assert!(!artifact.truncation_sweep.partial_frame_accepted_as_record);
    assert!(artifact.all_recovery_reconstructed_no_standing);
    assert!(artifact.scenarios.iter().all(|scenario| {
        !scenario.current_standing_reconstructed
            && scenario.mutation_authority == MutationAuthorityV1::None
    }));

    let checked: JournalCorruptionCorpusV1 = serde_json::from_str(include_str!(
        "../../../artifacts/journal-corruption-corpus.json"
    ))
    .expect("checked corruption artifact");
    assert_eq!(checked.scenarios.len(), artifact.scenarios.len());
    let torn: JournalScenarioV1 = serde_json::from_str(include_str!(
        "../../../artifacts/crash-torn-journal-demo.json"
    ))
    .expect("checked torn demo");
    assert!(!torn.history_complete);
    let interior: JournalScenarioV1 = serde_json::from_str(include_str!(
        "../../../artifacts/crash-interior-corruption-demo.json"
    ))
    .expect("checked interior demo");
    assert_eq!(interior.outcome, JournalRecoveryOutcomeV1::Refused);
}
