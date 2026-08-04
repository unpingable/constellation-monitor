use pulse_runtime::{
    JournalDamageClassV1, JournalRecoveryOutcomeV1, run_journal_corruption_corpus, run_reactor_demo,
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
}
