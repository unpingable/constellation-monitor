#![cfg(target_os = "linux")]

use std::path::Path;

use pulse_runtime::{JournalDamageClassV1, JournalRecoveryOutcomeV1, run_crash_harness};
use pulse_types::JudgmentCategoryV1;

#[test]
fn named_sigkill_boundaries_never_restore_current_support_or_deadlines() {
    let executable = Path::new(env!("CARGO_BIN_EXE_pulse-crash-campaign"));
    let artifact = run_crash_harness(executable).expect("Linux crash harness succeeds");
    assert_eq!(artifact.scenarios.len(), 12);
    assert!(artifact.all_restart_invariants_held);
    assert!(!artifact.current_standing_reconstructed);
    assert!(!artifact.active_escalation_authority_reconstructed);
    for scenario in &artifact.scenarios {
        assert!(scenario.marker_observed, "{}", scenario.name);
        assert!(scenario.child_killed, "{}", scenario.name);
        assert_eq!(
            scenario.current_standing_after_restart,
            JudgmentCategoryV1::Unknown,
            "{}",
            scenario.name
        );
        assert_eq!(scenario.supporting_evidence_after_restart, 0);
        assert_eq!(scenario.active_deadlines_after_restart, 0);
        assert!(!scenario.active_escalation_suppression_restored);
    }

    let before_sync = artifact
        .scenarios
        .iter()
        .find(|scenario| scenario.name == "after_withdrawal_written_before_sync")
        .expect("before-sync case");
    assert_eq!(
        before_sync.journal_outcome,
        JournalRecoveryOutcomeV1::RecoveredThroughValidPrefix
    );
    assert_eq!(
        before_sync.journal_damage,
        Some(JournalDamageClassV1::UncommittedSuffix)
    );
    assert!(!before_sync.durability_point_reached_before_kill);

    let after_sync = artifact
        .scenarios
        .iter()
        .find(|scenario| scenario.name == "after_sync_before_acknowledgement")
        .expect("after-sync case");
    assert_eq!(after_sync.journal_outcome, JournalRecoveryOutcomeV1::Clean);
    assert!(after_sync.durability_point_reached_before_kill);
    assert!(!after_sync.acknowledgement_delivery_known_after_restart);

    for (name, damage) in [
        (
            "during_record_framing",
            JournalDamageClassV1::TruncatedHeader,
        ),
        (
            "during_payload_write",
            JournalDamageClassV1::TruncatedPayload,
        ),
        (
            "during_trailer_checksum_write",
            JournalDamageClassV1::TruncatedTrailer,
        ),
    ] {
        let scenario = artifact
            .scenarios
            .iter()
            .find(|scenario| scenario.name == name)
            .expect("named torn-write case");
        assert_eq!(
            scenario.journal_outcome,
            JournalRecoveryOutcomeV1::RecoveredThroughValidPrefix
        );
        assert_eq!(scenario.journal_damage, Some(damage));
        assert!(!scenario.history_complete);
    }

    let contradiction = artifact
        .scenarios
        .iter()
        .find(|scenario| scenario.name == "after_contradiction_custody_persisted")
        .expect("contradiction case");
    assert_eq!(contradiction.contradiction_custody_recovered, 1);

    let escalation = artifact
        .scenarios
        .iter()
        .find(|scenario| scenario.name == "after_escalation_deduplication_persisted")
        .expect("escalation case");
    assert_eq!(escalation.historical_escalation_deduplication_keys, 1);
    assert!(!escalation.active_escalation_suppression_restored);
}
