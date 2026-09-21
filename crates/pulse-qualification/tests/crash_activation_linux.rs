#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use pulse_qualification::ActivationCrashCorpusV1;
use pulse_types::{JudgmentCategoryV1, RuntimeBindingStateV1};

static NEXT_PATH: AtomicU64 = AtomicU64::new(1);

#[test]
fn sigkill_at_activation_and_receipt_boundaries_never_reconstructs_binding() {
    let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
    let artifact = std::env::temp_dir().join(format!(
        "monitor-qualified-crash-integration-{}-{sequence}.json",
        std::process::id()
    ));
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_pulse-qualification"));
    let output = Command::new(executable)
        .arg("crash-demo")
        .arg(&artifact)
        .output()
        .expect("crash harness executes");
    assert!(
        output.status.success(),
        "crash harness failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let corpus: ActivationCrashCorpusV1 =
        serde_json::from_slice(&fs::read(&artifact).expect("artifact bytes"))
            .expect("artifact schema");
    assert!(corpus.all_executed_restart_checks_passed);
    assert_eq!(corpus.refused_point_count, 1);
    assert!(
        corpus
            .points
            .iter()
            .filter(|point| point.technically_executed)
            .all(|point| {
                point.process_killed
                    && point.restarted_binding_state == RuntimeBindingStateV1::Unbound
                    && point.restarted_judgment == JudgmentCategoryV1::Unknown
                    && point.restarted_supporting_evidence_count == 0
                    && point.restarted_active_deadlines == 0
                    && !point.standing_reconstructed
            })
    );
    assert!(corpus.points.iter().any(|point| {
        point.point == "while_current"
            && point.historical_current_records > 0
            && !point.standing_reconstructed
    }));
    assert!(corpus.points.iter().any(|point| {
        point.point == "after_activation_receipt_sync_before_ack"
            && point.historical_activation_receipts == 1
            && !point.standing_reconstructed
    }));
    assert!(corpus.points.iter().any(|point| {
        point.point == "after_receipt_sync_before_runtime_binding_activation"
            && !point.technically_executed
            && point.journal_recovery == "SemanticallyRefused"
    }));
    fs::remove_file(artifact).expect("remove bounded fixture artifact");
}
