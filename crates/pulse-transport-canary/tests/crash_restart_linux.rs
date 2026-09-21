#![cfg(target_os = "linux")]

use std::fs;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use pulse_runtime::{
    EphemeralPrivateKeyFileV1, HistoricalJournal, ReceiverSchedulerRuntime, RuntimeBoundsV1,
    RuntimeConfigV1,
};
use pulse_transport_canary::{
    CANARY_CONSUMER_A, CANARY_SUBJECT, CrashChildReadyV1, canary_registration,
    receiver_journal_config, sender_journal_config,
};
use pulse_types::{
    ClockId, ConsumerId, ContextActivationId, CustodyPeerRoleV1, IncarnationId, JudgmentCategoryV1,
    ReceiverId, RuntimeBindingStateV1, SCHEMA_VERSION_V1, SparseDurableEventKindV1, SubjectId,
};

fn kill_child_at(point: &str) -> CrashChildReadyV1 {
    let marker = std::env::temp_dir().join(format!(
        "monitor-custody-crash-{point}-{}.json",
        std::process::id()
    ));
    let _ = fs::remove_file(&marker);
    let mut child = Command::new(env!("CARGO_BIN_EXE_pulse-transport-canary"))
        .args([
            "crash-child",
            point,
            marker.to_str().expect("UTF-8 marker path"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn crash child");
    let started = Instant::now();
    while !marker.exists() {
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "crash child did not reach {point}"
        );
        if let Some(status) = child.try_wait().expect("poll child") {
            panic!("crash child exited before SIGKILL at {point}: {status}");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let ready: CrashChildReadyV1 =
        serde_json::from_slice(&fs::read(&marker).expect("read marker")).expect("parse marker");
    assert!(!ready.private_key_material_serialized);
    let kill_status = Command::new("kill")
        .args(["-KILL", &ready.process_id.to_string()])
        .status()
        .expect("send SIGKILL");
    assert!(kill_status.success());
    assert!(!child.wait().expect("reap crash child").success());

    for (journal_path, config) in [
        (&ready.sender_journal_path, sender_journal_config()),
        (&ready.receiver_journal_path, receiver_journal_config()),
    ] {
        let report = HistoricalJournal::scan(journal_path, &config).expect("scan crash journal");
        let projection = report.project_history().expect("history projection");
        assert!(!projection.current_standing_reconstructed);
        assert!(!projection.active_escalation_suppression_restored);
        fs::remove_file(journal_path).expect("remove crash journal");
    }
    fs::remove_file(marker).expect("remove crash marker");
    ready
}

#[test]
fn ephemeral_private_key_file_is_mode_0600_and_removed_on_drop() {
    use std::os::unix::fs::PermissionsExt as _;

    let path = std::env::temp_dir().join(format!(
        "monitor-custody-private-key-{}.seed",
        std::process::id()
    ));
    let _ = fs::remove_file(&path);
    {
        let key = EphemeralPrivateKeyFileV1::create_new(
            &path,
            CustodyPeerRoleV1::Sender,
            vec!["host".to_owned()],
            "temporary-key-policy:test",
        )
        .expect("create temporary private key");
        assert_eq!(
            fs::metadata(key.path())
                .expect("key metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let debug = format!("{key:?}");
        assert!(debug.contains("redacted"));
    }
    assert!(!path.exists());
}

#[test]
fn sigkill_while_remote_current_recovers_history_but_no_session_evidence_or_standing() {
    let marker = std::env::temp_dir().join(format!(
        "monitor-custody-crash-ready-{}.json",
        std::process::id()
    ));
    let _ = fs::remove_file(&marker);
    let mut child = Command::new(env!("CARGO_BIN_EXE_pulse-transport-canary"))
        .args([
            "crash-child",
            "receiver_current",
            marker.to_str().expect("UTF-8 marker path"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn crash child");
    let started = Instant::now();
    while !marker.exists() {
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "crash child did not reach its named point"
        );
        if let Some(status) = child.try_wait().expect("poll child") {
            panic!("crash child exited before SIGKILL: {status}");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let ready: CrashChildReadyV1 =
        serde_json::from_slice(&fs::read(&marker).expect("read marker")).expect("parse marker");
    assert_eq!(
        ready.receiver_judgment_before_kill,
        JudgmentCategoryV1::Current
    );
    assert_eq!(ready.receiver_live_sessions_before_kill, 1);
    assert!(!ready.private_key_material_serialized);
    let kill_status = Command::new("kill")
        .args(["-KILL", &ready.process_id.to_string()])
        .status()
        .expect("send SIGKILL");
    assert!(kill_status.success());
    let status = child.wait().expect("reap crash child");
    assert!(!status.success());

    let receiver_journal = std::path::Path::new(&ready.receiver_journal_path);
    let report = HistoricalJournal::scan(receiver_journal, &receiver_journal_config())
        .expect("scan crash journal");
    let projection = report.project_history().expect("history projection");
    assert!(projection.history_complete);
    assert!(!projection.current_standing_reconstructed);
    assert!(!projection.active_escalation_suppression_restored);
    assert!(
        projection
            .history
            .sparse_events
            .iter()
            .any(|event| matches!(
                event.event,
                SparseDurableEventKindV1::ReceiverBoundaryAcceptanceRecorded { .. }
            ))
    );
    assert!(
        projection
            .history
            .sparse_events
            .iter()
            .any(|event| matches!(
                &event.event,
                SparseDurableEventKindV1::SupportCertificateIssued { certificate }
                    if certificate.judgment == JudgmentCategoryV1::Current
            ))
    );

    let mut registration_a = canary_registration(CANARY_CONSUMER_A, 1);
    registration_a.policy.maximum_validity_ms = ready.pulse_validity_ms;
    registration_a.context.reliance_policy_semantic_digest =
        registration_a.policy.semantic_digest();
    registration_a.context.activation_id =
        ContextActivationId::new("activation:remote-canary:crash-restart-a");
    let mut registration_b = canary_registration(pulse_transport_canary::CANARY_CONSUMER_B, 2);
    registration_b.policy.maximum_validity_ms = ready.pulse_validity_ms;
    registration_b.context.reliance_policy_semantic_digest =
        registration_b.policy.semantic_digest();
    registration_b.context.activation_id =
        ContextActivationId::new("activation:remote-canary:crash-restart-b");
    let (runtime, _) = ReceiverSchedulerRuntime::recover(
        RuntimeConfigV1 {
            schema_version: SCHEMA_VERSION_V1,
            receiver: ReceiverId::new("receiver:receiver:custody-canary"),
            receiver_incarnation: IncarnationId::new("receiver-incarnation:crash-restart"),
            clock_id: ClockId::new("clock:crash-restart"),
            transport_custody_policy: Some(ready.receiver_policy_binding),
            bounds: RuntimeBoundsV1::qualification(),
        },
        vec![registration_a, registration_b],
        projection.history,
        0,
    )
    .expect("history-only recovery");
    let certificate = runtime
        .current_certificate(
            &SubjectId::new(CANARY_SUBJECT),
            &ConsumerId::new(CANARY_CONSUMER_A),
        )
        .expect("restart certificate");
    assert_eq!(
        runtime.binding_state(
            &SubjectId::new(CANARY_SUBJECT),
            &ConsumerId::new(CANARY_CONSUMER_A)
        ),
        RuntimeBindingStateV1::Unbound
    );
    assert_eq!(certificate.judgment, JudgmentCategoryV1::Unknown);
    assert!(certificate.supporting_evidence_ids.is_empty());
    assert!(certificate.remote_observation_custody.is_empty());
    assert_eq!(runtime.scheduled_deadline_count(), 0);

    fs::remove_file(&ready.receiver_journal_path).expect("remove receiver journal");
    fs::remove_file(&ready.sender_journal_path).expect("remove sender journal");
    fs::remove_file(marker).expect("remove marker");
}

#[test]
fn sigkill_before_session_during_session_and_after_signing_restores_no_live_custody() {
    let qualified = kill_child_at("sender_qualified");
    assert_eq!(qualified.sender_live_sessions_before_kill, 0);
    assert_eq!(qualified.receiver_live_sessions_before_kill, 0);
    assert_eq!(
        qualified.receiver_judgment_before_kill,
        JudgmentCategoryV1::Unknown
    );

    let session = kill_child_at("session_active");
    assert_eq!(session.sender_live_sessions_before_kill, 1);
    assert_eq!(session.receiver_live_sessions_before_kill, 1);
    assert_eq!(
        session.receiver_judgment_before_kill,
        JudgmentCategoryV1::Unknown
    );

    let signed = kill_child_at("envelope_signed");
    assert_eq!(signed.sender_live_sessions_before_kill, 1);
    assert_eq!(signed.receiver_live_sessions_before_kill, 1);
    assert_eq!(
        signed.receiver_judgment_before_kill,
        JudgmentCategoryV1::Unknown
    );
}
