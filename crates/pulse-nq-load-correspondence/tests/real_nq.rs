//! Real co-production against a pinned NQ executable and store.
//!
//! Ignored by default. Run deliberately in the disposable environment:
//!
//! ```sh
//! NQ_CORRESPONDENCE_PROFILE=/absolute/profile.json \
//! NQ_CORRESPONDENCE_CUSTODY_ROOT=/absolute/fresh/custody \
//! NQ_CORRESPONDENCE_EXPECTED_STATE=present \
//! NQ_CORRESPONDENCE_OCCURRENCES=3 \
//! NQ_CORRESPONDENCE_CADENCE_MS=2000 \
//! cargo test -p pulse-nq-load-correspondence --features synthetic-fixtures \
//!   --test real_nq -- --ignored --nocapture
//! ```
//!
//! Prerequisites (stop conditions S4, S7, S8, S11): a sealed profile whose NQ
//! identities were enrolled from a real run of the pinned build; a schema-13
//! NQ store with an admitted watcher that already has prior history; an NQ
//! executable path not writable by this principal; and a fresh custody root.
//! The Pulse reactor here is activated with the repository's local
//! qualification fixture inputs; a production embedding supplies its own.
//!
//! The harness, not the crate, reads the Linux boot identity.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use pulse_nq_load_correspondence::fixture::start_reactor;
use pulse_nq_load_correspondence::{
    Coproducer, CorrespondenceError, CorrespondenceProfileV1, NqDetectorStateV1,
    OccurrenceOutcomeV1, PinnedNqExecutable, SubjectIncarnationWitness, verify_audit_record,
};
use pulse_types::IncarnationId;

struct LinuxBootWitness;

impl SubjectIncarnationWitness for LinuxBootWitness {
    fn current(&self) -> Result<IncarnationId, CorrespondenceError> {
        let value = fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|error| CorrespondenceError::new("io", error.to_string()))?;
        let value = value.trim();
        if value.is_empty() {
            return Err(CorrespondenceError::new(
                "invalid_incarnation",
                "Linux boot identity is empty",
            ));
        }
        Ok(IncarnationId::new(format!("linux-boot:{value}")))
    }
}

fn env_path(name: &str) -> PathBuf {
    let value = std::env::var_os(name).unwrap_or_else(|| panic!("{name} is required"));
    let path = PathBuf::from(value);
    assert!(path.is_absolute(), "{name} must be absolute");
    path
}

fn expected_state() -> NqDetectorStateV1 {
    match std::env::var("NQ_CORRESPONDENCE_EXPECTED_STATE")
        .expect("NQ_CORRESPONDENCE_EXPECTED_STATE is required")
        .as_str()
    {
        "present" => NqDetectorStateV1::Present,
        "explicitly_absent" => NqDetectorStateV1::ExplicitlyAbsent,
        "cannot_evaluate" => NqDetectorStateV1::CannotEvaluate,
        other => panic!(
            "NQ_CORRESPONDENCE_EXPECTED_STATE must be present, explicitly_absent, or cannot_evaluate; got {other}"
        ),
    }
}

#[test]
#[ignore = "requires a pinned real NQ executable, store, and enrolled profile"]
fn real_nq_co_production_run() {
    let profile_path = env_path("NQ_CORRESPONDENCE_PROFILE");
    let custody_root = env_path("NQ_CORRESPONDENCE_CUSTODY_ROOT");
    let expected_state = expected_state();
    let occurrences: u64 = std::env::var("NQ_CORRESPONDENCE_OCCURRENCES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(3);
    let cadence_ms: u64 = std::env::var("NQ_CORRESPONDENCE_CADENCE_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(2_000);
    assert!(
        (1..=64).contains(&occurrences),
        "occurrences must be finite and bounded"
    );

    let profile = CorrespondenceProfileV1::decode(&fs::read(&profile_path).expect("profile"))
        .expect("profile validates");
    let port = PinnedNqExecutable::from_enrollment(&profile.nq).expect("pinned NQ");
    let witness = LinuxBootWitness;
    let subject_incarnation = witness.current().expect("boot identity");

    fs::create_dir_all(&custody_root).expect("custody root");
    let journal = custody_root.join("pulse.journal");
    let reactor =
        start_reactor(&profile, subject_incarnation, "real-nq", &journal).expect("reactor");
    let mut coproducer = Coproducer::begin(
        &profile,
        &port,
        &witness,
        &custody_root.join("intent"),
        &custody_root.join("audit"),
    )
    .expect("coproducer");

    let mut summary = Vec::new();
    for index in 0..occurrences {
        if index > 0 {
            std::thread::sleep(Duration::from_millis(cadence_ms));
        }
        match coproducer.run_occurrence(&reactor) {
            Ok(result) => {
                let bytes = fs::read(&result.record_path).expect("record");
                let verdict = verify_audit_record(&bytes, &profile).expect("record verifies");
                match &result.outcome {
                    OccurrenceOutcomeV1::Verified(_) => {}
                    OccurrenceOutcomeV1::AuditOnly { refusal } => {
                        panic!("occurrence {} was audit-only: {refusal}", result.sequence);
                    }
                }
                assert_eq!(
                    verdict.nq_detector_state, expected_state,
                    "occurrence {} produced the wrong NQ state",
                    result.sequence
                );
                let outcome = "verified";
                println!(
                    "occurrence {} acquisition={} state={} d={}ms f={}ms outcome={} record={}",
                    result.sequence,
                    result.acquisition_id,
                    verdict.nq_detector_state.as_str(),
                    result.delivery.holding_delay_ms,
                    result.delivery.ingress_fence_ms,
                    outcome,
                    result.record_path.display()
                );
                summary.push(serde_json::json!({
                    "sequence": result.sequence,
                    "acquisition_id": result.acquisition_id,
                    "correspondence_id": result.correspondence_id,
                    "nq_detector_state": verdict.nq_detector_state,
                    "holding_delay_ms": result.delivery.holding_delay_ms,
                    "ingress_fence_ms": result.delivery.ingress_fence_ms,
                    "outcome": outcome,
                    "record_path": result.record_path,
                }));
            }
            Err(error) => {
                panic!("occurrence refused before delivery: {error}");
            }
        }
    }
    let snapshot = reactor.shutdown().expect("shutdown");
    let mut bytes = serde_json::to_vec_pretty(&serde_json::json!({
        "schema": "constellation.nq_host_load_pressure_correspondence_run_summary.v1",
        "profile_digest": profile.digest(),
        "occurrences": summary,
        "final_reactor_condition": snapshot.condition,
        "nonclaims": [
            "this summary is a harness transcript, not qualification acceptance",
            "no retained record restores present support"
        ]
    }))
    .expect("summary");
    bytes.push(b'\n');
    pulse_nq_load_correspondence::write_create_new(
        &custody_root.join("run-summary.json"),
        &bytes,
        0o640,
    )
    .expect("summary is create-new");
}
