//! The resolver binary against a fake `nq` serving evaluation-history pages.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use constellation_remediation_resolver::{
    ACTIVE_BASIS_TYPE, BASIS_TYPE, CURRENTNESS_DOMAIN, ResolutionFields, Status,
    TYPED_BASIS_SCHEMA, hash_domain, jcs,
};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
const MACHINE: &str = "1853ff04ff7a42679bf212ec9a569c4f";
const UNIT: &str = "attention-canary.service";
const INSTANCE: &str = "svc-attention-canary";
const RESOLVER_ID: &str = "constellation-remediation-nq-unit/v1";
const CAMPAIGN: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const OBSERVATION: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const SUBJECT: &str = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
const OCCURRENCE: &str = "0b9f7d2e-5c1a-4f3e-9a8b-7c6d5e4f3a2b";
/// 2026-10-03T00:00:00Z in ms.
const NOW: u64 = 1_790_985_600_000;

struct Harness {
    dir: tempfile::TempDir,
    extra: Vec<String>,
}

impl Harness {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("fake/history")).unwrap();
        let wrapper = dir.path().join("nq");
        fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\nFAKE_NQ_DIR={} exec {}/fake-nq.sh \"$@\"\n",
                dir.path().join("fake").display(),
                FIXTURES
            ),
        )
        .unwrap();
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
        Self {
            dir,
            extra: Vec::new(),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn control(&self, name: &str) {
        fs::write(self.path("fake").join(name), "").unwrap();
    }

    fn len(&self) -> usize {
        fs::read_dir(self.path("fake/history")).unwrap().count()
    }

    /// Append one evaluation record.
    fn append(&self, envelope: &Value) {
        let sequence = self.len() + 1;
        fs::write(
            self.path(&format!("fake/history/{sequence}.json")),
            serde_json::to_vec(envelope).unwrap(),
        )
        .unwrap();
    }

    fn calls(&self) -> Vec<String> {
        fs::read_to_string(self.path("fake/calls.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn run_with(&self, request: &[u8]) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_constellation-nq-unit-resolver"))
            .args([
                "--nq-program",
                &self.path("nq").display().to_string(),
                "--config",
                "/etc/nq/nqd-ops.toml",
                "--instance-id",
                INSTANCE,
                "--unit",
                UNIT,
                "--machine-id",
                MACHINE,
                "--resolver-id",
                RESOLVER_ID,
            ])
            .args(&self.extra)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(request).unwrap();
        child.wait_with_output().unwrap()
    }

    fn resolve(&self) -> Value {
        let output = self.run_with(&request(NOW));
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn refuse(&self) -> String {
        let output = self.run_with(&request(NOW));
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        String::from_utf8_lossy(&output.stderr).into_owned()
    }
}

fn request(now: u64) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": "ag.governed-loop.observation-request/v1",
        "key": {"campaign": CAMPAIGN, "occurrence": OCCURRENCE},
        "observation": OBSERVATION,
        "subject": SUBJECT,
        "now_unix_ms": now,
    }))
    .unwrap()
}

fn stamp(ms: u64) -> String {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .unwrap()
        .format(&Rfc3339)
        .unwrap()
}

/// An `nq.evaluation_envelope.v2` of the `nq.systemd_unit` v2 profile.
fn envelope(instance: &str, unit: &str, evaluated_ms: u64, state: &str) -> Value {
    let profile = json!({"profile": {"id": "nq.systemd_unit", "version": 2}});
    json!({
        "schema": "nq.evaluation_envelope.v2",
        "evaluation_id": format!("eval-{instance}-{evaluated_ms}"),
        "context": {
            "instance_id": instance,
            "subject": format!("systemd-unit:{MACHINE}/{unit}"),
            "scope": {"kind": "systemd_unit", "value": {
                "machine_id": MACHINE,
                "schema": "nq.systemd_unit_scope.v2",
                "unit_name": unit,
            }},
            "vantage": {"kind": "local", "value": {}},
        },
        "profile": profile,
        "evaluated_at": stamp(evaluated_ms),
        "result": {
            "schema": "nq.evaluation_result.v1",
            "profile": profile,
            "state": state,
            "condition": "systemd_unit_not_active",
        },
    })
}

fn canary(evaluated_ms: u64, state: &str) -> Value {
    envelope(INSTANCE, UNIT, evaluated_ms, state)
}

fn other(evaluated_ms: u64) -> Value {
    envelope("unit-ssh", "ssh.service", evaluated_ms, "explicitly_absent")
}

fn basis() -> Value {
    let identity = json!({"instance_id": INSTANCE, "machine_id": MACHINE, "unit": UNIT});
    json!({
        "schema": TYPED_BASIS_SCHEMA,
        "basis_type": BASIS_TYPE,
        "basis_identity": hash_domain(BASIS_TYPE, &jcs(&identity)),
    })
}

fn witness(sequence: u64, evaluated_ms: u64, outcome: &str) -> String {
    hash_domain(
        CURRENTNESS_DOMAIN,
        &jcs(&json!({
            "evaluated_at": stamp(evaluated_ms),
            "outcome": outcome,
            "sequence": sequence,
        })),
    )
}

#[test]
fn current_when_newest_shows_unit_not_active_within_bound() {
    let harness = Harness::new();
    harness.append(&canary(NOW - 90_000, "explicitly_absent"));
    harness.append(&other(NOW - 4_000));
    harness.append(&canary(NOW - 3_000, "present"));
    harness.append(&other(NOW - 2_000));
    let record = harness.resolve();
    let expected = json!({
        "schema": "ag.governed-loop.observation-resolution/v3",
        "key": {"campaign": CAMPAIGN, "occurrence": OCCURRENCE},
        "observation": OBSERVATION,
        "currentness": witness(3, NOW - 3_000, "present"),
        "normalized_preconditions": hash_domain(TYPED_BASIS_SCHEMA, &jcs(&basis())),
        "basis": basis(),
        "resolver_id": RESOLVER_ID,
        "subject": SUBJECT,
        "status": "current",
        "resolved_at_unix_ms": NOW,
        "fresh_until_unix_ms": NOW + 57_000,
    });
    assert_eq!(record, expected);
    assert_eq!(
        harness.calls(),
        ["evaluations 1 none none", "evaluations 4 0 4"]
    );
}

/// The AG-side normalized_preconditions vector, computed with AG's own
/// `TypedOpaqueObservationBasisV1::binding_digest` (ag-campaign f21b243).
#[test]
fn basis_binding_matches_ag_vector() {
    let output = Command::new(env!("CARGO_BIN_EXE_constellation-nq-unit-resolver"))
        .args([
            "--print-basis",
            "--instance-id",
            INSTANCE,
            "--unit",
            UNIT,
            "--machine-id",
            MACHINE,
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let printed: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(printed["basis"], basis());
    assert_eq!(
        printed["normalized_preconditions"],
        hash_domain(TYPED_BASIS_SCHEMA, &jcs(&basis()))
    );
    let ag_vector = fs::read_to_string(Path::new(FIXTURES).join("ag-basis-vector.json")).unwrap();
    let ag_vector: Value = serde_json::from_str(&ag_vector).unwrap();
    assert_eq!(printed, ag_vector);
}

#[test]
fn synthetic_future_sample_boundary() {
    // Synthetic clock boundary; these values are not the retained #71 sample.
    const SAMPLE: u64 = 1_791_092_229_403;
    const DECIDE: u64 = 1_791_092_229_270;
    for (now, expected) in [
        (DECIDE, "current"),
        (SAMPLE - 2_000, "current"),
        (SAMPLE - 2_001, "unsupported"),
    ] {
        let harness = Harness::new();
        // Never substitute older current evidence for the newest future record.
        harness.append(&canary(now - 1_000, "present"));
        harness.append(&canary(SAMPLE, "present"));
        let output = harness.run_with(&request(now));
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let record: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(record["status"], expected, "sample={SAMPLE}, now={now}");
    }
}

#[test]
fn retained_71_newest_expired_testimony_refuses_authorization() {
    let mut harness = Harness::new();
    harness.extra = vec!["--max-age-ms".into(), "90000".into()];
    // Exact retained evaluation timestamps: the earlier present evaluation is
    // recent, but NQ's later testimony-expiry judgment takes precedence.
    harness.append(&canary(1_791_092_199_403, "present"));
    let decide = harness.run_with(&request(1_791_092_229_270));
    let record: Value = serde_json::from_slice(&decide.stdout).unwrap();
    assert_eq!(record["status"], "current");
    harness.append(&canary(1_791_092_229_693, "cannot_evaluate"));
    let authorize = harness.run_with(&request(1_791_092_229_832));
    assert!(authorize.status.success());
    let record: Value = serde_json::from_slice(&authorize.stdout).unwrap();
    assert_eq!(record["status"], "unsupported");
}

#[test]
fn stale_when_newest_is_older_than_the_bound() {
    let harness = Harness::new();
    harness.append(&canary(NOW - 60_000, "present"));
    harness.append(&other(NOW - 1_000));
    let record = harness.resolve();
    assert_eq!(record["status"], "stale");
    assert_eq!(record["fresh_until_unix_ms"], NOW);
    assert_eq!(record["currentness"], witness(1, NOW - 60_000, "present"));
    // One millisecond younger is current.
    let harness = Harness::new();
    harness.append(&canary(NOW - 59_999, "present"));
    assert_eq!(harness.resolve()["status"], "current");
}

#[test]
fn contradictory_when_newest_shows_unit_active() {
    let harness = Harness::new();
    harness.append(&canary(NOW - 20_000, "present"));
    harness.append(&canary(NOW - 2_000, "explicitly_absent"));
    let record = harness.resolve();
    assert_eq!(record["status"], "contradictory");
    assert_eq!(
        record["currentness"],
        witness(2, NOW - 2_000, "explicitly_absent")
    );
    assert_eq!(record["fresh_until_unix_ms"], NOW + 58_000);
}

#[test]
fn absent_when_no_evaluation_of_the_instance_in_the_window() {
    let mut harness = Harness::new();
    harness.extra = vec!["--window-records".into(), "3".into()];
    harness.append(&canary(NOW - 5_000, "present"));
    for offset in [4_000, 3_000, 2_000] {
        harness.append(&other(NOW - offset));
    }
    let record = harness.resolve();
    assert_eq!(record["status"], "absent");
    assert_eq!(
        record["currentness"],
        hash_domain(
            CURRENTNESS_DOMAIN,
            &jcs(&json!({"evaluated_at": null, "outcome": "absent", "sequence": 4}))
        )
    );
    assert_eq!(record["fresh_until_unix_ms"], NOW + 1);
    assert_eq!(
        harness.calls(),
        ["evaluations 1 none none", "evaluations 3 1 4"]
    );
    // An empty store is absent too.
    assert_eq!(Harness::new().resolve()["status"], "absent");
}

#[test]
fn indeterminate_or_foreign_newest_evaluation_is_not_current() {
    let harness = Harness::new();
    harness.append(&canary(NOW - 1_000, "cannot_evaluate"));
    assert_eq!(harness.resolve()["status"], "unsupported");

    let harness = Harness::new();
    let mut moved = canary(NOW - 1_000, "present");
    moved["context"]["scope"]["value"]["unit_name"] = json!("other.service");
    harness.append(&moved);
    assert_eq!(harness.resolve()["status"], "refused");

    let harness = Harness::new();
    let mut v1 = canary(NOW - 1_000, "present");
    v1["profile"]["profile"]["version"] = json!(1);
    harness.append(&v1);
    assert_eq!(harness.resolve()["status"], "unsupported");

    let harness = Harness::new();
    harness.append(&canary(NOW + 5_000, "present"));
    assert_eq!(harness.resolve()["status"], "unsupported");
}

#[test]
fn window_spans_pages_under_one_frozen_bound() {
    let mut harness = Harness::new();
    harness.extra = vec!["--window-records".into(), "2500".into()];
    for index in 0..2600 {
        harness.append(&other(NOW - 10_000 + index));
    }
    harness.append(&canary(NOW - 1_000, "present"));
    assert_eq!(harness.resolve()["status"], "current");
    assert_eq!(
        harness.calls(),
        [
            "evaluations 1 none none",
            "evaluations 1000 101 2601",
            "evaluations 1000 1101 2601",
            "evaluations 500 2101 2601",
        ]
    );
}

#[test]
fn malformed_page_is_refused() {
    let harness = Harness::new();
    harness.append(&canary(NOW - 1_000, "present"));
    harness.control("malformed");
    assert!(
        harness
            .refuse()
            .contains("schema is not nq.evaluation_history.v1")
    );

    let harness = Harness::new();
    fs::write(harness.path("fake/history/1.json"), "{\"context\":{}}").unwrap();
    assert!(harness.refuse().contains("has no instance id"));

    let harness = Harness::new();
    harness.append(&canary(NOW - 1_000, "present"));
    harness.control("history_moved");
    assert!(harness.refuse().contains("moved from through_sequence"));
}

#[test]
fn nq_failure_is_refused() {
    let harness = Harness::new();
    harness.control("fail");
    let error = harness.refuse();
    assert!(error.contains("store is locked"), "{error}");

    let mut harness = Harness::new();
    harness.extra = vec!["--nq-program".into(), "/nonexistent/nq".into()];
    assert!(harness.refuse().contains("cannot start"));
}

/// An unqualified read is a boundary failure, not a temporal diagnosis.
#[test]
fn a_single_nq_failure_is_refused_without_a_speculative_retry() {
    let harness = Harness::new();
    harness.append(&canary(NOW - 1_000, "present"));
    harness.control("fail_once");
    assert!(harness.refuse().contains("transient"));
    assert!(!harness.path("fake/fail_once").exists());
}

#[test]
fn oversize_output_is_refused() {
    let mut harness = Harness::new();
    harness.extra = vec!["--max-page-bytes".into(), "65536".into()];
    harness.control("oversize");
    assert!(harness.refuse().contains("printed more than 65536 bytes"));
}

#[test]
fn malformed_request_is_refused_before_nq() {
    let harness = Harness::new();
    for body in [
        b"not json".to_vec(),
        serde_json::to_vec(&json!({"schema": "other"})).unwrap(),
        {
            let mut value: Value = serde_json::from_slice(&request(NOW)).unwrap();
            value["extra"] = json!(1);
            serde_json::to_vec(&value).unwrap()
        },
        {
            let mut value: Value = serde_json::from_slice(&request(NOW)).unwrap();
            value["subject"] = json!("sha256:XYZ");
            serde_json::to_vec(&value).unwrap()
        },
    ] {
        let output = harness.run_with(&body);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
    assert!(harness.calls().is_empty());
}

fn active_basis() -> Value {
    let identity = json!({"instance_id": INSTANCE, "machine_id": MACHINE, "unit": UNIT});
    json!({
        "schema": TYPED_BASIS_SCHEMA,
        "basis_type": ACTIVE_BASIS_TYPE,
        "basis_identity": hash_domain(ACTIVE_BASIS_TYPE, &jcs(&identity)),
    })
}

fn active_harness() -> Harness {
    let mut harness = Harness::new();
    harness.extra = vec!["--claim".into(), "active".into()];
    harness
}

#[test]
fn active_claim_is_current_only_when_newest_shows_unit_active() {
    let harness = active_harness();
    harness.append(&canary(NOW - 20_000, "present"));
    harness.append(&canary(NOW - 2_000, "explicitly_absent"));
    let record = harness.resolve();
    assert_eq!(record["status"], "current");
    assert_eq!(record["basis"], active_basis());
    assert_eq!(
        record["normalized_preconditions"],
        hash_domain(TYPED_BASIS_SCHEMA, &jcs(&active_basis()))
    );
    assert_eq!(
        record["currentness"],
        witness(2, NOW - 2_000, "explicitly_absent")
    );
    assert_eq!(record["fresh_until_unix_ms"], NOW + 58_000);
    assert_ne!(record["basis"], basis());

    // Still down: the postcondition is contradicted, never current.
    let harness = active_harness();
    harness.append(&canary(NOW - 20_000, "explicitly_absent"));
    harness.append(&canary(NOW - 2_000, "present"));
    assert_eq!(harness.resolve()["status"], "contradictory");
}

#[test]
fn active_claim_is_not_current_on_stale_absent_or_indeterminate_evidence() {
    let harness = active_harness();
    harness.append(&canary(NOW - 60_000, "explicitly_absent"));
    assert_eq!(harness.resolve()["status"], "stale");

    let harness = active_harness();
    harness.append(&other(NOW - 1_000));
    assert_eq!(harness.resolve()["status"], "absent");

    let harness = active_harness();
    harness.append(&canary(NOW - 1_000, "cannot_evaluate"));
    assert_eq!(harness.resolve()["status"], "unsupported");
}

#[test]
fn active_claim_prints_its_own_basis_and_unknown_claims_refuse() {
    let output = Command::new(env!("CARGO_BIN_EXE_constellation-nq-unit-resolver"))
        .args([
            "--print-basis",
            "--claim",
            "active",
            "--instance-id",
            INSTANCE,
            "--unit",
            UNIT,
            "--machine-id",
            MACHINE,
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let printed: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(printed["basis"], active_basis());

    let mut harness = Harness::new();
    harness.extra = vec!["--claim".into(), "recovered".into()];
    assert!(harness.refuse().contains("--claim must be"));
    assert!(harness.calls().is_empty());
}

/// The exported projection carries exactly the typed fields a consumer may
/// forward, and refuses anything outside the closed vocabulary.
#[test]
fn resolution_fields_export_the_typed_projection() {
    let harness = Harness::new();
    harness.append(&canary(NOW - 3_000, "present"));
    let record = harness.resolve();
    let fields = ResolutionFields::from_value(&record).unwrap();
    assert_eq!(
        fields,
        ResolutionFields {
            status: Status::Current,
            resolver_id: RESOLVER_ID.into(),
            basis_type: BASIS_TYPE.into(),
            currentness: witness(1, NOW - 3_000, "present"),
            fresh_until_unix_ms: NOW + 57_000,
        }
    );
    assert_eq!(
        serde_json::to_value(&fields).unwrap(),
        json!({
            "status": "current",
            "resolver_id": RESOLVER_ID,
            "basis_type": BASIS_TYPE,
            "currentness": witness(1, NOW - 3_000, "present"),
            "fresh_until_unix_ms": NOW + 57_000,
        })
    );
    for (pointer, value) in [
        ("/status", json!("fixed")),
        ("/status", json!(null)),
        (
            "/basis/basis_type",
            json!("constellation.remediation.other/v1"),
        ),
        ("/currentness", json!("not-a-digest")),
        ("/fresh_until_unix_ms", json!(-1)),
        ("/resolver_id", json!("")),
    ] {
        let mut bad = record.clone();
        *bad.pointer_mut(pointer).unwrap() = value.clone();
        assert!(
            ResolutionFields::from_value(&bad).is_err(),
            "{pointer} = {value}"
        );
    }
    for status in Status::ALL {
        assert_eq!(Status::parse(status.as_str()), Some(status));
    }
}
