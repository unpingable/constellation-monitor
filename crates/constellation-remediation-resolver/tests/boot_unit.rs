use constellation_remediation_resolver::boot_unit::{
    BootSettings, PROFILE_DIGEST, RELIANCE_MS, judge, valid_boot_id,
};
use constellation_remediation_resolver::{Claim, Newest, Settings, Status, Window};
use serde_json::{Value, json};
use std::time::Duration;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const VECTORS: &str = include_str!(
    "../../../operational-contract/fixtures/systemd-unit-v3/observation-export-vectors.v1.json"
);
fn ms(value: &str) -> u64 {
    u64::try_from(
        OffsetDateTime::parse(value, &Rfc3339)
            .unwrap()
            .unix_timestamp_nanos()
            / 1_000_000,
    )
    .unwrap()
}
fn stamp(value: u64) -> String {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(value) * 1_000_000)
        .unwrap()
        .format(&Rfc3339)
        .unwrap()
}
fn settings() -> BootSettings {
    BootSettings {
        base: Settings {
            claim: Claim::NotActive,
            nq_program: "/usr/bin/nq".into(),
            nq_config: "/etc/nq/ops.toml".into(),
            instance_id: "systemd-v3-golden".into(),
            machine_id: "1a5b08928e884e73bf4f60a3c73ef497".into(),
            unit: "constellation-beta-http-fixture.service".into(),
            resolver_id: "monitor.boot-unit/v1".into(),
            window_records: 300,
            max_age_ms: RELIANCE_MS,
            page_bytes: 1024 * 1024,
            timeout: Duration::from_secs(5),
        },
        profile_digest: PROFILE_DIGEST.into(),
    }
}
fn window(reference: &Value, evaluated: &str) -> Window {
    let cfg = settings();
    Window {
        through_sequence: 9,
        newest: Some(Newest {
            sequence: 9,
            envelope: json!({
    "schema":"nq.evaluation_envelope.v2","profile":{"profile":{"id":"nq.systemd_unit","version":3},"profile_digest":PROFILE_DIGEST},
    "evaluated_at":evaluated,"context":{"instance_id":cfg.base.instance_id,"subject":format!("systemd-unit:{}/{}",cfg.base.machine_id,cfg.base.unit),
      "scope":{"kind":"systemd_unit","value":{"schema":"nq.systemd_unit_scope.v3","machine_id":cfg.base.machine_id,"unit_name":cfg.base.unit}},"vantage":{"kind":"local","value":{}}},
    "result":{"condition":"systemd_unit_not_active","state":"present","evidence":[reference]}}),
        }),
    }
}
fn first() -> Value {
    serde_json::from_str::<Value>(VECTORS).unwrap()["cases"][0].clone()
}
fn apply(case: &Value, now: u64) -> constellation_remediation_resolver::Judgement {
    judge(
        &settings(),
        &window(
            &case["reference"],
            case["response"]["observation"]["observed_at"]
                .as_str()
                .unwrap_or("2026-10-04T12:00:00Z"),
        ),
        Some(&case["response"]),
        case["consumer"]["current_boot_id"].as_str().unwrap(),
        case["consumer"]["current_boot_id"].as_str().unwrap(),
        now,
    )
}
#[test]
fn shared_nq_consumer_vectors() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(vectors["profile_digest"], PROFILE_DIGEST);
    for case in vectors["cases"].as_array().unwrap() {
        let judgment = apply(
            case,
            ms(case["consumer"]["resolution_at"].as_str().unwrap()),
        );
        assert_eq!(
            judgment.status.as_str(),
            case["expected_reliance"].as_str().unwrap(),
            "{}: {}",
            case["name"],
            judgment.note
        );
    }
}
#[test]
fn fresh_reevaluation_does_not_refresh_source_age_and_boundary_is_exclusive() {
    let case = first();
    let start = ms("2026-10-04T12:00:00Z");
    let boot = case["consumer"]["current_boot_id"].as_str().unwrap();
    let refreshed = window(&case["reference"], &stamp(start + 59000));
    assert_eq!(
        judge(
            &settings(),
            &refreshed,
            Some(&case["response"]),
            boot,
            boot,
            start + 59999
        )
        .status,
        Status::Current
    );
    let expired = judge(
        &settings(),
        &refreshed,
        Some(&case["response"]),
        boot,
        boot,
        start + 60000,
    );
    assert_eq!(expired.status, Status::Stale);
    assert_eq!(expired.fresh_until_unix_ms, start + 60000);
    assert_eq!(
        judge(
            &settings(),
            &refreshed,
            Some(&case["response"]),
            boot,
            boot,
            start + 120000
        )
        .status,
        Status::Stale
    );
}
#[test]
fn boot_transition_malformed_current_boot_and_missing_export_refuse() {
    let case = first();
    let now = ms("2026-10-04T12:00:01Z");
    let boot = case["consumer"]["current_boot_id"].as_str().unwrap();
    let history = window(&case["reference"], "2026-10-04T12:00:00Z");
    let new_boot = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    assert_eq!(
        judge(
            &settings(),
            &history,
            Some(&case["response"]),
            boot,
            new_boot,
            now
        )
        .status,
        Status::Refused
    );
    assert_eq!(
        judge(
            &settings(),
            &history,
            Some(&case["response"]),
            new_boot,
            new_boot,
            now
        )
        .status,
        Status::Stale
    );
    assert_eq!(
        judge(
            &settings(),
            &history,
            Some(&case["response"]),
            "invented",
            "invented",
            now
        )
        .status,
        Status::Refused
    );
    assert_eq!(
        judge(&settings(), &history, None, boot, boot, now).status,
        Status::Refused
    );
    assert!(!valid_boot_id("00000000-0000-0000-0000-000000000000"));
    assert!(!valid_boot_id(&boot.to_uppercase()));
}
#[test]
fn exact_source_binding_evidence_and_native_state_are_required() {
    let case = first();
    let now = ms("2026-10-04T12:00:01Z");
    let boot = case["consumer"]["current_boot_id"].as_str().unwrap();
    for pointer in [
        "/observation/payload/machine_id",
        "/observation/payload/unit_name",
        "/binding/scope/value/schema",
        "/observation/kind",
        "/standing",
    ] {
        let mut response = case["response"].clone();
        *response.pointer_mut(pointer).unwrap() = json!("different");
        assert_eq!(
            judge(
                &settings(),
                &window(
                    &case["reference"],
                    case["response"]["observation"]["observed_at"]
                        .as_str()
                        .unwrap_or("2026-10-04T12:00:00Z")
                ),
                Some(&response),
                boot,
                boot,
                now
            )
            .status,
            Status::Refused,
            "{pointer}"
        );
    }
    let mut response = case["response"].clone();
    response["observation"]["payload"]["active_state"] = json!("active");
    assert_eq!(
        judge(
            &settings(),
            &window(
                &case["reference"],
                case["response"]["observation"]["observed_at"]
                    .as_str()
                    .unwrap_or("2026-10-04T12:00:00Z")
            ),
            Some(&response),
            boot,
            boot,
            now
        )
        .status,
        Status::Refused
    );
}
#[test]
fn indeterminate_or_absent_never_claim_current() {
    let case = first();
    let now = ms("2026-10-04T12:00:01Z");
    let boot = case["consumer"]["current_boot_id"].as_str().unwrap();
    let mut history = window(&case["reference"], "2026-10-04T12:00:00Z");
    history.newest.as_mut().unwrap().envelope["result"]["state"] = json!("cannot_evaluate");
    assert_eq!(
        judge(&settings(), &history, None, boot, boot, now).status,
        Status::Unsupported
    );
    history.newest = None;
    assert_eq!(
        judge(&settings(), &history, None, boot, boot, now).status,
        Status::Absent
    );
}
#[test]
fn precondition_and_postcondition_have_separate_stable_logical_bases() {
    let cfg = settings();
    let mut active = cfg.clone();
    active.base.claim = Claim::Active;
    assert_ne!(cfg.basis().basis_type, active.basis().basis_type);
    assert_ne!(
        cfg.basis().binding_digest(),
        active.basis().binding_digest()
    );
    assert_eq!(cfg.basis(), cfg.clone().basis());
    let raw = serde_json::to_string(&cfg.basis()).unwrap();
    assert!(!raw.contains("boot_id"));
    let case = first();
    let now = ms("2026-10-04T12:00:01Z");
    let boot = case["consumer"]["current_boot_id"].as_str().unwrap();
    assert_eq!(
        judge(
            &active,
            &window(
                &case["reference"],
                case["response"]["observation"]["observed_at"]
                    .as_str()
                    .unwrap_or("2026-10-04T12:00:00Z")
            ),
            Some(&case["response"]),
            boot,
            boot,
            now
        )
        .status,
        Status::Contradictory
    );
}

#[test]
fn print_basis_is_a_no_acquisition_native_read_and_pins_new_claim_type() {
    let output =
        std::process::Command::new(env!("CARGO_BIN_EXE_constellation-nq-boot-unit-resolver"))
            .args([
                "--print-basis",
                "--machine-id",
                &settings().base.machine_id,
                "--unit",
                &settings().base.unit,
                "--instance-id",
                &settings().base.instance_id,
                "--nq-program",
                "/definitely/unavailable/nq",
            ])
            .output()
            .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value["basis"]["basis_type"],
        constellation_remediation_resolver::boot_unit::NOT_ACTIVE_BASIS
    );
    assert_eq!(
        value["normalized_preconditions"],
        settings().basis().binding_digest()
    );
}
