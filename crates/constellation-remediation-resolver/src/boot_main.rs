//! Separately named boot-bound consumer; existing unit resolver is unchanged.
use constellation_remediation_resolver::boot_unit::{
    BootSettings, PROFILE_DIGEST, RELIANCE_MS, read, resolution,
};
use constellation_remediation_resolver::{
    Claim, Judgement, PAGE_BYTES_DEFAULT, Request, Settings, Status, WINDOW_RECORDS_DEFAULT, jcs,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn main() {
    match run() {
        Ok(value) => println!("{}", String::from_utf8(jcs(&value)).unwrap_or_default()),
        Err(reason) => {
            eprintln!("constellation-nq-boot-unit-resolver refused: {reason}");
            std::process::exit(2);
        }
    }
}
fn run() -> Result<serde_json::Value, String> {
    let mut config = "-".to_owned();
    let mut instance = None;
    let mut unit = None;
    let mut machine = None;
    let mut resolver = "constellation-monitor-current-boot-systemd/v1".to_owned();
    let mut program = "/usr/bin/nq".to_owned();
    let mut claim = Claim::NotActive;
    let mut inspect = false;
    let mut print_basis = false;
    let mut descriptor = PROFILE_DIGEST.to_owned();
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        if flag == "--inspect" {
            inspect = true;
            continue;
        }
        if flag == "--print-basis" {
            print_basis = true;
            continue;
        }
        let value = args
            .next()
            .ok_or_else(|| format!("{flag} requires a value"))?;
        match flag.as_str() {
            "--config" => config = value,
            "--instance-id" => instance = Some(value),
            "--unit" => unit = Some(value),
            "--machine-id" => machine = Some(value),
            "--resolver-id" => resolver = value,
            "--nq-program" => program = value,
            "--claim" => claim = Claim::parse(&value)?,
            "--profile-digest" => descriptor = value,
            _ => return Err(format!("unknown flag {flag}")),
        }
    }
    let settings = BootSettings {
        base: Settings {
            claim,
            nq_program: program,
            nq_config: config,
            instance_id: instance.ok_or("--instance-id required")?,
            unit: unit.ok_or("--unit required")?,
            machine_id: machine.ok_or("--machine-id required")?,
            resolver_id: resolver,
            window_records: WINDOW_RECORDS_DEFAULT,
            max_age_ms: RELIANCE_MS,
            page_bytes: PAGE_BYTES_DEFAULT,
            timeout: Duration::from_secs(5),
        },
        profile_digest: descriptor,
    };
    settings.validate()?;
    if print_basis {
        let basis = settings.basis();
        return Ok(
            serde_json::json!({"normalized_preconditions":basis.binding_digest(),"basis":basis}),
        );
    }
    if settings.base.nq_config == "-" {
        return Err("--config required for owner read".into());
    }
    let request = if inspect {
        None
    } else {
        Some(Request::read(std::io::stdin().lock())?)
    };
    let now = match &request {
        Some(value) => value.now_unix_ms,
        None => u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "clock before epoch")?
                .as_millis(),
        )
        .map_err(|_| "clock out of range")?,
    };
    let record = read(&settings, now)?;
    if inspect {
        return Ok(record);
    }
    let status = record
        .pointer("/judgment/status")
        .and_then(serde_json::Value::as_str)
        .and_then(Status::parse)
        .ok_or("judgment status absent")?;
    let judgement = Judgement {
        status,
        witness: record["witness"].clone(),
        fresh_until_unix_ms: record
            .pointer("/judgment/fresh_until_unix_ms")
            .and_then(serde_json::Value::as_u64)
            .ok_or("freshness absent")?,
        note: record
            .pointer("/judgment/reason")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .into(),
    };
    serde_json::to_value(resolution(
        &settings,
        &request.ok_or("request absent")?,
        &judgement,
    ))
    .map_err(|e| e.to_string())
}
