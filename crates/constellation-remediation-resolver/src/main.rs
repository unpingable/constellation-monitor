//! `constellation-nq-unit-resolver`: one AG observation resolution per run.
//!
//! AG runs the genesis-pinned resolver with no arguments, so deployment pins a
//! wrapper whose argv fixes every input below. `--print-basis` prints the
//! catalog-constant typed basis for enrolment and reads nothing. `--claim
//! active` enrols the postcondition claim (unit active) instead of the
//! default precondition claim (unit not active).

use std::time::Duration;

use constellation_remediation_resolver::{
    Claim, MAX_AGE_MS_DEFAULT, PAGE_BYTES_DEFAULT, Request, Settings, TIMEOUT_SECONDS_DEFAULT,
    WINDOW_RECORDS_DEFAULT, jcs, judge, read_window, resolution,
};

const USAGE: &str = "usage: constellation-nq-unit-resolver --config NQ_CONFIG \
--instance-id ID --unit UNIT --machine-id HEX32 --resolver-id ID \
[--claim not-active|active] [--nq-program PATH] [--window-records N] [--max-age-ms MS] \
[--max-page-bytes N] [--timeout-seconds S] [--print-basis] < request.json";

fn main() {
    match run() {
        Ok(output) => {
            print!("{output}");
        }
        Err(error) => {
            eprintln!("constellation-nq-unit-resolver refused: {error}");
            std::process::exit(2);
        }
    }
}

fn run() -> Result<String, String> {
    let (settings, print_basis) = parse(std::env::args().skip(1))?;
    settings.validate()?;
    if print_basis {
        let basis = settings.basis();
        let document = serde_json::json!({
            "basis": basis,
            "normalized_preconditions": basis.binding_digest(),
        });
        return Ok(format!(
            "{}\n",
            String::from_utf8(jcs(&document)).unwrap_or_default()
        ));
    }
    let request = Request::read(std::io::stdin().lock())?;
    let window = read_window(&settings)?;
    let judgement = judge(&settings, &window, request.now_unix_ms);
    eprintln!(
        "constellation-nq-unit-resolver: {:?} {} (through_sequence {})",
        judgement.status, judgement.note, window.through_sequence
    );
    let record = resolution(&settings, &request, &judgement);
    String::from_utf8(jcs(&record)).map_err(|_| "resolution was not UTF-8".to_owned())
}

fn parse(arguments: impl Iterator<Item = String>) -> Result<(Settings, bool), String> {
    let mut claim = Claim::NotActive;
    let mut nq_program = "/usr/bin/nq".to_owned();
    let mut nq_config = None;
    let mut instance_id = None;
    let mut unit = None;
    let mut machine_id = None;
    let mut resolver_id = None;
    let mut window_records = WINDOW_RECORDS_DEFAULT;
    let mut max_age_ms = MAX_AGE_MS_DEFAULT;
    let mut page_bytes = PAGE_BYTES_DEFAULT;
    let mut timeout_seconds = TIMEOUT_SECONDS_DEFAULT;
    let mut print_basis = false;
    let mut arguments = arguments;
    while let Some(flag) = arguments.next() {
        if flag == "--print-basis" {
            print_basis = true;
            continue;
        }
        let value = arguments
            .next()
            .ok_or_else(|| format!("{flag} needs a value\n{USAGE}"))?;
        let number = |value: &str| {
            value
                .parse::<u64>()
                .map_err(|_| format!("{flag} must be an unsigned integer"))
        };
        match flag.as_str() {
            "--claim" => claim = Claim::parse(&value)?,
            "--nq-program" => nq_program = value,
            "--config" => nq_config = Some(value),
            "--instance-id" => instance_id = Some(value),
            "--unit" => unit = Some(value),
            "--machine-id" => machine_id = Some(value),
            "--resolver-id" => resolver_id = Some(value),
            "--window-records" => window_records = number(&value)?,
            "--max-age-ms" => max_age_ms = number(&value)?,
            "--max-page-bytes" => {
                page_bytes = usize::try_from(number(&value)?)
                    .map_err(|_| "--max-page-bytes is too large".to_owned())?;
            }
            "--timeout-seconds" => timeout_seconds = number(&value)?.clamp(1, 120),
            _ => return Err(format!("unknown flag {flag}\n{USAGE}")),
        }
    }
    let required = |value: Option<String>, flag: &str| {
        value.ok_or_else(|| format!("{flag} is required\n{USAGE}"))
    };
    // `--print-basis` needs only the basis inputs.
    let nq_config = if print_basis {
        nq_config.unwrap_or_else(|| "-".to_owned())
    } else {
        required(nq_config, "--config")?
    };
    let resolver_id = if print_basis {
        resolver_id.unwrap_or_else(|| "-".to_owned())
    } else {
        required(resolver_id, "--resolver-id")?
    };
    Ok((
        Settings {
            claim,
            nq_program,
            nq_config,
            instance_id: required(instance_id, "--instance-id")?,
            unit: required(unit, "--unit")?,
            machine_id: required(machine_id, "--machine-id")?,
            resolver_id,
            window_records,
            max_age_ms,
            page_bytes,
            timeout: Duration::from_secs(timeout_seconds),
        },
        print_basis,
    ))
}
