//! AG typed-v3 observation resolver over NQ ops-store `nq.systemd_unit` v2
//! evaluations, for Bounded Autonomous Remediation v1.
//!
//! The same program also owns the postcondition claim (`--claim active`):
//! the newest evaluation is fresh and shows the unit active, i.e. the
//! not-active condition explicitly absent. That claim has its own basis type,
//! so a postcondition answer can never be mistaken for a precondition one.
//!
//! AG invokes the pinned resolver once per resolution with an
//! `ag.governed-loop.observation-request/v1` document on stdin and reads one
//! `ag.governed-loop.observation-resolution/v3` document from stdout. This
//! resolver owns one claim for one enrolled watcher instance: the newest
//! `nq.systemd_unit` v2 evaluation of that instance is at most `max_age_ms`
//! old at AG's resolution time and shows the unit not active. It reads only
//! `nq --config <cfg> --json evaluations export` pages, never NQ diagnostics
//! artifacts, never acts, and grants nothing: AG decides what `current`
//! permits.
//!
//! Any failure to read a complete, well-formed window (nq failure, timeout,
//! oversize output, malformed or moving page) is an error, not a status: the
//! process exits non-zero and AG refuses the boundary.

use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub const REQUEST_SCHEMA: &str = "ag.governed-loop.observation-request/v1";
pub const RESOLUTION_SCHEMA: &str = "ag.governed-loop.observation-resolution/v3";
pub const TYPED_BASIS_SCHEMA: &str = "ag.governed-loop.typed-observation-basis/v1";
/// Application-owned basis type: "the enrolled unit is not active".
pub const BASIS_TYPE: &str = "constellation.remediation.systemd-not-active/v1";
/// Application-owned postcondition basis type: "the enrolled unit is active".
pub const ACTIVE_BASIS_TYPE: &str = "constellation.remediation.systemd-active/v1";
/// Domain of the currentness witness digest.
pub const CURRENTNESS_DOMAIN: &str = "constellation.remediation.nq-unit-currentness/v1";
pub const EVALUATION_HISTORY_SCHEMA: &str = "nq.evaluation_history.v1";
pub const SYSTEMD_UNIT_PROFILE: &str = "nq.systemd_unit";
pub const SYSTEMD_UNIT_VERSION: u64 = 2;
pub const SYSTEMD_UNIT_CONDITION: &str = "systemd_unit_not_active";
/// NQ's largest public page (`MAX_PUBLIC_QUERY_ROWS`).
pub const HISTORY_PAGE_MAX: u64 = 1000;
pub const WINDOW_RECORDS_DEFAULT: u64 = 300;
pub const WINDOW_RECORDS_MAX: u64 = 10_000;
pub const MAX_AGE_MS_DEFAULT: u64 = 60_000;
/// Largest stale bound accepted: AG's freshness is meant to be short.
pub const MAX_AGE_MS_MAX: u64 = 600_000;
pub const PAGE_BYTES_DEFAULT: usize = 16 * 1024 * 1024;
pub const TIMEOUT_SECONDS_DEFAULT: u64 = 10;
/// An evaluation stamped more than this after AG's clock reading is not
/// evidence of anything current: the clocks disagree.
pub const FUTURE_SKEW_MS: u64 = 2_000;
const REQUEST_BYTES_MAX: u64 = 64 * 1024;

/// Which claim this enrolment of the resolver owns.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Claim {
    /// Precondition: the newest fresh evaluation shows the unit not active.
    #[default]
    NotActive,
    /// Postcondition: the newest fresh evaluation shows the unit active.
    Active,
}

impl Claim {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "not-active" => Ok(Self::NotActive),
            "active" => Ok(Self::Active),
            other => Err(format!(
                "--claim must be not-active or active, not {other:?}"
            )),
        }
    }

    #[must_use]
    pub const fn basis_type(self) -> &'static str {
        match self {
            Self::NotActive => BASIS_TYPE,
            Self::Active => ACTIVE_BASIS_TYPE,
        }
    }
}

/// Bounded deployment inputs, fixed by the pinned wrapper's argv.
#[derive(Clone, Debug)]
pub struct Settings {
    pub claim: Claim,
    pub nq_program: String,
    pub nq_config: String,
    pub instance_id: String,
    pub unit: String,
    pub machine_id: String,
    pub resolver_id: String,
    pub window_records: u64,
    pub max_age_ms: u64,
    pub page_bytes: usize,
    pub timeout: Duration,
}

impl Settings {
    pub fn validate(&self) -> Result<(), String> {
        bounded_text("--nq-program", &self.nq_program, 4096)?;
        bounded_text("--config", &self.nq_config, 4096)?;
        bounded_text("--instance-id", &self.instance_id, 128)?;
        bounded_text("--unit", &self.unit, 256)?;
        if self.unit.contains('/') {
            return Err("--unit must be a unit name, not a path".into());
        }
        if self.machine_id.len() != 32
            || !self
                .machine_id
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err("--machine-id must be 32 lowercase hex digits".into());
        }
        bounded_text("--resolver-id", &self.resolver_id, 256)?;
        if !(1..=WINDOW_RECORDS_MAX).contains(&self.window_records) {
            return Err(format!("--window-records must be 1..={WINDOW_RECORDS_MAX}"));
        }
        if !(1..=MAX_AGE_MS_MAX).contains(&self.max_age_ms) {
            return Err(format!("--max-age-ms must be 1..={MAX_AGE_MS_MAX}"));
        }
        if self.page_bytes < 1024 {
            return Err("--max-page-bytes must be at least 1024".into());
        }
        Ok(())
    }

    /// The catalog-constant typed basis for this enrolment.
    pub fn basis(&self) -> Basis {
        let identity = json!({
            "instance_id": self.instance_id,
            "machine_id": self.machine_id,
            "unit": self.unit,
        });
        let basis_type = self.claim.basis_type();
        Basis {
            schema: TYPED_BASIS_SCHEMA.into(),
            basis_type: basis_type.into(),
            basis_identity: hash_domain(basis_type, &jcs(&identity)),
        }
    }
}

fn bounded_text(name: &str, value: &str, maximum: usize) -> Result<(), String> {
    if value.is_empty() || value.len() > maximum || value.bytes().any(|b| b.is_ascii_control()) {
        return Err(format!(
            "{name} must be 1..={maximum} bytes without control characters"
        ));
    }
    Ok(())
}

/// AG's `ag.governed-loop.typed-observation-basis/v1` envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Basis {
    pub schema: String,
    pub basis_type: String,
    pub basis_identity: String,
}

impl Basis {
    /// AG's `normalized_preconditions`: its domain-separated digest of the
    /// JCS envelope, under the envelope schema as domain.
    pub fn binding_digest(&self) -> String {
        hash_domain(TYPED_BASIS_SCHEMA, &jcs(self))
    }
}

/// AG's `OccurrenceKeyV1`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OccurrenceKey {
    pub campaign: String,
    pub occurrence: String,
}

/// AG's process observation request (`ObservationCommandRequestV1`).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: String,
    pub key: OccurrenceKey,
    pub observation: String,
    pub subject: String,
    pub now_unix_ms: u64,
}

impl Request {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let request: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("request is not an observation request: {error}"))?;
        if request.schema != REQUEST_SCHEMA {
            return Err(format!("request schema is not {REQUEST_SCHEMA}"));
        }
        for (name, digest) in [
            ("key.campaign", &request.key.campaign),
            ("observation", &request.observation),
            ("subject", &request.subject),
        ] {
            if !is_digest(digest) {
                return Err(format!("request {name} is not a sha256: digest"));
            }
        }
        if !is_uuid(&request.key.occurrence) {
            return Err("request key.occurrence is not a hyphenated lowercase UUID".into());
        }
        if request.now_unix_ms == 0 {
            return Err("request now_unix_ms is zero".into());
        }
        Ok(request)
    }

    /// Read one bounded request from stdin.
    pub fn read(mut input: impl Read) -> Result<Self, String> {
        let mut bytes = Vec::new();
        (&mut input)
            .take(REQUEST_BYTES_MAX + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("cannot read request: {error}"))?;
        if bytes.len() as u64 > REQUEST_BYTES_MAX {
            return Err(format!("request exceeds {REQUEST_BYTES_MAX} bytes"));
        }
        Self::parse(&bytes)
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                matches!(byte, b'0'..=b'9' | b'a'..=b'f')
            }
        })
}

/// AG's closed typed status vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Current,
    Stale,
    Contradictory,
    Absent,
    /// The newest evaluation cannot support the claim (indeterminate detector
    /// state, another profile or condition, or stamped in AG's future).
    Unsupported,
    /// The instance no longer observes the enrolled unit and machine.
    Refused,
}

impl Status {
    pub const ALL: [Self; 6] = [
        Self::Current,
        Self::Stale,
        Self::Contradictory,
        Self::Absent,
        Self::Unsupported,
        Self::Refused,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Stale => "stale",
            Self::Contradictory => "contradictory",
            Self::Absent => "absent",
            Self::Unsupported => "unsupported",
            Self::Refused => "refused",
        }
    }

    /// The closed vocabulary; anything else is not a status.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|status| status.as_str() == value)
    }
}

/// The typed fields of one v3 resolution that a consumer may carry forward
/// (for example into a model decider's evidence projection): status, the
/// resolver's identity, the basis type, the currentness witness digest and
/// the freshness bound. Nothing else of the record is exported.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResolutionFields {
    pub status: Status,
    pub resolver_id: String,
    pub basis_type: String,
    pub currentness: String,
    pub fresh_until_unix_ms: u64,
}

impl ResolutionFields {
    /// Validate and extract the fields from a resolution document a resolver
    /// printed. Unknown statuses, basis types other than this resolver's
    /// two, non-digest witnesses and missing fields are errors.
    pub fn from_value(value: &Value) -> Result<Self, String> {
        let text = |pointer: &str| value.pointer(pointer).and_then(Value::as_str);
        let status = text("/status")
            .and_then(Status::parse)
            .ok_or("resolution status is not in AG's closed vocabulary")?;
        let resolver_id = text("/resolver_id").ok_or("resolution has no resolver_id")?;
        bounded_text("resolver_id", resolver_id, 256)?;
        let basis_type = text("/basis/basis_type").ok_or("resolution has no basis type")?;
        if basis_type != BASIS_TYPE && basis_type != ACTIVE_BASIS_TYPE {
            return Err(format!(
                "resolution basis type {basis_type:?} is not this resolver's"
            ));
        }
        let currentness = text("/currentness").ok_or("resolution has no currentness")?;
        if !is_digest(currentness) {
            return Err("resolution currentness is not a sha256: digest".into());
        }
        let fresh_until_unix_ms = value
            .get("fresh_until_unix_ms")
            .and_then(Value::as_u64)
            .ok_or("resolution has no fresh_until_unix_ms")?;
        Ok(Self {
            status,
            resolver_id: resolver_id.to_owned(),
            basis_type: basis_type.to_owned(),
            currentness: currentness.to_owned(),
            fresh_until_unix_ms,
        })
    }
}

impl From<&Resolution> for ResolutionFields {
    fn from(resolution: &Resolution) -> Self {
        Self {
            status: resolution.status,
            resolver_id: resolution.resolver_id.clone(),
            basis_type: resolution.basis.basis_type.clone(),
            currentness: resolution.currentness.clone(),
            fresh_until_unix_ms: resolution.fresh_until_unix_ms,
        }
    }
}

/// AG's `ag.governed-loop.observation-resolution/v3`, field for field.
#[derive(Clone, Debug, Serialize)]
pub struct Resolution {
    pub schema: &'static str,
    pub key: OccurrenceKey,
    pub observation: String,
    pub currentness: String,
    pub normalized_preconditions: String,
    pub basis: Basis,
    pub resolver_id: String,
    pub subject: String,
    pub status: Status,
    pub resolved_at_unix_ms: u64,
    pub fresh_until_unix_ms: u64,
}

/// The newest evaluation of the enrolled instance in the window.
#[derive(Clone, Debug)]
pub struct Newest {
    pub sequence: u64,
    pub envelope: Value,
}

/// One frozen window of evaluation history.
#[derive(Clone, Debug)]
pub struct Window {
    pub through_sequence: u64,
    pub newest: Option<Newest>,
}

/// What the resolver judged, with the witness preimage.
#[derive(Clone, Debug)]
pub struct Judgement {
    pub status: Status,
    pub witness: Value,
    pub fresh_until_unix_ms: u64,
    pub note: String,
}

/// Judge the window against AG's clock reading `now_ms`.
pub fn judge(settings: &Settings, window: &Window, now_ms: u64) -> Judgement {
    let Some(newest) = &window.newest else {
        return Judgement {
            status: Status::Absent,
            witness: json!({
                "evaluated_at": null,
                "outcome": "absent",
                "sequence": window.through_sequence,
            }),
            fresh_until_unix_ms: now_ms.saturating_add(1),
            note: format!(
                "no evaluation of {} through sequence {}",
                settings.instance_id, window.through_sequence
            ),
        };
    };
    let envelope = &newest.envelope;
    let text = |pointer: &str| envelope.pointer(pointer).and_then(Value::as_str);
    let evaluated_text = text("/evaluated_at").unwrap_or_default().to_owned();
    let state = text("/result/state").unwrap_or_default().to_owned();
    let witness = json!({
        "evaluated_at": evaluated_text,
        "outcome": state,
        "sequence": newest.sequence,
    });
    let unusable = |status: Status, note: String| Judgement {
        status,
        witness: witness.clone(),
        fresh_until_unix_ms: now_ms.saturating_add(1),
        note,
    };
    let profile = text("/profile/profile/id");
    let version = envelope
        .pointer("/profile/profile/version")
        .and_then(Value::as_u64);
    let condition = text("/result/condition");
    if profile != Some(SYSTEMD_UNIT_PROFILE)
        || version != Some(SYSTEMD_UNIT_VERSION)
        || condition != Some(SYSTEMD_UNIT_CONDITION)
    {
        return unusable(
            Status::Unsupported,
            format!(
                "sequence {} is profile {profile:?} version {version:?} condition {condition:?}",
                newest.sequence
            ),
        );
    }
    let expected_subject = format!("systemd-unit:{}/{}", settings.machine_id, settings.unit);
    if text("/context/scope/value/unit_name") != Some(settings.unit.as_str())
        || text("/context/scope/value/machine_id") != Some(settings.machine_id.as_str())
        || text("/context/subject") != Some(expected_subject.as_str())
    {
        return unusable(
            Status::Refused,
            format!(
                "sequence {} observes {:?}, not {expected_subject:?}",
                newest.sequence,
                text("/context/subject")
            ),
        );
    }
    let Some(evaluated_ms) = OffsetDateTime::parse(&evaluated_text, &Rfc3339)
        .ok()
        .and_then(|at| u64::try_from(at.unix_timestamp_nanos() / 1_000_000).ok())
    else {
        return unusable(
            Status::Unsupported,
            format!("sequence {} has no valid evaluated_at", newest.sequence),
        );
    };
    if evaluated_ms > now_ms.saturating_add(FUTURE_SKEW_MS) {
        return unusable(
            Status::Unsupported,
            format!(
                "sequence {} evaluated {} ms after the resolution time",
                newest.sequence,
                evaluated_ms - now_ms
            ),
        );
    }
    let fresh_until = evaluated_ms.saturating_add(settings.max_age_ms);
    let judged = |status: Status, note: String| Judgement {
        status,
        witness: witness.clone(),
        fresh_until_unix_ms: fresh_until,
        note,
    };
    if now_ms >= fresh_until {
        return judged(
            Status::Stale,
            format!(
                "sequence {} evaluated {} ms before the resolution time",
                newest.sequence,
                now_ms - evaluated_ms
            ),
        );
    }
    let (when_not_active, when_active) = match settings.claim {
        Claim::NotActive => (Status::Current, Status::Contradictory),
        Claim::Active => (Status::Contradictory, Status::Current),
    };
    match state.as_str() {
        "present" => judged(
            when_not_active,
            format!("sequence {}: unit not active", newest.sequence),
        ),
        "explicitly_absent" => judged(
            when_active,
            format!("sequence {}: unit active", newest.sequence),
        ),
        other => unusable(
            Status::Unsupported,
            format!("sequence {}: detector state {other:?}", newest.sequence),
        ),
    }
}

/// Build AG's v3 record.
pub fn resolution(settings: &Settings, request: &Request, judgement: &Judgement) -> Resolution {
    let basis = settings.basis();
    Resolution {
        schema: RESOLUTION_SCHEMA,
        key: request.key.clone(),
        observation: request.observation.clone(),
        currentness: hash_domain(CURRENTNESS_DOMAIN, &jcs(&judgement.witness)),
        normalized_preconditions: basis.binding_digest(),
        basis,
        resolver_id: settings.resolver_id.clone(),
        subject: request.subject.clone(),
        status: judgement.status,
        resolved_at_unix_ms: request.now_unix_ms,
        fresh_until_unix_ms: judgement.fresh_until_unix_ms,
    }
}

/// Read the newest `window_records` evaluations, frozen at the store-wide
/// sequence the first call reports, and keep the newest of the instance.
pub fn read_window(settings: &Settings) -> Result<Window, String> {
    let probe = page(settings, 1, None)?;
    let through = probe
        .get("through_sequence")
        .and_then(Value::as_u64)
        .ok_or("evaluations export has no through_sequence")?;
    let mut after = through.saturating_sub(settings.window_records);
    let mut newest: Option<Newest> = None;
    let mut last_sequence = after;
    let mut complete = after >= through;
    for _ in 0..settings.window_records.div_ceil(HISTORY_PAGE_MAX) + 1 {
        if complete {
            break;
        }
        let limit = (through - after).min(HISTORY_PAGE_MAX);
        let page = page(settings, limit, Some((after, through)))?;
        if page.get("through_sequence").and_then(Value::as_u64) != Some(through) {
            return Err(format!(
                "evaluation history moved from through_sequence {through} to {}",
                page.get("through_sequence").unwrap_or(&Value::Null)
            ));
        }
        let records = page
            .get("records")
            .and_then(Value::as_array)
            .ok_or("evaluations export has no records")?;
        if records.len() as u64 > limit {
            return Err(format!(
                "evaluations export returned {} records for limit {limit}",
                records.len()
            ));
        }
        for record in records {
            let sequence = record
                .get("sequence")
                .and_then(Value::as_u64)
                .ok_or("evaluation record has no sequence")?;
            if sequence <= last_sequence || sequence > through {
                return Err(format!(
                    "evaluation record sequence {sequence} is outside ({last_sequence}, {through}]"
                ));
            }
            last_sequence = sequence;
            let envelope = record
                .get("result")
                .filter(|value| value.is_object())
                .ok_or_else(|| format!("evaluation record {sequence} has no envelope"))?;
            let instance = envelope
                .pointer("/context/instance_id")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("evaluation record {sequence} has no instance id"))?;
            if instance == settings.instance_id {
                newest = Some(Newest {
                    sequence,
                    envelope: envelope.clone(),
                });
            }
        }
        complete = page.get("complete").and_then(Value::as_bool) == Some(true);
        match page.get("next_after_sequence").and_then(Value::as_u64) {
            Some(next) if !complete && next > after => after = next,
            _ => break,
        }
    }
    if !complete {
        return Err(format!(
            "evaluation history page through {through} is not complete"
        ));
    }
    Ok(Window {
        through_sequence: through,
        newest,
    })
}

/// One `nq --config <cfg> --json evaluations export` page.
fn page(settings: &Settings, limit: u64, window: Option<(u64, u64)>) -> Result<Value, String> {
    let mut argv = vec![
        "--config".to_owned(),
        settings.nq_config.clone(),
        "--json".to_owned(),
        "evaluations".to_owned(),
        "export".to_owned(),
        "--limit".to_owned(),
        limit.to_string(),
    ];
    if let Some((after, through)) = window {
        argv.extend([
            "--after".to_owned(),
            after.to_string(),
            "--through".to_owned(),
            through.to_string(),
        ]);
    }
    let stdout = run_bounded(
        &settings.nq_program,
        &argv,
        settings.timeout,
        settings.page_bytes,
    )?;
    let page: Value = serde_json::from_slice(&stdout)
        .map_err(|error| format!("evaluations export is not JSON: {error}"))?;
    if page.get("schema").and_then(Value::as_str) != Some(EVALUATION_HISTORY_SCHEMA) {
        return Err(format!(
            "evaluations export schema is not {EVALUATION_HISTORY_SCHEMA}"
        ));
    }
    Ok(page)
}

/// Run `program argv` without a shell, a cleared environment, a deadline and
/// bounded stdout; any non-zero exit, timeout or overflow is an error.
fn run_bounded(
    program: &str,
    argv: &[String],
    timeout: Duration,
    limit: usize,
) -> Result<Vec<u8>, String> {
    let mut child = Command::new(program)
        .args(argv)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cannot start {program}: {error}"))?;
    let stdout = child.stdout.take().ok_or("no stdout pipe")?;
    let stderr = child.stderr.take().ok_or("no stderr pipe")?;
    let out_reader = thread::spawn(move || collect(stdout, limit));
    let err_reader = thread::spawn(move || collect(stderr, 4096));
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(error) => return Err(format!("cannot wait for {program}: {error}")),
        }
    };
    let (stdout, overflow) = out_reader.join().unwrap_or_default();
    let (stderr, _) = err_reader.join().unwrap_or_default();
    let Some(status) = status else {
        return Err(format!("{program} timed out after {} s", timeout.as_secs()));
    };
    if overflow {
        return Err(format!("{program} printed more than {limit} bytes"));
    }
    if !status.success() {
        return Err(format!(
            "{program} exited with {:?}: {}",
            status.code(),
            excerpt(&stderr)
        ));
    }
    Ok(stdout)
}

fn collect(mut reader: impl Read, limit: usize) -> (Vec<u8>, bool) {
    let mut kept = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut overflow = false;
    loop {
        match reader.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(count) => {
                let room = limit.saturating_sub(kept.len());
                if count > room {
                    overflow = true;
                }
                kept.extend_from_slice(&buffer[..count.min(room)]);
            }
        }
    }
    (kept, overflow)
}

fn excerpt(bytes: &[u8]) -> String {
    let text: String = String::from_utf8_lossy(bytes)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(240)
        .collect();
    text.trim().to_owned()
}

/// RFC 8785 canonical JSON bytes.
pub fn jcs<T: Serialize + ?Sized>(value: &T) -> Vec<u8> {
    serde_jcs::to_vec(value).expect("resolver values are strings, integers and objects")
}

/// AG's `Digest::hash_domain`: SHA-256 over
/// `"ag-ng\0digest\0v1\0" || u128be(len domain) || domain || u128be(len payload) || payload`.
pub fn hash_domain(domain: &str, payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ag-ng\0digest\0v1\0");
    hasher.update((domain.len() as u128).to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher.update((payload.len() as u128).to_be_bytes());
    hasher.update(payload);
    let raw = hasher.finalize();
    let mut text = String::with_capacity(71);
    text.push_str("sha256:");
    for byte in raw {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

/// Separately named systemd v3 acquired-boot consumer; existing v2 unchanged.
pub mod boot_unit;
