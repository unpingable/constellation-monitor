//! One TOML file of deployment inputs. Every path is owner-installed; the
//! consumer reads them and never writes outside its state directory and the
//! AG campaign database directory.

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Work schema of AG's systemd executor (`ag-effectd`).
pub const DEFAULT_WORK_SCHEMA: &str = "ag-effectd.docket-executor-systemd-work/v2";
/// Prestates a v1 Start plan may be enrolled for.
pub const ENROLLABLE_PRESTATES: [&str; 2] = ["inactive", "failed"];

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub enrollment: Enrollment,
    pub consumer: Consumer,
    pub ag: Ag,
    pub docket: Docket,
    pub nq: Nq,
    #[serde(default)]
    pub evaluator: Evaluator,
    /// The model decider (`--decider model`); absent, only the
    /// deterministic decider can run.
    #[serde(default)]
    pub model: Option<Model>,
}

/// OpenRouter endpoint the model decider posts to.
pub const OPENROUTER_ENDPOINT: &str = "https://openrouter.ai/api/v1/chat/completions";
/// Least remediation window left to open a model-decided episode: 35 s
/// reasoning, dispatch and collection, the 15 s dwell and the evaluator's
/// 120 s continuous clear.
pub const MODEL_WINDOW_MIN_SECONDS: i64 = 210;
/// Reasoning wall ceiling: every call, parse and settlement of an episode.
pub const MODEL_WALL_MAX_MS: u64 = 35_000;
pub const MODEL_TOTAL_TIMEOUT_MAX_MS: u64 = 15_000;
pub const MODEL_CONNECT_TIMEOUT_MAX_MS: u64 = 3_000;
pub const MODEL_RETRY_BACKOFF_MAX_MS: u64 = 2_000;

/// The model decider: Linear Accountant for every call, the provider adapter
/// for the call itself. Model, provider, request shape and per-episode
/// ceilings are constants of the decider, not configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Model {
    /// The `la_inference` program.
    pub la_program: PathBuf,
    /// Fixed arguments placed before each subcommand (e.g. the store path).
    #[serde(default)]
    pub la_arguments: Vec<String>,
    /// The owner-installed LA enrollment (`admission_id`) this consumer
    /// reserves under.
    pub la_admission_id: String,
    /// Opaque eligibility reference carried on every reservation (the
    /// owner's grant of this remediation envelope); LA never interprets it.
    pub la_eligibility_ref: String,
    /// `https://openrouter.ai/api/v1/chat/completions`; a loopback
    /// `http://127.0.0.1:PORT/...` requires a qualification-loopback build.
    #[serde(default = "default_endpoint")]
    pub endpoint: String,
    /// Root-owned 0600 env file holding `OPENROUTER_API_KEY=...`; read only
    /// by the provider adapter, never logged.
    pub key_file: PathBuf,
    #[serde(default = "default_model_window")]
    pub window_min_seconds: i64,
    #[serde(default = "default_wall")]
    pub wall_ms: u64,
    #[serde(default = "default_total_timeout")]
    pub total_timeout_ms: u64,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_backoff")]
    pub retry_backoff_ms: u64,
}

/// The one unit this consumer may ever ask about.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enrollment {
    /// The evaluator's `site`, part of the condition id.
    pub site: String,
    /// The enrolled unit, the condition's target class.
    pub unit: String,
    /// The NQ ops-store watcher instance observing the unit.
    pub instance_id: String,
    /// `/etc/machine-id` of the host.
    pub machine_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Consumer {
    /// Private (0700) state directory: lock, state, journal, episode inputs.
    pub state_dir: PathBuf,
    /// The evaluator's `report.json`.
    pub report: PathBuf,
    /// Least remediation window that must remain to open an episode.
    #[serde(default = "default_margin")]
    pub window_margin_seconds: i64,
    /// Oldest acceptable report.
    #[serde(default = "default_report_age")]
    pub report_max_age_seconds: i64,
    /// Polls of a dispatched attempt per pass.
    #[serde(default = "default_poll_attempts")]
    pub poll_attempts: u32,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_ms: u64,
    /// Postcondition resolutions per pass before waiting for the next pass.
    #[serde(default = "default_post_attempts")]
    pub postcondition_attempts: u32,
    #[serde(default = "default_post_interval")]
    pub postcondition_interval_ms: u64,
    /// The unit must still be active in an NQ evaluation taken at least this
    /// long after Docket's settlement before a completion is claimed.
    #[serde(default = "default_post_dwell")]
    pub postcondition_dwell_seconds: u64,
    /// Deadline of each external command.
    #[serde(default = "default_timeout")]
    pub command_timeout_seconds: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ag {
    pub loopctl: PathBuf,
    /// The campaign database the executor deployment pins; one campaign per
    /// episode is initialised here after the previous one is archived.
    pub database: PathBuf,
    pub runtime_profile: PathBuf,
    pub catalog: PathBuf,
    /// Precondition (unit not active) resolver wrapper pinned in the profile.
    pub observation_resolver: PathBuf,
    pub observation_resolver_id: String,
    pub standing_resolver: PathBuf,
    pub standing_resolver_id: String,
    pub max_standing_ttl_ms: u64,
    /// Postcondition (unit active) resolver wrapper.
    pub postcondition_resolver: PathBuf,
    pub postcondition_resolver_id: String,
    #[serde(default = "default_work_schema")]
    pub work_schema: String,
    /// Owner-built Start plans, one per enrolled prestate.
    pub plans: Vec<Plan>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub prestate: String,
    pub path: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Docket {
    pub program: PathBuf,
    pub state_dir: PathBuf,
    pub trust: PathBuf,
    /// The owner-enrolled bounded-grant standing resolver Docket calls.
    pub standing_resolver: PathBuf,
    /// The executor adapter (`ag-effectd`); also computes plan identities.
    pub executor: PathBuf,
    pub issuer_principal: String,
    pub issuer_key_id: String,
    pub issuer_key: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nq {
    #[serde(default = "default_nq")]
    pub program: PathBuf,
    pub config: PathBuf,
    /// Request `nq collect <instance>` after a settled success.
    #[serde(default = "default_true")]
    pub collect: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evaluator {
    #[serde(default = "default_systemctl")]
    pub systemctl: PathBuf,
    /// The evaluator's oneshot service, started once after a completion.
    #[serde(default = "default_evaluator_unit")]
    pub unit: String,
    #[serde(default = "default_true")]
    pub trigger: bool,
}

impl Default for Evaluator {
    fn default() -> Self {
        Self {
            systemctl: default_systemctl(),
            unit: default_evaluator_unit(),
            trigger: true,
        }
    }
}

fn default_margin() -> i64 {
    90
}
fn default_report_age() -> i64 {
    120
}
fn default_poll_attempts() -> u32 {
    10
}
fn default_poll_interval() -> u64 {
    1000
}
fn default_post_attempts() -> u32 {
    3
}
fn default_post_interval() -> u64 {
    2000
}
fn default_post_dwell() -> u64 {
    15
}
fn default_timeout() -> u64 {
    60
}
fn default_work_schema() -> String {
    DEFAULT_WORK_SCHEMA.to_owned()
}
fn default_nq() -> PathBuf {
    PathBuf::from("/usr/bin/nq")
}
fn default_systemctl() -> PathBuf {
    PathBuf::from("/usr/bin/systemctl")
}
fn default_evaluator_unit() -> String {
    "constellation-attention.service".to_owned()
}
fn default_true() -> bool {
    true
}
fn default_endpoint() -> String {
    OPENROUTER_ENDPOINT.to_owned()
}
fn default_model_window() -> i64 {
    MODEL_WINDOW_MIN_SECONDS
}
fn default_wall() -> u64 {
    MODEL_WALL_MAX_MS
}
fn default_total_timeout() -> u64 {
    MODEL_TOTAL_TIMEOUT_MAX_MS
}
fn default_connect_timeout() -> u64 {
    MODEL_CONNECT_TIMEOUT_MAX_MS
}
fn default_backoff() -> u64 {
    1_000
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        let config: Self =
            toml::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), String> {
        let e = &self.enrollment;
        text("enrollment.site", &e.site)?;
        unit_name("enrollment.unit", &e.unit)?;
        text("enrollment.instance_id", &e.instance_id)?;
        if e.machine_id.len() != 32
            || !e
                .machine_id
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err("enrollment.machine_id must be 32 lowercase hex digits".into());
        }
        let c = &self.consumer;
        if !(1..=600).contains(&c.window_margin_seconds) {
            return Err("consumer.window_margin_seconds must be 1..=600".into());
        }
        if !(1..=600).contains(&c.report_max_age_seconds) {
            return Err("consumer.report_max_age_seconds must be 1..=600".into());
        }
        if c.poll_attempts == 0 || c.postcondition_attempts == 0 {
            return Err("poll and postcondition attempts must be at least 1".into());
        }
        if !(5..=120).contains(&c.postcondition_dwell_seconds) {
            return Err("consumer.postcondition_dwell_seconds must be 5..=120".into());
        }
        if !(1..=600).contains(&c.command_timeout_seconds) {
            return Err("consumer.command_timeout_seconds must be 1..=600".into());
        }
        let a = &self.ag;
        let d = &self.docket;
        for (name, path) in [
            ("consumer.state_dir", &c.state_dir),
            ("consumer.report", &c.report),
            ("ag.loopctl", &a.loopctl),
            ("ag.database", &a.database),
            ("ag.runtime_profile", &a.runtime_profile),
            ("ag.catalog", &a.catalog),
            ("ag.observation_resolver", &a.observation_resolver),
            ("ag.standing_resolver", &a.standing_resolver),
            ("ag.postcondition_resolver", &a.postcondition_resolver),
            ("docket.program", &d.program),
            ("docket.state_dir", &d.state_dir),
            ("docket.trust", &d.trust),
            ("docket.standing_resolver", &d.standing_resolver),
            ("docket.executor", &d.executor),
            ("docket.issuer_key", &d.issuer_key),
            ("nq.program", &self.nq.program),
            ("nq.config", &self.nq.config),
            ("evaluator.systemctl", &self.evaluator.systemctl),
        ] {
            absolute(name, path)?;
        }
        if a.database
            .parent()
            .is_none_or(|parent| parent == Path::new("/"))
        {
            return Err("ag.database must live in its own directory".into());
        }
        if a.database.starts_with(&c.state_dir) {
            return Err("ag.database must not live inside consumer.state_dir".into());
        }
        for (name, value) in [
            ("ag.observation_resolver_id", &a.observation_resolver_id),
            ("ag.standing_resolver_id", &a.standing_resolver_id),
            ("ag.postcondition_resolver_id", &a.postcondition_resolver_id),
            ("ag.work_schema", &a.work_schema),
            ("docket.issuer_principal", &d.issuer_principal),
            ("docket.issuer_key_id", &d.issuer_key_id),
        ] {
            text(name, value)?;
        }
        if a.observation_resolver_id == a.postcondition_resolver_id {
            return Err("the postcondition resolver id must differ from the precondition's".into());
        }
        if a.max_standing_ttl_ms == 0 {
            return Err("ag.max_standing_ttl_ms must be positive".into());
        }
        if a.plans.is_empty() {
            return Err("ag.plans must enrol at least one Start plan".into());
        }
        for (index, plan) in a.plans.iter().enumerate() {
            if !ENROLLABLE_PRESTATES.contains(&plan.prestate.as_str()) {
                return Err(format!(
                    "ag.plans[{index}].prestate must be one of {ENROLLABLE_PRESTATES:?}"
                ));
            }
            absolute(&format!("ag.plans[{index}].path"), &plan.path)?;
            if a.plans[..index]
                .iter()
                .any(|other| other.prestate == plan.prestate)
            {
                return Err(format!("ag.plans enrols prestate {} twice", plan.prestate));
            }
        }
        unit_name("evaluator.unit", &self.evaluator.unit)?;
        if self.evaluator.unit == e.unit {
            return Err("evaluator.unit must not be the enrolled unit".into());
        }
        if let Some(model) = &self.model {
            model.validate()?;
        }
        Ok(())
    }

    /// The model section, required by `--decider model`.
    pub fn model(&self) -> Result<&Model, String> {
        self.model
            .as_ref()
            .ok_or_else(|| "--decider model needs a [model] section".to_owned())
    }

    /// The evaluator's condition id for the enrolled unit.
    #[must_use]
    pub fn condition_id(&self) -> String {
        format!(
            "constellation:{}:service:service-down:{}",
            self.enrollment.site, self.enrollment.unit
        )
    }
}

impl Model {
    pub fn validate(&self) -> Result<(), String> {
        absolute("model.la_program", &self.la_program)?;
        absolute("model.key_file", &self.key_file)?;
        for (name, value) in [
            ("model.la_admission_id", &self.la_admission_id),
            ("model.la_eligibility_ref", &self.la_eligibility_ref),
        ] {
            if !crate::la::valid_id(value) {
                return Err(format!(
                    "{name} must be an LA identifier ([A-Za-z0-9._:/@+=-], 1..=128 bytes)"
                ));
            }
        }
        if self.la_arguments.len() > 16 {
            return Err("model.la_arguments takes at most 16 arguments".into());
        }
        for (index, argument) in self.la_arguments.iter().enumerate() {
            text(&format!("model.la_arguments[{index}]"), argument)?;
        }
        endpoint(&self.endpoint)?;
        if !(MODEL_WINDOW_MIN_SECONDS..=600).contains(&self.window_min_seconds) {
            return Err(format!(
                "model.window_min_seconds must be {MODEL_WINDOW_MIN_SECONDS}..=600"
            ));
        }
        if !(1_000..=MODEL_WALL_MAX_MS).contains(&self.wall_ms) {
            return Err(format!("model.wall_ms must be 1000..={MODEL_WALL_MAX_MS}"));
        }
        if !(100..=MODEL_TOTAL_TIMEOUT_MAX_MS).contains(&self.total_timeout_ms) {
            return Err(format!(
                "model.total_timeout_ms must be 100..={MODEL_TOTAL_TIMEOUT_MAX_MS}"
            ));
        }
        if !(100..=MODEL_CONNECT_TIMEOUT_MAX_MS).contains(&self.connect_timeout_ms)
            || self.connect_timeout_ms > self.total_timeout_ms
        {
            return Err(format!(
                "model.connect_timeout_ms must be 100..={MODEL_CONNECT_TIMEOUT_MAX_MS} and at most total_timeout_ms"
            ));
        }
        if self.retry_backoff_ms > MODEL_RETRY_BACKOFF_MAX_MS {
            return Err(format!(
                "model.retry_backoff_ms must be at most {MODEL_RETRY_BACKOFF_MAX_MS}"
            ));
        }
        // Two calls, their backoff and settlement must fit the wall ceiling.
        if 2 * self.total_timeout_ms + self.retry_backoff_ms > self.wall_ms {
            return Err("model.wall_ms must cover two calls and the retry backoff".into());
        }
        Ok(())
    }
}

/// The exact OpenRouter endpoint, or a loopback HTTP endpoint for
/// qualification fakes. Nothing else: no other host, no redirect target.
pub(crate) fn endpoint(value: &str) -> Result<(), String> {
    if value == OPENROUTER_ENDPOINT {
        return Ok(());
    }
    let loopback = cfg!(feature = "qualification-loopback")
        && value.strip_prefix("http://127.0.0.1:").is_some_and(|rest| {
            let (port, path) = rest.split_once('/').unwrap_or((rest, ""));
            !port.is_empty()
                && port.len() <= 5
                && port.bytes().all(|byte| byte.is_ascii_digit())
                && port.parse::<u16>().is_ok_and(|port| port != 0)
                && path.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.')
                })
        });
    if loopback {
        return Ok(());
    }
    Err(format!(
        "model.endpoint must be {OPENROUTER_ENDPOINT}; loopback fixtures require a qualification-loopback build"
    ))
}

fn text(name: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 256 || value.bytes().any(|b| b.is_ascii_control()) {
        return Err(format!(
            "{name} must be 1..=256 bytes without control characters"
        ));
    }
    Ok(())
}

fn unit_name(name: &str, value: &str) -> Result<(), String> {
    text(name, value)?;
    if !value.ends_with(".service")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@'))
    {
        return Err(format!("{name} must be a plain .service unit name"));
    }
    Ok(())
}

fn absolute(name: &str, path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("{name} must be an absolute path"));
    }
    Ok(())
}

#[cfg(test)]
mod endpoint_tests {
    use super::{OPENROUTER_ENDPOINT, endpoint};

    #[test]
    fn only_the_enrolled_provider_or_compiled_fixture_is_allowed() {
        assert!(endpoint(OPENROUTER_ENDPOINT).is_ok());
        assert_eq!(
            endpoint("http://127.0.0.1:8099/api/v1/chat/completions").is_ok(),
            cfg!(feature = "qualification-loopback")
        );
        for invalid in [
            "http://127.0.0.1:0/",
            "http://127.0.0.1:65536/",
            "http://openrouter.ai/api/v1/chat/completions",
            "https://example.invalid/",
        ] {
            assert!(endpoint(invalid).is_err());
        }
    }
}
