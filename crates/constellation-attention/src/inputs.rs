//! Read the configured inputs and turn qualified current state into
//! three-valued observations. Nothing here decides attention; it only says
//! whether each rule's underlying state is present, clear or not knowable now.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::{Duration, Instant};

use constellation_status_projection::{ModeV1, ProjectedStateV1, read_current_artifact};
use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use serde_json::{Value, json};

use crate::condition::{ConditionKey, validate_token};
use crate::config::{
    Config, EffectiveRule, EstateInput, HostPostureInput, MetricAlertsInput, NightshiftInput,
    NqStatusInput, NqStatusSource, SavedCheckInput, default_metric_warmup_grace,
};
use crate::state::MetricAlertsHistory;
use crate::util::{
    ChildEnvironment, excerpt, format_seconds, parse_rfc3339, read_bounded, rfc3339_seconds,
    run_bounded, truncate, truncate_words,
};

const STATUS_EXPORT_LIMIT: usize = 16 * 1024 * 1024;
const SAVED_CHECK_LIMIT: usize = 1024 * 1024;
/// The host-posture projection these rules read, and its known generations.
pub const HOST_POSTURE_PROJECTION: &str = "operator-filesystem-capacity";
pub const HOST_POSTURE_GENERATIONS: &[&str] = &["filesystem-capacity-v1"];
pub const EVALUATION_HISTORY_SCHEMA: &str = "nq.evaluation_history.v1";
/// NQ's largest public page (`MAX_PUBLIC_QUERY_ROWS`).
const HISTORY_PAGE_MAX: u64 = 1000;
pub const NQ_STATUS_SCHEMA: &str = "nq.status_snapshot.v3";
pub const SYSTEMD_UNIT_PROFILE: &str = "nq.systemd_unit";
pub const SYSTEMD_UNIT_VERSION: u64 = 2;
pub const SYSTEMD_UNIT_CONDITION: &str = "systemd_unit_not_active";
pub const HOST_MEMORY_PROFILE: &str = "nq.host_memory";
pub const HOST_MEMORY_VERSION: u64 = 1;
/// NQ's filesystem capacity watcher. Its detector's threshold is compiled
/// into NQ (available space at or below 10 % of non-reserved capacity, i.e.
/// 90 % used); the evaluator reads only `present` / `explicitly_absent`.
pub const FILESYSTEM_PROFILE: &str = "nq.host_filesystem_capacity";
pub const FILESYSTEM_VERSION: u64 = 1;
pub const FILESYSTEM_CONDITION: &str = "filesystem_capacity_pressure";
pub const HOST_MEMORY_CONDITION: &str = "memory_pressure_stall";
/// NQ's I/O pressure watcher (NQ #28). Its detector's threshold is compiled
/// into NQ (`/proc/pressure/io` `full avg60` at or above 25 %); the
/// evaluator reads only `present` / `explicitly_absent`.
pub const HOST_IO_PROFILE: &str = "nq.host_io";
pub const HOST_IO_VERSION: u64 = 1;
pub const HOST_IO_CONDITION: &str = "io_pressure_stall";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Observation {
    /// The rule's underlying state holds now.
    Present,
    /// Current qualified state says it does not hold.
    Clear,
    /// No current qualified state; nothing changes.
    Unknown,
    /// The rule, its input kind or the input label was removed from the
    /// configuration. Never produced by an input: an explicit operator
    /// decision that the condition is no longer evaluated. It closes an open
    /// condition without claiming recovery.
    Removed,
}

#[derive(Clone, Debug, Serialize)]
pub struct Observed {
    pub key: ConditionKey,
    pub rule: &'static str,
    pub input_label: String,
    pub observation: Observation,
    /// Input identities (artifact id, cycle id, check reference). Never payloads.
    pub reference: Value,
    pub note: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputStatus {
    /// Read and current.
    Ok,
    /// Read, but the content is stale or indeterminate.
    NotCurrent,
    /// Could not be read or parsed.
    Unavailable,
}

#[derive(Clone, Debug, Serialize)]
pub struct InputReport {
    pub label: String,
    pub kind: &'static str,
    /// The v2 component this input's own availability is reported under.
    pub component: &'static str,
    pub source: String,
    pub status: InputStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub identity: Value,
    /// Fault classes, plus informational `warming` (which is not a fault).
    /// One class per kind of fault
    /// ([`INPUT_CAUSES`]). Each class is its own
    /// `evaluator-input-unavailable` condition, so a lasting fault of one
    /// class never masks a later fault of another.
    pub causes: Vec<&'static str>,
    /// Definitions the input carries that admission refused, one entry per
    /// definition (`{label}.rule_rejected:<name>` with the reason). A
    /// rejected definition is never evaluated and never clears anything, but
    /// it does not change `status`: every other definition of the input is
    /// evaluated normally. The class `rejected` in `causes` says so.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rejected_rules: Vec<Value>,
}

/// Fault classes of an input, each keyed separately (`{label}.{cause}`).
pub const INPUT_CAUSES: &[&str] = &[
    "unreadable",
    "stale",
    "unrecognised",
    "untargetable",
    "indeterminate",
    "unreported",
    "empty",
    REJECTED_CAUSE,
];

/// The fault class of a definition refused by per-definition admission.
/// Only inputs of [`ADMISSION_KINDS`] carry it.
pub const REJECTED_CAUSE: &str = "rejected";

/// Input kinds whose definitions are admitted one by one.
pub const ADMISSION_KINDS: &[&str] = &["metric_alerts"];

impl InputReport {
    /// Refuse one definition the input carries, or one site of it: it is
    /// listed in `rejected_rules` with its fault
    /// (`{label}.rule_rejected:<name>`), site, target and reason, and the
    /// class `rejected` is raised. `status` is left alone,
    /// so the input's other definitions stay current.
    pub fn reject(&mut self, name: &str, site: Option<&str>, target: &str, reason: &str) {
        let name = truncate(name, 128);
        let fault = format!("{}.rule_rejected:{name}", self.label);
        if !self.causes.contains(&REJECTED_CAUSE) {
            self.causes.push(REJECTED_CAUSE);
        }
        let message = format!("{fault}: {reason}");
        self.error = Some(match self.error.take() {
            Some(error) if !error.is_empty() => format!("{error}; {message}"),
            _ => message,
        });
        self.rejected_rules.push(json!({
            "fault": fault,
            "rule": name,
            "site": site,
            "target": target,
            "reason": reason,
        }));
    }

    /// Record a fault: its class, the worse of the two statuses, and the
    /// message appended to `error`.
    pub fn fault(&mut self, cause: &'static str, status: InputStatus, message: &str) {
        if !self.causes.contains(&cause) {
            self.causes.push(cause);
        }
        if self.status == InputStatus::Ok || status == InputStatus::Unavailable {
            self.status = status;
        }
        self.error = Some(match self.error.take() {
            Some(error) if !error.is_empty() => format!("{error}; {message}"),
            _ => message.to_owned(),
        });
    }
}

pub struct InputsRead {
    pub reports: Vec<InputReport>,
    pub observed: Vec<Observed>,
    /// Notice text independent of whether metric-alert-firing is enabled.
    pub metric_indeterminate_reason: Option<String>,
    pub metric_alerts: Option<MetricAlertsHistory>,
    /// Evaluation-history mode: the NQ status input's label and its updated
    /// watcher roster, to be remembered in the state.
    pub nq_watchers: Option<(String, BTreeMap<String, i64>)>,
}

pub struct Context<'a> {
    pub config: &'a Config,
    pub rules: &'a [EffectiveRule],
    pub now: i64,
    pub now_ms: i64,
    pub metric_alerts: Option<&'a MetricAlertsHistory>,
    pub first_seen: i64,
    pub reconfigured_at: Option<i64>,
    /// The remembered NQ watcher roster of the NQ status input's label.
    pub nq_watchers: Option<&'a BTreeMap<String, i64>>,
}

impl Context<'_> {
    fn enabled(&self, id: &str) -> Option<&EffectiveRule> {
        self.rules
            .iter()
            .find(|rule| rule.rule.id == id && rule.enabled)
    }

    fn key(&self, component: &str, rule: &str, target_class: Option<&str>) -> Option<ConditionKey> {
        ConditionKey::new(&self.config.site, component, rule, target_class).ok()
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(self.config.command_timeout_seconds)
    }
}

pub fn read_all(context: &Context<'_>) -> InputsRead {
    let mut read = InputsRead {
        reports: Vec::new(),
        observed: Vec::new(),
        metric_indeterminate_reason: None,
        metric_alerts: None,
        nq_watchers: None,
    };
    for input in &context.config.inputs.host_posture {
        host_posture(context, input, &mut read);
    }
    if let Some(input) = &context.config.inputs.nq_status {
        nq_status(context, input, &mut read);
    }
    if let Some(input) = &context.config.inputs.nightshift {
        nightshift(context, input, &mut read);
    }
    for input in &context.config.inputs.saved_checks {
        saved_check(context, input, &mut read);
    }
    if let Some(input) = &context.config.inputs.estate {
        estate(context, input, &mut read);
    }
    if let Some(input) = &context.config.inputs.metric_alerts {
        metric_alerts(context, input, &mut read);
    }
    for report in &mut read.reports {
        if report.causes.is_empty() {
            match report.status {
                InputStatus::Unavailable => report.causes.push("unreadable"),
                InputStatus::NotCurrent => report.causes.push("stale"),
                InputStatus::Ok => {}
            }
        }
    }
    read
}

#[allow(
    clippy::too_many_arguments,
    reason = "One flat constructor for every rule's observation keeps the call sites explicit."
)]
fn push(
    context: &Context<'_>,
    read: &mut InputsRead,
    rule: &'static str,
    component: &str,
    target_class: Option<&str>,
    input_label: &str,
    observation: Observation,
    reference: &Value,
    note: String,
) {
    if context.enabled(rule).is_none() {
        return;
    }
    let Some(key) = context.key(component, rule, target_class) else {
        return;
    };
    read.observed.push(Observed {
        key,
        rule,
        input_label: input_label.to_owned(),
        observation,
        reference: reference.clone(),
        note,
    });
}

fn host_posture(context: &Context<'_>, input: &HostPostureInput, read: &mut InputsRead) {
    let source = input.publication_root.display().to_string();
    let artifact = match read_current_artifact(&input.publication_root) {
        Ok(artifact) => artifact,
        Err(error) => {
            read.reports.push(InputReport {
                causes: Vec::new(),
                rejected_rules: Vec::new(),
                label: input.label.clone(),
                kind: "host_posture",
                component: "host_posture",
                source,
                status: InputStatus::Unavailable,
                error: Some(error.to_string()),
                identity: Value::Null,
            });
            return;
        }
    };
    if artifact.projection_id != HOST_POSTURE_PROJECTION
        || !HOST_POSTURE_GENERATIONS.contains(&artifact.projection_generation.as_str())
    {
        // Other producers write the same status object schema (memory, load,
        // systemd units, inodes); only the filesystem-capacity projection
        // feeds these rules.
        read.reports.push(InputReport {
            causes: Vec::new(),
            rejected_rules: Vec::new(),
            label: input.label.clone(),
            kind: "host_posture",
            component: "host_posture",
            source,
            status: InputStatus::Unavailable,
            error: Some(format!(
                "CURRENT is projection {:?} generation {:?}, not {HOST_POSTURE_PROJECTION:?} ({})",
                artifact.projection_id,
                artifact.projection_generation,
                HOST_POSTURE_GENERATIONS.join(", ")
            )),
            identity: json!({
                "artifact_id": artifact.artifact_id,
                "projection_id": artifact.projection_id,
                "projection_generation": artifact.projection_generation,
            }),
        });
        return;
    }
    let uncertainty = i64::try_from(artifact.admitted_clock_uncertainty_ms).unwrap_or(i64::MAX);
    let generated = i64::try_from(artifact.generated_at_unix_ms).unwrap_or(i64::MAX);
    let fresh_until = i64::try_from(artifact.fresh_until_unix_ms).unwrap_or(i64::MAX);
    // The renderer's rule: current iff generated <= earliest-now and latest-now < fresh_until.
    let current = context.now_ms.saturating_sub(uncertainty) >= generated
        && context.now_ms.saturating_add(uncertainty) < fresh_until;
    let identity = json!({
        "artifact_id": artifact.artifact_id,
        "projection_id": artifact.projection_id,
        "projection_generation": artifact.projection_generation,
        "aggregate_state": artifact.aggregate_state.as_str(),
        "generated_at": format_seconds(generated / 1000),
        "fresh_until": format_seconds(fresh_until / 1000),
        "current": current,
    });
    let all_maintenance = artifact
        .components
        .iter()
        .all(|component| component.mode == ModeV1::Maintenance);
    read.reports.push(InputReport {
        causes: Vec::new(),
        rejected_rules: Vec::new(),
        label: input.label.clone(),
        kind: "host_posture",
        component: "host_posture",
        source,
        status: if current {
            InputStatus::Ok
        } else {
            InputStatus::NotCurrent
        },
        error: None,
        identity: identity.clone(),
    });
    let label = input.label.as_str();
    let state = artifact.aggregate_state;

    let unknown = !current || state == ProjectedStateV1::Unknown;
    push(
        context,
        read,
        "host-posture-unknown",
        "host_posture",
        Some(label),
        label,
        if unknown {
            Observation::Present
        } else {
            Observation::Clear
        },
        &identity,
        if current {
            format!("aggregate_state {}", state.as_str())
        } else {
            "CURRENT is stale (fresh_until passed)".to_owned()
        },
    );

    let disk = if unknown || all_maintenance {
        Observation::Unknown
    } else if state == ProjectedStateV1::Healthy {
        Observation::Clear
    } else {
        Observation::Present
    };
    push(
        context,
        read,
        "host-disk",
        "host_posture",
        Some(label),
        label,
        disk,
        &identity,
        format!("aggregate_state {}", state.as_str()),
    );

    if let Some(rule) = context.enabled("nq-no-fresh-acquisition") {
        let age_ms = context.now_ms.saturating_sub(generated);
        push(
            context,
            read,
            "nq-no-fresh-acquisition",
            "nq",
            Some(label),
            label,
            if age_ms > rule.threshold_seconds.saturating_mul(1000) {
                Observation::Present
            } else {
                Observation::Clear
            },
            &identity,
            format!("newest status generated {} s ago", age_ms / 1000),
        );
    }
}

fn load_json(
    context: &Context<'_>,
    command: Option<&Vec<String>>,
    path: Option<&std::path::PathBuf>,
    limit: usize,
) -> Result<(String, Value), String> {
    let (source, bytes) = if let Some(argv) = command {
        let output = run_bounded(argv, context.timeout(), limit, ChildEnvironment::Minimal)?;
        if output.timed_out {
            return Err(format!("{} timed out", argv[0]));
        }
        if output.status != Some(0) {
            return Err(format!(
                "{} exited with {:?}: {}",
                argv[0],
                output.status,
                excerpt(&output.stderr)
            ));
        }
        (argv[0].clone(), output.stdout)
    } else if let Some(path) = path {
        (
            path.display().to_string(),
            read_bounded(path, limit as u64)?,
        )
    } else {
        return Err("input has no source".into());
    };
    let value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("{source} did not produce JSON: {error}"))?;
    Ok((source, value))
}

/// Bound on error text that carries watcher, unit or evaluation ids.
const ID_TEXT_MAX: usize = 512;

/// A watcher instance id the roster may remember: 1..=128 bytes, none of
/// them control bytes.
fn bounded_instance_id(id: &str) -> bool {
    (1..=128).contains(&id.len()) && id.bytes().all(|byte| byte >= 0x20 && byte != 0x7f)
}

/// The pass-clock time a source answered: the pass's `now` plus the time
/// the read took, rounded up to whole seconds.
fn answered_at(context: &Context<'_>, started: Instant) -> i64 {
    let elapsed = started.elapsed();
    let seconds = i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX);
    context
        .now
        .saturating_add(seconds)
        .saturating_add(i64::from(elapsed.subsec_nanos() > 0))
}

struct Lineage {
    /// (`evaluated_at` in nanoseconds, history position) for choosing the
    /// newest evaluation per lineage.
    order: (i128, usize),
    evaluated_at: i64,
    state: String,
    evaluation_id: String,
    instance_id: String,
}

/// What either NQ source yields for these rules.
struct NqSnapshot {
    generated: i64,
    identity: Value,
    /// (component or record id, evaluation envelope if it has one), oldest
    /// first where the source orders them.
    evaluations: Vec<(String, Option<Value>)>,
    /// Newest collection (or evaluation) time per watcher instance: the
    /// liveness signal.
    collected: BTreeMap<String, i64>,
    /// Why the snapshot as a whole cannot be relied on (an incomplete page).
    incomplete: Option<String>,
}

/// `nq --json status export`: one `nq.status_snapshot.v3` document.
fn status_export(context: &Context<'_>, input: &NqStatusInput) -> Result<NqSnapshot, String> {
    let (_, snapshot) = load_json(
        context,
        input.command.as_ref(),
        input.path.as_ref(),
        STATUS_EXPORT_LIMIT,
    )?;
    if snapshot.get("schema").and_then(Value::as_str) != Some(NQ_STATUS_SCHEMA) {
        return Err(format!("status export schema is not {NQ_STATUS_SCHEMA}"));
    }
    let generated = snapshot
        .get("generated_at")
        .and_then(Value::as_str)
        .ok_or_else(|| "status export has no generated_at".to_owned())
        .and_then(rfc3339_seconds)?;
    let components = snapshot
        .get("components")
        .and_then(Value::as_array)
        .ok_or_else(|| "status export has no components".to_owned())?;
    // Last collection commit per watcher instance: the only liveness signal.
    let collected = components
        .iter()
        .filter(|component| component.get("kind").and_then(Value::as_str) == Some("instance"))
        .filter_map(|component| {
            let id = component.get("id")?.as_str()?.to_owned();
            let at = rfc3339_seconds(component.get("observed_at")?.as_str()?).ok()?;
            Some((id, at))
        })
        .collect();
    let evaluations = components
        .iter()
        .filter(|component| component.get("kind").and_then(Value::as_str) == Some("evaluation"))
        .map(|component| {
            let id = component
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let envelope = component
                .get("detail")
                .filter(|detail| {
                    detail.get("detail_kind").and_then(Value::as_str) == Some("evaluation")
                })
                .and_then(|detail| detail.get("result"))
                .cloned();
            (id, envelope)
        })
        .collect();
    Ok(NqSnapshot {
        generated,
        identity: json!({
            "schema": NQ_STATUS_SCHEMA,
            "generated_at": format_seconds(generated),
            "evaluation_through_sequence": snapshot.get("evaluation_through_sequence"),
        }),
        evaluations,
        collected,
        incomplete: None,
    })
}

/// One `nq --json evaluations export` page.
fn history_page(
    context: &Context<'_>,
    base: &[String],
    limit: u64,
    window: Option<(u64, u64)>,
) -> Result<Value, String> {
    let mut argv = base.to_vec();
    argv.extend(["evaluations".into(), "export".into(), "--limit".into()]);
    argv.push(limit.to_string());
    if let Some((after, through)) = window {
        argv.extend(["--after".into(), after.to_string()]);
        argv.extend(["--through".into(), through.to_string()]);
    }
    let (_, page) = load_json(context, Some(&argv), None, STATUS_EXPORT_LIMIT)?;
    if page.get("schema").and_then(Value::as_str) != Some(EVALUATION_HISTORY_SCHEMA) {
        return Err(format!(
            "evaluations export schema is not {EVALUATION_HISTORY_SCHEMA}"
        ));
    }
    Ok(page)
}

/// `nq --json evaluations export`: the newest `window_records` evaluations,
/// frozen at the store-wide sequence the first call reports (nq#20: status
/// export walks the whole history; a page answers in well under a second).
fn evaluation_history(context: &Context<'_>, input: &NqStatusInput) -> Result<NqSnapshot, String> {
    let base = input
        .command
        .as_ref()
        .ok_or_else(|| "evaluation_history needs a command".to_owned())?;
    let probe = history_page(context, base, 1, None)?;
    let through = probe
        .get("through_sequence")
        .and_then(Value::as_u64)
        .ok_or_else(|| "evaluations export has no through_sequence".to_owned())?;
    let window = u64::from(input.window_records);
    let mut after = through.saturating_sub(window);
    let mut evaluations = Vec::new();
    let mut collected: BTreeMap<String, i64> = BTreeMap::new();
    let mut generated = None;
    let mut incomplete = None;
    let mut complete = after >= through;
    // At most NQ's 1000 rows per page; the window bounds the page count.
    for _ in 0..window.div_ceil(HISTORY_PAGE_MAX) + 1 {
        if complete {
            break;
        }
        let limit = (through - after).min(HISTORY_PAGE_MAX);
        let page = history_page(context, base, limit, Some((after, through)))?;
        generated = Some(
            page.get("generated_at")
                .and_then(Value::as_str)
                .ok_or_else(|| "evaluations export has no generated_at".to_owned())
                .and_then(rfc3339_seconds)?,
        );
        if page.get("through_sequence").and_then(Value::as_u64) != Some(through) {
            incomplete = Some(format!(
                "evaluation history moved from through_sequence {through} to {:?}",
                page.get("through_sequence")
            ));
            break;
        }
        let records = page
            .get("records")
            .and_then(Value::as_array)
            .ok_or_else(|| "evaluations export has no records".to_owned())?;
        for record in records {
            let sequence = record.get("sequence").and_then(Value::as_u64);
            let envelope = record.get("result").cloned();
            if let Some(envelope) = &envelope
                && let (Some(instance), Some(Ok(at))) = (
                    envelope
                        .pointer("/context/instance_id")
                        .and_then(Value::as_str),
                    envelope
                        .pointer("/evaluated_at")
                        .and_then(Value::as_str)
                        .map(rfc3339_seconds),
                )
            {
                let newest = collected.entry(instance.to_owned()).or_insert(at);
                *newest = (*newest).max(at);
            }
            evaluations.push((
                sequence.map_or_else(|| "record".to_owned(), |sequence| format!("seq-{sequence}")),
                envelope,
            ));
        }
        complete = page.get("complete").and_then(Value::as_bool) == Some(true);
        match page.get("next_after_sequence").and_then(Value::as_u64) {
            Some(next) if !complete && next > after => after = next,
            _ => break,
        }
    }
    if !complete && incomplete.is_none() {
        incomplete = Some(format!(
            "evaluation history page through {through} is not complete"
        ));
    }
    let generated = generated
        .or_else(|| {
            probe
                .get("generated_at")
                .and_then(Value::as_str)
                .and_then(|value| rfc3339_seconds(value).ok())
        })
        .ok_or_else(|| "evaluations export has no generated_at".to_owned())?;
    Ok(NqSnapshot {
        generated,
        identity: json!({
            "schema": EVALUATION_HISTORY_SCHEMA,
            "generated_at": format_seconds(generated),
            "through_sequence": through,
        }),
        evaluations,
        collected,
        incomplete,
    })
}

fn nq_status(context: &Context<'_>, input: &NqStatusInput, read: &mut InputsRead) {
    let mut report = InputReport {
        causes: Vec::new(),
        rejected_rules: Vec::new(),
        label: input.label.clone(),
        kind: "nq_status",
        component: "nq",
        source: input
            .command
            .as_ref()
            .and_then(|argv| argv.first().cloned())
            .or_else(|| input.path.as_ref().map(|path| path.display().to_string()))
            .unwrap_or_default(),
        status: InputStatus::Unavailable,
        error: None,
        identity: Value::Null,
    };
    let started = Instant::now();
    let fetched = match input.source {
        NqStatusSource::StatusExport => status_export(context, input),
        NqStatusSource::EvaluationHistory => evaluation_history(context, input),
    };
    let completed = answered_at(context, started);
    let snapshot = match fetched {
        Ok(snapshot) => snapshot,
        Err(error) => {
            report.error = Some(error);
            read.reports.push(report);
            return;
        }
    };
    let generated = snapshot.generated;
    let history = input.source == NqStatusSource::EvaluationHistory;
    // History mode: liveness is the remembered roster merged with the
    // window, so a watcher that stops evaluating stays stale after its
    // records scroll out, until the operator retires it.
    // No entry is later than the page itself: a window evaluation from more
    // than the 60 s skew allowance after the page (a past forward clock
    // step) is no liveness at all, and a remembered time is capped at the
    // page, so a clock step never leaves a watcher looking fresh for ever.
    let mut liveness: BTreeMap<String, i64> = snapshot
        .collected
        .iter()
        .filter(|(_, at)| !history || **at <= generated + 60)
        .map(|(instance, at)| (instance.clone(), (*at).min(generated)))
        .collect();
    if history && let Some(remembered) = context.nq_watchers {
        for (instance, at) in remembered {
            let at = (*at).min(generated);
            let newest = liveness.entry(instance.clone()).or_insert(at);
            *newest = (*newest).max(at);
        }
    }
    let mut unbounded_ids = Vec::new();
    let roster: BTreeMap<String, i64> = liveness
        .iter()
        .filter(|(instance, _)| !input.retired_instances.contains(instance))
        .filter(|(instance, _)| {
            let bounded = bounded_instance_id(instance);
            if !bounded {
                unbounded_ids.push(format!("{:?}", truncate(instance, 64)));
            }
            bounded
        })
        .map(|(instance, at)| (instance.clone(), *at))
        .collect();
    if history {
        read.nq_watchers = Some((input.label.clone(), roster.clone()));
    }
    let collected = &liveness;
    // Age and future skew are measured when the source answered, not when
    // the pass started: a slow export (bounded by the command timeout) is
    // not a snapshot from the future.
    let snapshot_age = completed - generated;
    let current = snapshot.incomplete.is_none()
        && snapshot_age <= input.max_age_seconds
        && snapshot_age >= -60;
    report.status = if current {
        InputStatus::Ok
    } else {
        InputStatus::NotCurrent
    };
    report.identity = snapshot.identity.clone();
    let mut units: BTreeMap<String, Lineage> = BTreeMap::new();
    let mut memory: Option<Lineage> = None;
    let mut io: Option<Lineage> = None;
    let mut filesystems: BTreeMap<String, Lineage> = BTreeMap::new();
    // Evaluations this input consumes but cannot interpret. Any of them makes
    // the input not current: a rule fed by it must hold, never read the
    // missing lineage as recovery.
    let mut unrecognised: Vec<String> = Vec::new();
    if !unbounded_ids.is_empty() {
        unrecognised.push(format!(
            "watcher instance ids beyond 128 printable bytes, not remembered: {}",
            unbounded_ids.join(", ")
        ));
    }
    let mut untargetable: Vec<String> = Vec::new();
    for (position, (id, envelope)) in snapshot.evaluations.iter().enumerate() {
        let Some(envelope) = envelope else {
            unrecognised.push(format!("evaluation {id:?} has no evaluation envelope"));
            continue;
        };
        let text = |pointer: &str| {
            envelope
                .pointer(pointer)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let profile = text("/profile/profile/id");
        let version = envelope
            .pointer("/profile/profile/version")
            .and_then(Value::as_u64);
        let condition = text("/result/condition");
        let instance_id = text("/context/instance_id");
        let consumed = [
            SYSTEMD_UNIT_PROFILE,
            HOST_MEMORY_PROFILE,
            HOST_IO_PROFILE,
            FILESYSTEM_PROFILE,
        ]
        .contains(&profile.as_str())
            || [
                SYSTEMD_UNIT_CONDITION,
                HOST_MEMORY_CONDITION,
                HOST_IO_CONDITION,
                FILESYSTEM_CONDITION,
            ]
            .contains(&condition.as_str());
        if !consumed {
            // Other profiles feed no rule here.
            continue;
        }
        let systemd = profile == SYSTEMD_UNIT_PROFILE
            && version == Some(SYSTEMD_UNIT_VERSION)
            && condition == SYSTEMD_UNIT_CONDITION;
        let host_memory = profile == HOST_MEMORY_PROFILE
            && version == Some(HOST_MEMORY_VERSION)
            && condition == HOST_MEMORY_CONDITION;
        let host_io = profile == HOST_IO_PROFILE
            && version == Some(HOST_IO_VERSION)
            && condition == HOST_IO_CONDITION;
        let filesystem = profile == FILESYSTEM_PROFILE
            && version == Some(FILESYSTEM_VERSION)
            && condition == FILESYSTEM_CONDITION;
        if !systemd && !host_memory && !host_io && !filesystem {
            unrecognised.push(format!(
                "unrecognised profile {profile:?} version {} condition {condition:?} (instance {instance_id:?})",
                version.map_or_else(|| "none".to_owned(), |version| version.to_string())
            ));
            continue;
        }
        let Ok(evaluated) = parse_rfc3339(&text("/evaluated_at")) else {
            unrecognised.push(format!(
                "evaluation {id:?} (instance {instance_id:?}) has no valid evaluated_at"
            ));
            continue;
        };
        let evaluated_at = evaluated.unix_timestamp();
        // Newest by full evaluated_at precision; on an exact tie the later
        // history record (higher sequence) wins. A later sequence with an
        // earlier evaluated_at loses.
        let order = (
            evaluated.unix_timestamp_nanos(),
            if history { position } else { 0 },
        );
        let lineage = Lineage {
            order,
            evaluated_at,
            state: text("/result/state"),
            evaluation_id: text("/evaluation_id"),
            instance_id,
        };
        if systemd {
            let subject = text("/context/subject");
            let unit = subject
                .strip_prefix("systemd-unit:")
                .and_then(|rest| rest.rsplit_once('/'))
                .map(|(_, unit)| unit.to_owned())
                .unwrap_or_default();
            if validate_token("target_class", &unit, 48).is_err() {
                untargetable.push(format!(
                    "{:?} (instance {:?})",
                    truncate(&unit, 96),
                    lineage.instance_id
                ));
                continue;
            }
            if units
                .get(&unit)
                .is_none_or(|existing| existing.order < order)
            {
                units.insert(unit, lineage);
            }
        } else if filesystem {
            // One watcher per filesystem: its instance id names the target.
            let target = lineage.instance_id.clone();
            if validate_token("target_class", &target, 48).is_err() {
                untargetable.push(format!("filesystem watcher {:?}", truncate(&target, 96)));
                continue;
            }
            if filesystems
                .get(&target)
                .is_none_or(|existing| existing.order < order)
            {
                filesystems.insert(target, lineage);
            }
        } else if host_io {
            if io.as_ref().is_none_or(|existing| existing.order < order) {
                io = Some(lineage);
            }
        } else if memory
            .as_ref()
            .is_none_or(|existing| existing.order < order)
        {
            memory = Some(lineage);
        }
    }
    let stale_instance = |lineage: &Lineage| {
        collected
            .get(&lineage.instance_id)
            .is_none_or(|at| generated - at > input.stale_after_seconds)
    };
    let stale: Vec<&str> = units
        .values()
        .chain(filesystems.values())
        .chain(memory.as_ref())
        .chain(io.as_ref())
        .filter(|lineage| stale_instance(lineage))
        .map(|lineage| lineage.instance_id.as_str())
        .chain(
            roster
                .iter()
                .filter(|(_, at)| history && generated - **at > input.stale_after_seconds)
                .map(|(instance, _)| instance.as_str()),
        )
        .collect::<std::collections::BTreeSet<&str>>()
        .into_iter()
        .collect();
    let indeterminate: Vec<String> = units
        .iter()
        .chain(filesystems.iter())
        .map(|(unit, lineage)| (unit.as_str(), lineage))
        .chain(memory.as_ref().map(|lineage| ("host memory", lineage)))
        .chain(io.as_ref().map(|lineage| ("host io", lineage)))
        .filter(|(_, lineage)| {
            current
                && !stale_instance(lineage)
                && !matches!(lineage.state.as_str(), "present" | "explicitly_absent")
        })
        .map(|(name, lineage)| format!("{name} ({})", lineage.state))
        .collect();
    if let Some(problem) = &snapshot.incomplete {
        report.fault("stale", InputStatus::NotCurrent, problem);
    } else if !current {
        report.fault(
            "stale",
            InputStatus::NotCurrent,
            &format!("NQ snapshot generated {snapshot_age} s before it was read"),
        );
    }
    if !stale.is_empty() {
        report.fault(
            "stale",
            InputStatus::NotCurrent,
            &format!(
                "watchers with no collection for more than {} s: {}",
                input.stale_after_seconds,
                truncate(&stale.join(","), ID_TEXT_MAX)
            ),
        );
    }
    if !unrecognised.is_empty() {
        report.fault(
            "unrecognised",
            InputStatus::NotCurrent,
            &format!(
                "evaluations this input cannot interpret: {}",
                truncate(&unrecognised.join("; "), ID_TEXT_MAX)
            ),
        );
    }
    if !untargetable.is_empty() {
        report.fault(
            "untargetable",
            InputStatus::NotCurrent,
            &format!(
                "systemd units that map to no bounded target class: {}",
                truncate(&untargetable.join(", "), ID_TEXT_MAX)
            ),
        );
    }
    if !indeterminate.is_empty() {
        // Per-condition unknown on an otherwise current export: reported
        // so a lasting `cannot_evaluate` reaches the operator.
        report.fault(
            "indeterminate",
            InputStatus::NotCurrent,
            &format!(
                "detectors that cannot evaluate: {}",
                truncate(&indeterminate.join(", "), ID_TEXT_MAX)
            ),
        );
    }
    read.reports.push(report);
    let observe = |lineage: &Lineage| -> (Observation, String) {
        if !current || stale_instance(lineage) {
            return (
                Observation::Unknown,
                "watcher collection is not current".to_owned(),
            );
        }
        match lineage.state.as_str() {
            "present" => (Observation::Present, "condition present".into()),
            "explicitly_absent" => (Observation::Clear, "condition explicitly absent".into()),
            other => (Observation::Unknown, format!("detector state {other}")),
        }
    };
    let reference = |lineage: &Lineage| {
        json!({
            "instance_id": lineage.instance_id,
            "collected_at": collected.get(&lineage.instance_id).map(|at| format_seconds(*at)),
            "evaluation_id": lineage.evaluation_id,
            "evaluated_at": format_seconds(lineage.evaluated_at),
            "status_generated_at": format_seconds(generated),
        })
    };
    for (unit, lineage) in &units {
        let (observation, note) = observe(lineage);
        push(
            context,
            read,
            "service-down",
            "service",
            Some(unit),
            &input.label,
            observation,
            &reference(lineage),
            note,
        );
    }
    for (target, lineage) in &filesystems {
        let (observation, note) = observe(lineage);
        push(
            context,
            read,
            "host-disk",
            "host_posture",
            Some(target),
            &input.label,
            observation,
            &reference(lineage),
            note,
        );
    }
    if let Some(lineage) = &memory {
        let (observation, note) = observe(lineage);
        push(
            context,
            read,
            "memory-pressure",
            "host_posture",
            None,
            &input.label,
            observation,
            &reference(lineage),
            note,
        );
    }
    if let Some(lineage) = &io {
        let (observation, note) = observe(lineage);
        push(
            context,
            read,
            "io-pressure",
            "host_posture",
            None,
            &input.label,
            observation,
            &reference(lineage),
            note,
        );
    }
}

fn nightshift(context: &Context<'_>, input: &NightshiftInput, read: &mut InputsRead) {
    let mut report = InputReport {
        causes: Vec::new(),
        rejected_rules: Vec::new(),
        label: input.label.clone(),
        kind: "nightshift",
        component: "nightshift",
        source: input.store_path.display().to_string(),
        status: InputStatus::Unavailable,
        error: None,
        identity: Value::Null,
    };
    let newest = match newest_closed_cycle(&input.store_path) {
        Ok(newest) => newest,
        Err(error) => {
            report.error = Some(error);
            read.reports.push(report);
            return;
        }
    };
    let Some((cycle_id, closed_at)) = newest else {
        let first_seen = context.metric_alerts.map_or(context.first_seen, |history| {
            context.first_seen.min(history.first_seen)
        });
        let grace = context
            .config
            .inputs
            .metric_alerts
            .as_ref()
            .map_or_else(default_metric_warmup_grace, |input| input.warmup_grace);
        if context.now.saturating_sub(first_seen) < grace {
            report.status = InputStatus::Ok;
            report.causes.push("warming");
            report.identity =
                json!({"first_seen": format_seconds(first_seen), "warmup_grace": grace});
        } else {
            report.fault(
                "empty",
                InputStatus::NotCurrent,
                "no closed observation cycle",
            );
        }
        read.reports.push(report);
        push(
            context,
            read,
            "nightshift-recurrence-missing",
            "nightshift",
            Some(&input.label),
            &input.label,
            Observation::Unknown,
            &Value::Null,
            "no closed observation cycle yet".into(),
        );
        return;
    };
    let identity = json!({"cycle_id": cycle_id, "closed_at": format_seconds(closed_at)});
    report.status = InputStatus::Ok;
    report.identity = identity.clone();
    read.reports.push(report);
    if let Some(rule) = context.enabled("nightshift-recurrence-missing") {
        let age = context.now - closed_at;
        push(
            context,
            read,
            "nightshift-recurrence-missing",
            "nightshift",
            Some(&input.label),
            &input.label,
            if age > rule.threshold_seconds {
                Observation::Present
            } else {
                Observation::Clear
            },
            &identity,
            format!("last closed cycle {age} s ago"),
        );
    }
}

/// The newest closed cycle (id, `updated_at` seconds), read-only.
pub fn newest_closed_cycle(path: &Path) -> Result<Option<(String, i64)>, String> {
    if !path.is_file() {
        return Err(format!("{} is not a readable file", path.display()));
    }
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| format!("cannot open {} read-only: {error}", path.display()))?;
    connection
        .busy_timeout(Duration::from_secs(2))
        .map_err(|error| error.to_string())?;
    connection
        .pragma_update(None, "query_only", true)
        .map_err(|error| error.to_string())?;
    let mut statement = connection
        .prepare(
            "SELECT cycle_id, updated_at FROM canonical_observation_cycles \
             WHERE status = 'closed' ORDER BY updated_at DESC LIMIT 16",
        )
        .map_err(|error| format!("cannot query canonical_observation_cycles: {error}"))?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|error| format!("cannot query canonical_observation_cycles: {error}"))?;
    let mut newest: Option<(String, i64)> = None;
    for row in rows {
        let (cycle_id, updated_at) = row.map_err(|error| error.to_string())?;
        let seconds = rfc3339_seconds(&updated_at)?;
        if newest.as_ref().is_none_or(|(_, best)| *best < seconds) {
            newest = Some((cycle_id, seconds));
        }
    }
    Ok(newest)
}

fn saved_check(context: &Context<'_>, input: &SavedCheckInput, read: &mut InputsRead) {
    let label = input.reference.as_str();
    let mut report = InputReport {
        causes: Vec::new(),
        rejected_rules: Vec::new(),
        label: label.to_owned(),
        kind: "saved_check",
        component: "nq",
        source: input
            .command
            .as_ref()
            .and_then(|argv| argv.first().cloned())
            .or_else(|| input.path.as_ref().map(|path| path.display().to_string()))
            .unwrap_or_default(),
        status: InputStatus::Unavailable,
        error: None,
        identity: Value::Null,
    };
    let result = match load_json(
        context,
        input.command.as_ref(),
        input.path.as_ref(),
        SAVED_CHECK_LIMIT,
    ) {
        Ok((_, value)) => value,
        Err(error) => {
            report.error = Some(error);
            read.reports.push(report);
            return;
        }
    };
    if let Some(named) = result.get("reference").and_then(Value::as_str)
        && named != label
    {
        report.error = Some(format!("result names saved check {named:?}, not {label:?}"));
        read.reports.push(report);
        return;
    }
    let outcome = result
        .get("outcome")
        .and_then(Value::as_str)
        .unwrap_or("missing")
        .to_owned();
    let evaluation_id = result
        .get("evaluation_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let read_at = result
        .pointer("/detail/read_attempted_at")
        .and_then(Value::as_str)
        .map(rfc3339_seconds);
    let identity = json!({
        "reference": label,
        "evaluation_id": evaluation_id,
        "outcome": outcome,
        "read_attempted_at": read_at.as_ref().and_then(|value| value.as_ref().ok()).map(|value| format_seconds(*value)),
    });
    report.identity = identity.clone();
    let (observation, cause, note) = match (outcome.as_str(), read_at) {
        ("passed" | "failed", Some(Ok(at))) if context.now - at > input.max_age_seconds => (
            Observation::Unknown,
            Some("stale"),
            format!("result read {} s ago; not current", context.now - at),
        ),
        ("failed", Some(Ok(_))) => (Observation::Present, None, "failed".into()),
        ("passed", Some(Ok(_))) => (Observation::Clear, None, "passed".into()),
        ("passed" | "failed", _) => (
            Observation::Unknown,
            Some("unrecognised"),
            "result has no valid read_attempted_at".into(),
        ),
        (other, _) => (
            Observation::Unknown,
            Some("indeterminate"),
            format!("result is {other}; indeterminate"),
        ),
    };
    report.status = InputStatus::Ok;
    if let Some(cause) = cause {
        report.fault(cause, InputStatus::NotCurrent, &note);
    }
    read.reports.push(report);
    push(
        context,
        read,
        "sqlite-health",
        "nq",
        Some(label),
        label,
        observation,
        &identity,
        note,
    );
}

const ESTATE_LIMIT: usize = 4 * 1024 * 1024;
pub const ESTATE_LABEL: &str = "estate";
/// The estate service whose journal `remediation-journal-critical` watches.
pub const REMEDIATION_SERVICE: &str = "remediation-consumer";
/// Its `project.ops.status/v1` concern that is `ABSENT` at 15 sealed journal
/// segments (the consumer refuses at 16).
pub const JOURNAL_CRITICAL_CONCERN: &str = "remediation.journal.generations-critical";

/// `constellation.estate/v1`: one verdict per service. DOWN and DEGRADED are
/// present; OK and a declared PAUSED are clear; UNKNOWN changes nothing. A
/// stale document makes every service unknown.
fn estate(context: &Context<'_>, input: &EstateInput, read: &mut InputsRead) {
    let mut report = InputReport {
        causes: Vec::new(),
        rejected_rules: Vec::new(),
        label: ESTATE_LABEL.to_owned(),
        kind: "estate",
        component: "estate",
        source: input.path.display().to_string(),
        status: InputStatus::Unavailable,
        error: None,
        identity: Value::Null,
    };
    let document = match load_json(context, None, Some(&input.path), ESTATE_LIMIT) {
        Ok((_, value)) => value,
        Err(error) => {
            report.error = Some(error);
            read.reports.push(report);
            return;
        }
    };
    if document.get("schema").and_then(Value::as_str) != Some("constellation.estate/v1") {
        report.fault(
            "unrecognised",
            InputStatus::NotCurrent,
            "not constellation.estate/v1",
        );
        read.reports.push(report);
        return;
    }
    let generated = document
        .get("generated_at")
        .and_then(Value::as_str)
        .map(rfc3339_seconds);
    let services = document
        .get("services")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let paused: Vec<Value> = services
        .iter()
        .filter(|s| s.get("verdict").and_then(Value::as_str) == Some("PAUSED"))
        .map(|s| {
            json!({
                "name": s.get("name"),
                "since": s.pointer("/declared/since"),
                "reason": s.pointer("/declared/reason").and_then(Value::as_str).map(|r| truncate(r, 160)),
            })
        })
        .collect();
    report.identity = json!({
        "generated_at": document.get("generated_at"),
        "counts": document.get("counts"),
        "paused": paused,
    });
    report.status = InputStatus::Ok;
    let stale = match generated {
        Some(Ok(at)) if context.now - at <= input.max_age_seconds => None,
        Some(Ok(at)) => Some(format!("estate document is {} s old", context.now - at)),
        _ => Some("estate document has no valid generated_at".to_owned()),
    };
    if let Some(note) = &stale {
        report.fault("stale", InputStatus::NotCurrent, note);
    }
    if services.is_empty() {
        report.fault(
            "empty",
            InputStatus::NotCurrent,
            "estate document lists no services",
        );
    }
    read.reports.push(report);
    for service in &services {
        let Some(name) = service.get("name").and_then(Value::as_str) else {
            continue;
        };
        let verdict = service
            .get("verdict")
            .and_then(Value::as_str)
            .unwrap_or("UNKNOWN");
        let reason = service
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let observation = match (stale.is_some(), verdict) {
            (true, _) => Observation::Unknown,
            (false, "DOWN" | "DEGRADED") => Observation::Present,
            (false, "OK" | "PAUSED") => Observation::Clear,
            _ => Observation::Unknown,
        };
        let reference = json!({
            "service": name,
            "verdict": verdict,
            "since": service.get("since"),
            "reason": truncate(reason, 200),
            "generated_at": document.get("generated_at"),
        });
        push(
            context,
            read,
            "service-not-doing-its-job",
            "service",
            Some(name),
            ESTATE_LABEL,
            observation,
            &reference,
            format!("{verdict}: {}", truncate(reason, 200)),
        );
    }
    remediation_journal(
        context,
        read,
        &services,
        stale.as_deref(),
        document.get("generated_at"),
    );
}

/// `remediation-journal-critical`: the remediation consumer's own
/// `generations-critical` concern, as the estate row carries it. `ABSENT` is
/// present, `PRESENT` is clear; a missing row or concern, any other state
/// (`STALE`, `UNKNOWN`, a missing required observation) and a stale document
/// are unknown, which holds an open page and never resolves it.
fn remediation_journal(
    context: &Context<'_>,
    read: &mut InputsRead,
    services: &[Value],
    stale: Option<&str>,
    generated_at: Option<&Value>,
) {
    let row = services
        .iter()
        .find(|s| s.get("name").and_then(Value::as_str) == Some(REMEDIATION_SERVICE));
    let concern = row
        .and_then(|row| row.get("concerns"))
        .and_then(Value::as_array)
        .and_then(|concerns| {
            concerns
                .iter()
                .find(|c| c.get("id").and_then(Value::as_str) == Some(JOURNAL_CRITICAL_CONCERN))
        });
    let state = concern.and_then(|c| c.get("state")).and_then(Value::as_str);
    let reason = concern
        .and_then(|c| c.get("reason"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let verdict = row
        .and_then(|row| row.get("verdict"))
        .and_then(Value::as_str);
    let (observation, note) = match (stale, row, state) {
        (Some(stale), _, _) => (Observation::Unknown, format!("unknown: {stale}")),
        (None, None, _) => (
            Observation::Unknown,
            format!("unknown: the estate document has no {REMEDIATION_SERVICE} row"),
        ),
        (None, Some(_), None) => (
            Observation::Unknown,
            format!(
                "unknown: {REMEDIATION_SERVICE} ({}) carries no {JOURNAL_CRITICAL_CONCERN}",
                verdict.unwrap_or("no verdict")
            ),
        ),
        (None, Some(_), Some("ABSENT")) => (
            Observation::Present,
            format!("{REMEDIATION_SERVICE}: {}", truncate(reason, 200)),
        ),
        (None, Some(_), Some("PRESENT")) => (
            Observation::Clear,
            format!("{REMEDIATION_SERVICE}: {}", truncate(reason, 200)),
        ),
        (None, Some(_), Some(other)) => (
            Observation::Unknown,
            format!(
                "unknown: {JOURNAL_CRITICAL_CONCERN} is {other}: {}",
                truncate(reason, 160)
            ),
        ),
    };
    // "15 sealed segments present (threshold 15, refusal at 16); ...".
    let sealed = reason
        .split_once(" sealed segments")
        .and_then(|(count, _)| count.trim().parse::<u64>().ok());
    let reference = json!({
        "service": REMEDIATION_SERVICE,
        "concern": JOURNAL_CRITICAL_CONCERN,
        "state": state,
        "verdict": verdict,
        "sealed_segments": sealed,
        "observed_at": concern.and_then(|c| c.get("observed_at")),
        "reason": truncate(&note, 200),
        "generated_at": generated_at,
    });
    push(
        context,
        read,
        "remediation-journal-critical",
        "service",
        Some(REMEDIATION_SERVICE),
        ESTATE_LABEL,
        observation,
        &reference,
        note,
    );
}

const METRIC_ALERTS_LIMIT: usize = 4 * 1024 * 1024;
pub const METRIC_ALERTS_SCHEMA: &str = "constellation.metric_alerts/v1";
/// The rule label that opts a vmalert alerting rule into evaluation.
pub const METRIC_ALERTS_OPT_IN_LABEL: &str = "attention";
const METRIC_ALERTS_INSTANCES_IN_NOTE: usize = 4;
const METRIC_ALERTS_DETAIL_BYTES: usize = 480;
const METRIC_INDETERMINATE_RULES_IN_NOTICE: usize = 8;
const METRIC_INDETERMINATE_NOTICE_BYTES: usize = 640;

/// Keep metric notice details within a byte bound without cutting a word.
fn metric_detail(value: &str) -> String {
    truncate_words(value, METRIC_ALERTS_DETAIL_BYTES)
}

/// A vmalert alert name as a condition target: `HostSwapExhausted` is
/// `host-swap-exhausted`. Anything outside `[a-z0-9._-]` becomes `-`.
fn metric_alert_target(name: &str) -> String {
    let mut target = String::with_capacity(name.len() + 4);
    let mut previous_lower = false;
    for ch in name.chars() {
        if ch.is_ascii_uppercase() {
            if previous_lower {
                target.push('-');
            }
            target.push(ch.to_ascii_lowercase());
            previous_lower = false;
        } else if ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '_' | '-') {
            target.push(ch);
            previous_lower = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        } else {
            target.push('-');
            previous_lower = false;
        }
    }
    if target.len() > 48 {
        target.truncate(48);
    }
    target
}

/// The condition target of one alert, keyed by `site` when the input lists
/// sites: `<alert-token>.<site>`. The combined token must still fit the
/// 48-byte target bound; it is never truncated, since a cut site would be a
/// different site.
fn metric_alert_site_target(target: &str, site: Option<&str>) -> Result<String, String> {
    let keyed = match site {
        Some(site) => format!("{target}.{site}"),
        None => target.to_owned(),
    };
    validate_token("target_class", &keyed, 48)?;
    Ok(keyed)
}

/// The longest condition target NQ admits.
pub const TARGET_MAX: usize = 48;

/// One site's condition target of an admitted alert definition.
pub type KeyedTarget<'s> = (Option<&'s str>, String);

/// A derived condition target admission refused, for one site (or for the
/// definition as a whole when `site` is `None` and no site could be keyed).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rejection<'s> {
    pub site: Option<&'s str>,
    pub target: String,
    pub reason: String,
}

/// The admission of one opted-in alert definition: the targets of the sites
/// it may be evaluated for, and the refusals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Admission<'s> {
    /// The alert-name token (cut at 48 bytes).
    pub target: String,
    pub keyed: Vec<KeyedTarget<'s>>,
    pub rejected: Vec<Rejection<'s>>,
}

/// Admission of one opted-in alert definition, before anything is evaluated:
/// its condition target (`<alert-token>`, or `<alert-token>.<site>` for each
/// listed site) must be a bounded condition token. A token that is not one
/// refuses the definition everywhere; a site-keyed target that is not one
/// refuses that (definition, site) only, and the definition is still
/// evaluated on the sites whose target fits. Refusals name the offending
/// target and the byte count. `metric-alerts-collect.py --check-targets`
/// applies the same derivation to a declared policy.
#[must_use]
pub fn admit_metric_alert<'s>(name: &str, sites: &[Option<&'s str>]) -> Admission<'s> {
    let target = metric_alert_target(name);
    let mut admission = Admission {
        target: target.clone(),
        keyed: Vec::with_capacity(sites.len()),
        rejected: Vec::new(),
    };
    if let Err(error) = validate_token("target_class", &target, TARGET_MAX) {
        admission.rejected.push(Rejection {
            site: None,
            target,
            reason: format!("derived target is not a condition token: {error}"),
        });
        return admission;
    }
    for site in sites {
        match metric_alert_site_target(&target, *site) {
            Ok(keyed_target) => admission.keyed.push((*site, keyed_target)),
            Err(error) => {
                let name = site.unwrap_or_default();
                let full = format!("{target}.{name}");
                let reason = if full.len() > TARGET_MAX {
                    format!(
                        "derived target {full:?} is {} bytes ({}-byte alert token, \".\", {}-byte site {name:?}); the condition target bound is {TARGET_MAX} bytes",
                        full.len(),
                        target.len(),
                        name.len()
                    )
                } else {
                    format!("derived target is not a condition token: {error}")
                };
                admission.rejected.push(Rejection {
                    site: *site,
                    target: full,
                    reason,
                });
            }
        }
    }
    admission
}

/// The `site` label of an alert instance.
fn instance_site(instance: &Value) -> Option<&str> {
    instance.pointer("/labels/site").and_then(Value::as_str)
}

const METRIC_VALUE_CODES_LABEL: &str = "constellation_value_codes";

struct MetricValueState {
    present: bool,
    unknown: bool,
    unknown_codes: BTreeMap<u8, String>,
    note: String,
}

fn metric_value_meaning(value: &str) -> Option<&'static str> {
    match value.parse::<f64>().ok()? {
        1.0 => Some("present"),
        2.0 => Some("acquisition_failed"),
        3.0 => Some("missing"),
        4.0 => Some("stale"),
        5.0 => Some("invalid_or_warming"),
        _ => None,
    }
}

/// The producer counts every active instance before bounding detail. Never
/// infer a marked rule's value from its state or its truncated instances.
fn metric_value_state(rule: &Value, site: Option<&str>) -> Result<MetricValueState, String> {
    if rule["labels"][METRIC_VALUE_CODES_LABEL].as_str() != Some("v1") {
        return Err("unsupported constellation_value_codes marker (expected v1)".into());
    }
    if rule["state"] == "inactive" {
        return Ok(MetricValueState {
            present: false,
            unknown: false,
            unknown_codes: BTreeMap::new(),
            note: "no active value codes".into(),
        });
    }
    let counts = rule["value_code_counts"]
        .as_array()
        .ok_or("missing complete value_code_counts; update the metric-alerts collector")?;
    let mut meanings = BTreeMap::new();
    let mut unknown_meanings = BTreeMap::new();
    let mut present = false;
    let mut unknown = false;
    let mut active = false;
    for row in counts {
        let count = row["count"].as_u64().ok_or("invalid value code count")?;
        let row_site = row["site"].as_str().ok_or("invalid value code site")?;
        let state = row["state"].as_str().ok_or("invalid value code state")?;
        let value = row["value"].as_str().ok_or("invalid value code value")?;
        if !matches!(state, "firing" | "pending") {
            return Err("invalid active value code state".into());
        }
        if count == 0 {
            continue;
        }
        active = true;
        if site.is_some_and(|site| site != row_site) {
            continue;
        }
        let code = value.parse::<f64>().ok();
        let meaning = metric_value_meaning(value)
            .ok_or_else(|| format!("value code {value:?} outside 1-5"))?;
        if code == Some(1.0) {
            present |= state == "firing";
        } else {
            unknown = true;
            let number = code.unwrap() as u8;
            unknown_meanings.insert(number, format!("code {number} ({meaning})"));
        }
        meanings.insert(value.to_owned(), format!("value code {value} ({meaning})"));
    }
    if !active {
        return Err("active rule has no complete value code counts".into());
    }
    Ok(MetricValueState {
        present,
        unknown,
        unknown_codes: unknown_meanings,
        note: if meanings.is_empty() {
            "no active value codes for this site".into()
        } else {
            meanings.into_values().collect::<Vec<_>>().join("; ")
        },
    })
}

/// `constellation.metric_alerts/v1`: vmalert's loaded alerting rules with
/// their state. A rule labelled `attention = "true"` is one condition,
/// `host_posture:metric-alert-firing:<alert-name>`: `firing` is present;
/// `pending` or `inactive` is clear; a rule whose health is not `ok`, whose
/// last evaluation is older than `max_evaluation_age_seconds`, or whose
/// document is stale is unknown. A firing alert is still present when the
/// effective policy differs from the declared one, but nothing is clear
/// then: a changed definition's silence is not recovery.
///
/// Rules marked `constellation_value_codes = "v1"` interpret active values
/// through the producer's complete summary: 1 is present, 2 acquisition_failed,
/// 3 missing, 4 stale, 5 invalid_or_warming. Invalid codes reject the rule.
///
/// With `sites`, each opted-in rule is one condition per listed site,
/// `<alert-name>.<site>`, present when a firing instance carries that `site`
/// label and clear when the rule is evaluable and none does; the note and
/// reference carry that site's instances only. Firing instances of unlisted
/// or unlabelled sites are counted (`instances_other_sites`) and named in the
/// first listed site's note, but are no condition.
fn metric_alerts(context: &Context<'_>, input: &MetricAlertsInput, read: &mut InputsRead) {
    let mut report = InputReport {
        causes: Vec::new(),
        rejected_rules: Vec::new(),
        label: input.label.clone(),
        kind: "metric_alerts",
        component: "host_posture",
        source: input.path.display().to_string(),
        status: InputStatus::Unavailable,
        error: None,
        identity: Value::Null,
    };
    let document = match load_json(context, None, Some(&input.path), METRIC_ALERTS_LIMIT) {
        Ok((_, value)) => value,
        Err(error) => {
            report.error = Some(error);
            read.reports.push(report);
            return;
        }
    };
    if document.get("schema").and_then(Value::as_str) != Some(METRIC_ALERTS_SCHEMA) {
        report.fault(
            "unrecognised",
            InputStatus::NotCurrent,
            &format!("not {METRIC_ALERTS_SCHEMA}"),
        );
        read.reports.push(report);
        return;
    }
    let mut history = context
        .metric_alerts
        .cloned()
        .unwrap_or(MetricAlertsHistory {
            first_seen: context.now,
            warming_since: BTreeMap::new(),
        });
    let reconfiguration_grace = context
        .reconfigured_at
        .is_some_and(|at| context.now.saturating_sub(at) < input.warmup_grace);
    let in_grace = context.now - history.first_seen < input.warmup_grace || reconfiguration_grace;
    let mut warming_rules = Vec::new();
    let generated = document
        .get("generated_at")
        .and_then(Value::as_str)
        .map(rfc3339_seconds);
    let rules = document
        .get("rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let opted: Vec<&Value> = rules
        .iter()
        .filter(|rule| {
            rule.pointer(&format!("/labels/{METRIC_ALERTS_OPT_IN_LABEL}"))
                .and_then(Value::as_str)
                == Some("true")
        })
        .collect();
    let effective = document.get("policy_sha256").and_then(Value::as_str);
    let declared = document
        .get("declared_policy_sha256")
        .and_then(Value::as_str);
    report.identity = json!({
        "generated_at": document.get("generated_at"),
        "site": document.get("site"),
        "policy_sha256": effective,
        "declared_policy_sha256": declared,
        "counts": document.get("counts"),
        "attention_rules": opted.iter().filter_map(|r| r.get("name")).collect::<Vec<_>>(),
    });
    report.status = InputStatus::Ok;
    let (generated_at, stale) = match generated {
        Some(Ok(at)) if context.now - at <= input.max_age_seconds => (Some(at), None),
        Some(Ok(at)) => (
            Some(at),
            Some(format!(
                "metric alerts document is {} s old",
                context.now - at
            )),
        ),
        _ => (
            None,
            Some("metric alerts document has no valid generated_at".to_owned()),
        ),
    };
    if let Some(note) = &stale {
        report.fault("stale", InputStatus::NotCurrent, note);
    }
    let drift = match (effective, declared) {
        (Some(effective), Some(declared)) if effective != declared => Some(format!(
            "effective vmalert policy {} is not the declared {}",
            truncate(effective, 19),
            truncate(declared, 19)
        )),
        (None, _) => Some("document carries no policy_sha256".to_owned()),
        _ => None,
    };
    if let Some(note) = &drift {
        report.fault("unrecognised", InputStatus::NotCurrent, note);
    }
    if opted.is_empty() {
        report.fault(
            "empty",
            InputStatus::NotCurrent,
            &format!("no alerting rule carries the label {METRIC_ALERTS_OPT_IN_LABEL}=\"true\""),
        );
    }
    let sites: Vec<Option<&str>> = input.sites.as_ref().map_or_else(
        || vec![None],
        |sites| sites.iter().map(|site| Some(site.as_str())).collect(),
    );
    let listed = |instance: &Value| -> bool {
        instance_site(instance).is_some_and(|site| sites.contains(&Some(site)))
    };
    // Per-definition admission: a definition (or one of its sites) whose
    // condition target cannot be derived is refused alone, and named; every
    // other definition is evaluated as usual. Definitions that share a token
    // are all refused: neither may take over the other's condition, which an
    // open condition then holds as `unreported`.
    let admissions: Vec<(&str, Admission<'_>)> = opted
        .iter()
        .map(|rule| {
            let name = rule.get("name").and_then(Value::as_str).unwrap_or_default();
            (name, admit_metric_alert(name, &sites))
        })
        .collect();
    if stale.is_none() && drift.is_none() && !opted.is_empty() {
        // A current qualified roster ends intervals for retired identities.
        // Per-rule faults retain an identity that is still in the roster;
        // whole-report faults cannot establish that an identity disappeared.
        let identities: BTreeSet<_> = admissions
            .iter()
            .flat_map(|(name, admission)| {
                admission
                    .keyed
                    .iter()
                    .map(move |(_, target)| format!("{name} ({target})"))
            })
            .collect();
        history
            .warming_since
            .retain(|identity, _| identities.contains(identity));
    }
    let mut sharing: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (name, admission) in &admissions {
        if !admission.keyed.is_empty() {
            sharing
                .entry(admission.target.as_str())
                .or_default()
                .push(name);
        }
    }
    let mut observations = Vec::new();
    let mut value_code_notes = Vec::new();
    let mut indeterminate_rules = BTreeMap::new();
    for (rule, (name, admission)) in opted.iter().zip(&admissions) {
        let name = *name;
        for rejection in &admission.rejected {
            report.reject(name, rejection.site, &rejection.target, &rejection.reason);
        }
        let shared = sharing
            .get(admission.target.as_str())
            .filter(|names| names.len() > 1);
        if let Some(names) = shared {
            let names: Vec<String> = names.iter().map(|n| format!("{n:?}")).collect();
            report.reject(
                name,
                None,
                &admission.target,
                &format!(
                    "derived target {:?} is shared by alerts {}",
                    admission.target,
                    names.join(", ")
                ),
            );
            continue;
        }
        let keyed = admission.keyed.clone();
        if keyed.is_empty() {
            continue;
        }
        // Validate the complete rule before considering any site. A bad value
        // rejects this definition alone, so it can neither trigger nor recover
        // a condition, including when the bad instance's detail was truncated.
        let marked = rule["labels"].get(METRIC_VALUE_CODES_LABEL).is_some();
        if marked && let Err(error) = metric_value_state(rule, None) {
            report.reject(name, None, &admission.target, &error);
            continue;
        }
        let state = rule.get("state").and_then(Value::as_str).unwrap_or("");
        let health = rule.get("health").and_then(Value::as_str).unwrap_or("");
        let last_evaluation = rule
            .get("last_evaluation")
            .and_then(Value::as_str)
            .map(rfc3339_seconds);
        let missing_evaluation = !matches!(last_evaluation, Some(Ok(_)));
        let evaluation_warming = missing_evaluation && reconfiguration_grace;
        let mut problems: Vec<String> = Vec::new();
        if health != "ok" {
            let error = rule
                .get("last_error")
                .and_then(Value::as_str)
                .unwrap_or_default();
            problems.push(format!(
                "health {health:?}: {}",
                truncate(error.trim(), 120)
            ));
        }
        match (generated_at, last_evaluation) {
            (Some(at), Some(Ok(evaluated)))
                if at - evaluated <= input.max_evaluation_age_seconds => {}
            (Some(at), Some(Ok(evaluated))) => problems.push(format!(
                "last evaluated {} s before the document",
                at - evaluated
            )),
            (Some(_), _) if evaluation_warming => {}
            _ => problems.push("has no valid last_evaluation".to_owned()),
        }
        if !matches!(state, "firing" | "pending" | "inactive") {
            problems.push(format!("state {state:?} is not recognised"));
        }
        for problem in &problems {
            report.fault(
                if problem.starts_with("state ") {
                    "unrecognised"
                } else {
                    "indeterminate"
                },
                InputStatus::NotCurrent,
                &format!("alert {name}: {problem}"),
            );
        }
        let instances = rule
            .get("instances")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let firing: Vec<&Value> = instances
            .iter()
            .filter(|i| i.get("state").and_then(Value::as_str) == Some("firing"))
            .collect();
        // Firing instances of sites the input does not key: counted and
        // named once, never a condition.
        let other_sites: Vec<&Value> = if input.sites.is_some() {
            firing.iter().copied().filter(|i| !listed(i)).collect()
        } else {
            Vec::new()
        };
        // vmalert's own data-presence counter: an inactive rule whose query fetched
        // no series has no evidence either way. A positive fetched count with
        // zero result samples cannot distinguish a healthy false comparison
        // from a missing operand (e.g. offset history). Leave plain rules alone;
        // definitions needing that distinction must emit explicit value codes.
        let no_data =
            state != "firing" && rule.get("last_series_fetched").and_then(Value::as_i64) == Some(0);
        // The producer's complete per-site firing summary, computed before it
        // truncates instance detail; instances alone could omit a site's firing
        // instance at high fan-out.
        let firing_sites = rule.get("firing_sites").and_then(Value::as_object);
        let unknown = stale.is_some() || !problems.is_empty() || missing_evaluation;
        let evaluation_note = evaluation_warming
            .then(|| "has no valid last_evaluation; warming after reconfiguration".to_owned());
        let unknown_why = stale
            .iter()
            .chain(problems.iter())
            .chain(drift.iter())
            .chain(evaluation_note.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join("; ");
        for (index, (site, keyed_target)) in keyed.into_iter().enumerate() {
            if !marked && !unknown && !no_data && drift.is_none() {
                history
                    .warming_since
                    .remove(&format!("{name} ({keyed_target})"));
            }
            if evaluation_warming {
                let since = *history
                    .warming_since
                    .entry(format!("{name} ({keyed_target})"))
                    .or_insert(context.now);
                let expired = context.now - since >= input.warming_bound;
                if expired {
                    report.fault(
                        "indeterminate",
                        InputStatus::NotCurrent,
                        &format!(
                            "alert {name} ({keyed_target}): has no valid last_evaluation; warming bound exceeded"
                        ),
                    );
                }
                if !marked {
                    warming_rules.push(json!({
                        "rule": name, "target": keyed_target, "codes": [],
                        "since": format_seconds(since), "elapsed_seconds": context.now - since,
                        "bound_exceeded": expired, "since_reconfiguration": true,
                    }));
                }
            }
            let mine: Vec<&Value> = match site {
                Some(site) => firing
                    .iter()
                    .copied()
                    .filter(|i| instance_site(i) == Some(site))
                    .collect(),
                None => firing.clone(),
            };
            let mut present = match site {
                Some(site) => match firing_sites {
                    Some(summary) => summary
                        .get(site)
                        .and_then(Value::as_u64)
                        .is_some_and(|n| n > 0),
                    None => !mine.is_empty(),
                },
                None => state == "firing",
            };
            let mut code_unknown = false;
            let code_note = if marked {
                let note = match metric_value_state(rule, site) {
                    Ok(value) => {
                        present = value.present;
                        code_unknown = value.unknown;
                        let identity = format!("{name} ({keyed_target})");
                        let warming_codes: Vec<_> = value
                            .unknown_codes
                            .iter()
                            .filter(|(code, _)| {
                                **code == 5 || (in_grace && matches!(**code, 2 | 3))
                            })
                            .map(|(code, _)| *code)
                            .collect();
                        let warming_since = if warming_codes.is_empty() && !evaluation_warming {
                            // An unqualified report cannot reset a warming interval.
                            if !unknown && !value.unknown && !no_data && drift.is_none() {
                                history.warming_since.remove(&identity);
                            }
                            None
                        } else {
                            Some(
                                *history
                                    .warming_since
                                    .entry(identity.clone())
                                    .or_insert(context.now),
                            )
                        };
                        let expired = warming_since
                            .is_some_and(|since| context.now - since >= input.warming_bound);
                        if let Some(since) = warming_since {
                            let mut warming = json!({
                                "rule": name,
                                "target": keyed_target,
                                "codes": warming_codes,
                                "since": format_seconds(since),
                                "elapsed_seconds": context.now - since,
                                "bound_exceeded": expired,
                            });
                            if reconfiguration_grace
                                && (evaluation_warming
                                    || warming_codes.iter().any(|code| matches!(code, 2 | 3)))
                            {
                                warming["since_reconfiguration"] = json!(true);
                            }
                            warming_rules.push(warming);
                        }
                        let mut fault_codes = value
                            .unknown_codes
                            .iter()
                            .filter(|(code, _)| expired || !warming_codes.contains(code))
                            .map(|(_, meaning)| meaning.as_str())
                            .collect::<Vec<_>>()
                            .join(", ");
                        if expired
                            && !fault_codes.is_empty()
                            && let Some(since) = warming_since
                        {
                            let elapsed = context.now - since;
                            let bound = input.warming_bound;
                            let bound_text = if bound % 3600 == 0 {
                                format!("{}h", bound / 3600)
                            } else if bound % 60 == 0 {
                                format!("{}m", bound / 60)
                            } else {
                                format!("{bound}s")
                            };
                            fault_codes.push_str(&format!(
                                "; warming for {}h {}m (bound {bound_text})",
                                elapsed / 3600,
                                elapsed % 3600 / 60,
                            ));
                        }
                        if !fault_codes.is_empty() {
                            report.fault(
                                "indeterminate",
                                InputStatus::NotCurrent,
                                &format!("alert {identity}: value {fault_codes}"),
                            );
                            indeterminate_rules.insert(identity, fault_codes);
                        }
                        value.note
                    }
                    Err(error) => {
                        code_unknown = true;
                        error
                    }
                };
                value_code_notes.push(format!("{keyed_target}: {}", truncate(&note, 160)));
                Some(note)
            } else {
                None
            };
            let observation = if unknown {
                Observation::Unknown
            } else if present {
                // Coverage families share one condition across instances. A
                // qualified code 1 proves presence even with partial coverage;
                // other codes remain visible as warming or input faults.
                Observation::Present
            } else if code_unknown || no_data || drift.is_some() {
                Observation::Unknown
            } else {
                Observation::Clear
            };
            let mut reason: Vec<String> = mine
                .iter()
                .take(METRIC_ALERTS_INSTANCES_IN_NOTE)
                .map(|i| {
                    let detail = describe_metric_instance(i);
                    let value = i["value"].as_str().unwrap_or_default();
                    match marked.then(|| metric_value_meaning(value)).flatten() {
                        Some(meaning) if meaning != "present" => {
                            format!("held unknown (code {value}: {meaning}) on {detail}")
                        }
                        _ => format!("firing on {detail}"),
                    }
                })
                .collect();
            if mine.len() > METRIC_ALERTS_INSTANCES_IN_NOTE {
                reason.push(format!(
                    "and {} more",
                    mine.len() - METRIC_ALERTS_INSTANCES_IN_NOTE
                ));
            }
            let reason = if !reason.is_empty() {
                format!("{name} {}", reason.join("; "))
            } else if let Some(site) = site {
                format!("{state}; nothing firing on {site}")
            } else {
                state.to_owned()
            };
            let since = mine
                .iter()
                .filter_map(|i| i.get("active_at").and_then(Value::as_str))
                .min();
            let mut reference = json!({
                "alert": name,
                "file": rule.get("file"),
                "group": rule.get("group"),
                "state": state,
                "health": health,
                "since": since,
                "instance_count": rule.get("instance_count"),
                "last_samples": rule.get("last_samples"),
                "last_series_fetched": rule.get("last_series_fetched"),
                "firing_sites": rule.get("firing_sites"),
                "instances": mine.iter().take(8).map(|i| json!({
                    "labels": i.get("labels"),
                    "active_at": i.get("active_at"),
                    "value": i.get("value"),
                    "summary": i.get("summary").and_then(Value::as_str).map(metric_detail),
                })).collect::<Vec<_>>(),
                "reason": metric_detail(&reason),
                "problems": problems,
                "last_evaluation": rule.get("last_evaluation"),
                "generated_at": document.get("generated_at"),
                "policy_sha256": effective,
            });
            if let Some(note) = &code_note {
                reference["value_codes"] = rule["labels"][METRIC_VALUE_CODES_LABEL].clone();
                reference["value_code_note"] = json!(note);
                reference["value_code_counts"] = rule["value_code_counts"].clone();
            }
            if let Some(site) = site {
                reference["site"] = json!(site);
                reference["instances_other_sites"] = json!(other_sites.len());
            }
            let mut note = match observation {
                Observation::Unknown if code_unknown => format!(
                    "{name} unknown: {}{}",
                    code_note.as_deref().unwrap_or_default(),
                    if unknown_why.is_empty() {
                        String::new()
                    } else {
                        format!("; {unknown_why}")
                    },
                ),
                Observation::Unknown if !unknown && no_data => format!(
                    "{name} unknown: query fetched no series (metric missing, or its window has no history yet)"
                ),
                Observation::Present => metric_detail(&reason),
                Observation::Clear => match site {
                    Some(site) => format!("{name} {state}; nothing firing on {site}"),
                    None => format!("{name} {state}"),
                },
                _ => format!("{name} unknown: {}", truncate(&unknown_why, 160)),
            };
            if let Some(code_note) = &code_note
                && (!code_unknown || observation == Observation::Present)
            {
                note.push_str(&format!("; {code_note}"));
            }
            if index == 0 && !other_sites.is_empty() {
                let mut names: Vec<&str> = other_sites
                    .iter()
                    .map(|i| instance_site(i).unwrap_or("(no site label)"))
                    .collect();
                names.sort_unstable();
                names.dedup();
                note.push_str(&format!(
                    "; {} firing on unlisted sites ({})",
                    other_sites.len(),
                    truncate(&names.join(", "), 80)
                ));
            }
            observations.push((keyed_target, observation, reference, note));
        }
    }
    if !warming_rules.is_empty() {
        report.causes.push("warming");
        report.identity["warming_rules"] = json!(warming_rules);
    }
    report.identity["first_seen"] = json!(format_seconds(history.first_seen));
    report.identity["warmup_grace"] = json!(input.warmup_grace);
    report.identity["warming_bound"] = json!(input.warming_bound);
    read.metric_alerts = Some(history);
    if !indeterminate_rules.is_empty() {
        // Whole identities only: cap both fan-out and bytes, reserving room
        // for the omitted count. Complete counts survive truncated instances.
        let mut details = Vec::new();
        for (identity, codes) in indeterminate_rules
            .iter()
            .take(METRIC_INDETERMINATE_RULES_IN_NOTICE)
        {
            let detail = format!("{identity}: {codes}");
            if details.join("; ").len() + detail.len() + 40 > METRIC_INDETERMINATE_NOTICE_BYTES {
                break;
            }
            details.push(detail);
        }
        if indeterminate_rules.len() > details.len() {
            details.push(format!(
                "+{} more",
                indeterminate_rules.len() - details.len()
            ));
        }
        read.metric_indeterminate_reason =
            Some(format!("indeterminate rules: {}", details.join("; ")));
    }
    if !value_code_notes.is_empty() {
        report.identity["value_code_notes"] = json!(value_code_notes);
    }
    read.reports.push(report);
    for (target, observation, reference, note) in observations {
        push(
            context,
            read,
            "metric-alert-firing",
            "host_posture",
            Some(&target),
            &input.label,
            observation,
            &reference,
            note,
        );
    }
}

/// One instance for a note: `<site> (<instance or host>): <summary>`,
/// or just `<site>: <summary>` when neither instance nor host is available.
fn describe_metric_instance(instance: &Value) -> String {
    let labels = instance.get("labels");
    let site = instance_site(instance).unwrap_or("(no site label)");
    let host = labels
        .and_then(|l| l.get("instance"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            labels
                .and_then(|l| l.get("host"))
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
        });
    let summary = instance
        .get("summary")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let location = match host {
        Some(host) => format!("{site} ({host})"),
        None => site.to_owned(),
    };
    format!("{location}: {}", metric_detail(summary.trim()))
}

#[cfg(test)]
mod metric_alert_tests {
    use super::{
        METRIC_ALERTS_DETAIL_BYTES, admit_metric_alert, metric_alert_site_target,
        metric_alert_target, metric_detail,
    };

    #[test]
    fn notice_detail_is_bounded_at_a_word_boundary_with_an_ellipsis() {
        let prefix = "complete words ".repeat(30);
        let detail = format!("{prefix}{}", "é".repeat(100));
        let shortened = metric_detail(&detail);
        assert_eq!(shortened, format!("{}…", prefix.trim_end()));
        assert!(shortened.len() <= METRIC_ALERTS_DETAIL_BYTES);
        assert_eq!(metric_detail(&"é".repeat(300)), "…");
        let exact = "x".repeat(METRIC_ALERTS_DETAIL_BYTES);
        assert_eq!(metric_detail(&exact), exact);
    }

    /// The shared admission vector: `metric-alerts-collect.py --check-targets`
    /// derives and refuses exactly the same targets.
    #[test]
    fn admission_matches_the_shared_target_vector() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../estate/fixtures/metric-alert-targets-v1.json"
        ))
        .unwrap();
        for case in vector["cases"].as_array().unwrap() {
            let alert = case["alert"].as_str().unwrap();
            let site = case["site"].as_str();
            let admission = admit_metric_alert(alert, &[site]);
            let admitted = admission.rejected.is_empty();
            let target = match admission.rejected.first() {
                Some(rejection) => rejection.target.clone(),
                None => admission.keyed[0].1.clone(),
            };
            assert_eq!(case["admitted"].as_bool().unwrap(), admitted, "{case}");
            assert_eq!(case["target"].as_str().unwrap(), target, "{case}");
            assert_eq!(
                case["bytes"].as_u64().unwrap(),
                target.len() as u64,
                "{case}"
            );
        }
    }

    /// Definitions sharing a token are all refused (the evaluator's tests
    /// show it end to end); the vector names groups that share one.
    #[test]
    fn shared_vector_collisions_share_a_token() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../estate/fixtures/metric-alert-targets-v1.json"
        ))
        .unwrap();
        for group in vector["collisions"].as_array().unwrap() {
            for alert in group["alerts"].as_array().unwrap() {
                assert_eq!(
                    metric_alert_target(alert.as_str().unwrap()),
                    group["target"].as_str().unwrap(),
                    "{group}"
                );
            }
        }
    }

    /// One site's overflow refuses that site only.
    #[test]
    fn an_overflowing_site_is_refused_alone() {
        let admission = admit_metric_alert(
            "HostMetricsAcquisitionNeedsAttention",
            &[Some("testbed"), Some("labelwatch")],
        );
        assert_eq!(
            admission.keyed,
            [(
                Some("testbed"),
                "host-metrics-acquisition-needs-attention.testbed".to_owned()
            )]
        );
        assert_eq!(admission.rejected.len(), 1);
        assert_eq!(admission.rejected[0].site, Some("labelwatch"));
        assert!(admission.rejected[0].reason.contains("is 51 bytes"));
        let admission = admit_metric_alert("-Leading", &[Some("crow")]);
        assert!(admission.keyed.is_empty());
        assert_eq!(admission.rejected[0].site, None);
    }

    /// The 2026-10-22 testbed drill: the 43-byte token of
    /// `ServiceMetricsObservationNeedsAttention` keyed by `.testbed` is 51
    /// bytes, and the refusal says so.
    #[test]
    fn the_drill_rule_is_refused_with_its_byte_count() {
        let admission = admit_metric_alert(
            "ServiceMetricsObservationNeedsAttention",
            &[Some("testbed")],
        );
        assert!(admission.keyed.is_empty());
        let (target, reason) = (&admission.rejected[0].target, &admission.rejected[0].reason);
        assert_eq!(
            target,
            "service-metrics-observation-needs-attention.testbed"
        );
        assert_eq!(
            reason,
            "derived target \"service-metrics-observation-needs-attention.testbed\" is 51 bytes (43-byte alert token, \".\", 7-byte site \"testbed\"); the condition target bound is 48 bytes"
        );
    }

    #[test]
    fn alert_names_become_stable_targets() {
        assert_eq!(
            metric_alert_target("HostSwapExhausted"),
            "host-swap-exhausted"
        );
        assert_eq!(
            metric_alert_target("HostIoPressureHigh"),
            "host-io-pressure-high"
        );
        assert_eq!(metric_alert_target("NQ2Down"), "nq2-down");
        assert_eq!(
            metric_alert_target("already-kebab_case.1"),
            "already-kebab_case.1"
        );
        assert_eq!(
            metric_alert_target("Spaces And/Slashes"),
            "spaces-and-slashes"
        );
        assert_eq!(metric_alert_target(&"A".repeat(60)).len(), 48);
    }

    /// A site-keyed target is `<alert>.<site>` and must fit the 48-byte
    /// target bound without truncation.
    #[test]
    fn site_keyed_targets_keep_the_target_bound() {
        assert_eq!(
            metric_alert_site_target("host-swap-exhausted", Some("crow")).unwrap(),
            "host-swap-exhausted.crow"
        );
        assert_eq!(
            metric_alert_site_target("host-swap-exhausted", None).unwrap(),
            "host-swap-exhausted"
        );
        let base = "z".repeat(43);
        assert_eq!(
            metric_alert_site_target(&base, Some("crow")).unwrap().len(),
            48
        );
        let base = "z".repeat(44);
        assert!(metric_alert_site_target(&base, Some("crow")).is_err());
        assert!(metric_alert_site_target(&base, None).is_ok());
        let base = "z".repeat(48);
        assert!(metric_alert_site_target(&base, Some("x")).is_err());
    }
}
