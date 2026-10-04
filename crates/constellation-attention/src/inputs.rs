//! Read the configured inputs and turn qualified current state into
//! three-valued observations. Nothing here decides attention; it only says
//! whether each rule's underlying state is present, clear or not knowable now.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

use constellation_status_projection::{ModeV1, ProjectedStateV1, read_current_artifact};
use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use serde_json::{Value, json};

use crate::condition::{ConditionKey, validate_token};
use crate::config::{
    Config, EffectiveRule, HostPostureInput, NightshiftInput, NqStatusInput, NqStatusSource,
    SavedCheckInput,
};
use crate::util::{
    ChildEnvironment, excerpt, format_seconds, parse_rfc3339, read_bounded, rfc3339_seconds,
    run_bounded, truncate,
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
    /// Why the input is not `ok`, one class per kind of fault
    /// ([`INPUT_CAUSES`]). Each class is its own
    /// `evaluator-input-unavailable` condition, so a lasting fault of one
    /// class never masks a later fault of another.
    pub causes: Vec<&'static str>,
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
];

impl InputReport {
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
    /// Evaluation-history mode: the NQ status input's label and its updated
    /// watcher roster, to be remembered in the state.
    pub nq_watchers: Option<(String, BTreeMap<String, i64>)>,
}

pub struct Context<'a> {
    pub config: &'a Config,
    pub rules: &'a [EffectiveRule],
    pub now: i64,
    pub now_ms: i64,
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
            FILESYSTEM_PROFILE,
        ]
        .contains(&profile.as_str())
            || [
                SYSTEMD_UNIT_CONDITION,
                HOST_MEMORY_CONDITION,
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
        let filesystem = profile == FILESYSTEM_PROFILE
            && version == Some(FILESYSTEM_VERSION)
            && condition == FILESYSTEM_CONDITION;
        if !systemd && !host_memory && !filesystem {
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
}

fn nightshift(context: &Context<'_>, input: &NightshiftInput, read: &mut InputsRead) {
    let mut report = InputReport {
        causes: Vec::new(),
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
        report.fault(
            "empty",
            InputStatus::NotCurrent,
            "no closed observation cycle",
        );
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
