//! One evaluation pass: read inputs, reconcile conditions with state, emit
//! intents through NQ, write the report.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{Value, json};

use crate::condition::ConditionKey;
use crate::config::{Config, EffectiveRule};
use crate::inputs::{self, Context, INPUT_CAUSES, InputReport, InputStatus, Observation, Observed};
use crate::intent::{self, Action, INTENT_V1, INTENT_V2, IntentInput, ResolveReason};
use crate::nq;
use crate::registry::{
    Class, InputKind, REGISTRY_VERSION, RESEND_INTERVAL_SECONDS, RESOLVE_CONFIRM_SECONDS,
    UNKNOWN_GAP_SECONDS,
};
use crate::state::{ConditionState, LastIntent, State};
use crate::util::{format_seconds, read_bounded, write_atomic};

pub const REPORT_SCHEMA: &str = "constellation.attention_report.v1";
const INPUT_UNAVAILABLE: &str = "evaluator-input-unavailable";

pub struct PassOptions {
    pub dry_run: bool,
    /// Unix seconds and milliseconds of "now".
    pub now: i64,
    pub now_ms: i64,
}

pub struct PassResult {
    pub report: Value,
    /// 0 clean; 3 an input was not current/readable or a delivery was not accepted.
    pub exit_code: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    /// `nq notification submit` of a new intent file.
    Submit,
    /// `nq notification submit` of an already written file (idempotent: NQ
    /// returns the existing record if it retained this exact event).
    SubmitAgain,
    /// `nq notification resubmit` of the newest retained v2 record.
    Resubmit,
    /// The same bytes of a trigger NQ never retained, submitted before the
    /// resolve that replaced it.
    SubmitBeforeResolve,
}

struct Planned {
    condition_id: String,
    role: String,
    action: Action,
    operation: Operation,
    retry_of: Option<String>,
}

#[derive(Serialize)]
struct IntentReport {
    condition_id: String,
    route_role: String,
    route: String,
    schema: String,
    action: String,
    operation: Operation,
    stable_event_id: String,
    transition_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_of: Option<String>,
    intent_file: String,
    outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    notification_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn rule_for<'a>(rules: &'a [EffectiveRule], id: &str) -> Option<&'a EffectiveRule> {
    rules.iter().find(|rule| rule.rule.id == id)
}

/// Lifecycle step for one condition. Returns the transition decided now.
pub fn step(
    condition: &mut ConditionState,
    observation: Observation,
    persistence_seconds: i64,
    now: i64,
) -> Option<Action> {
    // Time spent unknown never counts toward an interval, and never erases
    // the observed part of it either: a run of unknown observations longer
    // than one pass interval moves the interval's start forward by the run's
    // length. A condition that is present whenever it can be observed still
    // reaches its bound, on present observations only.
    let shift = condition
        .unknown_since
        .map(|since| now - since)
        .filter(|run| *run > UNKNOWN_GAP_SECONDS);
    if observation != Observation::Unknown {
        condition.unknown_since = None;
    }
    match observation {
        Observation::Present => {
            if let (Some(run), false) = (shift, condition.active)
                && let Some(first_seen) = condition.first_seen.as_mut()
            {
                *first_seen = (*first_seen + run).min(now);
            }
            let first_seen = *condition.first_seen.get_or_insert(now);
            condition.last_seen = Some(now);
            condition.clear_since = None;
            if !condition.active && now - first_seen > persistence_seconds {
                condition.active = true;
                condition.transition_at = Some(now);
                return Some(Action::Trigger);
            }
        }
        Observation::Clear => {
            if condition.active {
                if let (Some(run), Some(since)) = (shift, condition.clear_since.as_mut()) {
                    *since = (*since + run).min(now);
                }
                let since = *condition.clear_since.get_or_insert(now);
                if now - since >= RESOLVE_CONFIRM_SECONDS {
                    condition.active = false;
                    condition.first_seen = None;
                    condition.clear_since = None;
                    condition.transition_at = Some(now);
                    return Some(Action::Resolve);
                }
            } else {
                // Presence below the bound must be continuous; a clear pass restarts it.
                condition.first_seen = None;
                condition.clear_since = None;
            }
        }
        Observation::Unknown => {
            // Hold everything; remember when the unknown run began if an
            // interval is open.
            let open = if condition.active {
                condition.clear_since.is_some()
            } else {
                condition.first_seen.is_some()
            };
            if open {
                condition.unknown_since.get_or_insert(now);
            }
        }
        Observation::Removed => {
            condition.unknown_since = None;
            condition.first_seen = None;
            condition.clear_since = None;
            if condition.active {
                condition.active = false;
                condition.transition_at = Some(now);
                return Some(Action::Resolve);
            }
        }
    }
    None
}

/// Whether a retained intent still needs work, ignoring the resend interval.
/// Returns the operation and whether it waits for the interval.
fn follow_up(
    last: &LastIntent,
    condition: &ConditionState,
    config: &Config,
) -> Option<(Operation, bool)> {
    let relevant = match Action::parse(&last.action) {
        Some(Action::Trigger) => condition.active,
        Some(Action::Resolve) => !condition.active,
        None => false,
    };
    if !relevant {
        return None;
    }
    match (last.outcome.as_str(), &last.notification_id) {
        // Written, maybe submitted, never answered, or refused by the nq
        // command before custody: NQ retains nothing, so the same bytes go
        // again on the next pass. NQ answers an exact repeat idempotently.
        ("unknown" | "command_error", None) => Some((Operation::SubmitAgain, false)),
        ("accepted", _) => None,
        // A deliberate refusal (no network) is final until network is enabled.
        (_, Some(_)) if !config.routes.delivers(&last.schema) => None,
        // PagerDuty: NQ allows resubmitting the newest failed/unknown/refused/pending record.
        (_, Some(_)) if last.schema == INTENT_V2 => Some((Operation::Resubmit, true)),
        // Slack/Discord/local inbox: a new event only after a definite
        // non-delivery, never over an uncertain attempt.
        ("failed" | "refused", Some(_)) => Some((Operation::Submit, true)),
        _ => None,
    }
}

struct Lock {
    _file: Option<File>,
}

fn lock(config: &Config, dry_run: bool) -> Result<Lock, String> {
    let path = config.state_dir().join(format!(
        "{}.lock",
        config
            .state_path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
    ));
    if dry_run {
        // Never create the lock as a different account; share it when present.
        let Ok(file) = File::open(&path) else {
            return Ok(Lock { _file: None });
        };
        return match file.try_lock_shared() {
            Ok(()) => Ok(Lock { _file: Some(file) }),
            Err(_) => Err("another evaluation pass holds the state lock".into()),
        };
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(&path)
        .map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(Lock { _file: Some(file) }),
        Err(_) => Err("another evaluation pass holds the state lock".into()),
    }
}

fn ensure_dir(path: &Path) -> Result<(), String> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))
}

#[allow(
    clippy::too_many_lines,
    reason = "The pass is one ordered sequence: read, reconcile, persist, submit, report."
)]
pub fn evaluate(config: &Config, options: &PassOptions) -> Result<PassResult, String> {
    let rules = config.effective_rules();
    let digest = intent::policy_digest(&rules);
    let state_dir = config.state_dir();
    let output_dir = if options.dry_run {
        state_dir.join("dry-run")
    } else {
        state_dir.clone()
    };
    let _lock = lock(config, options.dry_run)?;
    let mut state = State::load(&config.state_path, &config.site)?;
    let now = options.now;
    if now < state.updated_at {
        // Event identities carry the decision time; a pass earlier than the
        // last one could replay an identity NQ already holds for another
        // incident.
        return Err(format!(
            "refusing the pass: now ({}) is earlier than the last completed pass ({}); \
             the clock moved backwards",
            format_seconds(now),
            format_seconds(state.updated_at)
        ));
    }

    let context = Context {
        config,
        rules: &rules,
        now,
        now_ms: options.now_ms,
    };
    let mut read = inputs::read_all(&context);
    let mut observed: BTreeMap<String, Observed> = BTreeMap::new();
    for item in read.observed {
        observed.entry(item.key.id()).or_insert(item);
    }
    // An open condition that a current input no longer reports has not been
    // observed to recover. Hold it, and report the input as not current so
    // `evaluator-input-unavailable` tells the operator.
    let current_labels: BTreeSet<String> = read
        .reports
        .iter()
        .filter(|report| report.status == InputStatus::Ok)
        .map(|report| report.label.clone())
        .collect();
    for (id, condition) in &state.conditions {
        if !condition.active
            || observed.contains_key(id)
            || condition.key.rule == INPUT_UNAVAILABLE
            || !current_labels.contains(&condition.input_label)
        {
            continue;
        }
        let Some(rule) = rule_for(&rules, &condition.key.rule) else {
            continue;
        };
        if !rule.enabled || !config.has_input(rule.rule.input) {
            continue;
        }
        if let Some(report) = read
            .reports
            .iter_mut()
            .find(|report| report.label == condition.input_label)
        {
            report.fault(
                "unreported",
                InputStatus::NotCurrent,
                &format!("open condition {id} is no longer reported; recovery not observed"),
            );
        }
    }
    if rule_for(&rules, INPUT_UNAVAILABLE).is_some_and(|rule| rule.enabled) {
        for report in &read.reports {
            for cause in INPUT_CAUSES {
                // A stale host-posture CURRENT is `host-posture-unknown`.
                if report.kind == "host_posture" && *cause == "stale" {
                    continue;
                }
                let Ok(key) = ConditionKey::new(
                    &config.site,
                    report.component,
                    INPUT_UNAVAILABLE,
                    Some(&format!("{}.{cause}", report.label)),
                ) else {
                    continue;
                };
                observed.entry(key.id()).or_insert(Observed {
                    key,
                    rule: INPUT_UNAVAILABLE,
                    input_label: report.label.clone(),
                    observation: if report.causes.contains(cause) {
                        Observation::Present
                    } else {
                        Observation::Clear
                    },
                    reference: json!({
                        "input": report.label,
                        "kind": report.kind,
                        "status": report.status,
                        "cause": cause,
                    }),
                    note: if report.causes.contains(cause) {
                        report.error.clone().unwrap_or_default()
                    } else {
                        String::new()
                    },
                });
            }
        }
    }

    let input_status: BTreeMap<&str, InputStatus> = read
        .reports
        .iter()
        .map(|report| (report.label.as_str(), report.status))
        .collect();

    let ids: BTreeSet<String> = observed
        .keys()
        .cloned()
        .chain(state.conditions.keys().cloned())
        .collect();
    let mut transitions: Vec<(String, Action, ResolveReason)> = Vec::new();
    let mut condition_reports = Vec::new();
    for id in &ids {
        let item = observed.get(id);
        let condition = state.conditions.entry(id.clone()).or_insert_with(|| {
            let item = item.expect("new conditions come from observations");
            ConditionState {
                key: item.key.clone(),
                rule_version: crate::registry::rule(item.rule).map_or(0, |rule| rule.version),
                input_label: item.input_label.clone(),
                first_seen: None,
                last_seen: None,
                clear_since: None,
                unknown_since: None,
                active: false,
                transition_at: None,
                last_intent: BTreeMap::new(),
                pending_trigger: BTreeMap::new(),
            }
        });
        if let Some(item) = item {
            // The input that reports a condition can be relabelled; follow it.
            condition.input_label.clone_from(&item.input_label);
        }
        let rule = rule_for(&rules, &condition.key.rule);
        let (observation, note) = if let Some(item) = item {
            (item.observation, item.note.clone())
        } else if condition.key.rule == INPUT_UNAVAILABLE {
            // Every configured input reports every fault class, so an
            // unreported one names a removed input or an older key format.
            (
                Observation::Removed,
                "input or fault class no longer evaluated".into(),
            )
        } else {
            match rule {
                Some(rule) if rule.enabled && config.has_input(rule.rule.input) => {
                    match input_status.get(condition.input_label.as_str()) {
                        // Absence is not recovery.
                        Some(InputStatus::Ok) => (
                            Observation::Unknown,
                            "not reported by a current input; recovery not observed".into(),
                        ),
                        Some(_) => (Observation::Unknown, "input not current".into()),
                        // The label names the condition (its target class):
                        // removing it is an explicit configuration removal.
                        None if rule.rule.input != InputKind::NqStatus => {
                            (Observation::Removed, "input no longer configured".into())
                        }
                        // NQ status conditions are keyed on units, not on
                        // the input label; the input kind is still
                        // configured, so a relabel is not a removal.
                        None => (
                            Observation::Unknown,
                            "input label changed; not yet observed under the new label".into(),
                        ),
                    }
                }
                _ => (
                    Observation::Removed,
                    "rule disabled or its input kind not configured".into(),
                ),
            }
        };
        let persistence = rule.map_or(0, EffectiveRule::persistence_seconds);
        let transition = step(condition, observation, persistence, now);
        if let Some(action) = transition {
            let reason = if observation == Observation::Removed {
                ResolveReason::NoLongerEvaluated
            } else {
                ResolveReason::Recovered
            };
            transitions.push((id.clone(), action, reason));
        }
        condition_reports.push(json!({
            "id": id,
            "rule": condition.key.rule,
            "observation": observation,
            "note": note,
            "reference": item.map(|item| item.reference.clone()),
            "first_seen": condition.first_seen.map(format_seconds),
            "unknown_since": condition.unknown_since.map(format_seconds),
            "persisted_seconds": condition.first_seen.map(|first| now - first),
            "persistence_bound_seconds": persistence,
            "active": condition.active,
            "transition": transition.map(Action::as_str),
        }));
    }

    // Plan: one intent per condition and route per pass.
    let intents_dir = output_dir.join("intents");
    ensure_dir(&intents_dir)?;
    let mut plan: Vec<Planned> = Vec::new();
    let notice_route = config.routes.notice_route.clone();
    for (id, action, reason) in &transitions {
        let condition = state
            .conditions
            .get_mut(id)
            .expect("transitioned condition");
        let Some(rule) = rule_for(&rules, &condition.key.rule) else {
            continue;
        };
        let mut roles: Vec<(String, String)> = Vec::new();
        match action {
            Action::Trigger => {
                if rule.class == Class::Page
                    && let Some(page) = &config.routes.page_route
                {
                    roles.push(("page".into(), page.clone()));
                }
                roles.push(("notice".into(), notice_route.clone()));
            }
            Action::Resolve => {
                for (role, last) in &condition.last_intent {
                    roles.push((role.clone(), last.route.clone()));
                }
                if roles.is_empty() {
                    roles.push(("notice".into(), notice_route.clone()));
                }
            }
        }
        let stable_event_id = intent::event_id(&condition.key, *action, now);
        let reference = observed
            .get(id)
            .map_or(Value::Null, |item| item.reference.clone());
        let persisted = condition.first_seen.map_or(0, |first| now - first);
        let input = IntentInput {
            config,
            rule,
            key: &condition.key,
            action: *action,
            resolve_reason: *reason,
            stable_event_id: &stable_event_id,
            transition_id: &stable_event_id,
            policy_digest: &digest,
            first_seen: condition.first_seen,
            persisted_seconds: persisted,
            reference: &reference,
        };
        let mut written = Vec::new();
        for (role, route) in roles {
            let (value, schema) = if role == "page" {
                (intent::v2(&input, &route), INTENT_V2)
            } else {
                (
                    intent::v1(
                        &input,
                        &route,
                        config.routes.notice_transport.destination_label(),
                    ),
                    INTENT_V1,
                )
            };
            let file = format!("{stable_event_id}.{role}.json");
            write_atomic(&intents_dir.join(&file), &intent::canonical(&value)?)?;
            written.push((
                role.clone(),
                LastIntent {
                    stable_event_id: stable_event_id.clone(),
                    transition_id: stable_event_id.clone(),
                    action: action.as_str().into(),
                    route,
                    schema: schema.into(),
                    notification_id: None,
                    outcome: "unknown".into(),
                    network: config.routes.delivers(schema),
                    at: now,
                    intent_file: file,
                },
            ));
            plan.push(Planned {
                condition_id: id.clone(),
                role,
                action: *action,
                operation: Operation::Submit,
                retry_of: None,
            });
        }
        for (role, last) in written {
            if let Some(previous) = condition.last_intent.insert(role.clone(), last)
                && previous.action == Action::Trigger.as_str()
                && previous.notification_id.is_none()
            {
                // A resolve never replaces a trigger NQ did not retain: the
                // trigger goes first in this pass.
                condition.pending_trigger.insert(role, previous);
            }
        }
    }
    let transitioned: BTreeSet<&String> = transitions.iter().map(|(id, _, _)| id).collect();
    let mut unreadable: Vec<IntentReport> = Vec::new();
    for (id, condition) in &mut state.conditions {
        if transitioned.contains(id) {
            continue;
        }
        let snapshot = condition.clone();
        for (role, last) in &mut condition.last_intent {
            let Some((operation, waits)) = follow_up(last, &snapshot, config) else {
                continue;
            };
            if waits && now - last.at < RESEND_INTERVAL_SECONDS {
                continue;
            }
            let Some(action) = Action::parse(&last.action) else {
                continue;
            };
            let mut retry_of = None;
            if operation != Operation::SubmitAgain {
                // A new record for the same condition: same bytes, new event id.
                let prior = match read_bounded(
                    &state_dir.join("intents").join(&last.intent_file),
                    64 * 1024,
                )
                .and_then(|bytes| {
                    serde_json::from_slice::<Value>(&bytes).map_err(|error| error.to_string())
                }) {
                    Ok(prior) => prior,
                    Err(error) => {
                        // Only this follow-up fails; the pass goes on.
                        eprintln!(
                            "follow-up condition={id} route={} outcome=intent_unreadable error={error}",
                            last.route
                        );
                        unreadable.push(IntentReport {
                            condition_id: id.clone(),
                            route_role: role.clone(),
                            route: last.route.clone(),
                            schema: last.schema.clone(),
                            action: last.action.clone(),
                            operation,
                            stable_event_id: last.stable_event_id.clone(),
                            transition_id: last.transition_id.clone(),
                            retry_of: last.notification_id.clone(),
                            intent_file: state_dir
                                .join("intents")
                                .join(&last.intent_file)
                                .display()
                                .to_string(),
                            outcome: "intent_unreadable".into(),
                            notification_id: None,
                            error: Some(error),
                        });
                        continue;
                    }
                };
                let stable_event_id = intent::event_id(&snapshot.key, action, now);
                let file = format!("{stable_event_id}.{role}.json");
                write_atomic(
                    &intents_dir.join(&file),
                    &intent::canonical(&intent::with_event_id(&prior, &stable_event_id))?,
                )?;
                retry_of = last.notification_id.clone();
                last.stable_event_id = stable_event_id;
                last.intent_file = file;
                last.notification_id = None;
            } else if options.dry_run {
                // The dry run reads the real intent file but writes nothing beside it.
                let source = state_dir.join("intents").join(&last.intent_file);
                if let Ok(bytes) = read_bounded(&source, 64 * 1024) {
                    write_atomic(&intents_dir.join(&last.intent_file), &bytes)?;
                }
            }
            last.outcome = "unknown".into();
            last.network = config.routes.delivers(&last.schema);
            last.at = now;
            plan.push(Planned {
                condition_id: id.clone(),
                role: role.clone(),
                action,
                operation: if operation == Operation::Resubmit && retry_of.is_none() {
                    Operation::SubmitAgain
                } else {
                    operation
                },
                retry_of,
            });
        }
    }
    for (id, condition) in &state.conditions {
        for (role, pending) in &condition.pending_trigger {
            if options.dry_run {
                let source = state_dir.join("intents").join(&pending.intent_file);
                if let Ok(bytes) = read_bounded(&source, 64 * 1024) {
                    write_atomic(&intents_dir.join(&pending.intent_file), &bytes)?;
                }
            }
            plan.push(Planned {
                condition_id: id.clone(),
                role: role.clone(),
                action: Action::Trigger,
                operation: Operation::SubmitBeforeResolve,
                retry_of: None,
            });
        }
    }
    // Triggers before resolves; within each, condition order.
    plan.sort_by(|left, right| {
        (
            left.action == Action::Resolve,
            &left.condition_id,
            &left.role,
        )
            .cmp(&(
                right.action == Action::Resolve,
                &right.condition_id,
                &right.role,
            ))
    });

    // Persist the decisions and written intents before any submission, so a
    // crash leaves `unknown` records that the next pass submits again.
    if !options.dry_run {
        state.updated_at = now;
        state.save(&config.state_path)?;
    }

    let mut delivery_problem = !unreadable.is_empty();
    let mut intent_reports = unreadable;
    let mut dropped_triggers = Vec::new();
    for item in &plan {
        let condition = state
            .conditions
            .get_mut(&item.condition_id)
            .expect("planned condition");
        let before_resolve = item.operation == Operation::SubmitBeforeResolve;
        let slot = if before_resolve {
            &mut condition.pending_trigger
        } else {
            &mut condition.last_intent
        };
        let last = slot.get_mut(&item.role).expect("planned intent");
        let (outcome, notification_id, error) = if options.dry_run {
            ("not_submitted".to_owned(), None, None)
        } else {
            let result = match (item.operation, &item.retry_of) {
                (Operation::Resubmit, Some(from)) => {
                    nq::resubmit(config, from, &last.stable_event_id)
                }
                _ if config.routes.local(&last.schema) => {
                    nq::deliver_local(config, &intents_dir.join(&last.intent_file), &last.route)
                }
                _ => nq::submit(config, &intents_dir.join(&last.intent_file), &last.route),
            };
            last.outcome.clone_from(&result.outcome);
            last.at = now;
            if result.notification_id.is_some() {
                last.notification_id.clone_from(&result.notification_id);
            }
            (result.outcome, result.notification_id, result.error)
        };
        let last = last.clone();
        if before_resolve && !options.dry_run {
            // Retained or not, the pending trigger is settled by this attempt.
            condition.pending_trigger.remove(&item.role);
            if notification_id.is_none() {
                eprintln!(
                    "dropped_trigger condition={} route={} stable_event_id={} outcome={outcome}",
                    item.condition_id, last.route, last.stable_event_id
                );
                dropped_triggers.push(json!({
                    "condition_id": item.condition_id,
                    "route_role": item.role,
                    "route": last.route,
                    "stable_event_id": last.stable_event_id,
                    "outcome": outcome,
                    "error": error,
                }));
                delivery_problem = true;
            }
        }
        if !options.dry_run {
            state.save(&config.state_path)?;
        }
        // A refusal of a submission made without --enable-network is the
        // configured qualification mode, not a delivery failure.
        let deliberate_refusal = outcome == "refused" && !last.network;
        if !options.dry_run && outcome != "accepted" && !deliberate_refusal {
            delivery_problem = true;
        }
        if let Some(error) = &error {
            eprintln!(
                "delivery condition={} route={} outcome={outcome} error={error}",
                item.condition_id, last.route
            );
        }
        intent_reports.push(IntentReport {
            condition_id: item.condition_id.clone(),
            route_role: item.role.clone(),
            route: last.route.clone(),
            schema: last.schema.clone(),
            action: item.action.as_str().into(),
            operation: item.operation,
            stable_event_id: last.stable_event_id.clone(),
            transition_id: last.transition_id.clone(),
            retry_of: item.retry_of.clone(),
            intent_file: intents_dir.join(&last.intent_file).display().to_string(),
            outcome,
            notification_id,
            error,
        });
    }

    if !options.dry_run {
        // Forget settled, inactive conditions and unreferenced intent files.
        state.conditions.retain(|_, condition| {
            condition.active
                || condition.first_seen.is_some()
                || condition
                    .last_intent
                    .values()
                    .any(|last| follow_up(last, condition, config).is_some())
                || !condition.pending_trigger.is_empty()
        });
        state.updated_at = now;
        state.save(&config.state_path)?;
        prune_intents(&intents_dir, &state);
    }

    // Deliveries still not accepted (other than deliberate refusals) keep the
    // pass visible until a resend succeeds or the condition is forgotten.
    let unresolved: Vec<Value> = if options.dry_run {
        Vec::new()
    } else {
        state
            .conditions
            .iter()
            .flat_map(|(id, condition)| {
                condition
                    .last_intent
                    .iter()
                    .filter_map(move |(role, last)| {
                        let deliberate = last.outcome == "refused" && !last.network;
                        (last.outcome != "accepted" && !deliberate).then(|| {
                            json!({
                                "condition_id": id,
                                "route_role": role,
                                "stable_event_id": last.stable_event_id,
                                "outcome": last.outcome,
                                "notification_id": last.notification_id,
                                "attempted_at": format_seconds(last.at),
                            })
                        })
                    })
            })
            .collect()
    };
    delivery_problem |= !unresolved.is_empty();
    let input_problem = read
        .reports
        .iter()
        .any(|report| report.status != InputStatus::Ok);
    let report = json!({
        "schema": REPORT_SCHEMA,
        "site": config.site,
        "evaluated_at": format_seconds(now),
        "dry_run": options.dry_run,
        "registry": REGISTRY_VERSION,
        "attention_policy_digest": digest,
        "network_enabled": config.routes.network_enabled,
        "rules": rules_report(&rules, config),
        "inputs": read.reports.iter().collect::<Vec<&InputReport>>(),
        "conditions": condition_reports,
        "intents": intent_reports,
        "unresolved_deliveries": unresolved,
        "dropped_triggers": dropped_triggers,
    });
    let mut bytes = serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    ensure_dir(&output_dir)?;
    write_atomic(&output_dir.join("report.json"), &bytes)?;
    Ok(PassResult {
        report,
        exit_code: if input_problem || delivery_problem {
            3
        } else {
            0
        },
    })
}

fn prune_intents(dir: &Path, state: &State) {
    let keep: BTreeSet<&str> = state
        .conditions
        .values()
        .flat_map(|condition| {
            condition
                .last_intent
                .values()
                .chain(condition.pending_trigger.values())
        })
        .map(|last| last.intent_file.as_str())
        .collect();
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".json") && !keep.contains(name.as_str()) {
            let _ = fs::remove_file(entry.path());
        }
    }
}

#[must_use]
pub fn rules_report(rules: &[EffectiveRule], config: &Config) -> Vec<Value> {
    rules
        .iter()
        .map(|rule| {
            json!({
                "id": rule.rule.id,
                "version": rule.rule.version,
                "enabled": rule.enabled,
                "disabled_reason": rule.rule.disabled,
                "class": rule.class.as_str(),
                "threshold_seconds": rule.threshold_seconds,
                "threshold_meaning": rule.rule.threshold_meaning,
                "persistence_seconds": rule.persistence_seconds(),
                "input": rule.rule.input,
                "input_configured": config.has_input(rule.rule.input),
            })
        })
        .collect()
}

/// The state file path, for the `state` subcommand.
#[must_use]
pub fn state_path(config: &Config) -> PathBuf {
    config.state_path.clone()
}
