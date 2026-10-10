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
use crate::recurrence;
use crate::registry::{
    Class, PAGE_RESEND_SECONDS, REGISTRY_VERSION, RESEND_INTERVAL_SECONDS, RESOLVE_CONFIRM_SECONDS,
    UNKNOWN_GAP_SECONDS,
};
use crate::remediation::{self, PageDecision};
use crate::state::{ConditionState, LastIntent, State};
use crate::util::{format_seconds, read_bounded, write_atomic};

pub const REPORT_SCHEMA: &str = "constellation.attention_report.v1";
pub const RECURRENCE_REPORT_SCHEMA: &str = "constellation.attention_report.v2";
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
    let digest = intent::config_policy_digest(config, &rules);
    let state_dir = config.state_dir();
    let output_dir = if options.dry_run {
        state_dir.join("dry-run")
    } else {
        state_dir.clone()
    };
    let _lock = lock(config, options.dry_run)?;
    let mut state = State::load(&config.state_path, &config.site)?;
    state.configure_recurrence(config)?;
    let now = options.now;
    if now < state.updated_at {
        // Event identities carry the decision time; a pass earlier than the
        // last one could replay an identity NQ already holds for another
        // incident.
        return Err(format!(
            "refusing the pass: now ({}) is earlier than the last completed pass ({}); \
             the clock moved backwards. If an earlier forward step has been corrected, \
             check the clock and run `constellation-attention reset-clock --config FILE`",
            format_seconds(now),
            format_seconds(state.updated_at)
        ));
    }

    let mut read = inputs::read_all(&Context {
        config,
        rules: &rules,
        now,
        now_ms: options.now_ms,
        nq_watchers: config
            .inputs
            .nq_status
            .as_ref()
            // One NQ status input: its roster survives a relabel.
            .and_then(|input| {
                state
                    .nq_watchers
                    .get(&input.label)
                    .or_else(|| state.nq_watchers.values().next())
            }),
    });
    if let Some((label, roster)) = read.nq_watchers.take() {
        state.nq_watchers = BTreeMap::from([(label, roster)]);
    }
    let mut observed: BTreeMap<String, Observed> = BTreeMap::new();
    // One condition fed by two inputs (a host-posture label equal to an NQ
    // filesystem watcher id): neither source may silently win.
    let mut collisions: Vec<(String, String, String)> = Vec::new();
    for item in read.observed {
        match observed.entry(item.key.id()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(item);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let existing = entry.get_mut();
                if existing.input_label != item.input_label {
                    collisions.push((
                        entry.key().clone(),
                        entry.get().input_label.clone(),
                        item.input_label.clone(),
                    ));
                    let existing = entry.get_mut();
                    existing.observation = Observation::Unknown;
                    existing.note = format!(
                        "fed by two inputs ({}, {}); not evaluated",
                        existing.input_label, item.input_label
                    );
                }
            }
        }
    }
    for (id, first, second) in &collisions {
        for report in read
            .reports
            .iter_mut()
            .filter(|report| report.label == *first || report.label == *second)
        {
            report.fault(
                "unrecognised",
                InputStatus::NotCurrent,
                &format!("condition {id} is fed by inputs {first} and {second}; rename one"),
            );
        }
    }
    // An open condition that a current input no longer reports has not been
    // observed to recover. Hold it, and report the input as not current so
    // `evaluator-input-unavailable` tells the operator.
    // Inputs that were read at all: a lasting fault of another class must
    // not hide an open condition the input stopped reporting.
    let current_labels: BTreeSet<String> = read
        .reports
        .iter()
        .filter(|report| report.status != InputStatus::Unavailable)
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
                    // A class the input is not showing now is clear only
                    // when the input is `ok`: while it has any fault, the
                    // others are unknown, so a fault that changes class
                    // from pass to pass still reaches the bound.
                    observation: if report.causes.contains(cause) {
                        Observation::Present
                    } else if report.status == InputStatus::Ok {
                        Observation::Clear
                    } else {
                        Observation::Unknown
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
        .chain(
            state
                .notice_recurrence
                .iter()
                .flat_map(|memory| memory.entries.keys().cloned()),
        )
        .collect();
    let mut transitions: Vec<(String, Action, ResolveReason)> = Vec::new();
    // Conditions whose deferred page is due this pass (page route only).
    let mut deferred_pages: BTreeSet<String> = BTreeSet::new();
    let mut condition_reports = Vec::new();
    let mut notice_decisions = BTreeMap::new();
    for id in &ids {
        let item = observed.get(id);
        let remembered = state
            .notice_recurrence
            .as_ref()
            .and_then(|memory| memory.entries.get(id));
        let remembered_key = remembered.map(|entry| (entry.key.clone(), entry.input_label.clone()));
        let condition = state.conditions.entry(id.clone()).or_insert_with(|| {
            let (key, label) = item
                .map(|item| (item.key.clone(), item.input_label.clone()))
                .or(remembered_key)
                .expect("condition comes from observation or notice history");
            ConditionState {
                rule_version: crate::registry::rule(&key.rule).map_or(0, |rule| rule.version),
                key,
                input_label: label,
                first_seen: None,
                last_seen: None,
                clear_since: None,
                unknown_since: None,
                active: false,
                transition_at: None,
                last_intent: BTreeMap::new(),
                pending_trigger: BTreeMap::new(),
                page_deferred: false,
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
                        None if condition.key.target_class.as_deref()
                            == Some(condition.input_label.as_str()) =>
                        {
                            (Observation::Removed, "input no longer configured".into())
                        }
                        // Conditions keyed on a unit, filesystem or nothing
                        // do not name the label; the input kind is still
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
        // A resolve clears first_seen and clear_since: keep when the window
        // ended and when the clear began, to name the resolve reason.
        let (opened_at, cleared_at) = (condition.first_seen, condition.clear_since.unwrap_or(now));
        let transition = step(condition, observation, persistence, now);
        let (policy, window) =
            config.response_policy(&condition.key.rule, condition.key.target_class.as_deref());
        let window_until =
            window.and_then(|window| remediation::window_until(condition.first_seen, window));
        if let Some(action) = transition {
            let reason = if observation == Observation::Removed {
                ResolveReason::NoLongerEvaluated
            } else if condition.page_deferred
                && window
                    .and_then(|window| remediation::window_until(opened_at, window))
                    .is_some_and(|until| cleared_at < until)
            {
                // Held page never sent and the clear began inside the window.
                ResolveReason::RecoveredWithinWindow
            } else {
                ResolveReason::Recovered
            };
            match action {
                Action::Resolve => condition.page_deferred = false,
                // The trigger's notice goes out now; its page may wait.
                Action::Trigger => {
                    condition.page_deferred = rule.is_some_and(|rule| rule.class == Class::Page)
                        && remediation::page_decision(policy, window_until, observation, now)
                            == PageDecision::Defer;
                }
            }
            transitions.push((id.clone(), action, reason));
        } else if condition.active
            && condition.page_deferred
            && remediation::page_decision(policy, window_until, observation, now)
                == PageDecision::Send
        {
            condition.page_deferred = false;
            deferred_pages.insert(id.clone());
        }
        if condition.key.rule == INPUT_UNAVAILABLE
            && let Some(memory) = &mut state.notice_recurrence
        {
            if !rule.is_some_and(|rule| rule.class == Class::Notice) {
                return Err("notice recurrence cannot select page or unknown rules".into());
            }
            if let Some(decision) = memory.step(
                &condition.key,
                &condition.input_label,
                observation,
                transition,
                condition.active,
                recurrence::may_replace(condition.last_intent.get("notice")),
                now,
            )? {
                notice_decisions.insert(id.clone(), decision);
            }
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
            "response_policy": policy.as_str(),
            "remediation_window_until": window_until,
            "page_deferred": condition.page_deferred,
        }));
    }

    // Raw transitions above remain in reports. Only notice planning is coalesced.
    if state.notice_recurrence.is_some() {
        transitions.retain(|(id, _, _)| state.conditions[id].key.rule != INPUT_UNAVAILABLE);
        for (id, decision) in &notice_decisions {
            let removed = decision
                .snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.kind == "removed")
                || !observed.contains_key(id);
            transitions.push((
                id.clone(),
                decision.action,
                if removed {
                    ResolveReason::NoLongerEvaluated
                } else {
                    ResolveReason::Recovered
                },
            ));
        }
    }

    // Plan: one intent per condition and route per pass.
    let intents_dir = output_dir.join("intents");
    ensure_dir(&intents_dir)?;
    let mut plan: Vec<Planned> = Vec::new();
    let mut superseded: Vec<Value> = Vec::new();
    let mut superseded_notices: Vec<Value> = Vec::new();
    let notice_route = config.routes.notice_route.clone();
    let work: Vec<(String, Action, ResolveReason, bool)> = transitions
        .iter()
        .map(|(id, action, reason)| (id.clone(), *action, *reason, false))
        .chain(
            deferred_pages
                .iter()
                .map(|id| (id.clone(), Action::Trigger, ResolveReason::Recovered, true)),
        )
        .collect();
    for (id, action, reason, page_only) in &work {
        let (action, reason) = (*action, *reason);
        let condition = state
            .conditions
            .get_mut(id)
            .expect("transitioned condition");
        let Some(rule) = rule_for(&rules, &condition.key.rule) else {
            continue;
        };
        let mut roles: Vec<(String, String)> = Vec::new();
        match action {
            // The remediation window expired with the condition present: the
            // held page goes out now, under its own event id, bound to the
            // trigger's transition.
            Action::Trigger if *page_only => {
                if let Some(page) = &config.routes.page_route {
                    roles.push(("page".into(), page.clone()));
                }
            }
            Action::Trigger => {
                if rule.class == Class::Page
                    && !condition.page_deferred
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
        let stable_event_id = if condition.key.rule == INPUT_UNAVAILABLE
            && let Some(memory) = &mut state.notice_recurrence
        {
            memory.event_id(action, now)?
        } else {
            intent::event_id(&condition.key, action, now)
        };
        let transition_id = if *page_only {
            intent::event_id(
                &condition.key,
                Action::Trigger,
                condition.transition_at.unwrap_or(now),
            )
        } else {
            stable_event_id.clone()
        };
        let reference = observed
            .get(id)
            .map_or(Value::Null, |item| item.reference.clone());
        let persisted = condition.first_seen.map_or(0, |first| now - first);
        let input = IntentInput {
            config,
            rule,
            key: &condition.key,
            action,
            resolve_reason: reason,
            stable_event_id: &stable_event_id,
            transition_id: &transition_id,
            policy_digest: &digest,
            first_seen: condition.first_seen,
            persisted_seconds: persisted,
            reference: &reference,
        };
        let mut written = Vec::new();
        for (role, route) in roles {
            let (mut value, schema) = if role == "page" {
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
            if role == "notice"
                && let Some(snapshot) = notice_decisions
                    .get(id)
                    .and_then(|decision| decision.snapshot.as_ref())
            {
                value["summary"] = json!(recurrence::summary(
                    &condition.key,
                    &condition.input_label,
                    snapshot
                )?);
            }
            let file = format!("{stable_event_id}.{role}.json");
            write_atomic(&intents_dir.join(&file), &intent::canonical(&value)?)?;
            written.push((
                role.clone(),
                LastIntent {
                    stable_event_id: stable_event_id.clone(),
                    transition_id: transition_id.clone(),
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
                action,
                operation: Operation::Submit,
                retry_of: None,
            });
        }
        for (role, last) in written {
            let Some(previous) = condition.last_intent.insert(role.clone(), last) else {
                continue;
            };
            if previous.action != Action::Trigger.as_str() {
                if notice_decisions.contains_key(id) && recurrence::unsettled(&previous) {
                    superseded_notices.push(json!({"condition_id": id, "route_role": role,
                        "stable_event_id": previous.stable_event_id, "notification_id": previous.notification_id,
                        "outcome": previous.outcome, "reason": if recurrence::may_replace(Some(&previous)) {
                            "definite nondelivery superseded by current notice"
                        } else { "ordinary lifecycle transition replaced unresolved prior notice" }}));
                }
                continue;
            }
            if previous.notification_id.is_none() {
                // A resolve never replaces a trigger NQ did not retain: the
                // trigger goes first in this pass.
                condition.pending_trigger.insert(role, previous);
            } else if previous.outcome != "accepted"
                && (previous.outcome != "refused" || previous.network)
            {
                // Retained but never accepted: the destination may never
                // have opened the incident this resolve closes.
                superseded.push(json!({
                    "condition_id": id,
                    "route_role": role,
                    "route": previous.route,
                    "stable_event_id": previous.stable_event_id,
                    "notification_id": previous.notification_id,
                    "outcome": previous.outcome,
                    "error": "superseded by a newer notice before acceptance",
                }));
            }
        }
    }
    // Conditions that got an intent this pass: no follow-up besides it.
    let transitioned: BTreeSet<&String> = transitions
        .iter()
        .map(|(id, _, _)| id)
        .chain(deferred_pages.iter())
        .collect();
    let mut unreadable: Vec<IntentReport> = Vec::new();
    for (id, condition) in &mut state.conditions {
        if transitioned.contains(id) {
            continue;
        }
        let snapshot = recurrence::delivery_snapshot(condition, state.notice_recurrence.as_ref());
        for (role, last) in &mut condition.last_intent {
            let Some((operation, waits)) = follow_up(last, &snapshot, config) else {
                continue;
            };
            let interval = if operation == Operation::Resubmit {
                PAGE_RESEND_SECONDS
            } else {
                RESEND_INTERVAL_SECONDS
            };
            if waits && now - last.at < interval {
                continue;
            }
            let Some(action) = Action::parse(&last.action) else {
                continue;
            };
            let mut retry_of = None;
            // A v2 intent retained before intents carried `response_class`
            // (builds before 784df43) would be refused by NQ's PagerDuty
            // route on every retry. Render it again as a page under a new
            // event id and submit it, so a page open across the upgrade is
            // delivered.
            let legacy_page = (last.schema == INTENT_V2)
                .then(|| {
                    read_bounded(
                        &state_dir.join("intents").join(&last.intent_file),
                        64 * 1024,
                    )
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                })
                .flatten()
                .filter(|prior| prior.get("response_class") != Some(&json!("page")));
            let (operation, rendered) = if let Some(prior) = legacy_page {
                let stable_event_id = intent::event_id(&snapshot.key, action, now);
                let mut fresh = intent::with_event_id(&prior, &stable_event_id);
                fresh["response_class"] = json!("page");
                let file = format!("{stable_event_id}.{role}.json");
                write_atomic(&intents_dir.join(&file), &intent::canonical(&fresh)?)?;
                eprintln!(
                    "follow-up condition={id} route={} intent without response_class re-rendered as a page under {stable_event_id}",
                    last.route
                );
                last.intent_file = file;
                last.stable_event_id = stable_event_id;
                last.notification_id = None;
                (Operation::Submit, true)
            } else {
                (operation, false)
            };
            if rendered {
                // A fresh record: nothing to resubmit from.
            } else if operation != Operation::SubmitAgain {
                // A new record for the same condition: same bytes, new event id.
                let prior = match read_bounded(
                    &state_dir.join("intents").join(&last.intent_file),
                    64 * 1024,
                )
                .and_then(|bytes| {
                    serde_json::from_slice::<Value>(&bytes).map_err(|error| error.to_string())
                }) {
                    Ok(prior) => Some(prior),
                    // A PagerDuty resubmit needs only NQ's record id; NQ
                    // re-derives the intent from its own retained copy.
                    Err(error) if operation == Operation::Resubmit => {
                        eprintln!(
                            "follow-up condition={id} route={} intent file unreadable ({error}); resubmitting from {}",
                            last.route,
                            last.notification_id.as_deref().unwrap_or_default()
                        );
                        None
                    }
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
                let stable_event_id = if snapshot.key.rule == INPUT_UNAVAILABLE
                    && let Some(memory) = &mut state.notice_recurrence
                {
                    memory.event_id(action, now)?
                } else {
                    intent::event_id(&snapshot.key, action, now)
                };
                retry_of = last.notification_id.clone();
                if let Some(prior) = prior {
                    let file = format!("{stable_event_id}.{role}.json");
                    write_atomic(
                        &intents_dir.join(&file),
                        &intent::canonical(&intent::with_event_id(&prior, &stable_event_id))?,
                    )?;
                    last.intent_file = file;
                }
                last.stable_event_id = stable_event_id;
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
        if let Some(memory) = &mut state.notice_recurrence {
            memory.refresh_delivery(&state.conditions);
        }
        state.updated_at = now;
        state.save(&config.state_path)?;
    }

    for dropped in &superseded {
        eprintln!(
            "dropped_trigger condition={} route={} stable_event_id={} outcome={}",
            dropped["condition_id"].as_str().unwrap_or_default(),
            dropped["route"].as_str().unwrap_or_default(),
            dropped["stable_event_id"].as_str().unwrap_or_default(),
            dropped["outcome"].as_str().unwrap_or_default(),
        );
    }
    let mut delivery_problem = !unreadable.is_empty() || !superseded.is_empty();
    let mut intent_reports = unreadable;
    let mut dropped_triggers = superseded;
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
            if let Some(memory) = &mut state.notice_recurrence {
                memory.refresh_delivery(&state.conditions);
            }
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
        if let Some(memory) = &mut state.notice_recurrence {
            memory.refresh_delivery(&state.conditions);
            memory.prune(&state.conditions, now);
        }
        // Forget settled, inactive conditions and unreferenced intent files.
        state.conditions.retain(|id, condition| {
            let snapshot =
                recurrence::delivery_snapshot(condition, state.notice_recurrence.as_ref());
            condition.active
                || condition.first_seen.is_some()
                || state
                    .notice_recurrence
                    .as_ref()
                    .and_then(|memory| memory.entries.get(id))
                    .is_some_and(|entry| {
                        entry.opened_at.is_some()
                            || entry.notice_active
                            || condition
                                .last_intent
                                .get("notice")
                                .is_some_and(recurrence::unsettled)
                    })
                || condition
                    .last_intent
                    .values()
                    .any(|last| follow_up(last, &snapshot, config).is_some())
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
    let mut report = json!({
        "schema": if state.notice_recurrence.is_some() { RECURRENCE_REPORT_SCHEMA } else { REPORT_SCHEMA },
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
    if let Some(memory) = &state.notice_recurrence {
        report["notice_recurrence"] =
            serde_json::to_value(memory).map_err(|error| error.to_string())?;
        report["superseded_notices"] = json!(superseded_notices);
    }
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

/// `reset-clock`: after a forward clock step has been corrected, clamp every
/// future timestamp in the state to `now` so passes proceed again. Refuses
/// nothing and deletes nothing; with no future timestamp it changes nothing.
pub fn reset_clock(config: &Config, now: i64) -> Result<Value, String> {
    let _lock = lock(config, false)?;
    let mut state = State::load(&config.state_path, &config.site)?;
    if let Some(memory) = &state.notice_recurrence {
        memory.check_binding(config)?;
    }
    let previous = state.updated_at;
    let clamped = state.reset_clock(now);
    if clamped > 0 {
        state.save(&config.state_path)?;
    }
    Ok(json!({
        "now": format_seconds(now),
        "previous_updated_at": format_seconds(previous),
        "clamped_timestamps": clamped,
    }))
}

/// Explicit downgrade boundary. No history/custody is silently discarded.
pub fn retire_recurrence(config: &Config) -> Result<Value, String> {
    let _lock = lock(config, false)?;
    let mut state = State::load(&config.state_path, &config.site)?;
    let memory = state
        .notice_recurrence
        .as_ref()
        .ok_or("no v2 recurrence state to retire")?;
    memory.check_binding(config)?;
    if !memory.entries.is_empty()
        || state.conditions.values().any(|condition| {
            condition.key.rule == INPUT_UNAVAILABLE
                && (condition.active
                    || !condition.pending_trigger.is_empty()
                    || condition.last_intent.values().any(recurrence::unsettled))
        })
    {
        return Err("cannot retire recurrence: history or input-notice custody remains; finish/reconcile it first".into());
    }
    state.notice_recurrence = None;
    state.schema = crate::state::STATE_SCHEMA.into();
    state.save(&config.state_path)?;
    Ok(json!({"schema": state.schema, "retired": true,
        "next": "restore v1 configuration before the next evaluation; re-enrollment creates a fresh issuance epoch"}))
}

/// The state file path, for the `state` subcommand.
#[must_use]
pub fn state_path(config: &Config) -> PathBuf {
    config.state_path.clone()
}
