//! One evaluation pass: read inputs, reconcile conditions with state, emit
//! intents through NQ, write the report.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::condition::ConditionKey;
use crate::config::{
    Config, EffectiveRule, default_metric_warming_bound, default_metric_warmup_grace,
};
use crate::inputs::{
    self, ADMISSION_KINDS, Context, INPUT_CAUSES, InputReport, InputStatus, Observation, Observed,
    REJECTED_CAUSE,
};
use crate::intent::{self, Action, INTENT_V1, INTENT_V2, IntentInput, ResolveReason};
use crate::nq;
use crate::registry::{
    Class, PAGE_RESEND_SECONDS, REGISTRY_VERSION, RESEND_INTERVAL_SECONDS, RESOLVE_CONFIRM_SECONDS,
    UNKNOWN_GAP_SECONDS,
};
use crate::remediation::{self, PageDecision};
use crate::state::{
    AttentionLifecycle, ConditionState, IdentityLifecycle, LastIntent, METRIC_ALERTS_STATE_SCHEMA,
    MetricAlertsHistory, MetricAlertsState, State,
};
use crate::util::{format_seconds, read_bounded, rfc3339_seconds, truncate, write_atomic};

pub const REPORT_SCHEMA: &str = "constellation.attention_report.v1";
/// Completed evaluation with an unmet delivery obligation or intent-log failure.
pub const DELIVERY_EXIT_CODE: i32 = 4;
const INPUT_UNAVAILABLE: &str = "evaluator-input-unavailable";

pub struct PassOptions {
    pub dry_run: bool,
    /// Unix seconds and milliseconds of "now".
    pub now: i64,
    pub now_ms: i64,
}

pub struct PassResult {
    pub report: Value,
    /// 0 clean; 3 input error (takes precedence); 4 delivery or intent-log failure.
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
    /// The route no longer has the identity this intent was created for.
    Retire,
}

struct Planned {
    condition_id: String,
    role: String,
    action: Action,
    operation: Operation,
    retry_of: Option<String>,
}

struct RouteDelivery {
    outcome: &'static str,
    last_attempt_at: Option<i64>,
}

fn delivery_outcome(outcome: &str) -> &'static str {
    match outcome {
        "accepted" => "accepted",
        "refused" => "refused",
        "skipped" => "skipped",
        _ => "failed",
    }
}

impl Default for RouteDelivery {
    fn default() -> Self {
        Self {
            outcome: "skipped",
            last_attempt_at: None,
        }
    }
}

struct DeliveryRoutes<'a> {
    config: &'a Config,
    current: BTreeMap<String, nq::Route>,
    page_local: bool,
    known: bool,
}

impl DeliveryRoutes<'_> {
    fn reference(&self, role: &str) -> Option<&str> {
        if role == "page" {
            self.config.routes.page_route.as_deref()
        } else {
            Some(&self.config.routes.notice_route)
        }
    }

    fn route(&self, role: &str) -> Option<&nq::Route> {
        self.current.get(self.reference(role)?)
    }

    fn missing(&self, route: &str) -> bool {
        self.known && !self.current.contains_key(route)
    }

    fn local(&self, schema: &str, route: &str) -> bool {
        schema == INTENT_V1
            && self.current.get(route).map_or_else(
                || !self.known && self.config.routes.local(schema),
                nq::Route::local,
            )
    }

    fn matches(&self, role: &str, last: &LastIntent, dir: &Path) -> bool {
        if self.reference(role) != Some(last.route.as_str()) {
            return false;
        }
        // A missing CURRENT route is still an obligation, never retirement.
        let Some(route) = self.route(role) else {
            return true;
        };
        let schema = if role == "page" && !route.local() {
            INTENT_V2
        } else {
            INTENT_V1
        };
        if last.schema != schema {
            return false;
        }
        // Missing files still follow the existing intent_unreadable/resubmit
        // path. A readable file binds even pre-upgrade state to its identity.
        read_bounded(&dir.join(&last.intent_file), 64 * 1024)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .is_none_or(|value| route.matches(&value))
    }

    fn delivers(&self, schema: &str, route: &str) -> bool {
        self.config.routes.network_enabled || self.local(schema, route)
    }

    /// Summarize obligations without changing NQ outcomes or retry decisions.
    /// Disabled transports and dry runs have no required delivery obligation.
    fn record(
        &self,
        delivery: &mut BTreeMap<String, RouteDelivery>,
        route: &str,
        outcome: &str,
        attempted_at: Option<i64>,
        dry_run: bool,
    ) {
        let required = (self.missing(route) || self.delivers(INTENT_V1, route)) && !dry_run;
        let outcome = if !required {
            "skipped"
        } else {
            delivery_outcome(outcome)
        };
        // A route with multiple obligations fails if any of them fails.
        let rank = |value| match value {
            "failed" => 3,
            "refused" => 2,
            "accepted" => 1,
            _ => 0,
        };
        let Some(current) = delivery.get_mut(route) else {
            return;
        };
        if rank(outcome) > rank(current.outcome) {
            current.outcome = outcome;
        }
        if !dry_run {
            current.last_attempt_at = current.last_attempt_at.max(attempted_at);
        }
    }

    /// Earlier builds wrote intents NQ could not retain. Repair only those
    /// without custody, so an active condition can recover on upgrade.
    fn repair_unretained(&self, last: &mut LastIntent, dir: &Path) -> Result<(), String> {
        if last.notification_id.is_some() {
            return Ok(());
        }
        if last.schema != INTENT_V1 {
            return Ok(());
        }
        let path = dir.join(&last.intent_file);
        // Missing files are handled by the existing follow-up error path.
        let Ok(bytes) = read_bounded(&path, 64 * 1024) else {
            return Ok(());
        };
        let Ok(mut value) = serde_json::from_slice::<Value>(&bytes) else {
            return Ok(());
        };
        let Some(fields) = value.as_object_mut() else {
            return Ok(());
        };
        let removed_url = fields.remove("runbook_url").is_some();
        if removed_url {
            write_atomic(&path, &intent::canonical(&value)?)?;
        }
        Ok(())
    }
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

impl IntentReport {
    fn normalize_outcome(&mut self) {
        if self.outcome == "unknown" {
            self.outcome = "failed".into();
            self.error = Some(unknown_delivery_error(self.error.as_deref()));
        }
    }

    fn cleanup(id: &str, cleanup: &PageCleanup, dir: &Path, error: Option<String>) -> Self {
        let mut report = Self::retired(
            id,
            if cleanup.manual { "notice" } else { "page" },
            &cleanup.last,
            dir,
        );
        report.operation = Operation::Submit;
        report.outcome.clone_from(&cleanup.last.outcome);
        report.error = error;
        report
    }

    fn retired(id: &str, role: &str, last: &LastIntent, dir: &Path) -> Self {
        Self {
            condition_id: id.into(),
            route_role: role.into(),
            route: last.route.clone(),
            schema: last.schema.clone(),
            action: last.action.clone(),
            operation: Operation::Retire,
            stable_event_id: last.stable_event_id.clone(),
            transition_id: last.transition_id.clone(),
            retry_of: None,
            intent_file: dir.join(&last.intent_file).display().to_string(),
            outcome: "route_retired".into(),
            notification_id: last.notification_id.clone(),
            error: Some("route removed or transport/destination identity changed".into()),
        }
    }
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
    routes: &DeliveryRoutes<'_>,
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
        ("unknown" | "command_error" | "failed", None) => Some((Operation::SubmitAgain, false)),
        ("accepted", _) => None,
        // A deliberate refusal (no network) is final until network is enabled.
        (_, Some(_)) if !routes.delivers(&last.schema, &last.route) => None,
        // PagerDuty: NQ allows resubmitting the newest failed/unknown/refused/pending record.
        (_, Some(_)) if last.schema == INTENT_V2 => Some((Operation::Resubmit, true)),
        // Slack/Discord/local inbox: a new event only after a definite
        // non-delivery, never over an uncertain attempt.
        ("failed" | "refused", Some(_)) => Some((Operation::Submit, true)),
        _ => None,
    }
}

/// Keep accepted provider pages across removal/re-addition during one incident.
/// A sidecar leaves the released lifecycle state schema unchanged.
#[derive(Default, Deserialize, Serialize)]
struct PageAcceptances(BTreeMap<String, BTreeMap<String, AcceptedPage>>);

#[derive(Deserialize, Serialize)]
struct AcceptedPage {
    last: LastIntent,
    body: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cleanup: Option<PageCleanup>,
}

#[derive(Deserialize, Serialize)]
struct PageCleanup {
    last: LastIntent,
    body: Value,
    manual: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl PageAcceptances {
    fn load(dir: &Path) -> (Self, bool) {
        let path = dir.join("accepted-pages.json");
        if !path.exists() {
            return (Self::default(), false);
        }
        let value = read_bounded(&path, 8 * 1024 * 1024)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
        let Some(entries) = value.as_ref().and_then(Value::as_object) else {
            eprintln!("accepted_pages: repaired; retiring unreadable sidecar");
            return (Self::default(), true);
        };
        let mut result = Self::default();
        let mut repaired = false;
        for (id, entries) in entries {
            let Some(entries) = entries.as_object() else {
                eprintln!("accepted_pages: repaired; retiring malformed condition={id}");
                repaired = true;
                continue;
            };
            for (route, value) in entries {
                let accepted = serde_json::from_value::<AcceptedPage>(value.clone()).ok();
                if let Some(accepted) = accepted.filter(|accepted| {
                    let identity = nq::Route {
                        reference: route.clone(),
                        transport: "pagerduty".into(),
                    };
                    let cleanup_valid = accepted.cleanup.as_ref().is_none_or(|cleanup| {
                        cleanup.body["schema"] == cleanup.last.schema
                            && cleanup.body["route_reference"] == cleanup.last.route
                            && cleanup.body["stable_event_id"] == cleanup.last.stable_event_id
                            && cleanup.body["transition_id"] == cleanup.last.transition_id
                            && if cleanup.manual {
                                cleanup.last.schema == INTENT_V1
                                    && cleanup.last.action == "notice"
                                    && ["slack", "discord", "local-inbox"].iter().any(|label| {
                                        cleanup.body["destination_identity"]
                                            == format!("{label}:{}", cleanup.last.route)
                                    })
                            } else {
                                cleanup.last.route == *route
                                    && cleanup.last.schema == INTENT_V2
                                    && cleanup.last.action == "resolve"
                                    && cleanup.body["action"] == "resolve"
                                    && identity.matches(&cleanup.body)
                                    && serde_json::from_value::<ConditionKey>(
                                        cleanup.body["condition"].clone(),
                                    )
                                    .is_ok_and(|key| key.id() == *id)
                            }
                    });
                    cleanup_valid
                        && accepted.last.schema == INTENT_V2
                        && accepted.last.action == "trigger"
                        && accepted.last.outcome == "accepted"
                        && accepted.last.notification_id.is_some()
                        && accepted.last.route == *route
                        && accepted.body.as_ref().is_some_and(|body| {
                            identity.matches(body)
                                && body["schema"] == INTENT_V2
                                && body["action"] == "trigger"
                                && body["stable_event_id"] == accepted.last.stable_event_id
                                && body["transition_id"] == accepted.last.transition_id
                                && serde_json::from_value::<ConditionKey>(body["condition"].clone())
                                    .is_ok_and(|key| key.id() == *id)
                        })
                }) {
                    result
                        .0
                        .entry(id.clone())
                        .or_default()
                        .insert(route.clone(), accepted);
                } else {
                    eprintln!(
                        "accepted_pages: repaired; retiring mismatched condition={id} route={route}"
                    );
                    repaired = true;
                }
            }
        }
        (result, repaired)
    }

    fn remember(&mut self, state: &State, dir: &Path) {
        for (id, condition) in &state.conditions {
            if let Some(last) = condition.last_intent.get("page").filter(|last| {
                condition.active
                    && last.schema == INTENT_V2
                    && last.action == "trigger"
                    && last.outcome == "accepted"
                    && last.notification_id.is_some()
            }) {
                let body = read_bounded(&dir.join("intents").join(&last.intent_file), 64 * 1024)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice(&bytes).ok());
                if body.is_none() {
                    continue;
                }
                let routes = self.0.entry(id.clone()).or_default();
                if routes.get(&last.route).is_none_or(|accepted| {
                    accepted.last.transition_id != last.transition_id
                        || (accepted
                            .cleanup
                            .as_ref()
                            .is_some_and(|cleanup| cleanup.last.outcome == "accepted")
                            && accepted.last.stable_event_id != last.stable_event_id)
                }) {
                    routes.insert(
                        last.route.clone(),
                        AcceptedPage {
                            last: last.clone(),
                            body,
                            cleanup: None,
                        },
                    );
                }
            }
        }
        self.0.retain(|id, routes| {
            routes.retain(|_, accepted| {
                if let Some(cleanup) = &accepted.cleanup {
                    return cleanup.last.outcome != "accepted"
                        || state.conditions.get(id).is_some_and(|condition| {
                            condition
                                .last_intent
                                .get("page")
                                .is_some_and(|last| last.route == accepted.last.route)
                        });
                }
                state.conditions.get(id).is_some_and(|condition| {
                    condition.active
                        && accepted.last.transition_id
                            == intent::event_id(
                                &condition.key,
                                Action::Trigger,
                                condition.transition_at.unwrap_or_default(),
                            )
                })
            });
            !routes.is_empty()
        });
    }

    fn restore(
        &mut self,
        state: &mut State,
        routes: &DeliveryRoutes<'_>,
        dir: &Path,
        repaired: &mut bool,
    ) -> Result<(), String> {
        let Some(route) = routes
            .route("page")
            .filter(|route| route.transport == "pagerduty")
        else {
            return Ok(());
        };
        for (id, condition) in &mut state.conditions {
            if !condition.active
                || condition.page_deferred
                || condition.last_intent.contains_key("page")
            {
                continue;
            }
            let Some(accepted) = self.0.get(id).and_then(|pages| pages.get(&route.reference))
            else {
                continue;
            };
            if accepted.cleanup.is_some() {
                continue;
            }
            if accepted.last.schema != INTENT_V2
                || accepted.last.outcome != "accepted"
                || accepted.last.action != "trigger"
                || accepted.last.route != route.reference
                || accepted
                    .body
                    .as_ref()
                    .is_some_and(|body| !route.matches(body))
            {
                eprintln!(
                    "accepted_pages: repaired; retiring mismatched condition={id} route={}",
                    route.reference
                );
                self.0
                    .get_mut(id)
                    .expect("accepted condition")
                    .remove(&route.reference);
                *repaired = true;
                continue;
            }
            if let Some(body) = &accepted.body {
                write_atomic(
                    &dir.join(&accepted.last.intent_file),
                    &intent::canonical(body)?,
                )?;
            }
            condition
                .last_intent
                .insert("page".into(), accepted.last.clone());
        }
        Ok(())
    }

    /// Finish provider incidents when the page role is removed. Persist each
    /// cleanup before calling NQ, so a failed/crashed resolve remains retryable.
    fn close_removed(
        &mut self,
        routes: &DeliveryRoutes<'_>,
        options: &PassOptions,
        abandoned: &mut Vec<Value>,
    ) -> Result<Vec<IntentReport>, String> {
        let config = routes.config;
        let dir = config.state_dir();
        let output = if options.dry_run {
            dir.join("dry-run")
        } else {
            dir.clone()
        };
        let mut reports = Vec::new();
        let keys: Vec<_> = self
            .0
            .iter()
            .flat_map(|(id, pages)| pages.keys().map(move |route| (id.clone(), route.clone())))
            .collect();
        for (id, reference) in keys {
            let accepted = &self.0[&id][&reference];
            if config.routes.page_route.is_some() && accepted.cleanup.is_none() {
                continue;
            }
            let body = accepted.body.as_ref().expect("validated accepted page");
            let manual = accepted
                .cleanup
                .as_ref()
                .is_some_and(|cleanup| cleanup.manual)
                || !routes
                    .current
                    .get(&reference)
                    .is_some_and(|route| route.matches(body));
            if manual {
                abandoned.push(json!({ "route": reference, "dedup_key": id }));
            }
            let accepted = self.0.get_mut(&id).unwrap().get_mut(&reference).unwrap();
            let notice = routes.route("notice");
            let cleanup_changed = accepted.cleanup.as_ref().is_some_and(|cleanup| {
                cleanup.manual != manual
                    || (cleanup.manual
                        && (cleanup.last.route != config.routes.notice_route
                            || notice.is_some_and(|route| !route.matches(&cleanup.body))))
            });
            if accepted.cleanup.is_none() || cleanup_changed {
                let event = format!("{}-retire-{}", accepted.last.stable_event_id, options.now);
                let mut body = intent::with_event_id(accepted.body.as_ref().unwrap(), &event);
                body["transition_id"] = json!(event);
                let route = if manual {
                    &config.routes.notice_route
                } else {
                    &reference
                };
                if manual {
                    body["schema"] = json!(INTENT_V1);
                    body["route_reference"] = json!(route);
                    let label = notice.map_or_else(
                        || config.routes.notice_transport.destination_label(),
                        nq::Route::destination_label,
                    );
                    body["destination_identity"] = json!(format!("{label}:{route}"));
                    body["response_class"] = json!("attention");
                    body["summary"] = json!(truncate(
                        &format!(
                            "abandoned_open_incident: route {reference}, dedup key {id}; the provider incident must be resolved by hand",
                        ),
                        512
                    ));
                    for field in ["action", "condition", "severity", "details", "runbook_url"] {
                        body.as_object_mut().unwrap().remove(field);
                    }
                } else {
                    body["action"] = json!("resolve");
                    body["summary"] =
                        json!("RESOLVE: page route removed from attention configuration");
                }
                accepted.cleanup = Some(PageCleanup {
                    last: LastIntent {
                        stable_event_id: event.clone(),
                        transition_id: event.clone(),
                        action: if manual { "notice" } else { "resolve" }.into(),
                        route: route.clone(),
                        schema: if manual { INTENT_V1 } else { INTENT_V2 }.into(),
                        notification_id: None,
                        outcome: "unknown".into(),
                        network: routes.delivers(if manual { INTENT_V1 } else { INTENT_V2 }, route),
                        at: options.now,
                        intent_file: format!("{event}.cleanup.json"),
                    },
                    body,
                    manual,
                    error: None,
                });
            }
            let cleanup = accepted.cleanup.as_mut().unwrap();
            if cleanup.last.outcome == "accepted" {
                continue;
            }
            if cleanup.last.notification_id.is_some()
                && options.now - cleanup.last.at < PAGE_RESEND_SECONDS
            {
                continue;
            }
            let retry_of = cleanup.last.notification_id.clone();
            if retry_of.is_some() {
                let event = format!("{}-retire-{}", accepted.last.stable_event_id, options.now);
                cleanup.body = intent::with_event_id(&cleanup.body, &event);
                cleanup.last.stable_event_id = event;
            }
            // After a crash, submit these same bytes to recover NQ custody;
            // never resubmit an older record again after an uncertain answer.
            cleanup.last.notification_id = None;
            cleanup.last.outcome = "unknown".into();
            cleanup.last.at = options.now;
            cleanup.error = None;
            write_atomic(
                &output.join("intents").join(&cleanup.last.intent_file),
                &intent::canonical(&cleanup.body)?,
            )?;
            if !options.dry_run {
                self.save(&dir)?;
            }
            let cleanup = self
                .0
                .get_mut(&id)
                .unwrap()
                .get_mut(&reference)
                .unwrap()
                .cleanup
                .as_mut()
                .unwrap();
            let result = if options.dry_run {
                nq::SubmitOutcome {
                    outcome: "not_submitted".into(),
                    notification_id: None,
                    error: None,
                }
            } else if routes.missing(&cleanup.last.route) {
                nq::missing_route()
            } else if !manual && retry_of.is_some() {
                nq::resubmit(
                    config,
                    retry_of.as_deref().unwrap(),
                    &cleanup.last.stable_event_id,
                )
            } else if routes.local(&cleanup.last.schema, &cleanup.last.route) {
                nq::deliver_local(
                    config,
                    &output.join("intents").join(&cleanup.last.intent_file),
                    &cleanup.last.route,
                )
            } else {
                nq::submit(
                    config,
                    &output.join("intents").join(&cleanup.last.intent_file),
                    &cleanup.last.route,
                )
            };
            cleanup.last.outcome = result.outcome;
            cleanup.last.notification_id = result.notification_id;
            cleanup.last.at = options.now;
            cleanup.error = result.error;
            let mut report =
                IntentReport::cleanup(&id, cleanup, &output.join("intents"), cleanup.error.clone());
            if !manual && retry_of.is_some() {
                report.operation = Operation::Resubmit;
                report.retry_of = retry_of;
            }
            reports.push(report);
            if !options.dry_run {
                self.save(&dir)?;
            }
        }
        self.0.retain(|_, pages| !pages.is_empty());
        Ok(reports)
    }

    fn save(&self, dir: &Path) -> Result<(), String> {
        if self.0.is_empty() && !dir.join("accepted-pages.json").exists() {
            return Ok(());
        }
        write_atomic(
            &dir.join("accepted-pages.json"),
            &serde_json::to_vec(self).map_err(|error| error.to_string())?,
        )
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reconfiguration {
    run_id: String,
    at: String,
    reason: String,
}

/// Read under the state lock. Removal waits for durable sidecar custody.
fn reconfiguration(path: &Path, now: i64, bound: i64) -> Result<Option<i64>, String> {
    let bytes = read_bounded(path, 4096)?;
    let marker: Reconfiguration = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid reconfiguration marker: {error}"))?;
    if marker.run_id.trim().is_empty()
        || marker.run_id.len() > 128
        || !matches!(
            marker.reason.as_str(),
            "vmalert restarted" | "rules changed" | "scrapes changed"
        )
    {
        return Err("invalid reconfiguration marker run_id or reason".into());
    }
    let at = rfc3339_seconds(&marker.at)?;
    if at > now.saturating_add(300) {
        return Err("reconfiguration marker is from the future".into());
    }
    if now.saturating_sub(at) >= bound {
        eprintln!(
            "ignoring stale reconfiguration marker: at={} warming_bound={bound}",
            marker.at
        );
        return Ok(None);
    }
    Ok(Some(at.min(now)))
}

/// An incomplete pass leaves the previous liveness report untouched. Only a
/// completed report published by THIS pass can have its exit fields corrected.
pub fn evaluate(config: &Config, options: &PassOptions) -> Result<PassResult, String> {
    let _lock = lock(config, options.dry_run)?;
    let mut completed = None;
    let result = evaluate_locked(config, options, &mut completed);
    let output = if options.dry_run {
        config.state_dir().join("dry-run")
    } else {
        config.state_dir()
    };
    finish_pass(result, completed, &output.join("report.json"))
}

fn finish_pass(
    result: Result<PassResult, String>,
    completed: Option<Value>,
    path: &Path,
) -> Result<PassResult, String> {
    if let (Err(error), Some(mut report)) = (&result, completed) {
        report["exit_code"] = json!(1);
        report["exit_class"] = json!("evaluator_error");
        report["first_error"] = json!(error.lines().next().unwrap_or_default());
        write_atomic(
            path,
            &serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
        )
        .map_err(|failure| format!("{error}; cannot correct completed report: {failure}"))?;
    }
    result
}

#[allow(
    clippy::too_many_lines,
    reason = "The pass is one ordered sequence: read, reconcile, persist, submit, report."
)]
fn evaluate_locked(
    config: &Config,
    options: &PassOptions,
    completed: &mut Option<Value>,
) -> Result<PassResult, String> {
    let rules = config.effective_rules();
    let digest =
        intent::policy_digest_with(&rules, &config.remediation.targets, &config.suspensions);
    let state_dir = config.state_dir();
    let output_dir = if options.dry_run {
        state_dir.join("dry-run")
    } else {
        state_dir.clone()
    };
    let mut state = State::load(&config.state_path, &config.site)?;
    let (mut page_acceptances, mut accepted_pages_repaired) = PageAcceptances::load(&state_dir);
    page_acceptances.remember(&state, &state_dir);
    let metric_history_path = state_dir.join("state-metric-alerts.json");
    let saved_metric_state = MetricAlertsState::load(&metric_history_path, &config.site)?;
    let warmup_grace = config
        .inputs
        .metric_alerts
        .as_ref()
        .map_or_else(default_metric_warmup_grace, |input| input.warmup_grace);
    let lifecycle_path = state_dir.join("state-attention-lifecycle.json");
    let saved_lifecycle = AttentionLifecycle::load(&lifecycle_path, &config.site)?;
    // Release state has no complete identity roster. An open aggregate input
    // incident also establishes prior faults, even if updated_at is unset.
    let seed_metric_identities_faulting = saved_lifecycle.is_none()
        && (state.updated_at > 0
            || config.inputs.metric_alerts.as_ref().is_some_and(|input| {
                state.conditions.values().any(|condition| {
                    condition.active
                        && condition.key.rule == INPUT_UNAVAILABLE
                        && condition.key.target_class.as_deref()
                            == Some(format!("{}.indeterminate", input.label).as_str())
                })
            }));
    let mut lifecycle = saved_lifecycle.unwrap_or_else(|| {
        let mut lifecycle = AttentionLifecycle::new(
            &config.site,
            if state.updated_at > 0 {
                options.now.saturating_sub(warmup_grace)
            } else {
                options.now
            },
        );
        // Preserve known targets even when they are absent from this pass.
        // Other first-pass targets are conservatively seeded by the reader.
        for condition in state.conditions.values() {
            if condition.key.rule == "metric-alert-firing"
                && let Some(target) = &condition.key.target_class
            {
                lifecycle.identities.insert(
                    target.clone(),
                    IdentityLifecycle {
                        faulting: true,
                        ..IdentityLifecycle::default()
                    },
                );
            }
        }
        lifecycle
    });
    // A rollback evaluator cannot attest per-identity continuity or recovery.
    if lifecycle.updated_at < state.updated_at {
        for identity in lifecycle.identities.values_mut() {
            identity.faulting = true;
        }
    }
    let first_seen = lifecycle.first_seen;
    let marker_path = state_dir.join("reconfigured");
    let marker_present = marker_path.try_exists().unwrap_or(true);
    let mut marker_error = None;
    if marker_present {
        let bound = config
            .inputs
            .metric_alerts
            .as_ref()
            .map_or_else(default_metric_warming_bound, |input| input.warming_bound);
        match reconfiguration(&marker_path, options.now, bound) {
            Ok(Some(at)) if lifecycle.reconfigured_at.is_none_or(|saved| at > saved) => {
                lifecycle.reconfigured_at = Some(at);
                for identity in lifecycle.identities.values_mut() {
                    identity.rearm(at, bound);
                }
            }
            Ok(_) => {}
            Err(error) => marker_error = Some(format!("invalid: {error}")),
        }
    }
    let reconfigured_at = lifecycle.reconfigured_at;
    let metric_history = match saved_metric_state {
        Some(mut metric_state) => {
            if metric_state.updated_at < state.updated_at
                && let Some(history) = &mut metric_state.history
            {
                // A rollback binary advances lifecycle state alone. It cannot
                // attest that pre-rollback warming continued throughout.
                history
                    .warming_since
                    .retain(|_, since| *since >= state.updated_at);
            }
            metric_state.history
        }
        None => config.inputs.metric_alerts.as_ref().and_then(|input| {
            // Upgrade or deleted sidecar: never grant an established evaluator
            // a new grace, even when its last pass was only one minute ago.
            let established = state.updated_at > 0
                || state.conditions.values().any(|condition| {
                    condition.key.rule == "metric-alert-firing"
                        || (condition.key.rule == INPUT_UNAVAILABLE
                            && condition.key.target_class.as_ref().is_some_and(|target| {
                                target.starts_with(&format!("{}.", input.label))
                            }))
                });
            established.then_some(MetricAlertsHistory {
                first_seen: options.now.saturating_sub(input.warmup_grace),
                warming_since: BTreeMap::new(),
            })
        }),
    };
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
        metric_alerts: metric_history.as_ref(),
        first_seen,
        lifecycle: &lifecycle,
        seed_metric_identities_faulting,
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
    if let Some(error) = &marker_error {
        read.reports.push(InputReport {
            label: "reconfiguration_marker".into(),
            kind: "reconfiguration_marker",
            component: "host_posture",
            source: marker_path.display().to_string(),
            status: InputStatus::Unavailable,
            causes: vec!["unreadable"],
            rejected_rules: Vec::new(),
            error: Some(error.clone()),
            identity: Value::Null,
        });
    }
    if let Some(updated) = read.lifecycle.take() {
        lifecycle = updated;
    } else if read
        .reports
        .iter()
        .any(|report| report.kind == "metric_alerts" && report.status != InputStatus::Ok)
    {
        for identity in lifecycle.identities.values_mut() {
            identity.faulting = true;
        }
    }
    if let Some(at) = reconfigured_at {
        for report in read
            .reports
            .iter_mut()
            .filter(|report| report.kind == "metric_alerts")
        {
            if !report.identity.is_object() {
                report.identity = json!({});
            }
            report.identity["reconfigured_at"] = json!(format_seconds(at));
        }
    }
    if let Some((label, roster)) = read.nq_watchers.take() {
        state.nq_watchers = BTreeMap::from([(label, roster)]);
    }
    let metric_history = read.metric_alerts.take().or(metric_history);
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
            || retired_target(config, condition)
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
                // Per-definition admission exists only for these kinds.
                if *cause == REJECTED_CAUSE && !ADMISSION_KINDS.contains(&report.kind) {
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
                let reference = input_fault_reference(
                    report,
                    cause,
                    read.metric_indeterminate_reason.as_deref(),
                );
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
                    } else if report.status == InputStatus::Ok
                        && !report.causes.contains(&"warming")
                    {
                        Observation::Clear
                    } else {
                        Observation::Unknown
                    },
                    reference,
                    note: if *cause == REJECTED_CAUSE {
                        rejected_note(report)
                    } else if report.causes.contains(cause) {
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
    let mut resolved_first_seen = BTreeMap::new();
    let mut transitions: Vec<(String, Action, ResolveReason)> = Vec::new();
    // Conditions whose deferred page is due this pass (page route only).
    let mut deferred_pages: BTreeSet<String> = BTreeSet::new();
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
        } else if retired_target(config, condition) {
            (
                Observation::Removed,
                "target retired from supervision by the operator".into(),
            )
        } else if condition.key.rule == INPUT_UNAVAILABLE
            && read.reports.iter().any(|report| {
                report.label == condition.input_label && report.causes.contains(&"warming")
            })
        {
            (
                Observation::Unknown,
                "input warming; recovery not observed".into(),
            )
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
        // A suspended definition is held, never evaluated: an open condition stays
        // open (no recovery is claimed) and nothing triggers.
        let suspension = config.suspensions.iter().find(|s| s.covers(&condition.key));
        let (observation, note) = match suspension {
            Some(s) => (
                Observation::Unknown,
                format!("suspended by {}: {}", s.owner, s.reason),
            ),
            None => (observation, note),
        };
        let persistence = rule.map_or(0, EffectiveRule::persistence_seconds);
        // A resolve clears first_seen and clear_since: keep when the window
        // ended and when the clear began, to name the resolve reason.
        let (opened_at, cleared_at) = (condition.first_seen, condition.clear_since.unwrap_or(now));
        let transition = step(condition, observation, persistence, now);
        if transition == Some(Action::Resolve) {
            resolved_first_seen.insert(id.clone(), opened_at);
        }
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
            "suspended": suspension,
        }));
    }

    let retained = state.conditions.values().any(|condition| {
        !condition.last_intent.is_empty() || !condition.pending_trigger.is_empty()
    }) || state_dir.join("digest.json").exists()
        || !page_acceptances.0.is_empty();
    let routes_needed = retained || config.routes.page_route.is_some();
    // No reconciliation on an idle notice-only deployment. New notices can
    // still use the configured transport when NQ's config is unreadable.
    let current_routes = if routes_needed {
        Some(nq::routes(config)?)
    } else if state.conditions.values().any(|condition| condition.active)
        || config.digest.as_ref().is_some_and(|settings| {
            settings
                .offset_seconds()
                .is_ok_and(|offset| crate::digest::due(offset, None, now))
        })
    {
        nq::routes(config).ok()
    } else {
        None
    };
    let known = current_routes.is_some();
    let current_routes = current_routes.unwrap_or_default();
    let delivery_routes = DeliveryRoutes {
        config,
        known,
        page_local: config
            .routes
            .page_route
            .as_ref()
            .and_then(|page| current_routes.get(page))
            .is_some_and(nq::Route::local),
        current: current_routes,
    };

    // Plan: one intent per condition and route per pass.
    let intents_dir = output_dir.join("intents");
    ensure_dir(&intents_dir)?;
    let mut abandoned = Vec::new();
    let mut retired = page_acceptances.close_removed(&delivery_routes, options, &mut abandoned)?;
    for (id, condition) in &mut state.conditions {
        for slot in [&mut condition.last_intent, &mut condition.pending_trigger] {
            slot.retain(|role, last| {
                let cleanup_completed = role == "page"
                    && page_acceptances
                        .0
                        .get(id)
                        .and_then(|pages| pages.get(&last.route))
                        .is_some_and(|accepted| {
                            accepted.last.stable_event_id == last.stable_event_id
                                && accepted
                                    .cleanup
                                    .as_ref()
                                    .is_some_and(|cleanup| cleanup.last.outcome == "accepted")
                        });
                if !cleanup_completed
                    && ((role == "page"
                        && config.routes.page_route.is_none()
                        && page_acceptances
                            .0
                            .get(id)
                            .and_then(|pages| pages.get(&last.route))
                            .is_some_and(|page| {
                                page.cleanup
                                    .as_ref()
                                    .is_none_or(|cleanup| cleanup.last.outcome != "accepted")
                            }))
                        || delivery_routes.matches(role, last, &state_dir.join("intents")))
                {
                    return true;
                }
                retired.push(IntentReport::retired(
                    id,
                    role,
                    last,
                    &state_dir.join("intents"),
                ));
                false
            });
        }
    }
    if let Some((record, body)) = crate::digest::retire_changed_route(
        config,
        delivery_routes.route("notice"),
        options.dry_run,
    )? {
        retired.push(IntentReport::retired(
            "daily-digest",
            "notice",
            &LastIntent {
                stable_event_id: record.stable_event_id.clone(),
                transition_id: body["transition_id"]
                    .as_str()
                    .unwrap_or(&record.stable_event_id)
                    .into(),
                action: "digest".into(),
                route: body["route_reference"].as_str().unwrap_or_default().into(),
                schema: INTENT_V1.into(),
                notification_id: record.notification_id,
                outcome: record.outcome,
                network: record.network,
                at: record.at,
                intent_file: "digest-intent.json".into(),
            },
            &state_dir,
        ));
    }
    page_acceptances.restore(
        &mut state,
        &delivery_routes,
        &intents_dir,
        &mut accepted_pages_repaired,
    )?;
    if !options.dry_run {
        for condition in state.conditions.values_mut() {
            for last in condition
                .last_intent
                .values_mut()
                .chain(condition.pending_trigger.values_mut())
            {
                delivery_routes.repair_unretained(last, &intents_dir)?;
            }
        }
    }
    let mut plan: Vec<Planned> = Vec::new();
    let mut superseded: Vec<Value> = Vec::new();
    let notice_route = config.routes.notice_route.clone();
    let mut work: Vec<(String, Action, ResolveReason, bool)> = transitions
        .iter()
        .map(|(id, action, reason)| (id.clone(), *action, *reason, false))
        .chain(
            deferred_pages
                .iter()
                .map(|id| (id.clone(), Action::Trigger, ResolveReason::Recovered, true)),
        )
        .collect();
    let transitioned: BTreeSet<String> = work.iter().map(|(id, _, _, _)| id.clone()).collect();
    work.extend(
        state
            .conditions
            .iter()
            .filter(|(id, condition)| {
                condition.active
                    && !transitioned.contains(*id)
                    && !config.suspensions.iter().any(|s| s.covers(&condition.key))
            })
            .map(|(id, _)| (id.clone(), Action::Trigger, ResolveReason::Recovered, false)),
    );
    for (id, action, reason, page_only) in &work {
        let (action, reason) = (*action, *reason);
        let condition = state
            .conditions
            .get_mut(id)
            .expect("transitioned condition");
        let Some(rule) = rule_for(&rules, &condition.key.rule) else {
            continue;
        };
        if !transitioned.contains(id) && !rule.enabled {
            continue;
        }
        let mut roles: Vec<(String, String)> = Vec::new();
        match action {
            // The remediation window expired with the condition present: the
            // held page goes out now, under its own event id, bound to the
            // trigger's transition.
            Action::Trigger if *page_only => {
                if let Some(page) = &config.routes.page_route {
                    roles.push(("page".into(), page.clone()));
                }
                if !condition.last_intent.contains_key("notice")
                    && !roles.iter().any(|(_, route)| route == &notice_route)
                {
                    roles.push(("notice".into(), notice_route.clone()));
                }
            }
            Action::Trigger => {
                if rule.class == Class::Page
                    && !condition.page_deferred
                    && let Some(page) = &config.routes.page_route
                {
                    roles.push(("page".into(), page.clone()));
                }
                if !roles.iter().any(|(_, route)| route == &notice_route) {
                    roles.push(("notice".into(), notice_route.clone()));
                }
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
        // Active conditions also acquire newly configured roles, but an
        // unchanged role (especially an accepted page) keeps its exact event.
        let refresh = !transitioned.contains(id);
        roles.retain(|(role, route)| {
            delivery_routes.reference(role) == Some(route.as_str())
                && (!refresh || !condition.last_intent.contains_key(role))
        });
        let stable_event_id = intent::event_id(&condition.key, action, now);
        let transition_id = if *page_only || refresh {
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
            first_seen: condition
                .first_seen
                .or_else(|| resolved_first_seen.get(id).copied().flatten()),
            persisted_seconds: persisted,
            reference: &reference,
        };
        let mut written = Vec::new();
        for (role, route) in roles {
            let local_page = role == "page" && delivery_routes.page_local;
            let (value, schema) = if role == "page" && !local_page {
                (intent::v2(&input, &route), INTENT_V2)
            } else {
                (
                    intent::v1(
                        &input,
                        &route,
                        delivery_routes.current.get(&route).map_or_else(
                            || config.routes.notice_transport.destination_label(),
                            nq::Route::destination_label,
                        ),
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
                    transition_id: transition_id.clone(),
                    action: action.as_str().into(),
                    network: delivery_routes.delivers(schema, &route),
                    route,
                    schema: schema.into(),
                    notification_id: None,
                    outcome: "unknown".into(),
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
                    "error": "superseded by a resolve before it was accepted",
                }));
            }
        }
    }
    let planned: BTreeSet<(String, String)> = plan
        .iter()
        .map(|item| (item.condition_id.clone(), item.role.clone()))
        .collect();
    let mut unreadable: Vec<IntentReport> = Vec::new();
    for (id, condition) in &mut state.conditions {
        let snapshot = condition.clone();
        for (role, last) in &mut condition.last_intent {
            if planned.contains(&(id.clone(), role.clone())) {
                continue;
            }
            let Some((operation, waits)) = follow_up(last, &snapshot, &delivery_routes) else {
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
                let stable_event_id = intent::event_id(&snapshot.key, action, now);
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
            last.network = delivery_routes.delivers(&last.schema, &last.route);
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
        MetricAlertsState {
            schema: METRIC_ALERTS_STATE_SCHEMA.into(),
            site: config.site.clone(),
            updated_at: now,
            history: metric_history,
        }
        .save(&metric_history_path)?;
        lifecycle.updated_at = now;
        lifecycle.save(&lifecycle_path)?;
        if marker_present && marker_error.is_some() {
            fs::rename(
                &marker_path,
                state_dir.join(format!("reconfigured.invalid-{now}")),
            )
            .map_err(|error| format!("cannot quarantine reconfiguration marker: {error}"))?;
        } else if marker_present {
            fs::remove_file(&marker_path)
                .map_err(|error| format!("cannot remove reconfiguration marker: {error}"))?;
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
    let mut intent_reports = retired;
    intent_reports.extend(unreadable);
    let mut withheld_count = 0;
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
            if last.schema == INTENT_V2
                && read_bounded(&intents_dir.join(&last.intent_file), 64 * 1024)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                    .is_some_and(|intent| {
                        intent.get("runbook_url").is_none()
                            && intent["inspection_reference"]
                                .as_str()
                                .is_some_and(|url| url.starts_with("http://"))
                    })
            {
                withheld_count += 1;
            }
            let result = if delivery_routes.missing(&last.route) {
                nq::missing_route()
            } else {
                match (item.operation, &item.retry_of) {
                    (Operation::Resubmit, Some(from)) => {
                        nq::resubmit(config, from, &last.stable_event_id)
                    }
                    _ if delivery_routes.local(&last.schema, &last.route) => {
                        nq::deliver_local(config, &intents_dir.join(&last.intent_file), &last.route)
                    }
                    _ => nq::submit(config, &intents_dir.join(&last.intent_file), &last.route),
                }
            };
            last.outcome.clone_from(&result.outcome);
            last.at = now;
            if result.notification_id.is_some() {
                last.notification_id.clone_from(&result.notification_id);
            }
            (result.outcome, result.notification_id, result.error)
        };
        let last = last.clone();
        if before_resolve && !options.dry_run && !delivery_routes.missing(&last.route) {
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
            }
        }
        if !options.dry_run {
            state.save(&config.state_path)?;
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

    if withheld_count > 0 {
        eprintln!(
            "runbook_url_withheld: non-HTTPS runbook URL withheld from NQ runbook_url for {withheld_count} intents; \
             link retained in human-readable inspection_reference"
        );
    }

    if !options.dry_run {
        // Forget settled, inactive conditions and unreferenced intent files.
        state.conditions.retain(|_, condition| {
            condition.active
                || condition.first_seen.is_some()
                || condition
                    .last_intent
                    .values()
                    .any(|last| follow_up(last, condition, &delivery_routes).is_some())
                || !condition.pending_trigger.is_empty()
        });
        state.updated_at = now;
        state.save(&config.state_path)?;
        page_acceptances.remember(&state, &state_dir);
        page_acceptances.save(&state_dir)?;
        prune_intents(&intents_dir, &state);
    }

    // Reporting uses the route vocabulary; retained NQ state above continues
    // to distinguish uncertainty for custody and retry decisions.
    for item in &mut intent_reports {
        item.normalize_outcome();
    }
    // Deliveries still not accepted (other than deliberate refusals) keep the
    // pass visible until a resend succeeds or the condition is forgotten.
    let mut unresolved: Vec<Value> = if options.dry_run {
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
                                "route": last.route,
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
    for item in &mut unresolved {
        if item["outcome"] == "refused" {
            let error = intent_reports
                .iter()
                .find(|attempt| {
                    item["route"] == attempt.route
                        && item["stable_event_id"] == attempt.stable_event_id
                })
                .and_then(|attempt| attempt.error.clone())
                .or_else(|| {
                    item["notification_id"]
                        .as_str()
                        .and_then(|id| nq::refusal_error(config, id))
                })
                .unwrap_or_else(|| "refused: NQ supplied no refusal reason".into());
            item["error"] = json!(error);
        }
    }
    // After the state is saved: a failed digest never holds a transition back.
    let mut digest_attempt = if options.dry_run {
        None
    } else {
        crate::digest::send_if_due(
            config,
            &state,
            &rules,
            &read.reports,
            &digest,
            now,
            delivery_routes.known.then_some(&delivery_routes.current),
        )?
    };
    // A rejected definition leaves its input `ok` but is still an input
    // problem: the pass exits 3, and the report tells the two apart (status
    // `ok`, cause `rejected`, `rejected_rules`).
    let input_problem = read.reports.iter().any(|report| {
        report.status != InputStatus::Ok || report.causes.iter().any(|cause| *cause != "warming")
    });
    // Include log failures in the same pass's durable outcome.
    let intent_log_error = if !options.dry_run && !intent_reports.is_empty() {
        append_intent_log(&state_dir, &format_seconds(now), &intent_reports)
            .err()
            .map(|error| format!("intent_log_unwritable {error}"))
    } else {
        None
    };
    if let Some(error) = &intent_log_error {
        eprintln!("{error}");
    }
    let mut delivery =
        BTreeMap::from([(config.routes.notice_route.clone(), RouteDelivery::default())]);
    if let Some(page) = &config.routes.page_route {
        delivery.insert(page.clone(), RouteDelivery::default());
    }
    for (id, condition) in &state.conditions {
        for (role, last) in &condition.last_intent {
            if delivery_routes.reference(role) == Some(last.route.as_str())
                && delivery_routes.missing(&last.route)
                && !options.dry_run
            {
                delivery_routes.record(&mut delivery, &last.route, "failed", None, false);
                unresolved.push(json!({
                    "condition_id": id, "route_role": role, "route": last.route,
                    "stable_event_id": last.stable_event_id,
                    "outcome": "failed", "error": nq::ROUTE_NOT_CONFIGURED,
                }));
                continue;
            }
            if last.outcome == "accepted"
                && read_bounded(&intents_dir.join(&last.intent_file), 64 * 1024)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                    .is_none_or(|value| {
                        !delivery_routes
                            .current
                            .get(&last.route)
                            .is_some_and(|route| route.matches(&value))
                    })
            {
                continue;
            }
            delivery_routes.record(
                &mut delivery,
                &last.route,
                &last.outcome,
                Some(last.at),
                options.dry_run,
            );
        }
    }
    for (id, pages) in &page_acceptances.0 {
        for page in pages.values() {
            let Some(cleanup) = &page.cleanup else {
                continue;
            };
            let last = &cleanup.last;
            delivery.entry(last.route.clone()).or_default();
            delivery_routes.record(
                &mut delivery,
                &last.route,
                &last.outcome,
                (!delivery_routes.missing(&last.route)).then_some(last.at),
                options.dry_run,
            );
            if !options.dry_run && last.outcome != "accepted" {
                unresolved.push(json!({
                    "condition_id": id, "route": last.route,
                    "outcome": last.outcome, "error": cleanup.error,
                    "stable_event_id": last.stable_event_id,
                    "attempted_at": format_seconds(last.at),
                }));
            }
        }
    }
    for item in &intent_reports {
        if item.outcome == "route_retired" {
            continue;
        }
        delivery.entry(item.route.clone()).or_default();
        delivery_routes.record(
            &mut delivery,
            &item.route,
            &item.outcome,
            (item.outcome != "intent_unreadable" && !delivery_routes.missing(&item.route))
                .then_some(now),
            options.dry_run,
        );
    }
    for item in &dropped_triggers {
        if let Some(route) = item["route"].as_str() {
            delivery_routes.record(&mut delivery, route, "failed", None, options.dry_run);
        }
    }
    if let Some(current) = crate::digest::current_outcome(
        config,
        now,
        delivery_routes.known.then_some(&delivery_routes.current),
    ) {
        delivery_routes.record(
            &mut delivery,
            &config.routes.notice_route,
            &current.outcome,
            (!delivery_routes.missing(&config.routes.notice_route)).then_some(current.at),
            options.dry_run,
        );
        if !options.dry_run
            && digest_attempt.is_none()
            && !matches!(current.outcome.as_str(), "accepted" | "skipped")
        {
            unresolved.push(json!({
                "condition_id": "daily-digest",
                "route": config.routes.notice_route,
                "outcome": current.outcome,
                "error": format!("digest retry pause: {}", current.error.as_deref().unwrap_or(&current.outcome)),
                "attempted_at": format_seconds(current.at),
            }));
        }
    }
    for item in unresolved.iter_mut().chain(dropped_triggers.iter_mut()) {
        normalize_delivery_outcome(item);
    }
    if let Some(attempt) = &mut digest_attempt {
        normalize_delivery_outcome(attempt);
    }
    let delivery_problem = delivery
        .values()
        .any(|route| matches!(route.outcome, "refused" | "failed"));
    let delivery_class = if !delivery_problem {
        "clean"
    } else if delivery.values().any(|route| route.outcome == "accepted") {
        "delivery_partial"
    } else {
        "delivery_failed"
    };
    // Observation failure is fundamental even when notification also fails.
    let exit_code = if input_problem {
        3
    } else if delivery_problem || intent_log_error.is_some() {
        DELIVERY_EXIT_CODE
    } else {
        0
    };
    let exit_class = if input_problem {
        "input_error"
    } else if intent_log_error.is_some() {
        "intent_log_unwritable"
    } else {
        delivery_class
    };
    let delivery: BTreeMap<_, _> = delivery
        .into_iter()
        .map(|(route, summary)| {
            (route.clone(), {
                let mut value = json!({
                    "outcome": summary.outcome,
                    "last_attempt_at": summary.last_attempt_at.map(format_seconds),
                });
                if summary.outcome == "failed" && delivery_routes.missing(&route) {
                    value["error"] = json!(nq::ROUTE_NOT_CONFIGURED);
                } else if let Some(error) = intent_reports
                    .iter()
                    .find(|item| {
                        item.route == route
                            && item.outcome != "route_retired"
                            && delivery_outcome(&item.outcome) == summary.outcome
                            && item.error.is_some()
                    })
                    .and_then(|item| item.error.as_deref())
                    .or_else(|| {
                        unresolved.iter().find_map(|item| {
                            (item["route"] == route
                                && item["outcome"].as_str().map(delivery_outcome)
                                    == Some(summary.outcome))
                            .then(|| item["error"].as_str())
                            .flatten()
                        })
                    })
                {
                    value["error"] = json!(error);
                }
                value
            })
        })
        .collect();
    let report = json!({
        "schema": REPORT_SCHEMA,
        "site": config.site,
        "evaluated_at": format_seconds(now),
        "dry_run": options.dry_run,
        "registry": REGISTRY_VERSION,
        "attention_policy_digest": digest,
        "network_enabled": config.routes.network_enabled,
        "page_delivery": delivery_routes.page_local.then_some("local_file route; v1 copy"),
        "rules": rules_report(&rules, config),
        "inputs": read.reports.iter().collect::<Vec<&InputReport>>(),
        "conditions": condition_reports,
        "intents": intent_reports,
        "unresolved_deliveries": unresolved,
        "dropped_triggers": dropped_triggers,
        "exit_code": exit_code,
        "exit_class": exit_class,
        "delivery": delivery,
        "delivery_class": delivery_class,
        "intent_log_error": intent_log_error,
    });
    let mut report = report;
    if let Some(attempt) = digest_attempt {
        report["digest"] = attempt;
    }
    if accepted_pages_repaired {
        report["accepted_pages"] = json!("repaired");
    }
    if !abandoned.is_empty() {
        report["abandoned_open_incident"] = json!(abandoned);
    }
    report["first_error"] = json!(first_pass_error(&report));
    let mut bytes = serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    ensure_dir(&output_dir)?;
    write_atomic(&output_dir.join("report.json"), &bytes)?;
    *completed = Some(report.clone());
    Ok(PassResult { report, exit_code })
}

/// First failure in report order, reduced to one line for status consumers.
fn unknown_delivery_error(error: Option<&str>) -> String {
    format!(
        "failed: delivery result unknown ({})",
        error.unwrap_or("NQ could not establish whether the destination accepted it")
    )
}

fn normalize_delivery_outcome(item: &mut Value) {
    if item["outcome"] == "unknown" {
        item["error"] = json!(unknown_delivery_error(item["error"].as_str()));
        item["outcome"] = json!("failed");
    }
}

fn first_pass_error(report: &Value) -> Option<String> {
    if report["exit_code"] == 0 {
        return None;
    }
    let input = report["inputs"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|input| {
            input["status"] != "ok"
                || input["causes"]
                    .as_array()
                    .is_some_and(|c| c.iter().any(|cause| cause != "warming"))
        });
    let error = input
        .map(|input| {
            format!(
                "input {}: {}",
                input["label"].as_str().unwrap_or("unknown"),
                input["error"]
                    .as_str()
                    .map_or_else(|| input["causes"].to_string(), str::to_owned)
            )
        })
        .or_else(|| {
            ["intents", "dropped_triggers", "unresolved_deliveries"]
                .into_iter()
                .flat_map(|key| report[key].as_array().into_iter().flatten())
                .find(|item| {
                    item["outcome"] != "route_retired"
                        && matches!(
                            item["route"]
                                .as_str()
                                .and_then(|route| report["delivery"][route]["outcome"].as_str()),
                            Some("refused" | "failed")
                        )
                        && (item["error"].is_string()
                            || !matches!(
                                item["outcome"].as_str(),
                                Some("accepted" | "not_submitted")
                            ))
                })
                .map(|item| {
                    format!(
                        "delivery {} ({}): {}",
                        item["route"].as_str().unwrap_or("unknown"),
                        item["condition_id"].as_str().unwrap_or("unknown"),
                        item["error"]
                            .as_str()
                            .unwrap_or_else(|| item["outcome"].as_str().unwrap_or("unknown"))
                    )
                })
        })
        .or_else(|| {
            (report["digest"]["settled"] == false).then(|| {
                format!(
                    "digest {}: {}",
                    report["digest"]["route"].as_str().unwrap_or("unknown"),
                    report["digest"]["error"].as_str().unwrap_or_else(|| {
                        report["digest"]["outcome"].as_str().unwrap_or("unsettled")
                    })
                )
            })
        })
        .or_else(|| report["intent_log_error"].as_str().map(str::to_owned))
        .or_else(|| {
            Some(format!(
                "pass: {}",
                report["exit_class"].as_str().unwrap_or("error")
            ))
        });
    error.map(|error| error.lines().next().unwrap_or_default().to_owned())
}

/// Name rejected definitions or the metric rules held by non-1 codes.
fn input_fault_reference(
    report: &InputReport,
    cause: &str,
    metric_indeterminate_reason: Option<&str>,
) -> Value {
    let mut reference = json!({
        "input": report.label,
        "kind": report.kind,
        "status": report.status,
        "cause": cause,
    });
    if cause == REJECTED_CAUSE && !report.rejected_rules.is_empty() {
        reference["rejected_rules"] = json!(
            report
                .rejected_rules
                .iter()
                .map(|rule| &rule["fault"])
                .collect::<Vec<_>>()
        );
        // Names first, so every rejected definition and the incident
        // reference fit the notice; the byte detail is in report.json.
        reference["reason"] = json!(truncate(&rejected_names(report), 400));
    }
    if cause == "indeterminate"
        && report.kind == "metric_alerts"
        && let Some(reason) = metric_indeterminate_reason
    {
        reference["reason"] = json!(reason);
    }
    reference
}

/// `rejected rules: A, B (site); see report.json rejected_rules`.
pub fn rejected_names(report: &InputReport) -> String {
    let mut names: Vec<String> = report
        .rejected_rules
        .iter()
        .map(|rule| {
            let name = rule["rule"].as_str().unwrap_or_default();
            match rule["site"].as_str() {
                Some(site) => format!("{name} ({site})"),
                None => name.to_owned(),
            }
        })
        .collect();
    names.dedup();
    format!(
        "rejected rules: {}; see report.json {}.rejected_rules",
        names.join(", "),
        report.label
    )
}

/// `<fault>: <reason>` for every rejected definition of the input.
fn rejected_note(report: &InputReport) -> String {
    report
        .rejected_rules
        .iter()
        .map(|rule| {
            format!(
                "{}: {}",
                rule["fault"].as_str().unwrap_or_default(),
                rule["reason"].as_str().unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// An NQ-status condition whose target the operator listed in
/// `[inputs.nq_status] retired_targets`.
fn retired_target(config: &Config, condition: &ConditionState) -> bool {
    config.inputs.nq_status.as_ref().is_some_and(|input| {
        condition.input_label == input.label
            && condition
                .key
                .target_class
                .as_ref()
                .is_some_and(|target| input.retired_targets.contains(target))
    })
}

/// The newest 1 MiB of delivery outcomes, with one rotated predecessor.
const INTENT_LOG_MAX: u64 = 1024 * 1024;

fn append_intent_log(state_dir: &Path, at: &str, reports: &[IntentReport]) -> Result<(), String> {
    use std::io::Write as _;
    let path = state_dir.join("intents.jsonl");
    if fs::metadata(&path).is_ok_and(|meta| meta.len() > INTENT_LOG_MAX) {
        fs::rename(&path, state_dir.join("intents.jsonl.1")).map_err(|error| error.to_string())?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let mut lines = String::new();
    for report in reports {
        let mut value = serde_json::to_value(report).map_err(|error| error.to_string())?;
        value["at"] = json!(at);
        lines.push_str(&serde_json::to_string(&value).map_err(|error| error.to_string())?);
        lines.push('\n');
    }
    file.write_all(lines.as_bytes())
        .map_err(|error| error.to_string())
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
    let metric_history_path = config.state_dir().join("state-metric-alerts.json");
    let mut metric_history = MetricAlertsState::load(&metric_history_path, &config.site)?;
    let lifecycle_path = config.state_dir().join("state-attention-lifecycle.json");
    let mut lifecycle = AttentionLifecycle::load(&lifecycle_path, &config.site)?;
    let previous = state.updated_at;
    let mut clamped = state.reset_clock(now);
    if let Some(history) = &mut metric_history {
        let history_clamped = history.reset_clock(now);
        if history_clamped > 0 {
            history.save(&metric_history_path)?;
        }
        clamped += history_clamped;
    }
    if let Some(lifecycle) = &mut lifecycle {
        let lifecycle_clamped = lifecycle.reset_clock(now);
        if lifecycle_clamped > 0 {
            lifecycle.save(&lifecycle_path)?;
        }
        clamped += lifecycle_clamped;
    }
    if clamped > 0 {
        state.save(&config.state_path)?;
    }
    Ok(json!({
        "now": format_seconds(now),
        "previous_updated_at": format_seconds(previous),
        "clamped_timestamps": clamped,
    }))
}

/// The state file path, for the `state` subcommand.
#[must_use]
pub fn state_path(config: &Config) -> PathBuf {
    config.state_path.clone()
}

#[cfg(test)]
mod tests {
    use super::first_pass_error;
    use serde_json::json;

    #[test]
    fn late_failure_corrects_only_this_pass_completed_report_exit_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.json");
        let completed = json!({
            "schema": super::REPORT_SCHEMA, "evaluated_at": "2026-10-02T12:00:00Z",
            "conditions": [{"id": "retained"}], "inputs": [],
            "delivery": {"operations": {"outcome": "accepted"}},
            "exit_code": 0, "exit_class": "clean", "first_error": null,
        });
        std::fs::write(&path, serde_json::to_vec(&completed).unwrap()).unwrap();
        let prior = std::fs::read(&path).unwrap();
        assert!(super::finish_pass(Err("early failure".into()), None, &path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), prior);
        assert!(
            super::finish_pass(
                Err("late failure\nmore".into()),
                Some(completed.clone()),
                &path
            )
            .is_err()
        );
        let mut expected = completed;
        expected["exit_code"] = json!(1);
        expected["exit_class"] = json!("evaluator_error");
        expected["first_error"] = json!("late failure");
        let actual: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn log_failure_is_reported_even_without_input_or_delivery_rows() {
        assert_eq!(
            first_pass_error(&json!({
                "exit_code": 4,
                "exit_class": "intent_log_unwritable",
                "intent_log_error": "intent_log_unwritable: permission denied\nmore detail",
            }))
            .as_deref(),
            Some("intent_log_unwritable: permission denied"),
        );
    }

    #[test]
    fn delivery_error_is_not_hidden_by_network_disabled() {
        assert_eq!(
            first_pass_error(&json!({
                "exit_code": 4,
                "network_enabled": false,
                "inputs": [],
                "delivery": {"local-page": {"outcome": "failed", "last_attempt_at": null}},
                "dropped_triggers": [{
                    "route": "local-page",
                    "condition_id": "page-condition",
                    "outcome": "refused",
                    "error": "superseded by a resolve before it was accepted",
                }],
            }))
            .as_deref(),
            Some(
                "delivery local-page (page-condition): superseded by a resolve before it was accepted"
            ),
        );
    }
}
