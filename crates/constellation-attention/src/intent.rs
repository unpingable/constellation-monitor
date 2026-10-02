//! NQ notification intents. v2 (`PagerDuty`) carries the condition; v1
//! (Slack/Discord) carries the condition id and action in its summary text.
//! Both are canonical JSON (JCS), as `nq notification submit` requires.

use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

use crate::condition::ConditionKey;
use crate::config::{Config, EffectiveRule};
use crate::registry::REGISTRY_VERSION;
use crate::util::{format_seconds, truncate};

pub const INTENT_V1: &str = "nq.notification_delivery_intent.v1";
pub const INTENT_V2: &str = "nq.notification_delivery_intent.v2";
pub const ATTENTION_POLICY_ID: &str = "constellation-attention";
const V1_SUMMARY_MAX: usize = 512;
const V2_SUMMARY_MAX: usize = 1024;
const DETAILS_MAX: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Trigger,
    Resolve,
}

impl Action {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trigger => "trigger",
            Self::Resolve => "resolve",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "trigger" => Some(Self::Trigger),
            "resolve" => Some(Self::Resolve),
            _ => None,
        }
    }
}

/// `sha256:` digest of the effective registry: rule ids, versions, enablement,
/// class and threshold. It names the policy that decided the intent.
#[must_use]
pub fn policy_digest(rules: &[EffectiveRule]) -> String {
    let rules: Vec<Value> = rules
        .iter()
        .map(|rule| {
            json!({
                "id": rule.rule.id,
                "version": rule.rule.version,
                "enabled": rule.enabled,
                "class": rule.class.as_str(),
                "threshold_seconds": rule.threshold_seconds,
            })
        })
        .collect();
    let bytes = serde_jcs::to_vec(&json!({"registry": REGISTRY_VERSION, "rules": rules}))
        .unwrap_or_default();
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// `{site}-{rule}[-{target_class}]-{action}-{unix_seconds}`.
#[must_use]
pub fn event_id(key: &ConditionKey, action: Action, at: i64) -> String {
    format!("{}-{}-{at}", key.event_prefix(), action.as_str())
}

/// Why a resolve was decided. Every resolve summary names its reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolveReason {
    /// Current qualified state was clear for the confirmation window.
    Recovered,
    /// The rule, its input or the input label was removed from the
    /// configuration; recovery was not observed.
    NoLongerEvaluated,
}

pub struct IntentInput<'a> {
    pub config: &'a Config,
    pub rule: &'a EffectiveRule,
    pub key: &'a ConditionKey,
    pub action: Action,
    pub resolve_reason: ResolveReason,
    pub stable_event_id: &'a str,
    pub transition_id: &'a str,
    pub policy_digest: &'a str,
    pub first_seen: Option<i64>,
    pub persisted_seconds: i64,
    pub reference: &'a Value,
}

fn summary(input: &IntentInput<'_>) -> String {
    let id = input.key.id();
    match input.action {
        Action::Trigger => format!(
            "TRIGGER {id} [{}]: {} Persisted {} s (bound {} s).",
            input.rule.class.as_str(),
            input.rule.rule.condition,
            input.persisted_seconds,
            input.rule.persistence_seconds(),
        ),
        Action::Resolve => match input.resolve_reason {
            ResolveReason::Recovered => format!(
                "RESOLVE {id} [{}]: underlying state clear for at least {} s.",
                input.rule.class.as_str(),
                crate::registry::RESOLVE_CONFIRM_SECONDS,
            ),
            ResolveReason::NoLongerEvaluated => format!(
                "RESOLVE {id} [{}]: no longer evaluated; recovery not observed.",
                input.rule.class.as_str(),
            ),
        },
    }
}

fn inspection_reference(input: &IntentInput<'_>) -> String {
    input
        .config
        .runbook_url(input.rule.rule)
        .unwrap_or_else(|| {
            format!(
                "{}#{}",
                input.rule.rule.runbook_document, input.rule.rule.runbook_anchor
            )
        })
}

fn details(input: &IntentInput<'_>) -> Value {
    let mut details = Map::new();
    details.insert("condition_id".into(), json!(input.key.id()));
    details.insert("registry".into(), json!(REGISTRY_VERSION));
    details.insert("rule_version".into(), json!(input.rule.rule.version));
    details.insert("evaluator".into(), json!("constellation-attention"));
    if let Some(first_seen) = input.first_seen {
        details.insert("first_seen".into(), json!(format_seconds(first_seen)));
    }
    details.insert("persisted_seconds".into(), json!(input.persisted_seconds));
    details.insert("input".into(), input.reference.clone());
    let value = Value::Object(details.clone());
    if serde_jcs::to_vec(&value).map_or(0, |bytes| bytes.len()) <= DETAILS_MAX {
        return value;
    }
    details.remove("input");
    Value::Object(details)
}

/// A v2 intent for a `PagerDuty` route.
#[must_use]
pub fn v2(input: &IntentInput<'_>, route: &str) -> Value {
    let mut condition = json!({
        "site": input.key.site,
        "component": input.key.component,
        "rule": input.key.rule,
    });
    if let Some(target_class) = &input.key.target_class {
        condition["target_class"] = json!(target_class);
    }
    let mut intent = json!({
        "schema": INTENT_V2,
        "attention_kind": "operator_assertion",
        "stable_event_id": input.stable_event_id,
        "attention_policy_id": ATTENTION_POLICY_ID,
        "attention_policy_digest": input.policy_digest,
        "transition_id": input.transition_id,
        "route_reference": route,
        "destination_identity": format!("pagerduty:{route}"),
        "summary": truncate(&summary(input), V2_SUMMARY_MAX),
        "inspection_reference": truncate(&inspection_reference(input), 1024),
        "action": input.action.as_str(),
        "condition": condition,
        "severity": input.rule.rule.severity,
        "details": details(input),
    });
    if let Some(url) = input.config.runbook_url(input.rule.rule) {
        intent["runbook_url"] = json!(url);
    }
    intent
}

/// A v1 intent for a Slack/Discord route.
#[must_use]
pub fn v1(input: &IntentInput<'_>, route: &str, transport: &str) -> Value {
    json!({
        "schema": INTENT_V1,
        "attention_kind": "operator_assertion",
        "stable_event_id": input.stable_event_id,
        "attention_policy_id": ATTENTION_POLICY_ID,
        "attention_policy_digest": input.policy_digest,
        "transition_id": input.transition_id,
        "route_reference": route,
        "destination_identity": format!("{transport}:{route}"),
        "summary": truncate(&summary(input), V1_SUMMARY_MAX),
        "inspection_reference": truncate(&inspection_reference(input), 1024),
    })
}

/// Canonical bytes (JCS, no trailing newline).
pub fn canonical(value: &Value) -> Result<Vec<u8>, String> {
    serde_jcs::to_vec(value).map_err(|error| error.to_string())
}

/// Replace the event identity of a retained v1 intent (a notice resend).
pub fn with_event_id(intent: &Value, stable_event_id: &str) -> Value {
    let mut intent = intent.clone();
    intent["stable_event_id"] = json!(stable_event_id);
    intent
}
