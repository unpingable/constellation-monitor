//! NQ notification intents. v2 (`PagerDuty`) carries the condition; v1
//! (Slack/Discord) carries the condition id and action in its summary text.
//! Both are canonical JSON (JCS), as `nq notification submit` requires.

use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

use crate::condition::ConditionKey;
use crate::config::{Config, EffectiveRule, RemediationTarget};
use crate::registry::{REGISTRY_VERSION, ResponseClass};
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
pub fn policy_digest(rules: &[EffectiveRule], remediation: &[RemediationTarget]) -> String {
    let rules: Vec<Value> = rules
        .iter()
        .map(|rule| {
            json!({
                "id": rule.rule.id,
                "version": rule.rule.version,
                "enabled": rule.enabled,
                "class": rule.class.as_str(),
                "response_class": rule.rule.response_class.as_str(),
                "response_policy": rule.rule.response_policy.as_str(),
                "threshold_seconds": rule.threshold_seconds,
            })
        })
        .collect();
    let bytes = serde_jcs::to_vec(
        &json!({"registry": REGISTRY_VERSION, "rules": rules, "remediation": remediation}),
    )
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
    /// An `auto_remediate_then_page` condition recovered before its
    /// remediation window expired; no page was sent.
    RecoveredWithinWindow,
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
            ResolveReason::RecoveredWithinWindow => format!(
                "RESOLVE {id} [{}]: recovered within the remediation window; no page was sent.",
                input.rule.class.as_str(),
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
        // Only page-class decisions reach a PagerDuty route.
        "response_class": ResponseClass::Page.as_str(),
        "condition": condition,
        "severity": input.rule.rule.severity,
        "details": details(input),
    });
    if let Some(url) = input.config.runbook_url(input.rule.rule) {
        intent["runbook_url"] = json!(url);
    }
    intent
}

/// NQ refuses a rendered local inbox message larger than this.
pub const LOCAL_INBOX_MESSAGE_MAX: usize = 4096;
pub const LOCAL_INBOX_LABEL: &str = "local-inbox";
/// Longest `local_file` notice route the configuration admits. With the
/// summary (512 bytes), inspection reference (1024) and event id bounds,
/// this keeps every rendered local message under
/// [`LOCAL_INBOX_MESSAGE_MAX`].
pub const LOCAL_ROUTE_MAX: usize = 128;

/// A v1 intent for a Slack, Discord or local inbox route. `label` is the
/// destination label (`slack`, `discord`, `local-inbox`).
#[must_use]
pub fn v1(input: &IntentInput<'_>, route: &str, label: &str) -> Value {
    json!({
        "schema": INTENT_V1,
        "attention_kind": "operator_assertion",
        "stable_event_id": input.stable_event_id,
        "attention_policy_id": ATTENTION_POLICY_ID,
        "attention_policy_digest": input.policy_digest,
        "transition_id": input.transition_id,
        "route_reference": route,
        "destination_identity": format!("{label}:{route}"),
        "summary": truncate(&summary(input), V1_SUMMARY_MAX),
        "inspection_reference": truncate(&inspection_reference(input), 1024),
        "response_class": response_class(input).as_str(),
    })
}

/// The response class of a notice: `page` for a decision that also pages,
/// otherwise `attention`, including a configuration-removal resolve ("no
/// longer evaluated"), which asks nobody to interrupt anything.
fn response_class(input: &IntentInput<'_>) -> ResponseClass {
    let removal = input.action == Action::Resolve
        && matches!(
            input.resolve_reason,
            ResolveReason::NoLongerEvaluated | ResolveReason::RecoveredWithinWindow
        );
    if input.rule.class == crate::registry::Class::Page && !removal {
        ResponseClass::Page
    } else {
        ResponseClass::Attention
    }
}

/// Size of the message NQ renders for a v1 intent on a `local_file` route
/// (`nq.local-inbox-message/v1`, canonical JSON), with a placeholder of the
/// exact length of the directory binding digest.
#[must_use]
pub fn local_inbox_message_bytes(intent: &Value) -> usize {
    let message = json!({
        "schema": "nq.local-inbox-message/v1",
        "stable_event_id": intent["stable_event_id"],
        "summary": intent["summary"],
        "inspection_reference": intent["inspection_reference"],
        "route_reference": intent["route_reference"],
        "destination_identity": intent["destination_identity"],
        "destination_binding_digest": format!("sha256:{}", "0".repeat(64)),
        "delivery_statement": "local file retained; human receipt is not established",
    });
    serde_jcs::to_vec(&message).map_or(usize::MAX, |bytes| bytes.len())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::condition::ConditionKey;
    use crate::config::Config;

    /// The longest values the configuration admits still render a local
    /// inbox message under NQ's 4 KiB limit, with JSON escaping.
    #[test]
    fn longest_local_inbox_message_fits() {
        let route = "\"".repeat(LOCAL_ROUTE_MAX);
        // The longest admissible URL: 900 bytes, all but the prefix escaped.
        let url = format!("https://docs.example.org/{}", "\"".repeat(875));
        assert_eq!(url.len(), 900);
        let text = format!(
            "schema = \"constellation.attention_config.v1\"\n\
             site = \"{site}\"\n\
             state_path = \"/var/lib/constellation-attention/state.json\"\n\
             [runbooks]\n\
             cartography_url = {url:?}\n\
             monitor_url = {url:?}\n\
             [nq]\n\
             program = \"/usr/bin/nq\"\n\
             config = \"/etc/nq/nqd-ops.toml\"\n\
             [routes]\n\
             notice_route = {route:?}\n\
             notice_transport = \"local_file\"\n\
             network_enabled = false\n",
            site = "s".repeat(64),
        );
        let config: Config = toml::from_str(&text).unwrap();
        config.validate().unwrap();
        let rules = config.effective_rules();
        let key = |rule: &str| {
            ConditionKey::new(&config.site, "host_posture", rule, Some(&"t".repeat(48))).unwrap()
        };
        for rule in &rules {
            for action in [Action::Trigger, Action::Resolve] {
                let key = key(rule.rule.id);
                let event = event_id(&key, action, 1_790_942_400);
                let input = IntentInput {
                    config: &config,
                    rule,
                    key: &key,
                    action,
                    resolve_reason: ResolveReason::NoLongerEvaluated,
                    stable_event_id: &event,
                    transition_id: &event,
                    policy_digest: &policy_digest(&rules, &[]),
                    first_seen: Some(1_790_942_400),
                    persisted_seconds: 660,
                    reference: &Value::Null,
                };
                let intent = v1(&input, &config.routes.notice_route, LOCAL_INBOX_LABEL);
                let bytes = local_inbox_message_bytes(&intent);
                assert!(bytes <= LOCAL_INBOX_MESSAGE_MAX, "{} {bytes}", rule.rule.id);
            }
        }
        let mut too_long = config.clone();
        too_long.runbooks.monitor_url = Some(format!("{url}x"));
        assert!(too_long.validate().is_err(), "900 bytes is the maximum");
        let mut longer = config;
        longer.routes.notice_route.push('x');
        assert!(longer.validate().is_err());
    }
}
