//! Per-condition lifecycle state, persisted atomically as JSON.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::condition::ConditionKey;
use crate::util::{read_bounded, write_atomic};

pub const STATE_SCHEMA: &str = "constellation.attention_state.v1";
const MAX_STATE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub schema: String,
    pub site: String,
    /// Unix seconds of the last completed pass.
    pub updated_at: i64,
    pub conditions: BTreeMap<String, ConditionState>,
    /// Evaluation-history mode: every NQ watcher instance ever seen, per NQ
    /// status input label, with its newest `evaluated_at` (unix seconds). A
    /// watcher that leaves the window stays stale from that time until the
    /// operator lists it in `retired_instances`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub nq_watchers: BTreeMap<String, BTreeMap<String, i64>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionState {
    pub key: ConditionKey,
    pub rule_version: u32,
    pub input_label: String,
    /// Start of the current continuous presence (unix seconds).
    pub first_seen: Option<i64>,
    /// Last pass that observed presence.
    pub last_seen: Option<i64>,
    /// Start of the current clear interval while active.
    pub clear_since: Option<i64>,
    /// First unknown observation since the last definite one, while a
    /// persistence or confirmation interval is open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unknown_since: Option<i64>,
    /// A trigger has been decided and no resolve since.
    pub active: bool,
    /// Unix seconds of the latest trigger/resolve decision (the transition epoch).
    pub transition_at: Option<i64>,
    /// Newest intent per route role (`page`, `notice`).
    pub last_intent: BTreeMap<String, LastIntent>,
    /// Triggers NQ never retained when a resolve replaced them. Each is
    /// submitted once more before that resolve, then forgotten: retained, or
    /// reported as a dropped trigger.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pending_trigger: BTreeMap<String, LastIntent>,
    /// `auto_remediate_then_page`: triggered, notice sent, page held for the
    /// remediation window.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub page_deferred: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LastIntent {
    pub stable_event_id: String,
    pub transition_id: String,
    /// `trigger` or `resolve`.
    pub action: String,
    pub route: String,
    pub schema: String,
    /// NQ's record id once NQ has answered.
    pub notification_id: Option<String>,
    /// `unknown` until NQ answers; then NQ's `delivery_state`, or
    /// `command_error` when NQ refused the command before custody.
    pub outcome: String,
    /// Whether the submission could deliver: it carried `--enable-network`,
    /// or went to a local inbox. A refusal without it is deliberate.
    pub network: bool,
    /// Unix seconds of the latest submission attempt.
    pub at: i64,
    /// Intent file (relative to the state directory) holding the exact bytes.
    pub intent_file: String,
}

impl State {
    #[must_use]
    pub fn empty(site: &str) -> Self {
        Self {
            schema: STATE_SCHEMA.into(),
            site: site.into(),
            updated_at: 0,
            conditions: BTreeMap::new(),
            nq_watchers: BTreeMap::new(),
        }
    }

    /// Load the state file. A missing file is an empty state; an unreadable or
    /// malformed one is an error, never silently replaced.
    pub fn load(path: &Path, site: &str) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::empty(site));
        }
        let bytes = read_bounded(path, MAX_STATE_BYTES)?;
        let state: Self = serde_json::from_slice(&bytes)
            .map_err(|error| format!("state file {} is malformed: {error}", path.display()))?;
        if state.schema != STATE_SCHEMA {
            return Err(format!("state file schema is not {STATE_SCHEMA}"));
        }
        if state.site != site {
            return Err(format!(
                "state file belongs to site {:?}, configuration names {site:?}",
                state.site
            ));
        }
        Ok(state)
    }

    /// Recover from a forward clock step that has since been corrected:
    /// every timestamp later than `now` becomes `now`. Returns how many were
    /// clamped. Nothing is deleted; open conditions and retained intents
    /// stay as they are.
    pub fn reset_clock(&mut self, now: i64) -> usize {
        let mut clamped = 0;
        let mut clamp = |value: &mut i64| {
            if *value > now {
                *value = now;
                clamped += 1;
            }
        };
        clamp(&mut self.updated_at);
        for roster in self.nq_watchers.values_mut() {
            for at in roster.values_mut() {
                clamp(at);
            }
        }
        for condition in self.conditions.values_mut() {
            for value in [
                &mut condition.first_seen,
                &mut condition.last_seen,
                &mut condition.clear_since,
                &mut condition.unknown_since,
                &mut condition.transition_at,
            ]
            .into_iter()
            .flatten()
            {
                clamp(value);
            }
            for last in condition
                .last_intent
                .values_mut()
                .chain(condition.pending_trigger.values_mut())
            {
                clamp(&mut last.at);
            }
        }
        clamped
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let mut bytes = serde_json::to_vec_pretty(self).map_err(|error| error.to_string())?;
        bytes.push(b'\n');
        write_atomic(path, &bytes)
    }
}
