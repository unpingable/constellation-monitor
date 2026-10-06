//! Notice episodes, never observation state or operational authority.
//!
//! Raw lifecycle decisions are inputs. This module cannot modify them.
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;

use serde::{Deserialize, Serialize};

use crate::condition::{ConditionKey, validate_token};
use crate::config::{Config, NoticeRecurrence};
use crate::inputs::Observation;
use crate::intent::Action;
use crate::registry::UNKNOWN_GAP_SECONDS;
use crate::state::{ConditionState, LastIntent};

pub const MAX_ENTRIES: usize = 1024;
pub const RULE: &str = "evaluator-input-unavailable";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Memory {
    pub policy: NoticeRecurrence,
    pub notice_route: String,
    pub notice_transport: String,
    /// Random event-issuance namespace, not an authority or secret.
    pub issuance_epoch: String,
    pub next_sequence: u64,
    pub entries: BTreeMap<String, Episode>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Episode {
    pub key: ConditionKey,
    pub input_label: String,
    pub last_resolved_at: Option<i64>,
    pub opened_at: Option<i64>,
    pub quiet_since: Option<i64>,
    pub unknown_since: Option<i64>,
    /// Latest decided notice action, independent of raw condition.active.
    pub notice_active: bool,
    pub announcement_pending: bool,
    pub removed: bool,
    pub raw_transitions: u64,
    pub coalesced_transitions: u64,
    pub pending_transitions: u64,
    pub last_decided_at: Option<i64>,
    pub last_summary: Option<Snapshot>,
    pub blocked_custody: bool,
    pub last_notice_event_id: Option<String>,
    pub last_notification_id: Option<String>,
    pub last_notice_outcome: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub kind: String,
    pub observation: String,
    pub raw_transitions: u64,
    pub coalesced_transitions: u64,
    pub pending_transitions: u64,
    pub decided_at: i64,
}

pub struct Decision {
    pub action: Action,
    pub snapshot: Option<Snapshot>,
}

#[must_use]
pub fn observation_name(observation: Observation) -> &'static str {
    match observation {
        Observation::Present => "present",
        Observation::Clear => "clear",
        Observation::Unknown => "unknown",
        Observation::Removed => "removed",
    }
}

/// An uncertain or unretained notice keeps its exact bytes; a new summary
/// does not turn uncertainty into definite delivery or nondelivery.
#[must_use]
pub fn may_replace(last: Option<&LastIntent>) -> bool {
    last.is_none_or(|last| {
        last.outcome == "accepted"
            || (last.outcome == "refused" && !last.network)
            || (last.notification_id.is_some()
                && matches!(last.outcome.as_str(), "failed" | "refused"))
    })
}

#[must_use]
pub fn unsettled(last: &LastIntent) -> bool {
    last.outcome != "accepted" && !(last.outcome == "refused" && !last.network)
}

#[must_use]
pub fn delivery_snapshot(condition: &ConditionState, memory: Option<&Memory>) -> ConditionState {
    let mut snapshot = condition.clone();
    if condition.key.rule == RULE
        && let Some(entry) = memory.and_then(|memory| memory.entries.get(&condition.key.id()))
    {
        snapshot.active = entry.notice_active;
    }
    snapshot
}

fn increment(value: &mut u64) -> Result<(), String> {
    *value = value
        .checked_add(1)
        .ok_or("recurrence counter exhausted; refusing pass")?;
    Ok(())
}

impl Memory {
    pub fn new(config: &Config) -> Result<Self, String> {
        let mut random = [0_u8; 16];
        File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut random))
            .map_err(|error| format!("cannot establish notice issuance epoch: {error}"))?;
        let issuance_epoch = random.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(Self {
            policy: config
                .notice_recurrence
                .clone()
                .ok_or("recurrence policy absent")?,
            notice_route: config.routes.notice_route.clone(),
            notice_transport: config.routes.notice_transport.destination_label().into(),
            issuance_epoch,
            next_sequence: 0,
            entries: BTreeMap::new(),
        })
    }

    pub fn validate(&self, site: &str) -> Result<(), String> {
        self.policy.validate()?;
        if self.issuance_epoch.len() != 32
            || !self
                .issuance_epoch
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.entries.len() > MAX_ENTRIES
        {
            return Err("invalid or oversized recurrence memory".into());
        }
        for (id, entry) in &self.entries {
            let key = ConditionKey::new(
                &entry.key.site,
                &entry.key.component,
                &entry.key.rule,
                entry.key.target_class.as_deref(),
            )?;
            validate_token("recurrence input label", &entry.input_label, 34)?;
            if key.id() != *id
                || key.site != site
                || key.rule != RULE
                || entry.coalesced_transitions > entry.raw_transitions
                || entry.pending_transitions > entry.raw_transitions
                || entry.last_summary.as_ref().is_some_and(|summary| {
                    !matches!(
                        summary.observation.as_str(),
                        "present" | "clear" | "unknown" | "removed"
                    )
                })
            {
                return Err("recurrence memory identity or counters are invalid".into());
            }
        }
        Ok(())
    }

    pub fn check_binding(&self, config: &Config) -> Result<(), String> {
        if config.notice_recurrence.as_ref() != Some(&self.policy)
            || self.notice_route != config.routes.notice_route
            || self.notice_transport != config.routes.notice_transport.destination_label()
        {
            return Err("recurrence policy/notice route changed; retire settled recurrence state before re-enrollment".into());
        }
        Ok(())
    }

    pub fn event_id(&mut self, action: Action, now: i64) -> Result<String, String> {
        increment(&mut self.next_sequence)?;
        Ok(format!(
            "recurrence-{}-{}-{}-{now}",
            self.issuance_epoch,
            self.next_sequence,
            action.as_str()
        ))
    }

    /// Only an emission snapshot resets pending counts; it says decided,
    /// never delivered. Exact bytes and NQ outcomes remain in normal custody.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "One bounded episode transition with explicit raw inputs and delivery eligibility."
    )]
    pub fn step(
        &mut self,
        key: &ConditionKey,
        input_label: &str,
        observation: Observation,
        raw_transition: Option<Action>,
        raw_active: bool,
        may_emit: bool,
        now: i64,
    ) -> Result<Option<Decision>, String> {
        let id = key.id();
        if !self.entries.contains_key(&id) {
            if raw_transition.is_none() {
                return Ok(None);
            }
            if self.entries.len() >= MAX_ENTRIES {
                return Err("recurrence memory capacity exhausted".into());
            }
            self.entries.insert(
                id.clone(),
                Episode {
                    key: key.clone(),
                    input_label: input_label.into(),
                    last_resolved_at: None,
                    opened_at: None,
                    quiet_since: None,
                    unknown_since: None,
                    notice_active: raw_active,
                    announcement_pending: false,
                    removed: false,
                    raw_transitions: 0,
                    coalesced_transitions: 0,
                    pending_transitions: 0,
                    last_decided_at: None,
                    last_summary: None,
                    blocked_custody: false,
                    last_notice_event_id: None,
                    last_notification_id: None,
                    last_notice_outcome: None,
                },
            );
        }
        let entry = self.entries.get_mut(&id).expect("inserted episode");
        if entry.removed && observation != Observation::Removed {
            return Err("removed recurrence scope still has custody; reconcile removal before restoring enrollment".into());
        }
        entry.input_label = input_label.into();
        let starts = entry.opened_at.is_none()
            && raw_transition == Some(Action::Trigger)
            && entry
                .last_resolved_at
                .is_some_and(|at| now.saturating_sub(at) <= self.policy.recurrence_horizon_seconds);
        if starts {
            entry.opened_at = Some(now);
            entry.announcement_pending = true;
            entry.raw_transitions = 0;
            entry.coalesced_transitions = 0;
            entry.pending_transitions = 0;
            entry.quiet_since = None;
            entry.unknown_since = None;
        }
        // Ordinary episodes preserve existing submission/trigger-before-resolve policy.
        if entry.opened_at.is_none() {
            if let Some(action) = raw_transition {
                entry.notice_active = action == Action::Trigger;
                entry.last_resolved_at =
                    (action == Action::Resolve && observation == Observation::Clear).then_some(now);
                entry.removed = observation == Observation::Removed;
                entry.last_decided_at = Some(now);
                return Ok(Some(Decision {
                    action,
                    snapshot: None,
                }));
            }
            if observation == Observation::Removed {
                entry.removed = true;
            }
            return Ok(None);
        }
        if raw_transition.is_some() {
            increment(&mut entry.raw_transitions)?;
            increment(&mut entry.pending_transitions)?;
            if !starts {
                increment(&mut entry.coalesced_transitions)?;
            }
        }
        let shift = entry
            .unknown_since
            .map(|since| now.saturating_sub(since))
            .filter(|duration| *duration > UNKNOWN_GAP_SECONDS);
        match observation {
            Observation::Present => {
                entry.quiet_since = None;
                entry.unknown_since = None;
            }
            Observation::Clear => {
                if let (Some(duration), Some(since)) = (shift, entry.quiet_since.as_mut()) {
                    *since = since.saturating_add(duration).min(now);
                }
                entry.unknown_since = None;
                entry.quiet_since.get_or_insert(now);
            }
            Observation::Unknown => {
                if entry.quiet_since.is_some() {
                    entry.unknown_since.get_or_insert(now);
                }
            }
            Observation::Removed => {
                entry.removed = true;
                entry.quiet_since = None;
                entry.unknown_since = None;
            }
        }
        entry.blocked_custody = !may_emit;
        if !may_emit {
            return Ok(None);
        }
        let (action, kind) = if entry.removed {
            (Action::Resolve, "removed")
        } else if entry.announcement_pending {
            (Action::Trigger, "recurrence_started")
        } else if observation == Observation::Clear
            && !raw_active
            && entry.quiet_since.is_some_and(|since| {
                now.saturating_sub(since) >= self.policy.recurrence_horizon_seconds
            })
        {
            (Action::Resolve, "quiet_recovery")
        } else if entry.pending_transitions > 0
            && entry
                .last_decided_at
                .is_some_and(|at| now.saturating_sub(at) >= self.policy.summary_interval_seconds)
        {
            (Action::Trigger, "summary")
        } else {
            return Ok(None);
        };
        let snapshot = Snapshot {
            kind: kind.into(),
            observation: observation_name(observation).into(),
            raw_transitions: entry.raw_transitions,
            coalesced_transitions: entry.coalesced_transitions,
            pending_transitions: entry.pending_transitions,
            decided_at: now,
        };
        entry.last_summary = Some(snapshot.clone());
        entry.last_decided_at = Some(now);
        entry.pending_transitions = 0;
        entry.announcement_pending = false;
        entry.notice_active = action == Action::Trigger;
        if action == Action::Resolve {
            entry.opened_at = None;
            entry.last_resolved_at = (observation == Observation::Clear).then_some(now);
        }
        Ok(Some(Decision {
            action,
            snapshot: Some(snapshot),
        }))
    }

    pub fn reset_clock(&mut self, now: i64) -> usize {
        let mut count = 0;
        for entry in self.entries.values_mut() {
            for at in [
                &mut entry.last_resolved_at,
                &mut entry.opened_at,
                &mut entry.quiet_since,
                &mut entry.unknown_since,
                &mut entry.last_decided_at,
            ]
            .into_iter()
            .flatten()
            {
                if *at > now {
                    *at = now;
                    count += 1;
                }
            }
            // last_summary is a frozen decision record, not a scheduling clock.
        }
        count
    }

    pub fn refresh_delivery(&mut self, conditions: &BTreeMap<String, ConditionState>) {
        for (id, entry) in &mut self.entries {
            if let Some(last) = conditions
                .get(id)
                .and_then(|condition| condition.last_intent.get("notice"))
            {
                entry.last_notice_event_id = Some(last.stable_event_id.clone());
                entry.last_notification_id.clone_from(&last.notification_id);
                entry.last_notice_outcome = Some(last.outcome.clone());
                entry.blocked_custody = !may_replace(Some(last));
            }
        }
    }

    pub fn prune(&mut self, conditions: &BTreeMap<String, ConditionState>, now: i64) {
        self.entries.retain(|id, entry| {
            let custody = conditions.get(id).is_some_and(|condition| {
                !condition.pending_trigger.is_empty()
                    || condition.last_intent.get("notice").is_some_and(unsettled)
            });
            custody
                || entry.opened_at.is_some()
                || entry.notice_active
                || (!entry.removed
                    && entry.last_resolved_at.is_some_and(|at| {
                        now.saturating_sub(at) <= self.policy.recurrence_horizon_seconds
                    }))
        });
    }
}

/// The full machine ID and qualifier are retained within NQ's 512-byte bound.
pub fn summary(key: &ConditionKey, label: &str, snapshot: &Snapshot) -> Result<String, String> {
    let title = match snapshot.kind.as_str() {
        "quiet_recovery" => "monitoring evidence restored",
        "removed" => "monitoring no longer evaluated",
        _ => "recurring evidence loss",
    };
    let qualifier = if snapshot.kind == "removed" {
        "Recovery was not observed."
    } else {
        "Monitoring only; service recovery not established."
    };
    let text = format!(
        "{}/{label}: {title}.\nNotice episode: {}.\nChanges: {} raw, {} coalesced, {} included.\n{qualifier}\nInspect collector/acquisition.\nID: {}",
        key.site,
        snapshot.observation,
        snapshot.raw_transitions,
        snapshot.coalesced_transitions,
        snapshot.pending_transitions,
        key.id()
    );
    if text.len() > 512 {
        return Err("recurrence summary exceeds NQ bound; refusing lossy rendering".into());
    }
    Ok(text)
}
