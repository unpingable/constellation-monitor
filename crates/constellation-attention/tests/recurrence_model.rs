//! Bounded transition exploration over the real raw and notification steps.
//! Delivery eligibility is an input; NQ and collector internals are not modeled.
use constellation_attention::{
    condition::ConditionKey,
    config::NoticeRecurrence,
    engine,
    inputs::Observation,
    intent::Action,
    recurrence::{self, Memory, Snapshot},
    state::ConditionState,
};
use std::collections::BTreeMap;
fn memory() -> Memory {
    Memory {
        policy: NoticeRecurrence {
            recurrence_horizon_seconds: 120,
            summary_interval_seconds: 60,
        },
        notice_route: "test-notices".into(),
        notice_transport: "slack".into(),
        issuance_epoch: "0123456789abcdef0123456789abcdef".into(),
        next_sequence: 0,
        entries: BTreeMap::new(),
    }
}
fn raw() -> ConditionState {
    ConditionState {
        key: ConditionKey::new("reference", "nq", recurrence::RULE, Some("nqd.stale")).unwrap(),
        rule_version: 1,
        input_label: "nqd".into(),
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
}
fn open() -> (Memory, ConditionState) {
    let mut m = memory();
    let mut c = raw();
    for (time, observation) in [
        (0, Observation::Present),
        (301, Observation::Present),
        (360, Observation::Clear),
        (480, Observation::Clear),
        (481, Observation::Present),
        (782, Observation::Present),
    ] {
        // The model uses a longer horizon only to establish recurrence; explored quiet
        // closure then uses the minimum admissible horizon.
        m.policy.recurrence_horizon_seconds = 600;
        let t = engine::step(&mut c, observation, 300, time);
        m.step(&c.key, "nqd", observation, t, c.active, true, time)
            .unwrap();
    }
    m.policy.recurrence_horizon_seconds = 120;
    assert!(m.entries[&c.key.id()].opened_at.is_some());
    (m, c)
}
#[test]
fn bounded_recurrence_transition_model_preserves_raw_state_and_closure_boundary() {
    // 4^6 observation histories x 2^6 delivery-eligibility histories = 262144.
    // Each advances in 60-second steps, including unknown-gap exclusion,
    // removal, below-bound presence and summary/final-resolution priority.
    let (initial, raw_initial) = open();
    for encoded in 0_u32..262_144 {
        let mut choices = encoded;
        let mut m = initial.clone();
        let mut c = raw_initial.clone();
        let mut reference = c.clone();
        for index in 0..6 {
            let digit = choices % 8;
            choices /= 8;
            let obs = [
                Observation::Present,
                Observation::Clear,
                Observation::Unknown,
                Observation::Removed,
            ][(digit % 4) as usize];
            let eligible = digit < 4;
            let now = 842 + index * 60;
            if m.entries[&c.key.id()].removed && obs != Observation::Removed {
                let before = m.clone();
                assert!(
                    m.step(&c.key, "nqd", obs, None, c.active, eligible, now)
                        .is_err()
                );
                assert_eq!(m, before);
                break; // The real pass refuses before persisting any state.
            }
            let transition = engine::step(&mut c, obs, 300, now);
            assert_eq!(transition, engine::step(&mut reference, obs, 300, now));
            let before = c.clone();
            let was_open = m.entries[&c.key.id()].opened_at.is_some();
            let decision = m
                .step(&c.key, "nqd", obs, transition, c.active, eligible, now)
                .unwrap();
            assert_eq!(c, before);
            assert_eq!(c, reference);
            let e = &m.entries[&c.key.id()];
            assert!(e.coalesced_transitions <= e.raw_transitions);
            assert!(e.pending_transitions <= e.raw_transitions);
            if was_open && !eligible {
                assert!(decision.is_none());
            }
            if let Some(d) = decision
                && let Some(s) = d.snapshot
            {
                if d.action == Action::Resolve && s.kind == "quiet_recovery" {
                    assert_eq!(obs, Observation::Clear);
                    assert!(!c.active);
                    assert!(now - e.quiet_since.unwrap() >= 120);
                }
                if s.kind == "removed" {
                    assert_eq!(d.action, Action::Resolve);
                }
                if s.kind == "summary" {
                    assert_eq!(d.action, Action::Trigger);
                }
            }
        }
    }
}
#[test]
fn recurrence_event_counter_refuses_wrap_and_clock_reset_keeps_unique_lineage() {
    let mut m = memory();
    let first = m.event_id(Action::Trigger, 1000).unwrap();
    m.reset_clock(0);
    let second = m.event_id(Action::Trigger, 1000).unwrap();
    assert_ne!(first, second);
    assert!(second.len() <= 256);
    m.next_sequence = u64::MAX;
    assert!(m.event_id(Action::Trigger, 1000).is_err());
    assert_eq!(m.next_sequence, u64::MAX);
}
#[test]
fn recurrence_summary_retains_full_identity_and_qualifier_at_maximum_input_bounds() {
    let site = "g".repeat(64);
    let label = "g".repeat(34);
    let target = "g".repeat(48);
    let key = ConditionKey::new(&site, "host_posture", recurrence::RULE, Some(&target)).unwrap();
    for kind in ["recurrence_started", "summary", "quiet_recovery", "removed"] {
        let s = Snapshot {
            kind: kind.into(),
            observation: "unknown".into(),
            raw_transitions: u64::MAX,
            coalesced_transitions: u64::MAX,
            pending_transitions: u64::MAX,
            decided_at: i64::MAX,
        };
        let text = recurrence::summary(&key, &label, &s).unwrap();
        assert!(text.len() <= 512);
        assert!(text.contains(&key.id()));
        assert!(text.contains("Notice episode; evidence: unknown."));
        assert!(text.contains(if kind == "removed" {
            "Recovery was not observed"
        } else {
            "service recovery not established"
        }));
    }
}
