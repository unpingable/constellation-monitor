//! The model decider's reasoning phase, inside the one consumer pass: after
//! the v1 evidence gates and the saved episode, before `ag init`.
//!
//! Sequence: saved episode → LA `reserve` → per call: saved call record →
//! LA `begin-call` → saved send permission → provider call → LA `settle` →
//! saved settlement and decision → (start only) LA `close`, fresh report,
//! window and precondition → the v1 AG/Docket path from the pinned plan.
//!
//! Crash law: nothing is sent unless its permission was saved first; a call
//! whose permission was saved and whose settlement was not is charged at its
//! ceiling and never repeated; a settled but unsaved decision is lost and the
//! episode escalates. No deterministic start ever replaces a model decision.

use std::thread;
use std::time::Duration;

use serde_json::{Value, json};

use super::{Decider, Fresh, Pass, Resolved};
use crate::config::Model;
use crate::decider::{
    self, Answer, CALL_INPUT_TOKENS, Decision, MAX_CALLS, Usage, Verdict, judge_response,
};
use crate::la::{self, Begin, Binding, Reserve, Settle};
use crate::provider::{self, SendError};
use crate::report::{Selection, select_with_margin};
use crate::store::{Call, write_atomic};

/// Allowance inside the wall ceiling for one settlement after a call.
const SETTLE_ALLOWANCE_MS: u64 = 2_000;

/// How a call's usage is known, as this consumer judged it (LA derives its
/// own from what it is given: no usage or cost means the full ceiling).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UsageSource {
    ProviderReported,
    CeilingAssumed,
    Unsent,
}

impl UsageSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ProviderReported => "provider_reported",
            Self::CeilingAssumed => "ceiling_assumed",
            Self::Unsent => "unsent",
        }
    }
}

/// What one call came to.
struct Judged {
    terminal: &'static str,
    usage: Usage,
    source: UsageSource,
    verdict: Option<Verdict>,
    /// Malformed answer, provider error or a proven-unsent failure: one more
    /// call may follow. Never after a timeout or an uncertain send.
    retryable: bool,
    /// Episode outcome when this call ends the reasoning without a verdict.
    outcome: &'static str,
    detail: Value,
}

fn judge(sent: Result<provider::Exchange, SendError>) -> Judged {
    match sent {
        Ok(exchange) => {
            let (answer, usage) = judge_response(exchange.status, &exchange.body);
            let source = if usage.complete() {
                UsageSource::ProviderReported
            } else {
                UsageSource::CeilingAssumed
            };
            if let Some(dimension) = usage.breach() {
                return Judged {
                    terminal: "accounting_error",
                    usage,
                    source,
                    verdict: None,
                    retryable: false,
                    outcome: "accounting_breach",
                    detail: json!({"dimension": dimension, "http_status": exchange.status}),
                };
            }
            let base = |terminal, verdict, retryable, outcome, detail| Judged {
                terminal,
                usage: usage.clone(),
                source,
                verdict,
                retryable,
                outcome,
                detail,
            };
            match answer {
                Answer::Verdict(verdict) => base(
                    match verdict.decision {
                        Decision::StartCanary => "proposal",
                        Decision::Abstain => "abstain",
                        Decision::Escalate => "escalate",
                    },
                    Some(verdict),
                    false,
                    "",
                    json!({"decision": verdict.decision.as_str(), "reason": verdict.reason.as_str()}),
                ),
                Answer::Malformed(why) => base(
                    "malformed",
                    None,
                    true,
                    "retry_exhausted",
                    json!({"why": why, "http_status": exchange.status}),
                ),
                Answer::ProviderError(why) => base(
                    "provider_error",
                    None,
                    true,
                    "retry_exhausted",
                    json!({"why": why, "http_status": exchange.status}),
                ),
            }
        }
        Err(SendError::Unsent(why)) => Judged {
            terminal: "cancelled_unsent",
            usage: Usage::default(),
            source: UsageSource::Unsent,
            verdict: None,
            retryable: true,
            outcome: "retry_exhausted",
            detail: json!({"why": why}),
        },
        Err(SendError::Timeout(why)) => Judged {
            terminal: "timeout",
            usage: Usage::default(),
            source: UsageSource::CeilingAssumed,
            verdict: None,
            retryable: false,
            outcome: "timeout",
            detail: json!({"why": why}),
        },
        Err(SendError::Uncertain(why)) => Judged {
            terminal: "provider_error",
            usage: Usage::default(),
            source: UsageSource::CeilingAssumed,
            verdict: None,
            retryable: false,
            outcome: "send_uncertain",
            detail: json!({"why": why}),
        },
    }
}

fn usage_detail(usage: &Usage) -> Value {
    json!({
        "input_tokens": usage.input_tokens,
        "output_tokens": usage.output_tokens,
        "total_tokens": usage.total_tokens,
        "cost_micro_usd": usage.cost_micro_usd,
        "generation_id": usage.generation_id,
        "reported_model": usage.reported_model,
        "reported_provider": usage.reported_provider,
    })
}

impl Pass<'_> {
    fn model_config(&self) -> Result<Model, String> {
        self.config.model().cloned()
    }

    /// Window that must still remain after the reasoning wall ceiling: the
    /// same room the opening margin reserved for dispatch, dwell and clear.
    fn post_reasoning_margin(model: &Model) -> i64 {
        model.window_min_seconds - i64::try_from(model.wall_ms / 1000).unwrap_or(i64::MAX)
    }

    fn update_call(&mut self, index: u32, change: impl FnOnce(&mut Call)) -> Result<(), String> {
        self.update(|episode| {
            if let Some(call) = episode
                .reasoning
                .as_mut()
                .and_then(|reasoning| reasoning.calls.iter_mut().find(|c| c.index == index))
            {
                change(call);
            }
        })
    }

    /// Re-establish the episode's evidence: the same condition episode is
    /// still selected with `margin` seconds left and the precondition is
    /// current under the episode's own identities.
    fn revalidate(&mut self, margin: i64) -> Result<Result<Fresh, (String, Value)>, String> {
        let episode = self.active()?;
        let path = self.config.consumer.report.clone();
        let report: Value = match std::fs::read(&path)
            .map_err(|error| error.to_string())
            .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|error| error.to_string()))
        {
            Ok(report) => report,
            Err(error) => return Ok(Err(("report_unreadable".into(), json!({"error": error})))),
        };
        let candidate = match select_with_margin(self.config, &report, self.now_seconds(), margin) {
            Selection::Act(candidate) => candidate,
            Selection::Abstain { reason, detail } => return Ok(Err((reason.into(), detail))),
        };
        if candidate.condition_id != episode.condition_id
            || candidate.first_seen != episode.first_seen
        {
            return Ok(Err((
                "episode_changed".into(),
                json!({"first_seen": candidate.first_seen}),
            )));
        }
        let observation =
            self.observation_id(&episode.campaign, &episode.occurrence, "unit-not-active");
        let Resolved {
            status,
            detail,
            fields,
        } = self.resolve(
            false,
            &episode.campaign,
            &episode.occurrence,
            &observation,
            &episode.subject,
        )?;
        match fields {
            Some(fields) if status == "current" => Ok(Ok(Fresh { candidate, fields })),
            _ => Ok(Err((format!("precondition_{status}"), detail))),
        }
    }

    /// Close the episode from the reasoning phase: LA `close` first (a
    /// failure is recorded, the episode closes anyway), no AG work.
    pub(super) fn end_reasoning(&mut self, outcome: &str, detail: Value) -> Result<String, String> {
        let episode = self.active()?;
        let reasoning = episode.reasoning.clone().unwrap_or_default();
        if let (Some(reservation), false, Some(model)) = (
            &reasoning.reservation,
            reasoning.la_closed,
            &self.config.model,
        ) {
            let closed = la::close(model, reservation);
            if closed.is_ok() {
                self.update(|e| {
                    if let Some(r) = e.reasoning.as_mut() {
                        r.la_closed = true;
                    }
                })?;
            }
            self.event(
                "la_closed",
                json!({"outcome": outcome, "ok": closed.is_ok(), "error": closed.err()}),
            )?;
        }
        self.close(outcome, detail)
    }

    /// The reasoning loop; `fresh` is the evidence the opening gates just
    /// established (absent on resume: it is re-established).
    pub(super) fn reason(&mut self, fresh: Option<Fresh>) -> Result<String, String> {
        let model = self.model_config()?;
        let after_margin = Self::post_reasoning_margin(&model);
        let mut fresh = fresh;
        loop {
            let episode = self.active()?;
            let reasoning = episode.reasoning.clone().unwrap_or_default();
            let deadline = reasoning.deadline_unix_ms;
            let Some(reservation) = reasoning.reservation.clone() else {
                if self.now() >= deadline {
                    return self.end_reasoning("wall_exhausted", json!({"stage": "reserve"}));
                }
                let binding = Binding {
                    episode: &episode.episode,
                    condition: &episode.condition_id,
                    campaign: &episode.campaign,
                    occurrence: &episode.occurrence,
                    eligibility_valid_until_unix_ms: u64::try_from(episode.window_until)
                        .unwrap_or(0)
                        .saturating_mul(1000),
                    deadline_unix_ms: deadline,
                };
                match la::reserve(&model, &binding) {
                    Ok(Reserve::Reserved { reservation }) => {
                        let kept = reservation.clone();
                        self.update(|e| {
                            if let Some(r) = e.reasoning.as_mut() {
                                r.reservation = Some(kept);
                            }
                        })?;
                        self.event("la_reserved", json!({"reservation": reservation}))?;
                        continue;
                    }
                    Ok(Reserve::Exhausted { dimension }) => {
                        return self.end_reasoning(
                            "budget_exhausted",
                            json!({"stage": "reserve", "dimension": dimension}),
                        );
                    }
                    Ok(Reserve::Refused { reason }) => {
                        return self.end_reasoning("la_refused", json!({"reason": reason}));
                    }
                    Err(error) => {
                        return self.end_reasoning("la_unavailable", json!({"error": error}));
                    }
                }
            };
            let index = u32::try_from(reasoning.calls.len()).unwrap_or(u32::MAX);
            if index >= MAX_CALLS {
                return self.end_reasoning("retry_exhausted", json!({"calls": index}));
            }
            let current = match fresh.take() {
                Some(current) if index == 0 => current,
                _ => {
                    if index > 0 {
                        let pause = model
                            .retry_backoff_ms
                            .min(deadline.saturating_sub(self.now()));
                        thread::sleep(Duration::from_millis(pause));
                    }
                    match self.revalidate(after_margin)? {
                        Ok(current) => current,
                        Err((why, detail)) => {
                            return self.end_reasoning(
                                "evidence_not_current",
                                json!({"why": why, "detail": detail}),
                            );
                        }
                    }
                }
            };
            if self
                .now()
                .saturating_add(model.total_timeout_ms)
                .saturating_add(SETTLE_ALLOWANCE_MS)
                > deadline
            {
                return self
                    .end_reasoning("wall_exhausted", json!({"stage": "call", "index": index}));
            }
            let remaining = current.candidate.window_until - self.now_seconds();
            let evidence = decider::evidence(
                &current.fields,
                &episode.prestate,
                &self.config.enrollment.unit,
                &current.candidate.projection,
                remaining,
                &current.candidate.narration,
            );
            let body = decider::request_body(&evidence);
            let bound = decider::input_token_bound(&body).unwrap_or(u64::MAX);
            if bound > CALL_INPUT_TOKENS {
                return self.end_reasoning(
                    "token_bound_exceeded",
                    json!({"bound": bound, "ceiling": CALL_INPUT_TOKENS}),
                );
            }
            let dir = self.store.episode_dir(&episode.episode)?;
            write_atomic(
                &dir.join(format!("evidence-{index}.json")),
                &decider_bytes(&evidence),
            )?;
            // Barrier 1: the call exists before LA is asked for it.
            self.update(|e| {
                if let Some(r) = e.reasoning.as_mut() {
                    r.calls.push(Call {
                        index,
                        state: "begin_requested".into(),
                        ..Call::default()
                    });
                }
            })?;
            let invocation = match la::begin_call(&model, &reservation, index) {
                Ok(Begin::Permitted { invocation }) => invocation,
                Ok(Begin::AlreadyBegun { invocation }) => {
                    // Not ours to send: whatever began it may have sent.
                    let kept = invocation.clone();
                    self.update_call(index, |c| {
                        c.state = "begun".into();
                        c.invocation = Some(kept);
                    })?;
                    self.recover_open(&model, &reservation, &[])?;
                    return self.end_reasoning("send_uncertain", json!({"index": index}));
                }
                Ok(Begin::Exhausted { dimension }) => {
                    self.update_call(index, |c| c.state = "refused".into())?;
                    return self.end_reasoning(
                        "budget_exhausted",
                        json!({"stage": "begin_call", "index": index, "dimension": dimension}),
                    );
                }
                Ok(Begin::Refused { reason }) => {
                    self.update_call(index, |c| c.state = "refused".into())?;
                    return self
                        .end_reasoning("la_refused", json!({"index": index, "reason": reason}));
                }
                Err(error) => {
                    return self.end_reasoning(
                        "la_unavailable",
                        json!({"stage": "begin_call", "index": index, "error": error}),
                    );
                }
            };
            // Barrier 2: the send permission is saved before the send.
            let kept = invocation.clone();
            self.update_call(index, |c| {
                c.state = "begun".into();
                c.invocation = Some(kept);
            })?;
            self.event(
                "model_call_started",
                json!({"index": index, "invocation": invocation, "input_token_bound": bound}),
            )?;
            let sent = provider::post(&model, body);
            if let Ok(exchange) = &sent {
                let mut record = serde_json::to_vec(&json!({
                    "http_status": exchange.status,
                    "body": String::from_utf8_lossy(&exchange.body),
                }))
                .map_err(|error| error.to_string())?;
                record.push(b'\n');
                write_atomic(&dir.join(format!("response-{index}.json")), &record)?;
            }
            let judged = judge(sent);
            let settled = la::settle(&model, &invocation, judged.terminal, Some(&judged.usage));
            let (receipt, breach) = match settled {
                Ok(Settle::Settled {
                    receipt,
                    escalation_required,
                }) => (receipt, escalation_required),
                other => {
                    let why = match other {
                        Ok(Settle::Conflict { reason }) => format!("conflict: {reason}"),
                        Ok(Settle::Refused { reason }) => format!("refused: {reason}"),
                        Err(error) => error,
                        Ok(Settle::Settled { .. }) => String::new(),
                    };
                    self.event(
                        "model_call_unsettled",
                        json!({"index": index, "terminal": judged.terminal, "error": why}),
                    )?;
                    return self.end_reasoning(
                        "settlement_failed",
                        json!({"index": index, "terminal": judged.terminal}),
                    );
                }
            };
            // Barrier 3: settlement and decision saved together.
            let verdict = judged.verdict;
            let kept = receipt.clone();
            self.update(|e| {
                if let Some(r) = e.reasoning.as_mut() {
                    if let Some(call) = r.calls.iter_mut().find(|c| c.index == index) {
                        call.state = "settled".into();
                        call.terminal = Some(judged.terminal.to_owned());
                        call.usage_source = Some(judged.source.as_str().to_owned());
                        call.receipt = Some(kept);
                        call.retryable = judged.retryable;
                    }
                    if let Some(verdict) = verdict {
                        r.decision = Some(verdict.decision.as_str().to_owned());
                        r.reason = Some(verdict.reason.as_str().to_owned());
                    }
                }
            })?;
            self.event(
                "model_call_settled",
                json!({
                    "index": index,
                    "terminal": judged.terminal,
                    "usage_source": judged.source.as_str(),
                    "usage": usage_detail(&judged.usage),
                    "receipt": receipt,
                    "la_escalation_required": breach,
                    "detail": judged.detail,
                }),
            )?;
            if breach {
                // LA recorded a reconciliation breach (usage over a ceiling,
                // another model): reasoning is frozen whatever the answer.
                return self.end_reasoning(
                    "accounting_breach",
                    json!({"index": index, "terminal": judged.terminal}),
                );
            }
            match verdict.map(|v| v.decision) {
                Some(Decision::StartCanary) => return self.accept_decision(),
                Some(Decision::Abstain) => {
                    return self.end_reasoning("model_abstained", judged.detail);
                }
                Some(Decision::Escalate) => {
                    return self.end_reasoning("model_escalated", judged.detail);
                }
                None if judged.retryable && index + 1 < MAX_CALLS => {}
                None => {
                    return self.end_reasoning(
                        judged.outcome,
                        json!({"index": index, "terminal": judged.terminal, "detail": judged.detail}),
                    );
                }
            }
        }
    }

    /// The saved decision is `start_canary/current_down`: close LA, then
    /// re-check report, window and precondition, then the v1 path.
    fn accept_decision(&mut self) -> Result<String, String> {
        let model = self.model_config()?;
        let episode = self.active()?;
        let reasoning = episode.reasoning.clone().unwrap_or_default();
        if let (Some(reservation), false) = (&reasoning.reservation, reasoning.la_closed) {
            match la::close(&model, reservation) {
                Ok(()) => {
                    self.update(|e| {
                        if let Some(r) = e.reasoning.as_mut() {
                            r.la_closed = true;
                        }
                    })?;
                    self.event("la_closed", json!({"outcome": "proposal", "ok": true}))?;
                }
                Err(error) => {
                    return self.end_reasoning("la_close_failed", json!({"error": error}));
                }
            }
        }
        match self.revalidate(Self::post_reasoning_margin(&model))? {
            Ok(_) => {}
            Err((why, detail)) => {
                return self.close(
                    "evidence_not_current_before_ag",
                    json!({"why": why, "detail": detail}),
                );
            }
        }
        self.update(|e| e.phase = "opening".into())?;
        self.event(
            "decision_accepted",
            json!({"decision": reasoning.decision, "reason": reasoning.reason}),
        )?;
        self.begin_campaign()
    }

    /// LA `recover` for this reservation: every open invocation is settled,
    /// those in `known_unsent` as `cancelled_unsent`, all others as
    /// `crash_unknown` at their ceiling. Never re-sends.
    fn recover_open(
        &mut self,
        model: &Model,
        reservation: &str,
        known_unsent: &[String],
    ) -> Result<(), String> {
        let recovered = la::recover(model, Some(reservation), known_unsent);
        if let Ok(settled) = &recovered {
            for (invocation, terminal) in settled {
                let (invocation, terminal) = (invocation.clone(), terminal.clone());
                self.update(|e| {
                    if let Some(call) = e.reasoning.as_mut().and_then(|r| {
                        r.calls
                            .iter_mut()
                            .find(|c| c.invocation.as_deref() == Some(invocation.as_str()))
                    }) {
                        call.state = "settled".into();
                        call.usage_source = Some(
                            if terminal == "cancelled_unsent" {
                                UsageSource::Unsent
                            } else {
                                UsageSource::CeilingAssumed
                            }
                            .as_str()
                            .to_owned(),
                        );
                        call.terminal = Some(terminal);
                    }
                })?;
            }
        }
        self.event(
            "la_recovered",
            json!({
                "known_unsent": known_unsent,
                "settled": recovered.as_ref().ok(),
                "error": recovered.as_ref().err(),
            }),
        )
    }

    /// LA's restart law, run before any new work of a model-mode pass: every
    /// call this consumer's durable state shows begun but unsettled (in any
    /// episode, open or closed) is settled through one `recover`, the
    /// never-sent ones named `known_unsent`; reservations of closed episodes
    /// that missed their LA `close` are closed. `Err` when LA could not be
    /// brought up to date.
    pub(super) fn la_sweep(&mut self) -> Result<(), String> {
        let Some(model) = self.config.model.clone() else {
            return Ok(());
        };
        let open = |state: &str| state == "begin_requested" || state == "begun";
        let episodes: Vec<(Option<usize>, crate::store::Reasoning)> = self
            .state
            .active
            .iter()
            .map(|e| (None, e))
            .chain(
                self.state
                    .closed
                    .iter()
                    .enumerate()
                    .map(|(i, e)| (Some(i), e)),
            )
            .filter_map(|(i, e)| e.reasoning.clone().map(|r| (i, r)))
            .filter(|(i, r)| {
                r.reservation.is_some()
                    && (r.calls.iter().any(|c| open(&c.state)) || (i.is_some() && !r.la_closed))
            })
            .collect();
        if episodes.is_empty() {
            return Ok(());
        }
        let mut known_unsent = Vec::new();
        let mut needs_recover = false;
        for (slot, reasoning) in &episodes {
            let reservation = reasoning.reservation.clone().unwrap_or_default();
            for call in reasoning.calls.iter().filter(|c| open(&c.state)) {
                needs_recover = true;
                if call.state != "begin_requested" {
                    continue;
                }
                // Never sent: its permission was never saved. Learn its id.
                let invocation = match la::begin_call(&model, &reservation, call.index) {
                    Ok(Begin::Permitted { invocation } | Begin::AlreadyBegun { invocation }) => {
                        invocation
                    }
                    Ok(_) => continue,
                    Err(error) => return Err(error),
                };
                self.set_call(*slot, call.index, |c| {
                    c.invocation = Some(invocation.clone())
                });
                known_unsent.push(invocation);
            }
        }
        if needs_recover {
            let settled = la::recover(&model, None, &known_unsent)?;
            for (invocation, terminal) in &settled {
                for slot in episodes.iter().map(|(slot, _)| *slot) {
                    self.set_call_by_invocation(slot, invocation, terminal);
                }
            }
            // A global recover leaves no invocation open at LA: whatever this
            // state still shows open was settled before (or never begun).
            for slot in episodes.iter().map(|(slot, _)| *slot) {
                if let Some(reasoning) = self.reasoning_at(slot) {
                    for call in reasoning.calls.iter_mut().filter(|c| open(&c.state)) {
                        if call.invocation.is_some() {
                            call.state = "settled".into();
                            call.terminal
                                .get_or_insert_with(|| "settled_before_recovery".into());
                        } else {
                            call.state = "never_begun".into();
                        }
                    }
                }
            }
            self.store.event(
                self.now(),
                "la_recovered",
                None,
                json!({"known_unsent": known_unsent, "settled": settled}),
            )?;
        }
        for (slot, reasoning) in &episodes {
            let (Some(index), Some(reservation)) = (slot, &reasoning.reservation) else {
                continue;
            };
            if reasoning.la_closed {
                continue;
            }
            la::close(&model, reservation)?;
            if let Some(r) = self.state.closed[*index].reasoning.as_mut() {
                r.la_closed = true;
            }
        }
        self.save()
    }

    fn reasoning_at(&mut self, slot: Option<usize>) -> Option<&mut crate::store::Reasoning> {
        match slot {
            None => self.state.active.as_mut(),
            Some(index) => self.state.closed.get_mut(index),
        }
        .and_then(|episode| episode.reasoning.as_mut())
    }

    fn set_call(&mut self, slot: Option<usize>, index: u32, change: impl FnOnce(&mut Call)) {
        if let Some(call) = self
            .reasoning_at(slot)
            .and_then(|r| r.calls.iter_mut().find(|c| c.index == index))
        {
            change(call);
        }
    }

    fn set_call_by_invocation(&mut self, slot: Option<usize>, invocation: &str, terminal: &str) {
        if let Some(call) = self.reasoning_at(slot).and_then(|r| {
            r.calls
                .iter_mut()
                .find(|c| c.invocation.as_deref() == Some(invocation))
        }) {
            call.state = "settled".into();
            call.terminal = Some(terminal.to_owned());
            call.usage_source = Some(
                if terminal == "cancelled_unsent" {
                    UsageSource::Unsent
                } else {
                    UsageSource::CeilingAssumed
                }
                .as_str()
                .to_owned(),
            );
        }
    }

    /// Restart inside the reasoning phase.
    pub(super) fn resume_reasoning(&mut self) -> Result<String, String> {
        if self.decider != Decider::Model || self.config.model.is_none() {
            return self.close("reasoning_interrupted", json!({"why": "not in model mode"}));
        }
        let model = self.model_config()?;
        let episode = self.active()?;
        let reasoning = episode.reasoning.clone().unwrap_or_default();
        match reasoning.decision.as_deref() {
            Some("start_canary") => return self.accept_decision(),
            Some("abstain") => return self.end_reasoning("model_abstained", json!({})),
            Some("escalate") => return self.end_reasoning("model_escalated", json!({})),
            Some(other) => {
                return self.end_reasoning("reasoning_interrupted", json!({"decision": other}));
            }
            None => {}
        }
        let open: Vec<Call> = reasoning
            .calls
            .iter()
            .filter(|c| c.state == "begin_requested" || c.state == "begun")
            .cloned()
            .collect();
        if !open.is_empty() {
            let reservation = reasoning.reservation.clone().unwrap_or_default();
            let mut known_unsent = Vec::new();
            for call in open.iter().filter(|c| c.state == "begin_requested") {
                // Its permission was never saved, so it was never sent: learn
                // the invocation (an identical begin-call replays it, or
                // begins one that this pass will not send) and cancel it.
                match la::begin_call(&model, &reservation, call.index) {
                    Ok(Begin::Permitted { invocation } | Begin::AlreadyBegun { invocation }) => {
                        let kept = invocation.clone();
                        self.update_call(call.index, |c| c.invocation = Some(kept))?;
                        known_unsent.push(invocation);
                    }
                    other => {
                        self.event(
                            "model_call_orphan_unbegun",
                            json!({"index": call.index, "result": format!("{other:?}")}),
                        )?;
                    }
                }
            }
            // Every saved send permission without a settlement: charged at its
            // ceiling (`crash_unknown`), never repeated.
            self.recover_open(&model, &reservation, &known_unsent)?;
            return self.end_reasoning(
                "reasoning_interrupted",
                json!({"open_calls": open.iter().map(|c| c.index).collect::<Vec<_>>()}),
            );
        }
        if let Some(last) = reasoning.calls.last()
            && !(last.retryable && reasoning.calls.len() < MAX_CALLS as usize)
        {
            return self.end_reasoning(
                if last.retryable {
                    "retry_exhausted"
                } else {
                    "reasoning_interrupted"
                },
                json!({"terminal": last.terminal}),
            );
        }
        self.reason(None)
    }
}

fn decider_bytes(value: &Value) -> Vec<u8> {
    let mut bytes = constellation_remediation_resolver::jcs(value);
    bytes.push(b'\n');
    bytes
}
