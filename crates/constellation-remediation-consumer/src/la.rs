//! Every Linear Accountant call of the model decider, in one place, so a
//! change in the `la_inference` interface touches exactly this module.
//!
//! Protocol `v: 1` (linear-accountant `src/bin/la_inference.rs`):
//! `la_inference [ARGS...] <command>` with one JSON request on stdin (`v`,
//! `cmd`, typed fields, unknown fields denied, identifiers restricted to
//! `[A-Za-z0-9._:/@+=-]{1,128}`) and one line `{"v":1,"cmd":..,"result":..}`
//! on stdout. Exit 0 means a result was emitted (refusals, conflicts and
//! exhaustion included); any other exit is a usage, protocol or storage
//! failure and is never read as a decision. LA keeps its own clock.
//!
//! The child runs through [`crate::external::run`]: no shell, cleared
//! environment, deadline, process-group kill, bounded output. No prompt,
//! response, model text or credential is ever sent to LA: only typed
//! accounting metadata.

use std::time::Duration;

use serde_json::{Map, Value, json};

use crate::config::Model;
use crate::decider::{
    CALL_COST_MICRO_USD, CALL_INPUT_TOKENS, CALL_OUTPUT_TOKENS, EPISODE_COST_MICRO_USD,
    EPISODE_INPUT_TOKENS, EPISODE_OUTPUT_TOKENS, MAX_CALLS, MODEL, RETRY_CEILING, Usage,
    request_policy_digest,
};
use crate::external::{Failure, run};

pub const PROTOCOL_VERSION: u64 = 1;
/// The provider class the owner enrolls for this route: OpenRouter, pinned
/// to its `google-vertex` upstream (`provider.only`, no fallbacks).
pub const LA_PROVIDER: &str = "openrouter/google-vertex";
/// Deadline of one LA command; part of the reasoning wall ceiling.
const LA_TIMEOUT: Duration = Duration::from_secs(10);
const ID_MAX: usize = 128;

/// LA's opaque identifier alphabet.
#[must_use]
pub fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= ID_MAX
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/@+=-".contains(&b))
}

/// The identities of one episode's reservation, all chosen by the trusted
/// shell and saved before `reserve`; a repeated `reserve` with the same
/// binding returns the same reservation.
#[derive(Clone, Debug)]
pub struct Binding<'a> {
    pub episode: &'a str,
    pub condition: &'a str,
    pub campaign: &'a str,
    pub occurrence: &'a str,
    /// The remediation window end: the episode is eligible only while the
    /// evaluator holds its page.
    pub eligibility_valid_until_unix_ms: u64,
    pub deadline_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Reserve {
    Reserved { reservation: String },
    Exhausted { dimension: String },
    Refused { reason: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Begin {
    /// A newly consumed send permission.
    Permitted {
        invocation: String,
    },
    /// This call index already began (identically or not): never a send.
    AlreadyBegun {
        invocation: String,
    },
    Exhausted {
        dimension: String,
    },
    Refused {
        reason: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Settle {
    /// Settled (or an identical replay). `escalation_required`: LA recorded a
    /// reconciliation breach (usage over a ceiling, model mismatch).
    Settled {
        receipt: String,
        escalation_required: bool,
    },
    Conflict {
        reason: String,
    },
    Refused {
        reason: String,
    },
}

/// One `la_inference` command; `Err` is a usage, protocol or storage fault.
fn call(model: &Model, command: &str, mut request: Map<String, Value>) -> Result<Value, String> {
    request.insert("v".into(), json!(PROTOCOL_VERSION));
    request.insert("cmd".into(), json!(command));
    let mut argv = model.la_arguments.clone();
    argv.push(command.to_owned());
    let bytes = serde_json::to_vec(&request).map_err(|error| error.to_string())?;
    let output = run(&model.la_program, &argv, Some(&bytes), LA_TIMEOUT)
        .map_err(|failure: Failure| failure.summary())?;
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("la_inference {command}: stdout is not JSON: {error}"))?;
    if value.get("v").and_then(Value::as_u64) != Some(PROTOCOL_VERSION)
        || value.get("cmd").and_then(Value::as_str) != Some(command)
    {
        return Err(format!(
            "la_inference {command}: not a protocol v{PROTOCOL_VERSION} result"
        ));
    }
    match value.get("result") {
        Some(result) if result.is_object() => Ok(result.clone()),
        _ => Err(format!("la_inference {command}: no result object")),
    }
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

fn outcome(result: &Value) -> &str {
    result.get("outcome").and_then(Value::as_str).unwrap_or("")
}

fn id(result: &Value, pointer: &str, command: &str) -> Result<String, String> {
    result
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|text| valid_id(text))
        .map(str::to_owned)
        .ok_or_else(|| format!("la_inference {command}: result has no {pointer}"))
}

fn reason(result: &Value) -> String {
    result
        .get("reason")
        .and_then(Value::as_str)
        .or_else(|| {
            result
                .pointer("/exhausted/dimension")
                .and_then(Value::as_str)
        })
        .unwrap_or("unspecified")
        .chars()
        .take(160)
        .collect()
}

fn dimension(result: &Value) -> String {
    result
        .pointer("/exhausted/dimension")
        .and_then(Value::as_str)
        .unwrap_or("unspecified")
        .chars()
        .take(32)
        .collect()
}

fn unknown(command: &str, result: &Value) -> String {
    format!(
        "la_inference {command}: unknown outcome {:?}",
        outcome(result)
    )
}

/// `reserve`: the episode's whole bounded allocation, keyed by the episode.
pub fn reserve(model: &Model, binding: &Binding<'_>) -> Result<Reserve, String> {
    let request = json!({
        "admission_id": model.la_admission_id,
        "episode_id": binding.episode,
        "condition_ref": binding.condition,
        "ag_campaign": binding.campaign,
        "ag_occurrence": binding.occurrence,
        "eligibility_ref": model.la_eligibility_ref,
        "eligibility_valid_until_unix_ms": binding.eligibility_valid_until_unix_ms,
        "provider": LA_PROVIDER,
        "model_class": MODEL,
        "bounds": {
            "max_calls": MAX_CALLS,
            "retry_ceiling": RETRY_CEILING,
            "max_input_tokens": EPISODE_INPUT_TOKENS,
            "max_output_tokens": EPISODE_OUTPUT_TOKENS,
            "max_cost_micro_usd": EPISODE_COST_MICRO_USD,
            "max_wall_ms": model.wall_ms,
        },
        "deadline_unix_ms": binding.deadline_unix_ms,
    });
    let result = call(model, "reserve", object(request))?;
    Ok(match outcome(&result) {
        "granted" | "replayed" => Reserve::Reserved {
            reservation: id(&result, "/reservation_id", "reserve")?,
        },
        "exhausted" => Reserve::Exhausted {
            dimension: dimension(&result),
        },
        "refused" | "conflict" => Reserve::Refused {
            reason: format!("{}: {}", outcome(&result), reason(&result)),
        },
        _ => return Err(unknown("reserve", &result)),
    })
}

/// `begin-call`: consume the call's worst case and take the durable send
/// fence for `(reservation, call_index)`. The request is a pure function of
/// its arguments and the configuration, so a repeat after a crash is an
/// identical replay.
pub fn begin_call(model: &Model, reservation: &str, call_index: u32) -> Result<Begin, String> {
    let request = json!({
        "reservation_id": reservation,
        "call_index": call_index,
        "request_policy_digest": request_policy_digest(),
        "max_input_tokens": CALL_INPUT_TOKENS,
        "max_output_tokens": CALL_OUTPUT_TOKENS,
        "max_cost_micro_usd": CALL_COST_MICRO_USD,
        "max_wall_ms": model.total_timeout_ms,
    });
    let result = call(model, "begin-call", object(request))?;
    let permitted = result.get("send_permitted").and_then(Value::as_bool) == Some(true);
    Ok(match outcome(&result) {
        "send_permitted" if permitted => Begin::Permitted {
            invocation: id(&result, "/invocation_id", "begin-call")?,
        },
        "already_begun" | "conflict" if !permitted => Begin::AlreadyBegun {
            invocation: id(&result, "/invocation_id", "begin-call")?,
        },
        "exhausted" if !permitted => Begin::Exhausted {
            dimension: dimension(&result),
        },
        "refused" if !permitted => Begin::Refused {
            reason: reason(&result),
        },
        _ => return Err(unknown("begin-call", &result)),
    })
}

/// `settle`: one terminal class and, when the provider reported them, the
/// typed usage and account charge of one invocation. A `cancelled_unsent`
/// settlement carries no provider data. LA derives the usage source: a
/// missing usage or cost is accounted at the call's full ceiling.
pub fn settle(
    model: &Model,
    invocation: &str,
    terminal: &str,
    usage: Option<&Usage>,
) -> Result<Settle, String> {
    let mut request = Map::new();
    request.insert("invocation_id".into(), json!(invocation));
    request.insert("terminal_class".into(), json!(terminal));
    if let Some(usage) = usage.filter(|_| terminal != "cancelled_unsent") {
        if let Some(reported) = usage.reported_model.as_deref().filter(|m| valid_id(m)) {
            request.insert("reported_model".into(), json!(reported));
        }
        if let Some(generation) = usage.generation_id.as_deref().filter(|g| valid_id(g)) {
            request.insert("provider_generation_id".into(), json!(generation));
        }
        if let (Some(input), Some(output), Some(total)) =
            (usage.input_tokens, usage.output_tokens, usage.total_tokens)
        {
            request.insert(
                "usage".into(),
                json!({"input_units": input, "output_units": output, "total_units": total}),
            );
        }
        if let Some(cost) = &usage.cost_usd {
            request.insert("actual_cost_usd".into(), json!(cost));
        }
    }
    let result = call(model, "settle", request)?;
    Ok(match outcome(&result) {
        "settled" | "replayed" => Settle::Settled {
            receipt: id(&result, "/settlement/receipt", "settle")?,
            escalation_required: result.get("escalation_required").and_then(Value::as_bool)
                != Some(false),
        },
        "conflict" => Settle::Conflict {
            reason: reason(&result),
        },
        "refused" => Settle::Refused {
            reason: reason(&result),
        },
        _ => return Err(unknown("settle", &result)),
    })
}

/// `recover`: settle every open invocation of `reservation` (every
/// reservation when `None`): those in `known_unsent` (this consumer's saved
/// state proves no send) as `cancelled_unsent`, every other one as
/// `crash_unknown` at its ceiling. Returns `(invocation_id, terminal_class)`
/// of each invocation settled now.
pub fn recover(
    model: &Model,
    reservation: Option<&str>,
    known_unsent: &[String],
) -> Result<Vec<(String, String)>, String> {
    let request = json!({"reservation_id": reservation, "known_unsent": known_unsent});
    let result = call(model, "recover", object(request))?;
    if outcome(&result) != "recovered" {
        return Err(format!(
            "la_inference recover: {} {}",
            outcome(&result),
            reason(&result)
        ));
    }
    Ok(result
        .get("settled")
        .and_then(Value::as_array)
        .map(|settled| {
            settled
                .iter()
                .filter_map(|s| {
                    Some((
                        s.get("invocation_id")?.as_str()?.to_owned(),
                        s.get("terminal_class")?.as_str()?.to_owned(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default())
}

/// `close`: end the episode's reasoning and retire the unused allocation.
pub fn close(model: &Model, reservation: &str) -> Result<(), String> {
    let result = call(
        model,
        "close",
        object(json!({"reservation_id": reservation})),
    )?;
    match outcome(&result) {
        "closed" | "already_closed" => Ok(()),
        other => Err(format!("la_inference close: {other} {}", reason(&result))),
    }
}
