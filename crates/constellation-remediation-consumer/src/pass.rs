//! One deterministic pass: finish or reconcile the open episode, else judge
//! the report and open at most one episode. AG's campaign store is the program
//! counter; the consumer's own state only adds the dispatch fence and the
//! episode bookkeeping.

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use constellation_remediation_resolver::{
    ACTIVE_BASIS_TYPE, BASIS_TYPE, REQUEST_SCHEMA, ResolutionFields, hash_domain, jcs,
};
use serde_json::{Value, json};

use crate::config::{Config, Plan};
use crate::external::{External, Failure};
use crate::report::{Candidate, Selection, select_with_margin};
use crate::store::{Episode, OpenError, Reasoning, State, Store, write_atomic};

mod reasoning;

pub const PASS_SCHEMA: &str = "constellation.remediation-consumer.pass/v1";
const EPISODE_DOMAIN: &str = "constellation.remediation.episode/v1";
const CAMPAIGN_DOMAIN: &str = "constellation.remediation.campaign/v1";
const PROGRAM_DOMAIN: &str = "constellation.remediation.program/v1";
const OBSERVATION_DOMAIN: &str = "constellation.remediation.observation/v1";
const TERMINAL_DOMAIN: &str = "constellation.remediation.terminal-witness/v1";
const PLAN_SCHEMA: &str = "ag-effectd.docket-executor-systemd-plan/v2";
const PROPOSAL_SCHEMA: &str = "ag.governed-loop.exact-work-proposal/v1";
/// AG program counters at which authority is spent but not settled.
const UNRESOLVED: [&str; 3] = [
    "authorization_consumed",
    "dispatched",
    "reconciliation_required",
];
const DRIVE_STEPS_MAX: usize = 32;

/// What a pass did, printed as one JSON line.
#[derive(Clone, Debug)]
pub struct Summary {
    pub pass: String,
    pub result: String,
    pub episode: Option<String>,
}

impl Summary {
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "schema": PASS_SCHEMA,
            "pass": self.pass,
            "result": self.result,
            "episode": self.episode,
        })
    }
}

/// Which decider judges a selected condition episode.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Decider {
    /// v1: the verified precondition alone opens the AG occurrence.
    #[default]
    Deterministic,
    /// v2: one bounded, LA-accounted model call (one retry) chooses among
    /// `start_canary`, `abstain` and `escalate` before any AG work.
    Model,
}

impl Decider {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "deterministic" => Ok(Self::Deterministic),
            "model" => Ok(Self::Model),
            other => Err(format!(
                "--decider must be deterministic or model, not {other:?}"
            )),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Deterministic => "deterministic",
            Self::Model => "model",
        }
    }
}

/// Run one deterministic pass. `now_ms` is the clock (injectable for tests).
pub fn run_pass(config: &Config, now_ms: &dyn Fn() -> u64) -> Result<Summary, String> {
    run_pass_with(config, Decider::Deterministic, now_ms)
}

/// Run one pass with the chosen decider.
pub fn run_pass_with(
    config: &Config,
    decider: Decider,
    now_ms: &dyn Fn() -> u64,
) -> Result<Summary, String> {
    if decider == Decider::Model {
        config.model()?;
    }
    let pass_id = random_hex(8)?;
    let store = match Store::open(&config.consumer.state_dir, pass_id.clone()) {
        Ok(store) => store,
        Err(OpenError::Busy) => {
            return Ok(Summary {
                pass: pass_id,
                result: "busy".into(),
                episode: None,
            });
        }
        Err(OpenError::Failed(error)) => return Err(error),
    };
    let state = store.load()?;
    let mut pass = Pass {
        config,
        decider,
        external: External { config },
        store,
        state,
        now_ms,
    };
    let active = pass.state.active.clone();
    pass.store.event(
        now_ms(),
        "pass_started",
        active.as_ref(),
        json!({"phase": active.as_ref().map(|e| &e.phase)}),
    )?;
    // LA's restart law before any new work: settle what an earlier pass left
    // begun. A failure blocks new reasoning, never a v1 campaign in flight.
    let swept = if decider == Decider::Model {
        pass.la_sweep()
    } else {
        Ok(())
    };
    if let Err(error) = &swept {
        pass.store.event(
            now_ms(),
            "la_recovery_failed",
            active.as_ref(),
            json!({"error": error}),
        )?;
    }
    let result = match (&active, swept) {
        (Some(_), _) => pass.resume()?,
        (None, Ok(())) => pass.consider()?,
        (None, Err(error)) => pass.abstain("la_recovery_failed", json!({"error": error}))?,
    };
    let episode = pass
        .state
        .active
        .as_ref()
        .or(pass.state.closed.last())
        .filter(|_| result != "abstained")
        .map(|e| e.episode.clone());
    pass.store.event(
        now_ms(),
        "pass_finished",
        pass.state.active.as_ref(),
        json!({"result": result}),
    )?;
    Ok(Summary {
        pass: pass_id,
        result,
        episode,
    })
}

struct Pass<'a> {
    config: &'a Config,
    decider: Decider,
    external: External<'a>,
    store: Store,
    state: State,
    now_ms: &'a dyn Fn() -> u64,
}

/// One resolver answer: its status (or the consumer's own `unbound`,
/// `malformed`, `resolver_failed`), the recorded detail, and the typed fields
/// when the record was well formed and bound.
pub(crate) struct Resolved {
    pub status: String,
    pub detail: Value,
    pub fields: Option<ResolutionFields>,
}

/// Evidence re-established for one model call.
pub(crate) struct Fresh {
    pub candidate: Candidate,
    pub fields: ResolutionFields,
}

/// A chosen, verified owner plan.
struct Chosen {
    prestate: String,
    path: PathBuf,
    subject: String,
    scope: String,
    work: String,
}

fn failure_detail(failure: &Failure) -> Value {
    json!({"argv": failure.argv, "code": failure.code, "message": failure.message})
}

/// The program counter of an AG occurrence snapshot.
#[must_use]
pub fn program_counter(snapshot: &Value) -> Option<String> {
    let state = snapshot.get("state")?.as_object()?;
    if state.len() != 1 {
        return None;
    }
    state.keys().next().cloned()
}

/// Docket's standing refusal reason inside an AG dispatch failure, as a
/// closed token: the grant resolver prints `execution-standing refused:
/// execution-standing-grant-<reason>`.
#[must_use]
pub fn docket_refusal(message: &str) -> String {
    const PREFIX: &str = "execution-standing-grant-";
    message
        .find(PREFIX)
        .map(|start| {
            message[start + PREFIX.len()..]
                .chars()
                .take_while(|c| c.is_ascii_lowercase() || *c == '-')
                .collect::<String>()
        })
        .filter(|reason| !reason.is_empty())
        .map_or_else(
            || "docket_refused".to_owned(),
            |reason| format!("grant_{}", reason.replace('-', "_")),
        )
}

/// A dispatch failure that is Docket's own refusal (its process exited
/// non-zero and AG reports the external boundary refused), as opposed to a
/// timeout, a killed or unreachable boundary.
fn docket_refused(failure: &Failure) -> bool {
    failure.code.is_some_and(|code| code != 0)
        && failure.message.contains("external boundary refused")
        && failure.message.contains("external-process:")
}

fn find_string(value: &Value, key: &str) -> Option<String> {
    match value {
        Value::Object(map) => map
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| map.values().find_map(|child| find_string(child, key))),
        Value::Array(items) => items.iter().find_map(|child| find_string(child, key)),
        _ => None,
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn random_bytes<const N: usize>() -> Result<[u8; N], String> {
    let mut bytes = [0u8; N];
    fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|error| format!("/dev/urandom: {error}"))?;
    Ok(bytes)
}

fn random_hex(bytes: usize) -> Result<String, String> {
    let raw: [u8; 32] = random_bytes()?;
    Ok(raw[..bytes.min(32)]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// A fresh random RFC 4122 v4 UUID, lowercase hyphenated.
fn uuid_v4() -> Result<String, String> {
    let mut raw: [u8; 16] = random_bytes()?;
    raw[6] = (raw[6] & 0x0f) | 0x40;
    raw[8] = (raw[8] & 0x3f) | 0x80;
    let hex: String = raw.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    write_atomic(path, &jcs(value))
}

impl Pass<'_> {
    fn now(&self) -> u64 {
        (self.now_ms)()
    }

    fn now_seconds(&self) -> i64 {
        i64::try_from(self.now() / 1000).unwrap_or(i64::MAX)
    }

    fn event(&mut self, event: &str, detail: Value) -> Result<(), String> {
        let now = self.now();
        let active = self.state.active.clone();
        self.store.event(now, event, active.as_ref(), detail)
    }

    fn save(&self) -> Result<(), String> {
        self.store.save(&self.state)
    }

    fn active(&self) -> Result<Episode, String> {
        self.state
            .active
            .clone()
            .ok_or_else(|| "no open episode".to_owned())
    }

    fn update(&mut self, change: impl FnOnce(&mut Episode)) -> Result<(), String> {
        if let Some(active) = self.state.active.as_mut() {
            change(active);
        }
        self.save()
    }

    fn abstain(&mut self, reason: &str, detail: Value) -> Result<String, String> {
        self.event("abstained", json!({"reason": reason, "detail": detail}))?;
        Ok("abstained".into())
    }

    fn close(&mut self, outcome: &str, detail: Value) -> Result<String, String> {
        let now = self.now();
        let active = self.state.active.clone();
        self.store.event(
            now,
            "episode_closed",
            active.as_ref(),
            json!({"outcome": outcome, "detail": detail, "record": active}),
        )?;
        self.state.close(outcome, now);
        self.save()?;
        Ok(outcome.to_owned())
    }

    // ---- opening ---------------------------------------------------------

    fn consider(&mut self) -> Result<String, String> {
        let path = self.config.consumer.report.clone();
        let report: Value = match fs::read(&path)
            .map_err(|error| error.to_string())
            .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|error| error.to_string()))
        {
            Ok(report) => report,
            Err(error) => {
                return self.abstain("report_unreadable", json!({"report": path, "error": error}));
            }
        };
        let margin = match self.decider {
            Decider::Deterministic => self.config.consumer.window_margin_seconds,
            Decider::Model => self.config.model()?.window_min_seconds,
        };
        let candidate = match select_with_margin(self.config, &report, self.now_seconds(), margin) {
            Selection::Act(candidate) => candidate,
            Selection::Abstain { reason, detail } => return self.abstain(reason, detail),
        };
        let episode_id = hash_domain(
            EPISODE_DOMAIN,
            &jcs(&json!({
                "condition_id": candidate.condition_id,
                "first_seen": candidate.first_seen,
            })),
        );
        let candidate_detail = json!({
            "episode": episode_id,
            "condition_id": candidate.condition_id,
            "first_seen": candidate.first_seen,
            "remediation_window_until": candidate.window_until,
            "page_deferred": candidate.page_deferred,
            "report_evaluated_at": candidate.evaluated_at,
        });
        if self.state.seen(&episode_id) {
            return self.abstain("episode_already_attempted", candidate_detail);
        }
        if let Some(until) = self.state.last_window_until
            && self.now_seconds() < until
        {
            return self.abstain(
                "attempt_within_previous_window",
                json!({"candidate": candidate_detail, "previous_window_until": until}),
            );
        }
        let chosen = match self.choose_plan() {
            Ok(chosen) => chosen,
            Err((reason, detail)) => return self.abstain(reason, detail),
        };
        let campaign = hash_domain(
            CAMPAIGN_DOMAIN,
            &jcs(&json!({
                "episode": episode_id,
                "instance_id": self.config.enrollment.instance_id,
                "unit": self.config.enrollment.unit,
                "nonce": random_hex(16)?,
            })),
        );
        let occurrence = uuid_v4()?;
        let observation = self.observation_id(&campaign, &occurrence, "unit-not-active");
        let resolved =
            self.resolve(false, &campaign, &occurrence, &observation, &chosen.subject)?;
        if resolved.status != "current" {
            return self.abstain(
                &format!("precondition_{}", resolved.status),
                json!({"candidate": candidate_detail, "resolution": resolved.detail}),
            );
        }
        let fresh = match (self.decider, resolved.fields) {
            (Decider::Deterministic, _) => None,
            (Decider::Model, Some(fields)) => {
                let model = self.config.model()?;
                if let Err(error) = crate::provider::credentials_ready(model) {
                    return self.abstain("model_key_unavailable", json!({"error": error}));
                }
                Some(Fresh {
                    candidate: candidate.clone(),
                    fields,
                })
            }
            (Decider::Model, None) => {
                return self.abstain(
                    "precondition_malformed",
                    json!({"candidate": candidate_detail, "resolution": resolved.detail}),
                );
            }
        };
        if let Err((reason, detail)) = self.retire_prior_campaign() {
            return self.abstain(reason, detail);
        }
        let reasoning = fresh.as_ref().map(|_| {
            let now = self.now();
            Reasoning {
                started_at_unix_ms: now,
                deadline_unix_ms: now
                    .saturating_add(self.config.model.as_ref().map_or(0, |m| m.wall_ms)),
                ..Reasoning::default()
            }
        });
        self.state.active = Some(Episode {
            episode: episode_id,
            condition_id: candidate.condition_id,
            first_seen: candidate.first_seen,
            window_until: candidate.window_until,
            page_deferred_at_open: candidate.page_deferred,
            prestate: chosen.prestate,
            plan: chosen.path,
            work: chosen.work.clone(),
            subject: chosen.subject.clone(),
            scope: chosen.scope.clone(),
            campaign: campaign.clone(),
            occurrence: occurrence.clone(),
            phase: if reasoning.is_some() {
                "reasoning".into()
            } else {
                "opening".into()
            },
            opened_at_unix_ms: self.now(),
            decider: reasoning.as_ref().map(|_| "model".to_owned()),
            reasoning,
            ..Episode::default()
        });
        self.state.last_window_until = Some(candidate.window_until);
        self.save()?;
        let mut opened = candidate_detail;
        opened["decider"] = json!(self.decider.as_str());
        self.event("episode_opened", opened)?;
        if let Some(fresh) = fresh {
            return self.reason(Some(fresh));
        }
        self.begin_campaign()
    }

    /// Write the episode's genesis and proposal from the pinned plan and the
    /// shell's own identities, initialise the AG occurrence and drive it.
    fn begin_campaign(&mut self) -> Result<String, String> {
        let episode = self.active()?;
        let (campaign, occurrence) = (episode.campaign.clone(), episode.occurrence.clone());
        let observation = self.observation_id(&campaign, &occurrence, "unit-not-active");
        let dir = self.store.episode_dir(&episode.episode)?;
        let genesis = dir.join("genesis.json");
        write_json(
            &genesis,
            &json!({
                "campaign": campaign,
                "occurrence": occurrence,
                "program": self.program(),
                "expected_ag_work": episode.work,
                "residuals": [],
                "budget": {
                    "retry_limit": 0, "retries_used": 0,
                    "probe_limit": 0, "probes_used": 0,
                    "escalation_limit": 0, "escalations_used": 0,
                },
            }),
        )?;
        write_json(
            &dir.join("proposal.json"),
            &json!({
                "observation": observation,
                "proposal": {
                    "schema": PROPOSAL_SCHEMA,
                    "campaign": campaign,
                    "subject": episode.subject,
                    "scope": episode.scope,
                    "work_schema": self.config.ag.work_schema,
                    "work": episode.work,
                    "repair": null,
                },
                "class": "initial",
            }),
        )?;
        let init = self.external.ag_init(&genesis, &episode.plan);
        self.step_event("init", &init)?;
        if init.is_err() && !self.config.ag.database.exists() {
            return self.close("refused_at_init", json!({}));
        }
        self.update(|e| e.phase = "driving".into())?;
        self.drive()
    }

    fn program(&self) -> String {
        let e = &self.config.enrollment;
        hash_domain(
            PROGRAM_DOMAIN,
            &jcs(&json!({
                "unit": e.unit,
                "instance_id": e.instance_id,
                "machine_id": e.machine_id,
                "scenario": "one governed start of the enrolled unit; independent postcondition",
            })),
        )
    }

    fn observation_id(&self, campaign: &str, occurrence: &str, claim: &str) -> String {
        let e = &self.config.enrollment;
        hash_domain(
            OBSERVATION_DOMAIN,
            &jcs(&json!({
                "campaign": campaign,
                "occurrence": occurrence,
                "claim": claim,
                "instance_id": e.instance_id,
                "unit": e.unit,
                "machine_id": e.machine_id,
            })),
        )
    }

    /// Pick the owner plan for the unit's prestate and verify it names only
    /// the enrolled unit, a Start, and this machine.
    fn choose_plan(&mut self) -> Result<Chosen, (&'static str, Value)> {
        let plans = &self.config.ag.plans;
        let plan: &Plan = if plans.len() == 1 {
            &plans[0]
        } else {
            let active_state = self
                .external
                .unit_active_state()
                .map_err(|failure| ("prestate_unreadable", failure_detail(&failure)))?;
            plans
                .iter()
                .find(|plan| plan.prestate == active_state)
                .ok_or((
                    "prestate_not_enrolled",
                    json!({"active_state": active_state}),
                ))?
        };
        let mismatch = |why: &str| ("plan_not_enrolled", json!({"plan": plan.path, "why": why}));
        let document: Value = fs::read(&plan.path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .ok_or_else(|| mismatch("unreadable"))?;
        let text = |pointer: &str| document.pointer(pointer).and_then(Value::as_str);
        let e = &self.config.enrollment;
        if text("/schema") != Some(PLAN_SCHEMA) {
            return Err(mismatch("schema"));
        }
        if text("/effect/kind") != Some("systemd_unit")
            || text("/effect/unit") != Some(e.unit.as_str())
            || text("/effect/action") != Some("start")
        {
            return Err(mismatch("effect is not a start of the enrolled unit"));
        }
        if text("/effect/expected_active_state") != Some(plan.prestate.as_str()) {
            return Err(mismatch("prestate"));
        }
        if text("/systemd_machine_identity") != Some(e.machine_id.as_str()) {
            return Err(mismatch("machine"));
        }
        let (Some(subject), Some(scope)) = (text("/subject"), text("/scope")) else {
            return Err(mismatch("subject or scope"));
        };
        if !is_digest(subject) || !is_digest(scope) {
            return Err(mismatch("subject or scope"));
        }
        let work = self
            .external
            .plan_id(&plan.path)
            .map_err(|failure| ("plan_unidentified", failure_detail(&failure)))?;
        if !is_digest(&work) {
            return Err(("plan_unidentified", json!({"work": work})));
        }
        Ok(Chosen {
            prestate: plan.prestate.clone(),
            path: plan.path.clone(),
            subject: subject.to_owned(),
            scope: scope.to_owned(),
            work,
        })
    }

    /// Run the precondition (`post == false`) or postcondition resolver the
    /// way AG does, and record its answer.
    fn resolve(
        &mut self,
        post: bool,
        campaign: &str,
        occurrence: &str,
        observation: &str,
        subject: &str,
    ) -> Result<Resolved, String> {
        let a = &self.config.ag;
        let (resolver, resolver_id, basis_type) = if post {
            (
                &a.postcondition_resolver,
                &a.postcondition_resolver_id,
                ACTIVE_BASIS_TYPE,
            )
        } else {
            (
                &a.observation_resolver,
                &a.observation_resolver_id,
                BASIS_TYPE,
            )
        };
        let request = json!({
            "schema": REQUEST_SCHEMA,
            "key": {"campaign": campaign, "occurrence": occurrence},
            "observation": observation,
            "subject": subject,
            "now_unix_ms": self.now(),
        });
        let mut fields = None;
        let (status, detail) = match self.external.resolve(resolver, &jcs(&request)) {
            Ok((resolution, note)) => {
                let status = resolution
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("malformed")
                    .to_owned();
                let bound = resolution.get("resolver_id").and_then(Value::as_str)
                    == Some(resolver_id.as_str())
                    && resolution
                        .pointer("/basis/basis_type")
                        .and_then(Value::as_str)
                        == Some(basis_type);
                let status = if bound { status } else { "unbound".to_owned() };
                if bound {
                    fields = ResolutionFields::from_value(&resolution).ok();
                }
                (
                    status,
                    json!({
                        "note": note,
                        "currentness": resolution.get("currentness"),
                        "fresh_until_unix_ms": resolution.get("fresh_until_unix_ms"),
                        "basis_type": resolution.pointer("/basis/basis_type"),
                    }),
                )
            }
            Err(failure) => ("resolver_failed".to_owned(), failure_detail(&failure)),
        };
        let event = if post {
            "postcondition"
        } else {
            "precondition"
        };
        let mut recorded = detail.clone();
        recorded["status"] = json!(status);
        recorded["occurrence"] = json!(occurrence);
        self.event(event, recorded)?;
        Ok(Resolved {
            status,
            detail,
            fields,
        })
    }

    /// Archive the previous episode's campaign so this episode can be
    /// initialised at the pinned path; refuse while its authority is
    /// unresolved (spent, dispatched or indeterminate).
    fn retire_prior_campaign(&mut self) -> Result<(), (&'static str, Value)> {
        let database = self.config.ag.database.clone();
        if !database.exists() {
            return Ok(());
        }
        let snapshot = self
            .external
            .ag_status()
            .map_err(|failure| ("prior_campaign_unreadable", failure_detail(&failure)))?;
        let pc = program_counter(&snapshot).unwrap_or_default();
        if UNRESOLVED.contains(&pc.as_str()) {
            return Err((
                "prior_campaign_unresolved",
                json!({"program_counter": pc, "campaign": find_string(&snapshot, "campaign")}),
            ));
        }
        let parent = database.parent().unwrap_or(Path::new("/"));
        let name = database
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        let target = parent
            .join("archive")
            .join(format!("{}-{}", self.now(), self.store.pass()));
        let moved: Result<Vec<String>, String> = (|| {
            fs::create_dir_all(&target).map_err(|error| error.to_string())?;
            let mut moved = Vec::new();
            for entry in fs::read_dir(parent).map_err(|error| error.to_string())? {
                let entry = entry.map_err(|error| error.to_string())?;
                let file = entry.file_name().to_string_lossy().into_owned();
                if file.starts_with(&name) {
                    fs::rename(entry.path(), target.join(&file))
                        .map_err(|error| error.to_string())?;
                    moved.push(file);
                }
            }
            Ok(moved)
        })();
        let detail = json!({
            "program_counter": pc,
            "campaign": find_string(&snapshot, "campaign"),
            "archive": target,
        });
        match moved {
            Ok(files) => {
                let _ = self.event(
                    "campaign_archived",
                    json!({"detail": detail, "files": files}),
                );
                Ok(())
            }
            Err(error) => Err((
                "prior_campaign_unarchivable",
                json!({"detail": detail, "error": error}),
            )),
        }
    }

    // ---- driving ---------------------------------------------------------

    fn resume(&mut self) -> Result<String, String> {
        let episode = self.active()?;
        self.event("episode_resumed", json!({"phase": episode.phase}))?;
        if episode.phase == "reasoning" {
            return self.resume_reasoning();
        }
        if episode.phase == "opening" && !self.config.ag.database.exists() {
            // Crashed before `init`: nothing exists in AG, nothing was spent.
            return self.close("interrupted_before_init", json!({}));
        }
        self.drive()
    }

    fn step_event(&mut self, step: &str, result: &Result<Value, Failure>) -> Result<(), String> {
        let detail = match result {
            Ok(output) => json!({
                "step": step,
                "ok": true,
                "program_counter": program_counter(output)
                    .or_else(|| output.get("record").and_then(program_counter)),
                "result": output.get("result"),
            }),
            Err(failure) => json!({"step": step, "ok": false, "failure": failure_detail(failure)}),
        };
        self.event("ag_step", detail)
    }

    /// Run one AG step; on failure decide from AG's own state whether it
    /// moved anyway. Returns `None` when the step was refused.
    fn ag_step(
        &mut self,
        step: &str,
        before: &str,
        call: impl FnOnce(&External<'_>) -> Result<Value, Failure>,
    ) -> Result<Option<Value>, String> {
        let result = call(&self.external);
        self.step_event(step, &result)?;
        match result {
            Ok(value) => Ok(Some(value)),
            Err(failure) => match self.external.ag_status() {
                Ok(snapshot) if program_counter(&snapshot).as_deref() != Some(before) => {
                    Ok(Some(snapshot))
                }
                _ => {
                    self.event(
                        "ag_refused",
                        json!({"step": step, "failure": failure_detail(&failure)}),
                    )?;
                    Ok(None)
                }
            },
        }
    }

    fn drive(&mut self) -> Result<String, String> {
        for _ in 0..DRIVE_STEPS_MAX {
            let episode = self.active()?;
            let snapshot = match self.external.ag_status() {
                Ok(snapshot) => snapshot,
                Err(failure) => {
                    self.event("ag_unreadable", failure_detail(&failure))?;
                    if self.now_seconds() >= episode.window_until {
                        return self.close("ag_unreadable", failure_detail(&failure));
                    }
                    return Ok("pending".into());
                }
            };
            if find_string(&snapshot, "campaign").as_deref() != Some(episode.campaign.as_str()) {
                return self.close(
                    "foreign_campaign",
                    json!({"found": find_string(&snapshot, "campaign")}),
                );
            }
            let pc = program_counter(&snapshot).unwrap_or_default();
            let plan = episode.plan.clone();
            let refused = |step: &str| format!("refused_at_{step}");
            match pc.as_str() {
                "observation_required" => {
                    if snapshot
                        .pointer("/state/observation_required/prior")
                        .is_some_and(|prior| !prior.is_null())
                    {
                        return self.postcondition(Some(snapshot));
                    }
                    let input = self
                        .store
                        .episode_dir(&episode.episode)?
                        .join("proposal.json");
                    if self
                        .ag_step("record-proposal", &pc, |x| x.ag_record_proposal(&input))?
                        .is_none()
                    {
                        return self.close(&refused("record_proposal"), json!({}));
                    }
                }
                "proposal_recorded" => {
                    if self
                        .ag_step("require-standing", &pc, |x| x.ag_require_standing())?
                        .is_none()
                    {
                        return self.close(&refused("require_standing"), json!({}));
                    }
                }
                "standing_required" => {
                    if self
                        .ag_step("decide", &pc, |x| x.ag_decide(&plan))?
                        .is_none()
                    {
                        return self.close(&refused("decide"), json!({}));
                    }
                }
                "admissible_pending_authorization" => {
                    if self.now_seconds() >= episode.window_until {
                        return self.close("window_expired_before_authorization", json!({}));
                    }
                    if self
                        .ag_step("authorize", &pc, |x| x.ag_authorize(&plan))?
                        .is_none()
                    {
                        return self.close(&refused("authorize"), json!({}));
                    }
                }
                "authorization_consumed" => {
                    let issuance = snapshot
                        .pointer("/state/authorization_consumed/issuance/issuance")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    if episode.issuance.is_none() && issuance.is_some() {
                        self.update(|e| e.issuance = issuance)?;
                    }
                    // AG's restart law first: Docket says whether it ever
                    // accepted this issuance.
                    let recovered = self.external.ag_recover(&plan);
                    self.step_event("recover", &recovered)?;
                    let recovered = match recovered {
                        Ok(value) => value,
                        Err(_) => return Ok("pending".into()),
                    };
                    match recovered.get("result").and_then(Value::as_str) {
                        Some("issuance_not_accepted") if episode.dispatch_started => {
                            // Never a second dispatch; Docket may still answer
                            // for an interrupted one until the window ends.
                            if self.now_seconds() < episode.window_until {
                                self.event("dispatch_unconfirmed", json!({}))?;
                                return Ok("pending".into());
                            }
                            return self.close("dispatch_not_accepted", json!({}));
                        }
                        Some("issuance_not_accepted") => {
                            if self.now_seconds() >= episode.window_until {
                                return self.close("window_expired_before_dispatch", json!({}));
                            }
                            self.update(|e| e.dispatch_started = true)?;
                            self.event("dispatch_started", json!({"plan": plan}))?;
                            let dispatched = self.external.ag_dispatch(&plan);
                            self.step_event("dispatch", &dispatched)?;
                            if let Err(failure) = &dispatched {
                                // AG's restart law says whether Docket took
                                // custody despite the error; only a refusal
                                // it confirms closes the episode, with
                                // Docket's own reason (grant exhausted,
                                // revoked, expired, ...).
                                let confirmed = self.external.ag_recover(&plan);
                                self.step_event("recover", &confirmed)?;
                                let not_accepted = confirmed.as_ref().is_ok_and(|value| {
                                    value.get("result").and_then(Value::as_str)
                                        == Some("issuance_not_accepted")
                                });
                                if not_accepted && !docket_refused(failure) {
                                    // A timeout or an unreachable boundary is
                                    // not a refusal: keep driving; later
                                    // passes ask AG's recover again.
                                    self.event(
                                        "dispatch_unconfirmed",
                                        json!({"failure": failure_detail(failure)}),
                                    )?;
                                    return Ok("pending".into());
                                }
                                if not_accepted {
                                    return self.close(
                                        "dispatch_refused",
                                        json!({
                                            "refusal": docket_refusal(&failure.message),
                                            "failure": failure_detail(failure),
                                        }),
                                    );
                                }
                            }
                        }
                        Some("advanced") => {}
                        other => {
                            self.event("recover_unexpected", json!({"result": other}))?;
                            return Ok("pending".into());
                        }
                    }
                }
                "dispatched" => {
                    let attempt = snapshot
                        .pointer("/state/dispatched/custody/attempt")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    if episode.attempt.is_none() && attempt.is_some() {
                        self.update(|e| e.attempt = attempt)?;
                    }
                    if !self.poll(&plan)? {
                        return Ok("pending".into());
                    }
                }
                "reconciliation_required" => {
                    return self.close("indeterminate", json!({}));
                }
                "settled_observation_required" => {
                    let settlement = snapshot
                        .pointer("/state/settled_observation_required/settlement")
                        .cloned()
                        .unwrap_or(Value::Null);
                    let outcome = settlement
                        .get("outcome")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    if episode.settlement.is_none() {
                        let text = |name: &str| {
                            settlement
                                .get(name)
                                .and_then(Value::as_str)
                                .map(str::to_owned)
                        };
                        let (id, attempt, issuance) =
                            (text("settlement"), text("attempt"), text("issuance"));
                        let settled_at = settlement
                            .get("settled_at_unix_ms")
                            .and_then(Value::as_u64)
                            .unwrap_or_else(|| self.now());
                        self.update(|e| {
                            e.settled_at_unix_ms = Some(settled_at);
                            e.settlement = id;
                            e.attempt = attempt.or(e.attempt.take());
                            e.issuance = issuance.or(e.issuance.take());
                        })?;
                        self.event("settled", json!({"outcome": outcome}))?;
                    }
                    if outcome != "success" {
                        return self.close("settled_failure", json!({"outcome": outcome}));
                    }
                    return self.postcondition(Some(snapshot));
                }
                "halted" => return self.close("halted", json!({})),
                "completed" => return self.completed(),
                other => {
                    return self.close("unknown_program_counter", json!({"pc": other}));
                }
            }
        }
        Ok("pending".into())
    }

    /// Poll a dispatched attempt read-only. True when AG left `dispatched`.
    fn poll(&mut self, plan: &Path) -> Result<bool, String> {
        let attempts = self.config.consumer.poll_attempts;
        for index in 0..attempts {
            let polled = self.external.ag_poll(plan);
            self.step_event("poll", &polled)?;
            if let Ok(snapshot) = polled
                && program_counter(&snapshot).as_deref() != Some("dispatched")
            {
                return Ok(true);
            }
            if index + 1 < attempts {
                thread::sleep(Duration::from_millis(self.config.consumer.poll_interval_ms));
            }
        }
        Ok(false)
    }

    // ---- completion ------------------------------------------------------

    fn postcondition(&mut self, snapshot: Option<Value>) -> Result<String, String> {
        let mut episode = self.active()?;
        if episode.phase != "awaiting_postcondition" {
            self.update(|e| e.phase = "awaiting_postcondition".into())?;
        }
        let pc = snapshot
            .as_ref()
            .and_then(program_counter)
            .unwrap_or_default();
        if pc == "settled_observation_required" {
            let occurrence = match episode.continuation_occurrence.clone() {
                Some(occurrence) => occurrence,
                None => {
                    let occurrence = uuid_v4()?;
                    let kept = occurrence.clone();
                    self.update(|e| e.continuation_occurrence = Some(kept))?;
                    occurrence
                }
            };
            let input = self
                .store
                .episode_dir(&episode.episode)?
                .join("continue.json");
            write_json(
                &input,
                &json!({"occurrence": occurrence, "expected_ag_work": episode.work}),
            )?;
            if self
                .ag_step("continue", &pc, |x| x.ag_continue(&input, &episode.plan))?
                .is_none()
            {
                return self.unproven("continue_refused");
            }
        }
        // The continuation occurrence AG actually holds.
        let snapshot = self.external.ag_status().ok();
        let held = snapshot
            .as_ref()
            .and_then(|s| s.pointer("/state/observation_required/meta/key/occurrence"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let Some(occurrence) = held else {
            if snapshot.as_ref().and_then(program_counter).as_deref() == Some("completed") {
                return self.completed();
            }
            return self.unproven("no_continuation_occurrence");
        };
        if episode.continuation_occurrence.as_deref() != Some(occurrence.as_str()) {
            let kept = occurrence.clone();
            self.update(|e| e.continuation_occurrence = Some(kept))?;
        }
        // Dwell: only an evaluation taken this long after the settlement may
        // prove the unit came up and stayed up. Wait for it inside the pass
        // when the window allows, else on a later pass.
        let not_before = episode
            .settled_at_unix_ms
            .unwrap_or_else(|| self.now())
            .saturating_add(self.config.consumer.postcondition_dwell_seconds * 1000);
        let window_end_ms = u64::try_from(episode.window_until)
            .unwrap_or(0)
            .saturating_mul(1000);
        if self.now() < not_before {
            if not_before >= window_end_ms {
                return self.unproven("dwell_beyond_window");
            }
            thread::sleep(Duration::from_millis(
                not_before - self.now().min(not_before),
            ));
        }
        if !episode.collect_requested && self.config.nq.collect {
            let collected = self.external.nq_collect();
            self.event(
                "collect_requested",
                json!({
                    "instance_id": self.config.enrollment.instance_id,
                    "ok": collected.is_ok(),
                    "failure": collected.as_ref().err().map(failure_detail),
                }),
            )?;
            self.update(|e| e.collect_requested = true)?;
        }
        episode = self.active()?;
        let observation = self.observation_id(&episode.campaign, &occurrence, "unit-active");
        let attempts = self.config.consumer.postcondition_attempts;
        for index in 0..attempts {
            let Resolved { status, detail, .. } = self.resolve(
                true,
                &episode.campaign,
                &occurrence,
                &observation,
                &episode.subject,
            )?;
            let sampled_at = if status == "current" {
                match self.external.newest_evaluated_at_ms() {
                    Ok(at) => at,
                    Err(error) => {
                        self.event("postcondition_sample_unreadable", json!({"error": error}))?;
                        None
                    }
                }
            } else {
                None
            };
            let after_dwell = sampled_at.is_some_and(|at| at >= not_before);
            if status == "current" && !after_dwell {
                self.event(
                    "postcondition_before_dwell",
                    json!({"sampled_at_unix_ms": sampled_at, "not_before_unix_ms": not_before}),
                )?;
            }
            if status == "current" && after_dwell {
                let witness = hash_domain(
                    TERMINAL_DOMAIN,
                    &jcs(&json!({
                        "settlement": episode.settlement,
                        "attempt": episode.attempt,
                        "issuance": episode.issuance,
                        "postcondition_currentness": detail.get("currentness"),
                    })),
                );
                let input = self
                    .store
                    .episode_dir(&episode.episode)?
                    .join("complete.json");
                write_json(
                    &input,
                    &json!({
                        "observation": observation,
                        "subject": episode.subject,
                        "terminal_witness": witness,
                    }),
                )?;
                if self
                    .ag_step("complete", "observation_required", |x| {
                        x.ag_complete(&input, &episode.plan)
                    })?
                    .is_some()
                {
                    return self.completed();
                }
            }
            if index + 1 < attempts {
                thread::sleep(Duration::from_millis(
                    self.config.consumer.postcondition_interval_ms,
                ));
            }
        }
        self.unproven("postcondition_not_current")
    }

    /// The postcondition is not (yet) proven: wait for the next pass while
    /// the window lasts, then close without claiming anything.
    fn unproven(&mut self, why: &str) -> Result<String, String> {
        let episode = self.active()?;
        if self.now_seconds() >= episode.window_until {
            return self.close("postcondition_not_proven", json!({"why": why}));
        }
        self.event("awaiting_postcondition", json!({"why": why}))?;
        Ok("awaiting_postcondition".into())
    }

    fn completed(&mut self) -> Result<String, String> {
        let outcome = self.close("completed", json!({}))?;
        if self.config.evaluator.trigger {
            let triggered = self.external.trigger_evaluator();
            let now = self.now();
            let closed = self.state.closed.last().cloned();
            self.store.event(
                now,
                "evaluator_triggered",
                closed.as_ref(),
                json!({
                    "unit": self.config.evaluator.unit,
                    "ok": triggered.is_ok(),
                    "failure": triggered.as_ref().err().map(failure_detail),
                }),
            )?;
        }
        Ok(outcome)
    }
}
