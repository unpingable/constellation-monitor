//! Durable consumer state: a lock, one atomically replaced `state.json` (the
//! open episode and the closed ones) and an append-only `journal.jsonl` with
//! one line per event of every pass. Both are fsynced before the external
//! step they describe, so a crash leaves a record of what may have started.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub const STATE_SCHEMA: &str = "constellation.remediation-consumer.state/v1";
pub const JOURNAL_SCHEMA: &str = "constellation.remediation-consumer.journal/v1";
/// Closed episodes kept in `state.json` (the journal keeps all of them).
const CLOSED_KEPT: usize = 256;

/// One condition episode: one AG campaign, at most one dispatch.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Episode {
    /// Digest of (condition id, first_seen).
    pub episode: String,
    pub condition_id: String,
    pub first_seen: String,
    /// Evaluator's remediation window end (unix seconds).
    pub window_until: i64,
    pub page_deferred_at_open: bool,
    pub prestate: String,
    pub plan: PathBuf,
    pub work: String,
    pub subject: String,
    pub scope: String,
    pub campaign: String,
    pub occurrence: String,
    /// `opening` → `driving` → `awaiting_postcondition`; closed episodes
    /// carry `outcome`.
    pub phase: String,
    /// Durable fence: set before `dispatch` is invoked, never cleared. With
    /// it set the consumer only ever polls or recovers.
    pub dispatch_started: bool,
    pub issuance: Option<String>,
    pub attempt: Option<String>,
    pub settlement: Option<String>,
    pub continuation_occurrence: Option<String>,
    pub collect_requested: bool,
    /// Docket's settlement time (AG's settlement record), or when the
    /// consumer first saw the settlement if AG did not carry it.
    #[serde(default)]
    pub settled_at_unix_ms: Option<u64>,
    pub outcome: Option<String>,
    pub opened_at_unix_ms: u64,
    pub closed_at_unix_ms: Option<u64>,
    /// `model` for an episode the model decider opened; absent for the
    /// deterministic decider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decider: Option<String>,
    /// The model decider's durable reasoning record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<Reasoning>,
}

/// The reasoning phase of a model-decided episode. Saved before LA
/// `reserve`; each call's record is saved before `begin-call`, again (with
/// the invocation) before the send, and again after settlement.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reasoning {
    pub started_at_unix_ms: u64,
    /// The wall ceiling: no call starts that cannot finish before it.
    pub deadline_unix_ms: u64,
    pub reservation: Option<String>,
    pub calls: Vec<Call>,
    /// The validated decision (`start_canary` only ever with `current_down`).
    pub decision: Option<String>,
    pub reason: Option<String>,
    /// LA `close` done.
    #[serde(default)]
    pub la_closed: bool,
}

/// One model call. `state`: `begin_requested` (begin-call asked, no send
/// permission saved, so never sent) → `begun` (permission saved; a send may
/// have happened) → `settled`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Call {
    pub index: u32,
    pub state: String,
    pub invocation: Option<String>,
    pub terminal: Option<String>,
    pub usage_source: Option<String>,
    pub receipt: Option<String>,
    /// A settled malformed answer, provider error or proven-unsent failure:
    /// one more call may follow within the ceilings.
    #[serde(default)]
    pub retryable: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub schema: String,
    /// The episode a pass must finish or reconcile before anything else.
    pub active: Option<Episode>,
    /// Window end of the newest opened episode: no new episode opens before it.
    pub last_window_until: Option<i64>,
    pub closed: Vec<Episode>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            schema: STATE_SCHEMA.to_owned(),
            active: None,
            last_window_until: None,
            closed: Vec::new(),
        }
    }
}

impl State {
    #[must_use]
    pub fn seen(&self, episode: &str) -> bool {
        self.active
            .as_ref()
            .is_some_and(|active| active.episode == episode)
            || self.closed.iter().any(|closed| closed.episode == episode)
    }

    pub fn close(&mut self, outcome: &str, now_ms: u64) -> Option<Episode> {
        let mut episode = self.active.take()?;
        episode.outcome = Some(outcome.to_owned());
        episode.closed_at_unix_ms = Some(now_ms);
        self.closed.push(episode.clone());
        if self.closed.len() > CLOSED_KEPT {
            let excess = self.closed.len() - CLOSED_KEPT;
            self.closed.drain(..excess);
        }
        Some(episode)
    }
}

/// The locked state directory of one pass.
pub struct Store {
    dir: PathBuf,
    _lock: File,
    journal: File,
    pass: String,
}

/// Why a store could not be opened.
pub enum OpenError {
    /// Another pass holds the lock.
    Busy,
    Failed(String),
}

fn failed(context: &str, error: impl std::fmt::Display) -> OpenError {
    OpenError::Failed(format!("{context}: {error}"))
}

impl Store {
    /// Create (0700) or verify the private state directory, take the lock.
    pub fn open(dir: &Path, pass: String) -> Result<Self, OpenError> {
        if !dir.exists() {
            fs::create_dir_all(dir).map_err(|error| failed("create state dir", error))?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
                .map_err(|error| failed("chmod state dir", error))?;
        }
        let metadata =
            fs::symlink_metadata(dir).map_err(|error| failed("stat state dir", error))?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(OpenError::Failed(format!(
                "{} must be a directory private to its owner (0700)",
                dir.display()
            )));
        }
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(dir.join("lock"))
            .map_err(|error| failed("open lock", error))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => return Err(OpenError::Busy),
            Err(fs::TryLockError::Error(error)) => return Err(failed("lock", error)),
        }
        let journal = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(dir.join("journal.jsonl"))
            .map_err(|error| failed("open journal", error))?;
        fs::create_dir_all(dir.join("episodes")).map_err(|error| failed("episodes dir", error))?;
        Ok(Self {
            dir: dir.to_owned(),
            _lock: lock,
            journal,
            pass,
        })
    }

    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    #[must_use]
    pub fn pass(&self) -> &str {
        &self.pass
    }

    pub fn load(&self) -> Result<State, String> {
        let path = self.dir.join("state.json");
        if !path.exists() {
            return Ok(State::default());
        }
        let bytes = fs::read(&path).map_err(|error| format!("read state: {error}"))?;
        let state: State =
            serde_json::from_slice(&bytes).map_err(|error| format!("state.json: {error}"))?;
        if state.schema != STATE_SCHEMA {
            return Err(format!("state.json schema is not {STATE_SCHEMA}"));
        }
        Ok(state)
    }

    pub fn save(&self, state: &State) -> Result<(), String> {
        let mut bytes = serde_json::to_vec_pretty(state).map_err(|error| error.to_string())?;
        bytes.push(b'\n');
        write_atomic(&self.dir.join("state.json"), &bytes)
    }

    /// Append and fsync one journal event.
    pub fn event(
        &mut self,
        now_ms: u64,
        event: &str,
        episode: Option<&Episode>,
        detail: Value,
    ) -> Result<(), String> {
        let line = json!({
            "schema": JOURNAL_SCHEMA,
            "pass": self.pass,
            "at": stamp(now_ms),
            "at_unix_ms": now_ms,
            "event": event,
            "episode": episode.map(|e| &e.episode),
            "campaign": episode.map(|e| &e.campaign),
            "occurrence": episode.map(|e| &e.occurrence),
            "detail": detail,
        });
        let mut bytes = serde_json::to_vec(&line).map_err(|error| error.to_string())?;
        bytes.push(b'\n');
        self.journal
            .write_all(&bytes)
            .and_then(|()| self.journal.sync_data())
            .map_err(|error| format!("journal: {error}"))
    }

    /// Directory for one episode's AG input records.
    pub fn episode_dir(&self, episode: &str) -> Result<PathBuf, String> {
        let name: String = episode
            .trim_start_matches("sha256:")
            .chars()
            .take(32)
            .collect();
        let dir = self.dir.join("episodes").join(name);
        fs::create_dir_all(&dir).map_err(|error| format!("episode dir: {error}"))?;
        Ok(dir)
    }
}

#[must_use]
pub fn stamp(now_ms: u64) -> String {
    i128::from(now_ms)
        .checked_mul(1_000_000)
        .and_then(|nanos| OffsetDateTime::from_unix_timestamp_nanos(nanos).ok())
        .and_then(|at| at.format(&Rfc3339).ok())
        .unwrap_or_else(|| now_ms.to_string())
}

/// Exclusive temporary file, fsync, rename, directory fsync; mode 0600.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("path has no parent")?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("path has no file name")?;
    let temporary = parent.join(format!(".{name}.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&temporary);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| format!("{}: {error}", temporary.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("{}: {error}", temporary.display()))?;
    fs::rename(&temporary, path).map_err(|error| format!("{}: {error}", path.display()))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("{}: {error}", parent.display()))
}
