//! Durable consumer state: a lock, one atomically replaced `state.json` (the
//! open episode and the closed ones) and an append-only `journal.jsonl` with
//! one line per event of every pass. Both are fsynced before the external
//! step they describe, so a crash leaves a record of what may have started.
//!
//! The journal is kept in bounded generations. When the live journal reaches
//! its bound it is sealed, never truncated: hard-linked to
//! `journal.sealed.NNNN.jsonl`, described by `journal.sealed.NNNN.json`, and
//! replaced by a fresh `journal.jsonl` whose first record (`journal_sealed`)
//! names its predecessor's length and SHA-256. Sealing reads only the journal
//! and never touches `state.json`, `episodes/` or the lock.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub const STATE_SCHEMA: &str = "constellation.remediation-consumer.state/v1";
pub const JOURNAL_SCHEMA: &str = "constellation.remediation-consumer.journal/v1";
pub const SEAL_SCHEMA: &str = "constellation.remediation-consumer.journal-seal/v1";
/// Maximum bytes in one consumer journal generation. A full generation is
/// sealed, never truncated; it never discards existing history or resets an
/// execution obligation.
pub const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
/// Sealed generations kept beside the live journal: with the live one at most
/// 17 x 64 MiB (1.06 GiB) on disk. Once this many are present a full journal
/// is refused as before, until an operator moves verified segments off-host.
pub const MAX_SEALED_JOURNALS: usize = 16;
const LIVE_JOURNAL: &str = "journal.jsonl";
const SEALED_PREFIX: &str = "journal.sealed.";
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
    journal_max_bytes: u64,
    max_sealed: usize,
    /// The live journal was full at open, or is still linked to a sealed
    /// segment by an interrupted seal: seal before the first append.
    seal_due: bool,
    /// A seal failed part-way: every later append is refused this pass.
    seal_failed: Option<String>,
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
        Self::open_bounded(dir, pass, MAX_JOURNAL_BYTES, MAX_SEALED_JOURNALS)
    }

    fn open_bounded(
        dir: &Path,
        pass: String,
        journal_max_bytes: u64,
        max_sealed: usize,
    ) -> Result<Self, OpenError> {
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
            .open(dir.join(LIVE_JOURNAL))
            .map_err(|error| failed("open journal", error))?;
        let used = journal
            .metadata()
            .map_err(|error| failed("stat journal", error))?
            .len();
        // Seal at open when less than 1/64 of the bound remains, so one pass
        // normally journals into one generation, or when an interrupted seal
        // left the live journal linked to a segment (whatever its size: no
        // append may grow a sealed segment). Refusal (all sealed generations
        // present) happens here, before any external command.
        let headroom = (journal_max_bytes / 64).max(1);
        let linked = linked_segment(dir, &journal).map_err(OpenError::Failed)?;
        let seal_due = linked.is_some() || used.saturating_add(headroom) > journal_max_bytes;
        if seal_due {
            seal_sequence(dir, &journal, max_sealed)
                .map_err(|error| OpenError::Failed(exhausted(&error, used, journal_max_bytes)))?;
        }
        fs::create_dir_all(dir.join("episodes")).map_err(|error| failed("episodes dir", error))?;
        Ok(Self {
            dir: dir.to_owned(),
            _lock: lock,
            journal,
            journal_max_bytes,
            max_sealed,
            seal_due,
            seal_failed: None,
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

    /// Append and fsync one journal event. A journal full at open, or one
    /// this record would carry over the bound, is sealed first.
    pub fn event(
        &mut self,
        now_ms: u64,
        event: &str,
        episode: Option<&Episode>,
        detail: Value,
    ) -> Result<(), String> {
        if let Some(error) = &self.seal_failed {
            return Err(format!("journal unusable after a failed seal: {error}"));
        }
        let bytes = self.record(now_ms, event, episode, detail)?;
        let required =
            u64::try_from(bytes.len()).map_err(|_| "journal record length exceeds u64")?;
        let mut used = self.used()?;
        let crosses = journal_capacity(used, required, self.journal_max_bytes).is_err();
        // A journal under half full is never sealed for one oversized record.
        if self.seal_due || (crosses && used >= self.journal_max_bytes / 2) {
            let trigger = if self.seal_due { "open" } else { "append" };
            if let Err(error) = self.seal(now_ms, trigger) {
                let error = exhausted(&error, used, self.journal_max_bytes);
                self.seal_failed = Some(error.clone());
                return Err(error);
            }
            self.seal_due = false;
            used = self.used()?;
        }
        journal_capacity(used, required, self.journal_max_bytes)?;
        self.journal
            .write_all(&bytes)
            .and_then(|()| self.journal.sync_data())
            .map_err(|error| format!("journal: {error}"))
    }

    fn used(&self) -> Result<u64, String> {
        Ok(self
            .journal
            .metadata()
            .map_err(|error| format!("stat journal: {error}"))?
            .len())
    }

    fn record(
        &self,
        now_ms: u64,
        event: &str,
        episode: Option<&Episode>,
        detail: Value,
    ) -> Result<Vec<u8>, String> {
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
        Ok(bytes)
    }

    /// Seal the live journal as the next generation. Every step leaves a
    /// complete `journal.jsonl`: hard link and directory fsync, sidecar
    /// (atomic), then the live name atomically replaced by a new journal
    /// holding only the `journal_sealed` record. A crash after the link is
    /// resumed by the next open (same inode, same sequence); nothing is ever
    /// truncated or deleted. A sealed name that exists but is not the live
    /// journal's own inode is refused before anything changes.
    fn seal(&mut self, now_ms: u64, trigger: &str) -> Result<(), String> {
        let resumed = linked_segment(&self.dir, &self.journal)?;
        let sequence = match resumed {
            Some(sequence) => sequence,
            None => seal_sequence(&self.dir, &self.journal, self.max_sealed)?,
        };
        let trigger = if resumed.is_some() { "resume" } else { trigger };
        let live = self.dir.join(LIVE_JOURNAL);
        let name = sealed_name(sequence);
        let sealed = self.dir.join(&name);
        match fs::symlink_metadata(&sealed) {
            Ok(_) if resumed == Some(sequence) => {}
            Ok(_) => {
                return Err(format!(
                    "seal journal: {name} already exists and is not the live journal; operator custody required"
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::hard_link(&live, &sealed).map_err(|error| format!("seal journal: {error}"))?;
                sync_dir(&self.dir)?;
            }
            Err(error) => return Err(format!("seal journal: {error}")),
        }
        let summary = summarize(&sealed)?;
        let sidecar = format!("{SEALED_PREFIX}{sequence:04}.json");
        let mut record = json!({
            "schema": SEAL_SCHEMA,
            "sequence": sequence,
            "segment": name,
            "sealed_at": stamp(now_ms),
            "sealed_at_unix_ms": now_ms,
            "sealed_by_pass": self.pass,
            "trigger": trigger,
            "journal_max_bytes": self.journal_max_bytes,
        });
        if let (Some(target), Some(source)) = (record.as_object_mut(), summary.as_object()) {
            target.extend(source.clone());
        }
        let mut sidecar_bytes =
            serde_json::to_vec_pretty(&record).map_err(|error| error.to_string())?;
        sidecar_bytes.push(b'\n');
        write_atomic(&self.dir.join(&sidecar), &sidecar_bytes)?;
        if let Some(detail) = record.as_object_mut() {
            detail.remove("schema");
            detail.insert("sidecar".into(), json!(sidecar));
            detail.insert("predecessor".into(), json!(name));
        }
        let first = self.record(now_ms, "journal_sealed", None, record)?;
        // The successor's append handle is opened on the temporary file, so
        // once the rename lands no later record can reach the sealed inode.
        let temporary = self
            .dir
            .join(format!(".{LIVE_JOURNAL}.{}.tmp", std::process::id()));
        let _ = fs::remove_file(&temporary);
        let mut successor = OpenOptions::new()
            .append(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|error| format!("{}: {error}", temporary.display()))?;
        successor
            .write_all(&first)
            .and_then(|()| successor.sync_all())
            .map_err(|error| format!("{}: {error}", temporary.display()))?;
        fs::rename(&temporary, &live).map_err(|error| format!("{}: {error}", live.display()))?;
        self.journal = successor;
        sync_dir(&self.dir)
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

fn sealed_name(sequence: u64) -> String {
    format!("{SEALED_PREFIX}{sequence:04}.jsonl")
}

/// `(sequence, is_segment)` of a sealed segment or sidecar name.
fn parse_sealed(name: &str) -> Option<(u64, bool)> {
    let rest = name.strip_prefix(SEALED_PREFIX)?;
    let (digits, segment) = match rest.strip_suffix(".jsonl") {
        Some(digits) => (digits, true),
        None => (rest.strip_suffix(".json")?, false),
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some((digits.parse().ok()?, segment))
}

/// Sealed segments present in `dir` (ascending), and the highest sequence
/// named by any segment or sidecar.
fn sealed_segments(dir: &Path) -> Result<(Vec<(u64, PathBuf)>, u64), String> {
    let mut segments = Vec::new();
    let mut highest = 0;
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((segments, highest));
        }
        Err(error) => return Err(format!("read state dir: {error}")),
    };
    for entry in entries {
        let entry = entry.map_err(|error| format!("read state dir: {error}"))?;
        let Some((sequence, segment)) = entry.file_name().to_str().and_then(parse_sealed) else {
            continue;
        };
        highest = highest.max(sequence);
        if segment {
            segments.push((sequence, entry.path()));
        }
    }
    segments.sort();
    Ok((segments, highest))
}

/// Sealed journal segments present in a state directory (`None` when it
/// cannot be read). Never creates or locks anything.
#[must_use]
pub fn sealed_journal_count(dir: &Path) -> Option<usize> {
    sealed_segments(dir)
        .ok()
        .map(|(segments, _)| segments.len())
}

/// The sealed segment that is the live journal's own inode: an interrupted
/// seal. Symlinks never match.
fn linked_segment(dir: &Path, journal: &File) -> Result<Option<u64>, String> {
    let live = journal
        .metadata()
        .map_err(|error| format!("stat journal: {error}"))?;
    if live.nlink() < 2 {
        return Ok(None);
    }
    let (segments, _) = sealed_segments(dir)?;
    Ok(segments.into_iter().find_map(|(sequence, path)| {
        fs::symlink_metadata(path)
            .ok()
            .filter(|metadata| {
                metadata.is_file() && metadata.dev() == live.dev() && metadata.ino() == live.ino()
            })
            .map(|_| sequence)
    }))
}

/// The sequence the live journal seals as: the segment already linked to it
/// (an interrupted seal), else one past every sealed name on disk and the
/// predecessor its own first record names (segments moved off-host keep the
/// chain monotonic). Refuses once `max_sealed` segments are present.
fn seal_sequence(dir: &Path, journal: &File, max_sealed: usize) -> Result<u64, String> {
    if let Some(sequence) = linked_segment(dir, journal)? {
        return Ok(sequence);
    }
    let (segments, highest) = sealed_segments(dir)?;
    if segments.len() >= max_sealed {
        return Err(format!(
            "sealed journal generations exhausted: {} sealed segments present, bound {max_sealed}",
            segments.len()
        ));
    }
    let predecessor = first_record(&dir.join(LIVE_JOURNAL))
        .filter(|record| record["event"] == "journal_sealed")
        .and_then(|record| record["detail"]["sequence"].as_u64())
        .unwrap_or(0);
    highest
        .max(predecessor)
        .checked_add(1)
        .ok_or_else(|| "seal journal: sealed sequence space exhausted".to_owned())
}

fn exhausted(error: &str, used: u64, limit: u64) -> String {
    if error.starts_with("sealed journal generations exhausted") {
        format!(
            "journal capacity exhausted: used {used} bytes, limit {limit}; {error}; history preserved, operator custody required (verify each sealed segment against its sidecar sha256, then move it off-host)"
        )
    } else {
        format!("journal seal failed: {error}")
    }
}

const PROBE_BYTES: u64 = 64 * 1024;

fn first_record(path: &Path) -> Option<Value> {
    let mut head = Vec::new();
    File::open(path)
        .ok()?
        .take(PROBE_BYTES)
        .read_to_end(&mut head)
        .ok()?;
    let end = head.iter().position(|byte| *byte == b'\n')?;
    serde_json::from_slice(&head[..end]).ok()
}

fn record_at(line: &[u8]) -> Value {
    serde_json::from_slice::<Value>(line)
        .ok()
        .and_then(|record| record.get("at").filter(|at| at.is_string()).cloned())
        .unwrap_or(Value::Null)
}

/// Length, SHA-256 and newline-terminated record count of a sealed segment,
/// with the `at` of its first and last complete records when readable.
fn summarize(path: &Path) -> Result<Value, String> {
    let context = |error: std::io::Error| format!("{}: {error}", path.display());
    let mut file = File::open(path).map_err(context)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; 1024 * 1024];
    // Bytes after the last newline: a torn final append, kept as it is.
    let (mut bytes, mut records, mut torn) = (0_u64, 0_u64, 0_u64);
    loop {
        let read = file.read(&mut buffer).map_err(context)?;
        if read == 0 {
            break;
        }
        let chunk = &buffer[..read];
        hasher.update(chunk);
        bytes += read as u64;
        records += chunk.iter().filter(|byte| **byte == b'\n').count() as u64;
        torn = match chunk.iter().rposition(|byte| *byte == b'\n') {
            Some(end) => (read - end - 1) as u64,
            None => torn + read as u64,
        };
    }
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let start = bytes.saturating_sub(PROBE_BYTES);
    let mut tail = Vec::new();
    file.seek(SeekFrom::Start(start)).map_err(context)?;
    file.read_to_end(&mut tail).map_err(context)?;
    let complete = tail
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |end| end + 1);
    let body = &tail[..complete.saturating_sub(1)];
    let last_at = match body.iter().rposition(|byte| *byte == b'\n') {
        Some(previous) => record_at(&body[previous + 1..]),
        None if start == 0 && complete > 0 => record_at(body),
        None => Value::Null,
    };
    Ok(json!({
        "bytes": bytes,
        "sha256": format!("sha256:{digest}"),
        "records": records,
        "torn_tail_bytes": torn,
        "first_at": first_record(path).map_or(Value::Null, |record| record["at"].clone()),
        "last_at": last_at,
    }))
}

fn sync_dir(dir: &Path) -> Result<(), String> {
    File::open(dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("{}: {error}", dir.display()))
}

fn journal_capacity(used: u64, required: u64, limit: u64) -> Result<(), String> {
    if used.checked_add(required).is_none_or(|end| end > limit) {
        return Err(format!(
            "journal capacity exhausted: used {used} bytes, record requires {required}, limit {limit}; history preserved, operator custody required"
        ));
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn private_dir() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn open(dir: &Path, limit: u64, max_sealed: usize) -> Result<Store, String> {
        Store::open_bounded(dir, "fixture".into(), limit, max_sealed).map_err(|error| match error {
            OpenError::Busy => "busy".into(),
            OpenError::Failed(error) => error,
        })
    }

    fn dispatched() -> State {
        State {
            active: Some(Episode {
                episode: "retained-episode".into(),
                campaign: "retained-campaign".into(),
                dispatch_started: true,
                attempt: Some("retained-attempt".into()),
                ..Episode::default()
            }),
            ..State::default()
        }
    }

    fn records(bytes: &[u8]) -> Vec<Value> {
        bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect()
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    fn sha256(bytes: &[u8]) -> String {
        let digest: String = Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        format!("sha256:{digest}")
    }

    #[test]
    fn append_crossing_the_bound_seals_and_preserves_every_byte_and_state() {
        let directory = private_dir();
        let dir = directory.path();
        let mut store = open(dir, 4096, 2).unwrap();
        let state = dispatched();
        store.save(&state).unwrap();
        let journal = dir.join(LIVE_JOURNAL);
        let mut appended = 0;
        while fs::metadata(&journal).unwrap().len() + 400 <= 4096 {
            store
                .event(
                    appended * 1000,
                    "fixture",
                    state.active.as_ref(),
                    Value::Null,
                )
                .unwrap();
            appended += 1;
        }
        let before = fs::read(&journal).unwrap();
        let state_before = fs::read(dir.join("state.json")).unwrap();
        let mut last = 0;
        while !dir.join("journal.sealed.0001.jsonl").exists() {
            last = appended * 1000;
            store
                .event(last, "fixture", state.active.as_ref(), Value::Null)
                .unwrap();
            appended += 1;
        }
        let sealed = fs::read(dir.join("journal.sealed.0001.jsonl")).unwrap();
        assert!(sealed.starts_with(&before));
        assert!(u64::try_from(sealed.len()).unwrap() <= 4096);
        let sidecar: Value =
            serde_json::from_slice(&fs::read(dir.join("journal.sealed.0001.json")).unwrap())
                .unwrap();
        assert_eq!(sidecar["schema"], SEAL_SCHEMA);
        assert_eq!(sidecar["sha256"], sha256(&sealed));
        assert_eq!(sidecar["bytes"], sealed.len());
        assert_eq!(sidecar["records"], records(&sealed).len());
        assert_eq!(sidecar["first_at"], stamp(0));
        assert_eq!(sidecar["torn_tail_bytes"], 0);
        assert_eq!(sidecar["trigger"], "append");
        let live = records(&fs::read(&journal).unwrap());
        assert_eq!(live.len(), 2);
        assert_eq!(live[0]["event"], "journal_sealed");
        assert!(live[0]["episode"].is_null());
        let detail = &live[0]["detail"];
        assert_eq!(detail["predecessor"], "journal.sealed.0001.jsonl");
        assert_eq!(detail["sequence"], 1);
        assert_eq!(detail["sha256"], sidecar["sha256"]);
        assert_eq!(detail["bytes"], sealed.len());
        assert_eq!(detail["last_at"], records(&sealed).last().unwrap()["at"]);
        assert_eq!(live[1]["at_unix_ms"], last);
        // Sealing never touches state, the fence or the episode inputs.
        assert_eq!(fs::read(dir.join("state.json")).unwrap(), state_before);
        assert!(store.load().unwrap().active.unwrap().dispatch_started);
        assert_eq!(
            names(dir),
            [
                "episodes",
                "journal.jsonl",
                "journal.sealed.0001.json",
                "journal.sealed.0001.jsonl",
                "lock",
                "state.json"
            ]
        );
    }

    #[test]
    fn full_journal_at_open_seals_before_the_first_record_and_keeps_the_chain() {
        let directory = private_dir();
        let dir = directory.path();
        let mut store = open(dir, 4096, 4).unwrap();
        store.event(5, "fixture", None, Value::Null).unwrap();
        drop(store);
        let journal = dir.join(LIVE_JOURNAL);
        // Already oversized, with a torn final append.
        let mut torn = fs::read(&journal).unwrap();
        torn.extend_from_slice(b"{\"partial\"");
        torn.resize(5000, b' ');
        fs::write(&journal, &torn).unwrap();
        let mut store = open(dir, 4096, 4).unwrap();
        assert!(!dir.join("journal.sealed.0001.jsonl").exists());
        store.event(9, "pass_started", None, Value::Null).unwrap();
        assert_eq!(
            fs::read(dir.join("journal.sealed.0001.jsonl")).unwrap(),
            torn
        );
        let live = records(&fs::read(&journal).unwrap());
        assert_eq!(live[0]["event"], "journal_sealed");
        assert_eq!(live[0]["detail"]["trigger"], "open");
        assert_eq!(live[0]["detail"]["records"], 1);
        assert_eq!(
            live[0]["detail"]["torn_tail_bytes"],
            5000 - torn.iter().position(|b| *b == b'\n').unwrap() - 1
        );
        assert_eq!(live[0]["detail"]["first_at"], stamp(5));
        assert_eq!(live[0]["detail"]["last_at"], stamp(5));
        assert_eq!(live[1]["event"], "pass_started");
        drop(store);

        // Segments moved off-host: the next generation still follows the
        // predecessor the live journal names.
        fs::remove_file(dir.join("journal.sealed.0001.jsonl")).unwrap();
        fs::remove_file(dir.join("journal.sealed.0001.json")).unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&journal)
            .unwrap()
            .set_len(4096)
            .unwrap();
        let mut store = open(dir, 4096, 4).unwrap();
        store.event(10, "pass_started", None, Value::Null).unwrap();
        let second = first_record(&dir.join("journal.sealed.0002.jsonl")).unwrap();
        assert_eq!(second["event"], "journal_sealed");
        let live = records(&fs::read(&journal).unwrap());
        assert_eq!(live[0]["detail"]["sequence"], 2);
        assert_eq!(live[0]["detail"]["first_at"], stamp(9));
        assert_eq!(live[0]["detail"]["bytes"], 4096);
    }

    #[test]
    fn interrupted_seal_resumes_under_the_same_name() {
        let directory = private_dir();
        let dir = directory.path();
        let journal = dir.join(LIVE_JOURNAL);
        drop(open(dir, 4096, 1).unwrap());
        fs::OpenOptions::new()
            .write(true)
            .open(&journal)
            .unwrap()
            .set_len(4096)
            .unwrap();
        // A crash after the hard link, before the live journal was replaced.
        fs::hard_link(&journal, dir.join("journal.sealed.0001.jsonl")).unwrap();
        let mut store = open(dir, 4096, 1).unwrap();
        store.event(1, "pass_started", None, Value::Null).unwrap();
        assert!(!dir.join("journal.sealed.0002.jsonl").exists());
        assert_eq!(
            fs::metadata(dir.join("journal.sealed.0001.jsonl"))
                .unwrap()
                .len(),
            4096
        );
        assert_eq!(
            records(&fs::read(&journal).unwrap())[0]["detail"]["sequence"],
            1
        );
    }

    #[test]
    fn interrupted_seal_below_the_headroom_is_resumed_and_never_grows_the_segment() {
        let directory = private_dir();
        let dir = directory.path();
        let journal = dir.join(LIVE_JOURNAL);
        drop(open(dir, 4096, 4).unwrap());
        fs::OpenOptions::new()
            .write(true)
            .open(&journal)
            .unwrap()
            .set_len(4096 * 40 / 64)
            .unwrap();
        let segment = dir.join("journal.sealed.0001.jsonl");
        fs::hard_link(&journal, &segment).unwrap();
        let mut store = open(dir, 4096, 4).unwrap();
        store.event(1, "pass_started", None, Value::Null).unwrap();
        let (live, sealed) = (
            fs::metadata(&journal).unwrap(),
            fs::metadata(&segment).unwrap(),
        );
        assert_ne!(live.ino(), sealed.ino());
        assert_eq!(sealed.len(), 4096 * 40 / 64);
        assert_eq!(sealed.nlink(), 1);
        assert!(!dir.join("journal.sealed.0002.jsonl").exists());
        let live = records(&fs::read(&journal).unwrap());
        assert_eq!(live[0]["detail"]["sequence"], 1);
        assert_eq!(live[0]["detail"]["trigger"], "resume");
        assert_eq!(live[1]["event"], "pass_started");
    }

    #[test]
    fn a_symlinked_segment_name_never_stands_in_for_the_journal() {
        let directory = private_dir();
        let dir = directory.path();
        let journal = dir.join(LIVE_JOURNAL);
        drop(open(dir, 4096, 4).unwrap());
        fs::write(&journal, b"{}\n".repeat(1366)).unwrap();
        let history = fs::read(&journal).unwrap();
        std::os::unix::fs::symlink(LIVE_JOURNAL, dir.join("journal.sealed.0001.jsonl")).unwrap();
        let mut store = open(dir, 4096, 4).unwrap();
        store.event(1, "pass_started", None, Value::Null).unwrap();
        assert!(
            fs::symlink_metadata(dir.join("journal.sealed.0001.jsonl"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read(dir.join("journal.sealed.0002.jsonl")).unwrap(),
            history
        );
        let live = records(&fs::read(&journal).unwrap());
        assert_eq!(
            live[0]["detail"]["predecessor"],
            "journal.sealed.0002.jsonl"
        );
    }

    #[test]
    fn exhausted_sequence_space_refuses_and_a_failed_seal_stops_the_pass() {
        let directory = private_dir();
        let dir = directory.path();
        let journal = dir.join(LIVE_JOURNAL);
        let mut store = open(dir, 4096, 4).unwrap();
        while fs::metadata(&journal).unwrap().len() + 400 <= 4096 {
            store.event(0, "fixture", None, Value::Null).unwrap();
        }
        fs::write(dir.join(format!("journal.sealed.{}.jsonl", u64::MAX)), b"").unwrap();
        let listing = names(dir);
        let mut error = String::new();
        for _ in 0..8 {
            if let Err(refused) = store.event(0, "fixture", None, Value::Null) {
                error = refused;
                break;
            }
        }
        assert!(error.contains("sealed sequence space exhausted"), "{error}");
        let before = fs::read(&journal).unwrap();
        let after_failure = store.event(0, "small", None, Value::Null).unwrap_err();
        assert!(
            after_failure.contains("unusable after a failed seal"),
            "{after_failure}"
        );
        assert_eq!(fs::read(&journal).unwrap(), before);
        assert_eq!(names(dir), listing);
        drop(store);
        fs::OpenOptions::new()
            .write(true)
            .open(&journal)
            .unwrap()
            .set_len(4096)
            .unwrap();
        let error = open(dir, 4096, 4).err().unwrap();
        assert!(error.contains("sealed sequence space exhausted"), "{error}");
        assert_eq!(names(dir), listing);
    }

    #[test]
    fn exhausted_generations_refuse_at_open_and_on_append_preserving_everything() {
        let directory = private_dir();
        let dir = directory.path();
        let journal = dir.join(LIVE_JOURNAL);
        let mut store = open(dir, 4096, 1).unwrap();
        let state = dispatched();
        store.save(&state).unwrap();
        fs::write(dir.join("journal.sealed.0001.jsonl"), b"").unwrap();
        while fs::metadata(&journal).unwrap().len() + 400 <= 4096 {
            store
                .event(0, "fixture", state.active.as_ref(), Value::Null)
                .unwrap();
        }
        let before = fs::read(&journal).unwrap();
        let state_before = fs::read(dir.join("state.json")).unwrap();
        let listing = names(dir);
        let mut error = String::new();
        for _ in 0..8 {
            if let Err(refused) = store.event(0, "fixture", state.active.as_ref(), Value::Null) {
                error = refused;
                break;
            }
        }
        assert!(
            error.contains("sealed journal generations exhausted"),
            "{error}"
        );
        assert!(error.contains("operator custody required"), "{error}");
        let full = fs::read(&journal).unwrap();
        assert!(full.starts_with(&before));
        drop(store);
        fs::OpenOptions::new()
            .write(true)
            .open(&journal)
            .unwrap()
            .set_len(4096)
            .unwrap();
        let full = fs::read(&journal).unwrap();
        let error = open(dir, 4096, 1).err().unwrap();
        assert!(error.starts_with("journal capacity exhausted"), "{error}");
        assert!(
            error.contains("sealed journal generations exhausted"),
            "{error}"
        );
        assert_eq!(fs::read(&journal).unwrap(), full);
        assert_eq!(fs::read(dir.join("state.json")).unwrap(), state_before);
        assert_eq!(names(dir), listing);
    }

    #[test]
    fn oversized_record_in_a_young_journal_is_refused_not_sealed() {
        let directory = private_dir();
        let dir = directory.path();
        let mut store = open(dir, 4096, 4).unwrap();
        store.event(0, "fixture", None, Value::Null).unwrap();
        let before = fs::read(dir.join(LIVE_JOURNAL)).unwrap();
        let error = store
            .event(0, "fixture", None, json!("x".repeat(5000)))
            .unwrap_err();
        assert!(error.contains("journal capacity exhausted"), "{error}");
        assert_eq!(fs::read(dir.join(LIVE_JOURNAL)).unwrap(), before);
        assert!(!dir.join("journal.sealed.0001.jsonl").exists());
    }

    #[test]
    fn sealed_names_parse_strictly() {
        assert_eq!(parse_sealed("journal.sealed.0007.jsonl"), Some((7, true)));
        assert_eq!(parse_sealed("journal.sealed.0007.json"), Some((7, false)));
        assert_eq!(
            parse_sealed("journal.sealed.12345.jsonl"),
            Some((12345, true))
        );
        assert_eq!(parse_sealed("journal.sealed..jsonl"), None);
        assert_eq!(parse_sealed("journal.sealed.07x.jsonl"), None);
        assert_eq!(parse_sealed("journal.jsonl"), None);
        assert_eq!(sealed_name(3), "journal.sealed.0003.jsonl");
    }

    #[test]
    fn capacity_length_overflow_refuses_without_wrapping() {
        assert!(journal_capacity(u64::MAX, 1, u64::MAX).is_err());
    }
}
