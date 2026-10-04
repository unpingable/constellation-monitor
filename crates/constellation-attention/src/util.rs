//! Small helpers: RFC3339 time, atomic file writes, bounded child processes.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub fn parse_rfc3339(value: &str) -> Result<OffsetDateTime, String> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|error| format!("invalid RFC3339 {value:?}: {error}"))
}

/// Unix seconds of an RFC3339 timestamp.
pub fn rfc3339_seconds(value: &str) -> Result<i64, String> {
    parse_rfc3339(value).map(OffsetDateTime::unix_timestamp)
}

#[must_use]
pub fn format_seconds(seconds: i64) -> String {
    OffsetDateTime::from_unix_timestamp(seconds)
        .ok()
        .and_then(|time| time.format(&Rfc3339).ok())
        .unwrap_or_else(|| seconds.to_string())
}

/// Write `bytes` to `path` atomically: exclusive temporary file, fsync,
/// rename, directory fsync. Mode 0600.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    let name = path
        .file_name()
        .ok_or_else(|| format!("{} has no file name", path.display()))?
        .to_string_lossy()
        .into_owned();
    let temporary = parent.join(format!(".{name}.tmp.{}", std::process::id()));
    let _ = fs::remove_file(&temporary);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|error| format!("cannot write {}: {error}", path.display()))
}

/// Read a regular file (not a symlink) of at most `limit` bytes.
pub fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot stat {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    let file =
        File::open(path).map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if bytes.len() as u64 > limit {
        return Err(format!("{} exceeds {limit} bytes", path.display()));
    }
    Ok(bytes)
}

pub struct CommandOutput {
    pub status: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
}

/// How a child inherits the environment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildEnvironment {
    /// Cleared except a fixed PATH and LANG: input readers need no secrets.
    Minimal,
    /// Inherited: `nq notification submit` reads route locators from it. The
    /// evaluator itself never reads, stores or prints those values.
    Inherit,
}

/// Run argv (no shell) with a deadline, collecting bounded stdout/stderr.
pub fn run_bounded(
    argv: &[String],
    timeout: Duration,
    stdout_limit: usize,
    environment: ChildEnvironment,
) -> Result<CommandOutput, String> {
    let (program, arguments) = argv
        .split_first()
        .ok_or_else(|| "empty command".to_owned())?;
    let mut command = Command::new(program);
    command
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if environment == ChildEnvironment::Minimal {
        command
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LANG", "C.UTF-8");
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot start {program}: {error}"))?;
    let stdout = child.stdout.take().ok_or("no stdout pipe")?;
    let stderr = child.stderr.take().ok_or("no stderr pipe")?;
    let out_reader = thread::spawn(move || collect(stdout, stdout_limit));
    let err_reader = thread::spawn(move || collect(stderr, 4096));
    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                timed_out = true;
                let _ = child.kill();
                break child
                    .wait()
                    .map_err(|error| format!("cannot reap {program}: {error}"))?;
            }
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(error) => return Err(format!("cannot wait for {program}: {error}")),
        }
    };
    let (stdout, stdout_overflow) = out_reader.join().unwrap_or_default();
    let (stderr, _) = err_reader.join().unwrap_or_default();
    if stdout_overflow {
        return Err(format!("{program} printed more than {stdout_limit} bytes"));
    }
    Ok(CommandOutput {
        status: status.code(),
        stdout,
        stderr,
        timed_out,
    })
}

fn collect(mut reader: impl Read, limit: usize) -> (Vec<u8>, bool) {
    let mut kept = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut overflow = false;
    loop {
        match reader.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(count) => {
                let room = limit.saturating_sub(kept.len());
                if count > room {
                    overflow = true;
                }
                kept.extend_from_slice(&buffer[..count.min(room)]);
            }
        }
    }
    (kept, overflow)
}

/// A bounded single-line excerpt of child stderr for the report.
#[must_use]
pub fn excerpt(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let line: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    truncate(line.trim(), 240)
}

/// Truncate to at most `maximum` bytes on a character boundary.
#[must_use]
pub fn truncate(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        return value.to_owned();
    }
    let mut end = maximum;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}
