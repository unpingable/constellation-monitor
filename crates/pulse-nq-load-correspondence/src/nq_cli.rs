//! The one closed NQ port.
//!
//! Only three read-or-acquire operations exist, and they are reachable only
//! through this module. The executable and configuration digests are checked
//! immediately before every spawn; the environment is cleared; standard input
//! is null; runtime and output are bounded.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::{CorrespondenceError, NqEnrollmentV1, read_regular_bounded, sha256_prefixed};

pub const NQ_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(60);
pub const NQ_READ_TIMEOUT: Duration = Duration::from_secs(15);
pub const MAX_NQ_OUTPUT_BYTES: usize = 2 * 1_024 * 1_024;
const MAX_EXECUTABLE_BYTES: usize = 128 * 1_024 * 1_024;
const MAX_CONFIG_BYTES: usize = 256 * 1_024;

/// Seals [`NqPort`] to implementations owned by this crate. Production must
/// use [`PinnedNqExecutable`]; the only other implementation is the explicit
/// `synthetic-fixtures` test double. A caller cannot substitute an arbitrary
/// command carrier while retaining the verified correspondence type.
pub(crate) mod sealed {
    pub trait Sealed {}
}

/// The three NQ operations the correspondence may invoke.
pub trait NqPort: sealed::Sealed {
    /// `diagnostics acquire-next-local INSTANCE --acquisition-id ID`; returns
    /// the exact canonical `nq.diagnostic_execution.v2` bytes NQ wrote.
    fn acquire_next_local(&self, acquisition_id: &str) -> Result<Vec<u8>, CorrespondenceError>;
    /// `diagnostics replay-local-successor INSTANCE --acquisition-id ID`.
    fn replay_local_successor(&self, acquisition_id: &str) -> Result<Vec<u8>, CorrespondenceError>;
    /// `--json diagnostics qualify ARTIFACT_ID`; returns the provenance JSON.
    fn qualify(&self, artifact_id: &str) -> Result<Vec<u8>, CorrespondenceError>;
}

/// The production port: a digest-pinned NQ executable and configuration.
#[derive(Clone, Debug)]
pub struct PinnedNqExecutable {
    executable_path: PathBuf,
    executable_sha256: String,
    config_path: PathBuf,
    config_sha256: String,
    instance_id: String,
}

impl PinnedNqExecutable {
    pub fn from_enrollment(enrollment: &NqEnrollmentV1) -> Result<Self, CorrespondenceError> {
        if !enrollment.executable_path.is_absolute() || !enrollment.config_path.is_absolute() {
            return Err(CorrespondenceError::new(
                "relative_path",
                "NQ executable and configuration paths must be absolute",
            ));
        }
        let port = Self {
            executable_path: enrollment.executable_path.clone(),
            executable_sha256: enrollment.executable_sha256.clone(),
            config_path: enrollment.config_path.clone(),
            config_sha256: enrollment.config_sha256.clone(),
            instance_id: enrollment.instance_id.clone(),
        };
        port.verify_pins()?;
        Ok(port)
    }

    /// Check-then-use: the digests are verified immediately before each spawn.
    /// The embedding must keep the executable path unwritable by its own
    /// principal; this check does not close that gap by itself.
    fn verify_pins(&self) -> Result<(), CorrespondenceError> {
        let executable = sha256_prefixed(&read_regular_bounded(
            &self.executable_path,
            MAX_EXECUTABLE_BYTES,
        )?);
        if executable != self.executable_sha256 {
            return Err(CorrespondenceError::new(
                "executable_digest_mismatch",
                "NQ executable bytes differ from the enrolled digest",
            ));
        }
        let config = sha256_prefixed(&read_regular_bounded(&self.config_path, MAX_CONFIG_BYTES)?);
        if config != self.config_sha256 {
            return Err(CorrespondenceError::new(
                "config_digest_mismatch",
                "NQ configuration bytes differ from the enrolled digest",
            ));
        }
        Ok(())
    }

    fn run(&self, args: &[&str], timeout: Duration) -> Result<Vec<u8>, CorrespondenceError> {
        self.verify_pins()?;
        let mut child = Command::new(&self.executable_path)
            .env_clear()
            .arg("--config")
            .arg(&self.config_path)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                CorrespondenceError::new("nq_spawn", format!("starting NQ: {error}"))
            })?;
        let started = Instant::now();
        loop {
            if child
                .try_wait()
                .map_err(|error| CorrespondenceError::new("nq_wait", error.to_string()))?
                .is_some()
            {
                break;
            }
            if started.elapsed() >= timeout {
                let _ = child.kill();
                let _ = child.wait();
                return Err(CorrespondenceError::new(
                    "nq_timeout",
                    "NQ exceeded its bounded runtime",
                ));
            }
            thread::sleep(Duration::from_millis(5));
        }
        let output = child
            .wait_with_output()
            .map_err(|error| CorrespondenceError::new("nq_wait", error.to_string()))?;
        if output.stdout.len() > MAX_NQ_OUTPUT_BYTES || output.stderr.len() > MAX_NQ_OUTPUT_BYTES {
            return Err(CorrespondenceError::new(
                "nq_output_bound",
                "NQ output exceeded its byte bound",
            ));
        }
        if !output.status.success() {
            return Err(CorrespondenceError::new(
                "nq_refused",
                format!(
                    "NQ exited with {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }
        Ok(output.stdout)
    }

    #[must_use]
    pub fn executable_path(&self) -> &Path {
        &self.executable_path
    }
}

impl NqPort for PinnedNqExecutable {
    fn acquire_next_local(&self, acquisition_id: &str) -> Result<Vec<u8>, CorrespondenceError> {
        self.run(
            &[
                "diagnostics",
                "acquire-next-local",
                &self.instance_id,
                "--acquisition-id",
                acquisition_id,
            ],
            NQ_ACQUIRE_TIMEOUT,
        )
    }

    fn replay_local_successor(&self, acquisition_id: &str) -> Result<Vec<u8>, CorrespondenceError> {
        self.run(
            &[
                "diagnostics",
                "replay-local-successor",
                &self.instance_id,
                "--acquisition-id",
                acquisition_id,
            ],
            NQ_READ_TIMEOUT,
        )
    }

    fn qualify(&self, artifact_id: &str) -> Result<Vec<u8>, CorrespondenceError> {
        self.run(
            &["--json", "diagnostics", "qualify", artifact_id],
            NQ_READ_TIMEOUT,
        )
    }
}

impl sealed::Sealed for PinnedNqExecutable {}

/// Whether an acquire error was produced only after `Command::spawn`
/// succeeded. Such an error may have lost the command result after NQ durably
/// completed the caller-named acquisition, so one read-only replay is safe.
/// Pin/read failures and `nq_spawn` are known to precede helper execution and
/// must not trigger reconciliation.
pub(crate) fn acquire_error_may_follow_launch(error: &CorrespondenceError) -> bool {
    matches!(
        error.code,
        "nq_wait" | "nq_timeout" | "nq_output_bound" | "nq_refused"
    )
}
