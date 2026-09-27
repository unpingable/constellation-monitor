//! The one closed NQ port.
//!
//! Only three read-or-acquire operations exist, and they are reachable only
//! through this module. The executable and configuration digests are checked
//! immediately before every spawn; the environment is cleared; standard input
//! is null; runtime and output are bounded.

use std::io::{self, Read};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::{CorrespondenceError, NqEnrollmentV1, read_regular_bounded, sha256_prefixed};

pub const NQ_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(60);
pub const NQ_READ_TIMEOUT: Duration = Duration::from_secs(15);
pub const MAX_NQ_OUTPUT_BYTES: usize = 2 * 1_024 * 1_024;
pub(crate) const NQ_STAGE_QUALIFY: &str = "qualify";
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
    /// The exact NQ enrollment served by this port.
    fn enrollment(&self) -> &NqEnrollmentV1;
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
    enrollment: NqEnrollmentV1,
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
            enrollment: enrollment.clone(),
        };
        port.verify_pins()?;
        Ok(port)
    }

    /// Check-then-use: the digests are verified immediately before each spawn.
    /// The embedding must keep the executable path unwritable by its own
    /// principal; this check does not close that gap by itself.
    fn verify_pins(&self) -> Result<(), CorrespondenceError> {
        let executable = sha256_prefixed(&read_regular_bounded(
            &self.enrollment.executable_path,
            MAX_EXECUTABLE_BYTES,
        )?);
        if executable != self.enrollment.executable_sha256 {
            return Err(CorrespondenceError::new(
                "executable_digest_mismatch",
                "NQ executable bytes differ from the enrolled digest",
            ));
        }
        let config = sha256_prefixed(&read_regular_bounded(
            &self.enrollment.config_path,
            MAX_CONFIG_BYTES,
        )?);
        if config != self.enrollment.config_sha256 {
            return Err(CorrespondenceError::new(
                "config_digest_mismatch",
                "NQ configuration bytes differ from the enrolled digest",
            ));
        }
        Ok(())
    }

    fn run(&self, args: &[&str], timeout: Duration) -> Result<Vec<u8>, CorrespondenceError> {
        self.verify_pins()?;
        let mut child = Command::new(&self.enrollment.executable_path)
            .env_clear()
            .arg("--config")
            .arg(&self.enrollment.config_path)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                CorrespondenceError::new("nq_spawn", format!("starting NQ: {error}"))
            })?;

        let stdout = child.stdout.take().ok_or_else(|| {
            stop_child(&mut child);
            CorrespondenceError::new("nq_output_io", "NQ stdout pipe was unavailable")
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            stop_child(&mut child);
            CorrespondenceError::new("nq_output_io", "NQ stderr pipe was unavailable")
        })?;
        let stdout_thread = thread::Builder::new()
            .name("nq-stdout-drain".to_owned())
            .spawn(move || drain_bounded(stdout))
            .map_err(|error| {
                stop_child(&mut child);
                CorrespondenceError::new(
                    "nq_output_thread",
                    format!("starting NQ stdout drain: {error}"),
                )
            })?;
        let stderr_thread = match thread::Builder::new()
            .name("nq-stderr-drain".to_owned())
            .spawn(move || drain_bounded(stderr))
        {
            Ok(handle) => handle,
            Err(error) => {
                stop_child(&mut child);
                let _ = stdout_thread.join();
                return Err(CorrespondenceError::new(
                    "nq_output_thread",
                    format!("starting NQ stderr drain: {error}"),
                ));
            }
        };

        let started = Instant::now();
        let disposition = loop {
            match child.try_wait() {
                Ok(Some(status)) => break ChildDisposition::Exited(status),
                Ok(None) if started.elapsed() < timeout => {
                    thread::sleep(Duration::from_millis(5));
                }
                Ok(None) => {
                    let elapsed = started.elapsed();
                    let kill_error = child.kill().err();
                    match child.wait() {
                        Ok(_) => break ChildDisposition::TimedOut(elapsed),
                        Err(wait_error) => {
                            break ChildDisposition::WaitFailed(format!(
                                "reaping NQ after timeout: {wait_error}; kill disposition: {kill_error:?}"
                            ));
                        }
                    }
                }
                Err(error) => {
                    stop_child(&mut child);
                    break ChildDisposition::WaitFailed(error.to_string());
                }
            }
        };

        let stdout = join_drain(stdout_thread, "stdout")?;
        let stderr = join_drain(stderr_thread, "stderr")?;
        match disposition {
            ChildDisposition::TimedOut(elapsed) => {
                return Err(CorrespondenceError::new(
                    "nq_timeout",
                    format!(
                        "NQ exceeded its bounded runtime; elapsed_ms={}",
                        elapsed.as_millis()
                    ),
                ));
            }
            ChildDisposition::WaitFailed(detail) => {
                return Err(CorrespondenceError::new("nq_wait", detail));
            }
            ChildDisposition::Exited(_) => {}
        }
        if stdout.exceeded || stderr.exceeded {
            return Err(CorrespondenceError::new(
                "nq_output_bound",
                "NQ output exceeded its byte bound",
            ));
        }
        let ChildDisposition::Exited(status) = disposition else {
            unreachable!("non-exit dispositions returned above")
        };
        if !status.success() {
            return Err(CorrespondenceError::new(
                "nq_refused",
                format!(
                    "NQ exited with {}: {}",
                    status,
                    String::from_utf8_lossy(&stderr.bytes)
                ),
            ));
        }
        Ok(stdout.bytes)
    }

    #[must_use]
    pub fn executable_path(&self) -> &Path {
        &self.enrollment.executable_path
    }

    /// The complete enrollment whose executable this port invokes.
    #[must_use]
    pub fn enrollment(&self) -> &NqEnrollmentV1 {
        &self.enrollment
    }
}

impl NqPort for PinnedNqExecutable {
    fn enrollment(&self) -> &NqEnrollmentV1 {
        self.enrollment()
    }

    fn acquire_next_local(&self, acquisition_id: &str) -> Result<Vec<u8>, CorrespondenceError> {
        self.run(
            &[
                "diagnostics",
                "acquire-next-local",
                &self.enrollment.instance_id,
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
                &self.enrollment.instance_id,
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
        "nq_wait"
            | "nq_timeout"
            | "nq_output_bound"
            | "nq_output_io"
            | "nq_output_thread"
            | "nq_refused"
    )
}

struct BoundedOutput {
    bytes: Vec<u8>,
    exceeded: bool,
}

fn drain_bounded(mut reader: impl Read) -> io::Result<BoundedOutput> {
    let mut bytes = Vec::new();
    let mut exceeded = false;
    let mut buffer = [0_u8; 8 * 1_024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let available = MAX_NQ_OUTPUT_BYTES.saturating_sub(bytes.len());
        let retained = count.min(available);
        bytes.extend_from_slice(&buffer[..retained]);
        exceeded |= retained < count;
    }
    Ok(BoundedOutput { bytes, exceeded })
}

fn join_drain(
    handle: thread::JoinHandle<io::Result<BoundedOutput>>,
    stream: &str,
) -> Result<BoundedOutput, CorrespondenceError> {
    handle
        .join()
        .map_err(|_| {
            CorrespondenceError::new(
                "nq_output_thread",
                format!("NQ {stream} drain thread failed"),
            )
        })?
        .map_err(|error| {
            CorrespondenceError::new("nq_output_io", format!("reading NQ {stream}: {error}"))
        })
}

fn stop_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

enum ChildDisposition {
    Exited(ExitStatus),
    TimedOut(Duration),
    WaitFailed(String),
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::{NqProducerV1, SemanticIdentityV1};

    fn identity() -> SemanticIdentityV1 {
        SemanticIdentityV1::new(
            "test",
            "1",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        )
    }

    fn port_with_script(script: String) -> (PinnedNqExecutable, tempfile::TempDir) {
        let root = tempfile::tempdir().expect("temporary command root");
        let executable_path = root.path().join("nq-output");
        let config_path = root.path().join("nq.toml");
        fs::write(&executable_path, script).expect("write command");
        let mut permissions = fs::metadata(&executable_path)
            .expect("command metadata")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&executable_path, permissions).expect("make command executable");
        fs::write(&config_path, "fixture = true\n").expect("write config");
        let executable_sha256 = sha256_prefixed(&fs::read(&executable_path).expect("command"));
        let config_sha256 = sha256_prefixed(&fs::read(&config_path).expect("config"));
        let enrollment = NqEnrollmentV1 {
            instance_id: "fixture".to_owned(),
            subject_id: "host:fixture".to_owned(),
            subject_scope: identity(),
            vantage: identity(),
            profile_semantic_id:
                "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            threshold_policy: identity(),
            evaluator: identity(),
            state_model: identity(),
            producer: NqProducerV1 {
                node_id: "fixture".to_owned(),
                build: identity(),
                cohort: identity(),
            },
            executable_path,
            executable_sha256,
            config_path,
            config_sha256,
        };
        (
            PinnedNqExecutable::from_enrollment(&enrollment).expect("pinned command"),
            root,
        )
    }

    fn port_that_writes(bytes: usize) -> (PinnedNqExecutable, tempfile::TempDir) {
        port_with_script(format!(
            "#!/bin/sh\nexec /usr/bin/head -c {bytes} /dev/zero\n"
        ))
    }

    #[test]
    fn drains_pipe_capacity_exceeding_bounded_stdout_while_the_child_runs() {
        let (port, _root) = port_that_writes(256 * 1_024);
        let started = Instant::now();
        let bytes = port
            .run(&[], Duration::from_secs(5))
            .expect("bounded output completes without a pipe deadlock");
        assert_eq!(bytes.len(), 256 * 1_024);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the output drain must complete rather than wait for the deadline"
        );
    }

    #[test]
    fn drains_over_bound_stdout_and_refuses_for_size_not_timeout() {
        let (port, _root) = port_that_writes(MAX_NQ_OUTPUT_BYTES + 1);
        let error = port
            .run(&[], Duration::from_secs(5))
            .expect_err("over-bound output is refused");
        assert_eq!(error.code, "nq_output_bound");
    }

    #[test]
    fn timeout_preserves_code_and_reports_the_pre_kill_elapsed_sample() {
        let (port, _root) = port_with_script("#!/bin/sh\nexec /bin/sleep 5\n".to_owned());
        let timeout = Duration::from_millis(20);
        let error = port
            .run(&[], timeout)
            .expect_err("the sleeping command must cross the bounded runtime");
        assert_eq!(error.code, "nq_timeout");
        let elapsed_ms = error
            .detail
            .strip_prefix("NQ exceeded its bounded runtime; elapsed_ms=")
            .expect("elapsed diagnostic")
            .parse::<u128>()
            .expect("integer milliseconds");
        assert!(elapsed_ms >= timeout.as_millis());
    }
}
