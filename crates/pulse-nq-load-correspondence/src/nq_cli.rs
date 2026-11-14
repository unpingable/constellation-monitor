//! The one closed NQ port.
//!
//! Only three read-or-acquire operations exist, and they are reachable only
//! through this module. One maintenance operation, `admin expire-due`, is an
//! inherent method of the production port only: it runs NQ's scheduled
//! ordinary-history expiry before an occurrence is sealed, under its own
//! bound, and carries no evidence. The executable and configuration digests
//! are checked immediately before every spawn; the environment is cleared;
//! standard input is null; runtime and output are bounded.

use std::io::{self, Read};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::{CorrespondenceError, NqEnrollmentV1, read_regular_bounded, sha256_prefixed};

pub const NQ_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(60);
pub const NQ_READ_TIMEOUT: Duration = Duration::from_secs(15);
/// Bound for `admin expire-due`, separate from the unchanged acquisition
/// deadline. It permits about twice the observed cost of one due expiry batch
/// on a large store. A batch that exceeds it is stopped and rolls back, and
/// the turn is refused without a seal; this is not a latency guarantee.
pub const NQ_DUE_EXPIRY_MAINTENANCE_TIMEOUT: Duration = Duration::from_secs(120);
const EXPIRE_DUE_SCHEMA: &str = "nq.admin.expire_due.v1";
const EXPIRY_REFUSAL_CLASSES: [&str; 4] =
    ["capacity", "contention", "history_changed", "disk_full"];
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

/// What NQ reported for one `admin expire-due` run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DueExpiryAttemptV1 {
    /// Not due: decided from NQ's persisted schedule alone; nothing was
    /// validated or attempted.
    Deferred { next_attempt_in_seconds: u64 },
    /// Due: NQ ran its unchanged expiry. `generation_after` moves only when
    /// an expiry committed.
    Completed {
        deleted_rows: u64,
        candidates_remaining: bool,
        generation_before: i64,
        generation_after: i64,
    },
    /// Due, and NQ refused the expiry without effect.
    Refused {
        class: String,
        detail: String,
        generation_before: i64,
        generation_after: i64,
    },
}

/// One strictly parsed `nq.admin.expire_due.v1` report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DueExpiryReportV1 {
    pub attempt: DueExpiryAttemptV1,
    /// Whether NQ's next local successor acquisition would still find its
    /// scheduled expiry due.
    pub scheduled_expiry_pending: bool,
    pub elapsed_ms: u64,
}

impl PinnedNqExecutable {
    /// `--json admin expire-due` under [`NQ_DUE_EXPIRY_MAINTENANCE_TIMEOUT`].
    pub fn maintain_due_expiry(&self) -> Result<DueExpiryReportV1, CorrespondenceError> {
        self.maintain_due_expiry_within(NQ_DUE_EXPIRY_MAINTENANCE_TIMEOUT)
    }

    pub(crate) fn maintain_due_expiry_within(
        &self,
        timeout: Duration,
    ) -> Result<DueExpiryReportV1, CorrespondenceError> {
        let bytes = self
            .run(&["--json", "admin", "expire-due"], timeout)
            .map_err(|error| {
                if error.code == "nq_timeout" {
                    CorrespondenceError::new("nq_maintenance_timeout", error.detail)
                } else {
                    error
                }
            })?;
        parse_due_expiry_report(&bytes)
    }
}

/// Seal only after maintenance that was not refused. A deferred or completed
/// report admits the seal, including a completion that committed nothing
/// (unchanged retention generation) and so leaves NQ's schedule pending; the
/// following acquisition then repeats NQ's attempt, as before this
/// maintenance step existed.
pub fn maintenance_admits_seal(report: &DueExpiryReportV1) -> Result<(), CorrespondenceError> {
    match &report.attempt {
        DueExpiryAttemptV1::Deferred { .. } | DueExpiryAttemptV1::Completed { .. } => Ok(()),
        DueExpiryAttemptV1::Refused { class, detail, .. } => Err(CorrespondenceError::new(
            "due_expiry_maintenance_refused",
            format!("class={class}; detail={detail}"),
        )),
    }
}

fn parse_due_expiry_report(bytes: &[u8]) -> Result<DueExpiryReportV1, CorrespondenceError> {
    fn invalid(detail: impl Into<String>) -> CorrespondenceError {
        CorrespondenceError::new("invalid_maintenance_report", detail)
    }
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| invalid(format!("not one JSON document: {error}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid("report is not a JSON object"))?;
    if object.get("schema").and_then(serde_json::Value::as_str) != Some(EXPIRE_DUE_SCHEMA) {
        return Err(invalid("unknown report schema"));
    }
    let kind = object
        .get("attempt")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invalid("missing attempt"))?;
    let (fields, scope): (&[&str], &str) = match kind {
        "deferred" => (&["next_attempt_in_seconds"], "schedule_hint_only"),
        "completed" => (
            &[
                "deleted_rows",
                "candidates_remaining",
                "generation_before",
                "generation_after",
            ],
            "engine_validated_expiry",
        ),
        "refused" => (
            &["refusal", "generation_before", "generation_after"],
            "engine_validated_expiry",
        ),
        other => return Err(invalid(format!("unknown attempt {other:?}"))),
    };
    let common = [
        "schema",
        "attempt",
        "scope",
        "scheduled_expiry_pending",
        "elapsed_ms",
    ];
    if object.len() != common.len() + fields.len()
        || common
            .iter()
            .chain(fields)
            .any(|field| !object.contains_key(*field))
    {
        return Err(invalid(format!(
            "{kind} report fields differ from its shape"
        )));
    }
    if object["scope"].as_str() != Some(scope) {
        return Err(invalid(format!("{kind} report must have scope {scope}")));
    }
    let unsigned = |name: &str| {
        object[name]
            .as_u64()
            .ok_or_else(|| invalid(format!("{name} is not a non-negative integer")))
    };
    let signed = |name: &str| {
        object[name]
            .as_i64()
            .ok_or_else(|| invalid(format!("{name} is not an integer")))
    };
    let boolean = |name: &str| {
        object[name]
            .as_bool()
            .ok_or_else(|| invalid(format!("{name} is not a boolean")))
    };
    let scheduled_expiry_pending = boolean("scheduled_expiry_pending")?;
    let elapsed_ms = unsigned("elapsed_ms")?;
    let attempt = match kind {
        "deferred" => {
            if scheduled_expiry_pending {
                return Err(invalid("a deferred schedule cannot be pending"));
            }
            DueExpiryAttemptV1::Deferred {
                next_attempt_in_seconds: unsigned("next_attempt_in_seconds")?,
            }
        }
        "completed" => {
            let (generation_before, generation_after) =
                (signed("generation_before")?, signed("generation_after")?);
            if generation_after < generation_before {
                return Err(invalid("retention generation moved backwards"));
            }
            DueExpiryAttemptV1::Completed {
                deleted_rows: unsigned("deleted_rows")?,
                candidates_remaining: boolean("candidates_remaining")?,
                generation_before,
                generation_after,
            }
        }
        _ => {
            let (generation_before, generation_after) =
                (signed("generation_before")?, signed("generation_after")?);
            if generation_after != generation_before {
                return Err(invalid("a refused expiry commits nothing"));
            }
            let refusal = object["refusal"]
                .as_object()
                .filter(|refusal| refusal.len() == 2)
                .ok_or_else(|| invalid("refusal must hold exactly class and detail"))?;
            let class = refusal
                .get("class")
                .and_then(serde_json::Value::as_str)
                .filter(|class| EXPIRY_REFUSAL_CLASSES.contains(class))
                .ok_or_else(|| invalid("unknown refusal class"))?;
            let detail = refusal
                .get("detail")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| invalid("refusal detail is not text"))?;
            DueExpiryAttemptV1::Refused {
                class: class.to_owned(),
                detail: detail.to_owned(),
                generation_before,
                generation_after,
            }
        }
    };
    Ok(DueExpiryReportV1 {
        attempt,
        scheduled_expiry_pending,
        elapsed_ms,
    })
}

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

    const COMPLETED: &str = r#"{"schema":"nq.admin.expire_due.v1","attempt":"completed","scope":"engine_validated_expiry","deleted_rows":12,"candidates_remaining":false,"generation_before":3,"generation_after":4,"scheduled_expiry_pending":false,"elapsed_ms":51234}"#;
    const DEFERRED: &str = r#"{"schema":"nq.admin.expire_due.v1","attempt":"deferred","scope":"schedule_hint_only","next_attempt_in_seconds":1800,"scheduled_expiry_pending":false,"elapsed_ms":3}"#;
    const REFUSED: &str = r#"{"schema":"nq.admin.expire_due.v1","attempt":"refused","scope":"engine_validated_expiry","refusal":{"class":"contention","detail":"fixture"},"generation_before":3,"generation_after":3,"scheduled_expiry_pending":true,"elapsed_ms":40}"#;

    /// The shared NQ/Monitor conformance vector (identical bytes in both
    /// repositories): every listed report parses to its own attempt, and only
    /// a refusal withholds the seal.
    #[test]
    fn shared_expire_due_vector_parses_to_its_attempts() {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/expire_due_report_v1.json"))
                .expect("shared vector");
        let mut seen = std::collections::BTreeSet::new();
        for report in vector["reports"].as_array().expect("reports") {
            let bytes = serde_json::to_vec(report).expect("report bytes");
            let parsed = parse_due_expiry_report(&bytes).expect("vector report parses");
            let attempt = report["attempt"].as_str().expect("attempt");
            seen.insert(attempt.to_owned());
            match (attempt, &parsed.attempt) {
                ("deferred", DueExpiryAttemptV1::Deferred { .. })
                | ("completed", DueExpiryAttemptV1::Completed { .. }) => {
                    maintenance_admits_seal(&parsed).expect("deferred or completed admits");
                }
                ("refused", DueExpiryAttemptV1::Refused { .. }) => assert_eq!(
                    maintenance_admits_seal(&parsed).unwrap_err().code,
                    "due_expiry_maintenance_refused"
                ),
                other => panic!("vector attempt parsed as another variant: {other:?}"),
            }
            assert_eq!(
                Some(parsed.scheduled_expiry_pending),
                report["scheduled_expiry_pending"].as_bool()
            );
        }
        assert_eq!(
            seen.into_iter().collect::<Vec<_>>(),
            ["completed", "deferred", "refused"]
        );
    }

    /// A command that accepts only the exact maintenance argument vector and
    /// prints `report`.
    fn maintenance_port(report: &str) -> (PinnedNqExecutable, tempfile::TempDir) {
        port_with_script(
            String::from("#!/bin/sh\n")
                + "[ \"$3 $4 $5 $#\" = \"--json admin expire-due 5\" ] || { echo \"unexpected arguments: $*\" >&2; exit 64; }\n"
                + "printf '%s' '"
                + report
                + "'\n",
        )
    }

    #[test]
    fn maintenance_admits_the_seal_only_after_deferred_or_completed() {
        for report in [COMPLETED, DEFERRED] {
            let (port, _root) = maintenance_port(report);
            let parsed = port.maintain_due_expiry().expect("valid report");
            maintenance_admits_seal(&parsed).expect("deferred or completed admits the seal");
        }
        let (port, _root) = maintenance_port(REFUSED);
        let parsed = port
            .maintain_due_expiry()
            .expect("a refusal is a valid report");
        assert!(matches!(parsed.attempt, DueExpiryAttemptV1::Refused { .. }));
        assert_eq!(
            maintenance_admits_seal(&parsed).unwrap_err().code,
            "due_expiry_maintenance_refused"
        );
    }

    #[test]
    fn maintenance_parser_rejects_unknown_schema_outcome_and_shape() {
        let cases = [
            COMPLETED.replace("nq.admin.expire_due.v1", "nq.admin.expire_due.v2"),
            COMPLETED.replace("\"completed\"", "\"skipped\""),
            COMPLETED.replace(",\"generation_after\":4", ""),
            COMPLETED.replace("\"elapsed_ms\":51234", "\"elapsed_ms\":51234,\"extra\":1"),
            COMPLETED.replace("engine_validated_expiry", "schedule_hint_only"),
            DEFERRED.replace("schedule_hint_only", "engine_validated_expiry"),
            DEFERRED.replace(
                "\"scheduled_expiry_pending\":false",
                "\"scheduled_expiry_pending\":true",
            ),
            COMPLETED.replace("\"generation_after\":4", "\"generation_after\":2"),
            COMPLETED.replace("\"deleted_rows\":12", "\"deleted_rows\":-1"),
            REFUSED.replace("\"contention\"", "\"unknown\""),
            format!("{COMPLETED}{COMPLETED}"),
            "not json".to_owned(),
        ];
        for case in cases {
            let (port, _root) = maintenance_port(&case);
            let error = port
                .maintain_due_expiry()
                .expect_err("an invalid maintenance report must be refused");
            assert_eq!(
                error.code, "invalid_maintenance_report",
                "{case}: {error:?}"
            );
        }
    }

    #[test]
    fn maintenance_failures_are_refusals_with_their_own_timeout_code() {
        let (port, _root) = port_with_script("#!/bin/sh\nexec /bin/sleep 5\n".to_owned());
        let error = port
            .maintain_due_expiry_within(Duration::from_millis(20))
            .expect_err("the sleeping command must cross the maintenance bound");
        assert_eq!(error.code, "nq_maintenance_timeout");
        assert!(NQ_DUE_EXPIRY_MAINTENANCE_TIMEOUT > NQ_ACQUIRE_TIMEOUT);
        assert_eq!(NQ_ACQUIRE_TIMEOUT, Duration::from_secs(60));

        let (port, _root) =
            port_with_script("#!/bin/sh\necho 'integrity failure' >&2\nexit 1\n".to_owned());
        assert_eq!(port.maintain_due_expiry().unwrap_err().code, "nq_refused");
    }
}
