//! Every external command the consumer runs, one function per call, so a
//! change in an AG, Docket, NQ or systemd interface touches exactly one place.
//! Commands run without a shell, with a cleared environment, a deadline and
//! bounded output.

use std::io::{Read, Write as _};
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::config::Config;

const STDOUT_LIMIT: usize = 16 * 1024 * 1024;
const STDERR_LIMIT: usize = 8 * 1024;

/// What one finished command printed.
#[derive(Clone, Debug)]
pub struct Output {
    pub stdout: Vec<u8>,
    pub stderr: String,
}

/// A command that did not succeed (non-zero exit, timeout, unreadable output).
#[derive(Clone, Debug)]
pub struct Failure {
    pub argv: Vec<String>,
    pub code: Option<i32>,
    pub message: String,
}

impl Failure {
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} exited {:?}: {}",
            self.argv.first().map_or("?", String::as_str),
            self.code,
            self.message
        )
    }
}

fn excerpt(bytes: &[u8]) -> String {
    let text: String = String::from_utf8_lossy(bytes)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let text = text.trim();
    let start = text.len().saturating_sub(600);
    let start = (start..=text.len())
        .find(|index| text.is_char_boundary(*index))
        .unwrap_or(0);
    text[start..].to_owned()
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

/// Run `program argv` with optional stdin bytes.
pub fn run(
    program: &Path,
    argv: &[String],
    stdin: Option<&[u8]>,
    timeout: Duration,
) -> Result<Output, Failure> {
    let full: Vec<String> = std::iter::once(program.display().to_string())
        .chain(argv.iter().cloned())
        .collect();
    let failure = |code: Option<i32>, message: String| Failure {
        argv: full.clone(),
        code,
        message,
    };
    let mut child = Command::new(program)
        .args(argv)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C.UTF-8")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Own process group: a timeout kills every descendant (Docket,
        // ag-effectd, resolvers), never only the direct child.
        .process_group(0)
        .spawn()
        .map_err(|error| failure(None, format!("cannot start: {error}")))?;
    if let Some(bytes) = stdin
        && let Some(mut pipe) = child.stdin.take()
    {
        // A child that exits without reading is judged by its status.
        let _ = pipe.write_all(bytes);
    }
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| failure(None, "no stdout".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| failure(None, "no stderr".into()))?;
    let out_reader = thread::spawn(move || collect(stdout, STDOUT_LIMIT));
    let err_reader = thread::spawn(move || collect(stderr, STDERR_LIMIT));
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() >= deadline => {
                kill_group(child.id());
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(error) => return Err(failure(None, format!("cannot wait: {error}"))),
        }
    };
    let (stdout, overflow) = out_reader.join().unwrap_or_default();
    let (stderr, _) = err_reader.join().unwrap_or_default();
    let stderr = excerpt(&stderr);
    let Some(status) = status else {
        return Err(failure(
            None,
            format!("timed out after {} s; {stderr}", timeout.as_secs()),
        ));
    };
    if overflow {
        return Err(failure(status.code(), "printed too much".into()));
    }
    if !status.success() {
        return Err(failure(status.code(), stderr));
    }
    Ok(Output { stdout, stderr })
}

/// SIGKILL the whole process group led by `pid` (no unsafe code: `kill(1)`).
fn kill_group(pid: u32) {
    let _ = Command::new("/bin/kill")
        .args(["-KILL", "--", &format!("-{pid}")])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn json(output: &Output, argv: &[String]) -> Result<Value, Failure> {
    serde_json::from_slice(&output.stdout).map_err(|error| Failure {
        argv: argv.to_vec(),
        code: Some(0),
        message: format!("stdout is not JSON: {error}"),
    })
}

fn path(value: &Path) -> String {
    value.display().to_string()
}

/// The external surface, bound to one configuration.
pub struct External<'a> {
    pub config: &'a Config,
}

impl External<'_> {
    fn timeout(&self) -> Duration {
        Duration::from_secs(self.config.consumer.command_timeout_seconds)
    }

    fn ag(&self, argv: Vec<String>) -> Result<Value, Failure> {
        let output = run(&self.config.ag.loopctl, &argv, None, self.timeout())?;
        json(&output, &argv)
    }

    fn database(&self) -> [String; 2] {
        ["--database".into(), path(&self.config.ag.database)]
    }

    fn gate(&self, plan: &Path) -> Vec<String> {
        let a = &self.config.ag;
        vec![
            "--catalog".into(),
            path(&a.catalog),
            "--observation-resolver".into(),
            path(&a.observation_resolver),
            "--expected-observation-resolver-id".into(),
            a.observation_resolver_id.clone(),
            "--standing-resolver".into(),
            path(&a.standing_resolver),
            "--expected-standing-resolver-id".into(),
            a.standing_resolver_id.clone(),
            "--max-standing-ttl-ms".into(),
            a.max_standing_ttl_ms.to_string(),
            "--executor-plan".into(),
            path(plan),
        ]
    }

    fn docket(&self, plan: &Path) -> Vec<String> {
        let d = &self.config.docket;
        vec![
            "--docket".into(),
            path(&d.program),
            "--docket-state".into(),
            path(&d.state_dir),
            "--docket-trust".into(),
            path(&d.trust),
            "--docket-standing-resolver".into(),
            path(&d.standing_resolver),
            "--executor".into(),
            path(&d.executor),
            "--executor-config".into(),
            path(plan),
            "--issuer-principal".into(),
            d.issuer_principal.clone(),
            "--issuer-key-id".into(),
            d.issuer_key_id.clone(),
            "--issuer-key".into(),
            path(&d.issuer_key),
        ]
    }

    fn step(&self, name: &str, extra: Vec<String>) -> Result<Value, Failure> {
        let mut argv = vec![name.to_owned()];
        argv.extend(self.database());
        argv.extend(extra);
        self.ag(argv)
    }

    /// `ag-loopctl init --database DB --genesis G --runtime-profile P --executor-plan PLAN`
    pub fn ag_init(&self, genesis: &Path, plan: &Path) -> Result<Value, Failure> {
        self.step(
            "init",
            vec![
                "--genesis".into(),
                path(genesis),
                "--runtime-profile".into(),
                path(&self.config.ag.runtime_profile),
                "--executor-plan".into(),
                path(plan),
            ],
        )
    }

    /// `ag-loopctl status --database DB`
    pub fn ag_status(&self) -> Result<Value, Failure> {
        self.step("status", Vec::new())
    }

    /// `ag-loopctl record-proposal --database DB --input I --observation-resolver R --expected-observation-resolver-id ID`
    pub fn ag_record_proposal(&self, input: &Path) -> Result<Value, Failure> {
        let a = &self.config.ag;
        self.step(
            "record-proposal",
            vec![
                "--input".into(),
                path(input),
                "--observation-resolver".into(),
                path(&a.observation_resolver),
                "--expected-observation-resolver-id".into(),
                a.observation_resolver_id.clone(),
            ],
        )
    }

    /// `ag-loopctl require-standing --database DB`
    pub fn ag_require_standing(&self) -> Result<Value, Failure> {
        self.step("require-standing", Vec::new())
    }

    /// `ag-loopctl decide --database DB <gate> --executor-plan PLAN`
    pub fn ag_decide(&self, plan: &Path) -> Result<Value, Failure> {
        self.step("decide", self.gate(plan))
    }

    /// `ag-loopctl authorize --database DB <gate> --executor-plan PLAN`
    pub fn ag_authorize(&self, plan: &Path) -> Result<Value, Failure> {
        self.step("authorize", self.gate(plan))
    }

    /// `ag-loopctl dispatch --database DB <docket>`
    pub fn ag_dispatch(&self, plan: &Path) -> Result<Value, Failure> {
        self.step("dispatch", self.docket(plan))
    }

    /// `ag-loopctl poll --database DB <docket>` (read-only at Docket)
    pub fn ag_poll(&self, plan: &Path) -> Result<Value, Failure> {
        self.step("poll", self.docket(plan))
    }

    /// `ag-loopctl recover --database DB <docket>`: AG's restart law; never
    /// a second dispatch.
    pub fn ag_recover(&self, plan: &Path) -> Result<Value, Failure> {
        self.step("recover", self.docket(plan))
    }

    /// `ag-loopctl continue --database DB --input I --executor-plan PLAN`
    pub fn ag_continue(&self, input: &Path, plan: &Path) -> Result<Value, Failure> {
        self.step(
            "continue",
            vec![
                "--input".into(),
                path(input),
                "--executor-plan".into(),
                path(plan),
            ],
        )
    }

    /// `ag-loopctl complete --database DB --input I --observation-resolver POST
    /// --expected-observation-resolver-id POST_ID --executor-plan PLAN`: AG
    /// accepts only its genesis-pinned postcondition resolver here.
    pub fn ag_complete(&self, input: &Path, plan: &Path) -> Result<Value, Failure> {
        let a = &self.config.ag;
        self.step(
            "complete",
            vec![
                "--input".into(),
                path(input),
                "--observation-resolver".into(),
                path(&a.postcondition_resolver),
                "--expected-observation-resolver-id".into(),
                a.postcondition_resolver_id.clone(),
                "--executor-plan".into(),
                path(plan),
            ],
        )
    }

    /// `ag-effectd plan-id PLAN`: the exact work identity of an owner plan.
    pub fn plan_id(&self, plan: &Path) -> Result<String, Failure> {
        let argv = vec!["plan-id".to_owned(), path(plan)];
        let output = run(&self.config.docket.executor, &argv, None, self.timeout())?;
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    /// Run a resolver wrapper (no argv) on one observation request.
    pub fn resolve(&self, resolver: &Path, request: &[u8]) -> Result<(Value, String), Failure> {
        let output = run(resolver, &[], Some(request), self.timeout())?;
        let value = json(&output, &[path(resolver)])?;
        Ok((value, output.stderr))
    }

    /// `nq --config CFG collect INSTANCE` (nq 0.2.3 `Command::Collect`).
    pub fn nq_collect(&self) -> Result<(), Failure> {
        let nq = &self.config.nq;
        let argv = vec![
            "--config".to_owned(),
            path(&nq.config),
            "collect".to_owned(),
            self.config.enrollment.instance_id.clone(),
        ];
        run(&nq.program, &argv, None, self.timeout()).map(|_| ())
    }

    /// `evaluated_at` (unix ms) of the newest NQ evaluation of the enrolled
    /// watcher instance, read the way the resolver reads it.
    pub fn newest_evaluated_at_ms(&self) -> Result<Option<u64>, String> {
        let e = &self.config.enrollment;
        let settings = constellation_remediation_resolver::Settings {
            claim: constellation_remediation_resolver::Claim::Active,
            nq_program: path(&self.config.nq.program),
            nq_config: path(&self.config.nq.config),
            instance_id: e.instance_id.clone(),
            unit: e.unit.clone(),
            machine_id: e.machine_id.clone(),
            resolver_id: "constellation.remediation.consumer-dwell-check".into(),
            window_records: constellation_remediation_resolver::WINDOW_RECORDS_DEFAULT,
            max_age_ms: constellation_remediation_resolver::MAX_AGE_MS_DEFAULT,
            page_bytes: constellation_remediation_resolver::PAGE_BYTES_DEFAULT,
            timeout: self.timeout(),
        };
        let window = constellation_remediation_resolver::read_window(&settings)?;
        Ok(window.newest.and_then(|newest| {
            newest
                .envelope
                .pointer("/evaluated_at")
                .and_then(Value::as_str)
                .and_then(|text| {
                    time::OffsetDateTime::parse(
                        text,
                        &time::format_description::well_known::Rfc3339,
                    )
                    .ok()
                })
                .and_then(|at| u64::try_from(at.unix_timestamp_nanos() / 1_000_000).ok())
        }))
    }

    /// `systemctl show --property=ActiveState --value UNIT`, enrolled unit only.
    pub fn unit_active_state(&self) -> Result<String, Failure> {
        let argv = vec![
            "show".to_owned(),
            "--property=ActiveState".to_owned(),
            "--value".to_owned(),
            self.config.enrollment.unit.clone(),
        ];
        let output = run(
            &self.config.evaluator.systemctl,
            &argv,
            None,
            self.timeout(),
        )?;
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    /// `systemctl start constellation-attention.service`: one on-demand pass.
    pub fn trigger_evaluator(&self) -> Result<(), Failure> {
        let argv = vec!["start".to_owned(), self.config.evaluator.unit.clone()];
        run(
            &self.config.evaluator.systemctl,
            &argv,
            None,
            self.timeout(),
        )
        .map(|_| ())
    }
}
