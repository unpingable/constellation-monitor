//! Generic repository concern discovery and bounded producer acquisition.
//! Monitor validates correspondence; it does not decide proposition truth.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MANIFEST_SCHEMA: &str = "project.concerns/v1";
pub const BINDING_SCHEMA: &str = "project.observation-binding/v1";
pub const BINDING_KIND: &str = "exec/v1";
pub const STATUS_SCHEMA: &str = "project.ops.status/v1";
pub const INVENTORY_SCHEMA: &str = "monitor.project-observation.inventory/v1";

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConcernDeclaration {
    pub id: String,
    pub question: String,
    pub profile: String,
    pub required: bool,
    pub description: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConcernManifest {
    pub schema: String,
    pub project: String,
    pub concerns: Vec<ConcernDeclaration>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AcquisitionBinding {
    pub schema: String,
    pub producer: String,
    pub output_schema: String,
    pub kind: String,
    pub argv: Vec<String>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ManifestReference {
    pub schema: String,
    pub path: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProducerIdentity {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub observation_present: bool,
    pub local_state: String,
    pub domain_state: Option<String>,
    pub observed_at: Option<String>,
    pub valid_for_seconds: Option<u64>,
    pub reason: String,
    pub facts: Value,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StatusConcern {
    pub id: String,
    pub question: String,
    pub profile: String,
    pub required: bool,
    pub description: String,
    pub observation: Observation,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StatusEnvelope {
    pub schema: String,
    pub project: String,
    pub generated_at: String,
    pub manifest: ManifestReference,
    pub producer: ProducerIdentity,
    pub authority: Value,
    pub concerns: Vec<StatusConcern>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Value>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BindingSummary {
    pub path: String,
    pub schema: String,
    pub kind: String,
    pub producer: String,
    pub output_schema: String,
    pub supported: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DiscoveredProject {
    pub project: String,
    pub repository: String,
    pub declaration_path: String,
    pub declaration_schema: String,
    pub declaration_supported: bool,
    pub concerns: Vec<ConcernDeclaration>,
    pub required_concerns: Vec<String>,
    pub acquisition: Option<BindingSummary>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DiscoveryReport {
    pub schema: String,
    pub root: String,
    pub projects: Vec<DiscoveredProject>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct InventoryConcern {
    pub declaration: ConcernDeclaration,
    pub monitor_state: String,
    pub observation: Option<Observation>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AcquisitionProvenance {
    pub disposition: String,
    pub acquired_at_unix_ms: u128,
    pub producer: String,
    pub binding_schema: String,
    pub manifest_digest: String,
    pub status_digest: Option<String>,
    pub exit_code: Option<i32>,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    pub repository_revision_context: Option<String>,
    pub repository_revision_is_deployment_provenance: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct InventoryReport {
    pub schema: String,
    pub project: String,
    pub repository: String,
    pub acquisition: AcquisitionProvenance,
    pub validation_issues: Vec<String>,
    pub concerns: Vec<InventoryConcern>,
}

#[derive(Debug, Clone, Copy)]
pub struct AcquisitionLimits {
    pub timeout: Duration,
    pub output_limit_bytes: usize,
}

impl Default for AcquisitionLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            output_limit_bytes: 1024 * 1024,
        }
    }
}

#[derive(Debug)]
pub enum ContractError {
    Io(String),
    MalformedManifest(String),
    MalformedBinding(String),
    UnsupportedManifest(String),
    UnsupportedBinding(String),
    Invalid(String),
    Untrusted(String),
}

impl std::fmt::Display for ContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (kind, detail) = match self {
            Self::Io(v) => ("io", v),
            Self::MalformedManifest(v) => ("malformed manifest", v),
            Self::MalformedBinding(v) => ("malformed binding", v),
            Self::UnsupportedManifest(v) => ("unsupported manifest", v),
            Self::UnsupportedBinding(v) => ("unsupported binding", v),
            Self::Invalid(v) => ("invalid contract", v),
            Self::Untrusted(v) => ("untrusted acquisition", v),
        };
        write!(f, "{kind}: {detail}")
    }
}

impl std::error::Error for ContractError {}

fn read_bytes(path: &Path) -> Result<Vec<u8>, ContractError> {
    fs::read(path).map_err(|error| ContractError::Io(format!("{}: {error}", path.display())))
}

fn validate_identity(label: &str, value: &str) -> Result<(), ContractError> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-/".contains(&b))
    {
        return Err(ContractError::Invalid(format!(
            "{label} has invalid identity characters: {value:?}"
        )));
    }
    Ok(())
}

pub fn parse_manifest(bytes: &[u8]) -> Result<ConcernManifest, ContractError> {
    let text =
        std::str::from_utf8(bytes).map_err(|e| ContractError::MalformedManifest(e.to_string()))?;
    let manifest: ConcernManifest =
        toml::from_str(text).map_err(|e| ContractError::MalformedManifest(e.to_string()))?;
    if manifest.schema != MANIFEST_SCHEMA {
        return Err(ContractError::UnsupportedManifest(manifest.schema));
    }
    validate_identity("project", &manifest.project)?;
    if manifest.concerns.is_empty() {
        return Err(ContractError::Invalid(
            "manifest has no concerns".to_owned(),
        ));
    }
    let mut ids = BTreeSet::new();
    for concern in &manifest.concerns {
        validate_identity("concern id", &concern.id)?;
        validate_identity("question id", &concern.question)?;
        validate_identity("profile id", &concern.profile)?;
        if concern.description.trim().is_empty() {
            return Err(ContractError::Invalid(format!(
                "{} has an empty description",
                concern.id
            )));
        }
        if !ids.insert(&concern.id) {
            return Err(ContractError::Invalid(format!(
                "duplicate concern id {}",
                concern.id
            )));
        }
    }
    Ok(manifest)
}

pub fn parse_binding(bytes: &[u8]) -> Result<AcquisitionBinding, ContractError> {
    let text =
        std::str::from_utf8(bytes).map_err(|e| ContractError::MalformedBinding(e.to_string()))?;
    let binding: AcquisitionBinding =
        toml::from_str(text).map_err(|e| ContractError::MalformedBinding(e.to_string()))?;
    if binding.schema != BINDING_SCHEMA
        || binding.kind != BINDING_KIND
        || binding.output_schema != STATUS_SCHEMA
    {
        return Err(ContractError::UnsupportedBinding(format!(
            "schema={}, kind={}, output_schema={}",
            binding.schema, binding.kind, binding.output_schema
        )));
    }
    validate_identity("producer", &binding.producer)?;
    if binding.argv.is_empty() || binding.argv.iter().any(String::is_empty) {
        return Err(ContractError::Invalid(
            "binding argv must be a non-empty direct argument vector".to_owned(),
        ));
    }
    for key in binding.environment.keys() {
        let valid = !key.is_empty()
            && key
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
        let forbidden =
            key == "PATH" || key == "HOME" || key.starts_with("LD_") || key.starts_with("DYLD_");
        if !valid || forbidden {
            return Err(ContractError::Invalid(format!(
                "binding environment key is unsafe: {key}"
            )));
        }
    }
    Ok(binding)
}

pub fn load_project(
    repository: &Path,
) -> Result<(ConcernManifest, Vec<u8>, AcquisitionBinding), ContractError> {
    let manifest_bytes = read_bytes(&repository.join(".ops/concerns.toml"))?;
    let manifest = parse_manifest(&manifest_bytes)?;
    let binding = parse_binding(&read_bytes(&repository.join(".ops/observation.toml"))?)?;
    Ok((manifest, manifest_bytes, binding))
}

fn load_declaration(repository: &Path) -> Result<(ConcernManifest, Vec<u8>), ContractError> {
    let manifest_bytes = read_bytes(&repository.join(".ops/concerns.toml"))?;
    let manifest = parse_manifest(&manifest_bytes)?;
    Ok((manifest, manifest_bytes))
}

fn candidate_repositories(root: &Path) -> Result<Vec<PathBuf>, ContractError> {
    let mut candidates = Vec::new();
    if root.join(".ops/concerns.toml").is_file() {
        candidates.push(root.to_path_buf());
    }
    for entry in
        fs::read_dir(root).map_err(|e| ContractError::Io(format!("{}: {e}", root.display())))?
    {
        let path = entry.map_err(|e| ContractError::Io(e.to_string()))?.path();
        if path.is_dir() && path.join(".ops/concerns.toml").is_file() {
            candidates.push(path);
        }
    }
    candidates.sort();
    candidates.dedup();
    Ok(candidates)
}

pub fn discover(root: &Path) -> Result<DiscoveryReport, ContractError> {
    let mut projects = Vec::new();
    let mut project_ids = BTreeSet::new();
    for repository in candidate_repositories(root)? {
        let (manifest, _) = load_declaration(&repository)?;
        let binding_path = repository.join(".ops/observation.toml");
        let binding = if binding_path.is_file() {
            Some(parse_binding(&read_bytes(&binding_path)?)?)
        } else {
            None
        };
        if !project_ids.insert(manifest.project.clone()) {
            return Err(ContractError::Invalid(format!(
                "duplicate project identity {}",
                manifest.project
            )));
        }
        projects.push(DiscoveredProject {
            project: manifest.project.clone(),
            repository: repository.display().to_string(),
            declaration_path: repository.join(".ops/concerns.toml").display().to_string(),
            declaration_schema: manifest.schema.clone(),
            declaration_supported: true,
            required_concerns: manifest
                .concerns
                .iter()
                .filter(|c| c.required)
                .map(|c| c.id.clone())
                .collect(),
            concerns: manifest.concerns,
            acquisition: binding.map(|binding| BindingSummary {
                path: binding_path.display().to_string(),
                schema: binding.schema,
                kind: binding.kind,
                producer: binding.producer,
                output_schema: binding.output_schema,
                supported: true,
            }),
        });
    }
    Ok(DiscoveryReport {
        schema: "monitor.project-concern.discovery/v1".to_owned(),
        root: root.display().to_string(),
        projects,
    })
}

fn digest(bytes: &[u8]) -> String {
    let value = Sha256::digest(bytes);
    let mut output = String::from("sha256:");
    for byte in value {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn repository_revision_context(repository: &Path) -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repository)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn read_limited<R: Read + Send + 'static>(
    mut reader: R,
    limit: usize,
    exceeded: Arc<AtomicBool>,
) -> thread::JoinHandle<io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut kept = Vec::new();
        let mut buffer = [0_u8; 8192];
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            let remaining = limit.saturating_sub(kept.len());
            kept.extend_from_slice(&buffer[..read.min(remaining)]);
            if read > remaining {
                exceeded.store(true, Ordering::SeqCst);
            }
        }
        Ok(kept)
    })
}

struct ProcessCapture {
    disposition: String,
    exit_code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run_producer(
    repository: &Path,
    binding: &AcquisitionBinding,
    limits: AcquisitionLimits,
    cancelled: &AtomicBool,
) -> ProcessCapture {
    let mut command = Command::new(&binding.argv[0]);
    command
        .args(&binding.argv[1..])
        .current_dir(repository)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .envs(&binding.environment)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return ProcessCapture {
                disposition: format!("PRODUCER_SPAWN_FAILED:{error}"),
                exit_code: None,
                stdout: vec![],
                stderr: vec![],
            };
        }
    };
    let exceeded = Arc::new(AtomicBool::new(false));
    let stdout = read_limited(
        child.stdout.take().expect("piped stdout"),
        limits.output_limit_bytes,
        Arc::clone(&exceeded),
    );
    let stderr = read_limited(
        child.stderr.take().expect("piped stderr"),
        limits.output_limit_bytes,
        Arc::clone(&exceeded),
    );
    let started = Instant::now();
    let (disposition, status) = loop {
        if cancelled.load(Ordering::SeqCst) {
            let _ = child.kill();
            break ("PRODUCER_CANCELLED".to_owned(), child.wait().ok());
        }
        if exceeded.load(Ordering::SeqCst) {
            let _ = child.kill();
            break ("OUTPUT_LIMIT_EXCEEDED".to_owned(), child.wait().ok());
        }
        if started.elapsed() >= limits.timeout {
            let _ = child.kill();
            break ("PRODUCER_TIMEOUT".to_owned(), child.wait().ok());
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                break (
                    (if status.success() {
                        "PROCESS_SUCCEEDED"
                    } else {
                        "PRODUCER_EXIT_NONZERO"
                    })
                    .to_owned(),
                    Some(status),
                );
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                let _ = child.kill();
                break (format!("PRODUCER_WAIT_FAILED:{error}"), child.wait().ok());
            }
        }
    };
    ProcessCapture {
        disposition,
        exit_code: status.and_then(|s| s.code()),
        stdout: stdout
            .join()
            .unwrap_or_else(|_| Ok(vec![]))
            .unwrap_or_default(),
        stderr: stderr
            .join()
            .unwrap_or_else(|_| Ok(vec![]))
            .unwrap_or_default(),
    }
}

fn is_rfc3339(value: &str) -> bool {
    if value.len() < 20 || value.as_bytes().get(10) != Some(&b'T') {
        return false;
    }
    let bytes = value.as_bytes();
    if bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return false;
    }
    let number = |a, b| value.get(a..b).and_then(|v| v.parse::<u32>().ok());
    let date = matches!(number(0, 4), Some(1..=9999))
        && matches!(number(5, 7), Some(1..=12))
        && matches!(number(8, 10), Some(1..=31));
    let time = matches!(number(11, 13), Some(0..=23))
        && matches!(number(14, 16), Some(0..=59))
        && matches!(number(17, 19), Some(0..=60));
    let zone = &value[19..];
    let zulu = zone == "Z"
        || (zone.starts_with('.')
            && zone.ends_with('Z')
            && zone[1..zone.len() - 1].bytes().all(|b| b.is_ascii_digit()));
    let offset = if zone.len() >= 6 {
        let part = &zone[zone.len() - 6..];
        (part.starts_with('+') || part.starts_with('-'))
            && part.as_bytes()[3] == b':'
            && part[1..3].parse::<u32>().is_ok_and(|v| v <= 23)
            && part[4..6].parse::<u32>().is_ok_and(|v| v <= 59)
            && (zone.len() == 6
                || (zone[..zone.len() - 6].starts_with('.')
                    && zone[1..zone.len() - 6].bytes().all(|b| b.is_ascii_digit())))
    } else {
        false
    };
    date && time && (zulu || offset)
}

fn validate_status(
    manifest: &ConcernManifest,
    binding: &AcquisitionBinding,
    status: &StatusEnvelope,
) -> Vec<String> {
    let mut issues = Vec::new();
    if status.schema != STATUS_SCHEMA {
        issues.push(format!("unsupported status schema {}", status.schema));
    }
    if status.project != manifest.project {
        issues.push(format!(
            "project identity mismatch: declared {}, returned {}",
            manifest.project, status.project
        ));
    }
    if status.producer.id != binding.producer {
        issues.push(format!(
            "producer identity mismatch: bound {}, returned {}",
            binding.producer, status.producer.id
        ));
    }
    if status.manifest.schema != manifest.schema || status.manifest.path != ".ops/concerns.toml" {
        issues.push("status manifest reference mismatch".to_owned());
    }
    if !is_rfc3339(&status.generated_at) {
        issues.push("generated_at is not RFC3339".to_owned());
    }
    let declared: BTreeMap<_, _> = manifest
        .concerns
        .iter()
        .map(|c| (c.id.as_str(), c))
        .collect();
    let mut returned = BTreeSet::new();
    for item in &status.concerns {
        if !returned.insert(item.id.as_str()) {
            issues.push(format!("duplicate observation for concern {}", item.id));
            continue;
        }
        let Some(expected) = declared.get(item.id.as_str()) else {
            issues.push(format!("observation for undeclared concern {}", item.id));
            continue;
        };
        if item.question != expected.question {
            issues.push(format!("question identity mismatch for {}", item.id));
        }
        if item.profile != expected.profile {
            issues.push(format!("profile identity mismatch for {}", item.id));
        }
        if item.required != expected.required {
            issues.push(format!("required flag mismatch for {}", item.id));
        }
        if item.description != expected.description {
            issues.push(format!("description mismatch for {}", item.id));
        }
        if item.observation.local_state.trim().is_empty()
            || item.observation.reason.trim().is_empty()
            || !item.observation.facts.is_object()
        {
            issues.push(format!("invalid observation structure for {}", item.id));
        }
        if item
            .observation
            .observed_at
            .as_deref()
            .is_some_and(|v| !is_rfc3339(v))
        {
            issues.push(format!("invalid observed_at for {}", item.id));
        }
    }
    issues
}

fn missing_inventory(manifest: &ConcernManifest) -> Vec<InventoryConcern> {
    manifest
        .concerns
        .iter()
        .cloned()
        .map(|declaration| InventoryConcern {
            monitor_state: if declaration.required {
                "MISSING_REQUIRED_OBSERVATION"
            } else {
                "MISSING_OPTIONAL_OBSERVATION"
            }
            .to_owned(),
            declaration,
            observation: None,
        })
        .collect()
}

pub fn collect(
    repository: &Path,
    trusted_root: &Path,
    allow_exec: bool,
    limits: AcquisitionLimits,
) -> Result<InventoryReport, ContractError> {
    collect_cancellable(
        repository,
        trusted_root,
        allow_exec,
        limits,
        Arc::new(AtomicBool::new(false)),
    )
}

pub fn collect_cancellable(
    repository: &Path,
    trusted_root: &Path,
    allow_exec: bool,
    limits: AcquisitionLimits,
    cancelled: Arc<AtomicBool>,
) -> Result<InventoryReport, ContractError> {
    if !allow_exec {
        return Err(ContractError::Untrusted(
            "collection requires explicit execution enablement".to_owned(),
        ));
    }
    let repository = repository
        .canonicalize()
        .map_err(|e| ContractError::Io(e.to_string()))?;
    let trusted_root = trusted_root
        .canonicalize()
        .map_err(|e| ContractError::Io(e.to_string()))?;
    if !repository.starts_with(&trusted_root) {
        return Err(ContractError::Untrusted(format!(
            "{} is outside configured root {}",
            repository.display(),
            trusted_root.display()
        )));
    }
    let (manifest, manifest_bytes, binding) = load_project(&repository)?;
    let process = run_producer(&repository, &binding, limits, &cancelled);
    let mut disposition = process.disposition.clone();
    let mut issues = Vec::new();
    let mut concerns = missing_inventory(&manifest);
    let mut status_digest = None;
    if process.disposition == "PROCESS_SUCCEEDED" {
        if process.stdout.is_empty() {
            disposition = "PRODUCER_EMITTED_NOTHING".to_owned();
        } else {
            status_digest = Some(digest(&process.stdout));
            match serde_json::from_slice::<StatusEnvelope>(&process.stdout) {
                Err(error) => disposition = format!("MALFORMED_STATUS:{error}"),
                Ok(status) => {
                    issues = validate_status(&manifest, &binding, &status);
                    if issues.is_empty() {
                        disposition = "ACQUIRED_AND_VALIDATED".to_owned();
                        let returned: BTreeMap<_, _> = status
                            .concerns
                            .into_iter()
                            .map(|i| (i.id, i.observation))
                            .collect();
                        concerns = manifest
                            .concerns
                            .iter()
                            .cloned()
                            .map(|declaration| {
                                let observation = returned.get(&declaration.id).cloned();
                                let present =
                                    observation.as_ref().is_some_and(|v| v.observation_present);
                                let monitor_state = if present {
                                    "OBSERVED"
                                } else if declaration.required {
                                    "MISSING_REQUIRED_OBSERVATION"
                                } else {
                                    "MISSING_OPTIONAL_OBSERVATION"
                                };
                                InventoryConcern {
                                    declaration,
                                    monitor_state: monitor_state.to_owned(),
                                    observation: observation.filter(|v| v.observation_present),
                                }
                            })
                            .collect();
                    } else {
                        disposition = "STATUS_REJECTED".to_owned();
                    }
                }
            }
        }
    }
    Ok(InventoryReport {
        schema: INVENTORY_SCHEMA.to_owned(),
        project: manifest.project,
        repository: repository.display().to_string(),
        acquisition: AcquisitionProvenance {
            disposition,
            acquired_at_unix_ms: now_unix_ms(),
            producer: binding.producer,
            binding_schema: binding.schema,
            manifest_digest: digest(&manifest_bytes),
            status_digest,
            exit_code: process.exit_code,
            stdout_bytes: process.stdout.len(),
            stderr_bytes: process.stderr.len(),
            repository_revision_context: repository_revision_context(&repository),
            repository_revision_is_deployment_provenance: false,
        },
        validation_issues: issues,
        concerns,
    })
}

pub fn render_discovery(report: &DiscoveryReport) -> String {
    let mut lines = vec![format!("project concerns under {}", report.root)];
    for project in &report.projects {
        let binding = if project.acquisition.is_some() {
            "supported"
        } else {
            "absent"
        };
        lines.push(format!(
            "{:<20} {:>3} concerns  {:>3} required  binding={binding}",
            project.project,
            project.concerns.len(),
            project.required_concerns.len()
        ));
    }
    lines.join("\n")
}

pub fn render_inventory(report: &InventoryReport) -> String {
    let observed = report
        .concerns
        .iter()
        .filter(|c| c.monitor_state == "OBSERVED")
        .count();
    let missing = report
        .concerns
        .iter()
        .filter(|c| c.monitor_state == "MISSING_REQUIRED_OBSERVATION")
        .count();
    let required = report
        .concerns
        .iter()
        .filter(|c| c.declaration.required)
        .count();
    let mut lines = vec![format!(
        "{}  required={} observed={} required-missing={} acquisition={}",
        report.project, required, observed, missing, report.acquisition.disposition
    )];
    for item in &report.concerns {
        let state = item
            .observation
            .as_ref()
            .map_or(item.monitor_state.as_str(), |v| v.local_state.as_str());
        let domain = item
            .observation
            .as_ref()
            .and_then(|v| v.domain_state.as_deref())
            .map_or(String::new(), |v| format!(" [{v}]"));
        lines.push(format!(
            "  {:<38} {:<30}{}",
            item.declaration.id, state, domain
        ));
    }
    lines.join("\n")
}
