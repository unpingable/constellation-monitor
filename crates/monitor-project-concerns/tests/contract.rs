use monitor_project_concerns::{
    AcquisitionLimits, ContractError, collect, collect_cancellable, discover, parse_binding,
    parse_manifest,
};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::Duration;

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Temp {
    path: PathBuf,
}

impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "monitor-project-concerns-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn manifest(project: &str) -> String {
    format!(
        r#"schema = "project.concerns/v1"
project = "{project}"

[[concerns]]
id = "{project}.required"
question = "{project}.question.required/v1"
profile = "{project}.profile.local/v1"
required = true
description = "A required fixture proposition."

[[concerns]]
id = "{project}.optional"
question = "{project}.question.optional/v1"
profile = "{project}.profile.local/v1"
required = false
description = "An optional fixture proposition."
"#
    )
}

fn status(project: &str, state: &str) -> Value {
    json!({
        "schema": "project.ops.status/v1",
        "project": project,
        "generated_at": "2026-08-25T12:00:00Z",
        "manifest": {"schema": "project.concerns/v1", "path": ".ops/concerns.toml"},
        "producer": {"id": format!("{project}.status")},
        "authority": {},
        "concerns": [{
            "id": format!("{project}.required"),
            "question": format!("{project}.question.required/v1"),
            "profile": format!("{project}.profile.local/v1"),
            "required": true,
            "description": "A required fixture proposition.",
            "observation": {
                "observation_present": true,
                "local_state": state,
                "domain_state": null,
                "observed_at": "2020-01-01T00:00:00Z",
                "valid_for_seconds": null,
                "reason": "project-owned state",
                "facts": {}
            }
        }]
    })
}

fn write_project(root: &Path, project: &str, script: &str, document: Option<Value>) -> PathBuf {
    let repo = root.join(project);
    fs::create_dir_all(repo.join(".ops")).unwrap();
    fs::write(repo.join(".ops/concerns.toml"), manifest(project)).unwrap();
    fs::write(
        repo.join(".ops/observation.toml"),
        format!(
            r#"schema = "project.observation-binding/v1"
producer = "{project}.status"
output_schema = "project.ops.status/v1"
kind = "exec/v1"
argv = ["python3", "producer.py", "literal;not-shell"]
environment = {{ FIXTURE_LITERAL = "yes" }}
"#
        ),
    )
    .unwrap();
    fs::write(repo.join("producer.py"), script).unwrap();
    if let Some(document) = document {
        fs::write(
            repo.join("status.json"),
            serde_json::to_vec(&document).unwrap(),
        )
        .unwrap();
    }
    repo
}

fn normal_script() -> &'static str {
    "import os,sys\nassert sys.argv[1]=='literal;not-shell'\nassert os.environ['FIXTURE_LITERAL']=='yes'\nassert 'HOME' not in os.environ\nprint(open('status.json').read())\n"
}

fn limits() -> AcquisitionLimits {
    AcquisitionLimits {
        timeout: Duration::from_secs(2),
        output_limit_bytes: 64 * 1024,
    }
}

#[test]
fn fourth_project_proves_discovery_acquisition_missingness_and_opaque_state() {
    let project = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fourth-project");
    let root = project.parent().unwrap();
    let discovery = discover(root).unwrap();
    assert_eq!(discovery.projects.len(), 1);
    assert_eq!(discovery.projects[0].project, "example-fixture");

    let report = collect(&project, root, true, limits()).unwrap();
    assert_eq!(report.acquisition.disposition, "ACQUIRED_AND_VALIDATED");
    let indexed: std::collections::BTreeMap<_, _> = report
        .concerns
        .iter()
        .map(|item| (item.declaration.id.as_str(), item))
        .collect();
    assert_eq!(indexed["example.queue.progress"].monitor_state, "OBSERVED");
    assert_eq!(
        indexed["example.queue.progress"]
            .observation
            .as_ref()
            .unwrap()
            .local_state,
        "UNKNOWN"
    );
    assert_eq!(
        indexed["example.output.freshness"].monitor_state,
        "MISSING_REQUIRED_OBSERVATION"
    );
    let optional = indexed["example.optional.mode"]
        .observation
        .as_ref()
        .unwrap();
    assert_eq!(optional.local_state, "EXAMPLE_PAUSED");
    assert_eq!(optional.domain_state.as_deref(), Some("FROBNICATED"));
    assert_eq!(
        indexed["example.queue.progress"]
            .observation
            .as_ref()
            .unwrap()
            .observed_at
            .as_deref(),
        Some("2026-08-25T11:00:00Z")
    );
}

#[test]
fn discovery_is_passive_ignores_unrelated_directories_and_supports_many_projects() {
    let temp = Temp::new();
    fs::create_dir(temp.path.join("unrelated")).unwrap();
    let first = write_project(
        &temp.path,
        "alpha",
        "raise SystemExit('discovery must not execute')\n",
        None,
    );
    let second = write_project(
        &temp.path,
        "beta",
        "raise SystemExit('discovery must not execute')\n",
        None,
    );
    let report = discover(&temp.path).unwrap();
    assert_eq!(report.projects.len(), 2);
    assert!(first.exists() && second.exists());

    fs::remove_file(second.join(".ops/observation.toml")).unwrap();
    let report = discover(&temp.path).unwrap();
    assert_eq!(report.projects.len(), 2);
    assert!(
        report
            .projects
            .iter()
            .any(|project| { project.project == "beta" && project.acquisition.is_none() })
    );

    let empty = Temp::new();
    assert!(discover(&empty.path).unwrap().projects.is_empty());
}

#[test]
fn malformed_unsupported_and_duplicate_declarations_are_refused() {
    assert!(matches!(
        parse_manifest(b"not = [toml"),
        Err(ContractError::MalformedManifest(_))
    ));
    assert!(matches!(
        parse_manifest(b"schema='project.concerns/v2'\nproject='x'\nconcerns=[]"),
        Err(ContractError::UnsupportedManifest(_))
    ));
    let duplicate = br#"
schema = "project.concerns/v1"
project = "x"
[[concerns]]
id = "x.same"
question = "x.q1"
profile = "x.p1"
required = true
description = "one"
[[concerns]]
id = "x.same"
question = "x.q2"
profile = "x.p2"
required = false
description = "two"
"#;
    assert!(matches!(
        parse_manifest(duplicate),
        Err(ContractError::Invalid(_))
    ));
    assert!(matches!(
        parse_binding(b"schema='project.observation-binding/v2'\nproducer='x.p'\noutput_schema='project.ops.status/v1'\nkind='exec/v1'\nargv=['x']"),
        Err(ContractError::UnsupportedBinding(_))
    ));
}

#[test]
fn duplicate_project_identity_is_refused() {
    let temp = Temp::new();
    let a = write_project(
        &temp.path,
        "a",
        normal_script(),
        Some(status("a", "UNKNOWN")),
    );
    let b = write_project(
        &temp.path,
        "b",
        normal_script(),
        Some(status("b", "UNKNOWN")),
    );
    fs::write(b.join(".ops/concerns.toml"), manifest("a")).unwrap();
    assert!(a.exists());
    assert!(matches!(
        discover(&temp.path),
        Err(ContractError::Invalid(_))
    ));
}

#[test]
fn execution_requires_both_enablement_and_containment_by_trusted_root() {
    let temp = Temp::new();
    let repo = write_project(
        &temp.path,
        "trust",
        normal_script(),
        Some(status("trust", "UNKNOWN")),
    );
    assert!(matches!(
        collect(&repo, &temp.path, false, limits()),
        Err(ContractError::Untrusted(_))
    ));
    let other = Temp::new();
    assert!(matches!(
        collect(&repo, &other.path, true, limits()),
        Err(ContractError::Untrusted(_))
    ));
}

#[test]
fn process_success_does_not_hide_missing_or_change_project_state_or_time() {
    let temp = Temp::new();
    let repo = write_project(
        &temp.path,
        "semantic",
        normal_script(),
        Some(status("semantic", "STALE")),
    );
    let report = collect(&repo, &temp.path, true, limits()).unwrap();
    assert_eq!(report.concerns[0].monitor_state, "OBSERVED");
    let observation = report.concerns[0].observation.as_ref().unwrap();
    assert_eq!(observation.local_state, "STALE");
    assert_eq!(
        observation.observed_at.as_deref(),
        Some("2020-01-01T00:00:00Z")
    );
    assert_eq!(
        report.concerns[1].monitor_state,
        "MISSING_OPTIONAL_OBSERVATION"
    );
}

#[test]
fn producer_failures_have_deterministic_acquisition_dispositions() {
    let cases = [
        ("nonzero", "raise SystemExit(7)\n", "PRODUCER_EXIT_NONZERO"),
        ("empty", "pass\n", "PRODUCER_EMITTED_NOTHING"),
        ("malformed", "print('{')\n", "MALFORMED_STATUS:"),
        ("excess", "print('x'*100000)\n", "OUTPUT_LIMIT_EXCEEDED"),
    ];
    for (name, script, expected) in cases {
        let temp = Temp::new();
        let repo = write_project(&temp.path, name, script, None);
        let mut bound = limits();
        bound.output_limit_bytes = 1024;
        let report = collect(&repo, &temp.path, true, bound).unwrap();
        assert!(
            report.acquisition.disposition.starts_with(expected),
            "{name}: {:?}",
            report.acquisition
        );
        assert!(
            report
                .concerns
                .iter()
                .any(|item| item.monitor_state == "MISSING_REQUIRED_OBSERVATION")
        );
    }

    let temp = Temp::new();
    let repo = write_project(&temp.path, "timeout", "import time\ntime.sleep(2)\n", None);
    let report = collect(
        &repo,
        &temp.path,
        true,
        AcquisitionLimits {
            timeout: Duration::from_millis(30),
            output_limit_bytes: 1024,
        },
    )
    .unwrap();
    assert_eq!(report.acquisition.disposition, "PRODUCER_TIMEOUT");
}

#[test]
fn absent_executable_is_reported_without_becoming_observation_success() {
    let temp = Temp::new();
    let repo = write_project(&temp.path, "absent", "", None);
    fs::write(
        repo.join(".ops/observation.toml"),
        "schema='project.observation-binding/v1'\nproducer='absent.status'\noutput_schema='project.ops.status/v1'\nkind='exec/v1'\nargv=['definitely-not-a-monitor-fixture-binary']\n",
    )
    .unwrap();
    let report = collect(&repo, &temp.path, true, limits()).unwrap();
    assert!(
        report
            .acquisition
            .disposition
            .starts_with("PRODUCER_SPAWN_FAILED:")
    );
    assert_eq!(
        report.concerns[0].monitor_state,
        "MISSING_REQUIRED_OBSERVATION"
    );
}

#[test]
fn cancellation_terminates_the_producer_without_observations() {
    let temp = Temp::new();
    let repo = write_project(&temp.path, "cancel", "import time\ntime.sleep(2)\n", None);
    let cancelled = Arc::new(AtomicBool::new(true));
    let report = collect_cancellable(&repo, &temp.path, true, limits(), cancelled).unwrap();
    assert_eq!(report.acquisition.disposition, "PRODUCER_CANCELLED");
    assert_eq!(
        report.concerns[0].monitor_state,
        "MISSING_REQUIRED_OBSERVATION"
    );
}

#[test]
fn structural_identity_and_timestamp_errors_reject_the_whole_status() {
    let mutations = [
        ("status.schema", json!("project.ops.status/v2")),
        ("project", json!("wrong")),
        ("producer.id", json!("wrong.status")),
        ("manifest.schema", json!("project.concerns/v2")),
        ("manifest.path", json!(".ops/other.toml")),
        ("concern.id", json!("undeclared.concern")),
        ("concern.question", json!("wrong.question")),
        ("concern.profile", json!("wrong.profile")),
        ("concern.required", json!(false)),
        ("concern.description", json!("a changed proposition")),
        ("generated_at", json!("not-a-time")),
        ("observed_at", json!("not-a-time")),
    ];
    for (name, replacement) in mutations {
        let temp = Temp::new();
        let project = format!("case{}", NEXT.fetch_add(1, Ordering::Relaxed));
        let mut document = status(&project, "UNKNOWN");
        match name {
            "status.schema" => document["schema"] = replacement,
            "project" => document["project"] = replacement,
            "producer.id" => document["producer"]["id"] = replacement,
            "manifest.schema" => document["manifest"]["schema"] = replacement,
            "manifest.path" => document["manifest"]["path"] = replacement,
            "concern.id" => document["concerns"][0]["id"] = replacement,
            "concern.question" => document["concerns"][0]["question"] = replacement,
            "concern.profile" => document["concerns"][0]["profile"] = replacement,
            "concern.required" => document["concerns"][0]["required"] = replacement,
            "concern.description" => document["concerns"][0]["description"] = replacement,
            "generated_at" => document["generated_at"] = replacement,
            "observed_at" => document["concerns"][0]["observation"]["observed_at"] = replacement,
            _ => unreachable!(),
        }
        let repo = write_project(&temp.path, &project, normal_script(), Some(document));
        let report = collect(&repo, &temp.path, true, limits()).unwrap();
        assert_eq!(report.acquisition.disposition, "STATUS_REJECTED", "{name}");
        assert!(!report.validation_issues.is_empty());
        assert!(
            report
                .concerns
                .iter()
                .all(|item| item.observation.is_none())
        );
    }
}

#[test]
fn explicit_not_present_is_an_inventory_gap_not_project_unknown() {
    let temp = Temp::new();
    let project = "notpresent";
    let mut document = status(project, "ABSENT");
    document["concerns"][0]["observation"]["observation_present"] = json!(false);
    let repo = write_project(&temp.path, project, normal_script(), Some(document));
    let report = collect(&repo, &temp.path, true, limits()).unwrap();
    assert_eq!(report.acquisition.disposition, "ACQUIRED_AND_VALIDATED");
    assert_eq!(
        report.concerns[0].monitor_state,
        "MISSING_REQUIRED_OBSERVATION"
    );
    assert!(report.concerns[0].observation.is_none());
}

#[test]
fn duplicate_and_undeclared_observations_are_rejected() {
    let temp = Temp::new();
    let project = "duplicates";
    let mut document = status(project, "NO_DRIFT_OBSERVED");
    let first = document["concerns"][0].clone();
    document["concerns"].as_array_mut().unwrap().push(first);
    let repo = write_project(&temp.path, project, normal_script(), Some(document));
    let report = collect(&repo, &temp.path, true, limits()).unwrap();
    assert_eq!(report.acquisition.disposition, "STATUS_REJECTED");
    assert!(report.validation_issues[0].contains("duplicate observation"));
}
