//! Real end-to-end chain: pinned NQ co-production, live Pulse admission,
//! projection, and local publication. Ignored by default; see the
//! correspondence crate's `real_nq` test for the environment variables and
//! prerequisites. This adds:
//!
//! ```sh
//! NQ_CORRESPONDENCE_PUBLISH_ROOT=/absolute/fresh/publish
//! NQ_CORRESPONDENCE_EXPECTED_STATE=present
//! ```
//!
//! The harness constructs separate public and operator policies from the same
//! verified fact and process-local live support, then publishes below
//! `publish/public` and `publish/operator` respectively. The optional
//! `NQ_CORRESPONDENCE_MOUNTPOINT_LABEL` (for example `/data`) is appended to
//! the operator label only; the public label never carries it.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use constellation_status_nq_filesystem_inodes::{
    CONSEQUENCE_SCHEMA_V1, FACT_OWNER, PUBLIC_COMPONENT_LABEL, admit_live, fact_for,
    live_support_selector, operator_component_label, operator_detail, operator_explanation,
    recommended_safe_reasons,
};
use constellation_status_projection::{
    AudienceClassV1, ComponentOutputFieldV1, ComponentPolicyV1, DisclosurePolicyV1,
    FactRequirementV1, LiveSupportSelectorV1, OutputComponentV1, PROJECTION_POLICY_SCHEMA_V1,
    ProjectionMomentV1, ProjectionPolicyV1, SourceFactClassV1, project, project_with_details,
    read_current_artifact, stage_publication,
};
use pulse_nq_load_correspondence::fixture::start_reactor;
use pulse_nq_load_correspondence::{
    Coproducer, CorrespondenceError, CorrespondenceProfileV1, NqDetectorStateV1,
    OccurrenceOutcomeV1, PinnedNqExecutable, SubjectIncarnationWitness,
};
use pulse_types::IncarnationId;

struct LinuxBootWitness;

impl SubjectIncarnationWitness for LinuxBootWitness {
    fn current(&self) -> Result<IncarnationId, CorrespondenceError> {
        let value = fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|error| CorrespondenceError::new("io", error.to_string()))?;
        Ok(IncarnationId::new(format!("linux-boot:{}", value.trim())))
    }
}

fn env_path(name: &str) -> PathBuf {
    let path =
        PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("{name} is required")));
    assert!(path.is_absolute(), "{name} must be absolute");
    path
}

fn expected_state() -> (NqDetectorStateV1, &'static str) {
    match std::env::var("NQ_CORRESPONDENCE_EXPECTED_STATE")
        .expect("NQ_CORRESPONDENCE_EXPECTED_STATE is required")
        .as_str()
    {
        "present" => (NqDetectorStateV1::Present, "degraded"),
        "explicitly_absent" => (NqDetectorStateV1::ExplicitlyAbsent, "healthy"),
        "cannot_evaluate" => (NqDetectorStateV1::CannotEvaluate, "unknown"),
        other => panic!(
            "NQ_CORRESPONDENCE_EXPECTED_STATE must be present, explicitly_absent, or cannot_evaluate; got {other}"
        ),
    }
}

fn filesystem_component(selector: LiveSupportSelectorV1, operator: bool) -> ComponentPolicyV1 {
    let display_name = match std::env::var("NQ_CORRESPONDENCE_MOUNTPOINT_LABEL") {
        Ok(mountpoint) if operator => operator_component_label(&mountpoint),
        _ => PUBLIC_COMPONENT_LABEL.to_owned(),
    };
    ComponentPolicyV1 {
        key: "nq.host_filesystem_inodes.pressure".to_owned(),
        output: Some(OutputComponentV1 {
            id: "filesystem-inodes".to_owned(),
            display_name,
        }),
        required_facts: vec![FactRequirementV1 {
            fact_id: "fact.nq.host_filesystem_inodes.pressure".to_owned(),
            owner: FACT_OWNER.to_owned(),
            native_schema: CONSEQUENCE_SCHEMA_V1.to_owned(),
            class: SourceFactClassV1::DerivedAdmitted,
            live_support: selector,
        }],
        maintenance_assertion_ids: Vec::new(),
    }
}

fn public_policy(selector: LiveSupportSelectorV1) -> ProjectionPolicyV1 {
    ProjectionPolicyV1 {
        schema: PROJECTION_POLICY_SCHEMA_V1.to_owned(),
        projection_id: "candidate-public-filesystem-inodes".to_owned(),
        generation: "candidate-public-1".to_owned(),
        root_component: "nq.host_filesystem_inodes.pressure".to_owned(),
        maximum_age_ms: 60_000,
        admitted_clock_uncertainty_ms: 250,
        timestamp_granularity_ms: 1_000,
        components: vec![filesystem_component(selector, false)],
        dependencies: Vec::new(),
        disclosure: DisclosurePolicyV1 {
            audience: AudienceClassV1::Public,
            component_fields: vec![
                ComponentOutputFieldV1::DisplayName,
                ComponentOutputFieldV1::State,
                ComponentOutputFieldV1::Mode,
                ComponentOutputFieldV1::Reason,
            ],
            safe_reasons: recommended_safe_reasons(),
            include_basis_digest: false,
            include_observation_window: false,
        },
    }
}

fn operator_policy(selector: LiveSupportSelectorV1) -> ProjectionPolicyV1 {
    ProjectionPolicyV1 {
        schema: PROJECTION_POLICY_SCHEMA_V1.to_owned(),
        projection_id: "candidate-operator-filesystem-inodes".to_owned(),
        generation: "candidate-operator-1".to_owned(),
        root_component: "nq.host_filesystem_inodes.pressure".to_owned(),
        maximum_age_ms: 60_000,
        admitted_clock_uncertainty_ms: 250,
        timestamp_granularity_ms: 1_000,
        components: vec![filesystem_component(selector, true)],
        dependencies: Vec::new(),
        disclosure: DisclosurePolicyV1 {
            audience: AudienceClassV1::Operator,
            component_fields: vec![
                ComponentOutputFieldV1::DisplayName,
                ComponentOutputFieldV1::State,
                ComponentOutputFieldV1::Mode,
                ComponentOutputFieldV1::Reason,
                ComponentOutputFieldV1::Detail,
            ],
            safe_reasons: recommended_safe_reasons(),
            include_basis_digest: true,
            include_observation_window: false,
        },
    }
}

#[test]
#[ignore = "requires a pinned real NQ executable, store, enrolled profile, and fresh custody roots"]
fn real_projection_chain() {
    let profile_path = env_path("NQ_CORRESPONDENCE_PROFILE");
    let custody_root = env_path("NQ_CORRESPONDENCE_CUSTODY_ROOT");
    let publish_root = env_path("NQ_CORRESPONDENCE_PUBLISH_ROOT");
    let (expected_state, expected_projection) = expected_state();
    let occurrences: u64 = std::env::var("NQ_CORRESPONDENCE_OCCURRENCES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(3);
    let cadence_ms: u64 = std::env::var("NQ_CORRESPONDENCE_CADENCE_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(2_000);
    assert!((1..=64).contains(&occurrences));

    let profile = CorrespondenceProfileV1::decode(&fs::read(&profile_path).expect("profile"))
        .expect("profile");
    let port = PinnedNqExecutable::from_enrollment(&profile.nq).expect("pinned NQ");
    let witness = LinuxBootWitness;
    let incarnation = witness.current().expect("boot identity");
    fs::create_dir_all(&custody_root).expect("custody root");
    fs::create_dir_all(&publish_root).expect("publish root");
    let public_publish_root = publish_root.join("public");
    let operator_publish_root = publish_root.join("operator");
    // The publisher refuses group- or other-writable roots; do not inherit the
    // process umask (a real host with umask 0002 made the harness fail here).
    for root in [&publish_root, &public_publish_root, &operator_publish_root] {
        fs::create_dir_all(root).expect("publish root");
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).expect("publish root mode");
    }
    let reactor = start_reactor(
        &profile,
        incarnation,
        "real-projection",
        &custody_root.join("pulse.journal"),
    )
    .expect("reactor");
    let mut coproducer = Coproducer::begin(
        &profile,
        &port,
        &witness,
        &custody_root.join("intent"),
        &custody_root.join("audit"),
    )
    .expect("coproducer");
    let consumer = profile.consumer();

    for index in 0..occurrences {
        if index > 0 {
            std::thread::sleep(Duration::from_millis(cadence_ms));
        }
        let result = coproducer
            .run_occurrence(&reactor)
            .unwrap_or_else(|error| panic!("occurrence refused before delivery: {error}"));
        let verified = match result.outcome {
            OccurrenceOutcomeV1::Verified(verified) => *verified,
            OccurrenceOutcomeV1::AuditOnly { refusal } => {
                panic!("occurrence {} was audit-only: {refusal}", result.sequence);
            }
        };
        assert_eq!(
            verified.nq_detector_state(),
            expected_state,
            "occurrence {} produced the wrong NQ state",
            result.sequence
        );
        // The owner's typed reason, when NQ carried one, and this leaf's
        // bounded explanation of it; neither changes the state above.
        println!(
            "occurrence {} owner failure: {:?} explanation: {:?}",
            result.sequence,
            verified.owner_failure(),
            operator_explanation(&verified).map(|explanation| explanation.text)
        );
        let selector = live_support_selector(&reactor.snapshot(), &consumer).expect("selector");
        let public_policy = public_policy(selector.clone());
        let operator_policy = operator_policy(selector);
        let fact = fact_for(
            &verified,
            &public_policy,
            "nq.host_filesystem_inodes.pressure",
        )
        .expect("shared fact");
        assert_eq!(
            fact_for(
                &verified,
                &operator_policy,
                "nq.host_filesystem_inodes.pressure"
            )
            .expect("operator fact"),
            fact,
            "both audiences build the same fact from the same correspondence"
        );
        let live = admit_live(
            &verified,
            &public_policy,
            "nq.host_filesystem_inodes.pressure",
            &reactor,
            &format!("nonce:{}", verified.correspondence_id()),
            120_000,
        )
        .expect("live admission");
        let now_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_millis(),
        )
        .expect("fits");
        let public_artifact = project(
            &public_policy,
            std::slice::from_ref(&fact),
            std::slice::from_ref(&live),
            &[],
            ProjectionMomentV1::now(now_ms),
        )
        .expect("public projection");
        let detail = operator_detail(
            &verified,
            &operator_policy,
            "nq.host_filesystem_inodes.pressure",
        )
        .expect("guarded detail");
        let details = detail.iter().cloned().collect::<Vec<_>>();
        let operator_artifact = project_with_details(
            &operator_policy,
            std::slice::from_ref(&fact),
            std::slice::from_ref(&live),
            &[],
            &details,
            ProjectionMomentV1::now(now_ms),
        )
        .expect("operator projection");
        println!(
            "occurrence {} operator detail: {:?}",
            result.sequence,
            operator_artifact.components[0].detail.as_deref()
        );
        assert_eq!(
            public_artifact.aggregate_state.as_str(),
            expected_projection,
            "occurrence {} produced the wrong public projected state",
            result.sequence
        );
        assert_eq!(
            operator_artifact.aggregate_state.as_str(),
            expected_projection,
            "occurrence {} produced the wrong operator projected state",
            result.sequence
        );
        assert!(
            public_artifact.basis_digest.is_none(),
            "public projection must not disclose a basis digest"
        );
        assert!(
            operator_artifact.basis_digest.is_some(),
            "operator projection must carry its independently computed basis digest"
        );
        let public_bytes = public_artifact.canonical_bytes().expect("public bytes");
        let public_text = String::from_utf8(public_bytes).expect("public artifact is UTF-8");
        for private_identity in [
            verified.acquisition_id(),
            verified.evidence_ref(),
            verified.correspondence_id(),
            verified.artifact_id(),
            verified.certificate_id(),
            profile.nq.producer.node_id.as_str(),
            profile.nq.subject_id.as_str(),
        ] {
            assert!(
                !public_text.contains(private_identity),
                "public artifact disclosed a source identity"
            );
        }
        let public_published = stage_publication(&public_publish_root, &public_artifact)
            .expect("stage public")
            .commit()
            .expect("commit public");
        assert_eq!(
            read_current_artifact(&public_publish_root)
                .expect("current public")
                .artifact_id,
            public_published
        );
        let operator_published = stage_publication(&operator_publish_root, &operator_artifact)
            .expect("stage operator")
            .commit()
            .expect("commit operator");
        assert_eq!(
            read_current_artifact(&operator_publish_root)
                .expect("current operator")
                .artifact_id,
            operator_published
        );
        assert_ne!(public_published, operator_published);
        println!(
            "occurrence {} nq_state={} public_state={} public_artifact={} operator_state={} operator_artifact={}",
            result.sequence,
            verified.nq_detector_state().as_str(),
            public_artifact.aggregate_state.as_str(),
            public_published,
            operator_artifact.aggregate_state.as_str(),
            operator_published
        );
    }
    reactor.shutdown().expect("shutdown");
}
