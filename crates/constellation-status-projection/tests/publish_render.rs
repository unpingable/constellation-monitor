mod common;

use std::{fs, os::unix::fs::PermissionsExt as _};

use constellation_status_projection::{
    AvailabilityV1, ImpactV1, ProjectionMomentV1, RenderedStatusV1, project, read_current_artifact,
    render_status, stage_publication,
};

use common::{fact, live_support, policy};

fn artifact() -> constellation_status_projection::StatusArtifactV1 {
    project(
        &policy(true),
        &[
            fact(
                "fact.synthetic.dependency",
                "synthetic.dependency",
                "evidence:subordinate",
                AvailabilityV1::Available,
                ImpactV1::None,
            ),
            fact(
                "fact.synthetic.service",
                "synthetic.service",
                "evidence:service",
                AvailabilityV1::Available,
                ImpactV1::None,
            ),
        ],
        &[
            live_support("evidence:service", 30_000, 0),
            live_support("evidence:subordinate", 30_000, 0),
        ],
        &[],
        ProjectionMomentV1::now(1_900_000_000_000),
    )
    .unwrap()
}

fn publish_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    root
}

#[test]
fn staged_publication_preserves_old_current_until_atomic_commit() {
    let root = publish_root();
    let first = artifact();
    stage_publication(root.path(), &first)
        .unwrap()
        .commit()
        .unwrap();
    assert_eq!(read_current_artifact(root.path()).unwrap(), first);

    let mut second = artifact();
    second.projection_generation = "synthetic-2".to_owned();
    second.artifact_id = second.compute_id().unwrap();
    let staged = stage_publication(root.path(), &second).unwrap();
    assert_eq!(read_current_artifact(root.path()).unwrap(), first);
    drop(staged);
    assert_eq!(read_current_artifact(root.path()).unwrap(), first);

    stage_publication(root.path(), &second)
        .unwrap()
        .commit()
        .unwrap();
    assert_eq!(read_current_artifact(root.path()).unwrap(), second);
}

#[test]
fn current_pointer_refuses_older_or_cross_projection_replacement() {
    let root = publish_root();
    let current = artifact();
    stage_publication(root.path(), &current)
        .unwrap()
        .commit()
        .unwrap();

    let mut older = artifact();
    older.generated_at_unix_ms = current.generated_at_unix_ms - 1_000;
    older.fresh_until_unix_ms = current.fresh_until_unix_ms - 1_000;
    older.artifact_id = older.compute_id().unwrap();
    let error = stage_publication(root.path(), &older)
        .unwrap()
        .commit()
        .unwrap_err();
    assert_eq!(error.code, "stale_replacement");
    assert_eq!(read_current_artifact(root.path()).unwrap(), current);

    let mut other = artifact();
    other.projection_id = "other-audience".to_owned();
    other.artifact_id = other.compute_id().unwrap();
    let error = stage_publication(root.path(), &other)
        .unwrap()
        .commit()
        .unwrap_err();
    assert_eq!(error.code, "projection_mismatch");
    assert_eq!(read_current_artifact(root.path()).unwrap(), current);
}

#[test]
fn corrupt_candidate_never_replaces_current() {
    let root = publish_root();
    let current = artifact();
    stage_publication(root.path(), &current)
        .unwrap()
        .commit()
        .unwrap();
    let object = fs::read_dir(root.path().join("objects"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    fs::write(&object, b"not-json").unwrap();
    assert!(read_current_artifact(root.path()).is_err());
}

#[test]
fn invalid_candidate_is_rejected_before_current_changes() {
    let root = publish_root();
    let current = artifact();
    stage_publication(root.path(), &current)
        .unwrap()
        .commit()
        .unwrap();
    let mut invalid = artifact();
    invalid.artifact_id = format!("sha256:{}", "0".repeat(64));
    assert!(stage_publication(root.path(), &invalid).is_err());
    assert_eq!(read_current_artifact(root.path()).unwrap(), current);
}

#[test]
fn retained_artifact_expires_when_publisher_disappears() {
    let artifact = artifact();
    assert!(matches!(
        render_status(&artifact, artifact.fresh_until_unix_ms - 1, 0).unwrap(),
        RenderedStatusV1::Current { .. }
    ));
    assert!(matches!(
        render_status(&artifact, artifact.fresh_until_unix_ms, 0).unwrap(),
        RenderedStatusV1::StatusUnavailable { .. }
    ));
}

#[test]
fn renderer_receives_only_reduced_artifact_and_escapes_safe_text() {
    let mut artifact = artifact();
    artifact.components[0].display_name = Some("Public <API>".to_owned());
    artifact.artifact_id = artifact.compute_id().unwrap();
    let RenderedStatusV1::Current { html } =
        render_status(&artifact, artifact.generated_at_unix_ms + 1_000, 0).unwrap()
    else {
        panic!("artifact should be current")
    };
    assert!(html.contains("Public &lt;API&gt;"));
    assert!(!html.contains("<API>"));
}

#[test]
fn artifact_without_positive_window_cannot_claim_a_positive_state() {
    let mut artifact = artifact();
    artifact.fresh_until_unix_ms = artifact.generated_at_unix_ms;
    artifact.artifact_id = artifact.compute_id().unwrap();
    let error = artifact.validate().unwrap_err();
    assert_eq!(error.code, "invalid_expiry_state");
}

#[test]
fn rendered_page_scopes_its_labels_and_shows_the_as_of_time() {
    let artifact = artifact();
    let RenderedStatusV1::Current { html } =
        render_status(&artifact, artifact.generated_at_unix_ms + 1_000, 0).unwrap()
    else {
        panic!("artifact should be current")
    };
    assert!(html.contains("Overall projection: No issue reported"));
    assert!(html.contains("As of 2030-03-17T17:46:40Z (UTC)"));
    assert!(html.contains("presentation deadline 2030-03-17T"));
    assert!(html.contains(&artifact.non_authorization));
    assert!(!html.contains("Operational"));
}
