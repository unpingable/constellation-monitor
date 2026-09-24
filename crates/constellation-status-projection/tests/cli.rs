mod common;

use std::{fs, os::unix::fs::PermissionsExt as _, process::Command};

use constellation_status_projection::{
    AvailabilityV1, ImpactV1, ProjectionMomentV1, project, stage_publication,
};

use common::{fact, live_support, policy};

#[test]
fn read_current_emits_exact_canonical_bytes_without_line_ending() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let artifact = project(
        &policy(true),
        &[
            fact(
                "fact.internal.cache",
                "internal.cache",
                "evidence:cache",
                AvailabilityV1::Available,
                ImpactV1::None,
            ),
            fact(
                "fact.public.api",
                "public.api",
                "evidence:api",
                AvailabilityV1::Available,
                ImpactV1::None,
            ),
        ],
        &[
            live_support("evidence:api", 30_000, 0),
            live_support("evidence:cache", 30_000, 0),
        ],
        &[],
        ProjectionMomentV1::now(1_900_000_000_000),
    )
    .unwrap();
    stage_publication(root.path(), &artifact)
        .unwrap()
        .commit()
        .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_constellation-status"))
        .args(["read-current", root.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout, artifact.canonical_bytes().unwrap());
}
