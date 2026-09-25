//! Shared canonical byte vectors for the filesystem inode-pressure
//! correspondence record: the vector suite under
//! [`QuestionV1::HostFilesystemInodePressureV1`], refused against every other
//! row. The capacity row shares this row's subject prefix and its 298 999 ms
//! frame validity, so the suite emits no validity or holding-delay case
//! against it: only the question separates the two.
//!
//! Regenerate deliberately with `REGENERATE_FILESYSTEM_INODES_VECTORS=1` and
//! update the pinned manifest digest.

mod common;

use common::vector_suite::{SuiteV1, run};
use pulse_nq_load_correspondence::QuestionV1;

const SUITE: SuiteV1 = SuiteV1 {
    question: QuestionV1::HostFilesystemInodePressureV1,
    others: &[
        (QuestionV1::HostLoadPressureV1, "load"),
        (QuestionV1::HostFilesystemCapacityPressureV1, "filesystem"),
        (QuestionV1::HostMemoryPressureStallV1, "memory"),
        (QuestionV1::SystemdUnitRequiredActiveV1, "systemd"),
    ],
    directory: "artifacts/nq-host-filesystem-inodes-correspondence-v1",
    manifest_schema: "constellation.nq_host_filesystem_inodes_correspondence_vectors.v1",
    manifest_sha256: "sha256:a879bba7aaf812523b20d39a5d2f43072fb0c8b7ed85fc1dd08d728664f2c677",
    regenerate_env: "REGENERATE_FILESYSTEM_INODES_VECTORS",
};

#[test]
fn filesystem_inodes_vectors_are_pinned_and_verify_exactly() {
    run(&SUITE);
}
