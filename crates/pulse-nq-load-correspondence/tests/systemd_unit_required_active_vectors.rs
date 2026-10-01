//! Shared canonical byte vectors for the systemd unit required-active
//! correspondence record: the vector suite under
//! [`QuestionV1::SystemdUnitRequiredActiveV1`], refused against every other
//! row, with the boundary cases of its own 58 999 ms frame validity and the
//! load row's 298 999 ms validity.
//!
//! Regenerate deliberately with `REGENERATE_SYSTEMD_UNIT_VECTORS=1` and
//! update the pinned manifest digest.

mod common;

use common::vector_suite::{SuiteV1, run};
use pulse_nq_load_correspondence::QuestionV1;

const SUITE: SuiteV1 = SuiteV1 {
    question: QuestionV1::SystemdUnitRequiredActiveV1,
    others: &[
        (QuestionV1::HostLoadPressureV1, "load"),
        (QuestionV1::HostFilesystemCapacityPressureV1, "filesystem"),
        (QuestionV1::HostMemoryPressureStallV1, "memory"),
    ],
    directory: "artifacts/nq-systemd-unit-required-active-correspondence-v1",
    manifest_schema: "constellation.nq_systemd_unit_required_active_correspondence_vectors.v1",
    manifest_sha256: "sha256:71b57020d92e1c14f0fed9310106d07677eb32802e07918a52eba21f9c6386e4",
    regenerate_env: "REGENERATE_SYSTEMD_UNIT_VECTORS",
};

#[test]
fn systemd_unit_required_active_vectors_are_pinned_and_verify_exactly() {
    run(&SUITE);
}
