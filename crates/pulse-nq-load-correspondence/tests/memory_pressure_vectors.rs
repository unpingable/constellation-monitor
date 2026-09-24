//! Shared canonical byte vectors for the memory pressure-stall correspondence
//! record: the vector suite under [`QuestionV1::HostMemoryPressureStallV1`],
//! refused against both other rows, with the boundary cases of its own
//! 118 999 ms frame validity and the load row's 298 999 ms validity.
//!
//! Regenerate deliberately with `REGENERATE_MEMORY_PRESSURE_VECTORS=1` and
//! update the pinned manifest digest.

mod common;

use common::vector_suite::{SuiteV1, run};
use pulse_nq_load_correspondence::QuestionV1;

const SUITE: SuiteV1 = SuiteV1 {
    question: QuestionV1::HostMemoryPressureStallV1,
    others: &[
        (QuestionV1::HostLoadPressureV1, "load"),
        (QuestionV1::HostFilesystemCapacityPressureV1, "filesystem"),
    ],
    directory: "artifacts/nq-host-memory-pressure-stall-correspondence-v1",
    manifest_schema: "constellation.nq_host_memory_pressure_stall_correspondence_vectors.v1",
    manifest_sha256: "sha256:dfd34dce81a18285337d055757f6ea1a33cf80a89530e1ab12cfb2ed2055543d",
    regenerate_env: "REGENERATE_MEMORY_PRESSURE_VECTORS",
};

#[test]
fn memory_pressure_stall_vectors_are_pinned_and_verify_exactly() {
    run(&SUITE);
}
