//! Golden pins for the non-load rows of the question table: every row
//! literal, and the reliance policy and context digests of the synthetic
//! profile, so that adding a row can never move an existing one.

use pulse_nq_load_correspondence::fixture::synthetic_profile_for;
use pulse_nq_load_correspondence::{INGRESS_FENCE_MS, QuestionV1};

fn print_or_assert(name: &str, actual: &str, pinned: &str) {
    if std::env::var_os("PIN_PRINT").is_some() {
        println!("PIN {name} = {actual}");
    } else {
        assert_eq!(actual, pinned, "{name} changed");
    }
}

fn pin_digests(question: QuestionV1, label: &str, profile: &str, policy: &str, context: &str) {
    let synthetic = synthetic_profile_for(question).expect("synthetic profile");
    print_or_assert(
        &format!("{label}.profile_digest"),
        synthetic.digest(),
        profile,
    );
    print_or_assert(
        &format!("{label}.reliance_policy_semantic_digest"),
        synthetic
            .reliance_policy()
            .expect("policy")
            .semantic_digest()
            .as_str(),
        policy,
    );
    print_or_assert(
        &format!("{label}.reliance_context_identity_digest"),
        synthetic
            .reliance_context("a")
            .expect("context")
            .identity_digest()
            .as_str(),
        context,
    );
    let policy = synthetic.reliance_policy().expect("policy");
    assert_eq!(policy.maximum_validity_ms, question.frame_validity_ms());
    assert_eq!(policy.scope, question.spec().pulse_scope);
    assert_eq!(
        policy.required_coverage,
        vec![question.spec().coverage_tag.to_owned()]
    );
    assert_eq!(
        policy
            .observer_failure_domains
            .values()
            .next()
            .map(String::as_str),
        Some(question.spec().failure_domain)
    );
}

#[test]
fn filesystem_capacity_row_is_literal() {
    let row = QuestionV1::HostFilesystemCapacityPressureV1.spec();
    assert_eq!(row.question_id, "nq.host_filesystem_capacity.pressure");
    assert_eq!(row.question_version, "1");
    assert_eq!(
        row.question_digest,
        "sha256:a95ea6b087bbb82c30e3430114d20a084e7d18b384a6bc1676c2291bd05ec81b"
    );
    assert_eq!(row.nq_profile_id, "nq.host_filesystem_capacity");
    assert_eq!(row.nq_profile_version, "1");
    assert_eq!(
        row.nq_profile_digest,
        "sha256:48d23e2e27fa47f591455c27a3d994b6409eb57a52dabf08d92607332d215636"
    );
    assert_eq!(row.refusal_profile_version, 1);
    assert_eq!(row.claim_id, "claim:filesystem_capacity_pressure");
    assert_eq!(row.condition, "filesystem_capacity_pressure");
    assert_eq!(row.subject_prefix, "host-filesystem:");
    assert_eq!(row.reliance_window_ms, 300_000);
    assert_eq!(
        QuestionV1::HostFilesystemCapacityPressureV1.frame_validity_ms(),
        300_000 - INGRESS_FENCE_MS - 1
    );
    assert_eq!(row.pulse_scope, "nq.host_filesystem_capacity.pressure/v1");
    assert_eq!(
        row.coverage_tag,
        "nq_host_filesystem_capacity_pressure_v1_terminal_artifact"
    );
    assert_eq!(
        row.acquisition_id_prefix,
        "constellation-nq-fs-capacity:v1:"
    );
    assert_eq!(
        row.transport_path,
        "in-process:nq-filesystem-capacity-correspondence/v1"
    );
    assert_eq!(
        row.failure_domain,
        "domain:nq-filesystem-capacity-correspondence"
    );
    assert_eq!(
        row.profile_schema,
        "constellation.nq_host_filesystem_capacity_correspondence_profile.v1"
    );
    assert_eq!(
        row.occurrence_schema,
        "constellation.nq_host_filesystem_capacity_correspondence_occurrence.v1"
    );
    assert_eq!(
        row.intent_schema,
        "constellation.nq_host_filesystem_capacity_correspondence_intent.v1"
    );
    assert_eq!(
        row.record_schema,
        "constellation.nq_host_filesystem_capacity_correspondence.v1"
    );
    assert_eq!(
        row.pulse_profile_name,
        "constellation.nq_host_filesystem_capacity_correspondence"
    );
    assert_eq!(
        row.pulse_profile_domain,
        "constellation.nq_host_filesystem_capacity_correspondence.pulse_profile.v1"
    );
    pin_digests(
        QuestionV1::HostFilesystemCapacityPressureV1,
        "filesystem",
        "sha256:192f529760093829a4ba62e7def8b3300d94b0d16de5a0cab5a7d11de1821c70",
        "sha256:36e9f96daea455ce191dd564b3c4a10a23788aaa25583b73cff96ee50b52c175",
        "sha256:e7f56c5ee364f2b10d9993142d3f0a7e2e80f1d5a18a3111c085810148802e8d",
    );
}

#[test]
fn memory_pressure_stall_row_is_literal_and_its_validity_differs_from_load() {
    let question = QuestionV1::HostMemoryPressureStallV1;
    let row = question.spec();
    assert_eq!(row.question_id, "nq.host_memory.pressure_stall");
    assert_eq!(row.question_version, "1");
    assert_eq!(
        row.question_digest,
        "sha256:3fe0860e73a1b3e039aaf3f94f4cc2eaf9658485d280be1ea4675e54b8bc7278"
    );
    assert_eq!(row.nq_profile_id, "nq.host_memory");
    assert_eq!(row.nq_profile_version, "1");
    assert_eq!(
        row.nq_profile_digest,
        "sha256:e4eb42dd954e7e4cd13514a5c787caa905fb395f9aaadc82e5b060638edf523e"
    );
    assert_eq!(row.refusal_profile_version, 1);
    assert_eq!(row.claim_id, "claim:memory_pressure_stall");
    assert_eq!(row.condition, "memory_pressure_stall");
    assert_eq!(row.subject_prefix, "host:");
    assert_eq!(row.reliance_window_ms, 120_000);
    assert_eq!(question.frame_validity_ms(), 118_999);
    assert_eq!(
        question.frame_validity_ms(),
        row.reliance_window_ms - INGRESS_FENCE_MS - 1
    );
    assert_ne!(
        question.frame_validity_ms(),
        QuestionV1::HostLoadPressureV1.frame_validity_ms()
    );
    assert_eq!(row.pulse_scope, "nq.host_memory.pressure_stall/v1");
    assert_eq!(
        row.coverage_tag,
        "nq_host_memory_pressure_stall_v1_terminal_artifact"
    );
    assert_eq!(
        row.acquisition_id_prefix,
        "constellation-nq-memory-stall:v1:"
    );
    assert_eq!(
        row.transport_path,
        "in-process:nq-memory-pressure-stall-correspondence/v1"
    );
    assert_eq!(
        row.failure_domain,
        "domain:nq-memory-pressure-stall-correspondence"
    );
    assert_eq!(
        row.profile_schema,
        "constellation.nq_host_memory_pressure_stall_correspondence_profile.v1"
    );
    assert_eq!(
        row.occurrence_schema,
        "constellation.nq_host_memory_pressure_stall_correspondence_occurrence.v1"
    );
    assert_eq!(
        row.intent_schema,
        "constellation.nq_host_memory_pressure_stall_correspondence_intent.v1"
    );
    assert_eq!(
        row.record_schema,
        "constellation.nq_host_memory_pressure_stall_correspondence.v1"
    );
    assert_eq!(
        row.pulse_profile_name,
        "constellation.nq_host_memory_pressure_stall_correspondence"
    );
    assert_eq!(
        row.pulse_profile_domain,
        "constellation.nq_host_memory_pressure_stall_correspondence.pulse_profile.v1"
    );
    pin_digests(
        question,
        "memory",
        "sha256:8abb2a7aaff6e3245514adb631d8b9d637f0648c1f50db5850837abfaa286839",
        "sha256:4790807db3cc0adc81b92679b2ed4f8bff5344c3aedec8bcfa92d4327bc585fa",
        "sha256:a8eba7ee4778043ceb26e939b44bda143bc6c51500f42324e589842bd7ba84d8",
    );
}

#[test]
fn systemd_unit_required_active_row_is_literal_and_names_the_second_profile_revision() {
    let question = QuestionV1::SystemdUnitRequiredActiveV1;
    let row = question.spec();
    assert_eq!(row.question_id, "nq.systemd_unit.required_active");
    assert_eq!(row.question_version, "1");
    assert_eq!(
        row.question_digest,
        "sha256:f8df6308f2af9d4cc12d107c310e86d22b9ef5f37ab72b71aa1b7d57446c159f"
    );
    assert_eq!(row.nq_profile_id, "nq.systemd_unit");
    assert_eq!(row.nq_profile_version, "2");
    assert_eq!(
        row.nq_profile_digest,
        "sha256:5691c4db8d736df5a7cf7da3557f8e07a9d9523d27ff16326963734e2b737b49"
    );
    // NQ writes a detector refusal's profile version as a number; v1 is the
    // operator-beta fixture contract and must never be accepted here.
    assert_eq!(row.refusal_profile_version, 2);
    assert_eq!(row.claim_id, "claim:systemd_unit_not_active");
    assert_eq!(row.condition, "systemd_unit_not_active");
    assert_eq!(row.subject_prefix, "systemd-unit:");
    assert_eq!(row.reliance_window_ms, 60_000);
    assert_eq!(question.frame_validity_ms(), 58_999);
    assert_eq!(
        question.frame_validity_ms(),
        row.reliance_window_ms - INGRESS_FENCE_MS - 1
    );
    for other in [
        QuestionV1::HostLoadPressureV1,
        QuestionV1::HostFilesystemCapacityPressureV1,
        QuestionV1::HostMemoryPressureStallV1,
    ] {
        assert_ne!(question.frame_validity_ms(), other.frame_validity_ms());
        assert!(!other.spec().subject_prefix.starts_with(row.subject_prefix));
        assert!(!row.subject_prefix.starts_with(other.spec().subject_prefix));
    }
    assert_eq!(row.pulse_scope, "nq.systemd_unit.required_active/v1");
    assert_eq!(
        row.coverage_tag,
        "nq_systemd_unit_required_active_v1_terminal_artifact"
    );
    assert_eq!(
        row.acquisition_id_prefix,
        "constellation-nq-systemd-unit:v1:"
    );
    assert_eq!(
        row.transport_path,
        "in-process:nq-systemd-unit-required-active-correspondence/v1"
    );
    assert_eq!(
        row.failure_domain,
        "domain:nq-systemd-unit-required-active-correspondence"
    );
    assert_eq!(
        row.profile_schema,
        "constellation.nq_systemd_unit_required_active_correspondence_profile.v1"
    );
    assert_eq!(
        row.occurrence_schema,
        "constellation.nq_systemd_unit_required_active_correspondence_occurrence.v1"
    );
    assert_eq!(
        row.intent_schema,
        "constellation.nq_systemd_unit_required_active_correspondence_intent.v1"
    );
    assert_eq!(
        row.record_schema,
        "constellation.nq_systemd_unit_required_active_correspondence.v1"
    );
    assert_eq!(
        row.pulse_profile_name,
        "constellation.nq_systemd_unit_required_active_correspondence"
    );
    assert_eq!(
        row.pulse_profile_domain,
        "constellation.nq_systemd_unit_required_active_correspondence.pulse_profile.v1"
    );
    pin_digests(
        question,
        "systemd_unit",
        "sha256:5bf7ff289f83fadaf797b0c63f5257caae2fcf223e23a850e8930d5422e8fd79",
        "sha256:46c996df2945753ca920ef10603bd977258c03ae59c4e8d593ddc35e056585c0",
        "sha256:62cd2c7581e1ffdea5facbdff3ec13d3f03c75edd6bc6a3fd52f387bdee87f20",
    );
}

#[test]
fn filesystem_inode_pressure_row_is_literal_and_shares_the_capacity_subject_and_validity() {
    let question = QuestionV1::HostFilesystemInodePressureV1;
    let capacity = QuestionV1::HostFilesystemCapacityPressureV1;
    let row = question.spec();
    assert_eq!(row.question_id, "nq.host_filesystem_inodes.pressure");
    assert_eq!(row.question_version, "1");
    assert_eq!(
        row.question_digest,
        "sha256:2986b802935b67bbc9247ba0888b08c762f437ed71464265f676ab0ffd914d89"
    );
    assert_eq!(row.nq_profile_id, "nq.host_filesystem_inodes");
    assert_eq!(row.nq_profile_version, "1");
    assert_eq!(
        row.nq_profile_digest,
        "sha256:1a4f5e289b2f63e811e552141c7d624ca46880343b3126450522dc338bcdd664"
    );
    assert_eq!(row.refusal_profile_version, 1);
    assert_eq!(row.claim_id, "claim:filesystem_inode_pressure");
    assert_eq!(row.condition, "filesystem_inode_pressure");
    // The capacity row's prefix and window, deliberately: NQ asks both
    // questions of one filesystem, and only the question separates them.
    assert_eq!(row.subject_prefix, "host-filesystem:");
    assert_eq!(row.subject_prefix, capacity.spec().subject_prefix);
    assert_eq!(row.reliance_window_ms, 300_000);
    assert_eq!(question.frame_validity_ms(), 298_999);
    assert_eq!(
        question.frame_validity_ms(),
        row.reliance_window_ms - INGRESS_FENCE_MS - 1
    );
    assert_eq!(question.frame_validity_ms(), capacity.frame_validity_ms());
    assert_ne!(row.question_digest, capacity.spec().question_digest);
    assert_ne!(row.nq_profile_id, capacity.spec().nq_profile_id);
    assert_ne!(row.claim_id, capacity.spec().claim_id);
    for other in [
        QuestionV1::HostLoadPressureV1,
        QuestionV1::HostMemoryPressureStallV1,
        QuestionV1::SystemdUnitRequiredActiveV1,
    ] {
        assert!(!other.spec().subject_prefix.starts_with(row.subject_prefix));
        assert!(!row.subject_prefix.starts_with(other.spec().subject_prefix));
    }
    assert_eq!(row.pulse_scope, "nq.host_filesystem_inodes.pressure/v1");
    assert_eq!(
        row.coverage_tag,
        "nq_host_filesystem_inodes_pressure_v1_terminal_artifact"
    );
    assert_eq!(row.acquisition_id_prefix, "constellation-nq-fs-inodes:v1:");
    assert_eq!(
        row.transport_path,
        "in-process:nq-filesystem-inodes-correspondence/v1"
    );
    assert_eq!(
        row.failure_domain,
        "domain:nq-filesystem-inodes-correspondence"
    );
    assert_eq!(
        row.profile_schema,
        "constellation.nq_host_filesystem_inodes_correspondence_profile.v1"
    );
    assert_eq!(
        row.occurrence_schema,
        "constellation.nq_host_filesystem_inodes_correspondence_occurrence.v1"
    );
    assert_eq!(
        row.intent_schema,
        "constellation.nq_host_filesystem_inodes_correspondence_intent.v1"
    );
    assert_eq!(
        row.record_schema,
        "constellation.nq_host_filesystem_inodes_correspondence.v1"
    );
    assert_eq!(
        row.pulse_profile_name,
        "constellation.nq_host_filesystem_inodes_correspondence"
    );
    assert_eq!(
        row.pulse_profile_domain,
        "constellation.nq_host_filesystem_inodes_correspondence.pulse_profile.v1"
    );
    pin_digests(
        question,
        "filesystem_inodes",
        "sha256:897d33bbb6bfd2aadc627a759a7218a2f505423271fd56b478bcb17e61601261",
        "sha256:a90af9895b06a43da53a0b31168a76cc2ce8e9292886babbb9106b11f725af7a",
        "sha256:8ddc03e19e0a2d7ccc7bd238a4cf68e42f179fe20ff392b1308ac1770f71bbdb",
    );
}
