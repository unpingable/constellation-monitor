//! Shared canonical byte vectors for the filesystem-capacity correspondence
//! record: the load vector suite replayed under
//! [`QuestionV1::HostFilesystemCapacityPressureV1`].
//!
//! The vectors are generated mechanically through the implementation under
//! `REGENERATE_FILESYSTEM_CAPACITY_VECTORS=1`, then pinned by manifest digest.
//! Every run without that variable verifies the pinned manifest, every file's
//! SHA-256, and the exact verdict or refusal code. There is no NQ contract
//! mirror for this question: NQ's checked-in fixture set at the pinned commit
//! predates the filesystem profiles, and the real crow artifacts are campaign
//! receipts, not vectors. The load vector suite is left byte-identical; this
//! file deliberately duplicates its case table rather than sharing code with
//! it.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use pulse_nq_load_correspondence::fixture::{
    SYNTHETIC_OBSERVER_INCARNATION, SYNTHETIC_SUBJECT_INCARNATION, SyntheticOutcome,
    canonical_json, reidentify_artifact, reidentify_provenance, reseal, synthetic_profile_for,
    synthetic_record,
};
use pulse_nq_load_correspondence::{
    CorrespondenceProfileV1, CorrespondenceRecordV1, INGRESS_FENCE_MS, NqDetectorStateV1,
    QuestionV1, build_frame, evidence_ref, verify_audit_record,
};
use pulse_types::{
    AuthenticationFieldV1, BoundedSignalValueV1, CoverageDescriptorV1, IncarnationId,
    ObservationProfileIdV1, ObserverId, PulseFrameV1, SignalAssessmentV1, SubjectId, digest_parts,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const QUESTION: QuestionV1 = QuestionV1::HostFilesystemCapacityPressureV1;
const FRAME_VALIDITY_MS: u64 = QUESTION.frame_validity_ms();
const MANIFEST_SCHEMA: &str = "constellation.nq_host_filesystem_capacity_correspondence_vectors.v1";
/// Pinned digest of `manifest.json`. Regeneration prints the new value.
const MANIFEST_SHA256: &str =
    "sha256:e506c4424d730af36fd8ea0bd063c0df28a98ed49fd1676762e7f2a511da9176";

fn vector_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../artifacts/nq-host-filesystem-capacity-correspondence-v1")
        .canonicalize()
        .expect("vector root exists")
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Expectation {
    Verified,
    Refused,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct VectorEntry {
    id: String,
    class: String,
    path: String,
    sha256: String,
    expected: Expectation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nq_detector_state: Option<NqDetectorStateV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProfileEntry {
    path: String,
    sha256: String,
    profile_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    digest_basis: String,
    profile: ProfileEntry,
    vectors: Vec<VectorEntry>,
}

struct Case {
    id: &'static str,
    class: &'static str,
    bytes: Vec<u8>,
    expected: Expectation,
    expected_code: Option<&'static str>,
    state: Option<NqDetectorStateV1>,
}

fn valid(id: &'static str, record: CorrespondenceRecordV1, state: NqDetectorStateV1) -> Case {
    Case {
        id,
        class: "valid",
        bytes: record.canonical_bytes().expect("canonical"),
        expected: Expectation::Verified,
        expected_code: None,
        state: Some(state),
    }
}

fn negative(id: &'static str, bytes: Vec<u8>, code: &'static str) -> Case {
    Case {
        id,
        class: "negative",
        bytes,
        expected: Expectation::Refused,
        expected_code: Some(code),
        state: None,
    }
}

fn negative_record(id: &'static str, record: CorrespondenceRecordV1, code: &'static str) -> Case {
    negative(id, record.canonical_bytes().expect("canonical"), code)
}

fn base(profile: &CorrespondenceProfileV1, outcome: SyntheticOutcome) -> CorrespondenceRecordV1 {
    synthetic_record(profile, outcome, 1, 7, 3).expect("synthetic record")
}

fn with_frame(
    mut record: CorrespondenceRecordV1,
    frame: PulseFrameV1,
    update_evidence_ref: bool,
) -> CorrespondenceRecordV1 {
    record.pulse.frame_wire_hex = frame
        .encode_wire()
        .expect("wire")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if update_evidence_ref {
        record.pulse.evidence_ref = evidence_ref(&frame);
    }
    reseal(record).expect("reseal")
}

fn with_artifact(
    mut record: CorrespondenceRecordV1,
    mutate: impl FnOnce(&mut Value),
) -> CorrespondenceRecordV1 {
    mutate(&mut record.nq.artifact);
    reidentify_artifact(&mut record.nq.artifact).expect("reidentify");
    reseal(record).expect("reseal")
}

fn with_provenance(
    mut record: CorrespondenceRecordV1,
    mutate: impl FnOnce(&mut Value),
) -> CorrespondenceRecordV1 {
    mutate(&mut record.nq.admission_provenance);
    reidentify_provenance(&mut record.nq.admission_provenance).expect("reidentify");
    reseal(record).expect("reseal")
}

fn foreign_frame(profile: &CorrespondenceProfileV1) -> PulseFrameV1 {
    let record = base(profile, SyntheticOutcome::Present);
    let mut frame = record.frame().expect("frame");
    frame.profile = ObservationProfileIdV1 {
        name: "linux.proc.summary".to_owned(),
        version: 1,
        semantic_digest: digest_parts("pulse.agent.profile", &[b"linux.proc.summary"]),
    };
    frame.coverage = CoverageDescriptorV1 {
        expected: vec!["proc.cpu".to_owned(), "proc.memory".to_owned()],
        observed: vec!["proc.cpu".to_owned()],
    };
    frame.signals = vec![BoundedSignalValueV1 {
        name: "cpu_idle_fraction".to_owned(),
        value: 0.5,
        unit: "ratio".to_owned(),
        assessment: SignalAssessmentV1::Observed,
    }];
    frame.seal()
}

fn cases(profile: &CorrespondenceProfileV1) -> Vec<Case> {
    let present = base(profile, SyntheticOutcome::Present);
    let absent = base(profile, SyntheticOutcome::ExplicitlyAbsent);
    let mut cases = vec![
        valid("present", present.clone(), NqDetectorStateV1::Present),
        valid(
            "explicitly_absent",
            absent.clone(),
            NqDetectorStateV1::ExplicitlyAbsent,
        ),
        valid(
            "cannot_evaluate",
            base(profile, SyntheticOutcome::CannotEvaluate),
            NqDetectorStateV1::CannotEvaluate,
        ),
        valid(
            "not_evaluated_input_refusal",
            base(profile, SyntheticOutcome::InputRefusal),
            NqDetectorStateV1::NotEvaluated,
        ),
        valid(
            "not_evaluated_provider_no_response",
            base(profile, SyntheticOutcome::ProviderNoResponse),
            NqDetectorStateV1::NotEvaluated,
        ),
        valid(
            "boundary_holding_delay_below_validity_and_fence_at_bound",
            synthetic_record(
                profile,
                SyntheticOutcome::ExplicitlyAbsent,
                3,
                FRAME_VALIDITY_MS - 1,
                INGRESS_FENCE_MS,
            )
            .expect("boundary record"),
            NqDetectorStateV1::ExplicitlyAbsent,
        ),
    ];

    // Format.
    let present_bytes = present.canonical_bytes().expect("canonical");
    let mut extended: Value = serde_json::from_slice(&present_bytes).expect("json");
    extended["unexpected"] = Value::Bool(true);
    cases.push(negative(
        "format_unknown_field",
        canonical_json(&extended).expect("canonical"),
        "record_decode",
    ));
    let pretty: Value = serde_json::from_slice(&present_bytes).expect("json");
    cases.push(negative(
        "format_noncanonical_bytes",
        serde_json::to_vec_pretty(&pretty).expect("pretty"),
        "record_noncanonical",
    ));
    let mut flipped = present.clone();
    let mut id = flipped.correspondence_id.clone();
    let last = id.pop().expect("digest char");
    id.push(if last == '0' { '1' } else { '0' });
    flipped.correspondence_id = id;
    cases.push(negative_record(
        "format_flipped_identity_byte",
        flipped,
        "record_identity_mismatch",
    ));
    let text = String::from_utf8(present_bytes.clone()).expect("utf8");
    let duplicated = text.replacen(
        "\"acquisition_id\":",
        "\"acquisition_id\":\"dup\",\"acquisition_id\":",
        1,
    );
    cases.push(negative(
        "format_duplicate_key",
        duplicated.into_bytes(),
        "record_decode",
    ));
    cases.push(negative(
        "format_oversized_record",
        vec![b' '; pulse_nq_load_correspondence::MAX_RECORD_BYTES + 1],
        "bound_exceeded",
    ));
    let mut malformed_wire = present.clone();
    malformed_wire.pulse.frame_wire_hex = "0".to_owned();
    cases.push(negative_record(
        "format_malformed_frame_wire_hex",
        reseal(malformed_wire).expect("reseal"),
        "invalid_hex",
    ));
    let mut wrong_schema = present.clone();
    wrong_schema.schema = "constellation.nq_host_filesystem_capacity_correspondence.v2".to_owned();
    wrong_schema.correspondence_id = wrong_schema.compute_id().expect("id");
    cases.push(negative_record(
        "format_unsupported_schema_version",
        wrong_schema,
        "unsupported_schema",
    ));
    let mut other_question = present.clone();
    other_question.schema = QuestionV1::HostLoadPressureV1
        .spec()
        .record_schema
        .to_owned();
    other_question.correspondence_id = other_question.compute_id().expect("id");
    cases.push(negative_record(
        "format_other_question_record_schema",
        other_question,
        "record_question_mismatch",
    ));
    let mut altered_nonclaims = present.clone();
    altered_nonclaims.nonclaims.pop();
    altered_nonclaims.correspondence_id = altered_nonclaims.compute_id().expect("id");
    cases.push(negative_record(
        "format_altered_nonclaims",
        altered_nonclaims,
        "authority_boundary",
    ));

    // Cross-source artifact slots.
    let mut slot = present.clone();
    slot.nq.artifact = json!({
        "schema": "pulse.nq_host_load_pressure_support_evidence.v1",
        "evidence_id": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "state": "explicitly_absent",
        "load_1m_token": "0.42",
        "logical_cpu_count": 8
    });
    cases.push(negative_record(
        "cross_source_bridge_evidence_in_artifact_slot",
        reseal(slot).expect("reseal"),
        "artifact_shape",
    ));
    let mut slot = present.clone();
    slot.nq.artifact = json!({
        "schema": "nightshift.qualified_support.v1",
        "support_id": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "standing": "current"
    });
    cases.push(negative_record(
        "cross_source_nightshift_qualified_support_in_artifact_slot",
        reseal(slot).expect("reseal"),
        "artifact_shape",
    ));
    let mut slot = present.clone();
    slot.nq.artifact = json!({
        "schema": "nq.status_snapshot.v3",
        "components": [{"kind": "evaluation", "state": "healthy", "code": "condition_present"}]
    });
    cases.push(negative_record(
        "cross_source_status_snapshot_v3_in_artifact_slot",
        reseal(slot).expect("reseal"),
        "artifact_shape",
    ));
    let mut slot = present.clone();
    slot.nq.artifact = json!({
        "schema": "nq.finding_snapshot.v3",
        "finding_id": "finding:1",
        "condition": {"name": "filesystem_capacity_pressure", "state": "present"}
    });
    cases.push(negative_record(
        "cross_source_finding_snapshot_v3_in_artifact_slot",
        reseal(slot).expect("reseal"),
        "artifact_shape",
    ));
    cases.push(negative_record(
        "cross_source_diagnostic_execution_v1_schema",
        with_artifact(present.clone(), |artifact| {
            artifact["schema"] = Value::String("nq.diagnostic_execution.v1".to_owned());
        }),
        "artifact_schema",
    ));
    cases.push(negative_record(
        "cross_source_initial_execute_fresh_selection_rule",
        with_artifact(present.clone(), |artifact| {
            artifact["inputs"]["selection_rule"]["id"] =
                Value::String("nq.fresh_single_admitted_report".to_owned());
        }),
        "artifact_selection_rule",
    ));
    cases.push(negative_record(
        "cross_source_imported_artifact_selection_rule",
        with_artifact(present.clone(), |artifact| {
            artifact["inputs"]["selection_rule"]["id"] =
                Value::String("nq.imported_single_admitted_report".to_owned());
        }),
        "artifact_selection_rule",
    ));
    cases.push(negative_record(
        "cross_source_pulse_agent_frame_in_frame_slot",
        with_frame(present.clone(), foreign_frame(profile), true),
        "frame_binding_mismatch",
    ));
    let mut signalled = present.frame().expect("frame");
    signalled.signals = vec![BoundedSignalValueV1 {
        name: "load_ratio".to_owned(),
        value: 3.5,
        unit: "ratio".to_owned(),
        assessment: SignalAssessmentV1::OutsideDeclaredBound,
    }];
    cases.push(negative_record(
        "cross_source_frame_with_assessed_signal",
        with_frame(present.clone(), signalled.seal(), true),
        "frame_carries_signals",
    ));
    cases.push(negative_record(
        "cross_source_artifact_for_other_subject",
        with_artifact(present.clone(), |artifact| {
            artifact["subject"]["id"] = Value::String("host-filesystem:other".to_owned());
        }),
        "artifact_pin_mismatch",
    ));
    cases.push(negative_record(
        "cross_source_artifact_for_other_vantage",
        with_artifact(present.clone(), |artifact| {
            artifact["vantage"]["id"] = Value::String("nq.vantage.local.other".to_owned());
        }),
        "artifact_pin_mismatch",
    ));
    cases.push(negative_record(
        "cross_source_cannot_evaluate_for_other_instance",
        with_artifact(
            base(profile, SyntheticOutcome::CannotEvaluate),
            |artifact| {
                artifact["outcome"]["refusals"][0]["origin"]["payload"]["refusal"]["instance_id"] =
                    Value::String("other-instance".to_owned());
            },
        ),
        "artifact_pin_mismatch",
    ));
    cases.push(negative_record(
        "cross_source_detector_refusal_names_other_profile",
        with_artifact(
            base(profile, SyntheticOutcome::CannotEvaluate),
            |artifact| {
                artifact["outcome"]["refusals"][0]["origin"]["payload"]["refusal"]["profile"] =
                    json!({"id": QuestionV1::HostLoadPressureV1.spec().nq_profile_id, "version": 1});
            },
        ),
        "artifact_ladder",
    ));
    cases.push(negative_record(
        "recomputation_bridge_state_offered_as_nq_state",
        with_artifact(present.clone(), |artifact| {
            artifact["outcome"] = json!({"state": "present", "standing": "current"});
        }),
        "artifact_shape",
    ));

    // Policy.
    cases.push(negative_record(
        "policy_load_question_identity_in_filesystem_artifact",
        with_artifact(present.clone(), |artifact| {
            artifact["question"] = json!({
                "id": QuestionV1::HostLoadPressureV1.spec().question_id,
                "version": QuestionV1::HostLoadPressureV1.spec().question_version,
                "digest": QuestionV1::HostLoadPressureV1.spec().question_digest
            });
        }),
        "artifact_pin_mismatch",
    ));
    cases.push(negative_record(
        "policy_load_claim_in_filesystem_artifact",
        with_artifact(present.clone(), |artifact| {
            let claim = QuestionV1::HostLoadPressureV1.spec().claim_id;
            artifact["primary_claim_id"] = Value::String(claim.to_owned());
            artifact["claims"][0]["claim_id"] = Value::String(claim.to_owned());
        }),
        "artifact_claim_mismatch",
    ));
    cases.push(negative_record(
        "policy_changed_threshold_policy_digest",
        with_artifact(present.clone(), |artifact| {
            artifact["threshold_policy"]["digest"] = Value::String(sha256(b"other-threshold"));
        }),
        "artifact_pin_mismatch",
    ));
    cases.push(negative_record(
        "policy_changed_question_digest",
        with_artifact(present.clone(), |artifact| {
            artifact["question"]["digest"] = Value::String(sha256(b"other-question"));
        }),
        "artifact_pin_mismatch",
    ));
    cases.push(negative_record(
        "policy_changed_profile_semantic_id",
        with_artifact(present.clone(), |artifact| {
            artifact["profile_semantic_id"] = Value::String(sha256(b"other-semantic"));
        }),
        "artifact_pin_mismatch",
    ));
    let mut short_validity = present.frame().expect("frame");
    short_validity.validity_ms = FRAME_VALIDITY_MS - 1;
    cases.push(negative_record(
        "policy_frame_validity_not_v",
        with_frame(present.clone(), short_validity.seal(), true),
        "frame_validity_mismatch",
    ));

    // Generation.
    cases.push(negative_record(
        "generation_changed_evaluator",
        with_artifact(present.clone(), |artifact| {
            artifact["evaluator"]["version"] = Value::String("2".to_owned());
        }),
        "artifact_pin_mismatch",
    ));
    cases.push(negative_record(
        "generation_changed_build",
        with_artifact(present.clone(), |artifact| {
            artifact["producer"]["build"]["digest"] = Value::String(sha256(b"other-build"));
        }),
        "artifact_pin_mismatch",
    ));
    cases.push(negative_record(
        "generation_changed_cohort",
        with_artifact(present.clone(), |artifact| {
            artifact["producer"]["cohort"]["digest"] = Value::String(sha256(b"other-cohort"));
        }),
        "artifact_pin_mismatch",
    ));
    cases.push(negative_record(
        "generation_changed_node",
        with_artifact(present.clone(), |artifact| {
            artifact["producer"]["node_id"] = Value::String("nq-store-genesis:other".to_owned());
        }),
        "artifact_pin_mismatch",
    ));
    let mut other_profile = present.clone();
    other_profile.profile_digest = sha256(b"other-correspondence-profile");
    cases.push(negative_record(
        "generation_changed_correspondence_profile",
        reseal(other_profile).expect("reseal"),
        "profile_mismatch",
    ));
    let mut other_pulse_profile = present.frame().expect("frame");
    other_pulse_profile.profile.semantic_digest = digest_parts("other", &[b"pulse-profile"]);
    cases.push(negative_record(
        "generation_changed_pulse_observation_profile",
        with_frame(present.clone(), other_pulse_profile.seal(), true),
        "frame_binding_mismatch",
    ));

    // Evidence.
    let mut empty_coverage = present.frame().expect("frame");
    empty_coverage.coverage.observed = Vec::new();
    cases.push(negative_record(
        "evidence_empty_observed_coverage",
        with_frame(present.clone(), empty_coverage.seal(), true),
        "frame_coverage_mismatch",
    ));
    cases.push(negative_record(
        "evidence_claim_depends_on_other_input",
        with_artifact(present.clone(), |artifact| {
            artifact["claims"][0]["dependency_input_ids"] = json!(["intake:other"]);
        }),
        "artifact_ladder",
    ));
    cases.push(negative_record(
        "evidence_two_selected_inputs",
        with_artifact(present.clone(), |artifact| {
            let mut second = artifact["inputs"]["selected"][0].clone();
            second["input_id"] = Value::String("intake:second".to_owned());
            artifact["inputs"]["selected"]
                .as_array_mut()
                .expect("array")
                .push(second);
        }),
        "artifact_single_acquisition",
    ));
    cases.push(negative_record(
        "evidence_provenance_raw_digest_mismatch",
        with_provenance(present.clone(), |provenance| {
            provenance["provider"]["raw_sha256"] = Value::String(sha256(b"other-raw"));
        }),
        "provenance_mismatch",
    ));
    cases.push(negative_record(
        "evidence_provenance_other_intake",
        with_provenance(present.clone(), |provenance| {
            provenance["provider"]["provider_intake_id"] = Value::String("intake:other".to_owned());
        }),
        "provenance_mismatch",
    ));
    cases.push(negative_record(
        "evidence_provenance_other_artifact_bytes_digest",
        with_provenance(present.clone(), |provenance| {
            provenance["artifact"]["canonical_bytes_sha256"] =
                Value::String(sha256(b"other-bytes"));
        }),
        "provenance_mismatch",
    ));
    cases.push(negative_record(
        "evidence_provenance_other_run",
        with_provenance(present.clone(), |provenance| {
            provenance["origin"]["run_id"] = Value::String("run:other".to_owned());
        }),
        "provenance_mismatch",
    ));
    cases.push(negative_record(
        "evidence_provenance_without_judgment_for_evaluated_outcome",
        with_provenance(present.clone(), |provenance| {
            provenance["disposition"] = Value::String("governed_refusal".to_owned());
            provenance
                .as_object_mut()
                .expect("object")
                .remove("judgment");
            provenance["origin"]
                .as_object_mut()
                .expect("object")
                .remove("evaluation_id");
        }),
        "provenance_mismatch",
    ));
    cases.push(negative_record(
        "evidence_provenance_unsupported_schema_version",
        with_provenance(present.clone(), |provenance| {
            provenance["schema"] =
                Value::String("nq.diagnostic_admission_provenance.v2".to_owned());
        }),
        "provenance_schema",
    ));
    let mut moved_t0 = present.frame().expect("frame");
    moved_t0.observer_monotonic_ns += 1;
    cases.push(negative_record(
        "evidence_frame_time_tampered_evidence_ref_kept",
        with_frame(present.clone(), moved_t0.clone().seal(), false),
        "evidence_ref_mismatch",
    ));
    cases.push(negative_record(
        "evidence_frame_time_tampered_evidence_ref_updated",
        with_frame(present.clone(), moved_t0.seal(), true),
        "acquisition_id_mismatch",
    ));

    // Coherent pair.
    let next_frame = build_frame(
        profile,
        IncarnationId::new(SYNTHETIC_SUBJECT_INCARNATION),
        IncarnationId::new(SYNTHETIC_OBSERVER_INCARNATION),
        2,
        2_000_000_000,
    )
    .expect("frame");
    cases.push(negative_record(
        "coherent_pair_frame_k_plus_one_with_artifact_k",
        with_frame(present.clone(), next_frame, true),
        "acquisition_id_mismatch",
    ));
    let mut flipped_state = absent.clone();
    flipped_state.nq_detector_state = NqDetectorStateV1::Present;
    cases.push(negative_record(
        "coherent_pair_stored_state_differs_from_artifact",
        reseal(flipped_state).expect("reseal"),
        "state_mismatch",
    ));
    let mut other_incarnation = present.frame().expect("frame");
    other_incarnation.subject_incarnation = IncarnationId::new("linux-boot:other");
    cases.push(negative_record(
        "coherent_pair_frame_incarnation_differs",
        with_frame(present.clone(), other_incarnation.seal(), true),
        "acquisition_id_mismatch",
    ));
    let mut other_subject = present.frame().expect("frame");
    other_subject.subject = SubjectId::new("host-filesystem:other");
    cases.push(negative_record(
        "coherent_pair_frame_subject_differs",
        with_frame(present.clone(), other_subject.seal(), true),
        "frame_binding_mismatch",
    ));
    let mut other_observer = present.frame().expect("frame");
    other_observer.observer = ObserverId::new("observer:other");
    other_observer.authentication = AuthenticationFieldV1::Placeholder {
        disclosure: "other".to_owned(),
    };
    cases.push(negative_record(
        "coherent_pair_frame_observer_differs",
        with_frame(present.clone(), other_observer.seal(), true),
        "frame_binding_mismatch",
    ));

    // Lifetime.
    let mut held = present.clone();
    held.delivery.holding_delay_ms = FRAME_VALIDITY_MS;
    cases.push(negative_record(
        "lifetime_holding_delay_equals_validity",
        reseal(held).expect("reseal"),
        "holding_delay_exceeds_validity",
    ));
    let mut slow = present.clone();
    slow.delivery.ingress_fence_ms = INGRESS_FENCE_MS + 1;
    cases.push(negative_record(
        "lifetime_ingress_fence_exceeded",
        reseal(slow).expect("reseal"),
        "ingress_fence_exceeded",
    ));
    let mut other_transport = present.clone();
    other_transport.delivery.transport_path = "udp:custody".to_owned();
    cases.push(negative_record(
        "lifetime_other_transport_path",
        reseal(other_transport).expect("reseal"),
        "transport_path_mismatch",
    ));
    cases
}

fn write_vectors(root: &Path, profile: &CorrespondenceProfileV1, cases: &[Case]) -> Manifest {
    for class in ["valid", "negative"] {
        let directory = root.join(class);
        if directory.exists() {
            fs::remove_dir_all(&directory).expect("remove old vectors");
        }
        fs::create_dir_all(&directory).expect("create vector directory");
    }
    let profile_bytes = canonical_json(&serde_json::to_value(profile).expect("profile value"))
        .expect("profile canonical");
    fs::write(root.join("profile.json"), &profile_bytes).expect("write profile");
    let mut entries = Vec::new();
    for case in cases {
        let path = format!("{}/{}.json", case.class, case.id);
        fs::write(root.join(&path), &case.bytes).expect("write vector");
        entries.push(VectorEntry {
            id: case.id.to_owned(),
            class: case.class.to_owned(),
            path,
            sha256: sha256(&case.bytes),
            expected: case.expected.clone(),
            expected_code: case.expected_code.map(str::to_owned),
            nq_detector_state: case.state,
        });
    }
    let manifest = Manifest {
        schema: MANIFEST_SCHEMA.to_owned(),
        digest_basis: "SHA-256 of exact file bytes; records are RFC 8785 canonical JSON whose correspondence_id is SHA-256 of the canonical record with that field omitted".to_owned(),
        profile: ProfileEntry {
            path: "profile.json".to_owned(),
            sha256: sha256(&profile_bytes),
            profile_digest: profile.digest().to_owned(),
        },
        vectors: entries,
    };
    let mut bytes = serde_json::to_vec_pretty(&manifest).expect("manifest");
    bytes.push(b'\n');
    fs::write(root.join("manifest.json"), &bytes).expect("write manifest");
    println!("regenerated manifest sha256 = {}", sha256(&bytes));
    manifest
}

#[test]
fn filesystem_capacity_vectors_are_pinned_and_verify_exactly() {
    let root = vector_root();
    let profile = synthetic_profile_for(QUESTION).expect("profile");
    assert_eq!(profile.question().expect("question"), QUESTION);
    let cases = cases(&profile);
    let regenerate = std::env::var_os("REGENERATE_FILESYSTEM_CAPACITY_VECTORS").is_some();
    if regenerate {
        write_vectors(&root, &profile, &cases);
    }
    let manifest_bytes = fs::read(root.join("manifest.json")).expect("manifest");
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes).expect("manifest decodes");
    if !regenerate {
        assert_eq!(
            sha256(&manifest_bytes),
            MANIFEST_SHA256,
            "manifest changed; regenerate deliberately and update the pinned digest"
        );
    }
    assert_eq!(manifest.schema, MANIFEST_SCHEMA);

    let load_profile = synthetic_profile_for(QuestionV1::HostLoadPressureV1).expect("load");
    // The checked-in profile is the exact synthetic profile.
    let profile_bytes = fs::read(root.join(&manifest.profile.path)).expect("profile");
    assert_eq!(sha256(&profile_bytes), manifest.profile.sha256);
    let checked_in = CorrespondenceProfileV1::decode(&profile_bytes).expect("profile decodes");
    assert_eq!(checked_in, profile);
    assert_eq!(manifest.profile.profile_digest, profile.digest());

    // Every generated case appears in the manifest with identical bytes, and
    // the manifest lists nothing else.
    assert_eq!(manifest.vectors.len(), cases.len());
    let mut seen = BTreeSet::new();
    for case in &cases {
        let entry = manifest
            .vectors
            .iter()
            .find(|entry| entry.id == case.id)
            .unwrap_or_else(|| panic!("manifest lacks {}", case.id));
        assert!(
            seen.insert(entry.id.clone()),
            "duplicate vector {}",
            entry.id
        );
        let bytes = fs::read(root.join(&entry.path)).expect("vector file");
        assert_eq!(sha256(&bytes), entry.sha256, "{}: file digest", entry.id);
        assert_eq!(bytes, case.bytes, "{}: generated bytes drifted", entry.id);
        assert_eq!(entry.expected, case.expected);
        assert_eq!(entry.expected_code.as_deref(), case.expected_code);
        assert_eq!(entry.nq_detector_state, case.state);
        // The load profile never verifies a filesystem vector; the ones that
        // are well formed it refuses on the question.
        let under_load = verify_audit_record(&bytes, &load_profile)
            .expect_err("the load profile must refuse every filesystem vector");
        if entry.expected == Expectation::Verified {
            assert_eq!(under_load.code, "record_question_mismatch", "{}", entry.id);
        }
        match verify_audit_record(&bytes, &profile) {
            Ok(verdict) => {
                assert_eq!(
                    entry.expected,
                    Expectation::Verified,
                    "{}: unexpectedly verified",
                    entry.id
                );
                assert_eq!(Some(verdict.nq_detector_state), entry.nq_detector_state);
            }
            Err(error) => {
                assert_eq!(
                    entry.expected,
                    Expectation::Refused,
                    "{}: refused: {error}",
                    entry.id
                );
                assert_eq!(
                    Some(error.code),
                    entry.expected_code.as_deref(),
                    "{}",
                    entry.id
                );
            }
        }
    }
    for class in ["valid", "negative"] {
        for entry in fs::read_dir(root.join(class)).expect("read dir") {
            let name = entry.expect("entry").file_name();
            let stem = name.to_string_lossy().trim_end_matches(".json").to_owned();
            assert!(seen.contains(&stem), "unlisted vector file {class}/{stem}");
        }
    }
    let valid_count = manifest
        .vectors
        .iter()
        .filter(|entry| entry.class == "valid")
        .count();
    assert!(valid_count >= 5 && manifest.vectors.len() - valid_count >= 30);
}
