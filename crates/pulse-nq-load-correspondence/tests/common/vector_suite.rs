//! A question-parameterized vector suite: the load vector case table
//! replayed under one non-load row, with cross-question cases against every
//! other row and the boundary cases of the row's own frame validity.
//!
//! The filesystem suite (`filesystem_capacity_vectors.rs`) predates this
//! module and keeps its own copy so its pinned manifest stays byte-identical;
//! rows added after it use this module.
#![allow(dead_code)]

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

/// One suite: the row under test, the rows it must be refused against, its
/// vector directory (relative to the repository root), manifest schema,
/// pinned manifest digest, and the environment variable that regenerates it.
pub struct SuiteV1 {
    pub question: QuestionV1,
    pub others: &'static [(QuestionV1, &'static str)],
    pub directory: &'static str,
    pub manifest_schema: &'static str,
    pub manifest_sha256: &'static str,
    pub regenerate_env: &'static str,
}

fn vector_root(directory: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../")
        .join(directory)
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
    id: String,
    class: &'static str,
    bytes: Vec<u8>,
    expected: Expectation,
    expected_code: Option<&'static str>,
    state: Option<NqDetectorStateV1>,
}

fn valid(id: impl Into<String>, record: CorrespondenceRecordV1, state: NqDetectorStateV1) -> Case {
    Case {
        id: id.into(),
        class: "valid",
        bytes: record.canonical_bytes().expect("canonical"),
        expected: Expectation::Verified,
        expected_code: None,
        state: Some(state),
    }
}

fn negative(id: impl Into<String>, bytes: Vec<u8>, code: &'static str) -> Case {
    Case {
        id: id.into(),
        class: "negative",
        bytes,
        expected: Expectation::Refused,
        expected_code: Some(code),
        state: None,
    }
}

fn negative_record(
    id: impl Into<String>,
    record: CorrespondenceRecordV1,
    code: &'static str,
) -> Case {
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

fn cases(suite: &SuiteV1, profile: &CorrespondenceProfileV1) -> Vec<Case> {
    let question = suite.question;
    let frame_validity_ms = question.frame_validity_ms();
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
                frame_validity_ms - 1,
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
    wrong_schema.schema = format!(
        "{}.v2",
        question.spec().record_schema.trim_end_matches(".v1")
    );
    wrong_schema.correspondence_id = wrong_schema.compute_id().expect("id");
    cases.push(negative_record(
        "format_unsupported_schema_version",
        wrong_schema,
        "unsupported_schema",
    ));
    for (other, name) in suite.others {
        let mut other_question = present.clone();
        other_question.schema = other.spec().record_schema.to_owned();
        other_question.correspondence_id = other_question.compute_id().expect("id");
        cases.push(negative_record(
            format!("format_{name}_record_schema"),
            other_question,
            "record_question_mismatch",
        ));
    }
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
        "condition": {"name": question.spec().condition, "state": "present"}
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
            artifact["subject"]["id"] =
                Value::String(format!("{}other", question.spec().subject_prefix));
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
        "recomputation_bridge_state_offered_as_nq_state",
        with_artifact(present.clone(), |artifact| {
            artifact["outcome"] = json!({"state": "present", "standing": "current"});
        }),
        "artifact_shape",
    ));

    // Policy.
    for (other, name) in suite.others {
        let spec = other.spec();
        cases.push(negative_record(
            format!("policy_{name}_question_identity_in_artifact"),
            with_artifact(present.clone(), |artifact| {
                artifact["question"] = json!({
                    "id": spec.question_id,
                    "version": spec.question_version,
                    "digest": spec.question_digest
                });
            }),
            "artifact_pin_mismatch",
        ));
        cases.push(negative_record(
            format!("policy_{name}_claim_in_artifact"),
            with_artifact(present.clone(), |artifact| {
                artifact["primary_claim_id"] = Value::String(spec.claim_id.to_owned());
                artifact["claims"][0]["claim_id"] = Value::String(spec.claim_id.to_owned());
            }),
            "artifact_claim_mismatch",
        ));
        cases.push(negative_record(
            format!("cross_source_detector_refusal_names_{name}_profile"),
            with_artifact(
                base(profile, SyntheticOutcome::CannotEvaluate),
                |artifact| {
                    artifact["outcome"]["refusals"][0]["origin"]["payload"]["refusal"]["profile"] =
                        json!({"id": spec.nq_profile_id, "version": spec.refusal_profile_version});
                },
            ),
            "artifact_ladder",
        ));
        // A frame sealed under the other row's validity is not this row's
        // frame, and a holding delay lawful only under the other row's
        // longer validity is refused under this one.
        if other.frame_validity_ms() != frame_validity_ms {
            let mut other_validity = present.frame().expect("frame");
            other_validity.validity_ms = other.frame_validity_ms();
            cases.push(negative_record(
                format!("policy_frame_validity_of_{name}_row"),
                with_frame(present.clone(), other_validity.seal(), true),
                "frame_validity_mismatch",
            ));
            if other.frame_validity_ms() > frame_validity_ms {
                let mut held_under_other = present.clone();
                held_under_other.delivery.holding_delay_ms = other.frame_validity_ms() - 1;
                cases.push(negative_record(
                    format!("lifetime_holding_delay_lawful_under_{name}_row_only"),
                    reseal(held_under_other).expect("reseal"),
                    "holding_delay_exceeds_validity",
                ));
            }
        }
    }
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
    short_validity.validity_ms = frame_validity_ms - 1;
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
    other_subject.subject = SubjectId::new(format!("{}other", question.spec().subject_prefix));
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
    held.delivery.holding_delay_ms = frame_validity_ms;
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

fn write_vectors(
    suite: &SuiteV1,
    root: &Path,
    profile: &CorrespondenceProfileV1,
    cases: &[Case],
) -> Manifest {
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
            id: case.id.clone(),
            class: case.class.to_owned(),
            path,
            sha256: sha256(&case.bytes),
            expected: case.expected.clone(),
            expected_code: case.expected_code.map(str::to_owned),
            nq_detector_state: case.state,
        });
    }
    let manifest = Manifest {
        schema: suite.manifest_schema.to_owned(),
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

/// Generate (under the suite's regenerate variable) or verify the suite.
pub fn run(suite: &SuiteV1) {
    let root = vector_root(suite.directory);
    let profile = synthetic_profile_for(suite.question).expect("profile");
    assert_eq!(profile.question().expect("question"), suite.question);
    let cases = cases(suite, &profile);
    let regenerate = std::env::var_os(suite.regenerate_env).is_some();
    if regenerate {
        write_vectors(suite, &root, &profile, &cases);
    }
    let manifest_bytes = fs::read(root.join("manifest.json")).expect("manifest");
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes).expect("manifest decodes");
    if !regenerate {
        assert_eq!(
            sha256(&manifest_bytes),
            suite.manifest_sha256,
            "manifest changed; regenerate deliberately and update the pinned digest"
        );
    }
    assert_eq!(manifest.schema, suite.manifest_schema);
    let other_profiles = suite
        .others
        .iter()
        .map(|(other, _)| synthetic_profile_for(*other).expect("other profile"))
        .collect::<Vec<_>>();
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
        // No other row's profile verifies a vector of this row; the well
        // formed ones it refuses on the question.
        for other_profile in &other_profiles {
            let under_other = verify_audit_record(&bytes, other_profile)
                .expect_err("another row's profile must refuse every vector");
            if entry.expected == Expectation::Verified {
                assert_eq!(under_other.code, "record_question_mismatch", "{}", entry.id);
            }
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
