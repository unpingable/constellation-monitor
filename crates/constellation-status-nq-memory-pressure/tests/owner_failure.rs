//! The leaf receives the owner's typed reason for a `cannot_evaluate` and
//! may explain the codes it knows; the projected state, the fact, the
//! consequence identity and the rendered text do not change.

mod common;

use constellation_status_nq_memory_pressure::{
    REQUIRED_QUESTION, consequence_identity, fact_for, operator_explanation,
};
use constellation_status_projection::{AvailabilityV1, ImpactV1};
use pulse_nq_load_correspondence::fixture::SyntheticOutcome;
use pulse_nq_load_correspondence::{NqDetectorStateV1, QuestionV1};

use common::{CONDITION_KEY, condition_policy, harness, harness_for};

#[test]
fn a_typed_cannot_evaluate_reaches_the_leaf_without_changing_the_projection() {
    let harness = harness("owner-failure", SyntheticOutcome::CannotEvaluateTyped);
    let mut coproducer = harness.coproducer();
    let typed = harness.verified(&mut coproducer);
    assert_eq!(typed.nq_detector_state(), NqDetectorStateV1::CannotEvaluate);
    let explanation = operator_explanation(&typed).expect("a known owner code is explained");
    assert_eq!(explanation.code, "machine_identity_mismatch");
    assert!(
        explanation
            .text
            .starts_with("Machine identity could not be verified")
    );
    assert_eq!(explanation.retriable, Some(false));
    for forbidden in [
        "/",
        "0123456789abcdef",
        "PSI",
        "avg60",
        "Operational",
        "healthy",
    ] {
        assert!(!explanation.text.contains(forbidden), "{forbidden}");
    }
    // Retriability travels only as the owner's flag; no explanation may
    // imply it in prose.
    for transient in ["this time", "temporar", "retry", "transient", "again"] {
        assert!(
            !explanation.text.to_lowercase().contains(transient),
            "{transient}"
        );
    }
    // The fact is the plain cannot_evaluate row: unknown stays unknown.
    let policy = condition_policy(harness.selector(), false);
    let fact = fact_for(&typed, &policy, CONDITION_KEY).expect("fact");
    assert_eq!(fact.availability, AvailabilityV1::Indeterminate);
    assert_eq!(fact.impact, ImpactV1::Indeterminate);
    assert_eq!(fact.reason_code, "nq_cannot_evaluate");

    // An untyped cannot_evaluate and every determinate state explain nothing.
    harness.nq.set_outcome(SyntheticOutcome::CannotEvaluate);
    let plain = harness.verified(&mut coproducer);
    assert!(plain.owner_failure().is_none());
    assert!(operator_explanation(&plain).is_none());
    let plain_fact = fact_for(&plain, &policy, CONDITION_KEY).expect("fact");
    assert_eq!(plain_fact.reason_code, fact.reason_code);
    for outcome in [
        SyntheticOutcome::Present,
        SyntheticOutcome::ExplicitlyAbsent,
    ] {
        harness.nq.set_outcome(outcome);
        let determinate = harness.verified(&mut coproducer);
        assert!(operator_explanation(&determinate).is_none());
    }
    harness.finish();
}

#[test]
fn another_owners_code_and_another_question_are_never_explained_here() {
    // The other question's typed refusal carries a code this adapter does not
    // own; the question check refuses it before any code is read.
    let other = if REQUIRED_QUESTION == QuestionV1::HostMemoryPressureStallV1 {
        QuestionV1::HostFilesystemCapacityPressureV1
    } else {
        QuestionV1::HostMemoryPressureStallV1
    };
    let foreign = harness_for(
        other,
        "foreign-owner-failure",
        SyntheticOutcome::CannotEvaluateTyped,
    );
    let mut coproducer = foreign.coproducer();
    let verified = foreign.verified(&mut coproducer);
    assert_eq!(
        verified
            .owner_failure()
            .map(|failure| failure.code.as_str()),
        Some("filesystem_identity_mismatch")
    );
    assert!(operator_explanation(&verified).is_none());
    foreign.finish();
    // The consequence identity is untouched by the explanations.
    assert!(consequence_identity().starts_with("sha256:"));
}
