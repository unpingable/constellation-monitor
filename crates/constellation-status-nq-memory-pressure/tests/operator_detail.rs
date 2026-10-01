//! The owner's bounded explanation may decorate an operator projection as a
//! display-only detail. It never changes the state, the fact, the basis or
//! the consequence identity; a public policy never carries it; every
//! substitution suppresses it while the state stays exactly what it was.

mod common;

use constellation_status_nq_memory_pressure::{
    admit_live, consequence_identity, fact_for, operator_detail, operator_explanation,
};
use constellation_status_projection::{
    COMPONENT_DETAIL_SCHEMA_V1, ComponentDetailV1, ComponentOutputFieldV1,
    LiveSupportObservationV1, ProjectedStateV1, ProjectionMomentV1, ProjectionPolicyV1,
    RenderedStatusV1, SourceFactV1, StatusArtifactV1, project, project_with_details, render_status,
};
use pulse_nq_load_correspondence::fixture::SyntheticOutcome;
use pulse_nq_load_correspondence::{QuestionV1, VerifiedCorrespondenceV1};

use common::{CONDITION_KEY, condition_policy, harness, harness_for};

const NOW: u64 = 1_900_000_000_000;

/// One fact and one live admission for a verified correspondence; projected
/// as many times as a test needs against the same inputs.
struct Inputs {
    policy: ProjectionPolicyV1,
    fact: SourceFactV1,
    live: LiveSupportObservationV1,
    moment: ProjectionMomentV1,
}

fn inputs(harness: &common::Harness, verified: &VerifiedCorrespondenceV1, public: bool) -> Inputs {
    let policy = condition_policy(harness.selector(), public);
    let fact = fact_for(verified, &policy, CONDITION_KEY).expect("fact");
    let live = admit_live(
        verified,
        &policy,
        CONDITION_KEY,
        &harness.reactor,
        &format!("nonce:detail-{public}-{}", verified.correspondence_id()),
        60_000,
    )
    .expect("live");
    Inputs {
        policy,
        fact,
        live,
        moment: ProjectionMomentV1::now(NOW),
    }
}

impl Inputs {
    fn project(&self, details: &[ComponentDetailV1]) -> Result<StatusArtifactV1, String> {
        project_with_details(
            &self.policy,
            std::slice::from_ref(&self.fact),
            std::slice::from_ref(&self.live),
            &[],
            details,
            self.moment,
        )
        .map_err(|error| error.code.to_owned())
    }
}

/// Everything about a projection except the display-only detail and the
/// artifact identity that covers it: aggregate state, generated and fresh
/// instants, basis and policy digests, and each component's id, state and
/// reason.
type Decision = (
    ProjectedStateV1,
    u64,
    u64,
    Option<String>,
    String,
    Vec<(String, ProjectedStateV1, Option<String>)>,
);

fn decision(artifact: &StatusArtifactV1) -> Decision {
    (
        artifact.aggregate_state,
        artifact.generated_at_unix_ms,
        artifact.fresh_until_unix_ms,
        artifact.basis_digest.clone(),
        artifact.policy_digest.clone(),
        artifact
            .components
            .iter()
            .map(|component| {
                (
                    component.id.clone(),
                    component.state,
                    component.reason.clone(),
                )
            })
            .collect(),
    )
}

#[test]
fn an_operator_detail_decorates_unknown_without_changing_any_decision() {
    let harness = harness("operator-detail", SyntheticOutcome::CannotEvaluateTyped);
    let mut coproducer = harness.coproducer();
    let typed = harness.verified(&mut coproducer);
    let operator = inputs(&harness, &typed, false);
    let public_policy = condition_policy(harness.selector(), true);

    let detail = operator_detail(&typed, &operator.policy, CONDITION_KEY)
        .expect("guarded")
        .expect("a known owner code yields a detail");
    assert_eq!(detail.schema, COMPONENT_DETAIL_SCHEMA_V1);
    assert_eq!(detail.fact_id, operator.fact.fact_id);
    assert_eq!(
        detail.text,
        operator_explanation(&typed).expect("explanation").text
    );
    assert_eq!(
        operator_detail(&typed, &public_policy, CONDITION_KEY).expect("guarded"),
        None,
        "a public policy never carries a detail"
    );

    let with = operator
        .project(std::slice::from_ref(&detail))
        .expect("projection");
    let without = operator.project(&[]).expect("projection");
    // Same decision from the same inputs; the detail is the only difference
    // besides the artifact identity that covers the bytes.
    assert_eq!(decision(&with), decision(&without));
    assert_eq!(with.aggregate_state, ProjectedStateV1::Unknown);
    assert_eq!(with.components[0].state, ProjectedStateV1::Unknown);
    assert_eq!(
        with.components[0].detail.as_deref(),
        Some(detail.text.as_str())
    );
    assert_eq!(without.components[0].detail, None);
    assert_eq!(with.components[0].reason, without.components[0].reason);
    assert_eq!(with.basis_digest, without.basis_digest);
    assert_ne!(with.artifact_id, without.artifact_id);
    // The plain entry point is the same projection with no details.
    let plain = project(
        &operator.policy,
        std::slice::from_ref(&operator.fact),
        std::slice::from_ref(&operator.live),
        &[],
        operator.moment,
    )
    .expect("projection");
    assert_eq!(plain, without);

    // Indifference: a different text under the same code, evidence, state and
    // identities yields the same decision again.
    let reworded = ComponentDetailV1 {
        text: "Reworded owner text for the same code".to_owned(),
        ..detail.clone()
    };
    let reworded_artifact = operator
        .project(std::slice::from_ref(&reworded))
        .expect("projection");
    assert_eq!(decision(&reworded_artifact), decision(&with));
    assert_eq!(
        reworded_artifact.components[0].detail.as_deref(),
        Some("Reworded owner text for the same code")
    );
    assert!(consequence_identity().starts_with("sha256:"));

    // The operator surface: the unavailable page names the condition,
    // its unavailable state and the detail, and still states no conclusion.
    let RenderedStatusV1::StatusUnavailable { html } =
        render_status(&with, NOW, 0).expect("render")
    else {
        panic!("an unknown artifact is never current")
    };
    assert!(html.contains("No current conclusion is supported."));
    assert!(html.contains("<strong>Memory pressure stall</strong>: Status unavailable"));
    // The page escapes the text; an apostrophe becomes `&#39;`.
    let escaped = detail.text.replace('\'', "&#39;");
    assert!(html.contains(&format!("Detail: {escaped}")));
    for stronger in [
        "Degraded",
        "No issue reported",
        "Retriable",
        "retriable",
        "Operational",
    ] {
        assert!(!html.contains(stronger), "{stronger}");
    }
    // Without a detail the unavailable page lists nothing.
    let RenderedStatusV1::StatusUnavailable { html: bare } =
        render_status(&without, NOW, 0).expect("render")
    else {
        panic!("unknown")
    };
    assert!(!bare.contains("<li>"));
    assert!(!bare.contains("Detail:"));

    // A public policy refuses the detail field outright.
    let mut leaking = condition_policy(harness.selector(), true);
    leaking
        .disclosure
        .component_fields
        .push(ComponentOutputFieldV1::Detail);
    assert_eq!(leaking.validate().unwrap_err().code, "public_disclosure");
    harness.finish();
}

#[test]
fn substitutions_suppress_the_detail_and_keep_the_state() {
    let harness = harness("detail-substitution", SyntheticOutcome::CannotEvaluateTyped);
    let mut coproducer = harness.coproducer();
    let typed = harness.verified(&mut coproducer);
    let operator = inputs(&harness, &typed, false);
    let good = operator_detail(&typed, &operator.policy, CONDITION_KEY)
        .expect("guarded")
        .expect("detail");

    // A detail for a fact that was not supplied, supplied twice, or over the
    // text bound is refused by the projector before anything is read.
    let foreign_fact = ComponentDetailV1 {
        fact_id: "fact.other".to_owned(),
        ..good.clone()
    };
    assert_eq!(
        operator.project(&[foreign_fact]).unwrap_err(),
        "unknown_detail_fact"
    );
    assert_eq!(
        operator.project(&[good.clone(), good.clone()]).unwrap_err(),
        "duplicate_detail"
    );
    let oversized = ComponentDetailV1 {
        text: "x".repeat(257),
        ..good.clone()
    };
    assert_eq!(operator.project(&[oversized]).unwrap_err(), "invalid_text");

    // Without the Detail field disclosed, a supplied detail is dropped, not
    // an error, and the artifact equals the plain projection.
    let mut undisclosed = operator.policy.clone();
    undisclosed
        .disclosure
        .component_fields
        .retain(|field| *field != ComponentOutputFieldV1::Detail);
    let moment = ProjectionMomentV1::now(NOW);
    let dropped = project_with_details(
        &undisclosed,
        std::slice::from_ref(&operator.fact),
        std::slice::from_ref(&operator.live),
        &[],
        std::slice::from_ref(&good),
        moment,
    )
    .expect("projection");
    let plain = project(
        &undisclosed,
        std::slice::from_ref(&operator.fact),
        std::slice::from_ref(&operator.live),
        &[],
        moment,
    )
    .expect("projection");
    assert_eq!(dropped, plain);
    assert_eq!(dropped.components[0].detail, None);

    // An untyped cannot_evaluate, and every determinate state, yield no
    // detail; the state is whatever it was.
    for (outcome, state) in [
        (SyntheticOutcome::CannotEvaluate, ProjectedStateV1::Unknown),
        (
            SyntheticOutcome::ExplicitlyAbsent,
            ProjectedStateV1::Healthy,
        ),
        (SyntheticOutcome::Present, ProjectedStateV1::Degraded),
        (SyntheticOutcome::InputRefusal, ProjectedStateV1::Unknown),
    ] {
        harness.nq.set_outcome(outcome);
        let verified = harness.verified(&mut coproducer);
        let operator = inputs(&harness, &verified, false);
        assert_eq!(
            operator_detail(&verified, &operator.policy, CONDITION_KEY).expect("guarded"),
            None
        );
        let artifact = operator.project(&[]).expect("projection");
        assert_eq!(artifact.components[0].state, state, "{outcome:?}");
        assert_eq!(artifact.components[0].detail, None);
    }
    harness.finish();

    // The other question's typed refusal: refused by the question check, so
    // no detail can be built from it here.
    let other = harness_for(
        QuestionV1::HostFilesystemCapacityPressureV1,
        "detail-other",
        SyntheticOutcome::CannotEvaluateTyped,
    );
    let mut other_coproducer = other.coproducer();
    let verified = other.verified(&mut other_coproducer);
    assert_eq!(
        verified
            .owner_failure()
            .map(|failure| failure.code.as_str()),
        Some("filesystem_identity_mismatch")
    );
    let policy = condition_policy(other.selector_any_scope(), false);
    assert_eq!(
        operator_detail(&verified, &policy, CONDITION_KEY)
            .unwrap_err()
            .code,
        "question_mismatch"
    );
    other.finish();
}
