//! The operator-facing text stays condition-scoped for the required unit
//! state: the artifact carries the projector's closed axis vocabulary
//! (`healthy` = available and no impact); the renderer labels it `No issue
//! reported` and appends the condition reason with its non-claim. No
//! audience is shown "Operational", "Healthy service", "service up", or
//! "application healthy"; the only "operational" on any page is inside the
//! healthy row's own negation ("not a service operational ... claim").

mod common;

use constellation_status_nq_systemd_unit::{
    admit_live, fact_for, operator_component_label, recommended_safe_reasons,
};
use constellation_status_projection::{
    ProjectedStateV1, ProjectionMomentV1, RenderedStatusV1, project, render_status,
};
use pulse_nq_load_correspondence::fixture::SyntheticOutcome;

use common::{CONDITION_KEY, SUBJECT_UNIT, condition_policy, harness};

const NOW: u64 = 1_900_000_000_000;

/// The three policy shapes that render: public (bare label), operator with
/// the bare label, and operator with the verified unit's label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    Public,
    OperatorBare,
    OperatorUnit,
}

impl Shape {
    fn label(self) -> String {
        match self {
            Self::Public | Self::OperatorBare => "Required unit state".to_owned(),
            Self::OperatorUnit => operator_component_label(SUBJECT_UNIT),
        }
    }
}

fn rendered(
    harness: &common::Harness,
    coproducer: &mut pulse_nq_load_correspondence::Coproducer<'_>,
    outcome: SyntheticOutcome,
    shape: Shape,
) -> String {
    harness.nq.set_outcome(outcome);
    let verified = harness.verified(coproducer);
    let mut policy = condition_policy(harness.selector(), shape == Shape::Public);
    policy.components[0]
        .output
        .as_mut()
        .expect("output")
        .display_name = shape.label();
    let fact = fact_for(&verified, &policy, CONDITION_KEY).expect("fact");
    let live = admit_live(
        &verified,
        &policy,
        CONDITION_KEY,
        &harness.reactor,
        &format!("nonce:presentation-{shape:?}-{outcome:?}"),
        60_000,
    )
    .expect("live");
    let artifact =
        project(&policy, &[fact], &[live], &[], ProjectionMomentV1::now(NOW)).expect("projection");
    if outcome == SyntheticOutcome::ExplicitlyAbsent {
        assert_eq!(artifact.aggregate_state, ProjectedStateV1::Healthy);
        assert_eq!(artifact.aggregate_state.as_str(), "healthy");
    }
    if outcome == SyntheticOutcome::CannotEvaluate {
        // Unknown carries no presentation window: the artifact expires at
        // its own generation instant and renders as unavailable.
        assert_eq!(artifact.aggregate_state, ProjectedStateV1::Unknown);
        assert_eq!(artifact.fresh_until_unix_ms, artifact.generated_at_unix_ms);
        let RenderedStatusV1::StatusUnavailable { html } =
            render_status(&artifact, NOW, 0).expect("render")
        else {
            panic!("an unknown artifact is never current")
        };
        return html;
    }
    let RenderedStatusV1::Current { html } =
        render_status(&artifact, NOW + 1_000, 250).expect("render")
    else {
        panic!("artifact should be current")
    };
    html
}

/// The page with every pinned condition reason removed: what is left must
/// carry no service-health vocabulary in any case.
fn outside_reasons(html: &str) -> String {
    let mut residue = html.to_owned();
    for reason in recommended_safe_reasons() {
        residue = residue.replace(&reason.text, "");
    }
    residue
}

#[test]
fn unit_states_render_condition_scoped_text_only() {
    let harness = harness("presentation", SyntheticOutcome::ExplicitlyAbsent);
    let mut coproducer = harness.coproducer();
    for shape in [Shape::Public, Shape::OperatorBare, Shape::OperatorUnit] {
        let label = shape.label();
        let absent = rendered(
            &harness,
            &mut coproducer,
            SyntheticOutcome::ExplicitlyAbsent,
            shape,
        );
        assert!(
            absent.contains(&format!(
                "<strong>{label}</strong>: No issue reported — The system manager reported the required unit loaded and active in the current NQ observation. This is not a service operational, reachability, or application health claim."
            )),
            "{shape:?}: {absent}"
        );
        assert!(absent.contains("Overall projection: No issue reported"));
        let present = rendered(&harness, &mut coproducer, SyntheticOutcome::Present, shape);
        assert!(
            present.contains(&format!(
                "<strong>{label}</strong>: Degraded — The system manager reported the required unit in a state other than loaded and active in the current NQ observation. No outage, user impact, or cause is claimed."
            )),
            "{shape:?}: {present}"
        );
        assert!(present.contains("Overall projection: Degraded"));
        let unknown = rendered(
            &harness,
            &mut coproducer,
            SyntheticOutcome::CannotEvaluate,
            shape,
        );
        assert!(unknown.contains("Status unavailable"));
        assert!(unknown.contains("No current conclusion is supported."));
        for (html, current) in [(&absent, true), (&present, true), (&unknown, false)] {
            // The projector's axis word never reaches a page as a label, and
            // no page names a state in service vocabulary, in any case.
            let residue = outside_reasons(html).to_lowercase();
            for unscoped in [
                "healthy",
                "operational",
                "healthy service",
                "service up",
                "application healthy",
                "service healthy",
                "unit healthy",
                "host healthy",
                "running",
                "restart",
                "activestate",
                "systemctl",
                "0123456789abcdef0123456789abcdef",
                "systemd-unit:",
            ] {
                assert!(
                    !residue.contains(unscoped),
                    "{shape:?}: rendered text carries `{unscoped}`"
                );
            }
            // Case-sensitive: the state word "Operational" never appears at
            // all, reasons included.
            assert!(!html.contains("Operational"), "{shape:?}");
            assert!(!html.contains("Healthy"), "{shape:?}");
            // The unit name reaches only the unit-labelled operator page, and
            // the unavailable page lists no component at all.
            assert_eq!(
                html.contains(SUBJECT_UNIT),
                shape == Shape::OperatorUnit && current,
                "{shape:?}: unit name placement"
            );
        }
        // The unavailable page carries no artifact fields at all; the current
        // pages carry the non-authorization line.
        for html in [&absent, &present] {
            assert!(html.contains("grants no authority or permission"));
        }
    }
    harness.finish();
}
