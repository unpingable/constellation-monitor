//! The operator-facing text stays condition-scoped. The artifact carries the
//! projector's closed axis vocabulary (`state: "healthy"` means available and
//! no impact); the renderer labels that state `No issue reported` and appends
//! the condition reason with its non-claim. No audience is shown "Healthy" or
//! "Operational".

mod common;

use constellation_status_nq_load_pressure::{admit_live, fact_for};
use constellation_status_projection::{
    ProjectedStateV1, ProjectionMomentV1, RenderedStatusV1, project, render_status,
};
use pulse_nq_load_correspondence::fixture::SyntheticOutcome;

use common::{CONDITION_KEY, condition_policy, harness};

const NOW: u64 = 1_900_000_000_000;

#[test]
fn an_absent_condition_renders_as_no_issue_reported_for_the_condition_only() {
    let harness = harness("presentation", SyntheticOutcome::ExplicitlyAbsent);
    let mut coproducer = harness.coproducer();
    for public in [true, false] {
        let verified = harness.verified(&mut coproducer);
        let policy = condition_policy(harness.selector(), public);
        let fact = fact_for(&verified, &policy, CONDITION_KEY).expect("fact");
        let live = admit_live(
            &verified,
            &policy,
            CONDITION_KEY,
            &harness.reactor,
            &format!("nonce:presentation-{public}"),
            120_000,
        )
        .expect("live");
        let artifact = project(&policy, &[fact], &[live], &[], ProjectionMomentV1::now(NOW))
            .expect("projection");
        // Internal axis vocabulary, unchanged and machine-readable.
        assert_eq!(artifact.aggregate_state, ProjectedStateV1::Healthy);
        assert_eq!(artifact.aggregate_state.as_str(), "healthy");
        // Operator-facing text: condition-scoped only.
        let RenderedStatusV1::Current { html } =
            render_status(&artifact, NOW + 1_000, 250).expect("render")
        else {
            panic!("artifact should be current")
        };
        assert!(html.contains("Overall projection: No issue reported"));
        assert!(html.contains(
            "<strong>Host load-pressure condition</strong>: No issue reported — Qualified load-pressure condition absent in the current NQ observation. This is not a host or service health claim."
        ));
        for unscoped in [
            "Healthy",
            "healthy",
            "Operational",
            "operational",
            "Host healthy",
        ] {
            assert!(
                !html.contains(unscoped),
                "public={public}: rendered text carries unscoped `{unscoped}`"
            );
        }
        assert!(html.contains("grants no authority or permission"));
    }
    harness.finish();
}
