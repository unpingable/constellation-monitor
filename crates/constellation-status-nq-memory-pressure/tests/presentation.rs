//! The operator-facing text stays condition-scoped for memory: the artifact
//! carries the projector's closed axis vocabulary (`healthy` = available and
//! no impact); the renderer labels it `No issue reported` and appends the
//! condition reason with its non-claim. No audience is shown "Healthy",
//! "Memory healthy", "Host healthy", or "Operational".

mod common;

use constellation_status_nq_memory_pressure::{admit_live, fact_for};
use constellation_status_projection::{
    ProjectedStateV1, ProjectionMomentV1, RenderedStatusV1, project, render_status,
};
use pulse_nq_load_correspondence::fixture::SyntheticOutcome;

use common::{CONDITION_KEY, condition_policy, harness};

const NOW: u64 = 1_900_000_000_000;

fn rendered(
    harness: &common::Harness,
    coproducer: &mut pulse_nq_load_correspondence::Coproducer<'_>,
    outcome: SyntheticOutcome,
    public: bool,
) -> String {
    harness.nq.set_outcome(outcome);
    let verified = harness.verified(coproducer);
    let policy = condition_policy(harness.selector(), public);
    let fact = fact_for(&verified, &policy, CONDITION_KEY).expect("fact");
    let live = admit_live(
        &verified,
        &policy,
        CONDITION_KEY,
        &harness.reactor,
        &format!("nonce:presentation-{public}-{outcome:?}"),
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

#[test]
fn memory_states_render_condition_scoped_text_only() {
    let harness = harness("presentation", SyntheticOutcome::ExplicitlyAbsent);
    let mut coproducer = harness.coproducer();
    for public in [true, false] {
        let absent = rendered(
            &harness,
            &mut coproducer,
            SyntheticOutcome::ExplicitlyAbsent,
            public,
        );
        assert!(absent.contains(
            "<strong>Memory pressure stall</strong>: No issue reported — Qualified memory pressure-stall condition absent in the current NQ observation. This is not a memory sufficiency or host health claim."
        ));
        assert!(absent.contains("Overall projection: No issue reported"));
        let present = rendered(&harness, &mut coproducer, SyntheticOutcome::Present, public);
        assert!(present.contains(
            "<strong>Memory pressure stall</strong>: Degraded — Qualified memory pressure-stall condition present in the current NQ observation. No outage, service impact, or cause is claimed."
        ));
        assert!(present.contains("Overall projection: Degraded"));
        let unknown = rendered(
            &harness,
            &mut coproducer,
            SyntheticOutcome::CannotEvaluate,
            public,
        );
        assert!(unknown.contains("Status unavailable"));
        assert!(unknown.contains("No current conclusion is supported."));
        for html in [&absent, &present, &unknown] {
            for unscoped in [
                "Healthy",
                "healthy",
                "Memory healthy",
                "memory healthy",
                "Host healthy",
                "Operational",
                "operational",
                "avg60",
                "PSI",
                "MemAvailable",
                "swap",
                "0123456789abcdef0123456789abcdef",
                "host:",
            ] {
                assert!(
                    !html.contains(unscoped),
                    "public={public}: rendered text carries `{unscoped}`"
                );
            }
        }
        // The unavailable page carries no artifact fields at all; the current
        // pages carry the non-authorization line.
        for html in [&absent, &present] {
            assert!(html.contains("grants no authority or permission"));
        }
    }
    harness.finish();
}
