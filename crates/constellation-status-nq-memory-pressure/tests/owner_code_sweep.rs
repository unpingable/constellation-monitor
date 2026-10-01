//! Every code this adapter explains yields its bounded text and nothing
//! stronger; every other owner code, every foreign owner's code and the
//! owner's own code-less refusal yield no explanation, while the state stays
//! `cannot_evaluate` throughout.

mod common;

use constellation_status_nq_memory_pressure::{operator_detail, operator_explanation};
use pulse_nq_load_correspondence::NqDetectorStateV1;
use pulse_nq_load_correspondence::fixture::SyntheticOutcome;

use common::{CONDITION_KEY, condition_policy, harness};

const EXPLAINED: &[(&str, &str)] = &[
    (
        "machine_identity_mismatch",
        "Machine identity could not be verified",
    ),
    (
        "psi_not_provided",
        "Memory pressure accounting is not available to the collector",
    ),
    (
        "psi_read_failed",
        "Memory pressure accounting could not be read",
    ),
    (
        "psi_malformed",
        "Memory pressure accounting was present but not in the expected form",
    ),
    ("boot_clock_unavailable", "The boot clock could not be read"),
];
const UNEXPLAINED_OWN: &[&str] = &["machine_identity_unavailable"];
const FOREIGN: &[&str] = &[
    "not_a_mountpoint",
    "filesystem_identity_mismatch",
    "statfs_failed",
];

#[test]
fn every_owner_code_maps_to_bounded_text_or_to_nothing_and_never_to_a_state() {
    let harness = harness("code-sweep", SyntheticOutcome::CannotEvaluateTyped);
    let mut coproducer = harness.coproducer();
    let operator = condition_policy(harness.selector(), false);
    for (code, prefix) in EXPLAINED {
        harness.nq.set_typed_code(Some(code));
        let verified = harness.verified(&mut coproducer);
        assert_eq!(
            verified.nq_detector_state(),
            NqDetectorStateV1::CannotEvaluate
        );
        assert_eq!(
            verified
                .owner_failure()
                .map(|failure| failure.code.as_str()),
            Some(*code)
        );
        let explanation = operator_explanation(&verified).unwrap_or_else(|| panic!("{code}"));
        assert_eq!(explanation.code, *code);
        assert!(
            explanation.text.starts_with(prefix),
            "{code}: {}",
            explanation.text
        );
        assert_eq!(explanation.retriable, Some(false));
        assert!(explanation.text.len() <= 256);
        for forbidden in [
            "this time",
            "temporar",
            "retry",
            "transient",
            "again",
            "/",
            "PSI",
            "avg60",
            "Operational",
            "healthy",
            "outage",
        ] {
            assert!(
                !explanation
                    .text
                    .to_lowercase()
                    .contains(&forbidden.to_lowercase()),
                "{code}: `{forbidden}`"
            );
        }
        let detail = operator_detail(&verified, &operator, CONDITION_KEY)
            .expect("guarded")
            .expect("detail");
        assert_eq!(detail.text, explanation.text);
    }
    // The owner's other codes are carried but not explained: plain unknown.
    for code in UNEXPLAINED_OWN.iter().chain(FOREIGN.iter()) {
        harness.nq.set_typed_code(Some(code));
        let verified = harness.verified(&mut coproducer);
        assert_eq!(
            verified.nq_detector_state(),
            NqDetectorStateV1::CannotEvaluate
        );
        assert_eq!(
            verified
                .owner_failure()
                .map(|failure| failure.code.as_str()),
            Some(*code),
            "the seam carries the token opaquely"
        );
        assert!(
            operator_explanation(&verified).is_none(),
            "{code} must not be explained here"
        );
        assert_eq!(
            operator_detail(&verified, &operator, CONDITION_KEY).expect("guarded"),
            None
        );
    }
    // The owner's own code-less refusal (for memory, the warm-up guard).
    harness.nq.set_typed_code(None);
    harness.nq.set_outcome(SyntheticOutcome::CannotEvaluate);
    let verified = harness.verified(&mut coproducer);
    assert!(verified.owner_failure().is_none());
    assert!(operator_explanation(&verified).is_none());
    harness.finish();
}
