//! Every code this adapter explains yields its bounded text and nothing
//! stronger; every other token, including another owner's code text and the
//! owner's own code-less refusal, yields no explanation, while the state
//! stays `cannot_evaluate` throughout.

mod common;

use constellation_status_nq_systemd_unit::{operator_detail, operator_explanation};
use pulse_nq_load_correspondence::NqDetectorStateV1;
use pulse_nq_load_correspondence::fixture::SyntheticOutcome;

use common::{CONDITION_KEY, condition_policy, harness};

/// The closed set of `nq.systemd_unit` v2 codes this adapter explains, with
/// the start of each bounded text.
const EXPLAINED: &[(&str, &str)] = &[
    (
        "system_bus_unavailable",
        "The system bus could not be reached",
    ),
    (
        "manager_unavailable",
        "The system manager did not answer on the system bus",
    ),
    (
        "query_timeout",
        "The unit state query did not complete within its deadline",
    ),
    ("query_failed", "The unit state query failed"),
    (
        "reply_malformed",
        "The system manager's reply was not in the expected form",
    ),
    (
        "machine_identity_mismatch",
        "Machine identity could not be verified",
    ),
    (
        "unit_list_cardinality",
        "The system manager did not report exactly one unit",
    ),
    (
        "unit_name_not_canonical",
        "The enrolled unit name is not the unit's canonical name",
    ),
    (
        "unit_state_unrecognized",
        "The reported unit state is outside the vocabulary",
    ),
];
/// Tokens this adapter never explains: another owner's code text carried
/// verbatim (memory's PSI and boot-clock codes, the filesystem owner's
/// codes) and a token no owner defines.
const FOREIGN: &[&str] = &[
    "psi_not_provided",
    "psi_read_failed",
    "psi_malformed",
    "boot_clock_unavailable",
    "not_a_mountpoint",
    "filesystem_identity_mismatch",
    "statfs_failed",
    "machine_identity_unavailable",
    "unit_not_found",
];

#[test]
fn every_owner_code_maps_to_bounded_text_or_to_nothing_and_never_to_a_state() {
    assert_eq!(
        EXPLAINED.len(),
        9,
        "the explained set is exactly nine codes"
    );
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
            "restart",
            "cron",
            "0123456789abcdef",
            "org.freedesktop",
            "systemctl",
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
    // Other tokens are carried but not explained: plain unknown.
    for code in FOREIGN {
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
    // The owner's own code-less refusal.
    harness.nq.set_typed_code(None);
    harness.nq.set_outcome(SyntheticOutcome::CannotEvaluate);
    let verified = harness.verified(&mut coproducer);
    assert!(verified.owner_failure().is_none());
    assert!(operator_explanation(&verified).is_none());
    harness.finish();
}
