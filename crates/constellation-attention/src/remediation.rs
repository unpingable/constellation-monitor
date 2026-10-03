//! `response_policy` (cartography #55): the evaluator half of
//! `auto_remediate_then_page`. The deferral semantics live in
//! [`page_decision`] only, so a later design can change the window rule in
//! one place.

use crate::inputs::Observation;
use crate::registry::ResponsePolicy;

/// Default and bounds of a target's remediation window.
pub const DEFAULT_WINDOW_SECONDS: i64 = 240;
pub const MIN_WINDOW_SECONDS: i64 = 60;
pub const MAX_WINDOW_SECONDS: i64 = 600;

/// Whether a page-class condition's page goes out now.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageDecision {
    /// Submit the page intent now.
    Send,
    /// Hold the page; the notice is unaffected.
    Defer,
}

/// End of the remediation window: `first_seen + window`.
#[must_use]
pub fn window_until(first_seen: Option<i64>, window_seconds: i64) -> Option<i64> {
    first_seen.map(|first| first.saturating_add(window_seconds))
}

/// The page decision for a condition that has triggered (or is waiting for
/// its deferred page), given its policy, its window end and this pass's
/// observation.
///
/// v1 semantics: `observe_only` pages at once. `auto_remediate_then_page`
/// holds the page until the window has expired, then sends it at the first
/// pass that does not observe the condition clear: present **or unknown**
/// (no current qualified state is not recovery, and must not hold a page
/// forever). A clear inside the window resolves without any page (decided by
/// the lifecycle, not here); a removed condition is closed by the operator's
/// configuration, not paged.
#[must_use]
pub fn page_decision(
    policy: ResponsePolicy,
    window_until: Option<i64>,
    observation: Observation,
    now: i64,
) -> PageDecision {
    match (policy, window_until) {
        (ResponsePolicy::ObserveOnly, _) | (_, None) => PageDecision::Send,
        (ResponsePolicy::AutoRemediateThenPage, Some(until)) => {
            if now >= until && matches!(observation, Observation::Present | Observation::Unknown) {
                PageDecision::Send
            } else {
                PageDecision::Defer
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observe_only_always_sends() {
        for observation in [Observation::Present, Observation::Unknown] {
            assert_eq!(
                page_decision(ResponsePolicy::ObserveOnly, Some(1_000), observation, 0),
                PageDecision::Send
            );
        }
    }

    #[test]
    fn remediation_defers_until_expiry_while_present() {
        let policy = ResponsePolicy::AutoRemediateThenPage;
        assert_eq!(
            page_decision(policy, Some(240), Observation::Present, 239),
            PageDecision::Defer
        );
        assert_eq!(
            page_decision(policy, Some(240), Observation::Present, 240),
            PageDecision::Send
        );
        assert_eq!(
            page_decision(policy, Some(240), Observation::Unknown, 239),
            PageDecision::Defer
        );
        // Unknown past expiry is not recovery: the held page goes out.
        assert_eq!(
            page_decision(policy, Some(240), Observation::Unknown, 300),
            PageDecision::Send
        );
        assert_eq!(
            page_decision(policy, Some(240), Observation::Clear, 300),
            PageDecision::Defer
        );
        assert_eq!(window_until(Some(100), 240), Some(340));
    }
}
