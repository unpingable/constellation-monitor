use proptest::prelude::*;

use pulse_replay::run_jsonl;
use pulse_types::{JudgmentCategoryV1, SequenceContinuityDimensionV1};

proptest! {
    #[test]
    fn duplicates_never_extend_receiver_owned_expiry(
        duplicate_count in 0_u8..24,
        validity_ms in 2_u64..500,
    ) {
        let mut trace = format!(
            "{{\"event\":\"config\",\"minimum_observers\":1,\"auto_bridge\":false}}\n{{\"event\":\"pulse\",\"at_ms\":0,\"observer\":\"observer:a\",\"observer_incarnation\":\"a:1\",\"sequence\":1,\"validity_ms\":{validity_ms}}}\n"
        );
        for index in 0..duplicate_count {
            let at = 1 + (u64::from(index) % (validity_ms - 1));
            trace.push_str(&format!(
                "{{\"event\":\"pulse\",\"at_ms\":{at},\"observer\":\"observer:a\",\"observer_incarnation\":\"a:1\",\"sequence\":1,\"validity_ms\":{validity_ms}}}\n"
            ));
        }
        // Sort the generated duplicate records by time because trace time is
        // itself part of the deterministic input contract.
        let mut lines: Vec<_> = trace.lines().map(str::to_owned).collect();
        let config = lines.remove(0);
        lines.sort_by_key(|line| {
            line.split("\"at_ms\":")
                .nth(1)
                .and_then(|tail| tail.split(',').next())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0)
        });
        let mut sorted = format!("{config}\n{}", lines.join("\n"));
        sorted.push_str(&format!("\n{{\"event\":\"tick\",\"at_ms\":{validity_ms}}}\n"));
        let report = run_jsonl(&sorted).expect("generated duplicate trace replays");
        prop_assert_eq!(report.final_judgment.category, JudgmentCategoryV1::Unknown);
        prop_assert_eq!(report.metrics.duplicate_count, u64::from(duplicate_count));
    }

    #[test]
    fn expiry_is_inclusive_and_stale_positive_overshoot_is_measured(
        validity_ms in 2_u64..2_000,
        overshoot_ms in 0_u64..100,
    ) {
        let evaluation = validity_ms + overshoot_ms;
        let trace = format!(
            "{{\"event\":\"config\",\"minimum_observers\":1,\"auto_bridge\":false}}\n{{\"event\":\"pulse\",\"at_ms\":0,\"observer\":\"observer:a\",\"observer_incarnation\":\"a:1\",\"sequence\":1,\"validity_ms\":{validity_ms}}}\n{{\"event\":\"tick\",\"at_ms\":{evaluation}}}\n"
        );
        let report = run_jsonl(&trace).expect("generated expiry trace replays");
        prop_assert_eq!(report.final_judgment.category, JudgmentCategoryV1::Unknown);
        prop_assert_eq!(
            report.metrics.maximum_stale_positive_duration_ms,
            overshoot_ms
        );
    }

    #[test]
    fn receiver_verified_prearrival_delay_shortens_freshness(
        validity_ms in 2_u64..2_000,
        delay_seed in 0_u64..2_000,
    ) {
        let delay_ms = 1 + (delay_seed % (validity_ms - 1));
        let expiry_ms = validity_ms - delay_ms;
        let trace = format!(
            "{{\"event\":\"config\",\"minimum_observers\":1,\"auto_bridge\":false}}\n{{\"event\":\"pulse\",\"at_ms\":0,\"observer\":\"observer:a\",\"observer_incarnation\":\"a:1\",\"sequence\":1,\"validity_ms\":{validity_ms},\"transport_delay_ms\":{delay_ms}}}\n{{\"event\":\"tick\",\"at_ms\":{expiry_ms}}}\n"
        );
        let report = run_jsonl(&trace).expect("generated delayed trace replays");
        prop_assert_eq!(report.final_judgment.category, JudgmentCategoryV1::Unknown);
        prop_assert_eq!(report.metrics.maximum_stale_positive_duration_ms, 0);
    }

    #[test]
    fn arbitrary_sequence_reset_under_new_incarnation_is_never_inherited(
        old_sequence in 1_u64..10_000,
        new_sequence in 0_u64..10_000,
    ) {
        let trace = format!(
            "{{\"event\":\"config\",\"minimum_observers\":1,\"auto_bridge\":false}}\n{{\"event\":\"pulse\",\"at_ms\":0,\"observer\":\"observer:a\",\"observer_incarnation\":\"a:old\",\"sequence\":{old_sequence},\"validity_ms\":100}}\n{{\"event\":\"pulse\",\"at_ms\":1,\"observer\":\"observer:a\",\"observer_incarnation\":\"a:new\",\"sequence\":{new_sequence},\"validity_ms\":100}}\n"
        );
        let report = run_jsonl(&trace).expect("generated incarnation trace replays");
        prop_assert_eq!(report.final_judgment.category, JudgmentCategoryV1::Degraded);
        prop_assert_eq!(
            report.final_judgment.dimensions.sequence_continuity,
            SequenceContinuityDimensionV1::Restarted
        );
    }

    #[test]
    fn old_reordered_sequences_cannot_replace_the_high_water_mark(
        high in 2_u64..10_000,
        old in 0_u64..2,
    ) {
        let trace = format!(
            "{{\"event\":\"config\",\"minimum_observers\":1,\"auto_bridge\":false}}\n{{\"event\":\"pulse\",\"at_ms\":0,\"observer\":\"observer:a\",\"observer_incarnation\":\"a:1\",\"sequence\":{high},\"validity_ms\":100}}\n{{\"event\":\"pulse\",\"at_ms\":1,\"observer\":\"observer:a\",\"observer_incarnation\":\"a:1\",\"sequence\":{old},\"validity_ms\":100,\"observed_coverage\":[\"load\"]}}\n"
        );
        let first = run_jsonl(&trace).expect("generated reorder trace replays");
        let second = run_jsonl(&trace).expect("generated reorder trace replays twice");
        prop_assert_eq!(&first, &second);
        prop_assert_eq!(first.final_judgment.category, JudgmentCategoryV1::Current);
        prop_assert_eq!(first.metrics.dropped_stale_pulse_count, 1);
        prop_assert!(first.final_judgment.coverage.missing.is_empty());
    }
}
