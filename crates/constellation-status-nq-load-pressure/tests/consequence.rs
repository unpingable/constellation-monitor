mod common;

use constellation_status_nq_load_pressure::{
    CONSEQUENCE_NONCLAIMS, CONSEQUENCE_SCHEMA_V1, FACT_OWNER, consequence_identity,
    consequence_row, consequence_table, fact_for, recommended_safe_reasons,
};
use constellation_status_nq_load_pressure::{REQUIRED_QUESTION, admit_live};
use constellation_status_projection::{
    AvailabilityV1, ComponentOutputFieldV1, ImpactV1, ProjectedStateV1, SourceFactClassV1,
};
use pulse_nq_load_correspondence::fixture::SyntheticOutcome;
use pulse_nq_load_correspondence::{NqDetectorStateV1, QuestionV1};

use common::{CONDITION_KEY, FACT_ID, condition_policy, harness, harness_for, requirement};

/// Pinned identity of the mapping contract. A deliberate table change must
/// update this constant and the contract document together.
const CONSEQUENCE_IDENTITY: &str =
    "sha256:bd53af2e457e0296e15a25576ff80c4293c3d97aa385aa6aafcd5fb5264691fe";

#[test]
fn the_table_is_exactly_the_accepted_mapping_and_total() {
    let table = consequence_table();
    assert_eq!(table.len(), 4);
    let present = consequence_row(NqDetectorStateV1::Present);
    assert_eq!(
        (
            present.availability,
            present.impact,
            present.projected_state
        ),
        (
            AvailabilityV1::Impaired,
            ImpactV1::None,
            ProjectedStateV1::Degraded
        )
    );
    let absent = consequence_row(NqDetectorStateV1::ExplicitlyAbsent);
    assert_eq!(
        (absent.availability, absent.impact, absent.projected_state),
        (
            AvailabilityV1::Available,
            ImpactV1::None,
            ProjectedStateV1::Healthy
        )
    );
    for state in [
        NqDetectorStateV1::CannotEvaluate,
        NqDetectorStateV1::NotEvaluated,
    ] {
        let row = consequence_row(state);
        assert_eq!(
            (row.availability, row.impact, row.projected_state),
            (
                AvailabilityV1::Indeterminate,
                ImpactV1::Indeterminate,
                ProjectedStateV1::Unknown
            )
        );
    }
    // No row ever claims partial or total impact, and none reaches an outage.
    assert!(table.iter().all(|row| {
        !matches!(row.impact, ImpactV1::Partial | ImpactV1::Total)
            && !matches!(
                row.projected_state,
                ProjectedStateV1::PartialOutage | ProjectedStateV1::MajorOutage
            )
    }));
    // The generic projector's own axis mapping agrees with every row.
    let identity = consequence_identity();
    assert!(identity.starts_with("sha256:"));
    assert_eq!(
        identity, CONSEQUENCE_IDENTITY,
        "the consequence table or its non-claims changed; update the pinned identity deliberately"
    );
}

#[test]
fn non_claims_and_reason_text_name_the_condition_not_the_host() {
    assert_eq!(
        CONSEQUENCE_SCHEMA_V1,
        "constellation.status_consequence.nq_host_load_pressure.v1"
    );
    assert_eq!(FACT_OWNER, "constellation-status-nq-load-pressure");
    let joined = CONSEQUENCE_NONCLAIMS.join(" ");
    for phrase in [
        "not error",
        "no impairment, outage, impact, or cause is claimed",
        "says nothing about host or service health",
        "not an outage",
        "condition itself, never a host or service as a whole",
        "not an NQ claim",
        "grants no authority",
    ] {
        assert!(
            joined.contains(phrase),
            "missing non-claim phrase: {phrase}"
        );
    }
    let reasons = recommended_safe_reasons();
    assert_eq!(reasons.len(), 3);
    for reason in &reasons {
        assert!(reason.text.contains("load-pressure condition"));
        assert!(!reason.text.to_lowercase().contains("host is healthy"));
        assert!(!reason.text.to_lowercase().contains("service is healthy"));
    }
    let states = reasons
        .iter()
        .map(|reason| reason.state)
        .collect::<Vec<_>>();
    assert_eq!(
        states,
        vec![
            ProjectedStateV1::Healthy,
            ProjectedStateV1::Degraded,
            ProjectedStateV1::Unknown
        ]
    );
}

#[test]
fn fact_for_binds_the_correspondence_and_the_one_fact_guard_is_structural() {
    let harness = harness("fact", SyntheticOutcome::Present);
    let mut coproducer = harness.coproducer();
    let verified = harness.verified(&mut coproducer);
    let policy = condition_policy(harness.selector(), true);

    let fact = fact_for(&verified, &policy, CONDITION_KEY).expect("fact");
    assert_eq!(fact.fact_id, FACT_ID);
    assert_eq!(fact.subject_key, CONDITION_KEY);
    assert_eq!(fact.owner, FACT_OWNER);
    assert_eq!(fact.native_schema, CONSEQUENCE_SCHEMA_V1);
    assert_eq!(fact.class, SourceFactClassV1::DerivedAdmitted);
    assert_eq!(fact.evidence_id, verified.evidence_ref());
    assert_eq!(fact.native_record_id, verified.correspondence_id());
    assert_eq!(fact.basis_digest, verified.correspondence_id());
    assert_eq!(fact.availability, AvailabilityV1::Impaired);
    assert_eq!(fact.impact, ImpactV1::None);
    assert_eq!(fact.reason_code, "nq_load_pressure_present");
    assert!(
        fact.observed_at_unix_ms.is_none(),
        "no wall-clock time is invented"
    );

    // Two required facts on the condition component.
    let mut two = condition_policy(harness.selector(), true);
    let mut second = requirement(harness.selector());
    second.fact_id = "fact.other".to_owned();
    two.components[0].required_facts.push(second);
    assert_eq!(
        fact_for(&verified, &two, CONDITION_KEY).unwrap_err().code,
        "one_fact_guard"
    );

    // Wrong owner, schema, or class.
    let mut owner = condition_policy(harness.selector(), true);
    owner.components[0].required_facts[0].owner = "constellation-nq".to_owned();
    assert_eq!(
        fact_for(&verified, &owner, CONDITION_KEY).unwrap_err().code,
        "requirement_mismatch"
    );
    let mut schema = condition_policy(harness.selector(), true);
    schema.components[0].required_facts[0].native_schema = "nq.status_snapshot.v3".to_owned();
    assert_eq!(
        fact_for(&verified, &schema, CONDITION_KEY)
            .unwrap_err()
            .code,
        "requirement_mismatch"
    );
    let mut class = condition_policy(harness.selector(), true);
    class.components[0].required_facts[0].class = SourceFactClassV1::Observed;
    assert_eq!(
        fact_for(&verified, &class, CONDITION_KEY).unwrap_err().code,
        "requirement_mismatch"
    );

    // A selector for another incarnation.
    let mut incarnation = condition_policy(harness.selector(), true);
    incarnation.components[0].required_facts[0]
        .live_support
        .subject_incarnation = "linux-boot:other".to_owned();
    assert_eq!(
        fact_for(&verified, &incarnation, CONDITION_KEY)
            .unwrap_err()
            .code,
        "selector_mismatch"
    );

    assert_eq!(
        fact_for(&verified, &policy, "missing").unwrap_err().code,
        "unknown_component"
    );
    harness.finish();
}

#[test]
fn a_filesystem_capacity_or_memory_correspondence_is_refused_by_this_adapter() {
    assert_eq!(REQUIRED_QUESTION, QuestionV1::HostLoadPressureV1);
    // Memory shares load's `host:` subject prefix; the refusal is on the
    // question, never on the prefix.
    for other in [
        QuestionV1::HostFilesystemCapacityPressureV1,
        QuestionV1::HostMemoryPressureStallV1,
    ] {
        let filesystem = harness_for(other, "other-refused", SyntheticOutcome::Present);
        let mut coproducer = filesystem.coproducer();
        let verified = filesystem.verified(&mut coproducer);
        assert_eq!(verified.question(), other);
        let policy = condition_policy(filesystem.selector_any_scope(), false);
        assert_eq!(
            fact_for(&verified, &policy, CONDITION_KEY)
                .unwrap_err()
                .code,
            "question_mismatch"
        );
        assert_eq!(
            admit_live(
                &verified,
                &policy,
                CONDITION_KEY,
                &filesystem.reactor,
                "nonce:filesystem-refused",
                120_000,
            )
            .unwrap_err()
            .code,
            "question_mismatch"
        );
        filesystem.finish();
    }

    let harness = harness("scope", SyntheticOutcome::ExplicitlyAbsent);
    let mut coproducer = harness.coproducer();
    let verified = harness.verified(&mut coproducer);
    let mut other_scope = condition_policy(harness.selector(), false);
    other_scope.components[0].required_facts[0]
        .live_support
        .scope = QuestionV1::HostFilesystemCapacityPressureV1
        .spec()
        .pulse_scope
        .to_owned();
    assert_eq!(
        fact_for(&verified, &other_scope, CONDITION_KEY)
            .unwrap_err()
            .code,
        "selector_mismatch"
    );
    harness.finish();
}

#[test]
fn every_audience_must_keep_the_qualified_condition_label_reason_and_nonclaim() {
    let harness = harness("contract-boundary", SyntheticOutcome::ExplicitlyAbsent);
    let mut coproducer = harness.coproducer();
    let verified = harness.verified(&mut coproducer);

    for public in [true, false] {
        let mut relabeled = condition_policy(harness.selector(), public);
        relabeled.components[0]
            .output
            .as_mut()
            .expect("condition output")
            .display_name = "Host health".to_owned();
        assert_eq!(
            fact_for(&verified, &relabeled, CONDITION_KEY)
                .expect_err("generic host-health label is not this condition")
                .code,
            "condition_contract_mismatch",
            "public={public}"
        );

        let mut omitted_reason = condition_policy(harness.selector(), public);
        omitted_reason
            .disclosure
            .component_fields
            .retain(|field| *field != ComponentOutputFieldV1::Reason);
        assert_eq!(
            fact_for(&verified, &omitted_reason, CONDITION_KEY)
                .expect_err("the condition must include its reason")
                .code,
            "condition_contract_mismatch",
            "public={public}"
        );

        let mut rewritten_nonclaim = condition_policy(harness.selector(), public);
        rewritten_nonclaim.disclosure.safe_reasons[0].text =
            "The current component is healthy.".to_owned();
        assert_eq!(
            fact_for(&verified, &rewritten_nonclaim, CONDITION_KEY)
                .expect_err("the condition must retain its fixed non-claim")
                .code,
            "condition_contract_mismatch",
            "public={public}"
        );

        let mut hidden = condition_policy(harness.selector(), public);
        hidden.components[0].output = None;
        assert_eq!(
            hidden.validate().unwrap_err().code,
            "hidden_root",
            "a hidden root is refused by the generic policy validator"
        );
    }
    harness.finish();
}
