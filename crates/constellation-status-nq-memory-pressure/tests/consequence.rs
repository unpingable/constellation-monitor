mod common;

use constellation_status_nq_memory_pressure::{
    CONSEQUENCE_NONCLAIMS, CONSEQUENCE_SCHEMA_V1, FACT_OWNER, consequence_identity,
    consequence_row, consequence_table, fact_for, recommended_safe_reasons,
};
use constellation_status_nq_memory_pressure::{
    PUBLIC_COMPONENT_LABEL, REQUIRED_QUESTION, admit_live, live_support_selector,
    live_support_selector_for,
};
use constellation_status_projection::{
    AvailabilityV1, ComponentOutputFieldV1, ImpactV1, ProjectedStateV1, SourceFactClassV1,
};
use pulse_nq_load_correspondence::fixture::SYNTHETIC_MEMORY_SUBJECT;
use pulse_nq_load_correspondence::fixture::SyntheticOutcome;
use pulse_nq_load_correspondence::{NqDetectorStateV1, QuestionV1};
use pulse_types::SubjectId;

use common::{CONDITION_KEY, FACT_ID, condition_policy, harness, harness_for, requirement};

/// Pinned identity of the mapping contract. A deliberate table change must
/// update this constant and the contract document together.
const CONSEQUENCE_IDENTITY: &str =
    "sha256:a0311c04a6713f3aa5a2a51c0ae6cf238990dc6ad9a732a3864c4ddb8791f4ac";

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
        "constellation.status_consequence.nq_host_memory_pressure_stall.v1"
    );
    assert_eq!(FACT_OWNER, "constellation-status-nq-memory-pressure");
    assert_eq!(REQUIRED_QUESTION, QuestionV1::HostMemoryPressureStallV1);
    let joined = CONSEQUENCE_NONCLAIMS.join(" ");
    for phrase in [
        "no impairment, outage, service impact, or cause is claimed",
        "kernel stall accounting only",
        "says nothing about memory sufficiency, available memory, OOM risk, swap, service impact, or host health",
        "not an outage",
        "never memory, a host, or a service as a whole",
        "not an NQ claim",
        "grants no authority",
        "enrolled machine",
    ] {
        assert!(
            joined.contains(phrase),
            "missing non-claim phrase: {phrase}"
        );
    }
    let reasons = recommended_safe_reasons();
    assert_eq!(reasons.len(), 3);
    for reason in &reasons {
        assert!(reason.text.contains("memory pressure-stall condition"));
        assert!(!reason.text.to_lowercase().contains("host is healthy"));
        assert!(!reason.text.to_lowercase().contains("service is healthy"));
        for restated in [
            "avg60",
            "10.00",
            "boot",
            "PSI",
            "MemAvailable",
            "swap health",
        ] {
            assert!(!reason.text.contains(restated), "{restated} restates NQ");
        }
    }
    assert_eq!(PUBLIC_COMPONENT_LABEL, "Memory pressure stall");
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
    assert_eq!(fact.reason_code, "nq_memory_pressure_stall_present");
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
fn a_load_or_filesystem_correspondence_is_refused_by_this_adapter() {
    for other in [
        QuestionV1::HostLoadPressureV1,
        QuestionV1::HostFilesystemCapacityPressureV1,
    ] {
        let load = harness_for(other, "other-refused", SyntheticOutcome::Present);
        let mut coproducer = load.coproducer();
        let verified = load.verified(&mut coproducer);
        assert_eq!(verified.question(), other);
        // A policy authored for this adapter but pointed at the load reactor's
        // certificate lineage: the question check fires before any selector or
        // certificate comparison.
        let policy = condition_policy(load.selector_any_scope(), false);
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
                &load.reactor,
                "nonce:other-refused",
                60_000,
            )
            .unwrap_err()
            .code,
            "question_mismatch"
        );
        load.finish();
    }

    // A memory correspondence with a selector whose scope names the load
    // question is refused as a selector mismatch.
    let harness = harness("scope", SyntheticOutcome::ExplicitlyAbsent);
    let mut coproducer = harness.coproducer();
    let verified = harness.verified(&mut coproducer);
    let mut other_scope = condition_policy(harness.selector(), false);
    other_scope.components[0].required_facts[0]
        .live_support
        .scope = QuestionV1::HostLoadPressureV1.spec().pulse_scope.to_owned();
    assert_eq!(
        fact_for(&verified, &other_scope, CONDITION_KEY)
            .unwrap_err()
            .code,
        "selector_mismatch"
    );
    harness.finish();
}

#[test]
fn a_public_policy_may_not_carry_the_machine_id_in_any_identifier_or_text() {
    let harness = harness("public-leak", SyntheticOutcome::Present);
    let mut coproducer = harness.coproducer();
    let verified = harness.verified(&mut coproducer);
    let machine = "0123456789abcdef0123456789abcdef";
    let clean = condition_policy(harness.selector(), true);
    fact_for(&verified, &clean, CONDITION_KEY).expect("clean public policy");

    // Component key, projection id, fact id, and safe-reason text.
    let mut key = condition_policy(harness.selector(), true);
    key.components[0].key = format!("mem-{machine}");
    key.root_component = key.components[0].key.clone();
    assert_eq!(
        fact_for(&verified, &key, &format!("mem-{machine}"))
            .unwrap_err()
            .code,
        "public_identity_leak"
    );
    let mut projection = condition_policy(harness.selector(), true);
    projection.projection_id = format!("public-{machine}");
    assert_eq!(
        fact_for(&verified, &projection, CONDITION_KEY)
            .unwrap_err()
            .code,
        "public_identity_leak"
    );
    let mut fact_id = condition_policy(harness.selector(), true);
    fact_id.components[0].required_facts[0].fact_id = format!("fact.{machine}");
    assert_eq!(
        fact_for(&verified, &fact_id, CONDITION_KEY)
            .unwrap_err()
            .code,
        "public_identity_leak"
    );
    assert_eq!(
        admit_live(
            &verified,
            &fact_id,
            CONDITION_KEY,
            &harness.reactor,
            "nonce:leak",
            60_000,
        )
        .unwrap_err()
        .code,
        "public_identity_leak"
    );
    // The same identifiers are allowed in an operator policy, whose basis is
    // disclosed anyway; only the label is guarded there.
    let mut operator = condition_policy(harness.selector(), false);
    operator.components[0].required_facts[0].fact_id = format!("fact.{machine}");
    fact_for(&verified, &operator, CONDITION_KEY).expect("operator fact id");
    let mut labelled = condition_policy(harness.selector(), false);
    labelled.components[0]
        .output
        .as_mut()
        .expect("output")
        .display_name = format!("{PUBLIC_COMPONENT_LABEL} ({machine})");
    assert_eq!(
        fact_for(&verified, &labelled, CONDITION_KEY)
            .unwrap_err()
            .code,
        "condition_contract_mismatch",
        "no audience may extend the label"
    );
    harness.finish();
}

#[test]
fn certificate_lookup_names_the_subject_and_scope_and_refuses_ambiguity() {
    let harness = harness("lookup", SyntheticOutcome::ExplicitlyAbsent);
    let mut coproducer = harness.coproducer();
    let _verified = harness.verified(&mut coproducer);
    let consumer = harness.profile.consumer();
    let snapshot = harness.reactor.snapshot();
    let by_consumer = live_support_selector(&snapshot, &consumer).expect("one certificate");
    let by_subject = live_support_selector_for(&snapshot, &consumer, SYNTHETIC_MEMORY_SUBJECT)
        .expect("same certificate by subject");
    assert_eq!(by_consumer, by_subject);
    assert_eq!(by_subject.scope, REQUIRED_QUESTION.spec().pulse_scope);
    assert_eq!(
        live_support_selector_for(
            &snapshot,
            &consumer,
            "host:ffffffffffffffffffffffffffffffff"
        )
        .unwrap_err()
        .code,
        "certificate_missing"
    );

    // Pulse keys consumers by subject and consumer, so one consumer id may
    // hold a certificate on a second subject: the consumer-only lookup is
    // then ambiguous and refused, while the subject lookup still selects.
    let mut doubled = snapshot.clone();
    let mut second = doubled.certificates[0].clone();
    second.subject_scope.subject = SubjectId::new("host:ffffffffffffffffffffffffffffffff");
    second.certificate_id = second.compute_id();
    doubled.certificates.push(second);
    assert_eq!(
        live_support_selector(&doubled, &consumer).unwrap_err().code,
        "certificate_ambiguous"
    );
    assert_eq!(
        live_support_selector_for(&doubled, &consumer, SYNTHETIC_MEMORY_SUBJECT)
            .expect("subject selects"),
        by_subject
    );
    // A certificate on another scope is never this adapter's.
    let mut other_scope = snapshot.clone();
    other_scope.certificates[0].subject_scope.scope =
        QuestionV1::HostLoadPressureV1.spec().pulse_scope.to_owned();
    assert_eq!(
        live_support_selector(&other_scope, &consumer)
            .unwrap_err()
            .code,
        "certificate_missing"
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
