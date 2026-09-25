mod common;

use constellation_status_nq_systemd_unit::{
    CONSEQUENCE_NONCLAIMS, CONSEQUENCE_SCHEMA_V1, FACT_OWNER, consequence_identity,
    consequence_row, consequence_table, fact_for, recommended_safe_reasons,
};
use constellation_status_nq_systemd_unit::{
    PUBLIC_COMPONENT_LABEL, REQUIRED_QUESTION, admit_live, live_support_selector,
    live_support_selector_for, operator_component_label,
};
use constellation_status_projection::{
    AvailabilityV1, ComponentOutputFieldV1, ImpactV1, ProjectedStateV1, ProjectionPolicyV1,
    SourceFactClassV1,
};
use pulse_nq_load_correspondence::fixture::SYNTHETIC_SYSTEMD_UNIT_SUBJECT;
use pulse_nq_load_correspondence::fixture::SyntheticOutcome;
use pulse_nq_load_correspondence::{NqDetectorStateV1, QuestionV1};
use pulse_types::SubjectId;

use common::{
    CONDITION_KEY, FACT_ID, OTHER_QUESTIONS, SUBJECT_MACHINE, SUBJECT_UNIT, condition_policy,
    harness, harness_for, requirement,
};

/// Pinned identity of the mapping contract. A deliberate table change must
/// update this constant and the contract document together.
const CONSEQUENCE_IDENTITY: &str =
    "sha256:f54e4aa8b7e81a32fcc8066f182967b0f30760125132e0ea5824bfab17e775d2";

fn relabel(policy: &mut ProjectionPolicyV1, label: impl Into<String>) {
    policy.components[0]
        .output
        .as_mut()
        .expect("condition output")
        .display_name = label.into();
}

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
    assert_eq!(present.reason_code, "nq_systemd_unit_not_active_present");
    let absent = consequence_row(NqDetectorStateV1::ExplicitlyAbsent);
    assert_eq!(
        (absent.availability, absent.impact, absent.projected_state),
        (
            AvailabilityV1::Available,
            ImpactV1::None,
            ProjectedStateV1::Healthy
        )
    );
    assert_eq!(
        absent.reason_code,
        "nq_systemd_unit_not_active_explicitly_absent"
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
fn non_claims_and_reason_text_name_the_condition_not_the_service() {
    assert_eq!(
        CONSEQUENCE_SCHEMA_V1,
        "constellation.status_consequence.nq_systemd_unit_required_active.v1"
    );
    assert_eq!(FACT_OWNER, "constellation-status-nq-systemd-unit");
    assert_eq!(REQUIRED_QUESTION, QuestionV1::SystemdUnitRequiredActiveV1);
    assert_eq!(CONSEQUENCE_NONCLAIMS.len(), 6);
    let joined = CONSEQUENCE_NONCLAIMS.join(" ");
    for phrase in [
        "in a state other than loaded and active",
        "no outage, user-visible impact, dependency failure, or cause is claimed",
        "reported the enrolled unit loaded and active",
        "not a service operational, reachable, healthy, available, or application health claim",
        "not an outage",
        "never a service, application, host, or dependency as a whole",
        "suggests or authorizes a restart, reload, or any other actuation",
        "not an NQ claim",
        "grants no authority",
        "enrolled systemd unit",
    ] {
        assert!(
            joined.contains(phrase),
            "missing non-claim phrase: {phrase}"
        );
    }
    let reasons = recommended_safe_reasons();
    assert_eq!(reasons.len(), 3);
    for reason in &reasons {
        assert!(reason.text.contains("required unit"), "{}", reason.text);
        let lower = reason.text.to_lowercase();
        for unscoped in [
            "service is healthy",
            "service is up",
            "service up",
            "healthy service",
            "application healthy",
            "is operational",
            "restart",
        ] {
            assert!(!lower.contains(unscoped), "{unscoped}");
        }
        for restated in [
            "ActiveState",
            "LoadState",
            "SubState",
            "active (running)",
            "systemctl",
            "org.freedesktop",
            "cron.service",
            "0123456789abcdef",
        ] {
            assert!(!reason.text.contains(restated), "{restated} restates NQ");
        }
    }
    // "Operational" appears only inside the healthy row's negation.
    assert!(
        reasons[0].text.contains(
            "This is not a service operational, reachability, or application health claim."
        )
    );
    assert_eq!(PUBLIC_COMPONENT_LABEL, "Required unit state");
    assert_eq!(
        operator_component_label("cron.service"),
        "Required unit state (cron.service)"
    );
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
    assert_eq!(verified.subject().as_str(), SYNTHETIC_SYSTEMD_UNIT_SUBJECT);
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
    assert_eq!(fact.reason_code, "nq_systemd_unit_not_active_present");
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
    // A selector for another unit on the same machine.
    let mut other_unit = condition_policy(harness.selector(), true);
    other_unit.components[0].required_facts[0]
        .live_support
        .subject = format!("systemd-unit:{SUBJECT_MACHINE}/rsyslog.service");
    assert_eq!(
        fact_for(&verified, &other_unit, CONDITION_KEY)
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
fn a_load_filesystem_or_memory_correspondence_is_refused_by_this_adapter() {
    for (other, _) in OTHER_QUESTIONS {
        let foreign = harness_for(other, "other-refused", SyntheticOutcome::Present);
        let mut coproducer = foreign.coproducer();
        let verified = foreign.verified(&mut coproducer);
        assert_eq!(verified.question(), other);
        // A policy authored for this adapter but pointed at the other
        // reactor's certificate lineage: the question check fires before any
        // selector or certificate comparison.
        let policy = condition_policy(foreign.selector_any_scope(), false);
        assert_eq!(
            fact_for(&verified, &policy, CONDITION_KEY)
                .unwrap_err()
                .code,
            "question_mismatch",
            "{other:?}"
        );
        assert_eq!(
            admit_live(
                &verified,
                &policy,
                CONDITION_KEY,
                &foreign.reactor,
                "nonce:other-refused",
                60_000,
            )
            .unwrap_err()
            .code,
            "question_mismatch",
            "{other:?}"
        );
        foreign.finish();
    }

    // A systemd unit correspondence with a selector whose scope names another
    // question is refused as a selector mismatch.
    let harness = harness("scope", SyntheticOutcome::ExplicitlyAbsent);
    let mut coproducer = harness.coproducer();
    let verified = harness.verified(&mut coproducer);
    for (other, _) in OTHER_QUESTIONS {
        let mut other_scope = condition_policy(harness.selector(), false);
        other_scope.components[0].required_facts[0]
            .live_support
            .scope = other.spec().pulse_scope.to_owned();
        assert_eq!(
            fact_for(&verified, &other_scope, CONDITION_KEY)
                .unwrap_err()
                .code,
            "selector_mismatch",
            "{other:?}"
        );
    }
    harness.finish();
}

#[test]
fn a_public_policy_may_not_carry_the_machine_id_or_unit_in_any_identifier_or_text() {
    let harness = harness("public-leak", SyntheticOutcome::Present);
    let mut coproducer = harness.coproducer();
    let verified = harness.verified(&mut coproducer);
    let clean = condition_policy(harness.selector(), true);
    fact_for(&verified, &clean, CONDITION_KEY).expect("clean public policy");
    // Each subject segment on its own; the whole `<machine>/<unit>` identity
    // cannot even reach this adapter in an identifier, because the generic
    // validator refuses `/` in a public id first.
    for leaked in [SUBJECT_MACHINE, SUBJECT_UNIT] {
        // Component key, projection id, and fact id.
        let mut key = condition_policy(harness.selector(), true);
        key.components[0].key = format!("unit-{leaked}");
        key.root_component = key.components[0].key.clone();
        assert_eq!(
            fact_for(&verified, &key, &format!("unit-{leaked}"))
                .unwrap_err()
                .code,
            "public_identity_leak",
            "{leaked}"
        );
        let mut projection = condition_policy(harness.selector(), true);
        projection.projection_id = format!("public-{leaked}");
        assert_eq!(
            fact_for(&verified, &projection, CONDITION_KEY)
                .unwrap_err()
                .code,
            "public_identity_leak",
            "{leaked}"
        );
        let mut fact_id = condition_policy(harness.selector(), true);
        fact_id.components[0].required_facts[0].fact_id = format!("fact.{leaked}");
        assert_eq!(
            fact_for(&verified, &fact_id, CONDITION_KEY)
                .unwrap_err()
                .code,
            "public_identity_leak",
            "{leaked}"
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
            "public_identity_leak",
            "{leaked}"
        );
    }
    // A public safe reason naming the unit is refused before the leak check
    // is reached: the reason table is pinned to the recommended text for
    // every audience, so no public reason can ever carry the unit name.
    let mut reason = condition_policy(harness.selector(), true);
    reason.disclosure.safe_reasons[1].text = format!(
        "{} ({SUBJECT_UNIT})",
        reason.disclosure.safe_reasons[1].text
    );
    assert_eq!(
        fact_for(&verified, &reason, CONDITION_KEY)
            .unwrap_err()
            .code,
        "condition_contract_mismatch"
    );
    let mut reason_machine = condition_policy(harness.selector(), true);
    reason_machine.disclosure.safe_reasons[2].text =
        format!("The required unit state on {SUBJECT_MACHINE} is currently unknown.");
    assert_eq!(
        fact_for(&verified, &reason_machine, CONDITION_KEY)
            .unwrap_err()
            .code,
        "condition_contract_mismatch"
    );
    // The same identifiers are allowed in an operator policy, whose basis is
    // disclosed anyway; only the label is guarded there.
    for leaked in [SUBJECT_MACHINE, SUBJECT_UNIT] {
        let mut operator = condition_policy(harness.selector(), false);
        operator.components[0].required_facts[0].fact_id = format!("fact.{leaked}");
        operator.projection_id = format!("operator-{leaked}");
        fact_for(&verified, &operator, CONDITION_KEY).expect("operator identifiers");
    }
    harness.finish();
}

#[test]
fn the_operator_label_may_name_only_the_verified_unit() {
    let harness = harness("operator-label", SyntheticOutcome::Present);
    let mut coproducer = harness.coproducer();
    let verified = harness.verified(&mut coproducer);
    let public = condition_policy(harness.selector(), true);
    let public_fact = fact_for(&verified, &public, CONDITION_KEY).expect("public fact");

    // The bare label and the verified unit's label are both accepted for an
    // operator policy, and yield exactly the public fact.
    let bare = condition_policy(harness.selector(), false);
    assert_eq!(
        fact_for(&verified, &bare, CONDITION_KEY).expect("bare operator label"),
        public_fact
    );
    let mut named = condition_policy(harness.selector(), false);
    relabel(&mut named, operator_component_label(SUBJECT_UNIT));
    assert_eq!(
        named.components[0]
            .output
            .as_ref()
            .expect("output")
            .display_name,
        "Required unit state (cron.service)"
    );
    assert_eq!(
        fact_for(&verified, &named, CONDITION_KEY).expect("verified unit label"),
        public_fact
    );
    admit_live(
        &verified,
        &named,
        CONDITION_KEY,
        &harness.reactor,
        "nonce:operator-label",
        60_000,
    )
    .expect("live admission under the unit label");

    // Another unit, a word that is not the verified unit, a state word, the
    // machine id, or the whole subject identity in the operator label.
    for wrong in [
        operator_component_label("rsyslog.service"),
        operator_component_label("cron.socket"),
        operator_component_label("Operational"),
        operator_component_label("healthy"),
        operator_component_label(SUBJECT_MACHINE),
        operator_component_label(&format!("{SUBJECT_MACHINE}/{SUBJECT_UNIT}")),
        format!("{PUBLIC_COMPONENT_LABEL} ({SUBJECT_UNIT}) (Operational)"),
        format!("{PUBLIC_COMPONENT_LABEL} ()"),
        format!("{PUBLIC_COMPONENT_LABEL} {SUBJECT_UNIT}"),
    ] {
        let mut policy = condition_policy(harness.selector(), false);
        relabel(&mut policy, wrong.clone());
        assert_eq!(
            fact_for(&verified, &policy, CONDITION_KEY)
                .unwrap_err()
                .code,
            "condition_contract_mismatch",
            "operator label {wrong:?}"
        );
        assert_eq!(
            admit_live(
                &verified,
                &policy,
                CONDITION_KEY,
                &harness.reactor,
                "nonce:wrong-label",
                60_000,
            )
            .unwrap_err()
            .code,
            "condition_contract_mismatch",
            "operator label {wrong:?}"
        );
    }

    // A public policy may use only the bare label, even for the verified unit.
    for public_label in [
        operator_component_label(SUBJECT_UNIT),
        operator_component_label("rsyslog.service"),
        operator_component_label("Operational"),
    ] {
        let mut policy = condition_policy(harness.selector(), true);
        relabel(&mut policy, public_label.clone());
        assert_eq!(
            fact_for(&verified, &policy, CONDITION_KEY)
                .unwrap_err()
                .code,
            "condition_contract_mismatch",
            "public label {public_label:?}"
        );
    }
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
    let by_subject =
        live_support_selector_for(&snapshot, &consumer, SYNTHETIC_SYSTEMD_UNIT_SUBJECT)
            .expect("same certificate by subject");
    assert_eq!(by_consumer, by_subject);
    assert_eq!(by_subject.scope, REQUIRED_QUESTION.spec().pulse_scope);
    assert_eq!(by_subject.scope, "nq.systemd_unit.required_active/v1");
    let other_subject = "systemd-unit:ffffffffffffffffffffffffffffffff/cron.service";
    assert_eq!(
        live_support_selector_for(&snapshot, &consumer, other_subject)
            .unwrap_err()
            .code,
        "certificate_missing"
    );
    assert_eq!(
        live_support_selector_for(
            &snapshot,
            &consumer,
            &format!("systemd-unit:{SUBJECT_MACHINE}/rsyslog.service")
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
    second.subject_scope.subject = SubjectId::new(other_subject);
    second.certificate_id = second.compute_id();
    doubled.certificates.push(second);
    assert_eq!(
        live_support_selector(&doubled, &consumer).unwrap_err().code,
        "certificate_ambiguous"
    );
    assert_eq!(
        live_support_selector_for(&doubled, &consumer, SYNTHETIC_SYSTEMD_UNIT_SUBJECT)
            .expect("subject selects"),
        by_subject
    );
    // A certificate on another scope is never this adapter's.
    for (other, _) in OTHER_QUESTIONS {
        let mut other_scope = snapshot.clone();
        other_scope.certificates[0].subject_scope.scope = other.spec().pulse_scope.to_owned();
        assert_eq!(
            live_support_selector(&other_scope, &consumer)
                .unwrap_err()
                .code,
            "certificate_missing",
            "{other:?}"
        );
    }
    harness.finish();
}

#[test]
fn every_audience_must_keep_the_qualified_condition_label_reason_and_nonclaim() {
    let harness = harness("contract-boundary", SyntheticOutcome::ExplicitlyAbsent);
    let mut coproducer = harness.coproducer();
    let verified = harness.verified(&mut coproducer);

    for public in [true, false] {
        for label in ["Service health", "cron", "Cron service", "Unit state"] {
            let mut relabeled = condition_policy(harness.selector(), public);
            relabel(&mut relabeled, label);
            assert_eq!(
                fact_for(&verified, &relabeled, CONDITION_KEY)
                    .expect_err("generic service-health label is not this condition")
                    .code,
                "condition_contract_mismatch",
                "public={public} label={label}"
            );
        }

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
            "The service is operational.".to_owned();
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
