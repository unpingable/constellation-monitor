//! Co-production, live admission, projection, reduction, dependency behavior,
//! expiry, and atomic publication for the load-pressure condition component.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::time::Duration;

use constellation_status_nq_load_pressure::{admit_live, fact_for};
use constellation_status_projection::{
    AvailabilityV1, ComponentPolicyV1, DependencyBehaviorV1, DependencyEdgeV1, DependencyEffectV1,
    DependencyKindV1, FactRequirementV1, ImpactV1, LiveQueryAnchorV1, LiveSupportObservationV1,
    LiveSupportSelectorV1, OutputComponentV1, ProjectedStateV1, ProjectionMomentV1,
    RenderedStatusV1, SOURCE_FACT_SCHEMA_V1, SourceFactClassV1, SourceFactV1, project,
    read_current_artifact, render_status, stage_publication,
};
use pulse_nq_load_correspondence::fixture::SyntheticOutcome;
use pulse_nq_load_correspondence::{Coproducer, FRAME_VALIDITY_MS};
use pulse_types::{
    AuthorityGrantsV1, ClockId, ConsumerId, ConsumerProfileGenerationId, ContextActivationId,
    CoverageSummaryV1, EscalationStateV1, EvaluatorSemanticGenerationId, EvidenceWindowId,
    IncarnationId, JudgmentCategoryV1, LIVE_PRESENT_SUPPORT_REQUEST_SCHEMA_V1,
    LivePresentSupportDispositionV1, LivePresentSupportNonce, LivePresentSupportRequestV1,
    LivePresentSupportResponseV1, MutationAuthorityV1, ObservationPolicyGenerationId,
    ObserverSetGenerationId, PolicyGenerationId, QualifiedGenerationBindingV1,
    QualifiedGenerationSetV1, ReceiverId, RelianceContextV1, RelianceSupportCertificateV1,
    SCHEMA_VERSION_V1, SubjectId, SubjectScopeV1, SupportCertificateId, digest_parts,
};

use common::{
    CONDITION_KEY, CONDITION_OUTPUT, condition_policy, dependency_policy, disclosure,
    hard_behavior, harness,
};

const NOW: u64 = 1_900_000_000_000;

fn project_condition(
    harness: &common::Harness,
    coproducer: &mut Coproducer<'_>,
    outcome: SyntheticOutcome,
    public: bool,
) -> (
    constellation_status_projection::StatusArtifactV1,
    constellation_status_projection::ProjectionPolicyV1,
) {
    harness.nq.set_outcome(outcome);
    let verified = harness.verified(coproducer);
    let policy = condition_policy(harness.selector(), public);
    let fact = fact_for(&verified, &policy, CONDITION_KEY).expect("fact");
    let live = admit_live(
        &verified,
        &policy,
        CONDITION_KEY,
        &harness.reactor,
        &format!("nonce:{}", verified.correspondence_id()),
        120_000,
    )
    .expect("live admission");
    let artifact =
        project(&policy, &[fact], &[live], &[], ProjectionMomentV1::now(NOW)).expect("projection");
    (artifact, policy)
}

#[test]
fn each_nq_outcome_projects_to_its_consequence_and_nothing_else() {
    let harness = harness("mapping", SyntheticOutcome::Present);
    let mut coproducer = harness.coproducer();
    for (outcome, expected) in [
        (SyntheticOutcome::Present, ProjectedStateV1::Degraded),
        (
            SyntheticOutcome::ExplicitlyAbsent,
            ProjectedStateV1::Healthy,
        ),
        (SyntheticOutcome::CannotEvaluate, ProjectedStateV1::Unknown),
        (SyntheticOutcome::InputRefusal, ProjectedStateV1::Unknown),
        (
            SyntheticOutcome::ProviderNoResponse,
            ProjectedStateV1::Unknown,
        ),
    ] {
        let (artifact, _) = project_condition(&harness, &mut coproducer, outcome, true);
        assert_eq!(artifact.aggregate_state, expected, "{outcome:?}");
        assert_eq!(artifact.components.len(), 1);
        assert_eq!(artifact.components[0].id, CONDITION_OUTPUT);
        assert_eq!(artifact.components[0].state, expected);
        if expected == ProjectedStateV1::Unknown {
            assert_eq!(artifact.fresh_until_unix_ms, artifact.generated_at_unix_ms);
        } else {
            assert!(artifact.fresh_until_unix_ms > artifact.generated_at_unix_ms);
            assert!(artifact.fresh_until_unix_ms <= NOW + 60_000);
        }
        let reason = artifact.components[0].reason.as_deref().unwrap_or_default();
        assert!(reason.contains("load-pressure condition"), "{reason}");
    }
    harness.finish();
}

#[test]
fn public_reduction_leaks_no_source_identity_and_operator_keeps_a_basis_digest() {
    let harness = harness("reduction", SyntheticOutcome::Present);
    let mut coproducer = harness.coproducer();
    let (public, _) = project_condition(&harness, &mut coproducer, SyntheticOutcome::Present, true);
    let text = String::from_utf8(public.canonical_bytes().expect("canonical")).expect("utf8");
    let snapshot_certificate = harness
        .reactor
        .snapshot()
        .certificates
        .into_iter()
        .find(|certificate| certificate.consumer == harness.profile.consumer())
        .expect("certificate");
    for forbidden in [
        "constellation-nq-load:v1",
        "nq-store-genesis",
        "host:synthetic",
        "observer:nq-load-correspondence",
        "nq_load_pressure_present",
        "correspondence",
        snapshot_certificate.supporting_evidence_ids[0].as_str(),
        snapshot_certificate.certificate_id.as_str(),
    ] {
        assert!(
            !text.contains(forbidden),
            "public artifact leaked {forbidden}"
        );
    }
    assert!(public.basis_digest.is_none());
    assert_eq!(
        public.components[0].display_name.as_deref(),
        Some("Host load-pressure condition")
    );
    let RenderedStatusV1::Current { html } =
        render_status(&public, public.generated_at_unix_ms + 1_000, 0).expect("render")
    else {
        panic!("artifact should be current")
    };
    assert!(html.contains("Host load-pressure condition"));
    assert!(html.contains("No outage or cause is claimed."));
    assert!(!html.contains("Operational"));

    let (operator, _) =
        project_condition(&harness, &mut coproducer, SyntheticOutcome::Present, false);
    assert!(operator.basis_digest.is_some());
    assert_eq!(operator.aggregate_state, ProjectedStateV1::Degraded);
    harness.finish();
}

#[test]
fn a_stale_verified_correspondence_is_refused_once_a_newer_frame_is_certified() {
    let harness = harness("stale", SyntheticOutcome::ExplicitlyAbsent);
    let mut coproducer = harness.coproducer();
    let first = harness.verified(&mut coproducer);
    let _second = harness.verified(&mut coproducer);
    let policy = condition_policy(harness.selector(), true);
    let error = admit_live(
        &first,
        &policy,
        CONDITION_KEY,
        &harness.reactor,
        "nonce:stale",
        120_000,
    )
    .expect_err("the earlier frame is no longer the supporting evidence");
    assert_eq!(error.code, "certificate_evidence_mismatch");
    harness.finish();
}

#[test]
fn expiry_and_caller_elapsed_time_only_shorten_and_never_extend() {
    let harness = harness("expiry", SyntheticOutcome::ExplicitlyAbsent);
    let mut coproducer = harness.coproducer();
    let verified = harness.verified(&mut coproducer);
    let policy = condition_policy(harness.selector(), true);
    let fact = fact_for(&verified, &policy, CONDITION_KEY).expect("fact");

    // A trusted-lifetime bound below the remaining support bounds the window.
    let live = admit_live(
        &verified,
        &policy,
        CONDITION_KEY,
        &harness.reactor,
        "nonce:short",
        40,
    )
    .expect("live");
    let artifact = project(
        &policy,
        std::slice::from_ref(&fact),
        &[live],
        &[],
        ProjectionMomentV1::now(NOW),
    )
    .expect("projection");
    assert_eq!(
        artifact.aggregate_state,
        ProjectedStateV1::Unknown,
        "40 ms minus 250 ms uncertainty leaves no window"
    );

    let mut lenient = policy.clone();
    lenient.admitted_clock_uncertainty_ms = 0;
    lenient.timestamp_granularity_ms = 1;
    let live = admit_live(
        &verified,
        &policy,
        CONDITION_KEY,
        &harness.reactor,
        "nonce:short-2",
        40,
    )
    .expect("live");
    let artifact = project(
        &lenient,
        std::slice::from_ref(&fact),
        &[live],
        &[],
        ProjectionMomentV1::now(NOW),
    )
    .expect("projection");
    assert_eq!(artifact.aggregate_state, ProjectedStateV1::Healthy);
    assert!(artifact.fresh_until_unix_ms - artifact.generated_at_unix_ms <= 40);

    // After the admitted interval elapses, the same observation projects unknown.
    let live = admit_live(
        &verified,
        &policy,
        CONDITION_KEY,
        &harness.reactor,
        "nonce:short-3",
        20,
    )
    .expect("live");
    std::thread::sleep(Duration::from_millis(30));
    let artifact = project(
        &lenient,
        &[fact],
        &[live],
        &[],
        ProjectionMomentV1::now(NOW + 30),
    )
    .expect("projection");
    assert_eq!(artifact.aggregate_state, ProjectedStateV1::Unknown);

    // A retained artifact renders unavailable at or after its deadline.
    let (fresh, _) = project_condition(
        &harness,
        &mut coproducer,
        SyntheticOutcome::ExplicitlyAbsent,
        true,
    );
    assert!(matches!(
        render_status(&fresh, fresh.generated_at_unix_ms + 1_000, 250).expect("render"),
        RenderedStatusV1::Current { .. }
    ));
    assert!(matches!(
        render_status(&fresh, fresh.fresh_until_unix_ms, 0).expect("render"),
        RenderedStatusV1::StatusUnavailable { .. }
    ));
    harness.finish();
}

#[test]
fn repeated_live_queries_get_new_anchors_but_do_not_extend_the_source_deadline() {
    let harness = harness("replay", SyntheticOutcome::ExplicitlyAbsent);
    let mut coproducer = harness.coproducer();
    let verified = harness.verified(&mut coproducer);
    let consumer = harness.profile.consumer();
    let policy = condition_policy(harness.selector(), true);
    let source_deadline = harness
        .reactor
        .snapshot()
        .certificates
        .into_iter()
        .find(|certificate| certificate.consumer == consumer)
        .and_then(|certificate| certificate.earliest_support_expiry_monotonic_ms)
        .expect("source deadline");
    let first = admit_live(
        &verified,
        &policy,
        CONDITION_KEY,
        &harness.reactor,
        "nonce:once",
        FRAME_VALIDITY_MS,
    )
    .expect("live");
    std::thread::sleep(Duration::from_millis(5));
    let second = admit_live(
        &verified,
        &policy,
        CONDITION_KEY,
        &harness.reactor,
        "nonce:once",
        FRAME_VALIDITY_MS,
    )
    .expect("a repeated query is a new measurement, not a refresh");
    let now = std::time::Instant::now();
    let first_remaining = first.usable_remaining_ms_at(now).unwrap_or(0);
    let second_remaining = second.usable_remaining_ms_at(now).unwrap_or(0);
    assert!(second_remaining <= first_remaining + 1);
    let deadline_after_queries = harness
        .reactor
        .snapshot()
        .certificates
        .into_iter()
        .find(|certificate| certificate.consumer == consumer)
        .and_then(|certificate| certificate.earliest_support_expiry_monotonic_ms)
        .expect("source deadline after queries");
    assert_eq!(deadline_after_queries, source_deadline);
    // Each call performs a fresh live query and therefore gets a new
    // process-local anchor. The adapter exposes no API that accepts a retained
    // response, and neither query moves Pulse's source-owned deadline.
    harness.finish();
}

#[test]
fn dependency_edges_cannot_carry_state_into_or_out_of_the_condition() {
    let harness = harness("dependency", SyntheticOutcome::ExplicitlyAbsent);
    let mut coproducer = harness.coproducer();
    let verified = harness.verified(&mut coproducer);

    let (dependency_requirement, dependency_fact, dependency_support) = synthetic_dependency(
        "evidence:dependency",
        AvailabilityV1::Impaired,
        ImpactV1::None,
    );

    // A hard or soft edge from the condition to a degraded hidden dependency
    // would make the projector select "condition present" reason text for an
    // NQ explicitly-absent judgment. Both entry points refuse the policy, in
    // both audiences, before any fact is built or any live query is made.
    for public in [true, false] {
        for kind in [DependencyKindV1::Hard, DependencyKindV1::Soft] {
            let mut policy = dependency_policy(
                harness.selector(),
                dependency_requirement.clone(),
                kind,
                hard_behavior(),
            );
            policy.disclosure = disclosure(public);
            assert_eq!(
                fact_for(&verified, &policy, CONDITION_KEY)
                    .unwrap_err()
                    .code,
                "dependency_guard",
                "{kind:?} public={public}"
            );
            assert_eq!(
                admit_live(
                    &verified,
                    &policy,
                    CONDITION_KEY,
                    &harness.reactor,
                    "nonce:dep-refused",
                    120_000,
                )
                .unwrap_err()
                .code,
                "dependency_guard",
                "{kind:?} public={public}"
            );
        }
    }

    // The reverse direction: a visible component that depends on the
    // condition would carry an NQ warning into its own state. Refused for
    // both edge kinds, both audiences, at both entry points.
    for public in [true, false] {
        for kind in [DependencyKindV1::Hard, DependencyKindV1::Soft] {
            let mut reverse = condition_policy(harness.selector(), public);
            reverse.components.push(ComponentPolicyV1 {
                key: "synthetic.service".to_owned(),
                output: Some(OutputComponentV1 {
                    id: "service".to_owned(),
                    display_name: "Synthetic service".to_owned(),
                }),
                required_facts: vec![dependency_requirement.clone()],
                maintenance_assertion_ids: Vec::new(),
            });
            reverse.root_component = "synthetic.service".to_owned();
            reverse.dependencies = vec![DependencyEdgeV1 {
                parent: "synthetic.service".to_owned(),
                dependency: CONDITION_KEY.to_owned(),
                kind,
                behavior: hard_behavior(),
            }];
            reverse
                .validate()
                .expect("the generic projector accepts this shape");
            assert_eq!(
                fact_for(&verified, &reverse, CONDITION_KEY)
                    .unwrap_err()
                    .code,
                "dependency_guard",
                "{kind:?} public={public}"
            );
            assert_eq!(
                admit_live(
                    &verified,
                    &reverse,
                    CONDITION_KEY,
                    &harness.reactor,
                    "nonce:reverse-refused",
                    120_000,
                )
                .unwrap_err()
                .code,
                "dependency_guard",
                "{kind:?} public={public}"
            );
        }
    }

    // An informational edge cannot alter the condition state and remains
    // admitted: the degraded dependency leaves the explicitly-absent condition
    // projected as condition-scoped healthy.
    let informational = dependency_policy(
        harness.selector(),
        dependency_requirement,
        DependencyKindV1::Informational,
        DependencyBehaviorV1 {
            on_unavailable: DependencyEffectV1::Ignore,
            on_degraded: DependencyEffectV1::Ignore,
            on_partial: DependencyEffectV1::Ignore,
            on_unknown: DependencyEffectV1::Ignore,
        },
    );
    let fact = fact_for(&verified, &informational, CONDITION_KEY).expect("fact");
    let live = admit_live(
        &verified,
        &informational,
        CONDITION_KEY,
        &harness.reactor,
        "nonce:dep-info",
        120_000,
    )
    .expect("live");
    let mut facts = vec![fact, dependency_fact];
    facts.sort_by(|left, right| left.fact_id.cmp(&right.fact_id));
    let mut support = vec![live, dependency_support];
    support.sort_by(|left, right| left.evidence_id().cmp(right.evidence_id()));
    let artifact = project(
        &informational,
        &facts,
        &support,
        &[],
        ProjectionMomentV1::now(NOW),
    )
    .expect("projection");
    assert_eq!(artifact.aggregate_state, ProjectedStateV1::Healthy);
    assert_eq!(artifact.components.len(), 1);
    harness.finish();
}

#[test]
fn live_admission_binds_the_policy_selector_to_the_reactor_certificate_lineage() {
    let harness = harness("selector", SyntheticOutcome::ExplicitlyAbsent);
    let mut coproducer = harness.coproducer();
    let verified = harness.verified(&mut coproducer);

    // The policy names another receiver incarnation: `fact_for` accepts the
    // subject binding, but the live query is refused before it is made.
    let mut other_lineage = condition_policy(harness.selector(), true);
    other_lineage.components[0].required_facts[0]
        .live_support
        .receiver_incarnation = "receiver-incarnation:other".to_owned();
    fact_for(&verified, &other_lineage, CONDITION_KEY).expect("subject binding holds");
    assert_eq!(
        admit_live(
            &verified,
            &other_lineage,
            CONDITION_KEY,
            &harness.reactor,
            "nonce:other-lineage",
            120_000,
        )
        .unwrap_err()
        .code,
        "selector_mismatch"
    );

    let mut other_generation = condition_policy(harness.selector(), true);
    other_generation.components[0].required_facts[0]
        .live_support
        .qualified_generation_digest = format!("sha256:{}", "b".repeat(64));
    assert_eq!(
        admit_live(
            &verified,
            &other_generation,
            CONDITION_KEY,
            &harness.reactor,
            "nonce:other-generation",
            120_000,
        )
        .unwrap_err()
        .code,
        "selector_mismatch"
    );

    // A consumer the reactor holds no certificate for.
    let mut other_consumer = condition_policy(harness.selector(), true);
    other_consumer.components[0].required_facts[0]
        .live_support
        .consumer = "consumer:nobody".to_owned();
    assert_eq!(
        admit_live(
            &verified,
            &other_consumer,
            CONDITION_KEY,
            &harness.reactor,
            "nonce:other-consumer",
            120_000,
        )
        .unwrap_err()
        .code,
        "certificate_missing"
    );
    harness.finish();
}

#[test]
fn the_generic_projector_cannot_distinguish_hand_built_facts_known_limit() {
    let harness = harness("hand-built", SyntheticOutcome::Present);
    let mut coproducer = harness.coproducer();
    let verified = harness.verified(&mut coproducer);
    let policy = condition_policy(harness.selector(), false);
    let mut fact = fact_for(&verified, &policy, CONDITION_KEY).expect("fact");
    assert_eq!(fact.availability, AvailabilityV1::Impaired);

    // Known limit, recorded rather than implied away: an embedding that
    // bypasses `fact_for` can hand the projector a fact carrying this
    // adapter's owner string and the opposite axis, and the projector accepts
    // it. The binding between NQ's judgment and the projected axes is a
    // convention of the embedding, enforced only by calling `fact_for`. It is
    // not a type guarantee of the generic projector. Likewise `fact_for`,
    // `admit_live`, and `project` each take their own policy argument; nothing
    // binds the three to one policy except the embedding.
    fact.availability = AvailabilityV1::Available;
    let live = admit_live(
        &verified,
        &policy,
        CONDITION_KEY,
        &harness.reactor,
        "nonce:hand-built",
        120_000,
    )
    .expect("live");
    let artifact =
        project(&policy, &[fact], &[live], &[], ProjectionMomentV1::now(NOW)).expect("projection");
    assert_eq!(
        artifact.aggregate_state,
        ProjectedStateV1::Healthy,
        "the generic projector trusts the caller's fact axes"
    );
    harness.finish();
}

#[test]
fn artifacts_publish_atomically_through_the_unchanged_helper() {
    let harness = harness("publish", SyntheticOutcome::ExplicitlyAbsent);
    let mut coproducer = harness.coproducer();
    let root = tempfile::tempdir().expect("root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    let (first, _) = project_condition(
        &harness,
        &mut coproducer,
        SyntheticOutcome::ExplicitlyAbsent,
        true,
    );
    stage_publication(root.path(), &first)
        .expect("stage")
        .commit()
        .expect("commit");
    assert_eq!(read_current_artifact(root.path()).expect("current"), first);
    std::thread::sleep(Duration::from_millis(1_100));
    let (second, _) = project_condition(&harness, &mut coproducer, SyntheticOutcome::Present, true);
    let mut later = second.clone();
    later.generated_at_unix_ms = first.generated_at_unix_ms + 1_000;
    later.fresh_until_unix_ms = later.fresh_until_unix_ms.max(later.generated_at_unix_ms);
    later.artifact_id = later.compute_id().expect("id");
    stage_publication(root.path(), &later)
        .expect("stage")
        .commit()
        .expect("commit");
    let current = read_current_artifact(root.path()).expect("current");
    assert_eq!(current.aggregate_state, ProjectedStateV1::Degraded);
    assert_eq!(current, later);
    harness.finish();
}

// ---------------------------------------------------------------------------
// Synthetic dependency support, mirroring the generic projector's own test
// fixture. It exists only to exercise dependency edges around the condition
// component; it is not a product adapter.

const DIGEST_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn synthetic_dependency(
    evidence: &str,
    availability: AvailabilityV1,
    impact: ImpactV1,
) -> (FactRequirementV1, SourceFactV1, LiveSupportObservationV1) {
    let context = RelianceContextV1 {
        schema_version: SCHEMA_VERSION_V1,
        activation_id: ContextActivationId::new("activation:dependency"),
        reliance_policy_generation: PolicyGenerationId::new("policy:dependency"),
        reliance_policy_semantic_digest: digest_parts("policy", &[b"dependency"]),
        consumer_profile_generation: ConsumerProfileGenerationId::new("profile:dependency"),
        evaluator_semantic_generation: EvaluatorSemanticGenerationId::new("evaluator:dependency"),
        observer_set_generation: ObserverSetGenerationId::new("observers:dependency"),
        observation_policy_generation: ObservationPolicyGenerationId::new(
            "observation-policy:dependency",
        ),
    };
    let consumer = ConsumerId::new("consumer:dependency");
    let subject_scope = SubjectScopeV1 {
        subject: SubjectId::new("subject:dependency"),
        subject_incarnation: IncarnationId::new("subject-incarnation:dependency"),
        scope: "dependency".to_owned(),
    };
    let binding = QualifiedGenerationBindingV1 {
        schema_version: SCHEMA_VERSION_V1,
        manifest_digest: digest_parts("manifest", &[b"dependency"]),
        qualification_certificate_digest: digest_parts("qualification", &[b"dependency"]),
        activation_receipt_digest: digest_parts("activation", &[b"dependency"]),
        activation_occurrence_id: IncarnationId::new("activation-occurrence:dependency"),
        process_epoch_id: IncarnationId::new("process-epoch:dependency"),
        generation_set: QualifiedGenerationSetV1::from_context(
            subject_scope.subject.clone(),
            consumer.clone(),
            &context,
        ),
        authority_grants: AuthorityGrantsV1::none(),
    };
    let measured_at = 10_000;
    let remaining_ms = 30_000;
    let mut certificate = RelianceSupportCertificateV1 {
        schema_version: SCHEMA_VERSION_V1,
        certificate_id: SupportCertificateId::new("pending"),
        consumer: consumer.clone(),
        subject_scope: subject_scope.clone(),
        context: context.clone(),
        qualified_generation: Some(binding.clone()),
        evaluated_at_monotonic_ms: measured_at,
        receiver_clock_id: "clock:dependency".to_owned(),
        judgment: JudgmentCategoryV1::Current,
        evidence_window_id: EvidenceWindowId::new("window:dependency"),
        supporting_evidence_ids: vec![evidence.to_owned()],
        remote_observation_custody: Vec::new(),
        missing_premises: Vec::new(),
        applicable_contradictions: Vec::new(),
        coverage: CoverageSummaryV1 {
            required: vec!["dependency".to_owned()],
            active: vec!["dependency".to_owned()],
            missing: Vec::new(),
            expired: Vec::new(),
            active_observers: 1,
            required_observers: 1,
            per_tag: Vec::new(),
        },
        earliest_support_expiry_monotonic_ms: Some(measured_at + remaining_ms + 1),
        next_scheduled_reevaluation_monotonic_ms: Some(measured_at + remaining_ms + 1),
        escalation: EscalationStateV1::NotRequested,
        mutation_authority: MutationAuthorityV1::None,
    };
    certificate.certificate_id = certificate.compute_id();
    let request = LivePresentSupportRequestV1 {
        schema: LIVE_PRESENT_SUPPORT_REQUEST_SCHEMA_V1.to_owned(),
        request_nonce: LivePresentSupportNonce::new(format!("nonce:{evidence}")),
        consumer: consumer.clone(),
        subject_scope: subject_scope.clone(),
        reliance_context_digest: context.identity_digest(),
        reliance_context: context.clone(),
        support_certificate_id: certificate.certificate_id.clone(),
        evidence_window_id: certificate.evidence_window_id.clone(),
        qualified_generation_digest: binding.identity_digest(),
        receiver: ReceiverId::new("receiver:dependency"),
        receiver_incarnation: IncarnationId::new("receiver-incarnation:dependency"),
        receiver_epoch_id: IncarnationId::new("receiver-epoch:dependency"),
        receiver_clock_id: ClockId::new("clock:dependency"),
    };
    let anchor = LiveQueryAnchorV1::begin(&request).expect("anchor");
    let response = LivePresentSupportResponseV1::new(
        request.clone(),
        request.receiver.clone(),
        request.receiver_incarnation.clone(),
        request.receiver_epoch_id.clone(),
        request.receiver_clock_id.clone(),
        "std::time::Instant/process-local".to_owned(),
        measured_at,
        LivePresentSupportDispositionV1::SupportedCurrent,
        Some(remaining_ms),
    );
    let live = anchor
        .admit(&request, &response, &certificate, evidence, 120_000)
        .expect("synthetic live support");
    let selector = LiveSupportSelectorV1 {
        consumer: consumer.as_str().to_owned(),
        subject: subject_scope.subject.as_str().to_owned(),
        subject_incarnation: subject_scope.subject_incarnation.as_str().to_owned(),
        scope: subject_scope.scope.clone(),
        reliance_context_digest: context.identity_digest().as_str().to_owned(),
        qualified_generation_digest: binding.identity_digest().as_str().to_owned(),
        receiver: "receiver:dependency".to_owned(),
        receiver_incarnation: "receiver-incarnation:dependency".to_owned(),
        receiver_epoch_id: "receiver-epoch:dependency".to_owned(),
        receiver_clock_id: "clock:dependency".to_owned(),
    };
    let requirement = FactRequirementV1 {
        fact_id: "fact.synthetic.dependency".to_owned(),
        owner: "synthetic-fixture".to_owned(),
        native_schema: "synthetic.status_fact.v1".to_owned(),
        class: SourceFactClassV1::DerivedAdmitted,
        live_support: selector,
    };
    let fact = SourceFactV1 {
        schema: SOURCE_FACT_SCHEMA_V1.to_owned(),
        fact_id: "fact.synthetic.dependency".to_owned(),
        subject_key: "synthetic.dependency".to_owned(),
        owner: "synthetic-fixture".to_owned(),
        native_schema: "synthetic.status_fact.v1".to_owned(),
        native_record_id: "native.dependency".to_owned(),
        class: SourceFactClassV1::DerivedAdmitted,
        evidence_id: evidence.to_owned(),
        availability,
        impact,
        reason_code: "qualified-state".to_owned(),
        basis_digest: DIGEST_A.to_owned(),
        observed_at_unix_ms: None,
    };
    (requirement, fact, live)
}
