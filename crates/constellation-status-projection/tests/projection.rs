mod common;

use std::time::Duration;

use constellation_status_projection::{
    AvailabilityV1, DependencyEffectV1, ImpactV1, MAINTENANCE_ASSERTION_SCHEMA_V1,
    MaintenanceAssertionV1, ModeV1, ProjectedStateV1, ProjectionMomentV1, SourceFactClassV1,
    project,
};

use common::{DIGEST_A, fact, live_support, policy, try_live_support};

const NOW: u64 = 1_900_000_000_000;

#[test]
fn same_inputs_produce_independent_disclosure_bounded_artifacts() {
    let facts = vec![
        fact(
            "fact.internal.cache",
            "internal.cache",
            "evidence:cache",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
        fact(
            "fact.public.api",
            "public.api",
            "evidence:api",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
    ];
    let support = vec![
        live_support("evidence:api", 30_000, 0),
        live_support("evidence:cache", 30_000, 0),
    ];
    let moment = ProjectionMomentV1::now(NOW);
    let public = project(&policy(true), &facts, &support, &[], moment).expect("public projection");
    let operator =
        project(&policy(false), &facts, &support, &[], moment).expect("operator projection");

    assert_eq!(public.aggregate_state, ProjectedStateV1::Healthy);
    assert_eq!(public.components.len(), 1);
    assert_eq!(operator.components.len(), 2);
    assert!(public.basis_digest.is_none());
    assert!(operator.basis_digest.is_some());
    let public_text = String::from_utf8(public.canonical_bytes().expect("canonical")).unwrap();
    assert_eq!(
        public_text,
        include_str!("../fixtures/public-atproto.artifact.json").trim()
    );
    for forbidden in [
        "internal.cache",
        "evidence:cache",
        "native.fact",
        "constellation-nq",
    ] {
        assert!(
            !public_text.contains(forbidden),
            "public output leaked {forbidden}"
        );
    }
}

#[test]
fn missing_or_replayed_support_cannot_establish_health_or_extend_expiry() {
    let facts = vec![
        fact(
            "fact.internal.cache",
            "internal.cache",
            "evidence:cache",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
        fact(
            "fact.public.api",
            "public.api",
            "evidence:api",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
    ];
    let missing = project(
        &policy(true),
        &facts,
        &[],
        &[],
        ProjectionMomentV1::now(NOW),
    )
    .expect("missing support becomes unknown");
    assert_eq!(missing.aggregate_state, ProjectedStateV1::Unknown);
    assert_eq!(missing.generated_at_unix_ms, missing.fresh_until_unix_ms);

    assert!(try_live_support("evidence:api", 1, 2).is_err());
    let short = project(
        &policy(true),
        &facts,
        &[
            live_support("evidence:api", 1_500, 0),
            live_support("evidence:cache", 1_500, 0),
        ],
        &[],
        ProjectionMomentV1::now(NOW),
    )
    .expect("short support projects conservatively");
    assert_eq!(short.fresh_until_unix_ms, NOW + 1_000);
}

#[test]
fn reusing_one_live_observation_never_moves_its_absolute_presentation_deadline() {
    let facts = vec![
        fact(
            "fact.internal.cache",
            "internal.cache",
            "evidence:cache",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
        fact(
            "fact.public.api",
            "public.api",
            "evidence:api",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
    ];
    let support = vec![
        live_support("evidence:api", 30_000, 0),
        live_support("evidence:cache", 30_000, 0),
    ];
    let first = project(
        &policy(true),
        &facts,
        &support,
        &[],
        ProjectionMomentV1::now(NOW),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(5));
    let later = project(
        &policy(true),
        &facts,
        &support,
        &[],
        ProjectionMomentV1::now(NOW + 5),
    )
    .unwrap();
    assert_eq!(first.fresh_until_unix_ms, later.fresh_until_unix_ms);

    let mut expiry_policy = policy(true);
    expiry_policy.timestamp_granularity_ms = 1;
    expiry_policy.admitted_clock_uncertainty_ms = 0;
    let short_support = vec![
        live_support("evidence:api", 5, 0),
        live_support("evidence:cache", 5, 0),
    ];
    std::thread::sleep(Duration::from_millis(10));
    let expired = project(
        &expiry_policy,
        &facts,
        &short_support,
        &[],
        ProjectionMomentV1::now(NOW + 10),
    )
    .unwrap();
    assert_eq!(expired.aggregate_state, ProjectedStateV1::Unknown);
    assert_eq!(expired.generated_at_unix_ms, expired.fresh_until_unix_ms);
}

#[test]
fn state_bearing_dependency_always_bounds_parent_freshness() {
    let facts = vec![
        fact(
            "fact.internal.cache",
            "internal.cache",
            "evidence:cache",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
        fact(
            "fact.public.api",
            "public.api",
            "evidence:api",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
    ];
    let artifact = project(
        &policy(true),
        &facts,
        &[
            live_support("evidence:api", 30_000, 0),
            live_support("evidence:cache", 5_000, 0),
        ],
        &[],
        ProjectionMomentV1::now(NOW),
    )
    .unwrap();
    assert_eq!(artifact.fresh_until_unix_ms, NOW + 4_000);
}

#[test]
fn public_output_is_independent_of_unreferenced_hidden_inventory() {
    let base_policy = policy(true);
    let facts = vec![
        fact(
            "fact.internal.cache",
            "internal.cache",
            "evidence:cache",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
        fact(
            "fact.public.api",
            "public.api",
            "evidence:api",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
    ];
    let make_support = || {
        vec![
            live_support("evidence:api", 30_000, 0),
            live_support("evidence:cache", 30_000, 0),
        ]
    };
    let base = project(
        &base_policy,
        &facts,
        &make_support(),
        &[],
        ProjectionMomentV1::now(NOW),
    )
    .unwrap();

    let mut expanded_policy = base_policy;
    expanded_policy.components.insert(
        1,
        constellation_status_projection::ComponentPolicyV1 {
            key: "internal.lab".to_owned(),
            output: None,
            required_facts: vec![common::requirement("fact.internal.lab")],
            maintenance_assertion_ids: Vec::new(),
        },
    );
    let expanded = project(
        &expanded_policy,
        &facts,
        &make_support(),
        &[],
        ProjectionMomentV1::now(NOW),
    )
    .unwrap();
    assert_eq!(
        base.canonical_bytes().unwrap(),
        expanded.canonical_bytes().unwrap()
    );
}

#[test]
fn direct_service_failure_is_distinct_from_observer_unavailability() {
    let failed_facts = vec![
        fact(
            "fact.internal.cache",
            "internal.cache",
            "evidence:cache",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
        fact(
            "fact.public.api",
            "public.api",
            "evidence:api",
            AvailabilityV1::Unavailable,
            ImpactV1::Total,
        ),
    ];
    let failed = project(
        &policy(true),
        &failed_facts,
        &[
            live_support("evidence:api", 30_000, 0),
            live_support("evidence:cache", 30_000, 0),
        ],
        &[],
        ProjectionMomentV1::now(NOW),
    )
    .unwrap();
    assert_eq!(failed.aggregate_state, ProjectedStateV1::MajorOutage);

    let observer_unavailable = project(
        &policy(true),
        &failed_facts,
        &[live_support("evidence:cache", 30_000, 0)],
        &[],
        ProjectionMomentV1::now(NOW),
    )
    .unwrap();
    assert_eq!(
        observer_unavailable.aggregate_state,
        ProjectedStateV1::Unknown
    );
}

#[test]
fn source_owner_schema_and_class_are_policy_bound() {
    let mut api = fact(
        "fact.public.api",
        "public.api",
        "evidence:api",
        AvailabilityV1::Available,
        ImpactV1::None,
    );
    api.owner = "substituted-owner".to_owned();
    let facts = vec![
        fact(
            "fact.internal.cache",
            "internal.cache",
            "evidence:cache",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
        api,
    ];
    let artifact = project(
        &policy(true),
        &facts,
        &[
            live_support("evidence:api", 30_000, 0),
            live_support("evidence:cache", 30_000, 0),
        ],
        &[],
        ProjectionMomentV1::now(NOW),
    )
    .unwrap();
    assert_eq!(artifact.aggregate_state, ProjectedStateV1::Unknown);
}

#[test]
fn live_support_consumer_and_lineage_are_policy_bound() {
    let mut mismatched = policy(true);
    mismatched.components[1].required_facts[0]
        .live_support
        .consumer = "consumer:other".to_owned();
    let artifact = project(
        &mismatched,
        &[
            fact(
                "fact.internal.cache",
                "internal.cache",
                "evidence:cache",
                AvailabilityV1::Available,
                ImpactV1::None,
            ),
            fact(
                "fact.public.api",
                "public.api",
                "evidence:api",
                AvailabilityV1::Available,
                ImpactV1::None,
            ),
        ],
        &[
            live_support("evidence:api", 30_000, 0),
            live_support("evidence:cache", 30_000, 0),
        ],
        &[],
        ProjectionMomentV1::now(NOW),
    )
    .unwrap();
    assert_eq!(artifact.aggregate_state, ProjectedStateV1::Unknown);
}

#[test]
fn contradictory_or_non_state_facts_become_unknown() {
    let mut historical = fact(
        "fact.public.api",
        "public.api",
        "evidence:api",
        AvailabilityV1::Available,
        ImpactV1::None,
    );
    historical.class = SourceFactClassV1::QualificationLifecycle;
    let facts = vec![
        fact(
            "fact.internal.cache",
            "internal.cache",
            "evidence:cache",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
        historical,
    ];
    let artifact = project(
        &policy(true),
        &facts,
        &[
            live_support("evidence:api", 30_000, 0),
            live_support("evidence:cache", 30_000, 0),
        ],
        &[],
        ProjectionMomentV1::now(NOW),
    )
    .expect("qualification is not health");
    assert_eq!(artifact.aggregate_state, ProjectedStateV1::Unknown);
}

#[test]
fn dependency_behaviors_are_explicit_and_maintenance_does_not_override_truth() {
    let facts = vec![
        fact(
            "fact.internal.cache",
            "internal.cache",
            "evidence:cache",
            AvailabilityV1::Unavailable,
            ImpactV1::Total,
        ),
        fact(
            "fact.public.api",
            "public.api",
            "evidence:api",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
    ];
    let maintenance = vec![MaintenanceAssertionV1 {
        schema: MAINTENANCE_ASSERTION_SCHEMA_V1.to_owned(),
        assertion_id: "maintenance.public.api".to_owned(),
        component_key: "public.api".to_owned(),
        active: true,
        basis_digest: DIGEST_A.to_owned(),
    }];
    let support = vec![
        live_support("evidence:api", 30_000, 0),
        live_support("evidence:cache", 30_000, 0),
    ];
    let artifact = project(
        &policy(true),
        &facts,
        &support,
        &maintenance,
        ProjectionMomentV1::now(NOW),
    )
    .expect("dependency conflict is represented");
    assert_eq!(artifact.aggregate_state, ProjectedStateV1::Unknown);
    assert_eq!(artifact.components[0].mode, ModeV1::Maintenance);

    let mut soft = policy(true);
    soft.dependencies[0].kind = constellation_status_projection::DependencyKindV1::Soft;
    soft.dependencies[0].behavior.on_unavailable = DependencyEffectV1::Degrade;
    let artifact = project(
        &soft,
        &facts,
        &[
            live_support("evidence:api", 30_000, 0),
            live_support("evidence:cache", 30_000, 0),
        ],
        &[],
        ProjectionMomentV1::now(NOW),
    )
    .expect("soft dependency");
    assert_eq!(artifact.aggregate_state, ProjectedStateV1::Degraded);

    let mut informational = policy(true);
    informational.dependencies[0].kind =
        constellation_status_projection::DependencyKindV1::Informational;
    informational.dependencies[0].behavior.on_unavailable = DependencyEffectV1::Ignore;
    informational.dependencies[0].behavior.on_degraded = DependencyEffectV1::Ignore;
    informational.dependencies[0].behavior.on_partial = DependencyEffectV1::Ignore;
    informational.dependencies[0].behavior.on_unknown = DependencyEffectV1::Ignore;
    let artifact = project(
        &informational,
        &facts,
        &[
            live_support("evidence:api", 30_000, 0),
            live_support("evidence:cache", 30_000, 0),
        ],
        &[],
        ProjectionMomentV1::now(NOW),
    )
    .expect("informational dependency");
    assert_eq!(artifact.aggregate_state, ProjectedStateV1::Healthy);
}

#[test]
fn serialization_and_identity_are_deterministic_and_extensions_fail_closed() {
    let facts = vec![
        fact(
            "fact.internal.cache",
            "internal.cache",
            "evidence:cache",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
        fact(
            "fact.public.api",
            "public.api",
            "evidence:api",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
    ];
    let make = || {
        project(
            &policy(true),
            &facts,
            &[
                live_support("evidence:api", 30_000, 0),
                live_support("evidence:cache", 30_000, 0),
            ],
            &[],
            ProjectionMomentV1::now(NOW),
        )
        .unwrap()
    };
    let first = make();
    let second = make();
    assert_eq!(first, second);
    assert_eq!(
        first.canonical_bytes().unwrap(),
        second.canonical_bytes().unwrap()
    );
    assert_eq!(first.artifact_id, second.artifact_id);

    let text = String::from_utf8(first.canonical_bytes().unwrap()).unwrap();
    let extended = text.replacen('{', "{\"unexpected\":true,", 1);
    assert!(
        constellation_status_projection::StatusArtifactV1::decode_canonical(extended.as_bytes())
            .is_err()
    );
}

#[test]
fn checked_in_synthetic_policies_are_valid_and_audience_specific() {
    let public: constellation_status_projection::ProjectionPolicyV1 =
        serde_json::from_str(include_str!("../fixtures/public-atproto.policy.json")).unwrap();
    let operator: constellation_status_projection::ProjectionPolicyV1 = serde_json::from_str(
        include_str!("../fixtures/neutral-zone-operator.policy.json"),
    )
    .unwrap();
    public.validate().unwrap();
    operator.validate().unwrap();
    assert_eq!(public, policy(true));
    assert_eq!(operator, policy(false));
    assert_ne!(
        public.disclosure_digest().unwrap(),
        operator.disclosure_digest().unwrap()
    );
}

#[test]
fn dependency_and_public_disclosure_policies_fail_closed() {
    let mut ignored_unknown = policy(true);
    ignored_unknown.dependencies[0].behavior.on_unknown = DependencyEffectV1::Ignore;
    assert_eq!(
        ignored_unknown.validate().unwrap_err().code,
        "invalid_dependency"
    );

    let mut stateful_information = policy(true);
    stateful_information.dependencies[0].kind =
        constellation_status_projection::DependencyKindV1::Informational;
    assert_eq!(
        stateful_information.validate().unwrap_err().code,
        "invalid_informational_dependency"
    );

    let mut public_basis = policy(true);
    public_basis.disclosure.include_basis_digest = true;
    assert_eq!(
        public_basis.validate().unwrap_err().code,
        "public_disclosure"
    );
}

#[test]
fn artifact_identity_covers_the_complete_serialized_surface() {
    let artifact = project(
        &policy(true),
        &[
            fact(
                "fact.internal.cache",
                "internal.cache",
                "evidence:cache",
                AvailabilityV1::Available,
                ImpactV1::None,
            ),
            fact(
                "fact.public.api",
                "public.api",
                "evidence:api",
                AvailabilityV1::Available,
                ImpactV1::None,
            ),
        ],
        &[
            live_support("evidence:api", 30_000, 0),
            live_support("evidence:cache", 30_000, 0),
        ],
        &[],
        ProjectionMomentV1::now(NOW),
    )
    .unwrap();
    let mut changed = artifact.clone();
    changed.non_authorization.push('!');
    assert_ne!(
        artifact.compute_id().unwrap(),
        changed.compute_id().unwrap()
    );
    assert_eq!(changed.validate().unwrap_err().code, "authority_boundary");
}
