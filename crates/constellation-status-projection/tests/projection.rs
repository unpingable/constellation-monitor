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
            "fact.synthetic.dependency",
            "synthetic.dependency",
            "evidence:subordinate",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
        fact(
            "fact.synthetic.service",
            "synthetic.service",
            "evidence:service",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
    ];
    let support = vec![
        live_support("evidence:service", 30_000, 0),
        live_support("evidence:subordinate", 30_000, 0),
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
        include_str!("../fixtures/synthetic-public-reduction.artifact.json").trim()
    );
    for forbidden in [
        "synthetic.dependency",
        "fact.synthetic.dependency",
        "evidence:subordinate",
        "native.fact",
        "constellation-nq",
        "synthetic-fixture",
        "synthetic.status_fact.v1",
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
            "fact.synthetic.dependency",
            "synthetic.dependency",
            "evidence:subordinate",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
        fact(
            "fact.synthetic.service",
            "synthetic.service",
            "evidence:service",
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

    assert!(try_live_support("evidence:service", 1, 2).is_err());
    let short = project(
        &policy(true),
        &facts,
        &[
            live_support("evidence:service", 1_500, 0),
            live_support("evidence:subordinate", 1_500, 0),
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
            "fact.synthetic.dependency",
            "synthetic.dependency",
            "evidence:subordinate",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
        fact(
            "fact.synthetic.service",
            "synthetic.service",
            "evidence:service",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
    ];
    let support = vec![
        live_support("evidence:service", 30_000, 0),
        live_support("evidence:subordinate", 30_000, 0),
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
        live_support("evidence:service", 5, 0),
        live_support("evidence:subordinate", 5, 0),
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
            "fact.synthetic.dependency",
            "synthetic.dependency",
            "evidence:subordinate",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
        fact(
            "fact.synthetic.service",
            "synthetic.service",
            "evidence:service",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
    ];
    let artifact = project(
        &policy(true),
        &facts,
        &[
            live_support("evidence:service", 30_000, 0),
            live_support("evidence:subordinate", 5_000, 0),
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
            "fact.synthetic.dependency",
            "synthetic.dependency",
            "evidence:subordinate",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
        fact(
            "fact.synthetic.service",
            "synthetic.service",
            "evidence:service",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
    ];
    let make_support = || {
        vec![
            live_support("evidence:service", 30_000, 0),
            live_support("evidence:subordinate", 30_000, 0),
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
            key: "synthetic.lab".to_owned(),
            output: None,
            required_facts: vec![common::requirement("fact.synthetic.lab")],
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
            "fact.synthetic.dependency",
            "synthetic.dependency",
            "evidence:subordinate",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
        fact(
            "fact.synthetic.service",
            "synthetic.service",
            "evidence:service",
            AvailabilityV1::Unavailable,
            ImpactV1::Total,
        ),
    ];
    let failed = project(
        &policy(true),
        &failed_facts,
        &[
            live_support("evidence:service", 30_000, 0),
            live_support("evidence:subordinate", 30_000, 0),
        ],
        &[],
        ProjectionMomentV1::now(NOW),
    )
    .unwrap();
    assert_eq!(failed.aggregate_state, ProjectedStateV1::MajorOutage);

    let observer_unavailable = project(
        &policy(true),
        &failed_facts,
        &[live_support("evidence:subordinate", 30_000, 0)],
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
        "fact.synthetic.service",
        "synthetic.service",
        "evidence:service",
        AvailabilityV1::Available,
        ImpactV1::None,
    );
    api.owner = "substituted-owner".to_owned();
    let facts = vec![
        fact(
            "fact.synthetic.dependency",
            "synthetic.dependency",
            "evidence:subordinate",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
        api,
    ];
    let artifact = project(
        &policy(true),
        &facts,
        &[
            live_support("evidence:service", 30_000, 0),
            live_support("evidence:subordinate", 30_000, 0),
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
                "fact.synthetic.dependency",
                "synthetic.dependency",
                "evidence:subordinate",
                AvailabilityV1::Available,
                ImpactV1::None,
            ),
            fact(
                "fact.synthetic.service",
                "synthetic.service",
                "evidence:service",
                AvailabilityV1::Available,
                ImpactV1::None,
            ),
        ],
        &[
            live_support("evidence:service", 30_000, 0),
            live_support("evidence:subordinate", 30_000, 0),
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
        "fact.synthetic.service",
        "synthetic.service",
        "evidence:service",
        AvailabilityV1::Available,
        ImpactV1::None,
    );
    historical.class = SourceFactClassV1::QualificationLifecycle;
    let facts = vec![
        fact(
            "fact.synthetic.dependency",
            "synthetic.dependency",
            "evidence:subordinate",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
        historical,
    ];
    let artifact = project(
        &policy(true),
        &facts,
        &[
            live_support("evidence:service", 30_000, 0),
            live_support("evidence:subordinate", 30_000, 0),
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
            "fact.synthetic.dependency",
            "synthetic.dependency",
            "evidence:subordinate",
            AvailabilityV1::Unavailable,
            ImpactV1::Total,
        ),
        fact(
            "fact.synthetic.service",
            "synthetic.service",
            "evidence:service",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
    ];
    let maintenance = vec![MaintenanceAssertionV1 {
        schema: MAINTENANCE_ASSERTION_SCHEMA_V1.to_owned(),
        assertion_id: "maintenance.synthetic.service".to_owned(),
        component_key: "synthetic.service".to_owned(),
        active: true,
        basis_digest: DIGEST_A.to_owned(),
    }];
    let support = vec![
        live_support("evidence:service", 30_000, 0),
        live_support("evidence:subordinate", 30_000, 0),
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
            live_support("evidence:service", 30_000, 0),
            live_support("evidence:subordinate", 30_000, 0),
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
            live_support("evidence:service", 30_000, 0),
            live_support("evidence:subordinate", 30_000, 0),
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
            "fact.synthetic.dependency",
            "synthetic.dependency",
            "evidence:subordinate",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
        fact(
            "fact.synthetic.service",
            "synthetic.service",
            "evidence:service",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
    ];
    let make = || {
        project(
            &policy(true),
            &facts,
            &[
                live_support("evidence:service", 30_000, 0),
                live_support("evidence:subordinate", 30_000, 0),
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
    let public: constellation_status_projection::ProjectionPolicyV1 = serde_json::from_str(
        include_str!("../fixtures/synthetic-public-reduction.policy.json"),
    )
    .unwrap();
    let operator: constellation_status_projection::ProjectionPolicyV1 = serde_json::from_str(
        include_str!("../fixtures/synthetic-operator-reduction.policy.json"),
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
                "fact.synthetic.dependency",
                "synthetic.dependency",
                "evidence:subordinate",
                AvailabilityV1::Available,
                ImpactV1::None,
            ),
            fact(
                "fact.synthetic.service",
                "synthetic.service",
                "evidence:service",
                AvailabilityV1::Available,
                ImpactV1::None,
            ),
        ],
        &[
            live_support("evidence:service", 30_000, 0),
            live_support("evidence:subordinate", 30_000, 0),
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

#[test]
fn projection_output_cannot_be_re_ingested_as_source_evidence() {
    use constellation_status_projection::{
        PROJECTOR_OWNED_SCHEMAS, PROJECTOR_OWNER, STATUS_ARTIFACT_SCHEMA_V1,
    };

    // A policy that would require a status artifact as a fact is refused.
    for schema in PROJECTOR_OWNED_SCHEMAS {
        let mut requires_projection = policy(true);
        requires_projection.components[1].required_facts[0].native_schema = schema.to_owned();
        assert_eq!(
            requires_projection.validate().unwrap_err().code,
            "projection_reingestion",
            "{schema}"
        );
    }
    let mut owned_by_projector = policy(true);
    owned_by_projector.components[1].required_facts[0].owner = PROJECTOR_OWNER.to_owned();
    assert_eq!(
        owned_by_projector.validate().unwrap_err().code,
        "projection_reingestion"
    );

    // A fact built from a projection's own output is refused, whatever its
    // class and whoever offers it.
    let artifact = project(
        &policy(true),
        &[
            fact(
                "fact.synthetic.dependency",
                "synthetic.dependency",
                "evidence:subordinate",
                AvailabilityV1::Available,
                ImpactV1::None,
            ),
            fact(
                "fact.synthetic.service",
                "synthetic.service",
                "evidence:service",
                AvailabilityV1::Available,
                ImpactV1::None,
            ),
        ],
        &[
            live_support("evidence:service", 30_000, 0),
            live_support("evidence:subordinate", 30_000, 0),
        ],
        &[],
        ProjectionMomentV1::now(NOW),
    )
    .unwrap();
    let mut from_artifact = fact(
        "fact.synthetic.service",
        "synthetic.service",
        "evidence:service",
        AvailabilityV1::Available,
        ImpactV1::None,
    );
    from_artifact.native_schema = STATUS_ARTIFACT_SCHEMA_V1.to_owned();
    from_artifact.native_record_id = artifact.artifact_id.clone();
    from_artifact.basis_digest = artifact.artifact_id;
    assert_eq!(
        from_artifact.validate().unwrap_err().code,
        "projection_reingestion"
    );
    let mut owner_is_projector = fact(
        "fact.synthetic.service",
        "synthetic.service",
        "evidence:service",
        AvailabilityV1::Available,
        ImpactV1::None,
    );
    owner_is_projector.owner = PROJECTOR_OWNER.to_owned();
    assert_eq!(
        owner_is_projector.validate().unwrap_err().code,
        "projection_reingestion"
    );
    let refused = project(
        &policy(true),
        &[
            fact(
                "fact.synthetic.dependency",
                "synthetic.dependency",
                "evidence:subordinate",
                AvailabilityV1::Available,
                ImpactV1::None,
            ),
            owner_is_projector,
        ],
        &[
            live_support("evidence:service", 30_000, 0),
            live_support("evidence:subordinate", 30_000, 0),
        ],
        &[],
        ProjectionMomentV1::now(NOW),
    )
    .unwrap_err();
    assert_eq!(refused.code, "projection_reingestion");
}

#[test]
fn observation_windows_are_refused_in_v1() {
    let mut windowed = policy(false);
    windowed.disclosure.include_observation_window = true;
    assert_eq!(
        windowed.validate().unwrap_err().code,
        "observation_window_unsupported"
    );
    let artifact = project(
        &policy(false),
        &[
            fact(
                "fact.synthetic.dependency",
                "synthetic.dependency",
                "evidence:subordinate",
                AvailabilityV1::Available,
                ImpactV1::None,
            ),
            fact(
                "fact.synthetic.service",
                "synthetic.service",
                "evidence:service",
                AvailabilityV1::Available,
                ImpactV1::None,
            ),
        ],
        &[
            live_support("evidence:service", 30_000, 0),
            live_support("evidence:subordinate", 30_000, 0),
        ],
        &[],
        ProjectionMomentV1::now(NOW),
    )
    .unwrap();
    assert!(artifact.observation_window.is_none());
    let mut with_window = artifact;
    with_window.observation_window = Some(constellation_status_projection::ObservationWindowV1 {
        earliest_observed_at_unix_ms: NOW,
        latest_observed_at_unix_ms: NOW,
    });
    with_window.artifact_id = with_window.compute_id().unwrap();
    assert_eq!(
        with_window.validate().unwrap_err().code,
        "observation_window_unsupported"
    );
}

#[test]
fn every_schema_string_this_crate_emits_is_refused_as_a_fact_schema() {
    use constellation_status_projection::{
        COMPONENT_DETAIL_SCHEMA_V1, CURRENT_POINTER_SCHEMA_V1, MAINTENANCE_ASSERTION_SCHEMA_V1,
        PROJECTION_BASIS_SCHEMA_V1, PROJECTION_DISCLOSURE_SCHEMA_V1, PROJECTION_POLICY_SCHEMA_V1,
        PROJECTOR_OWNED_SCHEMAS, SOURCE_FACT_SCHEMA_V1, STATUS_ARTIFACT_SCHEMA_V1,
    };
    let mut expected = vec![
        PROJECTION_POLICY_SCHEMA_V1,
        SOURCE_FACT_SCHEMA_V1,
        COMPONENT_DETAIL_SCHEMA_V1,
        MAINTENANCE_ASSERTION_SCHEMA_V1,
        STATUS_ARTIFACT_SCHEMA_V1,
        CURRENT_POINTER_SCHEMA_V1,
        PROJECTION_DISCLOSURE_SCHEMA_V1,
        PROJECTION_BASIS_SCHEMA_V1,
    ];
    let mut owned = PROJECTOR_OWNED_SCHEMAS.to_vec();
    expected.sort_unstable();
    owned.sort_unstable();
    assert_eq!(owned, expected);
    assert!(
        owned
            .iter()
            .all(|schema| schema.starts_with("constellation.status_"))
    );
}

#[test]
fn owner_details_attach_only_to_single_fact_components_and_never_change_the_decision() {
    use common::requirement;
    use constellation_status_projection::{
        COMPONENT_DETAIL_SCHEMA_V1, ComponentDetailV1, ComponentOutputFieldV1, RenderedStatusV1,
        StatusArtifactV1, project_with_details, render_status,
    };

    let mut policy = policy(false);
    policy
        .disclosure
        .component_fields
        .push(ComponentOutputFieldV1::Detail);
    policy.disclosure.component_fields.sort();
    // The service component combines two facts; the dependency has one.
    policy.components[1].required_facts = vec![
        requirement("fact.synthetic.service"),
        requirement("fact.synthetic.service.second"),
    ];
    policy.validate().expect("policy");
    let facts = vec![
        fact(
            "fact.synthetic.dependency",
            "synthetic.dependency",
            "evidence:subordinate",
            AvailabilityV1::Indeterminate,
            ImpactV1::Indeterminate,
        ),
        fact(
            "fact.synthetic.service",
            "synthetic.service",
            "evidence:service",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
        fact(
            "fact.synthetic.service.second",
            "synthetic.service",
            "evidence:service-second",
            AvailabilityV1::Available,
            ImpactV1::None,
        ),
    ];
    let support = vec![
        live_support("evidence:service", 30_000, 0),
        live_support("evidence:service-second", 30_000, 0),
        live_support("evidence:subordinate", 30_000, 0),
    ];
    let detail = |fact_id: &str, text: &str| ComponentDetailV1 {
        schema: COMPONENT_DETAIL_SCHEMA_V1.to_owned(),
        fact_id: fact_id.to_owned(),
        text: text.to_owned(),
    };
    let details = vec![
        detail("fact.synthetic.dependency", "Dependency owner text"),
        detail("fact.synthetic.service", "First service owner text"),
        detail("fact.synthetic.service.second", "Second service owner text"),
    ];
    let moment = ProjectionMomentV1::now(NOW);
    let with = project_with_details(&policy, &facts, &support, &[], &details, moment)
        .expect("details on a multi-fact component never refuse the projection");
    let without = project(&policy, &facts, &support, &[], moment).expect("projection");

    let strip = |artifact: &StatusArtifactV1| {
        let mut artifact = artifact.clone();
        artifact.artifact_id.clear();
        for component in &mut artifact.components {
            component.detail = None;
        }
        artifact
    };
    assert_eq!(strip(&with), strip(&without));
    let by_id = |id: &str| {
        with.components
            .iter()
            .find(|component| component.id == id)
            .expect("component")
            .detail
            .clone()
    };
    assert_eq!(
        by_id("subordinate").as_deref(),
        Some("Dependency owner text")
    );
    // Neither combined nor chosen: the combining component carries none.
    assert_eq!(by_id("service"), None);

    // The unavailable page dates the detail by the projection instant.
    let RenderedStatusV1::StatusUnavailable { html } =
        render_status(&with, with.fresh_until_unix_ms, 0).expect("render")
    else {
        panic!("an expired artifact is never current")
    };
    assert!(html.contains("No current conclusion is supported."));
    assert!(html.contains("Details as of the projection at 2030-03-17T17:46:40Z (UTC)."));
    assert!(html.contains("Detail: Dependency owner text"));
    assert!(!html.contains("service owner text"));
}
