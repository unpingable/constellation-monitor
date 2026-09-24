use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::{
    ComponentDetailV1, ComponentOutputFieldV1, DependencyEffectV1, DependencyKindV1, FreshnessV1,
    LiveSupportObservationV1, MaintenanceAssertionV1, ModeV1, PROJECTION_BASIS_SCHEMA_V1,
    ProjectedComponentV1, ProjectedStateV1, ProjectionError, ProjectionMomentV1,
    ProjectionPolicyV1, STATUS_ARTIFACT_SCHEMA_V1, SourceFactV1, StatusArtifactV1,
    canonical_digest, map_state, safe_reason_map,
};

#[derive(Clone, Debug)]
struct ComponentEvaluation {
    direct_state: ProjectedStateV1,
    state: ProjectedStateV1,
    mode: ModeV1,
    remaining_ms: Option<u64>,
}

#[derive(Serialize)]
struct BasisEntry<'a> {
    evidence_id: &'a str,
    certificate_id: &'a str,
    response_digest: &'a str,
    usable_remaining_ms: u64,
}

#[derive(Serialize)]
struct ProjectionBasis<'a> {
    schema: &'static str,
    policy_digest: &'a str,
    facts: &'a [SourceFactV1],
    maintenance: &'a [MaintenanceAssertionV1],
    support: Vec<BasisEntry<'a>>,
}

pub fn project(
    policy: &ProjectionPolicyV1,
    facts: &[SourceFactV1],
    support: &[LiveSupportObservationV1],
    maintenance: &[MaintenanceAssertionV1],
    moment: ProjectionMomentV1,
) -> Result<StatusArtifactV1, ProjectionError> {
    project_with_details(policy, facts, support, maintenance, &[], moment)
}

/// [`project`] with owner-supplied display-only details. Each detail names
/// one fact; it is copied onto a component whose only required fact is that
/// fact when the policy discloses [`ComponentOutputFieldV1::Detail`], and is
/// otherwise dropped (a component requiring several facts carries none). Details take no part in any evaluation, window, state, or basis
/// digest: the projection decision is identical with or without them.
pub fn project_with_details(
    policy: &ProjectionPolicyV1,
    facts: &[SourceFactV1],
    support: &[LiveSupportObservationV1],
    maintenance: &[MaintenanceAssertionV1],
    details: &[ComponentDetailV1],
    moment: ProjectionMomentV1,
) -> Result<StatusArtifactV1, ProjectionError> {
    policy.validate()?;
    validate_inputs(facts, support, maintenance)?;
    let details_by_fact = validate_details(details, facts)?;

    let facts_by_id = facts
        .iter()
        .map(|fact| (fact.fact_id.as_str(), fact))
        .collect::<BTreeMap<_, _>>();
    let support_by_evidence = support
        .iter()
        .map(|entry| (entry.evidence_id(), entry))
        .collect::<BTreeMap<_, _>>();
    let maintenance_by_id = maintenance
        .iter()
        .map(|assertion| (assertion.assertion_id.as_str(), assertion))
        .collect::<BTreeMap<_, _>>();

    let mut evaluations = BTreeMap::new();
    for component in &policy.components {
        let evaluation = evaluate_direct(
            &component.key,
            &component.required_facts,
            &component.maintenance_assertion_ids,
            &facts_by_id,
            &support_by_evidence,
            &maintenance_by_id,
            moment,
        );
        evaluations.insert(component.key.as_str(), evaluation);
    }

    for key in dependency_order(policy)? {
        apply_dependencies(key, policy, &mut evaluations)?;
    }

    let reasons = safe_reason_map(&policy.disclosure);
    let mut components = policy
        .components
        .iter()
        .filter_map(|component| {
            let output = component.output.as_ref()?;
            let evaluation = evaluations
                .get(component.key.as_str())
                .expect("validated component has an evaluation");
            // A detail explains one owner's fact, so it is shown only on a
            // component whose sole required fact is that fact. A component
            // that combines several facts shows none: owner texts are never
            // combined, never moved onto another owner's component, and
            // their presence never turns a projection into a refusal.
            let detail = match component.required_facts.as_slice() {
                [requirement]
                    if policy
                        .disclosure
                        .component_fields
                        .contains(&ComponentOutputFieldV1::Detail) =>
                {
                    details_by_fact
                        .get(requirement.fact_id.as_str())
                        .map(|text| (*text).to_owned())
                }
                _ => None,
            };
            Some(ProjectedComponentV1 {
                id: output.id.clone(),
                display_name: policy
                    .disclosure
                    .component_fields
                    .contains(&ComponentOutputFieldV1::DisplayName)
                    .then(|| output.display_name.clone()),
                state: evaluation.state,
                mode: evaluation.mode,
                reason: policy
                    .disclosure
                    .component_fields
                    .contains(&ComponentOutputFieldV1::Reason)
                    .then(|| reasons.get(&evaluation.state).cloned())
                    .flatten(),
                detail,
            })
        })
        .collect::<Vec<_>>();
    components.sort_by(|left, right| left.id.cmp(&right.id));

    let root = evaluations
        .get(policy.root_component.as_str())
        .ok_or_else(|| ProjectionError::new("missing_root", "root evaluation is absent"))?;
    let visible_keys = policy
        .components
        .iter()
        .filter(|component| component.output.is_some())
        .map(|component| component.key.as_str())
        .collect::<Vec<_>>();
    let positive_windows = visible_keys
        .iter()
        .filter_map(|key| {
            let evaluation = evaluations.get(key)?;
            (evaluation.state != ProjectedStateV1::Unknown).then_some(evaluation.remaining_ms)
        })
        .collect::<Vec<_>>();
    let all_positive_bounded = positive_windows.iter().all(Option::is_some);
    let minimum_support_ms = all_positive_bounded
        .then(|| positive_windows.into_iter().flatten().min())
        .flatten();
    let usable_window_ms = minimum_support_ms
        .map(|remaining| remaining.min(policy.maximum_age_ms))
        .and_then(|remaining| remaining.checked_sub(policy.admitted_clock_uncertainty_ms))
        .filter(|remaining| *remaining > 0);

    let generated_at = floor_time(moment.generated_at_unix_ms, policy.timestamp_granularity_ms);
    let fresh_until = usable_window_ms
        .and_then(|window| moment.generated_at_unix_ms.checked_add(window))
        .map(|deadline| floor_time(deadline, policy.timestamp_granularity_ms))
        .filter(|deadline| *deadline > generated_at)
        .unwrap_or(generated_at);
    let aggregate_state = if fresh_until == generated_at {
        for component in &mut components {
            component.state = ProjectedStateV1::Unknown;
            if policy
                .disclosure
                .component_fields
                .contains(&ComponentOutputFieldV1::Reason)
            {
                component.reason = reasons.get(&ProjectedStateV1::Unknown).cloned();
            }
        }
        ProjectedStateV1::Unknown
    } else {
        root.state
    };

    let full_policy_digest = policy.full_digest()?;
    let policy_digest = policy.disclosure_digest()?;
    let support_basis = support
        .iter()
        .map(|entry| BasisEntry {
            evidence_id: entry.evidence_id(),
            certificate_id: entry.certificate_id(),
            response_digest: entry.response_digest(),
            usable_remaining_ms: entry
                .usable_remaining_ms_at(moment.monotonic_now)
                .unwrap_or(0),
        })
        .collect::<Vec<_>>();
    let basis_digest = policy.disclosure.include_basis_digest.then(|| {
        canonical_digest(&ProjectionBasis {
            schema: PROJECTION_BASIS_SCHEMA_V1,
            policy_digest: &full_policy_digest,
            facts,
            maintenance,
            support: support_basis,
        })
    });
    let basis_digest = basis_digest.transpose()?;

    let mut artifact = StatusArtifactV1 {
        schema: STATUS_ARTIFACT_SCHEMA_V1.to_owned(),
        artifact_id: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .to_owned(),
        projection_id: policy.projection_id.clone(),
        projection_generation: policy.generation.clone(),
        policy_digest,
        generated_at_unix_ms: generated_at,
        fresh_until_unix_ms: fresh_until,
        admitted_clock_uncertainty_ms: policy.admitted_clock_uncertainty_ms,
        // v1 refuses `include_observation_window` at policy validation.
        observation_window: None,
        aggregate_state,
        components,
        basis_digest,
        mutation_authority: "none".to_owned(),
        non_authorization: "Derived status is read-only and grants no authority or permission."
            .to_owned(),
    };
    artifact.artifact_id = artifact.compute_id()?;
    artifact.validate()?;
    Ok(artifact)
}

/// Owner details must be well formed, name a supplied fact, and name each
/// fact at most once. Their text is never read.
fn validate_details<'a>(
    details: &'a [ComponentDetailV1],
    facts: &[SourceFactV1],
) -> Result<BTreeMap<&'a str, &'a str>, ProjectionError> {
    let mut by_fact = BTreeMap::new();
    for detail in details {
        detail.validate()?;
        if !facts.iter().any(|fact| fact.fact_id == detail.fact_id) {
            return Err(ProjectionError::new(
                "unknown_detail_fact",
                "an owner detail names a fact that was not supplied",
            ));
        }
        if by_fact
            .insert(detail.fact_id.as_str(), detail.text.as_str())
            .is_some()
        {
            return Err(ProjectionError::new(
                "duplicate_detail",
                "an owner detail names the same fact twice",
            ));
        }
    }
    Ok(by_fact)
}

fn validate_inputs(
    facts: &[SourceFactV1],
    support: &[LiveSupportObservationV1],
    maintenance: &[MaintenanceAssertionV1],
) -> Result<(), ProjectionError> {
    if facts.len() > crate::MAX_FACTS {
        return Err(ProjectionError::new("input_bound", "too many source facts"));
    }
    let mut prior_fact = None;
    for fact in facts {
        fact.validate()?;
        if prior_fact.is_some_and(|prior| prior >= fact.fact_id.as_str()) {
            return Err(ProjectionError::new(
                "noncanonical_order",
                "facts must be strictly ordered",
            ));
        }
        prior_fact = Some(fact.fact_id.as_str());
    }
    let mut prior_support = None;
    for entry in support {
        if prior_support.is_some_and(|prior| prior >= entry.evidence_id()) {
            return Err(ProjectionError::new(
                "noncanonical_order",
                "live support observations must be strictly ordered by evidence id",
            ));
        }
        prior_support = Some(entry.evidence_id());
    }
    let mut prior_assertion = None;
    for assertion in maintenance {
        assertion.validate()?;
        if prior_assertion.is_some_and(|prior| prior >= assertion.assertion_id.as_str()) {
            return Err(ProjectionError::new(
                "noncanonical_order",
                "maintenance assertions must be strictly ordered",
            ));
        }
        prior_assertion = Some(assertion.assertion_id.as_str());
    }
    Ok(())
}

fn evaluate_direct(
    component_key: &str,
    fact_requirements: &[crate::FactRequirementV1],
    maintenance_ids: &[String],
    facts: &BTreeMap<&str, &SourceFactV1>,
    support: &BTreeMap<&str, &LiveSupportObservationV1>,
    maintenance: &BTreeMap<&str, &MaintenanceAssertionV1>,
    moment: ProjectionMomentV1,
) -> ComponentEvaluation {
    let maintenance_active = maintenance_ids
        .iter()
        .filter_map(|id| maintenance.get(id.as_str()))
        .any(|assertion| assertion.active && assertion.component_key == component_key);
    let mode = if maintenance_active {
        ModeV1::Maintenance
    } else {
        ModeV1::Normal
    };

    if fact_requirements.is_empty() {
        return unknown_evaluation(mode, FreshnessV1::Missing);
    }
    let mut axes = None;
    let mut remaining_ms: Option<u64> = None;
    for requirement in fact_requirements {
        let Some(fact) = facts.get(requirement.fact_id.as_str()) else {
            return unknown_evaluation(mode, FreshnessV1::Missing);
        };
        if fact.subject_key != component_key
            || fact.owner != requirement.owner
            || fact.native_schema != requirement.native_schema
            || fact.class != requirement.class
            || !fact.class.may_establish_state()
        {
            return unknown_evaluation(mode, FreshnessV1::Missing);
        }
        let Some(live) = support.get(fact.evidence_id.as_str()) else {
            return unknown_evaluation(mode, FreshnessV1::Missing);
        };
        if !live.matches_selector(&requirement.live_support) {
            return unknown_evaluation(mode, FreshnessV1::Missing);
        }
        let Some(live_remaining_ms) = live.usable_remaining_ms_at(moment.monotonic_now) else {
            return unknown_evaluation(mode, FreshnessV1::Stale);
        };
        if let Some(existing) = axes {
            if existing != (fact.availability, fact.impact) {
                return unknown_evaluation(mode, FreshnessV1::Contradictory);
            }
        } else {
            axes = Some((fact.availability, fact.impact));
        }
        remaining_ms =
            Some(remaining_ms.map_or(live_remaining_ms, |current| current.min(live_remaining_ms)));
    }
    let Some((availability, impact)) = axes else {
        return unknown_evaluation(mode, FreshnessV1::Missing);
    };
    let direct_state = map_state(availability, impact, FreshnessV1::Fresh);
    ComponentEvaluation {
        direct_state,
        state: direct_state,
        mode,
        remaining_ms,
    }
}

fn unknown_evaluation(mode: ModeV1, _freshness: FreshnessV1) -> ComponentEvaluation {
    ComponentEvaluation {
        direct_state: ProjectedStateV1::Unknown,
        state: ProjectedStateV1::Unknown,
        mode,
        remaining_ms: None,
    }
}

fn apply_dependencies<'a>(
    component_key: &'a str,
    policy: &'a ProjectionPolicyV1,
    evaluations: &mut BTreeMap<&'a str, ComponentEvaluation>,
) -> Result<(), ProjectionError> {
    let direct = evaluations
        .get(component_key)
        .cloned()
        .ok_or_else(|| ProjectionError::new("missing_component", component_key))?;
    let mut effects = BTreeSet::new();
    let mut remaining_ms = direct.remaining_ms;

    for edge in policy
        .dependencies
        .iter()
        .filter(|edge| edge.parent == component_key)
    {
        let dependency = evaluations
            .get(edge.dependency.as_str())
            .ok_or_else(|| ProjectionError::new("missing_dependency", &edge.dependency))?;
        let effect = match dependency.state {
            ProjectedStateV1::Healthy => DependencyEffectV1::Ignore,
            ProjectedStateV1::Degraded => edge.behavior.on_degraded,
            ProjectedStateV1::PartialOutage => edge.behavior.on_partial,
            ProjectedStateV1::MajorOutage => edge.behavior.on_unavailable,
            ProjectedStateV1::Unknown => edge.behavior.on_unknown,
        };
        if edge.kind == DependencyKindV1::Hard
            && direct.direct_state == ProjectedStateV1::Healthy
            && dependency.state == ProjectedStateV1::MajorOutage
        {
            effects.insert(ProjectedStateV1::Unknown);
        } else if let Some(state) = effect.projected_state() {
            effects.insert(state);
        }
        if edge.kind != DependencyKindV1::Informational {
            remaining_ms = match (remaining_ms, dependency.remaining_ms) {
                (Some(left), Some(right)) => Some(left.min(right)),
                _ => None,
            };
        }
    }

    let state = if direct.direct_state == ProjectedStateV1::Unknown {
        ProjectedStateV1::Unknown
    } else if effects.is_empty() {
        direct.direct_state
    } else if effects.len() > 1 {
        ProjectedStateV1::Unknown
    } else {
        let effect = *effects.iter().next().expect("one effect");
        if direct.direct_state == ProjectedStateV1::Healthy || direct.direct_state == effect {
            effect
        } else {
            ProjectedStateV1::Unknown
        }
    };
    evaluations.insert(
        component_key,
        ComponentEvaluation {
            direct_state: direct.direct_state,
            state,
            mode: direct.mode,
            remaining_ms,
        },
    );
    Ok(())
}

fn dependency_order(policy: &ProjectionPolicyV1) -> Result<Vec<&str>, ProjectionError> {
    fn visit<'a>(
        key: &'a str,
        policy: &'a ProjectionPolicyV1,
        visited: &mut BTreeSet<&'a str>,
        output: &mut Vec<&'a str>,
    ) {
        if !visited.insert(key) {
            return;
        }
        for edge in policy.dependencies.iter().filter(|edge| edge.parent == key) {
            visit(&edge.dependency, policy, visited, output);
        }
        output.push(key);
    }
    policy.validate()?;
    let mut visited = BTreeSet::new();
    let mut output = Vec::new();
    for component in &policy.components {
        visit(&component.key, policy, &mut visited, &mut output);
    }
    Ok(output)
}

fn floor_time(value: u64, granularity: u64) -> u64 {
    value - (value % granularity)
}
