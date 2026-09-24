use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const PROJECTION_POLICY_SCHEMA_V1: &str = "constellation.status_projection_policy.v1";
pub const SOURCE_FACT_SCHEMA_V1: &str = "constellation.status_source_fact.v1";
pub const MAINTENANCE_ASSERTION_SCHEMA_V1: &str = "constellation.status_maintenance_assertion.v1";
pub const STATUS_ARTIFACT_SCHEMA_V1: &str = "constellation.status_artifact.v1";
pub const CURRENT_POINTER_SCHEMA_V1: &str = "constellation.status_current_pointer.v1";

/// Schemas this crate owns. A source fact or policy requirement naming one of
/// them would feed a projection's own output back in as source evidence, so
/// validation refuses them.
pub const PROJECTION_DISCLOSURE_SCHEMA_V1: &str = "constellation.status_projection_disclosure.v1";
pub const PROJECTION_BASIS_SCHEMA_V1: &str = "constellation.status_projection_basis.v1";
pub const PROJECTOR_OWNED_SCHEMAS: [&str; 8] = [
    PROJECTION_POLICY_SCHEMA_V1,
    SOURCE_FACT_SCHEMA_V1,
    COMPONENT_DETAIL_SCHEMA_V1,
    MAINTENANCE_ASSERTION_SCHEMA_V1,
    STATUS_ARTIFACT_SCHEMA_V1,
    CURRENT_POINTER_SCHEMA_V1,
    PROJECTION_DISCLOSURE_SCHEMA_V1,
    PROJECTION_BASIS_SCHEMA_V1,
];
/// The owner string this crate would carry if it were ever named as a fact
/// owner. It never is: a projection is not a producer.
pub const PROJECTOR_OWNER: &str = "constellation-status-projection";

pub const MAX_COMPONENTS: usize = 256;
pub const MAX_FACTS: usize = 1_024;
pub const MAX_DEPENDENCIES: usize = 1_024;
pub const MAX_TEXT_BYTES: usize = 256;
pub const MAX_ARTIFACT_BYTES: usize = 64 * 1_024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionError {
    pub code: &'static str,
    pub detail: String,
}

impl ProjectionError {
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for ProjectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for ProjectionError {}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AudienceClassV1 {
    Public,
    Operator,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceFactClassV1 {
    Observed,
    DerivedAdmitted,
    Asserted,
    Historical,
    QualificationLifecycle,
}

impl SourceFactClassV1 {
    #[must_use]
    pub const fn may_establish_state(self) -> bool {
        matches!(self, Self::Observed | Self::DerivedAdmitted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityV1 {
    Available,
    Impaired,
    Unavailable,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpactV1 {
    None,
    Partial,
    Total,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessV1 {
    Fresh,
    Stale,
    Missing,
    Contradictory,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModeV1 {
    Normal,
    Maintenance,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectedStateV1 {
    Healthy,
    Degraded,
    PartialOutage,
    MajorOutage,
    Unknown,
}

impl ProjectedStateV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::PartialOutage => "partial_outage",
            Self::MajorOutage => "major_outage",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKindV1 {
    Hard,
    Soft,
    Informational,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyEffectV1 {
    Ignore,
    Degrade,
    PartialOutage,
    MajorOutage,
    Unknown,
}

impl DependencyEffectV1 {
    #[must_use]
    pub const fn projected_state(self) -> Option<ProjectedStateV1> {
        match self {
            Self::Ignore => None,
            Self::Degrade => Some(ProjectedStateV1::Degraded),
            Self::PartialOutage => Some(ProjectedStateV1::PartialOutage),
            Self::MajorOutage => Some(ProjectedStateV1::MajorOutage),
            Self::Unknown => Some(ProjectedStateV1::Unknown),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentOutputFieldV1 {
    DisplayName,
    State,
    Mode,
    Reason,
    /// Optional bounded display-only text supplied by the condition owner
    /// for one component (see [`ComponentDetailV1`]). Operator audience
    /// only. The projector copies it and never reads it.
    Detail,
}

pub const COMPONENT_DETAIL_SCHEMA_V1: &str = "constellation.status_component_detail.v1";

/// Optional bounded display-only explanation supplied by a condition owner
/// after its own verified correspondence, attached to the one fact it
/// explains. It is presentation metadata: it is not a state, a reason code,
/// a classification, a retry policy, or an input to any projection decision,
/// and the projector never branches on its contents. It never enters the
/// basis digest. Absent by default.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentDetailV1 {
    pub schema: String,
    /// The fact this text accompanies; the projector attaches it to the
    /// component that requires that fact.
    pub fact_id: String,
    /// Bounded text with no control characters.
    pub text: String,
}

impl ComponentDetailV1 {
    pub fn validate(&self) -> Result<(), ProjectionError> {
        if self.schema != COMPONENT_DETAIL_SCHEMA_V1 {
            return Err(ProjectionError::new(
                "unsupported_schema",
                "component detail schema",
            ));
        }
        validate_token("fact_id", &self.fact_id)?;
        validate_safe_text("detail", &self.text)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SafeReasonV1 {
    pub state: ProjectedStateV1,
    pub text: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosurePolicyV1 {
    pub audience: AudienceClassV1,
    pub component_fields: Vec<ComponentOutputFieldV1>,
    pub safe_reasons: Vec<SafeReasonV1>,
    pub include_basis_digest: bool,
    /// Retained for schema compatibility. It must be `false`: v1 does not
    /// order producer timestamps from different clocks into one window.
    pub include_observation_window: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutputComponentV1 {
    pub id: String,
    pub display_name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FactRequirementV1 {
    pub fact_id: String,
    pub owner: String,
    pub native_schema: String,
    pub class: SourceFactClassV1,
    pub live_support: LiveSupportSelectorV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LiveSupportSelectorV1 {
    pub consumer: String,
    pub subject: String,
    pub subject_incarnation: String,
    pub scope: String,
    pub reliance_context_digest: String,
    pub qualified_generation_digest: String,
    pub receiver: String,
    pub receiver_incarnation: String,
    pub receiver_epoch_id: String,
    pub receiver_clock_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentPolicyV1 {
    /// Projection-private identity. It is never copied into an artifact.
    pub key: String,
    /// `None` makes this a hidden dependency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<OutputComponentV1>,
    pub required_facts: Vec<FactRequirementV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub maintenance_assertion_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyBehaviorV1 {
    pub on_unavailable: DependencyEffectV1,
    pub on_degraded: DependencyEffectV1,
    pub on_partial: DependencyEffectV1,
    pub on_unknown: DependencyEffectV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyEdgeV1 {
    pub parent: String,
    pub dependency: String,
    pub kind: DependencyKindV1,
    pub behavior: DependencyBehaviorV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionPolicyV1 {
    pub schema: String,
    pub projection_id: String,
    pub generation: String,
    pub root_component: String,
    pub maximum_age_ms: u64,
    pub admitted_clock_uncertainty_ms: u64,
    pub timestamp_granularity_ms: u64,
    pub components: Vec<ComponentPolicyV1>,
    pub dependencies: Vec<DependencyEdgeV1>,
    pub disclosure: DisclosurePolicyV1,
}

/// Projection-local input built in process by a leaf adapter from an exact
/// owner record. It serializes only into the operator basis digest. It is not
/// a wire format: it deliberately implements no deserialization, so its bytes
/// cannot be decoded back into a fact. Its availability and impact axes mean
/// only what the constructing adapter's contract says they mean; relabelled
/// content under another owner or schema is not detected (a known limit).
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SourceFactV1 {
    pub schema: String,
    pub fact_id: String,
    pub subject_key: String,
    pub owner: String,
    pub native_schema: String,
    pub native_record_id: String,
    pub class: SourceFactClassV1,
    pub evidence_id: String,
    pub availability: AvailabilityV1,
    pub impact: ImpactV1,
    pub reason_code: String,
    pub basis_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceAssertionV1 {
    pub schema: String,
    pub assertion_id: String,
    pub component_key: String,
    pub active: bool,
    pub basis_digest: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionMomentV1 {
    pub(crate) generated_at_unix_ms: u64,
    pub(crate) monotonic_now: Instant,
}

impl ProjectionMomentV1 {
    #[must_use]
    pub fn now(generated_at_unix_ms: u64) -> Self {
        Self {
            generated_at_unix_ms,
            monotonic_now: Instant::now(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationWindowV1 {
    pub earliest_observed_at_unix_ms: u64,
    pub latest_observed_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectedComponentV1 {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub state: ProjectedStateV1,
    pub mode: ModeV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Owner-supplied display-only detail (operator audience only); absent
    /// unless the policy discloses it and the owner supplied it. It decorates
    /// the state and never replaces or changes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StatusArtifactV1 {
    pub schema: String,
    pub artifact_id: String,
    pub projection_id: String,
    pub projection_generation: String,
    pub policy_digest: String,
    pub generated_at_unix_ms: u64,
    pub fresh_until_unix_ms: u64,
    pub admitted_clock_uncertainty_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation_window: Option<ObservationWindowV1>,
    pub aggregate_state: ProjectedStateV1,
    pub components: Vec<ProjectedComponentV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basis_digest: Option<String>,
    pub mutation_authority: String,
    pub non_authorization: String,
}

impl ProjectionPolicyV1 {
    pub fn validate(&self) -> Result<(), ProjectionError> {
        if self.schema != PROJECTION_POLICY_SCHEMA_V1 {
            return Err(ProjectionError::new(
                "unsupported_schema",
                "projection policy schema",
            ));
        }
        validate_public_id("projection_id", &self.projection_id)?;
        validate_token("generation", &self.generation)?;
        validate_token("root_component", &self.root_component)?;
        if self.maximum_age_ms == 0
            || self.timestamp_granularity_ms == 0
            || self.admitted_clock_uncertainty_ms >= self.maximum_age_ms
        {
            return Err(ProjectionError::new(
                "invalid_time_policy",
                "maximum age and granularity must be positive and clock uncertainty must be smaller than maximum age",
            ));
        }
        if self.components.is_empty() || self.components.len() > MAX_COMPONENTS {
            return Err(ProjectionError::new(
                "invalid_components",
                "component count is outside bounds",
            ));
        }
        if self.dependencies.len() > MAX_DEPENDENCIES {
            return Err(ProjectionError::new(
                "invalid_dependencies",
                "dependency count exceeds bound",
            ));
        }
        let mut keys = BTreeSet::new();
        let mut output_ids = BTreeSet::new();
        let mut prior_key: Option<&str> = None;
        for component in &self.components {
            validate_token("component key", &component.key)?;
            if prior_key.is_some_and(|prior| prior >= component.key.as_str()) {
                return Err(ProjectionError::new(
                    "noncanonical_order",
                    "components must be strictly ordered by key",
                ));
            }
            prior_key = Some(&component.key);
            if !keys.insert(component.key.as_str()) {
                return Err(ProjectionError::new("duplicate_component", &component.key));
            }
            let mut prior_fact: Option<&str> = None;
            for requirement in &component.required_facts {
                validate_token("required fact id", &requirement.fact_id)?;
                validate_token("required fact owner", &requirement.owner)?;
                validate_token("required fact native schema", &requirement.native_schema)?;
                refuse_projection_reingestion(&requirement.owner, &requirement.native_schema)?;
                requirement.live_support.validate()?;
                if !requirement.class.may_establish_state() {
                    return Err(ProjectionError::new(
                        "invalid_fact_class",
                        "policy requirements may use only observed or derived-admitted facts",
                    ));
                }
                if prior_fact.is_some_and(|prior| prior >= requirement.fact_id.as_str()) {
                    return Err(ProjectionError::new(
                        "noncanonical_order",
                        "required facts must be strictly ordered by id",
                    ));
                }
                prior_fact = Some(requirement.fact_id.as_str());
            }
            validate_sorted_tokens(
                "maintenance_assertion_ids",
                &component.maintenance_assertion_ids,
            )?;
            if let Some(output) = &component.output {
                validate_public_id("output id", &output.id)?;
                validate_safe_text("display name", &output.display_name)?;
                if !output_ids.insert(output.id.as_str()) {
                    return Err(ProjectionError::new("duplicate_output", &output.id));
                }
            }
        }
        if !keys.contains(self.root_component.as_str()) {
            return Err(ProjectionError::new(
                "missing_root",
                "root component is not declared",
            ));
        }
        if self
            .components
            .iter()
            .find(|component| component.key == self.root_component)
            .and_then(|component| component.output.as_ref())
            .is_none()
        {
            return Err(ProjectionError::new(
                "hidden_root",
                "root component must be visible",
            ));
        }
        self.disclosure.validate()?;
        let mut prior_edge: Option<(&str, &str)> = None;
        for edge in &self.dependencies {
            validate_token("dependency parent", &edge.parent)?;
            validate_token("dependency child", &edge.dependency)?;
            if edge.parent == edge.dependency
                || !keys.contains(edge.parent.as_str())
                || !keys.contains(edge.dependency.as_str())
            {
                return Err(ProjectionError::new(
                    "invalid_dependency",
                    "dependency endpoints are invalid",
                ));
            }
            let key = (edge.parent.as_str(), edge.dependency.as_str());
            if prior_edge.is_some_and(|prior| prior >= key) {
                return Err(ProjectionError::new(
                    "noncanonical_order",
                    "dependencies must be strictly ordered",
                ));
            }
            prior_edge = Some(key);
            if edge.kind == DependencyKindV1::Informational
                && (edge.behavior.on_unavailable != DependencyEffectV1::Ignore
                    || edge.behavior.on_degraded != DependencyEffectV1::Ignore
                    || edge.behavior.on_partial != DependencyEffectV1::Ignore
                    || edge.behavior.on_unknown != DependencyEffectV1::Ignore)
            {
                return Err(ProjectionError::new(
                    "invalid_informational_dependency",
                    "informational dependencies cannot alter state or freshness",
                ));
            }
            if edge.kind != DependencyKindV1::Informational
                && edge.behavior.on_unknown == DependencyEffectV1::Ignore
            {
                return Err(ProjectionError::new(
                    "invalid_dependency",
                    "state-bearing dependencies cannot ignore unknown support",
                ));
            }
        }
        validate_acyclic(self)?;
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProjectionError> {
        self.validate()?;
        serde_jcs::to_vec(self).map_err(|error| ProjectionError::new("encode", error.to_string()))
    }

    pub fn full_digest(&self) -> Result<String, ProjectionError> {
        Ok(sha256_id(&self.canonical_bytes()?))
    }

    pub fn disclosure_digest(&self) -> Result<String, ProjectionError> {
        self.validate()?;
        #[derive(Serialize)]
        struct Surface<'a> {
            schema: &'static str,
            projection_id: &'a str,
            generation: &'a str,
            maximum_age_ms: u64,
            admitted_clock_uncertainty_ms: u64,
            timestamp_granularity_ms: u64,
            outputs: Vec<&'a OutputComponentV1>,
            disclosure: &'a DisclosurePolicyV1,
        }
        let mut outputs = self
            .components
            .iter()
            .filter_map(|component| component.output.as_ref())
            .collect::<Vec<_>>();
        outputs.sort_by(|left, right| left.id.cmp(&right.id));
        let surface = Surface {
            schema: PROJECTION_DISCLOSURE_SCHEMA_V1,
            projection_id: &self.projection_id,
            generation: &self.generation,
            maximum_age_ms: self.maximum_age_ms,
            admitted_clock_uncertainty_ms: self.admitted_clock_uncertainty_ms,
            timestamp_granularity_ms: self.timestamp_granularity_ms,
            outputs,
            disclosure: &self.disclosure,
        };
        let bytes = serde_jcs::to_vec(&surface)
            .map_err(|error| ProjectionError::new("encode", error.to_string()))?;
        Ok(sha256_id(&bytes))
    }
}

impl DisclosurePolicyV1 {
    fn validate(&self) -> Result<(), ProjectionError> {
        if self.include_observation_window {
            return Err(ProjectionError::new(
                "observation_window_unsupported",
                "v1 refuses observation windows: producer timestamps from unrelated clocks cannot be ordered into one window",
            ));
        }
        if self.audience == AudienceClassV1::Public && self.include_basis_digest {
            return Err(ProjectionError::new(
                "public_disclosure",
                "public artifacts cannot include a rich-input basis digest",
            ));
        }
        if self.audience == AudienceClassV1::Public
            && self
                .component_fields
                .contains(&ComponentOutputFieldV1::Detail)
        {
            return Err(ProjectionError::new(
                "public_disclosure",
                "public artifacts cannot include owner detail text",
            ));
        }
        validate_sorted_unique("component fields", &self.component_fields)?;
        if !self
            .component_fields
            .contains(&ComponentOutputFieldV1::State)
            || !self
                .component_fields
                .contains(&ComponentOutputFieldV1::Mode)
        {
            return Err(ProjectionError::new(
                "missing_output_field",
                "state and mode are mandatory artifact fields",
            ));
        }
        let mut prior = None;
        for reason in &self.safe_reasons {
            if prior.is_some_and(|state| state >= reason.state) {
                return Err(ProjectionError::new(
                    "noncanonical_order",
                    "safe reasons must be ordered by state",
                ));
            }
            prior = Some(reason.state);
            validate_safe_text("safe reason", &reason.text)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn reason_for(&self, state: ProjectedStateV1) -> Option<&str> {
        self.safe_reasons
            .iter()
            .find(|reason| reason.state == state)
            .map(|reason| reason.text.as_str())
    }
}

impl LiveSupportSelectorV1 {
    fn validate(&self) -> Result<(), ProjectionError> {
        for (name, value) in [
            ("support consumer", &self.consumer),
            ("support subject", &self.subject),
            ("support subject incarnation", &self.subject_incarnation),
            ("support scope", &self.scope),
            ("support receiver", &self.receiver),
            ("support receiver incarnation", &self.receiver_incarnation),
            ("support receiver epoch", &self.receiver_epoch_id),
            ("support receiver clock", &self.receiver_clock_id),
        ] {
            validate_token(name, value)?;
        }
        validate_sha256("reliance context digest", &self.reliance_context_digest)?;
        validate_sha256(
            "qualified generation digest",
            &self.qualified_generation_digest,
        )
    }
}

impl SourceFactV1 {
    pub fn validate(&self) -> Result<(), ProjectionError> {
        if self.schema != SOURCE_FACT_SCHEMA_V1 {
            return Err(ProjectionError::new(
                "unsupported_schema",
                "source fact schema",
            ));
        }
        for (name, value) in [
            ("fact_id", &self.fact_id),
            ("subject_key", &self.subject_key),
            ("owner", &self.owner),
            ("native_schema", &self.native_schema),
            ("native_record_id", &self.native_record_id),
            ("evidence_id", &self.evidence_id),
            ("reason_code", &self.reason_code),
        ] {
            validate_token(name, value)?;
        }
        refuse_projection_reingestion(&self.owner, &self.native_schema)?;
        validate_sha256("basis_digest", &self.basis_digest)
    }
}

impl MaintenanceAssertionV1 {
    pub fn validate(&self) -> Result<(), ProjectionError> {
        if self.schema != MAINTENANCE_ASSERTION_SCHEMA_V1 {
            return Err(ProjectionError::new(
                "unsupported_schema",
                "maintenance assertion schema",
            ));
        }
        validate_token("assertion_id", &self.assertion_id)?;
        validate_token("component_key", &self.component_key)?;
        validate_sha256("basis_digest", &self.basis_digest)
    }
}

impl StatusArtifactV1 {
    pub fn compute_id(&self) -> Result<String, ProjectionError> {
        let mut preimage = serde_json::to_value(self)
            .map_err(|error| ProjectionError::new("encode", error.to_string()))?;
        preimage
            .as_object_mut()
            .ok_or_else(|| ProjectionError::new("encode", "artifact is not an object"))?
            .remove("artifact_id");
        let bytes = serde_jcs::to_vec(&preimage)
            .map_err(|error| ProjectionError::new("encode", error.to_string()))?;
        Ok(sha256_id(&bytes))
    }

    pub fn validate(&self) -> Result<(), ProjectionError> {
        if self.schema != STATUS_ARTIFACT_SCHEMA_V1 {
            return Err(ProjectionError::new(
                "unsupported_schema",
                "status artifact schema",
            ));
        }
        validate_sha256("artifact_id", &self.artifact_id)?;
        validate_public_id("projection_id", &self.projection_id)?;
        validate_token("projection_generation", &self.projection_generation)?;
        validate_sha256("policy_digest", &self.policy_digest)?;
        if self.fresh_until_unix_ms < self.generated_at_unix_ms {
            return Err(ProjectionError::new(
                "invalid_expiry",
                "fresh_until precedes generated_at",
            ));
        }
        if self.components.is_empty() || self.components.len() > MAX_COMPONENTS {
            return Err(ProjectionError::new(
                "invalid_components",
                "artifact component count is outside bounds",
            ));
        }
        if self.fresh_until_unix_ms == self.generated_at_unix_ms
            && (self.aggregate_state != ProjectedStateV1::Unknown
                || self
                    .components
                    .iter()
                    .any(|component| component.state != ProjectedStateV1::Unknown))
        {
            return Err(ProjectionError::new(
                "invalid_expiry_state",
                "an artifact without a positive presentation window must be unknown",
            ));
        }
        let mut prior: Option<&str> = None;
        for component in &self.components {
            validate_public_id("component id", &component.id)?;
            if prior.is_some_and(|value| value >= component.id.as_str()) {
                return Err(ProjectionError::new(
                    "noncanonical_order",
                    "artifact components are not strictly ordered",
                ));
            }
            prior = Some(component.id.as_str());
            if let Some(display_name) = &component.display_name {
                validate_safe_text("display name", display_name)?;
            }
            if let Some(reason) = &component.reason {
                validate_safe_text("reason", reason)?;
            }
            if let Some(detail) = &component.detail {
                validate_safe_text("detail", detail)?;
            }
        }
        if let Some(digest) = &self.basis_digest {
            validate_sha256("basis_digest", digest)?;
        }
        if self.observation_window.is_some() {
            return Err(ProjectionError::new(
                "observation_window_unsupported",
                "v1 artifacts carry no observation window",
            ));
        }
        if self.mutation_authority != "none"
            || self.non_authorization
                != "Derived status is read-only and grants no authority or permission."
        {
            return Err(ProjectionError::new(
                "authority_boundary",
                "artifact authority nonclaim changed",
            ));
        }
        if self.artifact_id != self.compute_id()? {
            return Err(ProjectionError::new(
                "identity_mismatch",
                "artifact id does not match content",
            ));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProjectionError> {
        self.validate()?;
        serde_jcs::to_vec(self).map_err(|error| ProjectionError::new("encode", error.to_string()))
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ProjectionError> {
        if bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(ProjectionError::new(
                "artifact_bound",
                "status artifact exceeds its byte bound",
            ));
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| ProjectionError::new("decode", error.to_string()))?;
        value.validate()?;
        if value.canonical_bytes()? != bytes {
            return Err(ProjectionError::new(
                "noncanonical",
                "artifact is not canonical JSON",
            ));
        }
        Ok(value)
    }
}

pub(crate) fn sha256_id(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn refuse_projection_reingestion(owner: &str, native_schema: &str) -> Result<(), ProjectionError> {
    if owner == PROJECTOR_OWNER || PROJECTOR_OWNED_SCHEMAS.contains(&native_schema) {
        return Err(ProjectionError::new(
            "projection_reingestion",
            "projection output is not source evidence and cannot be admitted as a fact",
        ));
    }
    Ok(())
}

pub(crate) fn validate_token(name: &str, value: &str) -> Result<(), ProjectionError> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.chars().any(char::is_control)
        || !value.is_ascii()
    {
        return Err(ProjectionError::new(
            "invalid_token",
            format!("{name} is invalid"),
        ));
    }
    Ok(())
}

fn validate_public_id(name: &str, value: &str) -> Result<(), ProjectionError> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
    {
        return Err(ProjectionError::new(
            "invalid_public_id",
            format!("{name} is invalid"),
        ));
    }
    Ok(())
}

fn validate_safe_text(name: &str, value: &str) -> Result<(), ProjectionError> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(ProjectionError::new(
            "invalid_text",
            format!("{name} is invalid"),
        ));
    }
    Ok(())
}

pub(crate) fn validate_sha256(name: &str, value: &str) -> Result<(), ProjectionError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(ProjectionError::new(
            "invalid_digest",
            format!("{name} is not sha256"),
        ));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ProjectionError::new(
            "invalid_digest",
            format!("{name} is invalid"),
        ));
    }
    Ok(())
}

fn validate_sorted_tokens(name: &str, values: &[String]) -> Result<(), ProjectionError> {
    let mut prior: Option<&str> = None;
    for value in values {
        validate_token(name, value)?;
        if prior.is_some_and(|item| item >= value.as_str()) {
            return Err(ProjectionError::new(
                "noncanonical_order",
                format!("{name} must be strictly ordered"),
            ));
        }
        prior = Some(value);
    }
    Ok(())
}

fn validate_sorted_unique<T: Ord>(name: &str, values: &[T]) -> Result<(), ProjectionError> {
    if values.windows(2).any(|window| window[0] >= window[1]) {
        return Err(ProjectionError::new(
            "noncanonical_order",
            format!("{name} must be strictly ordered"),
        ));
    }
    Ok(())
}

fn validate_acyclic(policy: &ProjectionPolicyV1) -> Result<(), ProjectionError> {
    fn visit<'a>(
        node: &'a str,
        policy: &'a ProjectionPolicyV1,
        visiting: &mut BTreeSet<&'a str>,
        visited: &mut BTreeSet<&'a str>,
    ) -> Result<(), ProjectionError> {
        if visited.contains(node) {
            return Ok(());
        }
        if !visiting.insert(node) {
            return Err(ProjectionError::new("dependency_cycle", node));
        }
        for edge in policy
            .dependencies
            .iter()
            .filter(|edge| edge.parent == node)
        {
            visit(&edge.dependency, policy, visiting, visited)?;
        }
        visiting.remove(node);
        visited.insert(node);
        Ok(())
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for component in &policy.components {
        visit(&component.key, policy, &mut visiting, &mut visited)?;
    }
    Ok(())
}

pub(crate) fn canonical_digest<T: Serialize>(value: &T) -> Result<String, ProjectionError> {
    let bytes = serde_jcs::to_vec(value)
        .map_err(|error| ProjectionError::new("encode", error.to_string()))?;
    Ok(sha256_id(&bytes))
}

pub(crate) fn map_state(
    availability: AvailabilityV1,
    impact: ImpactV1,
    freshness: FreshnessV1,
) -> ProjectedStateV1 {
    if freshness != FreshnessV1::Fresh {
        return ProjectedStateV1::Unknown;
    }
    match (availability, impact) {
        (AvailabilityV1::Available, ImpactV1::None) => ProjectedStateV1::Healthy,
        (AvailabilityV1::Impaired, ImpactV1::None) => ProjectedStateV1::Degraded,
        (AvailabilityV1::Impaired | AvailabilityV1::Unavailable, ImpactV1::Partial) => {
            ProjectedStateV1::PartialOutage
        }
        (AvailabilityV1::Unavailable, ImpactV1::Total) => ProjectedStateV1::MajorOutage,
        _ => ProjectedStateV1::Unknown,
    }
}

pub(crate) fn safe_reason_map(
    disclosure: &DisclosurePolicyV1,
) -> BTreeMap<ProjectedStateV1, String> {
    disclosure
        .safe_reasons
        .iter()
        .map(|reason| (reason.state, reason.text.clone()))
        .collect()
}
