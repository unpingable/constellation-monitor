#![forbid(unsafe_code)]
//! Consequence adapter for exactly one condition:
//! `constellation.status_consequence.nq_host_load_pressure.v1`.
//!
//! The generic projector never infers what an NQ outcome means for a status
//! component. This crate owns that one mapping for the load-pressure
//! *condition component* and nothing else. It maps a process-local
//! [`VerifiedCorrespondenceV1`] into one `SourceFactV1`, admits the live Pulse
//! exchange through the unchanged [`LiveQueryAnchorV1`], and carries fixed
//! non-claims: no host or service health, reachability, capacity, or cause is
//! ever asserted.
//!
//! The mapping is an operator condition projection, not a public status
//! component. Its structural guard covers exactly the shape that was
//! qualified: one dependency-free condition component whose label and reason
//! table carry the condition's non-claims, in every audience. The generic
//! projector cannot distinguish a fact built by [`fact_for`] from one built by
//! hand with the same owner string; that is a convention boundary of the
//! embedding, recorded as a known limit, not a type guarantee.

use constellation_status_projection::{
    AvailabilityV1, ComponentOutputFieldV1, DependencyKindV1, FactRequirementV1, ImpactV1,
    LiveQueryAnchorV1, LiveSupportObservationV1, LiveSupportSelectorV1, ProjectedStateV1,
    ProjectionError, ProjectionPolicyV1, SOURCE_FACT_SCHEMA_V1, SafeReasonV1, SourceFactClassV1,
    SourceFactV1,
};
use pulse_nq_load_correspondence::{NqDetectorStateV1, QuestionV1, VerifiedCorrespondenceV1};
use pulse_runtime::{LocalCrashReactor, ReactorSnapshotV1};
use pulse_types::{
    ConsumerId, JudgmentCategoryV1, LIVE_PRESENT_SUPPORT_REQUEST_SCHEMA_V1,
    LivePresentSupportNonce, LivePresentSupportRequestV1, RelianceSupportCertificateV1,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

pub const CONSEQUENCE_SCHEMA_V1: &str = "constellation.status_consequence.nq_host_load_pressure.v1";
/// The only correspondence question this adapter maps. A verified value for
/// any other question is refused before the consequence table is consulted.
pub const REQUIRED_QUESTION: QuestionV1 = QuestionV1::HostLoadPressureV1;
/// The fact owner named in projection policies. It is this adapter, not NQ
/// and not the generic projector.
pub const FACT_OWNER: &str = "constellation-status-nq-load-pressure";
/// The qualified condition label. Every audience must use it; the constant
/// keeps its original name for source compatibility.
pub const PUBLIC_COMPONENT_LABEL: &str = "Host load-pressure condition";

pub const CONSEQUENCE_NONCLAIMS: [&str; 5] = [
    "degraded means NQ found the bounded load-pressure condition present; NQ rates that condition warning, not error, and no impairment, outage, impact, or cause is claimed",
    "healthy means only that normalized one-minute load was below 2.0 per logical CPU with complete current local coverage; it says nothing about host or service health, reachability, capacity, or cause",
    "unknown means neither presence nor absence was established and is not an outage",
    "the component represents the load-pressure condition itself, never a host or service as a whole",
    "this mapping is a projection-policy consequence, not an NQ claim, and grants no authority",
];

/// One row of the closed consequence table.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ConsequenceRowV1 {
    pub nq_detector_state: NqDetectorStateV1,
    pub availability: AvailabilityV1,
    pub impact: ImpactV1,
    pub projected_state: ProjectedStateV1,
    pub reason_code: &'static str,
}

/// The complete table. Every NQ outcome maps to exactly one row.
#[must_use]
pub const fn consequence_table() -> [ConsequenceRowV1; 4] {
    [
        ConsequenceRowV1 {
            nq_detector_state: NqDetectorStateV1::Present,
            availability: AvailabilityV1::Impaired,
            impact: ImpactV1::None,
            projected_state: ProjectedStateV1::Degraded,
            reason_code: "nq_load_pressure_present",
        },
        ConsequenceRowV1 {
            nq_detector_state: NqDetectorStateV1::ExplicitlyAbsent,
            availability: AvailabilityV1::Available,
            impact: ImpactV1::None,
            projected_state: ProjectedStateV1::Healthy,
            reason_code: "nq_load_pressure_explicitly_absent",
        },
        ConsequenceRowV1 {
            nq_detector_state: NqDetectorStateV1::CannotEvaluate,
            availability: AvailabilityV1::Indeterminate,
            impact: ImpactV1::Indeterminate,
            projected_state: ProjectedStateV1::Unknown,
            reason_code: "nq_cannot_evaluate",
        },
        ConsequenceRowV1 {
            nq_detector_state: NqDetectorStateV1::NotEvaluated,
            availability: AvailabilityV1::Indeterminate,
            impact: ImpactV1::Indeterminate,
            projected_state: ProjectedStateV1::Unknown,
            reason_code: "nq_not_evaluated",
        },
    ]
}

#[must_use]
pub fn consequence_row(state: NqDetectorStateV1) -> ConsequenceRowV1 {
    consequence_table()
        .into_iter()
        .find(|row| row.nq_detector_state == state)
        .expect("the consequence table is total over NqDetectorStateV1")
}

#[derive(Serialize)]
struct ConsequenceDocumentV1 {
    schema: &'static str,
    fact_owner: &'static str,
    rows: [ConsequenceRowV1; 4],
    nonclaims: [&'static str; 5],
}

/// Pinned identity of the mapping contract: SHA-256 of the canonical table
/// document. A policy reviewer records it; a changed table changes it.
#[must_use]
pub fn consequence_identity() -> String {
    let document = ConsequenceDocumentV1 {
        schema: CONSEQUENCE_SCHEMA_V1,
        fact_owner: FACT_OWNER,
        rows: consequence_table(),
        nonclaims: CONSEQUENCE_NONCLAIMS,
    };
    let bytes = serde_jcs::to_vec(&document).expect("consequence document canonicalizes");
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// Required public reason text that names the condition (stop condition S9).
/// The leaf adapter requires these exact entries for a public policy; the
/// projector only ever emits reason text that the policy allowlists.
#[must_use]
pub fn recommended_safe_reasons() -> Vec<SafeReasonV1> {
    vec![
        SafeReasonV1 {
            state: ProjectedStateV1::Healthy,
            text: "Qualified load-pressure condition absent in the current NQ observation. This is not a host or service health claim.".to_owned(),
        },
        SafeReasonV1 {
            state: ProjectedStateV1::Degraded,
            text: "Qualified load-pressure condition present in the current NQ observation. No outage or cause is claimed.".to_owned(),
        },
        SafeReasonV1 {
            state: ProjectedStateV1::Unknown,
            text: "The load-pressure condition is currently unknown. This is not an outage.".to_owned(),
        },
    ]
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsequenceError {
    pub code: &'static str,
    pub detail: String,
}

impl ConsequenceError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for ConsequenceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for ConsequenceError {}

impl From<ProjectionError> for ConsequenceError {
    fn from(error: ProjectionError) -> Self {
        Self::new(error.code, error.detail)
    }
}

/// Structural guard shared by [`fact_for`] and [`admit_live`]: the condition
/// component must have exactly the shape that was qualified.
///
/// It must declare exactly one required fact, owned by this adapter, with
/// this schema and the `derived_admitted` class. No hard or soft dependency
/// edge may name it as parent or as dependency, because the projector selects
/// reason text by projected state and a dependency effect would attribute
/// text to NQ that NQ never produced. For every audience, its label and reason
/// table must carry the qualified condition wording and non-claims. Anything
/// else is refused so the load-pressure condition can never be blended into,
/// or blend into, another component's state.
fn condition_requirement<'a>(
    policy: &'a ProjectionPolicyV1,
    component_key: &str,
) -> Result<&'a FactRequirementV1, ConsequenceError> {
    policy.validate()?;
    let component = policy
        .components
        .iter()
        .find(|component| component.key == component_key)
        .ok_or_else(|| ConsequenceError::new("unknown_component", component_key))?;
    let [requirement] = component.required_facts.as_slice() else {
        return Err(ConsequenceError::new(
            "one_fact_guard",
            "the load-pressure condition component must require exactly one fact",
        ));
    };
    if requirement.owner != FACT_OWNER
        || requirement.native_schema != CONSEQUENCE_SCHEMA_V1
        || requirement.class != SourceFactClassV1::DerivedAdmitted
    {
        return Err(ConsequenceError::new(
            "requirement_mismatch",
            "component requirement does not name this adapter, schema, and derived_admitted class",
        ));
    }
    if policy.dependencies.iter().any(|edge| {
        edge.kind != DependencyKindV1::Informational
            && (edge.parent == component_key || edge.dependency == component_key)
    }) {
        return Err(ConsequenceError::new(
            "dependency_guard",
            "the load-pressure condition component cannot carry or receive state through a hard or soft dependency edge",
        ));
    }
    enforce_condition_contract(component.output.as_ref(), policy)?;
    Ok(requirement)
}

fn check_subject(
    requirement: &FactRequirementV1,
    verified: &VerifiedCorrespondenceV1,
) -> Result<(), ConsequenceError> {
    if verified.question() != REQUIRED_QUESTION {
        return Err(ConsequenceError::new(
            "question_mismatch",
            "verified correspondence is for a question this adapter does not map",
        ));
    }
    if requirement.live_support.scope != REQUIRED_QUESTION.spec().pulse_scope {
        return Err(ConsequenceError::new(
            "selector_mismatch",
            "policy live-support selector names a scope other than the load-pressure question",
        ));
    }
    if requirement.live_support.subject != verified.subject().as_str()
        || requirement.live_support.subject_incarnation != verified.subject_incarnation().as_str()
    {
        return Err(ConsequenceError::new(
            "selector_mismatch",
            "policy live-support selector names a different subject or incarnation",
        ));
    }
    Ok(())
}

/// The structural guard plus the consequence table: build the single
/// `SourceFactV1` for `component_key` from a verified correspondence.
pub fn fact_for(
    verified: &VerifiedCorrespondenceV1,
    policy: &ProjectionPolicyV1,
    component_key: &str,
) -> Result<SourceFactV1, ConsequenceError> {
    let requirement = condition_requirement(policy, component_key)?;
    check_subject(requirement, verified)?;
    let row = consequence_row(verified.nq_detector_state());
    let fact = SourceFactV1 {
        schema: SOURCE_FACT_SCHEMA_V1.to_owned(),
        fact_id: requirement.fact_id.clone(),
        subject_key: component_key.to_owned(),
        owner: FACT_OWNER.to_owned(),
        native_schema: CONSEQUENCE_SCHEMA_V1.to_owned(),
        native_record_id: verified.correspondence_id().to_owned(),
        class: SourceFactClassV1::DerivedAdmitted,
        evidence_id: verified.evidence_ref().to_owned(),
        availability: row.availability,
        impact: row.impact,
        reason_code: row.reason_code.to_owned(),
        basis_digest: verified.correspondence_id().to_owned(),
        observed_at_unix_ms: None,
    };
    fact.validate()?;
    Ok(fact)
}

/// Keep the qualified condition wording at the consequence boundary for every
/// audience. The generic projector remains policy-generic; this leaf alone
/// owns the condition label and the reason text that carries its non-claims.
fn enforce_condition_contract(
    output: Option<&constellation_status_projection::OutputComponentV1>,
    policy: &ProjectionPolicyV1,
) -> Result<(), ConsequenceError> {
    if output.is_none_or(|output| output.display_name != PUBLIC_COMPONENT_LABEL) {
        return Err(ConsequenceError::new(
            "condition_contract_mismatch",
            "load-pressure component label is not the qualified condition label",
        ));
    }
    if !policy
        .disclosure
        .component_fields
        .contains(&ComponentOutputFieldV1::Reason)
        || policy.disclosure.safe_reasons != recommended_safe_reasons()
    {
        return Err(ConsequenceError::new(
            "condition_contract_mismatch",
            "load-pressure policy must retain the qualified reason and non-claim text",
        ));
    }
    Ok(())
}

/// Build the projector's live-support selector for the consumer certificate
/// currently held by the reactor. Policies are authored per process because
/// the receiver incarnation, epoch, and qualified generation are per process.
pub fn live_support_selector(
    snapshot: &ReactorSnapshotV1,
    consumer: &ConsumerId,
) -> Result<LiveSupportSelectorV1, ConsequenceError> {
    let certificate = consumer_certificate(snapshot, consumer, None)?;
    selector_for(snapshot, &certificate)
}

/// As [`live_support_selector`], for one subject, when the consumer holds
/// certificates on more than one subject.
pub fn live_support_selector_for(
    snapshot: &ReactorSnapshotV1,
    consumer: &ConsumerId,
    subject: &str,
) -> Result<LiveSupportSelectorV1, ConsequenceError> {
    let certificate = consumer_certificate(snapshot, consumer, Some(subject))?;
    selector_for(snapshot, &certificate)
}

fn selector_for(
    snapshot: &ReactorSnapshotV1,
    certificate: &RelianceSupportCertificateV1,
) -> Result<LiveSupportSelectorV1, ConsequenceError> {
    let qualified = certificate.qualified_generation.as_ref().ok_or_else(|| {
        ConsequenceError::new(
            "no_qualified_generation",
            "certificate carries no qualified generation",
        )
    })?;
    Ok(LiveSupportSelectorV1 {
        consumer: certificate.consumer.as_str().to_owned(),
        subject: certificate.subject_scope.subject.as_str().to_owned(),
        subject_incarnation: certificate
            .subject_scope
            .subject_incarnation
            .as_str()
            .to_owned(),
        scope: certificate.subject_scope.scope.clone(),
        reliance_context_digest: certificate.context.identity_digest().as_str().to_owned(),
        qualified_generation_digest: qualified.identity_digest().as_str().to_owned(),
        receiver: snapshot.monotonic_epoch.receiver.as_str().to_owned(),
        receiver_incarnation: snapshot
            .monotonic_epoch
            .receiver_incarnation
            .as_str()
            .to_owned(),
        receiver_epoch_id: snapshot.monotonic_epoch.epoch_id.as_str().to_owned(),
        receiver_clock_id: snapshot.monotonic_epoch.clock_id.as_str().to_owned(),
    })
}

/// Query the live reactor for the exact certificate that supports this
/// correspondence and admit it through the unchanged projector anchor.
///
/// The same structural guard as [`fact_for`] runs first, and the policy's
/// live-support selector must name exactly the reactor's current certificate
/// lineage for the consumer it pins. The anchor is created before the query
/// and consumed once after it, so the admitted interval already excludes
/// request transit, actor processing, and admission delay. A certificate that
/// no longer lists exactly this frame, or that names another incarnation, is
/// refused before any query is made.
pub fn admit_live(
    verified: &VerifiedCorrespondenceV1,
    policy: &ProjectionPolicyV1,
    component_key: &str,
    reactor: &LocalCrashReactor,
    nonce: &str,
    maximum_trusted_lifetime_ms: u64,
) -> Result<LiveSupportObservationV1, ConsequenceError> {
    let requirement = condition_requirement(policy, component_key)?;
    check_subject(requirement, verified)?;
    let consumer = ConsumerId::new(requirement.live_support.consumer.as_str());
    let snapshot = reactor.snapshot();
    let certificate = consumer_certificate(
        &snapshot,
        &consumer,
        Some(requirement.live_support.subject.as_str()),
    )?;
    if requirement.live_support != selector_for(&snapshot, &certificate)? {
        return Err(ConsequenceError::new(
            "selector_mismatch",
            "policy live-support selector does not name the reactor's current certificate lineage",
        ));
    }
    if certificate.subject_scope.subject != *verified.subject()
        || certificate.subject_scope.subject_incarnation != *verified.subject_incarnation()
    {
        return Err(ConsequenceError::new(
            "certificate_subject_mismatch",
            "live certificate names a different subject or incarnation",
        ));
    }
    if certificate.supporting_evidence_ids != [verified.evidence_ref().to_owned()]
        || certificate.judgment != JudgmentCategoryV1::Current
    {
        return Err(ConsequenceError::new(
            "certificate_evidence_mismatch",
            "live certificate does not currently list exactly this correspondence frame",
        ));
    }
    let qualified = certificate.qualified_generation.as_ref().ok_or_else(|| {
        ConsequenceError::new(
            "no_qualified_generation",
            "certificate carries no qualified generation",
        )
    })?;
    let request = LivePresentSupportRequestV1 {
        schema: LIVE_PRESENT_SUPPORT_REQUEST_SCHEMA_V1.to_owned(),
        request_nonce: LivePresentSupportNonce::new(nonce),
        consumer: certificate.consumer.clone(),
        subject_scope: certificate.subject_scope.clone(),
        reliance_context: certificate.context.clone(),
        reliance_context_digest: certificate.context.identity_digest(),
        support_certificate_id: certificate.certificate_id.clone(),
        evidence_window_id: certificate.evidence_window_id.clone(),
        qualified_generation_digest: qualified.identity_digest(),
        receiver: snapshot.monotonic_epoch.receiver.clone(),
        receiver_incarnation: snapshot.monotonic_epoch.receiver_incarnation.clone(),
        receiver_epoch_id: snapshot.monotonic_epoch.epoch_id.clone(),
        receiver_clock_id: snapshot.monotonic_epoch.clock_id.clone(),
    };
    let anchor = LiveQueryAnchorV1::begin(&request)?;
    let response = reactor
        .query_live_present_support(request.clone())
        .map_err(|error| ConsequenceError::new("live_query_failed", error.to_string()))?;
    Ok(anchor.admit(
        &request,
        &response,
        &certificate,
        verified.evidence_ref(),
        maximum_trusted_lifetime_ms,
    )?)
}

/// The one certificate for a consumer on this question's scope, optionally
/// on one subject. Pulse keys consumers by subject and consumer, so one
/// consumer id may hold certificates on several subjects; more than one
/// match is refused rather than picked.
fn consumer_certificate(
    snapshot: &ReactorSnapshotV1,
    consumer: &ConsumerId,
    subject: Option<&str>,
) -> Result<RelianceSupportCertificateV1, ConsequenceError> {
    if !snapshot.condition.exposes_live_standing() {
        return Err(ConsequenceError::new(
            "reactor_not_operational",
            format!("reactor condition is {:?}", snapshot.condition),
        ));
    }
    let scope = REQUIRED_QUESTION.spec().pulse_scope;
    let mut matches = snapshot.certificates.iter().filter(|certificate| {
        &certificate.consumer == consumer
            && certificate.subject_scope.scope == scope
            && subject.is_none_or(|subject| certificate.subject_scope.subject.as_str() == subject)
    });
    let Some(certificate) = matches.next() else {
        return Err(ConsequenceError::new(
            "certificate_missing",
            "reactor holds no certificate for the consumer on this question's scope and subject",
        ));
    };
    if matches.next().is_some() {
        return Err(ConsequenceError::new(
            "certificate_ambiguous",
            "reactor holds more than one certificate for the consumer on this question's scope; name the subject",
        ));
    }
    Ok(certificate.clone())
}
