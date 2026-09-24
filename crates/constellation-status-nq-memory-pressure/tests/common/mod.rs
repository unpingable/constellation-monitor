#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use constellation_status_nq_memory_pressure::{
    CONSEQUENCE_SCHEMA_V1, FACT_OWNER, PUBLIC_COMPONENT_LABEL, live_support_selector,
    recommended_safe_reasons,
};
use constellation_status_projection::{
    AudienceClassV1, ComponentOutputFieldV1, ComponentPolicyV1, DependencyBehaviorV1,
    DependencyEdgeV1, DependencyEffectV1, DependencyKindV1, DisclosurePolicyV1, FactRequirementV1,
    LiveSupportSelectorV1, OutputComponentV1, PROJECTION_POLICY_SCHEMA_V1, ProjectionPolicyV1,
    SourceFactClassV1,
};
use pulse_nq_load_correspondence::fixture::{
    FakeNq, SYNTHETIC_SUBJECT_INCARNATION, SyntheticOutcome, start_reactor, synthetic_profile_for,
};
use pulse_nq_load_correspondence::{
    Coproducer, CorrespondenceProfileV1, FixedSubjectIncarnation, OccurrenceOutcomeV1, QuestionV1,
    VerifiedCorrespondenceV1,
};
use pulse_runtime::LocalCrashReactor;
use pulse_types::IncarnationId;

pub const CONDITION_KEY: &str = "nq.host_memory.pressure_stall";
pub const CONDITION_OUTPUT: &str = "memory-pressure";
pub const FACT_ID: &str = "fact.nq.host_memory.pressure_stall";
static SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub struct Harness {
    pub profile: CorrespondenceProfileV1,
    pub reactor: LocalCrashReactor,
    pub nq: FakeNq,
    pub intent_dir: PathBuf,
    pub audit_dir: PathBuf,
    pub witness: FixedSubjectIncarnation,
    journal: PathBuf,
    _root: tempfile::TempDir,
}

pub fn harness(label: &str, outcome: SyntheticOutcome) -> Harness {
    harness_for(QuestionV1::HostMemoryPressureStallV1, label, outcome)
}

/// A harness for any question of the closed table; the load question is used
/// only to prove this adapter refuses it.
pub fn harness_for(question: QuestionV1, label: &str, outcome: SyntheticOutcome) -> Harness {
    let profile = synthetic_profile_for(question).expect("profile");
    let root = tempfile::tempdir().expect("tempdir");
    let unique = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let journal = root.path().join(format!("{label}-{unique}.journal"));
    let reactor = start_reactor(
        &profile,
        IncarnationId::new(SYNTHETIC_SUBJECT_INCARNATION),
        &format!("consequence-{label}-{unique}"),
        &journal,
    )
    .expect("reactor");
    Harness {
        nq: FakeNq::new(profile.clone(), outcome),
        profile,
        reactor,
        intent_dir: root.path().join("intent"),
        audit_dir: root.path().join("audit"),
        witness: FixedSubjectIncarnation(IncarnationId::new(SYNTHETIC_SUBJECT_INCARNATION)),
        journal,
        _root: root,
    }
}

impl Harness {
    pub fn coproducer(&self) -> Coproducer<'_> {
        Coproducer::begin(
            &self.profile,
            &self.nq,
            &self.witness,
            &self.intent_dir,
            &self.audit_dir,
        )
        .expect("coproducer")
    }

    pub fn verified(&self, coproducer: &mut Coproducer<'_>) -> VerifiedCorrespondenceV1 {
        let result = coproducer
            .run_occurrence(&self.reactor)
            .expect("occurrence");
        match result.outcome {
            OccurrenceOutcomeV1::Verified(verified) => *verified,
            OccurrenceOutcomeV1::AuditOnly { refusal } => panic!("audit only: {refusal}"),
        }
    }

    pub fn selector(&self) -> LiveSupportSelectorV1 {
        live_support_selector(&self.reactor.snapshot(), &self.profile.consumer()).expect("selector")
    }

    /// The selector of this harness's certificate whatever its scope, built
    /// by hand so a harness for the other question can author a policy that
    /// this adapter must then refuse.
    pub fn selector_any_scope(&self) -> LiveSupportSelectorV1 {
        let snapshot = self.reactor.snapshot();
        let certificate = snapshot
            .certificates
            .iter()
            .find(|certificate| certificate.consumer == self.profile.consumer())
            .expect("certificate");
        let qualified = certificate
            .qualified_generation
            .as_ref()
            .expect("qualified generation");
        LiveSupportSelectorV1 {
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
        }
    }

    pub fn finish(self) {
        self.reactor.shutdown().expect("shutdown");
        let _ = std::fs::remove_file(self.journal);
    }
}

pub fn requirement(selector: LiveSupportSelectorV1) -> FactRequirementV1 {
    FactRequirementV1 {
        fact_id: FACT_ID.to_owned(),
        owner: FACT_OWNER.to_owned(),
        native_schema: CONSEQUENCE_SCHEMA_V1.to_owned(),
        class: SourceFactClassV1::DerivedAdmitted,
        live_support: selector,
    }
}

pub fn disclosure(public: bool) -> DisclosurePolicyV1 {
    DisclosurePolicyV1 {
        audience: if public {
            AudienceClassV1::Public
        } else {
            AudienceClassV1::Operator
        },
        component_fields: if public {
            vec![
                ComponentOutputFieldV1::DisplayName,
                ComponentOutputFieldV1::State,
                ComponentOutputFieldV1::Mode,
                ComponentOutputFieldV1::Reason,
            ]
        } else {
            vec![
                ComponentOutputFieldV1::DisplayName,
                ComponentOutputFieldV1::State,
                ComponentOutputFieldV1::Mode,
                ComponentOutputFieldV1::Reason,
                ComponentOutputFieldV1::Detail,
            ]
        },
        safe_reasons: recommended_safe_reasons(),
        include_basis_digest: !public,
        include_observation_window: false,
    }
}

/// A single-component policy: the memory pressure-stall condition is
/// the root.
pub fn condition_policy(selector: LiveSupportSelectorV1, public: bool) -> ProjectionPolicyV1 {
    ProjectionPolicyV1 {
        schema: PROJECTION_POLICY_SCHEMA_V1.to_owned(),
        projection_id: if public {
            "public-memory-pressure".to_owned()
        } else {
            "operator-memory-pressure".to_owned()
        },
        generation: "candidate-1".to_owned(),
        root_component: CONDITION_KEY.to_owned(),
        maximum_age_ms: 60_000,
        admitted_clock_uncertainty_ms: 250,
        timestamp_granularity_ms: 1_000,
        components: vec![ComponentPolicyV1 {
            key: CONDITION_KEY.to_owned(),
            output: Some(OutputComponentV1 {
                id: CONDITION_OUTPUT.to_owned(),
                display_name: PUBLIC_COMPONENT_LABEL.to_owned(),
            }),
            required_facts: vec![requirement(selector)],
            maintenance_assertion_ids: Vec::new(),
        }],
        dependencies: Vec::new(),
        disclosure: disclosure(public),
    }
}

/// The condition component depends on a hidden synthetic component whose
/// fact and support the test supplies. Used only to prove dependency behavior
/// stays explicit and never invents state.
pub fn dependency_policy(
    selector: LiveSupportSelectorV1,
    dependency: FactRequirementV1,
    kind: DependencyKindV1,
    behavior: DependencyBehaviorV1,
) -> ProjectionPolicyV1 {
    let mut policy = condition_policy(selector, false);
    policy.components.push(ComponentPolicyV1 {
        key: "synthetic.dependency".to_owned(),
        output: None,
        required_facts: vec![dependency],
        maintenance_assertion_ids: Vec::new(),
    });
    policy.dependencies = vec![DependencyEdgeV1 {
        parent: CONDITION_KEY.to_owned(),
        dependency: "synthetic.dependency".to_owned(),
        kind,
        behavior,
    }];
    policy
}

pub fn hard_behavior() -> DependencyBehaviorV1 {
    DependencyBehaviorV1 {
        on_unavailable: DependencyEffectV1::MajorOutage,
        on_degraded: DependencyEffectV1::Degrade,
        on_partial: DependencyEffectV1::PartialOutage,
        on_unknown: DependencyEffectV1::Unknown,
    }
}
