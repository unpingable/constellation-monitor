#![forbid(unsafe_code)]

use proptest::prelude::*;
use pulse_qualification::{
    FIXTURE_CONSUMER, FIXTURE_SUBJECT, build_fixture_package, fixture_config, fixture_ingress,
    fixture_registration, retarget_artifact, run_authority_laundering_corpus, run_lifecycle_demo,
    run_load_bearing_mismatch_corpus, run_matched_activation_demo, run_restart_demo,
};
use pulse_runtime::{
    ReceiverSchedulerRuntime, RuntimeInputV1, active_runtime_measurements,
    qualification_fixture_inputs,
};
use pulse_types::{
    ActivationReceiptV1, ArtifactRoleV1, AuthorityGrantsV1, ConsumerId,
    GenerationLifecycleFactBodyV1, GenerationLifecycleFactV1, GenerationLifecycleKindV1,
    JudgmentCategoryV1, LocalActivationContextV1, LocalCertificateStatusV1, MutationAuthorityV1,
    QualificationCertificateV1, QualificationEvidenceReportV1, QualifiedArtifactManifestV1,
    QualifiedGenerationSetV1, RuntimeBindingStateV1, SubjectId, verify_local_activation,
    verify_qualification_package,
};

fn subject() -> SubjectId {
    SubjectId::new(FIXTURE_SUBJECT)
}

fn consumer() -> ConsumerId {
    ConsumerId::new(FIXTURE_CONSUMER)
}

#[test]
fn exact_manifest_qualification_and_activation_are_three_distinct_judgments() {
    let (demo, package, receipt) = run_matched_activation_demo().expect("matched demo");
    assert_eq!(demo.steps.len(), 2);
    assert_eq!(demo.steps[0].judgment, JudgmentCategoryV1::Unknown);
    assert_eq!(demo.steps[1].judgment, JudgmentCategoryV1::Current);
    assert_eq!(
        receipt.body.state,
        RuntimeBindingStateV1::QualifiedAndMatched
    );
    assert_ne!(
        package.manifest.manifest_digest,
        package.certificate.certificate_digest
    );
    assert_ne!(
        package.certificate.certificate_digest,
        receipt.receipt_digest
    );
    assert_eq!(
        demo.steps[1].qualified_manifest_digest.as_ref(),
        Some(&package.manifest.manifest_digest)
    );
    assert_eq!(
        demo.steps[1].qualified_certificate_digest.as_ref(),
        Some(&package.certificate.certificate_digest)
    );
    assert_eq!(
        demo.steps[1].qualified_activation_receipt_digest.as_ref(),
        Some(&receipt.receipt_digest)
    );
    assert_eq!(demo.steps[1].mutation_authority, MutationAuthorityV1::None);
}

#[test]
fn caller_generation_label_and_fresh_evidence_cannot_bypass_unbound_gate() {
    let mut runtime = ReceiverSchedulerRuntime::new(fixture_config(
        "receiver-incarnation:unbound",
        "clock:unbound",
    ))
    .expect("runtime");
    runtime
        .register_consumer(fixture_registration(), 0)
        .expect("declared registration is admitted cautiously");
    runtime.enqueue(1, fixture_ingress(1, 100)).expect("pulse");
    runtime.run_until(1).expect("evaluation");
    let certificate = runtime
        .current_certificate(&subject(), &consumer())
        .expect("certificate");
    assert_eq!(
        runtime.binding_state(&subject(), &consumer()),
        RuntimeBindingStateV1::Unbound
    );
    assert_eq!(certificate.judgment, JudgmentCategoryV1::Unknown);
    assert!(certificate.qualified_generation.is_none());
    assert_eq!(runtime.scheduled_deadline_count(), 0);
}

#[test]
fn every_load_bearing_identity_mismatch_refuses_current_and_deadlines() {
    let corpus = run_load_bearing_mismatch_corpus().expect("mismatch corpus");
    assert!(corpus.all_passed);
    assert_eq!(corpus.checks.len(), 8);
    assert!(corpus.checks.iter().all(|check| {
        !check.current_permitted
            && !check.authority_granted
            && check.active_deadlines == 0
            && check.expected_binding_state == check.observed_binding_state
    }));
}

#[test]
fn authority_laundering_objects_are_individually_insufficient() {
    let corpus = run_authority_laundering_corpus().expect("authority corpus");
    assert!(corpus.all_passed);
    assert!(corpus.checks.len() >= 12);
    assert!(corpus.checks.iter().all(|check| {
        check.passed
            && !check.current_permitted
            && !check.authority_granted
            && check.active_deadlines == 0
    }));
}

#[test]
fn manifest_without_certificate_or_report_is_not_activation() {
    let config = fixture_config("receiver-incarnation:partial", "clock:partial");
    let registration = fixture_registration();
    let package = build_fixture_package(&config, &registration).expect("package");
    let manifest = package.manifest_bytes().expect("manifest bytes");
    let report = package.report_bytes().expect("report bytes");
    let mut runtime = ReceiverSchedulerRuntime::new(config).expect("runtime");
    let missing_certificate = runtime
        .activate_qualified_binding(
            &registration,
            Some(&manifest),
            None,
            Some(&report),
            package.acceptance.clone(),
            0,
        )
        .expect("failure is a receipt");
    assert_eq!(
        missing_certificate.receipt.body.state,
        RuntimeBindingStateV1::MissingCertificate
    );
    runtime
        .register_consumer(registration, 0)
        .expect("registration remains nonpositive");
    runtime.enqueue(1, fixture_ingress(1, 100)).expect("pulse");
    runtime.run_until(1).expect("evaluation");
    assert_eq!(
        runtime
            .current_certificate(&subject(), &consumer())
            .expect("certificate")
            .judgment,
        JudgmentCategoryV1::Unknown
    );
}

#[test]
fn caller_supplied_measurement_cannot_be_downgraded_to_a_warning() {
    let config = fixture_config(
        "receiver-incarnation:caller-measurement",
        "clock:caller-measurement",
    );
    let registration = fixture_registration();
    let package = build_fixture_package(&config, &registration).expect("package");
    let mut measurements =
        active_runtime_measurements(&config, &registration).expect("measurements");
    measurements[0].caller_supplied = true;
    let attempt = verify_local_activation(
        Some(&package.manifest_bytes().expect("manifest")),
        Some(&package.certificate_bytes().expect("certificate")),
        Some(&package.report_bytes().expect("report")),
        &package.acceptance,
        LocalActivationContextV1 {
            expected_generation_set: QualifiedGenerationSetV1::from_context(
                registration.policy.subject,
                registration.policy.consumer,
                &registration.context,
            ),
            receiver_incarnation: config.receiver_incarnation,
            receiver_clock_id: config.clock_id,
            activated_at_monotonic_ms: 0,
            runtime_version: "0.1.0".to_owned(),
            target_platform: "x86_64-unknown-linux".to_owned(),
            semantic_measurements: measurements,
        },
    )
    .expect("refusal receipt");
    assert_ne!(
        attempt.receipt.body.state,
        RuntimeBindingStateV1::QualifiedAndMatched
    );
    assert!(attempt.accepted.is_none());
    assert!(attempt.receipt.body.any_measurement_caller_supplied);
}

#[test]
fn old_certificate_new_manifest_and_changed_evidence_are_refused() {
    let config = fixture_config("receiver-incarnation:pairing", "clock:pairing");
    let registration = fixture_registration();
    let old = build_fixture_package(&config, &registration).expect("old package");
    let new = retarget_artifact(
        &old,
        ArtifactRoleV1::QualificationCorpus,
        b"different qualified corpus bytes",
    )
    .expect("new internally exact package");
    let manifest = new.manifest_bytes().expect("new manifest");
    let old_certificate = old.certificate_bytes().expect("old certificate");
    let new_report = new.report_bytes().expect("new report");
    let mut acceptance = new.acceptance.clone();
    acceptance.accepted_certificate_digest = old.certificate.certificate_digest.clone();
    let mut runtime = ReceiverSchedulerRuntime::new(config).expect("runtime");
    let result = runtime
        .activate_qualified_binding(
            &registration,
            Some(&manifest),
            Some(&old_certificate),
            Some(&new_report),
            acceptance,
            0,
        )
        .expect("cross-binding failure is recorded");
    assert_eq!(
        result.receipt.body.state,
        RuntimeBindingStateV1::ManifestMismatch
    );
    assert!(
        result
            .receipt
            .body
            .mismatches
            .iter()
            .any(|mismatch| mismatch.code == "package_cross_binding")
    );
}

#[test]
fn source_toolchain_and_feature_identity_changes_break_exact_package_pairing() {
    let config = fixture_config("receiver-incarnation:build-pairing", "clock:build-pairing");
    let registration = fixture_registration();
    let package = build_fixture_package(&config, &registration).expect("package");
    let mut variants = Vec::new();

    let mut source = package.manifest.body.clone();
    source.source.commit = "1111111111111111111111111111111111111111".to_owned();
    variants.push(source);

    let mut toolchain = package.manifest.body.clone();
    toolchain.build.toolchain_identity = "different exact toolchain identity".to_owned();
    variants.push(toolchain);

    let mut features = package.manifest.body.clone();
    features.build.enabled_features = vec!["different-feature-set".to_owned()];
    variants.push(features);

    for body in variants {
        let manifest = QualifiedArtifactManifestV1::new(body).expect("variant manifest");
        assert_ne!(manifest.manifest_digest, package.manifest.manifest_digest);
        assert!(
            verify_qualification_package(&manifest, &package.report, &package.certificate).is_err()
        );
    }
}

#[test]
fn qualification_results_bytes_must_exactly_match_checked_report_inputs() {
    let config = fixture_config("receiver-incarnation:results", "clock:results");
    let registration = fixture_registration();
    let mut inputs =
        qualification_fixture_inputs(pulse_qualification::CAMPAIGN_STARTING_COMMIT, 97);
    inputs.total_tests_passed = 98;
    let error = pulse_runtime::build_local_qualification_package(&config, &registration, inputs)
        .expect_err("caller assertions cannot outrun checked result bytes");
    assert_eq!(error.code, "qualification_artifact_mismatch");
}

#[test]
fn adversarial_binding_identity_churn_hits_an_explicit_bound_without_eviction() {
    let mut config = fixture_config("receiver-incarnation:binding-bound", "clock:binding-bound");
    config.bounds.maximum_subjects = 1;
    config.bounds.maximum_consumers_per_subject = 1;
    let first = fixture_registration();
    let first_package = build_fixture_package(&config, &first).expect("first package");
    let mut runtime = ReceiverSchedulerRuntime::new(config.clone()).expect("runtime");
    runtime
        .activate_qualified_binding(
            &first,
            Some(&first_package.manifest_bytes().expect("manifest")),
            Some(&first_package.certificate_bytes().expect("certificate")),
            Some(&first_package.report_bytes().expect("report")),
            first_package.acceptance,
            0,
        )
        .expect("first binding");

    let mut churn = fixture_registration();
    churn.policy.subject = SubjectId::new("subject:qualified-binding-churn");
    churn.context = pulse_qualification::fixture_context(&churn.policy);
    churn.subject_incarnation =
        pulse_types::IncarnationId::new("subject-incarnation:qualified-churn");
    let churn_package = build_fixture_package(&config, &churn).expect("churn package");
    let error = runtime
        .activate_qualified_binding(
            &churn,
            Some(&churn_package.manifest_bytes().expect("manifest")),
            Some(&churn_package.certificate_bytes().expect("certificate")),
            Some(&churn_package.report_bytes().expect("report")),
            churn_package.acceptance,
            0,
        )
        .expect_err("second identity is explicitly refused");
    assert_eq!(error.code, "qualified_binding_capacity");
    assert_eq!(
        runtime.binding_state(&subject(), &consumer()),
        RuntimeBindingStateV1::QualifiedAndMatched
    );
    assert_eq!(
        runtime.binding_state(
            &SubjectId::new("subject:qualified-binding-churn"),
            &consumer()
        ),
        RuntimeBindingStateV1::Unbound
    );
}

#[test]
fn duplicate_swapped_and_missing_artifact_roles_are_rejected() {
    let config = fixture_config("receiver-incarnation:roles", "clock:roles");
    let registration = fixture_registration();
    let package = build_fixture_package(&config, &registration).expect("package");

    let mut duplicate = package.manifest.body.clone();
    duplicate.artifacts[1].role = duplicate.artifacts[0].role;
    assert!(QualifiedArtifactManifestV1::new(duplicate).is_err());

    let mut swapped = package.manifest.body.clone();
    swapped.artifacts.swap(0, 1);
    assert!(QualifiedArtifactManifestV1::new(swapped).is_err());

    let mut missing = package.manifest.body.clone();
    missing.artifacts.pop();
    assert!(QualifiedArtifactManifestV1::new(missing).is_err());
}

#[test]
fn noncanonical_reordered_and_unknown_mandatory_fields_are_refused() {
    let config = fixture_config("receiver-incarnation:encoding", "clock:encoding");
    let registration = fixture_registration();
    let package = build_fixture_package(&config, &registration).expect("package");
    let canonical = package.manifest_bytes().expect("canonical");
    let mut value: serde_json::Value = serde_json::from_slice(&canonical).expect("JSON");
    let object = value.as_object_mut().expect("object");
    object.insert(
        "unknown_mandatory".to_owned(),
        serde_json::Value::Bool(true),
    );
    let unknown = serde_json::to_vec(&value).expect("JSON");
    assert!(QualifiedArtifactManifestV1::decode_canonical(&unknown).is_err());

    let pretty = serde_json::to_vec_pretty(&package.manifest).expect("pretty JSON");
    assert!(QualifiedArtifactManifestV1::decode_canonical(&pretty).is_err());

    let canonical_text = String::from_utf8(canonical).expect("UTF-8 canonical JSON");
    let duplicate = canonical_text.replacen(
        "\"schema_version\":1",
        "\"schema_version\":1,\"schema_version\":1",
        1,
    );
    assert!(QualifiedArtifactManifestV1::decode_canonical(duplicate.as_bytes()).is_err());
}

#[test]
fn lifecycle_supersession_and_revocation_both_withdraw_without_erasing_history() {
    for kind in [
        GenerationLifecycleKindV1::Superseded,
        GenerationLifecycleKindV1::Revoked,
    ] {
        let artifact = run_lifecycle_demo(kind).expect("lifecycle demo");
        assert_eq!(artifact.before_judgment, JudgmentCategoryV1::Current);
        assert_ne!(artifact.after_judgment, JudgmentCategoryV1::Current);
        assert_eq!(artifact.active_deadlines_after, 0);
        assert!(artifact.historical_receipt_preserved);
        assert!(!artifact.standing_preserved);
    }
}

#[test]
fn arbitrary_revocation_assertion_is_not_accepted_as_authority() {
    let config = fixture_config(
        "receiver-incarnation:revocation-authority",
        "clock:revocation-authority",
    );
    let registration = fixture_registration();
    let package = build_fixture_package(&config, &registration).expect("package");
    let mut runtime = ReceiverSchedulerRuntime::new(config).expect("runtime");
    runtime
        .activate_qualified_binding(
            &registration,
            Some(&package.manifest_bytes().expect("manifest")),
            Some(&package.certificate_bytes().expect("certificate")),
            Some(&package.report_bytes().expect("report")),
            package.acceptance,
            0,
        )
        .expect("activation");
    runtime
        .register_consumer(registration, 0)
        .expect("registration");
    runtime.enqueue(1, fixture_ingress(1, 100)).expect("pulse");
    runtime.run_until(1).expect("current");
    let false_fact = GenerationLifecycleFactV1::new(GenerationLifecycleFactBodyV1 {
        schema_version: pulse_types::SCHEMA_VERSION_V1,
        authority_id: "arbitrary-unconfigured-revoker".to_owned(),
        fact_sequence: 1,
        certificate_digest: package.certificate.certificate_digest,
        kind: GenerationLifecycleKindV1::Revoked,
        successor_manifest_digest: None,
        successor_certificate_digest: None,
        reason: "hostile unconfigured assertion".to_owned(),
        authority_grants: AuthorityGrantsV1::none(),
    })
    .expect("well-formed but unauthorized fact");
    let error = runtime
        .apply_generation_lifecycle_fact(&subject(), &consumer(), false_fact, 2)
        .expect_err("unconfigured authority is refused");
    assert_eq!(error.code, "lifecycle_authority_mismatch");
    assert_eq!(
        runtime.binding_state(&subject(), &consumer()),
        RuntimeBindingStateV1::QualifiedAndMatched
    );
    assert_eq!(
        runtime
            .current_certificate(&subject(), &consumer())
            .expect("certificate")
            .judgment,
        JudgmentCategoryV1::Current
    );
}

#[test]
fn unknown_lifecycle_status_never_activates() {
    let config = fixture_config(
        "receiver-incarnation:unknown-status",
        "clock:unknown-status",
    );
    let registration = fixture_registration();
    let package = build_fixture_package(&config, &registration).expect("package");
    let mut acceptance = package.acceptance.clone();
    acceptance.certificate_status = LocalCertificateStatusV1::Unknown;
    let mut runtime = ReceiverSchedulerRuntime::new(config).expect("runtime");
    let output = runtime
        .activate_qualified_binding(
            &registration,
            Some(&package.manifest_bytes().expect("manifest")),
            Some(&package.certificate_bytes().expect("certificate")),
            Some(&package.report_bytes().expect("report")),
            acceptance,
            0,
        )
        .expect("ambiguous lifecycle is recorded");
    assert_eq!(output.receipt.body.state, RuntimeBindingStateV1::Ambiguous);
}

#[test]
fn prior_activation_receipt_is_history_not_restart_activation() {
    let artifact = run_restart_demo().expect("restart demo");
    assert!(artifact.historical_activation_receipts_recovered > 0);
    assert_eq!(
        artifact.prior_process_binding_state,
        RuntimeBindingStateV1::QualifiedAndMatched
    );
    assert_eq!(
        artifact.restarted_binding_state,
        RuntimeBindingStateV1::Unbound
    );
    assert_eq!(artifact.restarted_judgment, JudgmentCategoryV1::Unknown);
    assert_eq!(artifact.restarted_supporting_evidence_count, 0);
    assert_eq!(artifact.restarted_active_deadlines, 0);
    assert!(!artifact.prior_receipt_reused);
}

#[test]
fn equal_policy_content_under_new_generation_requires_new_exact_package_and_evidence() {
    let config = fixture_config("receiver-incarnation:generation", "clock:generation");
    let old_registration = fixture_registration();
    let old_package = build_fixture_package(&config, &old_registration).expect("old package");
    let mut runtime = ReceiverSchedulerRuntime::new(config.clone()).expect("runtime");
    let old_manifest = old_package.manifest_bytes().expect("manifest");
    let old_certificate = old_package.certificate_bytes().expect("certificate");
    let old_report = old_package.report_bytes().expect("report");
    runtime
        .activate_qualified_binding(
            &old_registration,
            Some(&old_manifest),
            Some(&old_certificate),
            Some(&old_report),
            old_package.acceptance.clone(),
            0,
        )
        .expect("old binding");
    runtime
        .register_consumer(old_registration.clone(), 0)
        .expect("register");
    runtime.enqueue(1, fixture_ingress(1, 100)).expect("pulse");
    runtime.run_until(1).expect("current");
    assert_eq!(
        runtime
            .current_certificate(&subject(), &consumer())
            .expect("old")
            .judgment,
        JudgmentCategoryV1::Current
    );

    let mut new_registration = old_registration;
    new_registration.policy.generation =
        pulse_types::PolicyGenerationId::new("policy:qualified-two");
    new_registration.context.reliance_policy_generation =
        new_registration.policy.generation.clone();
    new_registration.context.activation_id =
        pulse_types::ContextActivationId::new("activation:qualified-two");
    assert_eq!(
        new_registration.policy.semantic_digest(),
        fixture_registration().policy.semantic_digest()
    );
    let rejected = runtime
        .activate_qualified_binding(
            &new_registration,
            Some(&old_manifest),
            Some(&old_certificate),
            Some(&old_report),
            old_package.acceptance,
            2,
        )
        .expect("generation mismatch is a receipt");
    assert_eq!(
        rejected.receipt.body.state,
        RuntimeBindingStateV1::Ambiguous
    );
    assert_ne!(
        runtime
            .current_certificate(&subject(), &consumer())
            .expect("barrier")
            .judgment,
        JudgmentCategoryV1::Current
    );

    let new_package = build_fixture_package(&config, &new_registration).expect("new package");
    runtime
        .activate_qualified_binding(
            &new_registration,
            Some(&new_package.manifest_bytes().expect("manifest")),
            Some(&new_package.certificate_bytes().expect("certificate")),
            Some(&new_package.report_bytes().expect("report")),
            new_package.acceptance,
            3,
        )
        .expect("new exact binding");
    runtime
        .enqueue(
            3,
            RuntimeInputV1::ActivateConsumer(pulse_runtime::ConsumerActivationV1 {
                policy: new_registration.policy,
                context: new_registration.context,
                cause: pulse_types::GenerationTransitionCauseV1::EquivalentBodyNewGeneration,
            }),
        )
        .expect("transition");
    runtime.run_until(3).expect("barrier");
    assert_eq!(
        runtime
            .current_certificate(&subject(), &consumer())
            .expect("new barrier")
            .judgment,
        JudgmentCategoryV1::Unknown
    );
    runtime
        .enqueue(
            3,
            RuntimeInputV1::Reevaluate {
                subject: subject(),
                consumer: consumer(),
            },
        )
        .expect("explicit reevaluation");
    runtime.run_until(3).expect("reevaluation");
    assert_eq!(
        runtime
            .current_certificate(&subject(), &consumer())
            .expect("new current")
            .judgment,
        JudgmentCategoryV1::Current
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn every_manifest_truncation_is_refused(cut_seed in any::<usize>()) {
        let config = fixture_config("receiver-incarnation:truncate", "clock:truncate");
        let registration = fixture_registration();
        let package = build_fixture_package(&config, &registration).expect("package");
        let bytes = package.manifest_bytes().expect("bytes");
        let cut = cut_seed % bytes.len();
        prop_assert!(QualifiedArtifactManifestV1::decode_canonical(&bytes[..cut]).is_err());
    }

    #[test]
    fn every_certificate_truncation_is_refused(cut_seed in any::<usize>()) {
        let config = fixture_config("receiver-incarnation:cert-truncate", "clock:cert-truncate");
        let registration = fixture_registration();
        let package = build_fixture_package(&config, &registration).expect("package");
        let bytes = package.certificate_bytes().expect("bytes");
        let cut = cut_seed % bytes.len();
        prop_assert!(QualificationCertificateV1::decode_canonical(&bytes[..cut]).is_err());
    }

    #[test]
    fn every_report_single_byte_mutation_is_refused(index_seed in any::<usize>(), replacement in any::<u8>()) {
        let config = fixture_config("receiver-incarnation:report-mutate", "clock:report-mutate");
        let registration = fixture_registration();
        let package = build_fixture_package(&config, &registration).expect("package");
        let mut bytes = package.report_bytes().expect("bytes");
        let index = index_seed % bytes.len();
        if bytes[index] == replacement {
            bytes[index] ^= 1;
        } else {
            bytes[index] = replacement;
        }
        prop_assert!(QualificationEvidenceReportV1::decode_canonical(&bytes).is_err());
    }

    #[test]
    fn every_activation_receipt_truncation_is_refused(cut_seed in any::<usize>()) {
        let (_, _, receipt) = run_matched_activation_demo().expect("matched demo");
        let bytes = receipt.canonical_bytes().expect("receipt bytes");
        let cut = cut_seed % bytes.len();
        prop_assert!(ActivationReceiptV1::decode_canonical(&bytes[..cut]).is_err());
    }
}
