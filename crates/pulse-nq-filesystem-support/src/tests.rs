use super::*;
use sha2::{Digest as _, Sha256};

fn test_scope() -> native::HostFilesystemScope {
    native::HostFilesystemScope {
        schema: native::SCOPE_SCHEMA.into(),
        machine_id: "a".repeat(32),
        filesystem_uuid: "00000000-0000-0000-0000-000000000000".into(),
        filesystem_type: "ext4".into(),
        mountpoint: "/".into(),
    }
}
fn test_payload(scope: &native::HostFilesystemScope) -> native::FilesystemSnapshotPayload {
    native::FilesystemSnapshotPayload {
        evidence_basis: EvidenceBasis {
            scope: ScopeGrant {
                kind: native::SCOPE_KIND.into(),
                value: serde_json::to_value(scope).unwrap(),
            },
            vantage: VantageGrant {
                kind: "local".into(),
                value: serde_json::json!({}),
            },
            access_path: native::ACCESS_PATH.into(),
            basis: "kernel_snapshot".into(),
            regime: "normal".into(),
            capabilities_used: native::CAPABILITIES
                .iter()
                .map(|x| (*x).to_owned())
                .collect(),
        },
        machine_id: scope.machine_id.clone(),
        filesystem_uuid: scope.filesystem_uuid.clone(),
        filesystem_type: scope.filesystem_type.clone(),
        mountpoint: scope.mountpoint.clone(),
        mount_id: 1,
        device_major: 8,
        device_minor: 1,
        fsid_hex: native::ext4_fsid_hex(&scope.filesystem_uuid).unwrap(),
        fragment_size: 4096,
        blocks_total: 1_000,
        blocks_free: 500,
        blocks_available: 500,
        inodes_total: 1_000,
        inodes_free: 500,
    }
}
fn test_config() -> FilesystemSupportConfigV1 {
    let scope = test_scope();
    let subject_id = native::subject_for(&scope.machine_id, &scope.filesystem_uuid);
    let descriptor = native::CAPACITY_MODULE.descriptor();
    let preimage = serde_json::json!({"schema":"nq.diagnostic_scope.v1","subject":subject_id,
        "scope":{"kind":native::SCOPE_KIND,"value":scope},"profile":{"id":descriptor.profile.id,
        "version":descriptor.profile.version.to_string(),"digest":descriptor.digest().unwrap()}});
    let mut result = FilesystemSupportConfigV1 {
        schema: CONFIG_SCHEMA.into(),
        authority_id: "filesystem-support:nightshift:filesystem-test".into(),
        consumer_id: "nightshift:filesystem-test".into(),
        producer_id: "filesystem-producer-test".into(),
        producer_key_id: "filesystem-key-test".into(),
        producer_public_key_hex: encode_hex(
            ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                .verifying_key()
                .as_bytes(),
        ),
        producer_private_key_path: "/test/private.key".into(),
        subject_id,
        scope_id: format!(
            "sha256:{:x}",
            Sha256::digest(nq_protocol::canonical_json_bytes(&preimage).unwrap())
        ),
        scope,
        vantage: VantageGrant {
            kind: "local".into(),
            value: serde_json::json!({}),
        },
        profile_semantic_id: nq_profiles::profile_semantic_id(descriptor)
            .unwrap()
            .as_str()
            .into(),
        realization: test_realization(),
        outgoing_directory: "/test/outgoing".into(),
        receipt_directory: "/test/receipts".into(),
        expected_diagnostic: pulse_nq_load_support::ExpectedDiagnosticV1 {
            diagnostic_inputs_id: format!("sha256:{}", "a".repeat(64)),
            artifact_ids: vec![format!("sha256:{}", "b".repeat(64))],
            expected_state: LoadPressureStateV1::ExplicitlyAbsent,
        },
    };
    result.realization.configuration_digest = result.configuration_digest().unwrap();
    result.realization.realization_id = object_id(&result.realization, "realization_id").unwrap();
    result
}
fn test_receipt(observed: u64, expiry: u64, state: LoadPressureStateV1) -> FilesystemReceiptV1 {
    let c = test_config();
    let enrollment_id = c.enrollment_id().unwrap();
    let instant = ReceiverInstantV1 {
        clock_id: "boot-a".into(),
        tick_ms: observed,
    };
    FilesystemReceiptV1 {
        schema: RECEIPT_SCHEMA.into(),
        receipt_id: String::new(),
        received_at: instant.clone(),
        expiry_tick_ms: expiry,
        envelope: FilesystemEnvelopeV1 {
            schema: ENVELOPE_SCHEMA.into(),
            signature_hex: String::new(),
            evidence: FilesystemEvidenceV1 {
                schema: EVIDENCE_SCHEMA.into(),
                evidence_id: String::new(),
                acquisition_id: "test-occurrence".into(),
                authority_id: c.authority_id,
                consumer_id: c.consumer_id,
                producer_id: c.producer_id,
                producer_key_id: c.producer_key_id,
                subject_id: c.subject_id,
                scope_id: c.scope_id,
                realization_id: c.realization.realization_id.clone(),
                enrollment_id,
                profile_semantic_id: c.profile_semantic_id,
                diagnostic_inputs_id: c.expected_diagnostic.diagnostic_inputs_id,
                artifact_ids: c.expected_diagnostic.artifact_ids,
                observation_started: instant.clone(),
                observation_ended: instant,
                payload: test_payload(&c.scope),
                state,
            },
        },
    }
}
fn test_query(c: &FilesystemSupportConfigV1) -> PresentEvidenceQueryV1 {
    let mut q = PresentEvidenceQueryV1 {
        schema: SUPPORT_QUERY_SCHEMA.into(),
        query_id: String::new(),
        observation_cycle_id: "cycle:test".into(),
        request_nonce: "nonce:test".into(),
        observation_id: "observation:test".into(),
        diagnostic_inputs_id: c.expected_diagnostic.diagnostic_inputs_id.clone(),
        subject_id: c.subject_id.clone(),
        scope_id: c.scope_id.clone(),
        artifact_ids: c.expected_diagnostic.artifact_ids.clone(),
    };
    q.query_id = object_id(&q, "query_id").unwrap();
    q
}

#[test]
fn missing_receipt_is_unknown_and_observation_expiry_is_not_refreshed() {
    let clock = ReceiverInstantV1 {
        clock_id: "boot-a".into(),
        tick_ms: 100,
    };
    assert_eq!(
        standing_at(None, &clock, LoadPressureStateV1::ExplicitlyAbsent),
        QualifiedStandingV1::Unknown
    );
    let receipt = test_receipt(100, 1_000, LoadPressureStateV1::ExplicitlyAbsent);
    assert_eq!(
        standing_at(
            Some(&receipt),
            &clock,
            LoadPressureStateV1::ExplicitlyAbsent
        ),
        QualifiedStandingV1::Current
    );
    let expired = ReceiverInstantV1 {
        clock_id: "boot-a".into(),
        tick_ms: 990,
    };
    assert_eq!(
        standing_at(
            Some(&receipt),
            &expired,
            LoadPressureStateV1::ExplicitlyAbsent
        ),
        QualifiedStandingV1::Expired
    );
    let other_boot = ReceiverInstantV1 {
        clock_id: "boot-b".into(),
        tick_ms: 100,
    };
    assert_eq!(
        standing_at(
            Some(&receipt),
            &other_boot,
            LoadPressureStateV1::ExplicitlyAbsent
        ),
        QualifiedStandingV1::Unknown
    );
    assert_eq!(
        standing_at(Some(&receipt), &clock, LoadPressureStateV1::Present),
        QualifiedStandingV1::Contradictory
    );
}

#[test]
fn native_capacity_law_preserves_edge_zero_and_identity_failures() {
    let scope = test_scope();
    let mut payload = test_payload(&scope);
    payload.blocks_total = 1_000;
    payload.blocks_free = 100;
    payload.blocks_available = 100;
    assert_eq!(
        classify(&scope, &payload).unwrap(),
        LoadPressureStateV1::Present
    );
    payload.blocks_free = 101;
    payload.blocks_available = 101;
    assert_eq!(
        classify(&scope, &payload).unwrap(),
        LoadPressureStateV1::ExplicitlyAbsent
    );
    payload.blocks_total = 0;
    payload.blocks_free = 0;
    payload.blocks_available = 0;
    assert!(classify(&scope, &payload).is_err());
    payload = test_payload(&scope);
    payload.filesystem_uuid = "00000000-0000-0000-0000-000000000001".into();
    assert!(classify(&scope, &payload).is_err());
}

#[test]
fn filesystem_configuration_refuses_status_consumer_and_wrong_native_profile() {
    let mut config = test_config();
    config.validate().unwrap();
    config.consumer_id = "constellation-status".into();
    assert!(config.validate().is_err());
    config = test_config();
    config.profile_semantic_id =
        "sha256:382b8dac14ef9353a3603757d60fc8fbc727e1bcaf088c9aab4bdf895d3f6ab1".into();
    assert!(config.validate().is_err());
    config = test_config();
    config.receipt_directory = config.outgoing_directory.clone();
    assert!(config.validate().is_err());
    config = test_config();
    config.vantage.kind = "remote".into();
    assert!(config.validate().is_err());
}

#[test]
fn query_binds_exact_diagnostic_subject_scope_and_artifacts() {
    let config = test_config();
    let query = test_query(&config);
    validate_filesystem_query(&config, &query).unwrap();
    let mut changed = query.clone();
    changed.subject_id.push('x');
    assert!(validate_filesystem_query(&config, &changed).is_err());
    changed = query.clone();
    changed.artifact_ids = vec![format!("sha256:{}", "c".repeat(64))];
    assert!(validate_filesystem_query(&config, &changed).is_err());
    changed = query;
    changed.diagnostic_inputs_id = format!("sha256:{}", "d".repeat(64));
    assert!(validate_filesystem_query(&config, &changed).is_err());
}

#[test]
fn signed_native_payload_cannot_be_substituted_or_rebound() {
    let c = test_config();
    let mut x = test_receipt(100, 300_100, LoadPressureStateV1::ExplicitlyAbsent).envelope;
    x.evidence.evidence_id = object_id(&x.evidence, "evidence_id").unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let mut message = SIGNATURE_DOMAIN.to_vec();
    message.extend(canonical_bytes(&x.evidence).unwrap());
    x.signature_hex = encode_hex(&key.sign(&message).to_bytes());
    verify_envelope(&c, &x, true).unwrap();
    let mut changed = x.clone();
    changed.evidence.payload.blocks_available -= 1;
    changed.evidence.evidence_id = object_id(&changed.evidence, "evidence_id").unwrap();
    assert!(verify_envelope(&c, &changed, true).is_err());
    changed = x.clone();
    changed.evidence.consumer_id = "constellation-status".into();
    assert!(verify_envelope(&c, &changed, true).is_err());
    changed = x;
    changed.evidence.diagnostic_inputs_id = format!("sha256:{}", "d".repeat(64));
    assert!(verify_envelope(&c, &changed, true).is_err());
}

#[test]
fn latest_custody_has_fixed_size_and_refuses_noncanonical_bytes() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o2750)).unwrap();
    replace_latest(d.path(), "current.json", b"{\"a\":1}").unwrap();
    replace_latest(d.path(), "current.json", b"{\"a\":2}").unwrap();
    assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 1);
    let file = std::fs::metadata(d.path().join("current.json")).unwrap();
    assert_eq!(file.mode() & 0o7777, 0o640);
    assert_eq!(file.gid(), std::fs::metadata(d.path()).unwrap().gid());
    let x: serde_json::Value = read_canonical(&d.path().join("current.json")).unwrap();
    assert_eq!(x["a"], 2);
    std::fs::write(d.path().join("current.json"), b"{ \"a\":2}").unwrap();
    assert!(read_canonical::<serde_json::Value>(&d.path().join("current.json")).is_err());
}

#[test]
fn producer_key_is_new_private_custody_and_is_never_overwritten() {
    use std::os::unix::fs::PermissionsExt as _;
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("producer.key");
    let public = create_producer_key(&p).unwrap();
    assert_eq!(public.len(), 64);
    assert_eq!(
        std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let bytes = std::fs::read(&p).unwrap();
    assert!(create_producer_key(&p).is_err());
    assert_eq!(std::fs::read(&p).unwrap(), bytes);
    assert_eq!(
        encode_hex(read_signing_key(&p).unwrap().verifying_key().as_bytes()),
        public
    );
}

fn test_realization() -> AdapterRealizationV1 {
    let mut x = AdapterRealizationV1 {
        schema: REALIZATION_SCHEMA.into(),
        realization_id: String::new(),
        executable_sha256: format!("sha256:{}", "1".repeat(64)),
        monitor_source_commit: "2".repeat(40),
        monitor_source_tree_digest: format!("sha256:{}", "3".repeat(64)),
        monitor_cargo_lock_digest: format!("sha256:{}", "4".repeat(64)),
        resolved_dependency_inventory_digest: format!("sha256:{}", "5".repeat(64)),
        qualification_receipt_digest: format!("sha256:{}", "6".repeat(64)),
        configuration_digest: format!("sha256:{}", "7".repeat(64)),
        nq_source_commit: NQ_SOURCE_COMMIT.into(),
    };
    x.realization_id = object_id(&x, "realization_id").unwrap();
    x
}

#[test]
fn realization_rejects_substituted_executable_source_lock_and_unsigned_rebinding() {
    let x = test_realization();
    x.validate().unwrap();
    let source = Some(x.monitor_source_commit.as_str());
    x.validate_running(&x.executable_sha256, source, &x.monitor_cargo_lock_digest)
        .unwrap();
    assert!(
        x.validate_running(
            &format!("sha256:{}", "f".repeat(64)),
            source,
            &x.monitor_cargo_lock_digest
        )
        .is_err()
    );
    assert!(
        x.validate_running(&x.executable_sha256, None, &x.monitor_cargo_lock_digest)
            .is_err()
    );
    assert!(
        x.validate_running(
            &x.executable_sha256,
            Some(&"0".repeat(40)),
            &x.monitor_cargo_lock_digest
        )
        .is_err()
    );
    assert!(
        x.validate_running(
            &x.executable_sha256,
            source,
            &format!("sha256:{}", "e".repeat(64))
        )
        .is_err()
    );
    let mut changed = x.clone();
    changed.qualification_receipt_digest = format!("sha256:{}", "a".repeat(64));
    assert!(changed.validate().is_err());
}

#[test]
fn signed_realization_and_enrollment_cannot_be_rebound() {
    let c = test_config();
    let mut x = test_receipt(100, 300_100, LoadPressureStateV1::ExplicitlyAbsent).envelope;
    x.evidence.evidence_id = object_id(&x.evidence, "evidence_id").unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let mut message = SIGNATURE_DOMAIN.to_vec();
    message.extend(canonical_bytes(&x.evidence).unwrap());
    x.signature_hex = encode_hex(&key.sign(&message).to_bytes());
    verify_envelope(&c, &x, true).unwrap();
    let mut changed = x.clone();
    changed.evidence.realization_id = format!("sha256:{}", "f".repeat(64));
    assert!(verify_envelope(&c, &changed, true).is_err());
    changed = x;
    changed.evidence.enrollment_id = format!("sha256:{}", "e".repeat(64));
    assert!(verify_envelope(&c, &changed, true).is_err());
    let mut substituted_config = c.clone();
    substituted_config.outgoing_directory = "/other/outgoing".into();
    assert!(substituted_config.validate().is_err());
    let mut next_basis = c.clone();
    next_basis.expected_diagnostic.diagnostic_inputs_id = format!("sha256:{}", "d".repeat(64));
    assert_eq!(
        c.enrollment_id().unwrap(),
        next_basis.enrollment_id().unwrap()
    );
    next_basis.consumer_id.push_str("-other");
    assert_ne!(
        c.enrollment_id().unwrap(),
        next_basis.enrollment_id().unwrap()
    );
}

#[test]
fn nq_owned_scope_and_canonical_preimages_use_owner_api() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../artifacts/nightshift-filesystem-support-v1/conformance.json"
    ))
    .unwrap();
    for case in vectors["nq_canonical_vectors"].as_array().unwrap() {
        let got = nq_protocol::canonical_json_bytes(&case["value"]);
        if let Some(expected) = case["expected_utf8"].as_str() {
            assert_eq!(got.unwrap(), expected.as_bytes(), "{}", case["id"]);
        } else {
            assert!(got.is_err(), "{}", case["id"]);
        }
    }
    let c = test_config();
    assert_eq!(
        native_scope_digest(&c.subject_id, &c.scope).unwrap(),
        vectors["scope_id"].as_str().unwrap()
    );
}

#[test]
fn shared_configuration_query_and_support_bytes_are_exact() {
    let config_bytes =
        include_bytes!("../../../artifacts/nightshift-filesystem-support-v1/config.json");
    let query_bytes =
        include_bytes!("../../../artifacts/nightshift-filesystem-support-v1/query.json");
    let support_bytes =
        include_bytes!("../../../artifacts/nightshift-filesystem-support-v1/support-current.json");
    let config: FilesystemSupportConfigV1 = serde_json::from_slice(config_bytes).unwrap();
    config.validate().unwrap();
    assert_eq!(
        canonical_bytes(&config).unwrap().as_slice(),
        config_bytes.as_slice()
    );
    let query: PresentEvidenceQueryV1 = serde_json::from_slice(query_bytes).unwrap();
    validate_filesystem_query(&config, &query).unwrap();
    assert_eq!(
        canonical_bytes(&query).unwrap().as_slice(),
        query_bytes.as_slice()
    );
    let support: QualifiedSupportV1 = serde_json::from_slice(support_bytes).unwrap();
    assert_eq!(
        canonical_bytes(&support).unwrap().as_slice(),
        support_bytes.as_slice()
    );
    assert_eq!(
        object_id(&support, "support_id").unwrap(),
        support.support_id
    );
    assert_eq!(support.query_id, query.query_id);
    assert_eq!(support.authority_id, config.authority_id);
    for field in ["subject_id", "scope_id", "diagnostic_inputs_id"] {
        let mut changed = serde_json::to_value(&query).unwrap();
        changed[field] = serde_json::json!("changed");
        let mut changed: PresentEvidenceQueryV1 = serde_json::from_value(changed).unwrap();
        changed.query_id = object_id(&changed, "query_id").unwrap();
        assert!(validate_filesystem_query(&config, &changed).is_err());
    }
}

#[test]
fn source_owned_capacity_vectors_keep_reserved_denominator_and_refusals() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../artifacts/nightshift-filesystem-support-v1/conformance.json"
    ))
    .unwrap();
    for case in vectors["capacity_vectors"].as_array().unwrap() {
        let scope = test_scope();
        let mut p = test_payload(&scope);
        for (field, target) in [
            ("total", &mut p.blocks_total),
            ("free", &mut p.blocks_free),
            ("available", &mut p.blocks_available),
        ] {
            *target = case[field].as_u64().unwrap();
        }
        if let Some(v) = case["payload_uuid"].as_str() {
            p.filesystem_uuid = v.into();
        }
        if let Some(v) = case["payload_fsid"].as_str() {
            p.fsid_hex = v.into();
        }
        if let Some(v) = case["fragment_size"].as_u64() {
            p.fragment_size = v;
        }
        let got = classify(&scope, &p);
        match case["expected"].as_str().unwrap() {
            "present" => assert_eq!(got.unwrap(), LoadPressureStateV1::Present, "{}", case["id"]),
            "explicitly_absent" => assert_eq!(
                got.unwrap(),
                LoadPressureStateV1::ExplicitlyAbsent,
                "{}",
                case["id"]
            ),
            "refused" => assert!(got.is_err(), "{}", case["id"]),
            other => panic!("unknown vector result {other}"),
        }
    }
}

#[test]
fn publication_requires_exact_setgid_read_only_reader_directory() {
    use std::os::unix::fs::PermissionsExt as _;
    for mode in [0o700, 0o750, 0o770, 0o2770, 0o2755] {
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(
            replace_latest(d.path(), "current.json", b"{}").is_err(),
            "mode {mode:o}"
        );
        assert!(!d.path().join("current.json").exists());
    }
}
