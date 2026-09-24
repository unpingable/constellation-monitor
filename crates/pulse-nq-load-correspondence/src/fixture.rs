//! Synthetic NQ output and an in-process NQ port double.
//!
//! Everything here is fixture material for qualifying the verifiers. The
//! artifacts follow the shape of `nq.diagnostic_execution.v2` and
//! `nq.diagnostic_admission_provenance.v1` closely enough to exercise every
//! correspondence rule, but they are produced by this crate, not by NQ, and
//! never establish anything about a host. Positive qualification vectors must
//! come from a real NQ run.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use pulse_types::IncarnationId;
use serde_json::{Value, json};

use crate::record::encode_hex;
use crate::{
    CorrespondenceError, CorrespondenceProfileV1, CorrespondenceRecordV1, DeliveryV1, NQ_CLAIM_ID,
    NQ_CONDITION, NQ_JUDGMENT_SCHEMA, NQ_PROFILE_DIGEST, NQ_PROFILE_ID, NQ_PROVENANCE_SCHEMA,
    NQ_QUESTION_DIGEST, NQ_QUESTION_ID, NQ_REFUSAL_SCHEMA, NQ_SELECTION_RULE_ID, NQ_SOURCE_KIND,
    NqDetectorStateV1, NqEnrollmentV1, NqPort, NqProducerV1, NqSideV1, PulseEnrollmentV1,
    PulseSideV1, SemanticIdentityV1, TRANSPORT_PATH, acquisition_id, build_frame, canonical_bytes,
    evidence_ref, object_id, sha256_hex, sha256_prefixed,
};

pub const SYNTHETIC_SUBJECT: &str = "host:synthetic-correspondence";
pub const SYNTHETIC_INSTANCE: &str = "host-local";
pub const SYNTHETIC_NODE: &str = "nq-store-genesis:00000000-0000-4000-8000-000000000001";
pub const SYNTHETIC_OBSERVER: &str = "observer:nq-load-correspondence";
pub const SYNTHETIC_CONSUMER: &str = "consumer:status-projection-nq-load";
pub const SYNTHETIC_SUBJECT_INCARNATION: &str = "linux-boot:00000000-0000-4000-8000-0000000000b0";
pub const SYNTHETIC_OBSERVER_INCARNATION: &str = "observer-incarnation:synthetic:1";

fn fixed_digest(label: &str) -> String {
    sha256_prefixed(format!("synthetic-correspondence-fixture:{label}").as_bytes())
}

fn identity(id: &str, version: &str, label: &str) -> SemanticIdentityV1 {
    SemanticIdentityV1::new(id, version, &fixed_digest(label))
}

/// A complete synthetic enrollment. Paths are absolute but need not exist;
/// the fake port never spawns anything.
#[must_use]
pub fn synthetic_enrollment() -> (NqEnrollmentV1, PulseEnrollmentV1) {
    (
        NqEnrollmentV1 {
            instance_id: SYNTHETIC_INSTANCE.to_owned(),
            subject_id: SYNTHETIC_SUBJECT.to_owned(),
            subject_scope: identity("nq.scope.host", "1", "scope"),
            vantage: identity("nq.vantage.local.synthetic.host-local", "1", "vantage"),
            profile_semantic_id: fixed_digest("profile-semantic"),
            threshold_policy: identity("nq.host.load_pressure.threshold_policy", "1", "threshold"),
            evaluator: identity("nq-ng.evaluator", "1", "evaluator"),
            state_model: identity("nq.state_model.subject_identity", "1", "state-model"),
            producer: NqProducerV1 {
                node_id: SYNTHETIC_NODE.to_owned(),
                build: identity("nq-ng", "0.1.0", "build"),
                cohort: identity("nq.profile_catalog", "1", "cohort"),
            },
            executable_path: PathBuf::from("/opt/constellation/synthetic/nq"),
            executable_sha256: fixed_digest("executable"),
            config_path: PathBuf::from("/etc/constellation/synthetic/nq.toml"),
            config_sha256: fixed_digest("config"),
        },
        PulseEnrollmentV1 {
            observer_id: SYNTHETIC_OBSERVER.to_owned(),
            consumer_id: SYNTHETIC_CONSUMER.to_owned(),
            policy_generation: "policy:nq-load-correspondence:1".to_owned(),
            observation_policy_generation: "observation-policy:nq-load-correspondence:1".to_owned(),
        },
    )
}

pub fn synthetic_profile() -> Result<CorrespondenceProfileV1, CorrespondenceError> {
    let (nq, pulse) = synthetic_enrollment();
    CorrespondenceProfileV1::seal(nq, pulse)
}

/// Which NQ outcome the fake port fabricates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyntheticOutcome {
    Present,
    ExplicitlyAbsent,
    CannotEvaluate,
    /// A helper-origin received-input refusal: governed refusal disposition.
    InputRefusal,
    /// Provider no response: acquisition-failure disposition, no bytes.
    ProviderNoResponse,
}

impl SyntheticOutcome {
    #[must_use]
    pub const fn expected_state(self) -> NqDetectorStateV1 {
        match self {
            Self::Present => NqDetectorStateV1::Present,
            Self::ExplicitlyAbsent => NqDetectorStateV1::ExplicitlyAbsent,
            Self::CannotEvaluate => NqDetectorStateV1::CannotEvaluate,
            Self::InputRefusal | Self::ProviderNoResponse => NqDetectorStateV1::NotEvaluated,
        }
    }
}

/// Deviations the fake port can inject to exercise refusals.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Tamper {
    #[default]
    None,
    AcquirePreLaunchFails,
    AcquireFails,
    AcquireResponseLost,
    ReplayDiffers,
    QualifyFails,
    ProvenanceRawMismatch,
    ProvenanceOtherArtifact,
    ProvenanceOtherRun,
    ArtifactOtherSubject,
    ArtifactFreshSelectionRule,
    ArtifactOtherQuestionDigest,
    ArtifactOtherProfileSemantic,
    ArtifactOtherEvaluator,
    ArtifactOtherNode,
    ArtifactTwoSelectedInputs,
    ArtifactClaimDependsOnOtherInput,
    ArtifactPresentWithPartialCoverage,
    ArtifactHelperRefusalLabelledCannotEvaluate,
}

fn short(value: &str) -> String {
    sha256_hex(value.as_bytes())[..16].to_owned()
}

/// Build one synthetic canonical v2 artifact for an acquisition identity.
pub fn synthetic_artifact(
    profile: &CorrespondenceProfileV1,
    acquisition_id: &str,
    outcome: SyntheticOutcome,
    tamper: Tamper,
) -> Result<Vec<u8>, CorrespondenceError> {
    let tag = short(acquisition_id);
    let run_id = format!("run:{tag}");
    let request_id = format!("request:{tag}");
    let intake_id = format!("intake:{tag}");
    let raw_sha256 = sha256_prefixed(format!("raw:{tag}").as_bytes());
    let nq = &profile.nq;
    let subject_id = if tamper == Tamper::ArtifactOtherSubject {
        "host:other".to_owned()
    } else {
        nq.subject_id.clone()
    };
    let mut question = json!({
        "id": NQ_QUESTION_ID, "version": "1", "digest": NQ_QUESTION_DIGEST
    });
    if tamper == Tamper::ArtifactOtherQuestionDigest {
        question["digest"] = Value::String(fixed_digest("other-question"));
    }
    let profile_semantic_id = if tamper == Tamper::ArtifactOtherProfileSemantic {
        fixed_digest("other-profile-semantic")
    } else {
        nq.profile_semantic_id.clone()
    };
    let evaluator = if tamper == Tamper::ArtifactOtherEvaluator {
        identity("nq-ng.evaluator", "2", "evaluator-2")
    } else {
        nq.evaluator.clone()
    };
    let node_id = if tamper == Tamper::ArtifactOtherNode {
        "nq-store-genesis:other".to_owned()
    } else {
        nq.producer.node_id.clone()
    };
    let selection_rule = if tamper == Tamper::ArtifactFreshSelectionRule {
        identity("nq.fresh_single_admitted_report", "1", "selection-fresh")
    } else {
        identity(NQ_SELECTION_RULE_ID, "1", "selection-successor")
    };
    let clock = identity("clock:local-realtime", "1", "clock");
    let interval = json!({
        "started_at": "2026-09-23T12:00:00Z",
        "ended_at": "2026-09-23T12:00:01Z",
        "clock": clock,
        "qualification": {"state": "unqualified", "code": "absolute_clock_quality_unqualified", "detail": "no finite UTC-error bound was established"}
    });
    let received = json!({
        "input_id": intake_id,
        "expectation_id": "expected:current_provider_report",
        "provider_intake_id": intake_id,
        "raw_artifact_id": raw_sha256,
        "capture_mode": "exact_source",
        "capture_policy": identity("nq.exact_source_capture", "1", "capture"),
        "availability_at_derivation": "online",
        "acquisition": interval,
        "received_at": "2026-09-23T12:00:01Z"
    });
    let admitted = json!({
        "input_id": intake_id,
        "admission_rule": identity("nq.local_provider_admission", "1", "admission"),
        "normalized_artifact_id": fixed_digest("normalized"),
        "normalization_rule": identity("nq.host.normalization", "1", "normalization"),
        "projected_artifact_id": fixed_digest("projected"),
        "projection_rule": identity("nq.host.projection", "1", "projection")
    });
    let selected = json!({"input_id": intake_id, "projected_artifact_id": fixed_digest("projected"), "role": "profile_report"});
    let state_binding = json!({
        "binding_id": "state:subject_identity",
        "kind": "subject_identity",
        "value": subject_id,
        "supporting_input_ids": [intake_id]
    });
    let profile_refusal = |code: &str, message: &str| {
        json!({
            "schema": NQ_REFUSAL_SCHEMA,
            "refusal_id": format!("refusal:{tag}"),
            "origin": {"kind": "profile", "payload": {
                "profile_semantic_id": profile_semantic_id,
                "refusal": {
                    "instance_id": nq.instance_id,
                    "profile": {"id": NQ_PROFILE_ID, "version": 1},
                    "boundary": "detector",
                    "code": code,
                    "message": message,
                    "details": {"reason": "fixture"}
                }
            }}
        })
    };
    let helper_refusal = json!({
        "schema": NQ_REFUSAL_SCHEMA,
        "refusal_id": format!("refusal:{tag}"),
        "origin": {"kind": "helper", "payload": {"code": "unsupported_capability", "message": "fixture helper refusal", "retryable": false}}
    });

    let (inputs, state_bindings, claims, primary_claim_id, outcome_value) = match outcome {
        SyntheticOutcome::Present | SyntheticOutcome::ExplicitlyAbsent => {
            let condition = if outcome == SyntheticOutcome::Present {
                "present"
            } else {
                "explicitly_absent"
            };
            let mut selected_inputs = vec![selected.clone()];
            let mut received_inputs = vec![received.clone()];
            let mut admitted_inputs = vec![admitted.clone()];
            let mut dependency = vec![Value::String(intake_id.clone())];
            if tamper == Tamper::ArtifactTwoSelectedInputs {
                let mut second = selected.clone();
                second["input_id"] = Value::String(format!("{intake_id}-b"));
                selected_inputs.push(second);
                let mut second_received = received.clone();
                second_received["input_id"] = Value::String(format!("{intake_id}-b"));
                second_received["provider_intake_id"] = Value::String(format!("{intake_id}-b"));
                received_inputs.push(second_received);
                let mut second_admitted = admitted.clone();
                second_admitted["input_id"] = Value::String(format!("{intake_id}-b"));
                admitted_inputs.push(second_admitted);
            }
            if tamper == Tamper::ArtifactClaimDependsOnOtherInput {
                dependency = vec![Value::String(format!("{intake_id}-z"))];
            }
            let coverage = if tamper == Tamper::ArtifactPresentWithPartialCoverage {
                "partial"
            } else {
                "complete"
            };
            (
                json!({
                    "selection_rule": selection_rule,
                    "expected": [{"expectation_id": "expected:current_provider_report", "role": "profile_report", "required": true}],
                    "received": received_inputs,
                    "admitted": admitted_inputs,
                    "refused": [],
                    "failed": [],
                    "excluded": [],
                    "selected": selected_inputs
                }),
                json!([state_binding]),
                json!([{
                    "claim_id": NQ_CLAIM_ID,
                    "proposition": format!("bounded condition {NQ_CONDITION} is {}", condition.replace('_', " ")),
                    "status": "established",
                    "condition_effect": condition,
                    "dependency_input_ids": dependency,
                    "dependency_refusal_ids": [],
                    "dependency_failure_ids": [],
                    "state_binding_ids": ["state:subject_identity"],
                    "required_distinctions": ["subject_identity"],
                    "limitations": ["One scheduler snapshot does not identify the workload causing load"],
                    "nonclaims": ["the causal source of the bounded condition is not established", "the host boot or deployment generation is not established"]
                }]),
                Some(NQ_CLAIM_ID.to_owned()),
                json!({
                    "derivation": "completed",
                    "condition": condition,
                    "coherence": "jointly_established",
                    "coverage": coverage,
                    "summary": "fixture summary",
                    "refusals": [],
                    "unsupported": []
                }),
            )
        }
        SyntheticOutcome::CannotEvaluate => {
            let refusal = if tamper == Tamper::ArtifactHelperRefusalLabelledCannotEvaluate {
                helper_refusal.clone()
            } else {
                profile_refusal("cannot_evaluate", "the newest report has no host snapshot")
            };
            (
                json!({
                    "selection_rule": selection_rule,
                    "expected": [{"expectation_id": "expected:current_provider_report", "role": "profile_report", "required": true}],
                    "received": [received],
                    "admitted": [admitted],
                    "refused": [],
                    "failed": [],
                    "excluded": [],
                    "selected": [selected]
                }),
                json!([state_binding]),
                json!([]),
                None,
                json!({
                    "derivation": "refused",
                    "condition": "unresolved",
                    "coherence": "not_evaluated",
                    "coverage": "partial",
                    "summary": "the newest report has no host snapshot",
                    "refusals": [refusal],
                    "unsupported": []
                }),
            )
        }
        SyntheticOutcome::InputRefusal => (
            json!({
                "selection_rule": selection_rule,
                "expected": [{"expectation_id": "expected:current_provider_report", "role": "profile_report", "required": true}],
                "received": [received],
                "admitted": [],
                "refused": [{"input_id": intake_id, "refusal": helper_refusal}],
                "failed": [],
                "excluded": [],
                "selected": []
            }),
            json!([]),
            json!([]),
            None,
            json!({
                "derivation": "refused",
                "condition": "unresolved",
                "coherence": "not_evaluated",
                "coverage": "missing",
                "summary": "the required provider input was refused",
                "refusals": [helper_refusal],
                "unsupported": []
            }),
        ),
        SyntheticOutcome::ProviderNoResponse => (
            json!({
                "selection_rule": selection_rule,
                "expected": [{"expectation_id": "expected:current_provider_report", "role": "profile_report", "required": true}],
                "received": [],
                "admitted": [],
                "refused": [],
                "failed": [{
                    "expectation_id": "expected:current_provider_report",
                    "failure_id": format!("failure:{intake_id}"),
                    "cause": {"kind": "provider_no_response", "provider_intake_id": intake_id, "attempt": interval, "raw_custody": "no_bytes_retained", "failure": {"class": "timeout", "phase": "response", "detail": "fixture timeout"}}
                }],
                "excluded": [],
                "selected": []
            }),
            json!([]),
            json!([]),
            None,
            json!({
                "derivation": "partial",
                "condition": "unresolved",
                "coherence": "not_evaluated",
                "coverage": "missing",
                "summary": "the provider returned no response",
                "refusals": [],
                "unsupported": []
            }),
        ),
    };

    let mut artifact = json!({
        "schema": "nq.diagnostic_execution.v2",
        "artifact_id": fixed_digest("placeholder"),
        "canonicalization": {"id": "rfc8785-jcs", "version": "1", "digest": "sha256:e49d92d4e86052e66ed2a481b9386d3b214ce3d2df5fd109a6491ccb9ffb24f3"},
        "producer": {"node_id": node_id, "build": nq.producer.build, "cohort": nq.producer.cohort},
        "request_id": request_id,
        "run_id": run_id,
        "question": question,
        "subject": {"id": subject_id, "scope": nq.subject_scope},
        "profile": {"id": NQ_PROFILE_ID, "version": "1", "digest": NQ_PROFILE_DIGEST},
        "profile_semantic_id": profile_semantic_id,
        "vantage": nq.vantage,
        "state_model": nq.state_model,
        "evaluator": evaluator,
        "threshold_policy": nq.threshold_policy,
        "projection": {"identity": identity("nq.host.load_pressure.projection", "1", "projection-identity"), "omitted_distinctions": []},
        "execution_clock": clock,
        "started_at": "2026-09-23T12:00:00Z",
        "completed_at": "2026-09-23T12:00:02Z",
        "attempt_interval": interval,
        "inputs": inputs,
        "state_bindings": state_bindings,
        "claims": claims,
        "outcome": outcome_value,
        "limitations": [{"kind": "other", "code": "boot_state_unbound", "detail": "boot generation is not established"}],
        "nonclaims": ["this artifact grants no authorization", "this artifact grants no consumer reliance"]
    });
    if let Some(primary) = primary_claim_id {
        artifact["primary_claim_id"] = Value::String(primary);
    }
    let id = object_id(&artifact, "artifact_id")?;
    artifact["artifact_id"] = Value::String(id);
    canonical_bytes(&artifact)
}

/// Build synthetic provenance for exact artifact bytes, in NQ's `--json`
/// (non-canonical, newline-terminated) shape.
pub fn synthetic_provenance(
    profile: &CorrespondenceProfileV1,
    artifact_bytes: &[u8],
    tamper: Tamper,
) -> Result<Vec<u8>, CorrespondenceError> {
    let artifact: Value = serde_json::from_slice(artifact_bytes)
        .map_err(|error| CorrespondenceError::new("decode", error.to_string()))?;
    let state = crate::classify_outcome(&artifact, None)?;
    let artifact_id = artifact["artifact_id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let run_id = artifact["run_id"].as_str().unwrap_or_default().to_owned();
    let inputs = &artifact["inputs"];
    let (intake_id, raw_sha256) = inputs["received"]
        .as_array()
        .and_then(|received| received.first())
        .map_or_else(
            || {
                let failed = &inputs["failed"][0]["cause"]["provider_intake_id"];
                (
                    failed.as_str().unwrap_or_default().to_owned(),
                    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                        .to_owned(),
                )
            },
            |received| {
                (
                    received["provider_intake_id"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                    received["raw_artifact_id"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                )
            },
        );
    let tag = short(&run_id);
    let raw_sha256 = if tamper == Tamper::ProvenanceRawMismatch {
        fixed_digest("other-raw")
    } else {
        raw_sha256
    };
    let bound_artifact_id = if tamper == Tamper::ProvenanceOtherArtifact {
        fixed_digest("other-artifact")
    } else {
        artifact_id
    };
    let run_id = if tamper == Tamper::ProvenanceOtherRun {
        format!("run:{tag}-other")
    } else {
        run_id
    };
    let disposition = match state {
        NqDetectorStateV1::Present
        | NqDetectorStateV1::ExplicitlyAbsent
        | NqDetectorStateV1::CannotEvaluate => "admitted_report",
        NqDetectorStateV1::NotEvaluated => {
            if inputs["received"].as_array().is_some_and(Vec::is_empty) {
                "acquisition_failure"
            } else {
                "governed_refusal"
            }
        }
    };
    let mut origin = json!({
        "run_id": run_id,
        "completed_at": "2026-09-23T12:00:02Z",
        "committed_at": "2026-09-23T12:00:02Z"
    });
    let mut provenance = json!({
        "schema": NQ_PROVENANCE_SCHEMA,
        "provenance_id": fixed_digest("placeholder"),
        "source": {"kind": NQ_SOURCE_KIND, "source_id": profile.nq.producer.node_id},
        "artifact": {
            "artifact_id": bound_artifact_id,
            "contract_schema": "nq.diagnostic_execution.v2",
            "canonical_bytes_sha256": sha256_prefixed(artifact_bytes),
            "canonical_bytes_length": artifact_bytes.len()
        },
        "provider": {
            "provider_intake_id": intake_id,
            "raw_sha256": raw_sha256,
            "provider_admission_id": fixed_digest("provider-admission"),
            "source_admission_id": format!("admission:{tag}"),
            "admission_context_digest": fixed_digest("admission-context"),
            "profile_semantic_id": profile.nq.profile_semantic_id
        },
        "disposition": disposition,
        "nonclaims": [
            "admission establishes evidence eligibility only",
            "this provenance does not establish freshness, reliance, authorization, or action",
            "source and resolver honesty remain environmental"
        ]
    });
    if disposition == "admitted_report" {
        origin["evaluation_id"] = Value::String(format!("evaluation:{tag}"));
        provenance["judgment"] = json!({
            "report_id": format!("report:{tag}"),
            "judgment_schema": NQ_JUDGMENT_SCHEMA,
            "judgment_digest": fixed_digest("judgment")
        });
    }
    provenance["origin"] = origin;
    let id = object_id(&provenance, "provenance_id")?;
    provenance["provenance_id"] = Value::String(id);
    let mut bytes = serde_json::to_vec(&provenance)
        .map_err(|error| CorrespondenceError::new("encode", error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// An in-process NQ double. It remembers what it returned per acquisition so
/// replay is byte-identical unless a tamper says otherwise, and it refuses to
/// acquire the same identity twice.
pub struct FakeNq {
    profile: CorrespondenceProfileV1,
    outcome: Mutex<SyntheticOutcome>,
    tamper: Mutex<Tamper>,
    acquired: Mutex<BTreeMap<String, Vec<u8>>>,
    acquire_attempts: AtomicUsize,
    replay_attempts: AtomicUsize,
}

impl FakeNq {
    #[must_use]
    pub fn new(profile: CorrespondenceProfileV1, outcome: SyntheticOutcome) -> Self {
        Self {
            profile,
            outcome: Mutex::new(outcome),
            tamper: Mutex::new(Tamper::None),
            acquired: Mutex::new(BTreeMap::new()),
            acquire_attempts: AtomicUsize::new(0),
            replay_attempts: AtomicUsize::new(0),
        }
    }

    pub fn set_outcome(&self, outcome: SyntheticOutcome) {
        *self.outcome.lock().expect("outcome lock") = outcome;
    }

    pub fn set_tamper(&self, tamper: Tamper) {
        *self.tamper.lock().expect("tamper lock") = tamper;
    }

    fn tamper(&self) -> Tamper {
        *self.tamper.lock().expect("tamper lock")
    }

    #[must_use]
    pub fn acquisition_count(&self) -> usize {
        self.acquired.lock().expect("acquired lock").len()
    }

    #[must_use]
    pub fn acquire_attempt_count(&self) -> usize {
        self.acquire_attempts.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn replay_attempt_count(&self) -> usize {
        self.replay_attempts.load(Ordering::Relaxed)
    }
}

impl NqPort for FakeNq {
    fn acquire_next_local(&self, acquisition_id: &str) -> Result<Vec<u8>, CorrespondenceError> {
        self.acquire_attempts.fetch_add(1, Ordering::Relaxed);
        if self.tamper() == Tamper::AcquirePreLaunchFails {
            return Err(CorrespondenceError::new(
                "nq_spawn",
                "fixture: NQ was not launched",
            ));
        }
        if self.tamper() == Tamper::AcquireFails {
            return Err(CorrespondenceError::new(
                "nq_refused",
                "fixture: NQ refused the acquisition",
            ));
        }
        let mut acquired = self.acquired.lock().expect("acquired lock");
        if let Some(existing) = acquired.get(acquisition_id) {
            return Ok(existing.clone());
        }
        let outcome = *self.outcome.lock().expect("outcome lock");
        let bytes = synthetic_artifact(&self.profile, acquisition_id, outcome, self.tamper())?;
        acquired.insert(acquisition_id.to_owned(), bytes.clone());
        if self.tamper() == Tamper::AcquireResponseLost {
            return Err(CorrespondenceError::new(
                "nq_wait",
                "fixture: NQ committed the acquisition but its response was lost",
            ));
        }
        Ok(bytes)
    }

    fn replay_local_successor(&self, acquisition_id: &str) -> Result<Vec<u8>, CorrespondenceError> {
        self.replay_attempts.fetch_add(1, Ordering::Relaxed);
        let acquired = self.acquired.lock().expect("acquired lock");
        let bytes = acquired.get(acquisition_id).ok_or_else(|| {
            CorrespondenceError::new("nq_refused", "fixture: no such local successor")
        })?;
        if self.tamper() == Tamper::ReplayDiffers {
            let mut altered = bytes.clone();
            altered.push(b'\n');
            return Ok(altered);
        }
        Ok(bytes.clone())
    }

    fn qualify(&self, artifact_id: &str) -> Result<Vec<u8>, CorrespondenceError> {
        if self.tamper() == Tamper::QualifyFails {
            return Err(CorrespondenceError::new(
                "nq_refused",
                "fixture: imported custody cannot be qualified",
            ));
        }
        let acquired = self.acquired.lock().expect("acquired lock");
        let bytes = acquired
            .values()
            .find(|bytes| {
                serde_json::from_slice::<Value>(bytes)
                    .ok()
                    .and_then(|value| value["artifact_id"].as_str().map(str::to_owned))
                    .is_some_and(|id| id == artifact_id)
            })
            .ok_or_else(|| {
                CorrespondenceError::new("nq_refused", "fixture: unknown artifact identity")
            })?;
        synthetic_provenance(&self.profile, bytes, self.tamper())
    }
}

impl crate::nq_cli::sealed::Sealed for FakeNq {}

/// Build one sealed audit record without a reactor, for deterministic
/// vectors. The frame uses fixed incarnations and a fixed monotonic sample.
pub fn synthetic_record(
    profile: &CorrespondenceProfileV1,
    outcome: SyntheticOutcome,
    sequence: u64,
    holding_delay_ms: u64,
    ingress_fence_ms: u64,
) -> Result<CorrespondenceRecordV1, CorrespondenceError> {
    let frame = build_frame(
        profile,
        IncarnationId::new(SYNTHETIC_SUBJECT_INCARNATION),
        IncarnationId::new(SYNTHETIC_OBSERVER_INCARNATION),
        sequence,
        sequence.saturating_mul(1_000_000_000),
    )?;
    let evidence_ref = evidence_ref(&frame);
    let acquisition = acquisition_id(profile.digest(), &profile.nq.instance_id, &evidence_ref)?;
    let artifact_bytes = synthetic_artifact(profile, &acquisition, outcome, Tamper::None)?;
    let provenance_bytes = synthetic_provenance(profile, &artifact_bytes, Tamper::None)?;
    let artifact: Value = serde_json::from_slice(&artifact_bytes)
        .map_err(|error| CorrespondenceError::new("decode", error.to_string()))?;
    let provenance: Value = serde_json::from_slice(&provenance_bytes)
        .map_err(|error| CorrespondenceError::new("decode", error.to_string()))?;
    CorrespondenceRecordV1 {
        schema: String::new(),
        correspondence_id: String::new(),
        profile_digest: profile.digest().to_owned(),
        acquisition_id: acquisition,
        pulse: PulseSideV1 {
            evidence_ref,
            frame_wire_hex: encode_hex(
                &frame.encode_wire().map_err(|error| {
                    CorrespondenceError::new("invalid_frame", error.to_string())
                })?,
            ),
        },
        nq: NqSideV1 {
            artifact,
            admission_provenance: provenance,
        },
        nq_detector_state: outcome.expected_state(),
        delivery: DeliveryV1 {
            transport_path: TRANSPORT_PATH.to_owned(),
            holding_delay_ms,
            ingress_fence_ms,
        },
        nonclaims: Vec::new(),
        mutation_authority: String::new(),
    }
    .seal()
}

/// Re-seal a record after a deliberate mutation so only the intended rule
/// fails, not the identity check.
pub fn reseal(
    record: CorrespondenceRecordV1,
) -> Result<CorrespondenceRecordV1, CorrespondenceError> {
    record.seal()
}

/// Recompute an artifact's self-identity after a deliberate mutation.
pub fn reidentify_artifact(artifact: &mut Value) -> Result<(), CorrespondenceError> {
    let id = object_id(artifact, "artifact_id")?;
    artifact["artifact_id"] = Value::String(id);
    Ok(())
}

/// Recompute a provenance carrier's self-identity after a mutation.
pub fn reidentify_provenance(provenance: &mut Value) -> Result<(), CorrespondenceError> {
    let id = object_id(provenance, "provenance_id")?;
    provenance["provenance_id"] = Value::String(id);
    Ok(())
}

/// Canonical JSON bytes of any value, using the crate's exact rule.
pub fn canonical_json(value: &Value) -> Result<Vec<u8>, CorrespondenceError> {
    canonical_bytes(value)
}

/// A real local Pulse reactor registered for the profile's consumer, using
/// the repository's existing local qualification fixture inputs. The journal
/// is created at `journal_path`, which must not exist.
pub fn start_reactor(
    profile: &CorrespondenceProfileV1,
    subject_incarnation: IncarnationId,
    label: &str,
    journal_path: &std::path::Path,
) -> Result<pulse_runtime::LocalCrashReactor, CorrespondenceError> {
    use pulse_runtime::{
        HistoricalJournal, JournalBoundsV1, JournalConfigV1, LocalCrashReactor, MonotonicEpochV1,
        ReactorConditionV1, ReactorConfigV1, ReceiverSchedulerRuntime, RuntimeBoundsV1,
        RuntimeConfigV1, qualification_fixture_inputs,
    };
    use pulse_types::{ClockId, ReceiverId, SCHEMA_VERSION_V1};

    let runtime_config = RuntimeConfigV1 {
        schema_version: SCHEMA_VERSION_V1,
        receiver: ReceiverId::new("receiver:nq-load-correspondence"),
        receiver_incarnation: IncarnationId::new(format!("receiver-incarnation:{label}")),
        clock_id: ClockId::new(format!("clock:{label}")),
        transport_custody_policy: None,
        bounds: RuntimeBoundsV1::qualification(),
    };
    let mut runtime = ReceiverSchedulerRuntime::new(runtime_config.clone())
        .map_err(|error| CorrespondenceError::new("reactor_setup", error.to_string()))?;
    let registration =
        profile.consumer_registration(subject_incarnation, &format!("activation:{label}"));
    runtime
        .qualify_and_activate_local_binding(
            &registration,
            qualification_fixture_inputs("3cd15b7a1e7f424f6fd57c09b30fa4790947eca2", 97),
            0,
        )
        .map_err(|error| CorrespondenceError::new("reactor_setup", error.to_string()))?;
    runtime
        .register_consumer(registration, 0)
        .map_err(|error| CorrespondenceError::new("reactor_setup", error.to_string()))?;
    let journal = HistoricalJournal::create_new(
        journal_path,
        JournalConfigV1 {
            schema_version: SCHEMA_VERSION_V1,
            journal_id: format!("journal:{label}"),
            bounds: JournalBoundsV1 {
                maximum_records: 512,
                maximum_record_payload_bytes: 256 * 1_024,
                maximum_file_bytes: 16 * 1_024 * 1_024,
            },
        },
    )
    .map_err(|error| CorrespondenceError::new("reactor_setup", error.to_string()))?;
    let epoch = MonotonicEpochV1 {
        schema_version: SCHEMA_VERSION_V1,
        epoch_id: IncarnationId::new(format!("epoch:{label}")),
        receiver: runtime_config.receiver.clone(),
        receiver_incarnation: runtime_config.receiver_incarnation.clone(),
        clock_id: runtime_config.clock_id.clone(),
        origin_runtime_monotonic_ms: 0,
        clock_source: "std::time::Instant/process-local".to_owned(),
    };
    let reactor =
        LocalCrashReactor::start(runtime, journal, epoch, ReactorConfigV1::qualification())
            .map_err(|error| CorrespondenceError::new("reactor_setup", error.to_string()))?;
    reactor
        .wait_until(std::time::Duration::from_secs(2), |snapshot| {
            snapshot.condition == ReactorConditionV1::Operational
        })
        .map_err(|error| CorrespondenceError::new("reactor_setup", error.to_string()))?;
    Ok(reactor)
}
