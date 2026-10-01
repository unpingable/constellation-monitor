//! One occurrence of the co-production sequence.
//!
//! 1. Re-read the subject incarnation and require it unchanged.
//! 2. Seal frame `F_k`; derive `E_k` and `A_k`.
//! 3. Write a create-new intent; refuse if `A_k` already exists.
//! 4. Ask NQ to acquire under `A_k`; verify the artifact (V5, V6).
//! 5. Require byte-identical replay (V10) and matching provenance (V7).
//! 6. Deliver `F_k` to the reactor with measured `d`; require `d < V`.
//! 7. Write the audit record with create-new semantics.
//! 8. If `f <= F` and the certificate binds exactly `E_k` (V11), build the
//!    process-local verified value.

use std::path::{Path, PathBuf};

use pulse_runtime::LocalCrashReactor;
use pulse_types::IncarnationId;
use serde::Serialize;

use crate::deliver::{consumer_certificate, deliver};
use crate::nq_cli::{NQ_STAGE_QUALIFY, acquire_error_may_follow_launch};
use crate::record::encode_hex;
use crate::{
    CorrespondenceError, CorrespondenceProfileV1, CorrespondenceRecordV1, DeliveryMeasurementV1,
    DeliveryV1, NqDetectorStateV1, NqPort, NqSideV1, ObserverLineage, PulseSideV1, QuestionV1,
    SealedOccurrenceV1, SubjectIncarnationWitness, VerifiedCorrespondenceV1, canonical_bytes,
    check_ingress_fence, sha256_hex, verify_artifact, verify_certificate_binding,
    verify_provenance, write_create_new,
};

const MAX_NQ_STAGE_ERROR_DETAIL_BYTES: usize = 512;

fn with_nq_stage(
    stage: &'static str,
    acquisition_id: &str,
    error: CorrespondenceError,
) -> CorrespondenceError {
    let prefix = format!("stage={stage}; acquisition_id={acquisition_id}; ");
    debug_assert!(prefix.len() <= MAX_NQ_STAGE_ERROR_DETAIL_BYTES);
    let remaining = MAX_NQ_STAGE_ERROR_DETAIL_BYTES.saturating_sub(prefix.len());
    let mut end = error.detail.len().min(remaining);
    while !error.detail.is_char_boundary(end) {
        end -= 1;
    }
    CorrespondenceError::new(error.code, format!("{prefix}{}", &error.detail[..end]))
}

#[derive(Serialize)]
struct IntentV1<'a> {
    schema: &'static str,
    profile_digest: &'a str,
    acquisition_id: &'a str,
    pulse_evidence_ref: &'a str,
    sequence: u64,
}

/// What one occurrence produced. The verified value is present only when the
/// complete law held; the audit record exists whenever NQ produced a verified
/// artifact and the frame was delivered.
#[derive(Debug)]
pub struct OccurrenceResultV1 {
    pub sequence: u64,
    pub acquisition_id: String,
    pub evidence_ref: String,
    pub record_path: PathBuf,
    pub correspondence_id: String,
    pub nq_detector_state: NqDetectorStateV1,
    pub delivery: DeliveryMeasurementV1,
    pub outcome: OccurrenceOutcomeV1,
}

#[derive(Debug)]
pub enum OccurrenceOutcomeV1 {
    /// The full law held; this value may feed one process-local projection.
    Verified(Box<VerifiedCorrespondenceV1>),
    /// The record was written but the live binding did not hold. The frame
    /// was delivered; Pulse alone decides what it supports.
    AuditOnly { refusal: CorrespondenceError },
}

/// One process's co-producer for one enrolled correspondence.
pub struct Coproducer<'a> {
    profile: &'a CorrespondenceProfileV1,
    question: QuestionV1,
    port: &'a dyn NqPort,
    witness: &'a dyn SubjectIncarnationWitness,
    lineage: ObserverLineage,
    initial_incarnation: IncarnationId,
    intent_dir: PathBuf,
    audit_dir: PathBuf,
}

impl<'a> Coproducer<'a> {
    /// Begin a co-producer with a fresh observer lineage. The initial subject
    /// incarnation is read once here and must not change afterwards.
    pub fn begin(
        profile: &'a CorrespondenceProfileV1,
        port: &'a dyn NqPort,
        witness: &'a dyn SubjectIncarnationWitness,
        intent_dir: &Path,
        audit_dir: &Path,
    ) -> Result<Self, CorrespondenceError> {
        let lineage = ObserverLineage::begin(profile)?;
        Self::with_lineage(profile, port, witness, lineage, intent_dir, audit_dir)
    }

    /// Begin with an explicit lineage (fixtures and vectors).
    pub fn with_lineage(
        profile: &'a CorrespondenceProfileV1,
        port: &'a dyn NqPort,
        witness: &'a dyn SubjectIncarnationWitness,
        lineage: ObserverLineage,
        intent_dir: &Path,
        audit_dir: &Path,
    ) -> Result<Self, CorrespondenceError> {
        profile.validate()?;
        let question = profile.question()?;
        if port.enrollment() != &profile.nq {
            return Err(CorrespondenceError::new(
                "nq_enrollment_mismatch",
                "NQ port enrollment differs from the correspondence profile",
            ));
        }
        if !intent_dir.is_absolute() || !audit_dir.is_absolute() || intent_dir == audit_dir {
            return Err(CorrespondenceError::new(
                "invalid_custody_paths",
                "intent and audit directories must be distinct absolute paths",
            ));
        }
        std::fs::create_dir_all(intent_dir)
            .and_then(|()| std::fs::create_dir_all(audit_dir))
            .map_err(|error| CorrespondenceError::new("io", error.to_string()))?;
        let initial_incarnation = witness.current()?;
        initial_incarnation
            .validate()
            .map_err(|error| CorrespondenceError::new("invalid_incarnation", error.to_string()))?;
        Ok(Self {
            profile,
            question,
            port,
            witness,
            lineage,
            initial_incarnation,
            intent_dir: intent_dir.to_path_buf(),
            audit_dir: audit_dir.to_path_buf(),
        })
    }

    #[must_use]
    pub fn subject_incarnation(&self) -> &IncarnationId {
        &self.initial_incarnation
    }

    #[must_use]
    pub fn lineage(&self) -> &ObserverLineage {
        &self.lineage
    }

    #[must_use]
    pub fn question(&self) -> QuestionV1 {
        self.question
    }

    /// Seal, acquire, verify, deliver, record. A failure before delivery
    /// burns the sequence and delivers nothing; the resulting Pulse gap fails
    /// closed on its own.
    pub fn run_occurrence(
        &mut self,
        reactor: &LocalCrashReactor,
    ) -> Result<OccurrenceResultV1, CorrespondenceError> {
        let incarnation = self.witness.current()?;
        if incarnation != self.initial_incarnation {
            return Err(CorrespondenceError::new(
                "subject_incarnation_changed",
                "subject incarnation changed since the co-producer started; stop",
            ));
        }
        let sequence = self.lineage.next_sequence();
        let occurrence = self.lineage.seal_next(self.profile, incarnation)?;
        self.write_intent(&occurrence, sequence)?;

        let acquisition_id = &occurrence.acquisition_id;
        let artifact_bytes = match self.port.acquire_next_local(acquisition_id) {
            Ok(bytes) => bytes,
            Err(acquire_error) if acquire_error_may_follow_launch(&acquire_error) => self
                .port
                .replay_local_successor(acquisition_id)
                .map_err(|replay_error| {
                    with_nq_stage(
                        "reconciliation_replay",
                        acquisition_id,
                        CorrespondenceError::new(
                            "acquire_reconciliation_failed",
                            format!(
                                "replay={}; original_acquire={}; replacement_acquisition=false; replay_detail={}; original_detail={}",
                                replay_error.code,
                                acquire_error.code,
                                replay_error.detail,
                                acquire_error.detail
                            ),
                        ),
                    )
                })?,
            Err(error) => return Err(with_nq_stage("acquire", acquisition_id, error)),
        };
        let artifact = verify_artifact(&artifact_bytes, self.profile)
            .map_err(|error| with_nq_stage("acquire", acquisition_id, error))?;
        // This is intentionally still required after result-loss recovery: the
        // first replay recovers the lost result and this second replay proves
        // the ordinary exact-byte reopening invariant.
        let replay_bytes = self
            .port
            .replay_local_successor(acquisition_id)
            .map_err(|error| with_nq_stage("mandatory_replay", acquisition_id, error))?;
        if replay_bytes != artifact_bytes {
            return Err(with_nq_stage(
                "mandatory_replay",
                acquisition_id,
                CorrespondenceError::new(
                    "replay_mismatch",
                    "NQ replay bytes differ from the acquisition bytes",
                ),
            ));
        }
        let provenance_bytes = self
            .port
            .qualify(&artifact.artifact_id)
            .map_err(|error| with_nq_stage(NQ_STAGE_QUALIFY, acquisition_id, error))?;
        let provenance = verify_provenance(&provenance_bytes, &artifact, self.profile)
            .map_err(|error| with_nq_stage(NQ_STAGE_QUALIFY, acquisition_id, error))?;

        let delivery = deliver(reactor, self.question, &occurrence)?;

        let record = CorrespondenceRecordV1 {
            schema: String::new(),
            correspondence_id: String::new(),
            profile_digest: self.profile.digest().to_owned(),
            acquisition_id: occurrence.acquisition_id.clone(),
            pulse: PulseSideV1 {
                evidence_ref: occurrence.evidence_ref.clone(),
                frame_wire_hex: encode_hex(&occurrence.frame.encode_wire().map_err(|error| {
                    CorrespondenceError::new("invalid_frame", error.to_string())
                })?),
            },
            nq: NqSideV1 {
                artifact: artifact.value.clone(),
                admission_provenance: provenance,
            },
            nq_detector_state: artifact.state,
            delivery: DeliveryV1 {
                transport_path: self.question.spec().transport_path.to_owned(),
                holding_delay_ms: delivery.holding_delay_ms,
                ingress_fence_ms: delivery.ingress_fence_ms,
            },
            nonclaims: Vec::new(),
            mutation_authority: String::new(),
        }
        .seal(self.question)?;
        let record_bytes = record.canonical_bytes()?;
        let record_path = occurrence_path(&self.audit_dir, &occurrence.acquisition_id);
        write_create_new(&record_path, &record_bytes, 0o640)?;

        let outcome = match self.verify_live_binding(reactor, &occurrence, delivery) {
            Ok(certificate_id) => {
                OccurrenceOutcomeV1::Verified(Box::new(VerifiedCorrespondenceV1::new(
                    self.question,
                    artifact.owner_failure.clone(),
                    record.correspondence_id.clone(),
                    occurrence.acquisition_id.clone(),
                    occurrence.evidence_ref.clone(),
                    artifact.artifact_id.clone(),
                    certificate_id,
                    self.profile.digest().to_owned(),
                    self.profile.subject(),
                    occurrence.subject_incarnation.clone(),
                    artifact.state,
                    delivery,
                    occurrence.sealed_at(),
                )))
            }
            Err(refusal) => OccurrenceOutcomeV1::AuditOnly { refusal },
        };
        Ok(OccurrenceResultV1 {
            sequence,
            acquisition_id: occurrence.acquisition_id,
            evidence_ref: occurrence.evidence_ref,
            record_path,
            correspondence_id: record.correspondence_id,
            nq_detector_state: artifact.state,
            delivery,
            outcome,
        })
    }

    fn verify_live_binding(
        &self,
        reactor: &LocalCrashReactor,
        occurrence: &SealedOccurrenceV1,
        delivery: DeliveryMeasurementV1,
    ) -> Result<String, CorrespondenceError> {
        check_ingress_fence(delivery.ingress_fence_ms)?;
        let certificate = consumer_certificate(reactor, self.profile)?;
        verify_certificate_binding(
            &certificate,
            self.profile,
            &occurrence.evidence_ref,
            &occurrence.subject_incarnation,
            delivery.holding_delay_ms,
        )?;
        Ok(certificate.certificate_id.as_str().to_owned())
    }

    fn write_intent(
        &self,
        occurrence: &SealedOccurrenceV1,
        sequence: u64,
    ) -> Result<(), CorrespondenceError> {
        let intent = IntentV1 {
            schema: self.question.spec().intent_schema,
            profile_digest: self.profile.digest(),
            acquisition_id: &occurrence.acquisition_id,
            pulse_evidence_ref: &occurrence.evidence_ref,
            sequence,
        };
        let path = occurrence_path(&self.intent_dir, &occurrence.acquisition_id);
        write_create_new(&path, &canonical_bytes(&intent)?, 0o640).map_err(|error| {
            if error.code == "already_exists" {
                CorrespondenceError::new(
                    "acquisition_id_reused",
                    "an intent for this acquisition identity already exists; identities are never reused",
                )
            } else {
                error
            }
        })
    }
}

/// Path of the intent or audit record for one acquisition identity inside
/// its directory: `sha256-<sha256(acquisition_id)>.json`.
#[must_use]
pub fn occurrence_path(directory: &Path, acquisition_id: &str) -> PathBuf {
    directory.join(format!(
        "sha256-{}.json",
        sha256_hex(acquisition_id.as_bytes())
    ))
}
