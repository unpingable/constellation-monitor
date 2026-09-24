//! Frame sealing, evidence reference, and acquisition identity.
//!
//! The frame is sealed before NQ is asked to acquire. Its evidence reference
//! is the only Pulse-side input to the acquisition identity, so NQ records the
//! pairing before its helper reads the host.

use std::time::Instant;

use pulse_types::{
    AuthenticationFieldV1, CoverageDescriptorV1, IncarnationId, ObserverId, PulseFrameV1,
    SCHEMA_VERSION_V1, digest_parts,
};
use rand_core::{OsRng, RngCore as _};
use serde::Serialize;

use crate::{
    CorrespondenceError, CorrespondenceProfileV1, FRAME_DISCLOSURE, QuestionV1, canonical_bytes,
    sha256_prefixed,
};

/// Supplies the subject incarnation at start and at every seal. The
/// correspondence crate deliberately owns no host source; the embedding
/// supplies the Linux boot identity or another qualified incarnation.
pub trait SubjectIncarnationWitness {
    fn current(&self) -> Result<IncarnationId, CorrespondenceError>;
}

/// A fixed incarnation for tests and vectors.
#[derive(Clone, Debug)]
pub struct FixedSubjectIncarnation(pub IncarnationId);

impl SubjectIncarnationWitness for FixedSubjectIncarnation {
    fn current(&self) -> Result<IncarnationId, CorrespondenceError> {
        Ok(self.0.clone())
    }
}

/// One observer lineage for one co-producer process: a fresh incarnation, a
/// process-local origin instant, and a contiguous sequence.
#[derive(Debug)]
pub struct ObserverLineage {
    observer: ObserverId,
    observer_incarnation: IncarnationId,
    origin: Instant,
    next_sequence: u64,
}

impl ObserverLineage {
    /// Begin a lineage with a fresh, never-reused observer incarnation.
    pub fn begin(profile: &CorrespondenceProfileV1) -> Result<Self, CorrespondenceError> {
        let mut random = [0_u8; 16];
        OsRng.try_fill_bytes(&mut random).map_err(|error| {
            CorrespondenceError::new(
                "observer_incarnation_randomness",
                format!("cannot create a fresh observer incarnation: {error}"),
            )
        })?;
        Ok(Self::with_incarnation(
            profile,
            IncarnationId::new(format!(
                "observer-incarnation:{}",
                random
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            )),
        ))
    }

    /// Begin a lineage with an explicit incarnation. Fixtures use this to make
    /// vectors reproducible; production uses [`Self::begin`].
    #[must_use]
    pub fn with_incarnation(
        profile: &CorrespondenceProfileV1,
        observer_incarnation: IncarnationId,
    ) -> Self {
        Self {
            observer: profile.observer(),
            observer_incarnation,
            origin: Instant::now(),
            next_sequence: 1,
        }
    }

    #[must_use]
    pub fn observer(&self) -> &ObserverId {
        &self.observer
    }

    #[must_use]
    pub fn observer_incarnation(&self) -> &IncarnationId {
        &self.observer_incarnation
    }

    #[must_use]
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Seal the next frame. The sequence is consumed even if the occurrence
    /// later fails, so a failed occurrence leaves a Pulse gap rather than a
    /// silently renumbered stream.
    pub fn seal_next(
        &mut self,
        profile: &CorrespondenceProfileV1,
        subject_incarnation: IncarnationId,
    ) -> Result<SealedOccurrenceV1, CorrespondenceError> {
        let sealed_at = Instant::now();
        let observer_monotonic_ns = u64::try_from(sealed_at.duration_since(self.origin).as_nanos())
            .map_err(|_| CorrespondenceError::new("clock_overflow", "observer clock overflow"))?;
        let sequence = self.next_sequence;
        self.next_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| CorrespondenceError::new("sequence_exhausted", "sequence overflow"))?;
        let frame = build_frame(
            profile,
            subject_incarnation.clone(),
            self.observer_incarnation.clone(),
            sequence,
            observer_monotonic_ns,
        )?;
        SealedOccurrenceV1::from_frame(profile, frame, subject_incarnation, sealed_at)
    }
}

/// One sealed frame with its derived identities and the seal instant.
#[derive(Debug)]
pub struct SealedOccurrenceV1 {
    pub frame: PulseFrameV1,
    pub evidence_ref: String,
    pub acquisition_id: String,
    pub subject_incarnation: IncarnationId,
    pub(crate) sealed_at: Instant,
}

impl SealedOccurrenceV1 {
    pub(crate) fn from_frame(
        profile: &CorrespondenceProfileV1,
        frame: PulseFrameV1,
        subject_incarnation: IncarnationId,
        sealed_at: Instant,
    ) -> Result<Self, CorrespondenceError> {
        verify_frame(&frame, profile)?;
        let evidence_ref = evidence_ref(&frame);
        let acquisition_id = acquisition_id(
            profile.question()?,
            profile.digest(),
            &profile.nq.instance_id,
            &evidence_ref,
        )?;
        Ok(Self {
            frame,
            evidence_ref,
            acquisition_id,
            subject_incarnation,
            sealed_at,
        })
    }

    #[must_use]
    pub fn sealed_at(&self) -> Instant {
        self.sealed_at
    }
}

/// Build and seal the exact correspondence frame: no signals, one expected and
/// observed coverage tag, validity `V`, placeholder authentication.
pub fn build_frame(
    profile: &CorrespondenceProfileV1,
    subject_incarnation: IncarnationId,
    observer_incarnation: IncarnationId,
    sequence: u64,
    observer_monotonic_ns: u64,
) -> Result<PulseFrameV1, CorrespondenceError> {
    let question = profile.question()?;
    let coverage_tag = question.spec().coverage_tag;
    let frame = PulseFrameV1 {
        schema_version: SCHEMA_VERSION_V1,
        subject: profile.subject(),
        subject_incarnation,
        observer: profile.observer(),
        observer_incarnation,
        sequence,
        observer_monotonic_ns,
        validity_ms: question.frame_validity_ms(),
        profile: profile.pulse_observation_profile()?,
        observation_policy_generation: profile.observation_policy_generation(),
        coverage: CoverageDescriptorV1 {
            expected: vec![coverage_tag.to_owned()],
            observed: vec![coverage_tag.to_owned()],
        },
        signals: Vec::new(),
        observation_digest: digest_parts("unsealed", &[]),
        authentication: AuthenticationFieldV1::Placeholder {
            disclosure: FRAME_DISCLOSURE.to_owned(),
        },
    }
    .seal();
    verify_frame(&frame, profile)?;
    Ok(frame)
}

/// V3: the frame validates and every pinned field equals the profile.
pub fn verify_frame(
    frame: &PulseFrameV1,
    profile: &CorrespondenceProfileV1,
) -> Result<(), CorrespondenceError> {
    frame
        .validate()
        .map_err(|error| CorrespondenceError::new("invalid_frame", error.to_string()))?;
    let question = profile.question()?;
    let coverage_tag = question.spec().coverage_tag;
    if frame.subject != profile.subject()
        || frame.observer != profile.observer()
        || frame.profile != profile.pulse_observation_profile()?
        || frame.observation_policy_generation != profile.observation_policy_generation()
    {
        return Err(CorrespondenceError::new(
            "frame_binding_mismatch",
            "frame subject, observer, profile, or observation policy differs from the profile",
        ));
    }
    if frame.validity_ms != question.frame_validity_ms() {
        return Err(CorrespondenceError::new(
            "frame_validity_mismatch",
            "frame validity is not the exact correspondence validity",
        ));
    }
    if frame.coverage.expected != [coverage_tag.to_owned()]
        || frame.coverage.observed != [coverage_tag.to_owned()]
    {
        return Err(CorrespondenceError::new(
            "frame_coverage_mismatch",
            "frame coverage is not exactly the terminal-artifact tag",
        ));
    }
    if !frame.signals.is_empty() {
        return Err(CorrespondenceError::new(
            "frame_carries_signals",
            "correspondence frames carry no signals",
        ));
    }
    if frame.authentication
        != (AuthenticationFieldV1::Placeholder {
            disclosure: FRAME_DISCLOSURE.to_owned(),
        })
    {
        return Err(CorrespondenceError::new(
            "frame_authentication_mismatch",
            "frame authentication is not the fixed placeholder disclosure",
        ));
    }
    if frame.observer.as_str().contains('/') || frame.observer_incarnation.as_str().contains('/') {
        return Err(CorrespondenceError::new(
            "invalid_observer",
            "observer lineage identities must not contain '/'",
        ));
    }
    Ok(())
}

/// Pulse's supporting-evidence reference for one frame. This reproduces the
/// exact format Pulse's evaluator places in a support certificate; the reactor
/// end-to-end test proves equality against a real certificate.
#[must_use]
pub fn evidence_ref(frame: &PulseFrameV1) -> String {
    format!(
        "{}/{}/seq={}/{}",
        frame.observer, frame.observer_incarnation, frame.sequence, frame.observation_digest
    )
}

#[derive(Serialize)]
struct OccurrencePreimage<'a> {
    schema: &'static str,
    correspondence_profile_digest: &'a str,
    nq_instance_id: &'a str,
    pulse_evidence_ref: &'a str,
}

/// The caller-named NQ acquisition identity: the question's fixed prefix plus
/// the SHA-256 of the canonical occurrence preimage under the question's
/// occurrence schema. Within NQ's identity bound for every row.
pub fn acquisition_id(
    question: QuestionV1,
    profile_digest: &str,
    nq_instance_id: &str,
    evidence_ref: &str,
) -> Result<String, CorrespondenceError> {
    let spec = question.spec();
    let preimage = OccurrencePreimage {
        schema: spec.occurrence_schema,
        correspondence_profile_digest: profile_digest,
        nq_instance_id,
        pulse_evidence_ref: evidence_ref,
    };
    Ok(format!(
        "{}{}",
        spec.acquisition_id_prefix,
        sha256_prefixed(&canonical_bytes(&preimage)?)
    ))
}
