use std::collections::{BTreeMap, BTreeSet};

use pulse_types::{
    ArrivalDispositionV1, AuthenticationResultV1, ClockId, IncarnationId,
    ObservationPolicyGenerationId, ObservationProfileIdV1, ObserverId, PulseError, PulseFrameV1,
    ReceiverAnnotationV1, ReceiverId, SCHEMA_VERSION_V1, SequenceGapV1, SubjectId,
};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ReceiverStreamKey {
    subject: SubjectId,
    observer: ObserverId,
    profile: ObservationProfileIdV1,
    observation_policy_generation: ObservationPolicyGenerationId,
}

#[derive(Clone, Debug)]
struct ReceiverStream {
    incarnation: IncarnationId,
    sequence: u64,
}

/// Deterministic receiver-side annotator used by local transports and replay.
#[derive(Clone, Debug)]
pub struct ReceiverTracker {
    receiver: ReceiverId,
    receiver_incarnation: IncarnationId,
    clock_id: ClockId,
    streams: BTreeMap<ReceiverStreamKey, ReceiverStream>,
    retired: BTreeSet<(ReceiverStreamKey, IncarnationId)>,
    subject_incarnations: BTreeMap<SubjectId, IncarnationId>,
    retired_subject_incarnations: BTreeSet<(SubjectId, IncarnationId)>,
}

impl ReceiverTracker {
    #[must_use]
    pub fn new(
        receiver: ReceiverId,
        receiver_incarnation: IncarnationId,
        clock_id: ClockId,
    ) -> Self {
        Self {
            receiver,
            receiver_incarnation,
            clock_id,
            streams: BTreeMap::new(),
            retired: BTreeSet::new(),
            subject_incarnations: BTreeMap::new(),
            retired_subject_incarnations: BTreeSet::new(),
        }
    }

    pub fn annotate(
        &mut self,
        frame: &PulseFrameV1,
        arrival_monotonic_ms: u64,
        transport_path: impl Into<String>,
        transport_observed_delay_ms: Option<u64>,
        authentication: AuthenticationResultV1,
    ) -> Result<ReceiverAnnotationV1, PulseError> {
        frame.validate()?;
        let effective_stale =
            transport_observed_delay_ms.is_some_and(|delay| delay >= frame.validity_ms);
        if effective_stale {
            return Ok(ReceiverAnnotationV1 {
                schema_version: SCHEMA_VERSION_V1,
                receiver: self.receiver.clone(),
                receiver_incarnation: self.receiver_incarnation.clone(),
                clock_id: self.clock_id.clone(),
                arrival_monotonic_ms,
                disposition: ArrivalDispositionV1::Stale,
                sequence_gap: None,
                transport_path: transport_path.into(),
                transport_observed_delay_ms,
                authentication,
            });
        }
        let subject_key = (frame.subject.clone(), frame.subject_incarnation.clone());
        let retired_subject = self.retired_subject_incarnations.contains(&subject_key);
        if !retired_subject {
            if let Some(prior) = self.subject_incarnations.get(&frame.subject).cloned() {
                if prior != frame.subject_incarnation {
                    self.retired_subject_incarnations
                        .insert((frame.subject.clone(), prior));
                    self.subject_incarnations
                        .insert(frame.subject.clone(), frame.subject_incarnation.clone());
                }
            } else {
                self.subject_incarnations
                    .insert(frame.subject.clone(), frame.subject_incarnation.clone());
            }
        }

        let stream_key = ReceiverStreamKey {
            subject: frame.subject.clone(),
            observer: frame.observer.clone(),
            profile: frame.profile.clone(),
            observation_policy_generation: frame.observation_policy_generation.clone(),
        };
        let (disposition, sequence_gap) = if retired_subject {
            (ArrivalDispositionV1::Replay, None)
        } else if let Some(stream) = self.streams.get_mut(&stream_key) {
            if stream.incarnation == frame.observer_incarnation {
                if frame.sequence == stream.sequence {
                    (ArrivalDispositionV1::Duplicate, None)
                } else if frame.sequence < stream.sequence {
                    (ArrivalDispositionV1::Replay, None)
                } else if frame.sequence == stream.sequence.saturating_add(1) {
                    stream.sequence = frame.sequence;
                    (ArrivalDispositionV1::Continuous, None)
                } else {
                    let expected_next = stream.sequence.saturating_add(1);
                    stream.sequence = frame.sequence;
                    (
                        ArrivalDispositionV1::Gap,
                        Some(SequenceGapV1 {
                            expected_next,
                            received: frame.sequence,
                            missing_count: frame.sequence - expected_next,
                        }),
                    )
                }
            } else if self
                .retired
                .contains(&(stream_key.clone(), frame.observer_incarnation.clone()))
            {
                (ArrivalDispositionV1::Replay, None)
            } else {
                self.retired
                    .insert((stream_key, stream.incarnation.clone()));
                stream.incarnation = frame.observer_incarnation.clone();
                stream.sequence = frame.sequence;
                (ArrivalDispositionV1::Restarted, None)
            }
        } else {
            self.streams.insert(
                stream_key,
                ReceiverStream {
                    incarnation: frame.observer_incarnation.clone(),
                    sequence: frame.sequence,
                },
            );
            (ArrivalDispositionV1::First, None)
        };
        debug_assert!(!effective_stale);
        Ok(ReceiverAnnotationV1 {
            schema_version: SCHEMA_VERSION_V1,
            receiver: self.receiver.clone(),
            receiver_incarnation: self.receiver_incarnation.clone(),
            clock_id: self.clock_id.clone(),
            arrival_monotonic_ms,
            disposition,
            sequence_gap,
            transport_path: transport_path.into(),
            transport_observed_delay_ms,
            authentication,
        })
    }

    /// Install an externally configured subject-incarnation replacement and
    /// retire all receiver stream lineages for that subject. This is separate
    /// from merely receiving a pulse that disagrees about incarnation.
    pub fn activate_subject_incarnation(
        &mut self,
        subject: &SubjectId,
        replacement: IncarnationId,
    ) -> Result<(), PulseError> {
        subject.validate().map_err(|error| PulseError {
            code: "invalid",
            field: "subject",
            detail: error.reason,
        })?;
        replacement.validate().map_err(|error| PulseError {
            code: "invalid",
            field: "subject_incarnation",
            detail: error.reason,
        })?;
        if let Some(prior) = self
            .subject_incarnations
            .insert(subject.clone(), replacement)
        {
            self.retired_subject_incarnations
                .insert((subject.clone(), prior));
        }
        let retiring = self
            .streams
            .iter()
            .filter(|(key, _)| &key.subject == subject)
            .map(|(key, stream)| (key.clone(), stream.incarnation.clone()))
            .collect::<Vec<_>>();
        for (key, incarnation) in retiring {
            self.streams.remove(&key);
            self.retired.insert((key, incarnation));
        }
        Ok(())
    }
}
