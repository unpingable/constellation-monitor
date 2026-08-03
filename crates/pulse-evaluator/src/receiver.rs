use std::collections::{BTreeMap, BTreeSet};

use pulse_types::{
    ArrivalDispositionV1, AuthenticationResultV1, ClockId, IncarnationId, ObserverId, PulseFrameV1,
    ReceiverAnnotationV1, ReceiverId, SCHEMA_VERSION_V1, SequenceGapV1,
};

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
    streams: BTreeMap<ObserverId, ReceiverStream>,
    retired: BTreeSet<(ObserverId, IncarnationId)>,
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
        }
    }

    #[must_use]
    pub fn annotate(
        &mut self,
        frame: &PulseFrameV1,
        arrival_monotonic_ms: u64,
        transport_path: impl Into<String>,
        transport_observed_delay_ms: Option<u64>,
        authentication: AuthenticationResultV1,
    ) -> ReceiverAnnotationV1 {
        let effective_stale =
            transport_observed_delay_ms.is_some_and(|delay| delay >= frame.validity_ms);
        if effective_stale {
            return ReceiverAnnotationV1 {
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
            };
        }
        let (disposition, sequence_gap) =
            if let Some(stream) = self.streams.get_mut(&frame.observer) {
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
                    .contains(&(frame.observer.clone(), frame.observer_incarnation.clone()))
                {
                    (ArrivalDispositionV1::Replay, None)
                } else {
                    self.retired
                        .insert((frame.observer.clone(), stream.incarnation.clone()));
                    stream.incarnation = frame.observer_incarnation.clone();
                    stream.sequence = frame.sequence;
                    (ArrivalDispositionV1::Restarted, None)
                }
            } else {
                self.streams.insert(
                    frame.observer.clone(),
                    ReceiverStream {
                        incarnation: frame.observer_incarnation.clone(),
                        sequence: frame.sequence,
                    },
                );
                (ArrivalDispositionV1::First, None)
            };
        debug_assert!(!effective_stale);
        ReceiverAnnotationV1 {
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
        }
    }
}
