use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    ClockId, DigestV1, IncarnationId, ObservationPolicyGenerationId, ObserverId, ReceiverId,
    SCHEMA_VERSION_V1, SubjectId, digest_parts,
};

pub const MAX_WIRE_FRAME_BYTES: usize = 64 * 1024;
pub const MAX_COVERAGE_TAGS: usize = 64;
pub const MAX_SIGNALS: usize = 32;
pub const MAX_FIELD_BYTES: usize = 256;
pub const MAX_VALIDITY_MS: u64 = 60 * 60 * 1_000;

const WIRE_MAGIC: &[u8; 4] = b"PLS1";

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationProfileIdV1 {
    pub name: String,
    pub version: u16,
    pub semantic_digest: DigestV1,
}

impl ObservationProfileIdV1 {
    pub fn validate(&self) -> Result<(), PulseError> {
        validate_field("profile.name", &self.name)?;
        if self.version == 0 {
            return Err(PulseError::invalid(
                "profile.version",
                "version zero is unsupported",
            ));
        }
        self.semantic_digest
            .validate()
            .map_err(|error| PulseError::invalid("profile.semantic_digest", error.0))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageDescriptorV1 {
    /// Profile-declared tags expected from this producer occurrence.
    pub expected: Vec<String>,
    /// Tags actually supported by this occurrence.
    pub observed: Vec<String>,
}

impl CoverageDescriptorV1 {
    pub fn validate(&self) -> Result<(), PulseError> {
        validate_sorted_tags("coverage.expected", &self.expected)?;
        validate_sorted_tags("coverage.observed", &self.observed)?;
        let expected: BTreeSet<_> = self.expected.iter().collect();
        if self.observed.iter().any(|tag| !expected.contains(tag)) {
            return Err(PulseError::invalid(
                "coverage.observed",
                "observed coverage is not declared in expected coverage",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn missing(&self) -> Vec<String> {
        let observed: BTreeSet<_> = self.observed.iter().collect();
        self.expected
            .iter()
            .filter(|tag| !observed.contains(tag))
            .cloned()
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalAssessmentV1 {
    /// A value was observed without a profile-local bound classification.
    Observed,
    /// The observation lies inside one explicitly declared profile bound.
    WithinDeclaredBound,
    /// The observation lies outside one explicitly declared profile bound.
    OutsideDeclaredBound,
    /// The signal could not be observed in this occurrence.
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BoundedSignalValueV1 {
    pub name: String,
    pub value: f64,
    pub unit: String,
    pub assessment: SignalAssessmentV1,
}

impl BoundedSignalValueV1 {
    pub fn validate(&self) -> Result<(), PulseError> {
        validate_field("signal.name", &self.name)?;
        validate_field("signal.unit", &self.unit)?;
        if !self.value.is_finite() {
            return Err(PulseError::invalid("signal.value", "value must be finite"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthenticationFieldV1 {
    /// Deliberate placeholder for the unauthenticated skunkworks transport.
    Placeholder { disclosure: String },
    /// Carrier for a future externally verified MAC. V1 does not verify it.
    Mac {
        scheme: String,
        key_id: String,
        tag: String,
    },
}

impl AuthenticationFieldV1 {
    fn validate(&self) -> Result<(), PulseError> {
        match self {
            Self::Placeholder { disclosure } => {
                validate_field("authentication.disclosure", disclosure)
            }
            Self::Mac {
                scheme,
                key_id,
                tag,
            } => {
                validate_field("authentication.scheme", scheme)?;
                validate_field("authentication.key_id", key_id)?;
                validate_field("authentication.tag", tag)
            }
        }
    }
}

/// Compact hot-path observation occurrence.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PulseFrameV1 {
    pub schema_version: u16,
    pub subject: SubjectId,
    pub subject_incarnation: IncarnationId,
    pub observer: ObserverId,
    pub observer_incarnation: IncarnationId,
    pub sequence: u64,
    pub observer_monotonic_ns: u64,
    pub validity_ms: u64,
    pub profile: ObservationProfileIdV1,
    pub observation_policy_generation: ObservationPolicyGenerationId,
    pub coverage: CoverageDescriptorV1,
    pub signals: Vec<BoundedSignalValueV1>,
    pub observation_digest: DigestV1,
    pub authentication: AuthenticationFieldV1,
}

impl PulseFrameV1 {
    pub fn validate(&self) -> Result<(), PulseError> {
        if self.schema_version != SCHEMA_VERSION_V1 {
            return Err(PulseError::unsupported("pulse schema version"));
        }
        self.subject
            .validate()
            .map_err(|error| PulseError::invalid("subject", error.reason))?;
        self.subject_incarnation
            .validate()
            .map_err(|error| PulseError::invalid("subject_incarnation", error.reason))?;
        self.observer
            .validate()
            .map_err(|error| PulseError::invalid("observer", error.reason))?;
        self.observer_incarnation
            .validate()
            .map_err(|error| PulseError::invalid("observer_incarnation", error.reason))?;
        self.observation_policy_generation
            .validate()
            .map_err(|error| PulseError::invalid("observation_policy_generation", error.reason))?;
        if self.validity_ms == 0 || self.validity_ms > MAX_VALIDITY_MS {
            return Err(PulseError::invalid(
                "validity_ms",
                "validity must be nonzero and within the v1 maximum",
            ));
        }
        self.profile.validate()?;
        self.coverage.validate()?;
        if self.signals.len() > MAX_SIGNALS {
            return Err(PulseError::bound("signals"));
        }
        let mut previous = None;
        for signal in &self.signals {
            signal.validate()?;
            if previous.is_some_and(|name: &str| name >= signal.name.as_str()) {
                return Err(PulseError::invalid(
                    "signals",
                    "signal names must be unique and sorted",
                ));
            }
            previous = Some(signal.name.as_str());
        }
        self.authentication.validate()?;
        self.observation_digest
            .validate()
            .map_err(|error| PulseError::invalid("observation_digest", error.0))?;
        if self.observation_digest != self.recompute_observation_digest() {
            return Err(PulseError::invalid(
                "observation_digest",
                "digest does not match the observation transcript",
            ));
        }
        Ok(())
    }

    /// Replace the digest with the exact v1 observation transcript digest.
    #[must_use]
    pub fn seal(mut self) -> Self {
        self.observation_digest = self.recompute_observation_digest();
        self
    }

    #[must_use]
    pub fn recompute_observation_digest(&self) -> DigestV1 {
        let mut owned = vec![
            self.schema_version.to_be_bytes().to_vec(),
            self.subject.as_str().as_bytes().to_vec(),
            self.subject_incarnation.as_str().as_bytes().to_vec(),
            self.observer.as_str().as_bytes().to_vec(),
            self.observer_incarnation.as_str().as_bytes().to_vec(),
            self.sequence.to_be_bytes().to_vec(),
            self.observer_monotonic_ns.to_be_bytes().to_vec(),
            self.validity_ms.to_be_bytes().to_vec(),
            self.profile.name.as_bytes().to_vec(),
            self.profile.version.to_be_bytes().to_vec(),
            self.profile.semantic_digest.as_str().as_bytes().to_vec(),
            self.observation_policy_generation
                .as_str()
                .as_bytes()
                .to_vec(),
        ];
        for tag in &self.coverage.expected {
            owned.push(b"expected".to_vec());
            owned.push(tag.as_bytes().to_vec());
        }
        for tag in &self.coverage.observed {
            owned.push(b"observed".to_vec());
            owned.push(tag.as_bytes().to_vec());
        }
        for signal in &self.signals {
            owned.push(signal.name.as_bytes().to_vec());
            owned.push(signal.value.to_bits().to_be_bytes().to_vec());
            owned.push(signal.unit.as_bytes().to_vec());
            owned.push(vec![assessment_tag(signal.assessment)]);
        }
        let parts: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
        digest_parts("pulse.observation.v1", &parts)
    }

    /// Encode the pulse into the bounded v1 binary wire format.
    pub fn encode_wire(&self) -> Result<Vec<u8>, PulseError> {
        self.validate()?;
        let mut output = Vec::with_capacity(512);
        output.extend_from_slice(WIRE_MAGIC);
        put_u16(&mut output, self.schema_version);
        put_string(&mut output, self.subject.as_str())?;
        put_string(&mut output, self.subject_incarnation.as_str())?;
        put_string(&mut output, self.observer.as_str())?;
        put_string(&mut output, self.observer_incarnation.as_str())?;
        put_u64(&mut output, self.sequence);
        put_u64(&mut output, self.observer_monotonic_ns);
        put_u64(&mut output, self.validity_ms);
        put_string(&mut output, &self.profile.name)?;
        put_u16(&mut output, self.profile.version);
        put_string(&mut output, self.profile.semantic_digest.as_str())?;
        put_string(&mut output, self.observation_policy_generation.as_str())?;
        put_strings(&mut output, &self.coverage.expected)?;
        put_strings(&mut output, &self.coverage.observed)?;
        put_u16(
            &mut output,
            u16::try_from(self.signals.len()).map_err(|_| PulseError::bound("signals"))?,
        );
        for signal in &self.signals {
            put_string(&mut output, &signal.name)?;
            put_u64(&mut output, signal.value.to_bits());
            put_string(&mut output, &signal.unit)?;
            output.push(assessment_tag(signal.assessment));
        }
        put_string(&mut output, self.observation_digest.as_str())?;
        match &self.authentication {
            AuthenticationFieldV1::Placeholder { disclosure } => {
                output.push(0);
                put_string(&mut output, disclosure)?;
            }
            AuthenticationFieldV1::Mac {
                scheme,
                key_id,
                tag,
            } => {
                output.push(1);
                put_string(&mut output, scheme)?;
                put_string(&mut output, key_id)?;
                put_string(&mut output, tag)?;
            }
        }
        if output.len() > MAX_WIRE_FRAME_BYTES {
            return Err(PulseError::bound("wire frame"));
        }
        Ok(output)
    }

    /// Decode and fully validate one bounded v1 binary frame.
    pub fn decode_wire(bytes: &[u8]) -> Result<Self, PulseError> {
        if bytes.len() > MAX_WIRE_FRAME_BYTES {
            return Err(PulseError::bound("wire frame"));
        }
        let mut reader = WireReader::new(bytes);
        if reader.take(4)? != WIRE_MAGIC {
            return Err(PulseError::unsupported("wire magic"));
        }
        let schema_version = reader.u16()?;
        let subject = SubjectId::new(reader.string("subject")?);
        let subject_incarnation = IncarnationId::new(reader.string("subject_incarnation")?);
        let observer = ObserverId::new(reader.string("observer")?);
        let observer_incarnation = IncarnationId::new(reader.string("observer_incarnation")?);
        let sequence = reader.u64()?;
        let observer_monotonic_ns = reader.u64()?;
        let validity_ms = reader.u64()?;
        let profile = ObservationProfileIdV1 {
            name: reader.string("profile.name")?,
            version: reader.u16()?,
            semantic_digest: DigestV1(reader.string("profile.semantic_digest")?),
        };
        let observation_policy_generation =
            ObservationPolicyGenerationId::new(reader.string("observation_policy_generation")?);
        let coverage = CoverageDescriptorV1 {
            expected: reader.strings("coverage.expected", MAX_COVERAGE_TAGS)?,
            observed: reader.strings("coverage.observed", MAX_COVERAGE_TAGS)?,
        };
        let signal_count = usize::from(reader.u16()?);
        if signal_count > MAX_SIGNALS {
            return Err(PulseError::bound("signals"));
        }
        let mut signals = Vec::with_capacity(signal_count);
        for _ in 0..signal_count {
            signals.push(BoundedSignalValueV1 {
                name: reader.string("signal.name")?,
                value: f64::from_bits(reader.u64()?),
                unit: reader.string("signal.unit")?,
                assessment: assessment_from_tag(reader.byte()?)?,
            });
        }
        let observation_digest = DigestV1(reader.string("observation_digest")?);
        let authentication = match reader.byte()? {
            0 => AuthenticationFieldV1::Placeholder {
                disclosure: reader.string("authentication.disclosure")?,
            },
            1 => AuthenticationFieldV1::Mac {
                scheme: reader.string("authentication.scheme")?,
                key_id: reader.string("authentication.key_id")?,
                tag: reader.string("authentication.tag")?,
            },
            _ => return Err(PulseError::unsupported("authentication kind")),
        };
        if !reader.is_empty() {
            return Err(PulseError::invalid(
                "wire frame",
                "trailing bytes are forbidden",
            ));
        }
        let frame = Self {
            schema_version,
            subject,
            subject_incarnation,
            observer,
            observer_incarnation,
            sequence,
            observer_monotonic_ns,
            validity_ms,
            profile,
            observation_policy_generation,
            coverage,
            signals,
            observation_digest,
            authentication,
        };
        frame.validate()?;
        Ok(frame)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArrivalDispositionV1 {
    First,
    Continuous,
    Gap,
    Duplicate,
    Replay,
    Restarted,
    Stale,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SequenceGapV1 {
    pub expected_next: u64,
    pub received: u64,
    pub missing_count: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthenticationResultV1 {
    NotChecked,
    Unauthenticated { disclosure: String },
    Verified { method: String, principal: String },
    Failed { reason: String },
}

impl AuthenticationResultV1 {
    pub fn validate(&self) -> Result<(), PulseError> {
        match self {
            Self::NotChecked => Ok(()),
            Self::Unauthenticated { disclosure } => {
                validate_field("authentication_result.disclosure", disclosure)
            }
            Self::Verified { method, principal } => {
                validate_field("authentication_result.method", method)?;
                validate_field("authentication_result.principal", principal)
            }
            Self::Failed { reason } => validate_field("authentication_result.reason", reason),
        }
    }
}

/// Receiver-owned facts attached after pulse arrival.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverAnnotationV1 {
    pub schema_version: u16,
    pub receiver: ReceiverId,
    pub receiver_incarnation: IncarnationId,
    pub clock_id: ClockId,
    pub arrival_monotonic_ms: u64,
    pub disposition: ArrivalDispositionV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence_gap: Option<SequenceGapV1>,
    pub transport_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_observed_delay_ms: Option<u64>,
    pub authentication: AuthenticationResultV1,
}

impl ReceiverAnnotationV1 {
    pub fn validate(&self) -> Result<(), PulseError> {
        if self.schema_version != SCHEMA_VERSION_V1 {
            return Err(PulseError::unsupported("receiver schema version"));
        }
        self.receiver
            .validate()
            .map_err(|error| PulseError::invalid("receiver", error.reason))?;
        self.receiver_incarnation
            .validate()
            .map_err(|error| PulseError::invalid("receiver_incarnation", error.reason))?;
        self.clock_id
            .validate()
            .map_err(|error| PulseError::invalid("clock_id", error.reason))?;
        validate_field("transport_path", &self.transport_path)?;
        self.authentication.validate()?;
        match (&self.disposition, &self.sequence_gap) {
            (ArrivalDispositionV1::Gap, Some(gap)) => {
                if gap.received <= gap.expected_next
                    || gap.missing_count != gap.received - gap.expected_next
                {
                    return Err(PulseError::invalid(
                        "sequence_gap",
                        "gap arithmetic is inconsistent",
                    ));
                }
            }
            (ArrivalDispositionV1::Gap, None) => {
                return Err(PulseError::invalid(
                    "sequence_gap",
                    "gap disposition requires gap detail",
                ));
            }
            (_, Some(_)) => {
                return Err(PulseError::invalid(
                    "sequence_gap",
                    "gap detail is only valid for a gap disposition",
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceivedPulseV1 {
    pub frame: PulseFrameV1,
    pub receiver: ReceiverAnnotationV1,
}

impl ReceivedPulseV1 {
    pub fn validate(&self) -> Result<(), PulseError> {
        self.frame.validate()?;
        self.receiver.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PulseError {
    pub code: &'static str,
    pub field: &'static str,
    pub detail: &'static str,
}

impl PulseError {
    const fn invalid(field: &'static str, detail: &'static str) -> Self {
        Self {
            code: "invalid",
            field,
            detail,
        }
    }

    const fn bound(field: &'static str) -> Self {
        Self {
            code: "bound_exceeded",
            field,
            detail: "bounded field exceeds the v1 maximum",
        }
    }

    const fn unsupported(field: &'static str) -> Self {
        Self {
            code: "unsupported",
            field,
            detail: "unsupported v1 value",
        }
    }

    const fn truncated() -> Self {
        Self {
            code: "malformed",
            field: "wire frame",
            detail: "truncated binary frame",
        }
    }
}

impl fmt::Display for PulseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} {}: {}", self.code, self.field, self.detail)
    }
}

impl std::error::Error for PulseError {}

fn validate_field(field: &'static str, value: &str) -> Result<(), PulseError> {
    if value.is_empty() {
        return Err(PulseError::invalid(field, "field is empty"));
    }
    if value.len() > MAX_FIELD_BYTES {
        return Err(PulseError::bound(field));
    }
    if value.chars().any(char::is_control) {
        return Err(PulseError::invalid(
            field,
            "field contains a control character",
        ));
    }
    Ok(())
}

fn validate_sorted_tags(field: &'static str, values: &[String]) -> Result<(), PulseError> {
    if values.len() > MAX_COVERAGE_TAGS {
        return Err(PulseError::bound(field));
    }
    let mut previous = None;
    for value in values {
        validate_field(field, value)?;
        if previous.is_some_and(|prior: &str| prior >= value) {
            return Err(PulseError::invalid(field, "tags must be unique and sorted"));
        }
        previous = Some(value.as_str());
    }
    Ok(())
}

fn assessment_tag(value: SignalAssessmentV1) -> u8 {
    match value {
        SignalAssessmentV1::Observed => 0,
        SignalAssessmentV1::WithinDeclaredBound => 1,
        SignalAssessmentV1::OutsideDeclaredBound => 2,
        SignalAssessmentV1::Unavailable => 3,
    }
}

fn assessment_from_tag(value: u8) -> Result<SignalAssessmentV1, PulseError> {
    match value {
        0 => Ok(SignalAssessmentV1::Observed),
        1 => Ok(SignalAssessmentV1::WithinDeclaredBound),
        2 => Ok(SignalAssessmentV1::OutsideDeclaredBound),
        3 => Ok(SignalAssessmentV1::Unavailable),
        _ => Err(PulseError::unsupported("signal.assessment")),
    }
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_string(output: &mut Vec<u8>, value: &str) -> Result<(), PulseError> {
    if value.len() > MAX_FIELD_BYTES {
        return Err(PulseError::bound("wire string"));
    }
    let length = u16::try_from(value.len()).map_err(|_| PulseError::bound("wire string"))?;
    put_u16(output, length);
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_strings(output: &mut Vec<u8>, values: &[String]) -> Result<(), PulseError> {
    let count = u16::try_from(values.len()).map_err(|_| PulseError::bound("wire list"))?;
    put_u16(output, count);
    for value in values {
        put_string(output, value)?;
    }
    Ok(())
}

struct WireReader<'a> {
    remaining: &'a [u8],
}

impl<'a> WireReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], PulseError> {
        if self.remaining.len() < count {
            return Err(PulseError::truncated());
        }
        let (value, remaining) = self.remaining.split_at(count);
        self.remaining = remaining;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, PulseError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, PulseError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| PulseError::truncated())?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, PulseError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| PulseError::truncated())?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn string(&mut self, field: &'static str) -> Result<String, PulseError> {
        let length = usize::from(self.u16()?);
        if length > MAX_FIELD_BYTES {
            return Err(PulseError::bound(field));
        }
        let value = std::str::from_utf8(self.take(length)?)
            .map_err(|_| PulseError::invalid(field, "string is not UTF-8"))?;
        Ok(value.to_owned())
    }

    fn strings(&mut self, field: &'static str, maximum: usize) -> Result<Vec<String>, PulseError> {
        let count = usize::from(self.u16()?);
        if count > maximum {
            return Err(PulseError::bound(field));
        }
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(self.string(field)?);
        }
        Ok(values)
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest_parts;

    fn frame() -> PulseFrameV1 {
        PulseFrameV1 {
            schema_version: SCHEMA_VERSION_V1,
            subject: SubjectId::new("host:a"),
            subject_incarnation: IncarnationId::new("boot:1"),
            observer: ObserverId::new("observer:a"),
            observer_incarnation: IncarnationId::new("process:1"),
            sequence: 7,
            observer_monotonic_ns: 99,
            validity_ms: 1_000,
            profile: ObservationProfileIdV1 {
                name: "local.summary".to_owned(),
                version: 1,
                semantic_digest: digest_parts("profile", &[b"local.summary/v1"]),
            },
            observation_policy_generation: ObservationPolicyGenerationId::new("policy:1"),
            coverage: CoverageDescriptorV1 {
                expected: vec!["load".to_owned(), "memory".to_owned()],
                observed: vec!["load".to_owned(), "memory".to_owned()],
            },
            signals: vec![BoundedSignalValueV1 {
                name: "load".to_owned(),
                value: 0.25,
                unit: "ratio".to_owned(),
                assessment: SignalAssessmentV1::WithinDeclaredBound,
            }],
            observation_digest: digest_parts("placeholder", &[]),
            authentication: AuthenticationFieldV1::Placeholder {
                disclosure: "unauthenticated test pulse".to_owned(),
            },
        }
        .seal()
    }

    #[test]
    fn compact_wire_round_trip_is_stable() {
        let frame = frame();
        let bytes = frame.encode_wire().expect("frame encodes");
        assert!(bytes.len() < 512);
        let decoded = PulseFrameV1::decode_wire(&bytes).expect("frame decodes");
        assert_eq!(decoded, frame);
        assert_eq!(decoded.encode_wire().expect("re-encode"), bytes);
    }

    #[test]
    fn digest_detects_semantic_change() {
        let frame = frame();
        let mut changed = frame.clone();
        changed.sequence += 1;
        assert!(changed.validate().is_err());
        assert_ne!(
            changed.recompute_observation_digest(),
            frame.observation_digest
        );
    }

    #[test]
    fn decoder_rejects_trailing_and_oversized_frames() {
        let mut bytes = frame().encode_wire().expect("frame encodes");
        bytes.push(0);
        assert!(PulseFrameV1::decode_wire(&bytes).is_err());
        assert!(PulseFrameV1::decode_wire(&vec![0; MAX_WIRE_FRAME_BYTES + 1]).is_err());
    }

    #[test]
    fn partial_coverage_is_explicit() {
        let coverage = CoverageDescriptorV1 {
            expected: vec!["load".to_owned(), "memory".to_owned()],
            observed: vec!["load".to_owned()],
        };
        coverage.validate().expect("coverage is valid");
        assert_eq!(coverage.missing(), vec!["memory"]);
    }
}
