#![forbid(unsafe_code)]
//! Bounded pulse producer with synthetic and narrow Linux `/proc` profiles.

use std::fmt;
use std::fs;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pulse_types::{
    AuthenticationFieldV1, BoundedSignalValueV1, CoverageDescriptorV1, DigestV1, IncarnationId,
    ObservationPolicyGenerationId, ObservationProfileIdV1, ObserverId, PulseFrameV1,
    SCHEMA_VERSION_V1, SignalAssessmentV1, SubjectId, digest_parts,
};

static INCARNATION_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProducerProfile {
    Synthetic,
    LinuxProc,
}

#[derive(Clone, Debug)]
pub struct AgentConfig {
    pub subject: SubjectId,
    pub subject_incarnation: IncarnationId,
    pub observer: ObserverId,
    pub observation_policy_generation: ObservationPolicyGenerationId,
    pub profile: ProducerProfile,
    pub cadence: Duration,
    pub validity_ms: u64,
    pub fault_at_sequence: Option<u64>,
    pub coverage_collapse_at_sequence: Option<u64>,
}

impl AgentConfig {
    #[must_use]
    pub fn synthetic() -> Self {
        Self {
            subject: SubjectId::new("subject:demo-host"),
            subject_incarnation: IncarnationId::new("subject-incarnation:demo-1"),
            observer: ObserverId::new("observer:synthetic-local"),
            observation_policy_generation: ObservationPolicyGenerationId::new("policy:demo-v1"),
            profile: ProducerProfile::Synthetic,
            cadence: Duration::from_millis(250),
            validity_ms: 750,
            fault_at_sequence: None,
            coverage_collapse_at_sequence: None,
        }
    }

    #[must_use]
    pub fn linux_proc() -> Self {
        let mut config = Self::synthetic();
        config.observer = ObserverId::new("observer:linux-proc-local");
        config.profile = ProducerProfile::LinuxProc;
        config.subject_incarnation = linux_boot_incarnation()
            .unwrap_or_else(|_| IncarnationId::new("subject-incarnation:boot-id-unavailable"));
        config
    }

    pub fn validate(&self) -> Result<(), AgentError> {
        if self.cadence.is_zero() {
            return Err(AgentError::new("cadence must be nonzero"));
        }
        if self.validity_ms == 0 || self.validity_ms > pulse_types::MAX_VALIDITY_MS {
            return Err(AgentError::new(
                "validity must be nonzero and within the pulse v1 bound",
            ));
        }
        self.subject
            .validate()
            .map_err(|error| AgentError::new(error.to_string()))?;
        self.subject_incarnation
            .validate()
            .map_err(|error| AgentError::new(error.to_string()))?;
        self.observer
            .validate()
            .map_err(|error| AgentError::new(error.to_string()))?;
        self.observation_policy_generation
            .validate()
            .map_err(|error| AgentError::new(error.to_string()))?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ShutdownToken(Arc<AtomicBool>);

impl ShutdownToken {
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    pub fn request(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    #[must_use]
    pub fn requested(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

impl Default for ShutdownToken {
    fn default() -> Self {
        Self::new()
    }
}

pub struct PulseAgent {
    config: AgentConfig,
    observer_incarnation: IncarnationId,
    sequence: u64,
    started: Instant,
}

impl PulseAgent {
    pub fn new(config: AgentConfig) -> Result<Self, AgentError> {
        config.validate()?;
        Ok(Self {
            config,
            observer_incarnation: fresh_observer_incarnation(),
            sequence: 0,
            started: Instant::now(),
        })
    }

    #[must_use]
    pub const fn observer_incarnation(&self) -> &IncarnationId {
        &self.observer_incarnation
    }

    pub fn next_pulse(&mut self) -> Result<PulseFrameV1, AgentError> {
        self.sequence = self.sequence.saturating_add(1);
        let (coverage, signals) = match self.config.profile {
            ProducerProfile::Synthetic => self.synthetic_observation(),
            ProducerProfile::LinuxProc => linux_proc_observation()?,
        };
        let profile = profile_identity(self.config.profile);
        let frame = PulseFrameV1 {
            schema_version: SCHEMA_VERSION_V1,
            subject: self.config.subject.clone(),
            subject_incarnation: self.config.subject_incarnation.clone(),
            observer: self.config.observer.clone(),
            observer_incarnation: self.observer_incarnation.clone(),
            sequence: self.sequence,
            observer_monotonic_ns: u64::try_from(self.started.elapsed().as_nanos())
                .unwrap_or(u64::MAX),
            validity_ms: self.config.validity_ms,
            profile,
            observation_policy_generation: self.config.observation_policy_generation.clone(),
            coverage,
            signals,
            observation_digest: DigestV1::from_parts("unsealed", &[]),
            authentication: AuthenticationFieldV1::Placeholder {
                disclosure: "v1 producer has no authentication infrastructure".to_owned(),
            },
        }
        .seal();
        frame
            .validate()
            .map_err(|error| AgentError::new(error.to_string()))?;
        Ok(frame)
    }

    /// Run at the configured cadence until the count is reached or shutdown is
    /// requested. A count of zero means no count limit.
    pub fn run<F>(
        &mut self,
        count: u64,
        shutdown: &ShutdownToken,
        mut emit: F,
    ) -> Result<u64, AgentError>
    where
        F: FnMut(PulseFrameV1) -> Result<(), AgentError>,
    {
        let mut produced = 0_u64;
        while !shutdown.requested() && (count == 0 || produced < count) {
            let cycle_started = Instant::now();
            emit(self.next_pulse()?)?;
            produced = produced.saturating_add(1);
            if count != 0 && produced >= count {
                break;
            }
            let remaining = self.config.cadence.saturating_sub(cycle_started.elapsed());
            sleep_interruptibly(remaining, shutdown);
        }
        Ok(produced)
    }

    fn synthetic_observation(&self) -> (CoverageDescriptorV1, Vec<BoundedSignalValueV1>) {
        let expected = vec!["load".to_owned(), "memory".to_owned()];
        let collapsed = self
            .config
            .coverage_collapse_at_sequence
            .is_some_and(|start| self.sequence >= start);
        let fault = self
            .config
            .fault_at_sequence
            .is_some_and(|start| self.sequence >= start);
        let observed = if collapsed {
            vec!["load".to_owned()]
        } else {
            expected.clone()
        };
        let mut signals = vec![BoundedSignalValueV1 {
            name: "load_ratio".to_owned(),
            value: if fault { 1.25 } else { 0.25 },
            unit: "ratio".to_owned(),
            assessment: if fault {
                SignalAssessmentV1::OutsideDeclaredBound
            } else {
                SignalAssessmentV1::WithinDeclaredBound
            },
        }];
        if !collapsed {
            signals.push(BoundedSignalValueV1 {
                name: "memory_available_ratio".to_owned(),
                value: 0.70,
                unit: "ratio".to_owned(),
                assessment: SignalAssessmentV1::WithinDeclaredBound,
            });
        }
        (CoverageDescriptorV1 { expected, observed }, signals)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentError {
    detail: String,
}

impl AgentError {
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

impl fmt::Display for AgentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for AgentError {}

impl From<io::Error> for AgentError {
    fn from(error: io::Error) -> Self {
        Self::new(error.to_string())
    }
}

#[must_use]
pub fn profile_identity(profile: ProducerProfile) -> ObservationProfileIdV1 {
    let name = match profile {
        ProducerProfile::Synthetic => "synthetic.present",
        ProducerProfile::LinuxProc => "linux.proc.summary",
    };
    ObservationProfileIdV1 {
        name: name.to_owned(),
        version: 1,
        semantic_digest: digest_parts("observation.profile.v1", &[name.as_bytes(), b"1"]),
    }
}

fn fresh_observer_incarnation() -> IncarnationId {
    let counter = INCARNATION_COUNTER.fetch_add(1, Ordering::SeqCst);
    let epoch_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    IncarnationId::new(format!(
        "observer-incarnation:{}:{epoch_ns}:{counter}",
        std::process::id()
    ))
}

fn linux_boot_incarnation() -> Result<IncarnationId, AgentError> {
    let value = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let value = value.trim();
    if value.is_empty() {
        return Err(AgentError::new("Linux boot identity is empty"));
    }
    Ok(IncarnationId::new(format!("linux-boot:{value}")))
}

fn linux_proc_observation() -> Result<(CoverageDescriptorV1, Vec<BoundedSignalValueV1>), AgentError>
{
    let expected = vec!["proc.cpu".to_owned(), "proc.memory".to_owned()];
    let mut observed = Vec::new();
    let mut signals = Vec::new();

    if let Ok(stat) = fs::read_to_string("/proc/stat")
        && let Some(ratio) = parse_cpu_idle_fraction(&stat)
    {
        observed.push("proc.cpu".to_owned());
        signals.push(BoundedSignalValueV1 {
            name: "cpu_idle_fraction".to_owned(),
            value: ratio,
            unit: "ratio".to_owned(),
            assessment: SignalAssessmentV1::Observed,
        });
    }
    if let Ok(meminfo) = fs::read_to_string("/proc/meminfo")
        && let Some(ratio) = parse_memory_available_fraction(&meminfo)
    {
        observed.push("proc.memory".to_owned());
        signals.push(BoundedSignalValueV1 {
            name: "memory_available_fraction".to_owned(),
            value: ratio,
            unit: "ratio".to_owned(),
            assessment: SignalAssessmentV1::Observed,
        });
    }
    observed.sort();
    signals.sort_by(|left, right| left.name.cmp(&right.name));
    Ok((CoverageDescriptorV1 { expected, observed }, signals))
}

fn parse_cpu_idle_fraction(input: &str) -> Option<f64> {
    let line = input.lines().find(|line| line.starts_with("cpu "))?;
    let values: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    if values.len() < 4 {
        return None;
    }
    let total: u64 = values.iter().copied().fold(0, u64::saturating_add);
    if total == 0 {
        return None;
    }
    let idle = values[3].saturating_add(values.get(4).copied().unwrap_or(0));
    Some(idle as f64 / total as f64)
}

fn parse_memory_available_fraction(input: &str) -> Option<f64> {
    let mut total = None;
    let mut available = None;
    for line in input.lines() {
        let mut fields = line.split_whitespace();
        match fields.next()? {
            "MemTotal:" => total = fields.next()?.parse::<u64>().ok(),
            "MemAvailable:" => available = fields.next()?.parse::<u64>().ok(),
            _ => {}
        }
    }
    let total = total?;
    let available = available?;
    if total == 0 {
        return None;
    }
    Some(available.min(total) as f64 / total as f64)
}

fn sleep_interruptibly(duration: Duration, shutdown: &ShutdownToken) {
    let deadline = Instant::now() + duration;
    while !shutdown.requested() {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        thread::sleep((deadline - now).min(Duration::from_millis(25)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_process_instance_gets_a_new_observer_incarnation() {
        let first = PulseAgent::new(AgentConfig::synthetic()).expect("first agent");
        let second = PulseAgent::new(AgentConfig::synthetic()).expect("second agent");
        assert_ne!(first.observer_incarnation(), second.observer_incarnation());
    }

    #[test]
    fn synthetic_faults_and_coverage_collapse_are_explicit() {
        let mut config = AgentConfig::synthetic();
        config.fault_at_sequence = Some(2);
        config.coverage_collapse_at_sequence = Some(2);
        let mut agent = PulseAgent::new(config).expect("agent");
        let first = agent.next_pulse().expect("first pulse");
        let second = agent.next_pulse().expect("second pulse");
        assert_eq!(first.coverage.missing(), Vec::<String>::new());
        assert_eq!(second.coverage.missing(), vec!["memory"]);
        assert!(
            second
                .signals
                .iter()
                .any(|signal| { signal.assessment == SignalAssessmentV1::OutsideDeclaredBound })
        );
    }

    #[test]
    fn proc_parsers_are_narrow_and_deterministic() {
        let stat = "cpu  10 2 3 85 0 0 0 0 0 0\ncpu0 1 1 1 1\n";
        assert_eq!(parse_cpu_idle_fraction(stat), Some(0.85));
        let mem = "MemTotal:       1000 kB\nMemAvailable:    250 kB\nSwapTotal: 0 kB\n";
        assert_eq!(parse_memory_available_fraction(mem), Some(0.25));
    }

    #[test]
    fn shutdown_token_stops_before_unbounded_count() {
        let mut agent = PulseAgent::new(AgentConfig::synthetic()).expect("agent");
        let stop = ShutdownToken::new();
        stop.request();
        let produced = agent.run(0, &stop, |_| Ok(())).expect("graceful shutdown");
        assert_eq!(produced, 0);
    }
}
