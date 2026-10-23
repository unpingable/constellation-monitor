//! Optional operator telemetry. Every failure is contained here; these values
//! never feed publication, reactor admission, or the runner's exit decision.

use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::{HostPostureConfig, ProjectedStateV1, ReactorConditionV1, count_regular_store_entries};

const TEXTFILE: &str = "host-posture.prom";
const COUNTER_FILE: &str = "metrics-custody-lost-total";
const PREFIX: &str = "constellation_host_posture_";
const STATES: [ProjectedStateV1; 5] = [
    ProjectedStateV1::Healthy,
    ProjectedStateV1::Degraded,
    ProjectedStateV1::PartialOutage,
    ProjectedStateV1::MajorOutage,
    ProjectedStateV1::Unknown,
];
const CONDITIONS: [(ReactorConditionV1, &str); 10] = [
    (ReactorConditionV1::Starting, "starting"),
    (ReactorConditionV1::Operational, "operational"),
    (ReactorConditionV1::MailboxOverloaded, "mailbox_overloaded"),
    (ReactorConditionV1::ExplicitBlindness, "explicit_blindness"),
    (ReactorConditionV1::WakeupFailure, "wakeup_failure"),
    (ReactorConditionV1::ActorTerminated, "actor_terminated"),
    (ReactorConditionV1::JournalFailure, "journal_failure"),
    (
        ReactorConditionV1::CommandChannelClosed,
        "command_channel_closed",
    ),
    (ReactorConditionV1::ShuttingDown, "shutting_down"),
    (ReactorConditionV1::Terminated, "terminated"),
];

pub(super) struct Metrics<'a> {
    config: &'a HostPostureConfig,
    process_started: f64,
    last_acquisition: f64,
    state: ProjectedStateV1,
    condition: ReactorConditionV1,
    custody_lost: Option<u64>,
    counter_dirty: bool,
    counted_latch: bool,
    stores: Result<StoreCounts, String>,
    failures: FailureLog,
}

struct StoreCounts {
    intents: Arc<IntentCount>,
    publications: u64,
    temporary: u64,
}

pub(super) struct IntentCount {
    value: AtomicU64,
    valid: AtomicBool,
}

impl IntentCount {
    pub(super) fn completed(&self, config: &HostPostureConfig, success: bool) {
        if success && self.valid.load(Ordering::Relaxed) {
            let _ = self
                .value
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    Some(value.saturating_add(1))
                });
            return;
        }
        // A refused occurrence may already have written its intent. Reconcile
        // only this exceptional path, on the acquisition worker, never render.
        match count_regular_store_entries(
            &config.intent_dir(),
            config.maximum_occurrences,
            "intents",
        ) {
            Ok(value) => {
                self.value.store(value, Ordering::Relaxed);
                self.valid.store(true, Ordering::Release);
            }
            Err(_) => self.valid.store(false, Ordering::Release),
        }
    }
}

#[derive(Debug, PartialEq)]
enum LogEvent {
    Failed,
    Recovered,
}

#[derive(Default)]
struct FailureLog {
    last_report: Option<Instant>,
}

impl FailureLog {
    fn transition(&mut self, failed: bool, now: Instant) -> Option<LogEvent> {
        match (failed, self.last_report) {
            (true, Some(last)) if now.duration_since(last) < Duration::from_secs(600) => None,
            (true, _) => {
                self.last_report = Some(now);
                Some(LogEvent::Failed)
            }
            (false, Some(_)) => {
                self.last_report = None;
                Some(LogEvent::Recovered)
            }
            (false, None) => None,
        }
    }
}

impl<'a> Metrics<'a> {
    /// Called only while the runner holds its existing state writer lock.
    pub(super) fn new(config: &'a HostPostureConfig, process_started: SystemTime) -> Self {
        let (custody_lost, counter_dirty) = if config.metrics_textfile_dir.is_some() {
            match read_counter(&config.state_root.join(COUNTER_FILE)) {
                Ok(value) => (Some(value), true),
                Err(error) => {
                    report(error);
                    // Never manufacture a reset from unreadable/corrupt state.
                    // Other families remain available; repair requires an operator.
                    (None, false)
                }
            }
        } else {
            (None, false)
        };
        Self {
            config,
            process_started: seconds(process_started),
            last_acquisition: 0.0,
            state: ProjectedStateV1::Unknown,
            condition: ReactorConditionV1::Starting,
            custody_lost,
            counter_dirty,
            counted_latch: false,
            stores: if config.metrics_textfile_dir.is_some() {
                read_store_counts(config).map_err(|error| error.to_string())
            } else {
                // Disabled metrics must not inspect any stores.
                Ok(StoreCounts {
                    intents: Arc::new(IntentCount {
                        value: AtomicU64::new(0),
                        valid: AtomicBool::new(true),
                    }),
                    publications: 0,
                    temporary: 0,
                })
            },
            failures: FailureLog::default(),
        }
    }

    pub(super) fn intent_count(&self) -> Option<Arc<IntentCount>> {
        self.config.metrics_textfile_dir.as_ref()?;
        self.stores
            .as_ref()
            .ok()
            .map(|stores| Arc::clone(&stores.intents))
    }

    pub(super) fn publication_store_counts(&mut self, objects: u64, temporary: u64) {
        // Reuse the publication path's existing capacity check, without adding
        // scans to the projection cadence or using telemetry for admission.
        if let Ok(stores) = &mut self.stores {
            stores.publications = objects;
            stores.temporary = temporary;
        }
    }

    pub(super) fn object_exists(&self, artifact_id: &str) -> bool {
        self.config.metrics_textfile_dir.is_some()
            && self
                .config
                .publication_root
                .join("objects")
                .join(format!(
                    "{}.json",
                    artifact_id.trim_start_matches("sha256:")
                ))
                .exists()
    }

    pub(super) fn publication_finished(&mut self, existed: bool, success: bool) {
        if self.config.metrics_textfile_dir.is_none() {
            return;
        }
        if success {
            if let Ok(stores) = &mut self.stores {
                stores.publications = stores.publications.saturating_add(u64::from(!existed));
            }
        } else {
            // Staging/commit failure can leave an object or temporary entry.
            // Reconcile on failure only; keep the independently updated intents.
            let counts = read_publication_counts(self.config);
            match (&mut self.stores, counts) {
                (Ok(stores), Ok((objects, temporary))) => {
                    stores.publications = objects;
                    stores.temporary = temporary;
                }
                (_, Err(error)) => self.stores = Err(error.to_string()),
                _ => {}
            }
        }
    }

    pub(super) fn acquired(&mut self) {
        self.last_acquisition = seconds(SystemTime::now());
    }

    pub(super) fn observe(
        &mut self,
        state: Option<ProjectedStateV1>,
        condition: ReactorConditionV1,
        custody_lost: bool,
    ) {
        if let Some(state) = state {
            self.state = state;
        }
        self.condition = condition;
        if custody_lost && !self.counted_latch {
            self.counted_latch = true;
            if let Some(total) = &mut self.custody_lost {
                *total = total.saturating_add(1);
                self.counter_dirty = true;
            }
        }
        self.emit();
    }

    fn emit(&mut self) {
        if self.config.metrics_textfile_dir.is_none() {
            return;
        }
        let result = self.write();
        match self.failures.transition(result.is_err(), Instant::now()) {
            Some(LogEvent::Failed) => report(result.expect_err("failed write")),
            Some(LogEvent::Recovered) => {
                let _ = writeln!(io::stderr().lock(), "host_posture_metrics_write_recovered");
            }
            None => {}
        }
    }

    fn write(&mut self) -> io::Result<()> {
        // Save the latch before exposure, even if the textfile directory is
        // unavailable. Retry failed persistence on the next cycle/exit write.
        if self.counter_dirty {
            let total = self.custody_lost.expect("dirty counter has a value");
            atomic_write(
                &self.config.state_root.join(COUNTER_FILE),
                format!("{total}\n").as_bytes(),
                0o600,
                true,
            )?;
            self.counter_dirty = false;
        }
        let text = self.render()?;
        let directory = self.config.metrics_textfile_dir.as_ref().expect("enabled");
        atomic_write(&directory.join(TEXTFILE), text.as_bytes(), 0o644, false)
    }

    fn render(&self) -> io::Result<String> {
        let config = self.config;
        let stores = self
            .stores
            .as_ref()
            .map_err(|error| io::Error::other(error.clone()))?;
        if !stores.intents.valid.load(Ordering::Acquire) {
            return Err(io::Error::other("intent store count is unavailable"));
        }
        let occurrences = stores.intents.value.load(Ordering::Relaxed);
        let publications = stores.publications;
        let temporary = stores.temporary;
        let mut text = String::new();
        family(
            &mut text,
            "projection_state",
            "gauge",
            "Last published projection state; initially unknown.",
        );
        for state in STATES {
            writeln!(
                text,
                "{PREFIX}projection_state{{state=\"{}\"}} {}",
                state.as_str(),
                u8::from(state == self.state)
            )
            .expect("String write");
        }
        family(
            &mut text,
            "reactor_condition",
            "gauge",
            "Last observed reactor condition before shutdown.",
        );
        for (condition, label) in CONDITIONS {
            writeln!(
                text,
                "{PREFIX}reactor_condition{{condition=\"{label}\"}} {}",
                u8::from(condition == self.condition)
            )
            .expect("String write");
        }
        if let Some(total) = self.custody_lost {
            sample(
                &mut text,
                "custody_lost_total",
                "counter",
                "Observed custody latches, persisted across runner restarts.",
                total,
            );
        }
        sample(
            &mut text,
            "process_start_timestamp_seconds",
            "gauge",
            "Unix time this runner invocation started.",
            self.process_started,
        );
        sample(
            &mut text,
            "occurrences_total",
            "counter",
            "Retained occurrence intents; drops on governed rotation (gauge in practice).",
            occurrences,
        );
        sample(
            &mut text,
            "last_acquisition_timestamp_seconds",
            "gauge",
            "Unix time the last verified acquisition reached this process; zero until then.",
            self.last_acquisition,
        );
        sample(
            &mut text,
            "publications_total",
            "counter",
            "Retained immutable publication objects; drops on governed rotation (gauge in practice).",
            publications,
        );
        sample(
            &mut text,
            "publications_used",
            "gauge",
            "Publication capacity used by objects and temporary entries.",
            publications.saturating_add(temporary),
        );
        sample(
            &mut text,
            "maximum_occurrences",
            "gauge",
            "Configured aggregate occurrence ceiling.",
            config.maximum_occurrences,
        );
        sample(
            &mut text,
            "maximum_publications",
            "gauge",
            "Configured aggregate publication ceiling.",
            config.maximum_publications,
        );
        sample(
            &mut text,
            "textfile_write_timestamp_seconds",
            "gauge",
            "Unix time this textfile was rendered; a scrape does not refresh it.",
            seconds(SystemTime::now()),
        );
        Ok(text)
    }
}

impl Drop for Metrics<'_> {
    fn drop(&mut self) {
        self.emit();
    }
}

fn seconds(time: SystemTime) -> f64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn report(error: io::Error) {
    // Debug escaping keeps arbitrary path/error text on one stderr line.
    let _ = writeln!(
        io::stderr().lock(),
        "host_posture_metrics_write_failed: {error:?}"
    );
}

fn family(text: &mut String, name: &str, kind: &str, help: &str) {
    writeln!(
        text,
        "# HELP {PREFIX}{name} {help}\n# TYPE {PREFIX}{name} {kind}"
    )
    .expect("String write");
}

fn sample(text: &mut String, name: &str, kind: &str, help: &str, value: impl std::fmt::Display) {
    family(text, name, kind, help);
    writeln!(text, "{PREFIX}{name} {value}").expect("String write");
}

fn read_counter(path: &Path) -> io::Result<u64> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    if !metadata.is_file() || metadata.len() > 32 {
        return Err(io::Error::other(
            "metrics counter must be a small regular file",
        ));
    }
    let mut text = String::new();
    File::open(path)?.take(33).read_to_string(&mut text)?;
    text.trim().parse().map_err(io::Error::other)
}

/// Same-directory replacement: scrapers see either complete generation. The
/// temporary name never ends in .prom. chmod overrides the service's 0077 mask.
fn atomic_write(path: &Path, bytes: &[u8], mode: u32, durable: bool) -> io::Result<()> {
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("missing parent"))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = parent.join(format!(
        ".host-posture-{}-{nonce}-{}.tmp",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        if durable {
            file.sync_all()?;
        }
        fs::rename(&temporary, path)?;
        if durable {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn read_publication_counts(config: &HostPostureConfig) -> io::Result<(u64, u64)> {
    let objects = count_regular_store_entries(
        &config.publication_root.join("objects"),
        config.maximum_publications,
        "publications",
    )
    .map_err(io::Error::other)?;
    let temporary = count_regular_store_entries(
        &config.publication_root.join("tmp"),
        config.maximum_publications,
        "publication temporary entries",
    )
    .map_err(io::Error::other)?;
    Ok((objects, temporary))
}

fn read_store_counts(config: &HostPostureConfig) -> io::Result<StoreCounts> {
    let intents =
        count_regular_store_entries(&config.intent_dir(), config.maximum_occurrences, "intents")
            .map_err(io::Error::other)?;
    let (publications, temporary) = read_publication_counts(config)?;
    Ok(StoreCounts {
        intents: Arc::new(IntentCount {
            value: AtomicU64::new(intents),
            valid: AtomicBool::new(true),
        }),
        publications,
        temporary,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_logs_transitions_and_at_most_one_repeat_per_ten_minutes() {
        let mut log = FailureLog::default();
        let start = Instant::now();
        assert_eq!(log.transition(false, start), None);
        assert_eq!(log.transition(true, start), Some(LogEvent::Failed));
        for seconds in 1..600 {
            assert_eq!(
                log.transition(true, start + Duration::from_secs(seconds)),
                None
            );
        }
        assert_eq!(
            log.transition(true, start + Duration::from_secs(600)),
            Some(LogEvent::Failed)
        );
        assert_eq!(log.transition(true, start + Duration::from_secs(601)), None);
        assert_eq!(
            log.transition(false, start + Duration::from_secs(602)),
            Some(LogEvent::Recovered)
        );
        assert_eq!(
            log.transition(false, start + Duration::from_secs(603)),
            None
        );
        assert_eq!(
            log.transition(true, start + Duration::from_secs(604)),
            Some(LogEvent::Failed)
        );
    }
}
