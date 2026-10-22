//! Optional operator telemetry. Every failure is contained here; these values
//! never feed publication, reactor admission, or the runner's exit decision.

use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

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
        if let Err(error) = self.write() {
            report(error);
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
            )?;
            self.counter_dirty = false;
        }
        let text = self.render()?;
        let directory = self.config.metrics_textfile_dir.as_ref().expect("enabled");
        if !directory.is_absolute() {
            return Err(io::Error::other("metrics_textfile_dir must be absolute"));
        }
        atomic_write(&directory.join(TEXTFILE), text.as_bytes(), 0o644)
    }

    fn render(&self) -> io::Result<String> {
        let config = self.config;
        let count = |path: &Path, bound, name| {
            count_regular_store_entries(path, bound, name).map_err(io::Error::other)
        };
        let occurrences = count(&config.intent_dir(), config.maximum_occurrences, "intents")?;
        let publications = count(
            &config.publication_root.join("objects"),
            config.maximum_publications,
            "publications",
        )?;
        let temporary = count(
            &config.publication_root.join("tmp"),
            config.maximum_publications,
            "publication temporary entries",
        )?;
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
            "Retained occurrence intents, including failed attempts.",
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
            "Retained immutable publication objects.",
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
fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
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
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
