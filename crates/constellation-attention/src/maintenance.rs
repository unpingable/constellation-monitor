//! Bounded service delivery windows. Only the maintenance CLI writes this sidecar.
use std::collections::BTreeSet;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::condition::{ConditionKey, validate_token};
use crate::config::Config;
use crate::state::State;
use crate::util::{format_seconds, read_bounded, rfc3339_seconds, write_atomic};

pub const MAX_WINDOW_SECONDS: i64 = 24 * 60 * 60;
const MAX_BYTES: usize = 64 * 1024;
const SCHEMA: &str = "constellation.attention_maintenance.v1";
pub const NOT_COVERED: &[&str] = &[
    "site-wide service metric threshold aggregates",
    "shared input faults, ProbeExporterDown, remediation-journal-critical, host_posture, saved checks, nightshift, docket and ag",
    "already accepted provider pages: provider escalation continues; acknowledge it in the provider",
    "manual nq notification submit/resubmit and other producers",
    "scheduled, recurring, group or dependency-cascading maintenance",
    "notifications from a pass already running when start was issued",
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Window {
    pub service: String,
    pub units: Vec<String>,
    pub started_at: String,
    pub until: String,
    pub reason: String,
    pub by: String,
}
impl Window {
    fn validate(&self) -> Result<(), String> {
        validate_token("service", &self.service, 48)?;
        if self.units.len() > 64 {
            return Err("too many units".into());
        }
        for unit in &self.units {
            validate_token("unit", unit, 48)?;
        }
        reason(&self.reason)?;
        if self.by.is_empty() || self.by.len() > 300 {
            return Err("by must be 1..=300 bytes".into());
        }
        let duration = rfc3339_seconds(&self.until)? - rfc3339_seconds(&self.started_at)?;
        if !(1..=MAX_WINDOW_SECONDS).contains(&duration) {
            return Err("invalid maintenance duration (maximum 24 h)".into());
        }
        Ok(())
    }
    #[must_use]
    pub fn active(&self, now: i64) -> bool {
        matches!((rfc3339_seconds(&self.started_at), rfc3339_seconds(&self.until)), (Ok(start), Ok(end)) if start <= now && now < end)
    }
    #[must_use]
    pub fn owns(&self, site: &str, key: &ConditionKey) -> bool {
        key.site == site
            && key.component == "service"
            && match key.rule.as_str() {
                "service-not-doing-its-job" | "service-endpoint-unavailable" => {
                    key.target_class.as_deref() == Some(&self.service)
                }
                "service-down" => key
                    .target_class
                    .as_ref()
                    .is_some_and(|unit| self.units.contains(unit)),
                _ => false,
            }
    }
}
fn reason(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 300 {
        Err("reason must be 1..=300 bytes".into())
    } else {
        Ok(())
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema: String,
    site: String,
    windows: Vec<Window>,
}
#[derive(Default, Serialize)]
pub struct View {
    pub windows: Vec<Window>,
    pub error: Option<String>,
}
impl View {
    #[must_use]
    pub fn covering(&self, site: &str, key: &ConditionKey) -> Option<&Window> {
        self.windows.iter().find(|window| window.owns(site, key))
    }
}
/// Invalid state never suppresses delivery.
#[must_use]
pub fn read(config: &Config, now: i64) -> View {
    let path = config.state_dir().join("maintenance.json");
    let result = (|| {
        // Only NotFound is absence; permissions and malformed files are visible.
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.to_string()),
            Ok(_) => (),
        }
        let bytes = read_bounded(&path, MAX_BYTES as u64)?;
        let doc: Document = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if doc.schema != SCHEMA || doc.site != config.site || doc.windows.len() > 64 {
            return Err("invalid maintenance schema, site or window count".into());
        }
        let mut seen = BTreeSet::new();
        for window in &doc.windows {
            window.validate()?;
            if !seen.insert(&window.service) {
                return Err("duplicate maintenance service".into());
            }
        }
        Ok(doc.windows.into_iter().filter(|w| w.active(now)).collect())
    })();
    match result {
        Ok(windows) => View {
            windows,
            error: None,
        },
        Err(error) => View {
            windows: Vec::new(),
            error: Some(format!("{}: {error}", path.display())),
        },
    }
}

/// Run as nq, just like the evaluator: atomic files deliberately retain mode 0600.
pub fn command(
    config: &Config,
    action: &str,
    window: Option<Window>,
    service: Option<&str>,
    end_reason: Option<&str>,
    replace: bool,
    now: i64,
) -> Result<Value, String> {
    std::fs::create_dir_all(config.state_dir()).map_err(|e| e.to_string())?;
    let start = Instant::now();
    let _lock = loop {
        match crate::engine::lock(config, false) {
            Ok(lock) => break lock,
            Err(error) if start.elapsed() >= Duration::from_secs(30) => return Err(error),
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    };
    let state = State::load(&config.state_path, &config.site)?;
    if now < state.updated_at {
        return Err("clock moved backwards; use reset-clock".into());
    }
    let mut view = read(config, now);
    if let Some(error) = &view.error {
        eprintln!("maintenance: {error}; treating as no windows");
    }
    if action == "list" {
        let mut value = serde_json::to_value(&view).map_err(|e| e.to_string())?;
        if let Some(estate) = &config.inputs.estate {
            for window in value["windows"].as_array_mut().expect("serialized windows") {
                if window["service"].as_str().is_some_and(|name| {
                    estate
                        .retired_services
                        .iter()
                        .any(|retired| retired == name)
                }) {
                    window["declaration"] = json!("(not declared)");
                }
            }
        }
        return Ok(value);
    }
    let service = service.ok_or("--service is required")?;
    validate_token("service", service, 48)?;
    let existing = view.windows.iter().any(|w| w.service == service);
    let operation = match action {
        "start" => {
            let window = window.ok_or("start requires --until, --reason and --by")?;
            window.validate()?;
            if window.service != service || rfc3339_seconds(&window.started_at)? != now {
                return Err("window must name the requested service and start now".into());
            }
            if !window.active(now) {
                return Err("until must be after now".into());
            }
            if existing && !replace {
                return Err("active window exists; use --replace".into());
            }
            view.windows.retain(|w| w.service != service);
            view.windows.push(window);
            if view.windows.len() > 64 {
                return Err("at most 64 maintenance windows".into());
            }
            if replace { "replace" } else { "start" }
        }
        "end" => {
            if let Some(value) = end_reason {
                reason(value)?;
            }
            if !existing {
                return Ok(json!({"windows": view.windows, "error": view.error, "changed": false}));
            }
            view.windows.retain(|w| w.service != service);
            "end"
        }
        _ => return Err("expected maintenance start|end|list".into()),
    };
    let doc = Document {
        schema: SCHEMA.into(),
        site: config.site.clone(),
        windows: view.windows.clone(),
    };
    let bytes = serde_json::to_vec_pretty(&doc).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_BYTES {
        return Err("maintenance document exceeds 64 KiB".into());
    }
    let audit = config.state_dir().join("maintenance.jsonl");
    if std::fs::metadata(&audit).is_ok_and(|m| m.len() >= 1024 * 1024) {
        std::fs::rename(&audit, audit.with_extension("jsonl.1")).map_err(|e| e.to_string())?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&audit)
        .map_err(|e| e.to_string())?;
    let event = json!({"at": format_seconds(now), "operation": operation, "service": service, "reason": end_reason, "window": view.windows.iter().find(|w| w.service == service)});
    writeln!(file, "{event}").map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    write_atomic(&config.state_dir().join("maintenance.json"), &bytes)?;
    let accepted: Vec<_> = state
        .conditions
        .values()
        .filter(|c| {
            view.covering(&config.site, &c.key)
                .is_some_and(|w| w.service == service)
                && c.last_intent
                    .get("page")
                    .is_some_and(|i| i.action == "trigger" && i.outcome == "accepted")
        })
        .map(|c| c.key.id())
        .collect();
    Ok(
        json!({"windows": view.windows, "accepted_pages": accepted, "provider_warning": "provider escalation continues; acknowledge it in the provider", "not_covered": NOT_COVERED}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn window() -> Window {
        Window {
            service: "bar".into(),
            units: vec!["bar.service".into()],
            started_at: format_seconds(1000),
            until: format_seconds(2000),
            reason: "upgrade".into(),
            by: "operator".into(),
        }
    }
    fn config(dir: &std::path::Path) -> Config {
        toml::from_str(&format!(
            r#"
            schema = "constellation.attention_config.v1"
            site = "example"
            state_path = {:?}
            [nq]
            program = "/bin/false"
            config = "/tmp/unused-nq.toml"
            [routes]
            notice_route = "operations"
            notice_transport = "local_file"
            network_enabled = false
        "#,
            dir.join("state.json")
        ))
        .unwrap()
    }
    #[test]
    fn ownership_is_closed_and_site_scoped() {
        for (site, component, rule, target, owned) in [
            (
                "example",
                "service",
                "service-not-doing-its-job",
                "bar",
                true,
            ),
            (
                "example",
                "service",
                "service-endpoint-unavailable",
                "bar",
                true,
            ),
            ("example", "service", "service-down", "bar.service", true),
            ("example", "service", "service-down", "baz.service", false),
            (
                "example",
                "service",
                "service-not-doing-its-job",
                "baz",
                false,
            ),
            (
                "other",
                "service",
                "service-not-doing-its-job",
                "bar",
                false,
            ),
            (
                "example",
                "service",
                "remediation-journal-critical",
                "bar",
                false,
            ),
            (
                "example",
                "host_posture",
                "metric-alert-firing",
                "bar",
                false,
            ),
            (
                "example",
                "service",
                "evaluator-input-unavailable",
                "bar",
                false,
            ),
            (
                "example",
                "nightshift",
                "service-down",
                "bar.service",
                false,
            ),
        ] {
            let key = ConditionKey::new(site, component, rule, Some(target)).unwrap();
            assert_eq!(window().owns("example", &key), owned, "{key:?}");
        }
    }
    #[test]
    fn window_bounds_and_reason_bytes() {
        let mut w = window();
        assert!(!w.active(999));
        assert!(w.active(1000));
        assert!(w.active(1999));
        assert!(!w.active(2000));
        for duration in [0, -1, MAX_WINDOW_SECONDS + 1] {
            w.until = format_seconds(1000 + duration);
            assert!(w.validate().is_err());
        }
        w.until = format_seconds(1000 + MAX_WINDOW_SECONDS);
        assert!(w.validate().is_ok());
        for reason in [String::new(), "x".repeat(301), "é".repeat(151)] {
            w.reason = reason;
            assert!(w.validate().is_err());
        }
        w.reason = "x".repeat(300);
        assert!(w.validate().is_ok());
    }
    #[test]
    fn start_replace_end_prune_and_audit() {
        let dir = tempfile::tempdir().unwrap();
        let c = config(dir.path());
        command(&c, "start", Some(window()), Some("bar"), None, false, 1000).unwrap();
        assert!(command(&c, "start", Some(window()), Some("bar"), None, false, 1000).is_err());
        command(&c, "start", Some(window()), Some("bar"), None, true, 1000).unwrap();
        assert_eq!(read(&c, 1999).windows.len(), 1);
        assert!(read(&c, 2000).windows.is_empty());
        let mut next = window();
        next.service = "baz".into();
        next.started_at = format_seconds(2000);
        next.until = format_seconds(3000);
        command(&c, "start", Some(next), Some("baz"), None, false, 2000).unwrap();
        let doc: Document =
            serde_json::from_slice(&std::fs::read(dir.path().join("maintenance.json")).unwrap())
                .unwrap();
        assert_eq!(doc.windows.len(), 1);
        assert_eq!(doc.windows[0].service, "baz");
        command(&c, "end", None, Some("baz"), None, false, 2100).unwrap();
        command(&c, "end", None, Some("baz"), None, false, 2100).unwrap();
        assert!(read(&c, 2100).windows.is_empty());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("maintenance.jsonl"))
                .unwrap()
                .lines()
                .count(),
            4
        );
    }
    #[test]
    fn broken_files_never_mute() {
        let dir = tempfile::tempdir().unwrap();
        let c = config(dir.path());
        let path = dir.path().join("maintenance.json");
        assert!(read(&c, 1000).error.is_none());
        for bytes in [
            b"bad".to_vec(),
            vec![b'x'; MAX_BYTES + 1],
            serde_json::to_vec(&Document {
                schema: SCHEMA.into(),
                site: "foreign".into(),
                windows: vec![window()],
            })
            .unwrap(),
        ] {
            std::fs::write(&path, bytes).unwrap();
            let view = read(&c, 1000);
            assert!(view.windows.is_empty());
            assert!(view.error.is_some());
        }
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let view = read(&c, 1000);
        assert!(view.windows.is_empty());
        assert!(view.error.is_some());
    }
}
