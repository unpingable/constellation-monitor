//! Root-owned TOML configuration. It names inputs, routes and per-rule
//! overrides; it carries no secrets and cannot add rules.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::condition::validate_token;
use crate::registry::{
    self, Class, InputKind, REMEDIATION_RULES, RULES, ResponseClass, ResponsePolicy, Rule,
    ThresholdMeaning,
};
use crate::remediation::{MAX_WINDOW_SECONDS, MIN_WINDOW_SECONDS};

pub const CONFIG_SCHEMA: &str = "constellation.attention_config.v1";
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_THRESHOLD_SECONDS: i64 = 7 * 24 * 3600;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema: String,
    /// Bounded site token; the `site` of every condition.
    pub site: String,
    /// JSON state file (atomic write). `report.json`, `intents/` and
    /// `state.json.lock` live beside it.
    pub state_path: PathBuf,
    #[serde(default = "default_command_timeout")]
    pub command_timeout_seconds: u64,
    #[serde(default)]
    pub runbooks: Runbooks,
    pub nq: NqProgram,
    pub routes: Routes,
    #[serde(default)]
    pub inputs: Inputs,
    #[serde(default)]
    pub rules: BTreeMap<String, RuleOverride>,
    #[serde(default)]
    pub remediation: Remediation,
    /// `[digest]`: one notice a day listing every active condition and every
    /// input that is not current. Absent, no digest is sent.
    pub digest: Option<Digest>,
    /// `[[suspensions]]`: definitions the owner has deliberately suspended.
    #[serde(default)]
    pub suspensions: Vec<Suspension>,
}

/// A declared, owned suspension of one rule, or of one rule on one target.
/// Suspended is not healthy: the condition is held as it is (an open one stays
/// open, nothing triggers or resolves), reported as suspended with its reason,
/// and listed apart in the daily digest.
#[derive(Clone, Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Suspension {
    pub rule: String,
    /// Target class (unit, saved-check reference, service); absent = every target.
    pub target: Option<String>,
    pub owner: String,
    pub reason: String,
    /// The condition under which the suspension must be lifted.
    pub resume_when: String,
    /// When it was declared (RFC 3339 date or time).
    pub since: String,
}

impl Suspension {
    #[must_use]
    pub fn covers(&self, key: &crate::condition::ConditionKey) -> bool {
        self.rule == key.rule
            && self
                .target
                .as_ref()
                .is_none_or(|target| key.target_class.as_ref() == Some(target))
    }
}

/// A trigger is notified once; a condition that stays active is otherwise
/// silent. The digest restates what is still open, and its absence shows a
/// silent evaluator.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Digest {
    /// UTC time of day, `HH:MM`, after which the day's digest is due.
    pub at_utc: String,
}

impl Digest {
    /// Seconds after UTC midnight.
    pub fn offset_seconds(&self) -> Result<i64, String> {
        let invalid = || "digest.at_utc must be HH:MM (UTC)".to_owned();
        let (hours, minutes) = self.at_utc.split_once(':').ok_or_else(invalid)?;
        if hours.len() != 2 || minutes.len() != 2 {
            return Err(invalid());
        }
        let hours: i64 = hours.parse().map_err(|_| invalid())?;
        let minutes: i64 = minutes.parse().map_err(|_| invalid())?;
        if !(0..24).contains(&hours) || !(0..60).contains(&minutes) {
            return Err(invalid());
        }
        Ok(hours * 3600 + minutes * 60)
    }
}

/// `[remediation]`: per-target `response_policy` (cartography #55).
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Remediation {
    #[serde(default)]
    pub targets: Vec<RemediationTarget>,
}

/// `[[remediation.targets]]`: one condition target of a rule in
/// `REMEDIATION_RULES` given `auto_remediate_then_page`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationTarget {
    pub rule: String,
    /// The condition's target class, e.g. `attention-canary.service`.
    pub target_class: String,
    pub policy: ResponsePolicy,
    #[serde(default = "default_window")]
    pub window_seconds: i64,
}

const fn default_window() -> i64 {
    crate::remediation::DEFAULT_WINDOW_SECONDS
}

const fn default_command_timeout() -> u64 {
    90
}

/// Optional published copies of the runbook documents (https). A rule's
/// `runbook_url` is the matching base plus `#anchor`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Runbooks {
    /// Published copy of Cartography's beta-observability `RUNBOOKS.md`.
    pub cartography_url: Option<String>,
    /// Published copy of Monitor's `docs/ATTENTION.md`.
    pub monitor_url: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NqProgram {
    /// Absolute path of the `nq` executable used for submission.
    pub program: PathBuf,
    /// Absolute path of the NQ configuration that holds the routes.
    pub config: PathBuf,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoticeTransport {
    Slack,
    Discord,
    /// An NQ `local_file` inbox, for qualification runs: notices are written
    /// by `nq notification deliver-local` and never reach a production
    /// channel.
    LocalFile,
}

impl NoticeTransport {
    /// The destination label NQ requires in `destination_identity`
    /// (`{label}:{route}`).
    #[must_use]
    pub const fn destination_label(self) -> &'static str {
        match self {
            Self::Slack => "slack",
            Self::Discord => "discord",
            Self::LocalFile => "local-inbox",
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Routes {
    /// NQ route reference of a slack, discord or `local_file` route (v1 intents).
    pub notice_route: String,
    /// Transport of `notice_route`; it names the destination identity label
    /// and, for `local_file`, selects `nq notification deliver-local`.
    pub notice_transport: NoticeTransport,
    /// NQ route reference of a pagerduty route (v2 intents). Without it, page
    /// rules reach the operator through `notice_route` only.
    pub page_route: Option<String>,
    /// Pass `--enable-network` to `nq notification submit`. When false NQ
    /// retains a refusal and sends nothing. A `local_file` notice route
    /// needs no network and ignores it.
    pub network_enabled: bool,
}

impl Routes {
    /// Whether intents of `schema` go to the local inbox (`deliver-local`).
    #[must_use]
    pub fn local(&self, schema: &str) -> bool {
        self.notice_transport == NoticeTransport::LocalFile && schema == crate::intent::INTENT_V1
    }

    /// Whether a submission of `schema` can deliver: a local inbox always
    /// can; a network route only with `network_enabled`.
    #[must_use]
    pub fn delivers(&self, schema: &str) -> bool {
        self.network_enabled || self.local(schema)
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inputs {
    #[serde(default)]
    pub host_posture: Vec<HostPostureInput>,
    pub nq_status: Option<NqStatusInput>,
    pub nightshift: Option<NightshiftInput>,
    #[serde(default)]
    pub saved_checks: Vec<SavedCheckInput>,
    /// The estate collector's per-service verdicts (`constellation.estate/v1`).
    pub estate: Option<EstateInput>,
    /// vmalert's loaded alerting rules and their state (`constellation.metric_alerts/v1`).
    pub metric_alerts: Option<MetricAlertsInput>,
}

/// `[inputs.estate]`: every service the site is responsible for, with whether it
/// is running and doing its job by its own status contract.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EstateInput {
    /// JSON file written by `constellation-estate-collect`.
    pub path: PathBuf,
    /// The document's `generated_at` must be at most this old.
    #[serde(default = "default_estate_age")]
    pub max_age_seconds: i64,
}

const fn default_estate_age() -> i64 {
    600
}

/// `[inputs.metric_alerts]`: the document `metric-alerts-collect.py` writes
/// from vmalert's `/api/v1/rules`. Only rules labelled `attention = "true"`
/// become conditions; the rest are carried for the report only.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricAlertsInput {
    /// Input label (`evaluator-input-unavailable` target prefix).
    #[serde(default = "default_metric_alerts_label")]
    pub label: String,
    /// JSON file written by `metric-alerts-collect.py`.
    pub path: PathBuf,
    /// The document's `generated_at` must be at most this old.
    #[serde(default = "default_metric_alerts_age")]
    pub max_age_seconds: i64,
    /// Each rule's `last_evaluation` must be at most this much older than
    /// the document: a rule vmalert stopped evaluating is unknown, not clear.
    #[serde(default = "default_metric_alerts_age")]
    pub max_evaluation_age_seconds: i64,
    /// Sites whose alert instances are keyed apart, when one vmalert
    /// evaluates rules for several sites: each opted-in rule is then one
    /// condition per listed site, `<alert-name>.<site>`, present when an
    /// instance labelled `site` fires there. An instance of an unlisted site
    /// is counted but never a condition. Absent, each rule is one condition
    /// whatever its instances' sites.
    pub sites: Option<Vec<String>>,
}

/// The most sites one `[inputs.metric_alerts]` keys apart.
pub const METRIC_ALERTS_MAX_SITES: usize = 8;

fn default_metric_alerts_label() -> String {
    "metric_alerts".to_owned()
}

const fn default_metric_alerts_age() -> i64 {
    300
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPostureInput {
    /// Target class token, e.g. `root`.
    pub label: String,
    /// The runner's publication root (`<state_root>/status`, holding `CURRENT`).
    pub publication_root: PathBuf,
}

/// Where the NQ status input reads evaluations from.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum NqStatusSource {
    /// `nq --json status export` (`command` is the full argv, or `path`).
    /// It walks the whole evaluation history (nq#20): for small stores only.
    #[default]
    StatusExport,
    /// `nq --json evaluations export` pages: `command` is the base argv up to
    /// and including `--json`; the evaluator appends the subcommand.
    EvaluationHistory,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NqStatusInput {
    pub label: String,
    #[serde(default)]
    pub source: NqStatusSource,
    /// Evaluation-history mode: how many of the newest evaluations to read
    /// (50..=5000). It must cover at least `stale_after_seconds` of every
    /// watcher's evaluations.
    #[serde(default = "default_window_records")]
    pub window_records: u32,
    /// Evaluation-history mode: watcher instances the operator has removed
    /// from NQ. Every other watcher ever seen is remembered and is stale once
    /// it stops evaluating, even after it leaves the window.
    #[serde(default)]
    pub retired_instances: Vec<String>,
    /// Targets (unit names, filesystem targets) the operator has retired from
    /// supervision. An open condition on a retired target that NQ no longer
    /// reports resolves as "no longer evaluated" instead of being held open,
    /// unknown, for ever.
    #[serde(default)]
    pub retired_targets: Vec<String>,
    /// argv printing `nq.status_snapshot.v3` JSON, e.g.
    /// `["/usr/bin/nq","--config","/etc/nq/nqd-ops.toml","--json","status","export"]`.
    pub command: Option<Vec<String>>,
    /// Or a status JSON file written by a timer.
    pub path: Option<PathBuf>,
    /// The snapshot's `generated_at` must be at most this old.
    #[serde(default = "default_status_age")]
    pub max_age_seconds: i64,
    /// A watcher whose instance `observed_at` (last collection commit) is
    /// older than this at `generated_at` is stale. NQ's export has no
    /// staleness flag; default 3 x the 60 s watcher interval.
    #[serde(default = "default_instance_stale")]
    pub stale_after_seconds: i64,
}

const fn default_window_records() -> u32 {
    300
}

const fn default_status_age() -> i64 {
    300
}

const fn default_instance_stale() -> i64 {
    180
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NightshiftInput {
    pub label: String,
    /// The Nightshift observation store, opened read-only.
    pub store_path: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedCheckInput {
    /// Target class token naming the check, e.g. `atproto-freelist`.
    pub reference: String,
    /// argv printing one `nq saved-check result|evaluate --json` document.
    pub command: Option<Vec<String>>,
    /// Or a result JSON file written by the timer that runs the check.
    pub path: Option<PathBuf>,
    /// The result's `read_attempted_at` must be at most this old.
    #[serde(default = "default_saved_check_age")]
    pub max_age_seconds: i64,
}

const fn default_saved_check_age() -> i64 {
    3600
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleOverride {
    pub enabled: Option<bool>,
    pub threshold_seconds: Option<i64>,
    pub class: Option<Class>,
}

impl<'de> Deserialize<'de> for Class {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match String::deserialize(deserializer)?.as_str() {
            "page" => Ok(Self::Page),
            "notice" => Ok(Self::Notice),
            other => Err(serde::de::Error::custom(format!(
                "class must be page or notice, not {other:?}"
            ))),
        }
    }
}

/// A rule after applying the configuration's bounded overrides.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct EffectiveRule {
    #[serde(flatten)]
    pub rule: &'static Rule,
    pub enabled: bool,
    pub class: Class,
    pub threshold_seconds: i64,
}

impl EffectiveRule {
    /// How long the condition must persist before it is actionable.
    #[must_use]
    pub const fn persistence_seconds(&self) -> i64 {
        match self.rule.threshold_meaning {
            ThresholdMeaning::Persistence => self.threshold_seconds,
            ThresholdMeaning::Age => self.rule.fixed_persistence_seconds,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.is_absolute() {
            return Err("configuration path must be absolute".into());
        }
        let metadata = fs::metadata(path)
            .map_err(|error| format!("cannot stat {}: {error}", path.display()))?;
        if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES {
            return Err("configuration must be a regular file of at most 64 KiB".into());
        }
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err("configuration must not be group- or other-writable".into());
        }
        let text = fs::read_to_string(path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        let config: Self =
            toml::from_str(&text).map_err(|error| format!("invalid configuration: {error}"))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != CONFIG_SCHEMA {
            return Err(format!("schema must be {CONFIG_SCHEMA}"));
        }
        validate_token("site", &self.site, 64)?;
        absolute("state_path", &self.state_path)?;
        if self.state_path.file_name().is_none() {
            return Err("state_path must name a file".into());
        }
        if !(1..=600).contains(&self.command_timeout_seconds) {
            return Err("command_timeout_seconds must be 1..=600".into());
        }
        for url in [&self.runbooks.cartography_url, &self.runbooks.monitor_url]
            .into_iter()
            .flatten()
        {
            if !url.starts_with("https://")
                || url.len() > 900
                || url.contains('#')
                || url.chars().any(|c| c.is_control() || c.is_whitespace())
            {
                return Err(
                    "runbook URLs must be https, without a fragment, at most 900 bytes".into(),
                );
            }
        }
        if let Some(digest) = &self.digest {
            digest.offset_seconds()?;
        }
        for suspension in &self.suspensions {
            if crate::registry::rule(&suspension.rule).is_none() {
                return Err(format!(
                    "suspension names unknown rule {:?}",
                    suspension.rule
                ));
            }
            for (field, value) in [
                ("owner", &suspension.owner),
                ("reason", &suspension.reason),
                ("resume_when", &suspension.resume_when),
                ("since", &suspension.since),
            ] {
                if value.trim().is_empty() || value.len() > 300 {
                    return Err(format!(
                        "suspension of {} needs a {field} (1..=300 bytes)",
                        suspension.rule
                    ));
                }
            }
        }
        absolute("nq.program", &self.nq.program)?;
        absolute("nq.config", &self.nq.config)?;
        route_reference("routes.notice_route", &self.routes.notice_route)?;
        if self.routes.notice_transport == NoticeTransport::LocalFile
            && self.routes.notice_route.len() > crate::intent::LOCAL_ROUTE_MAX
        {
            return Err(format!(
                "a local_file notice_route must be at most {} bytes so its rendered message fits NQ's 4 KiB limit",
                crate::intent::LOCAL_ROUTE_MAX
            ));
        }
        if let Some(page) = &self.routes.page_route {
            route_reference("routes.page_route", page)?;
            if page == &self.routes.notice_route {
                return Err("page_route and notice_route must be different NQ routes".into());
            }
        }
        let mut labels = BTreeSet::new();
        let mut label = |value: &str| -> Result<(), String> {
            // 48-byte target class minus `.` and the longest fault class
            // (`indeterminate`), for `evaluator-input-unavailable` keys.
            validate_token("input label", value, 34)?;
            if !labels.insert(value.to_owned()) {
                return Err(format!("input label {value:?} is used twice"));
            }
            Ok(())
        };
        for input in &self.inputs.host_posture {
            label(&input.label)?;
            absolute("host_posture.publication_root", &input.publication_root)?;
        }
        if let Some(input) = &self.inputs.nq_status {
            label(&input.label)?;
            source("nq_status", input.command.as_ref(), input.path.as_ref())?;
            age("nq_status.max_age_seconds", input.max_age_seconds)?;
            age("nq_status.stale_after_seconds", input.stale_after_seconds)?;
            if input.source == NqStatusSource::EvaluationHistory {
                if input.command.is_none() {
                    return Err(
                        "nq_status source evaluation_history needs a command (the nq argv up to --json)"
                            .into(),
                    );
                }
                if !(50..=5000).contains(&input.window_records) {
                    return Err("nq_status.window_records must be 50..=5000".into());
                }
            }
        }
        if let Some(input) = &self.inputs.nightshift {
            label(&input.label)?;
            absolute("nightshift.store_path", &input.store_path)?;
        }
        if let Some(input) = &self.inputs.estate {
            absolute("inputs.estate.path", &input.path)?;
            age("inputs.estate.max_age_seconds", input.max_age_seconds)?;
        }
        if let Some(input) = &self.inputs.metric_alerts {
            label(&input.label)?;
            absolute("inputs.metric_alerts.path", &input.path)?;
            age(
                "inputs.metric_alerts.max_age_seconds",
                input.max_age_seconds,
            )?;
            age(
                "inputs.metric_alerts.max_evaluation_age_seconds",
                input.max_evaluation_age_seconds,
            )?;
            if let Some(sites) = &input.sites {
                if sites.is_empty() || sites.len() > METRIC_ALERTS_MAX_SITES {
                    return Err(format!(
                        "inputs.metric_alerts.sites must list 1..={METRIC_ALERTS_MAX_SITES} sites"
                    ));
                }
                let mut seen = BTreeSet::new();
                for site in sites {
                    validate_token("inputs.metric_alerts.sites entry", site, 48)?;
                    if !seen.insert(site.as_str()) {
                        return Err(format!("inputs.metric_alerts.sites lists {site:?} twice"));
                    }
                }
            }
        }
        for input in &self.inputs.saved_checks {
            label(&input.reference)?;
            source("saved_checks", input.command.as_ref(), input.path.as_ref())?;
            age("saved_checks.max_age_seconds", input.max_age_seconds)?;
        }
        for (id, value) in &self.rules {
            let rule = registry::rule(id).ok_or_else(|| format!("unknown rule {id:?}"))?;
            if rule.disabled.is_some() && value.enabled == Some(true) {
                return Err(format!(
                    "rule {id} cannot be enabled: {}",
                    rule.disabled.unwrap_or_default()
                ));
            }
            if value.class == Some(Class::Page) && rule.response_class != ResponseClass::Page {
                return Err(format!(
                    "rule {id} may not page: its response class is {}",
                    rule.response_class.as_str()
                ));
            }
            if let Some(threshold) = value.threshold_seconds {
                age(&format!("rules.{id}.threshold_seconds"), threshold)?;
            }
        }
        let mut targets = BTreeSet::new();
        for target in &self.remediation.targets {
            let rule = registry::rule(&target.rule).ok_or_else(|| {
                format!("remediation target names unknown rule {:?}", target.rule)
            })?;
            if !REMEDIATION_RULES.contains(&rule.id) || rule.response_class != ResponseClass::Page {
                return Err(format!(
                    "rule {} cannot carry remediation targets (only {})",
                    rule.id,
                    REMEDIATION_RULES.join(", ")
                ));
            }
            validate_token("remediation target_class", &target.target_class, 48)?;
            if target.policy != ResponsePolicy::AutoRemediateThenPage {
                return Err(format!(
                    "remediation target {} policy must be auto_remediate_then_page (observe_only is the default)",
                    target.target_class
                ));
            }
            if !(MIN_WINDOW_SECONDS..=MAX_WINDOW_SECONDS).contains(&target.window_seconds) {
                return Err(format!(
                    "remediation target {} window_seconds must be {MIN_WINDOW_SECONDS}..={MAX_WINDOW_SECONDS}",
                    target.target_class
                ));
            }
            if !targets.insert((target.rule.clone(), target.target_class.clone())) {
                return Err(format!(
                    "remediation target {} {} is listed twice",
                    target.rule, target.target_class
                ));
            }
        }
        Ok(())
    }

    /// The configured remediation target of a condition, if any.
    #[must_use]
    pub fn remediation_target(
        &self,
        rule: &str,
        target_class: Option<&str>,
    ) -> Option<&RemediationTarget> {
        self.remediation.targets.iter().find(|target| {
            target.rule == rule && Some(target.target_class.as_str()) == target_class
        })
    }

    /// A condition's effective response policy and window.
    #[must_use]
    pub fn response_policy(
        &self,
        rule: &str,
        target_class: Option<&str>,
    ) -> (ResponsePolicy, Option<i64>) {
        self.remediation_target(rule, target_class).map_or_else(
            || {
                (
                    registry::rule(rule)
                        .map_or(ResponsePolicy::ObserveOnly, |rule| rule.response_policy),
                    None,
                )
            },
            |target| (target.policy, Some(target.window_seconds)),
        )
    }

    #[must_use]
    pub fn effective_rules(&self) -> Vec<EffectiveRule> {
        RULES
            .iter()
            .map(|rule| {
                let value = self.rules.get(rule.id).cloned().unwrap_or_default();
                EffectiveRule {
                    rule,
                    enabled: rule.disabled.is_none() && value.enabled.unwrap_or(true),
                    class: value.class.unwrap_or(rule.default_class),
                    threshold_seconds: value
                        .threshold_seconds
                        .unwrap_or(rule.default_threshold_seconds),
                }
            })
            .collect()
    }

    #[must_use]
    pub fn runbook_url(&self, rule: &Rule) -> Option<String> {
        let base = if rule.runbook_document.starts_with("cartography:") {
            self.runbooks.cartography_url.as_ref()
        } else {
            self.runbooks.monitor_url.as_ref()
        }?;
        Some(format!("{base}#{}", rule.runbook_anchor))
    }

    #[must_use]
    pub fn state_dir(&self) -> PathBuf {
        self.state_path
            .parent()
            .map_or_else(|| PathBuf::from("/"), Path::to_path_buf)
    }

    /// The input kinds the configuration names, for rules that need one.
    #[must_use]
    pub fn has_input(&self, kind: InputKind) -> bool {
        match kind {
            InputKind::HostPosture => !self.inputs.host_posture.is_empty(),
            InputKind::NqStatus => self.inputs.nq_status.is_some(),
            InputKind::HostPostureOrNqStatus => {
                !self.inputs.host_posture.is_empty() || self.inputs.nq_status.is_some()
            }
            InputKind::Nightshift => self.inputs.nightshift.is_some(),
            InputKind::SavedCheck => !self.inputs.saved_checks.is_empty(),
            InputKind::Estate => self.inputs.estate.is_some(),
            InputKind::MetricAlerts => self.inputs.metric_alerts.is_some(),
            InputKind::Evaluator => true,
            InputKind::NotDeployed => false,
        }
    }
}

fn absolute(label: &str, path: &Path) -> Result<(), String> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(format!("{label} must be an absolute path"))
    }
}

fn route_reference(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(format!("{label} must be 1..=256 non-control bytes"));
    }
    Ok(())
}

fn source(
    label: &str,
    command: Option<&Vec<String>>,
    path: Option<&PathBuf>,
) -> Result<(), String> {
    match (command, path) {
        (Some(argv), None) => {
            let Some(program) = argv.first() else {
                return Err(format!("{label}.command must not be empty"));
            };
            if !Path::new(program).is_absolute() || argv.len() > 32 {
                return Err(format!(
                    "{label}.command must start with an absolute program and have at most 32 arguments"
                ));
            }
            Ok(())
        }
        (None, Some(path)) => absolute(&format!("{label}.path"), path),
        _ => Err(format!("{label} needs exactly one of command or path")),
    }
}

fn age(label: &str, value: i64) -> Result<(), String> {
    if (1..=MAX_THRESHOLD_SECONDS).contains(&value) {
        Ok(())
    } else {
        Err(format!("{label} must be 1..={MAX_THRESHOLD_SECONDS}"))
    }
}
