//! Present reliance over exact NQ systemd v3 observation custody.
//! Acquisition, custody, current boot, present reliance and effect authority
//! remain distinct. A new evaluation cannot refresh its source observation.
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    Basis, Claim, Judgement, RESOLUTION_SCHEMA, Request, Resolution, Settings, Status,
    TYPED_BASIS_SCHEMA, Window, hash_domain, jcs, read_window, run_bounded,
};

pub const PROFILE_DIGEST: &str =
    "sha256:25fbbdd320248701b79b3e5f6c3109667b6aa9388ed113678ee0e6ba3c04a853";
pub const RELIANCE_MS: u64 = 60_000;
pub const NOT_ACTIVE_BASIS: &str = "constellation.remediation.current-boot-systemd-not-active/v1";
pub const ACTIVE_BASIS: &str = "constellation.remediation.current-boot-systemd-active/v1";
pub const WITNESS_DOMAIN: &str = "constellation.remediation.nq-boot-unit-currentness/v1";
pub const READ_SCHEMA: &str = "monitor.live-unit-read/v1";

#[derive(Clone, Debug)]
pub struct BootSettings {
    pub base: Settings,
    pub profile_digest: String,
}
impl BootSettings {
    pub fn validate(&self) -> Result<(), String> {
        self.base.validate()?;
        if self.profile_digest != PROFILE_DIGEST {
            return Err("systemd v3 compiled descriptor digest differs".into());
        }
        if self.base.max_age_ms != RELIANCE_MS || self.base.page_bytes > 16 * 1024 * 1024 {
            return Err(
                "boot-unit consumer requires exclusive 60000ms reliance and bounded pages".into(),
            );
        }
        Ok(())
    }
    pub fn basis(&self) -> Basis {
        let kind = match self.base.claim {
            Claim::NotActive => NOT_ACTIVE_BASIS,
            Claim::Active => ACTIVE_BASIS,
        };
        Basis {
            schema: TYPED_BASIS_SCHEMA.into(),
            basis_type: kind.into(),
            basis_identity: hash_domain(
                kind,
                &jcs(&json!({"instance_id": self.base.instance_id,
                "machine_id": self.base.machine_id, "unit": self.base.unit,
                "profile": {"id":"nq.systemd_unit","version":3,"digest":self.profile_digest}})),
            ),
        }
    }
}

pub fn valid_boot_id(value: &str) -> bool {
    crate::is_uuid(value) && value != "00000000-0000-0000-0000-000000000000"
}
pub fn current_boot() -> Result<String, String> {
    let raw = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|_| "local current boot identity unavailable")?;
    let value = raw.strip_suffix('\n').unwrap_or(&raw);
    if !valid_boot_id(value) {
        return Err("local current boot identity malformed".into());
    }
    Ok(value.to_owned())
}
fn timestamp(value: Option<&str>) -> Option<u64> {
    OffsetDateTime::parse(value?, &Rfc3339)
        .ok()
        .and_then(|x| u64::try_from(x.unix_timestamp_nanos() / 1_000_000).ok())
}
fn text<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer).and_then(Value::as_str)
}

/// Pure consumer law. Inputs are exact frozen NQ evaluation/export and two
/// independent local-boot reads, not a UI clock or replayed support assertion.
pub fn judge(
    settings: &BootSettings,
    window: &Window,
    exported: Option<&Value>,
    boot_before: &str,
    boot_after: &str,
    now_ms: u64,
) -> Judgement {
    let witness = json!({"schema":"monitor.nq-boot-unit-witness/v1", "through_sequence":window.through_sequence,
        "evaluation_sequence":window.newest.as_ref().map(|x|x.sequence),
        "evaluation":window.newest.as_ref().map(|x|&x.envelope), "observation_export":exported,
        "current_boot_before":boot_before,"current_boot_after":boot_after,"resolved_at_unix_ms":now_ms,
        "profile_digest":settings.profile_digest,"reliance_ms":RELIANCE_MS});
    let reject = |status, reason: &str| Judgement {
        status,
        witness: witness.clone(),
        fresh_until_unix_ms: now_ms.saturating_add(1),
        note: reason.into(),
    };
    if !valid_boot_id(boot_before) || !valid_boot_id(boot_after) || boot_before != boot_after {
        return reject(
            Status::Refused,
            "current_boot_unavailable_malformed_or_changed",
        );
    }
    let Some(newest) = &window.newest else {
        return reject(Status::Absent, "no_instance_evaluation");
    };
    let eval = &newest.envelope;
    let expected_subject = format!(
        "systemd-unit:{}/{}",
        settings.base.machine_id, settings.base.unit
    );
    let expected_scope = json!({"kind":"systemd_unit","value":{"schema":"nq.systemd_unit_scope.v3",
        "machine_id":settings.base.machine_id,"unit_name":settings.base.unit}});
    let expected_vantage = json!({"kind":"local","value":{}});
    if text(eval, "/schema") != Some("nq.evaluation_envelope.v2")
        || text(eval, "/profile/profile/id") != Some("nq.systemd_unit")
        || eval
            .pointer("/profile/profile/version")
            .and_then(Value::as_u64)
            != Some(3)
        || text(eval, "/profile/profile_digest") != Some(settings.profile_digest.as_str())
        || text(eval, "/result/condition") != Some("systemd_unit_not_active")
    {
        return reject(Status::Refused, "evaluation_profile_or_condition_mismatch");
    }
    if text(eval, "/context/instance_id") != Some(settings.base.instance_id.as_str())
        || text(eval, "/context/subject") != Some(expected_subject.as_str())
        || eval.pointer("/context/scope") != Some(&expected_scope)
        || eval.pointer("/context/vantage") != Some(&expected_vantage)
    {
        return reject(Status::Refused, "evaluation_subject_scope_vantage_mismatch");
    }
    let Some(evaluated_ms) = timestamp(text(eval, "/evaluated_at")) else {
        return reject(Status::Refused, "evaluation_time_invalid");
    };
    if evaluated_ms > now_ms {
        return reject(Status::Refused, "evaluation_time_future");
    }
    let state = text(eval, "/result/state").unwrap_or_default();
    if !matches!(state, "present" | "explicitly_absent") {
        return reject(Status::Unsupported, "detector_indeterminate_or_refused");
    }
    let Some(evidence) = eval
        .pointer("/result/evidence")
        .and_then(Value::as_array)
        .filter(|x| x.len() == 1)
        .and_then(|x| x.first())
    else {
        return reject(Status::Refused, "exact_observation_reference_missing");
    };
    let Some(reference) = evidence.as_object() else {
        return reject(Status::Refused, "observation_reference_malformed");
    };
    if reference.len() != 5
        || ![
            "report_id",
            "report_sequence",
            "report_digest",
            "observation_ordinal",
            "observed_at",
        ]
        .iter()
        .all(|x| reference.contains_key(*x))
        || reference
            .get("report_id")
            .and_then(Value::as_str)
            .is_none_or(|x| x.is_empty() || x.len() > 256)
        || reference
            .get("report_digest")
            .and_then(Value::as_str)
            .is_none_or(|x| !crate::is_digest(x))
        || reference
            .get("report_sequence")
            .and_then(Value::as_u64)
            .is_none_or(|x| x == 0)
        || reference
            .get("observation_ordinal")
            .and_then(Value::as_u64)
            .is_none_or(|x| x > u64::from(u32::MAX))
    {
        return reject(Status::Refused, "observation_reference_malformed");
    }
    let Some(export) = exported else {
        return reject(Status::Refused, "exact_observation_export_missing");
    };
    let expected_profile =
        json!({"id":"nq.systemd_unit","version":"3","digest":settings.profile_digest});
    if text(export, "/schema") != Some("nq.admitted-observation-export/v1")
        || text(export, "/standing") != Some("historical_custody_only")
        || export.get("evidence") != Some(evidence)
        || text(export, "/instance_id") != Some(settings.base.instance_id.as_str())
        || export.get("profile") != Some(&expected_profile)
        || text(export, "/binding/subject") != Some(expected_subject.as_str())
        || export.pointer("/binding/scope") != Some(&expected_scope)
        || export.pointer("/binding/vantage") != Some(&expected_vantage)
        || text(export, "/report_status") != Some("complete")
        || text(export, "/observation/kind") != Some("systemd_unit_state_snapshot")
        || text(export, "/observation/subject") != Some(expected_subject.as_str())
        || export.pointer("/observation/ordinal") != evidence.get("observation_ordinal")
        || !reference_time_matches(
            &export["observation"]["observed_at"],
            &evidence["observed_at"],
            &export["reference_time_basis"],
        )
    {
        return reject(
            Status::Refused,
            "observation_reference_profile_or_binding_mismatch",
        );
    }
    let Some(observed_ms) = timestamp(text(export, "/observation/observed_at")) else {
        return reject(Status::Refused, "source_observation_time_invalid");
    };
    if observed_ms > now_ms || observed_ms > evaluated_ms {
        return reject(Status::Refused, "source_observation_time_future");
    }
    let acquired_boot = text(export, "/observation/payload/boot_id").unwrap_or_default();
    if !valid_boot_id(acquired_boot) {
        return reject(Status::Refused, "acquired_boot_malformed");
    }
    if text(export, "/observation/payload/machine_id") != Some(settings.base.machine_id.as_str())
        || text(export, "/observation/payload/unit_name") != Some(settings.base.unit.as_str())
        || export.pointer("/observation/payload/evidence_basis/scope") != Some(&expected_scope)
        || export.pointer("/observation/payload/evidence_basis/vantage") != Some(&expected_vantage)
    {
        return reject(Status::Refused, "native_payload_subject_binding_mismatch");
    }
    if acquired_boot != boot_before {
        return reject(Status::Stale, "source_observation_old_boot");
    }
    let fresh_until = observed_ms.min(evaluated_ms).saturating_add(RELIANCE_MS);
    if now_ms >= fresh_until {
        return Judgement {
            status: Status::Stale,
            witness,
            fresh_until_unix_ms: fresh_until,
            note: "source_or_evaluation_expired".into(),
        };
    }
    if ["load_state", "active_state", "sub_state"]
        .iter()
        .any(|field| {
            text(export, &format!("/observation/payload/{field}")).is_none_or(|x| {
                x.is_empty() || x.len() > 128 || x.bytes().any(|b| b.is_ascii_control())
            })
        })
    {
        return reject(Status::Refused, "native_payload_state_missing_or_malformed");
    }
    let active = text(export, "/observation/payload/load_state") == Some("loaded")
        && text(export, "/observation/payload/active_state") == Some("active");
    if (state == "explicitly_absent") != active {
        return reject(Status::Refused, "detector_payload_state_mismatch");
    }
    let holds = match settings.base.claim {
        Claim::NotActive => !active,
        Claim::Active => active,
    };
    Judgement {
        status: if holds {
            Status::Current
        } else {
            Status::Contradictory
        },
        witness,
        fresh_until_unix_ms: fresh_until,
        note: if holds {
            "current_boot_claim_supported"
        } else {
            "current_boot_claim_contradicted"
        }
        .into(),
    }
}

pub fn resolution(settings: &BootSettings, request: &Request, judgement: &Judgement) -> Resolution {
    let basis = settings.basis();
    Resolution {
        schema: RESOLUTION_SCHEMA,
        key: request.key.clone(),
        observation: request.observation.clone(),
        currentness: hash_domain(WITNESS_DOMAIN, &jcs(&judgement.witness)),
        normalized_preconditions: basis.binding_digest(),
        basis,
        resolver_id: settings.base.resolver_id.clone(),
        subject: request.subject.clone(),
        status: judgement.status,
        resolved_at_unix_ms: request.now_unix_ms,
        fresh_until_unix_ms: judgement.fresh_until_unix_ms,
    }
}

fn read_export(settings: &BootSettings, window: &Window) -> Result<Option<Value>, String> {
    let Some(evidence) = window
        .newest
        .as_ref()
        .and_then(|x| x.envelope.pointer("/result/evidence"))
        .and_then(Value::as_array)
        .filter(|x| x.len() == 1)
        .and_then(|x| x.first())
    else {
        return Ok(None);
    };
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "clock unavailable")?
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "monitor-observation-reference-{}-{nonce}.json",
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| e.to_string())?;
    let identity = file.metadata().map_err(|e| e.to_string())?;
    let result = (|| {
        file.write_all(&jcs(evidence)).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        let raw = run_bounded(
            &settings.base.nq_program,
            &[
                "--config".into(),
                settings.base.nq_config.clone(),
                "--json".into(),
                "observations".into(),
                "export".into(),
                "--reference".into(),
                path.to_string_lossy().into_owned(),
            ],
            settings.base.timeout,
            1024 * 1024,
        )?;
        serde_json::from_slice(&raw)
            .map(Some)
            .map_err(|e| format!("observation export is not JSON: {e}"))
    })();
    drop(file);
    let current = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
    if !current.is_file()
        || current.ino() != identity.ino()
        || current.dev() != identity.dev()
        || current.nlink() != 1
    {
        return Err("exact temporary observation reference custody changed; retained".into());
    }
    fs::remove_file(path).map_err(|e| e.to_string())?;
    result
}

/// Match the declared native time or the existing durable evaluation projection.
pub fn reference_time_matches(source: &Value, reference: &Value, basis: &Value) -> bool {
    let parse = |value: &Value| {
        value
            .as_str()
            .and_then(|s| OffsetDateTime::parse(s, &Rfc3339).ok())
            .map(|t| t.unix_timestamp_nanos())
    };
    let (Some(source), Some(reference)) = (parse(source), parse(reference)) else {
        return false;
    };
    match basis.as_str() {
        Some("native_observation_time") => source == reference,
        Some("evaluation_millisecond_projection") => {
            source != reference && (source / 1_000_000) * 1_000_000 == reference
        }
        _ => false,
    }
}

/// Normal owner read; NQ queries cannot collect, evaluate or change enrollment.
pub fn read(settings: &BootSettings, requested_at_unix_ms: u64) -> Result<Value, String> {
    settings.validate()?;
    let before = current_boot()?;
    let window = read_window(&settings.base)?;
    let export = read_export(settings, &window)?;
    let after = current_boot()?;
    // Acquisition custody queries consume time. Reliance is judged at the
    // completed local read, never at the earlier caller request cut.
    let now_ms = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "clock before epoch")?
            .as_millis(),
    )
    .map_err(|_| "clock out of range")?;
    if requested_at_unix_ms > now_ms {
        return Err("caller request time is in the local future".into());
    }
    let judgement = judge(settings, &window, export.as_ref(), &before, &after, now_ms);
    let mut other = settings.clone();
    other.base.claim = match settings.base.claim {
        Claim::Active => Claim::NotActive,
        Claim::NotActive => Claim::Active,
    };
    let other_judgement = judge(&other, &window, export.as_ref(), &before, &after, now_ms);
    Ok(
        json!({"schema":READ_SCHEMA,"owner":"Monitor","subject":format!("systemd-unit:{}/{}",settings.base.machine_id,settings.base.unit),
        "instance_id":settings.base.instance_id,"current_boot_id":after,"boot_before":before,"read_at_unix_ms":now_ms,"requested_at_unix_ms":requested_at_unix_ms,
        "through_sequence":window.through_sequence,"evaluation":window.newest.map(|x|x.envelope),"observation_export":export,
        "claim":match settings.base.claim {Claim::Active=>"active",Claim::NotActive=>"not-active"},
        "basis":settings.basis(),"judgment":{"status":judgement.status,"reason":judgement.note,"fresh_until_unix_ms":judgement.fresh_until_unix_ms},
        "opposite_basis":other.basis(),"opposite_judgment":{"status":other_judgement.status,"reason":other_judgement.note,"fresh_until_unix_ms":other_judgement.fresh_until_unix_ms},
        "currentness":hash_domain(WITNESS_DOMAIN,&jcs(&judgement.witness)),"witness":judgement.witness,
        "nonclaims":["Required unit state only, not HTTP or application health","Present reliance grants no acquisition, restart, effect or settlement authority"]}),
    )
}
