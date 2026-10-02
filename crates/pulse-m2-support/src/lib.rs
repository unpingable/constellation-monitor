#![forbid(unsafe_code)]
//! Two local M2 proposition families; NQ owns acquisition/diagnostic semantics,
//! Pulse owns the exact support rule, boot-bound custody and exclusive expiry.
use pulse_nq_load_support::{
    PresentEvidenceQueryV1, QualifiedStandingV1, QualifiedSupportV1, SupportExpiryV1,
    SupportInstantV1,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
};

pub const CONFIG: &str = "pulse.m2_support_config.v1";
pub const RECEIPT: &str = "pulse.m2_support_receipt.v1";
pub const WINDOW_MS: u64 = 60_000;
const LIMIT: u64 = 2 * 1024 * 1024;
const UNIT: &str = "constellation-beta-http-fixture.service";
const BODY: &str = "sha256:6489d6d7a33c5d40e18fc61eeb6c34c341279ee61816394dde5189aa4ad8fae5";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema: String,
    pub authority_id: String,
    pub generation: String,
    pub local_machine_id: String,
    pub boot_id: String,
    pub family: String,
    pub nq_program: PathBuf,
    pub nq_program_sha256: String,
    pub nq_config: PathBuf,
    pub nq_config_sha256: String,
    pub watcher_instance: String,
    pub baseline_artifact_id: String,
    pub baseline_bytes_sha256: String,
    pub diagnostic_inputs_id: String,
    pub observation_id: String,
    pub custody_directory: PathBuf,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema: String,
    pub receipt_id: String,
    pub config_id: String,
    pub acquisition_id: String,
    pub clock_id: String,
    pub observed_at_tick_ms: u64,
    pub completed_at_tick_ms: u64,
    pub expiry_tick_ms: u64,
    /// NQ testimony retained verbatim; never used as the expiry clock.
    pub nq_observed_at: String,
    pub artifact_bytes_sha256: String,
    pub artifact: Value,
    pub admission: Value,
}
fn sha(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn canonical<T: Serialize>(v: &T) -> Result<Vec<u8>, String> {
    serde_jcs::to_vec(v).map_err(|e| e.to_string())
}
fn id<T: Serialize>(v: &T, field: &str) -> Result<String, String> {
    let mut v = serde_json::to_value(v).map_err(|e| e.to_string())?;
    v.as_object_mut()
        .ok_or("identity preimage is not an object")?
        .remove(field);
    Ok(sha(&canonical(&v)?))
}
fn text<'a>(v: &'a Value, path: &str) -> Result<&'a str, String> {
    v.pointer(path)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing {path}"))
}
fn digest(s: &str) -> Result<(), String> {
    let h = s.strip_prefix("sha256:").ok_or("digest prefix")?;
    if h.len() != 64
        || !h
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid digest".into());
    }
    Ok(())
}
fn token(s: &str) -> Result<(), String> {
    if s.is_empty() || s.chars().any(char::is_whitespace) {
        Err("empty/invalid token".into())
    } else {
        Ok(())
    }
}
fn controlled(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("custody path must be absolute".into());
    }
    for parent in path.ancestors() {
        let m = fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
        if m.file_type().is_symlink() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err(format!("path is not root-controlled: {}", parent.display()));
        }
    }
    Ok(())
}
fn read(path: &Path) -> Result<Vec<u8>, String> {
    controlled(path)?;
    let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !m.is_file() || m.len() > LIMIT {
        return Err("not a bounded regular custody file".into());
    }
    let mut b = Vec::new();
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(0o400000)
        .open(path)
        .map_err(|e| e.to_string())?
        .take(LIMIT + 1)
        .read_to_end(&mut b)
        .map_err(|e| e.to_string())?;
    if b.len() as u64 > LIMIT {
        return Err("custody byte limit".into());
    }
    Ok(b)
}
fn pin_program(c: &Config) -> Result<(), String> {
    controlled(&c.nq_program)?;
    let b = fs::read(&c.nq_program).map_err(|e| e.to_string())?;
    if sha(&b) != c.nq_program_sha256 {
        return Err("NQ executable substitution".into());
    }
    Ok(())
}
pub fn load(path: &Path) -> Result<Config, String> {
    let c: Config = serde_json::from_slice(&read(path)?).map_err(|e| e.to_string())?;
    validate_config(&c)?;
    Ok(c)
}
fn family(c: &Config) -> Result<&str, String> {
    match c.family.as_str() {
        "systemd_unit" | "http_endpoint" => Ok(&c.family),
        _ => Err("only the two fixed M2 families exist".into()),
    }
}
fn validate_config(c: &Config) -> Result<(), String> {
    if c.schema != CONFIG {
        return Err("unknown M2 enrollment".into());
    }
    for s in [
        &c.authority_id,
        &c.generation,
        &c.watcher_instance,
        &c.boot_id,
        &c.local_machine_id,
    ] {
        token(s)?
    }
    family(c)?;
    for s in [
        &c.nq_program_sha256,
        &c.nq_config_sha256,
        &c.baseline_artifact_id,
        &c.baseline_bytes_sha256,
        &c.diagnostic_inputs_id,
        &c.observation_id,
    ] {
        digest(s)?
    }
    let os = fs::read_to_string("/etc/os-release").map_err(|e| e.to_string())?;
    if !os.lines().any(|l| l == "ID=ubuntu" || l == "ID=\"ubuntu\"")
        || !os
            .lines()
            .any(|l| l == "VERSION_ID=\"22.04\"" || l == "VERSION_ID=22.04")
    {
        return Err("M2 support is restricted to Ubuntu22.04".into());
    }
    if fs::read_to_string("/etc/machine-id")
        .map_err(|e| e.to_string())?
        .trim()
        != c.local_machine_id
        || fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|e| e.to_string())?
            .trim()
            != c.boot_id
    {
        return Err("VM or boot generation mismatch".into());
    }
    pin_program(c)?;
    let bytes = read(&c.nq_config)?;
    if sha(&bytes) != c.nq_config_sha256 {
        return Err("NQ configuration substitution".into());
    }
    let cfg: toml::Value = toml::from_str(std::str::from_utf8(&bytes).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let cfg = serde_json::to_value(cfg).map_err(|e| e.to_string())?;
    let watcher = cfg["watchers"]
        .as_array()
        .and_then(|a| a.iter().find(|w| w["instance_id"] == c.watcher_instance))
        .ok_or("enrolled watcher missing")?;
    validate_watcher(c, watcher)?;
    controlled(&c.custody_directory)?;
    Ok(())
}
fn validate_watcher(c: &Config, w: &Value) -> Result<(), String> {
    let f = family(c)?;
    let p = &w["threshold_policy"]["value"];
    let subject = &p["service_subject"];
    if w["profile"]["id"] != format!("nq.{f}")
        || w["profile"]["version"] != 1
        || p["schema"] != format!("nq.operator_beta.{f}_threshold_policy.v1")
        || subject["schema"] != "constellation.operator_beta.service_subject.v1"
        || subject["campaign_id"] != "constellation-operator-beta-2026"
        || subject["fixture_run_id"] != c.generation
        || p["fixture_run_id"] != c.generation
        || subject["unit_name"] != UNIT
    {
        return Err("not the enrolled exact M2 proposition".into());
    }
    let s = &w["scope"]["value"];
    if f == "systemd_unit" {
        if subject["target_machine_identity"] != c.local_machine_id
            || s["target_machine_identity"] != c.local_machine_id
            || s["unit_name"] != UNIT
            || s["unit_file_sha256"] != subject["unit_file_sha256"]
            || s["properties"]
                != serde_json::json!(["LoadState", "ActiveState", "SubState", "UnitFileState"])
            || p["expected_load_state"] != "loaded"
            || p["expected_active_state"] != "active"
            || p["expected_sub_state"] != "running"
            || p["expected_unit_file_state"] != "disabled"
        {
            return Err("M2 unit/property binding mismatch".into());
        }
    } else {
        let endpoint = text(s, "/endpoint")?;
        let ip = endpoint
            .strip_prefix("http://")
            .and_then(|s| s.strip_suffix(":18080/healthz"))
            .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
            .ok_or("M2 endpoint must be numeric IPv4 port18080 /healthz")?;
        if !(ip.is_private() || ip.is_loopback())
            || s["controller_vantage_identity"] != format!("machine:{}", c.local_machine_id)
            || s["method"] != "GET"
            || s["redirect_policy"] != "refuse"
            || s["max_response_bytes"] != 1024
            || p["expected_status"] != 200
            || p["expected_body_sha256"] != BODY
        {
            return Err("M2 HTTP proposition/vantage mismatch".into());
        }
    }
    Ok(())
}
/// Fixed local boot clock, matching the repository's existing receiver model.
fn clock(c: &Config) -> Result<(String, u64), String> {
    if fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|e| e.to_string())?
        .trim()
        != c.boot_id
    {
        return Err("boot generation changed".into());
    }
    let u = fs::read_to_string("/proc/uptime").map_err(|e| e.to_string())?;
    let n = u.split_whitespace().next().ok_or("missing boot clock")?;
    let (s, f) = n.split_once('.').ok_or("invalid boot clock")?;
    let millis = s
        .parse::<u64>()
        .map_err(|e| e.to_string())?
        .checked_mul(1000)
        .and_then(|x| {
            f.get(..2)
                .and_then(|f| f.parse::<u64>().ok())
                .and_then(|f| x.checked_add(f * 10))
        })
        .ok_or("boot clock overflow")?;
    Ok((
        format!("pulse-m2-boottime:{}", sha(c.boot_id.as_bytes())),
        millis,
    ))
}
fn nq(c: &Config, args: &[&str]) -> Result<Vec<u8>, String> {
    pin_program(c)?;
    let out = Command::new(&c.nq_program)
        .arg("--config")
        .arg(&c.nq_config)
        .arg("--json")
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "pinned NQ refused: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    if out.stdout.len() as u64 > LIMIT {
        return Err("NQ output limit".into());
    }
    Ok(out.stdout)
}
fn reopen(c: &Config, artifact_id: &str) -> Result<(Value, Value, Vec<u8>), String> {
    digest(artifact_id)?;
    let bytes = nq(c, &["diagnostics", "export", artifact_id])?;
    let a: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if text(&a, "/artifact_id")? != artifact_id || canonical(&a)? != bytes {
        return Err("NQ artifact identity/canonical bytes mismatch".into());
    }
    let admission: Value =
        serde_json::from_slice(&nq(c, &["diagnostics", "qualify", artifact_id])?)
            .map_err(|e| e.to_string())?;
    validate_artifact(c, &a)?;
    Ok((a, admission, bytes))
}
fn validate_artifact(c: &Config, a: &Value) -> Result<(), String> {
    let f = family(c)?;
    if a["schema"] != "nq.diagnostic_execution.v2"
        || a["profile"]["id"] != format!("nq.{f}")
        || a["profile"]["version"] != "1"
        || a["question"]["id"] != format!("nq.{f}.postcondition")
        || a["question"]["version"] != "1"
    {
        return Err("unsupported exact M2 NQ contract".into());
    }
    Ok(())
}
fn binding(a: &Value) -> Value {
    let mut v = serde_json::Map::new();
    for k in [
        "subject",
        "question",
        "profile",
        "profile_semantic_id",
        "vantage",
        "state_model",
        "evaluator",
        "threshold_policy",
        "projection",
        "producer",
    ] {
        v.insert(k.into(), a[k].clone());
    }
    Value::Object(v)
}
fn state(a: &Value) -> Option<&str> {
    let o = &a["outcome"];
    if o["derivation"] != "completed"
        || o["coverage"] != "complete"
        || o["coherence"] != "jointly_established"
    {
        return None;
    }
    match o["condition"].as_str() {
        Some(s @ ("present" | "explicitly_absent")) => Some(s),
        _ => None,
    }
}
fn validate_receipt(c: &Config, r: &Receipt, baseline: &Value) -> Result<(), String> {
    if r.schema != RECEIPT
        || r.config_id != sha(&canonical(c)?)
        || r.receipt_id != id(r, "receipt_id")?
        || r.completed_at_tick_ms < r.observed_at_tick_ms
        || r.completed_at_tick_ms - r.observed_at_tick_ms > 30_000
        || r.expiry_tick_ms
            != r.observed_at_tick_ms
                .checked_add(WINDOW_MS)
                .ok_or("expiry overflow")?
        || r.artifact_bytes_sha256 != sha(&canonical(&r.artifact)?)
        || binding(&r.artifact) != binding(baseline)
        || r.artifact["artifact_id"] == baseline["artifact_id"]
        || r.artifact["run_id"] == baseline["run_id"]
        || r.nq_observed_at != text(&r.artifact, "/started_at")?
    {
        return Err("support acquisition/custody substitution".into());
    }
    validate_artifact(c, &r.artifact)
}
/// Acquires one new, internally named NQ occurrence. Claim is permanent even
/// on interruption; retrying this enrollment never restamps historical bytes.
pub fn acquire(c: &Config) -> Result<Receipt, String> {
    validate_config(c)?;
    let (base, _, bytes) = reopen(c, &c.baseline_artifact_id)?;
    if sha(&bytes) != c.baseline_bytes_sha256 {
        return Err("baseline substitution".into());
    }
    let claim = c.custody_directory.join("acquisition.claim");
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&claim)
        .map_err(|e| format!("M2 acquisition already claimed or unavailable: {e}"))?
        .sync_all()
        .map_err(|e| e.to_string())?;
    let mut random = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|e| e.to_string())?;
    let acquisition = format!("pulse-m2-{}", sha(&random).trim_start_matches("sha256:"));
    let (clock_id, start) = clock(c)?;
    let bytes = nq(
        c,
        &[
            "diagnostics",
            "acquire-next-local",
            &c.watcher_instance,
            "--acquisition-id",
            &acquisition,
        ],
    )?;
    let a: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let (artifact, admission, reopened) = reopen(c, text(&a, "/artifact_id")?)?;
    if bytes != reopened {
        return Err("NQ live acquisition/reopen mismatch".into());
    }
    let (end_clock, end) = clock(c)?;
    if clock_id != end_clock {
        return Err("clock generation changed during acquisition".into());
    }
    let mut receipt = Receipt {
        schema: RECEIPT.into(),
        receipt_id: String::new(),
        config_id: sha(&canonical(c)?),
        acquisition_id: acquisition,
        clock_id,
        observed_at_tick_ms: start,
        completed_at_tick_ms: end,
        expiry_tick_ms: start.checked_add(WINDOW_MS).ok_or("expiry overflow")?,
        nq_observed_at: text(&artifact, "/started_at")?.into(),
        artifact_bytes_sha256: sha(&bytes),
        artifact,
        admission,
    };
    receipt.receipt_id = id(&receipt, "receipt_id")?;
    validate_receipt(c, &receipt, &base)?;
    let target = c.custody_directory.join("receipt.json");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(target)
        .map_err(|e| e.to_string())?;
    file.write_all(&canonical(&receipt)?)
        .map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    fs::File::open(&c.custody_directory)
        .map_err(|e| e.to_string())?
        .sync_all()
        .map_err(|e| e.to_string())?;
    Ok(receipt)
}
fn validate_query(c: &Config, q: &PresentEvidenceQueryV1, base: &Value) -> Result<(), String> {
    if q.schema != "nightshift.present_evidence_query.v1"
        || q.query_id != id(q, "query_id")?
        || q.subject_id != text(base, "/subject/id")?
        || q.scope_id != text(base, "/subject/scope/digest")?
        || q.artifact_ids != [c.baseline_artifact_id.clone()]
        || q.diagnostic_inputs_id != c.diagnostic_inputs_id
        || q.observation_id != c.observation_id
    {
        return Err("M2 support query/proposition binding mismatch".into());
    }
    for s in [&q.observation_cycle_id, &q.request_nonce] {
        token(s)?
    }
    Ok(())
}
fn result(
    c: &Config,
    q: &PresentEvidenceQueryV1,
    base: &Value,
    r: Option<&Receipt>,
    clock_id: &str,
    now: u64,
) -> Result<QualifiedSupportV1, String> {
    validate_query(c, q, base)?;
    let (standing, expiry, evidence_refs, contradiction_refs) = match r {
        None => (QualifiedStandingV1::Unknown, None, vec![], vec![]),
        Some(r) => {
            validate_receipt(c, r, base)?;
            if r.clock_id != clock_id || now < r.completed_at_tick_ms {
                return Err("support clock or transition history mismatch".into());
            }
            let refs = vec![
                r.receipt_id.clone(),
                text(&r.artifact, "/artifact_id")?.into(),
            ];
            if now >= r.expiry_tick_ms {
                (
                    QualifiedStandingV1::Expired,
                    Some(SupportExpiryV1 {
                        clock_id: clock_id.into(),
                        tick: r.expiry_tick_ms,
                    }),
                    refs,
                    vec![],
                )
            } else {
                match (state(base), state(&r.artifact)) {
                    (Some(a), Some(b)) if a == b => (
                        QualifiedStandingV1::Current,
                        Some(SupportExpiryV1 {
                            clock_id: clock_id.into(),
                            tick: r.expiry_tick_ms,
                        }),
                        refs,
                        vec![],
                    ),
                    (Some(_), Some(_)) => (QualifiedStandingV1::Contradictory, None, vec![], refs),
                    _ => (QualifiedStandingV1::Unknown, None, refs, vec![]),
                }
            }
        }
    };
    let mut evidence_refs = evidence_refs;
    evidence_refs.sort();
    let mut contradiction_refs = contradiction_refs;
    contradiction_refs.sort();
    let mut out = QualifiedSupportV1 {
        schema: "nightshift.qualified_support.v1".into(),
        support_id: String::new(),
        authority_id: c.authority_id.clone(),
        query_id: q.query_id.clone(),
        observation_cycle_id: q.observation_cycle_id.clone(),
        request_nonce: q.request_nonce.clone(),
        observation_id: q.observation_id.clone(),
        diagnostic_inputs_id: q.diagnostic_inputs_id.clone(),
        subject_id: q.subject_id.clone(),
        scope_id: q.scope_id.clone(),
        artifact_ids: q.artifact_ids.clone(),
        evaluated_at: SupportInstantV1 {
            clock_id: clock_id.into(),
            tick: now,
        },
        expiry,
        standing,
        evidence_refs,
        contradiction_refs,
    };
    out.support_id = id(&out, "support_id")?;
    Ok(out)
}
/// Read-only resolution; never invokes acquire or refreshes receipt expiry.
pub fn resolve(c: &Config, q: &PresentEvidenceQueryV1) -> Result<QualifiedSupportV1, String> {
    validate_config(c)?;
    let (base, _, bytes) = reopen(c, &c.baseline_artifact_id)?;
    if sha(&bytes) != c.baseline_bytes_sha256 {
        return Err("baseline byte substitution".into());
    }
    let path = c.custody_directory.join("receipt.json");
    let r = if path.exists() {
        Some(serde_json::from_slice::<Receipt>(&read(&path)?).map_err(|e| e.to_string())?)
    } else {
        None
    };
    if let Some(r) = &r {
        let (a, admission, b) = reopen(c, text(&r.artifact, "/artifact_id")?)?;
        if a != r.artifact || admission != r.admission || sha(&b) != r.artifact_bytes_sha256 {
            return Err("support evidence/admission changed".into());
        }
    }
    let (cid, tick) = clock(c)?;
    result(c, q, &base, r.as_ref(), &cid, tick)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn config(f: &str) -> Config {
        Config {
            schema: CONFIG.into(),
            authority_id: "pulse.m2-local/test".into(),
            generation: "m2-test".into(),
            local_machine_id: "target-vm".into(),
            boot_id: "boot-one".into(),
            family: f.into(),
            nq_program: "/usr/bin/nq".into(),
            nq_program_sha256: sha(b"nq"),
            nq_config: "/etc/m2/nq.toml".into(),
            nq_config_sha256: sha(b"config"),
            watcher_instance: f.into(),
            baseline_artifact_id: sha(b"baseline"),
            baseline_bytes_sha256: sha(b"bytes"),
            diagnostic_inputs_id: sha(b"inputs"),
            observation_id: sha(b"observation"),
            custody_directory: "/var/lib/m2/support".into(),
        }
    }
    fn artifact(c: &Config, condition: &str, run: &str) -> Value {
        json!({"schema":"nq.diagnostic_execution.v2","artifact_id":sha(run.as_bytes()),"run_id":run,"started_at":"2026-10-01T00:00:00Z","subject":{"id":sha(b"subject"),"scope":{"digest":sha(b"scope")}},"profile":{"id":format!("nq.{}",c.family),"version":"1"},"question":{"id":format!("nq.{}.postcondition",c.family),"version":"1"},"outcome":{"derivation":"completed","coverage":"complete","coherence":"jointly_established","condition":condition},"attempt_interval":{"qualification":{"state":"unqualified","code":"absolute_clock_quality_unqualified","detail":"UTC bound not established"}}})
    }
    fn fixture(f: &str) -> (Config, Value, PresentEvidenceQueryV1, Receipt) {
        let mut c = config(f);
        let b = artifact(&c, "present", "baseline");
        c.baseline_artifact_id = b["artifact_id"].as_str().unwrap().into();
        let mut q = PresentEvidenceQueryV1 {
            schema: "nightshift.present_evidence_query.v1".into(),
            query_id: String::new(),
            observation_cycle_id: "cycle".into(),
            request_nonce: "nonce".into(),
            observation_id: c.observation_id.clone(),
            diagnostic_inputs_id: c.diagnostic_inputs_id.clone(),
            subject_id: sha(b"subject"),
            scope_id: sha(b"scope"),
            artifact_ids: vec![c.baseline_artifact_id.clone()],
        };
        q.query_id = id(&q, "query_id").unwrap();
        let a = artifact(&c, "present", "new-run");
        let mut r = Receipt {
            schema: RECEIPT.into(),
            receipt_id: String::new(),
            config_id: sha(&canonical(&c).unwrap()),
            acquisition_id: "new-acquisition".into(),
            clock_id: "boot-one".into(),
            observed_at_tick_ms: 100,
            completed_at_tick_ms: 200,
            expiry_tick_ms: 100 + WINDOW_MS,
            nq_observed_at: "2026-10-01T00:00:00Z".into(),
            artifact_bytes_sha256: sha(&canonical(&a).unwrap()),
            artifact: a,
            admission: json!({"fixture":"retained admission"}),
        };
        r.receipt_id = id(&r, "receipt_id").unwrap();
        (c, b, q, r)
    }
    fn reseal(r: &mut Receipt) {
        r.artifact_bytes_sha256 = sha(&canonical(&r.artifact).unwrap());
        r.receipt_id = id(r, "receipt_id").unwrap()
    }
    #[test]
    fn both_exact_families_support_current_without_relabeling_utc() {
        for f in ["systemd_unit", "http_endpoint"] {
            let (c, b, q, r) = fixture(f);
            let out = result(&c, &q, &b, Some(&r), "boot-one", 201).unwrap();
            assert_eq!(out.standing, QualifiedStandingV1::Current);
            assert_eq!(out.expiry.as_ref().unwrap().tick, 60100);
            assert_eq!(
                r.artifact["attempt_interval"]["qualification"]["state"],
                "unqualified"
            );
            assert_eq!(out.support_id, id(&out, "support_id").unwrap());
        }
    }
    #[test]
    fn missing_is_unknown() {
        let (c, b, q, _) = fixture("systemd_unit");
        assert_eq!(
            result(&c, &q, &b, None, "boot-one", 201).unwrap().standing,
            QualifiedStandingV1::Unknown
        )
    }
    #[test]
    fn equality_is_expired_and_replay_does_not_refresh() {
        let (c, b, q, r) = fixture("systemd_unit");
        for now in [60100, 60101, 80000] {
            let out = result(&c, &q, &b, Some(&r), "boot-one", now).unwrap();
            assert_eq!(out.standing, QualifiedStandingV1::Expired);
            assert_eq!(out.expiry.as_ref().unwrap().tick, 60100);
        }
    }
    #[test]
    fn changed_condition_is_contradictory() {
        let (c, b, q, mut r) = fixture("http_endpoint");
        r.artifact["outcome"]["condition"] = json!("explicitly_absent");
        reseal(&mut r);
        let out = result(&c, &q, &b, Some(&r), "boot-one", 201).unwrap();
        assert_eq!(out.standing, QualifiedStandingV1::Contradictory);
        assert!(!out.contradiction_refs.is_empty());
    }
    #[test]
    fn incomplete_or_refused_is_indeterminate() {
        for change in [
            json!({"derivation":"refused","coverage":"missing","coherence":"not_evaluated","condition":"unresolved"}),
            json!({"derivation":"completed","coverage":"partial","coherence":"jointly_established","condition":"present"}),
        ] {
            let (c, b, q, mut r) = fixture("systemd_unit");
            r.artifact["outcome"] = change;
            reseal(&mut r);
            assert_eq!(
                result(&c, &q, &b, Some(&r), "boot-one", 201)
                    .unwrap()
                    .standing,
                QualifiedStandingV1::Unknown
            );
        }
    }
    #[test]
    fn wrong_boot_or_clock_transition_refuses() {
        let (c, b, q, r) = fixture("systemd_unit");
        assert!(result(&c, &q, &b, Some(&r), "boot-two", 201).is_err());
        assert!(result(&c, &q, &b, Some(&r), "boot-one", 199).is_err());
    }
    #[test]
    fn exact_subject_proposition_and_basis_substitution_refuse() {
        let (c, b, q, r) = fixture("systemd_unit");
        for field in [
            "subject",
            "question",
            "profile",
            "profile_semantic_id",
            "vantage",
            "threshold_policy",
            "producer",
        ] {
            let mut r = r.clone();
            r.artifact[field] = json!({"substituted":true});
            reseal(&mut r);
            assert!(
                result(&c, &q, &b, Some(&r), "boot-one", 201).is_err(),
                "{field}"
            );
        }
    }
    #[test]
    fn receipt_mutation_and_enrollment_generation_refuse() {
        let (c, b, q, mut r) = fixture("systemd_unit");
        r.expiry_tick_ms += 1;
        assert!(result(&c, &q, &b, Some(&r), "boot-one", 201).is_err());
        let mut c = c;
        c.generation = "later-generation".into();
        assert!(result(&c, &q, &b, Some(&r), "boot-one", 201).is_err());
    }
    #[test]
    fn historical_artifact_cannot_be_restamped_as_acquisition() {
        let (c, b, q, mut r) = fixture("systemd_unit");
        r.artifact = b.clone();
        reseal(&mut r);
        assert!(result(&c, &q, &b, Some(&r), "boot-one", 201).is_err())
    }
    #[test]
    fn query_substitution_refuses() {
        let (c, b, mut q, r) = fixture("systemd_unit");
        q.artifact_ids = vec![sha(b"other")];
        q.query_id = id(&q, "query_id").unwrap();
        assert!(result(&c, &q, &b, Some(&r), "boot-one", 201).is_err())
    }
    #[test]
    fn acquisition_budget_is_bounded() {
        let (c, b, q, mut r) = fixture("systemd_unit");
        r.completed_at_tick_ms = 30101;
        reseal(&mut r);
        assert!(result(&c, &q, &b, Some(&r), "boot-one", 30102).is_err())
    }
    #[test]
    fn unknown_family_refuses() {
        assert!(family(&config("other")).is_err())
    }
    #[test]
    fn shared_current_wire_vector_is_canonical_and_query_bound() {
        let v: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/m2-qualified-support-v1.json"
        ))
        .unwrap();
        let q: PresentEvidenceQueryV1 = serde_json::from_value(v["query"].clone()).unwrap();
        let a: QualifiedSupportV1 = serde_json::from_value(v["answer"].clone()).unwrap();
        assert_eq!(q.query_id, id(&q, "query_id").unwrap());
        assert_eq!(a.support_id, id(&a, "support_id").unwrap());
        assert_eq!(a.query_id, q.query_id);
        assert_eq!(a.expiry.as_ref().unwrap().clock_id, a.evaluated_at.clock_id);
        assert!(a.expiry.as_ref().unwrap().tick > a.evaluated_at.tick);
        assert_eq!(serde_json::to_value(a).unwrap(), v["answer"]);
    }
}
