//! Historical cycle-support admission for the explicitly opted-in reader.
//!
//! This checks retained identities and intrinsic support shape. It does not ask
//! a live authority, translate receiver ticks to UTC, or renew stored Current.
use std::collections::BTreeSet;
use std::path::Path;

use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::util::{read_bounded, rfc3339_seconds};

/// The existing Pulse Linux boot-clock identity, not a present-support query.
pub(crate) fn local_filesystem_clock_id() -> Result<String, String> {
    local_filesystem_clock_id_from(Path::new("/proc/sys/kernel/random/boot_id"))
}

pub(crate) fn local_filesystem_clock_id_from(path: &Path) -> Result<String, String> {
    boot_clock_id(&read_bounded(path, 4096)?)
}

fn boot_clock_id(bytes: &[u8]) -> Result<String, String> {
    let boot = std::str::from_utf8(bytes)
        .map_err(|_| "local Linux boot ID is not UTF-8".to_owned())?
        .trim();
    if boot.is_empty() || boot.chars().any(char::is_whitespace) {
        return Err("local Linux boot ID is empty or malformed".into());
    }
    Ok(format!(
        "pulse-linux-boottime:sha256:{:x}",
        Sha256::digest(boot)
    ))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Instant {
    clock_id: String,
    tick: u64,
}

/// Private read-side representation of the existing owning support schema.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Support {
    schema: String,
    support_id: String,
    authority_id: String,
    query_id: String,
    observation_cycle_id: String,
    request_nonce: String,
    observation_id: String,
    diagnostic_inputs_id: String,
    subject_id: String,
    scope_id: String,
    artifact_ids: Vec<String>,
    evaluated_at: Instant,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expiry: Option<Instant>,
    standing: Standing,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    contradiction_refs: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Standing {
    Current,
    Expired,
    Unknown,
    Unsupported,
    Contradictory,
    Blind,
}

fn token(value: &str) -> Result<(), String> {
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        return Err("cycle support contains an empty or invalid token".into());
    }
    Ok(())
}

fn digest(value: &str) -> Result<(), String> {
    let hex = value.strip_prefix("sha256:").unwrap_or_default();
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("cycle support contains an invalid digest".into());
    }
    Ok(())
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("cycle support lacks string {key}"))
}

fn object_id(value: &Value, key: &str) -> Result<String, String> {
    let mut value = value.clone();
    value
        .as_object_mut()
        .ok_or("cycle identity preimage is not an object")?
        .remove(key);
    let canonical = serde_jcs::to_vec(&value).map_err(|error| error.to_string())?;
    Ok(format!("sha256:{:x}", Sha256::digest(canonical)))
}

fn identified(value: &Value, key: &str) -> Result<(), String> {
    let id = field(value, key)?;
    digest(id)?;
    if id != object_id(value, key)? {
        return Err(format!("cycle {key} does not match retained bytes"));
    }
    Ok(())
}

fn ordered_digests(values: &[String]) -> Result<(), String> {
    for value in values {
        digest(value)?;
    }
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("cycle support references are not ordered and unique".into());
    }
    Ok(())
}

fn member<'a>(value: &'a Value, key: &str, allowed: &[&str]) -> Result<&'a str, String> {
    let value = field(value, key)?;
    if !allowed.contains(&value) {
        return Err(format!("unsupported cycle {key}"));
    }
    Ok(value)
}

impl Support {
    fn validate(&self) -> Result<(), String> {
        if self.schema != "nightshift.qualified_support.v1" {
            return Err("unsupported retained support schema".into());
        }
        for value in [
            &self.support_id,
            &self.query_id,
            &self.observation_id,
            &self.diagnostic_inputs_id,
            &self.scope_id,
        ] {
            digest(value)?;
        }
        for value in [
            &self.authority_id,
            &self.observation_cycle_id,
            &self.request_nonce,
            &self.subject_id,
            &self.evaluated_at.clock_id,
        ] {
            token(value)?;
        }
        for values in [
            &self.artifact_ids,
            &self.evidence_refs,
            &self.contradiction_refs,
        ] {
            ordered_digests(values)?;
        }
        let expiry_current = self
            .expiry
            .as_ref()
            .map(|expiry| -> Result<bool, String> {
                token(&expiry.clock_id)?;
                if expiry.clock_id != self.evaluated_at.clock_id {
                    return Err(
                        "support expiry and evaluation use different receiver clocks".into(),
                    );
                }
                Ok(expiry.tick > self.evaluated_at.tick)
            })
            .transpose()?;
        if (self.standing == Standing::Current && expiry_current != Some(true))
            || (self.standing == Standing::Expired && expiry_current != Some(false))
            || (self.standing == Standing::Contradictory && self.contradiction_refs.is_empty())
            || (self.standing == Standing::Current && !self.contradiction_refs.is_empty())
        {
            return Err("retained support violates its intrinsic expiry/contradiction law".into());
        }
        let value = serde_json::to_value(self).map_err(|error| error.to_string())?;
        identified(&value, "support_id")?;
        let query = json!({
            "schema": "nightshift.present_evidence_query.v1",
            "query_id": self.query_id,
            "observation_cycle_id": self.observation_cycle_id,
            "request_nonce": self.request_nonce,
            "observation_id": self.observation_id,
            "diagnostic_inputs_id": self.diagnostic_inputs_id,
            "subject_id": self.subject_id,
            "scope_id": self.scope_id,
            "artifact_ids": self.artifact_ids,
        });
        identified(&query, "query_id")
    }
}

pub(crate) struct HistoricalSupport {
    pub identity: Value,
    pub loss: bool,
    pub clock_id: String,
}

/// Validate exactly the selected row. Never search older rows for Current.
pub(crate) fn read_selected(
    path: &Path,
    cycle_id: &str,
    closed_at: i64,
    now: i64,
) -> Result<HistoricalSupport, String> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| error.to_string())?;
    connection
        .busy_timeout(std::time::Duration::from_secs(2))
        .map_err(|error| error.to_string())?;
    connection
        .pragma_update(None, "query_only", true)
        .map_err(|error| error.to_string())?;
    // This bounds the selected JSON allocation, not SQLite's selection cost.
    let (slot_id, version, status, state_digest, snapshot, updated_at): (String, i64, String, String, Option<String>, String) = connection.query_row(
        "SELECT slot_id, version, status, state_digest, CASE WHEN length(CAST(snapshot_json AS BLOB)) <= 16777216 THEN snapshot_json ELSE NULL END, updated_at FROM canonical_observation_cycles WHERE cycle_id=?1",
        [cycle_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
    ).map_err(|error| error.to_string())?;
    let cycle: Value =
        serde_json::from_str(&snapshot.ok_or("selected cycle snapshot exceeds read limit")?)
            .map_err(|error| error.to_string())?;
    if field(&cycle, "schema")? != "nightshift.observation_cycle.v1"
        || field(&cycle, "cycle_id")? != cycle_id
        || field(&cycle, "status")? != "closed"
        || status != "closed"
        || field(&cycle, "state_digest")? != state_digest
        || field(&cycle, "updated_at")? != updated_at
        || cycle["version"].as_i64() != Some(version)
        || version <= 0
        || rfc3339_seconds(&updated_at)? != closed_at
        || closed_at > now
    {
        return Err("selected cycle row/snapshot/time identity is inconsistent".into());
    }
    token(cycle_id)?;
    identified(&cycle, "state_digest")?;
    let slot = &cycle["slot"];
    if field(slot, "schema")? != "nightshift.recurrence_slot.v1"
        || field(slot, "slot_id")? != slot_id
    {
        return Err("selected cycle slot identity is inconsistent".into());
    }
    identified(slot, "slot_id")?;
    let observation = &cycle["observation"];
    member(
        observation,
        "schema",
        &[
            "nightshift.observation_record.v1",
            "nightshift.observation_record.v2",
            "nightshift.observation_record.v3",
            "nightshift.observation_record.v4",
            "nightshift.observation_record.v5",
            "nightshift.observation_record.v6",
        ],
    )?;
    let support: Support = serde_json::from_value(observation["support"].clone())
        .map_err(|error| error.to_string())?;
    support.validate()?;
    let posture = &observation["posture"];
    if field(posture, "schema")? != "nightshift.operational_posture.v2" {
        return Err("unsupported retained posture schema".into());
    }
    identified(posture, "posture_id")?;
    let present: Support = serde_json::from_value(posture["present_support"].clone())
        .map_err(|error| error.to_string())?;
    let inputs = &posture["input_evidence"];
    identified(inputs, "inputs_id")?;
    identified(&posture["policy"], "policy_id")?;
    let subject = &posture["policy"]["subject"];
    let mut artifact_ids = BTreeSet::new();
    for input in inputs["inputs"]
        .as_array()
        .ok_or("cycle input list is absent")?
    {
        match field(input, "status")? {
            "delivered" => {
                let id = field(&input["artifact"], "artifact_id")?;
                digest(id)?;
                artifact_ids.insert(id.to_owned());
            }
            "no_response" | "acquisition_failed" | "not_configured" => {}
            _ => return Err("unsupported cycle input status".into()),
        }
    }
    if support.observation_cycle_id != cycle_id
        || support.observation_id != field(observation, "observation_id")?
        || support.diagnostic_inputs_id != field(inputs, "inputs_id")?
        || present != support
        || support.subject_id != field(subject, "id")?
        || support.subject_id != field(slot, "subject_id")?
        || support.scope_id != field(&subject["scope"], "digest")?
        || support.scope_id != field(slot, "scope_id")?
        || support.artifact_ids != artifact_ids.into_iter().collect::<Vec<_>>()
    {
        return Err("observation/support/posture basis is not exact".into());
    }
    let complete = member(posture, "completeness", &["complete", "incomplete"])? == "complete";
    let coverage = member(posture, "coverage", &["complete", "narrowed", "absent"])? == "complete";
    let recurrence = member(posture, "recurrence_axis", &["current", "incomplete"])? == "current";
    let current = posture["current"]
        .as_bool()
        .ok_or("posture currentness is absent")?;
    if current != (support.standing == Standing::Current && complete && coverage && recurrence) {
        return Err("posture currentness does not match retained support and axes".into());
    }
    member(
        posture,
        "condition",
        &["clean", "condition_present", "unresolved"],
    )?;
    let attention = &cycle["attention"];
    if field(attention, "source_posture_id")? != field(posture, "posture_id")? {
        return Err("cycle attention does not bind the selected posture".into());
    }
    member(
        attention,
        "class",
        &["display", "attention_required", "escalation_requested"],
    )?;
    let reason = field(attention, "reason_code")?;
    token(reason)?;
    Ok(HistoricalSupport {
        loss: support.standing != Standing::Current
            || matches!(reason, "support_not_current" | "support_not_decidable"),
        clock_id: support.evaluated_at.clock_id,
        identity: json!({"cycle_id": cycle_id, "closed_at": updated_at,
            "state_digest": state_digest, "support_id": support.support_id,
            "support_standing": support.standing, "posture_current": current,
            "historical_support_only": true}),
    })
}

#[cfg(test)]
mod local_boot_tests {
    use super::*;

    #[test]
    fn local_boot_encoding_matches_shared_pulse_vectors() {
        let vector: Value = serde_json::from_str(include_str!(
            "../../../artifacts/linux-boot-clock-v1/conformance.json"
        ))
        .unwrap();
        for case in vector["accepted"].as_array().unwrap() {
            assert_eq!(
                boot_clock_id(case["raw_boot_id"].as_str().unwrap().as_bytes()).unwrap(),
                case["clock_id"].as_str().unwrap()
            );
        }
        for case in vector["rejected"].as_array().unwrap() {
            assert!(boot_clock_id(case.as_str().unwrap().as_bytes()).is_err());
        }
        assert!(boot_clock_id(&[0xff]).is_err());
    }

    #[test]
    fn local_boot_missing_malformed_and_oversized_files_refuse() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boot-id");
        assert!(local_filesystem_clock_id_from(&path).is_err());
        for bytes in [
            b"\n".to_vec(),
            b"boot epoch".to_vec(),
            vec![0xff],
            vec![b'a'; 4097],
        ] {
            std::fs::write(&path, bytes).unwrap();
            assert!(local_filesystem_clock_id_from(&path).is_err());
        }
        std::fs::write(&path, b"boot-epoch-alpha\n").unwrap();
        assert_eq!(
            local_filesystem_clock_id_from(&path).unwrap(),
            boot_clock_id(b"boot-epoch-alpha").unwrap()
        );
    }
}
