//! Fixed bounded I/O, signing-key and Linux boot-clock operations.
use ed25519_dalek::SigningKey;
use pulse_nq_load_support::ReceiverInstantV1;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, File},
    io::Read as _,
    os::unix::fs::MetadataExt as _,
    path::Path,
};
const MAX_SOURCE_BYTES: usize = 4096;
const PROC_BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";
const PROC_UPTIME: &str = "/proc/uptime";
pub(crate) trait AuthorityClock {
    fn now(&self) -> Result<ReceiverInstantV1, String>;
}

pub(crate) struct LinuxBootClock;

impl AuthorityClock for LinuxBootClock {
    fn now(&self) -> Result<ReceiverInstantV1, String> {
        let boot_id = read_fixed_source(PROC_BOOT_ID)?;
        let boot_id = boot_id.trim();
        if boot_id.is_empty() || boot_id.chars().any(char::is_whitespace) {
            return Err("Linux boot ID is empty or malformed".into());
        }
        let uptime = read_fixed_source(PROC_UPTIME)?;
        let token = uptime
            .split_ascii_whitespace()
            .next()
            .ok_or_else(|| "/proc/uptime is empty".to_owned())?;
        Ok(ReceiverInstantV1 {
            clock_id: format!("pulse-linux-boottime:sha256:{:x}", Sha256::digest(boot_id)),
            tick_ms: decimal_seconds_to_millis(token)?,
        })
    }
}

pub(crate) fn decimal_seconds_to_millis(token: &str) -> Result<u64, String> {
    let (seconds, fraction) = token.split_once('.').unwrap_or((token, ""));
    if seconds.is_empty()
        || !seconds.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("boot-clock source is not a non-negative decimal".into());
    }
    let seconds = seconds.parse::<u64>().map_err(|error| error.to_string())?;
    let mut millis = 0_u64;
    for (index, byte) in fraction.bytes().take(3).enumerate() {
        let digit = u64::from(byte - b'0');
        millis += digit * [100, 10, 1][index];
    }
    seconds
        .checked_mul(1_000)
        .and_then(|value| value.checked_add(millis))
        .ok_or_else(|| "boot-clock milliseconds overflow".to_owned())
}

pub(crate) fn read_signing_key(path: &Path) -> Result<SigningKey, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err("producer signing key must be a non-symlink regular file".into());
    }
    if metadata.mode() & 0o077 != 0 {
        return Err("producer signing key must not be accessible by group or others".into());
    }
    let text = String::from_utf8(read_regular_bounded(path, 256)?)
        .map_err(|_| "producer signing key is not UTF-8 hex".to_owned())?;
    let bytes = decode_hex_exact(text.trim(), 32)?;
    Ok(SigningKey::from_bytes(
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| "producer signing key length changed".to_owned())?,
    ))
}

pub(crate) fn read_fixed_source(path: &str) -> Result<String, String> {
    String::from_utf8(read_regular_bounded(Path::new(path), MAX_SOURCE_BYTES)?)
        .map_err(|_| format!("{path} is not UTF-8"))
}

pub(crate) fn read_regular_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "{} must be a non-symlink regular file",
            path.display()
        ));
    }
    let limit = u64::try_from(maximum)
        .map_err(|error| error.to_string())?
        .saturating_add(1);
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|error| error.to_string())?
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > maximum {
        return Err(format!("{} exceeds its byte bound", path.display()));
    }
    Ok(bytes)
}

pub(crate) fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    serde_jcs::to_vec(value).map_err(|error| error.to_string())
}

pub(crate) fn object_id<T: Serialize>(value: &T, identity_field: &str) -> Result<String, String> {
    let mut value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    value
        .as_object_mut()
        .ok_or_else(|| "identity-bearing value must be an object".to_owned())?
        .remove(identity_field);
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(canonical_bytes(&value)?)
    ))
}

pub(crate) fn require_token(name: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_whitespace) {
        return Err(format!("{name} must be a bounded non-whitespace token"));
    }
    Ok(())
}

pub(crate) fn require_digest(name: &str, value: &str) -> Result<(), String> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(format!("{name} must use sha256:<64 lowercase hex>"));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{name} must use sha256:<64 lowercase hex>"));
    }
    Ok(())
}

pub(crate) fn strictly_ordered_digests(name: &str, values: &[String]) -> Result<(), String> {
    if values.is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    let mut prior: Option<&str> = None;
    for value in values {
        require_digest(name, value)?;
        if prior.is_some_and(|item| item >= value.as_str()) {
            return Err(format!("{name} must be strictly ordered and unique"));
        }
        prior = Some(value);
    }
    Ok(())
}

pub(crate) fn require_hex(name: &str, value: &str, bytes: usize) -> Result<(), String> {
    if value.len() != bytes * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{name} must be exact lowercase hex"));
    }
    Ok(())
}

pub(crate) fn decode_hex_exact(value: &str, bytes: usize) -> Result<Vec<u8>, String> {
    require_hex("hex value", value, bytes)?;
    (0..bytes)
        .map(|index| {
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                .map_err(|error| error.to_string())
        })
        .collect()
}

pub(crate) fn encode_hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
