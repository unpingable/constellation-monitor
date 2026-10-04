//! Condition identity, derived exactly as NQ's v2 contract derives its dedup key:
//! `constellation:{site}:{component}:{rule}[:{target_class}]`.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ConditionKey {
    pub site: String,
    pub component: String,
    pub rule: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_class: Option<String>,
}

impl ConditionKey {
    /// Build and validate a key with NQ's submission rules.
    pub fn new(
        site: &str,
        component: &str,
        rule: &str,
        target_class: Option<&str>,
    ) -> Result<Self, String> {
        validate_token("site", site, 64)?;
        validate_token("component", component, 64)?;
        validate_token("rule", rule, 64)?;
        if let Some(target_class) = target_class {
            validate_token("target_class", target_class, 48)?;
        }
        Ok(Self {
            site: site.to_owned(),
            component: component.to_owned(),
            rule: rule.to_owned(),
            target_class: target_class.map(str::to_owned),
        })
    }

    #[must_use]
    pub fn id(&self) -> String {
        let mut key = format!(
            "constellation:{}:{}:{}",
            self.site, self.component, self.rule
        );
        if let Some(target_class) = &self.target_class {
            key.push(':');
            key.push_str(target_class);
        }
        key
    }

    /// `{site}-{rule}[-{target_class}]`, the prefix of event identities.
    #[must_use]
    pub fn event_prefix(&self) -> String {
        match &self.target_class {
            Some(target_class) => format!("{}-{}-{}", self.site, self.rule, target_class),
            None => format!("{}-{}", self.site, self.rule),
        }
    }
}

/// Name the per-event identity a condition value appears to carry, if any.
/// This mirrors NQ 0.2.1 `per_event_identity` so a value NQ would refuse is
/// refused here first.
#[must_use]
pub fn per_event_identity(value: &str) -> Option<&'static str> {
    let lower = value.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    if lower.contains("sha256") {
        return Some("a digest");
    }
    let uuid = |window: &[u8]| {
        window.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    };
    if bytes.windows(36).any(uuid) {
        return Some("a UUID");
    }
    let date = |window: &[u8]| {
        window.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 4 | 7) {
                *byte == b'-'
            } else {
                byte.is_ascii_digit()
            }
        })
    };
    if bytes.windows(10).any(date) {
        return Some("a date");
    }
    let mut hex_run = 0usize;
    let mut digit_run = 0usize;
    for byte in bytes {
        hex_run = if byte.is_ascii_hexdigit() {
            hex_run + 1
        } else {
            0
        };
        digit_run = if byte.is_ascii_digit() {
            digit_run + 1
        } else {
            0
        };
        if hex_run >= 32 {
            return Some("a hexadecimal identifier");
        }
        if digit_run >= 8 {
            return Some("a numeric timestamp or identifier");
        }
    }
    if bytes.iter().all(u8::is_ascii_digit) {
        return Some("a numeric identifier");
    }
    None
}

/// A bounded condition token: 1..=maximum of `[a-z0-9._-]`, starting with an
/// alphanumeric, and not shaped like a per-event identity.
pub fn validate_token(label: &str, value: &str, maximum: usize) -> Result<(), String> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > maximum
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(format!(
            "{label} {value:?} must be 1..={maximum} characters of [a-z0-9._-] starting with a letter or digit"
        ));
    }
    if let Some(kind) = per_event_identity(value) {
        return Err(format!(
            "{label} {value:?} looks like {kind}; a condition names a stable class, not an event"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_matches_nq_dedup_key() {
        let key = ConditionKey::new(
            "qualification-lab",
            "nq",
            "nq-no-fresh-acquisition",
            Some("demo"),
        )
        .unwrap();
        assert_eq!(
            key.id(),
            "constellation:qualification-lab:nq:nq-no-fresh-acquisition:demo"
        );
        let key = ConditionKey::new(
            "qualification-lab",
            "host_posture",
            "host-posture-unknown",
            None,
        )
        .unwrap();
        assert_eq!(
            key.id(),
            "constellation:qualification-lab:host_posture:host-posture-unknown"
        );
    }

    #[test]
    fn rejects_event_shaped_target_classes() {
        for bad in [
            "sha256-abc",
            "0123456789abcdef0123456789abcdef",
            "123e4567-e89b-12d3-a456-426614174000",
            "run-2026-10-02",
            "t12345678",
            "42",
            "Root",
            "getty@tty1.service",
            "",
            "-root",
            &"a".repeat(49),
        ] {
            assert!(
                ConditionKey::new("site", "service", "service-down", Some(bad)).is_err(),
                "{bad:?} must be refused"
            );
        }
        for good in ["nqd.service", "root", "host-1", "run-a7", "n42"] {
            ConditionKey::new("site", "service", "service-down", Some(good)).unwrap();
        }
    }
}
