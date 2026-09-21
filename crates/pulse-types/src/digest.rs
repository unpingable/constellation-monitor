use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// SHA-256 digest with an explicit textual algorithm prefix.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct DigestV1(pub String);

impl DigestV1 {
    #[must_use]
    pub fn from_parts(domain: &str, parts: &[&[u8]]) -> Self {
        digest_parts(domain, parts)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<(), DigestError> {
        let Some(hex) = self.0.strip_prefix("sha256:") else {
            return Err(DigestError("digest has no sha256 prefix"));
        };
        if hex.len() != 64 {
            return Err(DigestError("digest has the wrong length"));
        }
        if !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(DigestError(
                "digest contains non-canonical hexadecimal bytes",
            ));
        }
        if hex.bytes().all(|byte| byte == b'0') {
            return Err(DigestError("all-zero digest is not a content identity"));
        }
        Ok(())
    }
}

impl fmt::Display for DigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DigestError(pub &'static str);

impl fmt::Display for DigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for DigestError {}

/// Hash a versioned, length-delimited transcript.
#[must_use]
pub fn digest_parts(domain: &str, parts: &[&[u8]]) -> DigestV1 {
    let mut hasher = Sha256::new();
    hasher.update(b"monitor-skunkworks.digest.v1\0");
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain.as_bytes());
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    let bytes = hasher.finalize();
    let mut value = String::with_capacity(7 + bytes.len() * 2);
    value.push_str("sha256:");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    DigestV1(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_is_domain_and_boundary_separated() {
        assert_ne!(digest_parts("a", &[b"bc"]), digest_parts("ab", &[b"c"]));
        assert_ne!(
            digest_parts("a", &[b"b", b"c"]),
            digest_parts("a", &[b"bc"])
        );
        digest_parts("fixture", &[b"value"])
            .validate()
            .expect("generated digest is valid");
    }

    #[test]
    fn digest_validation_rejects_algorithm_downgrade_uppercase_and_zero() {
        assert!(DigestV1("sha1:00".to_owned()).validate().is_err());
        assert!(
            DigestV1(format!("sha256:{}", "A".repeat(64)))
                .validate()
                .is_err()
        );
        assert!(
            DigestV1(format!("sha256:{}", "0".repeat(64)))
                .validate()
                .is_err()
        );
    }
}
