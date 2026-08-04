use std::fmt;

use serde::{Deserialize, Serialize};

/// Longest identity token admitted by the initial schemas.
pub const MAX_IDENTITY_BYTES: usize = 160;

macro_rules! identity_type {
    ($name:ident) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            #[must_use]
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn validate(&self) -> Result<(), IdentityError> {
                validate_identity(stringify!($name), &self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_owned())
            }
        }
    };
}

identity_type!(SubjectId);
identity_type!(ObserverId);
identity_type!(ReceiverId);
identity_type!(IncarnationId);
identity_type!(ClockId);
// Exact consumer reliance-policy generation.
identity_type!(PolicyGenerationId);
// Exact collection law named by a pulse occurrence.
identity_type!(ObservationPolicyGenerationId);
identity_type!(ConsumerProfileGenerationId);
identity_type!(EvaluatorSemanticGenerationId);
identity_type!(ObserverSetGenerationId);
identity_type!(ContextActivationId);
identity_type!(SupportCertificateId);
identity_type!(RuntimeRefusalId);
identity_type!(EvidenceWindowId);
identity_type!(TransitionId);
identity_type!(ContradictionId);
identity_type!(EscalationRequestId);
identity_type!(DiagnosticRunId);
identity_type!(DiagnosticReceiptId);
identity_type!(BridgeId);
identity_type!(ConsumerId);
identity_type!(SparseEventId);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityError {
    pub field: &'static str,
    pub reason: &'static str,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid {}: {}", self.field, self.reason)
    }
}

impl std::error::Error for IdentityError {}

fn validate_identity(field: &'static str, value: &str) -> Result<(), IdentityError> {
    if value.is_empty() {
        return Err(IdentityError {
            field,
            reason: "identity is empty",
        });
    }
    if value.len() > MAX_IDENTITY_BYTES {
        return Err(IdentityError {
            field,
            reason: "identity exceeds the byte bound",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(IdentityError {
            field,
            reason: "identity contains a control character",
        });
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectScopeV1 {
    pub subject: SubjectId,
    pub subject_incarnation: IncarnationId,
    pub scope: String,
}

impl SubjectScopeV1 {
    pub fn validate(&self) -> Result<(), IdentityError> {
        self.subject.validate()?;
        self.subject_incarnation.validate()?;
        validate_identity("subject scope", &self.scope)
    }
}
