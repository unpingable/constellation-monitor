#![forbid(unsafe_code)]
//! Versioned records for the present-confidence experiment.
//!
//! These types carry bounded observation and reliance facts. None grants
//! mutation authority, and no type contains a global health boolean.

mod custody;
mod digest;
mod escalation;
mod event;
mod ids;
mod judgment;
mod pulse;
mod qualification;
mod runtime;

pub use custody::*;
pub use digest::{DigestV1, digest_parts};
pub use escalation::*;
pub use event::*;
pub use ids::*;
pub use judgment::*;
pub use pulse::*;
pub use qualification::*;
pub use runtime::*;

/// Initial schema version shared by the closed v1 records.
pub const SCHEMA_VERSION_V1: u16 = 1;
