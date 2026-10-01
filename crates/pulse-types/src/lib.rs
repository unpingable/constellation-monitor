#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
//! Versioned records for the present-confidence experiment.
//!
//! These types carry bounded observation and reliance facts. None grants
//! mutation authority, and no type contains a global health boolean.

extern crate alloc;

mod alloc_prelude {
    pub use alloc::{
        borrow::ToOwned,
        boxed::Box,
        collections::BTreeSet,
        format,
        string::{String, ToString},
        vec,
        vec::Vec,
    };
}

mod custody;
mod digest;
mod escalation;
mod event;
mod ids;
mod judgment;
#[cfg(feature = "std")]
mod live_support;
mod pulse;
mod qualification;
mod runtime;

pub use custody::*;
pub use digest::{DigestV1, digest_parts};
pub use escalation::*;
pub use event::*;
pub use ids::*;
pub use judgment::*;
#[cfg(feature = "std")]
pub use live_support::*;
pub use pulse::*;
pub use qualification::*;
pub use runtime::*;

/// Initial schema version shared by the closed v1 records.
pub const SCHEMA_VERSION_V1: u16 = 1;
