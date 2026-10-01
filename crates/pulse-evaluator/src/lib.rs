#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
//! Deterministic, in-memory present-confidence evaluation.

extern crate alloc;

mod alloc_prelude {
    pub use alloc::{
        borrow::ToOwned,
        boxed::Box,
        collections::{BTreeMap, BTreeSet},
        format,
        string::{String, ToString},
        vec,
        vec::Vec,
    };
}

mod evaluator;
mod policy;
mod receiver;

pub use evaluator::*;
pub use policy::*;
pub use receiver::*;
