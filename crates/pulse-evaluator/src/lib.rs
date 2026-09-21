#![forbid(unsafe_code)]
//! Deterministic, in-memory present-confidence evaluation.

mod evaluator;
mod policy;
mod receiver;

pub use evaluator::*;
pub use policy::*;
pub use receiver::*;
