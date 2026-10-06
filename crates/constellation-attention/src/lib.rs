//! Bounded operator-attention evaluator for Constellation.
//!
//! It consumes qualified, current product state (host-posture status objects,
//! NQ's status export, the Nightshift observation store, NQ saved-check
//! results) and produces NQ notification intents. It is not evidence,
//! observation or execution authority, not a policy language and not a rules
//! engine: the rule registry is closed and compiled in. Delivery is NQ's job;
//! the evaluator writes an intent file, runs `nq notification submit` (or
//! `resubmit`) and records the outcome. It never reads Classic NQ and never
//! stores secrets.

pub mod build_info;
pub mod condition;
pub mod config;
pub mod engine;
pub mod inputs;
pub mod intent;
pub mod nq;
pub mod recurrence;
pub mod registry;
pub mod remediation;
pub mod state;
pub mod util;
