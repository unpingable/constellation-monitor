//! `constellation-remediation-consumer`: the deterministic consumer of
//! Bounded Autonomous Remediation v1.
//!
//! One oneshot pass (a 30 s timer, lock-protected) reads the attention
//! evaluator's report, selects only the enrolled `service-down` condition
//! under `auto_remediate_then_page` with enough remediation window left,
//! re-establishes the precondition through the pinned resolver, and drives
//! exactly one AG occurrence per condition episode: `init`,
//! `record-proposal`, `require-standing`, `decide`, `authorize`, `dispatch`
//! (Docket custody under the owner-enrolled grant), `poll`; then, on a
//! settled success, a fresh NQ collection, `continue` and `complete` on the
//! unit-active postcondition, and one on-demand evaluator pass.
//!
//! The consumer holds no authority of its own: every admission is AG's and
//! Docket's. It never asks about any unit but the enrolled one, never
//! dispatches twice (a durable fence precedes `dispatch`; after a crash only
//! AG's `recover`/`poll` run), and never claims a completion the
//! postcondition resolver has not answered `current`. Anything else leaves
//! the condition present and the evaluator pages at window expiry.

pub mod config;
pub mod external;
pub mod pass;
pub mod report;
pub mod store;

pub use config::Config;
pub use pass::{Summary, run_pass};
