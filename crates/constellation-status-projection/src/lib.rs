#![forbid(unsafe_code)]

//! Deterministic, read-only reduction of exact Constellation records into a
//! disclosure-bounded status artifact.
//!
//! The projector acquires no observations, grants no authority, and mutates no
//! monitored system. Its Pulse adapter uses a process-local monotonic clock to
//! preserve custody of one live query; source components retain ownership of
//! their native semantics. The filesystem publication helper operates only on
//! an already reduced and validated artifact.

mod adapter;
mod model;
mod projector;
mod publish;
mod render;

pub use adapter::{LiveQueryAnchorV1, LiveSupportObservationV1};
pub use model::*;
pub use projector::{project, project_with_details};
pub use publish::{CurrentPointerV1, StagedPublication, read_current_artifact, stage_publication};
pub use render::{RenderedStatusV1, render_status};
