//! The only delivery path: `nq notification submit|resubmit|deliver-local`. The evaluator
//! never contacts a destination itself and never reads route secrets; the
//! child inherits the service environment that holds NQ's route locators.

use std::path::Path;
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use crate::config::Config;
use crate::util::{ChildEnvironment, excerpt, run_bounded};

#[derive(Clone, Debug, Serialize)]
pub struct SubmitOutcome {
    pub notification_id: Option<String>,
    /// NQ `delivery_state`, or `command_error`.
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn run(config: &Config, tail: Vec<String>, network: bool) -> SubmitOutcome {
    let mut argv = vec![
        config.nq.program.display().to_string(),
        "--config".to_owned(),
        config.nq.config.display().to_string(),
        "--json".to_owned(),
        "notification".to_owned(),
    ];
    argv.extend(tail);
    if network && config.routes.network_enabled {
        argv.push("--enable-network".to_owned());
    }
    let output = match run_bounded(
        &argv,
        Duration::from_secs(config.command_timeout_seconds),
        64 * 1024,
        ChildEnvironment::Inherit,
    ) {
        Ok(output) => output,
        Err(error) => {
            return SubmitOutcome {
                notification_id: None,
                outcome: "command_error".into(),
                error: Some(error),
            };
        }
    };
    if output.timed_out {
        // NQ may have claimed and sent: the record, if any, is uncertain.
        return SubmitOutcome {
            notification_id: None,
            outcome: "unknown".into(),
            error: Some("nq timed out".into()),
        };
    }
    if output.status != Some(0) {
        return SubmitOutcome {
            notification_id: None,
            outcome: "command_error".into(),
            error: Some(format!(
                "nq exited with {:?}: {}",
                output.status,
                excerpt(&output.stderr)
            )),
        };
    }
    let Ok(value) = serde_json::from_slice::<Value>(&output.stdout) else {
        return SubmitOutcome {
            notification_id: None,
            outcome: "unknown".into(),
            error: Some("nq printed no JSON result".into()),
        };
    };
    let notification_id = value
        .get("notification_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let outcome = value
        .get("delivery_state")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_owned();
    SubmitOutcome {
        notification_id,
        outcome,
        error: None,
    }
}

/// `nq notification submit --intent FILE --route R [--enable-network]`.
pub fn submit(config: &Config, intent: &Path, route: &str) -> SubmitOutcome {
    run(
        config,
        vec![
            "submit".into(),
            "--intent".into(),
            intent.display().to_string(),
            "--route".into(),
            route.into(),
        ],
        true,
    )
}

/// `nq notification deliver-local --intent FILE --route R`, for a
/// `local_file` route. It needs no network and takes no `--enable-network`.
pub fn deliver_local(config: &Config, intent: &Path, route: &str) -> SubmitOutcome {
    run(
        config,
        vec![
            "deliver-local".into(),
            "--intent".into(),
            intent.display().to_string(),
            "--route".into(),
            route.into(),
        ],
        false,
    )
}

/// `nq notification resubmit --notification-id ID --stable-event-id NEW [--enable-network]`.
pub fn resubmit(config: &Config, notification_id: &str, stable_event_id: &str) -> SubmitOutcome {
    run(
        config,
        vec![
            "resubmit".into(),
            "--notification-id".into(),
            notification_id.into(),
            "--stable-event-id".into(),
            stable_event_id.into(),
        ],
        true,
    )
}
