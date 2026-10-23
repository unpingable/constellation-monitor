//! The only delivery path: `nq notification submit|resubmit|deliver-local`. The evaluator
//! never contacts a destination itself and never reads route secrets; the
//! child inherits the service environment that holds NQ's route locators.

use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::Config;
use crate::util::{ChildEnvironment, excerpt, read_bounded, run_bounded};

/// Only protocol identity is read here; transport locators remain NQ's concern.
#[derive(Clone, Debug, Deserialize)]
pub struct Route {
    pub reference: String,
    pub transport: String,
}

impl Route {
    #[must_use]
    pub fn local(&self) -> bool {
        self.transport == "local_file"
    }

    #[must_use]
    pub fn destination_label(&self) -> &str {
        if self.local() {
            "local-inbox"
        } else {
            &self.transport
        }
    }

    #[must_use]
    pub fn matches(&self, intent: &Value) -> bool {
        intent["route_reference"] == self.reference
            && intent["destination_identity"]
                == format!("{}:{}", self.destination_label(), self.reference)
    }
}

pub fn routes(config: &Config) -> Result<std::collections::BTreeMap<String, Route>, String> {
    #[derive(Deserialize)]
    struct Routes {
        #[serde(default)]
        notification_routes: Vec<Route>,
    }
    let bytes = read_bounded(&config.nq.config, 1024 * 1024)?;
    let routes: Routes =
        toml::from_str(std::str::from_utf8(&bytes).map_err(|error| error.to_string())?)
            .map_err(|error| format!("cannot read NQ route transports: {error}"))?;
    let mut current = std::collections::BTreeMap::new();
    for route in routes.notification_routes {
        if route.local()
            && (route.reference == config.routes.notice_route
                || config.routes.page_route.as_ref() == Some(&route.reference))
            && route.reference.len() > crate::intent::LOCAL_ROUTE_MAX
        {
            return Err(format!(
                "a local_file route must be at most {} bytes so its rendered message fits NQ's 4 KiB limit",
                crate::intent::LOCAL_ROUTE_MAX
            ));
        }
        current.insert(route.reference.clone(), route);
    }
    Ok(current)
}

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
