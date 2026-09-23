use crate::{ModeV1, ProjectedStateV1, ProjectionError, StatusArtifactV1};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RenderedStatusV1 {
    Current { html: String },
    StatusUnavailable { html: String },
}

/// Render an already reduced artifact. `now_unix_ms` and uncertainty belong to
/// the presentation clock; they do not reinterpret a Pulse receiver clock.
pub fn render_status(
    artifact: &StatusArtifactV1,
    now_unix_ms: u64,
    clock_uncertainty_ms: u64,
) -> Result<RenderedStatusV1, ProjectionError> {
    artifact.validate()?;
    let latest_possible_now = now_unix_ms
        .checked_add(clock_uncertainty_ms)
        .ok_or_else(|| ProjectionError::new("clock_overflow", "presentation clock overflow"))?;
    let earliest_possible_now = now_unix_ms.saturating_sub(clock_uncertainty_ms);
    if earliest_possible_now < artifact.generated_at_unix_ms
        || latest_possible_now >= artifact.fresh_until_unix_ms
    {
        return Ok(RenderedStatusV1::StatusUnavailable {
            html: unavailable_html(),
        });
    }
    Ok(RenderedStatusV1::Current {
        html: render_html(artifact),
    })
}

/// Render reduced, validated fields only. This function has no source-record
/// input and performs no health inference.
#[must_use]
fn render_html(artifact: &StatusArtifactV1) -> String {
    let mut html = String::from(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Status</title></head><body><main><h1>Status</h1>",
    );
    html.push_str("<p class=\"overall\">");
    html.push_str(state_label(artifact.aggregate_state));
    html.push_str("</p><ul>");
    for component in &artifact.components {
        html.push_str("<li><strong>");
        html.push_str(&escape_html(
            component.display_name.as_deref().unwrap_or(&component.id),
        ));
        html.push_str("</strong>: ");
        html.push_str(state_label(component.state));
        if component.mode == ModeV1::Maintenance {
            html.push_str(" (maintenance)");
        }
        if let Some(reason) = &component.reason {
            html.push_str(" — ");
            html.push_str(&escape_html(reason));
        }
        html.push_str("</li>");
    }
    html.push_str("</ul></main></body></html>");
    html
}

fn unavailable_html() -> String {
    "<!doctype html><html><head><meta charset=\"utf-8\"><title>Status unavailable</title></head><body><main><h1>Status unavailable</h1><p>No current conclusion is supported.</p></main></body></html>".to_owned()
}

const fn state_label(state: ProjectedStateV1) -> &'static str {
    match state {
        ProjectedStateV1::Healthy => "Operational",
        ProjectedStateV1::Degraded => "Degraded",
        ProjectedStateV1::PartialOutage => "Partial outage",
        ProjectedStateV1::MajorOutage => "Major outage",
        ProjectedStateV1::Unknown => "Status unavailable",
    }
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
