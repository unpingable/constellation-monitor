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
            html: unavailable_html(artifact),
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
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Operator projection</title></head><body><main><h1>Operator projection</h1>",
    );
    html.push_str("<p class=\"overall\">Overall projection: ");
    html.push_str(state_label(artifact.aggregate_state));
    html.push_str("</p><p class=\"as-of\">As of ");
    html.push_str(&format_unix_ms(artifact.generated_at_unix_ms));
    html.push_str(" (UTC); presentation deadline ");
    html.push_str(&format_unix_ms(artifact.fresh_until_unix_ms));
    html.push_str(" (UTC).</p><ul>");
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
        push_detail(&mut html, component.detail.as_deref());
        html.push_str("</li>");
    }
    html.push_str("</ul><p class=\"nonclaim\">");
    html.push_str(&escape_html(&artifact.non_authorization));
    html.push_str("</p></main></body></html>");
    html
}

/// Format a Unix millisecond timestamp as UTC ISO-8601 at second precision.
/// Presentation only; the artifact's numeric fields remain authoritative.
fn format_unix_ms(unix_ms: u64) -> String {
    let seconds = unix_ms / 1_000;
    let (year, month, day) = civil_from_days(seconds / 86_400);
    let remainder = seconds % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        remainder / 3_600,
        (remainder % 3_600) / 60,
        remainder % 60
    )
}

/// Proleptic Gregorian civil date from days since 1970-01-01.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

/// The unavailable page. It states no conclusion. When a component carries
/// an owner detail (operator artifacts only), the page lists that component
/// with its unavailable state and the detail, dated by the projection
/// instant, so the operator can read why the condition could not be
/// evaluated without the page claiming anything more; components without a
/// detail are not listed.
fn unavailable_html(artifact: &StatusArtifactV1) -> String {
    let mut html = String::from(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Status unavailable</title></head><body><main><h1>Status unavailable</h1><p>No current conclusion is supported.</p>",
    );
    let detailed = artifact
        .components
        .iter()
        .filter(|component| component.detail.is_some())
        .collect::<Vec<_>>();
    if !detailed.is_empty() {
        // The page may be shown long after the artifact was produced; the
        // detail is dated so a stale explanation never reads as current.
        html.push_str("<p class=\"as-of\">Details as of the projection at ");
        html.push_str(&format_unix_ms(artifact.generated_at_unix_ms));
        html.push_str(" (UTC).</p><ul>");
        for component in detailed {
            html.push_str("<li><strong>");
            html.push_str(&escape_html(
                component.display_name.as_deref().unwrap_or(&component.id),
            ));
            html.push_str("</strong>: ");
            html.push_str(state_label(ProjectedStateV1::Unknown));
            push_detail(&mut html, component.detail.as_deref());
            html.push_str("</li>");
        }
        html.push_str("</ul>");
    }
    html.push_str("</main></body></html>");
    html
}

/// Append an owner detail as a separate labelled line. The text is copied
/// and escaped; nothing about it is read.
fn push_detail(html: &mut String, detail: Option<&str>) {
    if let Some(detail) = detail {
        html.push_str("<br><span class=\"detail\">Detail: ");
        html.push_str(&escape_html(detail));
        html.push_str("</span>");
    }
}

const fn state_label(state: ProjectedStateV1) -> &'static str {
    match state {
        ProjectedStateV1::Healthy => "No issue reported",
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

#[cfg(test)]
mod tests {
    use super::format_unix_ms;

    #[test]
    fn unix_ms_formats_as_utc_iso_8601() {
        assert_eq!(format_unix_ms(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_unix_ms(951_782_400_000), "2000-02-29T00:00:00Z");
        assert_eq!(format_unix_ms(1_900_000_000_999), "2030-03-17T17:46:40Z");
    }
}
