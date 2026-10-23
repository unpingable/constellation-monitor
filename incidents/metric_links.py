"""Incident metric links owned by Monitor; no network access.

Only standard-library dependencies; compatible with the island's Python 3.10.
The CLI and board can import incident_metric_links with an inspection incident dict.
"""
import argparse
from datetime import datetime, timezone
import json
import math
import time
from urllib.parse import urlencode, urlsplit

DASHBOARDS = {
    "host": "constellation-host",
    "services": "constellation-services",
    "alerts": "constellation-alerts",
}


def _milliseconds(value):
    if isinstance(value, bool):
        raise ValueError("first_seen must be Unix seconds or a timezone-aware ISO timestamp")
    if isinstance(value, (int, float)):
        seconds = value
    elif isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("first_seen needs a timezone")
        seconds = parsed.astimezone(timezone.utc).timestamp()
    else:
        raise ValueError("first_seen is required; do not silently substitute the current time")
    if not math.isfinite(seconds) or seconds < 0:
        raise ValueError("first_seen must be a finite time at or after the Unix epoch")
    return int(seconds * 1000)


def metric_link(first_seen, *, site, host, dashboard="host", base_url="http://localhost:3100",
                before_seconds=1800, after_seconds=1800, last_observed=None, now=None):
    """Return a dashboard URL from first_seen -30m through the observation window.

    site and host are scrape labels, supplied by site configuration, not inferred
    from incident subjects. base_url may contain a reverse-proxy subpath.
    """
    parsed = urlsplit(base_url)
    if (parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment):
        raise ValueError("base_url must be an HTTP(S) origin/path without credentials, query or fragment")
    if not isinstance(site, str) or not site or not isinstance(host, str) or not host:
        raise ValueError("site and host labels are required")
    for span in (before_seconds, after_seconds):
        if isinstance(span, bool) or not isinstance(span, int) or span < 0 or span > 604800:
            raise ValueError("window spans must be integer seconds between zero and seven days")
    if before_seconds + after_seconds == 0:
        raise ValueError("time range must have positive duration")
    at = _milliseconds(first_seen)
    end = _milliseconds(last_observed if last_observed is not None else (time.time() if now is None else now))
    query = urlencode({"orgId": 1, "var-site": site, "var-host": host,
                       "from": max(0, at - before_seconds * 1000),
                       "to": max(at + after_seconds * 1000, end)})
    return "%s/d/%s?%s" % (base_url.rstrip("/"), DASHBOARDS[dashboard], query)


def incident_metric_links(incident, *, site, host, base_url="http://localhost:3100", now=None):
    """Create board/CLI links from an incidents inspect object; require first_seen."""
    now = time.time() if now is None else now
    return {name: metric_link(incident.get("first_seen"), site=site, host=host,
                             base_url=base_url, dashboard=name,
                             last_observed=incident.get("last_observed_at") or incident.get("last_observed"), now=now) for name in DASHBOARDS}


def main():
    parser = argparse.ArgumentParser(description="Open graphs around an incident's first_seen")
    parser.add_argument("--first-seen", required=True)
    parser.add_argument("--last-observed", help="last observed timestamp; otherwise use now")
    parser.add_argument("--site", required=True)
    parser.add_argument("--host", required=True, help="host scrape label from site configuration")
    parser.add_argument("--base-url", default="http://localhost:3100")
    args = parser.parse_args()
    try:
        print(json.dumps(incident_metric_links({"first_seen": args.first_seen, "last_observed_at": args.last_observed}, site=args.site,
                                              host=args.host, base_url=args.base_url), indent=2))
    except (ValueError, KeyError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
