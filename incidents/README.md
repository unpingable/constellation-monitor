# Incident continuity (cartography #93)

An alert says something happened. An incident says something still needs
dealing with. `constellation-incidents` keeps one durable incident per
supervised subject and failure condition, so that after hours away the
operator can ask one question:

    constellation-incidents            # what is broken, what was tried, what worked, what failed, what needs you
    constellation-incidents show inc-e048fb3e   # one retained incident's timeline
    constellation-incidents show 'constellation:labelwatch:service:service-down:attention-canary.service@2026-10-14T18:45:03Z'
                                              # copy the key@first_seen from a notice
    constellation-incidents ack|note|resolve ...  # operator actions, recorded as such

- **Identity.** The key is the condition key (`site:component:rule:target`),
  never a definition revision, so changing a threshold continues the same
  incident. A failure after closure opens `inc-…-2`.
- **Notice references.** The incidents tool is the only incident ID authority.
  Attention trigger and resolve summaries carry `condition-key@first_seen`
  immediately after the action; daily digests carry the same reference per
  active condition. Sync annotates the reference in the incident timeline with
  an `attention-reference` event containing the actual `incident_id`. `show`
  accepts that exact reference. After closure, the next reference resolves to
  `inc-…-2`; a new attention epoch inside incident recovery resolves to the
  original incident. Exact `inc-…` lookups always select that retained ID.
  An exact pre-upgrade `inc-X` lookup therefore returns the base incident, even
  when a later `inc-X-N` episode is open. Use `show inc-X-N` for that episode,
  or `show '<condition-key>'` for the newest retained incident and its ID.
  Delivered messages remain unchanged: they contain a lookup reference, not
  a preallocated `inc-…` ID. Before sync observes the active condition, the
  lookup reports no incident; it never guesses the closed episode. References
  are available for the store's retained history (normally 30 days, 300 events).
  If attention state predates this change and lacks `first_seen`, the summary
  carries only the condition key, which looks up its newest retained incident.
- **No resolution by disappearance.** Suspended, retired ("no longer
  evaluated") and vanished-while-present all leave the incident open, with an
  event saying why. It closes only after the attention evaluator resolved the
  condition as recovered *and* it stayed clear for 300 s, with no remediation
  episode still in flight. A flap inside that window continues the incident.
- **Remediation accounting.** The remediation consumer's episodes are attached
  by condition key and `first_seen`. The command outcome (`settled_failure`,
  `completed`, ...) is kept apart from verification: `completed` means the
  consumer re-sampled the postcondition after its dwell. Failed remediation, an
  expired remediation window with no attempt, or no remediation authority sets
  "needs you", using the rule's own operator instruction.
- **Independence.** The store is its own SQLite file
  (`/var/lib/constellation-incidents/incidents.sqlite`). `list` and `show`
  open it read-only, so they work with the evaluator, NQ or the remediation
  consumer down. Each sync writes a heartbeat and
  `constellation_incidents_*` metrics to the telemetry textfile directory;
  crow alerts when the sync goes stale.
- **Bounded.** Resolved incidents are kept 30 days, with at most 300 events
  per incident. Observations stay where they are and are not copied.
- **Shim.** Lifecycle semantics live in `sync()`. A backend implements the
  small `Store` interface. `test_incidents.py` runs the whole lifecycle
  against SQLite and an in-memory stub. A failed write raises
  `StoreUnavailable`, and the CLI exits 3 having claimed nothing.

The bounded machine interface for the Operations Board is
[`inspect`](INSPECTION.md). It returns unresolved and recently resolved incidents,
exact attempts, retained history, sync metadata and explicit missing fields.
The UI lives in Constellation Workbench, separate from this lifecycle owner.

## Incident metric links

`show` prints Host, Services and Alerts links, and `inspect` includes them as
`metric_links` on each entry beside `incident`, `events` and `attempts`. The
retained incident row and its lifecycle are unchanged. The helper now belongs
to Monitor at `incidents/metric_links.py`, moved from Cartography's temporary
home. Release assembly must install that sibling beside
`constellation-incidents.py` (including when the command is a symlink), and
stop maintaining a separate Cartography implementation. It uses only stdlib.

Packaging must ship these files together in the implementation directory
(normally `/usr/local/lib/constellation-incidents/`):

- `constellation-incidents.py`: the incident CLI and sync implementation.
- `metric_links.py`: required sibling for Grafana links.

Cartography's estate task, release `ASSETS`, day-two definition scripts and
testbed installer must all include the sibling; Cartography adopts this in
parallel. A single-file install still supports help, sync and incident queries,
with empty links and `metric_links_status: "unavailable: metric_links.py not installed"`
on inspection entries and the same explanation in `show`.

The generic install does not generate presentation configuration. The
Cartography installer should render scrape labels and, optionally, the
browser-facing Grafana URL in
`/etc/constellation-incidents/incidents.json`, or pass global `--config PATH`:

```json
{"grafana": {"site": "example", "host": "machine-01", "base_url": "http://localhost:3100"}}
```

The root must be a JSON object with these keys (maximum file size 64 KiB):

| Key | Expected value |
| --- | --- |
| `grafana` | Object containing the link settings. |
| `grafana.site` | Required nonempty string matching the metrics' `site` scrape label. |
| `grafana.host` | Required nonempty string matching the metrics' `host` scrape label. |
| `grafana.base_url` | Optional HTTP(S) browser endpoint, default `http://localhost:3100`. |

`base_url` defaults to `http://localhost:3100`; site and host must match the
installed dashboard scrape labels. They are never inferred from incident
subjects or machine-id. A reverse-proxy path is supported. Credentials, query
strings and fragments in the base URL are refused. This presentation config
contains no secrets. Missing config keeps incident inspection available with
empty links and `metric_links_status: "links unavailable: no incidents.json"`
(also printed by `show`). Invalid config likewise leaves queries available with
an explicit explanation. Missing/invalid
`first_seen` also leaves links unavailable; it never substitutes another time.

The stable dashboard UIDs are `constellation-host`, `constellation-services`,
`constellation-alerts`. URLs carry `orgId=1`, encoded `var-site` and `var-host`,
and Unix milliseconds: `from = max(0, first_seen - 30m)` and
`to = max(first_seen + 30m, last_observed_at or now)`. The lower bound is clamped
only at the Unix epoch. `last_observed_at` is the incident sync update, not an
independent metric acquisition time. No graph query or Grafana availability
check is performed. A resolved incident's link does not assert current health.

Grafana's default listener is loopback. From the operator's computer:

```sh
ssh -N -L 3100:127.0.0.1:3100 operator@monitored-machine
```

Keep the forward open while visiting the printed localhost URLs. If using local
port 13100, forward `13100:127.0.0.1:3100` and set `base_url` to
`http://localhost:13100`. This setting describes the operator browser's endpoint;
it does not publish Grafana. The helper CLI also accepts `--first-seen`,
`--last-observed`, `--site`, `--host`, and `--base-url` for offline link creation.

### Service maintenance and endpoint retirement

Attention maintenance suppresses covered trigger delivery, not observation or
incident creation. Sync records a `maintenance` timeline event once per window
start, including until, reason and operator; early end is recorded when the next
report removes the window. Active windows display
"Open — notifications suppressed (maintenance until …)". `needs_operator` is
unchanged. A clear condition during maintenance still enters `recovering` and
follows the usual confirmation rules. Provider pages accepted before maintenance
keep escalating there; acknowledge them in the provider. Run the maintenance CLI
as nq; see [Service maintenance](../docs/ATTENTION.md#service-maintenance).

Endpoint probe modes fold into one
`service:service-endpoint-unavailable:<service>` condition and incident. Migration
retires the old site-wide probe aggregates as "no longer evaluated". Their
incidents remain open with "recovery not observed"; use the existing operator
resolution procedure. Endpoint conditions retired with a service have the same
semantics. Maintenance never supplies evidence of recovery.
