# Estate supervision

Constellation's operational promise for a host, in four parts:

1. Know which services it is responsible for: `estate.<host>.json`, the estate
   registry. A service missing from it is unsupervised.
2. Know whether each one is doing its job: `constellation-estate-collect.py`
   combines runtime state (systemd or Docker) with the project's own status
   contract. That contract is the `.ops/observation.toml` producer emitting
   `project.ops.status/v1`, a Labelwatch-recent watcher report, or an HTTP
   probe. A required concern that is not `PRESENT` makes the service
   `DEGRADED`, including a missing observation. A container that Docker calls
   healthy is not thereby doing its job.
3. Fix what it is authorized to fix: the remediation consumer (unchanged here).
4. Say when it cannot: the attention evaluator reads `[inputs.estate]`. Its
   `service-not-doing-its-job` rule sends a Slack notice after 600 s, giving the
   service's own reason. The daily digest restates every open condition and
   every declared pause.

A deliberate pause is declared in the registry (`"declared": {"state":
"paused", "since", "reason"}`). The service then shows as `PAUSED`: never an
alert, always visible on the dashboard and in the digest.

Host registries are deployment data, not code: they name units, paths and
contracts of a real host, so they live in the private deployment repository
(for labelwatch-host: cartography
`architecture/beta-observability/mvp/labelwatch-host/`), with the vendored
contracts, the declared definition snapshot and the crosswalk.

The registry's `definitions` pin every alert and policy definition to the
identity its own subsystem computes: a file sha256, the attention
`attention_policy_digest` from `check-config`, or NQ's saved-check
`definition_digest`. Each pass compares the deployed side, and any mismatch
makes `estate-definitions` DEGRADED, naming the definition. The repository
side, where every pin must equal the committed declared copy, is a test next
to the registry.

Each `constellation.estate/v1` document also carries `registry_sha256`, the
lowercase SHA-256 of the exact registry bytes read for that pass. This additive
field lets the existing release verifier distinguish a fresh observation of
the intended declaration from an old or differently configured `OK` result.
It is provenance, not authorization or an assertion of current service health.
Older readers may ignore it; a verifier requiring it must report older reports
as unsupported. The shared `fixtures/definition-release/` vector is consumed
by Cartography's `architecture/day-two-release-lifecycle` release tests.

`nq-watcher-admission` definitions use the NQ-owned bounded read operation
`nq --config FILE --json watcher inspect INSTANCE`. The collector requires
`nq.watcher_inspection.v1`, the exact instance and a valid binding digest,
then compares that digest with the declared pin. NQ performs its own config,
profile, protocol/corpus, capability and execution-identity checks; Monitor
does not implement them. An older CLI, failed verification or unsupported
response is UNKNOWN. `program` may name an exact side-by-side NQ read artifact
so enrollment and the resident NQ binary remain unchanged. Its file identity
must also be pinned by the site registry. Admission verification does not
collect observations or assert service health. The shared
`fixtures/watcher-inspection-v1.json` vector is also in NQ's CLI tests.
New source and contract tests are not a deployment claim.
Admission inspection runs in the collector's existing account. On the deployed
Linux profile the startup-image identity checks require root's metadata access;
dropping to the database account would make loader inspection unavailable.
This operation still performs no collection, helper execution or store write.
No account, filesystem permission or capability is changed to make a read pass.

Install on the host:

    install -D -m 0755 constellation-estate-collect.py /usr/local/lib/constellation-estate/constellation-estate-collect.py
    install -D -m 0644 <registry from the deployment repo> /etc/constellation-estate/estate.json
    install -m 0644 constellation-estate-collect.{service,timer} /etc/systemd/system/
    systemctl daemon-reload && systemctl enable --now constellation-estate-collect.timer
    # attention.toml:  [inputs.estate]  path = "/var/lib/constellation-estate/estate.json"

## Metric alerts: vmalert as an attention input

`metric-alerts-collect.py` reads vmalert's `/api/v1/rules` once (1 MiB bound)
and writes `constellation.metric_alerts/v1`: every loaded alerting rule with
the same definition identity the estate collector pins
(`constellation.vmalert_policy/v1`), its state, health, last evaluation and
alert instances. The attention evaluator's `[inputs.metric_alerts]` turns each
rule labelled `attention: "true"` into a condition (`metric-alert-firing`,
notice after 60 s, carrying the alert's own summary); see
`docs/ATTENTION.md`. It observes only: no evaluation, no notifier, and an
unreadable source leaves the last good document in place and exits 1.

    useradd --system --no-create-home --shell /usr/sbin/nologin constellation-metrics
    install -D -m 0755 metric-alerts-collect.py constellation-estate-collect.py /usr/local/lib/constellation-estate/
    install -m 0644 constellation-metric-alerts-collect.{service,timer} /etc/systemd/system/
    systemctl daemon-reload && systemctl enable --now constellation-metric-alerts-collect.timer
    # attention.toml:  [inputs.metric_alerts]  path = "/var/lib/constellation-metric-alerts/metric-alerts.json"

`--declared <declared-vmalert-policy.json>` carries the deployment
repository's declared policy identity so the evaluator can tell a firing
alert under a drifted definition set from one under the declared set. The
shared vector `fixtures/vmalert-rules-runtime-v1.json` is consumed by
`test_metric_alerts.py` and by the evaluator's tests.

Binding value-code contract (2026-10-22), verbatim:

one alert identity per family; the alert value is a code: 1 = present (threshold met / violation), 2 = acquisition failed (exporter or producer unreachable), 3 = missing (no series), 4 = stale or future timestamp, 5 = invalid or warming (no history yet, counter reset, invalid limit). Every value-coded rule carries the static label `constellation_value_codes: "v1"` (this is the machine-readable marker; `description` annotations do not reach the reader, labels and `summary` do). The evaluator maps non-1 values to unknown-held ONLY for rules carrying that label, with the cause naming the code's meaning (2 acquisition_failed, 3 missing, 4 stale, 5 invalid_or_warming); unlabelled rules keep raw-value semantics exactly as today (their values may legitimately be 2 or 3). A labelled rule with a value outside 1-5 is an input fault for that rule (rejected-rule class, like the per-rule admission in 0.1.10), never present and never clear. The `summary` annotation of value-coded rules reads `evidence code={{ $value }} (<meaning>)`; the notice text for a present code should use that summary as today.

Rules also carry `attention: "true"` to opt into the evaluator. Code 1 is
present only when firing; pending retains vmalert's hold. Inactive rules clear
only when freshness, health, evaluation and policy checks permit recovery.

Rule labels and bounded instance values pass through unchanged. For marked
rules the producer additionally writes `value_code_counts`, a complete list
of `{site, state, value, count}` rows for firing and pending instances,
computed before the 32-instance detail bound (empty site means no label).
This keeps unknown codes visible at high fan-out and across sites. Deploy
the collector with the evaluator: a marked active rule missing that summary
is rejected per rule, as are malformed values and unsupported versions. An
open condition holds as `unreported`; other definitions keep evaluating.
The shared vector covers both producer bytes and evaluator meaning,
including pending and unsupported codes.

Unknown-held conditions send no metric notice until they have been present.
Their code and meaning appear immediately in the report and bounded digest;
lasting unknown codes surface through the existing input `indeterminate`
fault and `evaluator-input-unavailable` notice after its default 300 s.
No additional timer is introduced. Plain `lastSamples = 0` with positive
`lastSeriesFetched` cannot reliably reveal missing comparison history;
definitions needing that distinction must opt into explicit value codes.

**Admission before deployment.** The evaluator admits each opted-in rule on
its own: a rule whose condition target cannot be derived (the alert name as a
token, plus `.<site>` for each `[inputs.metric_alerts] sites` entry, at most
48 bytes of `[a-z0-9._-]`, not shaped like a date or digest) is rejected
alone, for the site whose target overflows only, and reported as
`metric_alerts.rule_rejected:<AlertName>`; rules sharing a token are all
rejected; the other rules are evaluated. To
refuse such a rule set before it reaches a host, run the check against the
declared policy the producer carries, with the evaluator's sites:

    metric-alerts-collect.py --check-targets --declared declared-vmalert-policy.json --key-site labelwatch

The value-code marker is accepted without changing target derivation. Every
labelled rule must have a `summary` containing `evidence code=`, including
rules without attention opt-in. Description-only annotations fail this check.
It reads nothing else, prints `constellation.metric_alert_admission/v1` (each
attention rule with its admitted targets, its refusals per site and the
longest derived byte count), names each refused rule and site on stderr and exits 1 if any rule would be rejected. A
renderer or a definitions test should run it for every site set it deploys.
`ServiceMetricsObservationNeedsAttention` is the case it exists for: its
43-byte token plus `.testbed` is 51 bytes (`.labelwatch`: 54). The shared
vector `fixtures/metric-alert-targets-v1.json` holds both implementations to
the same derivation.
## External file probes (P1)

The registry may add read-only file probes to a service entry. P2 will derive
these entries from service declarations; this collector reads the additive JSON
form today:

```json
"probes": {
  "stores": [{"name": "main", "path": "/var/lib/example/main.sqlite"}],
  "outputs": [{"name": "report", "path": "/var/lib/example/report.json"}],
  "backups": [{"name": "daily", "path": "/var/backups/example.sqlite"}]
}
```

Names are unique lowercase tokens within each list. Paths are absolute host
paths visible to the collector account. A container-only path must be exposed
as a read-only host path before declaration. A missing path is a failed probe,
never a zero-size file or a healthy result. A store means a SQLite database.
The collector does not open it through SQLite or create any sibling file. It
reads the 100-byte main database header, checks the SQLite magic and page size,
and reads the main-header freelist count. For a declared symlink, it reads the
resolved target and measures the WAL beside that target. The freelist count
may lag uncheckpointed WAL changes; none of these file measurements asserts
transactional SQLite health.
WAL absence yields zero WAL bytes only after the database itself was read and
validated.

The existing two-minute timer is the fast schedule: filesystem capacity and
file mtimes are checked on every pass. SQLite header and WAL geometry run every
ten minutes by default (`--probe-slow-seconds`). Each file operation runs in a
child process with its own three-second deadline (`--probe-timeout`), with at
most four probe workers. Service checks run with at most four workers
(`--service-workers`). A delayed service status producer cannot prevent probes
from publishing, because the probe textfile is replaced before service checks
begin. If a child remains blocked after its deadline and SIGKILL, the collector
reports its exact PID as pending exit; it does not wait without a bound. Command
stdout retains at most 1 MiB (4 KiB for a probe), while stderr
retains its final 2 KiB; both pipes are drained throughout execution.

`--textfile-dir` must name the existing node_exporter textfile directory when
probes are declared. The service unit uses `/var/lib/prometheus/node-exporter`.
The collector atomically replaces `constellation-estate.prom` there and stores
the schedule cache as `probe-state.json` beside its estate JSON output. The
collector discards malformed or future-dated cache entries and probes again. The
textfile exposes `service_filesystem_avail_bytes`,
`service_filesystem_avail_inodes`, `service_store_bytes`,
`service_store_wal_bytes`, `service_store_freelist_pages`,
`service_store_page_size_bytes`, `service_store_age_seconds`,
`service_output_age_seconds`, `service_backup_age_seconds`, and
`service_backup_created_timestamp_seconds`. The backup timestamp is file mtime,
not a verified creation or successful restore time. Measurement labels include
`service` and the appropriate `store`, `output`, or `backup` name.

Every operation also emits `service_probe_success{service,<kind>,probe}`. A
failure emits zero and omits its measurement families; it cannot turn missing
data into a clear reading. `service_probe_last_success_timestamp_seconds` and
`service_probe_observed_timestamp_seconds` retain the observation time when a
slow probe is skipped, and last success survives a failed attempt. Rules must
check success, observation age, and textfile freshness (node_exporter's
`node_textfile_mtime_seconds`) before treating measurements as current. The
collector removes old metric series when a registry removes its probes.

Formalization consideration for P1: the source is Monitor revision `0c6928a`;
the resulting revision and local test receipt are named in the immutable lane
notice for run `fec2dc7f-8535-41e4-9bd8-18c4c6ebc08e`. The proposition is
limited to one collector pass: for each declared file operation, a successful
measurement has an observation time, and an unavailable or timed-out operation
emits success zero without a fabricated measurement; one blocked operation does
not prevent other probe results from publishing. Counterexamples outside that
scope include the filesystem changing immediately after observation, a
stopped collector leaving an old textfile, and a store header that does not
reflect WAL content. The Monitor lane owns this decision. The bounded child
deadline, atomic output, and deterministic missing/FIFO fixtures directly test
the boundary, so practical tests and prose are sufficient for this change.
Freshness rules and end-to-end delivery remain separate integration claims.

### Authored service declarations (P2)

An approved desired-state registry remains the expected set even when the service,
collector or entire target host is unavailable. Render it before deployment from
`/etc/constellation/services.d/<name>.toml`; retain that JSON in the existing
versioned deployment inventory off-host. Collection never reconstructs expectations
from a live directory, processes or advertisements. Retire a subject by reviewing
and rendering an explicit desired-state change.

```toml
name = "demo"
role = "worker"
runtime = {systemd = "demo.service"}
health_url = "http://127.0.0.1:8080/health"
probes = {outputs = [{name = "result", path = "/var/lib/demo/result"}]}
thresholds = {output_age_seconds = 60}
```

`runtime`, `status`, `contract`, `declared`, `probes` and `timers` retain the
existing JSON shapes (TOML inline tables work). `health_url` is shorthand for
HTTP status; `status_command = ["producer", "--json"]` plus `status_user = "demo"` is
shorthand for a project-ops-status producer. New declaration command statuses
require an explicit non-root execution user, including the full `status` table
form. The renderer rejects missing, empty, root and UID-zero execution users.
Legacy JSON command configuration retains its existing behavior. Choose one status source. Optional `metrics_url`
is checked for HTTP availability; `dependencies = ["other-service"]` records
graph edges between expected subjects. Thresholds are positive finite service
limits preserved for the generic rule renderer; declaring one alone does not
activate an alert. Existing collector permissions and action boundaries apply.

```sh
python3 constellation-estate-collect.py --registry base.json \
  --services-dir ./services.d --declaration-root /etc/constellation/services.d \
  --render-registry derived-estate.json
```

This mode makes no runtime observations. It replaces `services` in the base,
retains its other fields, and pins each declaration's target path and exact byte
SHA-256. Identical inputs produce identical sorted JSON. Deploy the rendered
registry and the exact declaration files together. Ordinary `--registry` collection
verifies those pins, retains the approved service fields when files are missing or
changed, and reports `declaration.drift`. Unavailable declared runtime, status or
metrics endpoints and missing declared paths also report drift. Unregistered
workload coverage still runs. `--declaration-root` is render-only: collection always uses the approved paths.

Timers can add `first_result_due_at = "2026-10-20T12:00:00Z"` and
`max_success_age_seconds = 3600` (the latter requires a first deadline). Armed
without an observed successful completion is UNKNOWN before that deadline and
DEGRADED at or after it. Success means systemd reports `Result=success`, an
accepted exit status and `ExecMainExitTimestamp`; the maximum age expires strictly
after its limit. A failed run remains DEGRADED. Output existence/mtime is a separate
probe and cannot establish successful execution. Legacy timers without these
fields retain their existing armed/result checks. No earlier success is inferred
when systemd exposes only a later unsuccessful run.

P3 limits accept exactly `last_success_age_seconds`, `cursor_lag_seconds`,
`output_age_seconds`, `store_bytes`, `wal_growth_bytes`, and `backup_age_seconds`.
Unknown keys fail validation. Collection publishes each as
`service_<key>_limit{service="name"}` in the same textfile, including services
without file probes. Threshold declarations require `--textfile-dir`.
`service_declaration_observed_timestamp_seconds{service="name"}` records the
collector pass over an expected subject, even when its runtime is absent. It is
not successful observation or application health. Generic rules must separately
gate on current successful probe/application observations. Applications supply
`service_last_success_timestamp_seconds` and `service_cursor_lag_seconds` through
ordinary Prometheus instrumentation; authored limits do not create those facts.

Service declarations and their rendered registry must be installed and approved
by the trusted operator through the existing deployment procedure. They are not
untrusted application input and cannot grant collector access or authorize an
action. Command producers run with the explicitly named account using the
existing collector execution path; installation must ensure that account has
only its intended permissions.

Authored `first_result_due_at` must be a quoted ISO timestamp with an explicit
UTC designator or numeric timezone offset, or a finite nonnegative Unix timestamp
in seconds. Date-only and timezone-free text, native systemd timestamp text and
nonfinite numbers are rejected. This makes the approved deadline independent of
the renderer's or target host's local timezone. Native systemd completion-time
parsing retains its existing UTC text support.

For application-owned textfiles, declare `thresholds.metrics_observation_age_seconds`
and export `service_observation_timestamp_seconds{service="..."}` from the
application's recorded observation time. A node_exporter scrape timestamp only
proves the file was read, so it cannot establish that the application advanced.
The collector emits the authored limit even when the application is absent;
Cartography's optional `ServiceMetricsObservationNeedsAttention` rule detects
missing, future or frozen observation timestamps. Declare a separate
`last_success_age_seconds` budget for useful committed work: an application
heartbeat is not evidence of successful output. Neither timestamp grants action
authority. Existing declarations without this threshold keep their current rules.
