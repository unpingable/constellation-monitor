# Installed filesystem-capacity host-posture runner

`constellation-host-posture` is the narrow installed composition for
`nq.host_filesystem_capacity.pressure/v1`. It coordinates existing NQ,
correspondence, Pulse, consequence-adapter, projection and publication APIs;
it defines no new diagnostic threshold, consequence rule or general scheduler.

The selected NQ watcher belongs exclusively to this service. Run it in a
newly initialized store with `nqd` inactive for that watcher. The service owns
the local-successor acquisition cadence; a second scheduler must not run the
same obligation. NQ remains responsible for invoking the packaged
`nq-host-resource-helper` under its admitted cross-UID boundary. The installed
service unit therefore needs the same narrowly reviewed helper-launch
capability envelope as the released NQ unit; the runner does not bypass NQ or
invoke the helper directly.

Start authoring with:

```sh
constellation-host-posture example-config > host-posture.toml
```

Release builds embed the clean source commit/tree, exact toolchain/target,
profile/features and `Cargo.lock` digest supplied by the clean-build producer.
`--build-info` emits that record without loading configuration. If a build
omits a field, the probe and rendered example say `unavailable`, and offline
qualification refuses it rather than inventing an identity. Preparation also
requires the configured source/build record to equal the embedded record.

Installation renders that example to a root-owned configuration, creates a
dedicated non-root service identity and private state/publication directories,
and installs the exact runner, NQ executable/configuration, sealed profile and
qualification package outside that identity's write authority. `run` and
`preflight` verify the effective uid, file ownership/modes and ancestors. The
offline `enroll` and `prepare-qualification` commands may instead be run by the
governance/install principal.

Preflight and run take the same stable-file writer lock and require private,
service-owned `intent` and `audit` directories. The configured projection
cadence plus the reactor command-response timeout must meet an explicit
withdrawal-publication tolerance no greater than five seconds for this
installed profile. The reactor admits no deliberate deadline delay and uses
file-synced journal durability. Publication is exactly `state_root/status`, so
the same stable writer lock covers journal, occurrence and publication state.

The finite setup sequence is:

1. Initialize and admit the native NQ filesystem-capacity watcher and retain
   its first ordinary `nq.diagnostic_execution.v2` artifact.
2. `enroll CONFIG INITIAL_ARTIFACT` copies NQ-owned semantic identities and
   hashes the exact installed NQ executable/configuration into the existing
   correspondence profile schema.
3. Supply canonical retained corpus/results plus clean source/build identities
   in the qualification section. `prepare-qualification CONFIG NEW_DIRECTORY`
   executes no command and preserves the recorded outcomes while creating the
   existing manifest/report/certificate/acceptance objects.
4. Install that directory read-only, run `preflight CONFIG` as the service
   identity, then start `run CONFIG`.

`run` never creates or accepts a certificate. It remeasures the installed
executable and active semantic values against the separately retained accepted
package and requires `QualifiedAndMatched`. Every restart uses a fresh process
occurrence and activation, recovers only journal history, and starts with no
support or deadlines. The first publication is unknown. Acquisition runs on a
separate bounded worker so periodic projection continues while NQ is blocked;
silence therefore becomes unknown when Pulse support expires. Clean stop also
withdraws support and publishes unknown. Journal damage, exhausted bounds,
package mismatch, pathname custody failure and a concurrent writer fail closed.
The exact loaded configuration digest and fresh process identities are emitted
at preflight/startup. Journal bytes/records are bounded by the owner journal;
the persistent intent/audit and immutable publication stores have aggregate
entry ceilings that survive restart and fail closed when exhausted. Retention
or rotation is an explicit governed installation operation, not an automatic
runner cleanup policy.

## Reactor custody failure

The Pulse reactor latches every custody failure for the life of its process.
After a command response timeout, mailbox overload, wakeup or journal
failure, actor termination or explicit blindness it never reports
`Operational` again, and every live admission is refused. The runner does not
retry, reset or rebuild the reactor in-process. It reads the reactor condition
at least every 200 ms; the first time it sees any condition other than
`Starting` or `Operational` it:

1. publishes the projection in that cycle, which is unknown because live
   admission is refused;
2. writes one stderr line naming the condition, its detail, the unknown
   artifact and that it is terminating for supervision;
3. stops the acquisition worker, declares blindness, publishes the final
   unknown and shuts the reactor down, as on any other terminal error;
4. exits with status 75 (`EX_TEMPFAIL`). Status 2 is a usage fault and status
   1 is every other runner refusal.

The packaged unit restarts only this case: `Restart=no` with
`RestartForceExitStatus=75` and `RestartSec=30s`. The owner asked for one
narrow recovery contract, and only the latched-custody exit has evidence that
a fresh process is the right recovery. Preflight failures, runner refusals
(exit 1), usage faults (exit 2), panics and OOM kills are not restarted and
stay visible to the owner. A restart is a fresh
process occurrence and activation, as described above, so recovery comes from
a new reactor and journal recovery, never from clearing the latch. The
projection stays unknown from the latch until the new process verifies an
occurrence. `StartLimitIntervalSec=1h` with `StartLimitBurst=5` bounds this:
a sixth start within an hour leaves the unit failed, the runner stops
publishing, and the stopped runner is reported through
`nq-no-fresh-acquisition`, `host-posture-unknown` and any `service-down`
watcher of the unit. Nothing restarts it automatically after that. An
operator can start it manually once the one-hour interval has passed; inside
the interval it needs `systemctl reset-failed` first. Each restart consumes occurrence and publication
capacity: the intent/audit and publication stores persist across processes
and count toward `maximum_occurrences` and `maximum_publications`, and each
process adds at least an initial and a final unknown publication. A unit
that exhausts either bound exits 1 and is not restarted.

A latch that recovers by restart still leaves a record. The unknown artifacts
stay in the publication store and in the `CURRENT` history. The
`reactor_custody_lost` stderr line stays in the unit journal, and the unit's
`NRestarts` counter rises. Attention raises `host-posture-unknown` only if
unknown persists past 600 s, so a latch followed by a quick recovery pages
nobody. The optional runner textfile below retains a per-latch counter for
operator visibility through the ordinary metrics path (Monitor #14).

Exit 75 is not guaranteed when the reactor actor itself is wedged, for
example blocked in fsync. The final `reactor.shutdown()` joins the actor
thread without a time bound, so such a process stays active but publishes
nothing more. Nothing turns into success: `host-posture-unknown` fires once
`fresh_until` passes and `nq-no-fresh-acquisition` fires on the missing
publications, and `TimeoutStopSec=90` bounds a stop request.

The example's 2,048 occurrences at a 60-second cadence are a bounded
qualification profile (about 34 hours), not a sustained-production retention
claim. A production retention envelope requires an explicit owner-approved
capacity and rotation/disposition procedure before deployment.

## Optional operator metrics textfile

Set the top-level `metrics_textfile_dir` in `host-posture.toml` to an absolute
directory to enable `host-posture.prom`. Omit the key to disable all metrics
I/O; existing installed configurations keep working. The packaged example is
`crates/constellation-host-posture/examples/host-posture.toml`, also rendered
by `example-config`; its optional key is commented out.

Pre-create the directory with write/search permission for the runner's service
identity and read/search permission for node_exporter. The unit's
`ReadWritePaths` must include that directory: use an installation-specific
systemd drop-in. The labelwatch island uses **`/var/lib/prometheus/node-exporter`**
(Cartography `architecture/beta-observability/mvp/labelwatch-host/definitions/systemd/constellation-estate-collect.service`).
For example, the drop-in's `[Service]` section can contain:

```ini
ReadWritePaths=/var/lib/prometheus/node-exporter
```

The packaged unit is unchanged because the default configuration does not
enable this output. Directory permissions and this sandbox exception are both
necessary. No directory, collector, scrape job, or alert rule is installed by
the runner. Use the existing node_exporter textfile → island VictoriaMetrics
→ vmalert path; there is no listener or new rule engine.

Every initial/periodic/final projection attempt writes a complete generation,
and returning from `run` after acquiring the state writer lock writes again.
Refusals before the lock (including a concurrent writer), abrupt termination,
panics, and a wedged shutdown cannot promise an exit write. The temporary file
is created in the destination directory with a name that does not end in
`.prom`, flushed with `sync_all`, chmodded to **0644** even under the unit's
0077 umask, and atomically renamed; the directory is synced too. A failed
metrics operation writes one escaped stderr line with
`host_posture_metrics_write_failed` and returns to the runner. It does not
alter publication results, reactor commands, or exit codes. A failed write can
leave the previous complete textfile in place. No metrics values are read by
the projection or used to authorize action, and scraping triggers no work.

All names have the prefix `constellation_host_posture_`. The exact families are:

| Metric | Type / labels | Meaning |
|---|---|---|
| `constellation_host_posture_projection_state` | gauge `{state}` | One-hot last successfully published state; unknown until a successful publication. |
| `constellation_host_posture_reactor_condition` | gauge `{condition}` | One-hot last observed reactor condition before shutdown. Final observation can reflect deliberate shutdown blindness. |
| `constellation_host_posture_custody_lost_total` | counter, no labels | Observed custody latches, at most once per process; deliberate final blindness does not increment it. |
| `constellation_host_posture_process_start_timestamp_seconds` | gauge, no labels | Unix seconds at entry to this `run` invocation. |
| `constellation_host_posture_occurrences_total` | counter, no labels | Retained intent entries, including failed/audit-only attempts; survives restart. |
| `constellation_host_posture_last_acquisition_timestamp_seconds` | gauge, no labels | Unix seconds when this process last received a verified acquisition; zero until its first verified acquisition. |
| `constellation_host_posture_publications_total` | counter, no labels | Retained immutable publication objects; survives restart. |
| `constellation_host_posture_publications_used` | gauge, no labels | Objects plus temporary publication entries, matching the capacity check. |
| `constellation_host_posture_maximum_occurrences` | gauge, no labels | Configured aggregate occurrence ceiling. |
| `constellation_host_posture_maximum_publications` | gauge, no labels | Configured aggregate publication ceiling. |
| `constellation_host_posture_textfile_write_timestamp_seconds` | gauge, no labels | Unix seconds of rendering, for detecting a frozen file despite fresh scrapes. |

The closed `state` values are `healthy`, `degraded`, `partial_outage`,
`major_outage`, `unknown`. The closed `condition` values are `starting`,
`operational`, `mailbox_overloaded`, `explicit_blindness`, `wakeup_failure`,
`actor_terminated`, `journal_failure`, `command_channel_closed`, `shutting_down`,
`terminated`. All members are always emitted, exactly one per family set to
1. There are no identity, path, artifact, detail, or acquisition labels.
The `site`, `job`, and `instance` labels in queries come from ordinary scraping.

The latch counter is a small decimal file, `state_root/metrics-custody-lost-total`,
mode 0600, protected by the runner's existing writer lock and replaced with the
same atomic protocol. It is saved before textfile exposure and retried on the
next write if persistence fails. A missing file starts at zero; unreadable or
corrupt state logs an error and omits only the custody counter for that process
instead of inventing a reset. Other metrics can still be written. Repair such
state explicitly with the runner stopped. This is best-effort telemetry:
unwritable state, a kill before persistence, or lost storage can lose a latch.
The counter records observed custody failures even if their projection fails
to publish. It does not infer faults from the unknown publication store,
because ordinary startup and clean shutdown also publish unknown.

Occurrence/publication counters reflect retained stores, not a new retention
policy. Explicit governed rotation can reset them. `publications_used` also
includes stranded temporary entries so headroom remains accurate after a
publication failure. A store-count error leaves the prior textfile unchanged
and logs a metrics error; metrics do not validate or repair the stores on a
scrape. Last acquisition time is process-local and intentionally resets to
zero on restart; it does not restore live support from retained evidence.

Suggested vmalert expressions (review thresholds and routing for the island;
these are documentation, with no Cartography changes):

```promql
# Per-latch notice: retain visibility after a healthy restart. Requires a
# sample an hour ago; a newly enabled series needs that baseline first.
(constellation_host_posture_custody_lost_total
 - constellation_host_posture_custody_lost_total offset 1h) > 0

# Repeated supervised custody exits: three or more observed latches/hour.
(constellation_host_posture_custody_lost_total
 - constellation_host_posture_custody_lost_total offset 1h) >= 3

# Process starts seen by scraping, including non-custody/manual restarts.
changes(constellation_host_posture_process_start_timestamp_seconds[1h]) >= 3

# Less than 20% remaining capacity; plan governed retention/re-enrollment.
constellation_host_posture_occurrences_total
 / constellation_host_posture_maximum_occurrences > 0.8
constellation_host_posture_publications_used
 / constellation_host_posture_maximum_publications > 0.8

# Frozen output, even when node_exporter itself is scraped successfully.
time() - constellation_host_posture_textfile_write_timestamp_seconds > 60
absent(constellation_host_posture_textfile_write_timestamp_seconds)
```

The per-latch notice may use `for: 0s`; the subtraction remains positive for an
hour after a latch and survives a fast healthy restart. This coalesces latches
into an active notice; the counter delta supplies their count. It does not
promise one notification per event. Offset subtraction assumes retained counter
state and history and cannot recover missing samples or a counter reset.
Process-start changes can miss starts between scrapes, so the persisted latch
delta is the stronger custody-storm signal. A final textfile remains after
exit: pair these rules with textfile age/absence, node scrape health and
existing unit/Attention checks. Scope absence queries to the intended scraped
host using its existing scrape labels. Validate alert evaluation, routing and
thresholds separately before deployment.
