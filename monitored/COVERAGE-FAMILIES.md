# Coverage families

Source delivery for cartography #106/#109 on base `faea608`. No family is closed.
Closure still requires observation and history, rendered/pinned declarations,
an effective operator route, a runbook, and trigger/resolve receipt at every
in-scope site. Every host is an island. This lane did not inspect hosts.

The requested May audit pathname in `nq-wal-fence-20261019` is absent. The copy
read was `/data/git/.worktrees/nq-operator-beta-profile-v1/docs/working/coverage/traditional-monitoring-coverage-audit.md`,
including its second-pass candidates. Status below follows the committed
`MONITORING-BACKLOG.md` and #109's source reconciliation
(`reviews/ISSUE-109-BODY-20261020-p14.md` in the registry checkout), including
P14's subsequent routing correction recorded in the backlog. “Activated
elsewhere” describes recorded activation, not current runtime verification.
“Defined” includes unactivated source, not deployed coverage.

| May audit family | Default home | Status on this branch | Owning package / lane |
|---|---|---|---|
| disk capacity (bytes) | node_exporter rule | activated elsewhere; site/drill evidence incomplete | P8; Attention host-disk owns `/` |
| inode exhaustion | node_exporter rule | activated elsewhere; site/drill evidence incomplete | P8 |
| mount state (ro/remount/missing) | node_exporter rule + textfile declaration | activated elsewhere ro; missing open | P8/P10 |
| block I/O pressure | node_exporter rule | activated elsewhere PSI only | P8; NQ host_io admitted path separate |
| kernel filesystem errors | textfile producer | open | P10 |
| filesystem scope declaration | textfile producer | open | P10 expected mounts/exclusions |
| clock skew / NTP failure | node_exporter rule | activated elsewhere; drills open | P8 |
| OOM / memory pressure events | node_exporter rule | activated elsewhere; partial OOM drill | P8; PSI drills open |
| CPU saturation / scheduler pressure | node_exporter rule | activated elsewhere; drills open | P8 |
| process presence | node_exporter rule + product concern | activated elsewhere enrolled services; scope open | P1–P6 useful work; P9 processes |
| listener presence | blackbox probe | open | P9 |
| file descriptor exhaustion | node_exporter rule | activated elsewhere system-wide; per-process open | P8 |
| PID / process table pressure | node_exporter rule | open | P9 |
| TLS certificate expiry | blackbox probe | defined internal; activated elsewhere public | Extended families / P9 |
| network interface errors / drops | node_exporter rule | activated elsewhere; scope/drills open | P8 |
| conntrack / socket table pressure | node_exporter rule | activated elsewhere conntrack; socket/port scope open | P8/P9 |
| reboot / unexpected uptime reset | node_exporter rule | activated elsewhere; warming/drills open | P8 |
| log pattern observed | textfile producer | defined | Extended families; product owns meaning |
| package / restart-required state | textfile producer | defined | Extended families / #109 security posture |
| DNS state | blackbox probe | defined; NQ preflight separate | Extended families |
| TLS handshake state | blackbox probe | defined internal TLS/SMTP; general scope open | Extended families / P9 |
| SMTP state | blackbox probe + textfile producer | defined | Extended families |
| HTTP probe | blackbox probe | defined content and duration p95 | Extended families / P9 reachability |
| witness silence | NQ-only admitted claims; textfile supervisor | activated elsewhere enrolled inputs; external proof open | NQ / P12 |
| stale findings | NQ-only admitted claims; product concern otherwise | activated elsewhere enrolled inputs; scope open | NQ / P4/P12 |
| ingest state | NQ-only admitted ingest; product concern otherwise | activated elsewhere enrolled inputs; scope open | NQ / P4 |
| SQLite WAL pressure | textfile producer | defined P1 geometry / P3 growth | P1/P2/P3 activation and scope open |
| SQLite freelist pressure | textfile producer | defined P1 geometry; enrolled saved checks activated elsewhere | P1/P2 inventory open |
| DB lock contention | stock exporter rule / saved-check textfile | defined; held lock alone is not contention | Extended families |
| DB replication lag | stock exporter rule | defined | Extended families |
| DB vacuum / autovacuum debt | stock exporter rule | defined frozen XID and declared-table autovacuum age; other debt open | Extended families / database owner |
| ZFS pool / vdev state | node_exporter textfile producer | open for physical-host scope | P10; NQ ZFS separate |
| SMART device state | node_exporter textfile producer | open for physical-host scope | P10 smartmon |
| coverage honesty (operational vs declared) | NQ-only claims; product declaration otherwise | defined doctrine/P2 split; scope open | NQ / P2/P4 |
| time-basis poisoning | NQ-only | open claim-side adjudication | NQ; offset cannot adjudicate |
| swap_thrashing (second-pass candidate) | node_exporter rule | activated elsewhere swap-in + low free; drills open | P8 |
| cgroup_container_limits (candidate) | node_exporter / cgroup exporter rule | open | Runtime owner / P9 |
| scheduled_job_freshness (candidate) | textfile producer | defined timer declarations / P3 obligations | P1–P4 |
| backup_age / restore_evidence (candidate) | textfile producer + product concern | defined P3 age; restores open | P11 |
| log_rotation_pressure (candidate) | textfile producer | open | P10 / service owner |
| local_resolver_state (candidate) | blackbox probe | defined declared DNS checks | Extended families |
| cloud_instance_metadata_state (candidate) | textfile producer | open | Host integration owner |
| entropy_pool (candidate) | node_exporter rule | open | P10 |
| security_event_counts (candidate) | textfile producer / product concern | defined selected literals only; interpretation open | Extended families / security owner |
| firewall_rules_state (candidate) | product concern / estate definition | defined saved-file pins; kernel parity open | P13 |
| package_version_drift (candidate) | textfile producer | open; pending security updates are distinct | Host-posture owner |

## Family delivery and drill plans

Paths in this table are relative to `mvp/labelwatch-host/definitions/vmalert/rules`.
The exact metrics, thresholds and holds are committed in each file.

| Family / standard source | Rule file and alert(s) | Threshold / rationale | Applicability declaration | Testbed trigger → recovery | Runbook |
|---|---|---|---|---|---|
| DNS: blackbox `probe_dns_query_succeeded`, `probe_success`, `probe_dns_serial` | `family-dns.rules.yml`: DnsResolver, DnsNameExists, DnsAnswer; `family-dns-soa.rules.yml`: DnsSoa | exchange/NXDOMAIN 2m; RR mismatch 5m; serial inequality 30m for propagation | resolver IP/port, name/type/RR regex; separate NXDOMAIN module; authoritative zone and expected serial only if declared | stop resolver → restore; NXDOMAIN → NOERROR; wrong RR → expected RR; changed SOA → declared serial; exercise each separately | [coverage-dns](#coverage-dns) |
| Log: bounded journald → `coverage_log_matches_total`, epoch | `family-log.rules.yml`: LogPatternRate | >10 matching records/hour for 5m; hour baseline avoids first-sample increase | unit, ≤16 literal patterns with stable IDs, cursor state, 60s schedule | 11 matching fixture records after baseline → complete recovered hour with ≤10; separately test overflow/cursor loss/restart | [coverage-log](#coverage-log) |
| Updates: read-only python3-apt cache, reboot marker, selected installed boot kernel vs uname | `family-updates.rules.yml`: SecurityUpdates, RebootRequired, KernelMismatch | positive/true 24h; 2h observation freshness, hourly schedule; 48h index age bound | apt host, update-success stamp and `/vmlinuz` selector, schedule | pending candidate/marker/mismatch fixtures through full hold → fresh zero/absent/match; stale indexes never clear | [coverage-updates](#coverage-updates) |
| SMTP: blackbox TCP banner/EHLO/STARTTLS; postfix `postqueue -j` / exim `-bpc` | `family-smtp.rules.yml`: SmtpStartTls; `family-mail-queue.rules.yml`: MailQueueDepth | conversation failure 5m; queue >100 messages 30m tolerates bursts | submission endpoint, banner/EHLO expectation, SNI/CA; MTA kind and 60s queue schedule only if declared | fixture wrong banner/disabled STARTTLS → restore; isolated queue >100 → drain ≤100; malformed count stays unknown | [coverage-smtp](#coverage-smtp) |
| SQLite: reuse P1 geometry; approved read-only saved-check result | `family-sqlite-lock.rules.yml`: SqliteWriteLock; P3 geometry unchanged | `coverage_sqlite_write_lock_held` =1 for 5m; result ≤180s | store identity, approved saved-check/result path with granted access; never generic write probe | fixture held=1 → held=0; remove result mid-fault and verify no resolve; drill geometry separately | [coverage-database](#coverage-database) |
| PostgreSQL: stock postgres_exporter activity/locks/settings/wraparound/replication collectors | `family-postgres.rules.yml`: PgLongTransaction, PgConnections, PgVacuumAge, PgExclusiveLocks; `family-postgres-vacuum.rules.yml`: PgAutovacuumAge; `family-postgres-replica.rules.yml`: PgReplicaLag | oldest transaction >300s 10m; connections >80% 10m; frozen XID age >150M 1h; declared-table last autovacuum >24h for 1h; access-exclusive locks >0 5m; lag >60s 10m | endpoint, role, database inventory, collector flags/read-only account; replica rule only on declared replicas | isolated long transaction/lock/session load/XID/autovacuum-age fixture/paused replay → release/drain/restore age fixture/resume; exporter loss stays unknown | [coverage-database](#coverage-database) |
| MySQL: stock mysqld_exporter global status/variables, info_schema.innodb_trx, slave_status | `family-mysql.rules.yml`: MysqlConnections, MysqlLockWait, MysqlLongTransaction; `family-mysql-replica.rules.yml`: MysqlReplicaLag | connections >80% 10m; row lock waits >0 5m; transaction >300s 10m; lag >60s or stopped thread 10m | endpoint, version, engine, role, channel and collectors; no PostgreSQL vacuum on MySQL | isolated locks/long transaction/sessions/paused replica → release/drain/resume; missing transaction rows/NULL lag stay unknown | [coverage-database](#coverage-database) |
| HTTP: blackbox regex success and `probe_duration_seconds` | `family-http.rules.yml`: HttpContent, HttpLatency | content failure 5m; 15m empirical p95 >1s for 15m; ≥28 samples and baseline at 30s cadence | URL, method/status/body regex/cap, timeout, schedule | wrong body/delayed fixture response → expected body/<1s duration for full recovered window | [coverage-http](#coverage-http) |
| Internal certificates: blackbox TCP+TLS `probe_ssl_earliest_cert_expiry` | `family-internal-tls.rules.yml`: InternalCertExpiry | chain earliest expiry <14d 1h; renewal margin | internal endpoint, SNI/CA, separate from public scope | trusted short-lived fixture certificate → >14d certificate; handshake loss must not resolve | [coverage-internal-tls](#coverage-internal-tls) |

## Declaration and rendering

`definitions/coverage/applicability.json` explicitly covers labelwatch, crow,
testbed, bobcephala and servo. NOT_APPLICABLE declares no corresponding service
in this lane's scope; it is not a host-discovery claim. The brief says no current
host runs PostgreSQL/MySQL. Mail and authoritative-zone applicability must be
rechecked during activation. Other families are NOT_ACTIVATED, never implicitly
healthy. Every family/site needs an explicit state and reason.

Keep role, runtime, health/metrics, stores and schedules in the existing P2 service
declaration. Optional extensions would look like this; current P2 collectors do
**not** yet consume these new extension fields:

```toml
name = "example-api"
role = "HTTP API"
runtime = {systemd = "example-api.service"}
[coverage.http]
state = "APPLICABLE"
check = "content"
url = "http://127.0.0.1:8080/health"
body_regex = "expected public marker"
interval_seconds = 30
[coverage.log]
state = "APPLICABLE"
check = "journal"
patterns = {error = "failed to commit"}
interval_seconds = 60
[coverage.postgres]
state = "NOT_APPLICABLE"
reason = "Service uses SQLite"
```

The activation lane projects explicit desired scope to the controller JSON.
Start from one site's complete `applicability.json` entry. Replace only selected
entries, for example `http` with:

```json
{"state":"APPLICABLE","reason":"Declared fixture API","checks":[
  {"service":"example-api","check":"content"}]}
```

Run `python3 definitions/coverage/render.py site.json > selected.yml` from
`mvp/labelwatch-host`. SOA checks additionally require `serial`; log checks
`pattern`; MySQL replica checks `channel`; table-autovacuum checks `database`, `schema`, `table` (SQL identifiers). Each resolver/name, endpoint, channel
or log pattern gets a separate check. The renderer requires all families,
rejects malformed/duplicate checks and target overflow, and produces review
material only. It never installs, activates or pins anything. The activating
lane must add declaration integration, package scheduling, scrape configuration,
render/pin through #95, crosswalk ownership and effective local attention input.

All 14 new files and P3's three service files remain in `NOT-DECLARED.txt` with
“defined, not activated on any site”. Never install `rules/*.yml` by glob.
Existing installers are unchanged; the activating lane must select rendered
files explicitly. No estate or declared-policy pins change here.

Stock scrape labels must include `site`, `service`, `check`. DNS pairs additionally
use `probe_kind=answer|nxdomain`; SOA uses `probe_kind=soa`. Other checks use their
own dedicated scrape/check without probe_kind. Do not share a check identity
between physical endpoints. DB aggregates require a complete database inventory
and one exporter target per check. Primary roles do not enroll replica families.
MySQL rules use legacy `seconds_behind_master` / `slave_*_running` names; newer
source/replica variants need reviewed relabeling. NULL lag must stay missing.

Each expression is a literal obligation `vector(1) unless on() (clear evidence)`
with stable rendered labels. It survives total metric disappearance independently
of declaration/limit producers. Firing means measured violation **or unavailable
evidence**, as each summary states. Classify with the underlying series:

| State | Meaning |
|---|---|
| NOT_APPLICABLE | Authored absent service; no emitted rule |
| NOT_ACTIVATED | No active claim; no emitted rule |
| Missing | Required metric/result absent; no clear |
| Stale | Sample older than 120s, or producer observation older than 180s (updates 7200s); future/invalid timestamps also unavailable |
| Warming | Missing offset baseline, changed journal epoch, insufficient latency history; no clear |
| Observed violation | Valid fresh observation outside threshold; hold applies |
| Clear | All required fresh valid observations within bound; permits resolution |

No finite historical latch or `or vector(0)` fabricates clear. Violation → unknown
retains the same labels/value and therefore cannot resolve. Cold unknown checks
can fire after their hold; inspect the evidence state before diagnosing. Multiple
checks retain labels in vmalert; Attention currently groups by alert name/site.
Per-check incident presentation is outside this lane. Evaluator/store loss still
requires P12; a query cannot supervise its own missing engine.

## Producer and packaging contract

`definitions/coverage/textfile.py --config check.json --out check.prom` runs
bounded read-only acquisition and atomic output replacement. `--fixture input.json
--now SECONDS` bypasses commands for tests. Config for journald:

```json
{"kind":"journal","site":"testbed","service":"example-api","check":"journal",
 "unit":"example-api.service","patterns":{"error":"failed to commit"},
 "state":"/var/lib/constellation-coverage/example-api-journal.json"}
```

Kinds `updates`, `postfix`, `exim` use the same identity fields without unit,
patterns or state. Metrics are `coverage_{security_pending,reboot_required,
kernel_mismatch,queue_messages,log_matches_total,log_epoch_seconds}` and
`coverage_{collection_success,observation_timestamp_seconds}`. Pattern labels
contain authored IDs only. Failures replace old facts with success=0 and omit
measurements. No metric/error/stdout contains journal text, mail contents, queue
IDs, package names or kernel strings. State stores counters/cursor, never logs.

Journal bounds: ≤16 literals of ≤128 characters, 1024 records, 4 MiB, 15s command
timeout; only the exact child is killed. Counts measure matching records, not
occurrences. Persist state before metrics. Restart retains epoch; state loss
needs a fresh hour. Overflow, malformed input, changed patterns or cursor failure
stays unavailable; operator investigation precedes explicit reseeding. Empty
initial intervals use previous acquisition time until a cursor exists. A
single-writer systemd service is required. The producer checks the exact saved cursor with an inclusive one-entry read before
collecting the subsequent interval. Actual systemd version behavior and journal
access remain testbed qualification work; gaps are not reconstructed.

Updates use distro python3-apt, local cache, an index-update-success stamp ≤48h
and `/vmlinuz` selecting an installed boot kernel. Missing inputs are unknown.
Security pending counts upgradable packages whose candidate has a `-security`
origin, not CVEs or pinned-out candidates. Kernel mismatch compares selected
installed and running versions; it does not establish which is newer.

The activation lane owns account/ACL access, tool paths and node_exporter's
textfile directory. Use one oneshot systemd service per check, 60s timer (updates
1h), `TimeoutStartSec=20s`, `MemoryMax=128M`, `NoNewPrivileges=yes`,
`ProtectSystem=strict`, write access only to its output/state directories and
journal read access only where needed. Failed output replacement must fail the
service. These producers install nothing, reboot nothing, submit/delete no mail
and never open SQLite. Scheduling and tool/OS integration are not activated here.

<a id="coverage-dns"></a>
## DNS operator checks

Check observation age, then `probe_dns_query_succeeded` on the answer probe.
Zero means no completed exchange from this vantage, not proof the resolver
process is down. With a completed exchange, success on the NXDOMAIN-only probe
identifies NXDOMAIN. NOERROR+RR expectation failure means an unexpected answer
or another RCODE. Inspect blackbox debug on the testbed and the declared
name/type/regex/resolver before correcting configuration through its owner.
Paired probes occur at different times; inconsistent results need another sample.

Compare authoritative SOA to the declared expected serial and RR expectation.
Equality is intentional: serial arithmetic wraps, so subtraction is not elapsed
drift. Review intentional serial changes. These rules do not prove all DNS
clients work, the zone is lost or the resolver process died. Restore fresh
expected answers in each independent drill; include evidence loss mid-fault.

<a id="coverage-log"></a>
## Journal pattern operator checks

Check success, age, epoch and both one-hour counter endpoints first. Reset,
cursor failure and insufficient history are unknown/warming, not zero matches.
Read bounded service journal records under normal operator access to interpret
the literal. A string match alone proves neither application failure nor a
security event. Fix the underlying cause or review a noisy authored pattern;
verify a recovered full hour. Drill restart, overflow and malformed input too.

<a id="coverage-updates"></a>
## Update and reboot operator checks

Check index age/cache success, pending candidate origins, reboot marker and
selected/running kernels. Arrange ordinary approved maintenance if needed,
then verify fresh zero counts, absent marker and matching kernel. The rule
neither authorizes install/reboot nor proves vulnerability, boot success or a
safe restart. The 24h hold accommodates maintenance, not emergency CVE policy.
Fixture long holds are a plan; actual distro cache/reboot recovery needs a drill.

<a id="coverage-smtp"></a>
## SMTP operator checks

Inspect port, expected banner/EHLO and SNI/trust configuration. The example
checks STARTTLS advertisement and upgrade without authentication or submission.
Inspect queue counts first; they measure messages, not bytes/age or remote
acceptance. A high queue does not identify delivery, spam, auth or disk causes.
The MTA owner chooses remediation. Restore fixture protocol behavior and drain
only the isolated test queue through its normal path; verify fresh counts.
Malformed output is unknown. The observer never flushes or deletes mail.

<a id="coverage-database"></a>
## Database operator checks

Check exporter/result freshness, identities, inventory, role and access first.
SQLite reuses P1 geometry. Project `coverage_sqlite_write_lock_held` only from
an approved saved-check result with store identity, success and observation time.
This lane adds no generic detector: never `BEGIN IMMEDIATE`, open writable or
create `-wal`/`-shm`. A check unable to report this fact read-only stays unavailable.
A held writer lock alone does not prove contention; absence of a qualified check
must not be silently converted to NOT_APPLICABLE.

For PostgreSQL inspect active/idle transaction durations, max connections,
access-exclusive locks, frozen XID age and replica replay. Sustained exclusive
locks include ordinary DDL, not proof of blocked clients. Frozen XID age is in
transaction IDs, **not seconds**: 150M is an initial margin before the common
200M freeze horizon; review the actual setting before activation. It does not
measure table bloat or dead tuples. The separate declared-table rule measures last-autovacuum time against a 24h expectation only for tables whose owner declares that schedule. Zero/NULL/never or future autovacuum times are unavailable, never clear. Review quiet/new tables rather than asserting autovacuum failure from age alone.
Use `pg_database_wraparound_age_datfrozenxid`; legacy `_seconds` names are not time.

For MySQL inspect InnoDB lock waits/oldest transactions, connection limits and
the declared channel's IO/SQL state and lag. Pin a version with the
`info_schema.innodb_trx` collector. Versions emitting no transaction rows when
idle remain unknown for that rule until an explicit zero contract exists;
never fabricate zero. MySQL has no PostgreSQL autovacuum: vacuum is
NOT_APPLICABLE by engine. Lag is not data equivalence or absence of data loss.
NULL lag/stopped threads cannot clear. The observer never cancels queries,
checkpoints, vacuums or repairs replicas. The DB owner chooses those actions.
Restore each isolated fault and verify both rule and incident recovery.

<a id="coverage-http"></a>
## HTTP operator checks

Check URL, method, status/body regex, cap and timeout. Success observes the
configured response from this island, not useful application work. Duration
p95 is an empirical quantile of periodic **whole-probe duration** samples, not
application request histogram p95 or a client-wide SLO. Inspect sample count,
baseline and DNS/connect/TLS/transfer phases before attributing latency. Missing
baseline is warming. Restore the fixture handler/body for a complete recovered
window. P3/product concerns own useful-work obligations.

<a id="coverage-internal-tls"></a>
## Internal certificate operator checks

Inspect SNI, trust and the observed chain's earliest expiry. Failed handshake or
missing expiry is unknown and cannot resolve a prior alert. Arrange normal
renewal/reload through the endpoint owner and verify a newly observed chain
with ≥14d remaining. This complements `PublicCertificateExpiryNear`, not proof
of renewal failure or universal client trust. Blackbox uses TCP with `tls: true`,
not a `tls` prober. Use the isolated short-lived trusted certificate drill.

## Source verification and formalization consideration

Primary contracts consulted on 2026-10-22:
[journalctl cursor and line semantics](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html),
[blackbox configuration](https://github.com/prometheus/blackbox_exporter/blob/master/CONFIGURATION.md),
[DNS metrics](https://github.com/prometheus/blackbox_exporter/blob/master/prober/dns.go),
[PG activity](https://github.com/prometheus-community/postgres_exporter/blob/master/collector/pg_stat_activity.go),
[PG locks](https://github.com/prometheus-community/postgres_exporter/blob/master/collector/pg_locks.go),
[PG XID age](https://github.com/prometheus-community/postgres_exporter/blob/master/collector/pg_database_wraparound.go),
[PG table autovacuum](https://github.com/prometheus-community/postgres_exporter/blob/master/collector/pg_stat_user_tables.go),
[PG replication](https://github.com/prometheus-community/postgres_exporter/blob/master/collector/pg_replication.go),
[MySQL replication](https://github.com/prometheus/mysqld_exporter/blob/main/collector/slave_status.go),
[MySQL transactions](https://github.com/prometheus/mysqld_exporter/blob/main/collector/info_schema_innodb_trx.go).
These moving links are name/semantic references, not installed version pins.
Actual versions, complete-scrape behavior and tools need activation qualification.

The proposition considered is bounded: while the evaluator runs, absence of a
rendered check's clear vector cannot remove its attention vector. Literal
expectation plus `unless on()` expresses it. Finite fixture tests cover input
failure/bounds, counters/restart, redaction, applicability, rendering, anchors
and targets. Prose and practical tests suffice for source delivery; exact
MetricsQL transitions, systemd/exporter behavior and end-to-end receipts remain
activation work. The activation lane owns independent acceptance. Outside scope:
evaluator/store failure, wrong authored identities, incomplete inventory and
incorrect exporter values. No action permission or distributed proof is claimed.
