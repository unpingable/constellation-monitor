# Read-only diagnostic, first slice (P7)

The `constellation-monitored` package installs `/usr/bin/constellation-diagnostic`
and this guide at `/usr/share/doc/constellation-monitored/DIAGNOSTIC.md`. It adds
no diagnostic service. Run on the monitored host with Python 3.10 or newer
(standard library only, Linux). No model,
API key or provider is required. Use the existing rendered registry; declarations
and dependency edges remain expectations and grant no access or action authority.

```sh
constellation-diagnostic \
  --registry /etc/constellation-estate/estate.json \
  --attention /var/lib/constellation-attention/report.json \
  --vm-url http://127.0.0.1:8428 \
  --instance 127.0.0.1:9100 --job node \
  --record /path/to/new-investigation.json
```

For one condition add `--condition EXACT_ATTENTION_ID` (or
`--condition host.memory_pressure`). Add `--incidents PATH` for JSON from the
existing `constellation-incidents inspect` command. This diagnostic never opens
the incident SQLite database itself. Optional `--local-readers` reads only
`systemctl show` and 100 journald lines for up to five registry systemd units;
it executes no declaration/status argv, shell, container command, restart or
remediation. `--runbook PATH` reads a local runbook (repeat at most five times).
Unit state is context: active alone never proves productivity. Journals and
runbooks are retained excerpts, not automatically interpreted diagnoses.

The JSON result has four bins: wrong, probably wrong, checked and not wrong
within scope, and unknown. Findings cite source IDs. Sources retain locators,
SHA-256, byte counts and at most 8192 bytes of excerpt. A fresh attention
`present` condition is wrong only if active; a pending condition is probably
wrong. Unknown, removed or suspended conditions do not clear. Incidents are
retained history, never current service-health evidence. A missing condition
does not establish recovery. A declaration is never placed in the clear bin.

The host sweep also checks memory using five fixed range queries: occupied swap,
paging rate, memory waiting PSI rate, underlying sample age, and the five raw
required metric families. `--instance` and `--job` select the exact expected
node_exporter target in every query (use the host's actual scrape labels).
The registry's nonempty `site` is also selected in every query and checked in
every raw series; a missing registry site is unknown. Each required family must
supply exactly one series with those three labels and a
complete window; a missing family, mixed target or duplicate series from another
site is unknown. The range must
be ordered, finite and cover the window with no gap over 120 seconds; source
age must stay within `--max-age` (default 300 seconds). No paging and PSI zero
means no pressure **by those measures in the sampled window**. Paging or stalls
are symptoms requiring investigation, not a root cause or automatic severity
threshold. Empty, stale, gapped, malformed and missing history is unknown.
The explicit target labels select observations; they do not authenticate target
identity or establish coverage of other expected targets. They do not cover OOMs, memory
capacity or service productivity. Cross-service causal inference is not delivered.

For one declared worker's useful-work history, select the service and its actual
scrape target instead of the memory sweep:

```sh
constellation-diagnostic \
  --registry /etc/constellation-estate/estate.json \
  --attention /var/lib/constellation-attention/report.json \
  --vm-url http://127.0.0.1:8428 \
  --service demo-worker --instance 127.0.0.1:18080 --job service-demo-worker \
  --record /path/to/new-worker-investigation.json
```

`--service` and `--condition` are alternative selections. A direct application
endpoint normally uses the existing declaration renderer's `service-<name>` job;
application textfiles use their actual node_exporter instance/job. The exact
site and service come from the approved registry. The worker must already supply
the standard `service_last_success_timestamp_seconds` (last committed useful
work) and `service_observation_timestamp_seconds` (application observation
clock), with declared positive `last_success_age_seconds` and
`metrics_observation_age_seconds` thresholds.
A counter alone has no generic useful-work meaning here; the application records
its successful-work timestamp when its own commit succeeds. No Constellation
library, agent-status protocol or process attribution is introduced.

The diagnostic makes four bounded range queries: both timestamp families and
the underlying scrape sample time of each. Each must contain exactly one
complete, aligned history for the selected site/service/instance/job. Missing,
duplicated, wrong-target, stale, future, nonfinite, gapped or backwards/reset
history is unknown. A fresh scrape of a frozen application textfile cannot prove
fresh application observations. Missing declarations or either authored limit
also remain unknown. These are source-labelled observations, not authentication
of the exporter or proof that its claim is true.

Fresh application observations with an overdue committed-work timestamp produce
`probably_wrong`, naming the observed age and the authored useful-work budget.
Timestamp advancement with a latest success inside that budget supports only
sampled progress (`checked_not_wrong_within_scope`). No advancement inside an
unexpired budget is unknown: quiet work is not a stall finding. An active unit
or HTTP 200 cannot replace useful-work observations, establish worker loss or
identify a failure cause. Optional unit/journal reads remain context; this
command does not perform health probes, execute declaration/status argv, restart
work, retry work or change any authority. Service mode has at most 32 sources /
96 seconds of reader budget, and never expands into unrelated service queries.

For offline replay, `--metrics-fixture` reads `service_work.json`,
`service_observation.json`, `service_work_source_time.json` and
`service_observation_source_time.json` as captured `query_range` responses.
The result retains each response's query/path, byte hash and excerpt. The
operator owns the investigation record and retires it when its incident/replay
dependency ends. Local HTTP fixtures exercise fresh progress and overdue useful
work while the fixture's health endpoint still returns 200; they do not claim
an installed worker or live VictoriaMetrics acceptance. The root disposable
operator campaign owns that separate runtime demonstration.

The CLI accepts literal loopback HTTP only, disables proxies and redirects, and
performs GET query_range requests. Each source has a hard three-second deadline
and a 1 MiB cap. Registry services are capped at 100; conditions/incidents at
1000; the investigation reads at most 33 sources (99 seconds of reader budget
at maximum settings, plus finite parsing/record work). Window is 300–3600
seconds. Units can be reduced with `--unit-limit` (0–10). Missing access becomes
unknown; this command does not request more authority. A socket/reader failure
never becomes clear. The dedicated CLI uses SIGALRM and must run in the main
thread without another in-process alarm user.

`--record` is mandatory and exclusive; reuse fails. A mode-0600 pending question
is fsynced before reads. Successful completion replaces it atomically with the
asked question, exact reader settings, evidence and findings. An interrupted
investigation may leave a pending record; that is incomplete, not a result.
Exit 0 means a completed investigation, including unknown findings, **not** a
healthy host. Exit 3 means incomplete. Records/excerpts can contain operational
information; the invoking operator owns their destination and retirement once
the incident/replay dependency ends. Stdout contains the same final JSON.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s diagnostic -v
```

The committed swap fixture reconstructs the qualitative 2026-10-19 case:
occupied swap, zero paging and zero PSI. It is synthetic observation data at
2026-10-20 00:00 UTC, not a retained production capture or proof of that host's
history. Tests replay it at its captured time and remove history as the negative
control. The HTTP test uses a temporary loopback server. P6's unfamiliar
application and controller-disconnected live witness remain later acceptance; this
source delivery does not claim P7's full product acceptance or production use.
