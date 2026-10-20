# Read-only diagnostic, first slice (P7)

Run on the monitored host with Python 3 (standard library only, Linux). No model,
API key or provider is required. Use the existing rendered registry; declarations
and dependency edges remain expectations and grant no access or action authority.

```sh
python3 diagnostic/constellation-diagnostic.py \
  --registry /etc/constellation-estate/registry.json \
  --attention /var/lib/constellation-attention/report.json \
  --vm-url http://127.0.0.1:8428 \
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

The host sweep also checks memory using four fixed range queries: occupied swap,
paging rate, memory waiting PSI rate, and underlying sample age. The range must
be ordered, finite and cover the window with no gap over 120 seconds; source
age must stay within `--max-age` (default 300 seconds). No paging and PSI zero
means no pressure **by those measures in the sampled window**. Paging or stalls
are symptoms requiring investigation, not a root cause or automatic severity
threshold. Empty, stale, gapped, malformed and missing history is unknown.
VictoriaMetrics must contain only this host's intended node_exporter population:
the fixed queries aggregate that local store; they do not authenticate target
identity or establish expected scrape coverage. They do not cover OOMs, memory
capacity or service productivity. Cross-service causal inference is not delivered.

The CLI accepts literal loopback HTTP only, disables proxies and redirects, and
performs GET query_range requests. Each source has a hard three-second deadline
and a 1 MiB cap. Registry services are capped at 100; conditions/incidents at
1000; the investigation reads at most 32 sources (96 seconds of reader budget
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
application and crow-disconnected live witness remain later acceptance; this
source delivery does not claim P7's full product acceptance or production use.
