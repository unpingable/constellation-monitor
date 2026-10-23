# What is monitored on this host?

Run `constellation-monitored list`. Find your service, its runtime, how it is
observed, the last acquisition, and its verdict. The route says what would tell
you if it failed. `constellation-monitored show web` shows one service;
`constellation-monitored show HostIoPressureHigh` shows one alert rule. Use the
name printed by `list`. If rule names repeat, use its full `file/group/name`
identity. An unknown name exits 1 and explains that no matching declaration was
read. `list` and successful `show` exit 0 even when monitoring is degraded or
unknown; this command explains evidence, rather than acting as a health check.

For the browser, open `monitored.html` beside the host status page. The renderer
prints its generation time at the top. If that time stops advancing for more
than five minutes plus scheduler delay, treat this page as unknown and inspect
`systemctl status constellation-monitored.timer constellation-monitored.service`.
The page needs no JavaScript. Navigation and a linked glossary are included.
A static page cannot detect its own failure after it has been written.

Start by answering these questions:

1. Is the service listed? An entry from a declaration means someone intended to
   monitor it. Check its acquisition and verdict to see what actually arrived.
2. Does it have application concerns or just runtime state? An active systemd
   unit or healthy container alone does not establish that useful work is done.
3. What would tell you? Read the named route and handler, the rule's hold, and
   its runbook anchor. Configuration alone does not prove delivery. Inspect an
   actual incident with `constellation-incidents show <incident-id>`.
4. What is missing? Read **Not monitored**, including excluded unit patterns,
   declarations without acquisitions, missing required observations, and
   families with no mapped rule. An excluded unit is visible, not covered.
5. Is the family covered on this host? All five coverage columns need evidence;
   a source ledger saying “activated elsewhere” is insufficient.

`DEGRADED` means a required observation does not hold. `DOWN` means the runtime
was down. `PAUSED` is a declared pause, not a health assertion. `UNKNOWN` means
the answer cannot be established. Missing files, unsupported schemas, stale or
future reports, a different site, changed registry bytes, policy drift, an
unevaluated rule, failed evaluation health and absent series all show the cause.
A fresh collection never refreshes an expired application observation.

Value-coded metric rules carry `constellation_value_codes = "v1"`. Code 1 is
present when firing; pending retains the rule's hold. Codes 2 (acquisition
failed), 3 (missing series), 4 (stale/future) and 5 (invalid/warming) remain
unknown. Unsupported codes and missing complete counts also remain unknown.
Unmarked metric rules retain raw numeric values; a value of 2 is not interpreted
as acquisition failure there. Counts are checked before bounded instance detail,
so an omitted instance cannot hide a missing observation. Instances on other
sites do not establish this host's state. Attention's report also shows compiled
rules and their effective persistence and condition notes. An absent condition
never establishes recovery.

## Inputs and scope

The command reads local files only. It executes no collectors or status
commands, contacts no service, and never opens notification credential files.
It publishes selected fields rather than entire configurations. Run it as an
account that can read the declarations and reports. The supplied systemd unit
uses root for those reads and writes only the status directory.

| Input | Default |
|---|---|
| Deployed estate registry | `/etc/constellation-estate/estate.json` |
| Acquired estate output | `/var/lib/constellation-estate/estate.json` |
| Optional service declarations | `/etc/constellation/services.d/*.toml` |
| Attention configuration | `/etc/constellation-attention/attention.toml` |
| Attention report | `/var/lib/constellation-attention/report.json` |
| Declared metric policy | `/etc/constellation-metric-alerts/declared-vmalert-policy.json` |
| Acquired metric alerts | `/var/lib/constellation-metric-alerts/metric-alerts.json` |
| Coverage family table | Packaged `COVERAGE-FAMILIES.md` |
| Optional host coverage receipts | `/etc/constellation-monitored/coverage.json` |

Global options precede `list`, `show`, or `render`: `--registry`, `--estate`,
`--services-dir`, `--attention-config`, `--attention-report`, `--policy`,
`--metric-alerts`, `--ledger`, and `--coverage-evidence` override those paths.
`--site` requires the expected site identifier; otherwise the local registry
supplies it. `--max-age` defaults to 600 seconds for reports; estate and metrics
use attention's configured bounds where supplied. `--now` takes an RFC3339 time
for reproducible offline inspection. `--help` describes the source-defined flags.

The estate acquisition must carry the SHA-256 of the exact registry bytes read.
A local service declaration differing from that registry remains unknown until
it is reconciled and acquired. Synthetic estate coverage/definition rows are
included. Probes and producers listed here are the registry's status producers,
HTTP checks, declared timers, and configured attention inputs. The acquisition
is the inventory authority: the page does not scan systemd, Docker, repositories,
blackbox configuration, or the network. Probes/producers outside those inputs
cannot be enumerated; missing inventory is unknown. External supervision and
host-loss notification are explicitly unverified from these local inputs.

The effective metric policy must match both the canonical local declared policy
digest and a registry `vmalert-policy` pin. Rules are joined by file, group and
name. The attention policy's report digest and matching registry pin are shown
separately. Neither identity authorizes action. Routes show the configured
notice handler or page handler; Alertmanager delivery stays unknown because its
configuration and delivery receipts are not inputs. Probe URLs omit userinfo and
query parameters. Keep operational declarations free of secrets and apply the
status site's existing operator access policy before publishing service names.

Python 3.10 or newer is required. Python 3.11+ uses the standard TOML parser.
For 3.10, a bundled stdlib parser supports the deployed subset: strings,
booleans, decimal numbers, arrays, inline tables, dotted keys, tables and array
tables. Unsupported syntax such as multiline strings is shown as an unreadable
input; use Python 3.11+ for the full TOML language.

## Coverage evidence

The packaged table is an exact snapshot of Cartography's 46-row
`COVERAGE-FAMILIES.md`, from coverage integration commit `c760f82` as read on
2026-10-22. Its first table supplies family names and source context. Override
`--ledger` with a newer committed copy when the site release updates it. The
page never treats the ledger's development status as evidence about this host.

Existing host-pressure/substrate rule names have explicit family mappings.
Additional rules can carry `constellation_family` with the exact ledger family
name, or the host evidence file can map exact `[file, group, name]` triples.
Unmapped rules remain visible with an unknown family. A rule mapped to a family
is only a candidate: it does not establish the whole family's applicability or
scope. This reader does not decide that an unobserved family is inapplicable.

The ledger does not contain host-specific history, delivery, published-anchor,
or drill receipts. The site release can supply them in this additive document:

```json
{
  "schema": "constellation.monitored_coverage/v1",
  "site": "example",
  "policy_sha256": "sha256:<exact canonical vmalert policy digest>",
  "families": {
    "block I/O pressure": {
      "rules": [["host-pressure.rules.yml", "host-pressure", "HostIoPressureHigh"]],
      "observed": {"holds": true, "evidence": ["receipts/history.json#io-pressure"]},
      "routed": {"holds": true, "evidence": ["receipts/delivery.json#operator-receipt"]},
      "runbook": {"holds": true, "evidence": ["receipts/published-anchors.json#host-pressure"]},
      "drilled": {"holds": true, "evidence": ["receipts/drill.json#trigger-and-recovery"]}
    }
  }
}
```

These are explicit local release attestations covering the family's entire
host scope. The reader displays their pointers but does not fetch them, verify
signatures, or certify the contents. The release owner must retain the receipts
and verify their claims. A changed host or policy digest invalidates the
attestations. Families using compiled attention rules also require a matching
`attention_policy_digest` at the document root. Never put credentials in this document. Missing receipts remain
unknown. A family closes on this host only when all five hold:

- **Observed:** each mapped rule has fresh, healthy, usable evidence on this
  host, and the host/history scope receipt is present.
- **Declared:** all mapped rules are in the local declaration, the effective
  policy matches it, and the estate registry pins that exact identity.
- **Routed:** attention is configured, its report is current and not a dry run,
  network delivery is enabled through an external handler, and the delivery
  receipt is present. Drop and local qualification inboxes cannot satisfy it.
- **Runbook:** there is a safe published document URL with an anchor and a
  published-anchor receipt. An unpublished label remains visibly unknown.
- **Drilled:** the host/revision-scoped trigger and recovery receipt is present.

Closed here says nothing about other sites. No family is claimed closed by the
committed sample. Update delivery and drill receipts through the site's existing
release procedure; this page has no enrollment or mutation operation.

## Install and refresh

Build the package from this source checkout without a Rust build:

```sh
packaging/monitored/build-deb.sh 0.1.0 /tmp/monitored-debs
```

The `all` package depends only on Python 3.10+, includes the command, ledger,
glossary/operator documentation and systemd units. It installs no live
configuration, enables no services, and changes no site exposure. The site
installer owns activation and its output directory. On the target host:

```sh
sudo apt install ./constellation-monitored_0.1.0_all.deb
sudo install -d -m 0755 /var/www/constellation-status
sudo constellation-monitored render --out /var/www/constellation-status/monitored.html
sudo systemctl daemon-reload
sudo systemctl enable --now constellation-monitored.timer
```

`render --out` takes an HTML filename, creates its parent directory, writes a
mode-0644 temporary file, then atomically replaces that filename. It never
replaces `index.html`, `status.json` or `projection.sqlite`. A valid page of
unknown results is a successful render; an output-write failure exits nonzero
and leaves the previous page in place. The renderer's own timestamp must be
supervised independently. The timer runs after boot and every five minutes.
The supplied unit restricts writes to `/var/www/constellation-status`; when
choosing another output directory, update both `ExecStart` and `ReadWritePaths`
in a systemd override and create that directory first.

Rollback: disable `constellation-monitored.timer`, remove its package or install
the previous one, and remove only `monitored.html` if it is no longer used. The
reader creates no evidence store and does not change the monitoring producers.

## Offline sample and checks

From this checkout:

```sh
python3 monitored/sample.py --out /tmp/monitored-sample.html
umask 022
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s monitored -v
```

The sample uses the committed fixtures at the fixed time
`2026-10-22T21:01:00Z`. It shows a degraded web endpoint, an unacquired worker,
a local-only declaration, an unregistered unit, and a metric acquisition failure
(code 2). Fixture URLs and evidence references are examples, not deployment
claims. The metric definitions and runtime fields derive from the shared real
vmalert vector; estate and attention fields follow the collector and evaluator
report contracts. The attention declaration is copied from the testbed.

The human acceptance session has not run. Have an unfamiliar operator find
`web`, explain how it is observed, name the notification route, distinguish
`worker` from an acquired service, explain code 2, and explain why a ledger row
is still open. Score each step `obvious / reread docs / needed hint / blocked`.
No test count substitutes for that session.

Integration remains a site decision: should the status index link to
`monitored.html`, or should the Operations Board embed/link that same page?
This package supplies the standalone page without editing Cartography or the
Board. Published runbook content, receipt production, external supervision and
site activation remain with their owning release lanes.
