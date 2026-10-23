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
   a source-development claim is insufficient. Only labeled metric rule scopes
   are enumerated; unlabeled rules remain visible as gaps.

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
runs as `nq`, the same account that owns the mode-0600 attention configuration,
mode-0700 attention report directory, and existing status renderer. No root or
capabilities are needed. Packaging sets the status directory owner to `nq:nq`.
The unit empties its capability set, denies network access, restricts address
families to AF_UNIX, and applies all attention-unit process/kernel/filesystem
restrictions. Only the status directory is writable. Other release input paths
must grant `nq` read access; an unreadable input stays unknown.

| Input | Default |
|---|---|
| Deployed estate registry | `/etc/constellation-estate/estate.json` |
| Acquired estate output | `/var/lib/constellation-estate/estate.json` |
| Optional service declarations | `/etc/constellation/services.d/*.toml` |
| Attention configuration | `/etc/constellation-attention/attention.toml` |
| Attention report | `/var/lib/constellation-attention/report.json` |
| Declared metric policy | `/etc/constellation-metric-alerts/declared-vmalert-policy.json` |
| Acquired metric alerts | `/var/lib/constellation-metric-alerts/metric-alerts.json` |
| Release receipts index | `/usr/share/constellation/release/receipts/index.json` |

Global options precede `list`, `show`, or `render`: `--registry`, `--estate`,
`--services-dir`, `--attention-config`, `--attention-report`, `--policy`,
`--metric-alerts`, and `--receipts-index` override those paths.
`--site` requires the expected site identifier; otherwise the local registry
supplies it. `--max-age` defaults to 600 seconds for reports; estate and metrics
use attention's configured bounds where supplied. `--now` takes an RFC3339 time
for reproducible offline inspection. `--help` describes the source-defined flags.

The estate acquisition must carry the SHA-256 of the exact registry bytes read.
Service declaration bytes are compared with the registry's `service_declarations`
SHA-256 pins, keyed by service name and declaration filename. Matching pins keep
the collector-derived fields (health/metrics/store declarations are normalized
by that collector), and supply the displayed service revision. Without a pin,
only an exactly equal declaration/registry entry can inherit the acquisition.
A changed declaration remains unknown until reconciled and acquired. Synthetic estate coverage/definition rows are
included. Probes and producers listed here are the registry's status producers,
HTTP checks, declared timers, and configured attention inputs. The acquisition
is the inventory authority: the page does not scan systemd, Docker, repositories,
blackbox configuration, or the network. Probes/producers outside those inputs
cannot be enumerated; missing inventory is unknown. External supervision and
host-loss notification are explicitly unverified from these local inputs.

The effective metric policy must match both the canonical local declared policy
digest and a registry `vmalert-policy` pin. Rules are joined by file, group and
name. The attention policy's report digest and matching registry pin are shown
separately. When no `attention-policy` pin exists, the page shows the `file` pin
for the attention config and compares its exact bytes; it explicitly says the
effective policy digest is unverified. A matched file pin establishes that
configuration declaration only. Neither identity authorizes action. Routes show the configured
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

Families come exclusively from the nonempty `family` label in each declared
vmalert rule. Put the same label in the source YAML rule file so rendering and
loaded policy retain it, for example:

```yaml
labels:
  family: "block I/O pressure"
  attention: "true"
```

Use a stable, case-sensitive family name and apply it to every rule needed for
that scope. This is the `family` convention (not `constellation_family`); the
Cartography re-cut owns adoption in its rule sources. Unlabeled rules render a
family gap. No alert-name mapping, copied coverage ledger, manual host coverage
file, or inferred family for compiled attention rules participates in closure.
This page does not enumerate obligations absent from all supplied rule labels,
and cannot establish whole-estate completeness from this list.

Release assembly commits receipts and their index, ships them together under
`/usr/share/constellation/release/receipts/`, and keeps them read-only at runtime.
`--receipts-index` selects that release's index (also useful for offline review).
The reader never creates or edits receipts. The index schema is:

```json
{
  "schema": "constellation.monitored_receipts/v1",
  "receipts": [{
    "family": "block I/O pressure",
    "part": "observed",
    "site": "example",
    "policy_sha256": "sha256:<canonical vmalert policy digest>",
    "rules": [["host-pressure.rules.yml", "host-pressure", "HostIoPressureHigh"]],
    "path": "io-history.json",
    "sha256": "<64 lowercase hex digits: exact receipt bytes>"
  }]
}
```

`part` is one of `observed`, `routed`, `runbook`, `drilled`. `rules` is the sorted
list of exact `[file, group, name]` triples for **all** labeled rules in that
family. `path` is relative to the index directory; absolute paths, traversal and
symlinks escaping that directory cannot supply evidence. The reader checks the
file SHA-256 before accepting this receipt schema:

```json
{
  "schema": "constellation.monitored_receipt/v1",
  "family": "block I/O pressure",
  "part": "observed",
  "site": "example",
  "policy_sha256": "sha256:<canonical vmalert policy digest>",
  "rules": [["host-pressure.rules.yml", "host-pressure", "HostIoPressureHigh"]],
  "holds": true,
  "evidence": ["release history receipt identifier and retained scope explanation"]
}
```

The five scope fields must equal the index entry, `holds` must be true, and
`evidence` must contain nonempty strings. The release owner attests that the
retained material demonstrates the whole family scope on that site and revision.
The page displays those evidence references; it does not fetch references,
verify signatures, or certify the attestation's truth. A file digest binds bytes,
not authority. Missing, modified, wrong-scope or wrong-revision receipts render
**not demonstrated**. The committed sample index is empty and closes no family.

Closure also requires current supporting inputs:

- **Observed:** every rule has fresh, healthy, usable evidence plus a family
  history receipt.
- **Declared:** every rule is loaded with matching labels, and the effective
  policy matches both the local declaration and registry pin. This part is
  mechanically checked; no receipt can override a mismatch.
- **Routed:** current attention inputs, enabled external transport, and a
  family delivery receipt. Drop, dry run and local inboxes cannot satisfy it.
- **Runbook:** safe published URL and anchor plus a published-anchor receipt.
- **Drilled:** a release receipt of trigger and recovery for that family scope.

Closed here says nothing about other sites or unlabeled obligations. Receipt
production, commitment and release assembly remain with their owning lanes;
source tests and fixture receipts never establish deployed host coverage.

## Install and refresh

Build the package from this source checkout without a Rust build:

```sh
packaging/monitored/build-deb.sh 0.1.0 /tmp/monitored-debs
```

The `all` package requires Python 3.10+ and the existing `nq-ng` account/package,
and includes the command, glossary/operator documentation and systemd units. It installs no live
configuration, enables no services, and changes no site exposure. Its postinst
only creates `/var/www/constellation-status` owned by `nq:nq` and reloads
systemd unit definitions. The site installer owns activation and exposure. The status projection index links to
`monitored.html` in both current and unavailable views. Cartography's separate
Python status-site renderer needs the supplied
[`status-site-monitored-link.patch`](../packaging/monitored/status-site-monitored-link.patch)
in its re-cut; this lane validates the patch against a temporary copy of that
read-only source without changing Cartography. On the target host:

```sh
sudo apt install ./constellation-monitored_0.1.0_all.deb
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
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest monitored -q -p no:cacheprovider
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
`worker` from an acquired service, explain code 2, and explain why a labeled family
is still open. Score each step `obvious / reread docs / needed hint / blocked`.
No test count substitutes for that session.

Published runbook content, committed release receipts, external supervision,
and site activation remain with their owning release lanes. The status index
links the standalone page; the Operations Board may consume the same page.
