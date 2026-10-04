# constellation-attention packaging

`constellation-attention` evaluates a closed registry of operator-attention
rules over qualified, current Constellation state once a minute and asks NQ to
deliver the resulting notifications. See `docs/ATTENTION.md` for the rules,
lifecycle and boundary.

What it is: a oneshot reader of host-posture status objects, NQ's status
export, the Nightshift observation store and NQ saved-check results, plus a
caller of `nq notification submit|resubmit|deliver-local`.

What it is not: an evidence, observation or execution authority, a policy
language, a rules engine, a daemon, an HTTP client or a reader of Classic NQ.
It stores no secrets and never contacts Slack, Discord or PagerDuty itself.

## Files

| File | Installed as |
|---|---|
| `constellation-attention` (release binary) | `/usr/bin/constellation-attention` |
| `constellation-attention.service` | `/lib/systemd/system/` |
| `constellation-attention.timer` | `/lib/systemd/system/` |
| `attention.toml.example` | `/etc/constellation-attention/attention.toml.example` (package conffile); copy to `attention.toml` and edit |
| `docs/ATTENTION.md`, `README.md` | `/usr/share/doc/constellation-attention/` |
| `build-deb.sh`, `debian/` | the Debian package recipe (below) |

`build-deb.sh` follows the host-posture package recipe on the packaging
branch (`packaging/build-deb.sh`).

## Requirements

NQ 0.2.2 or later. This build writes `response_class` into every intent;
NQ 0.2.1 refuses unknown intent fields, so it would refuse every intent
before custody and nothing would be delivered. Do not install the evaluator
against an older NQ; upgrade NQ first. A page retained by an earlier build
of the evaluator is re-rendered with `response_class` on its next retry
(ATTENTION.md, Routing).

## Build the Debian package (hermetic, Ubuntu 22.04)

The package is built from a `git archive` export of one commit, inside the
local `jammy-packager:1` image (ubuntu:22.04 with rustup 1.94.0, the image
the NQ 0.2.x bundles are built in), with no network. The image carries no
cargo registry, so the export is vendored on the host first:

```sh
commit=$(git rev-parse HEAD)            # the commit to package
src=$(mktemp -d)
git archive "$commit" | tar -x -C "$src"
( cd "$src" && mkdir -p .cargo && \
  CARGO_NET_OFFLINE=true cargo +1.94.0 vendor --locked vendor > .cargo/config.toml )
docker run --rm --network none -v "$src":/work -w /work \
  -e MONITOR_SOURCE_COMMIT="$commit" \
  -e SOURCE_DATE_EPOCH="$(git log -1 --format=%ct "$commit")" \
  jammy-packager:1 bash -c '
    cargo build --release --locked --offline -p constellation-attention &&
    packaging/attention/build-deb.sh 0.1.0 amd64 target/release dist;
    rc=$?; chown -R '"$(id -u):$(id -g)"' /work; exit $rc'
ls "$src/dist"   # constellation-attention_0.1.0_amd64.deb and .sha256
```

`build-deb.sh VERSION ARCH BIN_DIR OUT_DIR` refuses a binary whose
`--build-info` does not carry that version, `minimum_nq` 0.2.2 and a source
commit. The package contains `/usr/bin/constellation-attention`, the unit
and timer under `/lib/systemd/system/`,
`/etc/constellation-attention/attention.toml.example` (a conffile; the live
`attention.toml` is never packaged) and `ATTENTION.md` and this README under
`/usr/share/doc/constellation-attention/`. It `Depends: nq-ng (>= 0.2.2)`.
The postinst only creates `/var/lib/constellation-attention` (0700 nq:nq)
when the `nq` account exists and reloads systemd; it never writes
configuration or secrets and never enables or starts the timer. Purge
removes the state directory. Install with `sudo apt install
./constellation-attention_0.1.0_amd64.deb`, then continue at "Qualify before
enabling" (copy the example to `attention.toml` and create
`nq-routes.env` as below).

## Install (by hand)

```sh
cargo +1.94.0 build --locked --release -p constellation-attention
sudo install -m 0755 target/release/constellation-attention /usr/bin/
sudo install -m 0644 packaging/attention/constellation-attention.{service,timer} /lib/systemd/system/
sudo install -d -m 0755 /etc/constellation-attention /usr/share/doc/constellation-attention
sudo install -m 0644 packaging/attention/attention.toml.example /etc/constellation-attention/attention.toml
sudo install -m 0644 docs/ATTENTION.md /usr/share/doc/constellation-attention/
# Route locators named by the NQ routes, e.g. NQ_OPERATIONS_WEBHOOK_URL=... and
# NQ_PAGERDUTY_OPS_ROUTING_KEY=...; never commit or print these.
sudo install -m 0600 /dev/null /etc/constellation-attention/nq-routes.env
sudoedit /etc/constellation-attention/nq-routes.env /etc/constellation-attention/attention.toml
sudo systemctl daemon-reload
```

The configuration must not be group- or other-writable. The NQ configuration
named in `[nq] config` must define the `notice_route` (slack, discord or
local_file) and, if set, the `page_route` (pagerduty) as described in NQ's
`NOTIFICATIONS.md`.

The unit writes NQ's notification custody into NQ's store, so its
`ReadWritePaths=` must name the parent directory of `database_path` in that
NQ configuration. The packaged unit names `/var/lib/nq-ops` (the Linode:
`/etc/nq/nqd-ops.toml`, `database_path = "/var/lib/nq-ops/nq.db"`) and an
optional `-/var/lib/nq`. A host whose store lives elsewhere needs a drop-in
(`systemctl edit constellation-attention.service`); otherwise every
submission fails as `command_error`.

NQ status: on an operated store use `source = "evaluation_history"` (the
example configuration does). `nq status export` walks the whole evaluation
history (nq#20): on reference-host it took 60-90 s under contention, and
every pass read the input as not current or timed out, so every NQ
condition was unknown. Evaluation-history pages answer in about 0.2 s. NQ
filesystem capacity watchers (for example `fs-zonestorage`) raise
`host-disk:<instance id>`. In that mode every NQ watcher ever seen is
remembered in the state and stays stale once it stops evaluating; when a
watcher is removed from NQ on purpose, add its instance id to
`retired_instances`. Keep `window_records` above `stale_after_seconds` worth
of every watcher's evaluations (production uses 600) and re-check it when
watchers are added. Do not give a host-posture input the label of an NQ
filesystem watcher id.

Saved checks: each configured reference reads one raw `nq --json
saved-check evaluate REF ...` document. On the Linode the check timer writes
one per reference at `/var/lib/nq-ops-results/<reference>.json`; the
`latest.json` run summary is not accepted (see ATTENTION.md,
`sqlite-health`).

## Qualify before enabling

1. `constellation-attention rules` shows the registry and versions.
2. `sudo -u nq constellation-attention check-config --config /etc/constellation-attention/attention.toml`
   validates the configuration and prints the effective rules and policy digest.
3. `sudo -u nq constellation-attention evaluate --config /etc/constellation-attention/attention.toml --dry-run`
   reads every input, writes `/var/lib/constellation-attention/dry-run/report.json`
   and runs no `nq notification` command (an `nq_status.command` input
   still runs `nq evaluations export`, or `nq status export` in
   `status_export` mode). Every input should be `ok`; fix any
   `unavailable` or `not_current` first. A dry run continues from saved
   state, so on a fresh install it shows no intents: nothing has persisted
   past a bound yet.
4. Qualify delivery against a local inbox, so no test notice reaches a
   production channel. In the NQ configuration add a `local_file` route
   (for example `reference = "attention-test"`, `transport = "local_file"`,
   `local_inbox_directory = "/var/lib/nq-ops-attention-test-inbox"`). NQ
   validates that directory as daemon-owned (`nq:nq`) with exact mode `0711`
   and writes each message there as a `0600` file. The unit's
   `ProtectSystem=strict` sandbox makes it read-only, so `deliver-local`
   fails and the notice is retained as `failed` (seen on reference-host)
   until the inbox is listed in `ReadWritePaths=` with a drop-in:

   ```sh
   sudo install -d -m 0755 /etc/systemd/system/constellation-attention.service.d
   printf '[Service]\nReadWritePaths=/var/lib/nq-ops-attention-test-inbox\n' |
     sudo tee /etc/systemd/system/constellation-attention.service.d/qualification-inbox.conf
   sudo systemctl daemon-reload
   ```

   This drop-in belongs to the qualification profile only. Remove it (and
   `daemon-reload`) before moving to production routes; it must not be
   present in production. Set `notice_route = "attention-test"`,
   `notice_transport = "local_file"` and omit `page_route`, then
   `sudo systemctl start constellation-attention.service` for real passes.
   Notices go through `nq notification deliver-local` (destination
   `local-inbox:attention-test`) and land as files; inspect them with
   `nq --config /etc/nq/nqd-ops.toml notification inspect`. A by-hand
   `deliver-local` through such a route has been accepted on the Linode
   (route `attention-test`); this step qualifies the evaluator's own passes
   through it.

   If `[inputs.nq_status]` uses `path =` (a file written by a timer) rather
   than `command =`, the file must be readable by `nq` and must lie outside
   the unit's `ProtectHome=` paths: `/root` and `/home` are invisible to the
   unit, so a file there reads as `unreadable`.
5. With the production routes and `network_enabled = false`, one real pass
   retains intents as NQ refusals (`network_dispatch_not_explicitly_enabled`)
   and sends nothing.
6. Set `network_enabled = true` and send one deliberate test through each NQ
   route by hand (NQ's runbook) to confirm the routes, then
   `sudo systemctl enable --now constellation-attention.timer`.
7. Watch `journalctl -u constellation-attention`, `report.json` and
   `constellation-attention state --config ...`. A unit in `failed` state
   (exit 3) means an input is not current, a delivery was not accepted or a
   trigger was dropped; exit 1 means the pass could not run (state lock,
   malformed state, clock moved backwards). After a corrected forward clock
   step, confirm the clock and run `sudo -u nq constellation-attention
   reset-clock --config /etc/constellation-attention/attention.toml`
   (ATTENTION.md, Clock); never delete the state.

`TimeoutStartSec` follows `(I + S) x command_timeout_seconds + 60`, with I
command inputs (nq_status command plus saved-check commands) and S
submissions in one pass; the unit assumes I <= 2 and S <= 6 (780 s). Raise
it with a drop-in for more command inputs.

Operator acceptance: nothing in the estate watches this unit. A pass that
cannot run fails every minute with no report and no notification, and an
NQ `nq.systemd_unit` watcher cannot see a oneshot unit. The liveness signal
is the age of `/var/lib/constellation-attention/report.json`; the status site
or renderer that reads it is responsible for flagging a report older than a
few minutes. The unit has a commented `OnFailure=` for an optional local
handler.

Input labels are at most 34 bytes (they form `{label}.{fault class}` input
notice keys).

Remove: `systemctl disable --now constellation-attention.timer`. The state
directory holds only condition state, the last report and intent files.
