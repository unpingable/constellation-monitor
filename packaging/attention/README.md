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
| `attention.toml.example` | `/etc/constellation-attention/attention.toml` (edit) |
| `docs/ATTENTION.md` | `/usr/share/doc/constellation-attention/` |

The jammy Debian package for host-posture lives on the packaging branch
(`packaging/build-deb.sh`); this directory is the standalone recipe until the
binary is added there.

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
   and runs no `nq notification` command (an `nq_status.command` input still
   runs `nq status export`). Every input should be `ok`; fix any
   `unavailable` or `not_current` first. A dry run continues from saved
   state, so on a fresh install it shows no intents: nothing has persisted
   past a bound yet.
4. Qualify delivery against a local inbox, so no test notice reaches a
   production channel. In the NQ configuration add a `local_file` route
   (for example `reference = "attention-test"`, `transport = "local_file"`,
   `local_inbox_directory = "/var/lib/nq-ops/attention-inbox"`). NQ validates
   that directory as daemon-owned (`nq:nq`) with exact mode `0711` and writes
   each message there as a `0600` file; a directory outside the unit's
   `ReadWritePaths=` needs a drop-in. Set `notice_route = "attention-test"`,
   `notice_transport = "local_file"` and omit `page_route`, then
   `sudo systemctl start constellation-attention.service` for real passes.
   Notices go through `nq notification deliver-local` (destination
   `local-inbox:attention-test`) and land as files; inspect them with
   `nq --config /etc/nq/nqd-ops.toml notification inspect`. A by-hand
   `deliver-local` through such a route has been accepted on the Linode
   (route `attention-test`); this step qualifies the evaluator's own passes
   through it.
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
   malformed state, clock moved backwards).

Operator acceptance: nothing in the estate watches this unit. A pass that
cannot run fails every minute with no report and no notification, and an
NQ `nq.systemd_unit` watcher cannot see a oneshot unit. The liveness signal
is the age of `/var/lib/constellation-attention/report.json`; the status site
or renderer that reads it is responsible for flagging a report older than a
few minutes. The unit has a commented `OnFailure=` for an optional local
handler.

Remove: `systemctl disable --now constellation-attention.timer`. The state
directory holds only condition state, the last report and intent files.
