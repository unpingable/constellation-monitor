# constellation-attention packaging

`constellation-attention` evaluates a closed registry of operator-attention
rules over qualified, current Constellation state once a minute and asks NQ to
deliver the resulting notifications. See `docs/ATTENTION.md` for the rules,
lifecycle and boundary.

What it is: a oneshot reader of host-posture status objects, NQ's status
export, the Nightshift observation store and NQ saved-check results, plus a
caller of `nq notification submit|resubmit`.

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
named in `[nq] config` must define the `notice_route` (slack or discord) and,
if set, the `page_route` (pagerduty) as described in NQ's `NOTIFICATIONS.md`.

## Qualify before enabling

1. `constellation-attention rules` shows the registry and versions.
2. `sudo -u nq constellation-attention check-config --config /etc/constellation-attention/attention.toml`
   validates the configuration and prints the effective rules and policy digest.
3. `sudo -u nq constellation-attention evaluate --config /etc/constellation-attention/attention.toml --dry-run`
   reads every input, writes `/var/lib/constellation-attention/dry-run/report.json`
   and the intents it would submit, and runs no `nq` command. Every input
   should be `ok`; fix any `unavailable` or `not_current` first.
4. With `network_enabled = false`, `sudo systemctl start constellation-attention.service`
   runs one real pass: intents are retained by NQ as refusals
   (`network_dispatch_not_explicitly_enabled`) and nothing is sent. Inspect
   with `nq --config /etc/nq/nqd-ops.toml notification inspect`.
5. Set `network_enabled = true` and send one deliberate test through each NQ
   route by hand (NQ's runbook) to confirm the routes, then
   `sudo systemctl enable --now constellation-attention.timer`.
6. Watch `journalctl -u constellation-attention`, `report.json` and
   `constellation-attention state --config ...`. A unit in `failed` state
   (exit 3) means an input is not current or a delivery was not accepted.

Remove: `systemctl disable --now constellation-attention.timer`. The state
directory holds only condition state, the last report and intent files.
