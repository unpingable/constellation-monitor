# constellation-remediation packaging

Bounded Autonomous Remediation v1 (cartography
`architecture/bounded-autonomous-remediation.md`): one condition
(`service-down` of one enrolled unit), one fix (one governed systemd Start of
exactly that unit), decided deterministically. The package carries:

| File | Installed as |
|---|---|
| `constellation-remediation-consumer` | `/usr/bin/` |
| `constellation-nq-unit-resolver` (AG typed-v3 observation resolver over NQ ops-store `nq.systemd_unit` v2 evaluations; `--claim not-active` precondition, `--claim active` postcondition) | `/usr/bin/` |
| `nq-ops-as-nq` (runs `nq` as `nq` in nqd's sandbox over `/var/lib/nq-ops`; used for `nq collect`) | `/usr/libexec/constellation-remediation/` |
| `constellation-remediation-consumer.{service,timer}` | `/lib/systemd/system/` |
| `consumer.toml.example` | `/etc/constellation-remediation/` (conffile) |

Installation is inert: no configuration, AG profile, catalog, plans, keys,
Docket trust or grant, and the timer is neither enabled nor started.

## Build (hermetic, Ubuntu 22.04)

As for `packaging/attention` (see its README): vendor a `git archive`
export on the host, then build inside `jammy-packager:1` with
`--network none`:

```sh
commit=$(git rev-parse HEAD); src=$(mktemp -d)
git archive "$commit" | tar -x -C "$src"
( cd "$src" && mkdir -p .cargo && \
  CARGO_NET_OFFLINE=true cargo +1.94.0 vendor --locked vendor > .cargo/config.toml )
docker run --rm --network none -v "$src":/work -w /work \
  -e MONITOR_SOURCE_COMMIT="$commit" \
  -e SOURCE_DATE_EPOCH="$(git log -1 --format=%ct "$commit")" \
  jammy-packager:1 bash -c '
    cargo build --release --locked --offline \
      -p constellation-remediation-consumer -p constellation-remediation-resolver &&
    packaging/remediation/build-deb.sh 0.1.0 amd64 target/release dist;
    rc=$?; chown -R '"$(id -u):$(id -g)"' /work; exit $rc'
```

## Runtime premises (declared)

- **Same root.** The unit runs `User=root`: the consumer, AG's issuer key,
  Docket's state, the grant journal and `ag-effectd` are all root on one
  host. The consumer holds no authority of its own; AG admits only the
  owner-pinned plan digests (`admitted_plans`), Docket derives standing only
  from the owner's bounded grant. Root can replace all of it.
- **Sandbox.** `ProtectSystem=strict`; writable: `/var/lib/constellation-remediation`
  (consumer state, AG campaign and archive, Docket state, executor attempt
  store, grant use journal) and `/var/lib/nq-ops` (SQLite `-shm` for the
  resolvers' reads). `/etc/constellation-remediation` and `/etc/nq` are
  read-only. Only `AF_UNIX` (the systemd bus).
- **Campaign lifecycle.** One AG campaign per condition episode at the path
  `ag-effectd.deployment.json` pins (`ag.database`). Before opening the next
  episode the consumer archives a finished campaign (completed, halted,
  settled, or observation pending) to `<database dir>/archive/<ms>-<pass>/`.
  `ag-effectd` refuses any issuance whose campaign is not the one at the
  pinned path, so an archived campaign's issuance can never execute. A
  completed occurrence cannot be continued, so continuation occurrences in
  one campaign are not used across episodes.
- **Refused dispatch wedges.** When Docket refuses custody (grant exhausted,
  revoked, expired) AG stays at `authorization_consumed`: AG has no halt from
  that state and the consumer never archives spent, unresolved authority.
  Later episodes abstain (`prior_campaign_unresolved`) and the evaluator
  pages at window expiry until the operator archives the campaign by hand
  (stop the timer; move `campaign.sqlite*` to `archive/`). Declared limit.
- **Start only.** v1 starts a not-active unit (prestates enrolled per plan);
  it never restarts an active-but-wedged unit.
