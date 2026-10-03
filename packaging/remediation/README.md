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

## What a completion asserts

AG `completed` (and the consumer's `completed`) means: Docket settled the
one start as success, and an NQ ops-store evaluation taken at least
`postcondition_dwell_seconds` (default 15) after that settlement, and within
the resolver's 60 s freshness bound when AG asked, showed the unit loaded and
active. A unit that dies inside the dwell is never claimed (the episode
closes `postcondition_not_proven` at window end and the held page goes out).
It does not assert durable recovery: the evaluator resolves the condition only
after 120 s of continuous clear, and a relapse before that sends the held
page at window expiry.

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
- **The sandbox can write what bounds it (review F3).** The writable paths
  cover the grant use journal, Docket custody state, the AG campaign
  database, the executor attempt store and the NQ ops store that holds the
  pre- and postcondition evidence, and the process tree reads the AG issuer
  key. `docket` takes its standing resolver from argv (only `ag-loopctl`
  checks it against the profile). So `max_uses`, revocation and the
  independence of the postcondition hold only while the consumer binary is
  the reviewed one. The profile pins the resolver wrappers' bytes, not
  `constellation-nq-unit-resolver` or `nq`. Not yet mitigated: running the
  resolvers as `nq` via `systemd-run` (so `/var/lib/nq-ops` leaves
  `ReadWritePaths`) and Docket pinning its own standing resolver.
- **Torn grant journal entry (review F5).** A crash between the `O_EXCL`
  create and the write of `use-NNNNNN.json` leaves an empty entry; every
  later derivation then refuses (`journal-entry-document`) and remediation
  stops (fail closed, the evaluator pages). Repair is an owner step: enroll a
  new grant with a new, empty journal and a new pin (Docket
  `execution-standing-enrollment.md`, "Torn journal entry").
- **D-Bus address from the environment (review F6).** `ag-effectd` connects
  with `Connection::system()`, which honours `DBUS_SYSTEM_BUS_ADDRESS`. The
  consumer clears the environment of every command, which is the only thing
  pinning the executor to `unix:path=/run/dbus/system_bus_socket` today.
- **Grant has no rate limit.** Per-episode attempts are bounded by the
  consumer and by `max_uses`; choose a small `max_uses` and a short validity.
- **Start only.** v1 starts a not-active unit (prestates enrolled per plan);
  it never restarts an active-but-wedged unit.
