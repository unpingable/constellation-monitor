# Constellation Monitor local guide

Clone the canonical public repository and build the locked workspace:

```sh
git clone https://github.com/unpingable/constellation-monitor.git
cd constellation-monitor
cargo build --locked --workspace
```

Use these commands only against user-owned local trees and disposable local
fixtures. Rust 1.85 or newer and Cargo are required; the Linux `/proc`
examples additionally require Linux.

## Inspect without collecting

Discover declarations below a workspace, then inspect or validate one declared
project:

```sh
cargo run -p monitor-project-concerns --bin monitor-concerns -- discover /absolute/workspace --json
cargo run -p monitor-project-concerns --bin monitor-concerns -- inspect /absolute/project --json
cargo run -p monitor-project-concerns --bin monitor-concerns -- validate /absolute/project
```

These commands identify concern declarations and structural correspondence.
They do not acquire current evidence. Collection is explicit and requires both
an exact trusted root and `--allow-exec`:

```sh
cargo run -p monitor-project-concerns --bin monitor-concerns -- collect /absolute/project \
  --trusted-root /absolute/workspace --allow-exec --timeout-ms 10000 \
  --output-limit-bytes 1048576 --json
```

The collector runs only the declared bounded producer. Its output remains an
acquisition result, not mutation authority.

## Pulse and NQ support boundaries

Use `pulse-agent` or `pulse-runtime` for local demonstrations of ephemeral
pulses and receiver-owned expiry:

```sh
cargo run -p pulse-agent -- --profile synthetic --count 3 --cadence-ms 250
cargo run -p pulse-runtime -- demo
cargo run -p pulse-runtime -- restart-demo
```

The closed load-pressure family has separate producer, intake, and read-only
resolver roles. Producer and intake require an absolute configuration path and
an acquisition token:

```sh
cargo run -p pulse-nq-load-support -- produce --config /absolute/load-support.json --acquisition-id TOKEN
cargo run -p pulse-nq-load-support -- ingest --config /absolute/load-support.json --acquisition-id TOKEN
```

Deployment uses the role-specific executable names
`pulse-load-pressure-producer`, `pulse-load-pressure-receiver`, and
`pulse-support-resolver`. The resolver accepts a bounded Nightshift query on
standard input, reads `PULSE_LOAD_SUPPORT_CONFIG`, and emits canonical JSON on
standard output. It never invokes the producer or NQ. See
`docs/nq-host-load-pressure-support-v1.md` for its exact proposition.

`pulse-project-predicate-support qualify` consumes already-produced NQ receipt,
inventory, catalog, and optional signed support evidence paths. It does not
replace NQ evaluation:

```sh
cargo run -p pulse-project-predicate-support -- qualify \
  --policy /absolute/policy.json --nq-executable /absolute/nq \
  --nq-receipt /absolute/nq.json --inventory /absolute/inventory.json \
  --catalog /absolute/catalog.json --support-evidence /absolute/support.json \
  --at 2026-09-12T00:00:00Z --output /absolute/new-receipt.json
```

Output paths are create-only where documented. Use fresh paths; never infer
permission to replace an existing record.

## Resume an existing campaign

Read its checkpoint before starting anything. Reconcile the exact
run identity, source revisions, working directory, log, artifact paths, and
expected terminal record. Inspect the existing process and journal; do not
restart merely because its supervisor disappeared. If the original producer
cannot be established, record the result as indeterminate and follow that
campaign's recovery procedure.

If a composed consumer is unavailable, retain the discovery/acquisition output
and report that limited boundary. A binary, command, resolver, or tool being
available does not establish current evidence, standing, or authority to act.

## Operating and retained state

Most examples are one-shot commands. `pulse-runtime` owns its configured local
journal; the project-concern tools write only to explicit output paths; the
queue-attention example retains SQLite stores and receipts below the root the
caller selects. Keep a SQLite database with its WAL-related files and quiesce
writers before copying it. A process restart does not restore hot Pulse
standing: current evidence and deadlines restart empty and `UNKNOWN` unless a
documented profile reacquires them.

Before retrying after a timeout or lost response, inspect the command's exact
output path, journal, receipt, and occurrence identity. Do not infer that the
absence of a response means the operation did not complete. Cross-version
restore, migration, and rollback are not qualified for this experimental
repository; retain the previous binary, configuration, complete state, and
receipts until an operator has verified the replacement.

Monitor and Pulse do not deliver Slack, Discord, or PagerDuty notifications.
They may emit bounded attention or escalation records for another component to
route. Deterministic notification adapters elsewhere in Constellation are not
evidence of live destination delivery.
