# Constellation Monitor local guide

This repository is private. Use these commands only against user-owned local
trees and campaign-owned fixtures. Rust 1.85 or newer and Cargo are required;
the Linux `/proc` examples additionally require Linux.

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
