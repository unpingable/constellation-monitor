# monitor-skunkworks

`monitor-skunkworks` is a provisional name for an experimental near-real-time
present-confidence plane.

The project asks one bounded question:

> Under a named policy, explicit coverage, and a receiver-local evaluation
> time, may a named consumer still rely on this present-state judgment?

It detects when the available evidence no longer supports that reliance and
may emit a bounded request for a predeclared deeper diagnostic. It does not
establish global truth and cannot authorize repair.

## Core claim boundary

A received pulse can establish only that an identified observer emitted a
bounded observation about an identified subject, under an identified profile,
incarnation, policy generation, and sequence, and that a receiver observed its
arrival within a receiver-owned freshness calculation.

It does **not** establish:

```text
subject health
observation truthfulness
observer coherence
complete coverage
authority to continue operating
authority to mutate anything
```

The strongest target claim for this campaign is:

> Under a named policy and explicit coverage, the runtime detects within a
> bounded interval that current reliance conditions have ceased to hold,
> preserves the reason for that loss of confidence, and emits a bounded
> request for deeper diagnostic observation.

It must never claim that it knows a distributed system is healthy in real
time.

## Jurisdiction

```text
monitor plane   present freshness, continuity, coherence, contradiction,
                missingness, and consumer-indexed reliance
NQ-NG           permission and execution semantics for a deeper diagnostic
Witness         bounded evidence collected by that diagnostic
Nightshift      recurrence, expiry, retry, and operational posture
Docket          separately governed mutation
Synesthesia     human presentation of present-state coherence or collapse
```

This repository owns only the first line and a stubbed, non-authorizing seam
toward the second.

## Judgment vocabulary

- `CURRENT`: the exact named reliance conditions are satisfied *now*.
- `DEGRADED`: current evidence exists, but observation quality has degraded.
- `SUSPECT`: current evidence contains a coherently grounded bound violation.
- `UNKNOWN`: evidence is insufficient for the named reliance judgment.
- `CONTRADICTED`: incompatible grounded evidence remains unresolved.

`CURRENT` is the only positive reliance category and expires automatically.
It does not mean `healthy`. `ESCALATED` is intentionally not a judgment
category: escalation state is recorded separately so it cannot hide the
evidence condition that caused it.

The same evidence can lawfully be `CURRENT` for one consumer and `UNKNOWN` for
another because every judgment is indexed by consumer/reliance class and
policy generation.

## Workspace

The minimal Rust workspace contains:

- `pulse-types`: closed versioned records and compact bounded pulse encoding;
- `pulse-agent`: synthetic and small Linux `/proc` pulse production;
- `pulse-evaluator`: deterministic, multi-dimensional present-state logic;
- `pulse-replay`: deterministic JSONL hostile-trace replay and terminal demo;
- `pulse-l3-bridge`: closed-profile, harmless local diagnostic stub.

Pulses are hot, bounded, ephemeral records. JSONL is used for fixtures, replay,
diagnostics, and sparse durable events, not as the assumed high-rate wire.

## Local commands

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo run -p pulse-replay -- demo
cargo run -p pulse-replay -- replay traces/packet-loss.jsonl
cargo run -p pulse-agent -- --profile proc --count 3 --cadence-ms 250
```

No command performs remediation, invokes an arbitrary shell command, or grants
mutation authority.

## Normative documents

- [Architecture](docs/architecture.md)
- [Invariants](docs/invariants.md)
- [Non-goals](docs/non-goals.md)
- [Threat model](docs/threat-model.md)
- [Escalation seam](docs/escalation-seam.md)
- [Hostile scenarios](docs/hostile-scenarios.md)
- [Focused reconnaissance](docs/reconnaissance.md)

When documents disagree, `docs/invariants.md` governs the runtime claim and
`docs/non-goals.md` limits its scope.
