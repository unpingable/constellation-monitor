# Constellation Monitor

Constellation Monitor acquires bounded observations and evaluates whether a
named consumer may still rely on current evidence. Pulse is the hosted
subsystem that carries the repository's bounded observation, custody,
freshness, replay, and qualification records.

This is an experimental public component of Constellation. The canonical
source is [unpingable/constellation-monitor](https://github.com/unpingable/constellation-monitor).
Existing crate, executable, service, filesystem, database, and protocol
identities retain their current names for compatibility.

The project asks one bounded question:

> Under a named policy, explicit coverage, and a receiver-local evaluation
> time, may a named consumer still rely on this present-state judgment?

It detects when the available evidence no longer supports that reliance and
may emit a bounded request for a predeclared deeper diagnostic. It does not
establish global truth and cannot authorize repair.

## Install and verify

Rust 1.85 or newer and Cargo are required. The Linux `/proc` demonstrations
also require Linux.

```sh
git clone https://github.com/unpingable/constellation-monitor.git
cd constellation-monitor
cargo build --locked --workspace
cargo test --locked --workspace --all-targets --all-features
```

Start with the [operator guide](HOWTO.md), the
[public interface reference](docs/public-interfaces.md), or the disposable
[queue-attention example](docs/local-queue-attention.md). The example names
its separately pinned Constellation NQ and Nightshift revisions; this
repository alone does not supply their responsibilities.

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
Monitor         bounded discovery and acquisition
Pulse           present freshness, continuity, coherence, contradiction,
                missingness, and consumer-indexed reliance
Constellation NQ  diagnostic judgment and evidence admission
Nightshift      recurrence, expiry, retry, and operational posture
Docket          separately governed mutation
Phosphor        optional read-only presentation and inspection
```

This repository owns only the first line and a stubbed, non-authorizing seam
toward the second.

Monitor discovers bounded observations and evaluates consumer-indexed present
reliance. Pulse records and preserves the exact evidence, custody, freshness,
and replay facts consumed at that boundary. Discovery is not evidence custody;
custody is not currentness; `CURRENT` is not authorization. Nightshift may
consume the proposition-exact `nightshift.qualified_support.v1` result, but it
still owns the consequence and must independently satisfy its other gates.

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

The Rust workspace contains eleven crates spanning the experimental monitor
plane, a generic repository-concern acquisition boundary, and closed
proposition-exact support adapters:

- `pulse-types`: closed versioned records and compact bounded pulse encoding;
- `pulse-agent`: synthetic and small Linux `/proc` pulse production;
- `pulse-evaluator`: deterministic, multi-dimensional present-state logic;
- `pulse-replay`: deterministic JSONL hostile-trace replay and terminal demo;
- `pulse-l3-bridge`: closed-profile, harmless local diagnostic stub;
- `pulse-runtime`: bounded deterministic scheduling plus local reactor/journal
  custody; and
- `pulse-qualification`: canonical local artifact-package generation,
  verification, activation demos, and crash/substitution qualification; and
- `pulse-transport-canary`: one bounded Ed25519-pinned UDP custody path and
  deterministic sender/receiver qualification harness; and
- `monitor-project-concerns`: passive generic concern discovery, explicitly
  trusted bounded producer acquisition, structural correspondence validation,
  and required-observation inventory gaps; and
- `pulse-nq-load-support`: a closed one-shot producer, separate intake, and
  read-only resolver for exactly `nq.host.load_pressure/v1`; and
- `pulse-project-predicate-support`: proposition-exact qualification of
  already-produced NQ evidence for the generic project-predicate profile.

`pulse-runtime` is a bounded local owner for
receiver admission, exact context-generation barriers, per-consumer support
certificates, and earliest-expiry reevaluation. It is not a production or
distributed scheduler. The local crash-fault campaign encloses that semantic
kernel in one dedicated monotonic wakeup thread and one bounded, checksummed,
append-only historical journal. See the [runtime contract](docs/runtime-contract.md)
and [crash-fault contract](docs/crash-fault-contract.md).

The new local claim is deliberately narrower than crash-durable reliance:

> While one reactor process is operational, a real runtime actor wakes for the
> earliest support deadline and withdraws expired positive standing without a
> new pulse. After process death, only explicitly recovered history survives;
> current standing, support, and deadlines restart empty and `UNKNOWN`.

The qualified-generation campaign adds one further gate:

> `CURRENT` requires a live, non-serializable activation whose exact manifest,
> checked qualification certificate, locally measured executable, canonical
> evaluator/policy/profile/observer/observation/configuration values, process
> occurrence, and support-certificate context all match.

A declared generation, digest, manifest, certificate, source commit, passing
test result, or historical activation receipt is individually insufficient.
Local self-measurement identifies what one process observed; it is not
independent attestation, source-to-binary proof, signer authority, or host
integrity.

The receiver-boundary campaign adds one authenticated observation path while
preserving four different facts:

```text
authenticated pinned-key transport
!= sender assertion of qualified local activation
!= receiver admission of one exact envelope
!= one consumer's present reliance
```

The five-message session is sender offer, receiver challenge, sender binding,
receiver acceptance, then observation envelope. Each message is a bounded
canonical PCN1 datagram with a distinct Ed25519 signature domain. A sender
cannot emit until the live receiver occurrence accepts its process-bound
binding. The sender pins an exact receiver-policy content anchor and verifies
the challenge's exact sender-package-bound composite policy identity; a policy
generation label alone is insufficient. The receiver assigns arrival and expiry; sender clocks are provenance
only. Restart destroys sessions and accepted evidence, and historical receipts
cannot recreate `CURRENT`. This is pinned-key local custody, not remote
attestation, confidentiality, observer truth, or production transport.

Pulses are hot, bounded, ephemeral records. JSONL is used for fixtures, replay,
diagnostics, and sparse durable events, not as the assumed high-rate wire.

## Local commands

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo run -p pulse-replay -- demo
cargo run -p pulse-replay -- replay traces/packet-loss.jsonl
cargo run -p pulse-replay -- replay-json traces/demo.jsonl
cargo run -p pulse-agent -- --profile proc --count 3 --cadence-ms 250
cargo run -p pulse-runtime -- demo
cargo run -p pulse-runtime -- restart-demo
cargo run -p pulse-runtime -- qualify
cargo run -p pulse-runtime -- live-linux
cargo run -p pulse-runtime --bin pulse-crash-campaign -- reactor-demo
cargo run -p pulse-runtime --bin pulse-crash-campaign -- restart-demo
cargo run -p pulse-runtime --bin pulse-crash-campaign -- torn-journal-demo
cargo run -p pulse-runtime --bin pulse-crash-campaign -- interior-corruption-demo
cargo run -p pulse-runtime --bin pulse-crash-campaign -- crash-harness
cargo run -p pulse-runtime --bin pulse-crash-campaign -- corruption-corpus
cargo run -p pulse-runtime --bin pulse-crash-campaign -- live-linux
cargo run -p pulse-qualification -- demo
cargo run -p pulse-qualification -- crash-demo
cargo run -p pulse-qualification -- qualify /tmp/create-new-artifact-directory
cargo run -p pulse-transport-canary -- demo
cargo run -p pulse-transport-canary -- expiry-demo
cargo run -p pulse-transport-canary -- restart-demo
cargo run -p pulse-transport-canary -- udp-loopback
cargo run -p pulse-transport-canary -- artifacts /tmp/create-new-custody-artifact-directory
cargo run -p monitor-project-concerns --bin monitor-concerns -- discover /path/to/workspace
cargo run -p monitor-project-concerns --bin monitor-concerns -- validate /path/to/project
cargo run -p monitor-project-concerns --bin monitor-concerns -- collect /path/to/project --trusted-root /path/to/workspace --allow-exec
```

Optional report paths are created without overwriting an existing file. Their
JSON contains sparse transition provenance, support/deadline facts,
escalation dispositions, and diagnostic receipts; it is not a general event
store. Checked-in [qualification artifacts](artifacts/README.md) keep replay
clock results separate from the one bounded wall-clock `/proc` exercise.

No command performs remediation, invokes an arbitrary shell command, or grants
mutation authority.

## Normative documents

- [Architecture](docs/architecture.md)
- [Invariants](docs/invariants.md)
- [Non-goals](docs/non-goals.md)
- [Threat model](docs/threat-model.md)
- [Escalation seam](docs/escalation-seam.md)
- [Hostile scenarios](docs/hostile-scenarios.md)
- [Receiver/scheduler contract](docs/runtime-contract.md)
- [Local crash-fault reactor and journal contract](docs/crash-fault-contract.md)
- [Qualified-generation binding contract](docs/qualified-generation-contract.md)
- [Receiver-boundary custody contract](docs/receiver-boundary-contract.md)
- [Exact NQ host-load-pressure support contract](docs/nq-host-load-pressure-support-v1.md)
- [Generic project-concern discovery and acquisition contract](docs/project-concern-contract.md)
- [Public interfaces and operating limits](docs/public-interfaces.md)
- [Public source provenance](PUBLIC_RELEASE.md)

When documents disagree, `docs/invariants.md` governs the runtime claim and
`docs/non-goals.md` limits its scope.
