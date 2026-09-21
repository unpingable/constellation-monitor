# Public interfaces and operating limits

Constellation Monitor owns bounded concern discovery and observation
acquisition. Pulse is the hosted subsystem that owns the repository's bounded
observation records, receiver custody, freshness, replay, and present-reliance
evaluation. Neither component grants permission to change an observed system.

## Supported entry points

The public Rust workspace builds these primary command-line entry points:

| Package | Entry point | Supported purpose |
|---|---|---|
| `monitor-project-concerns` | `monitor-concerns` | Discover, inspect, validate, and explicitly acquire declared project concerns. |
| `pulse-agent` | `pulse-agent` | Emit synthetic or bounded Linux `/proc` observations for local qualification. |
| `pulse-replay` | `pulse-replay` | Replay checked-in JSONL observation traces and render deterministic results. |
| `pulse-runtime` | `pulse-runtime` and `pulse-crash-campaign` | Exercise the local scheduler, journal, expiry, restart, and recovery contracts. |
| `pulse-qualification` | `pulse-qualification` | Generate and verify exact local qualification packages and activation examples. |
| `pulse-transport-canary` | `pulse-transport-canary` | Exercise the bounded, pinned-key custody protocol and its deterministic qualification cases. |
| `pulse-nq-load-support` | role-specific binaries documented in `HOWTO.md` | Produce, ingest, and resolve the exact `nq.host.load_pressure/v1` profile. |
| `pulse-project-predicate-support` | `pulse-project-predicate-support` | Qualify already-produced NQ evidence for the generic project-predicate profile. |

The remaining workspace crates are libraries used by these entry points. There
is no supported HTTP service, MCP server, generic SDK, arbitrary command
runner, or live notification-delivery API in this repository.

## Project observation envelopes

`monitor-concerns collect` reads the exact public schema family:

- `project.concerns/v1` — a repository's stable concern inventory;
- `project.observation-binding/v1` — one direct-argv producer binding;
- `project.ops.status/v1` — the project-owned observation result; and
- `monitor.project-observation.inventory/v1` — Monitor's left join of every
  declaration onto acquired or missing observation state.

Collection binds the consumed manifest digest, status-byte digest, producer
identity, acquisition occurrence, process disposition, exit code, bounded
output counts, and repository revision context. A completed producer process
does not prove that its proposition is true. An explicit `UNKNOWN` observation
remains distinct from a missing required observation.

## `PulseFrameV1`

A compact Pulse frame binds:

- subject and subject-incarnation identities;
- observer and observer-incarnation identities;
- sequence and observer-local monotonic time;
- declared validity;
- the versioned observation profile and semantic digest;
- observation-policy generation;
- expected and observed coverage tags;
- bounded signal values and assessments;
- an exact observation digest; and
- the closed authentication field.

Receiver arrival time, not sender wall time, is the basis for local freshness.
`CURRENT` is consumer- and policy-specific and expires. It is not a global
health verdict or permission to continue or mutate work.

## `ObservationCustodyEnvelopeV1`

The bounded custody envelope body binds schema and protocol versions; receiver
challenge and session-binding digests; receiver and sender key identities;
sender process occurrence and monotonic epoch; sender manifest, qualification
certificate, and activation receipt digests; observer and failure-domain
claim; subject scope; observation identity; observation and session sequences;
the closed observation kind; exact payload bytes and payload digest; and
sender-local observation/emission times.

The V1 payload is at most 640 bytes and its identity is the domain-separated
digest of the exact received bytes. A complete signed datagram is at most
1,232 bytes. The envelope grants no continuation, transport administration,
diagnostic execution, deployment, signing, revocation, or mutation authority.
The receiver separately records verification, replay/deduplication,
admission/refusal, arrival, and local journal facts. Restart does not recreate
a live session or positive present reliance from historical receipts.

The current implementation accepts only `PulseV1`. OpenTelemetry/OTLP carriage
is a post-alpha.6 roadmap investigation, not an implemented public interface.

## Attention and notification boundary

Monitor may record a judgment transition and emit one bounded
`DiagnosticEscalationRequestV1`. That record includes an occurrence identity,
exact subject scope, consumer, trigger class, evidence-window digest, policy
and observation-policy generations, one predeclared diagnostic profile,
runtime/output/observation limits, local clock and expiry, deduplication key,
and causal transition identity.

This is an attention or diagnostic-admission input, not a Slack, Discord, or
PagerDuty message. Monitor and Pulse do not own destination routing,
acknowledgment, or live delivery. A downstream delivery record cannot make the
underlying evidence current, establish success, or grant action authority.

## Installation, state, and recovery

Build and test from the repository root with locked dependencies:

```sh
cargo build --locked --workspace
cargo test --locked --workspace --all-targets --all-features
```

CLI help and the source-defined parsers are authoritative for exact flags.
Configuration and output paths are caller-selected; commands do not use a
shared implicit credential store. The authenticated canary uses explicit test
key material and pinned peer identities. Do not put secret values in command
history, examples, or retained diagnostic excerpts.

When a command is interrupted, inspect the exact output path, journal, receipt,
and occurrence identity before retrying. A missing response is not proof that
the operation did not complete. Current Pulse standing is intentionally
ephemeral. Sparse journals and receipts support inspection but do not recreate
hot evidence or authorization. See `HOWTO.md` and the normative contracts for
the exact component-specific recovery behavior.

## Known limitations

- The runtime owner is local and experimental; it is not a production or
  distributed scheduler.
- The authenticated custody path is a bounded qualification canary, not a
  production transport, PKI, dynamic enrollment, or two-host deployment claim.
- Live Slack, Discord, and PagerDuty delivery is not implemented or verified.
- Cross-version restore, migration, and rollback are not qualified.
- The repository provides no general OpenTelemetry ingestion or export today.
- It does not establish observer truthfulness, complete coverage, host
  integrity, remote attestation, or authority to act.
