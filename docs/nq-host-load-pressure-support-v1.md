# Exact NQ host-load-pressure support family v1

Status: production-candidate contract for one proposition only.

## Proposition

`nq.host.load_pressure/v1` is `present` exactly when:

```text
parse_f64(first ASCII-whitespace token of /proc/loadavg)
--------------------------------------------------------  >= 2.000
       Rust std::thread::available_parallelism()
```

Both raw values must be available, the load must be finite and non-negative,
and logical CPU count must be nonzero. The exact NQ question, profile,
profile-semantic, and threshold-policy identities are compiled into this
support family. Equality is pressure-present. The profile's present-support
horizon is 300,000 milliseconds.

The subject is a configured governed subject. The vantage is the exact local
NQ watcher vantage named in deployment configuration. Neither hostname nor
another identity heuristic participates.

## Three separate objects

1. `pulse.nq_host_load_pressure_support_evidence.v1` is one independently
   acquired proposition-exact observation. It preserves the raw load token,
   logical CPU count, fixed threshold, derived state, source basis, producer,
   subject, vantage, semantic identities, acquisition identity, and Linux
   boot-clock observation point. It is signed by the dedicated producer.
2. `pulse.nq_host_load_pressure_support_receipt.v1` is receiver custody. A
   distinct principal verifies the signature and exact family, records arrival
   on the same kernel-owned boot clock, and fixes the exclusive 300-second
   expiry. Exact intake replay converges.
3. `nightshift.qualified_support.v1` is the read-only resolver's exact
   query-bound applicability result. Nightshift still owns the consequence.

The resolver never invokes the producer and neither role invokes NQ. The
producer source closure contains only `/proc/loadavg`,
`available_parallelism()`, `/proc/uptime`, the Linux boot ID, its fixed
configuration, and its signing key. It cannot read a diagnostic artifact.

## Temporal and contradiction law

A later independent occurrence can support the unchanged earlier diagnostic
object because it establishes the identical proposition at the later support
occurrence. This is semantic identity, not cross-proposition implication. The
diagnostic bytes and time remain unchanged.

Receiver arrival starts the exclusive 300-second support horizon. At equality
the receipt is expired. Replaying evidence does not move observation, arrival,
or expiry. A deliberate new acquisition ID causes one new raw read and one new
append-only occurrence.

If the newest current support occurrence disagrees with the configured exact
diagnostic state, the resolver emits `contradictory` with the exact evidence
reference. It does not fall back to older agreeing evidence or erase either
object.

## Deployment closure

The configuration pins exactly one diagnostic input/artifact basis, subject,
scope, vantage, producer key, and semantic identity set. This is not a generic
support registry. A different proposition, threshold, watcher, subject, or
artifact basis requires another independently ratified contract.

Producer, intake, and resolver are closed roles of one binary. Production
uses role-specific executable names and principals. The producer writes only
its append-only outgoing directory. Intake alone writes the receipt store.
Nightshift receives read-only receipt access and invokes only the resolver
name already allowed by its command port.

This family establishes only the bounded load-pressure proposition under one
local kernel vantage. It does not establish host health, workload cause,
external reachability, clock UTC accuracy, authority to act, or any other NQ
claim.
