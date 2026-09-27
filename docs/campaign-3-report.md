# Local crash-fault reactor and journal campaign report

Status: qualified local experimental result on 2026-08-03. Repository and
record names remain provisional.

## Baseline and scope

The campaign began from exact clean commit
`668589e537e9cffe151913f72ca45a61ca32b1d7` on `main`, with no remote. The
baseline had 73 passing tests. Read-only reconnaissance covered the README,
architecture, runtime contract, campaign-2 report, every existing artifact,
all `pulse-runtime` APIs/tests, and the repository history.

The permitted neighbor recheck recorded these exact clean commits without
copying schemas or machinery:

- NQ-NG: `59abd3bcb2d0cc30657a659b3ebc57b981289d9f`;
- Witness: `e3d22f9bef8dc248e58e0fa5b7fa474b2dd78c5d`;
- Nightshift: `500f4b7bd4f066c7ca43963d192f314559cdbc83`;
- Docket: `3ce07f9bb3be6ba86ca65f3b521f807970b56119`;
  and
- Synesthesia: `d1a731c383d4fce8f9bc21f40b63af5dbae2aa94`.

No neighboring repository was modified. No remote was created and nothing was
pushed.

## Architecture

The deterministic `ReceiverSchedulerRuntime` remains the semantic kernel. A
new `LocalCrashReactor` owns it on one dedicated standard-library thread. A
fixed-capacity mutex/condition-variable mailbox wakes the thread for commands,
nearer deadlines, blindness, shutdown, and overload. One process-local
`Instant` origin is bound to one explicit `MonotonicEpochV1`. At a timeout the
actor calls `run_until(actual_receiver_now)`, not `run_until(requested_deadline)`.

The actor publishes a bounded `ReactorSnapshotV1`. Operational snapshots may
carry current certificates and the earliest deadline. Mailbox overload,
response timeout, explicit blindness, wakeup failure, actor unwind, required
journal failure, command-channel abandonment, and termination expose no live
certificates, supporting evidence, or deadlines. Journal failure and timer/
actor failure have distinct conditions and counters.

The actor preserves the deterministic same-instant law: blindness/capacity,
generation barriers, inclusive expiry, pulses, receipt/disposition,
reevaluation, then shutdown. A command reply is sent only after the completed
snapshot is published, so immediate inspection cannot race actor publication.

## Journal format and append protocol

`HistoricalJournal` is one bounded append-only regular file. It accepts only:

- `SparseDurableEventV1`;
- `ContradictionCustodyV1`; and
- `MockDiagnosticReceiptV1`.

Each PCJ-v1 record has a fixed magic/version/kind/sequence/length/prior-digest
header, bounded JSON payload, trailer magic and SHA-256 frame digest, followed
by a separately checksummed sequence-and-digest commit marker. The payload
repeats journal identity, exact sequence and kind, one monotonic epoch,
epoch-local timestamp, optional reliance-context digest, declared durability,
and `mutation_authority: none`.

SHA-256 is used for corruption detection and linkage only. It is not a MAC,
signature, writer authentication, hostile-storage defense, or attestation.
Record count, payload bytes, and total file bytes are bounded. Exhaustion
refuses before a write and never evicts.

The append protocol is:

```text
validate + encode bounded frame
-> append data frame and flush userspace buffering
-> sync data frame according to Written/DataSynced/FileSynced
-> append commit marker and flush userspace buffering
-> sync commit marker according to the same mode
-> return acknowledgement for exact sequence and frame digest
```

An interrupted append returns no acknowledgement and latches that journal
instance against further appends until reopening/scanning. `create_new`
`sync_all`s the empty file and parent directory entry. No rotation, rename,
compaction, database, replication, or query layer was added.

## Exact durability boundary

`Written` means the complete frame and marker were passed through `write_all`
and userspace `flush`; it makes no process-kill or host-crash durability claim.
`DataSynced` means `sync_data` returned after both data and commit phases.
`FileSynced` means `sync_all` returned after both phases. An acknowledgement is
constructed and returned only after that declared final boundary.

The Linux harness demonstrates that a record killed after the frame write but
before sync is an `UncommittedSuffix`, while a record killed after the commit
sync but before acknowledgement return is recoverable and clean. Separate
post-acknowledgement contradiction and deduplication cases are also clean.
Recovery cannot determine whether a sync-complete in-memory acknowledgement
reached an external caller; the artifact reports that ambiguity.

These results qualify local process-kill recovery through the operating-system
interface on the exercised filesystem. They do not qualify physical media,
host power loss, kernel/filesystem/device correctness, or directory durability
beyond journal creation.

## Recovery and restart semantics

Scanning begins at byte zero, sequence one, and a fixed genesis link. It stops
at the first invalid structure and never searches later bytes for another
magic value.

- `Clean` means exact EOF after zero or more valid committed records.
- `RecoveredThroughValidPrefix` permits a committed prefix but records damage,
  first damaged offset, incomplete history, and required operator action.
- `Refused` prevents historical projection. The scanner may report the
  structurally validated leading count, but the runtime cannot consume it.

An allowed projection preserves its recovery outcome and health fields.
Regardless of clean, prefix, or refused history, process restart uses a new
receiver incarnation, clock identity, context activation, and monotonic epoch:

```text
current standing = UNKNOWN
supporting evidence = 0
active deadlines = 0
```

Historical timestamps remain provenance and are never compared to current
`Instant`. Historical `CURRENT` certificate events do not reconstruct current
coverage, observer availability, transport assumptions, support, or standing.

## Escalation and contradiction custody

Recovered escalation requests, dispositions, deduplication records, and
receipts are history only. The implementation deliberately restores no active
request owner or exact-key suppression lease because its expiry belonged to
the prior epoch and restoring it could launder operational authority. A later
fresh transition may lawfully create a new bounded request.

Contradiction custody is journaled independently of current standing. The
crash harness recovers an acknowledged contradiction record, while the
existing diagnostic-completion test continues to prove that a receipt cannot
clear it. No append, scan, projection, restart, request, receipt, or reactor
object grants diagnostic execution or mutation authority.

## Earned claims

The campaign earns exactly these local claims:

1. A real dedicated runtime actor withdraws expired `CURRENT` without a pulse
   or external `run_until` call.
2. Inclusive expiry remains encoded; a delayed wake evaluates at actual time
   and records lateness and stale-positive overshoot instead of extending the
   deadline.
3. A newly inserted nearer deadline wakes and re-arms the actor; multiple
   deadlines are serviced earliest first.
4. Generation transition at an old deadline remains a barrier and cannot
   inherit or revive the old scheduled standing.
5. Mailbox, actor, timer-custody, command-channel, and journal failures remove
   the live positive surface; bounds do not evict silently.
6. Process death cannot preserve `CURRENT`, support, active deadlines, current
   coverage, or active escalation ownership.
7. Persisted monotonic timestamps name exact process epochs and are not used to
   compute elapsed time across restart.
8. Acknowledged and unacknowledged append boundaries are represented
   separately, including the sync-before-ack delivery ambiguity.
9. Torn headers, payloads, trailers, and commit markers are detected. An
   allowed valid prefix is explicitly incomplete.
10. Interior corruption, unsupported versions/kinds, sequence gaps,
    duplicates, replay, reorder, prior-link/checksum failure, oversized length,
    trailing bytes, I/O failure, and bound exhaustion are explicit; recovery
    never silently skips damage.
11. A `Refused` scan cannot project runtime history.
12. Journal exhaustion refuses without eviction; required journal failure is
    distinct from timer/actor failure and removes live custody.
13. Historical `CURRENT` records cannot reconstruct standing, even when their
    file is clean and fully synced.
14. Bounded mock diagnostic receipts append, sync, scan, and project exactly as
    history while granting no standing or authority.
15. Contradiction custody survives an acknowledged append and restart;
    diagnostic completion does not resolve it.
16. Historical escalation-dedup evidence restores no suppression or execution
    authority, while equivalent live failures still deduplicate within an
    active exact request lifetime.
17. Every emitted authority field remains `none`; the runtime grants neither
    continuation nor mutation authority.

Each is backed by a named test or checked artifact. No subject-health,
truthfulness, independence, or complete-coverage claim follows.

## Exact nonclaims

This campaign does not claim hard real-time behavior, bounded scheduler
latency under arbitrary load, physical-media durability, immunity to
filesystem/kernel/device defects, host-crash durability, qualified network
transport, distributed crash consistency, Byzantine correctness, truthful or
independent observers, complete coverage, subject health, crash-durable current
standing, durable diagnostic authority, full contradiction resolution,
production deployment viability, product-plane status, authority to continue
operation, or authority to mutate anything.

It also does not claim writer authenticity, malicious-storage resistance,
generic WAL/database semantics, multi-writer safety, compaction, replication,
rotation, or exact committed-prefix rollback detection.

## Qualification results

The local milestone sequence before the final report/artifact commit was:

```text
61257b5 Define local crash-fault custody contract
1d29d1b Implement local crash-fault reactor and journal
693d0cc Qualify crash recovery and reactor failure paths
```

The final report/artifact commit is necessarily identified by Git rather than
embedding its own content hash in this file. The completion report names it.

The final gates passed:

```text
cargo fmt --all -- --check                                      PASS
cargo clippy --workspace --all-targets --all-features -- -D warnings PASS
cargo test --workspace --all-targets --all-features            PASS (97)
```

The 97 tests comprise 43 previously qualified non-runtime tests, 30 preserved
deterministic runtime tests, and 24 new reactor/journal/crash tests. The new
set includes 12 journal/reactor unit tests, two artifact tests, nine real
reactor integration tests, and one Linux SIGKILL integration test.

Machine-readable results are indexed in
[`artifacts/crash-reactor-qualification.json`](../artifacts/crash-reactor-qualification.json).

Retrospective qualification note (2026-09-26): the original JSON's `pass`
labels were emitted from a declared check list rather than independently
observed command results. Its exact bytes remain retrievable at path
`artifacts/crash-reactor-qualification.json` in commit `bfe5b8c` as Git blob
`18f9d820dbddc662d4fb76c90173a46bfbffe2aa`; they are historical provenance,
not evidence that those checks ran. The active checked artifact and current
`qualification` command instead emit the required test names as
`not_exercised`. A new acceptance record must pair them with retained gate logs
and observed test outcomes before reporting a pass.

## Demo traces

Real monotonic reactor demo:

```text
[000025ms] UNKNOWN receiver actor operational; support=0 deadlines=0
[000026ms] CURRENT exact evidence accepted; deadline=326ms
[000326ms] UNKNOWN inclusive deadline processed; lateness=0ms overshoot=0ms
[journal] withdrawal_records=1 recovery=Clean complete=true
```

Crash-before-expiry restart demo:

```text
CURRENT bounded support established
real monotonic deadline armed
child process SIGKILLed before expiry
restart history_records=5 recovery=Clean
current standing UNKNOWN
supporting evidence 0
active deadlines 0
fresh evidence required
```

Torn-journal demo:

```text
valid records appended
final record torn
restart outcome=RecoveredThroughValidPrefix valid_prefix_records=1 damaged_offset=1316
history_complete=false
current standing UNKNOWN (not reconstructed)
```

Interior-corruption demo:

```text
valid record
corrupted interior record
later valid-looking bytes present
recovery outcome=Refused damage=InteriorCorruption damaged_offset=1124
complete replay refused; current standing not reconstructed
```

Exact runnable commands and JSON are in [`artifacts/README.md`](../artifacts/README.md).

## Hostile scenarios covered

The corruption artifact contains 19 named scenarios and a 3,088-position
truncation sweep. The child harness uses real Linux `SIGKILL` at 12 named
points: before/after arming, before expiry, after in-memory expiry before
journal, before sync, after sync before ack, during header/payload/trailer,
after acknowledged contradiction, after acknowledged dedup custody, and during
clean shutdown. Reactor tests additionally cover early wake/re-arm,
earliest-first deadlines, controlled lateness, generation cancellation,
mailbox saturation, journal saturation, actor unwind, channel abandonment, and
clean termination. All preserved generation, replay, contradiction, and
consumer-isolation tests continue to pass.

## Live Linux measurements

Six real timer samples were generated while other campaign artifact processes
also created CPU/filesystem load. Observed distributions were:

| measurement | minimum | median | maximum |
|---|---:|---:|---:|
| wakeup lateness | 0 ms | 0 ms | 17 ms |
| stale-positive overshoot | 0 ms | 0 ms | 17 ms |
| journal append latency | 5,864 us | 47,478 us | 55,832 us |
| journal sync latency | 5,822 us | 46,986 us | 55,797 us |
| restart recovery latency | 3,581 us | 16,110 us | 16,918 us |

The controlled delayed-wakeup sample requested deadline 187 ms and withdrew at
204 ms, recording 17 ms lateness/overshoot. The CPU-load sample recorded zero
millisecond overshoot in this run; that is an observation, not a guarantee.
An eight-millisecond injected write-path stall produced 11,523 us append and
3,431 us sync measurements. The two-expiry sample recorded one deduplicated
escalation. Every sample restarted `UNKNOWN` with zero support and deadlines.
The live exercise also ran all 12 `SIGKILL` cases and both torn/interior
corruption injections. `/proc/loadavg` and `/proc/meminfo` readability was
probed but was deliberately not used as reliance evidence.

## Known semantic and engineering gaps

1. A self-contained journal cannot detect truncation to zero or another exact
   committed-record boundary; those bytes equal a legitimately shorter clean
   file. A trusted external tail anchor would be a separate campaign.
2. Sync completion cannot prove that the returned acknowledgement reached a
   caller before death. External exactly-once effects remain out of scope.
3. `sync_all` is an OS request, not physical-media or host-crash proof.
4. The journal is one trusted single-writer file. There is no file locking,
   hostile-writer authentication, replacement detection, rotation, or repair.
5. An actor unwind clears the in-memory live surface, but process death can
   prevent journaling the failure occurrence itself. Restart caution does not
   depend on that record.
6. Active escalation suppression is intentionally not recovered. The system
   may issue a new request after fresh post-restart evidence and a new causal
   transition; cross-restart operational deduplication remains a seam.
7. Journal capacity exhaustion fail-stops required custody and therefore live
   reliance. No rotation policy has been defined.
8. Live measurements are local samples and provide no deployment sizing,
   fairness, tail-latency, or scheduler-bound result.
9. Generation identities are exact values but are not yet qualified bindings
   to deployed evaluator, policy, profile, and executable artifact bytes.

No campaign stopping condition was reached. No previously earned invariant was
falsified or weakened. The earlier statement that filesystem atomicity and
crash recovery were unqualified has been replaced by this narrower,
process-kill-tested history-only boundary; current standing remains explicitly
non-durable.

## Assessment and next campaign

This remains a **useful runtime component**, not evidence for a separate
product plane. The campaign converts deadline and history semantics into one
coherent local crash-fault custody mechanism, but it does not establish
distributed operation, deployment viability, operator utility, or category
demand.

The single most defensible next campaign is qualified binding between exact
runtime generation identities and the deployed evaluator, reliance policy,
consumer profile, observation profile, observer-set configuration, and
executable artifact bytes. That campaign should prove what exact code/config
an identity names without adding distributed orchestration or remediation. It
was not begun here.
