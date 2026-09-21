# Local crash-fault reactor and journal contract

Status: normative for campaign 3 and the campaign-4 activation-receipt
interaction. Names and format remain provisional.

## Owned question

This campaign adds local temporal and historical custody around the existing
deterministic evaluator:

> While this one receiver process is alive, does one identified reactor still
> own waking for every active support deadline, and which bounded historical
> records reached an explicitly described local append boundary?

It does not establish subject health, observer truth, host-failure tolerance,
distributed consistency, diagnostic authority, or mutation authority.

## Reactor ownership

One dedicated thread owns one `ReceiverSchedulerRuntime`, one monotonic epoch,
one bounded command mailbox, and the earliest active support deadline. It uses
`std::time::Instant` plus a condition variable; it is not a general async
executor. No network, collection, diagnostic execution, or remediation runs on
the reactor.

The thread maps elapsed `Instant` duration to receiver time within exactly one
`MonotonicEpochV1`. It waits without busy polling. A newly admitted command
notifies the condition variable, so a nearer deadline or immediate generation
barrier causes re-arming. Timeout wakeups process every deadline due at the
actual receiver time even when no evidence arrived.

Expiry is inclusive: support is unavailable at `now >= deadline`. A late
wakeup evaluates at actual receiver time, never at the requested deadline, and
records:

```text
stale-positive overshoot = actual withdrawal time - support expiry deadline
```

The encoded deadline never slides because the wakeup was late. Existing
`SchedulerReevaluated` sparse records expose requested deadline, actual
evaluation, and overshoot.

The bounded mailbox refuses a new command when full. Saturation latches an
out-of-band custody failure and wakes the actor; it cannot depend on adding one
more item to the full queue. While that latch is set, the shared observation
surface exposes no positive certificate. The live reactor also installs
monitor blindness in the deterministic kernel before further reliance can be
reported.

A condition-variable poison/wait failure, command-channel abandonment,
required-journal failure, or unexpected actor termination is a distinct typed
reactor state. Cached output is historical after termination and is not a live
claim. Graceful shutdown first withdraws temporal custody, processes already
admitted same-instant work under the order below, journals what it can, then
terminates and joins.

## Real-time event order

Receiver assignment, not sender wall time or thread arrival speculation,
defines simultaneity. At one receiver millisecond the order remains:

1. clock/custody blindness and capacity withdrawal;
2. subject-incarnation and reliance-context generation barriers;
3. inclusive support expiry;
4. pulse/evidence input;
5. diagnostic disposition and receipt;
6. restoration and explicit reevaluation; and
7. shutdown after all already admitted work at that receiver instant.

The reactor drains the bounded mailbox before one `run_until(actual_now)` call.
Stable semantic keys inside the deterministic kernel decide distinct
same-instant inputs. If a command is admitted only after expiry was already
processed at an earlier receiver instant, it is later rather than
retroactively simultaneous.

## Monotonic epoch law

`MonotonicEpochV1` binds:

- one explicit epoch identity;
- receiver identity and receiver process incarnation;
- receiver clock-generation identity;
- the runtime monotonic value corresponding to the actor's local `Instant`
  origin; and
- the origin semantics (`std::time::Instant`, process-local).

Every journal envelope binds its timestamp to exactly that epoch. Epoch
identities are provenance, not synchronized clocks. Scanner and restart code
never subtract or order monotonic values from different epochs. A previous
epoch timestamp cannot reconstruct remaining freshness, a current deadline,
current standing, or elapsed restart time. Wall time is not substituted.

## Restart law

After every restart:

```text
current standing = UNKNOWN
supporting evidence = empty
active deadlines = empty
```

Recovery may provide the existing history-only runtime payload: sparse events,
historical support-certificate occurrences, receipt custody, contradiction
custody, and journal recovery findings. Historical escalation request and
deduplication events remain evidence only. No active request owner, diagnostic
execution, retry permission, or suppression lease is recovered.

Recovery cannot provide hot pulses, active support, current coverage, observer
availability, transport assumptions, timer authority, diagnostic authority, or
mutation authority. Fresh evidence and explicit evaluation in the new exact
context and monotonic epoch are required for any new `CURRENT`.

Qualified manifests, checked reports, certificates, binding failures, and
activation receipts are also historical after restart. The opened executable
handle and accepted activation token are deliberately non-serializable. A new
process therefore starts `Unbound` in addition to `UNKNOWN`, remeasures every
load-bearing active object, emits a new process-local receipt, and then still
needs fresh evidence. A previously synced `QualifiedAndMatched` receipt or
historical `CURRENT` event cannot restore binding, support, or a deadline.

## Journal format

The journal is one append-only regular file with no rotation or compaction in
this campaign. `JournalBoundsV1` fixes nonzero maximum committed records,
maximum JSON payload bytes, and maximum total file bytes. Exhaustion refuses
before writing; no record is evicted.

Each logical record uses two append-only structures:

```text
data frame:
  8-byte magic
  big-endian format version
  closed record-kind tag and reserved byte
  big-endian record sequence
  exact payload length
  prior committed-frame digest
  bounded JSON JournalRecordEnvelopeV1
  trailer magic
  frame checksum/digest

commit marker:
  8-byte magic
  exact record sequence
  exact frame digest
  commit-marker checksum/digest
```

The payload envelope repeats and validates the journal identity, sequence,
closed record kind, monotonic epoch, epoch-local receiver timestamp, optional
exact reliance-context digest, and structural `mutation_authority: none`.
Record bodies are only sparse events, contradiction-custody records, or mock
diagnostic receipts.

SHA-256 is used as a deterministic corruption checksum and prior-record link.
It is not a MAC, signature, authenticity claim, hostile-storage defense, or
cryptographic attestation. The exact payload bytes, length, sequence, kind,
prior link, frame checksum, and commit checksum must all agree.

## Append and acknowledgement

For a fully synced append:

```text
validate bounds and encode exact frame
-> write complete data frame
-> flush userspace buffering
-> sync data frame according to requested mode
-> write exact commit marker
-> flush userspace buffering
-> sync commit marker according to requested mode
-> return JournalAppendAckV1 for that exact sequence and digest
```

The implementation exposes three modes:

- `Written`: both structures were written and flushed to the operating-system
  interface. No process-kill or host-crash durability claim is made.
- `DataSynced`: `File::sync_data` returned after both phases. This requests
  data durability from the OS but does not claim all metadata or directory
  durability.
- `FileSynced`: `File::sync_all` returned after both phases. This requests file
  data and file metadata durability. It still does not sync a newly created
  directory entry.

Journal creation separately calls `sync_all` on the empty file and, on the
qualified Linux path, `sync_all` on the parent directory. Its creation receipt
states both results. Append does not rename or rotate the file.

An append acknowledgement is constructed only after the declared final
boundary. A crash after final sync but before the caller receives the returned
value leaves a committed recoverable record; recovery cannot know whether the
in-memory acknowledgement was observed. This is acknowledged-delivery
ambiguity, not journal corruption and not permission to retry an external
effect.

### Activation-receipt ordering

An activation receipt states what one process actually activated. V1 therefore
commits the ephemeral, non-serializable binding before handing the receipt to
the historical journal. It refuses the hypothetical ordering “sync activation
receipt, then activate,” because a kill between those steps would leave a
durable receipt falsely claiming activation. Consequences are explicit:

- a kill after measurement but before binding commit leaves neither binding
  nor receipt;
- a kill after binding commit but before receipt append loses only historical
  receipt custody; restart still loses the ephemeral binding;
- a torn or uncommitted receipt suffix is reported under the normal journal
  damage law; and
- a fully committed receipt remains historical after restart and cannot
  construct the accepted activation token.

The campaign-4 child harness injects `SIGKILL` before/during measurement,
between measurement and binding commit, between binding and receipt custody,
during receipt framing, before and after sync/commit, before evidence, while
`CURRENT`, and after mismatch detection. The semantically invalid
receipt-before-activation point is recorded as a refused qualification point,
not simulated as though it were lawful.

`sync_data`/`sync_all` success is an operating-system request. The campaign
tests process-kill recovery on one local Linux filesystem. It does not claim
physical-media durability, immunity to filesystem/kernel/device defects, or
host-crash survival.

## Recovery

Scanning begins at byte zero with expected record sequence one and the fixed
genesis prior digest. It stops at the first defect. It never searches later
bytes for another magic value and never skips damage.

`JournalRecoveryReportV1` separates outcome from damage:

- `Clean`: empty journal or every frame has a valid committed marker and EOF is
  exact; history is complete within configured journal bounds.
- `RecoveredThroughValidPrefix`: a permitted incomplete suffix follows one or
  more committed records. Prefix records are returned, history is explicitly
  incomplete, and operator action is required.
- `Refused`: corruption, unsupported format, sequence/prior-link failure,
  bound violation, identity ambiguity, or I/O failure prevents a complete
  replay. The scanner reports how many leading records were structurally
  validated, but `project_history` refuses to turn this outcome into runtime
  history. Later bytes are not interpreted and the journal is not healthy.

Damage classes distinguish partial header, partial payload, partial trailer,
partial/uncommitted commit marker, unexpected trailing bytes, checksum or
interior corruption, unsupported version/kind, duplicate/gapped/reordered
sequence, prior-link failure, oversized length, configured-bound exhaustion,
payload identity conflict, and I/O failure. Reports name records recovered,
first damaged byte offset, history completeness, and operator-action posture.

A historical runtime payload projected from a clean or explicitly recovered
prefix carries the recovery outcome, damage class, completeness, and
operator-action requirement and remains history only. A damaged journal cannot
create reliance, deadlines, escalation authority, diagnostic authority, or
mutation authority.

A self-contained append-only file cannot detect that a previously longer file
was truncated at byte zero or at another exact committed-record boundary: those
bytes are identical to a legitimately shorter clean journal. Detecting that
class of rollback would require a separately durable trusted tail anchor,
generation manifest, or external custody service. This campaign records the
limitation and does not add such a component. It cannot strengthen standing
because every restart is `UNKNOWN` regardless of apparent journal completeness.

## Escalation and contradiction custody

Sparse escalation request, disposition, deduplication, and receipt facts may be
journaled. On restart they are historical evidence only. Active escalation
ownership and suppression are deliberately not restored because their
receiver-monotonic expiry belonged to the prior epoch and because restoring
them would risk laundering operational state.

Contradiction custody records are historical inputs to the existing narrow
recovery path. Applicable active contradictions may continue blocking a new
consumer evaluation, but they do not supply positive coverage. Diagnostic
acceptance or completion does not resolve them.

No journal envelope, append acknowledgement, recovery report, reactor command,
reactor status, certificate, request, disposition, or receipt grants mutation
authority.
