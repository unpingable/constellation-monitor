# Local crash-fault reactor campaign plan

Status: implementation plan fixed on 2026-08-03 before campaign code changes.
The repository and component names remain provisional.

Starting point: exact clean commit
`668589e537e9cffe151913f72ca45a61ca32b1d7` on `main`, with no configured
remote. The baseline passed formatting, strict clippy, and all 73 tests.

## Scope

1. Preserve the existing deterministic `ReceiverSchedulerRuntime` as the
   semantic kernel. Add only the public hooks needed to report external
   reactor blindness and to inspect its bounded current projection.
2. Add one dedicated local thread, a condition-variable wakeup, and a bounded
   command mailbox. The thread maps one `std::time::Instant` origin to one
   explicit monotonic epoch and calls `run_until` itself at actual wake time.
3. Add one project-specific append-only journal. A bounded data frame is
   checksummed and prior-linked; a separate commit marker is written and
   synced before a durable acknowledgement is returned.
4. Journal sparse events, receipt custody, and contradiction custody only.
   Never journal hot pulses, current projection, support ownership, active
   deadlines, current coverage, or diagnostic authority.
5. Add deterministic decoder/corruption tests, real-thread timer tests, and a
   Linux child-process `SIGKILL` harness at named write/reactor boundaries.
6. Produce deterministic demos, bounded live measurements, machine-readable
   artifacts, a campaign report, and a coherent local commit sequence.

## Deliberate constraints

- No async runtime, networking, database, compaction system, generic WAL,
  replication, remediation, or diagnostic executor is introduced.
- Valid-prefix recovery is explicit and incomplete. Recovery never skips an
  interior defect to continue with later bytes.
- Cross-restart escalation deduplication is historical evidence only. No
  active request or suppression lease is reconstructed.
- A process-kill test can distinguish a committed on-disk append from an
  uncommitted suffix. It cannot prove whether an acknowledgement already
  reached a caller after the final sync; that unavoidable ambiguity is
  reported rather than hidden.
- Any reactor mailbox, timer-custody, or required-journal failure makes the
  exposed temporal-custody status non-operational and withdraws positive
  standing when the actor is still alive.

## Qualification order

Contract and record format precede implementation. Pure framing/recovery
tests precede reactor integration. Existing tests run throughout. Final
qualification runs formatting, strict clippy, all workspace tests, all demos,
the crash harness, and the bounded live Linux exercise before commits are
fast-forwarded into the standalone repository.
