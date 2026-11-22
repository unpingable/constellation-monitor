# Duty-scoped host availability — Monitor #26

The owner's implementation decision is Monitor #26 (2026-11-21). This is an
implementation note, not another approval gate. Base: Monitor `8468286`.

Known or online hosts acquire no availability obligation by observation. A
trusted off-host operator assigns an explicit workload duty to a registered
host incarnation. Only an explicit operator disposition or atomic transfer
ends that assignment; disappearance and shutdown claims cannot do so. Expiry
is overdue outstanding work, never successful completion. A boot changes the
observed session, not the duty. Replacement requires an explicit incarnation
change after old duties are released or transferred.

Use Monitor's Python operational tools and SQLite, like its incident owner.
Do not change NQ profiles, Cargo.lock, Pulse contracts or action authority.
Ordinary reachability/sample records are observer facts, not NQ-admitted
diagnoses. Existing metrics collection continues independently of duty.

## Deliverables and ownership

1. `host_duty/core.py` and real-SQLite regression tests: explicit durable host,
   workload and duty state, atomic reassignment, audit trail, indexed current
   reads, bounded observation history, no remote I/O under a writer lock.
2. `host_duty/cli.py`, `probe.py`, `sample.py`: owner-only off-host CLI and
   bounded fresh external acquisition using the existing SSH transport. Target
   identity and nonce bind samples; failed acquisition cannot fabricate health.
3. `host_duty/concerns.toml`, operational docs and package/unit assets: emit
   `project.ops.status/v1` for existing estate → attention → incident handling.
   `PRESENT` for an unbreached conditional duty never asserts host health.
4. Regression tests, independent review and disposable installed proof for all
   issue cases. Use the approved provider mechanisms, finite scoped identities
   and verified teardown. Prepare fatbot deployment; coordinate its real build
   and interruption with the host's resource owner before affecting it.

## Core API for the CLI/probe consumer

`Ledger.create(path, clock=None)` creates an owner-only new ledger;
`Ledger(path, clock=None, readonly=False)` opens an existing ledger, never
implicitly initializes it. Both support `close()`/context-manager use.

- `register(host_id, instance_id)`; `replace(host_id, instance_id, reason)`.
- `assign(duty_id, work_id, host_id, deadline, reason="")`.
- `release(duty_id, disposition, reason, evidence_sha256=None)` where a completed
  disposition requires explicit operator confirmation and an evidence hash.
  It records an operator decision, not an automatically verified outcome.
- `transfer(duty_id, successor_id, host_id, deadline, reason)` is atomic and
  preserves the workload identity; repeated settled mutations refuse.
- `observe(host_id, instance_id, state, *, boot_id=None, observed_at=None,
  detail="", telemetry=None, source_sha256=None)` accepts external `reachable`,
  `unreachable` or `unknown` observations. Wrong incarnation and retired boot
  sessions refuse; old samples cannot refresh a newer head.
- `shutdown_claim(host_id, instance_id, reason)` records a claim without
  changing duty or observed reachability.
- `report(host_id, freshness_seconds=60, grace_seconds=30)` returns identity,
  availability requirement, current presence, duties, overdue state and source
  age. `status_document(...)` wraps this in the existing concern contract.
- `hosts()`, `duties(host_id=None)`, `events(limit=100)` are bounded read APIs.

Use epoch seconds internally. The CLI uses the real observer clock; tests
inject a clock. The trusted local account owns ledger mutations; a target is
not given that account or any release interface. No generic verifier or worker
orchestrator is introduced. Operator-confirmed completion remains labelled as
such, separate from an automated independently verified build result.

## Verification and boundary proposition

Tests exercise real SQLite transactions and the consumer-visible state, with
literal expected outcomes: offline/online idle, lost on-duty host, shutdown
claim, cancel/complete/release, overdue duty, boot change, retired incarnation,
atomic transfer, restart, concurrent writer refusal, corrupt/missing ledger and
stale/malformed observations. Probe tests use actual processes/loopback servers
for timeout, output bounds and identity/nonce refusal. Then run existing Python
estate/incident/work-observation suites and applicable repository checks.

The durable invariant is: observation events alone never reduce the set of
outstanding duty commitments. A terminal disposition needs an operator mutation;
transfer closes the predecessor and creates its successor in one transaction.
A finite transition test plus real transaction/restart/concurrent-writer tests
is the chosen bounded model. It proves neither an untrusted operator's honesty,
cryptographic authorization, complete host health nor arbitrary distributed
execution settlement. Decision owner: Root under the owner's #26 mandate.
