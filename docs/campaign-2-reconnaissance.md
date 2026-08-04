# Receiver/scheduler campaign reconnaissance

Status: completed read-only on 2026-08-03 before campaign implementation.

## Starting repository

The exact qualified starting commit was
`0a9fe16e6d091c6b4b1128fcb6166e53d712fc3f` on `main`. The tree was clean and
had no configured remote. Its four commits were the focused reconnaissance,
normative semantics, five-crate vertical slice, and hostile qualification
milestones. The baseline passed:

```text
cargo fmt --all -- --check                                      PASS
cargo clippy --workspace --all-targets --all-features -- -D warnings PASS
cargo test --workspace --all-targets --all-features            PASS (41)
```

The README, architecture, reconnaissance, invariants/non-goals, threat model,
escalation seam, hostile-scenario specification, checked-in demo report, every
public crate API, manifests, and integration/property tests were inspected.

## Existing representation findings

- Support expiry is the inclusive receiver-clock deadline exposed as
  `PresentStateJudgmentV1.positive_support_expires_at_monotonic_ms`. The
  evaluator expires it correctly on ingest or tick, but no runtime schedules
  that tick.
- `PolicyGenerationId` is an exact value rather than policy content, but the
  first slice uses it both in `PulseFrameV1` and `ReliancePolicyV1`. Collection
  policy and reliance policy therefore need explicit separation before
  evidence can be lawfully reconsidered across a reliance-policy transition.
- Judgments are consumer-indexed because an `Evaluator` owns exactly one
  `ReliancePolicyV1`. There is no multi-consumer runtime owner.
- Active contradictions are exact `ContradictionRecordV1` values with explicit
  lifecycle state. Every active record currently blocks its evaluator;
  applicability across an explicit subject replacement is not represented.
- Escalation deduplication is keyed by subject scope, consumer, policy
  generation, trigger, and diagnostic profile, with inclusive request expiry.
  It is in-memory and evaluator-local.
- `SparseDurableEventV1` holds semantic transitions, contradiction lifecycle,
  escalation facts, diagnostic receipt correlation, and monitor degradation.
  Hot pulses and current standing are not persisted.

These representations do not reach a stopping condition. Identity is not
derived from content, current standing is not entangled with durable history,
and ordered maps plus receiver time permit an explicit total event order.

## Bounded donor recheck

Only paths already identified as lawful conceptual donors in the first
reconnaissance were rechecked. No schema, type, or implementation was copied.

| project | commit | paths inspected | principle retained |
|---|---|---|---|
| NQ-NG | `59abd3bcb2d0cc30657a659b3ebc57b981289d9f` | `docs/NORTH_STAR.md` (static profile cohorts); `diagnostic-contract-v2/README.md` | Semantic policy, evaluator, profile, and build inputs need exact independent identities; schema/content resemblance is not reliance. |
| Witness | `e3d22f9bef8dc248e58e0fa5b7fa474b2dd78c5d` | `SPEC.md` coverage and partial-cycle rules | Coverage is current-cycle-specific; partial acquisition demotes coverage in the same occurrence and never remains sticky. Producer standing is not imported. |
| Nightshift | `500f4b7bd4f066c7ca43963d192f314559cdbc83` | `crates/nightshiftd/src/scheduled.rs`, `crates/nightshiftd/src/freshness.rs`, `docs/architecture/FLOW-tolerability-horizon.md`, `docs/NQ_RELIANCE_SOURCE.md` | Receiver-owned time cannot be laundered by custody; expiry and recurrence are separate; exact generations support idempotency but do not create present reliance. |
| Docket | `3ce07f9bb3be6ba86ca65f3b521f807970b56119` | `normative-packet/implementation-plan.md`, `normative-packet/proved-negatives.md`, `continuity-nightshift-support/stage8-docket-continuity-subject-audit.md`, `stage9-docket-continuity-subject-design.md` | Immutable history and current projections are distinct; equal endpoints/content are not equal transitions; expired records do not revive; historical fact does not imply current standing. |
| Synesthesia | `d1a731c383d4fce8f9bc21f40b63af5dbae2aa94` | `docs/design.md`, `src/ingestion.rs` | Every memory-bearing stream needs a ceiling, saturation needs an explicit loss counter, and temporal projection is separate from source receipt. |

The donor repositories were clean at the listed commits before and after this
read-only pass. No neighboring repository was modified.

