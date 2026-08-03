# Focused reconnaissance

Status: completed 2026-08-03. The project name `monitor-skunkworks` is
provisional.

This was a bounded, read-only reconnaissance pass. Its purpose was to fix this
project's jurisdiction before defining runtime semantics, not to import an
existing architecture. The inspected repositories were clean at the recorded
commits before and after the pass:

| project | inspected repository | commit |
|---|---|---|
| NQ-NG | `/home/jbeck/git/skunkworks/nq-ng` | `59abd3bcb2d0` |
| Witness | `/home/jbeck/git/nq-root/nq-witness` | `e3d22f9bef8d` |
| Nightshift | `/home/jbeck/git/nightshift` | `500f4b7bd4f0` |
| Docket campaign / runtime | `/home/jbeck/git/docket` | `3ce07f9bb3be` |
| Synesthesia | `/home/jbeck/git/synesthesia` | `d1a731c383d4` |

The older witness-ledger protocol was located but was not treated as current
law. NQ Classic was consulted only through its repository guidance where that
was necessary to disambiguate the current Witness repository.

## Sources selected

The pass stopped after the ownership boundaries and seam shape were clear. The
principal surfaces were:

- NQ-NG `README.md`, `docs/NORTH_STAR.md`, `profiles/README.md`,
  `diagnostic-contract-v2/README.md`, its v2 execution record, and selected
  hostile contract tests.
- Witness `README.md`, `SPEC.md`, and the identity/coverage portions of its
  concrete profiles.
- Nightshift `README.md`, `docs/architecture/DESIGN.md`, the tolerability
  horizon flow, `docs/NQ_RELIANCE_SOURCE.md`, and the closed diagnostic
  operation and scheduled-idempotency implementations.
- Docket's governed-runtime invariants, architecture, trust model, bridge
  specifications, and the Continuity-to-NQ seam report.
- Synesthesia `README.md`, `docs/design.md`, and its temporal model and status
  projection surfaces.

## Concepts directly reusable

"Reusable" means the principle is adopted and expressed in this project's own
types and vocabulary. It does not mean source code or schemas are copied.

1. **Exact, versioned identities.** NQ-NG distinguishes request, run, profile,
   vantage, state model, evaluator, threshold policy, and evidence identities.
   Docket distinguishes a request from one provider run and from an admitted
   exact attempt. This project likewise needs separate subject, observer,
   incarnation, observation-profile, policy-generation, evidence-window, and
   escalation-occurrence identities.
2. **Receiver-owned reliance.** NQ-NG testimony does not mint downstream
   reliance, and Nightshift applies its own age and consumer policy. A pulse
   producer therefore cannot declare a subject current or grant a consumer
   permission to rely.
3. **Complete input accounting and explicit nonclaims.** NQ-NG retains selected,
   excluded, missing, failed, and refused inputs and emits material
   limitations. Present-state judgments should similarly carry coverage,
   missingness, exact reasons, and stable nonclaims.
4. **Coverage is explicit and current-cycle-specific.** Witness requires
   current coverage demotion on partial acquisition and forbids sticky inferred
   coverage. Aggregation here must preserve expected, active, missing, and
   expired coverage rather than count only received pulses.
5. **Typed refusal is useful evidence.** NQ-NG keeps complete refusal carriers,
   including multiple refusals, and Nightshift distinguishes a fresh refusal
   from silence. This project should retain rejected, unauthenticated, stale,
   and unsupported observations as distinct facts rather than one generic
   error.
6. **Bounded, predeclared diagnostics.** Nightshift's diagnostic operation
   category is closed and operation-specific; Docket treats tool requests as
   provenance, not authority. The L3 bridge should accept only a named profile
   from a local registry with explicit cost, resource, and expiry bounds.
7. **Expiry does not revive authority or currency.** Nightshift separates
   evidence freshness from tolerance horizons; Docket forbids revival of
   expired records. This project applies expiry to positive reliance and to
   escalation requests, while keeping those two clocks semantically separate.
8. **Immutable sparse receipts beside current projections.** Docket's split
   between current projections and immutable typed history is appropriate for
   judgment transitions, contradiction lifecycle events, escalation
   dispositions, and diagnostic receipts. It is not a reason to persist the
   high-rate pulse stream.
9. **Hostile, substitution-oriented validation.** NQ-NG and Docket test
   individually well-formed artifacts whose cross-bindings are wrong, rather
   than only malformed bytes. Replay tests here should mutate order,
   incarnation, generation, time, coverage, and correlation independently.
10. **Human status must name projection and loss.** Synesthesia keeps source,
    temporal model, and view separate; it exposes distinct loss counters and
    makes stale decay visible. A later human view can reuse that discipline:
    show evidence dimensions and observation blindness, never just a green
    scalar.

## Similar concepts that must remain separate

| nearby concept | this project's concept | required separation |
|---|---|---|
| NQ diagnostic execution | pulse and present-state evaluation | A pulse is cheap recurrent observation testimony, not a completed diagnostic or NQ disposition. |
| NQ compiled diagnostic profile | observation profile | The observation profile defines bounded pulse fields and coverage; it does not contain NQ's diagnostic derivation law. |
| Witness report | pulse frame | Witness reports are richer bounded acquisition documents. A pulse is a compact hot-path occurrence with receiver annotation and continuity semantics. |
| Witness standing | consumer reliance policy | Producer-declared standing cannot decide whether a named consumer may rely now. |
| Nightshift recurrence and tolerance horizon | pulse cadence and freshness | Cadence says when observation is expected; freshness says whether evidence is current; tolerance is an operational deferral policy owned elsewhere. |
| Nightshift posture | present-state judgment | Nightshift composes diagnostic operations across time. This project evaluates a bounded present evidence window only. |
| Docket work request / attempt | diagnostic escalation request | Escalation asks for deeper observation. It neither describes nor admits an effect and carries no mutation authority. |
| Docket recovery resolution | contradiction resolution | Resolving an evidence contradiction changes its visibility under a named rule; it does not resolve an indeterminate mutation attempt. |
| Synesthesia normalized event | sparse durable event | Synesthesia's event is rendering input. This project's sparse event is an auditable semantic transition, not a visual primitive. |

## Concepts dangerous to inherit implicitly

- **`pulse received` as `subject healthy`.** Transport success proves only a
  bounded observation occurrence and its receiver-side arrival facts.
- **Sender wall time as the freshness clock.** Sender timestamps can be useful
  provenance, but receiver-observed monotonic arrival and receiver evaluation
  time govern freshness. Pre-receipt delay cannot always be detected and must
  remain a stated gap.
- **Producer-minted authority or standing.** The draft Witness v0
  `authoritative_for` field is specifically not promoted by NQ-NG's current
  direction. This project will not accept it as consumer reliance.
- **A quorum as contradiction resolution.** Majority agreement may describe
  distribution, but it cannot erase independently grounded conflicting
  evidence.
- **"Latest row" as present truth.** Queueing, replay, retry, and last-value
  retention must not reset evidence age.
- **One confidence score.** A scalar would hide whether weakness came from
  freshness, observer absence, coverage, provenance, transport, sequence, or
  incompatible observations.
- **Diagnostic success as durable health.** A receipt establishes only the
  bounded diagnostic execution and findings it names, for its own interval and
  scope.
- **Escalation as action authority.** NQ selection, Nightshift recurrence, AG
  authorization, and Docket mutation remain outside this repository. No bridge
  response grants repair authority.
- **Generic execution or agent APIs.** A user- or agent-supplied command would
  turn the seam into an authority bypass. Agents may select or explain an
  already-declared profile only.
- **Implicit storage-platform inheritance.** NQ stores diagnostic custody;
  Nightshift stores recurrence; Docket stores governed work. None justifies a
  telemetry lake, TSDB, or generic event store here.
- **Presentation semantics as evaluation law.** Synesthesia is a potential
  downstream renderer. Its decay, bins, colors, and glyphs cannot define
  reliance or erase missingness.

## Proposed NQ-NG seam objects

The initial bridge remains a local stub. These objects establish the shape to
test before any NQ-NG integration is claimed.

### `DiagnosticEscalationRequestV1`

The request contains:

- exact subject scope and consumer/reliance class;
- trigger class and the causal judgment-transition identity;
- evidence-window digest and observation-policy generation;
- one requested predeclared diagnostic-profile identity;
- explicit runtime, output, and observation-count bounds;
- receiver-clock identity, creation time, and expiry;
- a stable semantic deduplication key; and
- nonclaims stating that the request is not diagnostic evidence,
  authorization, or a command.

It deliberately contains no shell command, argument vector, mutation target,
credential, generic tool call, or free-form authority field.

### `EscalationDispositionV1`

The bridge returns exactly one of `accept`, `refuse`, `narrow`, or `defer`, with
the request identity, decision time, responsible bridge identity, and a typed
reason. `narrow` returns the smaller allowed profile/bounds for explicit
resubmission. `defer` does not extend expiry. Only `accept` may begin the named
bounded diagnostic.

### `MockDiagnosticReceiptV1`

The skunkworks receipt correlates request, deduplication key, causal transition,
diagnostic profile, run occurrence, execution interval, bounded result digest,
and explicit nonclaims. It records a harmless local stub execution only. A
future real integration should consume NQ-NG's independently versioned
diagnostic-execution contract rather than relabel this mock receipt as NQ
testimony.

### Direction and ownership

```text
monitor evaluator
  -- DiagnosticEscalationRequestV1 --> bounded bridge / future NQ adapter
  <-- EscalationDispositionV1 ------
  <-- NQ-owned execution artifact -- only after accepted execution
```

The monitor owns the trigger, evidence-window binding, consumer, deduplication,
and causal transition. The future NQ adapter owns translation into an admitted
NQ request and must preserve any refusal exactly. NQ owns diagnostic execution
and its evidence artifact. Returning a receipt can enrich the monitor's
evidence model; it cannot make a present-state judgment current indefinitely.

## Modification confirmation

No file, index, branch, tag, configuration, worktree state, or remote in NQ-NG,
Witness, Nightshift, Docket, or Synesthesia was modified. Their recorded Git
statuses were empty before and after reconnaissance. The pre-existing modified
and untracked files in `/home/jbeck/git/skunkworks/formalization/` were not
opened for editing or staged. This new work was created in a separate temporary
Git root for later placement as an adjacent standalone repository.
