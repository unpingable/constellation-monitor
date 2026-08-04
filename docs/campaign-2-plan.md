# Receiver/scheduler campaign plan

Status: implementation plan written before campaign code changes.

Starting qualified commit:
`0a9fe16e6d091c6b4b1128fcb6166e53d712fc3f`.

The campaign will keep the existing evaluator as the deterministic semantic
kernel and add the smallest enclosing runtime that can own receiver time,
bounded admission, exact reliance-context generations, and support deadlines.
It will not introduce a generic scheduler or transport framework.

## Reconnaissance findings that constrain the work

- `PulseFrameV1.policy_generation` currently binds collection-side pulse
  semantics, while `ReliancePolicyV1.generation` also names the consumer
  evaluation law. The first campaign used the same value for both. This
  campaign will separate those roles explicitly; it will not relabel old
  evidence or infer generation equality from content equality.
- `PresentStateJudgmentV1` exposes the inclusive earliest support-expiry
  deadline, but only explicit ingest/tick calls currently reevaluate it. The
  new runtime must own scheduling of that deadline.
- Current standing, hot pulse evidence, receiver lineages, and active
  escalation deduplication are in memory. Sparse transition records and mock
  diagnostic receipts are historical records. This permits restart into
  `UNKNOWN` without reconstructing standing.
- Contradictions have explicit lifecycle states and diagnostic completion does
  not resolve them. Applicability is not yet a general rule language. The
  campaign will add only exact incarnation/consumer custody needed to prevent
  laundering during transition and restart.
- Existing ordered maps and receiver-clock evaluation make deterministic
  ordering possible without depending on hash iteration or thread scheduling.

## Implementation sequence

1. Write a normative receiver/scheduler contract, generation-transition law,
   simultaneous-event ordering, contradiction-custody rule, persistence split,
   overload posture, and exact claims/nonclaims.
2. Add versioned exact reliance-context identities and bounded support
   certificate/runtime event types. Keep observation-policy generation
   distinct from reliance-policy, consumer-profile, evaluator-semantic, and
   observer-set generations.
3. Add a `pulse-runtime` crate that owns bounded input admission, subject and
   observer cardinality, per-consumer evaluators, earliest-deadline scheduling,
   synchronous generation barriers, restart behavior, bounded sparse history,
   and typed refusals. No bound failure may silently evict evidence or preserve
   `CURRENT`.
4. Extend the evaluator only where needed to export/import bounded historical
   contradiction custody and to perform an explicit policy replacement that
   first withdraws standing. Evidence reconsideration will be an explicit
   evaluation under the complete new reliance context.
5. Build deterministic qualification and demo binaries plus a bounded local
   Linux `/proc` exercise. Check in machine-readable reports and separate
   logical-clock results from wall-clock measurements.
6. Run format, strict Clippy, all tests, deterministic artifact comparison, and
   source/status audits. Commit coherent local milestones, fast-forward the
   standalone repository only, and verify it remains clean and remote-free.

## Conservative ordering rule to qualify

For one receiver-clock instant, the runtime applies: clock-integrity and
overload withdrawals; exact generation barriers; inclusive support expiry;
admitted pulse inputs in receiver ordinal order; then explicitly requested
reevaluation and sparse output. A generation barrier always emits or records a
non-positive standing under the new exact context before evidence can be
reconsidered. Thus an expiry tied with a policy transition cannot inherit the
old positive result.

## Stop audit

No campaign stopping condition is presently reached: identity is distinct from
content; current standing is not durably entangled with history; a total event
ordering can be specified; bounds can refuse explicitly; and contradiction
non-laundering can be implemented without a broad resolution language. Any
contrary implementation or test finding will stop the campaign and be reported.
