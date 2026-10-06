# Bounded recurrence policy — design recommendation

Investigation recorded 2026-10-06 against Monitor
`ea7438aa6dc365525a614620c5e091ee9643522e`. Status: **design/acceptance decision
required for a lifecycle extension**. The accompanying tests describe current
behavior, not acceptance of a new suppression policy.

## Finding and evidence scope

The reported resolve at 10:53 followed by a trigger at 10:59, with 301 s of
stale presence against a 300 s bound, follows the existing state machine. A
resolve clears presence timing; recurrence starts a fresh interval. Accepted
inactive conditions are pruned. There is no post-resolution cooldown, recurrence
counter or separate notification episode.

The original attention implementation and the explicit
`recurrence_while_a_trigger_is_pending` regression already expect another trigger
after its bound. Owning attention qualification describes persistence and clear
confirmation. Deferred notification-policy work is adjacent, not an omitted
specified cooldown. Classification: **correct-but-incomplete notification policy**,
with ambiguous earlier use of “flap” in documentation. No lost implementation
requirement was found in the searched history, issues or current contracts.
The exact deployed identity and production occurrence were not read; the
authorized existing SSH agent was unavailable. Source reproduction cannot
establish what caused the actual NQ collection-currentness oscillation.

The five new `stale_input_*` integration regressions use the real evaluator
binary, NQ status parser and persisted state, with the existing local NQ
submission fixture. They exercise exact 300/301 s and 119/120 s boundaries,
repeated episodes, fault-class/unknown handling and replacement of a failed
resolve. Delivery fixtures establish local decisions/commands, not live Slack
or PagerDuty delivery.

## Smallest defensible extension

Recommend an **opt-in, notice-only recurring episode** for
`evaluator-input-unavailable`, keyed by the exact existing condition identity.
Keep raw condition decisions, input evidence and currentness unchanged. The
first ordinary trigger remains immediate after its existing bound. A recurrence
after observed resolution opens a separate notification episode and sends a
clear “recurrent monitoring failure” notice. Subsequent notice transitions may
be coalesced into bounded summaries under an owner-selected recurrence horizon
and summary cadence. Never silently suppress the first notification of a new
fault class. Do not extend this policy to pages in the initial scope.

Retain bounded recent-resolution and notification-episode state independently
of `ConditionState`, so pruning a raw inactive condition does not destroy the
needed memory. Each report must expose raw observation/decision alongside the
notification episode, pending summary and coalesced counts. A summary states
the actual current state (including unknown), transition count, time range and
what was not delivered individually. A suppressed transition cannot set raw
state to healthy or count unknown time as recovery. A final recovery summary
needs observed clear confirmation; configuration removal says “no longer
evaluated; recovery not observed.”

This is a proposal, not selected defaults. Before implementation the owner must
accept the recurrence horizon, summary cadence and final-summary behavior;
decide whether coalescing is wanted at all; and name configuration/migration
ownership. Successful delivery versus attempted/unknown delivery must remain
separate. Do not choose a horizon from an unrelated retry constant or merely
increase the 120 s/300 s thresholds. A read-only recurrence annotation without
suppression is the fallback if suppression policy remains unaccepted.

## Required interaction boundaries

| Boundary | Requirement for the proposed extension |
|---|---|
| Fault classes | Exact `{input}.{fault}` scope; a stale episode cannot suppress a new unreadable/indeterminate notice. Other faults make this class unknown, not clear. |
| Unknown gaps | Preserve current short-gap tolerance and long-gap exclusion. Unknown cannot close an episode; elapsed time is not observed recovery. |
| NQ identities | Condition/dedup key remains stable. Each summary needs a fresh stable event ID and exact retry bytes. Evidence and notification summaries stay distinct. |
| Restart/custody | Persist summary decision before submit; recover the same event after uncertainty. Expiry of recent history must not discard pending delivery/custody. |
| Ordering | Preserve existing trigger-before-resolve attempts and dropped-trigger reporting. Define explicit treatment of an unaccepted resolve superseded by recurrence; do not claim complete sink delivery. |
| Routes | Input-unavailable is attention-only. No page eligibility or PagerDuty authority is added; existing page rules keep ordinary recurrence until separately qualified. |
| Removal | Mark no-longer-evaluated, retain outstanding custody and stop new notices for removed scope; never call this observed recovery. |
| Clock | Backwards time still refuses. Specify reset/migration of every new timestamp, preserve frozen event bytes and avoid duplicate decisions after reset. |

## Compatibility, acceptance and limits

Current changes touch tests and documentation only: state/config/report/intent
schemas, registry versions, thresholds and defaults remain unchanged. A future
persisted notification-history field changes state compatibility because current
readers deny unknown fields. It needs an explicitly versioned state contract,
tested migration and rollback/refusal behavior, bounded retention and policy
identity binding. Report additions and any summary configuration must also be
versioned deliberately. Do not add a new NQ protocol to render a notice when
the current notice contract suffices.

Acceptance should cover the exact reported cycle; one initial recurrence notice
followed by visible coalescing; unknown and fault-class changes; summary expiry
while present, clear or unknown; restart before/after NQ custody; failed resolve
followed by recurrence; configuration removal; and reset-clock. Assert raw
reports still expose every evaluated condition and no suppression affects page
eligibility or effect authority. Use dedicated local/test routes, not production.

The existing behavior is contract-consistent but must not be advertised as
cross-episode flap suppression. Operator-beta suitability for this notice
churn needs an explicit accepted limitation or the separately accepted extension.
This investigation neither invalidates unrelated qualification nor establishes
that the deployment is healthy.

Formalization consideration: the durable proposition is that notification
coalescing cannot alter raw observation, evidence currentness, fault-class
identity or effect/page authority. Current tests and source/history review
suffice to document existing behavior. Any implemented notification episode
warrants a small transition model covering unknown, removal, restart and clock
reset plus deterministic correspondence tests. Integration owner records this
proposal; policy and independent acceptance owners select its bounds. No
universal anti-flapping or successful-delivery guarantee is claimed.
