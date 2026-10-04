# Operator attention evaluator

`constellation-attention` decides when a person should be told that a
Constellation component needs attention, and asks NQ to tell them. It answers
Cartography issue #20 (who evaluates the beta alert registry) for the rules
whose inputs exist today.

**Minimum NQ: 0.2.2.** Every intent carries `response_class`, which NQ
0.2.2 introduced. NQ 0.2.1 parses intents with unknown fields refused, so it
refuses every intent from this build before custody: nothing would be
delivered. Do not install the evaluator against an NQ older than 0.2.2.

## Boundary

The evaluator consumes qualified, current product state and produces
notification intents. Nothing else.

- It is **not evidence authority.** It reads status objects, NQ's status
  export, the Nightshift observation store and NQ saved-check results as their
  owners publish them. It never admits, signs, repairs or re-derives evidence.
- It is **not observation authority.** It does not probe hosts, units, files or
  endpoints. When an input cannot be read it says so
  (`evaluator-input-unavailable`) and holds every condition whose evidence
  that input no longer carries.
- It is **not execution authority.** A notification grants no permission and
  triggers no action. Nothing here restarts, silences or reconciles anything.
- It is **not a policy language or rules engine.** The registry below is
  compiled in and versioned (`constellation.attention_registry.v4`).
  Configuration may enable or disable a rule, change its one threshold, and
  move a page rule down to `notice` (never another rule up to `page`). There are no
  user-defined rules, expressions or plugins.
- **Delivery is NQ's job.** The evaluator writes a canonical intent file and
  runs `nq notification submit` (or `resubmit`, or `deliver-local` for a
  `local_file` route), then records NQ's answer. It never talks to Slack,
  Discord or PagerDuty, never reads route secrets, and stores none.
- It never reads Classic NQ (`/opt/notquery`).

## Registry

Bounds are defaults; `threshold_seconds` overrides the one threshold. For
*persistence* rules the threshold is how long the underlying state must
persist; for *age* rules it is the age a source timestamp must exceed, after
which the condition must persist a further fixed time. Runbook anchors marked
(C) are in Cartography `architecture/beta-observability/docs/RUNBOOKS.md`;
anchors marked (M) are below in this document.

| Rule | Class (default) | Response class | Bound | Component | Target class | Input | Runbook | Operator response |
|---|---|---|---|---|---|---|---|---|
| `host-posture-unknown` | page | page | persists 600 s | `host_posture` | publication-root label | host-posture `CURRENT` of projection `operator-filesystem-capacity`: `aggregate_state` unknown, or `fresh_until` passed | (C) `host-posture-unknown` | Follow the runner's refusal code; re-enroll on digest mismatch. |
| `host-disk` (v3) | notice | attention | persists 900 s | `host_posture` | publication-root label, or the NQ filesystem watcher's instance id (e.g. `fs-zonestorage`) | host-posture `CURRENT`: current and `aggregate_state` degraded or worse; or NQ: newest `nq.host_filesystem_capacity` version 1 evaluation of a non-stale watcher reports `filesystem_capacity_pressure` present | (C) `host-disk` | Ordinary host operations; check NQ store, host-posture state root, Nightshift stores, Classic backups. |
| `nq-no-fresh-acquisition` | page | page | age 600 s, then persists 300 s | `nq` | publication-root label | host-posture `CURRENT`: `generated_at_unix_ms` | (C) `nq-no-fresh-acquisition` | Read the runner journal for `acquisition_refused`; start a stopped runner and watch two occurrences. |
| `service-down` | page | page | persists 180 s | `service` | unit name, e.g. `nqd.service` | NQ status input: newest `nq.systemd_unit` version 2 evaluation of a non-stale watcher reports `systemd_unit_not_active` present | (C) `service-down` | `systemctl status <unit>`; restart if failed; read preflight errors. |
| `memory-pressure` | notice | attention | persists 600 s | `host_posture` | none | NQ status input: newest `nq.host_memory` version 1 evaluation of a non-stale watcher reports `memory_pressure_stall` present | (M) [`memory-pressure`](#memory-pressure) | Check PSI and the largest resident processes. |
| `nightshift-recurrence-missing` | page | page | age 1800 s, then persists 300 s | `nightshift` | Nightshift input label | Nightshift store: newest `canonical_observation_cycles.updated_at` with `status = 'closed'` | (C) `nightshift-recurrence-missing` | Check `nightshift-*` timers; slow ticks see `nightshift-cycle-slow`. |
| `sqlite-health` | notice | attention | persists 600 s | `nq` | saved-check reference | one `nq saved-check evaluate` document per reference: current `outcome` failed | (M) [`sqlite-health`](#sqlite-health) | Inspect the retained result and the named SQLite file. |
| `evaluator-input-unavailable` | notice | attention | persists 300 s | the input's (`host_posture`, `nq`, `nightshift`) | `{input label}.{fault class}` | the evaluator's own read of each configured input | (M) [`evaluator-input-unavailable`](#evaluator-input-unavailable) | Read `report.json`; fix the path, permission or producing timer. |
| `docket-unsettled` | page | page | age 3600 s, then 300 s | `docket` | — | disabled: input not deployed | (C) `docket-unsettled` | — |
| `ag-executor-unavailable` | page | page | persists 300 s | `ag` | — | disabled: input not deployed | (C) `ag-executor-unavailable` | — |

The response class is the registry's page eligibility, explicit per rule
and closed (`informational`, `attention`, `page`; no rule is informational
today). Only the six `page` rules can reach a PagerDuty route; configuration
may move a page rule down to `notice` but never moves another rule up, so
`[rules.host-disk] class = "page"` is refused. NQ 0.2.1's v2 contract
accepts 17 Cartography anchors (`host-disk` among them); `memory-pressure`,
`sqlite-health` and `evaluator-input-unavailable` are not anchors at all.
`host-disk` is version 3: version 2 added NQ filesystem watchers, version 3
made it attention-only.

### Classification

Generated from the registry (`constellation-attention rules` prints the
same `response_class`, `operator_action` and `escalation_reason`).

| Rule | Informational | Attention | Page | Escalation/persistence condition | Operator action |
|---|---|---|---|---|---|
| `host-posture-unknown` | condition row in `report.json` from first observation | notice copy of the page (`response_class: page`); a configuration-removal resolve (`attention`) | trigger and resolve on `page_route` (v2) once it persists 600 s | Unknown or stale for more than 600 s: the projection has stopped saying anything about disk pressure, so a full disk would go unseen. | Read the runner's refusal code in its journal and fix the cause it names (re-enroll on digest mismatch); the projection cannot recover by itself. |
| `host-disk` | condition row in `report.json` from first observation | trigger and resolve on `notice_route` (v1, `attention`) once it persists 900 s | never (not page-eligible) | persists 900 s; persistence never escalates it to a page | Ordinary host operations: check the NQ store, host-posture state root, Nightshift stores and Classic backups first. |
| `nq-no-fresh-acquisition` | condition row in `report.json` from first observation | notice copy of the page (`response_class: page`); a configuration-removal resolve (`attention`) | trigger and resolve on `page_route` (v2) once it is older than 600 s, then persists 300 s | No status object generated for more than 600 s, then 300 s more: the host-posture runner has stopped and nothing is being observed. | Read the runner journal for acquisition_refused; if the runner is down start it and watch two occurrences. |
| `service-down` | condition row in `report.json` from first observation | notice copy of the page (`response_class: page`); a configuration-removal resolve (`attention`) | trigger and resolve on `page_route` (v2) once it persists 180 s | The unit is not active for more than 180 s: past a restart or reload window, the service is down until someone acts. | systemctl status <unit>; restart it if failed; if it refuses to start read its preflight and identity errors. |
| `memory-pressure` | condition row in `report.json` from first observation | trigger and resolve on `notice_route` (v1, `attention`) once it persists 600 s | never (not page-eligible) | persists 600 s; persistence never escalates it to a page | Check PSI (/proc/pressure/memory) and the largest resident processes; this is stall pressure, not memory used. |
| `nightshift-recurrence-missing` | condition row in `report.json` from first observation | notice copy of the page (`response_class: page`); a configuration-removal resolve (`attention`) | trigger and resolve on `page_route` (v2) once it is older than 1800 s, then persists 300 s | No closed observation cycle for more than 1800 s, then 300 s more: the recurring observation has stopped and evidence is going stale. | systemctl list-timers 'nightshift-*'; start an inactive timer; slow ticks see nightshift-cycle-slow. |
| `sqlite-health` | condition row in `report.json` from first observation | trigger and resolve on `notice_route` (v1, `attention`) once it persists 600 s | never (not page-eligible) | persists 600 s; persistence never escalates it to a page | Inspect the saved check's retained result (nq saved-check result) and the named SQLite file; do not edit the store. |
| `evaluator-input-unavailable` | condition row in `report.json` from first observation | trigger and resolve on `notice_route` (v1, `attention`) once it persists 300 s | never (not page-eligible) | persists 300 s; persistence never escalates it to a page | Read report.json for the input's error; fix permissions, paths or the producing timer. Rules fed by the input hold their state meanwhile. |
| `docket-unsettled` (disabled: input not deployed) | condition row in `report.json` from first observation | notice copy of the page (`response_class: page`); a configuration-removal resolve (`attention`) | trigger and resolve on `page_route` (v2) once it is older than 3600 s, then persists 300 s | The oldest accepted governed-loop attempt is older than 3600 s, then 300 s more: work is stuck unsettled. | Determine whether the executor is available or the observer never reported, then follow the Docket reconciliation procedure. |
| `ag-executor-unavailable` (disabled: input not deployed) | condition row in `report.json` from first observation | notice copy of the page (`response_class: page`); a configuration-removal resolve (`attention`) | trigger and resolve on `page_route` (v2) once it persists 300 s | AG effectd not ready for more than 300 s: governed actions cannot execute. | Check the ag-effectd unit; restart it only on a crash; an intentional stop is acknowledged for its declared window. |

`constellation-attention rules` prints the registry with versions.

## Inputs the evaluator can interpret

An input is `ok` only when everything it carries for these rules is
recognised. Otherwise it is `not_current` or `unavailable`, and a condition
whose evidence is missing or unrecognised is unknown (it holds) rather than
reading the gap as recovery. Lineages of the same input that are recognised
and current are still evaluated.

- Host posture: `CURRENT` must name projection `operator-filesystem-capacity`
  at a known generation (`filesystem-capacity-v1`). Memory, load, unit and
  inode producers write the same `status_artifact.v1` schema; any other
  projection or generation is `unavailable` with the reason.
- NQ status input: every evaluation of profile `nq.systemd_unit`,
  `nq.host_memory` or `nq.host_filesystem_capacity`, or of condition
  `systemd_unit_not_active`, `memory_pressure_stall` or
  `filesystem_capacity_pressure`, must be exactly `nq.systemd_unit` version
  2, `nq.host_memory` version 1 or `nq.host_filesystem_capacity` version 1
  with its condition, with an evaluation envelope and a valid
  `evaluated_at`. An unrecognised profile id or version, or an evaluation
  that cannot be parsed, makes the input `not_current`. Evaluations of other
  profiles feed no rule and are ignored. A filesystem watcher's instance id
  is the `host-disk` target class; its threshold is NQ's compiled detector
  (available space at or below 10 % of non-reserved capacity, i.e. about
  90 % used), not the evaluator's.

### NQ status sources

`[inputs.nq_status] source` chooses how the evaluations are read. Both give
the same lineages, checks and fault classes.

- `status_export` (default): `command` is the full argv of `nq --json status
  export` (or `path` names a file a timer writes). Liveness is each watcher
  instance's last collection (`observed_at`). `status export` walks the
  whole evaluation history (nq#20): on the Linode ops store it takes 26 s
  alone and 60–90 s under contention, so use it only for small stores.
- `evaluation_history`: `command` is the nq argv up to and including
  `--json` (for example `["/usr/bin/nq", "--config",
  "/etc/nq/nqd-ops.toml", "--json"]`); the evaluator appends `evaluations
  export`. It first asks for `--limit 1` to learn the store-wide
  `through_sequence`, then reads the newest `window_records` evaluations
  (default 300, 50..=5000) with `--after max(0, through - window) --through
  through`, paged at NQ's 1000-row limit (about 0.2 s a page). Liveness is
  each instance's newest `evaluated_at` in the window. A page that is not
  `complete`, or whose `through_sequence` moved, makes the input
  `not_current` (`stale`). The identity is the page `schema`,
  `generated_at` and `through_sequence`. Size the window so it holds more
  than `stale_after_seconds` of every watcher's evaluations (the nqd spike
  recorded two to four evaluations per watcher a minute: with 4 watchers,
  300 records cover roughly 20 to 35 minutes); a watcher with no evaluation in the window has no
  lineage, and if its condition is open the input reports `unreported`.
  Use this mode for operated stores.

  **Watcher roster.** The window alone cannot show a watcher that stopped
  evaluating: once its records scroll out it would simply vanish. So every
  watcher instance ever seen in the window is remembered in `state.json`
  (`nq_watchers`, with its newest `evaluated_at`; it survives a relabel of
  the input). A remembered watcher missing from the window is `stale`
  measured from that remembered time, and stays stale until the operator
  lists it in `[inputs.nq_status] retired_instances = ["unit-old"]`, which
  also drops it from the roster. Retire a watcher only after removing it
  from NQ; a retired id that evaluates again is read normally but never
  stale. Roster ids are at most 128 printable bytes (longer ids are reported
  `unrecognised` and not remembered), times are capped at the page's
  `generated_at`, an evaluation stamped more than 60 s after the page (a
  past forward clock step) counts as no liveness, and `reset-clock` clamps
  the roster like every other timestamp. **Rollback:** builds before
  bac0e1a refuse a `state.json` that contains `nq_watchers` (the state is
  read with unknown fields refused). Before rolling back, stop the timer and
  remove that field from the state file. `status_export` mode needs no roster: NQ's instance components
  keep `observed_at` for every configured watcher.

  **Ordering.** Per lineage the evaluation with the newest `evaluated_at`
  (full sub-second precision) wins. On an exact tie the later history
  record (higher sequence) wins. A later sequence with an earlier
  `evaluated_at` loses: the evaluator trusts NQ's evaluation time, not the
  append order.

  **Window sizing.** `window_records` must hold more than
  `stale_after_seconds` of every watcher's evaluations, or a live but quiet
  watcher reads as stale. Re-check it whenever watchers are added.

In both modes the snapshot's age and future skew are measured when the
source answered, not when the pass started, so a slow command (bounded by
`command_timeout_seconds`) is not read as a snapshot from the future. The
snapshot is current when it was generated at most `max_age_seconds` before,
and at most 60 s after, that moment.
- Saved checks: see [`sqlite-health`](#sqlite-health).

## Conditions and lifecycle

A condition's identity is NQ's derived dedup key:
`constellation:{site}:{component}:{rule}[:{target_class}]`. `site` and
`target_class` are bounded tokens (`[a-z0-9._-]`, 64 and 48 bytes) that must
not look like a digest, UUID, date, timestamp or bare number; the evaluator
applies NQ's own heuristic and refuses such labels in configuration. A unit
whose name maps to no bounded target class (a templated `@` unit, uppercase,
`\x2d` escapes, more than 48 bytes, or a date or long digit run in the name)
makes the NQ status input `not_current` with the unit named in its error, so
`evaluator-input-unavailable` tells the operator (fault class
`untargetable`); it is never skipped silently.

Each pass turns every input into one of three observations per condition:
**present**, **clear**, or **unknown** (input unreadable, not current,
indeterminate, refused, unrecognised, or a detector that cannot evaluate).
The state file keeps, per condition, `first_seen`, `last_seen`,
`clear_since`, `unknown_since`, `active`, `transition_at`, and the newest
intent per route role.

- Present: `first_seen` is set once. The condition becomes actionable only
  when it has persisted for longer than its bound, covered by present
  observations; then exactly one trigger is decided and `active` is set.
- Clear while not active: `first_seen` is reset. Presence below the bound is
  never notified, however often it recurs.
- Clear while active: the condition resolves exactly once after it has stayed
  clear for 120 s. A flap inside that window sends nothing.
- Unknown: nothing changes. Legitimate unknown or refusal never notifies on its
  own; it reaches the operator through `host-posture-unknown` (for the
  projection) or `evaluator-input-unavailable` (for an input).
- Unknown runs: time spent unknown never counts toward an interval, and
  never erases the observed part of it. At the next definite observation
  after a run of unknown observations longer than 90 s (one 60 s pass
  interval plus timer jitter), the interval's start (`first_seen`, or
  `clear_since` while active) moves forward by the run's length. A bound is
  therefore met only by present (or clear) observations, and a condition
  that is present whenever it can be observed still reaches it: cron.service
  down for two hours with NQ answering `cannot_evaluate` on 2 of every 6
  passes pages after about 240 s of observed presence. One unknown pass is
  absorbed without a shift. `constellation-attention rules` prints the
  threshold as `unknown_gap_seconds`; report rows show `unknown_since`.
- A condition the state remembers but no input reports is unknown, whether
  or not the input was current: absence is not recovery. If the condition is
  active and its input is otherwise current, the input is reported
  `not_current` ("open condition ... is no longer reported; recovery not
  observed") so `evaluator-input-unavailable` fires.
- A condition follows the label of the input that reports it, so an input
  can be relabelled without effect.
- Only an explicit configuration change ends a condition without observed
  recovery: the rule disabled, its input kind no longer configured, or, for
  rules keyed on the input label (host posture, Nightshift, saved checks,
  input notices), that label removed. NQ status conditions are keyed on the
  unit, so a missing NQ status label while the input kind is configured is
  an unobserved relabel, held as unknown. An active condition removed by
  configuration resolves at once, and the resolve says so.

Every resolve summary names its reason: `RESOLVE <id> [<class>]: underlying
state clear for at least 120 s.` after observed recovery, or `RESOLVE <id>
[<class>]: no longer evaluated; recovery not observed.` after a
configuration removal.

Per pass there is at most one intent per condition and route, all triggers
are submitted before any resolve, and a trigger and a resolve for the same
condition are never both decided. That is how the evaluator enforces NQ's
newest-only rule for `submit`, which NQ itself enforces only for `resubmit`.

`stable_event_id` is `{site}-{rule}[-{target_class}]-{action}-{unix_seconds}`
of the decision. `transition_id` is the event id of the transition and stays
fixed across retries.

## Routing

Notification sinks are not semantically interchangeable. PagerDuty is an
interruption channel: a page means a human should interrupt what they are
doing. Page eligibility is the evaluator's decision, explicit per rule,
expressed in every intent, and refused by NQ's PagerDuty transport when
absent.

```text
condition observed -> attention -> persists beyond the rule's bound -> page
                                                                     |
                                    fresh verified recovery -> resolve
```

A condition is visible in `report.json` from its first observation. A notice
rule that persists beyond its bound sends one `attention` notice; a page
rule that persists beyond its bound pages. Only fresh verified recovery (or
an explicit configuration removal) resolves.

Every intent carries `response_class`: v2 (PagerDuty) intents are always
`page`. A v2 intent that is not a page, presented to NQ's PagerDuty route,
is retained as a `refused` record (reason `response_class_not_page`) and
nothing is sent; it is not dropped before custody. v1 notices are `page`
for a paging decision's notice copy and `attention` otherwise, including a
configuration-removal resolve.

Across the upgrade from builds before 784df43, a retained page intent has
no `response_class`, and every resubmit of its NQ record would be refused
the same way. When such a page is due for a retry (an unanswered or
not-accepted record), the evaluator re-renders it with `response_class:
page` under a new event id (same transition id) and submits it, so a page
open across the upgrade is delivered.

| Class | Trigger and resolve go to |
|---|---|
| page | `page_route` as `nq.notification_delivery_intent.v2` (PagerDuty), **and** `notice_route` as `nq.notification_delivery_intent.v1` |
| notice | `notice_route` as v1 only |

`notice_transport` names the NQ transport of `notice_route`: `slack`,
`discord` or `local_file`. The destination identity is `slack:<route>`,
`discord:<route>` or, for `local_file`, `local-inbox:<route>` exactly as NQ
requires. A `local_file` route is for qualification runs, so test notices
never reach a production channel: the evaluator delivers through `nq
notification deliver-local --intent FILE --route R` (NQ refuses `submit` on
such a route), which takes no `--enable-network` and is not affected by
`network_enabled`. NQ refuses a rendered local message larger than 4 KiB;
the configuration bounds a `local_file` route to 128 bytes, which with the
summary, inspection and event id bounds keeps every message under it. A
`local_file` route has no resubmit path: like Slack and Discord, a definite
`failed` gets a new event after 900 s and an `unknown` is never resent.

NQ accepts v2 only on PagerDuty routes and v1 only elsewhere. A v1 intent has
no condition fields, so its summary carries the action and condition id, for
example `TRIGGER constellation:reference:service:service-down:nqd.service
[page]: ...`. Without a `page_route`, page rules reach the operator only
through the notice route. A resolve goes to the routes that received the
trigger. Severity on v2 is the registry's (`critical` for page rules,
`warning` for `host-disk`). Details carry the condition id, rule version,
first-seen time, persistence and the input identities (status artifact id,
evaluation id, cycle id, saved-check reference), never payloads or secrets.
`runbook_url` and `inspection_reference` come from the configured published
runbook copies.

## Response policy (remediation window)

Every rule has `response_policy = observe_only` in the registry: notices
and pages go out on the rule's normal schedule. The one alternative,
`auto_remediate_then_page` (cartography #55), is configured per condition
target and only for rules in the registry's remediation list (v1:
`service-down`, a page rule):

```toml
[[remediation.targets]]
rule = "service-down"
target_class = "attention-canary.service"   # the unit, a bounded token
policy = "auto_remediate_then_page"
window_seconds = 240                         # 60..=600, default 240
```

`check-config` refuses any other rule, a target that is not a bounded unit
token, any other policy (`observe_only` is the default and is not listed),
a window outside 60..=600 and a duplicate rule/target pair.

For such a target (v1 semantics; the rule lives in one function,
`remediation::page_decision`, so a later design can change it in one
place):

- The trigger is decided at the rule's bound as usual, and its notice goes
  out then.
- The page is held until the remediation window ends, at `first_seen +
  window_seconds`, and is sent at the first pass at or after that moment
  that does not observe it clear: present, or unknown (an input that is not
  current is not recovery and never holds a page past the window). It is a v2 page under its own event id, bound to the trigger's
  transition id.
- If the condition clears inside the window and resolves while the page is
  held, no page is ever sent. The resolve goes only to the notice route and says
  `RESOLVE <id> [page]: recovered within the remediation window; no page
  was sent.` (`response_class: attention`). The resolve still needs the
  usual 120 s of clear.
- Once the page is sent, recovery resolves both routes as usual.

The evaluator does not remediate anything itself; the window is time for
whatever remediation exists (for example a unit's own `Restart=`) to work
before a human is interrupted. Report rows show `response_policy`,
`remediation_window_until` (unix seconds, for targets) and `page_deferred`.
The remediation targets are part of the policy digest.

## Sink failures and restarts

Before submitting anything a pass writes the intent files and saves state
with each new intent recorded as `unknown` without a notification id. Then:

- A crash between that save and NQ's answer is recovered on the next pass by
  submitting the **same file** again. NQ returns the existing record if it
  retained that exact event, so the same event is never submitted twice under
  two identities and a condition is never double-triggered.
- An NQ command error before custody (`command_error`: nq missing, store
  busy or read-only, intent refused) and an unanswered submission (`unknown`
  without a notification id) are retried with the same bytes on the **next
  pass**. NQ retained nothing, or answers an exact repeat idempotently.
- A submission NQ retained and answered with `failed`, `unknown`, `pending`
  or a refusal is recorded; `first_seen` and `active` never depend on it.
  If the record is still the newest for its condition and route, the pass
  retries: PagerDuty after 120 s with `nq notification resubmit
  --notification-id OLD --stable-event-id NEW` (NQ's runbook: retryable,
  resubmit after a pause; the dedup key makes it idempotent at PagerDuty;
  this needs only the record id, so it proceeds even if the local intent
  file is gone); Slack, Discord and local inboxes after 900 s with a new
  event id, only after a definite `failed` or refusal, never over an
  uncertain (`unknown`/`pending`) attempt, as NQ's notification guide
  requires. Accepted records are never resent.
- A resolve never replaces a trigger NQ never retained. When a resolve is
  decided while a route's trigger has no notification id, that trigger is
  kept as `pending_trigger` and submitted again (same bytes) before the
  resolve in the same pass. If NQ still does not retain it, the trigger is
  reported in `dropped_triggers` and on stderr (`dropped_trigger ...`), the
  pass exits 3, and the trigger is never sent after its resolve.
- A resolve that replaces a trigger NQ retained but never accepted (for
  example a PagerDuty trigger still `failed` after its resubmits) is also
  reported in `dropped_triggers` with exit 3: the destination may never
  have opened the incident that resolve closes.
- A retained intent file that is missing or unreadable fails only its own
  follow-up (`intent_unreadable` in the report and on stderr, exit 3); the
  rest of the pass, including new conditions, goes on.
- With `network_enabled = false`, NQ retains each network intent as the
  refusal `network_dispatch_not_explicitly_enabled` and sends nothing; those
  are not retried and are not counted as failures.

A pass exits 3 when any input was not readable or current, any retained
delivery is not accepted (other than deliberate refusals), or a trigger was
dropped, so the systemd unit shows failed and the condition stays visible in
`systemctl --failed` without a recursive notification.

## Clock

Event identities carry the decision time. A pass whose clock is earlier than
the last completed pass (`state.updated_at`) is refused with exit 1 ("the
clock moved backwards"), so a regressed clock can never replay an identity NQ
already holds for an earlier incident. Only backwards time is refused: a
forward step lets its own pass proceed. The unit runs after
`time-sync.target`, so a boot with a bad RTC does not set `updated_at` from
it.

Recovery from a forward step that has since been corrected (passes exit 1
with the hint below until wall time would otherwise catch up):

1. Confirm the system clock is right (`timedatectl`).
2. `sudo -u nq constellation-attention reset-clock --config /etc/constellation-attention/attention.toml`.
   It takes the state lock, clamps every timestamp in the state later than
   now (`updated_at`, condition times, intent attempt times) to now, prints
   how many it clamped, and deletes nothing. Open conditions stay open and
   retained intents stay retained; with no future timestamp it changes
   nothing.
3. The next timer pass proceeds.

Events decided during the false time keep their identities; a later
decision for the same condition and action could reuse one only at that
exact second. A forward step also counts the jump toward any open
persistence interval, so a condition below its bound can trigger at the
stepped pass.

`--now` chooses the evaluation time for what-if dry runs only: release
builds refuse `--now` without `--dry-run`, and the packaged unit never
passes it. (Debug builds accept it, also on `reset-clock`, so the test suite
can drive the clock.)

## Report

Every pass writes `report.json` beside the state file (atomically): rules
with their effective class and thresholds, each input with its status
(`ok`, `not_current`, `unavailable`), fault classes (`causes`), identity
and error, each condition with
its observation (`present`, `clear`, `unknown`, or `removed` for a
configuration removal) and persistence, each intent with operation and NQ
outcome, unresolved deliveries and dropped triggers. `--dry-run` writes
`dry-run/report.json` and the intents it would submit under
`dry-run/intents/`, changes no state, and runs no `nq notification` command
(an `nq_status.command` input still runs `nq evaluations export`, or
`nq status export` in `status_export` mode). A dry run
continues from the saved state; on a fresh install there is none, so it
shows no intents until a condition has persisted past its bound across real
passes.

## Runbook anchors owned here

### memory-pressure

NQ's `nq.host_memory` detector reports `/proc/pressure/memory` `some avg60`
at or above 10 % (stall pressure, not memory used). Look at PSI, the largest
resident processes and recent deploys. Do not tune the detector to silence it.

### sqlite-health

The newest NQ saved-check result for the reference failed (its bounded
query returned the failing shape). Read it with `nq --json saved-check
result --evaluation-id ID` and inspect the named file (freelist, WAL size)
as the owning account. Never edit the store to clear it.

**Input requirement: one file per reference.** Each `[[inputs.saved_checks]]`
entry reads exactly one raw `nq --json saved-check evaluate REF
--evaluation-id ...` document, written atomically by the check's own timer.
On the Linode that is `/var/lib/nq-ops-results/<reference>.json`. The
reader uses the top-level `reference` (if present it must equal the
configured reference, otherwise the input is unavailable), `outcome`,
`evaluation_id` and `detail.read_attempted_at` (age against
`max_age_seconds`); `detail.binding.definition_digest` and the rest are
carried by NQ, not interpreted. The `nq-ops.saved-check-run.v1` run summary
(`latest.json`, `results[]` per check) is not that document: pointed at it,
the input reads `outcome = missing` and holds as not current. NQ 0.2.1's
`saved-check result` takes only `--evaluation-id`, and no command lists
results by reference, so the file (or a `command` printing the newest
document) is the supported input. Results expose only `passed`, `failed` or
`refused`, never the measured value.

### evaluator-input-unavailable

A configured input is not `ok`. Each fault class is its own condition,
`{label}.{class}`, so a lasting fault of one class (a watched templated
unit) never masks a later fault of another (nqd stops collecting). Input
labels are therefore at most 34 bytes. The report lists an input's current
classes in `causes` and the detail in `error`:

| Class | Meaning |
|---|---|
| `unreadable` | missing path, permission, command failure, malformed JSON, wrong schema, a host-posture `CURRENT` of another projection, a saved-check result naming another reference |
| `stale` | NQ snapshot older than `max_age_seconds`, or an evaluation-history page that is not complete or whose upper bound moved; a watcher whose last collection (status export) or newest evaluation (evaluation history) is older than `stale_after_seconds` at the snapshot's `generated_at` (default 180 s; a stopped nqd still answers from its store, so this is the only daemon-down signal); a saved-check result older than `max_age_seconds` |
| `unrecognised` | an NQ evaluation with an unrecognised profile id or version, or that cannot be parsed; a saved-check result without a valid `read_attempted_at` |
| `untargetable` | a systemd unit with no bounded target class |
| `indeterminate` | a detector on a current export that cannot evaluate (for example `cannot_evaluate`); a saved-check result that is `refused`, `missing` or `claimed` |
| `unreported` | an open condition the input no longer reports |
| `empty` | no closed Nightshift cycle yet |

Each class notifies after it has persisted 300 s. While the input has any
fault, a class it is not showing now is unknown, not clear, so a fault that
changes class from pass to pass still reaches the bound (the unknown passes
are shifted out as for any condition). All classes are clear only when the
input is `ok`, and a class resolves after 120 s of that. `unreported` is
raised whenever the input was read at all, so a lasting fault of another
class does not hide an open condition the input stopped reporting. Rules fed by the input hold their state while their own
evidence is missing. A stale host-posture `CURRENT` is reported as
`host-posture-unknown`, not here. An input notice open under the earlier
key format (`{label}` alone) is resolved once as "no longer evaluated".

## Known limits

These are operator acceptance items.

- **Nothing watches the evaluator.** A pass that cannot run (a malformed
  `state.json`, which is never replaced; the lock; a clock that moved
  backwards) exits 1 with no report and no notification, every minute,
  indefinitely; exit 3 is likewise only a failed oneshot unit. An NQ
  `nq.systemd_unit` watcher cannot see it, because the unit is inactive
  between passes. The liveness signal is the age of `report.json`
  (`evaluated_at`, rewritten by every completed pass): the status site or
  renderer that reads it is responsible for flagging a report older than a
  few minutes, and the operator must name who watches that. The unit
  carries a commented `OnFailure=` for an optional local handler.
- Configuration removal (rule disabled, input kind removed, a label-keyed
  input removed) resolves open conditions at once without observed
  recovery. Restoring the configuration re-pages as a new incident after the
  bound.
- A removed or renamed NQ watcher holds its page open (unknown), keeps the
  NQ input `not_current` (`unreported`) and every pass exits 3 until the
  watcher returns. Disabling `service-down` clears it but resolves every
  service-down page. Below-bound conditions of a removed watcher stay in the
  state (unknown, harmless) until the watcher returns.
- Watching a unit with no bounded target class (templated, escaped or long
  names) keeps the NQ input `not_current` (`untargetable`) permanently. It
  no longer masks other faults of that input.
- Clock: a backwards step stops passes until wall time passes `updated_at`;
  recover with `reset-clock` (see [Clock](#clock)).
- Passes that do not run at all (timer stopped, host suspended) are not
  unknown observations: a persistence interval spanning such a gap still
  counts.
- Notice routes (Slack, Discord, local inbox) are never resent over
  `unknown`, and a failed notice is retried only after 900 s.
- PagerDuty records that are not accepted are resubmitted every 120 s while
  the condition stays active, including an `unknown` answer that carries a
  record id (`success_not_confirmed`). PagerDuty folds them into the one
  incident by dedup key, but NQ retains a new record each time: about 30
  records an hour per route while it lasts. There is no back-off.
- Input notices are per fault class, so a class change gives one resolve
  and one trigger, at most one per 300 s.
- After `reset-clock`, records decided during a forward clock step keep
  their future event ids (for example `...-trigger-1791029460`). If a later
  transition of the same condition and action falls on that exact second,
  NQ answers with the old record instead of creating a new one. The odds
  are negligible; it is listed for completeness.
- Saved checks need the per-reference `<reference>.json` writer deployed on
  the Linode; without it `sqlite-health` never fires and the input notice is
  permanent.
- A pass submits in order, triggers first. If a route hangs, each attempt
  costs up to `command_timeout_seconds`; with more submissions than
  `TimeoutStartSec` allows (see the unit's budget formula), the pass is
  stopped and the next one starts again from the first, so later items can
  be starved while the route hangs.
- `service-down` keys on the unit name only. The machine id in
  `systemd-unit:<machine>/<unit>` is dropped and the newest `evaluated_at`
  wins, so with two machines in one export a healthy unit on one hides the
  same unit down on the other. One nqd watches one host today; one host per
  export is required, as for `nq.host_memory`.
- A stopped host-posture runner raises two pages under two dedup keys:
  `host-posture-unknown` (about `fresh_until` + 600 s) and
  `nq-no-fresh-acquisition` (600 s + 300 s). That follows the registry as
  written, two Cartography anchors with separate runbooks (refusal code
  versus stopped runner); Cartography's owner should confirm both pages are
  wanted.
- Presence below the bound is never notified, however often it recurs: a
  unit that dies every two minutes and is restarted between scrapes stays
  silent. Cartography's owner should confirm that is wanted for
  `service-down`.
- `run_bounded` kills only the direct child on timeout; reader threads then
  wait for any grandchild that still holds the pipes.
- Nightshift: the newest closed cycle is taken across the whole store, so
  one healthy recurrence family hides a missing one, and a future
  `updated_at` (clock skew) gives a negative age that reads as clear.
- `nq-no-fresh-acquisition` uses the newest host-posture status object's
  `generated_at`, as specified. The runner republishes about every 4 s even
  when acquisitions refuse, so this detects a stopped runner, not refused
  acquisitions; those surface as `host-posture-unknown`.
- `host-disk` inherits NQ's compiled 90 % capacity threshold, through the
  projection or directly from an NQ filesystem watcher; Cartography's rule
  says 85 %. The same filesystem can raise two `host-disk` conditions (the
  publication-root label and the watcher id) if both sources watch it.
- A host-posture label equal to an NQ filesystem watcher id would feed one
  `host-disk` condition from two inputs. `check-config` cannot see NQ's
  instance ids, so this is caught at runtime: the condition is unknown (no
  source wins) and both inputs report `unrecognised` naming it, until one
  is renamed. An NQ filesystem watcher whose instance id equals the NQ input
  label would be read as label-keyed and resolved as removed on a relabel;
  avoid that naming.
- `service-down` reads NQ's evaluation result, not a component's coarse
  `state`: NQ reports `healthy` for both instance and evaluation components
  while a unit is down. It cannot tell failed from inactive or not-found.
- Docket and AG inputs are not deployed; their rules stay disabled.
