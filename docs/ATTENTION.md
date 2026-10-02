# Operator attention evaluator

`constellation-attention` decides when a person should be told that a
Constellation component needs attention, and asks NQ to tell them. It answers
Cartography issue #20 (who evaluates the beta alert registry) for the rules
whose inputs exist today.

## Boundary

The evaluator consumes qualified, current product state and produces
notification intents. Nothing else.

- It is **not evidence authority.** It reads status objects, NQ's status
  export, the Nightshift observation store and NQ saved-check results as their
  owners publish them. It never admits, signs, repairs or re-derives evidence.
- It is **not observation authority.** It does not probe hosts, units, files or
  endpoints. When an input cannot be read it says so
  (`evaluator-input-unavailable`) and holds every condition fed by that input.
- It is **not execution authority.** A notification grants no permission and
  triggers no action. Nothing here restarts, silences or reconciles anything.
- It is **not a policy language or rules engine.** The registry below is
  compiled in and versioned (`constellation.attention_registry.v1`).
  Configuration may enable or disable a rule, change its one threshold, and
  choose `page` or `notice` where the registry allows it. There are no
  user-defined rules, expressions or plugins.
- **Delivery is NQ's job.** The evaluator writes a canonical intent file and
  runs `nq notification submit` (or `resubmit`), then records NQ's answer. It
  never talks to Slack, Discord or PagerDuty, never reads route secrets, and
  stores none.
- It never reads Classic NQ (`/opt/notquery`).

## Registry

Bounds are defaults; `threshold_seconds` overrides the one threshold. For
*persistence* rules the threshold is how long the underlying state must
persist; for *age* rules it is the age a source timestamp must exceed, after
which the condition must persist a further fixed time. Runbook anchors marked
(C) are in Cartography `architecture/beta-observability/docs/RUNBOOKS.md`;
anchors marked (M) are below in this document.

| Rule | Class (default) | May page | Bound | Component | Target class | Input | Runbook | Operator response |
|---|---|---|---|---|---|---|---|---|
| `host-posture-unknown` | page | yes | persists 600 s | `host_posture` | publication-root label | host-posture `CURRENT`: `aggregate_state` unknown, or `fresh_until` passed | (C) `host-posture-unknown` | Follow the runner's refusal code; re-enroll on digest mismatch. |
| `host-disk` | notice | yes | persists 900 s | `host_posture` | publication-root label | host-posture `CURRENT`: current and `aggregate_state` degraded or worse | (C) `host-disk` | Ordinary host operations; check NQ store, host-posture state root, Nightshift stores, Classic backups. |
| `nq-no-fresh-acquisition` | page | yes | age 600 s, then persists 300 s | `nq` | publication-root label | host-posture `CURRENT`: `generated_at_unix_ms` | (C) `nq-no-fresh-acquisition` | Read the runner journal for `acquisition_refused`; start a stopped runner and watch two occurrences. |
| `service-down` | page | yes | persists 180 s | `service` | unit name, e.g. `nqd.service` | NQ status export: newest `nq.systemd_unit` v2 evaluation of a non-stale watcher reports `systemd_unit_not_active` present | (C) `service-down` | `systemctl status <unit>`; restart if failed; read preflight errors. |
| `memory-pressure` | notice | no | persists 600 s | `host_posture` | none | NQ status export: newest `nq.host_memory` evaluation of a non-stale watcher reports `memory_pressure_stall` present | (M) [`memory-pressure`](#memory-pressure) | Check PSI and the largest resident processes. |
| `nightshift-recurrence-missing` | page | yes | age 1800 s, then persists 300 s | `nightshift` | Nightshift input label | Nightshift store: newest `canonical_observation_cycles.updated_at` with `status = 'closed'` | (C) `nightshift-recurrence-missing` | Check `nightshift-*` timers; slow ticks see `nightshift-cycle-slow`. |
| `sqlite-health` | notice | no | persists 600 s | `nq` | saved-check reference | NQ saved-check result: current `outcome` failed | (M) [`sqlite-health`](#sqlite-health) | Inspect the retained result and the named SQLite file. |
| `evaluator-input-unavailable` | notice | no | persists 300 s | the input's (`host_posture`, `nq`, `nightshift`) | input label | the evaluator's own read of each configured input | (M) [`evaluator-input-unavailable`](#evaluator-input-unavailable) | Read `report.json`; fix the path, permission or producing timer. |
| `docket-unsettled` | page | yes | age 3600 s, then 300 s | `docket` | — | disabled: input not deployed | (C) `docket-unsettled` | — |
| `ag-executor-unavailable` | page | yes | persists 300 s | `ag` | — | disabled: input not deployed | (C) `ag-executor-unavailable` | — |

"May page" is fixed by NQ 0.2.1: its v2 (PagerDuty) contract accepts only
the 17 Cartography registry anchors. `memory-pressure`, `sqlite-health` and
`evaluator-input-unavailable` are not anchors, so NQ would refuse them on a
PagerDuty route; they are notices until the registry and NQ add them.
`evaluator-input-unavailable` never pages by design.

`constellation-attention rules` prints the registry with versions.

## Conditions and lifecycle

A condition's identity is NQ's derived dedup key:
`constellation:{site}:{component}:{rule}[:{target_class}]`. `site` and
`target_class` are bounded tokens (`[a-z0-9._-]`, 64 and 48 bytes) that must
not look like a digest, UUID, date, timestamp or bare number; the evaluator
applies NQ's own heuristic and refuses such labels in configuration. A unit
whose name falls outside the charset (for example a templated `@` unit) is
skipped and named in the report.

Each pass turns every input into one of three observations per condition:
**present**, **clear**, or **unknown** (input unreadable, not current,
indeterminate, refused, or a detector that cannot evaluate). The state file
keeps, per condition, `first_seen`, `last_seen`, `clear_since`, `active`,
`transition_at`, and the newest intent per route role.

- Present: `first_seen` is set once. The condition becomes actionable only
  when it has persisted continuously for longer than its bound; then exactly
  one trigger is decided and `active` is set.
- Clear while not active: `first_seen` is reset. Presence below the bound is
  never notified, however often it recurs.
- Clear while active: the condition resolves exactly once after it has stayed
  clear for 120 s. A flap inside that window sends nothing.
- Unknown: nothing changes. Legitimate unknown or refusal never notifies on its
  own; it reaches the operator through `host-posture-unknown` (for the
  projection) or `evaluator-input-unavailable` (for an input).
- A condition the state remembers but no current input reports is clear when
  its input was read and is current, unknown when the input was not, and
  clear when its rule or input has been removed from configuration (so an
  open alert is resolved rather than orphaned).

Per pass there is at most one intent per condition and route, all triggers
are submitted before any resolve, and a trigger and a resolve for the same
condition are never both decided. That is how the evaluator enforces NQ's
newest-only rule for `submit`, which NQ itself enforces only for `resubmit`.

`stable_event_id` is `{site}-{rule}[-{target_class}]-{action}-{unix_seconds}`
of the decision. `transition_id` is the event id of the transition and stays
fixed across retries.

## Routing

| Class | Trigger and resolve go to |
|---|---|
| page | `page_route` as `nq.notification_delivery_intent.v2` (PagerDuty), **and** `notice_route` as `nq.notification_delivery_intent.v1` |
| notice | `notice_route` as v1 only |

NQ accepts v2 only on PagerDuty routes and v1 only elsewhere. A v1 intent has
no condition fields, so its summary carries the action and condition id, for
example `TRIGGER constellation:labelwatch:service:service-down:nqd.service
[page]: ...`. Without a `page_route`, page rules reach the operator only
through the notice route. A resolve goes to the routes that received the
trigger. Severity on v2 is the registry's (`critical` for page rules,
`warning` for `host-disk`). Details carry the condition id, rule version,
first-seen time, persistence and the input identities (status artifact id,
evaluation id, cycle id, saved-check reference), never payloads or secrets.
`runbook_url` and `inspection_reference` come from the configured published
runbook copies.

## Sink failures and restarts

Before submitting anything a pass writes the intent files and saves state
with each new intent recorded as `unknown` without a notification id. Then:

- A crash between that save and NQ's answer is recovered on the next pass by
  submitting the **same file** again. NQ returns the existing record if it
  retained that exact event, so the same event is never submitted twice under
  two identities and a condition is never double-triggered.
- A submission NQ answers with `failed`, `unknown`, `pending` or a refusal is
  recorded; `first_seen` and `active` never depend on it. After 900 s, if the
  record is still the newest for its condition and route, the pass retries:
  PagerDuty with `nq notification resubmit --notification-id OLD
  --stable-event-id NEW`; Slack/Discord with a new event id, only after a
  definite `failed` or refusal, never over an uncertain (`unknown`/`pending`)
  attempt, as NQ's notification guide requires. Accepted records are never
  resent.
- With `network_enabled = false`, NQ retains each intent as the refusal
  `network_dispatch_not_explicitly_enabled` and sends nothing; those are not
  retried and are not counted as failures.
- An NQ command error (for example a refused intent) is recorded as
  `command_error` and retried with the same bytes after 900 s.

A pass exits 3 when any input was not readable or current, or any retained
delivery is not accepted (other than deliberate refusals), so the systemd
unit shows failed and the condition stays visible in `systemctl --failed`
without a recursive notification.

## Report

Every pass writes `report.json` beside the state file (atomically): rules
with their effective class and thresholds, each input with its status
(`ok`, `not_current`, `unavailable`), identity and error, each condition with
its observation and persistence, each intent with operation and NQ outcome,
and unresolved deliveries. `--dry-run` writes `dry-run/report.json` and the
intents it would submit under `dry-run/intents/`, changes no state, and runs
no `nq` command.

## Runbook anchors owned here

### memory-pressure

NQ's `nq.host_memory` detector reports `/proc/pressure/memory` `some avg60`
at or above 10 % (stall pressure, not memory used). Look at PSI, the largest
resident processes and recent deploys. Do not tune the detector to silence it.

### sqlite-health

The newest retained NQ saved-check result for the reference failed (its
bounded query returned the failing shape). Read it with
`nq --json saved-check result --evaluation-id ID` and inspect the named file
(freelist, WAL size) as the owning account. Never edit the store to clear it.
NQ 0.2.1's `saved-check result` takes only `--evaluation-id` (caller-chosen,
for example `sc-<unix>`), and there is no command that lists results by
reference. The simplest supported input is therefore the file the check's
own timer writes: it runs `nq --json saved-check evaluate REF
--evaluation-id sc-$(date +%s) ...` and writes that output atomically to the
configured `path` (or a `command` prints the newest result). A result that
names a different `reference` is refused as unavailable. Results expose only
`passed`, `failed` or `refused`, never the measured value.

### evaluator-input-unavailable

A configured input could not be read (missing path, permission, command
failure, malformed JSON) or is not current (status export older than
`max_age_seconds`, a watcher whose last collection is older than
`stale_after_seconds` at the export's `generated_at` (default 180 s, three
60 s intervals; a stopped nqd still answers `status export` from its store,
so this is the only daemon-down signal), a stale or indeterminate
saved-check result, no closed Nightshift cycle yet). Read the
input's `error` in `report.json`. Rules fed by the input hold their state
until it is readable again. A stale host-posture `CURRENT` is reported as
`host-posture-unknown`, not here.

## Known limits

- `nq-no-fresh-acquisition` uses the newest host-posture status object's
  `generated_at`, as specified. The runner republishes about every 4 s even
  when acquisitions refuse, so this detects a stopped runner, not refused
  acquisitions; those surface as `host-posture-unknown`.
- `host-disk` inherits NQ's compiled 90 % capacity threshold through the
  projection; Cartography's rule says 85 %.
- `service-down` reads NQ's evaluation result, not a component's coarse
  `state`: NQ reports `healthy` for both instance and evaluation components
  while a unit is down. It cannot tell failed from inactive or not-found.
- Only one `nq.host_memory` lineage (one host) is expected per export.
- Docket and AG inputs are not deployed; their rules stay disabled.
