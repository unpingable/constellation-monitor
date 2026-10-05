# NQ systemd-unit required-active / Pulse correspondence v1

Status: **Candidate**, qualified read-only on one real host (the qualification host,
systemd 255) through the disposable same-process profile recorded in the
campaign receipts
(`.campaign-artifacts/host-posture-20260924/systemd-v2-20260924/`, local). The
seam is the qualified correspondence parameterized by question
(`nq-host-filesystem-capacity-correspondence-v1.md`); this document records
only the systemd row and what it was the first row to exercise: a categorical
(unit lifecycle) condition, and an NQ profile that is a second revision of an
existing profile id. The projected component is an operator condition
projection, not a public status component.

## The question row

| Field | `SystemdUnitRequiredActiveV1` |
|---|---|
| NQ question | `nq.systemd_unit.required_active` / `1` / `sha256:f8df6308…159f` |
| NQ profile | `nq.systemd_unit` / `2` / `sha256:5691c4db…7b49` (detector refusal names version `2`) |
| Claim, condition | `claim:systemd_unit_not_active`, `systemd_unit_not_active` |
| Subject rule | prefix `systemd-unit:` (NQ's `systemd-unit:<machine-id>/<unit>`); a bare prefix is refused |
| Reliance window, frame validity | `60000 ms`, `58999 ms` (the shared law, checked at compile time) |
| Pulse scope, coverage tag | `nq.systemd_unit.required_active/v1`, `nq_systemd_unit_required_active_v1_terminal_artifact` |
| Acquisition id prefix | `constellation-nq-systemd-unit:v1:` |
| Transport path, failure domain | `in-process:nq-systemd-unit-required-active-correspondence/v1`, `domain:nq-systemd-unit-required-active-correspondence` |
| Schemas | `constellation.nq_systemd_unit_required_active_correspondence_{profile,occurrence,intent}.v1`, record `constellation.nq_systemd_unit_required_active_correspondence.v1` |
| Pulse observation profile | `constellation.nq_systemd_unit_required_active_correspondence` v1, digest domain `….pulse_profile.v1` over `P` |

The row fits the seam with no new field, subject rule, validity law, or
projector behavior. The seam carries NQ's detector state and nothing of the
condition: no load, active, or sub state string, bus name, or unit-file fact
crosses it or is named in the correspondence crate (structural script). NQ's
law (explicitly absent exactly when the system manager reports the unit
loaded and active; every other reported state present) and its closed
vocabularies are NQ's.

## What the second revision means

`nq.systemd_unit` v1 is the operator-beta fixture contract and stays
untouched. The row pins profile version `2` for the first artifact and
`refusal_profile_version = 2` for detector refusals, so a v1 refusal (or a
string `"2"`, or `3`) is refused by the ladder (`artifact_ladder`) before any
owner code is read (`tests/systemd_unit_seam.rs`).

## What the 60 s window means

Every validity check reads the row: `check_holding_delay_for` accepts
`58998` and refuses `58999`; a frame carrying any other row's validity is
refused (`frame_validity_mismatch`); a record held `100000 ms`, lawful under
every other row, is refused. The projector's 60 s maximum age equals the
reliance window and lies above the frame validity.

## Consequence

`constellation-status-nq-systemd-unit` owns
`constellation.status_consequence.nq_systemd_unit_required_active.v1` (fact
owner `constellation-status-nq-systemd-unit`, pinned
`REQUIRED_QUESTION = SystemdUnitRequiredActiveV1`, identity
`sha256:f54e4aa8b7e81a32fcc8066f182967b0f30760125132e0ea5824bfab17e775d2`):

| NQ state | Availability | Impact | Projected state | Reason code |
|---|---|---|---|---|
| `present` | `impaired` | `none` | `degraded` | `nq_systemd_unit_not_active_present` |
| `explicitly_absent` | `available` | `none` | `healthy` | `nq_systemd_unit_not_active_explicitly_absent` |
| `cannot_evaluate` | `indeterminate` | `indeterminate` | `unknown` | `nq_cannot_evaluate` |
| `not_evaluated` | `indeterminate` | `indeterminate` | `unknown` | `nq_not_evaluated` |

Labels: public `Required unit state`; an operator policy may use
`Required unit state (<unit>)` only for the unit of the verified subject
(the unit name is part of the correspondence subject, so the adapter checks
it; any other unit or word is `condition_contract_mismatch`). Neither the
machine id nor the unit name may appear in a public identifier or text.
Reason text, fixed per state:

- healthy: "The system manager reported the required unit loaded and active
  in the current NQ observation. This is not a service operational,
  reachability, or application health claim."
- degraded: "The system manager reported the required unit in a state other
  than loaded and active in the current NQ observation. No outage, user
  impact, or cause is claimed."
- unknown: "The required unit state is currently unknown. This is not an
  outage."

`healthy` is the projector's axis vocabulary; the renderer shows
`Required unit state (…): No issue reported — …`. No state suggests or
authorizes a restart, reload, or any other actuation.

## Typed owner failure

NQ carries `failure_code` and `failure_retriable` when the helper's single
collection error is on `nq.systemd_unit` v2's closed list (9 codes:
`system_bus_unavailable`, `manager_unavailable`, `query_timeout`,
`query_failed`, `reply_malformed`, `machine_identity_mismatch`,
`unit_list_cardinality`, `unit_name_not_canonical`,
`unit_state_unrecognized`). An unexpected unit state (including `failed`,
`not-found`, `masked`) is an observation, never a failure code. The adapter
explains all nine with bounded operator-only `Detail` text that the
projector copies and never reads; unknown stays unknown with or without it.

## Qualification material

- `tests/question_row_pins.rs`: every systemd row literal and the synthetic
  profile, reliance policy and context digests; existing rows unmoved.
- `tests/systemd_unit_seam.rs`: the 60 s law and boundaries, prefix refusal
  in both directions against every other row, the second-revision refusal
  pin, and co-production with support bounded by the 60 s row.
- `artifacts/nq-systemd-unit-required-active-correspondence-v1/`: the shared
  vector suite under the systemd row, refused against the load, filesystem
  and memory rows.
- Adapter tests: consequence table, label binding, public leakage, owner
  code sweep, operator detail, presentation, end-to-end projection, and an
  ignored real harness (`tests/real_projection.rs`).
