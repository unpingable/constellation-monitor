# NQ host-memory-pressure-stall / Pulse correspondence v1

Status: **Candidate**, qualified on one real host through the disposable
same-process profile recorded in the campaign receipts
(`.campaign-artifacts/host-posture-20260924/memory-20260924/REAL-RUN-RESULT.md`,
local). The seam is the qualified load-pressure correspondence
(`nq-host-load-pressure-correspondence-v1.md`) parameterized by question
(`nq-host-filesystem-capacity-correspondence-v1.md` records the
parameterization); this document records only the memory row and what memory
was the first row to exercise: a subject prefix shared with another row, and
a reliance window shorter than load's. The projected component is an operator
condition projection, not a public status component.

## The question row

| Field | `HostMemoryPressureStallV1` |
|---|---|
| NQ question | `nq.host_memory.pressure_stall` / `1` / `sha256:3fe0860e…7278` |
| NQ profile | `nq.host_memory` / `1` / `sha256:e4eb42dd…523e` (detector refusal names version `1`) |
| Claim, condition | `claim:memory_pressure_stall`, `memory_pressure_stall` |
| Subject rule | prefix `host:` (NQ's `host:<machine-id>`), shared with load's `host:crow`; a bare prefix is refused |
| Reliance window, frame validity | `120000 ms`, `118999 ms` (`reliance - fence(1000) - 1`, the same law as every row, checked at compile time) |
| Pulse scope, coverage tag | `nq.host_memory.pressure_stall/v1`, `nq_host_memory_pressure_stall_v1_terminal_artifact` |
| Acquisition id prefix | `constellation-nq-memory-stall:v1:` |
| Transport path, failure domain | `in-process:nq-memory-pressure-stall-correspondence/v1`, `domain:nq-memory-pressure-stall-correspondence` |
| Schemas | `constellation.nq_host_memory_pressure_stall_correspondence_{profile,occurrence,intent}.v1`, record `constellation.nq_host_memory_pressure_stall_correspondence.v1` |
| Pulse observation profile | `constellation.nq_host_memory_pressure_stall_correspondence` v1, digest domain `….pulse_profile.v1` over `P` |

The seam carries NQ's detector state and nothing of the condition: no PSI
value, average, total, threshold, or boot age crosses it, and none is named in
the correspondence crate (structural script). The 180 s warm-up guard, the
`avg60` window, and the `full > some` refusal are NQ's; a young boot reaches
the seam as an ordinary `cannot_evaluate` and projects `unknown`. The
correspondence witness reads the Linux boot identity only as the subject
incarnation, and never compares it with NQ's boot age.

## What the shared prefix means

A load-row profile can be sealed over the memory enrollment (`host:` prefix,
same subject string). Everything after sealing refuses on the question: the
first artifact (`artifact_pin_mismatch` on question and profile), the frame
(`frame_binding_mismatch`, the Pulse observation profile digest is
question-scoped), the record (`record_question_mismatch`), the claim
(`artifact_claim_mismatch`), a memory detector refusal under the load row
(`artifact_ladder`), the certificate (`certificate_binding_mismatch` on scope),
and the adapters (`question_mismatch`). The filesystem row cannot seal the
memory enrollment at all (`invalid_subject`). `tests/memory_pressure_seam.rs`
proves each, with one subject string under both rows.

## What the shorter window means

Every validity check reads the row: the profile constants and reliance policy
(`maximum_validity_ms = 118999`), the sealed frame, `check_holding_delay_for`
(`118998` accepted, `118999` refused), the certificate window, and the audit
verifier (a record held `200000 ms`, lawful under load, is refused). A frame
carrying load's `298999 ms` is refused as `frame_validity_mismatch`. The
load-named wrappers (`check_holding_delay`, `frame_ingress`,
`classify_outcome`, `seal`) keep load's meaning and would accept what memory
refuses; the structural script forbids calling them from any crate source or
example, and forbids the load constants outside the load row and the frozen
load tests. The projector's 60 s maximum age lies below both windows.

## Consequence

`constellation-status-nq-memory-pressure` owns
`constellation.status_consequence.nq_host_memory_pressure_stall.v1` (fact
owner `constellation-status-nq-memory-pressure`, pinned
`REQUIRED_QUESTION = HostMemoryPressureStallV1`):

| NQ state | Availability | Impact | Projected state | Reason code |
|---|---|---|---|---|
| `present` | `impaired` | `none` | `degraded` | `nq_memory_pressure_stall_present` |
| `explicitly_absent` | `available` | `none` | `healthy` | `nq_memory_pressure_stall_explicitly_absent` |
| `cannot_evaluate` | `indeterminate` | `indeterminate` | `unknown` | `nq_cannot_evaluate` |
| `not_evaluated` | `indeterminate` | `indeterminate` | `unknown` | `nq_not_evaluated` |

Consequence identity: ``sha256:a0311c04a6713f3aa5a2a51c0ae6cf238990dc6ad9a732a3864c4ddb8791f4ac``. Label
`Memory pressure stall` in every audience, with no operator variant. Reason
text, fixed per state:

- healthy: "Qualified memory pressure-stall condition absent in the current
  NQ observation. This is not a memory sufficiency or host health claim."
- degraded: "Qualified memory pressure-stall condition present in the current
  NQ observation. No outage, service impact, or cause is claimed."
- unknown: "The memory pressure-stall condition is currently unknown. This is
  not an outage."

`healthy` is the projector's closed axis vocabulary and appears only in the
artifact's machine-readable `state` fields; the renderer shows
`Memory pressure stall: No issue reported — …`. The renderer's
`Overall projection:` line is the projector's aggregate over the policy's
components and is not itself condition-scoped; with one component it repeats
the component's label text. The non-claims say the
condition is kernel stall accounting under NQ's qualified threshold and name
no PSI figure, threshold, or boot age (the adapter cannot bind them). A public
policy identifier or text carrying the machine id is refused
(`public_identity_leak`).

## Qualification material

- `tests/question_row_pins.rs`: every memory row literal, and the synthetic
  profile, reliance policy and context digests; the filesystem row likewise.
- `tests/memory_pressure_seam.rs`: the 120 s law and its boundaries, the
  shared-prefix refusals, port binding over the same subject, and
  co-production with support bounded by the 120 s row.
- `artifacts/nq-host-memory-pressure-stall-correspondence-v1/`: the shared
  vector suite (`tests/common/vector_suite.rs`) under the memory row, refused
  against the load and filesystem rows, with the load-validity frame and the
  load-only holding delay as negative vectors.
- Adapter tests mirror the filesystem adapter's minus the mountpoint label,
  plus refusal of load and filesystem correspondences and a presentation pin.
- Real host: see the campaign receipt.

## Typed owner failure (2026-09-24)

As for the filesystem row: NQ carries `failure_code` and `failure_retriable`
in the memory detector's incomplete-coverage refusal when the helper's single
collection error is on `nq.host_memory`'s closed list (6 codes:
`machine_identity_unavailable`, `machine_identity_mismatch`,
`psi_read_failed`, `psi_malformed`, `psi_not_provided`,
`boot_clock_unavailable`). NQ's own warm-up refusal
(`psi_average_warming_up`) is a detector reason, not a helper code, and
carries no `failure_code`. `machine_identity_mismatch` shares its text with
the filesystem list; the owning profile is this row's, pinned by the ladder
before the code is read, and the memory adapter returns no explanation for
any other question's value (its question check runs before a code is read).
As for the filesystem row, the record embeds NQ's artifact with the keys and
the seam adds no field, and an operator policy disclosing `Detail` may carry
the adapter's explanation as display-only component text that the projector
copies and never reads (`operator_detail()`); unknown stays unknown, with or
without it. The adapter explains five codes with bounded
text; state, fact, identity (`a0311c04…`) and rendered text are unchanged.
