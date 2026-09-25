# NQ host-filesystem-inodes / Pulse correspondence v1

Status: **Candidate**, synthetic qualification only; no real-host run is
recorded for this row yet. The seam is the qualified correspondence
parameterized by question (`nq-host-filesystem-capacity-correspondence-v1.md`);
this document records only the inode row and what it was the first row to
exercise: a subject and a frame validity shared byte for byte with another
row. The projected component is an operator condition projection, not a
public status component.

## The question row

| Field | `HostFilesystemInodePressureV1` |
|---|---|
| NQ question | `nq.host_filesystem_inodes.pressure` / `1` / `sha256:2986b802…4d89` |
| NQ profile | `nq.host_filesystem_inodes` / `1` / `sha256:1a4f5e28…d664` (detector refusal names version `1`) |
| Claim, condition | `claim:filesystem_inode_pressure`, `filesystem_inode_pressure` |
| Subject rule | prefix `host-filesystem:` (NQ's `host-filesystem:<machine-id>/<filesystem-uuid>`, the capacity row's rule); a bare prefix is refused |
| Reliance window, frame validity | `300000 ms`, `298999 ms` (the shared law, checked at compile time; equal to the capacity row's) |
| Pulse scope, coverage tag | `nq.host_filesystem_inodes.pressure/v1`, `nq_host_filesystem_inodes_pressure_v1_terminal_artifact` |
| Acquisition id prefix | `constellation-nq-fs-inodes:v1:` |
| Transport path, failure domain | `in-process:nq-filesystem-inodes-correspondence/v1`, `domain:nq-filesystem-inodes-correspondence` |
| Schemas | `constellation.nq_host_filesystem_inodes_correspondence_{profile,occurrence,intent}.v1`, record `constellation.nq_host_filesystem_inodes_correspondence.v1` |
| Pulse observation profile | `constellation.nq_host_filesystem_inodes_correspondence` v1, digest domain `….pulse_profile.v1` over `P` |

Synthetic profile pins (`tests/question_row_pins.rs`): profile digest
`sha256:897d33bb…1261`, reliance policy semantic digest
`sha256:a90af989…af7a`, reliance context identity digest
`sha256:8ddc03e1…bbdb`. Every earlier row's pin is unmoved.

The row fits the seam with no new field, subject rule, validity law, or
projector behavior. The seam carries NQ's detector state and nothing of the
condition: no inode count, `statfs` field, or threshold crosses it or is
named in the correspondence crate (structural script). NQ's law (the
enrolled filesystem's inode usage against its qualified inode threshold) and
its closed vocabularies are NQ's.

## What the shared subject means

NQ asks the capacity question and the inode question of the same enrolled
filesystem. The two rows therefore share the subject prefix, and a real
enrollment shares the exact subject string; the synthetic inode enrollment
names the capacity fixture's subject byte for byte on purpose
(`SYNTHETIC_FILESYSTEM_INODES_SUBJECT == SYNTHETIC_FILESYSTEM_SUBJECT`). Both
rows also carry NQ's 300 s reliance window, so their frame validity is the
same 298 999 ms. Neither the subject check nor any validity check separates
the two rows; only the question does, and `tests/filesystem_inodes_seam.rs`
proves that in both directions:

- a capacity-row profile sealed over the inode enrollment seals (same
  prefix), with the same NQ enrollment and the same validity constant, and
  the reverse seals too;
- under that profile the first inode artifact is `artifact_pin_mismatch`,
  the inode record `record_question_mismatch`, the inode frame
  `frame_binding_mismatch` (same subject, observer and validity; different
  observation profile digest), the inode claim `artifact_claim_mismatch`,
  and a detector refusal naming either filesystem profile is
  `artifact_ladder` under the other row;
- a co-producer for a capacity-row profile bound to an inode port (the same
  enrollment) is refused on the question pin at the first acquisition,
  before any delivery; the reverse likewise;
- inode co-production verifies with its own scope, and the certificate,
  same subject and same validity, is `certificate_binding_mismatch` under
  the capacity-row profile sealed over the same enrollment;
- the load, memory and systemd rows cannot seal over the filesystem subject
  at all (`invalid_subject`), in either direction.

Because the validities are equal, the vector suite emits no
`policy_frame_validity_of_filesystem_row` or
`lifetime_holding_delay_lawful_under_filesystem_row_only` case for this row;
its cross-row cases against the capacity row are the question cases alone.

An embedding that runs both filesystem questions must run one co-producer,
one reactor, and distinct observer and consumer identities per question, as
for every other row. Pulse keys consumers by subject and consumer; the two
questions share the subject, so `check_disjoint_enrollment` is the only
check that a shared reactor is safe, and it refuses the same consumer on
both.

## Consequence

`constellation-status-nq-filesystem-inodes` owns
`constellation.status_consequence.nq_host_filesystem_inode_pressure.v1`
(fact owner `constellation-status-nq-filesystem-inodes`, pinned
`REQUIRED_QUESTION = HostFilesystemInodePressureV1`, identity
`sha256:afafa1b16057adddbb6e3d46f7b2ffecaf954864559330c3b3ecad0ceeea4c28`):

| NQ state | Availability | Impact | Projected state | Reason code |
|---|---|---|---|---|
| `present` | `impaired` | `none` | `degraded` | `nq_filesystem_inode_pressure_present` |
| `explicitly_absent` | `available` | `none` | `healthy` | `nq_filesystem_inode_pressure_explicitly_absent` |
| `cannot_evaluate` | `indeterminate` | `indeterminate` | `unknown` | `nq_cannot_evaluate` |
| `not_evaluated` | `indeterminate` | `indeterminate` | `unknown` | `nq_not_evaluated` |

Labels: public `Filesystem inode pressure`; an operator policy may use
`Filesystem inode pressure (<mountpoint>)` where the mountpoint is an
absolute, normalized path (the same mechanism and limit as the capacity
adapter: the adapter cannot check the mountpoint against the correspondence,
whose subject is the machine id and filesystem UUID). Neither may appear in
a public identifier or text. Reason text, fixed per state:

- healthy: "Qualified filesystem inode-pressure condition absent in the
  current NQ observation. This is not a storage health, integrity, or
  capacity claim."
- degraded: "Qualified filesystem inode-pressure condition present in the
  current NQ observation. No outage, write failure, or cause is claimed."
- unknown: "The filesystem inode-pressure condition is currently unknown.
  This is not an outage."

The non-claims say the condition is inode accounting only: no capacity,
storage health, integrity, write-failure, performance, quota, growth, host
or service health, or cause claim. A verified capacity correspondence for
the same subject is refused by this adapter as `question_mismatch` before
any selector or certificate comparison, and the capacity adapter refuses an
inode correspondence the same way (`tests/consequence.rs`,
`a_capacity_correspondence_on_the_exact_same_subject_is_refused_on_the_question_alone`).

## Typed owner failure

The filesystem owner's closed list of 13 failure codes is shared by
`nq.host_filesystem_capacity` and `nq.host_filesystem_inodes`. The adapter
explains the same six the capacity adapter explains
(`filesystem_identity_mismatch`, `machine_identity_mismatch`,
`not_a_mountpoint`, `unsupported_filesystem_type`,
`mount_changed_during_observation`, `filesystem_identity_unavailable`) with
the same bounded operator-only `Detail` text, carries the other seven
opaquely with no explanation, and never explains another question's code
even when it is the same token on the same subject. Unknown stays unknown
with or without the detail.

## Qualification material

- `tests/question_row_pins.rs`: every inode row literal, the shared prefix
  and validity with the capacity row, and the synthetic profile, reliance
  policy and context digests; existing rows unmoved.
- `tests/filesystem_inodes_seam.rs`: the shared subject and validity, the
  question-only separation in both directions, refusal before custody, and
  co-production with support bounded by the row.
- `artifacts/nq-host-filesystem-inodes-correspondence-v1/`: the shared
  vector suite under the inode row (6 valid, 68 negative), refused against
  the load, filesystem capacity, memory and systemd rows; manifest
  `sha256:a879bba7…c677`.
- Adapter tests: consequence table and identity, label binding, public
  leakage, owner code sweep, operator detail, end-to-end projection, refusal
  of every other row including the same-subject capacity row, and an ignored
  real harness (`tests/real_projection.rs`).
