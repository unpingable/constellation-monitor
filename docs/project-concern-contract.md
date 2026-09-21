# Generic project-concern discovery and acquisition contract

This contract lets a repository state which bounded propositions should be
observable and lets Monitor acquire a project-owned status document without
learning those propositions' domain semantics.

The central invariant is:

```text
declared concern
!= producer returned an observation
!= NQ admitted the observation
!= current qualified support
```

A declaration is inventory, not evidence. An explicit producer `UNKNOWN` is
an acquired observation of insufficient knowledge. A required declaration for
which no observation was acquired is instead
`MISSING_REQUIRED_OBSERVATION`. Monitor never silently merges those states.

## The three artifacts

### Semantic declaration

`.ops/concerns.toml` uses the exact schema identity
`project.concerns/v1`:

```toml
schema = "project.concerns/v1"
project = "example"

[[concerns]]
id = "example.queue.progress"
question = "example.queue.progressing/v1"
profile = "example.queue.local/v1"
required = true
description = "Accepted queue work is advancing."
```

Each concern has a stable concern, question, and profile identity; a required
flag; and a concise proposition. The file contains no execution, paging,
severity, retry, remediation, recurrence, or escalation policy.

### Acquisition binding

`.ops/observation.toml` uses `project.observation-binding/v1`. It is
deliberately separate from the semantic inventory:

```toml
schema = "project.observation-binding/v1"
producer = "example.status"
output_schema = "project.ops.status/v1"
kind = "exec/v1"
argv = ["python3", "-m", "example.status", "--json"]
environment = { PYTHONPATH = "src" }
```

One project-level producer emits observations for multiple concerns. The
argument vector is executed directly, never through a shell. Environment
values are literal. Keeping this operational binding separate means the
declaration remains intelligible if acquisition later moves from process
execution to another transport.

### Observation envelope

The shared envelope is `project.ops.status/v1`. It carries project,
manifest, and producer identity; producer generation time; authority metadata;
and zero or more concern observations. Each returned concern repeats the
declared identity and proposition metadata so Monitor can reject mismatches.

An observation contains:

- `observation_present`;
- an opaque, nonempty project-owned `local_state`;
- an optional project-owned `domain_state`;
- the producer's `observed_at`, which may be null;
- an optional producer-supplied validity duration;
- a reason and structured supporting facts.

Monitor preserves states such as `UNKNOWN`, `STALE`, `REFUSED`,
`DRIFT_OBSERVED`, and unfamiliar future states. It does not map them to a
health boolean. Project-specific material may appear only below
`extensions`.

If a concern is omitted, or its item says `observation_present = false`,
Monitor emits no observation for it and retains the declaration as missing.
This is not the same as the producer returning an explicit `UNKNOWN`.

## Monitor inventory and provenance

Collection produces `monitor.project-observation.inventory/v1`. It is the
left join of declarations onto structurally valid acquired observations. Its
only join dispositions are `OBSERVED`,
`MISSING_REQUIRED_OBSERVATION`, and
`MISSING_OPTIONAL_OBSERVATION`; the proposition state remains untouched
inside the observation.

Provenance records the consumed manifest digest, status-byte digest when any,
producer identity, acquisition occurrence, process disposition, exit code,
bounded output counts, and repository revision context. Repository HEAD is
explicitly labelled as worktree context and never as proof of the deployed
producer's revision. Successful execution is not successful observation, and
acquisition time never replaces `observed_at`.

## Discovery, validation, and the execution boundary

```sh
cargo run -p monitor-project-concerns --bin monitor-concerns -- discover ROOT
cargo run -p monitor-project-concerns --bin monitor-concerns -- inspect PROJECT
cargo run -p monitor-project-concerns --bin monitor-concerns -- validate PROJECT
cargo run -p monitor-project-concerns --bin monitor-concerns -- collect PROJECT --trusted-root ROOT --allow-exec
cargo run -p monitor-project-concerns --bin monitor-concerns -- workspace ROOT --trusted-root ROOT --allow-exec
```

`discover` is passive. It reads compatible direct-child repositories and
never executes producer content. A semantic declaration without a binding is
still discoverable. `inspect` and `validate` require the complete currently
supported producer contract.

`collect` requires both explicit execution enablement and containment below
the configured trusted root. It clears the ambient environment, retains only
`PATH` for executable lookup, adds declared literal environment values,
rejects declared `PATH`, `HOME`, loader-control variables, and unsafe
environment names, sets the repository as the working directory, provides no
stdin, invokes direct argv, and bounds runtime and captured stdout/stderr.
Cancellation kills the child. Discovery of a manifest never grants execution
trust.

Structural validation rejects malformed or unsupported schemas, duplicate
project or concern identities, duplicate returned observations, undeclared
concerns, project/producer/manifest-reference mismatches, changed
question/profile/required/description fields, invalid timestamps, and invalid
envelope structure. Monitor rejects correspondence failures; it does not
decide whether a domain proposition is true.

## Versioning

The supported exact v1 identities are:

- `project.concerns/v1`
- `project.observation-binding/v1` with kind `exec/v1`
- `project.ops.status/v1`
- `monitor.project-observation.inventory/v1`

An unknown major or otherwise unknown exact identity is refused explicitly.
There is no implicit downgrade and no schema negotiation framework.

## Adoption and conformance

A new project:

1. adds the semantic declaration;
2. chooses stable concern/question/profile identities;
3. exposes one deterministic machine-readable producer;
4. adds the separate project-level acquisition binding;
5. runs `monitor-concerns validate PROJECT`;
6. runs collection and verifies required missing observations remain visible;
7. optionally builds an NQ adapter only when NQ has a real matching semantic
   admission seam.

The checked-in `example-fixture` is a fourth project unknown to Monitor
production code. It proves discovery, acquisition, stable identity matching,
one required observed concern, one required missing concern, one optional
concern, and preservation of the unfamiliar `EXAMPLE_PAUSED/FROBNICATED`
state without adding a registry or project-specific adapter.

## Ownership and non-goals

Repositories own their propositions and the facts they can support. Monitor
owns passive discovery, bounded explicitly trusted acquisition, structural
correspondence, provenance, and inventory gaps. NQ owns semantic admission and
governed inquiry. Pulse owns independent support/currentness judgments where
applicable. Nightshift owns recurrence, horizon, escalation, and attention.

Monitor does not know whether a domain proposition is true, decide alert
severity, own remediation, infer currentness absent in evidence, make NQ
admissions, infer no events or no drift, confer publication authority, or
execute arbitrary discovered repositories. NQ's separate, closed
`project-predicate` profile catalog may admit exact typed predicates over this
inventory; that does not widen Monitor's role or turn an opaque producer state
into a universal health verdict.

The checked-in schemas are the public contract used by this implementation.
A consumer must pin their exact bytes or a repository revision and qualify its
own producer binding. A change to accepted v1 meaning requires an explicit
contract version; a producer repair to satisfy established v1 does not.
