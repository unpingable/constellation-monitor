# Service Progress Diagnostic Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans for this bounded task; root owns VM integration and independent acceptance.

**Goal:** Let the existing operator diagnostic explain overdue useful work from standard service observations without inferring progress from process state.

**Architecture:** Add opt-in `--service NAME` to the existing one-shot diagnostic. Read the approved registry's existing useful-work and observation-age limits, then query the existing loopback range API for exact site/service/instance/job histories and their underlying sample times. Missing, stale, reset, malformed or ambiguous observations remain unknown.

**Tech Stack:** Existing Python JSON, urllib, argparse and unittest. No new formats, dependencies, providers or daemons.

**Spec:** Cartography `architecture/beta-observability/MONITORING-BACKLOG.md`, P7 follow-through; Monitor `estate/README.md`, application observation/useful-work timestamps; root's November 3 bounded implementation order.

## Global Constraints

- Base `3d7396de201c5198b70767802dfd8387b8c9f0a5`; branch `feat/beta-useful-work-diagnostic-20261103`.
- Reuse `service_last_success_timestamp_seconds` and `service_observation_timestamp_seconds`; no new counter or agent-status protocol.
- No target VM or production mutation, no Cargo builds, no action authority.
- Process and HTTP state are context only. A completed investigation is not a healthy-worker verdict.
- Root-owned disposable operator CLI is the concrete consumer; installed demonstration waits for rehearsal handback.

## Review Focus

- Scrapes of a frozen application textfile cannot establish fresh application observations.
- Missing, duplicated, wrong-target or incomplete histories cannot establish progress or a stall.
- A quiet window inside its authored work budget cannot establish a failure.
- A backwards timestamp/reset is unknown, never progress.
- Existing memory and no-action behavior must remain intact.

### Task 1: Diagnose standard useful-work history

- [x] Establish existing diagnostic baseline (21 tests).
- [x] Add CLI/real-loopback query-port tests for fresh progress, overdue work with active/HTTP-healthy context, and unknown cases; observe RED before implementation.
- [x] Implement bounded service selection, declared limits, exact queries, freshness/completeness checks and evidence-backed classification in the existing diagnostic.
- [x] Document exact operator command, standard producer inputs, interpretation and limits.
- [ ] Run full diagnostic tests, syntax/diff checks and independent source review.
- [ ] Record exact source/evidence identities; root decides integration and later disposable runtime demonstration.
