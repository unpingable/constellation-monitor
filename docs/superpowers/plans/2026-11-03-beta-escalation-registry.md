# Attention Escalation Registry Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans for this single bounded task. The root agent supplied the implementation scope and owns VM verification and integration.

**Goal:** Export all notification capabilities from the compiled attention registry for installed NQ policy validation.

**Architecture:** A config-free CLI command serializes typed registry entries. Runtime input reports and the exporter share the input-kind component mapping.

**Tech Stack:** Existing Rust, serde and serde_json; no dependencies added.

**Spec:** `docs/superpowers/specs/2026-11-03-beta-escalation-registry-design.md`

## Global Constraints

- Base `3d7396d`; isolated branch `feat/beta-escalation-registry-20261103`.
- No crow Cargo builds. Root runs red/green and regression checks on its build VM.
- No configuration, policy, rule semantics, evaluation digests or dependency changes.
- Commit only after VM evidence; no PR or publication.

## Review Focus

- Disabled rules remain exported.
- Input-fault components include the existing estate producer.
- Page rules include attention-class downgraded and removal notices.
- No runtime configuration, database, secret or executable is required.
- Unknown commands and arguments refuse without output.

### Task 1: Export and document the compiled capabilities

- [ ] Add `tests/escalation_registry.rs`: strict schema, complete RULES coverage, disabled and remediation page rules, class/component boundaries, deterministic read-only CLI and invalid arguments.
- [ ] Root runs `cargo test -p constellation-attention --test escalation_registry`; observe failure before implementation.
- [ ] Add typed export in `registry.rs`, share `InputKind` input component mapping with runtime reports, and add the CLI branch in `main.rs`.
- [ ] Document export and `nq notification policy --check-registry` use in `docs/ATTENTION.md`.
- [ ] Root runs formatter, focused tests, attention regression tests and Clippy on VM; validate output with NQ `2c1749f`.
- [ ] Review diff and evidence, then commit the bounded change.
