# Qualified-generation binding campaign plan

Status: implementation plan written after read-only reconnaissance and before
campaign code changes. The repository and record names remain provisional.

Starting point: clean `main` at
`3cd15b7a1e7f424f6fd57c09b30fa4790947eca2`, with no configured remote. The
baseline formatting and lint gates passed and all 97 tests passed.

1. Define a closed, bounded canonical manifest, checked qualification report,
   qualification certificate, local acceptance policy, lifecycle fact,
   activation receipt, and runtime binding-state contract.
2. Add exact canonical identities for the executable and the evaluator,
   reliance policy, consumer profile, observer set, observation policy, and
   runtime configuration values actually supplied to the runtime.
3. Build a narrow local package generator/verifier. It will ingest exact
   machine-readable command results rather than act as a build system, and it
   will refuse claims not present in checked evidence.
4. Gate every `CURRENT` support certificate on a non-serializable accepted
   activation produced by fresh local measurement. Preserve consumer isolation,
   generation barriers, restart `UNKNOWN`, contradiction custody, deadline
   custody, and all no-authority boundaries.
5. Add local configured supersession/revocation handling, adversarial
   substitution/canonicalization tests, restart/crash tests, deterministic
   demos, and machine-readable qualification artifacts.
6. Run the complete workspace gates and demos, update architecture and the
   campaign report, commit coherent local milestones, then verify a clean tree,
   no remote, and unchanged neighboring repositories.

The campaign stops rather than weakening exactness if an active input cannot be
measured, qualification evidence cannot be checked, or runtime acceptance would
have to trust a generation label, prior receipt, manifest digest, or certificate
alone.
