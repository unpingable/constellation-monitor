# P3 collector limit projection

Owner: P3 collector follow-up lane; acceptance owner: parent integration lane.
Source base: P2 `c3f0f7b`; result source is this receipt's commit.
Threshold keys are restricted to the six supported service limits. Their gauges
and a collector-pass timestamp share the existing estate textfile, including
services without file probes. A declared threshold with no textfile destination
fails instead of silently dropping its projection.

Validation: `PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider
estate/test_collect.py estate/test_metric_alerts.py`: 40 passed. New cases cover
unknown keys, deterministic limit rendering and threshold publication with no
file probes and a DOWN runtime. `git diff --check` passed. No Rust checks run.
Parent owns generic rules, testbed execution and production acceptance.

Formalization consideration: emitting an authored threshold and pass timestamp
must not imply application health. The timestamp explicitly remains present for
a DOWN runtime; tests demonstrate that distinction. This is a bounded projection
of approved inputs, with no state transitions or new authority. Practical tests
and prose suffice; no liveness or alert-delivery claim is made. Decision owner:
collector lane, subject to independent parent review.

Custody: source, receipt and tests retained in Git for review and replay. No VMs,
credentials, compiler targets or caches created. Bytecode writing disabled. Parent
owns aggregate storage and worktree retirement after integration; the only new
artifacts are source, this minimal receipt and the immutable completion notice.
