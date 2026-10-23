# P2 source delivery

Owner: P2 implementation lane; acceptance owner: parent integration lane.
Base source: `3b514b3`. Result source is the commit containing this receipt.
The diff adds authored TOML rendering, pinned declaration verification, retained
expected subjects, dependencies and explicit timer first-result/success-age checks.
No production deployment, route or credential changed.

Validation: `PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider
estate/test_collect.py estate/test_metric_alerts.py`: 37 passed. Tests cover a missing
declared service, unavailable declaration while retaining off-host subjects, content
drift, deterministic rendering, installed path relocation, graph translation,
false output path and timer boundaries. Collector loss and host loss preserve the
approved registry by construction: collection does not rewrite it; live delivery
and off-host custody are integration tests owned by the parent lane. Rust checks
were not run for this Python-only change.

Formalization consideration: proposition is that loss/change of observation or
local declaration availability cannot remove expected subjects from the approved
registry. Scope is this collector invocation and immutable input JSON, not remote
custody or deployment authority. Practical tests plus the direct separation of
pure rendering from read-only collection suffice for this bounded change. The
counterexample of rebuilding from a live glob is avoided by requiring explicit
render mode; an operator explicitly rendering incomplete desired inputs can remove
subjects and requires review in the existing deployment procedure. Timer checks
cover boundary states rather than claiming historical success retention beyond
systemd's current record. No new formal model is needed. Decision owner: P2 lane,
subject to independent integration acceptance.

Custody: retain source, tests and this small receipt in Git for review and replay.
No build trees, VMs, caches or credentials created. Python bytecode/cache writing
was disabled. Parent owns aggregate storage and worktree retirement after source
integration; this lane's only outputs are source and the immutable completion
notice. Source receipt and minimal notice remain with commit provenance.
