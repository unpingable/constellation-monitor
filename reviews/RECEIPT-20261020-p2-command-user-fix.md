# P2 command execution user correction

Base: `04167bc`; result identity is the commit containing this receipt.
Review identified a declaration shortcut that could inherit a root collector's
execution user. New declaration command statuses now require explicit non-root
`status_user` (shortcut) or `status.user` (full table). Missing users, root and
UID-zero strings fail rendering before output publication or any execution.
Existing legacy JSON behavior is unchanged. Declarations and approved registries
remain trusted operator inputs, not grants of access or action permission.

Future timer-success timestamps are UNKNOWN rather than PRESENT, and nonfinite
numeric timestamps are rejected.

Validation: 44 tests passed with `PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q
-p no:cacheprovider estate/test_collect.py estate/test_metric_alerts.py`.
Tests include root/missing user rejection, accepted explicit user, malformed
render producing no output/command effects, and main CLI collection retaining
approved names/runtime and original registry bytes when declarations disappear
or change. `git diff --check` passed. No production or Rust checks performed.

Formalization consideration: explicit execution identity is required for newly
rendered command declarations. Scope is the renderer's declared identity checks,
not proof of the target account's permissions or deployment trust. Tests and prose
suffice for this bounded validation; the trusted operator retains responsibility
for account identity and file installation. Decision owner: P2 lane, subject to
parent independent acceptance. No new authority mechanism introduced.

Custody: only source/tests/receipt and immutable notice created. No credentials,
VMs, compiler outputs or caches. Parent owns aggregate storage and worktree
retirement after source integration; minimal source provenance remains in Git.
