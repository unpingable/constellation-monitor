# constellation-attention

Bounded operator-attention evaluator. One invocation is one pass:

```text
constellation-attention evaluate --config FILE [--dry-run] [--now RFC3339]
constellation-attention state --config FILE
constellation-attention reset-clock --config FILE
constellation-attention rules
constellation-attention check-config --config FILE
```

`evaluate` reads the configured inputs, turns them into present / clear /
unknown observations per condition, applies the closed rule registry's
persistence bounds, writes NQ notification intents (v2 for PagerDuty, v1 for
Slack/Discord/local inbox), submits them with `nq notification submit` (or
`resubmit` for a PagerDuty retry, or `deliver-local` for a `local_file`
route), records the outcomes in the state file and writes `report.json`.
`--now` is for dry runs; release builds refuse it without `--dry-run`.
`reset-clock` recovers from a corrected forward clock step (it clamps future
timestamps in the state to now and deletes nothing).
Exit codes: 0 clean; 1 runtime error (including another pass holding the
state lock, an unreadable state file, which is never replaced, or a clock
earlier than the last pass); 2 usage or configuration error; 3 the pass
completed but an input was not current, a delivery is not accepted or a
trigger was dropped.

It consumes qualified current product state and produces notification
intents. It is not evidence, observation or execution authority, not a policy
language and not a rules engine; it never reads Classic NQ, never stores
secrets and never contacts a destination itself. See
[`docs/ATTENTION.md`](../../docs/ATTENTION.md) for the registry, lifecycle,
routing and limits, and [`packaging/attention`](../../packaging/attention) for
the systemd units, example configuration and qualification steps.

Tests run passes of the real binary against fixture inputs (host-posture
status objects, an `nq.status_snapshot.v3` export, a scratch Nightshift
store, saved-check results) and a fake `nq` (`tests/fixtures/fake-nq.sh`)
that records submissions. Golden intents are in `tests/fixtures/golden/`;
regenerate with `UPDATE_GOLDEN=1 cargo test -p constellation-attention`.
