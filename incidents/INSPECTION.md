# Read-only incident inspection

`constellation-incidents inspect` emits `constellation.incidents.inspection/v1`.
This is the incident owner's machine read interface for
[cartography #102](https://github.com/unpingable/cartography/issues/102).
It adds no lifecycle operation or incident store. The accepted production baseline
was `a42822f`; the implementation is based on operational head `b6f35f4`, whose
incident source is identical to that baseline.

```sh
python3 incidents/constellation-incidents.py --db /absolute/incidents.sqlite inspect
python3 incidents/constellation-incidents.py --db /absolute/incidents.sqlite inspect --id inc-e048fb3e
python3 incidents/constellation-incidents.py inspect --handover /absolute/latest.json
```

The normal inspection returns every unresolved incident and incidents resolved
in the last 24 hours, with exact retained rows, attempt episode identities, and
history in source append order. `--id` reads an exact retained identity, including
older resolved records. Source retention still applies. A single SQLite read
transaction supplies rows, attempts, events and metadata consistently. The
connection is `mode=ro` with `query_only`. SQLite may create WAL read-coordination
sidecars; no incident row, history or metadata is updated and no store is created.
Do not use `immutable=1` on a changing store: it would omit live WAL state.

The envelope contains `schema`, `read_at`, `source` (kind, configured locator and
implementation SHA-256), `meta`, `scope`, `missing_fields` and `incidents`.
Each entry has `incident`, `events` and `attempts`. No UI-generated fields are
stored here. Bounds are 1000 incidents and 16 MiB encoded output: over-limit,
missing, malformed or unsupported sources exit 3 with no successful JSON result.
A successful empty inspection is a read of zero retained matching records,
never an estate-health assertion.

`inspect --handover` converts the existing off-host export to the inspection
envelope without import. It preserves exported identities and histories,
labels its source `off-host-handover/v1`, exposes `exported_at`, and supplies no
sync health. This mode contains unresolved records only. It is neither a live
service-health view nor lossless replication. The original handover contract
and lifecycle behavior remain unchanged.

The source does **not** supply assignment, response actor, authority decisions,
proposal/queue state, a next checkpoint, service-health verdicts, acquisition
timestamps, detection counts or unpersisted detections. `ack_by` names an
acknowledger, not a current handling agent. `last_observed_at` is an incident
sync update, not an independently established acquisition time. Metadata has
only the latest sync result; after a failed sync the last *successful* sync time
cannot be reconstructed. These omissions are explicit in `missing_fields`.

Verification uses the unchanged lifecycle tests plus `test_inspection.py`.
`generate_board_fixture.py --out PATH` generates deterministic cross-repository
conformance/demo vectors using the real shim. The Workbench retains that JSON
as `fixtures/incidents/demo.json`. Fixture authority/checkpoint examples are
explicitly synthetic and do not claim these fields exist in the live contract.

Formalization consideration: incident identity, read-only state, bounded
failure and exact event/attempt preservation are the propositions. The scope is
this inspection command over the existing shim and SQLite snapshot semantics;
external service truth and source honesty are outside it. Decision owner: the
implementing agent, subject to PR review. Practical contract tests, immutable
vectors, before/after database hashes and source review suffice for this small
read transformation. There is no new transition system to model. Reordered
history, URI-character paths, missing stores, operator closure and unconfirmed
attempts are explicit counterexample cases. This does not formalize or broaden
the incident lifecycle's recovery claim.
