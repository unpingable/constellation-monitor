# Incident continuity (cartography #93)

An alert says something happened. An incident says something still needs
dealing with. `constellation-incidents` keeps one durable incident per
supervised subject and failure condition, so that after hours away the
operator can ask one question:

    constellation-incidents            # what is broken, what was tried, what worked, what failed, what needs you
    constellation-incidents show inc-e048fb3e   # one incident's timeline (Slack notices end with "Incident: inc-...")
    constellation-incidents ack|note|resolve ...  # operator actions, recorded as such

- **Identity.** The key is the condition key (`site:component:rule:target`),
  never a definition revision, so changing a threshold continues the same
  incident. A failure after closure opens `inc-…-2`.
- **No resolution by disappearance.** Suspended, retired ("no longer
  evaluated") and vanished-while-present all leave the incident open, with an
  event saying why. It closes only after the attention evaluator resolved the
  condition as recovered *and* it stayed clear for 300 s, with no remediation
  episode still in flight. A flap inside that window continues the incident.
- **Remediation accounting.** The remediation consumer's episodes are attached
  by condition key and `first_seen`. The command outcome (`settled_failure`,
  `completed`, ...) is kept apart from verification: `completed` means the
  consumer re-sampled the postcondition after its dwell. Failed remediation, an
  expired remediation window with no attempt, or no remediation authority sets
  "needs you", using the rule's own operator instruction.
- **Independence.** The store is its own SQLite file
  (`/var/lib/constellation-incidents/incidents.sqlite`). `list` and `show`
  open it read-only, so they work with the evaluator, NQ or the remediation
  consumer down. Each sync writes a heartbeat and
  `constellation_incidents_*` metrics to the telemetry textfile directory;
  crow alerts when the sync goes stale.
- **Bounded.** Resolved incidents are kept 30 days, with at most 300 events
  per incident. Observations stay where they are and are not copied.
- **Shim.** Lifecycle semantics live in `sync()`. A backend implements the
  small `Store` interface. `test_incidents.py` runs the whole lifecycle
  against SQLite and an in-memory stub. A failed write raises
  `StoreUnavailable`, and the CLI exits 3 having claimed nothing.

The bounded machine interface for the Operations Board is
[`inspect`](INSPECTION.md). It returns unresolved and recently resolved incidents,
exact attempts, retained history, sync metadata and explicit missing fields.
The UI lives in Constellation Workbench, separate from this lifecycle owner.
