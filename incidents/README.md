# Incident continuity (cartography #93)

An alert says something happened. An incident says something still needs
dealing with. `constellation-incidents` keeps one durable incident per
supervised subject and failure condition, so that after hours away the
operator can ask one question:

    constellation-incidents            # what is broken, what was tried, what worked, what failed, what needs you
    constellation-incidents show inc-e048fb3e   # one retained incident's timeline
    constellation-incidents show 'constellation:labelwatch:service:service-down:attention-canary.service@2026-10-14T18:45:03Z'
                                              # copy the key@first_seen from a notice
    constellation-incidents ack|note|resolve ...  # operator actions, recorded as such

- **Identity.** The key is the condition key (`site:component:rule:target`),
  never a definition revision, so changing a threshold continues the same
  incident. A failure after closure opens `inc-…-2`.
- **Notice references.** The incidents tool is the only incident ID authority.
  Attention trigger and resolve summaries carry `condition-key@first_seen`
  immediately after the action; daily digests carry the same reference per
  active condition. Sync annotates the reference in the incident timeline with
  an `attention-reference` event containing the actual `incident_id`. `show`
  accepts that exact reference. After closure, the next reference resolves to
  `inc-…-2`; a new attention epoch inside incident recovery resolves to the
  original incident. Exact `inc-…` lookups always select that retained ID.
  Delivered messages remain unchanged: they contain a lookup reference, not
  a preallocated `inc-…` ID. Before sync observes the active condition, the
  lookup reports no incident; it never guesses the closed episode. References
  are available for the store's retained history (normally 30 days, 300 events).
  If attention state predates this change and lacks `first_seen`, the summary
  carries only the condition key, which looks up its newest retained incident.
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
