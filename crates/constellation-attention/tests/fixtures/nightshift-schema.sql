-- Subset of the Nightshift canonical store (constellation-nightshift
-- crates/nightshiftd/src/canonical_store.rs) that the evaluator reads.
CREATE TABLE canonical_recurrence_slots (
    slot_id TEXT PRIMARY KEY,
    cycle_id TEXT,
    status TEXT NOT NULL,
    basis_json TEXT NOT NULL,
    state_digest TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;
CREATE TABLE canonical_observation_cycles (
    cycle_id TEXT PRIMARY KEY,
    slot_id TEXT NOT NULL UNIQUE,
    version INTEGER NOT NULL,
    status TEXT NOT NULL,
    state_digest TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(slot_id) REFERENCES canonical_recurrence_slots(slot_id)
) STRICT;
