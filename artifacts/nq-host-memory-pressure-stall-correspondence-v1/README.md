# NQ / Pulse memory pressure-stall correspondence v1 vectors

The shared question-parameterized vector suite
(`crates/pulse-nq-load-correspondence/tests/common/vector_suite.rs`) under
the third row of the correspondence table, `nq.host_memory.pressure_stall/1`
against `nq.host_memory/1`, subject `host:<machine-id>` (the prefix load also
uses), reliance 120 s and frame validity 118 999 ms.

`manifest.json` pins the SHA-256 of every exact vector byte file and the
expected audit-verifier verdict or refusal code. `profile.json` is the exact
synthetic memory enrollment used to generate the cases. Beyond the load case
table the suite adds, per other row (load, filesystem): a record carrying the
other row's schema (`record_question_mismatch`), an artifact carrying the
other question identity (`artifact_pin_mismatch`) or claim
(`artifact_claim_mismatch`), a detector refusal naming the other NQ profile
(`artifact_ladder`); and, because the other rows' validity differs, a frame
sealed with 298 999 ms (`frame_validity_mismatch`) and a record held
298 998 ms, lawful under the other rows only (`holding_delay_exceeds_validity`).
Every vector, valid or not, is refused by both other rows' profiles.

There is no NQ contract mirror here. Everything is generated fixture
material, not NQ output; none of it can construct `VerifiedCorrespondenceV1`
or restore Pulse currentness.

```sh
cargo test -p pulse-nq-load-correspondence --all-features --test memory_pressure_vectors
REGENERATE_MEMORY_PRESSURE_VECTORS=1 cargo test -p pulse-nq-load-correspondence \
  --all-features --test memory_pressure_vectors -- --nocapture
```
