# NQ / Pulse filesystem-capacity correspondence v1 vectors

The load-pressure vector suite (`../nq-host-load-pressure-correspondence-v1`)
replayed under the second question of the correspondence table,
`nq.host_filesystem_capacity.pressure/1` against `nq.host_filesystem_capacity/1`
with the `host-filesystem:<machine-id>/<filesystem-uuid>` subject rule.

`manifest.json` pins the SHA-256 of every exact vector byte file and the
expected audit-verifier verdict or refusal code. `profile.json` is the exact
synthetic filesystem-capacity enrollment used to generate the cases. Three
cases exist only here: a record carrying the load record schema
(`record_question_mismatch`), an artifact carrying the load question identity
(`artifact_pin_mismatch`), and an artifact exporting the load claim
(`artifact_claim_mismatch`). Every vector, valid or not, is also refused by the
load profile on its question or profile digest.

There is no NQ contract mirror here: NQ's checked-in fixture set at the pinned
commit predates the filesystem profiles. The real `/data` artifacts from the
qualification host are campaign receipts, not vectors.

Everything here is generated fixture material, not NQ output; none of it can
construct `VerifiedCorrespondenceV1` or restore Pulse currentness.

```sh
cargo test -p pulse-nq-load-correspondence --all-features --test filesystem_capacity_vectors
```

Regeneration is an intentional source change. It rewrites `valid/`,
`negative/`, `profile.json`, and `manifest.json`; review the new bytes and then
update the compiled manifest digest deliberately:

```sh
REGENERATE_FILESYSTEM_CAPACITY_VECTORS=1 cargo test -p pulse-nq-load-correspondence \
  --all-features --test filesystem_capacity_vectors -- --nocapture
```
