# NQ / Pulse correspondence v1 vectors

`manifest.json` pins the SHA-256 of every exact vector byte file and the
expected audit-verifier verdict or refusal code. `profile.json` is the exact
synthetic enrollment used to generate the correspondence cases. The
`nq-diagnostic-contract-v2-mirror/` directory is a digest-pinned mirror of the
NQ fixture set at commit `6190218f1da817d6900d1dbc551d52818673154e`; its
`SOURCE.json` records the source tree and manifest digest.

The `valid/` and `negative/` names describe acceptance or refusal by the
persisted-record audit verifier. They do not mean that synthetic records are
live reliance input. All correspondence records here are generated fixtures,
not NQ output, and cannot construct `VerifiedCorrespondenceV1` or restore
Pulse currentness. Positive Present and ExplicitlyAbsent qualification vectors
must be replaced or supplemented with records from the separately authorized
real disposable run before Candidate standing can advance.

Normal tests verify the pinned manifest, each file digest, byte-for-byte
mechanical regeneration, expected result, and absence of unlisted vector
files:

```sh
cargo test -p pulse-nq-load-correspondence --all-features --test vectors
```

Regeneration is an intentional source change. It rewrites only `valid/`,
`negative/`, `profile.json`, and `manifest.json`; review the new bytes and then
update the compiled manifest digest deliberately:

```sh
REGENERATE_CORRESPONDENCE_VECTORS=1 \
  cargo test -p pulse-nq-load-correspondence --all-features --test vectors \
  -- --nocapture
```
