
## Exact native-time versus evaluation-time projection

Current NQ `prepare_evaluations` seals evidence references at millisecond
precision (engine.rs 5744–5750), while its canonical report preserves native
precision. The query-only observation export names `reference_time_basis`.
Monitor accepts exact native time or exactly that existing millisecond
projection, with the declared basis checked. Other fractional substitutions
refuse. Native source time remains visible and determines present reliance;
this conversion does not refresh it or reconstruct discarded precision.
Shared NQ/Monitor golden vectors include nanosecond source, projected reference,
changed fraction and substituted projection-name cases. Both repositories retain
identical vector bytes; source and result identities are in lane receipts.

Owner reads judge after custody queries complete. Their witness records final
local read time, and records the earlier request time separately. Native AG
`resolved_at_unix_ms` retains its existing caller-time correlation convention;
it is not testimony that the filesystem queries finished at that instant.
Expiry is never extended or a source timestamp clamped to force acceptance.
