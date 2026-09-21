# Qualification artifacts

`demo-report.json` is the deterministic JSON report produced from
`traces/demo.jsonl` during the 2026-08-03 qualification run. It retains sparse
transition provenance, the escalation disposition, and the mock diagnostic
receipt so the historical result does not depend only on terminal prose.

The receiver/scheduler campaign adds:

- `runtime-generation-demo.json`: deterministic exact-generation,
  rollback/ABA-resistance, explicit reevaluation, and inclusive-expiry steps;
- `runtime-restart-demo.json`: an exact serialized history round trip in which
  a historical `CURRENT` certificate record is recovered but current standing
  is `UNKNOWN` with no support or schedule;
- `runtime-qualification.json`: machine-readable index of the deterministic
  runtime qualification cases and required gate commands; and
- `runtime-live-linux.json`: one bounded local `/proc` wall-clock exercise,
  explicitly separated from replay-clock measurements and carrying no
  real-time guarantee.

These reports are regression artifacts, not production telemetry storage and
not Constellation NQ or independent evidence-producer artifacts. Generation deliberately refuses to overwrite
an existing file; remove or move an old report explicitly before creating a
replacement.

The local crash-fault campaign adds:

- `crash-reactor-demo.json`: one real monotonic `UNKNOWN -> CURRENT -> UNKNOWN`
  deadline withdrawal with the encoded deadline, wake time, overshoot, and
  committed historical withdrawal;
- `crash-restart-demo.json`: the selected pre-expiry `SIGKILL` trace showing
  recovered historical `CURRENT` provenance but restart `UNKNOWN`, support
  zero, and deadline zero;
- `crash-injection.json`: all 12 named child-process kill boundaries, including
  write-before-sync, sync-before-acknowledgement, acknowledged custody, and
  restart invariants;
- `journal-corruption-corpus.json`: 19 clean, torn, corrupt, reordered, replay,
  version, length, I/O, and bound cases plus a 3,088-position byte-truncation
  sweep;
- `crash-torn-journal-demo.json` and
  `crash-interior-corruption-demo.json`: the two focused recovery demo records;
- `crash-reactor-live-linux.json`: six real monotonic timer samples, controlled
  scheduler delay, CPU load, write-path delay, restart scans, escalation
  deduplication, `SIGKILL`, and corruption injections; and
- `crash-reactor-qualification.json`: the machine-readable check/test index and
  required gate commands.

The live timings describe one local run. Concurrent artifact generation placed
additional CPU and filesystem load on that run; the measurements are evidence
of observed behavior, not latency guarantees. Checksums are corruption
detection, not authenticity, and no artifact restores current standing or
grants diagnostic or mutation authority.

The qualified-generation campaign adds the
`qualified-generation-binding/` directory:

- canonical `qualified-manifest.json`, `qualification-report.json`, and
  `qualification-certificate.json` bind the exact ten-role artifact inventory,
  source/build assumptions, three checked gate commands, 125 observed tests,
  and hostile corpus;
- canonical `activation-receipt.json` records one local
  `QualifiedAndMatched` process occurrence and eight activation-required
  measurements, including the opened `/proc/self/exe` object;
- `matched-activation-demo.json`, `executable-mismatch-demo.json`, and
  `policy-substitution-demo.json` show exact acceptance and two fail-closed
  substitutions;
- `mismatch-corpus.json` covers every activation-required artifact role, while
  `authority-laundering-refusals.json` records why labels, digests, manifests,
  certificates, source identities, test results, historical receipts,
  superseded/revoked packages, and partial matches are insufficient;
- `restart-activation.json` records historical receipt recovery with binding
  `Unbound`, judgment `UNKNOWN`, support zero, and deadlines zero;
- `crash-restart-activation-corpus.json` records 12 real `SIGKILL` boundaries
  and the one semantically refused receipt-before-activation ordering; and
- supersession/revocation and the exact checked qualification summary remain
  separate machine-readable records.

The manifest, report, certificate, corpus, results, and activation receipt are
stored as their exact compact canonical bytes, without a trailing newline.
Other demonstration/index artifacts are ordinary pretty JSON. SHA-256 here is
content identity and corruption detection, not authorship, signer authority,
source-to-binary proof, independent attestation, or supply-chain security.

The receiver-boundary campaign adds the `receiver-boundary-custody/`
directory. It contains exact canonical sender/receiver policies and local
qualification packages; public peer-key identities; signed sender-offer,
receiver-challenge, sender-binding, receiver-session-acceptance and observation
envelope corpora; admission/support references; authentication, replay,
sequence, occurrence, restart and authority-refusal corpora; local Linux timing
and actual UDP loopback measurements; and an exact qualification index.

All private-key fields are absent and artifact generation is regression-tested
by reparsing every JSON object, verifying all three qualification packages and
decoding every signed datagram under the retained public keys. The loopback
measurement is not labeled two-host. This public source cut contains no
two-host qualification claim or retained machine-specific two-host record.
