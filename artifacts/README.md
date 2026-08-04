# Qualification artifacts

`demo-report.json` is the deterministic JSON report produced from
`traces/demo.jsonl` during the 2026-08-03 qualification run. It retains sparse
transition provenance, the escalation disposition, and the mock diagnostic
receipt so the skunkworks result does not depend only on terminal prose.

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
not NQ-NG or Witness artifacts. Generation deliberately refuses to overwrite
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
