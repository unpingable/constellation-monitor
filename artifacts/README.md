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
