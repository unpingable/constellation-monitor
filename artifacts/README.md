# Qualification artifacts

`demo-report.json` is the deterministic JSON report produced from
`traces/demo.jsonl` during the 2026-08-03 qualification run. It retains sparse
transition provenance, the escalation disposition, and the mock diagnostic
receipt so the skunkworks result does not depend only on terminal prose.

The report is a regression artifact, not production telemetry storage and not
an NQ-NG or Witness artifact. Regeneration deliberately refuses to overwrite
the existing file; remove or move an old report explicitly before creating a
replacement.
