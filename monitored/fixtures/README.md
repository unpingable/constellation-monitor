These are synthetic local operator fixtures in the deployed wire shapes, not
host observations. The estate registry and output follow estate/README.md and
constellation-estate-collect.py. The attention report follows docs/ATTENTION.md
and engine.rs rules_report/condition_reports. The attention service declaration
is copied verbatim from the read-only Cartography testbed services.d/attention.toml.
The metric policy/runtime fields derive from estate/fixtures/vmalert-rules-runtime-v1.json,
restricted to HostIoPressureHigh and the marked HostSwapExhausted, with example
site labels, fixed times, and acquisition-failed code 2. Canonical digests and
the registry byte hash match these fixture bytes. No family is closed.

The snapshot ledger is copied byte-for-byte from the read-only coverage
integration worktree's architecture/beta-observability/docs/COVERAGE-FAMILIES.md.
Its prose is development context, never a claim about this example host.
