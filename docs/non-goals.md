# Non-goals

Status: normative scope boundary for the first campaign.

The repository does not implement or claim:

- global consensus over reality;
- Byzantine correctness;
- trusted self-attestation;
- full cryptographic attestation infrastructure;
- automatic repair or remediation;
- production mutation of any kind;
- distributed persistent storage;
- long-term metrics or pulse retention;
- generic metrics, logging, tracing, event, or observability ingestion;
- a Prometheus replacement or Prometheus compatibility;
- OpenTelemetry compatibility;
- Kubernetes-specific architecture or integration;
- cloud-provider integration;
- eBPF collection;
- dashboards or a full TUI;
- a general rules engine;
- machine-learned anomaly detection;
- a generic agent API;
- agent-defined diagnostics;
- universal health semantics;
- a global `healthy` boolean;
- proof that an observation is truthful;
- proof that named observers have independent failure domains;
- proof of complete distributed-world knowledge;
- use of sender wall clock as the primary freshness authority;
- arbitrary diagnostic command execution;
- diagnostic success as indefinite health;
- escalation as authorization, repair, or mutation;
- replacement of NQ-NG, Witness, Nightshift, Docket, or Synesthesia behavior;
- Lean code, formalization, or claims of formal verification; or
- hard real-time scheduling or latency guarantees.

The Linux `/proc` producer is a narrow demonstration profile, not the start of
a collector ecosystem. The JSONL replay corpus is a semantic test surface, not
an event-storage product. The bridge is a closed local stub, not a generic NQ
client or execution API.

## Product-category restraint

A working demo can establish only that a coherent semantic kernel is possible.
It cannot establish market demand, operational usability, adversarial security,
deployment viability, or that a new product category exists. The campaign's
final assessment must distinguish:

1. a novel presentation of ordinary monitoring;
2. a useful runtime component; and
3. a separate present-confidence product plane.

The implementation should be judged against the bounded earned result in the
README, not against breadth.
