# Non-goals

Status: normative scope boundary for the qualified vertical slice, bounded
receiver/scheduler, local crash-fault custody, and qualified-generation binding
and receiver-boundary custody campaigns.

The repository does not implement or claim:

- global consensus over reality;
- Byzantine correctness;
- trusted self-attestation;
- full cryptographic attestation infrastructure;
- reproducible builds or source-to-binary correspondence;
- compiler, toolchain, kernel, loader, or host trust;
- secure boot, TPM-backed measurement, or remote attestation;
- signer authorization, public key infrastructure, or a global certificate or
  revocation authority;
- artifact freshness, organizational approval, supply-chain security, or
  malware absence;
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
- replacement of Constellation NQ, a separate evidence producer, Nightshift,
  Docket, or Phosphor behavior;
- Lean code, formalization, or claims of formal verification;
- hard real-time scheduling or latency guarantees;
- a production receiver, production transport, distributed scheduler,
  leader election, or failover protocol;
- network confidentiality, traffic-analysis resistance, service discovery,
  general RPC, trust-on-first-use, dynamic enrollment, key rotation, public
  PKI, DNS or network-endpoint authority;
- key secrecy or exclusive custody, organizational or host identity, signer
  authorization, remote attestation, or failure-domain independence;
- synchronized clocks, sender-clock freshness, bounded one-way delay,
  first-seen observation-age knowledge, guaranteed packet delivery, ordering
  or network availability;
- multi-hop, multi-receiver, arbitrary multi-sender or distributed session
  custody;
- crash-durable current standing or recovery of hot pulse windows;
- hard bounds on scheduler latency under arbitrary host load;
- physical-media durability or immunity to filesystem, kernel, or storage
  device defects;
- host-crash, distributed crash-consistency, replication, failover, or
  consensus semantics;
- a database, generic write-ahead log, compaction framework, journal query
  engine, or long-term historical store;
- detection of exact committed-prefix rollback without a separately trusted
  external tail anchor;
- durable diagnostic execution, retry, request ownership, or suppression
  authority;
- a general async runtime, generic scheduler, or networking service;
- a general build system, package manager, transparency log, deployment
  orchestrator, or mutable artifact watcher;
- unbounded policy/configuration history or a general configuration service;
- a general query engine, plugin framework, or runtime rules engine; or
- full contradiction-resolution or policy-supersession semantics.

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
