# Application observation freshness for P4

Weatherwatch's standard textfile is a current consumer: node_exporter can keep
scraping a frozen file after the application stops. The existing collector
heartbeat witnesses declaration acquisition, not application progress. Add the
optional `metrics_observation_age_seconds` threshold to the existing declaration
whitelist, preserving the expected obligation without inventing an observation.
The matching Cartography rule compares the application timestamp value with time;
useful output retains its separate last-success budget.

The actual-declaration regression renders the limit for an absent service and
asserts the collector does not fabricate application observation time. Estate
collection tests: 38 passed. No Rust source/dependency changed and Cargo checks
were not run. Full source/live query evidence is owned by Cartography P4 root run
`88711845-9171-4593-89c8-7927152f148c`.

Formalization consideration (root): bounded claim is separation of authored
freshness obligations from observed progress. A fresh scrape of frozen values is
the counterexample that motivates this change. Tests plus the exact MetricsQL
frozen/missing/future drill are sufficient for this finite change; no distributed
availability or operator-delivery claim follows. The optional threshold itself
neither acquires evidence nor authorizes remediation.
