# Estate supervision

Constellation's operational promise for a host, in four parts:

1. Know which services it is responsible for: `estate.<host>.json`, the estate
   registry. A service missing from it is unsupervised.
2. Know whether each one is doing its job: `constellation-estate-collect.py`
   combines runtime state (systemd or Docker) with the project's own status
   contract. That contract is the `.ops/observation.toml` producer emitting
   `project.ops.status/v1`, a Labelwatch-recent watcher report, or an HTTP
   probe. A required concern that is not `PRESENT` makes the service
   `DEGRADED`, including a missing observation. A container that Docker calls
   healthy is not thereby doing its job.
3. Fix what it is authorized to fix: the remediation consumer (unchanged here).
4. Say when it cannot: the attention evaluator reads `[inputs.estate]`. Its
   `service-not-doing-its-job` rule sends a Slack notice after 600 s, giving the
   service's own reason. The daily digest restates every open condition and
   every declared pause.

A deliberate pause is declared in the registry (`"declared": {"state":
"paused", "since", "reason"}`). The service then shows as `PAUSED`: never an
alert, always visible on the dashboard and in the digest.

Host registries are deployment data, not code: they name units, paths and
contracts of a real host, so they live in the private deployment repository
(for labelwatch-host: cartography
`architecture/beta-observability/mvp/labelwatch-host/`), with the vendored
contracts, the declared definition snapshot and the crosswalk.

The registry's `definitions` pin every alert and policy definition to the
identity its own subsystem computes: a file sha256, the attention
`attention_policy_digest` from `check-config`, or NQ's saved-check
`definition_digest`. Each pass compares the deployed side, and any mismatch
makes `estate-definitions` DEGRADED, naming the definition. The repository
side, where every pin must equal the committed declared copy, is a test next
to the registry.

Each `constellation.estate/v1` document also carries `registry_sha256`, the
lowercase SHA-256 of the exact registry bytes read for that pass. This additive
field lets the existing release verifier distinguish a fresh observation of
the intended declaration from an old or differently configured `OK` result.
It is provenance, not authorization or an assertion of current service health.
Older readers may ignore it; a verifier requiring it must report older reports
as unsupported. The shared `fixtures/definition-release/` vector is consumed
by Cartography's `architecture/day-two-release-lifecycle` release tests.

`nq-watcher-admission` definitions use the NQ-owned bounded read operation
`nq --config FILE --json watcher inspect INSTANCE`. The collector requires
`nq.watcher_inspection.v1`, the exact instance and a valid binding digest,
then compares that digest with the declared pin. NQ performs its own config,
profile, protocol/corpus, capability and execution-identity checks; Monitor
does not implement them. An older CLI, failed verification or unsupported
response is UNKNOWN. `program` may name an exact side-by-side NQ read artifact
so enrollment and the resident NQ binary remain unchanged. Its file identity
must also be pinned by the site registry. Admission verification does not
collect observations or assert service health. The shared
`fixtures/watcher-inspection-v1.json` vector is also in NQ's CLI tests.
New source and contract tests are not a deployment claim.
Admission inspection runs in the collector's existing account. On the deployed
Linux profile the startup-image identity checks require root's metadata access;
dropping to the database account would make loader inspection unavailable.
This operation still performs no collection, helper execution or store write.
No account, filesystem permission or capability is changed to make a read pass.

Install on the host:

    install -D -m 0755 constellation-estate-collect.py /usr/local/lib/constellation-estate/constellation-estate-collect.py
    install -D -m 0644 <registry from the deployment repo> /etc/constellation-estate/estate.json
    install -m 0644 constellation-estate-collect.{service,timer} /etc/systemd/system/
    systemctl daemon-reload && systemctl enable --now constellation-estate-collect.timer
    # attention.toml:  [inputs.estate]  path = "/var/lib/constellation-estate/estate.json"

## Metric alerts: vmalert as an attention input

`metric-alerts-collect.py` reads vmalert's `/api/v1/rules` once (1 MiB bound)
and writes `constellation.metric_alerts/v1`: every loaded alerting rule with
the same definition identity the estate collector pins
(`constellation.vmalert_policy/v1`), its state, health, last evaluation and
alert instances. The attention evaluator's `[inputs.metric_alerts]` turns each
rule labelled `attention: "true"` into a condition (`metric-alert-firing`,
notice after 60 s, carrying the alert's own summary); see
`docs/ATTENTION.md`. It observes only: no evaluation, no notifier, and an
unreadable source leaves the last good document in place and exits 1.

    useradd --system --no-create-home --shell /usr/sbin/nologin constellation-metrics
    install -D -m 0755 metric-alerts-collect.py constellation-estate-collect.py /usr/local/lib/constellation-estate/
    install -m 0644 constellation-metric-alerts-collect.{service,timer} /etc/systemd/system/
    systemctl daemon-reload && systemctl enable --now constellation-metric-alerts-collect.timer
    # attention.toml:  [inputs.metric_alerts]  path = "/var/lib/constellation-metric-alerts/metric-alerts.json"

`--declared <declared-vmalert-policy.json>` carries the deployment
repository's declared policy identity so the evaluator can tell a firing
alert under a drifted definition set from one under the declared set. The
shared vector `fixtures/vmalert-rules-runtime-v1.json` is consumed by
`test_metric_alerts.py` and by the evaluator's tests.

Binding value-code contract (2026-10-22), verbatim:

one alert identity per family; the alert value is a code: 1 = present (threshold met / violation), 2 = acquisition failed (exporter or producer unreachable), 3 = missing (no series), 4 = stale or future timestamp, 5 = invalid or warming (no history yet, counter reset, invalid limit). Every value-coded rule carries the static label `constellation_value_codes: "v1"` (this is the machine-readable marker; `description` annotations do not reach the reader, labels and `summary` do). The evaluator maps non-1 values to unknown-held ONLY for rules carrying that label, with the cause naming the code's meaning (2 acquisition_failed, 3 missing, 4 stale, 5 invalid_or_warming); unlabelled rules keep raw-value semantics exactly as today (their values may legitimately be 2 or 3). A labelled rule with a value outside 1-5 is an input fault for that rule (rejected-rule class, like the per-rule admission in 0.1.10), never present and never clear. The `summary` annotation of value-coded rules reads `evidence code={{ $value }} (<meaning>)`; the notice text for a present code should use that summary as today.

Rules also carry `attention: "true"` to opt into the evaluator. Code 1 is
present only when firing; pending retains vmalert's hold. Inactive rules clear
only when freshness, health, evaluation and policy checks permit recovery.

Rule labels and bounded instance values pass through unchanged. For marked
rules the producer additionally writes `value_code_counts`, a complete list
of `{site, state, value, count}` rows for firing and pending instances,
computed before the 32-instance detail bound (empty site means no label).
This keeps unknown codes visible at high fan-out and across sites. Deploy
the collector with the evaluator: a marked active rule missing that summary
is rejected per rule, as are malformed values and unsupported versions. An
open condition holds as `unreported`; other definitions keep evaluating.
The shared vector covers both producer bytes and evaluator meaning,
including pending and unsupported codes.

Unknown-held conditions send no metric notice until they have been present.
Their code and meaning appear immediately in the report and bounded digest;
lasting unknown codes surface through the existing input `indeterminate`
fault and `evaluator-input-unavailable` notice after its default 300 s.
No additional timer is introduced. Plain `lastSamples = 0` with positive
`lastSeriesFetched` cannot reliably reveal missing comparison history;
definitions needing that distinction must opt into explicit value codes.

**Admission before deployment.** The evaluator admits each opted-in rule on
its own: a rule whose condition target cannot be derived (the alert name as a
token, plus `.<site>` for each `[inputs.metric_alerts] sites` entry, at most
48 bytes of `[a-z0-9._-]`, not shaped like a date or digest) is rejected
alone, for the site whose target overflows only, and reported as
`metric_alerts.rule_rejected:<AlertName>`; rules sharing a token are all
rejected; the other rules are evaluated. To
refuse such a rule set before it reaches a host, run the check against the
declared policy the producer carries, with the evaluator's sites:

    metric-alerts-collect.py --check-targets --declared declared-vmalert-policy.json --key-site labelwatch

The value-code marker is accepted without changing target derivation. Every
labelled rule must have a `summary` containing `evidence code=`, including
rules without attention opt-in. Description-only annotations fail this check.
It reads nothing else, prints `constellation.metric_alert_admission/v1` (each
attention rule with its admitted targets, its refusals per site and the
longest derived byte count), names each refused rule and site on stderr and exits 1 if any rule would be rejected. A
renderer or a definitions test should run it for every site set it deploys.
`ServiceMetricsObservationNeedsAttention` is the case it exists for: its
43-byte token plus `.testbed` is 51 bytes (`.labelwatch`: 54). The shared
vector `fixtures/metric-alert-targets-v1.json` holds both implementations to
the same derivation.
