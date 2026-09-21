# Diagnostic escalation seam

Status: normative for the local stub; exploratory for a future
Constellation NQ adapter.

The seam asks for deeper observation after a named reliance bound ceases to
hold. It does not authorize the diagnostic in Constellation NQ, authorize any mutation,
or transport an arbitrary command.

## Lifecycle

```text
judgment transition away from CURRENT
  -> policy threshold matches
  -> request built and semantic key checked
  -> active equivalent? record deduplication and stop
  -> bridge validates schema, clock, expiry, profile, scope, and bounds
       -> accept  -> execute exact compiled harmless stub -> receipt
       -> refuse  -> terminal typed refusal for this request
       -> narrow  -> return smaller bounds; explicit resubmission required
       -> defer   -> no execution and no expiry extension
```

Escalation lifecycle is orthogonal to the evidence category. A
`CONTRADICTED` judgment remains `CONTRADICTED` after request acceptance and
diagnostic completion until its evidence semantics change lawfully.

## `DiagnosticEscalationRequestV1`

The closed request contains:

| field | meaning |
|---|---|
| `schema_version` | exact supported request version |
| `request_id` | escalation occurrence identity |
| `subject_scope` | exact subject and scope under evaluation |
| `consumer` | reliance class whose bound ceased to hold |
| `trigger_class` | closed reason class such as contradiction or coverage collapse |
| `evidence_window_digest` | identity of the evidence basis that caused the request |
| `policy_generation` | exact consumer reliance-policy law |
| `observation_policy_generation` | exact collection law admitted by that reliance policy |
| `diagnostic_profile` | one predeclared profile identity and version |
| `bounds` | maximum runtime, output bytes, and observation count |
| `clock_id` | receiver/bridge monotonic clock generation for V1 local comparison |
| `created_at_ms` | request creation on that clock |
| `expires_at_ms` | inclusive expiry on that clock |
| `deduplication_key` | stable digest over the equivalent-failure semantics |
| `causal_transition_id` | exact transition away from satisfied reliance |
| `nonclaims` | fixed statements excluding truth, authority, repair, and mutation |

The semantic deduplication transcript is versioned and includes subject scope,
consumer, reliance-policy generation, observation-policy generation, trigger
class, and requested diagnostic profile. It intentionally excludes the request
occurrence ID and creation time. The evidence-window digest remains in the
request even when the semantic key deduplicates a later equivalent window.

V1's monotonic expiry is deliberately local. A bridge with a different clock
generation refuses the request rather than guessing comparability. A future
process or network seam needs an explicit qualified deadline translation; it
must not substitute an unqualified sender wall clock.

## Trigger classes

The initial closed set is:

- `freshness_lost`;
- `coverage_collapse`;
- `observer_disagreement`;
- `contradiction_retained`;
- `subject_bound_violated`;
- `provenance_failed`;
- `transport_blind`; and
- `sequence_discontinuity`.

Adding a class is a schema/policy change, not a free-form label.

## Bounds

`DiagnosticBoundsV1` contains only maxima. The local registry contains an equal
or smaller limit for every profile. The bridge behavior is:

- requested bounds within the registry: may accept;
- requested bounds above the registry: return `narrow` with registry limits;
- a zero, malformed, or unsupported bound: refuse;
- unavailable local capacity: defer without changing expiry; and
- expired request or clock mismatch: refuse before execution.

No bound is interpreted as permission to read outside the compiled profile's
scope.

## Disposition

`EscalationDispositionV1` identifies the request, bridge, decision time, and
one of:

- `accept`: exact profile and bounds admitted for one run;
- `refuse`: typed final reason, no run;
- `narrow`: proposed smaller profile/bounds, no run; or
- `defer`: typed temporary reason, no run and no expiry extension.

An `accept` disposition is diagnostic-execution admission only. It is not
consumer reliance and not Docket/AG authority.

## Local profile registry

The initial registry contains only `local.readonly.summary/v1`. The
implementation is compiled code and performs a deterministic harmless local
summary. It accepts no command string, arguments, environment, path, network
target, credential, or mutation target from the request.

An agent may select this profile when policy already permits it and may explain
why. An agent cannot create another profile or change its implementation or
bounds through the seam.

## `MockDiagnosticReceiptV1`

An accepted stub run emits a versioned receipt containing:

- receipt and run identities;
- exact request, transition, evidence-window, deduplication, subject, consumer,
  reliance-policy, observation-policy, and profile bindings;
- bridge clock identity and start/completion times;
- bounded result entries and result digest;
- observed diagnostic coverage;
- terminal status; and
- fixed nonclaims.

The mock receipt is not labeled as an NQ artifact. A future adapter must return
or reference Constellation NQ's own validated execution artifact and preserve any exact
typed refusal. Schema resemblance is not compatibility.

## Receipt effect on evaluation

The evaluator may record that deeper observation completed and correlate the
result. It may not:

- refresh a pulse's arrival time;
- fill pulse coverage implicitly;
- resolve a contradiction without an explicit resolution record;
- change subject incarnation;
- produce indefinite `CURRENT`; or
- grant execution or mutation authority.

## Refusal preference

Ambiguous scope, unsupported profile, invalid bounds, expired time, clock
mismatch, malformed correlation, or unknown policy generation is refused. A
refusal is preferable to attempting a broader diagnostic.
