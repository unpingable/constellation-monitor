# Bounded published Kubernetes observation v1

Monitor owns this ordinary read-only acquisition adapter in
`scripts/kubernetes_observation.py`. It consumes Kubernetes' published API and
three fixed application routes. It is not a Kubernetes monitoring service,
new evidence store, NQ diagnostic profile, Pulse current-support adapter or
cluster mutation executor. Workbench may present these owned observations;
a qualification campaign supplies disposable installation and independent
verification separately.

## Installed interface and trust admission

```sh
python3 /installed/Monitor/scripts/kubernetes_observation.py --config /installed/reader.json
python3 /installed/Monitor/scripts/kubernetes_observation.py --config /installed/reader.json --declarations
```

The closed `monitor.kubernetes-observation-settings/v1` configuration is an
explicitly admitted installation input. HTTP clients and rendered subject text
cannot supply it. There are no commands, mutation verbs, arbitrary routes,
expected outcomes or oracle inputs.

```json
{
  "schema": "monitor.kubernetes-observation-settings/v1",
  "project": "qualification-app",
  "api_url": "https://127.0.0.1:26443",
  "ca_file": "/installed/cluster-ca.pem",
  "token_file": "/private/reader-token",
  "namespace": "qualification-123",
  "namespace_uid": "exact-admitted-namespace-uid",
  "node_names": ["qualified-server", "qualified-agent-a", "qualified-agent-b"],
  "app_url": "http://127.0.0.1:28080",
  "timeout_ms": 5000,
  "max_response_bytes": 2097152
}
```

API origin must be HTTPS with a port and no path, credentials, query or
fragment. TLS CA and hostname verification remain enabled. The application
origin is explicitly admitted HTTP/HTTPS or null; routes are exactly
`/readyz`, `/version`, `/semantic`. Redirects are returned as their original
status and never followed. The reader credential is loaded from an owner-only
regular file using `O_NOFOLLOW`, an exact descriptor, bounded length and
before/after metadata checks. It must belong to the invoking account. It is
sent only to the admitted Kubernetes origin, never application probes.

Installation should use a dedicated read-only ServiceAccount. Its namespace
Role needs get/list pods, services, deployments and EndpointSlices. Exact
namespace and registered node reads require corresponding get permission;
node acquisition uses individual exact-name paths, not cluster-wide lists.
No Secret/ConfigMap, logs, exec, watch or write operations exist. API RBAC
remains an independent operational boundary: supplying an administrator token
would not make this program a least-authority deployment.

The CLI enforces at most five seconds using its process-local deadline;
individual reads also consume the remaining deadline. Total received bodies
are at most 2 MiB, each at most 256 KiB. Lists inspect at most 64 entries and
retain explicit PARTIAL when a continuation token or larger list exists.
There is no background recurrence, cache, durable worker or automatic retry.
The installed acquisition supervisor should retain its own finite invocation
and custody records.

## Existing observation contract

The producer emits `project.ops.status/v1`, matching the existing generic
[project concern contract](project-concern-contract.md). `--declarations`
emits matching `project.concerns/v1` JSON; a repository can retain equivalent
TOML under `.ops/concerns.toml` and the normal separately admitted
`project.observation-binding/v1` argv binding. Monitor's generic collector
still owns structural correspondence and acquisition provenance. This Python
adapter does not impersonate that generic collector's inventory result.

Nine concern suffixes are `namespace`, `nodes`, `pods`, `deployments`,
`services`, `endpointslices`, `readiness`, `version`, `semantic`. Each id is
`PROJECT.kubernetes.SUFFIX`, question is
`monitor.kubernetes.SUFFIX.published/v1`, and profile is
`monitor.kubernetes.published/v1`. Description, required flag and identities
are identical between declaration and observation.

Acquisition states are **ACQUIRED**, **PARTIAL**, **UNAVAILABLE**, never an
aggregate application health verdict. UNAVAILABLE has
`observation_present=false`, `observed_at=null`; generic inventory therefore
records a missing required observation. This differs from an explicit
project-owned UNKNOWN observation. Failure to establish the exact namespace
UID initially or after collection refuses the whole acquisition (exit 2,
`monitor.kubernetes-read-refusal/v1`), rather than joining different namespace
generations. No fallback returns a previous successful envelope.

## Facts, identity and time

The scope in `extensions` retains the exact API origin, namespace name/UID,
registered node names and application vantage. A namespace is not a host;
service/deployment logical names are distinct from Kubernetes object UIDs,
resourceVersions, deployment generations, pod UIDs/image IDs and reported node
boot/machine identities. Node information is Kubernetes testimony, not
independent kernel/hypervisor attestation. Containerized k3d nodes share a host
kernel; a node container restart is not a qualified VM boot transition.

The allow-list retains native metadata identity, deployment replica and
observed-generation counters, pod phase/readiness/restarts/images and owner
references, node Ready conditions/version/boot assertions, Service selectors
and ports, and EndpointSlice target/condition relations. Native heartbeat and
transition timestamps remain native strings. ResourceVersion is an opaque
native version, not a wall-clock observation timestamp.

`observed_at` means local acquisition completion; `facts.acquisition` retains
start/end/duration and explicitly `snapshot_atomic=false`. Sequential resource
reads are not a transactional cluster snapshot. The namespace UID recheck
fences that named scope substitution only; it cannot establish arbitrary
cross-resource atomicity or controller freshness. `valid_for_seconds=null`
and `no_health_or_current_support_claim=true` deliberately assert **no**
positive Pulse current support. A consumer may separately refuse old retained
acquisition bytes under a read-recency rule, but may not refresh native
controller timestamps or describe that rule as general Kubernetes health.

A Ready pod and a successful `/readyz` response are distinct from application
`/semantic` behavior. Probe facts retain HTTP status, body SHA-256 and only
short structured `role`, `version`, boolean `ok`/`dependency_ok`, nonnegative
integer `counter`. Arbitrary response text, credentials, container environment,
annotations, configuration, logs and exception text are omitted. Native source
body hashes identify consumed responses without retaining their raw bodies.
Unknown bounded native enum values remain inspectable; obvious credential-like
string prefixes are not emitted. This is an allow-list, not a claim that all
possible application-authored text can be classified perfectly.

## Qualification and formalization consideration

Source basis: selected Monitor `cdd99eb5ccd743ccd01ac4f76f1301cdb37f368e`, plus
this dedicated `lane/monitor-kubernetes-observation-v1` result. Decision owner:
primary Workbench integrating owner. Proposition: installed finite GET-only
acquisition preserves exact namespace correspondence, bounded native facts,
readiness/semantic separation and acquisition/time distinctions, without
granted effects or hidden expected outcomes. The existing shared envelope
retains its established schema; facts are owned by this producer. Practical
boundary tests, actual loopback HTTP qualification and downstream real-cluster
acceptance are sufficient for this bounded acquisition adapter. No model of
Kubernetes consistency, global truth or independent support is claimed.

Counterexamples outside the claim include an incorrect control plane, an
administrator token installed instead of the scoped principal, concurrent
resource generation changes within the non-atomic snapshot, stale controller
status reported by a reachable API, or an application publishing misleading
semantic testimony. The external qualification oracle must independently check
selected actual cases. Operator diagnosis and oracle verdict remain separate.

Run focused tests with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_kubernetes_observation.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_nq_live_http_read.py
```

No Rust source or dependency changes; no new Rust compilation/whole-workspace
claim is made for this Python-only change. Full installed-cluster qualification
belongs to the separately admitted Tier-5 campaign and is not established by
these source tests.

References: [Kubernetes EndpointSlice](https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/),
[RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/),
[K3s requirements](https://docs.k3s.io/installation/requirements),
[k3d cluster controls](https://k3d.io/stable/usage/commands/k3d_cluster_create/).
