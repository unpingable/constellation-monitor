# NQ host-load-pressure / Pulse correspondence v1 qualification

Status: **Candidate pending independent review**

This receipt records one disposable, non-production qualification of
`constellation.nq_host_load_pressure_correspondence.v1` and
`constellation.status_consequence.nq_host_load_pressure.v1`. It establishes a
narrow path for NQ's load-pressure condition only. It does not establish
general host health, a remote protocol, production monitoring, public
publication, or authority to change a monitored system.

## Pinned product inputs

| Input | Identity |
|---|---|
| Constellation Monitor candidate | commit `b23ee3139cf1a77da8e1ad00bbc547f6412daba2`, tree `f8a666e95f909a3f652c43d2ac010e9550e171eb` |
| Pulse live-present-support baseline | commit `53bce039afae84a5f9bedbefdeecfe186c3a0080`, tree `6ee1fceafa7052852901434a9f106214c27e9b01` |
| NQ | commit `6190218f1da817d6900d1dbc551d52818673154e`, tree `3d88e212e211d4aa9e6302d1da647d30f967325b` |
| NQ qualification executable | SHA-256 `cf56cd9064e1eaaaf18050e62f2531204db2ee7b8f7239ed6b78a9c5d29fc5cc` |
| Real projection harness | SHA-256 `bc719976cba8d4b3e7e18323eca9f267455be63f9585597aa1005fa7adcf5c6b` |
| Shared-vector tests | SHA-256 `34e48314be8a6a023c5d405f8f09eb56e99572bf05c2c1d852c7548b6005c52c` |

The NQ executable was built from the pinned clean source in a network-disabled
Debian 12 builder, in the optimized release profile with debug assertions
retained. That fixture-only setting permits the NQ supervisor and synthetic
helper to run as the same unprivileged UID. It does not qualify same-identity
operation as a production deployment pattern.

## Disposable environment and permission boundary

The finite producer ran in a Debian 12 QEMU guest under TCG with a restricted
user network and loopback-only SSH forwarding for installation and evidence
retrieval. It contacted no production system or public route.

The embedding and helper ran as UID/GID 1201. The exact NQ executable,
configuration, profile sealer, and projection harness were owned by root and
were mode `0555` or `0444`. The finite producer refused to start if its
principal could write any of them. NQ state, occurrence custody, and local
publication roots were fresh disposable paths owned by UID 1201.

## Positive results

One rich source path produced each source-native state through actual NQ
evaluation, deliberate NQ/Pulse co-production, live Pulse support admission,
the condition consequence adapter, deterministic projection, disclosure
reduction, rendering, and atomic local publication:

| NQ state | Condition projection | Public artifact | Operator artifact |
|---|---|---|---|
| `present` | `degraded` | `sha256:a34a8f1a9885484a3eefd623f6edd94124f4f8cdbcce4b25bbda89eb505dc089` | `sha256:c88352557e9634b94dab36c98872e5eeacaab9ad452f5c1e952b7b5ff9dad9e1` |
| `explicitly_absent` | condition-scoped `healthy` | `sha256:a32f59d9a161dfd840b22d3022b3d2bca4032878d33f858ab0a9db04195b9cbd` | `sha256:b1a1486c3da5ace0fa65a998f33182f24f3bf8d6d805ae90abbe6c69230ad917` |
| `cannot_evaluate` | `unknown` | `sha256:01609af3b5ad73759a273ee28b394be077ebcf13d4c7596d3b26b45f0ff4eeb7` | `sha256:63d844e826768cbaef8e57fda028a93081ae27d954851f2dd6c8d9415551bff7` |

`healthy` above means only that this qualified load-pressure condition was
explicitly absent. The public leaf adapter requires the condition label,
reason field, and exact safe reason table carrying that non-claim. Relabeling
the fact as general host health or omitting the non-claim is refused.

The real harness passed three of three state runs. Twelve reactor cases,
seven consequence/projection cases, and two shared-vector tests passed in the
guest. The full workspace passed format checking, strict all-target/all-feature
clippy, and all-target/all-feature tests before the guest run.

## Expiry, restart, and response loss

The latest positive artifact expired at `1790233271000` ms. Before restart,
the guest time was already `1790233300376` ms. After a graceful stop and
restart of the same overlay, the checker:

- found no NQ acquisition process;
- verified every pre-restart evidence-manifest entry unchanged;
- validated all six retained artifacts; and
- rendered every public and operator artifact as `Status unavailable` at
  `1790233477545` ms.

No retained record recreated a process-local timing anchor or refreshed Pulse
support.

A separate qualification case lost the original command response after NQ
had committed `provider_intake_completed`. Exact read-only replay recovered
the same NQ artifact. Because the embedding process and its monotonic anchor
had ended, the correspondence was not resumed, no Pulse frame was delivered,
and no projection was published. This is the intended recovery boundary, not
permission to submit a replacement acquisition.

## Evidence custody

The frozen successful archives are:

- pre-restart: SHA-256
  `9607a71a20a18abf7286685f18c9daeb5c8c3c984954b5f181e59837f89a8ff4`;
- post-restart: SHA-256
  `7451c1f0a2006f97f19b8d9d79e1f6f65aec89bc8d206e363d1614c9933e49c0`.

They are retained in private campaign custody because they contain local
qualification paths and detailed records. The identities above allow review
without making those campaign archives part of the public product tree.

## Deliberate limits

- The observed subject and helper data were synthetic and disposable.
- The qualification used one process for correspondence production and Pulse
  currentness; it does not qualify a remote evidence protocol.
- Publication was local filesystem publication only. No cloud, DNS, public
  route, notification destination, or production consumer changed.
- Historical audit verification checks byte-exact consistency but cannot
  reconstruct `VerifiedCorrespondenceV1` or current support.
- An independently acquired legacy NQ record cannot be promoted into this
  contract by matching names, times, or semantic similarity.
