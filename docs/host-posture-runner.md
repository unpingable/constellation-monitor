# Installed filesystem-capacity host-posture runner

`constellation-host-posture` is the narrow installed composition for
`nq.host_filesystem_capacity.pressure/v1`. It coordinates existing NQ,
correspondence, Pulse, consequence-adapter, projection and publication APIs;
it defines no new diagnostic threshold, consequence rule or general scheduler.

The selected NQ watcher belongs exclusively to this service. Run it in a
newly initialized store with `nqd` inactive for that watcher. The service owns
the local-successor acquisition cadence; a second scheduler must not run the
same obligation. NQ remains responsible for invoking the packaged
`nq-host-resource-helper` under its admitted cross-UID boundary. The installed
service unit therefore needs the same narrowly reviewed helper-launch
capability envelope as the released NQ unit; the runner does not bypass NQ or
invoke the helper directly.

Start authoring with:

```sh
constellation-host-posture example-config > host-posture.toml
```

Release builds embed the clean source commit/tree, exact toolchain/target,
profile/features and `Cargo.lock` digest supplied by the clean-build producer.
`--build-info` emits that record without loading configuration. If a build
omits a field, the probe and rendered example say `unavailable`, and offline
qualification refuses it rather than inventing an identity. Preparation also
requires the configured source/build record to equal the embedded record.

Installation renders that example to a root-owned configuration, creates a
dedicated non-root service identity and private state/publication directories,
and installs the exact runner, NQ executable/configuration, sealed profile and
qualification package outside that identity's write authority. `run` and
`preflight` verify the effective uid, file ownership/modes and ancestors. The
offline `enroll` and `prepare-qualification` commands may instead be run by the
governance/install principal.

Preflight and run take the same stable-file writer lock and require private,
service-owned `intent` and `audit` directories. The configured projection
cadence plus the reactor command-response timeout must meet an explicit
withdrawal-publication tolerance no greater than five seconds for this
installed profile. The reactor admits no deliberate deadline delay and uses
file-synced journal durability. Publication is exactly `state_root/status`, so
the same stable writer lock covers journal, occurrence and publication state.

The finite setup sequence is:

1. Initialize and admit the native NQ filesystem-capacity watcher and retain
   its first ordinary `nq.diagnostic_execution.v2` artifact.
2. `enroll CONFIG INITIAL_ARTIFACT` copies NQ-owned semantic identities and
   hashes the exact installed NQ executable/configuration into the existing
   correspondence profile schema.
3. Supply canonical retained corpus/results plus clean source/build identities
   in the qualification section. `prepare-qualification CONFIG NEW_DIRECTORY`
   executes no command and preserves the recorded outcomes while creating the
   existing manifest/report/certificate/acceptance objects.
4. Install that directory read-only, run `preflight CONFIG` as the service
   identity, then start `run CONFIG`.

`run` never creates or accepts a certificate. It remeasures the installed
executable and active semantic values against the separately retained accepted
package and requires `QualifiedAndMatched`. Every restart uses a fresh process
occurrence and activation, recovers only journal history, and starts with no
support or deadlines. The first publication is unknown. Acquisition runs on a
separate bounded worker so periodic projection continues while NQ is blocked;
silence therefore becomes unknown when Pulse support expires. Clean stop also
withdraws support and publishes unknown. Journal damage, exhausted bounds,
package mismatch, pathname custody failure and a concurrent writer fail closed.
The exact loaded configuration digest and fresh process identities are emitted
at preflight/startup. Journal bytes/records are bounded by the owner journal;
the persistent intent/audit and immutable publication stores have aggregate
entry ceilings that survive restart and fail closed when exhausted. Retention
or rotation is an explicit governed installation operation, not an automatic
runner cleanup policy.

The example's 2,048 occurrences at a 60-second cadence are a bounded
qualification profile (about 34 hours), not a sustained-production retention
claim. A production retention envelope requires an explicit owner-approved
capacity and rotation/disposition procedure before deployment.
