# Native filesystem-capacity support for Nightshift

Status: source candidate. Native tests, adapter qualification, installation
and current observation-to-cycle acceptance are pending. The existing
installed load-support adapter remains unknown; this source does not change it.

`pulse-nq-filesystem-support` is a closed support adapter for one enrolled
ext4 filesystem and `nq.host_filesystem_capacity/v1`. The exact NQ source
revision is pinned in Cargo.toml. NQ's native filesystem helper owns machine,
mount and device identity checks and source acquisition. NQ's profile library
owns payload validation and the capacity-pressure law. NQ's protocol API owns
canonicalization of the NQ diagnostic-scope preimage. Monitor's existing
canonicalizer still owns its unchanged query/support and new custody records.
These API calls establish only the scope/payload identity and counter checks
and the capacity law, not full NQ report/framing/admission validation. This
adapter does not copy a detector or open an NQ store.

The support proposition is only whether that exact filesystem's current
native capacity observation agrees with the selected diagnostic's present
or explicitly-absent condition. It says nothing about storage health,
integrity, performance, quota, growth, host/service health or permission to act.

The configuration schema is
`pulse.nq_filesystem_capacity_support_config.v1`. Configuration contains one
exact native scope, its diagnostic scope digest, pinned native profile semantic
identity, a separately accepted adapter realization, declared vantage, and a
separately enrolled Nightshift consumer/authority and public signing key. It
contains no per-slot diagnostic basis or expected condition. A `nightshift:` consumer namespace distinguishes this deployment from
the status consumer; the namespace itself authenticates nobody. The operator
owns the configuration, signing-key custody and resolver selection.

The source-defined commands are:

```text
pulse-nq-filesystem-support produce --config ABSOLUTE_PATH --request ABSOLUTE_PATH --acquisition-id TOKEN
pulse-nq-filesystem-support ingest --config ABSOLUTE_PATH --request ABSOLUTE_PATH --acquisition-id TOKEN
pulse-nq-filesystem-support resolve --config ABSOLUTE_PATH --request ABSOLUTE_PATH
pulse-nq-filesystem-support create-key --path ABSOLUTE_PATH
```

Production acquisition reads the actual enrolled filesystem through the
pinned native helper library. It is explicit, separate from intake and never
triggered by resolution. The caller supplies a unique occurrence token. A
failed or unevaluable observation emits no absence testimony.

The signed envelope binds the exact consumer, subject/scope, native profile,
adapter realization and static enrollment,
diagnostic basis, acquisition identity and observation interval. Intake checks
the signature and recomputes the native condition from the signed counters.
It stamps receiver custody on the same Linux boot clock. Lifetime is bounded
from observation start, never restarted at intake, resolution or replay.
Intake of an identical envelope returns its original receipt; an older/equal
acquisition cannot replace a later current-boot acquisition.

Producer, receiver and operator state directories must already exist as
non-symlink directories with exact mode `02750`. Each is owned by its sole
writer, with a setgid group containing only its intended next readers. The
producer owns the outgoing directory with the receiver's envelope-reader
group; the receiver owns the receipt directory with the resolver's
receipt-reader group. Group access is read/traverse, never write. The
operator-owned configuration directory uses a separate common reader group.
The operator installs static configuration and realization once; no runtime
role or ordinary scheduler rewrites them. A common writable state parent is
not allowed: every ancestor controlling either role directory entry or
accepted record remains outside all runtime writers. Directory ancestry, accepted realization and selected
executable remain outside all runtime writers. Do not substitute one shared
writable UID for this handoff.

Each replacement starts private and incomplete, writes all bytes, verifies
that the new inode has the directory writer UID and inherited reader GID,
sets final mode `0640`, synchronizes it, and only then renames it atomically.
Thus both first publication and every later replacement retain reader access;
permissions on an old inode or default ACL assumptions are not the handoff.
Unsafe directory modes or unexpected writer/group ownership refuse
publication. Signing-key creation is unchanged: an owner-only regular `0600`
file, readable only by the producer among runtime roles. No world read/write
permission or new identity mechanism is used for these custody files.

The deployment serializes acquisition/intake through its existing finite
service and enforces resource/time bounds. Successful work examines fixed
latest files independently of directory history. A failed replacement may
leave its unique temporary file for diagnosis; it never becomes a receipt.

Resolution consumes the existing bounded Nightshift query schema from stdin
and emits the existing qualified-support schema on stdout. Missing receipt
means unknown; a previous boot cannot provide current support. Expiry uses
the conservative source-time bound with a centisecond clock margin. A future
receiver time is blind, and disagreement with the diagnostic is contradictory.
Wrong scope, signature, profile or custody bytes are refused. A valid receipt
for a prior diagnostic basis is unsupported for the new query; it is never
retold as current support. The no-argument resolver form obtains its absolute
configuration from `PULSE_FILESYSTEM_SUPPORT_CONFIG` and this invocation's
canonical request from `PULSE_FILESYSTEM_SUPPORT_REQUEST`, for the existing
Nightshift resolver process contract. Both are required; no embedded-basis or
mutable global latest-request fallback exists. Key creation is explicit and refuses
an existing file; it prints only the public key.
No status publication or historical correspondence record is read as evidence.

This receipt does not fill Nightshift's recurrence records or make an
incomplete cycle healthy. The owning deployment must still supply actual
recurrence evidence and pass an observed native acquisition → intake → cycle
test, retaining missing-receipt and expiry negatives, before current standing
is claimed. No general provider, registry, orchestrator, retired load-profile
bridge or authority delegation is added here.


The realization record

`pulse.nq_filesystem_capacity_adapter_realization.v1` identifies this adapter's
own ELF SHA-256, complete Monitor source commit and source-tree digest, actual
Monitor Cargo.lock digest, actual resolved dependency/unit/feature inventory
digest, fixed upstream NQ commit, qualification receipt digest, and static
configuration digest. `realization_id` hashes that record with only its own ID
field removed. These fields identify records; naming a qualification digest
does not establish acceptance. The independent acceptance owner must examine
the named records and install the accepted record and configuration outside
producer, receiver and resolver write authority. No key or filename supplies
that authority by itself.

`configuration_digest` hashes static configuration with `realization` removed. This avoids a digest cycle while pinning the
consumer, authority, subject, scope, vantage, declared profile, key and paths.
The signed `enrollment_id` hashes the entire static configuration, so it
also binds the selected realization and qualification. The diagnostic basis remains separately signed. Replacing the
per-cycle basis does not give an older receipt new relevance: it is Unsupported
for the new query. Replacing static enrollment or realization is refused.

Enrollment is an ordinary operator operation: explicitly create the producer key
with `create-key` as the producer, retain its private `0600` file there, and use
only the printed public key when authoring the static configuration. Install
configuration and its matching separately accepted realization under operator
custody. The unpublished per-slot `prepare` command was removed; old candidate
configuration containing `expected_diagnostic` is refused, not migrated by a
runtime role. There are no released consumers requiring that old shape.

Every invocation supplies the exact immutable canonical Nightshift request.
The producer, receiver and resolver independently decode its bounded canonical
bytes, verify request/inputs identities and the NQ-owned artifact preimage,
require one delivered native filesystem-capacity diagnostic matching the
accepted profile semantic identity, subject and scope, and derive the expected
condition through the existing diagnostic outcome classifier. Policy subject
and diagnostic subject must match. This validates only the adapter's binding;
Nightshift still owns full request, policy, recurrence and diagnostic admission.
A self-consistent request is not enrollment or authority.

The request must remain at its per-slot immutable absolute path through all
three roles and the existing Nightshift invocation. The caller supplies that
path in `--request` to producer/intake and in the per-invocation resolver
environment, alongside `PULSE_FILESYSTEM_SUPPORT_CONFIG`. Query stdin and
qualified-support stdout retain their existing schemas. Resolver checks the
query's observation ID, diagnostic inputs, exact artifact, subject and scope
against that request. Query alone lacks the expected condition. A different
basis requires a different immutable request, never an accepted-config edit.
Interleaved requests remain independent; request A/query B is refused, while a
valid B query with an old A receipt is Unsupported. No extra daemon or
privileged per-slot preparation is introduced.

Produce, intake and resolve all hash
Linux `/proc/self/exe`, compare the embedded source commit, and compare the
Monitor lock digest embedded from the actual build input. Missing build source
identity and substituted ELF/source/lock are refused before reliance. The
realization record is enrolled by the operator after qualification; the adapter
does not discover, create or approve that record. Build `--build-info` remains
a read-only declaration, independently checked against source/build evidence.

This is a separately realized support adapter. It is not an NQ-admitted helper
or evaluator process. It borrows none of NQ's startup/runtime admission,
governed replay, custody or currentness guarantees. `profile_semantic_id`
references declared diagnostic meaning; it does not establish equality of the
adapter's externally resolved implementation to a different NQ realization.
No NQ evaluator executable digest is used as this adapter's identity.

Qualification is bounded to the recorded native OS, kernel, architecture,
loader, libc and other actual runtime dependency identities. Retain those
identities in the existing qualification/deployment occurrence record. The
own-ELF/source/lock checks do not seal dynamically loaded libc or kernel bytes.
A later change or unknown runtime identity invalidates that qualification's
applicability: withdraw resolver selection or refuse support through the
existing deployment preflight until the exact runtime is reviewed and
qualified again. Do not keep claiming Current by treating the old record as a
general compatibility guarantee. No new runtime supervisor is introduced here.

Source vectors and native readiness

`artifacts/nightshift-filesystem-support-v1/conformance.json` pins exact shared
configuration, realization, NQ scope-preimage, two distinct diagnostic request
contexts and matching Nightshift queries, and qualified-support bytes. Monitor's Rust tests and Cartography's renderer/request tests
must consume these same bytes/digests, including reidentified wrong-scope and
wrong-basis refusals. They are synthetic binding fixtures, never enrolled configuration, complete
accepted Nightshift cycle requests, qualification receipts or current testimony.
The source decoder intentionally does not claim full Nightshift validation;
qualification uses actual complete canonical requests from its owning caller. The capacity cases
preserve e721's source-owned reserved-block denominator, inclusive threshold,
zero-usable refusal and identity/counter bounds. NQ canonicalization cases run
through `nq_protocol` in the adapter's native Rust tests. The light Python check
only verifies exact ASCII/safe-integer wire fixture bytes and cross-bindings;
it is not a general JCS implementation or native conformance result.

The retired original NQ builder's rlibs are unavailable. Historical compiler
JSON and checksums identify former artifacts; they do not supply an executable
oracle. These vectors are source-based conformance evidence for a new narrow
realization. A separately admitted law-only reference build, if required by the
acceptance owner, is a new identified reference, never recovered original NQ
execution. No such build is implied or launched by this source.

Native engineering on the preceding source `b0ba833` resolved the actual
Monitor lock `af7b991a944545781ceee44f24b16356d35827585ca9384379cf2f3024a11bc5`,
passed the offline all-target check and 14 library tests. Root committed that
lock as `0b7f7b3b44a5d5fcf7e41a1e6c7c722d4744c95b`. Those results do not execute
this static-enrollment/request correction or establish live integration.
The current source retains that exact lock. New Rust and principal cases are
tests-ready, not executed PASS.
The next native occurrence must follow this bounded recipe:

1. Obtain Root's SDK and storage GO. Use a fresh source/output root and fresh
   target directories, the admitted 12 GiB aggregate forecast and 60 GiB floor;
   preserve qualified binaries, package evidence and prior terminal records.
   No Crow Cargo and no reuse of retired targets or assumed rlibs.
2. Provide exact e721 git/source custody without pushing it: an admitted exact
   git mirror/bundle or checked source export with recorded hashes and explicit
   Cargo source mapping. No credentials in that source transfer. The original
   URL/revision declaration and actual resolved source must both be recorded.
   Stop if offline dependencies are unavailable; do not silently fetch, relax
   the pin, alter NQ manifests/lock or substitute another commit.
3. On the admitted SDK, verify the committed actual Monitor lock unchanged and
   retain `cargo metadata --locked --offline --format-version=1` for the new
   frozen source in its distinct source/output root. Do not silently resolve a
   different lock; return any unavailable dependency or lock mismatch to Root. Preserve package versions,
   registry checksums, git revisions, dependency edges, enabled features and
   proc-macro/build units. A lock diff alone does not prove feature equality.
4. Root freezes a truthful complete Monitor source commit including that lock.
   Use Rust 1.94 and the exact target; record `rustc -vV`, OS/kernel/architecture,
   loader/libc identities and build environment without credentials. A WIP
   source capsule may be tested under its own hashes with build source unset;
   never label it as the earlier committed HEAD or as a qualified producer.
5. Use separate test and production targets. Run `cargo test --locked --offline
   -p pulse-nq-filesystem-support --lib` for these source cases and relevant
   existing load-support/correspondence suites. Run the existing format/lint
   checks within admission. Preserve real failures; the source-only preparation
   has no native RED or GREEN result. Keep broad test-feature builds separate
   from the selected production artifact.
6. Set `MONITOR_SOURCE_COMMIT` to the complete frozen source and
   `MONITOR_BUILD_IDENTITY` to the occurrence identity. Build only the selected
   adapter with `cargo build --locked --offline --release
   -p pulse-nq-filesystem-support --bin pulse-nq-filesystem-support
   --message-format=json` in its fresh production target. Retain actual compiler
   artifact records and the exact CLI fingerprint-selected NQ helper/profile/
   protocol dependency edges and unit features. Before artifact-specific tests,
   freeze the selected adapter as an ordinary independent copy outside Cargo
   outputs; the adapter-only selected set is this one ELF, not a relabeled
   Host Posture cohort. All tests and later selection use that exact frozen
   path. Test builds use their separate target; no selected production rebuild
   follows. Record the ELF SHA and embedded
   build identity, source/lock/configuration/qualification digests. This is its
   own native realization, not whole-NQ closure equivalence. Do not overwrite
   any previously qualified Host Posture ELF with an all-feature rebuild.
7. Under the existing finite unit and distinct real deployment principals,
   qualify actual enrolled-ext4 observation, separate signed production,
   receiver intake and the actual Nightshift resolver. Check missing intake,
   source-time expiry, previous boot, future clock, replay without renewal,
   equal/older acquisition, wrong signature/consumer/scope/profile/config/ELF,
   zero/failed observation, contradiction and changed diagnostic basis. Verify
   producer cannot write receiver custody and resolver cannot acquire or write
   custody; accepted records/configuration stay outside those writers.
8. Record acceptance independently with exact evidence identities and runtime
   scope before installing/selecting this realization for present reliance.
   Candidate test configuration is not acceptance. Actual Nightshift recurrence
   `record_missing` remains a separate unresolved input even if FS support is
   Current. The FS receipt cannot complete a cycle or authorize an effect.


The ordinary crate integration target `cli_custody` runs real CLI processes
against real temporary configuration/outgoing/receipt files. Its signed
substitution fixtures exercise custody/currentness without claiming native
acquisition or qualification. Run it with a truthful committed build identity;
`PULSE_FS_TEST_BINARY` may select the frozen production ELF for the same tests.
These operator-context cases are explicitly ignored by ordinary unidentified
development builds, following the existing native-projection test pattern.
Native qualification must execute all four with
`cargo test --locked --offline -p pulse-nq-filesystem-support --test cli_custody
-- --ignored --test-threads=1`; zero executed cases is not a pass. The existing
`packaging/host-posture-qualify.sh` includes that required command against the
staged production adapter when qualifying a new full helper package. Do not
invoke the full helper qualifier merely to qualify this separately selected
adapter.
The SDK preflight must record boot age above 300010 ms for deterministic expired
receipt fixtures; a missing precondition is a failure, never a silent skip.
Cases preserve missing/Current, replay byte identity, contradiction, expiry,
previous boot, bad signature, equal acquisition, changed-basis Unsupported and
stale-query refusal.

For the meaningful realization regression, use a distinct temporary
counterfactual source/output with all new APIs and tests intact. Remove only
the final `self.validate_running(...)` call in
`AdapterRealizationV1::validate_current_process`, returning `Ok(())` there.
Keep schema/record/signature/enrollment checks intact. Identify the
counterfactual with its own complete temporary source commit and build
declaration; never label patched source as the selected candidate commit. Run only
`same_declared_semantics_wrong_runtime_realization_cannot_establish_current`
with `--ignored` against that counterfactual CLI: it must compile and fail because a reidentified
wrong ELF/source/lock record with the same profile semantic ID establishes
Current. Crate absence, unresolved dependency, compile failure or timeout is
not behavioral RED. Run the exact same test against final source/ELF for GREEN,
then retain both source diff and command/terminal identities. Do not mutate the
selected producer or its result to create the counterfactual.

For a full helper package, the owning qualifier now performs its final selected
production build first, freezes all four actual compiler-selected executables
outside Cargo, and checks the whole frozen cohort throughout isolated tests.
The packager must consume that same `OUT/frozen-bin`; see `packaging/README.md`.
A later shared production rebuild is removed from this lifecycle, not repaired
by adding only an FS checksum. Earlier HP feature-unification drift and the
original FS source HOLD remain preserved evidence.

Run the admitted native commands under one existing SDK durable unit, with its
ordinary recovery checkpoint and original unit/InvocationID. Record exact
source/candidate-lock/command/feature and OS/runtime identities before launch,
separate test and selected artifact identities, durable logs and output root.
Expected terminal evidence is that same unit's native exit status, MainPID 0,
empty cgroup, explicit test/qualifier/packager result records and hashed
artifacts. A notice is not acceptance. Supervisor loss reconciles this producer
and its terminal records; it never authorizes a duplicate launch. The existing
packager/qualifier may assemble a later reviewed helper cohort after its own
required gates; no intermediate archive or installation is implied here.


Distinct-principal native case

On the admitted disposable qualification VM, the operator must enroll three
distinct non-root UIDs and the narrow envelope-reader, receipt-reader and common
configuration-reader groups. No account or group is created by the test. For a
fresh campaign-owned state root, establish operator-owned `02750` ancestry,
producer-owned `02750` outgoing custody with its next-reader GID, receiver-owned
`02750` receipt custody with its next-reader GID, and operator-owned `0640`
configuration outside both writer directories. The key remains producer-owned
`0600`; the frozen executable has no write bits and is owned outside all three
runtime roles. The operator's accepted realization/configuration pins must
already describe these exact paths, source and selected ELF. Key creation/public enrollment, accepted record installation and group setup
are explicit operator operations, never scheduler or resolver work. Keep
configuration/realization and both immutable request/query pairs outside all
runtime writers, with operator-controlled ancestry. The real principal case
checks parent replacement authority as well as child file write permission.

Run this ordinary qualification case on that VM, not Crow:

```text
python3 -B packaging/test_fs_principal_handoff.py FROZEN_FS_ELF CONFIG REALIZATION REQUEST_A QUERY_A REQUEST_B QUERY_B FRESH_PROOF_ROOT PRODUCER RECEIVER RESOLVER
```

It checks real `runuser` UIDs and intended group membership before actual
acquisition. Two distinct real canonical request bases use the same immutable
configuration and realization. An ordinary resolver/caller handles both
without secret access or accepted-record writes. Request B/query B against
receipt A must be Unsupported; cross-paired requests/queries refuse. Both
producer→receiver→resolver turns then read newly replaced `0640` inodes through
the intended groups; accepted record and request file hashes remain identical. Reader-only roles cannot read the
key; producer cannot create receiver custody; receiver cannot write outgoing;
resolver cannot write either directory, change configuration or acquire/sign.
It also temporarily changes only proof-owned directory modes to exercise
publication refusals, restores them in `finally`, and requires refusal to leave
receiver custody unchanged. It leaves scoped evidence for Root rather than
cleaning another consumer's files. This is a required distinct-real-UID case;
same-UID CLI tests or the old Cartography `User=nq` unit are not its proof.
Failure to provision these exact preconditions is apparatus-not-ready, not a
native product pass. Native execution of this case remains unrun at source
freeze, and it does not close Nightshift recurrence or installed consumer
acceptance.


Before GREEN, reproduce the old custody defect against a separately identified
old-source ELF and its own matching realization. Freeze old source
`0b7f7b3b44a5d5fcf7e41a1e6c7c722d4744c95b`, old config shape and actual watcher
binding in a distinct proof root. The old producer key is private and the
ordinary caller can read the actual request, watcher and old realization. Run:

```text
python3 -B packaging/test_fs_principal_handoff.py --old-prepare OLD_FS_ELF REQUEST_B NQ_CONFIG INSTANCE OLD_STATE OLD_REALIZATION ORDINARY_CALLER
```

That reproduction must reach the old private-key read and fail with real
permission denial, leaving configuration unchanged; usage, unknown command,
missing file, invalid realization or compilation failure is not behavioral RED.
The test reports its exact old argv/UID/error before the final expected failure.
Then run the two-basis case above against the new final frozen ELF for GREEN.
This is a bounded regression in the existing qualification test, not a new
harness or acceptance schema. Both executions remain pending separate Root GO.
The earlier 14-test engineering PASS is unchanged and provides no live
preparation/custody proof.
