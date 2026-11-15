# Host-posture executable identity

The candidate source recipe selects four native executables:
`constellation-host-posture`, `constellation-status`, `pulse-nq-load-support`
and `pulse-nq-filesystem-support`, plus three role symlinks to load support.
The new filesystem adapter remains unqualified until its separate source,
native realization and deployment gates pass; this source does not change an
already installed package or carry an old acceptance forward.

`constellation-status`, `pulse-nq-load-support` (including its role names),
and `pulse-nq-filesystem-support`
accept sole `--build-info`, `--version` and `-V` before configuration, stdin,
state or Linux source acquisition. Metadata schema
`constellation.host_posture_helper.build_info.v1` reports component, version,
source commit, builder ID, compiler, target and debug-assertions flag. Source
and build declarations use `MONITOR_SOURCE_COMMIT` (40 lowercase hex digits)
and `MONITOR_BUILD_IDENTITY` (1–256 printable ASCII bytes without spaces).
Absent development declarations are null; malformed explicit declarations
fail compilation. Runtime environment variables cannot replace compiled values.

The main host-posture executable keeps its existing
`constellation.host_posture.build_info.v1` structure and stamp inputs, including
source archive and Cargo.lock digests, compiler, target, profile and feature set.
Its enrollment and qualification records remain byte-specific. Rebuilding does
not carry an old qualification verdict forward or authorize re-enrollment.

Before compiling a release cohort, set both `MONITOR_*` declarations and the
existing `CONSTELLATION_HOST_POSTURE_*` stamp variables from the same exact
source archive, Cargo.lock and compiler. Assembly requires an identical source,
compiler, target, release/debug profile, crate version and production feature
set `[]` across the main stamp and helpers. It probes only staged copies and
records before/after SHA-256 values. All three relative role symlinks are checked
and probed under their invoked names. The receipt is embedded under
`/usr/share/doc/constellation-host-posture/build-identity.json` and emitted as
an identical `.build-identity.json` sidecar beside the Debian package.

The receipt schema is `constellation.host_posture_helper.package_build_identity.v1`.
This records builder declarations and exact packaged bytes under exclusive
staging custody. It grants no action authority and does not establish operational
qualification. `QUAL_INPUT_DIR` remains optional and must contain results from
the actual check commands; this change does not fabricate or relabel them.


Final production selection and packaging

The qualifier interface remains:

```text
CARGO_NET_OFFLINE=true packaging/host-posture-qualify.sh WORK BIN OUT SOURCE_COMMIT
```

`BIN` identifies the HP executable emitted by the qualifier's owning final
production build, normally the selected production target's
`release/constellation-host-posture`. The qualifier records that build first
with actual Cargo compiler-artifact JSON. All four selected executable origins
must occur in that one successful build and match the expected HP input; an
arbitrary prebuilt directory or common source stamp is not build provenance.
The selected artifact/profile/features and original paths are retained in
`OUT/frozen-cohort.json`, alongside the existing per-executable build-identity
record and hashes of production argv/stdout. Individually built mixed inputs
are not supported by this path without their own separately accepted origins.

The qualifier copies ordinary executable files (never hard links) into new
`OUT/frozen-bin`, outside the production Cargo target, creates the existing
relative aliases, and freezes the directory/files as `0555`. Existing run, frozen-cohort or result output
refuses before another production writer; reconcile the original producer
rather than replacing its records. Source/feature checks run
with `CARGO_TARGET_DIR=OUT/test-target`. Filesystem CLI tests explicitly select
`PULSE_FS_TEST_BINARY=OUT/frozen-bin/pulse-nq-filesystem-support`. Every check
is followed by whole-cohort identity verification. No production build follows
selection or qualification. Frozen custody stays exclusive; read-only mode is
not a claim that an owner can never chmod a file, and any selected member's
substitution refuses even if HP is unchanged.

After successful qualification, the owning packaging call is:

```text
QUAL_INPUT_DIR=OUT packaging/build-deb.sh VERSION ARCH OUT/frozen-bin PACKAGE_OUT
```

With `QUAL_INPUT_DIR`, the builder requires the same frozen `BIN_DIR`, checks
all selected hashes before/after staging, and verifies the actual Debian
payload against those same frozen identities. It preserves the canonical
corpus/results schemas and embeds the frozen provenance receipt with the real
check records. `QUAL_INPUT_DIR` remains optional for ordinary unqualified
assembly; omitting it does not supply qualification. The qualifier's canonical
results retain actual reordered argv, sequence, stream digests, exits and
observed counts; exact source case passes are read rather than invented.

The old constraint of rebuilding shared selected production outputs after
qualification was dropped because both prior HP feature drift and the frozen
FS source gap arose from it. Preserved old failures are not rerun or relabeled.
The new packaging tool/source identity must be recorded in its own freeze.
`test_host_posture_qualification.py` uses bounded Cargo/compiler/build-info
stand-ins to reproduce the old late-writer defect and exercise the real shell,
identity helper and packager. It is apparatus evidence, never a Rust/native
qualification result. The distinct-real-UID filesystem handoff case and its
native/currentness limits are documented in
`docs/nightshift-filesystem-support-v1.md`.


The final selected FS entry retains `production_dependency_inventory` in
`frozen-cohort.json`. It preserves the complete ordered successful public
Cargo JSON stream of the owning four-helper release build, including every
compiler-artifact and build-script record, actual per-record features,
package/version identifiers, targets and profiles. It also binds the actual
argv/raw stream digests, compiler/source/lock inputs, and one unique selected
record plus exact ELF hash for every frozen helper. This is a cohort superset
inventory. It does not claim minimal FS dependency reachability, feature
unification analysis or NQ realization equivalence. The private fingerprint
parser and its older minimal-graph claim are withdrawn; the original ambiguity
FAIL and partial frozen files remain unqualified evidence.

The existing tool exposes:

```text
python3 packaging/frozen-helper-cohort.py inventory CARGO_JSON ARGV_JSON PRODUCTION_TARGET OUTPUT
```

`inventory_preimage` and `verify_inventory` own the shared digest seam.
Exclude only top-level `sha256`; encode sorted compact ASCII JSON with
`ensure_ascii=True`, `allow_nan=False`, exact integers and no trailing newline.
This is not NQ canonicalization. Shared exact vectors are under
`artifacts/host-posture-production-inventory-v1`; the runtime realization value
remains `sha256:` followed by the inventory's 64-hex `sha256`. Internal digest
consistency supplies no qualification authority.

Before the production compiler, `record-build-identity.py check-declarations
ARCH TARGET release` checks the existing HP declaration contract. The companion
`derive-declarations` command emits the canonical values from explicit Monitor
source/build, tree/lock, toolchain and native target inputs. The five HP
repository/commit/target/profile/features declarations cannot be omitted. This
guard does not repair the original HP executable with unavailable fields; that
artifact remains unusable and retained separately.

An explicitly admitted continuation can use an already successful production
receipt instead of rebuilding its selected bytes:

```text
QUAL_REUSE_FROZEN_COHORT=/absolute/prior/frozen-cohort.json packaging/host-posture-qualify.sh WORK BIN OUT SOURCE_COMMIT
```

This verifies the original four frozen files, raw production argv/stdout/stderr/
exit hashes and source inputs before any Cargo check. It runs no production
build/freeze, writes `selection_inherited_from`, and packages the same receipt's
`frozen_bin_dir`. Existing output still refuses. The continuation's `run` and
`results.json` contain only commands it actually executes; original compiler
evidence is data under `production-input/production.{argv.json,stdout,stderr,exit}`.
Each `production_inputs` entry retains its original absolute path/hash/size and
its relative `packaged_path`. The packager verifies that bundle before embedding
it beside the existing qualification records. No historical command is copied
into a new run or claimed to have executed again.

The f4ee8d5 runtime/product source and seven original ELFs retain their own
identity. This repair has a separate apparatus/docs source identity; it cannot
claim that the earlier product commit contained the new collector or guard.
The 19 native library tests were engineering evidence. Five qualified FS CLI
cases, distinct-principal qualification and package acceptance remain pending.
