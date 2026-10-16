# Host-posture executable identity

This source line retains the existing Jammy packaging recipe from `a7edcae`
and its qualification runner unchanged. The helper changes are based on the
production source `81212a5`. The installed package has three native executables
and three role symlinks to `pulse-nq-load-support`.

`constellation-status` and `pulse-nq-load-support`, including its role names,
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
