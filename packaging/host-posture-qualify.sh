#!/usr/bin/env bash
# Final owning production build -> independent frozen cohort -> isolated checks.
# Optional QUAL_REUSE_FROZEN_COHORT verifies inherited actual production data
# and skips production build/freeze. Its origin records are data, never new commands.
# Existing interface: host-posture-qualify.sh WORK BIN OUT SOURCE_COMMIT
# BIN names the HP executable emitted by that final build. Package only
# the receipt-selected frozen BIN_DIR with QUAL_INPUT_DIR=OUT. No production writer follows freeze.
set -uo pipefail
[[ $# -eq 4 ]] || { echo "usage: $0 WORK BIN OUT SOURCE_COMMIT" >&2; exit 2; }
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
WORK=$(cd "$1" && pwd -P)
BIN=$(python3 -c 'import pathlib,sys; p=pathlib.Path(sys.argv[2]); print((p if p.is_absolute() else pathlib.Path(sys.argv[1])/p).resolve())' "$WORK" "$2")
OUT=$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())' "$3")
COMMIT=$4
[[ "${MONITOR_SOURCE_COMMIT:-}" == "$COMMIT" ]] || { echo "source declaration differs from qualification input" >&2; exit 2; }
PRODUCTION_TARGET=$(python3 -c 'import pathlib,sys; p=pathlib.Path(sys.argv[2]); print((p if p.is_absolute() else pathlib.Path(sys.argv[1])/p).resolve())' "$WORK" "${CARGO_TARGET_DIR:-target}")
FROZEN=$OUT/frozen-bin
if [[ -n "${QUAL_REUSE_FROZEN_COHORT:-}" ]]; then
    [[ "$QUAL_REUSE_FROZEN_COHORT" = /* ]] || { echo "QUAL_REUSE_FROZEN_COHORT must be absolute" >&2; exit 2; }
    FROZEN=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["frozen_bin_dir"])' "$QUAL_REUSE_FROZEN_COHORT") || exit 2
fi
TEST_TARGET=$OUT/test-target
python3 -c 'import pathlib,sys; p,f,t=map(pathlib.Path,sys.argv[1:]); assert not any(a.is_relative_to(b) or b.is_relative_to(a) for a,b in [(p,f),(p,t),(f,t)]), "production/frozen/test paths must be separate"' "$PRODUCTION_TARGET" "$FROZEN" "$TEST_TARGET" || exit 2
for existing in run frozen-bin frozen-cohort.json hostile-corpus.json results.json production-input; do
    [[ ! -e "$OUT/$existing" ]] || { echo "existing qualification output requires original-producer reconciliation: $existing" >&2; exit 2; }
done
mkdir -p "$OUT"
mkdir -m 0700 "$OUT/run"
cd "$WORK" || exit 2
export CONSTELLATION_HOST_POSTURE_TOOLCHAIN_IDENTITY="${CONSTELLATION_HOST_POSTURE_TOOLCHAIN_IDENTITY:-$(rustc --version)}"
R=$OUT/run
i=0
LAST_EXIT=0
run() {
    i=$((i+1)); name=$1; shift
    python3 - "$@" > "$R/$i-$name.argv.json" <<'ARGV'
import json,sys
print(json.dumps(sys.argv[1:]),end="")
ARGV
    "$@" > "$R/$i-$name.stdout" 2> "$R/$i-$name.stderr"
    LAST_EXIT=$?
    echo "$LAST_EXIT" > "$R/$i-$name.exit"
    echo "[$i $name] exit $LAST_EXIT"
}
TARGET=$(rustc -vV | python3 -c 'import sys; rows=[line.split(":",1)[1].strip() for line in sys.stdin if line.startswith("host:")]; assert len(rows)==1; print(rows[0])') || exit 2
case "$TARGET" in x86_64-*) ARCH=amd64;; aarch64-*) ARCH=arm64;; *) echo "unsupported native target" >&2; exit 2;; esac
run declarations python3 "$HERE/record-build-identity.py" check-declarations "$ARCH" "$TARGET" release
[[ $LAST_EXIT -eq 0 ]] || exit "$LAST_EXIT"
if [[ -n "${QUAL_REUSE_FROZEN_COHORT:-}" ]]; then
    run reused-selection python3 "$HERE/frozen-helper-cohort.py" reuse "$QUAL_REUSE_FROZEN_COHORT" "$FROZEN" "$OUT"
    [[ $LAST_EXIT -eq 0 ]] || exit "$LAST_EXIT"
else
    export CARGO_TARGET_DIR=$PRODUCTION_TARGET
    run release cargo build --locked --release -p constellation-host-posture -p constellation-status-projection -p pulse-nq-load-support -p pulse-nq-filesystem-support --bins --message-format=json
    [[ $LAST_EXIT -eq 0 ]] || exit "$LAST_EXIT"
    RELEASE_PREFIX="$R/$i-release"
    run freeze python3 "$HERE/frozen-helper-cohort.py" freeze "$RELEASE_PREFIX.stdout" "$BIN" "$PRODUCTION_TARGET" "$FROZEN" "$OUT/frozen-cohort.json" "$RELEASE_PREFIX.argv.json"
    [[ $LAST_EXIT -eq 0 ]] || exit "$LAST_EXIT"
fi
sha256sum "$FROZEN/constellation-host-posture" > "$R/binary-before.sha256"
export CARGO_TARGET_DIR=$TEST_TARGET
run_guarded() {
    local step=$1
    run "$@"
    run "cohort-$step" python3 "$HERE/frozen-helper-cohort.py" check "$OUT/frozen-cohort.json" "$FROZEN"
    [[ $LAST_EXIT -eq 0 ]] || exit "$LAST_EXIT"
}
run_guarded fmt cargo fmt --all -- --check
run_guarded clippy cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
run_guarded focused cargo test --locked -p constellation-host-posture --release --all-targets -- --nocapture --test-threads=1
run_guarded workspace cargo test --locked --release --workspace --all-targets --all-features --no-fail-fast -- --test-threads=1
run_guarded filesystem-cli env PULSE_FS_TEST_BINARY="$FROZEN/pulse-nq-filesystem-support" cargo test --locked -p pulse-nq-filesystem-support --test cli_custody -- --ignored --test-threads=1
sha256sum "$FROZEN/constellation-host-posture" > "$R/binary-after.sha256"
diff "$R/binary-before.sha256" "$R/binary-after.sha256" >/dev/null || { echo "selected HP binary changed" >&2; exit 1; }
cp "$0" "$R/run-checks.sh"
python3 - "$R" "$OUT" "$COMMIT" <<'PY'
import glob, hashlib, json, os, re, sys
run, out, commit = sys.argv[1:]
d = lambda p: "sha256:" + hashlib.sha256(open(p, "rb").read()).hexdigest()
results, total, ok = [], 0, True
for argv in sorted(glob.glob(os.path.join(run, "*.argv.json")), key=lambda p: int(os.path.basename(p).split("-")[0])):
    stem = argv[:-len(".argv.json")]
    code = int(open(stem + ".exit").read())
    tests = None
    if os.path.basename(stem).split("-", 1)[1] in ("focused", "workspace", "filesystem-cli"):
        tests = sum(int(n) for n in re.findall(r"^test result: \w+\. (\d+) passed", open(stem + ".stdout").read(), re.M))
        total += tests
    ok = ok and code == 0
    results.append({"sequence": int(os.path.basename(stem).split("-")[0]), "argv": json.load(open(argv)), "exit_code": code,
                    "stdout_digest": d(stem + ".stdout"), "stderr_digest": d(stem + ".stderr"), "observed_test_count": tests})
# These are required source cases, not an unchecked claim that they ran.
# Emit the corpus only after the captured focused runner proves each exact
# name passed once. Missing, ignored, failed or duplicate outcomes refuse.
required = {
    "tests::build_probe_never_invents_an_unset_identity": "build-identity-nonfabrication-negative-control",
    "tests::packaged_example_decodes_with_the_owner_schema": "packaged-example-owner-schema-and-bounds",
    "tests::service_local_custody_and_withdrawal_bounds_fail_closed": "service-custody-and-withdrawal-negative-controls",
}
focused_matches = [p[:-len(".argv.json")] for p in glob.glob(os.path.join(run, "*.argv.json"))
                   if os.path.basename(p).split("-", 1)[1] == "focused.argv.json"]
if len(focused_matches) != 1:
    sys.exit("qualification corpus refused: exactly one recorded focused command required")
focused = focused_matches[0]
if int(open(focused + ".exit").read()) != 0:
    sys.exit("qualification corpus refused: focused command did not pass")
observed = {case: [] for case in required}
for case, outcome in re.findall(r"^test (\S+) \.\.\. (.*)$", open(focused + ".stdout").read(), re.M):
    if case in observed:
        observed[case].append(outcome)
for case, outcomes in observed.items():
    if outcomes != ["ok"]:
        sys.exit("qualification corpus refused: %s requires one explicit pass, observed %r" % (case, outcomes))
# The existing FS operator-context command must actually execute all five
# already-required cases; ignored/missing/duplicate cases are not qualification.
fs_matches = [p[:-len(".argv.json")] for p in glob.glob(os.path.join(run, "*.argv.json"))
              if os.path.basename(p).split("-", 1)[1] == "filesystem-cli.argv.json"]
if len(fs_matches) != 1 or int(open(fs_matches[0] + ".exit").read()) != 0:
    sys.exit("qualification refused: one successful filesystem CLI command required")
fs_required = [
    "cli_missing_current_replay_contradiction_and_new_basis_use_real_files",
    "cli_source_expiry_and_previous_boot_do_not_become_current",
    "cli_bad_signature_and_equal_acquisition_are_refused",
    "same_declared_semantics_wrong_runtime_realization_cannot_establish_current",
    "cli_exact_negative_context_is_unknown_without_receipt_or_acquisition",
]
fs_seen = {case: [] for case in fs_required}
fs_output = open(fs_matches[0] + ".stdout").read()
for case, outcome in re.findall(r"^test (\S+) \.\.\. (.*)$", fs_output, re.M):
    if case in fs_seen:
        fs_seen[case].append(outcome)
if any(outcomes != ["ok"] for outcomes in fs_seen.values()) or sum(int(n) for n in re.findall(r"^test result: \w+\. (\d+) passed", fs_output, re.M)) != 5:
    sys.exit("qualification refused: five exact filesystem CLI passes required")
corpus = {"schema_version": 1, "corpus_id": "constellation-host-posture-jammy-%s-v1" % commit[:7],
          "hostile_scenarios": list(observed),
          "property_families": list(required.values())}
res = {"schema_version": 1, "command_results": results, "total_tests_passed": total, "all_required_commands_passed": ok}
for name, doc in (("hostile-corpus.json", corpus), ("results.json", res)):
    open(os.path.join(out, name), "w").write(json.dumps(doc, separators=(",", ":")))
print("qualification inputs: %d tests passed, all commands passed: %s" % (total, ok))
sys.exit(0 if ok else 1)
PY
