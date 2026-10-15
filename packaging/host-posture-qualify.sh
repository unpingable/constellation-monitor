#!/usr/bin/env bash
# Produce host-posture's local qualification inputs (QUAL_INPUT_DIR for build-deb.sh) for the exact source in WORK and
# the binary already built there: run the check commands, record argv/stdout/stderr/exit per command (run/), then
# assemble hostile-corpus.json and results.json in the canonical form `prepare-qualification` decodes (compact JSON,
# field order as below, no trailing newline). Honest capture only: a failing command is recorded as failing.
# Until cartography #94 this procedure existed only as a copy inside the shipped package (run/run-checks.sh) and the
# assembly step existed nowhere.
#   host-posture-qualify.sh WORK BIN OUT SOURCE_COMMIT       (run inside the build image, toolchain on PATH)
set -uo pipefail
WORK=$1 BIN=$2 OUT=$3 COMMIT=$4
mkdir -p "$OUT/run"; cd "$WORK"
export CONSTELLATION_HOST_POSTURE_TOOLCHAIN_IDENTITY="${CONSTELLATION_HOST_POSTURE_TOOLCHAIN_IDENTITY:-$(rustc --version)}"
R=$OUT/run
sha256sum "$BIN" > "$R/binary-before.sha256"
i=0
run() { i=$((i+1)); name=$1; shift; { printf '['; sep=''; for a in "$@"; do printf '%s"%s"' "$sep" "$a"; sep=','; done; printf ']'; } > "$R/$i-$name.argv.json"; "$@" > "$R/$i-$name.stdout" 2> "$R/$i-$name.stderr"; echo $? > "$R/$i-$name.exit"; echo "[$i $name] exit $(cat "$R/$i-$name.exit")"; }
run fmt cargo fmt --all -- --check
run clippy cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
run focused cargo test --locked -p constellation-host-posture --release --all-targets -- --nocapture --test-threads=1
run workspace cargo test --locked --release --workspace --all-targets --all-features --no-fail-fast -- --test-threads=1
run release cargo build --locked --release -p constellation-host-posture -p constellation-status-projection --bins
sha256sum "$BIN" > "$R/binary-after.sha256"
diff "$R/binary-before.sha256" "$R/binary-after.sha256" >/dev/null && echo "binary unchanged" || { echo "BINARY CHANGED"; exit 1; }
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
    if os.path.basename(stem).split("-", 1)[1] in ("focused", "workspace"):
        tests = sum(int(n) for n in re.findall(r"^test result: \w+\. (\d+) passed", open(stem + ".stdout").read(), re.M))
        total += tests
    ok = ok and code == 0
    results.append({"sequence": int(os.path.basename(stem).split("-")[0]), "argv": json.load(open(argv)), "exit_code": code,
                    "stdout_digest": d(stem + ".stdout"), "stderr_digest": d(stem + ".stderr"), "observed_test_count": tests})
corpus = {"schema_version": 1, "corpus_id": "constellation-host-posture-jammy-%s-v1" % commit[:7],
          "hostile_scenarios": ["executed::tests::build_probe_never_invents_an_unset_identity",
                                "executed::tests::packaged_example_decodes_with_the_owner_schema",
                                "executed::tests::service_local_custody_and_withdrawal_bounds_fail_closed"],
          "property_families": ["build-identity-nonfabrication-negative-control", "packaged-example-owner-schema-and-bounds",
                                "service-custody-and-withdrawal-negative-controls"]}
res = {"schema_version": 1, "command_results": results, "total_tests_passed": total, "all_required_commands_passed": ok}
for name, doc in (("hostile-corpus.json", corpus), ("results.json", res)):
    open(os.path.join(out, name), "w").write(json.dumps(doc, separators=(",", ":")))
print("qualification inputs: %d tests passed, all commands passed: %s" % (total, ok))
sys.exit(0 if ok else 1)
PY
