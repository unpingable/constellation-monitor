#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
source_file="$root/crates/pulse-nq-load-support/src/lib.rs"
main_file="$root/crates/pulse-nq-load-support/src/main.rs"

fail() {
  echo "exact-load-support structural check failed: $*" >&2
  exit 1
}

rg -q 'const PROC_LOADAVG: &str = "/proc/loadavg"' "$source_file" || fail "fixed load source missing"
rg -q 'available_parallelism' "$source_file" || fail "fixed logical CPU source missing"
rg -q 'NORMALIZED_LOAD_THRESHOLD_MILLIS: u32 = 2_000' "$source_file" || fail "exact threshold missing"
rg -q 'SUPPORT_VALIDITY_MS: u64 = 300_000' "$source_file" || fail "exact profile horizon missing"

if rg -n 'std::process::Command|Command::new|diagnostics execute|diagnostics qualify|nq-monitor|/opt/notquery|TcpStream|UdpSocket|reqwest|curl|hostname|/proc/stat|/proc/meminfo' "$source_file" "$main_file"; then
  fail "forbidden command, diagnostic, historical, network, naming, or correlated-source surface"
fi

if rg -n 'current\s*[:=]\s*true|register_support|proposition_implication|retry.*diagnostic' "$source_file" "$main_file"; then
  fail "generic support, mutable currentness, implication, or diagnostic retry surface"
fi

echo "exact-load-support: closed proposition-specific non-actuating surface"
