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

# --- pulse-nq-load-correspondence: closed co-production surface -------------
# These checks are additive. The bridge rules above are unchanged and the two
# crates must remain independent of each other.
corr_dir="$root/crates/pulse-nq-load-correspondence/src"
corr_cli="$corr_dir/nq_cli.rs"
[ -f "$corr_cli" ] || fail "correspondence NQ port module missing"
rg -q 'env_clear\(\)' "$corr_cli" || fail "correspondence NQ port must clear the environment"
rg -q 'executable_sha256' "$corr_cli" || fail "correspondence NQ port must check the executable digest"
rg -q 'config_sha256' "$corr_cli" || fail "correspondence NQ port must check the configuration digest"
rg -q 'pub trait NqPort: sealed::Sealed' "$corr_cli" || fail "correspondence NQ port must be sealed"

if rg -n 'acquire-next-local|replay-local-successor|"qualify"' "$corr_dir" --glob '!nq_cli.rs'; then
  fail "NQ command names outside the closed correspondence port"
fi

if rg -n '/proc/loadavg|available_parallelism|/proc/stat|/proc/meminfo|/proc/sys|hostname|TcpStream|UdpSocket|reqwest|curl' "$corr_dir"; then
  fail "correspondence crate reads a host source or network surface"
fi

if rg -n '"execute"|"import"|"collect"|diagnostics execute|diagnostics import' "$corr_dir"; then
  fail "correspondence crate names an NQ operation other than the closed three"
fi

if rg -n 'derive_state|load_pressure_state|normalized_load|pulse_nq_load_support' "$corr_dir"; then
  fail "correspondence crate recomputes load pressure or references the bridge"
fi

if rg -n 'WithinDeclaredBound|OutsideDeclaredBound|AuthenticationResultV1::Verified|LivePresentSupportResponseV1::new|current\s*[:=]\s*true' "$corr_dir"; then
  fail "correspondence crate assesses a signal, claims authentication, or fabricates currentness"
fi

if rg -n 'pulse_nq_load_correspondence|pulse-nq-load-correspondence|constellation_status_nq_load_pressure' "$root/crates/pulse-nq-load-support"; then
  fail "bridge references the correspondence or consequence crate"
fi

# --- constellation-status-nq-load-pressure: consequence adapter --------------
cons_dir="$root/crates/constellation-status-nq-load-pressure/src"
[ -d "$cons_dir" ] || fail "consequence adapter source missing"
if rg -n 'std::process|Command::new|/proc|derive_state|load_pressure_state|normalized_load|pulse_nq_load_support|LivePresentSupportResponseV1::new' "$cons_dir"; then
  fail "consequence adapter acquires, recomputes, or fabricates"
fi

# --- constellation-status-nq-filesystem-capacity: second consequence adapter -
# Additive. Same closed surface as the load adapter, plus: it maps exactly one
# question and never names the load question.
fscap_dir="$root/crates/constellation-status-nq-filesystem-capacity/src"
[ -d "$fscap_dir" ] || fail "filesystem-capacity consequence adapter source missing"
if rg -n 'std::process|Command::new|/proc|/dev/disk|std::fs|mountinfo|nix::|libc::|derive_state|pulse_nq_load_support|LivePresentSupportResponseV1::new|HostLoadPressureV1' "$fscap_dir"; then
  fail "filesystem-capacity consequence adapter acquires, recomputes, fabricates, or maps another question"
fi
rg -q 'REQUIRED_QUESTION: QuestionV1 = QuestionV1::HostFilesystemCapacityPressureV1' "$fscap_dir/lib.rs" || fail "filesystem-capacity adapter must pin its question"
rg -q 'REQUIRED_QUESTION: QuestionV1 = QuestionV1::HostLoadPressureV1' "$cons_dir/lib.rs" || fail "load-pressure adapter must pin its question"
if rg -n 'statfs|statvfs|permille|non-reserved' "$fscap_dir"; then
  fail "filesystem-capacity consequence adapter restates NQ's measurement or threshold"
fi

# The load-default wrappers exist for the frozen load v1 tests only. No
# crate source or example may call them; production paths name the question.
if rg -n '(^|[^_a-zA-Z])classify_outcome\(|(^|[^_a-zA-Z])check_holding_delay\(|(^|[^_a-zA-Z])frame_ingress\(|CorrespondenceProfileV1::seal\(|synthetic_profile\(\)|synthetic_enrollment\(\)' "$root"/crates/*/src "$root"/crates/*/examples --glob '!**/nq_cli.rs' \
  | rg -v 'pub fn (classify_outcome|check_holding_delay|frame_ingress|synthetic_profile|synthetic_enrollment)\(|pub fn seal\('; then
  fail "a crate source or example calls a load-default wrapper; use the *_for form with a question"
fi

echo "nq-load-correspondence: closed co-production surface; consequence adapters: no acquisition or recomputation surface, one question each"
