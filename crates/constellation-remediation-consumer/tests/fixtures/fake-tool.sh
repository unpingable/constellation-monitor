#!/bin/bash
# Fake nq / systemctl / ag-effectd: logs argv; `systemctl show` prints
# $FAKE_DIR/active_state (default inactive); `plan-id` prints a digest.
set -u
tool="$1"; shift; dir="$FAKE_DIR"
echo "$tool $*" >> "$dir/calls.log"
[ -e "$dir/${tool}_fail" ] && { echo "$tool failed" >&2; exit 1; }
case "$tool" in
  nq) if [ "${3:-}" = --json ] && [ "${4:-}" = evaluations ]; then
        # One-record nq.evaluation_history.v1 page: the newest evaluation of the
        # enrolled instance, taken $FAKE_DIR/sample_offset_s (default 0) from now.
        at=$(date -u -d "now $(cat "$dir/sample_offset_s" 2>/dev/null || echo 0) seconds" +%Y-%m-%dT%H:%M:%S.%3NZ)
        printf '{"schema":"nq.evaluation_history.v1","limit":1,"after_sequence":null,"through_sequence":1,"records":[{"sequence":1,"result":{"context":{"instance_id":"svc-attention-canary"},"evaluated_at":"%s"}}],"next_after_sequence":null,"complete":true}\n' "$at"
      fi;;
  systemctl) [ "$1" = show ] && { cat "$dir/active_state" 2>/dev/null || echo inactive; };;
  effectd) [ "$1" = plan-id ] && echo "sha256:$(sha256sum "$2" | cut -c1-64)";;
esac
exit 0
