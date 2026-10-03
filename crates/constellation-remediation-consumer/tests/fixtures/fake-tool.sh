#!/bin/bash
# Fake nq / systemctl / ag-effectd: logs argv; `systemctl show` prints
# $FAKE_DIR/active_state (default inactive); `plan-id` prints a digest.
set -u
tool="$1"; shift; dir="$FAKE_DIR"
echo "$tool $*" >> "$dir/calls.log"
[ -e "$dir/${tool}_fail" ] && { echo "$tool failed" >&2; exit 1; }
case "$tool" in
  systemctl) [ "$1" = show ] && { cat "$dir/active_state" 2>/dev/null || echo inactive; };;
  effectd) [ "$1" = plan-id ] && echo "sha256:$(sha256sum "$2" | cut -c1-64)";;
esac
exit 0
