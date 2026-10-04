#!/bin/bash
# Fake observation resolver wrapper: `pre` (unit not active) or `post` (unit
# active). Answers the status in $FAKE_DIR/<which>_status (default current).
set -u
which="$1"; dir="$FAKE_DIR"
cat > /dev/null
status=$(cat "$dir/${which}_status" 2>/dev/null || echo current)
echo "resolve $which $status" >> "$dir/calls.log"
if [ "$which" = pre ]; then basis=constellation.remediation.systemd-not-active/v1; id=pre-resolver/v1
else basis=constellation.remediation.systemd-active/v1; id=post-resolver/v1; fi
printf '{"schema":"ag.governed-loop.observation-resolution/v3","status":"%s","resolver_id":"%s","basis":{"schema":"ag.governed-loop.typed-observation-basis/v1","basis_type":"%s","basis_identity":"sha256:4444444444444444444444444444444444444444444444444444444444444444"},"currentness":"sha256:5555555555555555555555555555555555555555555555555555555555555555","fresh_until_unix_ms":1}\n' "$status" "$id" "$basis"
echo "fake resolver: $status" >&2
