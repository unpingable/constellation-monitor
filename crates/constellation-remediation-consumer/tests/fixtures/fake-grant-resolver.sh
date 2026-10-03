#!/bin/bash
# Fake Docket bounded-grant standing resolver: refuses once $FAKE_DIR/grant_uses
# reaches $FAKE_DIR/grant_max (default 1).
set -u
dir="$FAKE_DIR"
uses=$(cat "$dir/grant_uses" 2>/dev/null || echo 0)
max=$(cat "$dir/grant_max" 2>/dev/null || echo 1)
echo "grant $uses/$max" >> "$dir/calls.log"
[ "$uses" -ge "$max" ] && { echo "grant use count exhausted" >&2; exit 1; }
echo $((uses + 1)) > "$dir/grant_uses"
echo '{"status":"current"}'
