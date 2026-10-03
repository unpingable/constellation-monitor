#!/bin/bash
# Fake Docket bounded-grant standing resolver: refuses once $FAKE_DIR/grant_uses
# reaches $FAKE_DIR/grant_max (default 1).
set -u
dir="$FAKE_DIR"
uses=$(cat "$dir/grant_uses" 2>/dev/null || echo 0)
max=$(cat "$dir/grant_max" 2>/dev/null || echo 1)
echo "grant $uses/$max" >> "$dir/calls.log"
[ -e "$dir/grant_revoked" ] && { echo "execution-standing refused: execution-standing-grant-revoked" >&2; exit 2; }
[ "$uses" -ge "$max" ] && { echo "execution-standing refused: execution-standing-grant-exhausted" >&2; exit 2; }
echo $((uses + 1)) > "$dir/grant_uses"
echo '{"status":"current"}'
