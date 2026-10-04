#!/bin/bash
# Fake `nq` for resolver tests, after constellation-attention's fake: answers
# `--config C --json evaluations export --limit N [--after A --through T]`
# like NQ's nq.evaluation_history.v1 from $FAKE_NQ_DIR/history/<sequence>.json
# (one envelope per file). Controls in $FAKE_NQ_DIR: `fail` (exit 1),
# `oversize` (print far more than any page bound), `malformed` (print a page
# of another schema), `history_moved` (the upper bound moves under paging).
set -eu
dir="$FAKE_NQ_DIR"
[ "$1" = --config ] && [ "$3" = --json ] && [ "$4" = evaluations ] && [ "$5" = export ] \
  || { echo "unexpected argv: $*" >&2; exit 64; }
shift 5
limit=1; after=""; through=""
while [ $# -gt 0 ]; do
  case "$1" in
    --limit) limit="$2"; shift 2;;
    --after) after="$2"; shift 2;;
    --through) through="$2"; shift 2;;
    *) echo "unexpected flag $1" >&2; exit 64;;
  esac
done
echo "evaluations ${limit} ${after:-none} ${through:-none}" >> "$dir/calls.log"
[ -e "$dir/fail" ] && { echo "store is locked" >&2; exit 1; }
[ -e "$dir/fail_once" ] && { rm -f "$dir/fail_once"; echo "nq: database integrity check failed: transient" >&2; exit 1; }
[ -e "$dir/oversize" ] && { head -c 200000 /dev/zero | tr '\0' ' '; exit 0; }
[ -e "$dir/malformed" ] && { echo '{"schema":"nq.status_snapshot.v3","records":[]}'; exit 0; }
hist="$dir/history"
current=$(ls "$hist" 2>/dev/null | sed 's/\.json$//' | sort -n | tail -1)
current=${current:-0}
given="$through"
through=${through:-$current}
start=${after:-0}
end=$((start + limit)); [ "$end" -gt "$through" ] && end=$through
records=""
if [ "$end" -gt "$start" ]; then
  records=$(seq $((start + 1)) "$end" | awk -v hist="$hist" '{
    file = hist "/" $1 ".json"; getline body < file; close(file)
    printf "%s{\"sequence\":%s,\"result\":%s}", (NR > 1 ? "," : ""), $1, body
  }')
fi
if [ "$end" -ge "$through" ]; then complete=true; next=null; else complete=false; next=$end; fi
reported=$through
[ -e "$dir/history_moved" ] && [ -n "$given" ] && reported=$((through + 1))
printf '{"schema":"nq.evaluation_history.v1","generated_at":"2026-10-03T00:00:00Z","limit":%s,"after_sequence":%s,"through_sequence":%s,"records":[%s],"next_after_sequence":%s,"complete":%s}\n' \
  "$limit" "${after:-null}" "$reported" "$records" "$next" "$complete"
