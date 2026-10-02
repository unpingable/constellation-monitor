#!/bin/bash
# Fake `nq` for tests: records each notification command and answers like
# NQ 0.2.1 (`notification_id`, `delivery_state`). Exact resubmission of the
# same event to the same route returns the existing record, as NQ does.
# Controls in $FAKE_NQ_DIR: `next_state` (accepted|failed|unknown),
# `crash` (kill the caller before NQ retains anything, once), `crash_after`
# (retain, then kill the caller before it hears the answer, once),
# `command_error` (exit 1 before custody). `deliver-local` answers like
# `submit` for a local_file route and is logged under route `local:<route>`;
# `local_route` names a route that `submit` must refuse as local_file.
set -eu
dir="$FAKE_NQ_DIR"
[ "$1" = --config ] && [ "$3" = --json ] && [ "$4" = notification ] || { echo "unexpected argv: $*" >&2; exit 64; }
sub="$5"; shift 5
net=false; intent=""; route=""; from=""; event=""
while [ $# -gt 0 ]; do
  case "$1" in
    --intent) intent="$2"; shift 2;;
    --route) route="$2"; shift 2;;
    --notification-id) from="$2"; shift 2;;
    --stable-event-id) event="$2"; shift 2;;
    --enable-network) net=true; shift;;
    *) echo "unexpected flag $1" >&2; exit 64;;
  esac
done
if [ -e "$dir/crash" ]; then rm -f "$dir/crash"; kill -9 "$PPID"; sleep 2; exit 1; fi
crash_after=false
if [ -e "$dir/crash_after" ]; then rm -f "$dir/crash_after"; crash_after=true; fi
if [ -e "$dir/command_error" ]; then echo "notification condition target_class is refused" >&2; exit 1; fi
state=$(cat "$dir/next_state" 2>/dev/null || echo accepted)
mkdir -p "$dir/records" "$dir/intents"
n=$(($(ls "$dir/intents" | wc -l) + 1))
if [ "$sub" = deliver-local ]; then
  # NQ 0.2.1: a local_file route takes no --enable-network, requires
  # destination_identity local-inbox:<route>, and refuses submit.
  $net && { echo "unexpected flag --enable-network" >&2; exit 64; }
  grep -q "\"destination_identity\":\"local-inbox:$route\"" "$intent" || {
    echo "local inbox intent destination identity does not match its configured route" >&2; exit 1; }
  sub=submit
  route="local:$route"
elif [ -e "$dir/local_route" ] && [ "$route" = "$(cat "$dir/local_route")" ]; then
  echo "local_file routes require notification deliver-local" >&2; exit 1
else
  $net || state=refused
fi
case "$sub" in
  submit)
    event=$(sed -n 's/.*"stable_event_id":"\([^"]*\)".*/\1/p' "$intent")
    record="$dir/records/$event@$route"
    if [ -e "$record" ]; then
      read -r id state < "$record"
      echo "submit $route $event $id $state existing" >> "$dir/calls.log"
      printf '{"delivery_state":"%s","notification_id":"%s"}\n' "$state" "$id"
      exit 0
    fi
    id="n$n"
    cp "$intent" "$dir/intents/$id.json"
    echo "$id $state" > "$record"
    echo "submit $route $event $id $state new" >> "$dir/calls.log"
    if $crash_after; then kill -9 "$PPID"; sleep 2; exit 1; fi
    printf '{"delivery_state":"%s","notification_id":"%s"}\n' "$state" "$id"
    ;;
  resubmit)
    id="n$n"
    touch "$dir/intents/$id.json"
    original=$(grep -l "^$from " "$dir"/records/* | head -1)
    echo "$id $state" > "$dir/records/$event@${original##*@}"
    echo "resubmit $from $event $id $state" >> "$dir/calls.log"
    printf '{"delivery_state":"%s","notification_id":"%s","resubmitted_from":"%s"}\n' "$state" "$id" "$from"
    ;;
  *) echo "unexpected subcommand $sub" >&2; exit 64;;
esac
