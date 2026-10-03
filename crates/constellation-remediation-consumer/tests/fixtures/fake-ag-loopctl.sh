#!/bin/bash
# Fake `ag-loopctl` for consumer tests: a small program-counter machine over
# "$DB.d/", answering with snapshots shaped like AG's OccurrenceSnapshotV1
# ({"state":{"<program_counter>":{...}}}). Docket custody is "$DB.d/docket";
# every real effect is one line in "$FAKE_DIR/effects.log". Controls in
# $FAKE_DIR: refuse_<command> (exit 1), crash_before_init, crash_after_authorize
# and crash_in_dispatch (SIGKILL the caller once), dispatch_outcome
# (success|failure|indeterminate|pending).
set -u
dir="$FAKE_DIR"
cmd="$1"; shift
db=""; input=""; genesis=""; dsr=""; obsres=""; plan=""
while [ $# -gt 0 ]; do
  case "$1" in
    --executor-plan) plan="$2"; shift 2;;
    --database) db="$2"; shift 2;;
    --input) input="$2"; shift 2;;
    --genesis) genesis="$2"; shift 2;;
    --docket-standing-resolver) dsr="$2"; shift 2;;
    --observation-resolver) obsres="$2"; shift 2;;
    --*) shift 2;;
    *) echo "unexpected argument $1" >&2; exit 64;;
  esac
done
echo "ag $cmd" >> "$dir/calls.log"
# Every catalog entry pins its plans: these steps need the exact plan (AG 18aac24).
case "$cmd" in
  init|decide|authorize|continue|complete)
    [ -n "$plan" ] || { echo "the catalog pins exact plans; the exact executor plan is required" >&2; exit 1; }
    echo "$cmd $plan" >> "$dir/plans.log";;
esac
st="$db.d"
D0="sha256:0000000000000000000000000000000000000000000000000000000000000000"
ISS="sha256:1111111111111111111111111111111111111111111111111111111111111111"
ATT="sha256:2222222222222222222222222222222222222222222222222222222222222222"
SET="sha256:3333333333333333333333333333333333333333333333333333333333333333"
get() { cat "$st/$1" 2>/dev/null; }
put() { printf '%s' "$2" > "$st/$1"; }
field() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" "$2" | head -1; }
key() { printf '{"campaign":"%s","occurrence":"%s"}' "$(get campaign)" "$1"; }
snapshot() {
  local pc body k
  pc=$(get pc); k=$(key "$(get occurrence)")
  case "$pc" in
    observation_required)
      if [ -e "$st/cont" ]; then body="{\"meta\":{\"key\":$(key "$(get cont)")},\"prior\":{\"key\":$k}}"
      else body="{\"meta\":{\"key\":$k},\"prior\":null}"; fi;;
    proposal_recorded|standing_required|admissible_pending_authorization|halted)
      body="{\"meta\":{\"key\":$k}}";;
    authorization_consumed) body="{\"issuance\":{\"issuance\":\"$ISS\",\"key\":$k}}";;
    dispatched) body="{\"authorized\":{\"issuance\":{\"issuance\":\"$ISS\",\"key\":$k}},\"custody\":{\"attempt\":\"$ATT\"}}";;
    reconciliation_required) body="{\"dispatch\":{\"authorized\":{\"issuance\":{\"key\":$k}},\"custody\":{\"attempt\":\"$ATT\"}}}";;
    settled_observation_required)
      body="{\"dispatch\":{\"authorized\":{\"issuance\":{\"key\":$k}}},\"settlement\":{\"attempt\":\"$ATT\",\"issuance\":\"$ISS\",\"outcome\":\"$(get outcome)\",\"settled_at_unix_ms\":$(get settled_at),\"settlement\":\"$SET\"}}";;
    completed) body="{\"meta\":{\"key\":$(key "$(get cont)")}}";;
    *) echo "fake has no state $pc" >&2; exit 70;;
  esac
  printf '{"prior_state_digest":"%s","state":{"%s":%s},"state_digest":"%s"}\n' "$D0" "$pc" "$body" "$D0"
}
expect() { [ "$(get pc)" = "$1" ] || { echo "illegal transition from $(get pc) to $cmd" >&2; exit 1; }; }
refuse() { [ -e "$dir/refuse_$cmd" ] && { cat "$dir/refuse_$cmd" >&2; echo " ($cmd refused)" >&2; exit 1; }; return 0; }
settle() {
  case "$(cat "$dir/dispatch_outcome" 2>/dev/null || echo success)" in
    success) put outcome success; put pc settled_observation_required; put settled_at $(( $(date +%s%3N) - $(cat "$dir/settled_ago_ms" 2>/dev/null || echo 60000) ));;
    failure) put outcome failure; put pc settled_observation_required; put settled_at "$(date +%s%3N)";;
    indeterminate) put pc reconciliation_required;;
    pending) [ "$1" = recover ] && put pc reconciliation_required;;
  esac
}
case "$cmd" in
  init)
    [ -e "$db" ] && { echo "campaign store already exists: $db" >&2; exit 1; }
    if [ -e "$dir/crash_before_init" ]; then rm "$dir/crash_before_init"; kill -9 "$PPID"; exit 0; fi
    refuse
    touch "$db"; mkdir -p "$st"
    put campaign "$(field campaign "$genesis")"; put occurrence "$(field occurrence "$genesis")"
    put pc observation_required; snapshot;;
  status) [ -e "$db" ] || { echo "no campaign store" >&2; exit 1; }; snapshot;;
  record-proposal) expect observation_required; refuse; put pc proposal_recorded; snapshot;;
  require-standing) expect proposal_recorded; refuse; put pc standing_required; snapshot;;
  decide) expect standing_required; refuse; put pc admissible_pending_authorization; snapshot;;
  authorize)
    expect admissible_pending_authorization; refuse; put pc authorization_consumed
    if [ -e "$dir/crash_after_authorize" ]; then rm "$dir/crash_after_authorize"; kill -9 "$PPID"; fi
    snapshot;;
  dispatch)
    expect authorization_consumed
    [ -e "$st/docket" ] && { echo "Docket already holds custody of this issuance" >&2; exit 1; }
    [ -e "$dir/dispatch_unavailable" ] && { echo "Error: Docket boundary unavailable: connection reset" >&2; exit 1; }
    refusal=$("$dsr" 2>&1 < /dev/null > /dev/null) || { echo "Error: external boundary refused (external-process:refused/error: process-refused:$refusal)" >&2; exit 1; }
    put docket accepted; echo "start" >> "$dir/effects.log"; put pc dispatched
    if [ -e "$dir/crash_in_dispatch" ]; then rm "$dir/crash_in_dispatch"; kill -9 "$PPID"; fi
    snapshot;;
  poll) expect dispatched; settle poll; snapshot;;
  recover)
    case "$(get pc)" in
      authorization_consumed)
        if [ -e "$st/docket" ]; then put pc dispatched; settle recover; printf '{"result":"advanced","record":%s}\n' "$(snapshot)"
        else printf '{"result":"issuance_not_accepted","record":{"issuance":"%s"}}\n' "$ISS"; fi;;
      dispatched) settle recover; printf '{"result":"advanced","record":%s}\n' "$(snapshot)";;
      *) printf '{"result":"external_revalidation","record":"none"}\n';;
    esac;;
  continue) expect settled_observation_required; refuse; put cont "$(field occurrence "$input")"; put pc observation_required; snapshot;;
  complete)
    expect observation_required; refuse
    echo '{}' | "$obsres" | grep -q '"status":"current"' || { echo "terminal observation is not current" >&2; exit 1; }
    put pc completed; snapshot;;
  *) echo "fake does not implement $cmd" >&2; exit 64;;
esac
