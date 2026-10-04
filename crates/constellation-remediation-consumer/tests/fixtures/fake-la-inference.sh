#!/bin/bash
# Fake `la_inference` (protocol v 1, linear-accountant src/bin/la_inference.rs)
# for consumer tests: one JSON request on stdin, one
# {"v":1,"cmd":..,"result":{"outcome":..}} line on stdout, state under
# "$FAKE_DIR/la/". Logs "la <command>" to calls.log and the accounting detail
# to la.log. Controls in $FAKE_DIR: la_reserve / la_begin (exhausted|refused),
# la_fail_<command> (exit 3, storage failure), la_breach (settle reports
# escalation_required), crash_after_reserve, crash_after_begin,
# crash_before_settle, crash_after_settle (SIGKILL the caller once).
set -u
dir="$FAKE_DIR"; st="$dir/la"; mkdir -p "$st"
cmd="${!#}"
request=$(cat)
echo "la $cmd" >> "$dir/calls.log"
str() { printf '%s' "$request" | sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" | head -1; }
num() { printf '%s' "$request" | sed -n "s/.*\"$1\":\([0-9]*\).*/\1/p" | head -1; }
has() { printf '%s' "$request" | grep -q "\"$1\":"; }
out() { printf '{"v":1,"cmd":"%s","result":%s}\n' "$cmd" "$1"; }
key() { printf '%s' "$1" | tr '/' '_'; }
crash() { [ -e "$dir/crash_$1" ] && { rm "$dir/crash_$1"; kill -9 "$PPID"; exit 0; }; return 0; }
[ -e "$dir/la_fail_$cmd" ] && { printf '{"v":1,"error":{"kind":"sqlite","message":"disk I/O error"}}\n'; exit 3; }
[ "$(num v)" = 1 ] && [ "$(str cmd)" = "$cmd" ] || { printf '{"v":1,"error":{"kind":"protocol","message":"header"}}\n'; exit 2; }
settle_record() { # invocation terminal record
  printf '%s' "$3" > "$st/settle-$(key "$1")"
  echo "settle $1 $3" >> "$dir/la.log"
}
case "$cmd" in
  reserve)
    episode=$(str episode_id); rid="rsv-$(printf '%s' "$episode" | sha256sum | cut -c1-12)"
    echo "reserve $episode $(str model_class) $(str provider) calls=$(num max_calls) retries=$(num retry_ceiling) cost=$(num max_cost_micro_usd) admission=$(str admission_id) campaign=$(str ag_campaign) eligible_until=$(num eligibility_valid_until_unix_ms)" >> "$dir/la.log"
    if [ -e "$st/$rid" ]; then
      [ "$(cat "$st/$rid")" = "$request" ] || { out '{"outcome":"conflict","reason":"episode_id already reserved with a different payload"}'; exit 0; }
      out "{\"outcome\":\"replayed\",\"reservation_id\":\"$rid\",\"status\":\"open\"}"; exit 0
    fi
    case "$(cat "$dir/la_reserve" 2>/dev/null)" in
      exhausted) out '{"outcome":"exhausted","exhausted":{"dimension":"milestone","terminal_class":"budget_exhausted","attempts_used":0,"reasoning_stopped":true,"escalation_required":true},"send_permitted":false}'; exit 0;;
      refused) out '{"outcome":"refused","reason":"enrollment_not_valid_now"}'; exit 0;;
    esac
    printf '%s' "$request" > "$st/$rid"
    out "{\"outcome\":\"granted\",\"reservation_id\":\"$rid\",\"status\":\"open\"}"
    crash after_reserve;;
  begin-call)
    rid=$(str reservation_id); index=$(num call_index); inv="$rid/c$index"
    echo "begin-call $rid $index wall=$(num max_wall_ms) cost=$(num max_cost_micro_usd)" >> "$dir/la.log"
    [ -e "$st/$rid" ] || { out '{"outcome":"refused","reason":"unknown_reservation","send_permitted":false}'; exit 0; }
    if [ -e "$st/inv-$(key "$inv")" ]; then
      outcome=already_begun; [ "$(cat "$st/inv-$(key "$inv")")" = "$request" ] || outcome=conflict
      out "{\"outcome\":\"$outcome\",\"send_permitted\":false,\"invocation_id\":\"$inv\"}"; exit 0
    fi
    case "$(cat "$dir/la_begin" 2>/dev/null)" in
      exhausted) out '{"outcome":"exhausted","send_permitted":false,"exhausted":{"dimension":"cost"}}'; exit 0;;
      refused) out '{"outcome":"refused","reason":"reservation_frozen:timeout","send_permitted":false}'; exit 0;;
    esac
    printf '%s' "$request" > "$st/inv-$(key "$inv")"
    out "{\"outcome\":\"send_permitted\",\"send_permitted\":true,\"invocation_id\":\"$inv\",\"call_index\":$index}"
    crash after_begin;;
  settle)
    crash before_settle
    inv=$(str invocation_id); terminal=$(str terminal_class)
    [ -e "$st/inv-$(key "$inv")" ] || { out '{"outcome":"refused","reason":"unknown_invocation"}'; exit 0; }
    if [ "$terminal" = cancelled_unsent ] && { has usage || has actual_cost_usd || has provider_generation_id; }; then
      out '{"outcome":"refused","reason":"cancelled_unsent_with_provider_data"}'; exit 0
    fi
    source=ceiling_assumed
    [ "$terminal" = cancelled_unsent ] && source=unsent
    has usage && has actual_cost_usd && [ "$terminal" != cancelled_unsent ] && source=provider_reported
    record="$terminal $source in=$(num input_units) out=$(num output_units) cost=$(str actual_cost_usd) model=$(str reported_model)"
    escalation=false; [ -e "$dir/la_breach" ] && escalation=true
    if [ -e "$st/settle-$(key "$inv")" ]; then
      if [ "$(cat "$st/settle-$(key "$inv")")" = "$record" ]; then
        out "{\"outcome\":\"replayed\",\"settlement\":{\"receipt\":\"rcpt-$(key "$inv")\"},\"escalation_required\":$escalation}"
      else echo "settle-conflict $inv $terminal" >> "$dir/la.log"; out '{"outcome":"conflict","reason":"invocation already settled with a different payload"}'; fi
      exit 0
    fi
    settle_record "$inv" "$terminal" "$record"
    out "{\"outcome\":\"settled\",\"settlement\":{\"receipt\":\"rcpt-$(key "$inv")\",\"usage_source\":\"$source\"},\"escalation_required\":$escalation}"
    crash after_settle;;
  recover)
    rid=$(str reservation_id)
    unsent=$(printf '%s' "$request" | sed -n 's/.*"known_unsent":\[\([^]]*\)\].*/\1/p' | tr -d '"' | tr ',' ' ')
    settled=""
    for file in "$st"/inv-"$(key "$rid")"*_c*; do
      [ -e "$file" ] || continue
      inv=$(basename "$file" | sed 's/^inv-//; s/_c\([0-9]*\)$/\/c\1/')
      [ -e "$st/settle-$(key "$inv")" ] && continue
      class=crash_unknown; source=ceiling_assumed
      for u in $unsent; do [ "$u" = "$inv" ] && { class=cancelled_unsent; source=unsent; }; done
      settle_record "$inv" "$class" "$class $source in= out= cost= model="
      settled="$settled${settled:+,}{\"invocation_id\":\"$inv\",\"terminal_class\":\"$class\",\"source\":\"recovery\"}"
    done
    echo "recover ${rid:-all} unsent=[$unsent]" >> "$dir/la.log"
    out "{\"outcome\":\"recovered\",\"settled\":[$settled]}";;
  close)
    rid=$(str reservation_id)
    for file in "$st"/inv-"$(key "$rid")"_c*; do
      [ -e "$file" ] || continue
      inv=$(basename "$file" | sed 's/^inv-//; s/_c\([0-9]*\)$/\/c\1/')
      [ -e "$st/settle-$(key "$inv")" ] || { out '{"outcome":"refused","reason":"open_invocation"}'; exit 0; }
    done
    echo "close $rid" >> "$dir/la.log"
    out "{\"outcome\":\"closed\",\"reservation_id\":\"$rid\"}";;
  *) printf '{"v":1,"error":{"kind":"usage","message":"unknown command"}}\n'; exit 2;;
esac
