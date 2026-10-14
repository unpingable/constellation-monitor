#!/bin/bash
# Acceptance drill for incident continuity (cartography #93). Run as root ON THE HOST (as a supervision-drill-* unit).
#   1 the canary cannot start (drop-in), then is stopped: one incident despite repeated failing observations;
#     the remediation consumer's authorized restart fails and is recorded; the operator is told
#   2 the attention evaluator is stopped mid-incident and restarted: incident and history survive
#   3 the definition changes (a declared suspension of service-down for the canary): the incident stays open
#   4 the drop-in is removed and the canary started, the suspension lifted: verified recovery closes the incident
#   5 one query reconstructs the sequence
set -uo pipefail
R=/root/supervision-drill/record-incident-$(date -u +%Y%m%dT%H%M%SZ); mkdir -p $R; exec > >(tee -a $R/drill.log) 2>&1
ts() { date -u +%FT%TZ; }
U=attention-canary.service; DROP=/etc/systemd/system/$U.d/zz-drill-cannot-start.conf; CFG=/etc/constellation-attention/attention.toml
KEY=constellation:labelwatch:service:service-down:attention-canary.service; INC=inc-e048fb3e
cp -a $CFG $R/attention.toml.before
cleanup() { rm -f $DROP; systemctl daemon-reload; cp -a $R/attention.toml.before $CFG; systemctl start constellation-attention.timer constellation-incidents.timer; systemctl start $U; }
trap cleanup EXIT
inc_field() { constellation-incidents show $INC 2>/dev/null | sed -n "$1"; }
wait_for() { local limit=$1 what=$2; shift 2; local end=$(( $(date +%s) + limit ))
  while [ $(date +%s) -lt $end ]; do if "$@" >/dev/null 2>&1; then echo "[$(ts)] OK: $what"; return 0; fi; sleep 20; done
  echo "[$(ts)] FAILED: $what (not within ${limit} s)"; return 1; }
has() { constellation-incidents show $INC | grep -q "$1"; }

echo "== [$(ts)] 1 failure the remediation cannot fix"
install -d /etc/systemd/system/$U.d; printf '[Service]\n# supervision drill: the canary cannot start\nExecStartPre=/bin/false\n' > $DROP; systemctl daemon-reload
systemctl stop $U; echo "[$(ts)] canary stopped and unable to start"
wait_for 600 "incident opened" has "detected"
wait_for 900 "remediation attempt recorded" has "remediation"
wait_for 900 "remediation failure recorded and operator needed" bash -c "constellation-incidents show $INC | grep -q 'needs you: remediation failed'"
constellation-incidents show $INC | head -12
echo "incidents for the key: $(sqlite3 -readonly /var/lib/constellation-incidents/incidents.sqlite "select count(*) from incident where key='$KEY'" 2>/dev/null || python3 -c "import sqlite3;print(sqlite3.connect('file:/var/lib/constellation-incidents/incidents.sqlite?mode=ro',uri=True).execute(\"select count(*) from incident where key='$KEY'\").fetchone()[0])")"

echo; echo "== [$(ts)] 2 evaluator stopped mid-incident, then restarted"
systemctl stop constellation-attention.timer; sleep 150; systemctl start constellation-attention.timer; echo "[$(ts)] evaluator timer restarted"
wait_for 300 "incident still open after the restart" bash -c "constellation-incidents show $INC | head -1 | grep -qv resolved"

echo; echo "== [$(ts)] 3 definition changed: service-down suspended for the canary"
printf '\n[[suspensions]]\nrule = "service-down"\ntarget = "attention-canary.service"\nowner = "drill"\nreason = "incident-continuity drill: definition change mid-incident"\nresume_when = "the drill lifts it"\nsince = "%s"\n' "$(date -u +%F)" >> $CFG
sudo -u nq constellation-attention check-config --config $CFG >/dev/null && echo "suspension accepted"
wait_for 300 "suspension recorded, incident still open" has "suspended"
constellation-incidents | sed -n '1,12p'

echo; echo "== [$(ts)] 4 restore the service, lift the suspension"
rm -f $DROP; systemctl daemon-reload; systemctl start $U; cp -a $R/attention.toml.before $CFG; echo "[$(ts)] canary running, definition restored"
wait_for 900 "incident recovering" has "recovering"
wait_for 900 "incident resolved by verified recovery" has "resolved .*verified=True"

echo; echo "== [$(ts)] 5 one query"
constellation-incidents show $INC
echo "RECORD=$R"
