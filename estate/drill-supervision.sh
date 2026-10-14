#!/bin/bash
# End-to-end supervision drill on labelwatch-host. Run as root ON THE HOST after the NQ rollover and the estate deploy.
# A: remediation path. Stop attention-canary.service (policy auto_remediate_then_page, window 300 s). Expect NQ service-down
#    detection, the remediation consumer to restart it inside the window, the condition to resolve, no escalation.
# B: notification path. Stop estate-drill.service (a sleep unit with no remediation authority). Expect estate DOWN, a Slack
#    notice after 600 s naming the unit, then a resolve notice after it is started again.
# Every observation is timestamped into the record; the script never edits Constellation state by hand.
set -uo pipefail
R=/root/supervision-drill/record-$(date -u +%Y%m%dT%H%M%SZ); mkdir -p $R; exec > >(tee -a $R/drill.log) 2>&1
ts() { date -u +%FT%TZ; }
report() { sudo -u nq python3 - "$1" <<'PY'
import json, sys
r = json.load(open("/var/lib/constellation-attention/report.json")); want = sys.argv[1]
conds = [c for c in r["conditions"] if c["id"].endswith(":" + want) and c["observation"] != "absent"]
ints = [(i["action"], i["route_role"], i["outcome"]) for i in r["intents"] if i["condition_id"].endswith(":" + want)]
print(r["evaluated_at"], [(c["rule"], c["observation"], c["active"], c.get("remediation_window_until")) for c in conds], ints)
PY
}
wait_for() { # wait_for <seconds> <description> <test command...>
  local limit=$1 what=$2; shift 2; local end=$(( $(date +%s) + limit ))
  while [ $(date +%s) -lt $end ]; do if "$@" >/dev/null 2>&1; then echo "[$(ts)] OK: $what"; return 0; fi; sleep 15; done
  echo "[$(ts)] FAILED: $what (not within ${limit} s)"; return 1; }
# Intents are read from the evaluator's journal: intent files of a settled condition are pruned at once.
sent() { journalctl -u constellation-attention --since "@$2" --no-pager -o cat | grep -q "\"action\":\"$1\",\"condition_id\":\"[^\"]*:$3\".*\"outcome\":\"accepted\""; }

echo "== [$(ts)] preflight"
systemctl is-active attention-canary.service nqd-ops.service constellation-host-posture.service constellation-attention.timer constellation-remediation-consumer.timer constellation-estate-collect.timer | paste -sd" "
report attention-canary.service

echo; echo "== [$(ts)] A: remediation path (attention-canary)"
A0=$(date +%s); systemctl stop attention-canary.service; echo "[$(ts)] stopped attention-canary.service"
wait_for 300 "attention sees service-down for the canary" bash -c "sudo -u nq grep -q '\"constellation:labelwatch:service:service-down:attention-canary.service\"' /var/lib/constellation-attention/report.json && sudo -u nq python3 -c \"import json,sys;r=json.load(open('/var/lib/constellation-attention/report.json'));sys.exit(0 if any(c['id'].endswith('attention-canary.service') and c['rule']=='service-down' and c['observation']=='present' for c in r['conditions']) else 1)\""
report attention-canary.service
wait_for 420 "canary restarted (by the remediation consumer)" systemctl is-active --quiet attention-canary.service
A1=$(date +%s); echo "canary down for $((A1-A0)) s"
journalctl -u constellation-remediation-consumer --since "@$A0" --no-pager -o cat | grep -E '"result"' | grep -v abstained | tail -5
wait_for 420 "service-down for the canary clear and not active" sudo -u nq python3 -c "import json,sys;r=json.load(open('/var/lib/constellation-attention/report.json'));sys.exit(0 if not any(c['id'].endswith('attention-canary.service') and c['rule']=='service-down' and c['active'] for c in r['conditions']) else 1)"
report attention-canary.service
echo "canary notices since the stop:"; journalctl -u constellation-attention --since "@$A0" --no-pager -o cat | grep -o '"action":"[a-z]*","condition_id":"[^"]*attention-canary[^"]*"' | sort | uniq -c

echo; echo "== [$(ts)] B: notification path (estate-drill, no remediation authority)"
cat > /etc/systemd/system/estate-drill.service <<'U'
[Unit]
Description=Supervision drill target (sleeps; stopping it is the drill)
[Service]
ExecStart=/bin/sleep infinity
DynamicUser=yes
U
systemctl daemon-reload; systemctl start estate-drill.service
cp -a /etc/constellation-estate/estate.json $R/estate.json.before
python3 - <<'PY'
import json; p = "/etc/constellation-estate/estate.json"; d = json.load(open(p))
if not any(s["name"] == "estate-drill" for s in d["services"]):
    d["services"].append({"name": "estate-drill", "role": "supervision drill target", "runtime": {"systemd": "estate-drill.service"}})
json.dump(d, open(p, "w"), indent=1)
PY
systemctl start constellation-estate-collect.service
B0=$(date +%s); systemctl stop estate-drill.service; echo "[$(ts)] stopped estate-drill.service"
systemctl start constellation-estate-collect.service
python3 -c 'import json;print([ (s["verdict"],s["reason"]) for s in json.load(open("/var/lib/constellation-estate/estate.json"))["services"] if s["name"]=="estate-drill"])'
wait_for 900 "Slack notice for estate-drill accepted" sent trigger $B0 estate-drill
B1=$(date +%s); echo "detection to notice: $((B1-B0)) s"; report estate-drill
sudo -u nq python3 -c "import json;s=json.load(open('/var/lib/constellation-attention/state.json'));c=[v for k,v in s['conditions'].items() if k.endswith(':estate-drill')];print(c[0]['last_intent'] if c else 'no state')" | cut -c1-400
systemctl start estate-drill.service; echo "[$(ts)] started estate-drill.service"; systemctl start constellation-estate-collect.service
wait_for 600 "resolve notice for estate-drill accepted" sent resolve $B0 estate-drill
report estate-drill

echo; echo "== [$(ts)] cleanup"
cp -a $R/estate.json.before /etc/constellation-estate/estate.json; systemctl stop estate-drill.service; rm -f /etc/systemd/system/estate-drill.service; systemctl daemon-reload
systemctl start constellation-estate-collect.service
echo "RECORD=$R"
