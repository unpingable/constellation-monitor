#!/bin/bash
# Supervision drill, part 2 (cartography #90). Run as root ON THE HOST.
# C: degraded by its own contract. A running drill service whose project.ops.status/v1 producer reports a required
#    concern DEGRADED. Expect estate DEGRADED (not DOWN), a Slack notice after 600 s naming the concern, and a
#    resolve once the concern is PRESENT again.
# D: dead supervision input. Stop the estate collector. Expect the evaluator's evaluator-input-unavailable
#    (estate.stale) notice on the Linode, and crow's EstateCollectorStale alert from outside; both resolve when
#    the collector runs again.
# Notices are read from the evaluator's journal (settled intent files are pruned at once).
set -uo pipefail
R=/root/supervision-drill/record-cd-$(date -u +%Y%m%dT%H%M%SZ); mkdir -p $R; exec > >(tee -a $R/drill.log) 2>&1
ts() { date -u +%FT%TZ; }
sent() { journalctl -u constellation-attention --since "@$2" --no-pager -o cat | grep -q "\"action\":\"$1\",\"condition_id\":\"[^\"]*:$3\".*\"outcome\":\"accepted\""; }
summary() { journalctl -u constellation-attention --since "@$2" --no-pager -o cat | grep -o "\"action\":\"$1\",\"condition_id\":\"[^\"]*:$3\"[^}]*" | head -1 | cut -c1-300; }
wait_for() { local limit=$1 what=$2; shift 2; local end=$(( $(date +%s) + limit ))
  while [ $(date +%s) -lt $end ]; do if "$@" >/dev/null 2>&1; then echo "[$(ts)] OK: $what"; return 0; fi; sleep 15; done
  echo "[$(ts)] FAILED: $what (not within ${limit} s)"; return 1; }
verdict() { python3 -c "import json,sys;print([(s['verdict'],s['reason']) for s in json.load(open('/var/lib/constellation-estate/estate.json'))['services'] if s['name']=='$1'])"; }
REG=/etc/constellation-estate/estate.json; cp -a $REG $R/estate.json.before

echo "== [$(ts)] setup"
cat > /usr/local/lib/constellation-estate/drill-status.py <<'PY'
#!/usr/bin/env python3
"""Drill producer: project.ops.status/v1 with one required concern, DEGRADED while /run/estate-drill/degraded exists."""
import json, os, datetime
bad = os.path.exists("/run/estate-drill/degraded")
now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
print(json.dumps({"schema": "project.ops.status/v1", "project": "estate-drill", "generated_at": now, "concerns": [
    {"id": "estate-drill.work.progress", "required": True, "description": "the drill service is making progress",
     "observation": {"local_state": "DEGRADED" if bad else "PRESENT", "observed_at": now, "valid_for_seconds": 300,
                     "reason": "drill flag set: work is not progressing" if bad else "progressing"}}]}))
PY
chmod 0755 /usr/local/lib/constellation-estate/drill-status.py; install -d /run/estate-drill
cat > /etc/systemd/system/estate-drill.service <<'U'
[Unit]
Description=Supervision drill target (sleeps; its status producer is the drill)
[Service]
ExecStart=/bin/sleep infinity
DynamicUser=yes
U
systemctl daemon-reload; systemctl start estate-drill.service
python3 - <<'PY'
import json; p = "/etc/constellation-estate/estate.json"; d = json.load(open(p))
d["services"] = [s for s in d["services"] if s["name"] != "estate-drill"] + [{"name": "estate-drill", "role": "supervision drill target",
    "runtime": {"systemd": "estate-drill.service"},
    "status": {"kind": "project-ops-status", "argv": ["/usr/bin/python3", "/usr/local/lib/constellation-estate/drill-status.py"]}}]
json.dump(d, open(p, "w"), indent=1)
PY
systemctl start constellation-estate-collect.service; verdict estate-drill

echo; echo "== [$(ts)] C: degraded by its own contract"
C0=$(date +%s); touch /run/estate-drill/degraded; echo "[$(ts)] concern flipped to DEGRADED (service still running)"
systemctl start constellation-estate-collect.service; verdict estate-drill
wait_for 1000 "Slack notice for estate-drill accepted" sent trigger $C0 estate-drill; echo "detection to notice: $(( $(date +%s) - C0 )) s"
summary trigger $C0 estate-drill
journalctl -u constellation-attention --since "@$C0" --no-pager -o cat | grep -o 'Now: [^"]*' | head -1
C1=$(date +%s); rm -f /run/estate-drill/degraded; echo "[$(ts)] concern PRESENT again"; systemctl start constellation-estate-collect.service; verdict estate-drill
wait_for 600 "resolve for estate-drill accepted" sent resolve $C1 estate-drill

echo; echo "== [$(ts)] D: dead supervision input (estate collector stopped)"
D0=$(date +%s); systemctl stop constellation-estate-collect.timer; echo "[$(ts)] collector timer stopped"
wait_for 1500 "evaluator notices its estate input is stale" sent trigger $D0 estate.stale; echo "input death to notice: $(( $(date +%s) - D0 )) s"
summary trigger $D0 estate.stale
D1=$(date +%s); systemctl start constellation-estate-collect.timer; systemctl start constellation-estate-collect.service; echo "[$(ts)] collector restored"
wait_for 600 "resolve for estate.stale accepted" sent resolve $D1 estate.stale

echo; echo "== [$(ts)] cleanup"
cp -a $R/estate.json.before $REG; systemctl stop estate-drill.service; rm -f /etc/systemd/system/estate-drill.service /usr/local/lib/constellation-estate/drill-status.py; rm -rf /run/estate-drill
systemctl daemon-reload; systemctl start constellation-estate-collect.service
echo "D window for crow's EstateCollectorStale: $(date -u -d @$D0 +%FT%TZ) .. $(date -u -d @$D1 +%FT%TZ)"
echo "RECORD=$R"
