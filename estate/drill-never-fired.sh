#!/bin/bash
# Drill the attention rules that had never fired (cartography #95 effectiveness). Run as root ON THE HOST.
# E host-disk: fill /mnt/zonestorage (only Driftwatch's paused store lives there) to ~91% with one fallocate
#   file, so NQ's fs-zonestorage watcher reports capacity pressure; delete it; expect trigger then resolve.
# F nq-no-fresh-acquisition and host-posture-unknown: stop the host-posture runner so its status object ages past
#   600 s; start it again; expect both to trigger, then resolve.
# memory-pressure is NOT drilled here: manufacturing a memory stall on a host with ~200 MB free risks real services.
set -uo pipefail
R=/root/supervision-drill/record-ef-$(date -u +%Y%m%dT%H%M%SZ); mkdir -p $R; exec > >(tee -a $R/drill.log) 2>&1
ts() { date -u +%FT%TZ; }
FILL=/mnt/zonestorage/.supervision-drill-fill
cleanup() { rm -f $FILL; systemctl start constellation-host-posture.service; }
trap cleanup EXIT
fired() { journalctl -u constellation-attention --since "@$T0" --no-pager -o cat | grep -o "\"action\":\"$1\",\"condition_id\":\"[^\"]*$2[^\"]*\"[^}]*\"outcome\":\"[a-z]*\"" | head -1; }
wait_for() { local limit=$1 what=$2; shift 2; local end=$(( $(date +%s) + limit ))
  while [ $(date +%s) -lt $end ]; do if [ -n "$("$@")" ]; then echo "[$(ts)] OK: $what"; return 0; fi; sleep 20; done
  echo "[$(ts)] FAILED: $what (not within ${limit} s)"; return 1; }

echo "== [$(ts)] start"
df -B1 --output=size,used,avail /mnt/zonestorage | tail -1 | tee $R/df-before.txt
read size used avail < $R/df-before.txt
need=$(( size * 91 / 100 - used )); [ $need -gt 0 ] && [ $need -lt $(( avail - 5*1024*1024*1024 )) ] || { echo "refusing: fill $need would leave under 5 GiB"; exit 70; }
T0=$(date +%s)
fallocate -l $need $FILL; df -h /mnt/zonestorage | tail -1
systemctl stop constellation-host-posture.service; echo "[$(ts)] fill placed (91%) and host-posture runner stopped"

wait_for 1500 "nq-no-fresh-acquisition trigger" fired trigger nq-no-fresh-acquisition
wait_for 600 "host-posture-unknown trigger" fired trigger host-posture-unknown
wait_for 1500 "host-disk trigger (zonestorage)" fired trigger host-disk
for r in nq-no-fresh-acquisition host-posture-unknown host-disk; do fired trigger $r; done

T1=$(date +%s); rm -f $FILL; systemctl start constellation-host-posture.service; echo "[$(ts)] fill removed, runner started"
T0=$T1
wait_for 900 "host-disk resolve" fired resolve host-disk
wait_for 900 "host-posture-unknown resolve" fired resolve host-posture-unknown
wait_for 900 "nq-no-fresh-acquisition resolve" fired resolve nq-no-fresh-acquisition
df -h /mnt/zonestorage | tail -1
echo "RECORD=$R"
