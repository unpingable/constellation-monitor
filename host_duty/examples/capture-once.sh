#!/bin/bash
# One optional local NQ custody occurrence; neither a daemon nor a health check.
set -euo pipefail
umask 077
[[ $# -eq 6 ]] || { echo 'usage: capture-once.sh SNAPSHOT HOST INSTANCE REFERENCE NQ_CONFIG OUTPUT_ROOT' >&2; exit 2; }
snapshot_path=$1 host_id=$2 instance_id=$3 reference=$4 nq_config=$5 output_root=$6
recipe_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
evaluation_id="custody-$(/usr/bin/python3 -I -c 'import uuid; print(uuid.uuid4().hex)')"
occurrence_dir="$output_root/$evaluation_id"
preparation=$(/usr/bin/python3 -I "$recipe_dir/snapshot_custody.py" prepare \
    --snapshot "$snapshot_path" --host "$host_id" --instance "$instance_id" \
    --reference "$reference" --evaluation-id "$evaluation_id" --directory "$occurrence_dir") || { printf '%s\n' "$preparation"; exit 3; }
printf '%s\n' "$preparation"
publication_assertion=$(/usr/bin/python3 -I -c 'import json,sys; print(json.loads(sys.argv[1])["publication_assertion"])' "$preparation")
snapshot_path=$(/usr/bin/python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["snapshot_path"])' "$occurrence_dir/expected.json")
/usr/bin/timeout --kill-after=2s 15s /usr/bin/nq --config "$nq_config" --json \
    saved-check install --definition "$occurrence_dir/definition.json" > "$occurrence_dir/install.json"
/usr/bin/timeout --kill-after=2s 15s /usr/bin/nq --config "$nq_config" --json \
    saved-check evaluate "$reference" --evaluation-id "$evaluation_id" \
    --target "$snapshot_path" --source-observed-at "$publication_assertion" > "$occurrence_dir/evaluate.json"
/usr/bin/timeout --kill-after=2s 15s /usr/bin/nq --config "$nq_config" --json \
    saved-check result --evaluation-id "$evaluation_id" > "$occurrence_dir/result.json"
/usr/bin/python3 -I "$recipe_dir/snapshot_custody.py" inspect \
    --expected "$occurrence_dir/expected.json" --install "$occurrence_dir/install.json" \
    --result "$occurrence_dir/result.json" | /usr/bin/tee "$occurrence_dir/inspection.json"
