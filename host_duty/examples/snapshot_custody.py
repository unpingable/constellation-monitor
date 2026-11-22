#!/usr/bin/env python3
"""Prepare one snapshot-custody request or inspect an NQ-verified retained row.

This optional caller reads only the public snapshot. NQ owns claim/digest
verification. A confirmed custody tuple says nothing about host health or work.
"""
import argparse
from contextlib import closing
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import struct
import sys
import time

SCHEMA = "constellation.host_duty_observation.v1"
COLUMNS = ["schema", "host_id", "instance_id", "boot_id", "source_observed_at", "source_state",
           "source_sha256", "source_detail", "telemetry_json", "exported_at"]
SQL = "SELECT " + ",".join(COLUMNS) + " FROM host_duty_observations"


def _token(value, maximum):
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:@+-]*", value):
        raise ValueError("invalid logical identity or occurrence reference")
    return value


def _cell(value):
    if value is None:
        return {"type":"null"}
    if isinstance(value, str):
        return {"type":"text", "value":value}
    if type(value) is float and math.isfinite(value):
        return {"type":"real", "value":struct.pack(">d", value).hex()}
    if type(value) is int:
        return {"type":"integer", "value":str(value)}
    raise ValueError("unsupported snapshot scalar")


def publication_assertion(value):
    if type(value) is not float or not math.isfinite(value) or value < 0:
        raise ValueError("snapshot publication time is unavailable")
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="microseconds")


def prepare(snapshot, host, instance, reference, evaluation_id):
    _token(host, 48); _token(instance, 128)
    _token(reference, 256); _token(evaluation_id, 256)
    snapshot = Path(snapshot).resolve(strict=True)
    info = snapshot.stat()
    if not snapshot.is_file() or info.st_size > 65536 or info.st_mode & 0o222:
        raise ValueError("input must be a bounded read-only snapshot")
    deadline = time.monotonic()+2
    with closing(sqlite3.connect(snapshot.as_uri()+"?mode=ro&immutable=1", uri=True, timeout=0.25)) as connection:
        connection.set_progress_handler(lambda:time.monotonic() >= deadline, 1000)
        rows = connection.execute(SQL + " LIMIT 2").fetchall()
    if len(rows) != 1:
        raise ValueError("snapshot must contain exactly one singleton observation row")
    row = list(rows[0])
    if row[:3] != [SCHEMA, host, instance]:
        raise ValueError("snapshot schema, logical host or incarnation differs")
    if row[5] not in {"reachable", "unreachable", "unknown", "missing"}:
        raise ValueError("unsupported observer state")
    publication_assertion(row[9])
    if row[4] is not None and (type(row[4]) is not float or not math.isfinite(row[4])):
        raise ValueError("invalid original source time")
    definition = {"schema":"nq.saved-check-definition/v1", "reference":reference,
        "source_identity":SCHEMA+"/"+host+"/"+instance, "currentness_seconds":60,
        "name":"snapshot-custody "+host+"/"+instance, "sql_text":SQL,
        "mode":"empty", "threshold":None, "column":None,
        "description":"Ordinary Monitor snapshot custody; no target freshness, host health, work completion or action claim.",
        "row_evidence":"selected_rows_v1"}
    return {"evaluation_id":evaluation_id, "snapshot_path":str(snapshot), "definition":definition, "values":row}


def inspect_result(expected, installed, result):
    def uncertain(reason):
        return {"disposition":"indeterminate", "reason":reason,
            "evaluation_id":expected["evaluation_id"], "nq_outcome":result.get("outcome")}

    if result.get("evaluation_id") != expected["evaluation_id"]:
        return uncertain("evaluation_identity_mismatch")
    if result.get("outcome") != "passed" or result.get("indeterminate"):
        return uncertain("nq_not_settled_pass")
    inspection = result.get("row_evidence_inspection") or {}
    if inspection.get("state") != "valid":
        return uncertain("native_row_evidence_not_valid")
    definition = expected["definition"]
    values = expected["values"]
    if not isinstance(values, list) or len(values) != len(COLUMNS) or values[0] != SCHEMA:
        return uncertain("caller_tuple_unavailable")
    identity = SCHEMA+"/"+values[1]+"/"+values[2]
    if definition["source_identity"] != identity:
        return uncertain("logical_source_identity_mismatch")
    assertion = publication_assertion(values[9])
    digest = installed.get("definition_digest")
    if installed.get("reference") != definition["reference"] or not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        return uncertain("installed_definition_unavailable")
    binding = {"definition_digest":digest, "target_reference":expected["snapshot_path"],
        "source_identity":identity, "currentness_seconds":60,
        "source_observed_at_assertion":assertion}
    detail = result.get("detail") or {}
    if detail.get("binding") != binding:
        return uncertain("retained_request_binding_mismatch")
    payload = (detail.get("row_evidence") or {}).get("payload") or {}
    if payload.get("schema") != "nq.saved-check-selected-rows/v1" or payload.get("columns") != COLUMNS:
        return uncertain("retained_columns_unavailable")
    if payload.get("rows") != [[_cell(value) for value in values]]:
        return uncertain("publication_tuple_mismatch")
    return {"disposition":"custody_confirmed", "evaluation_id":expected["evaluation_id"],
        "scope":"ordinary snapshot custody; no host-health, target-freshness, completed-work or action claim",
        "publication_assertion":assertion,
        "nq_read_attempted_at":detail.get("read_attempted_at"),
        "payload_sha256":inspection.get("payload_sha256"),
        "observer_testimony":dict(zip(COLUMNS, values))}


def _load(path):
    with open(path, "rb") as source:
        raw = source.read(262145)
    if len(raw) > 262144:
        raise ValueError("receipt exceeds the example's 256 KiB input bound")
    def reject(_):
        raise ValueError("non-finite JSON value")
    return json.loads(raw, parse_constant=reject)


def _write(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as output:
        json.dump(value, output, allow_nan=False, sort_keys=True, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    start = commands.add_parser("prepare")
    for name in ("snapshot", "host", "instance", "reference", "evaluation-id", "directory"):
        start.add_argument("--"+name, required=True)
    check = commands.add_parser("inspect")
    for name in ("expected", "install", "result"):
        check.add_argument("--"+name, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            expected = prepare(args.snapshot, args.host, args.instance, args.reference, args.evaluation_id)
            directory = Path(args.directory)
            if not directory.is_absolute():
                raise ValueError("occurrence directory must be absolute")
            directory.mkdir(mode=0o700)
            _write(directory/"expected.json", expected)
            _write(directory/"definition.json", expected["definition"])
            result = {"disposition":"prepared", "evaluation_id":args.evaluation_id, "directory":str(directory),
                      "publication_assertion":publication_assertion(expected["values"][9])}
        else:
            result = inspect_result(_load(args.expected), _load(args.install), _load(args.result))
        print(json.dumps(result, allow_nan=False, sort_keys=True))
        return 0 if result["disposition"] in {"prepared", "custody_confirmed"} else 3
    except (OSError, ValueError, TypeError, KeyError, sqlite3.Error) as exc:
        print(json.dumps({"disposition":"indeterminate", "reason":str(exc)[:300]}))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
