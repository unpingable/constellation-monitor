"""Disposable qualification provider derived from NQ's host diagnostic fixture."""

import datetime
import json
import os
import sys


request = json.load(sys.stdin)
echo = dict(request)
del echo["schema"]
observed_at = (
    datetime.datetime.now(datetime.timezone.utc)
    .isoformat(timespec="microseconds")
    .replace("+00:00", "Z")
)
binding = request["binding"]
capabilities = request["granted_capabilities"]
report = {
    "schema": "nq.evidence_report.v1",
    "profile": request["profile"],
    "binding": binding,
    "observed_at": observed_at,
    "status": "complete",
    "coverage": [
        {"kind": "host_identity", "state": "complete"},
        {"kind": "uptime", "state": "complete"},
        {"kind": "load", "state": "complete"},
    ],
    "observations": [
        {
            "ordinal": 0,
            "kind": "host_snapshot",
            "subject": binding["subject"],
            "observed_at": observed_at,
            "payload": {
                "evidence_basis": {
                    "scope": binding["scope"],
                    "vantage": binding["vantage"],
                    "access_path": "procfs_sysinfo",
                    "basis": "kernel_snapshot",
                    "regime": "normal",
                    "capabilities_used": capabilities,
                },
                "hostname": "diagnostic-fixture",
                "uptime_seconds": 3600,
                "cpu_count": 4,
                "load_1m": 1.0,
            },
        }
    ],
    "errors": [],
    "used_capabilities": capabilities,
    "backend": {
        "implementation": {"name": "host-diagnostic-fixture", "version": "1"},
        "tools": [],
    },
}

with open(os.environ["NQ_DIAGNOSTIC_TEST_MODE"], "r", encoding="utf-8") as source:
    mode = source.read().strip()

if mode == "present":
    # 12 / 4 = 3.0, above NQ's fixed 2.0 normalized-load threshold.
    report["observations"][0]["payload"]["load_1m"] = 12.0
elif mode == "partial":
    report["status"] = "partial"
    report["coverage"][2]["state"] = "partial"
    del report["observations"][0]["payload"]["load_1m"]
    report["errors"] = [
        {
            "code": "load_partial",
            "severity": "error",
            "message": "one-minute load was unavailable",
            "retriable": True,
        }
    ]
elif mode != "complete":
    raise SystemExit(f"unsupported qualification mode: {mode}")

response = {
    "schema": "nq.helper.response.v1",
    "echo": echo,
    "outcome": {"kind": "report", "report": report},
}
json.dump(response, sys.stdout, sort_keys=True, separators=(",", ":"))
sys.stdout.write("\n")
