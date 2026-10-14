#!/usr/bin/env python3
"""Constellation estate collector: is every service we are responsible for up AND doing its job?

One pass reads the estate registry (JSON, `constellation.estate_registry/v1`), and for each service:
  runtime  - systemd ActiveState, or Docker State/Health
  status   - the project's own declared status producer (`project.ops.status/v1`, the `.ops/observation.toml`
             contract), a Labelwatch-recent watcher report, or an HTTP probe
  declared - an operator declaration such as a deliberate pause (with since and reason)
and writes one verdict per service to `constellation.estate/v1` (atomic JSON), which the attention evaluator,
the telemetry exporter and the dashboard read. Verdicts:
  DOWN      runtime not running
  DEGRADED  running, but a required concern is not PRESENT (missing required observation counts, as in
            Monitor's project-concern contract), or the probe failed
  PAUSED    declared paused by the operator (never alerts; shown with since/reason)
  UNKNOWN   status producer could not be run or returned an unrecognised document
  OK        running and every required concern PRESENT (or NOT_APPLICABLE)
Read-only towards services. Never shells out through a shell; argv is executed directly with a timeout.
"""
import argparse, json, os, subprocess, sys, tempfile, time, urllib.request
from datetime import datetime, timezone

REGISTRY_SCHEMA = "constellation.estate_registry/v1"
OUTPUT_SCHEMA = "constellation.estate/v1"
STATUS_SCHEMA = "project.ops.status/v1"
OK_STATES = {"PRESENT", "NOT_APPLICABLE"}
NAME_OK = set("abcdefghijklmnopqrstuvwxyz0123456789-")


def now_iso(t=None):
    return datetime.fromtimestamp(time.time() if t is None else t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run(argv, timeout, user=None, cwd=None, env=None, limit=1 << 20):
    if user:
        argv = ["setpriv", "--reuid", user, "--regid", user, "--init-groups", "--"] + argv
    full_env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LC_ALL": "C.UTF-8"}
    full_env.update(env or {})
    p = subprocess.run(argv, cwd=cwd, env=full_env, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
    return p.returncode, p.stdout[:limit], p.stderr[-2000:].decode("utf-8", "replace")


def runtime_state(spec, timeout):
    if "systemd" in spec:
        unit = spec["systemd"]
        rc, out, _ = run(["systemctl", "show", unit, "-p", "ActiveState,SubState,ActiveEnterTimestamp"], timeout)
        props = dict(line.split("=", 1) for line in out.decode().splitlines() if "=" in line)
        up = props.get("ActiveState") == "active"
        return {"kind": "systemd", "target": unit, "up": up,
                "state": "%s/%s" % (props.get("ActiveState", "?"), props.get("SubState", "?"))}
    if "docker" in spec:
        name = spec["docker"]
        rc, out, err = run(["docker", "inspect", "--format", "{{json .State}}", name], timeout)
        if rc != 0:
            return {"kind": "docker", "target": name, "up": False, "state": "absent"}
        st = json.loads(out)
        health = (st.get("Health") or {}).get("Status")
        up = bool(st.get("Running")) and health != "unhealthy"
        return {"kind": "docker", "target": name, "up": up,
                "state": st.get("Status", "?") + ("/" + health if health else "")}
    raise ValueError("runtime needs systemd or docker")


def project_status(spec, timeout):
    """Run a project.ops.status/v1 producer; return (concerns, error)."""
    rc, out, err = run(spec["argv"], spec.get("timeout_seconds", timeout), user=spec.get("user"),
                       cwd=spec.get("cwd"), env=spec.get("environment"))
    if rc != 0:
        return None, "producer exited %d: %s" % (rc, err.strip().splitlines()[-1] if err.strip() else "")
    doc = json.loads(out)
    if doc.get("schema", STATUS_SCHEMA) != STATUS_SCHEMA or not isinstance(doc.get("concerns"), list):
        return None, "producer output is not %s" % STATUS_SCHEMA
    concerns = []
    for c in doc["concerns"]:
        obs = c.get("observation") or {}
        concerns.append({"id": c.get("id"), "required": bool(c.get("required", True)),
                         "state": obs.get("local_state") or "ABSENT", "reason": obs.get("reason") or ""})
    return concerns, None


def recent_watch_status(spec):
    """Labelwatch-recent obligations watcher report: L1..L11 verdicts are the product's concerns."""
    path, max_age = spec["path"], spec.get("max_age_seconds", 900)
    with open(path) as fh:
        report = json.load(fh)
    at = datetime.strptime(report["evaluated_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    age = time.time() - at
    if age > max_age:
        return [{"id": "labelwatch-recent-watch.report", "required": True, "state": "STALE",
                 "reason": "watcher report is %d s old" % age}], None
    ignore = set(spec.get("advisory", []))
    out = []
    for oid, v in sorted((report.get("verdicts") or {}).items()):
        verdict = v["verdict"] if isinstance(v, dict) else v
        state = {"ok": "PRESENT", "skip": "NOT_APPLICABLE", "held": "NOT_APPLICABLE", "unknown": "UNKNOWN"}.get(verdict, "DEGRADED")
        out.append({"id": "labelwatch-recent." + oid, "required": oid not in ignore, "state": state,
                    "reason": verdict})
    return out, None


def http_status(spec, timeout):
    req = urllib.request.Request(spec["url"], headers={"User-Agent": "constellation-estate/1"})
    try:
        with urllib.request.urlopen(req, timeout=spec.get("timeout_seconds", timeout)) as r:
            code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
    want = spec.get("expect_status", 200)
    return [{"id": spec.get("concern", "http.health"), "required": True,
             "state": "PRESENT" if code == want else "DEGRADED",
             "reason": "HTTP %d from %s" % (code, spec["url"]) }], None


def evaluate(svc, timeout):
    out = {"name": svc["name"], "role": svc.get("role", ""), "declared": svc.get("declared")}
    try:
        out["runtime"] = runtime_state(svc["runtime"], timeout)
    except Exception as e:  # noqa: BLE001 - one service never stops the pass
        out["runtime"] = {"up": False, "state": "error", "error": str(e)[:300]}
    concerns, error = None, None
    st = svc.get("status")
    if st and out["runtime"].get("up"):
        try:
            kind = st["kind"]
            if kind == "project-ops-status":
                concerns, error = project_status(st, timeout)
            elif kind == "labelwatch-recent-watch":
                concerns, error = recent_watch_status(st)
            elif kind == "http":
                concerns, error = http_status(st, timeout)
            else:
                error = "unknown status kind %r" % kind
        except subprocess.TimeoutExpired:
            error = "status producer timed out"
        except Exception as e:  # noqa: BLE001
            error = "%s: %s" % (type(e).__name__, str(e)[:300])
    out["concerns"] = concerns or []
    failing = [c for c in out["concerns"] if c["required"] and c["state"] not in OK_STATES]
    declared = (svc.get("declared") or {}).get("state")
    if declared == "paused":
        verdict = "PAUSED"
        reason = "declared paused since %s: %s" % (svc["declared"].get("since", "?"), svc["declared"].get("reason", ""))
    elif not out["runtime"].get("up"):
        verdict, reason = "DOWN", "%s %s is %s" % (out["runtime"].get("kind", ""), out["runtime"].get("target", ""), out["runtime"].get("state"))
    elif error:
        verdict, reason = "UNKNOWN", error
    elif failing:
        verdict = "DEGRADED"
        reason = "; ".join("%s %s" % (c["id"].split(".", 1)[-1], c["state"]) for c in failing)
    else:
        required = sum(1 for c in out["concerns"] if c["required"])
        verdict, reason = "OK", "running" + (", %d required concerns present" % required if required else "")
    out["verdict"], out["reason"] = verdict, reason[:400]
    out["failing"] = [c["id"] for c in failing]
    return out


def validate(reg):
    if reg.get("schema") != REGISTRY_SCHEMA:
        raise ValueError("registry schema must be " + REGISTRY_SCHEMA)
    names = set()
    for svc in reg["services"]:
        n = svc["name"]
        if not n or len(n) > 48 or set(n) - NAME_OK or n in names:
            raise ValueError("service names must be unique lowercase tokens: %r" % n)
        names.add(n)
        if not ({"systemd", "docker"} & set(svc["runtime"])):
            raise ValueError("%s: runtime needs systemd or docker" % n)


def write_atomic(path, doc):
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".estate-")
    with os.fdopen(fd, "w") as fh:
        json.dump(doc, fh, indent=1, sort_keys=True)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--registry", default="/etc/constellation-estate/estate.json")
    ap.add_argument("--output", default="/var/lib/constellation-estate/estate.json")
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--print", action="store_true")
    a = ap.parse_args(argv)
    with open(a.registry) as fh:
        reg = json.load(fh)
    validate(reg)
    started = time.time()
    try:
        with open(a.output) as fh:
            previous = {s["name"]: s for s in json.load(fh).get("services", [])}
    except (OSError, ValueError):
        previous = {}
    services = []
    for svc in reg["services"]:
        s = evaluate(svc, a.timeout)
        prev = previous.get(s["name"])
        s["since"] = prev["since"] if prev and prev.get("verdict") == s["verdict"] and prev.get("since") else now_iso(started)
        services.append(s)
    doc = {"schema": OUTPUT_SCHEMA, "site": reg.get("site", ""), "generated_at": now_iso(),
           "duration_seconds": round(time.time() - started, 3), "services": services,
           "counts": {v: sum(1 for s in services if s["verdict"] == v) for v in ("OK", "DEGRADED", "DOWN", "PAUSED", "UNKNOWN")}}
    write_atomic(a.output, doc)
    if a.print:
        for s in services:
            print("%-9s %-24s %s" % (s["verdict"], s["name"], s["reason"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
