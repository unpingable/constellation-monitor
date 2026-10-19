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
import argparse, fnmatch, hashlib, json, os, shutil, subprocess, sys, tempfile, time, urllib.request
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


def parse_concerns(path):
    """Required concern ids of a project.concerns/v1 file. Minimal reader for the [[concerns]] id/required keys
    (the host has Python 3.10, without tomllib); anything it cannot read is an error, never an empty contract."""
    ids, current = [], None
    with open(path) as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip()
            if line == "[[concerns]]":
                current = {"required": True}; ids.append(current)
            elif line.startswith("[") :
                current = None
            elif current is not None and "=" in line:
                key, value = (x.strip() for x in line.split("=", 1))
                if key == "id":
                    current["id"] = value.strip('"')
                elif key == "required":
                    current["required"] = value == "true"
    if not ids or any("id" not in c for c in ids):
        raise ValueError("no readable [[concerns]] in %s" % path)
    return [c["id"] for c in ids if c["required"]]


def unit_props(unit, timeout, props):
    rc, out, _ = run(["systemctl", "show", unit, "-p", ",".join(props)], timeout)
    return dict(line.split("=", 1) for line in out.decode().splitlines() if "=" in line)


def timer_concern(spec, timeout):
    """A timer is part of its service's job: armed, and its last run did not fail (unless result checks are off)."""
    spec = {"unit": spec} if isinstance(spec, str) else spec
    t = unit_props(spec["unit"], timeout, ["ActiveState", "Unit", "LastTriggerUSec"])
    svc = unit_props(t.get("Unit", ""), timeout, ["Result", "ExecMainStatus", "ActiveState"]) if t.get("Unit") else {}
    ok_status = [str(x) for x in spec.get("ok_status", [0])]
    if t.get("ActiveState") != "active":
        state, reason = "DEGRADED", "timer %s is %s" % (spec["unit"], t.get("ActiveState", "?"))
    elif spec.get("check_result", True) and svc.get("ActiveState") == "failed" and svc.get("ExecMainStatus") not in ok_status:
        state, reason = "DEGRADED", "last run of %s failed (status %s)" % (t.get("Unit"), svc.get("ExecMainStatus"))
    else:
        state, reason = "PRESENT", "armed; last trigger %s" % (t.get("LastTriggerUSec") or "never")
    return {"id": "timer." + spec["unit"], "required": True, "state": state, "reason": reason}


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
    now = time.time()
    for c in doc["concerns"]:
        obs = c.get("observation") or {}
        state, reason = obs.get("local_state") or "ABSENT", obs.get("reason") or ""
        # the observation's own time and validity travel with it: a fresh estate document must not refresh old evidence
        observed_at, valid_for = obs.get("observed_at"), obs.get("valid_for_seconds")
        if observed_at and isinstance(valid_for, (int, float)) and valid_for > 0:
            try:
                at = datetime.strptime(observed_at[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
                if now - at > valid_for and state in ("PRESENT", "NOT_APPLICABLE"):
                    state, reason = "STALE", "observation %ds old exceeds its %ds validity; was %s: %s" % (now - at, valid_for, obs.get("local_state"), reason)
            except ValueError:
                state, reason = "UNKNOWN", "observed_at %r is not a timestamp" % observed_at
        concerns.append({"id": c.get("id"), "required": bool(c.get("required", True)), "state": state, "reason": reason,
                         "observed_at": observed_at, "valid_for_seconds": valid_for})
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
    # Declared means acquired: every required concern of the service's contract must have been observed.
    contract = svc.get("contract") or {}
    if contract.get("concerns") and out["runtime"].get("up") and not error:
        try:
            with open(contract["concerns"], "rb") as fh:
                digest = "sha256:" + hashlib.sha256(fh.read()).hexdigest()
            if contract.get("sha256") and digest != contract["sha256"]:
                out["concerns"].append({"id": "contract.revision", "required": True, "state": "DEGRADED",
                                        "reason": "contract drift: %s is %s, registry pins %s" % (contract["concerns"], digest[:19], contract["sha256"][:19])})
            acquired = {c["id"] for c in out["concerns"]}
            for cid in parse_concerns(contract["concerns"]):
                if cid not in acquired:
                    out["concerns"].append({"id": cid, "required": True, "state": "MISSING_REQUIRED_OBSERVATION",
                                            "reason": "declared in %s, not acquired" % contract["concerns"]})
        except Exception as e:  # noqa: BLE001 - an unreadable contract is a failure, not an empty one
            error = "contract unreadable: %s" % str(e)[:200]
    for spec in svc.get("timers", []):
        try:
            out["concerns"].append(timer_concern(spec, timeout))
        except Exception as e:  # noqa: BLE001
            out["concerns"].append({"id": "timer." + str(spec), "required": True, "state": "UNKNOWN", "reason": str(e)[:200]})
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


def coverage(reg, timeout):
    """Deterministic completeness: every enabled or running service unit and every running container is either
    supervised (a registry runtime target) or explicitly unsupervised (an `unsupervised` glob with a reason).
    Anything else is reported, so an unregistered workload is a visible failure, not a silent gap."""
    targets = {"systemd": set(), "docker": set(), "timer": set()}
    for s in reg["services"]:
        for kind in ("systemd", "docker"):
            if kind in s["runtime"]:
                targets[kind].add(s["runtime"][kind])
        for spec in s.get("timers", []):
            targets["timer"].add(spec if isinstance(spec, str) else spec["unit"])
    excluded = reg.get("unsupervised") or {}
    found = {"systemd": set(), "docker": set(), "timer": set()}
    rc, out, err = run(["systemctl", "list-units", "--type=timer", "--state=active", "--no-legend", "--plain"], timeout)
    if rc != 0:
        raise RuntimeError("systemctl list-units --type=timer failed")
    found["timer"].update(line.split()[0] for line in out.decode().splitlines() if line.strip())
    for args in (["list-unit-files", "--type=service", "--state=enabled"], ["list-units", "--type=service", "--state=running"]):
        rc, out, err = run(["systemctl"] + args + ["--no-legend", "--plain"], timeout)
        if rc != 0:
            raise RuntimeError("systemctl %s failed" % args[0])
        found["systemd"].update(line.split()[0] for line in out.decode().splitlines() if line.strip())
    # A host without Docker runs no containers; only a registry that declares containers needs it to answer.
    if targets["docker"] or shutil.which("docker", path="/usr/local/bin:/usr/bin:/bin"):
        rc, out, err = run(["docker", "ps", "--format", "{{.Names}}"], timeout)
        if rc != 0:
            raise RuntimeError("docker ps failed")
        found["docker"].update(out.decode().split())
    unregistered = []
    # A supervised unit whose working directory declares an .ops contract must acquire it (or waive it with a reason).
    for s in reg["services"]:
        unit = s["runtime"].get("systemd")
        if not unit or (s.get("contract") or {}).get("concerns") or (s.get("contract") or {}).get("waived"):
            continue
        wd = unit_props(unit, timeout, ["WorkingDirectory"]).get("WorkingDirectory", "")
        if wd and os.path.isfile(os.path.join(wd, ".ops", "concerns.toml")):
            unregistered.append("contract:%s:%s/.ops" % (s["name"], wd))
    for kind in ("systemd", "docker", "timer"):
        globs = [e["match"] for e in excluded.get(kind, [])]
        for name in sorted(found[kind] - targets[kind]):
            if not any(fnmatch.fnmatchcase(name, g) for g in globs):
                unregistered.append("%s:%s" % (kind, name))
    return unregistered


def vmalert_policy(document):
    """Stable identity of actually loaded alert definitions, not firing state."""
    if document.get("status") != "success":
        raise ValueError("vmalert rule read unsuccessful")
    groups, identities = [], set()
    for group in document["data"]["groups"]:
        identity = (os.path.basename(group["file"]), group["name"])
        if identity in identities:
            raise ValueError("duplicate vmalert group identity")
        identities.add(identity)
        rules, names = [], set()
        for rule in group["rules"]:
            if rule.get("type") != "alerting" or rule["name"] in names:
                raise ValueError("unsupported or duplicate loaded rule")
            names.add(rule["name"])
            rules.append({"name": rule["name"], "query": rule["query"].strip(),
                          "duration_seconds": rule["duration"], "keep_firing_for_seconds": rule.get("keep_firing_for", 0),
                          "labels": rule.get("labels", {}), "annotations": rule.get("annotations", {})})
        groups.append({"file": identity[0], "name": identity[1], "interval_seconds": group["interval"],
                       "rules": sorted(rules, key=lambda r: r["name"])})
    if not groups or not any(g["rules"] for g in groups):
        raise ValueError("vmalert loaded no alert definitions")
    return {"schema": "constellation.vmalert_policy/v1", "groups": sorted(groups, key=lambda g: (g["file"], g["name"]))}


def deployed_digest(d, timeout):
    """The deployed identity of one definition, as its own subsystem computes it."""
    kind = d["kind"]
    if kind == "file":
        with open(d["path"], "rb") as fh:
            return "sha256:" + hashlib.sha256(fh.read()).hexdigest()
    if kind == "attention-policy":
        rc, out, err = run(["/usr/bin/constellation-attention", "check-config", "--config", d["config"]], timeout, user="nq")
        if rc != 0:
            raise RuntimeError("check-config refused the deployed config: %s" % err.strip()[-200:])
        return json.loads(out)["attention_policy_digest"]
    if kind == "nq-saved-check":
        rc, out, err = run(["/usr/bin/nq", "--config", d["nq_config"], "--json", "saved-check", "inspect", d["reference"]], timeout, user="nq")
        if rc != 0:
            raise RuntimeError("saved check %s is not installed: %s" % (d["reference"], err.strip()[-200:]))
        return json.loads(out)["definition_digest"]
    if kind == "nq-watcher-admission":
        rc, out, err = run([d.get("program", "/usr/bin/nq"), "--config", d["nq_config"], "--json",
                            "watcher", "inspect", d["instance_id"]], timeout)
        if rc != 0:
            raise RuntimeError("watcher admission inspection unavailable: %s" % err.strip()[-200:])
        doc = json.loads(out)
        digest = doc.get("binding_digest", "")
        if (doc.get("schema") != "nq.watcher_inspection.v1" or doc.get("instance_id") != d["instance_id"] or
                len(digest) != 71 or not digest.startswith("sha256:") or
                any(c not in "0123456789abcdef" for c in digest[7:])):
            raise ValueError("watcher admission inspection has wrong identity or digest")
        return digest
    if kind == "vmalert-policy":
        with urllib.request.urlopen(d["url"], timeout=timeout) as response:
            raw = response.read((1 << 20) + 1)
        if len(raw) > 1 << 20:
            raise ValueError("vmalert rule read exceeds 1 MiB")
        policy = vmalert_policy(json.loads(raw))
        return "sha256:" + hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    raise ValueError("unknown definition kind %r" % kind)


def definitions(reg, timeout):
    """Declared versus deployed: every pinned definition must be deployed exactly as declared."""
    concerns = []
    for d in reg.get("definitions", []):
        try:
            got = deployed_digest(d, timeout)
            state = "PRESENT" if got == d["digest"] else "DEGRADED"
            reason = "deployed as declared" if state == "PRESENT" else "drift: deployed %s, declared %s" % (got[:19], d["digest"][:19])
        except Exception as e:  # noqa: BLE001 - a definition that cannot be read is not "as declared"
            state, reason = "UNKNOWN", "%s: %s" % (type(e).__name__, str(e)[:200])
        concerns.append({"id": "definition." + d["id"], "required": True, "state": state, "reason": reason,
                         "owner": d.get("owner", "")})
    return concerns


def definition_service(defs):
    bad = [x for x in defs if x["state"] != "PRESENT"]
    return {"name": "estate-definitions", "role": "alert and policy definitions deployed exactly as declared",
            "runtime": {"kind": "registry", "up": True, "state": "checked"}, "concerns": defs,
            # Unknown required verification is a known supervision failure;
            # preserve the individual UNKNOWN and notify through the evaluator.
            "verdict": "DEGRADED" if bad else "OK",
            "reason": ("; ".join("%s %s" % (x["id"][len("definition."):], x["reason"]) for x in bad)[:400]
                       if bad else "%d definitions deployed as declared" % len(defs)),
            "failing": [x["id"] for x in bad]}


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
    ap.add_argument("--definitions-only", action="store_true", help="inspect only declared definition pins; no workload or coverage claim")
    a = ap.parse_args(argv)
    with open(a.registry, "rb") as fh:
        registry_bytes = fh.read()
    reg = json.loads(registry_bytes)
    validate(reg)
    started = time.time()
    if a.definitions_only:
        defs = definitions(reg, a.timeout)
        if not defs:
            raise ValueError("definitions-only registry has no definitions")
        service = definition_service(defs)
        service["since"] = now_iso(started)
        doc = {"schema": OUTPUT_SCHEMA, "site": reg.get("site", ""), "scope": "definitions-only",
               "generated_at": now_iso(), "registry_sha256": hashlib.sha256(registry_bytes).hexdigest(),
               "duration_seconds": round(time.time() - started, 3), "services": [service],
               "counts": {v: int(service["verdict"] == v) for v in ("OK", "DEGRADED", "DOWN", "PAUSED", "UNKNOWN")}}
        write_atomic(a.output, doc)
        return 0
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
    # The registry's own completeness is a supervised service like any other.
    cov = {"name": "estate-coverage", "role": "every workload supervised or explicitly excluded",
           "runtime": {"kind": "registry", "up": True, "state": "checked"}}
    try:
        unregistered = coverage(reg, a.timeout)
        state = "DEGRADED" if unregistered else "PRESENT"
        cov.update(verdict="DEGRADED" if unregistered else "OK",
                   reason=("unsupervised and not excluded: " + ", ".join(unregistered))[:400] if unregistered
                   else "every enabled/running service and container is supervised or explicitly excluded",
                   unregistered=unregistered, failing=["estate.coverage.complete"] if unregistered else [],
                   concerns=[{"id": "estate.coverage.complete", "required": True, "state": state, "reason": ""}])
    except Exception as e:  # noqa: BLE001 - an unknown inventory is never "complete"
        cov.update(verdict="UNKNOWN", reason="inventory failed: %s" % str(e)[:200], failing=[], concerns=[])
    defs = definitions(reg, a.timeout)
    if defs:
        services.append(definition_service(defs))
        prev = previous.get("estate-definitions")
        services[-1]["since"] = prev["since"] if prev and prev.get("verdict") == services[-1]["verdict"] and prev.get("since") else now_iso(started)
    prev = previous.get(cov["name"])
    cov["since"] = prev["since"] if prev and prev.get("verdict") == cov["verdict"] and prev.get("since") else now_iso(started)
    services.append(cov)
    doc = {"schema": OUTPUT_SCHEMA, "site": reg.get("site", ""), "generated_at": now_iso(),
           "registry_sha256": hashlib.sha256(registry_bytes).hexdigest(),
           "duration_seconds": round(time.time() - started, 3), "services": services,
           "counts": {v: sum(1 for s in services if s["verdict"] == v) for v in ("OK", "DEGRADED", "DOWN", "PAUSED", "UNKNOWN")}}
    write_atomic(a.output, doc)
    if a.print:
        for s in services:
            print("%-9s %-24s %s" % (s["verdict"], s["name"], s["reason"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
