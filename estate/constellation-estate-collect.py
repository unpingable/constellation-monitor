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
import argparse, concurrent.futures, fnmatch, hashlib, json, math, os, selectors, shutil, signal, subprocess, sys, tempfile, time, urllib.request
from datetime import datetime, timezone
try:
    import tomllib
except ImportError:  # Ubuntu 22.04 / Python 3.10
    import tomli as tomllib

REGISTRY_SCHEMA = "constellation.estate_registry/v1"
OUTPUT_SCHEMA = "constellation.estate/v1"
STATUS_SCHEMA = "project.ops.status/v1"
OK_STATES = {"PRESENT", "NOT_APPLICABLE"}
THRESHOLD_KEYS = {"metrics_observation_age_seconds", "last_success_age_seconds", "cursor_lag_seconds", "output_age_seconds",
                  "store_bytes", "wal_growth_bytes", "backup_age_seconds"}
NAME_OK = set("abcdefghijklmnopqrstuvwxyz0123456789-")


def now_iso(t=None):
    return datetime.fromtimestamp(time.time() if t is None else t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def kill_and_reap(p, original):
    """Stop a timed-out child without making cleanup an unbounded wait."""
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        p.wait(timeout=0.2)
    except subprocess.TimeoutExpired:
        raise RuntimeError("child PID %d remains pending exit after SIGKILL; original %s: %s" %
                           (p.pid, type(original).__name__, original)) from original


def run(argv, timeout, user=None, cwd=None, env=None, limit=1 << 20):
    if user:
        argv = ["setpriv", "--reuid", user, "--regid", user, "--init-groups", "--"] + argv
    full_env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LC_ALL": "C.UTF-8"}
    full_env.update(env or {})
    # Drain pipes throughout the run. communicate()/subprocess.run() retains all
    # output before slicing, so a noisy producer could exhaust collector memory.
    p = subprocess.Popen(argv, cwd=cwd, env=full_env, stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    captured = {p.stdout: bytearray(), p.stderr: bytearray()}
    caps = {p.stdout: limit, p.stderr: 2000}
    deadline = time.monotonic() + timeout
    with selectors.DefaultSelector() as sel:
        for pipe in captured:
            os.set_blocking(pipe.fileno(), False)
            sel.register(pipe, selectors.EVENT_READ)
        try:
            while sel.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, timeout)
                for key, _ in sel.select(remaining):
                    pipe = key.fileobj
                    try:
                        chunk = os.read(pipe.fileno(), 65536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        sel.unregister(pipe)
                        pipe.close()
                        continue
                    if pipe is p.stderr:
                        captured[pipe] = (captured[pipe] + chunk)[-caps[pipe]:]
                    else:
                        room = caps[pipe] - len(captured[pipe])
                        if room > 0:
                            captured[pipe].extend(chunk[:room])
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, timeout)
            p.wait(timeout=remaining)
        except BaseException as exc:
            kill_and_reap(p, exc)
            raise
        finally:
            for pipe in captured:
                pipe.close()
    return p.returncode, bytes(captured[p.stdout]), captured[p.stderr].decode("utf-8", "replace")


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


def timestamp(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value) if math.isfinite(value) and value >= 0 else None
    if isinstance(value, bool):
        return None
    if not value or value in ("n/a", "never"):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.timestamp() if parsed.tzinfo is not None else None
    except ValueError:
        try:
            return datetime.strptime(value, "%a %Y-%m-%d %H:%M:%S %Z").replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            return None


def deadline_timestamp(value):
    """Authored deadlines have portable timezone semantics, unlike native unit text."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value) if math.isfinite(value) and value >= 0 else None
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.timestamp() if parsed.tzinfo is not None else None
    except ValueError:
        return None


def derive_registry(reg, directory, declaration_root=None):
    """Build expected subjects from authored inputs, never runtime/discovery state."""
    import copy
    from pathlib import Path
    result = copy.deepcopy(reg)
    services, declarations = [], []
    for path in sorted(Path(directory).glob("*.toml")):
        raw = path.read_bytes()
        service = tomllib.loads(raw.decode())
        allowed = {"name", "role", "runtime", "status", "declared", "contract", "timers",
                   "probes", "dependencies", "health_url", "metrics_url", "status_command", "status_user", "thresholds"}
        if set(service) - allowed:
            raise ValueError("unknown declaration fields: " + str(sorted(set(service) - allowed)))
        if service.get("health_url"):
            if "status" in service or "status_command" in service:
                raise ValueError("choose health_url, status or status_command")
            service["status"] = {"kind": "http", "url": service.pop("health_url")}
        if "status_command" in service:
            if "status" in service:
                raise ValueError("choose status or status_command")
            argv = service.pop("status_command")
            if not isinstance(argv, list) or not argv or not all(isinstance(x, str) for x in argv):
                raise ValueError("status_command must be an argv list")
            service["status"] = {"kind": "project-ops-status", "argv": argv, "user": service.pop("status_user", None)}
        elif "status_user" in service:
            raise ValueError("status_user requires status_command")
        if (service.get("status") or {}).get("kind") == "project-ops-status":
            user = service["status"].get("user")
            if not isinstance(user, str) or not user.strip() or user != user.strip() or user.lower() == "root" or (user.isdecimal() and int(user) == 0):
                raise ValueError("declaration command status requires explicit non-root user")
        services.append(service)
        declarations.append({"name": service["name"], "path": str(Path(declaration_root) / path.name) if declaration_root else str(path.resolve()),
                             "sha256": hashlib.sha256(raw).hexdigest()})
    if not services:
        raise ValueError("no service declarations")
    result["services"] = sorted(services, key=lambda x: x["name"])
    result["service_declarations"] = sorted(declarations, key=lambda x: x["name"])
    validate(result)
    return result


def declaration_findings(reg, directory=None):
    """Verify the approved copy; unavailable inputs cannot retire its subjects."""
    from pathlib import Path
    findings = {}
    for declaration in reg.get("service_declarations", []):
        path = Path(declaration["path"])
        if directory is not None:
            path = Path(directory) / path.name
        try:
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            reason = "declaration differs from approved registry" if actual != declaration["sha256"] else None
        except OSError as error:
            reason = "declaration unavailable: " + str(error)
        if reason:
            findings[declaration["name"]] = reason
    return findings


def timer_concern(spec, timeout, now=None):
    """A timer is part of its service's job: armed, and its last run did not fail (unless result checks are off)."""
    spec = {"unit": spec} if isinstance(spec, str) else spec
    now = time.time() if now is None else now
    t = unit_props(spec["unit"], timeout, ["ActiveState", "Unit", "LastTriggerUSec"])
    svc = unit_props(t.get("Unit", ""), timeout, ["Result", "ExecMainStatus", "ActiveState", "ExecMainExitTimestamp"]) if t.get("Unit") else {}
    ok_status = [str(x) for x in spec.get("ok_status", [0])]
    if t.get("ActiveState") != "active":
        state, reason = "DEGRADED", "timer %s is %s" % (spec["unit"], t.get("ActiveState", "?"))
    elif spec.get("check_result", True) and svc.get("ActiveState") == "failed" and svc.get("ExecMainStatus") not in ok_status:
        state, reason = "DEGRADED", "last run of %s failed (status %s)" % (t.get("Unit"), svc.get("ExecMainStatus"))
        if t.get("Unit") == "constellation-attention.service" and svc.get("ExecMainStatus") == "4":
            reason += ": attention delivery failure (delivery_failed or delivery_partial); inspect report.json"
    elif "first_result_due_at" in spec or "max_success_age_seconds" in spec:
        exited = timestamp(svc.get("ExecMainExitTimestamp"))
        success = exited if svc.get("Result") == "success" and svc.get("ExecMainStatus") in ok_status else None
        due = deadline_timestamp(spec.get("first_result_due_at"))
        if success is None:
            state = "DEGRADED" if due is not None and now >= due else "UNKNOWN"
            reason = "first successful result overdue" if state == "DEGRADED" else "armed; no successful result observed"
        elif success > now:
            state, reason = "UNKNOWN", "successful result timestamp is in the future"
        elif "max_success_age_seconds" in spec and now - success > spec["max_success_age_seconds"]:
            state, reason = "STALE", "last success exceeds maximum age"
        else:
            state, reason = "PRESENT", "successful result within declared age"
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
    declaration_errors = []
    if svc.get("_has_declaration"):
        if not out["runtime"].get("up"):
            declaration_errors.append("declared runtime is unavailable")
        for entries in (svc.get("probes") or {}).values():
            for entry in entries:
                if not os.path.exists(entry["path"]):
                    declaration_errors.append("declared path unavailable: " + entry["path"])
        if error or any(c["id"] == "http.health" and c["state"] not in OK_STATES for c in out["concerns"]):
            declaration_errors.append("declared status endpoint or producer unavailable")
        if svc.get("metrics_url"):
            try:
                metrics, _ = http_status({"url": svc["metrics_url"]}, timeout)
                if metrics[0]["state"] not in OK_STATES:
                    declaration_errors.append("declared metrics endpoint unavailable")
            except Exception:
                declaration_errors.append("declared metrics endpoint unavailable")
    if svc.get("_declaration_drift") or declaration_errors:
        out["concerns"].append({"id": "declaration.drift", "required": True, "state": "DEGRADED",
                                "reason": svc.get("_declaration_drift") or "; ".join(declaration_errors)})
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


PROBE_FIELDS = {"stores": "store", "outputs": "output", "backups": "backup"}
PROBE_OPERATION_FIELDS = {
    "filesystem": {"filesystem_avail_bytes", "filesystem_avail_inodes"},
    "sqlite": {"store_bytes", "store_wal_bytes", "store_freelist_pages", "store_page_size_bytes"},
    "store_mtime": {"store_age_seconds"},
    "output_mtime": {"output_age_seconds"},
    "backup_mtime": {"backup_age_seconds", "backup_created_timestamp_seconds"},
}
PROBE_FAMILIES = {
    "filesystem_avail_bytes": "Available bytes on the filesystem containing the declared store",
    "filesystem_avail_inodes": "Available inodes on the filesystem containing the declared store",
    "store_bytes": "Declared SQLite store file size in bytes",
    "store_wal_bytes": "Declared SQLite store WAL file size in bytes (zero when absent)",
    "store_freelist_pages": "SQLite freelist page count from the database header",
    "store_page_size_bytes": "SQLite page size from the database header",
    "store_age_seconds": "Age of the declared store file mtime in seconds",
    "output_age_seconds": "Age of the declared output file mtime in seconds",
    "backup_age_seconds": "Age of the declared backup file mtime in seconds",
    "backup_created_timestamp_seconds": "Declared backup file mtime as Unix seconds",
    "probe_success": "Whether the latest scheduled probe succeeded",
    "probe_last_success_timestamp_seconds": "Unix time of the last successful probe observation",
    "probe_observed_timestamp_seconds": "Unix time when the emitted measurement was observed",
}


def probe_specs(reg):
    """The P1 additive JSON surface; P2 owns TOML and derived declarations."""
    specs = []
    for svc in reg["services"]:
        probes = svc.get("probes") or {}
        if not isinstance(probes, dict) or set(probes) - set(PROBE_FIELDS):
            raise ValueError("%s: probes must contain only stores, outputs, backups" % svc["name"])
        for field, kind in PROBE_FIELDS.items():
            entries = probes.get(field, [])
            if not isinstance(entries, list):
                raise ValueError("%s: probes.%s must be a list" % (svc["name"], field))
            seen = set()
            for entry in entries:
                if not isinstance(entry, dict) or set(entry) != {"name", "path"}:
                    raise ValueError("%s: %s probe needs only name and path" % (svc["name"], kind))
                name, path = entry["name"], entry["path"]
                if (not isinstance(name, str) or not name or len(name) > 48 or set(name) - NAME_OK or
                        name in seen or not isinstance(path, str) or not os.path.isabs(path)):
                    raise ValueError("%s: invalid or duplicate %s probe" % (svc["name"], kind))
                seen.add(name)
                operations = ("filesystem", "sqlite", "store_mtime") if kind == "store" else (kind + "_mtime",)
                for operation in operations:
                    specs.append((svc["name"], kind, name, path, operation))
    if len(specs) > 256:
        raise ValueError("too many probes (maximum 256)")
    return specs


def probe_worker(operation, path):
    """One read-only filesystem operation, isolated in a deadline-bound child."""
    if operation == "filesystem":
        stat = os.statvfs(path)
        return {"filesystem_avail_bytes": stat.f_bavail * stat.f_frsize,
                "filesystem_avail_inodes": stat.f_favail}
    if operation == "sqlite":
        # Use the same resolved pathname for the main file and its WAL. A
        # declared symlink may point to a store on another filesystem.
        main_path = os.path.realpath(path)
        with open(main_path, "rb") as fh:
            header = fh.read(100)
            size = os.fstat(fh.fileno()).st_size
        if len(header) != 100 or header[:16] != b"SQLite format 3\x00":
            raise ValueError("invalid SQLite header")
        page_size = int.from_bytes(header[16:18], "big")
        if page_size == 1:
            page_size = 65536
        if page_size < 512 or page_size > 65536 or page_size & (page_size - 1):
            raise ValueError("invalid SQLite page size")
        wal_path = main_path + "-wal"
        try:
            wal_size = os.stat(wal_path).st_size
        except FileNotFoundError:
            wal_size = 0
        return {"store_bytes": size, "store_wal_bytes": wal_size,
                "store_freelist_pages": int.from_bytes(header[36:40], "big"),
                "store_page_size_bytes": page_size}
    st = os.stat(path)
    observed = time.time()
    if operation == "store_mtime":
        return {"store_age_seconds": max(0, observed - st.st_mtime)}
    if operation == "output_mtime":
        return {"output_age_seconds": max(0, observed - st.st_mtime)}
    if operation == "backup_mtime":
        return {"backup_age_seconds": max(0, observed - st.st_mtime),
                "backup_created_timestamp_seconds": st.st_mtime}
    raise ValueError("unknown probe operation")


def probe_key(spec):
    return json.dumps(spec, separators=(",", ":"))


def collect_one_probe(spec, timeout):
    _, _, _, path, operation = spec
    rc, out, err = run([sys.executable, "-I", os.path.abspath(__file__), "--probe-worker", operation, path],
                       timeout, limit=4096)
    if rc != 0:
        raise RuntimeError("probe exited %d: %s" % (rc, err[-200:]))
    values = json.loads(out)
    if not isinstance(values, dict) or set(values) != PROBE_OPERATION_FIELDS[operation]:
        raise ValueError("unexpected probe result")
    return values


def finite_nonnegative(value):
    try:
        return type(value) in (int, float) and math.isfinite(value) and value >= 0
    except OverflowError:
        return False


def valid_probe_cache_entry(entry, operation, now):
    if not isinstance(entry, dict) or not isinstance(entry.get("success"), bool):
        return False
    attempt = entry.get("attempted_at")
    observation = entry.get("observed_at")
    values = entry.get("values")
    if not finite_nonnegative(attempt) or attempt > now:
        return False
    if observation is not None and (not finite_nonnegative(observation) or observation > now):
        return False
    if not isinstance(values, dict):
        return False
    if entry["success"]:
        return observation is not None and set(values) == PROBE_OPERATION_FIELDS[operation] and all(
            finite_nonnegative(value) for value in values.values())
    return not values


def collect_probes(specs, state_path, timeout, slow_seconds=600, workers=4):
    try:
        with open(state_path) as fh:
            old = json.load(fh)
        if not isinstance(old, dict) or old.get("schema") != "constellation.estate_probes/v1":
            old = {}
    except (OSError, ValueError):
        old = {}
    old_entries = old.get("entries", {})
    if not isinstance(old_entries, dict):
        old_entries = {}
    now = time.time()
    entries = {}
    futures = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for spec in specs:
            key = probe_key(spec)
            previous = old_entries.get(key, {})
            if not valid_probe_cache_entry(previous, spec[4], now):
                previous = {}
            entries[key] = dict(previous)
            due = (spec[4] != "sqlite" or now - previous.get("attempted_at", 0) >= slow_seconds)
            if due:
                futures[pool.submit(collect_one_probe, spec, timeout)] = key
        for future in concurrent.futures.as_completed(futures):
            key = futures[future]
            entry = entries[key]
            entry["attempted_at"] = time.time()
            try:
                entry["values"] = future.result()
                entry["observed_at"] = time.time()
                entry["success"] = True
            except Exception as exc:  # one unavailable path must not stop another
                entry["values"] = {}
                entry["success"] = False
                entry["error"] = "%s: %s" % (type(exc).__name__, str(exc)[:200])
    state = {"schema": "constellation.estate_probes/v1", "entries": entries}
    write_atomic(state_path, state)
    return entries


def prometheus_escape(value):
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def render_probes(specs, entries, now=None):
    now = time.time() if now is None else now
    rows = {name: [] for name in PROBE_FAMILIES}
    for spec in specs:
        service, kind, name, _, operation = spec
        entry = entries[probe_key(spec)]
        labels = {"service": service, kind: name, "probe": operation}
        probe_labels = ",".join('%s="%s"' % (k, prometheus_escape(v)) for k, v in labels.items())
        rows["probe_success"].append((probe_labels, int(bool(entry.get("success")))))
        if entry.get("observed_at"):
            rows["probe_last_success_timestamp_seconds"].append((probe_labels, entry["observed_at"]))
        if not entry.get("success"):
            continue
        for field, value in entry.get("values", {}).items():
            # Age measurements keep the original file mtime when carried from
            # a slow pass; a schedule skip must not make old data look fresh.
            if field.endswith("_age_seconds"):
                value += max(0, now - entry["observed_at"])
            metric_labels = ",".join('%s="%s"' % (k, prometheus_escape(v))
                                     for k, v in {"service": service, kind: name}.items())
            rows[field].append((metric_labels, value))
        rows["probe_observed_timestamp_seconds"].append((probe_labels, entry["observed_at"]))
    lines = []
    for name, help_text in PROBE_FAMILIES.items():
        metric = "service_" + name
        lines.extend(["# HELP %s %s" % (metric, help_text), "# TYPE %s gauge" % metric])
        lines.extend("%s{%s} %s" % (metric, labels, value) for labels, value in rows[name])
    return "\n".join(lines) + "\n"


def render_service_limits(reg, now=None):
    """Publish authored limits; timestamp means a collector pass, never health."""
    now = time.time() if now is None else now
    lines = ["# HELP service_declaration_observed_timestamp_seconds Collector pass over expected service declaration; not service health",
             "# TYPE service_declaration_observed_timestamp_seconds gauge"]
    for key in sorted(THRESHOLD_KEYS):
        metric = "service_" + key + "_limit"
        lines.extend(["# HELP " + metric + " Authored service threshold", "# TYPE " + metric + " gauge"])
        for svc in sorted(reg["services"], key=lambda service: service["name"]):
            if key in svc.get("thresholds", {}):
                lines.append('%s{service="%s"} %s' % (metric, prometheus_escape(svc["name"]), svc["thresholds"][key]))
    for svc in sorted(reg["services"], key=lambda service: service["name"]):
        lines.append('service_declaration_observed_timestamp_seconds{service="%s"} %s' %
                     (prometheus_escape(svc["name"]), now))
    return "\n".join(lines) + "\n"


def write_textfile(path, text):
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".estate-probes-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


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
        if len(set(svc["runtime"]) & {"systemd", "docker"}) != 1:
            raise ValueError("runtime must select exactly one kind")
        deps = svc.get("dependencies", [])
        if not isinstance(deps, list) or any(not isinstance(x, str) for x in deps) or len(set(deps)) != len(deps):
            raise ValueError("dependencies must be unique names")
        for timer in svc.get("timers", []):
            if isinstance(timer, str):
                continue
            if "first_result_due_at" in timer and deadline_timestamp(timer["first_result_due_at"]) is None:
                raise ValueError("first_result_due_at must be timezone-aware ISO text or finite nonnegative Unix seconds")
            if "max_success_age_seconds" in timer:
                value = timer["max_success_age_seconds"]
                if not finite_nonnegative(value) or value <= 0 or "first_result_due_at" not in timer:
                    raise ValueError("maximum success age needs positive seconds and first_result_due_at")
        thresholds = svc.get("thresholds", {})
        if not isinstance(thresholds, dict) or set(thresholds) - THRESHOLD_KEYS:
            raise ValueError("unknown service threshold")
        for value in thresholds.values():
            if not finite_nonnegative(value) or value <= 0:
                raise ValueError("thresholds must be positive finite numbers")
    for svc in reg["services"]:
        if set(svc.get("dependencies", [])) - names or svc["name"] in svc.get("dependencies", []):
            raise ValueError("dependencies must name another declared service")
    pins = reg.get("service_declarations", [])
    if pins and (len({x["name"] for x in pins}) != len(pins) or {x["name"] for x in pins} != names):
        raise ValueError("declaration pins must cover every service exactly once")
    probe_specs(reg)


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
    if argv is None and len(sys.argv) == 4 and sys.argv[1] == "--probe-worker":
        print(json.dumps(probe_worker(sys.argv[2], sys.argv[3])))
        return 0
    ap = argparse.ArgumentParser()
    ap.add_argument("--registry", default="/etc/constellation-estate/estate.json")
    ap.add_argument("--services-dir", help="authored TOML inputs, only with --render-registry")
    ap.add_argument("--render-registry", help="write deterministic expected registry without observations")
    ap.add_argument("--declaration-root", help="target declaration directory used while rendering")
    ap.add_argument("--output", default="/var/lib/constellation-estate/estate.json")
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--textfile-dir", help="node_exporter textfile collector directory for declared probes")
    ap.add_argument("--probe-timeout", type=float, default=3, help="deadline in seconds for each file probe")
    ap.add_argument("--probe-slow-seconds", type=int, default=600, help="SQLite geometry polling interval")
    ap.add_argument("--service-workers", type=int, default=4, help="maximum concurrent service checks")
    ap.add_argument("--print", action="store_true")
    ap.add_argument("--definitions-only", action="store_true", help="inspect only declared definition pins; no workload or coverage claim")
    a = ap.parse_args(argv)
    with open(a.registry, "rb") as fh:
        registry_bytes = fh.read()
    reg = json.loads(registry_bytes)
    if a.render_registry:
        if not a.services_dir:
            raise ValueError("--render-registry requires --services-dir")
        reg = derive_registry(reg, a.services_dir, a.declaration_root)
        write_atomic(a.render_registry, reg)
        return 0
    if a.services_dir or a.declaration_root:
        raise ValueError("--services-dir and --declaration-root require --render-registry; collection uses approved registry")
    validate(reg)
    drift = declaration_findings(reg)
    declared_names = {d["name"] for d in reg.get("service_declarations", [])}
    for svc in reg["services"]:
        svc["_has_declaration"] = svc["name"] in declared_names
        if svc["name"] in drift:
            svc["_declaration_drift"] = drift[svc["name"]]
    started = time.time()
    if a.service_workers < 1 or a.service_workers > 16:
        raise ValueError("service-workers must be between 1 and 16")
    specs = probe_specs(reg)
    has_limits = any(svc.get("thresholds") for svc in reg["services"])
    if has_limits and not a.definitions_only and (not a.textfile_dir or not os.path.isdir(a.textfile_dir)):
        raise ValueError("declared thresholds require an existing --textfile-dir")
    if specs and not a.definitions_only:
        if not a.textfile_dir or not os.path.isdir(a.textfile_dir):
            raise ValueError("declared probes require an existing --textfile-dir")
        if a.probe_timeout <= 0 or a.probe_slow_seconds <= 0:
            raise ValueError("probe deadlines and schedule must be positive")
        entries = collect_probes(specs, os.path.join(os.path.dirname(a.output), "probe-state.json"),
                                 a.probe_timeout, a.probe_slow_seconds)
        write_textfile(os.path.join(a.textfile_dir, "constellation-estate.prom"), render_probes(specs, entries) + render_service_limits(reg))
    elif a.textfile_dir and os.path.isdir(a.textfile_dir) and not a.definitions_only:
        # Removing the last declaration must remove its old metric series.
        write_textfile(os.path.join(a.textfile_dir, "constellation-estate.prom"), render_probes([], {}) + render_service_limits(reg))
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
    # File metrics are already published above. A slow status producer cannot
    # keep unrelated service evaluations waiting behind it in registry order.
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.service_workers) as pool:
        evaluated = list(pool.map(lambda svc: evaluate(svc, a.timeout), reg["services"]))
    for s in evaluated:
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
