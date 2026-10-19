#!/usr/bin/env python3
"""Write the `constellation.metric_alerts/v1` document from vmalert's rules API.

One bounded read of `/api/v1/rules`, one atomically replaced JSON file. The
document carries each alerting rule's definition identity (the same policy
identity the estate collector pins), its runtime state (firing, pending,
inactive), health and last evaluation time, and its alert instances. The
attention evaluator's `[inputs.metric_alerts]` reads it; only rules labelled
`attention: "true"` become conditions there. This program observes; it
evaluates nothing and talks to no notifier.
"""
import argparse, datetime, hashlib, importlib.util, json, os, sys, tempfile, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA = "constellation.metric_alerts/v1"
LIMIT = 1 << 20  # the rules API answer must fit in 1 MiB, as for the estate collector
SUMMARY_LIMIT = 300
INSTANCE_LIMIT = 32  # instances kept per rule; the count is always carried


def _collector():
    spec = importlib.util.spec_from_file_location("collect", os.path.join(HERE, "constellation-estate-collect.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def policy_sha256(policy):
    return "sha256:" + hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def declared_sha256(path):
    """The declared policy file's identity, computed exactly as the estate registry pins it."""
    with open(path, "rb") as fh:
        document = json.loads(fh.read())
    if document.get("schema") != "constellation.vmalert_policy/v1":
        raise ValueError("declared policy is not constellation.vmalert_policy/v1")
    return policy_sha256(document)


def _instance(alert):
    labels = alert.get("labels") or {}
    return {
        "state": alert.get("state"),
        "active_at": alert.get("activeAt"),
        "value": str(alert.get("value", ""))[:64],
        "labels": {k: str(v)[:128] for k, v in sorted(labels.items())},
        "summary": str((alert.get("annotations") or {}).get("summary", ""))[:SUMMARY_LIMIT],
    }


def document(api, site, generated_at, declared=None):
    """The document for one API answer. `generated_at` is the read time (RFC 3339)."""
    collector = _collector()
    policy = collector.vmalert_policy(api)  # refuses unsuccessful, duplicate or non-alerting definitions
    rules = []
    for group in api["data"]["groups"]:
        for rule in group["rules"]:
            alerts = rule.get("alerts") or []
            rules.append({
                "file": os.path.basename(group["file"]),
                "group": group["name"],
                "name": rule["name"],
                "state": rule.get("state"),
                "health": rule.get("health"),
                "last_error": str(rule.get("lastError", ""))[:SUMMARY_LIMIT],
                "last_evaluation": rule.get("lastEvaluation"),
                "duration_seconds": rule.get("duration", 0),
                "labels": {k: str(v) for k, v in sorted((rule.get("labels") or {}).items())},
                "instance_count": len(alerts),
                "instances": [_instance(a) for a in alerts[:INSTANCE_LIMIT]],
            })
    rules.sort(key=lambda r: (r["file"], r["group"], r["name"]))
    effective = policy_sha256(policy)
    return {
        "schema": SCHEMA,
        "site": site,
        "generated_at": generated_at,
        "policy_sha256": effective,
        "declared_policy_sha256": declared,
        "policy_matches_declared": None if declared is None else declared == effective,
        "counts": {"groups": len(policy["groups"]), "rules": len(rules),
                   "firing": sum(1 for r in rules if r["state"] == "firing"),
                   "attention": sum(1 for r in rules if r["labels"].get("attention") == "true")},
        "rules": rules,
    }


def read_api(url, timeout):
    with urllib.request.urlopen(url, timeout=timeout) as response:
        raw = response.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError("vmalert rule read exceeds 1 MiB")
    return json.loads(raw)


def atomic_write(path, data):
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".metric-alerts-", dir=directory)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, 0o644)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8880/api/v1/rules")
    parser.add_argument("--site", required=True, help="the evaluator site this document is written for")
    parser.add_argument("--out", required=True)
    parser.add_argument("--declared", help="declared-vmalert-policy.json; its identity is carried for the reader to compare")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args(argv)
    declared = declared_sha256(args.declared) if args.declared else None
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    try:
        api = read_api(args.url, args.timeout)
        doc = document(api, args.site, now, declared)
    except Exception as e:  # noqa: BLE001 - an unreadable source is reported, never replaced by an empty document
        sys.stderr.write("metric-alerts-collect: %s: %s\n" % (type(e).__name__, str(e)[:200]))
        return 1
    atomic_write(args.out, json.dumps(doc, sort_keys=True, indent=1, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
