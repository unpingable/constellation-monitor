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
VALUE_CODES_LABEL = "constellation_value_codes"


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


def _evaluated(value):
    if not value or str(value).startswith("0001-01-01"):
        return None
    return value


def _instance(alert):
    labels = alert.get("labels") or {}
    return {
        "state": alert.get("state"),
        "active_at": alert.get("activeAt"),
        "value": str(alert.get("value", ""))[:64],
        "labels": {k: str(v)[:128] for k, v in sorted(labels.items())},
        "summary": str((alert.get("annotations") or {}).get("summary", ""))[:SUMMARY_LIMIT],
    }


def value_code_counts(alerts):
    """Complete active value/state counts by site, before instance detail is truncated."""
    counts = {}
    for alert in alerts:
        state = alert.get("state")
        if state not in ("firing", "pending"):
            continue
        site = str((alert.get("labels") or {}).get("site", ""))[:128]
        value = str(alert.get("value", ""))[:64]
        key = (site, state, value)
        counts[key] = counts.get(key, 0) + 1
    return [dict(site=s, state=t, value=v, count=n) for (s, t, v), n in sorted(counts.items())]


def document(api, site, generated_at, declared=None):
    """The document for one API answer. `generated_at` is the read time (RFC 3339)."""
    collector = _collector()
    policy = collector.vmalert_policy(api)  # refuses unsuccessful, duplicate or non-alerting definitions
    rules = []
    for group in api["data"]["groups"]:
        for rule in group["rules"]:
            alerts = rule.get("alerts") or []
            firing_sites = {}
            for a in alerts:
                if a.get("state") == "firing":
                    alert_site = str((a.get("labels") or {}).get("site", ""))[:128]
                    firing_sites[alert_site] = firing_sites.get(alert_site, 0) + 1
            rules.append({
                "file": os.path.basename(group["file"]),
                "group": group["name"],
                "name": rule["name"],
                "state": rule.get("state"),
                "health": rule.get("health"),
                "last_error": str(rule.get("lastError", ""))[:SUMMARY_LIMIT],
                # vmalert reports a rule it has not evaluated yet (just loaded) with Go's zero time; that is "never", not a date
                "last_evaluation": _evaluated(rule.get("lastEvaluation")),
                "duration_seconds": rule.get("duration", 0),
                "labels": {k: str(v) for k, v in sorted((rule.get("labels") or {}).items())},
                # vmalert's own data-presence counters: a query that fetched no series has no evidence either way
                "last_samples": rule.get("lastSamples"),
                "last_series_fetched": rule.get("lastSeriesFetched"),
                "instance_count": len(alerts),
                # complete, computed over every instance before detail is truncated ("" = no site label)
                "firing_sites": dict(sorted(firing_sites.items())),
                "instances": [_instance(a) for a in alerts[:INSTANCE_LIMIT]],
            })
            if VALUE_CODES_LABEL in (rule.get("labels") or {}):
                rules[-1]["value_code_counts"] = value_code_counts(alerts)
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


# ---- admission of opted-in definitions, before deployment ----
# The attention evaluator derives each opted-in rule's condition target exactly as below
# (crates/constellation-attention/src/inputs.rs: metric_alert_target, admit_metric_alert) and refuses a
# definition whose target is not a bounded token. --check-targets applies it to the declared policy, so a rule
# set that the evaluator would refuse is refused before it is deployed. fixtures/metric-alert-targets-v1.json
# is the shared vector both sides test against.
TARGET_MAX = 48


def alert_target(name):
    """`HostSwapExhausted` is `host-swap-exhausted`; anything outside [a-z0-9._-] becomes `-`; cut at 48 bytes."""
    out, previous_lower = [], False
    for ch in name:
        if "A" <= ch <= "Z":
            if previous_lower:
                out.append("-")
            out.append(ch.lower())
            previous_lower = False
        elif ("a" <= ch <= "z") or ("0" <= ch <= "9") or ch in "._-":
            out.append(ch)
            previous_lower = ("a" <= ch <= "z") or ("0" <= ch <= "9")
        else:
            out.append("-")
            previous_lower = False
    return "".join(out).encode()[:TARGET_MAX].decode("utf-8", "ignore")


def per_event_identity(value):
    """NQ's heuristic: the kind of per-event identity a condition token appears to carry, or None."""
    lower = value.lower()
    if "sha256" in lower:
        return "a digest"
    hexd, dig = set("0123456789abcdef"), set("0123456789")
    for i in range(len(lower) - 35):
        w = lower[i:i + 36]
        if all((c == "-") if j in (8, 13, 18, 23) else (c in hexd) for j, c in enumerate(w)):
            return "a UUID"
    for i in range(len(lower) - 9):
        w = lower[i:i + 10]
        if all((c == "-") if j in (4, 7) else (c in dig) for j, c in enumerate(w)):
            return "a date"
    hex_run = digit_run = 0
    for c in lower:
        hex_run = hex_run + 1 if c in hexd else 0
        digit_run = digit_run + 1 if c in dig else 0
        if hex_run >= 32:
            return "a hexadecimal identifier"
        if digit_run >= 8:
            return "a numeric timestamp or identifier"
    if all(c in dig for c in lower):
        return "a numeric identifier"
    return None


def token_error(value, maximum=TARGET_MAX):
    raw = value.encode()
    if not raw or len(raw) > maximum or not chr(raw[0]).isalnum() or not all(
            chr(b) in "abcdefghijklmnopqrstuvwxyz0123456789._-" for b in raw):
        return "must be 1..=%d characters of [a-z0-9._-] starting with a letter or digit" % maximum
    kind = per_event_identity(value)
    if kind:
        return "looks like %s; a condition names a stable class, not an event" % kind
    return None


def admit(name, sites=None):
    """One opted-in definition: {"target", "keyed": [(site, target)], "rejected": [(site, target, reason)]}.

    A token that is not a condition token refuses the definition everywhere (site None); a site-keyed target that
    is not one refuses that (definition, site) only."""
    target = alert_target(name)
    out = {"target": target, "keyed": [], "rejected": []}
    error = token_error(target)
    if error:
        out["rejected"].append((None, target, "derived target is not a condition token: %s" % error))
        return out
    for site in sites or [None]:
        full = target if site is None else "%s.%s" % (target, site)
        if len(full.encode()) > TARGET_MAX:
            out["rejected"].append((site, full, "derived target %s is %d bytes (%d-byte alert token, \".\", %d-byte site %s); "
                                    "the condition target bound is %d bytes" % (json.dumps(full), len(full.encode()),
                                                                                len(target.encode()), len(site.encode()),
                                                                                json.dumps(site), TARGET_MAX)))
            continue
        error = token_error(full)
        if error:
            out["rejected"].append((site, full, "derived target is not a condition token: %s" % error))
        else:
            out["keyed"].append((site, full))
    return out


def admit_endpoint(labels, expected_site):
    service, probe, site = (labels.get(k) for k in ("constellation_service", "probe", "site"))
    target = "endpoint:%s:%s" % (service, probe)
    out = {"target": target, "keyed": [], "rejected": [], "service": service}
    error = token_error(service) if isinstance(service, str) else "constellation_service must be a string"
    if not error and (not site or expected_site != site):
        error = "endpoint site does not match configured site (supply --site or one --key-site)"
    if not error and probe not in ("tcp", "http", "tls"):
        error = "probe must be tcp, http or tls"
    allowed = {"constellation_service", "probe", "site", "attention", "constellation_value_codes", "family", "severity", "area", "runbook"}
    if not error and set(labels) - allowed:
        error = "unsupported endpoint labels; no additional subjects allowed"
    if error:
        out["rejected"].append((site, target, error))
    else:
        out["keyed"].append((site, service))
    return out


def check_targets(policy, sites=None, site=None):
    """Every attention-labelled alerting rule of a declared policy with its admitted targets and refusals, in policy
    order. Rules that share a token are all refused, as the evaluator refuses them.
    Every value-coded rule must expose its evidence code in the summary."""
    named = []
    for group in policy.get("groups", []):
        for rule in group.get("rules", []):
            labels = rule.get("labels") or {}
            if labels.get("attention") == "true" or VALUE_CODES_LABEL in labels:
                verdict = admit_endpoint(labels, site or (sites[0] if sites and len(sites) == 1 else None)) if "constellation_service" in labels else admit(rule.get("name", ""), sites)
                if VALUE_CODES_LABEL in labels and "evidence code=" not in str((rule.get("annotations") or {}).get("summary", "")):
                    verdict["rejected"].append((None, verdict["target"], "value-coded rule summary must contain evidence code="))
                    verdict["summary_invalid"] = True
                named.append((group, rule.get("name", ""), verdict))
    sharing = {}
    for _, name, verdict in named:
        if verdict["keyed"]:
            sharing.setdefault(verdict["target"], []).append(name)
    rows = []
    for group, name, verdict in named:
        rejected = [{"site": s, "target": t, "bytes": len(t.encode()), "reason": r} for s, t, r in verdict["rejected"]]
        keyed = verdict["keyed"]
        if len(sharing.get(verdict["target"], [])) > 1:
            rejected.append({"site": None, "target": verdict["target"], "bytes": len(verdict["target"].encode()),
                             "reason": "derived target %s is shared by alerts %s" % (
                                 json.dumps(verdict["target"]), ", ".join(json.dumps(n) for n in sharing[verdict["target"]]))})
            keyed = []
        if verdict.get("summary_invalid"):
            keyed = []
        derived = [t for _, t in keyed] + [r["target"] for r in rejected]
        rows.append({"rule": name, "group": group.get("name"), "file": group.get("file"), "admitted": not rejected,
                     "targets": [t for _, t in keyed], "rejected": rejected,
                     "bytes": max(len(t.encode()) for t in derived)})
    return rows


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
    parser.add_argument("--site", help="the evaluator site this document is written for (required to collect)")
    parser.add_argument("--out", help="the document to write (required to collect)")
    parser.add_argument("--declared", help="declared-vmalert-policy.json; its identity is carried for the reader to compare")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--check-targets", action="store_true",
                        help="check the declared policy's attention targets and value-coded summaries (needs --declared); "
                             "print the verdict and exit 1 if any rule fails; reads nothing else")
    parser.add_argument("--key-site", action="append", dest="key_sites", metavar="SITE",
                        help="with --check-targets: a site the evaluator keys conditions by ([inputs.metric_alerts] sites); repeat")
    args = parser.parse_args(argv)
    if args.check_targets:
        if not args.declared:
            parser.error("--check-targets needs --declared")
        with open(args.declared, "rb") as fh:
            policy = json.loads(fh.read())
        rows = check_targets(policy, args.key_sites, args.site)
        rejected = [r for r in rows if not r["admitted"]]
        print(json.dumps({"schema": "constellation.metric_alert_admission/v1", "declared_policy_sha256": declared_sha256(args.declared),
                          "sites": args.key_sites, "rules": rows, "rejected": len(rejected)}, indent=1, sort_keys=True))
        for r in rejected:
            for x in r["rejected"]:
                sys.stderr.write("rule_rejected:%s%s: %s\n" % (r["rule"], " (%s)" % x["site"] if x["site"] else "", x["reason"]))
        return 1 if rejected else 0
    if not args.site or not args.out:
        parser.error("--site and --out are required to collect")
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
