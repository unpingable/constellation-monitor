#!/usr/bin/env python3
"""Bounded read-only host investigation. No model, mutation or command provider."""
import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request

LIMIT = 1024 * 1024
FAMILIES = ("node_memory_SwapTotal_bytes", "node_memory_SwapFree_bytes", "node_vmstat_pswpin",
            "node_vmstat_pswpout", "node_pressure_memory_waiting_seconds_total")
QUERIES = {
    "swap_used_bytes": "sum(node_memory_SwapTotal_bytes) - sum(node_memory_SwapFree_bytes)",
    "paging_pages_per_second": "sum(rate(node_vmstat_pswpin[5m]) + rate(node_vmstat_pswpout[5m]))",
    "memory_psi_ratio": "max(rate(node_pressure_memory_waiting_seconds_total[5m]))",
    "metric_source_age_seconds": 'max(time() - timestamp({__name__=~"node_memory_SwapTotal_bytes|node_memory_SwapFree_bytes|node_vmstat_pswpin|node_vmstat_pswpout|node_pressure_memory_waiting_seconds_total"}))',
    "required_families": '{__name__=~"node_memory_SwapTotal_bytes|node_memory_SwapFree_bytes|node_vmstat_pswpin|node_vmstat_pswpout|node_pressure_memory_waiting_seconds_total"}',
}
BINS = ("wrong", "probably_wrong", "checked_not_wrong_within_scope", "unknown")


def target_query(query, instance, job, site):
    selector = "instance=" + json.dumps(instance) + ",job=" + json.dumps(job) + ",site=" + json.dumps(site)
    if "__name__" in query:
        return query.replace("{__name__", "{" + selector + ",__name__")
    return re.sub("|".join(FAMILIES), lambda match: match[0] + "{" + selector + "}", query)


def required_families(document, instance, job, site, now, window):
    if document.get("status") != "success" or document.get("data", {}).get("resultType") != "matrix":
        raise ValueError("required family range query failed")
    results = document["data"]["result"]
    names = set()
    for series in results:
        labels = series.get("metric", {})
        name = labels.get("__name__")
        if (labels.get("instance") != instance or labels.get("job") != job or labels.get("site") != site
                or name not in FAMILIES or name in names):
            raise ValueError("insufficient history: mixed target, duplicate or unexpected family")
        names.add(name)
        history({"status": "success", "data": {"resultType": "matrix", "result": [series]}}, now, window)
    if names != set(FAMILIES):
        raise ValueError("insufficient history: required target family missing")
    return [1]


def read_bytes(path):
    with open(path, "rb") as stream:
        data = stream.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError("source exceeds 1 MiB limit")
    return data


def stamp(value):
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("source timestamp must include timezone")
    return parsed.timestamp()


def command(argv, timeout=3):
    """Capture at most LIMIT bytes; kill/reap the exact child on timeout/overflow."""
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError("reader timeout")
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fileobj.fileno(), min(65536, LIMIT + 1 - len(output)))
                    if not chunk:
                        selector.unregister(key.fileobj)
                    output.extend(chunk)
                    if len(output) > LIMIT:
                        raise ValueError("reader output limit")
            code = proc.wait(timeout=max(0.001, deadline - time.monotonic()))
            if code:
                raise ValueError(f"reader exited {code}: {output[:512].decode(errors='replace')}")
            return bytes(output)
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        proc.stdout.close()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("redirects are not accepted")


def vm_query(base, query, now, window):
    url = urllib.parse.urlsplit(base)
    # Literal loopback only: no DNS, proxy, redirect, credentials or external API.
    if (url.scheme != "http" or url.username or url.password or url.query or url.fragment
            or not ipaddress.ip_address(url.hostname).is_loopback):
        raise ValueError("VictoriaMetrics URL must use a literal loopback HTTP address")
    params = urllib.parse.urlencode({"query": query, "start": now - window,
                                    "end": now, "step": 60})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(base.rstrip("/") + "/api/v1/query_range?" + params, timeout=3) as response:
        data = response.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError("metric response exceeds limit")
    return data


def history(document, now, window):
    if document.get("status") != "success" or document.get("data", {}).get("resultType") != "matrix":
        raise ValueError("metric query failed or is not a range matrix")
    results = document["data"]["result"]
    if len(results) != 1:
        raise ValueError("insufficient history: expected one aggregate series")
    values = [(float(t), float(v)) for t, v in results[0]["values"]]
    if (len(values) < 2 or any(not math.isfinite(t) or not math.isfinite(v) for t, v in values)
            or any(b[0] <= a[0] for a, b in zip(values, values[1:]))
            or values[0][0] > now - window + 60 or values[-1][0] < now - 120
            or values[0][0] < now - window - 1 or values[-1][0] > now + 1
            or any(b[0] - a[0] > 120 for a, b in zip(values, values[1:]))):
        raise ValueError("insufficient history: incomplete, stale, nonfinite or gapped window")
    return [v for _, v in values]


class Investigation:
    def __init__(self, args, now):
        self.args, self.now = args, now
        self.sources = []
        self.bins = {name: [] for name in BINS}

    def finding(self, bin_name, subject, statement, evidence, recommendation):
        self.bins[bin_name].append(dict(subject=subject, statement=statement,
                                        evidence=evidence, recommendation=recommendation))

    def source(self, name, locator, reader):
        entry = dict(id=name, locator=str(locator), read_at=self.now)
        self.sources.append(entry)
        def expired(signum, frame):
            raise TimeoutError("reader exceeded 3 second deadline")
        previous = signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, 3)
        try:
            data = reader()
            entry.update(sha256=hashlib.sha256(data).hexdigest(), bytes=len(data),
                         excerpt=data[:8192].decode(errors="replace"), excerpt_truncated=len(data) > 8192)
            return data
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            entry["error"] = str(error)
            self.finding("unknown", name, str(error), [name], "Restore this read source and repeat the investigation.")
            return None
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)

    def document(self, name, path, schema, freshness=None):
        data = self.source(name, path, lambda: read_bytes(path))
        if data is None:
            return None
        try:
            doc = json.loads(data)
            if doc.get("schema") != schema:
                raise ValueError("unsupported source schema")
            if freshness:
                age = self.now - stamp(doc[freshness])
                if not 0 <= age <= self.args.max_age:
                    raise ValueError("stale or future source timestamp")
            return doc
        except (ValueError, KeyError, TypeError, AttributeError) as error:
            self.finding("unknown", name, str(error), [name], "Provide a current supported source.")
            return None

    def run(self):
        args = self.args
        registry = self.document("registry", args.registry, "constellation.estate_registry/v1")
        if registry:
            services = registry.get("services", [])
            if not isinstance(services, list) or len(services) > 100:
                raise ValueError("registry services must be a list of at most 100")
            self.finding("unknown", "declared services", "Declarations describe expectations; they do not establish current health.",
                         ["registry"], "Read current observations for the declared services.")
            if args.local_readers:
                for service in services[:args.unit_limit]:
                    unit = service.get("runtime", {}).get("systemd")
                    if unit and re.fullmatch(r"[A-Za-z0-9_.@:-]+\.(service|timer)", unit):
                        raw = self.source("unit:" + unit, unit, lambda u=unit: command([
                            "systemctl", "show", "--no-pager", "--property=LoadState,ActiveState,SubState,Result", "--", u]))
                        if raw is not None:
                            text = raw.decode(errors="replace")
                            self.finding("probably_wrong" if "ActiveState=failed\n" in text else "unknown",
                                         unit, text.strip(), ["unit:" + unit], "Compare unit state to its declared role and schedule.")
                        self.source("journal:" + unit, unit, lambda u=unit: command([
                            "journalctl", "--no-pager", "--output=short-iso", "--lines=100",
                            "--since=@" + str(int(self.now - args.window)), "--unit=" + u]))
        attention = self.document("attention", args.attention, "constellation.attention_report.v1", "evaluated_at")
        if attention:
            matched = False
            for condition in attention.get("conditions", [])[:1000]:
                identity = condition.get("id")
                if args.condition and identity != args.condition:
                    continue
                matched = True
                active = condition.get("active") is True
                observation = condition.get("observation")
                unknown = (observation not in ("present", "clear") or condition.get("unknown_since") is not None
                           or condition.get("suspended") is not None)
                bin_name = ("unknown" if unknown else "wrong" if active and observation == "present"
                            else "probably_wrong" if observation == "present" else "checked_not_wrong_within_scope")
                self.finding(bin_name, identity,
                             f"Attention observation={observation}, active={active}; evaluator state, not an independent root cause.",
                             ["attention"], "Follow the condition's runbook and existing incident/remediation path.")
            if args.condition and not matched:
                self.finding("unknown", args.condition, "Condition not present in this attention report.", ["attention"], "Check retained incident history; absence does not establish recovery.")
        if args.incidents:
            incidents = self.document("incidents", args.incidents, "constellation.incidents.inspection/v1", "read_at")
            if incidents:
                for entry in incidents.get("incidents", [])[:1000]:
                    incident = entry.get("incident", {})
                    if args.condition and args.condition not in (incident.get("key"), incident.get("id")):
                        continue
                    self.finding("unknown" if incident.get("state") == "resolved" else "probably_wrong",
                                 incident.get("id"), f"Retained incident state={incident.get('state')}; not current service-health evidence.",
                                 ["incidents"], incident.get("needs_operator") or "Inspect retained history and current observations.")
        for index, path in enumerate(args.runbook):
            self.source("runbook:" + str(index), path, lambda p=path: read_bytes(p))
        site = registry.get("site") if registry else None
        memory_requested = not args.condition or args.condition == "host.memory_pressure"
        if memory_requested and (not isinstance(site, str) or not site):
            self.finding("unknown", "host.memory_pressure", "Registry has no usable expected site identity.", ["registry"], "Restore the expected host registry before diagnosing memory.")
        if memory_requested and isinstance(site, str) and site:
            metrics, ids = {}, []
            for name, query in QUERIES.items():
                query = target_query(query, args.instance, args.job, site)
                identity = "metric:" + name
                ids.append(identity)
                path = Path(args.metrics_fixture) / (name + ".json") if args.metrics_fixture else None
                raw = self.source(identity, path or (args.vm_url + " query=" + query),
                                  lambda p=path, q=query: read_bytes(p) if p else vm_query(args.vm_url, q, self.now, args.window))
                if raw is not None:
                    try:
                        doc = json.loads(raw)
                        metrics[name] = (required_families(doc, args.instance, args.job, site, self.now, args.window)
                                         if name == "required_families" else history(doc, self.now, args.window))
                    except (ValueError, KeyError, TypeError) as error:
                        self.finding("unknown", identity, str(error), [identity], "Acquire a complete fresh range; do not infer from occupied swap.")
            if len(metrics) == len(QUERIES):
                paging = max(metrics["paging_pages_per_second"])
                psi = max(metrics["memory_psi_ratio"])
                if max(metrics["metric_source_age_seconds"]) > args.max_age:
                    self.finding("unknown", "host.memory_pressure", "Insufficient fresh source history: underlying samples exceed maximum age.", ids, "Restore scraping and repeat after a complete fresh window.")
                elif min(min(v) for v in metrics.values()) < 0:
                    self.finding("unknown", "host.memory_pressure", "Invalid negative memory observations.", ids, "Check metric source and query semantics.")
                elif paging == 0 and psi == 0:
                    self.finding("checked_not_wrong_within_scope", "host.memory_pressure",
                                 "No paging and memory PSI zero throughout the sampled window: not pressure by these measures. Occupied swap alone is not pressure.",
                                 ids, "No action indicated by these measures; other memory failure modes remain outside this check.")
                else:
                    self.finding("probably_wrong", "host.memory_pressure",
                                 f"Paging or memory stalls observed (maximum pages/s={paging}, PSI ratio={psi}); severity and cause not established.",
                                 ids, "Inspect history and workload before considering governed remediation.")
        return dict(schema="constellation.diagnostic/v1", asked=dict(vars(args), mode="condition" if args.condition else "host-sweep",
                    at=self.now),
                    scope="Read-only observations; no action authority, no whole-host health assertion.",
                    sources=self.sources, bins=self.bins)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", required=True)
    parser.add_argument("--attention", required=True)
    parser.add_argument("--incidents", help="JSON from constellation-incidents inspect")
    parser.add_argument("--condition", help="Exact attention condition ID, or host.memory_pressure")
    parser.add_argument("--vm-url", default="http://127.0.0.1:8428")
    parser.add_argument("--instance", required=True, help="Exact expected node_exporter instance label")
    parser.add_argument("--job", required=True, help="Exact expected node_exporter job label")
    parser.add_argument("--metrics-fixture", help="Directory of captured query_range responses (one per named query)")
    parser.add_argument("--window", type=int, default=900)
    parser.add_argument("--max-age", type=int, default=300)
    parser.add_argument("--local-readers", action="store_true", help="Read bounded local systemctl/journald for registry units")
    parser.add_argument("--unit-limit", type=int, default=5)
    parser.add_argument("--runbook", action="append", default=[])
    parser.add_argument("--record", required=True, help="New exclusive asked/result JSON file (never overwritten)")
    args = parser.parse_args(argv)
    if not 300 <= args.window <= 3600 or not 1 <= args.max_age <= 3600 or not 0 <= args.unit_limit <= 10 or len(args.runbook) > 5:
        parser.error("bounds: window 300..3600, max-age 1..3600, units 0..10, runbooks <=5")
    # Reserve the record before collecting, ensuring every started investigation records its question.
    try:
        with open(args.record, "x", encoding="utf-8", opener=lambda path, flags: os.open(path, flags, 0o600)) as stream:
            now = time.time()
            json.dump({"schema": "constellation.diagnostic.pending/v1", "asked": vars(args), "at": now}, stream)
            stream.flush()
            os.fsync(stream.fileno())
            result = Investigation(args, now).run()
            encoded = json.dumps(result, indent=2, allow_nan=False) + "\n"
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=Path(args.record).parent,
                                             prefix=".diagnostic-", delete=False) as final:
                temporary = final.name
                final.write(encoded)
                final.flush()
                os.fsync(final.fileno())
            os.replace(temporary, args.record)
        finally:
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)
        print(encoded, end="")
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(3, f"diagnostic incomplete: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
