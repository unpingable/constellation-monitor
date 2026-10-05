#!/usr/bin/env python3
"""Bounded published Kubernetes observation; no health judgment or mutation."""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import ssl
import stat
import sys
import time
import uuid
from urllib.parse import urlsplit, quote

SCHEMA = "monitor.kubernetes-observation-settings/v1"
PROFILE = "monitor.kubernetes.published/v1"
FAMILIES = ("namespace", "nodes", "pods", "deployments", "services", "endpointslices", "readiness", "version", "semantic")
IDENT = re.compile(r"[a-zA-Z0-9_.:-]{1,160}")
SECRET_PREFIX = re.compile(r"(?:bearer[ _:-]|sk-(?:proj-)?|sk_proj-|-----BEGIN)", re.IGNORECASE)
DNS = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?")
class Refusal(ValueError):
    pass

def stamp():
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")

def parse(raw):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise Refusal("duplicate_json_field")
            out[key] = value
        return out
    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(Refusal("invalid_numeric_token")))
    except (ValueError, UnicodeError, RecursionError):
        raise Refusal("malformed_json")

def origin(value, tls):
    if not isinstance(value, str):
        raise Refusal("origin_invalid")
    u = urlsplit(value)
    if u.scheme not in (("https",) if tls else ("http", "https")) or not u.hostname or u.username or u.password or u.path not in ("", "/") or u.query or u.fragment:
        raise Refusal("origin_invalid")
    try:
        port = u.port
    except ValueError:
        raise Refusal("origin_invalid")
    if not port:
        raise Refusal("explicit_origin_port_required")
    return u

def settings(v):
    keys = {"schema", "project", "api_url", "ca_file", "token_file", "namespace", "namespace_uid", "node_names", "app_url", "timeout_ms", "max_response_bytes"}
    if not isinstance(v, dict) or set(v) != keys or v["schema"] != SCHEMA:
        raise Refusal("settings_schema_mismatch")
    for name in ("project", "namespace_uid"):
        if not isinstance(v[name], str) or not IDENT.fullmatch(v[name]):
            raise Refusal("scope_identity_invalid")
    if not isinstance(v["namespace"], str) or not DNS.fullmatch(v["namespace"]):
        raise Refusal("namespace_invalid")
    nodes = v["node_names"]
    if not isinstance(nodes, list) or not 1 <= len(nodes) <= 8 or any(not isinstance(x, str) or not DNS.fullmatch(x) for x in nodes) or len(set(nodes)) != len(nodes):
        raise Refusal("node_scope_invalid")
    origin(v["api_url"], True)
    if v["app_url"] is not None:
        origin(v["app_url"], False)
    for key in ("ca_file", "token_file"):
        if not isinstance(v[key], str) or not Path(v[key]).is_absolute():
            raise Refusal("credential_path_invalid")
    for key, low, high in (("timeout_ms", 1, 5000), ("max_response_bytes", 1024, 2097152)):
        if type(v[key]) is not int or not low <= v[key] <= high:
            raise Refusal("resource_bound_invalid")
    return v

def declarations(project):
    return {"schema": "project.concerns/v1", "project": project, "concerns": [{"id": project + ".kubernetes." + f, "question": "monitor.kubernetes." + f + ".published/v1", "profile": PROFILE, "required": True, "description": "Published Kubernetes " + f + " observation; no aggregate health claim."} for f in FAMILIES]}

def scalar(value):
    return value is None or type(value) in (bool, int) or isinstance(value, str) and len(value) <= 256 and not SECRET_PREFIX.match(value)

def select(value, names):
    if not isinstance(value, dict):
        return {}
    return {k: value[k] for k in names if k in value and scalar(value[k])}

def metadata(v):
    return select(v.get("metadata"), ("name", "namespace", "uid", "resourceVersion", "generation", "creationTimestamp", "deletionTimestamp"))

def conditions(v):
    if not isinstance(v, list):
        return []
    return [select(x, ("type", "status", "reason", "lastTransitionTime", "lastHeartbeatTime")) for x in v[:32]]

def addresses(values):
    result = []
    if not isinstance(values, list):
        return result
    for value in values[:4]:
        try:
            if not isinstance(value, str):
                continue
            result.append(str(ipaddress.ip_address(value)))
        except ValueError:
            continue
    return result

def normalize(family, v):
    out = {"metadata": metadata(v)}
    spec = v.get("spec", {}); status = v.get("status", {})
    if not isinstance(spec, dict) or not isinstance(status, dict):
        raise Refusal("native_object_invalid")
    if family == "nodes":
        out.update(node_info=select(status.get("nodeInfo"), ("bootID", "machineID", "systemUUID", "kubeletVersion", "containerRuntimeVersion", "kernelVersion", "osImage")), conditions=conditions(status.get("conditions")))
    elif family == "pods":
        out.update(spec=select(spec, ("nodeName",)), status=select(status, ("phase", "podIP", "hostIP", "startTime")), conditions=conditions(status.get("conditions")))
        out["containers"] = [select(x, ("name", "image", "imageID", "ready", "restartCount", "started")) | {"state": {k: select(y, ("reason", "exitCode", "startedAt", "finishedAt")) for k, y in x.get("state", {}).items() if k in ("running", "waiting", "terminated")}} for x in status.get("containerStatuses", [])[:16] if isinstance(x, dict)]
        out["owner_references"] = [select(x, ("kind", "name", "uid", "controller")) for x in v.get("metadata", {}).get("ownerReferences", [])[:16]]
    elif family == "deployments":
        out.update(spec=select(spec, ("replicas",)), status=select(status, ("observedGeneration", "replicas", "updatedReplicas", "readyReplicas", "availableReplicas", "unavailableReplicas")), conditions=conditions(status.get("conditions")))
        template = spec.get("template", {}).get("spec", {})
        out["containers"] = [select(x, ("name", "image")) for x in template.get("containers", [])[:16]]
    elif family == "services":
        out["spec"] = select(spec, ("type", "clusterIP", "publishNotReadyAddresses"))
        out["selector"] = {k: val for k, val in spec.get("selector", {}).items() if isinstance(k, str) and len(k) <= 100 and isinstance(val, str) and len(val) <= 100 and not SECRET_PREFIX.match(k) and not SECRET_PREFIX.match(val)}
        out["ports"] = [select(x, ("name", "protocol", "port", "targetPort", "nodePort")) for x in spec.get("ports", [])[:16]]
    elif family == "endpointslices":
        out["address_type"] = select(v, ("addressType",)).get("addressType")
        out["service_name"] = select(v.get("metadata", {}).get("labels", {}), ("kubernetes.io/service-name",)).get("kubernetes.io/service-name")
        out["endpoints"] = [{"addresses": addresses(ep.get("addresses", [])), "conditions": select(ep.get("conditions"), ("ready", "serving", "terminating")), "target_ref": select(ep.get("targetRef"), ("kind", "namespace", "name", "uid")), "node_name": select(ep, ("nodeName",)).get("nodeName")} for ep in v.get("endpoints", [])[:64] if isinstance(ep, dict)]
    return out

class Reader:
    def __init__(self, config):
        self.config = config
        self.started = time.monotonic()
        self.remaining_bytes = config["max_response_bytes"]
        ca_fd = os.open(config["ca_file"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            ca_info = os.fstat(ca_fd)
            if not stat.S_ISREG(ca_info.st_mode) or ca_info.st_size > 65536:
                raise Refusal("ca_custody_invalid")
            ca_bytes = os.read(ca_fd, 65537)
            if not ca_bytes or len(ca_bytes) > 65536:
                raise Refusal("ca_custody_invalid")
        finally:
            os.close(ca_fd)
        self.ca_sha256 = hashlib.sha256(ca_bytes).hexdigest()
        self.context = ssl.create_default_context(cadata=ca_bytes.decode("ascii"))
        path = Path(config["token_file"])
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid() or info.st_size > 8192:
                raise Refusal("reader_credential_custody_invalid")
            self.token = os.read(fd, 8193).decode("ascii").strip()
            after = os.fstat(fd)
            if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise Refusal("reader_credential_changed")
        finally:
            os.close(fd)
        if not self.token or len(self.token) > 8192 or not re.fullmatch(r"[A-Za-z0-9_.-]+", self.token):
            raise Refusal("reader_credential_invalid")
    def get(self, base, route, authenticated):
        remaining = self.config["timeout_ms"] / 1000 - (time.monotonic() - self.started)
        if remaining <= 0 or self.remaining_bytes <= 0:
            raise Refusal("acquisition_budget_exhausted")
        u = origin(base, authenticated)
        cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
        kw = {"timeout": remaining}
        if u.scheme == "https":
            kw["context"] = self.context
        conn = cls(u.hostname, u.port, **kw)
        headers = {"Accept": "application/json"}
        if authenticated:
            headers["Authorization"] = "Bearer " + self.token
        try:
            conn.request("GET", route, headers=headers)
            response = conn.getresponse()
            raw = response.read(min(262144, self.remaining_bytes) + 1)
            if len(raw) > min(262144, self.remaining_bytes):
                raise Refusal("native_response_bound")
            self.remaining_bytes -= len(raw)
            return response.status, parse(raw), hashlib.sha256(raw).hexdigest()
        except (OSError, http.client.HTTPException):
            raise Refusal("published_read_unavailable")
        finally:
            conn.close()

def collect(config, reader=None):
    started = stamp()
    monotonic_start = time.monotonic()
    r = reader if reader is not None else Reader(config)
    ns = quote(config["namespace"], safe="")
    code, namespace, ns_digest = r.get(config["api_url"], "/api/v1/namespaces/" + ns, True)
    if code != 200 or not isinstance(namespace, dict) or namespace.get("metadata", {}).get("uid") != config["namespace_uid"]:
        raise Refusal("namespace_identity_not_established")
    routes = { "pods": "/api/v1/namespaces/" + ns + "/pods?limit=64", "deployments": "/apis/apps/v1/namespaces/" + ns + "/deployments?limit=64", "services": "/api/v1/namespaces/" + ns + "/services?limit=64", "endpointslices": "/apis/discovery.k8s.io/v1/namespaces/" + ns + "/endpointslices?limit=64"}
    acquired = {"namespace": ("ACQUIRED", {"items": [normalize("namespace", namespace)], "source_sha256": ns_digest})}
    nodes = []; node_digests = []; node_errors = []
    for name in config["node_names"]:
        try:
            code, value, body_digest = r.get(config["api_url"], "/api/v1/nodes/" + quote(name, safe=""), True)
            if code != 200 or not isinstance(value, dict) or value.get("metadata", {}).get("name") != name:
                raise Refusal("node_scope_not_established")
            nodes.append(normalize("nodes", value)); node_digests.append(body_digest)
        except (Refusal, AttributeError, TypeError, KeyError):
            node_errors.append(name)
    acquired["nodes"] = ("PARTIAL" if node_errors and nodes else "UNAVAILABLE" if node_errors else "ACQUIRED", {"items": nodes, "source_sha256": node_digests, "missing_nodes": node_errors})
    for family, route in routes.items():
        try:
            code, data, source_digest = r.get(config["api_url"], route, True)
            if code != 200 or not isinstance(data, dict) or not isinstance(data.get("items"), list):
                raise Refusal("native_collection_unavailable")
            values = data["items"]
            partial = bool(data.get("metadata", {}).get("continue")) or len(values) > 64
            if any(x.get("metadata", {}).get("namespace") != config["namespace"] for x in values):
                raise Refusal("native_namespace_mismatch")
            acquired[family] = ("PARTIAL" if partial else "ACQUIRED", {"items": [normalize(family, x) for x in values[:64]], "source_sha256": source_digest})
        except (Refusal, AttributeError, TypeError, KeyError):
            acquired[family] = ("UNAVAILABLE", {"code": "published_collection_not_established"})
    for family, route in (("readiness", "/readyz"), ("version", "/version"), ("semantic", "/semantic")):
        try:
            if config["app_url"] is None:
                raise Refusal("application_probe_not_enrolled")
            code, data, source_digest = r.get(config["app_url"], route, False)
            facts = {"http_status": code, "source_sha256": source_digest, "probe": route}
            if isinstance(data, dict):
                facts["response"] = {k: v for k, v in data.items() if k in ("role", "version") and isinstance(v, str) and IDENT.fullmatch(v) and not SECRET_PREFIX.match(v) or k in ("ok", "dependency_ok") and type(v) is bool or k == "counter" and type(v) is int and v >= 0}
            acquired[family] = ("ACQUIRED", facts)
        except Refusal:
            acquired[family] = ("UNAVAILABLE", {"code": "published_probe_not_established"})
    code, final_namespace, _ = r.get(config["api_url"], "/api/v1/namespaces/" + ns, True)
    if code != 200 or not isinstance(final_namespace, dict) or final_namespace.get("metadata", {}).get("uid") != config["namespace_uid"]:
        raise Refusal("namespace_identity_changed_during_acquisition")
    finished = stamp()
    elapsed_ms = int((time.monotonic() - monotonic_start) * 1000)
    if elapsed_ms > config["timeout_ms"]:
        raise Refusal("acquisition_budget_exhausted")
    concerns = []
    for declaration in declarations(config["project"])["concerns"]:
        family = declaration["id"].rsplit(".", 1)[1]
        state, facts = acquired[family]
        facts["acquisition"] = {"started_at": started, "finished_at": finished, "snapshot_atomic": False, "duration_ms": elapsed_ms, "source_assertion_time_basis": "native_controller_timestamps_only"}
        facts["namespace_uid"] = config["namespace_uid"]
        concerns.append(declaration | {"observation": {"observation_present": state != "UNAVAILABLE", "local_state": state, "domain_state": None, "observed_at": finished if state != "UNAVAILABLE" else None, "valid_for_seconds": None, "reason": "Published snapshot acquisition " + state.lower() + "; native readiness is not semantic health and controller timestamps remain separate.", "facts": facts}})
    return {"schema": "project.ops.status/v1", "project": config["project"], "generated_at": finished, "manifest": {"schema": "project.concerns/v1", "path": ".ops/concerns.toml"}, "producer": {"id": "monitor.kubernetes-observation", "session_id": str(uuid.uuid4()), "version": "1"}, "authority": {"kind": "read-only-published-api", "effects": []}, "concerns": concerns, "extensions": {"owner": "Monitor", "contract": PROFILE, "no_health_or_current_support_claim": True, "scope": {"api_origin": config["api_url"], "ca_sha256": getattr(r, "ca_sha256", None), "namespace": config["namespace"], "namespace_uid": config["namespace_uid"], "registered_nodes": config["node_names"]}, "vantage": {"kind": "published-control-plane-api-and-application-http", "application_origin": config["app_url"]}}}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--declarations", action="store_true")
    args = parser.parse_args()
    try:
        raw = Path(args.config).read_bytes()
        if len(raw) > 16384:
            raise Refusal("settings_bound")
        config = settings(parse(raw))
        if args.declarations:
            output = declarations(config["project"])
        else:
            def deadline(_signum, _frame):
                raise Refusal("acquisition_deadline")
            signal.signal(signal.SIGALRM, deadline)
            signal.setitimer(signal.ITIMER_REAL, config["timeout_ms"] / 1000)
            try:
                output = collect(config)
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
        encoded = json.dumps(output, sort_keys=True, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > 2097152:
            raise Refusal("publication_byte_bound")
        print(encoded)
        return 0
    except (Refusal, OSError, UnicodeError, AttributeError, TypeError, KeyError):
        print(json.dumps({"schema": "monitor.kubernetes-read-refusal/v1", "owner": "Monitor", "reason": "scope_or_acquisition_not_established"}, sort_keys=True))
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
