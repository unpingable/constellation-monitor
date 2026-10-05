#!/usr/bin/env python3
"""Finite correspondence and published-native-data boundary tests."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import http.server
import threading
import time
import ssl
import subprocess
import os
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("collector", Path(__file__).with_name("kubernetes_observation.py"))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
CONFIG = {"schema": m.SCHEMA, "project": "qualification-app", "api_url": "https://127.0.0.1:6443", "ca_file": "/installed/ca.pem", "token_file": "/private/reader-token", "namespace": "case-123", "namespace_uid": "exact-namespace-uid", "node_names": ["node-a", "node-b"], "app_url": "http://127.0.0.1:18080", "timeout_ms": 5000, "max_response_bytes": 2097152}

class PublishedFixture:
    def __init__(self):
        self.calls = []
        self.fail = set()
        self.namespace_reads = 0
        self.replaced_namespace = False
        self.partial = False
        self.old_stamp = "2020-01-01T00:00:00Z"
    def get(self, origin, route, authenticated):
        self.calls.append((origin, route, authenticated))
        if route in self.fail:
            raise m.Refusal("fixture_connection_refused")
        if route.startswith("/api/v1/namespaces/") and "?" not in route and route.count("/") == 4:
            self.namespace_reads += 1
            uid = "changed" if self.replaced_namespace and self.namespace_reads > 1 else CONFIG["namespace_uid"]
            return 200, {"metadata": {"name": CONFIG["namespace"], "uid": uid}}, "a" * 64
        if route.startswith("/api/v1/nodes/"):
            name = route.rsplit("/", 1)[1]
            return 200, {"metadata": {"name": name, "uid": "uid-" + name}, "status": {"nodeInfo": {"bootID": "host-boot", "kubeletVersion": "v1.35.2"}, "conditions": [{"type": "Ready", "status": "True", "lastHeartbeatTime": self.old_stamp}]}}, "b" * 64
        if authenticated:
            meta = {"namespace": CONFIG["namespace"], "name": "frontend", "uid": "uid-frontend", "resourceVersion": "123", "generation": 2, "annotations": {"credential": "Bearer PRIVATE_VALUE"}}
            value = {"metadata": meta, "spec": {"nodeName": "node-a", "containers": [{"name": "frontend", "env": [{"value": "SECRET"}]}]}, "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True", "lastTransitionTime": self.old_stamp}], "containerStatuses": [{"name": "frontend", "ready": True, "imageID": "sha256:abc", "restartCount": 3, "state": {"waiting": {"reason": "CrashLoopBackOff", "message": "Bearer PRIVATE_VALUE"}}}]}}
            return 200, {"metadata": {"continue": "next" if self.partial else ""}, "items": [value]}, "c" * 64
        return (503 if route == "/semantic" else 200), {"role": "frontend", "version": "v1", "ok": route != "/semantic", "dependency_ok": False, "counter": 17, "token": "Bearer PRIVATE_VALUE", "env": "SECRET", "description": "untrusted text"}, "d" * 64

def by_name(output, name):
    return next(x["observation"] for x in output["concerns"] if x["id"].endswith("." + name))

class CollectorTests(unittest.TestCase):
    def test_closed_settings(self):
        self.assertEqual(m.settings(copy.deepcopy(CONFIG)), CONFIG)
        for key, value in (("command", "delete"), ("kubeconfig", "/ambient")):
            bad = copy.deepcopy(CONFIG); bad[key] = value
            with self.assertRaises(m.Refusal): m.settings(bad)
    def test_scope_paths_refused(self):
        for key, value in (("namespace", "../other"), ("namespace_uid", ""), ("node_names", ["node-a", "node-a"]), ("node_names", [{}]), ("api_url", "https://127.0.0.1:6443/arbitrary"), ("api_url", "http://127.0.0.1:6443"), ("api_url", "https://secret@127.0.0.1:6443"), ("app_url", "http://127.0.0.1:18080/production"), ("timeout_ms", True)):
            bad = copy.deepcopy(CONFIG); bad[key] = value
            with self.assertRaises(m.Refusal): m.settings(bad)
    def test_declared_correspondence(self):
        out = m.collect(CONFIG, PublishedFixture())
        self.assertEqual([ {k: x[k] for k in ("id", "question", "profile", "required", "description")} for x in out["concerns"]], m.declarations(CONFIG["project"])["concerns"])
    def test_no_ready_equals_semantic_health(self):
        out = m.collect(CONFIG, PublishedFixture())
        self.assertEqual(by_name(out, "readiness")["facts"]["http_status"], 200)
        self.assertEqual(by_name(out, "semantic")["facts"]["http_status"], 503)
        self.assertFalse(by_name(out, "semantic")["facts"]["response"]["ok"])
        self.assertNotIn("health", out)
        self.assertTrue(all(x["observation"]["valid_for_seconds"] is None for x in out["concerns"]))
    def test_secret_and_environment_not_captured(self):
        out = m.collect(CONFIG, PublishedFixture())
        raw = json.dumps(out)
        for value in ("Bearer PRIVATE_VALUE", "SECRET", "untrusted text", "annotations", "env", "message"):
            self.assertNotIn(value, raw)
    def test_no_ground_truth_input(self):
        bad = copy.deepcopy(CONFIG); bad["expected_root_cause"] = "service failed"
        with self.assertRaises(m.Refusal): m.settings(bad)
        self.assertNotIn("oracle", json.dumps(m.collect(CONFIG, PublishedFixture())))
    def test_registered_node_paths_and_probe_authorization(self):
        fixture = PublishedFixture(); m.collect(CONFIG, fixture)
        self.assertEqual([route for _, route, _ in fixture.calls if route.startswith("/api/v1/nodes")], ["/api/v1/nodes/node-a", "/api/v1/nodes/node-b"])
        self.assertTrue(all(not auth for _, route, auth in fixture.calls if route in ("/readyz", "/version", "/semantic")))
        self.assertTrue(all("secrets" not in route and "exec" not in route and "logs" not in route for _, route, _ in fixture.calls))
    def test_native_timestamps_not_rejuvenated(self):
        out = m.collect(CONFIG, PublishedFixture())
        node = by_name(out, "nodes")["facts"]["items"][0]
        self.assertEqual(node["conditions"][0]["lastHeartbeatTime"], "2020-01-01T00:00:00Z")
        self.assertNotEqual(by_name(out, "nodes")["observed_at"], node["conditions"][0]["lastHeartbeatTime"])
    def test_unavailable_not_empty_current(self):
        fixture = PublishedFixture(); fixture.fail.add("/api/v1/namespaces/case-123/pods?limit=64")
        out = m.collect(CONFIG, fixture); obs = by_name(out, "pods")
        self.assertEqual(obs["local_state"], "UNAVAILABLE")
        self.assertFalse(obs["observation_present"])
        self.assertIsNone(obs["observed_at"])
    def test_partial_collection_preserved(self):
        fixture = PublishedFixture(); fixture.partial = True
        self.assertEqual(by_name(m.collect(CONFIG, fixture), "pods")["local_state"], "PARTIAL")
    def test_missing_registered_node_preserved(self):
        fixture = PublishedFixture(); fixture.fail.add("/api/v1/nodes/node-b")
        obs = by_name(m.collect(CONFIG, fixture), "nodes")
        self.assertEqual(obs["local_state"], "PARTIAL")
        self.assertEqual(obs["facts"]["missing_nodes"], ["node-b"])
    def test_namespace_replacement_refuses(self):
        fixture = PublishedFixture(); fixture.replaced_namespace = True
        with self.assertRaises(m.Refusal): m.collect(CONFIG, fixture)
    def test_duplicate_json_and_constants_refused(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}'):
            with self.assertRaises(m.Refusal): m.parse(raw)
    def test_endpoint_fields_cannot_capture_nested_or_secret_data(self):
        out = m.normalize("endpointslices", {"metadata": {"labels": {"kubernetes.io/service-name": {"secret": "private"}}}, "addressType": {"secret": "private"}, "endpoints": [{"addresses": ["Bearer PRIVATE", "127.0.0.1"], "nodeName": {"env": "private"}}]})
        self.assertNotIn("private", json.dumps(out))
        self.assertEqual(out["endpoints"][0]["addresses"], ["127.0.0.1"])
    def test_unknown_native_enum_preserved(self):
        out = m.normalize("pods", {"metadata": {"uid": "pod-uid"}, "status": {"phase": "FuturePodState"}})
        self.assertEqual(out["status"]["phase"], "FuturePodState")
    def test_secret_like_allowed_field_refused(self):
        self.assertEqual(m.select({"imageID": "Bearer PRIVATE"}, ("imageID",)), {})
        class Changed(PublishedFixture):
            def get(self, base, route, authenticated):
                code, data, digest = super().get(base, route, authenticated)
                if not authenticated: data["version"] = "sk-proj-private"
                return code, data, digest
        self.assertNotIn("sk-proj-private", json.dumps(m.collect(CONFIG, Changed())))
    def test_actual_http_headers_and_route(self):
        received = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                received.append((self.path, self.headers.get("Authorization")))
                raw = b'{"role":"frontend","ok":true}'
                self.send_response(200); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
            def log_message(self, *args): pass
        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            reader = m.Reader.__new__(m.Reader); reader.config = CONFIG; reader.started = time.monotonic(); reader.remaining_bytes = 2097152; reader.token = "never-send-this-to-app"
            code, result, digest = reader.get("http://127.0.0.1:" + str(server.server_port), "/semantic", False)
            self.assertEqual(code, 200); self.assertTrue(result["ok"])
            self.assertEqual(received, [("/semantic", None)])
        finally:
            server.shutdown(); thread.join(); server.server_close()
    def test_actual_redirect_not_followed(self):
        received = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                received.append(self.path)
                raw = b'{}'; self.send_response(302); self.send_header("Location", "/elsewhere"); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(raw)
            def log_message(self, *args): pass
        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            reader = m.Reader.__new__(m.Reader); reader.config = CONFIG; reader.started = time.monotonic(); reader.remaining_bytes = 2097152
            code, result, digest = reader.get("http://127.0.0.1:" + str(server.server_port), "/semantic", False)
            self.assertEqual(code, 302); self.assertEqual(received, ["/semantic"])
        finally:
            server.shutdown(); thread.join(); server.server_close()
    def test_exact_token_descriptor_custody(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); ca = root / "ca.pem"; ca.write_text("public-ca-fixture"); token = root / "token"; token.write_text("testtoken"); token.chmod(0o600)
            config = CONFIG | {"ca_file": str(ca), "token_file": str(token)}
            with patch.object(m.ssl, "create_default_context", return_value=object()):
                self.assertEqual(m.Reader(config).token, "testtoken")
                token.chmod(0o644)
                with self.assertRaises(m.Refusal): m.Reader(config)
                token.chmod(0o600); link = root / "link"; link.symlink_to(token)
                with self.assertRaises(OSError): m.Reader(config | {"token_file": str(link)})
    def test_actual_tls_published_collections(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); ca = root / "ca.pem"; key = root / "key.pem"; token = root / "token"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(ca), "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1", "-days", "1"], check=True, timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            token.write_text("testtoken"); token.chmod(0o600)
            fixture = PublishedFixture(); authorization = []
            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    auth = self.path.startswith("/api")
                    authorization.append((self.path, self.headers.get("Authorization")))
                    code, data, _ = fixture.get("unused", self.path, auth)
                    raw = json.dumps(data).encode(); self.send_response(code); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
                def log_message(self, *args): pass
            server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(ca, key); server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            try:
                url = "https://127.0.0.1:" + str(server.server_port)
                config = CONFIG | {"api_url": url, "app_url": url, "ca_file": str(ca), "token_file": str(token)}
                out = m.collect(config)
                self.assertEqual(by_name(out, "pods")["local_state"], "ACQUIRED")
                self.assertEqual(by_name(out, "semantic")["facts"]["http_status"], 503)
                self.assertTrue(all(value == ("Bearer testtoken" if path.startswith("/api") else None) for path, value in authorization))
                self.assertEqual(len(out["extensions"]["scope"]["ca_sha256"]), 64)
            finally:
                server.shutdown(); thread.join(); server.server_close()
    def test_topology_separate_generation(self):
        out = m.collect(CONFIG, PublishedFixture()); pod = by_name(out, "pods")["facts"]["items"][0]
        self.assertEqual(pod["metadata"]["uid"], "uid-frontend")
        self.assertEqual(pod["metadata"]["generation"], 2)
        self.assertEqual(out["extensions"]["scope"]["namespace_uid"], CONFIG["namespace_uid"])
        self.assertFalse(by_name(out, "pods")["facts"]["acquisition"]["snapshot_atomic"])

if __name__ == "__main__": unittest.main()
