"""Bounded acquisition from explicitly configured off-host SSH samplers.

The local account/configuration is trusted. TCP failure describes this
observer's transport path; ordinary samples grant no diagnosis or action right.
These records and their source code are not NQ-admitted evidence.

One pass admits at most 30 seconds of configured target timeouts. A shared
monotonic deadline also caps every acquisition and prevents starting later
targets after exhaustion. It cannot bound OS scheduling, process creation or
uninterruptible kernel I/O; cleanup may consume an additional second per
started process. The service supervisor supplies the outer wall-clock limit.
Skipped/refused targets return an unrecorded UNKNOWN; prior ledger source times
remain unchanged and age naturally. A target-local refusal does not skip peers.
"""
import errno
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import socket
import sqlite3
import stat
import subprocess
import time

from .core import Ledger, Refused
from .snapshot import canonical_snapshot_path, publish_snapshot

CONFIG_SCHEMA = "constellation.host_duty_probe_config.v1"
SAMPLE_SCHEMA = "constellation.host_duty_sample.v1"
MAX_OUTPUT = 65536
PASS_BUDGET_SECONDS = 30
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
BOOT_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
TELEMETRY = {
    "uptime_seconds", "load1", "load5", "load15", "cpu_count",
    "memory_total_bytes", "memory_available_bytes", "swap_total_bytes",
    "swap_free_bytes", "root_total_bytes", "root_available_bytes",
}


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("non-finite JSON number")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def _text(value, name, maximum=256):
    if (not isinstance(value, str) or not value.strip() or len(value) > maximum
            or any(ord(c) < 32 for c in value)):
        raise ValueError("invalid " + name)
    return value


def validate_target(target):
    if not isinstance(target, dict):
        raise ValueError("target must be an object")
    required = {"host_id", "instance_id", "address", "argv", "machine_identity_sha256"}
    if not required <= target.keys() or target.keys() - required - {"port", "timeout_seconds", "snapshot_path"}:
        raise ValueError("unexpected or missing probe target fields")
    _text(target["host_id"], "host_id")
    _text(target["instance_id"], "instance_id")
    # Numeric addresses prevent an unbounded resolver call outside the process
    # deadline. The SSH command itself is subject to the process deadline.
    ipaddress.ip_address(_text(target["address"], "numeric endpoint address"))
    port = target.get("port", 22)
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("port must be an integer in 1..65535")
    timeout = target.get("timeout_seconds", 3)
    if (type(timeout) not in (int, float) or not 0.05 <= timeout <= 30
            or not math.isfinite(timeout)):
        raise ValueError("timeout_seconds must be finite in 0.05..30")
    argv = target["argv"]
    if not isinstance(argv, list) or not 1 <= len(argv) <= 128:
        raise ValueError("argv must explicitly name the trusted SSH sampler command")
    for arg in argv:
        _text(arg, "command argument", 4096)
    if not os.path.isabs(argv[0]):
        raise ValueError("sampler executable must be absolute")
    if not isinstance(target["machine_identity_sha256"], str) or not HEX64.fullmatch(target["machine_identity_sha256"]):
        raise ValueError("machine_identity_sha256 must be lowercase SHA-256")
    normalized = dict(target, port=port, timeout_seconds=timeout)
    if "snapshot_path" in target:
        if not os.path.isabs(_text(target["snapshot_path"], "snapshot_path", 4096)):
            raise ValueError("snapshot_path must be absolute")
        normalized["snapshot_path"] = str(canonical_snapshot_path(target["snapshot_path"]))
    return normalized


def load_config(path):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("configuration path must be absolute")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077):
            raise ValueError("configuration must be a regular owner-only file owned by this account")
        with os.fdopen(fd, "rb", closefd=False) as source:
            raw = source.read(MAX_OUTPUT + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_OUTPUT:
        raise ValueError("configuration exceeds size bound")
    config = _json(raw)
    if (not isinstance(config, dict) or set(config) != {"schema", "database", "targets"}
            or config["schema"] != CONFIG_SCHEMA):
        raise ValueError("invalid probe configuration schema")
    database = _text(config["database"], "database", 4096)
    if not os.path.isabs(database):
        raise ValueError("database path must be absolute")
    if not isinstance(config["targets"], list) or not 1 <= len(config["targets"]) <= 100:
        raise ValueError("configuration requires 1..100 explicit targets")
    targets = [validate_target(target) for target in config["targets"]]
    if math.fsum(target["timeout_seconds"] for target in targets) > PASS_BUDGET_SECONDS:
        raise ValueError("configured target timeouts exceed the 30-second pass budget")
    identities = [target["host_id"] for target in targets]
    if len(identities) != len(set(identities)):
        raise ValueError("duplicate host targets")
    outputs = [target["snapshot_path"] for target in targets if "snapshot_path" in target]
    protected = {str(path.resolve())}
    for base in {os.path.normpath(database), os.path.realpath(database)}:
        protected.update(base + suffix for suffix in ("", "-wal", "-shm", "-journal"))
    protected_ids = {(info.st_dev, info.st_ino)}
    for source in protected:
        try:
            existing = os.stat(source)
            protected_ids.add((existing.st_dev, existing.st_ino))
        except FileNotFoundError:
            pass
    if len(outputs) != len(set(outputs)) or set(outputs) & protected:
        raise ValueError("snapshot paths must be distinct and separate from the ledger, sidecars and probe configuration")
    output_ids = set()
    for output in outputs:
        try:
            existing = os.stat(output, follow_symlinks=False)
        except FileNotFoundError:
            continue
        identity = (existing.st_dev, existing.st_ino)
        if existing.st_nlink != 1 or identity in protected_ids or identity in output_ids:
            raise ValueError("snapshot destination identities must be distinct and separate from protected inputs")
        output_ids.add(identity)
    return dict(config, targets=targets)


def _kill_and_reap(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=1)


def _run(argv, deadline):
    """Drain bounded pipes and kill the owned group on timeout or flooding."""
    if time.monotonic() >= deadline:
        raise TimeoutError("sampler acquisition deadline exhausted before process start")
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, start_new_session=True,
        env={"PATH":"/usr/local/bin:/usr/bin:/bin", "LC_ALL":"C.UTF-8"})
    captured = {process.stdout: bytearray(), process.stderr: bytearray()}
    limits = {process.stdout: MAX_OUTPUT, process.stderr: 8192}
    try:
        with selectors.DefaultSelector() as selector:
            for pipe in captured:
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("sampler exceeded acquisition deadline")
                for key, _ in selector.select(remaining):
                    pipe = key.fileobj
                    try:
                        chunk = os.read(pipe.fileno(), 8192)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(pipe)
                        continue
                    if len(captured[pipe]) + len(chunk) > limits[pipe]:
                        raise ValueError("sampler exceeded output bound")
                    captured[pipe].extend(chunk)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("sampler exceeded acquisition deadline")
            process.wait(timeout=remaining)
        if process.returncode:
            raise ValueError("sampler process failed (exit %d)" % process.returncode)
        return bytes(captured[process.stdout])
    finally:
        # Also retire a descendant that closed its pipes before its leader
        # returned. A sampler has no authorized persistent subprocess lifetime.
        try:
            _kill_and_reap(process)
        finally:
            for pipe in captured:
                pipe.close()


def validate_sample(raw, target, nonce):
    if len(raw) > MAX_OUTPUT:
        raise ValueError("sample exceeds size bound")
    doc = _json(raw)
    if not isinstance(doc, dict) or set(doc) != {"schema", "nonce", "machine_identity_sha256", "boot_id", "telemetry"}:
        raise ValueError("unexpected or missing sample fields")
    if doc["schema"] != SAMPLE_SCHEMA or doc["nonce"] != nonce:
        raise ValueError("sample schema or nonce mismatch")
    if doc["machine_identity_sha256"] != target["machine_identity_sha256"]:
        raise ValueError("sample machine identity mismatch")
    if not isinstance(doc["boot_id"], str) or not BOOT_ID.fullmatch(doc["boot_id"]):
        raise ValueError("invalid sample boot identity")
    telemetry = doc["telemetry"]
    if not isinstance(telemetry, dict) or set(telemetry) != TELEMETRY:
        raise ValueError("unexpected or missing telemetry fields")
    for key, value in telemetry.items():
        if type(value) not in (int, float) or value < 0:
            raise ValueError("non-finite or negative telemetry")
        maximum = 10 ** 12 if key == "uptime_seconds" else 10 ** 6 if key in {"load1", "load5", "load15", "cpu_count"} else 2 ** 63 - 1
        if value > maximum or not math.isfinite(value):
            raise ValueError("telemetry exceeds field bound")
        if key not in {"uptime_seconds", "load1", "load5", "load15"} and type(value) is not int:
            raise ValueError("telemetry count must be an integer")
    if not 1 <= telemetry["cpu_count"]:
        raise ValueError("invalid CPU count")
    for total, available in [("memory_total_bytes", "memory_available_bytes"),
            ("swap_total_bytes", "swap_free_bytes"), ("root_total_bytes", "root_available_bytes")]:
        if telemetry[available] > telemetry[total] or (total != "swap_total_bytes" and telemetry[total] == 0):
            raise ValueError("invalid telemetry capacity")
    return doc


def _unrecorded(target, detail):
    return {"host_id":target["host_id"], "instance_id":target["instance_id"],
            "state":"unknown", "recorded":False, "observed_at":None, "detail":detail[:300]}


def collect_target(ledger, target, clock=None, *, pass_deadline=None):
    target = validate_target(target)
    observed_at = (clock or time.time)()
    deadline = time.monotonic() + target["timeout_seconds"]
    if pass_deadline is not None:
        deadline = min(deadline, pass_deadline)
    if time.monotonic() >= deadline:
        return _unrecorded(target, "pass deadline exhausted; target acquisition was not started")
    state, detail, sample, raw = "unknown", "", None, None
    address = ipaddress.ip_address(target["address"])
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    connected = False
    try:
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.settimeout(max(0.001, deadline - time.monotonic()))
            try:
                connection.connect((str(address), target["port"]))
            except OSError as exc:
                if isinstance(exc, TimeoutError) or exc.errno in {
                        errno.ECONNREFUSED, errno.ETIMEDOUT, errno.ENETUNREACH,
                        errno.EHOSTUNREACH, errno.ECONNRESET}:
                    state = "unreachable"
                    detail = "TCP endpoint unreachable from this observer; host death is not established"
                else:
                    detail = "Observer TCP acquisition failed locally; target presence unknown: " + type(exc).__name__
            else:
                connected = True
    except OSError as exc:
        connected = False
        state = "unknown"
        detail = "Observer socket setup failed; target presence unknown: " + type(exc).__name__
    if connected:
        try:
            nonce = secrets.token_hex(32)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("acquisition deadline exhausted")
            raw = _run(target["argv"] + ["--nonce", nonce], deadline)
            sample = validate_sample(raw, target, nonce)
            state = "reachable"
            detail = "Identity and nonce bound external sample; no complete host-health or action-authority claim"
        except (OSError, ValueError, UnicodeError, RecursionError, TimeoutError, subprocess.SubprocessError) as exc:
            detail = "TCP endpoint reached; sample unavailable or invalid: " + str(exc)[:300]
    observation = {"observed_at":observed_at, "detail":detail}
    if sample is not None:
        observation.update(boot_id=sample["boot_id"], telemetry=sample["telemetry"],
                           source_sha256=hashlib.sha256(raw).hexdigest())
    # The ledger checks incarnation again here, after the network work; a
    # replacement during acquisition must refuse the superseded binding.
    ledger.observe(target["host_id"], target["instance_id"], state, **observation)
    return {"host_id":target["host_id"], "instance_id":target["instance_id"],
            "state":state, "recorded":True, **observation}


def collect_config(path, *, budget_seconds=PASS_BUDGET_SECONDS):
    # Callers may tighten the acquisition budget; configuration/CLI cannot
    # expand the fixed admission limit or manufacture a new source timestamp.
    if (type(budget_seconds) not in (int, float) or not 0 < budget_seconds <= PASS_BUDGET_SECONDS
            or not math.isfinite(budget_seconds)):
        raise ValueError("pass budget must be positive and at most 30 seconds")
    deadline = time.monotonic() + budget_seconds
    config = load_config(path)
    observations = []
    with Ledger(config["database"]) as ledger:
        for target in config["targets"]:
            if time.monotonic() >= deadline:
                row = _unrecorded(target, "pass deadline exhausted; target acquisition was not started")
            else:
                try:
                    row = collect_target(ledger, target, pass_deadline=deadline)
                except Refused as exc:
                    row = _unrecorded(target, "target observation refused: " + str(exc))
            if "snapshot_path" in target:
                try:
                    row["snapshot"] = publish_snapshot(ledger, target["host_id"], target["snapshot_path"])
                except (OSError, ValueError, sqlite3.Error) as exc:
                    row["snapshot_error"] = (type(exc).__name__ + ": " + str(exc))[:300]
            observations.append(row)
    return observations
