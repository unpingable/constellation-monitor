#!/usr/bin/env python3
"""Verify the staged Host-posture helper cohort and record its exact executable bytes."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

BINARIES = ("constellation-status", "pulse-nq-load-support")
ALIASES = ("pulse-load-pressure-producer", "pulse-load-pressure-receiver", "pulse-support-resolver")


def record(binary_dir, package_version, architecture):
    source = os.environ.get("MONITOR_SOURCE_COMMIT", "")
    build_id = os.environ.get("MONITOR_BUILD_IDENTITY", "")
    if not re.fullmatch(r"[0-9a-f]{40}", source):
        raise ValueError("MONITOR_SOURCE_COMMIT must name the full expected lowercase commit")
    if not re.fullmatch(r"[!-~]{1,256}", build_id):
        raise ValueError("MONITOR_BUILD_IDENTITY must name the expected build (1..256 ASCII bytes, no spaces)")
    target_prefix = {"amd64": "x86_64-", "arm64": "aarch64-"}[architecture]
    executables = {}
    cohort = None
    for name in BINARIES:
        path = Path(binary_dir) / name
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        output = subprocess.run([str(path), "--build-info"], check=True,
                                capture_output=True, timeout=10)
        if output.stderr:
            raise ValueError(f"{name}: build probe wrote to stderr")
        info = json.loads(output.stdout)
        if not isinstance(info, dict):
            raise ValueError(f"{name}: build probe is not an object")
        if info.get("schema") != "constellation.host_posture_helper.build_info.v1" or info.get("component") != name:
            raise ValueError(f"{name}: unexpected build-info identity")
        if info.get("source_commit") != source or info.get("build_id") != build_id:
            raise ValueError(f"{name}: missing or mismatched source/build identity")
        version = info.get("version")
        if not isinstance(version, str) or not version or not (
                package_version == version or package_version.startswith(version + "+")):
            raise ValueError(f"{name}: package version does not extend its crate version")
        target, rustc = info.get("target"), info.get("rustc")
        if not isinstance(target, str) or not target.startswith(target_prefix):
            raise ValueError(f"{name}: target does not match package architecture")
        if not isinstance(rustc, str) or not rustc.startswith("rustc "):
            raise ValueError(f"{name}: missing compiler identity")
        if type(info.get("debug_assertions")) is not bool:
            raise ValueError(f"{name}: missing build-profile flag")
        identity = (version, target, rustc, info["debug_assertions"])
        if cohort is not None and identity != cohort:
            raise ValueError(f"{name}: executable cohort has inconsistent build inputs")
        cohort = identity
        after = hashlib.sha256(path.read_bytes()).hexdigest()
        if before != after:
            raise ValueError(f"{name}: staged bytes changed during the build probe")
        executables[name] = {"sha256": after, "build_info": info}
    path = Path(binary_dir) / "constellation-host-posture"
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    output = subprocess.run([str(path), "--build-info"], check=True, capture_output=True, timeout=10)
    if output.stderr:
        raise ValueError("host-posture: build probe wrote to stderr")
    info = json.loads(output.stdout)
    expected = {
        "schema": "constellation.host_posture.build_info.v1",
        "component": "constellation-host-posture", "version": cohort[0],
        "source_repository": "constellation-monitor", "source_commit": source,
        "target_triple": cohort[1], "toolchain_identity": cohort[2],
        "build_profile": "debug" if cohort[3] else "release",
    }
    for field, value in expected.items():
        if info.get(field) != value:
            raise ValueError(f"host-posture: mismatched {field}")
    for field in ["source_tree_digest", "cargo_lock_digest"]:
        variable = "CONSTELLATION_HOST_POSTURE_" + field.upper()
        value = os.environ.get(variable, "")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", value) or info.get(field) != value:
            raise ValueError(f"host-posture: missing or mismatched {field}")
    if info.get("enabled_features_json") != "[]":
        raise ValueError("host-posture: expected the production feature set []")
    after = hashlib.sha256(path.read_bytes()).hexdigest()
    if before != after:
        raise ValueError("host-posture: staged bytes changed during the build probe")
    executables[path.name] = {"sha256": after, "build_info": info}
    aliases = {}
    for name in ALIASES:
        path = Path(binary_dir) / name
        if not path.is_symlink() or os.readlink(path) != "pulse-nq-load-support":
            raise ValueError(f"{name}: unexpected alias target")
        output = subprocess.run([str(path), "--build-info"], check=True, capture_output=True, timeout=10)
        info = json.loads(output.stdout)
        expected = dict(executables["pulse-nq-load-support"]["build_info"], component=name)
        if output.stderr or info != expected:
            raise ValueError(f"{name}: mismatched role build identity")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != executables["pulse-nq-load-support"]["sha256"]:
            raise ValueError(f"{name}: staged bytes changed during alias probe")
        aliases[name] = {"target": "pulse-nq-load-support", "sha256": digest, "build_info": info}
    return {
        "schema": "constellation.host_posture_helper.package_build_identity.v1",
        "package_version": package_version,
        "architecture": architecture,
        "source_commit": source,
        "build_id": build_id,
        "executables": executables,
        "aliases": aliases,
    }


def main():
    if len(sys.argv) != 5:
        raise ValueError("usage: record-build-identity.py STAGED_BIN_DIR VERSION ARCH OUTPUT")
    binary_dir, version, architecture, output = sys.argv[1:]
    receipt = record(binary_dir, version, architecture)
    Path(output).write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        sys.exit(f"Host-posture helper package identity refused: {error}")
