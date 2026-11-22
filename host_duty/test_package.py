"""Exercise the relocated entry points and provenance of the real Debian package."""
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time

import pytest


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "packaging/host-duty/build-deb.sh"


@pytest.fixture(scope="module")
def installed(tmp_path_factory):
    scratch = tmp_path_factory.mktemp("host-duty-package")
    packages = scratch / "packages"
    assert BUILDER.is_file(), "an inert Debian package builder must deliver the installed commands"
    build = subprocess.run([str(BUILDER), "0.1.0+test", str(packages)],
                           capture_output=True, text=True, timeout=20)
    assert build.returncode == 0, build.stderr
    package = packages / "constellation-host-duty_0.1.0+test_all.deb"
    result = scratch / "extracted package"
    subprocess.run(["dpkg-deb", "-R", str(package), str(result)], check=True, timeout=10)
    return result


def checked(command, *args, cwd):
    run = subprocess.run([str(command), *args], cwd=cwd, capture_output=True, text=True,
                         env=dict(os.environ, PYTHONPATH=str(cwd)), timeout=5)
    assert run.returncode == 0, run.stderr
    return json.loads(run.stdout)


def test_extracted_operator_command_preserves_explicit_duty_across_processes(installed, tmp_path):
    command = installed / "usr/bin/constellation-host-duty"
    shadow = tmp_path / "host_duty"
    shadow.mkdir()
    (shadow / "__init__.py").write_text("raise RuntimeError('untrusted Python import')\n")
    (tmp_path / "sitecustomize.py").write_text("raise SystemExit('untrusted Python startup hook')\n")
    database = tmp_path / "ledger.sqlite"

    def run(*args):
        return checked(command, "--database", str(database), *args, cwd=tmp_path)

    missing = run("status", "fatbot", "--grace-seconds", "30")
    assert missing["schema"] == "project.ops.status/v1"
    assert {c["id"]: c["observation"]["local_state"] for c in missing["concerns"]} == {
        "duty.availability": "UNKNOWN", "duty.observation": "UNKNOWN", "duty.deadline": "UNKNOWN"}
    assert not database.exists()

    run("init")
    assert stat.S_IMODE(database.stat().st_mode) == 0o600
    run("register", "fatbot", "example-incarnation")
    run("assign", "duty-a", "work-a", "fatbot", "--deadline", str(int(time.time()) + 600))
    assert run("status", "fatbot")["extensions"]["report"]["availability_required"] is True
    run("release", "duty-a", "released", "--reason", "operator withdrew the assignment")
    assert run("list", "--host", "fatbot")["duties"][0]["disposition"] == "released"
    report = run("status", "fatbot")["extensions"]["report"]
    assert report["availability_required"] is False
    assert report["presence"] == "unknown"
    export = tmp_path / "latest.sqlite"
    assert run("export-observation", "fatbot", "--output", str(export))["snapshot_path"] == str(export)
    assert stat.S_IMODE(export.stat().st_mode) == 0o444


def test_extracted_sampler_produces_nonce_bound_linux_sample(installed, tmp_path):
    nonce = "a" * 64
    sample = checked(installed / "usr/bin/constellation-host-sample", "--nonce", nonce, cwd=tmp_path)
    assert sample["schema"] == "constellation.host_duty_sample.v1"
    assert sample["nonce"] == nonce
    machine_id = Path("/etc/machine-id").read_text().strip().encode()
    assert sample["machine_identity_sha256"] == hashlib.sha256(machine_id).hexdigest()


def test_package_records_exact_payload_and_git_context(installed):
    share = installed / "usr/share/doc/constellation-host-duty"
    build_info = dict(line.split("=", 1) for line in (share / "BUILDINFO").read_text().splitlines())
    git = ["git", "-C", str(ROOT)]
    head = subprocess.check_output([*git, "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output([*git, "status", "--porcelain", "--untracked-files=normal"], text=True)
    assert build_info["git_head"] == head
    assert build_info["git_worktree_state"] == ("dirty" if dirty else "clean")
    payload = installed / "usr/lib/constellation-host-duty/host_duty"
    assert {source.name for source in payload.iterdir()} == {
        "__init__.py", "core.py", "cli.py", "probe.py", "sample.py", "snapshot.py"}
    assert (share / "fixtures/host-duty-row-custody-v1.json").read_bytes() == (ROOT / "host_duty/fixtures/host-duty-row-custody-v1.json").read_bytes()
    subprocess.run(["sha256sum", "--check", str(share / "SHA256SUMS")],
                   cwd=installed, check=True, capture_output=True, timeout=5)
    for source in [*payload.glob("*.py"), *(installed / "usr/bin").iterdir()]:
        ast.parse(source.read_text(), filename=str(source), feature_version=(3, 10))
    assert not (installed / "etc/constellation-host-duty/probes.json").exists()
    assert not (installed / "var/lib/constellation-host-duty").exists()
    assert not (installed / "etc/systemd/system/timers.target.wants").exists()


def test_optional_custody_recipe_is_shipped_as_documentation_and_prepares_null_source_time(installed, tmp_path):
    import sqlite3
    examples = installed / "usr/share/doc/constellation-host-duty/examples"
    names = {"snapshot_custody.py", "capture-once.sh", "constellation-host-duty-custody.service.example", "constellation-host-duty-custody.timer.example"}
    assert {path.name for path in examples.iterdir()} == names
    for name in names:
        assert (examples/name).read_bytes() == (ROOT/"host_duty/examples"/name).read_bytes()
    ast.parse((examples/"snapshot_custody.py").read_text(), feature_version=(3, 10))
    assert not (installed/"lib/systemd/system/constellation-host-duty-custody.service").exists()
    assert not (installed/"lib/systemd/system/constellation-host-duty-custody.timer").exists()
    vector = json.loads((ROOT/"host_duty/fixtures/host-duty-row-custody-v1.json").read_text())
    missing = next(case for case in vector["cases"] if case["name"] == "missing")
    snapshot = tmp_path/"public.sqlite"
    with sqlite3.connect(snapshot) as connection:
        connection.execute("CREATE TABLE host_duty_observations (schema TEXT,host_id TEXT,instance_id TEXT,boot_id TEXT,source_observed_at REAL,source_state TEXT,source_sha256 TEXT,source_detail TEXT,telemetry_json TEXT,exported_at REAL)")
        connection.execute("INSERT INTO host_duty_observations VALUES (?,?,?,?,?,?,?,?,?,?)", missing["values"])
    snapshot.chmod(0o444)
    run = subprocess.run(["/usr/bin/python3", "-I", str(examples/"snapshot_custody.py"), "prepare",
        "--snapshot", str(snapshot), "--host", "fatbot", "--instance", "machine-a", "--reference", "fatbot-custody",
        "--evaluation-id", "capture-a", "--directory", str(tmp_path/"capture-a")], capture_output=True, text=True, timeout=5)
    assert run.returncode == 0, run.stderr
    expected = json.loads((tmp_path/"capture-a/expected.json").read_text())
    assert expected["values"][4] is None
    assert json.loads(run.stdout)["publication_assertion"] == "1970-01-01T00:16:45.500000+00:00"
