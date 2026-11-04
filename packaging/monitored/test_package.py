"""Exercise the installed reader command from the actual inert Debian package."""
import hashlib
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]


def test_package_delivers_read_only_diagnostic_and_keeps_unknown_unknown(tmp_path):
    output = tmp_path / "packages"
    subprocess.run([str(ROOT / "packaging/monitored/build-deb.sh"),
                    "0.1.0+diagnostic.test", str(output)], check=True, capture_output=True)
    package = output / "constellation-monitored_0.1.0+diagnostic.test_all.deb"
    installed = tmp_path / "installed"
    subprocess.run(["dpkg-deb", "-x", str(package), str(installed)], check=True)
    command = installed / "usr/bin/constellation-diagnostic"
    assert command.is_file(), "the monitored package must deliver its diagnostic command"
    assert command.stat().st_mode & 0o111
    assert command.read_bytes() == (ROOT / "diagnostic/constellation-diagnostic.py").read_bytes()
    readme = installed / "usr/share/doc/constellation-monitored/DIAGNOSTIC.md"
    assert readme.read_bytes() == (ROOT / "diagnostic/README.md").read_bytes()
    assert "\nconstellation-diagnostic " in readme.read_text()
    record = tmp_path / "investigation.json"
    argv = [str(command), "--registry", str(tmp_path / "missing-registry.json"),
            "--attention", str(tmp_path / "missing-attention.json"), "--service", "worker",
            "--instance", "127.0.0.1:1", "--job", "service-worker", "--record", str(record)]
    completed = subprocess.run(argv, capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result == json.loads(record.read_text())
    assert result["schema"] == "constellation.diagnostic/v1"
    assert result["bins"]["unknown"]
    assert not result["bins"]["wrong"]
    assert not result["bins"]["probably_wrong"]
    assert not result["bins"]["checked_not_wrong_within_scope"]
    assert record.stat().st_mode & 0o777 == 0o600
    before = hashlib.sha256(record.read_bytes()).hexdigest()
    refused = subprocess.run(argv, capture_output=True, text=True)
    assert refused.returncode == 3, "an existing investigation must not be overwritten"
    assert hashlib.sha256(record.read_bytes()).hexdigest() == before
    assert not list((installed / "lib/systemd/system").glob("*diagnostic*"))
