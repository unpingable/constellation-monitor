"""Real loopback/process tests for bounded, identity-bound acquisition."""
import contextlib
import errno
import hashlib
import importlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def implementation():
    try:
        return importlib.import_module("host_duty.probe")
    except ModuleNotFoundError:
        pytest.fail("Missing behavior: an external probe must bind and bound each acquired sample")


class Observations:
    def __init__(self):
        self.rows = []

    def observe(self, host_id, instance_id, state, **kw):
        self.rows.append(dict(host_id=host_id, instance_id=instance_id, state=state, **kw))


@contextlib.contextmanager
def endpoint(with_socket=False):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    try:
        yield (listener.getsockname()[1], listener) if with_socket else listener.getsockname()[1]
    finally:
        listener.close()


def target(tmp_path, port, code=None):
    script = tmp_path / "fixture.py"
    if code is None:
        code = """import json, sys
nonce = sys.argv[sys.argv.index('--nonce') + 1]
print(json.dumps({
 'schema':'constellation.host_duty_sample.v1', 'nonce':nonce,
 'machine_identity_sha256':'a'*64,
 'boot_id':'11111111-2222-4333-8444-555555555555',
 'telemetry': {'uptime_seconds':10.0, 'load1':0.1, 'load5':0.2, 'load15':0.3,
 'memory_total_bytes':1000, 'memory_available_bytes':500,
 'swap_total_bytes':200, 'swap_free_bytes':200, 'cpu_count':2,
 'root_total_bytes':10000, 'root_available_bytes':5000}}))
"""
    script.write_text(code)
    return dict(host_id="fatbot", instance_id="machine-a", address="127.0.0.1",
                port=port, argv=[sys.executable, str(script)],
                machine_identity_sha256="a" * 64, timeout_seconds=0.5)


def test_valid_sample_records_bound_identity_and_observer_start(tmp_path):
    probe = implementation()
    ledger = Observations()
    with endpoint() as port:
        result = probe.collect_target(ledger, target(tmp_path, port), clock=lambda: 1234)
    row = ledger.rows[0]
    assert result["state"] == row["state"] == "reachable"
    assert row["host_id"] == "fatbot"
    assert row["instance_id"] == "machine-a"
    assert row["boot_id"] == "11111111-2222-4333-8444-555555555555"
    assert row["observed_at"] == 1234
    assert row["telemetry"]["memory_available_bytes"] == 500
    assert len(row["source_sha256"]) == 64


def test_closed_transport_is_observer_unreachable_and_never_runs_sampler(tmp_path):
    probe = implementation()
    ledger = Observations()
    with endpoint() as port:
        pass
    marker = tmp_path / "ran"
    conf = target(tmp_path, port, "from pathlib import Path\nPath(%r).touch()\n" % str(marker))
    result = probe.collect_target(ledger, conf)
    assert result["state"] == "unreachable"
    assert "observer" in ledger.rows[0]["detail"]
    assert not marker.exists()


@pytest.mark.parametrize("mutate", [
    "doc['nonce'] = 'b'*64", "doc['machine_identity_sha256'] = 'b'*64",
    "doc['schema'] = 'wrong'", "doc['boot_id'] = 'not-a-boot'",
    "doc['telemetry']['load1'] = float('nan')",
    "doc['telemetry']['load1'] = 10**400",
    "doc['telemetry']['memory_available_bytes'] = 2000",
    "doc['telemetry']['cpu_count'] = True",
    "doc['remote_clock'] = 9999999999999999",
])
def test_bad_binding_or_telemetry_is_unknown_not_reachable(tmp_path, mutate):
    probe = implementation()
    ledger = Observations()
    with endpoint() as port:
        conf = target(tmp_path, port)
        original = Path(conf["argv"][1]).read_text()
        original = original.replace("print(json.dumps({", "doc = {").replace("}}))", "}}\n")
        Path(conf["argv"][1]).write_text(original + mutate + "\nprint(json.dumps(doc))\n")
        result = probe.collect_target(ledger, conf)
    assert result["state"] == "unknown"
    assert ledger.rows[0]["state"] == "unknown"
    assert ledger.rows[0].get("telemetry") is None


@pytest.mark.parametrize("code", ["import time\ntime.sleep(30)\n",
    "import os\nwhile True: os.write(1,b'x'*8192)\n",
    "import os\nwhile True: os.write(2,b'x'*8192)\n",
    "raise SystemExit(255)\n", "print('{malformed')\n"])
def test_bounded_process_failure_is_unknown(tmp_path, code):
    probe = implementation()
    ledger = Observations()
    start = time.monotonic()
    with endpoint() as port:
        result = probe.collect_target(ledger, target(tmp_path, port, code))
    assert time.monotonic() - start < 3
    assert result["state"] == ledger.rows[0]["state"] == "unknown"


def test_timeout_kills_descendant_after_leader_exits(tmp_path):
    probe = implementation()
    marker = tmp_path / "descendant-survived"
    ready = tmp_path / "descendant-started"
    code = """import os, time
if os.fork() == 0:
 open(%r, 'w').write('started')
 time.sleep(0.9)
 open(%r, 'w').write('survived')
 os._exit(0)
os._exit(0)
""" % (str(ready), str(marker))
    with endpoint() as port:
        result = probe.collect_target(Observations(), target(tmp_path, port, code))
    assert result["state"] == "unknown"
    assert ready.exists()
    time.sleep(0.7)
    assert not marker.exists()


def test_output_flood_kills_descendant(tmp_path):
    probe = implementation()
    marker = tmp_path / "descendant-survived"
    ready = tmp_path / "descendant-started"
    code = """import os, time
pid = os.fork()
if pid == 0:
 open(%r, 'w').write('started')
 time.sleep(0.5)
 open(%r, 'w').write('survived')
 os._exit(0)
while not os.path.exists(%r): time.sleep(0.001)
while True: os.write(1, b'x'*8192)
""" % (str(ready), str(marker), str(ready))
    with endpoint() as port:
        result = probe.collect_target(Observations(), target(tmp_path, port, code))
    assert result["state"] == "unknown"
    assert ready.exists()
    time.sleep(0.7)
    assert not marker.exists()


def test_config_is_explicit_owner_only_and_does_not_initialize_ledger(tmp_path):
    probe = implementation()
    conf = tmp_path / "probe.json"
    conf.write_text(json.dumps({"schema":"constellation.host_duty_probe_config.v1",
        "database": str(tmp_path / "absent.sqlite"), "targets": [target(tmp_path, 12345)]}))
    conf.chmod(0o600)
    parsed = probe.load_config(conf)
    assert parsed["targets"][0]["port"] == 12345
    with pytest.raises((OSError, ValueError)):
        probe.collect_config(conf)
    assert not (tmp_path / "absent.sqlite").exists()
    conf.chmod(0o644)
    with pytest.raises(ValueError, match="owner"):
        probe.load_config(conf)


@pytest.mark.parametrize("change", [
    {"address":"localhost"}, {"timeout_seconds":float('inf')},
    {"timeout_seconds":10**400},
    {"port":True}, {"argv":["relative-ssh"]}, {"machine_identity_sha256":"bad"},
])
def test_invalid_config_target_refuses_before_network(tmp_path, change):
    probe = implementation()
    conf = tmp_path / "probe.json"
    spec = target(tmp_path, 22)
    spec.update(change)
    conf.write_text(json.dumps({"schema":"constellation.host_duty_probe_config.v1",
        "database":str(tmp_path / "ledger.sqlite"), "targets":[spec]}))
    conf.chmod(0o600)
    with pytest.raises(ValueError):
        probe.load_config(conf)


def test_linux_sampler_echoes_nonce_and_local_identity_with_bounded_telemetry():
    implementation()
    result = subprocess.run([sys.executable, "-m", "host_duty.sample", "--nonce", "e" * 64],
        capture_output=True, timeout=3)
    assert result.returncode == 0, result.stderr
    assert len(result.stdout) <= 65536
    doc = json.loads(result.stdout)
    assert doc["schema"] == "constellation.host_duty_sample.v1"
    assert doc["nonce"] == "e" * 64
    machine = Path("/etc/machine-id").read_text().strip().encode()
    assert doc["machine_identity_sha256"] == hashlib.sha256(machine).hexdigest()
    assert doc["telemetry"]["memory_total_bytes"] > 0
    assert doc["telemetry"]["cpu_count"] > 0


def test_sampler_refuses_invalid_nonce():
    implementation()
    result = subprocess.run([sys.executable, "-m", "host_duty.sample", "--nonce", "bad"],
        capture_output=True, timeout=3)
    assert result.returncode != 0
    assert not result.stdout


def test_replacement_during_acquisition_refuses_old_binding_without_writer_lock(tmp_path):
    """A live acquisition must neither block replacement nor cross incarnations."""
    probe = implementation()
    from host_duty.core import Ledger, Refused

    database = tmp_path / "ledger.sqlite"
    with Ledger.create(database) as ledger:
        ledger.register("fatbot", "machine-a")
    started, finish = tmp_path / "started", tmp_path / "finish"
    errors = []
    with endpoint() as port:
        spec = target(tmp_path, port)
        script = Path(spec["argv"][1])
        original = script.read_text()
        script.write_text("import pathlib, time\npathlib.Path(%r).touch()\nwhile not pathlib.Path(%r).exists(): time.sleep(0.01)\n" %
                          (str(started), str(finish)) + original)
        spec["timeout_seconds"] = 3

        def acquire():
            try:
                with Ledger(database) as ledger:
                    probe.collect_target(ledger, spec)
            except Exception as exc:
                errors.append(exc)

        worker = threading.Thread(target=acquire)
        worker.start()
        try:
            until = time.monotonic() + 2
            while not started.exists() and time.monotonic() < until:
                time.sleep(0.01)
            assert started.exists(), errors
            with Ledger(database) as ledger:
                ledger.replace("fatbot", "machine-b", "replacement during acquisition")
        finally:
            finish.touch()
            worker.join(timeout=4)
        assert not worker.is_alive()
    assert len(errors) == 1 and isinstance(errors[0], Refused)
    with Ledger(database) as ledger:
        report = ledger.report("fatbot")
    assert report["instance_id"] == "machine-b"
    assert report["boot_id"] is None


def write_config(tmp_path, database, targets):
    path = tmp_path / "pass-config.json"
    path.write_text(json.dumps({"schema":"constellation.host_duty_probe_config.v1",
                               "database":str(database), "targets":targets}))
    path.chmod(0o600)
    return path


def test_aggregate_over_budget_refuses_before_any_socket(tmp_path):
    probe = implementation()
    from host_duty.core import Ledger

    database = tmp_path / "ledger.sqlite"
    with Ledger.create(database) as ledger:
        ledger.register("fatbot", "machine-a")
        ledger.register("gojira", "machine-b")
    with endpoint(with_socket=True) as (port, listener):
        first = target(tmp_path, port)
        first["timeout_seconds"] = 16
        second = dict(first, host_id="gojira", instance_id="machine-b")
        config = write_config(tmp_path, database, [first, second])
        with pytest.raises(ValueError, match="30"):
            probe.load_config(config)
        with pytest.raises(ValueError, match="30"):
            probe.collect_config(config)
        # Inspect the actual listener queue: no target TCP acquisition started.
        listener.settimeout(0.05)
        with pytest.raises(TimeoutError):
            listener.accept()
    with Ledger(database) as ledger:
        assert ledger.report("fatbot")["boot_id"] is None
        assert ledger.report("gojira")["boot_id"] is None


def test_one_replaced_target_cannot_prevent_later_acquisition(tmp_path):
    probe = implementation()
    from host_duty.core import Ledger

    database = tmp_path / "ledger.sqlite"
    with Ledger.create(database) as ledger:
        ledger.register("fatbot", "machine-new")
        ledger.register("gojira", "machine-b")
    with endpoint() as port:
        first = target(tmp_path, port)
        second = dict(first, host_id="gojira", instance_id="machine-b")
        result = probe.collect_config(write_config(tmp_path, database, [first, second]))
    assert result[0]["state"] == "unknown"
    assert result[0]["recorded"] is False
    assert "refused" in result[0]["detail"].lower()
    assert result[1]["state"] == "reachable"
    with Ledger(database) as ledger:
        assert ledger.report("fatbot")["instance_id"] == "machine-new"
        assert ledger.report("fatbot")["boot_id"] is None
        assert ledger.report("gojira")["presence"] == "reachable"


def test_shared_pass_deadline_stops_later_target_and_preserves_source_age(tmp_path):
    probe = implementation()
    from host_duty.core import Ledger

    database = tmp_path / "ledger.sqlite"
    with Ledger.create(database) as ledger:
        ledger.register("fatbot", "machine-a")
        ledger.register("gojira", "machine-b")
        ledger.observe("gojira", "machine-b", "reachable", boot_id="previous-boot")
        previous = ledger.report("gojira")["observed_at"]
    first_dir, second_dir = tmp_path / "first", tmp_path / "second"
    first_dir.mkdir()
    second_dir.mkdir()
    marker = tmp_path / "later-target-ran"
    with endpoint() as port:
        first = target(first_dir, port, "import time\ntime.sleep(10)\n")
        first["timeout_seconds"] = 1
        second = target(second_dir, port, "from pathlib import Path\nPath(%r).touch()\n" % str(marker))
        second.update(host_id="gojira", instance_id="machine-b", timeout_seconds=1)
        started = time.monotonic()
        result = probe.collect_config(write_config(tmp_path, database, [first, second]), budget_seconds=0.1)
    assert time.monotonic() - started < 2
    assert result[0]["state"] == "unknown"
    assert result[1]["state"] == "unknown"
    assert result[1]["recorded"] is False
    assert "deadline" in result[1]["detail"]
    assert not marker.exists()
    with Ledger(database) as ledger:
        assert ledger.report("gojira")["observed_at"] == previous
        assert ledger.report("gojira")["boot_id"] == "previous-boot"


@pytest.mark.parametrize("code", [errno.EPERM, errno.EACCES, errno.EMFILE, errno.ENFILE, errno.ENOBUFS])
def test_local_socket_creation_errors_are_unknown_in_real_ledger(tmp_path, monkeypatch, code):
    probe = implementation()
    from host_duty.core import Ledger, status_document

    clock = [1000]
    with Ledger.create(tmp_path / "ledger.sqlite", clock=lambda: clock[0]) as ledger:
        ledger.register("fatbot", "machine-a")
        ledger.assign("duty-a", "build-a", "fatbot", 2000)
        clock[0] = 1031

        def unavailable_socket(*args, **kwargs):
            raise OSError(code, os.strerror(code))

        # Inject the precise OS boundary error already observed for socket()
        # under the network sandbox; assert persisted consumer behavior.
        monkeypatch.setattr(probe.socket, "socket", unavailable_socket)
        result = probe.collect_target(ledger, target(tmp_path, 22), clock=lambda: clock[0])
        assert result["state"] == "unknown"
        concerns = {c["id"]: c["observation"]["local_state"]
                    for c in status_document(ledger, "fatbot")["concerns"]}
        assert concerns["duty.availability"] == "UNKNOWN"
        assert concerns["duty.observation"] == "ABSENT"


@pytest.mark.parametrize("code", [errno.EACCES, errno.EPERM, errno.EADDRNOTAVAIL, errno.ENOBUFS])
def test_local_connect_errors_are_unknown(tmp_path, monkeypatch, code):
    probe = implementation()
    real_socket = socket.socket

    class LocalFailure(real_socket):
        def connect(self, address):
            raise OSError(code, os.strerror(code))

    monkeypatch.setattr(probe.socket, "socket", LocalFailure)
    ledger = Observations()
    assert probe.collect_target(ledger, target(tmp_path, 22))["state"] == "unknown"
    assert ledger.rows[0]["state"] == "unknown"


def test_real_descriptor_exhaustion_is_unknown_in_process(tmp_path):
    implementation()
    script = """import errno, json, os, resource, socket
from host_duty.probe import collect_target
class Recorder:
 def observe(self, *args, **kwargs): self.state = args[2]
ledger = Recorder()
resource.setrlimit(resource.RLIMIT_NOFILE, (64, resource.getrlimit(resource.RLIMIT_NOFILE)[1]))
opened = []
try:
 while True: opened.append(os.open('/dev/null', os.O_RDONLY))
except OSError as exc:
 assert exc.errno == errno.EMFILE
try:
 socket.socket()
except OSError as exc:
 observed_error = exc.errno
target = {'host_id':'fatbot','instance_id':'a','address':'127.0.0.1','port':22,
          'argv':['/bin/true'],'machine_identity_sha256':'a'*64,'timeout_seconds':0.1}
result = collect_target(ledger, target)
for fd in opened: os.close(fd)
print(json.dumps({'errno':observed_error,'state':result['state'],'recorded_state':ledger.state}))
"""
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=3)
    assert result.returncode == 0, result.stderr
    doc = json.loads(result.stdout)
    assert doc["errno"] == errno.EMFILE
    assert doc["state"] == doc["recorded_state"] == "unknown"
