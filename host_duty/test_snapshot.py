"""Separate bounded snapshots of the observer head, with real SQLite readers."""
import hashlib
import fcntl
import importlib
import json
import os
from pathlib import Path
import sqlite3
import struct
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from host_duty.core import Ledger


def publisher():
    try:
        return importlib.import_module("host_duty.snapshot").publish_snapshot
    except ModuleNotFoundError:
        pytest.fail("Missing behavior: publish one bounded read-only observer snapshot separately from the duty ledger")


def read_snapshot(path):
    with sqlite3.connect(path.as_uri()+"?mode=ro", uri=True) as connection:
        return connection.execute("SELECT schema,host_id,instance_id,boot_id,source_observed_at,source_state,source_sha256,source_detail,telemetry_json,exported_at FROM host_duty_observations").fetchall()


@pytest.fixture
def state(tmp_path):
    clock = [1000]
    ledger = Ledger.create(tmp_path / "ledger.sqlite", clock=lambda:clock[0])
    ledger.register("fatbot", "machine-a")
    yield ledger, clock, tmp_path / "latest.sqlite"
    ledger.close()


def test_snapshot_carries_literal_tuple_original_age_and_separate_export_time(state):
    ledger, clock, output = state
    ledger.observe("fatbot", "machine-a", "reachable", boot_id="boot-a", detail="fresh nonce bound",
                   telemetry={"load1":0.5}, source_sha256="a"*64)
    clock[0] = 1120
    result = publisher()(ledger, "fatbot", output, clock=lambda:1120)
    assert read_snapshot(output) == [("constellation.host_duty_observation.v1", "fatbot", "machine-a", "boot-a",
        1000.0, "reachable", "a"*64, "fresh nonce bound", '{"load1":0.5}', 1120.0)]
    assert result["snapshot_sha256"] == hashlib.sha256(output.read_bytes()).hexdigest()
    assert output.stat().st_mode & 0o777 == 0o444
    assert output.stat().st_size <= 65536
    assert ledger.path.stat().st_mode & 0o777 == 0o600


def test_missing_head_is_explicit_missing_without_source_timestamp(state):
    ledger, _, output = state
    publisher()(ledger, "fatbot", output, clock=lambda:1010)
    assert read_snapshot(output) == [("constellation.host_duty_observation.v1", "fatbot", "machine-a", None,
                                     None, "missing", None, "no observation acquired", None, 1010.0)]


def test_atomic_replacement_keeps_old_reader_coherent_and_new_reader_current(state):
    ledger, clock, output = state
    ledger.observe("fatbot", "machine-a", "reachable", boot_id="boot-a", detail="before")
    publish = publisher()
    publish(ledger, "fatbot", output, clock=lambda:1001)
    reader = sqlite3.connect(output.as_uri()+"?mode=ro", uri=True)
    try:
        reader.execute("BEGIN")
        assert reader.execute("SELECT source_state,source_detail FROM host_duty_observations").fetchone() == ("reachable", "before")
        clock[0] = 1020
        ledger.observe("fatbot", "machine-a", "unknown", detail="sampler unavailable")
        publish(ledger, "fatbot", output, clock=lambda:1021)
        assert reader.execute("SELECT source_state,source_detail FROM host_duty_observations").fetchone() == ("reachable", "before")
        assert read_snapshot(output)[0][4:8] == (1020.0, "unknown", None, "sampler unavailable")
    finally:
        reader.close()


@pytest.mark.parametrize("destination", ["ledger", "ledger-wal", "ledger-shm", "ledger-journal", "ledger-alias", "symlink", "hardlink", "writable-parent", "symlink-parent"])
def test_publication_refuses_unsafe_destinations_without_changing_victim(state, tmp_path, destination):
    ledger, _, output = state
    victim = tmp_path / "victim"
    victim.write_bytes(b"preserve existing bytes")
    if destination == "ledger":
        output = ledger.path
    elif destination in {"ledger-wal", "ledger-shm", "ledger-journal"}:
        output = Path(str(ledger.path) + "-" + destination.split("-", 1)[1])
    elif destination == "ledger-alias":
        output = tmp_path / "ledger-alias.sqlite"
        os.link(ledger.path, output)
    elif destination == "symlink":
        output.symlink_to(victim)
    elif destination == "hardlink":
        os.link(victim, output)
    elif destination == "writable-parent":
        parent = tmp_path / "writable"
        parent.mkdir(mode=0o777);parent.chmod(0o777)
        output = parent / "snapshot.sqlite"
    else:
        parent = tmp_path / "alias"
        parent.symlink_to(tmp_path, target_is_directory=True)
        output = parent / "snapshot.sqlite"
    before = ledger.path.read_bytes()
    with pytest.raises((ValueError, OSError)):
        publisher()(ledger, "fatbot", output)
    assert victim.read_bytes() == b"preserve existing bytes"
    assert ledger.path.read_bytes() == before
    if destination in {"ledger-wal", "ledger-shm", "ledger-journal"}:
        assert not output.exists()


def test_oversized_snapshot_refuses_and_preserves_previous_file(state):
    ledger, clock, output = state
    publish = publisher()
    publish(ledger, "fatbot", output, clock=lambda:1000)
    before = output.read_bytes()
    clock[0] = 1001
    ledger.observe("fatbot", "machine-a", "reachable", boot_id="boot-a", detail="x"*1000,
                   telemetry={"value":"y"*65000})
    with pytest.raises(ValueError, match="bound"):
        publish(ledger, "fatbot", output)
    assert output.read_bytes() == before
    assert not list(output.parent.glob(".host-duty-snapshot-*"))


@pytest.mark.parametrize("name", ["reachable", "unreachable", "unknown", "missing"])
def test_shared_nq_vector_round_trips_native_sqlite_types_and_exact_values(tmp_path, name):
    vector = json.loads((Path(__file__).parent / "fixtures/host-duty-row-custody-v1.json").read_text())
    case = next(case for case in vector["cases"] if case["name"] == name)
    value = case["values"]
    with Ledger.create(tmp_path / "ledger.sqlite", clock=lambda:1000.25) as ledger:
        ledger.register("fatbot", "machine-a")
        if name != "missing":
            ledger.observe("fatbot", "machine-a", name, boot_id=value[3],
                source_sha256=value[6], detail=value[7],
                telemetry=None if value[8] is None else json.loads(value[8]))
        output = tmp_path / "latest.sqlite"
        publisher()(ledger, "fatbot", output, clock=lambda:1005.5)
    with sqlite3.connect(output.as_uri()+"?mode=ro", uri=True) as connection:
        cursor = connection.execute(vector["select_sql"])
        assert [column[0] for column in cursor.description] == vector["columns"]
        rows = cursor.fetchall()
        assert rows == [tuple(value)]
        types = connection.execute("SELECT " + ",".join("typeof(%s)" % name for name in vector["columns"]) + " FROM host_duty_observations").fetchone()
        assert list(types) == case["sqlite_types"]
    typed = [{"type":"null"} if value is None else {"type":kind, "value":struct.pack(">d", value).hex() if kind == "real" else value}
             for kind, value in zip(types, rows[0])]
    assert typed == case["selected_row"]


def test_concurrent_publisher_refuses_without_replacing_prior_snapshot(state):
    ledger, _, output = state
    publish = publisher()
    publish(ledger, "fatbot", output, clock=lambda:1000)
    before = output.read_bytes()
    lock = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):
            publish(ledger, "fatbot", output, clock=lambda:1001)
        assert output.read_bytes() == before
    finally:
        os.close(lock)
    publish(ledger, "fatbot", output, clock=lambda:1002)
    assert read_snapshot(output)[0][-1] == 1002.0


def test_failed_rename_leaves_prior_snapshot_and_retires_temporary(state, monkeypatch):
    ledger, _, output = state
    snapshot = importlib.import_module("host_duty.snapshot")
    snapshot.publish_snapshot(ledger, "fatbot", output, clock=lambda:1000)
    before = output.read_bytes()

    def failed_replace(*args, **kwargs):
        raise OSError("injected publication failure")

    monkeypatch.setattr(snapshot.os, "replace", failed_replace)
    with pytest.raises(OSError, match="publication failure"):
        snapshot.publish_snapshot(ledger, "fatbot", output, clock=lambda:1001)
    assert output.read_bytes() == before
    assert not list(output.parent.glob(".host-duty-snapshot-*"))


def test_foreign_owned_destination_refuses_without_replacing_existing_bytes(state, monkeypatch):
    ledger, _, output = state
    snapshot = importlib.import_module("host_duty.snapshot")
    snapshot.publish_snapshot(ledger, "fatbot", output, clock=lambda:1000)
    before = output.read_bytes()
    original_stat = snapshot.os.stat

    def foreign_stat(path, *args, **kwargs):
        result = original_stat(path, *args, **kwargs)
        if path == output.name and kwargs.get("dir_fd") is not None:
            fields = list(result)
            fields[4] = os.getuid()+1
            return os.stat_result(fields)
        return result

    # A precise metadata boundary fixture avoids granting/changing filesystem
    # ownership merely to exercise rejection of someone else's existing file.
    monkeypatch.setattr(snapshot.os, "stat", foreign_stat)
    with pytest.raises(ValueError, match="owned"):
        snapshot.publish_snapshot(ledger, "fatbot", output)
    assert output.read_bytes() == before


def test_temporary_name_collision_never_removes_an_existing_file(state, monkeypatch):
    ledger, _, output = state
    snapshot = importlib.import_module("host_duty.snapshot")
    temporary = output.parent / ".host-duty-snapshot-fixed.sqlite"
    temporary.write_bytes(b"another operation owns these bytes")
    monkeypatch.setattr(snapshot.secrets, "token_hex", lambda _:"fixed")
    with pytest.raises(FileExistsError):
        snapshot.publish_snapshot(ledger, "fatbot", output)
    assert temporary.read_bytes() == b"another operation owns these bytes"
    assert not output.exists()


def test_real_temporary_creation_permission_failure_preserves_prior_file(state):
    ledger, _, output = state
    publish = publisher()
    publish(ledger, "fatbot", output, clock=lambda:1000)
    before = output.read_bytes()
    original_mode = output.parent.stat().st_mode & 0o777
    output.parent.chmod(0o500)
    try:
        with pytest.raises(PermissionError):
            publish(ledger, "fatbot", output)
        assert output.read_bytes() == before
    finally:
        output.parent.chmod(original_mode)


@pytest.mark.parametrize("kind", ["config-json", "foreign-sqlite", "wrong-host", "wrong-schema", "multiple-rows", "extra-table", "extra-hidden-column"])
def test_only_managed_same_host_singleton_snapshot_can_be_replaced(state, kind):
    ledger, _, output = state
    publish = publisher()
    if kind == "config-json":
        output.write_text('{"database":"valuable-configuration"}\n')
        output.chmod(0o600)
    elif kind == "foreign-sqlite":
        with sqlite3.connect(output) as connection:
            connection.execute("CREATE TABLE valuable(value TEXT)")
            connection.execute("INSERT INTO valuable VALUES ('preserve')")
        output.chmod(0o444)
    else:
        publish(ledger, "fatbot", output, clock=lambda:1000)
        output.chmod(0o600)
        with sqlite3.connect(output) as connection:
            if kind == "wrong-host":
                connection.execute("UPDATE host_duty_observations SET host_id='another-host'")
            elif kind == "wrong-schema":
                connection.execute("UPDATE host_duty_observations SET schema='foreign.v1'")
            elif kind == "multiple-rows":
                connection.execute("INSERT INTO host_duty_observations SELECT * FROM host_duty_observations")
            elif kind == "extra-hidden-column":
                connection.execute("ALTER TABLE host_duty_observations ADD COLUMN valuable TEXT GENERATED ALWAYS AS ('keep') VIRTUAL")
            else:
                connection.execute("CREATE TABLE valuable(value TEXT)")
        output.chmod(0o444)
    before, mode = output.read_bytes(), output.stat().st_mode
    with pytest.raises(ValueError, match="managed"):
        publish(ledger, "fatbot", output, clock=lambda:1010)
    assert output.read_bytes() == before
    assert output.stat().st_mode == mode


def test_managed_same_host_snapshot_advances_explicit_incarnation(state):
    ledger, clock, output = state
    publish = publisher()
    ledger.observe("fatbot", "machine-a", "reachable", boot_id="boot-a")
    publish(ledger, "fatbot", output, clock=lambda:1001)
    clock[0] = 1010
    ledger.replace("fatbot", "machine-b", "explicit new incarnation")
    ledger.observe("fatbot", "machine-b", "reachable", boot_id="boot-b")
    publish(ledger, "fatbot", output, clock=lambda:1011)
    assert read_snapshot(output)[0][1:6] == ("fatbot", "machine-b", "boot-b", 1010.0, "reachable")


@pytest.mark.parametrize("foreign", ["sqlitecache", "changed-constraints"])
def test_exact_catalog_refuses_foreign_data_and_changed_constraints_without_byte_change(state, foreign):
    ledger, _, output = state
    snapshot = importlib.import_module("host_duty.snapshot")
    snapshot.publish_snapshot(ledger, "fatbot", output, clock=lambda:1001)
    output.chmod(0o600)
    with sqlite3.connect(output) as connection:
        if foreign == "sqlitecache":
            connection.execute("CREATE TABLE sqlitecache(note TEXT)")
            connection.execute("INSERT INTO sqlitecache VALUES ('retain-this-row')")
        else:
            original = connection.execute("SELECT * FROM host_duty_observations").fetchone()
            connection.execute("DROP TABLE host_duty_observations")
            changed = snapshot._TABLE.replace("schema TEXT NOT NULL", "schema TEXT UNIQUE")
            assert changed != snapshot._TABLE
            connection.execute(changed)
            connection.execute("INSERT INTO host_duty_observations VALUES (?,?,?,?,?,?,?,?,?,?)", original)
    output.chmod(0o444)
    before = output.read_bytes()
    with pytest.raises(ValueError, match="managed"):
        snapshot.publish_snapshot(ledger, "fatbot", output, clock=lambda:1002)
    assert output.read_bytes() == before
    with sqlite3.connect(output.as_uri()+"?mode=ro", uri=True) as connection:
        if foreign == "sqlitecache":
            assert connection.execute("SELECT note FROM sqlitecache").fetchall() == [("retain-this-row",)]
        else:
            assert connection.execute("SELECT sql FROM sqlite_schema WHERE name='host_duty_observations'").fetchone() == (changed,)
