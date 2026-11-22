"""Publish one bounded, read-only SQLite head of Monitor observer testimony.

This exports the ledger head, not original sampler bytes or independent target
provenance. Source observation time is unchanged by publication or later reads.
"""
import fcntl
from contextlib import closing
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import time

SCHEMA = "constellation.host_duty_observation.v1"
MAX_BYTES = 65536
_TABLE = """CREATE TABLE host_duty_observations (
 schema TEXT NOT NULL, host_id TEXT NOT NULL, instance_id TEXT NOT NULL,
 boot_id TEXT, source_observed_at REAL,
 source_state TEXT NOT NULL CHECK(source_state IN ('reachable','unreachable','unknown','missing')),
 source_sha256 TEXT, source_detail TEXT NOT NULL, telemetry_json TEXT, exported_at REAL NOT NULL
)"""


def _parent(path):
    """Hold a directory FD reached without symlinks or replaceable ancestors."""
    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            previous = os.fstat(current)
            if previous.st_mode & 0o022 and not (previous.st_uid == 0 and previous.st_mode & stat.S_ISVTX):
                raise ValueError("snapshot directory ancestor is writable by another account")
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=current)
            os.close(current)
            current = following
            if os.fstat(current).st_uid not in (0, os.getuid()):
                raise ValueError("snapshot directory ancestor is not owned by a trusted account")
        info = os.fstat(current)
        if info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise ValueError("snapshot parent must be owned by this account and not writable by others")
        return current
    except BaseException:
        os.close(current)
        raise


def canonical_snapshot_path(path):
    raw = os.fspath(path)
    if not os.path.isabs(raw) or raw.startswith("//"):
        raise ValueError("snapshot path must be an absolute local path")
    normalized = os.path.normpath(raw)
    if normalized == "/":
        raise ValueError("snapshot path must name a file")
    if os.path.realpath(normalized) != normalized:
        raise ValueError("snapshot path must not contain symlinks")
    return Path(normalized)


def _destination(directory, name, ledger, host_id):
    try:
        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1):
        raise ValueError("existing snapshot must be an owned regular file with one link")
    source = ledger.path.stat()
    if (info.st_dev, info.st_ino) == (source.st_dev, source.st_ino):
        raise ValueError("snapshot must not replace the duty ledger")
    if info.st_size > MAX_BYTES or stat.S_IMODE(info.st_mode) != 0o444:
        raise ValueError("existing output is not a managed read-only snapshot")
    uri = Path("/proc/self/fd/%d/%s" % (directory, name)).as_uri() + "?mode=ro&immutable=1"
    try:
        with closing(sqlite3.connect(uri, uri=True, timeout=0.25)) as connection:
            if connection.execute("PRAGMA user_version").fetchone() != (1,):
                raise ValueError("existing output is not a managed snapshot schema")
            catalog = connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_schema").fetchall()
            if catalog != [("table", "host_duty_observations", "host_duty_observations", _TABLE)]:
                raise ValueError("existing output is not the exact managed snapshot catalog")
            if connection.execute("SELECT schema,host_id FROM host_duty_observations LIMIT 2").fetchall() != [(SCHEMA, host_id)]:
                raise ValueError("existing output is not a managed singleton snapshot for this host")
    except sqlite3.Error as exc:
        raise ValueError("existing output is not a managed SQLite snapshot") from exc


def publish_snapshot(ledger, host_id, path, clock=None):
    path = canonical_snapshot_path(path)
    protected = str(ledger.path.resolve())
    if os.path.normpath(str(path)) in {protected + suffix for suffix in ("", "-wal", "-shm", "-journal")}:
        raise ValueError("snapshot must be separate from the duty ledger and its SQLite sidecars")
    directory = _parent(path.parent)
    temporary = None
    temporary_fd = None
    try:
        # Serialize cooperative exporters before reading their heads. Readers
        # need no lock: the published file changes by one atomic rename.
        fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _destination(directory, path.name, ledger, host_id)
        head = ledger.observation_head(host_id)
        exported_at = (clock or time.time)()
        if (type(exported_at) not in (int, float) or not 0 <= exported_at <= 253402300799
                or not math.isfinite(exported_at)):
            raise ValueError("invalid export time")
        telemetry = None if head["telemetry"] is None else json.dumps(head["telemetry"],
            allow_nan=False, sort_keys=True, separators=(",", ":"))
        row = (SCHEMA, head["host_id"], head["instance_id"], head["boot_id"],
            head["source_observed_at"], head["source_state"], head["source_sha256"],
            head["source_detail"], telemetry, float(exported_at))
        # Leave room for the selected-row type/column envelope. Physical file
        # size is separately checked after SQLite commits its complete row.
        if len(json.dumps(row, allow_nan=False, separators=(",", ":")).encode()) > 60 * 1024:
            raise ValueError("snapshot row exceeds the byte bound")
        temporary_name = ".host-duty-snapshot-" + secrets.token_hex(16) + ".sqlite"
        temporary_fd = os.open(temporary_name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                               0o600, dir_fd=directory)
        temporary = temporary_name  # Cleanup owns this name only after creation succeeds.
        # The held descriptor binds SQLite's path to the checked directory even
        # if a same-account operation renames its external pathname.
        database_path = "/proc/self/fd/%d/%s" % (directory, temporary)
        with closing(sqlite3.connect(database_path, timeout=0.25)) as connection:
            with connection:
                connection.execute("PRAGMA journal_mode=DELETE")
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute("PRAGMA user_version=1")
                connection.execute(_TABLE)
                connection.execute("INSERT INTO host_duty_observations VALUES (?,?,?,?,?,?,?,?,?,?)", row)
        if os.fstat(temporary_fd).st_size > MAX_BYTES:
            raise ValueError("snapshot file exceeds the byte bound")
        os.fchmod(temporary_fd, 0o444)
        os.fsync(temporary_fd)
        raw = os.pread(temporary_fd, MAX_BYTES + 1, 0)
        digest = hashlib.sha256(raw).hexdigest()
        _destination(directory, path.name, ledger, host_id)
        os.replace(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
        temporary = None
        os.fsync(directory)
        return {"snapshot_path":str(path), "snapshot_sha256":digest,
                "host_id":head["host_id"], "instance_id":head["instance_id"],
                "source_observed_at":head["source_observed_at"], "exported_at":float(exported_at)}
    finally:
        try:
            if temporary_fd is not None:
                os.close(temporary_fd)
        finally:
            try:
                if temporary is not None:
                    os.unlink(temporary, dir_fd=directory)
            finally:
                os.close(directory)
