"""Off-host, operator-owned workload duties and conditional availability.

Only operator transitions settle duties. Observations are external facts and
never attest completion, authorize actions, or assert complete host health.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import time


class Refused(ValueError):
    """An operation cannot be supported by the current trusted ledger state."""


def _id(value, kind="identity", maximum=128):
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:@+-]*", value):
        raise Refused("invalid " + kind)
    return value


def _text(value, kind="reason", required=False):
    if not isinstance(value, str) or len(value) > 1000 or (required and not value.strip()):
        raise Refused(kind + " must be text of at most 1000 characters" + (" and nonempty" if required else ""))
    return value


def _seconds(value, kind="time", positive=False):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0 or value > 253402300799 or not math.isfinite(value) or (positive and value == 0):
        raise Refused(kind + " must be finite nonnegative seconds")
    return float(value)


def _hash(value):
    if value is not None and (not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)):
        raise Refused("evidence must be a lowercase SHA-256 hash")
    return value


def _custody(path, existing=True):
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or parent.st_mode & 0o022:
        raise Refused("ledger directory must be owned and not writable by other accounts")
    if existing:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
            raise Refused("ledger must be an owned regular 0600 file with one link")


_SCHEMA = """
PRAGMA user_version=1;
CREATE TABLE meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1), last_at REAL NOT NULL CHECK(last_at>=0));
CREATE TABLE hosts (
 host_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, registered_at REAL NOT NULL,
 boot_id TEXT, observed_at REAL, presence TEXT CHECK(presence IN ('reachable','unreachable','unknown')),
 detail TEXT NOT NULL DEFAULT '', telemetry TEXT, source_sha256 TEXT);
CREATE TABLE incarnations (
 host_id TEXT NOT NULL REFERENCES hosts(host_id), instance_id TEXT NOT NULL,
 registered_at REAL NOT NULL, retired_at REAL, PRIMARY KEY(host_id,instance_id));
CREATE TABLE boots (
 host_id TEXT NOT NULL, instance_id TEXT NOT NULL, boot_id TEXT NOT NULL, retired_at REAL,
 PRIMARY KEY(host_id,instance_id,boot_id), FOREIGN KEY(host_id,instance_id) REFERENCES incarnations(host_id,instance_id));
CREATE TABLE work (
 work_id TEXT PRIMARY KEY, state TEXT NOT NULL CHECK(state IN ('open','completed','cancelled')));
CREATE TABLE duties (
 duty_id TEXT PRIMARY KEY, work_id TEXT NOT NULL REFERENCES work(work_id), host_id TEXT NOT NULL,
 instance_id TEXT NOT NULL, assigned_at REAL NOT NULL, deadline REAL NOT NULL CHECK(deadline>=0),
 reason TEXT NOT NULL, disposition TEXT CHECK(disposition IN ('released','cancelled','completed','transferred')),
 settled_at REAL, settlement_reason TEXT, evidence_sha256 TEXT, evidence_kind TEXT,
 successor_id TEXT REFERENCES duties(duty_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(host_id,instance_id) REFERENCES incarnations(host_id,instance_id),
 CHECK((disposition IS NULL AND settled_at IS NULL) OR (disposition IS NOT NULL AND settled_at IS NOT NULL)),
 CHECK(disposition!='completed' OR (evidence_sha256 IS NOT NULL AND length(evidence_sha256)=64 AND evidence_kind IS 'operator_attestation')));
CREATE UNIQUE INDEX one_active_work ON duties(work_id) WHERE disposition IS NULL;
CREATE INDEX active_host ON duties(host_id) WHERE disposition IS NULL;
CREATE INDEX duty_host_history ON duties(host_id);
CREATE TABLE observations (
 id INTEGER PRIMARY KEY, host_id TEXT NOT NULL, instance_id TEXT NOT NULL, boot_id TEXT,
 state TEXT NOT NULL CHECK(state IN ('reachable','unreachable','unknown')), observed_at REAL NOT NULL,
 detail TEXT NOT NULL, telemetry TEXT, source_sha256 TEXT,
 FOREIGN KEY(host_id,instance_id) REFERENCES incarnations(host_id,instance_id));
CREATE INDEX observation_host_history ON observations(host_id,id);
CREATE TABLE events (
 id INTEGER PRIMARY KEY, at REAL NOT NULL, kind TEXT NOT NULL, host_id TEXT REFERENCES hosts(host_id),
 duty_id TEXT REFERENCES duties(duty_id), detail TEXT NOT NULL);
"""


class Ledger:
    @classmethod
    def create(cls, path, clock=None):
        path = Path(path).absolute()
        _custody(path, existing=False)
        now = _seconds((clock or time.time)())
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        connection = None
        try:
            connection = sqlite3.connect(path, timeout=0.25)
            connection.executescript("PRAGMA foreign_keys=ON;\n" + _SCHEMA)
            connection.execute("INSERT INTO meta VALUES (1,?)", (now,))
            connection.commit()
        except sqlite3.Error as exc:
            raise Refused("ledger initialization failed: " + str(exc)) from exc
        finally:
            if connection is not None:
                connection.close()
        return cls(path, clock=clock)

    def __init__(self, path, clock=None, readonly=False):
        self.path, self.clock, self.readonly = Path(path).absolute(), clock or time.time, readonly
        self.connection = None
        self._last_clock = None
        _custody(self.path)
        try:
            self.connection = sqlite3.connect(self.path.as_uri() + ("?mode=ro" if readonly else "?mode=rw"), uri=True, timeout=0.25, isolation_level=None)
            self.connection.row_factory = sqlite3.Row
            self.connection.execute("PRAGMA foreign_keys=ON")
            if self.connection.execute("PRAGMA user_version").fetchone()[0] != 1:
                raise Refused("unsupported ledger schema")
            # Validate the current surface without historical foreign-key scans.
            self.connection.execute("SELECT last_at FROM meta WHERE singleton=1").fetchone()[0]
            for query in ("SELECT host_id,instance_id,observed_at FROM hosts LIMIT 0", "SELECT duty_id,disposition FROM duties LIMIT 0", "SELECT id FROM events LIMIT 0"):
                self.connection.execute(query)
        except (sqlite3.Error, TypeError, IndexError) as exc:
            self.close()
            raise Refused("invalid ledger schema or database: " + str(exc)) from exc
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    @contextmanager
    def _transaction(self, write=False):
        if write and self.readonly:
            raise Refused("ledger was opened readonly")
        try:
            self.connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            now = _seconds(self.clock())
            last_at = self.connection.execute("SELECT last_at FROM meta WHERE singleton=1").fetchone()[0]
            regressed = now < last_at or (self._last_clock is not None and now < self._last_clock)
            self._last_clock = max(now, self._last_clock or 0)
            if write and regressed:
                raise Refused("observer clock regressed before last ledger transition")
            yield now, regressed
            if write:
                self.connection.execute("UPDATE meta SET last_at=? WHERE singleton=1", (now,))
            self.connection.commit()
        except sqlite3.Error as exc:
            self.connection.rollback()
            raise Refused("ledger busy, locked or invalid: " + str(exc)) from exc
        except BaseException:
            self.connection.rollback()
            raise

    def _host(self, host_id, instance_id=None):
        _id(host_id, "host", 48)
        row = self.connection.execute("SELECT * FROM hosts WHERE host_id=?", (host_id,)).fetchone()
        if row is None:
            raise Refused("host is not registered")
        if instance_id is not None and row["instance_id"] != _id(instance_id, "instance"):
            raise Refused("observation instance is not the registered incarnation")
        return row

    def _active_duty(self, duty_id):
        row = self.connection.execute("SELECT * FROM duties WHERE duty_id=?", (_id(duty_id, "duty"),)).fetchone()
        if row is None or row["disposition"] is not None:
            raise Refused("duty is missing or already settled")
        return row

    def _event(self, at, kind, host_id=None, duty_id=None, **detail):
        self.connection.execute("INSERT INTO events(at,kind,host_id,duty_id,detail) VALUES (?,?,?,?,?)", (at, kind, host_id, duty_id, json.dumps(detail, allow_nan=False, sort_keys=True)))

    def register(self, host_id, instance_id):
        _id(host_id, "host", 48)
        _id(instance_id, "instance")
        with self._transaction(write=True) as (now, _):
            if self.connection.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] >= 256:
                raise Refused("host capacity of 256 reached")
            self.connection.execute("INSERT INTO hosts(host_id,instance_id,registered_at) VALUES (?,?,?)", (host_id, instance_id, now))
            self.connection.execute("INSERT INTO incarnations VALUES (?,?,?,NULL)", (host_id, instance_id, now))
            self._event(now, "registered", host_id, instance_id=instance_id)

    def replace(self, host_id, instance_id, reason):
        _id(instance_id, "instance")
        _text(reason, required=True)
        with self._transaction(write=True) as (now, _):
            old = self._host(host_id)
            if self.connection.execute("SELECT 1 FROM duties WHERE host_id=? AND disposition IS NULL LIMIT 1", (host_id,)).fetchone():
                raise Refused("old incarnation still has outstanding duty")
            if self.connection.execute("SELECT 1 FROM incarnations WHERE host_id=? AND instance_id=?", (host_id, instance_id)).fetchone():
                raise Refused("replacement incarnation was already registered or retired")
            self.connection.execute("UPDATE incarnations SET retired_at=? WHERE host_id=? AND instance_id=?", (now, host_id, old["instance_id"]))
            self.connection.execute("UPDATE boots SET retired_at=? WHERE host_id=? AND instance_id=? AND retired_at IS NULL", (now, host_id, old["instance_id"]))
            self.connection.execute("INSERT INTO incarnations VALUES (?,?,?,NULL)", (host_id, instance_id, now))
            self.connection.execute("UPDATE hosts SET instance_id=?,registered_at=?,boot_id=NULL,observed_at=NULL,presence=NULL,detail='',telemetry=NULL,source_sha256=NULL WHERE host_id=?", (instance_id, now, host_id))
            self._event(now, "replaced", host_id, old_instance_id=old["instance_id"], instance_id=instance_id, reason=reason)

    def _insert_duty(self, duty_id, work_id, host_id, deadline, reason, now):
        host = self._host(host_id)
        if self.connection.execute("SELECT COUNT(*) FROM duties WHERE host_id=? AND disposition IS NULL", (host_id,)).fetchone()[0] >= 64:
            raise Refused("host capacity of 64 active duties reached")
        self.connection.execute("INSERT INTO work(work_id,state) VALUES (?,'open') ON CONFLICT(work_id) DO NOTHING", (work_id,))
        if self.connection.execute("SELECT state FROM work WHERE work_id=?", (work_id,)).fetchone()[0] != "open":
            raise Refused("work already has a terminal operator outcome")
        self.connection.execute("INSERT INTO duties(duty_id,work_id,host_id,instance_id,assigned_at,deadline,reason) VALUES (?,?,?,?,?,?,?)", (duty_id, work_id, host_id, host["instance_id"], now, deadline, reason))

    def assign(self, duty_id, work_id, host_id, deadline, reason=""):
        _id(duty_id, "duty")
        _id(work_id, "work")
        deadline, reason = _seconds(deadline, "deadline"), _text(reason)
        with self._transaction(write=True) as (now, _):
            self._insert_duty(duty_id, work_id, host_id, deadline, reason, now)
            self._event(now, "assigned", host_id, duty_id, work_id=work_id, deadline=deadline, reason=reason)

    def release(self, duty_id, disposition, reason, evidence_sha256=None):
        if disposition not in ("released", "cancelled", "completed"):
            raise Refused("unsupported operator disposition")
        _text(reason, required=True)
        _hash(evidence_sha256)
        if disposition == "completed" and evidence_sha256 is None:
            raise Refused("completed needs operator attestation with an evidence hash")
        evidence_kind = "operator_attestation" if disposition == "completed" else None
        with self._transaction(write=True) as (now, _):
            duty = self._active_duty(duty_id)
            self.connection.execute("UPDATE duties SET disposition=?,settled_at=?,settlement_reason=?,evidence_sha256=?,evidence_kind=? WHERE duty_id=?", (disposition, now, reason, evidence_sha256, evidence_kind, duty_id))
            if disposition != "released":
                self.connection.execute("UPDATE work SET state=? WHERE work_id=?", (disposition, duty["work_id"]))
            self._event(now, disposition, duty["host_id"], duty_id, reason=reason, evidence_sha256=evidence_sha256, evidence_kind=evidence_kind)

    def transfer(self, duty_id, successor_id, host_id, deadline, reason):
        _id(successor_id, "successor duty")
        deadline = _seconds(deadline, "deadline")
        _text(reason, required=True)
        with self._transaction(write=True) as (now, _):
            duty = self._active_duty(duty_id)
            self.connection.execute("UPDATE duties SET disposition='transferred',settled_at=?,settlement_reason=?,successor_id=? WHERE duty_id=?", (now, reason, successor_id, duty_id))
            self._insert_duty(successor_id, duty["work_id"], host_id, deadline, reason, now)
            self._event(now, "transferred", duty["host_id"], duty_id, successor_id=successor_id, successor_host_id=host_id, reason=reason)
            self._event(now, "assigned", host_id, successor_id, work_id=duty["work_id"], predecessor_id=duty_id, deadline=deadline, reason=reason)

    def observe(self, host_id, instance_id, state, *, boot_id=None, observed_at=None, detail="", telemetry=None, source_sha256=None):
        if state not in ("reachable", "unreachable", "unknown"):
            raise Refused("invalid observed presence")
        if boot_id is not None:
            _id(boot_id, "boot")
        _text(detail, "detail")
        _hash(source_sha256)
        encoded = None
        if telemetry is not None:
            if not isinstance(telemetry, dict):
                raise Refused("telemetry must be a JSON object")
            try:
                encoded = json.dumps(telemetry, allow_nan=False, separators=(",", ":"))
            except (TypeError, ValueError, RecursionError) as exc:
                raise Refused("telemetry must be finite JSON") from exc
            if len(encoded.encode("utf-8")) > 65536:
                raise Refused("telemetry exceeds 64 KiB")
        with self._transaction(write=True) as (now, _):
            host = self._host(host_id, instance_id)
            at = now if observed_at is None else _seconds(observed_at)
            if at > now or at < host["registered_at"] or (host["observed_at"] is not None and at <= host["observed_at"]):
                raise Refused("observation is future, duplicate, or older than the current incarnation/head")
            if boot_id is not None and boot_id != host["boot_id"]:
                prior = self.connection.execute("SELECT retired_at FROM boots WHERE host_id=? AND instance_id=? AND boot_id=?", (host_id, instance_id, boot_id)).fetchone()
                if prior is not None:
                    raise Refused("boot session is retired")
                self.connection.execute("UPDATE boots SET retired_at=? WHERE host_id=? AND instance_id=? AND retired_at IS NULL", (now, host_id, instance_id))
                self.connection.execute("INSERT INTO boots VALUES (?,?,?,NULL)", (host_id, instance_id, boot_id))
                if host["boot_id"] is not None:
                    self._event(now, "boot_changed", host_id, old_boot_id=host["boot_id"], boot_id=boot_id, instance_id=instance_id, observed_at=at)
            current_boot = boot_id if boot_id is not None else host["boot_id"]
            self.connection.execute("INSERT INTO observations(host_id,instance_id,boot_id,state,observed_at,detail,telemetry,source_sha256) VALUES (?,?,?,?,?,?,?,?)", (host_id, instance_id, current_boot, state, at, detail, encoded, source_sha256))
            self.connection.execute("UPDATE hosts SET boot_id=?,observed_at=?,presence=?,detail=?,telemetry=?,source_sha256=? WHERE host_id=?", (current_boot, at, state, detail, encoded, source_sha256, host_id))
            self.connection.execute("DELETE FROM observations WHERE host_id=? AND id <= (SELECT id FROM observations WHERE host_id=? ORDER BY id DESC LIMIT 1 OFFSET 256)", (host_id, host_id))

    def shutdown_claim(self, host_id, instance_id, reason):
        _text(reason, required=True)
        with self._transaction(write=True) as (now, _):
            self._host(host_id, instance_id)
            self._event(now, "shutdown_claim", host_id, instance_id=instance_id, reason=reason)

    def observation_head(self, host_id):
        """Read original observer testimony without refreshing/projecting it."""
        with self._transaction():
            host = self._host(host_id)
            return {"host_id":host["host_id"], "instance_id":host["instance_id"],
                "boot_id":host["boot_id"], "source_observed_at":host["observed_at"],
                "source_state":host["presence"] if host["observed_at"] is not None else "missing",
                "source_sha256":host["source_sha256"],
                "source_detail":host["detail"] if host["observed_at"] is not None else "no observation acquired",
                "telemetry":json.loads(host["telemetry"]) if host["telemetry"] is not None else None}

    def report(self, host_id, freshness_seconds=60, grace_seconds=30):
        freshness = _seconds(freshness_seconds, "freshness", positive=True)
        grace = _seconds(grace_seconds, "grace")
        with self._transaction() as (now, regressed):
            host = dict(self._host(host_id))
            duties = [dict(row) for row in self.connection.execute("SELECT * FROM duties WHERE host_id=? AND disposition IS NULL ORDER BY rowid", (host_id,))]
            age = None if host["observed_at"] is None else now - host["observed_at"]
            presence = "unknown" if regressed or age is None or age < 0 else "stale" if age > freshness else host["presence"]
            required = bool(duties)
            in_grace = required and all(now < duty["assigned_at"] + grace for duty in duties)
            overdue = any(now >= duty["deadline"] for duty in duties)
            if required:
                state = "observation_unknown" if presence in ("unknown", "stale") else "missing_on_duty" if presence == "unreachable" and not in_grace else "on_duty"
            else:
                state = "online_idle" if presence == "reachable" else "registered_offline" if presence == "unreachable" else "observation_unknown"
            return dict(host, at=now, state=state, presence=presence, availability_required=required, duties=duties,
                        overdue=overdue, in_grace=in_grace, clock_regression=regressed,
                        source_observed_at=host["observed_at"], observation_age_seconds=age,
                        freshness_seconds=freshness, grace_seconds=grace,
                        telemetry=json.loads(host["telemetry"]) if host["telemetry"] is not None else None)

    def hosts(self):
        with self._transaction():
            return [dict(row) for row in self.connection.execute("SELECT host_id,instance_id,registered_at,boot_id,observed_at FROM hosts ORDER BY host_id LIMIT 256")]

    def duties(self, host_id=None):
        with self._transaction():
            if host_id is not None:
                self._host(host_id)
                rows = self.connection.execute("SELECT * FROM duties WHERE host_id=? ORDER BY rowid DESC LIMIT 256", (host_id,)).fetchall()
            else:
                rows = self.connection.execute("SELECT * FROM duties ORDER BY rowid DESC LIMIT 256").fetchall()
            return [dict(row) for row in reversed(rows)]

    def events(self, limit=100):
        if type(limit) is not int or not 1 <= limit <= 256:
            raise Refused("event limit must be from 1 through 256")
        with self._transaction():
            return [dict(row, detail=json.loads(row["detail"])) for row in self.connection.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()[::-1]]


def _timestamp(at):
    return datetime.fromtimestamp(at, timezone.utc).isoformat()


def _document(host_id, now, observations, report=None):
    return {"schema":"project.ops.status/v1", "project":"duty-scoped-host-availability", "generated_at":_timestamp(now),
            "manifest":{"schema":"project.concerns/v1", "path":"host_duty/concerns.toml"},
            "producer":{"id":"monitor.host-duty", "version":"1"},
            "authority":{"scope":"conditional duty observations and operator attestations; no host-health, work-verification or action authority"},
            "concerns":[{"id":"duty." + name, "question":"duty." + name + "/v1", "profile":"duty.host/v1", "required":True, "observation":obs} for name, obs in observations.items()],
            "extensions":{"host_id":host_id, "report":report}}


def unknown_document(host_id, error, now=None):
    now = _seconds(time.time() if now is None else now)
    reason = "Duty ledger unavailable: " + str(error)[:1000]
    return _document(host_id, now, {name:{"observation_present":True, "local_state":"UNKNOWN", "domain_state":"UNKNOWN", "observed_at":_timestamp(now), "valid_for_seconds":60, "reason":reason, "facts":{"host_id":host_id}} for name in ("availability", "observation", "deadline")})


def status_document(ledger, host_id, freshness_seconds=60, grace_seconds=30):
    report = ledger.report(host_id, freshness_seconds, grace_seconds)
    now, freshness = report["at"], report["freshness_seconds"]
    if report["clock_regression"]:
        return unknown_document(host_id, "observer clock regressed before last ledger transition", now)
    observations = {}

    def add(name, local, domain, reason, source=False, boundary=None):
        observed_at = _timestamp(report["source_observed_at"] if source else now)
        validity = freshness
        if boundary is not None:
            # Estate expires at age > validity. Account for ISO microsecond
            # rounding and expire one float before the known state transition.
            serialized_at = datetime.fromisoformat(observed_at).timestamp()
            validity = min(freshness, math.nextafter(boundary - max(now, serialized_at), 0.0))
            if validity <= 0:
                local, domain, validity = "UNKNOWN", "TRANSITION_DUE", freshness
                reason = "The known duty transition is too near to retain a positive confirmation; query again."
        observations[name] = {"observation_present":True, "local_state":local, "domain_state":domain,
            "observed_at":observed_at, "valid_for_seconds":validity, "reason":reason,
            "facts":{"host_id":host_id, "instance_id":report["instance_id"], "availability_required":report["availability_required"],
                     "presence":report["presence"], "overdue":report["overdue"], "in_grace":report["in_grace"],
                     "source_observed_at_epoch":report["source_observed_at"], "observation_age_seconds":report["observation_age_seconds"]}}

    if not report["availability_required"]:
        for name in ("availability", "observation", "deadline"):
            add(name, "PRESENT", "NOT_REQUIRED", "No outstanding operator-assigned duty at query time; no host-health claim.")
    else:
        if report["in_grace"]:
            grace_end = min(d["assigned_at"] + report["grace_seconds"] for d in report["duties"])
            add("availability", "PRESENT", "WITHIN_GRACE", "The declared duty grace has not elapsed at query time; no host-health claim.", boundary=grace_end)
        elif report["presence"] in ("reachable", "unreachable"):
            reachable = report["presence"] == "reachable"
            add("availability", "PRESENT" if reachable else "ABSENT", "REACHABLE" if reachable else "MISSING_ON_DUTY", "Fresh external reachability supports the active duty condition; no work-completion or host-health claim." if reachable else "Fresh external acquisition found the on-duty host unreachable after grace.", source=True)
        else:
            add("availability", "UNKNOWN", "OBSERVATION_UNKNOWN", "Active duty availability lacks a fresh known source observation at query time.")
        if report["presence"] in ("reachable", "unreachable"):
            add("observation", "PRESENT", "OBSERVED", "External reachability observation is within its original freshness interval.", source=True)
        elif report["in_grace"]:
            add("observation", "PRESENT", "WITHIN_GRACE", "The initial observation grace has not elapsed at query time; source presence remains unknown.", boundary=grace_end)
        else:
            add("observation", "ABSENT", "OBSERVATION_GAP", "A current freshness gap is known at query time; this does not establish host disappearance.")
        deadline = min(d["deadline"] for d in report["duties"])
        add("deadline", "ABSENT" if report["overdue"] else "PRESENT", "OVERDUE" if report["overdue"] else "OUTSTANDING", "An outstanding duty deadline has elapsed at query time; work remains outstanding." if report["overdue"] else "No outstanding duty deadline has elapsed at query time; this does not establish completion.", boundary=None if report["overdue"] else deadline)
    return _document(host_id, now, observations, report)
