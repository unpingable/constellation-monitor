"""Independent shim-conformance contract suite (cartography #94 "Shim conformance"; #93 shim requirements).

The incident lifecycle in sync() must work through the Store shim irrespective of backend. This suite runs the
contract against the real SqliteStore and a SECOND, separately written in-memory backend (JournalStore: an
append-only op journal folded into a projection), plus fault-injection and concurrency fixtures. It records
which behaviors are contract-level and which are implementation properties of one backend.

Inline findings (F1..F5) are collected in the lane report; each names the test that reproduces it.
"""
import importlib.util, json, os, pathlib, sqlite3, stat, threading
import pytest

HERE = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location("inc", HERE / "constellation-incidents.py")
inc = importlib.util.module_from_spec(spec); spec.loader.exec_module(inc)

KEY = "constellation:labelwatch:service:service-down:attention-canary.service"
KEY2 = "constellation:labelwatch:sqlite-health:store-main:nq-main"
RULES = {"service-down": {"id": "service-down", "response_policy": "auto_remediate_then_page",
                          "operator_response": "systemctl status <unit>; restart if failed"},
         "sqlite-health": {"id": "sqlite-health", "response_policy": "observe_only", "operator_response": "inspect the saved check"}}
T0 = 1_792_000_000


# ------------------------------------------------------------------ the independent second backend
class JournalStore(inc.Store):
    """An in-memory backend written from the Store docstring and sync()'s call pattern alone: mutations append to
    an op journal; reads fold the journal into a projection. Shares no code with test_incidents.MemoryStore;
    identical observable semantics are the claim under test, not an assumption.

    Fault injection (deliberate, per-test):
      down=True           every operation raises StoreUnavailable before doing anything (backend unavailable)
      fail_on=<method>    the named mutation is APPLIED to the journal, then StoreUnavailable is raised:
                          the write landed, the acknowledgment did not.
    """
    def __init__(self):
        self.journal = []                                   # (op, payload) in apply order
        self.rows, self.seq = {}, []                        # id -> incident dict; ids in insertion order
        self.ev, self.att = [], {}                          # (incident, at, kind, detail_json, dedup); (incident, episode) -> fields
        self.m = {"schema": inc.SCHEMA}
        self.down = False
        self.fail_on = None

    def _mutate(self, op, fn):
        if self.down:
            raise inc.StoreUnavailable("journal backend is down (injected)")
        out = fn()
        if self.fail_on == op:
            self.fail_on = None                             # one fault per arming, as a lost ack is
            raise inc.StoreUnavailable("acknowledgment lost after %s was applied (injected)" % op)
        return out

    def _read(self, fn):
        if self.down:
            raise inc.StoreUnavailable("journal backend is down (injected)")
        return fn()

    def open_incident(self, key, at, first_seen):
        def apply():
            iid = inc.next_incident_id(key, self.seq)
            self.seq.append(iid)
            self.rows[iid] = {"id": iid, "key": key, "rule": key.split(":")[3], "subject": ":".join(key.split(":")[4:]),
                              "state": "open", "opened_at": at, "first_seen": first_seen, "last_observed_at": None,
                              "last_observation": None, "recovering_since": None, "resolved_at": None, "resolution": None,
                              "needs_operator": None, "ack_by": None, "ack_note": None, "severity": None}
            self.journal.append(("open_incident", iid))
            return iid
        return self._mutate("open_incident", apply)

    def current(self, key):
        return self._read(lambda: max((dict(self.rows[i]) for i in self.seq if self.rows[i]["key"] == key),
                                      key=lambda i: self.seq.index(i["id"]), default=None))

    def update(self, iid, **fields):
        return self._mutate("update", lambda: (self.rows[iid].update(fields), self.journal.append(("update", iid)))[0])

    def event(self, iid, at, kind, detail, dedup=None):
        def apply():
            if dedup and any(e[4] == dedup for e in self.ev):
                return False
            self.ev.append((iid, at, kind, json.dumps(detail, sort_keys=True), dedup))
            self.journal.append(("event", iid))
            return True
        return self._mutate("event", apply)

    def attempt(self, iid, episode, fields):
        def apply():
            old = self.att.get((iid, episode))
            if old is None:
                self.att[(iid, episode)] = dict(fields)
                self.journal.append(("attempt", iid))
                return True, False
            changed = any((old.get(k) or None) != (fields.get(k) or None) for k in ("settled_at", "outcome", "phase", "verified"))
            old.update(fields)
            return False, changed
        return self._mutate("attempt", apply)

    def incidents(self, unresolved_only=True):
        return self._read(lambda: [dict(self.rows[i]) for i in self.seq
                                   if not unresolved_only or self.rows[i]["state"] != "resolved"])

    def events(self, iid):
        return self._read(lambda: [{"at": e[1], "kind": e[2], "detail": e[3]} for e in self.ev if e[0] == iid])

    def attempts(self, iid):
        return self._read(lambda: [dict(v, episode=k[1]) for k, v in self.att.items() if k[0] == iid])

    def heartbeat(self, at, ok, note):
        return self._mutate("heartbeat", lambda: self.m.update(
            last_sync_at=at, last_sync_ok="1" if ok else "0", last_sync_note=note[:500]))

    def meta(self):
        return self._read(lambda: dict(self.m))

    def adopt(self, row):
        def apply():
            self.seq.append(row["id"])
            self.rows[row["id"]] = dict(row)
            self.journal.append(("adopt", row["id"]))
        return self._mutate("adopt", apply)


class LostAck:
    """Proxy around any Store: the named mutation runs to completion (for SqliteStore each statement commits in
    autocommit), then StoreUnavailable is raised — the write landed, the response did not. The caller cannot
    distinguish this from "not written" without reading the store back: that is the unknown persistence outcome."""
    def __init__(self, store, method):
        self._store, self._method = store, method

    def __getattr__(self, name):
        attr = getattr(self._store, name)
        if name != self._method or not callable(attr):
            return attr
        def faulted(*args, **kwargs):
            out = attr(*args, **kwargs)                     # the mutation lands and (for sqlite) commits
            raise inc.StoreUnavailable("acknowledgment lost after %s committed (injected)" % name)
        return faulted


@pytest.fixture(params=["sqlite", "journal"])
def store(request, tmp_path):
    return inc.SqliteStore(str(tmp_path / "i.sqlite")) if request.param == "sqlite" else JournalStore()


def report(obs, active, key=KEY, first_seen="2026-10-14T18:45:03Z", suspended=None):
    c = {"id": key, "rule": key.split(":")[3], "observation": obs, "active": active, "first_seen": first_seen, "note": "x"}
    if suspended:
        c["suspended"] = suspended
    return {"evaluated_at": "t", "conditions": [c]}


def episode(ep, outcome=None, key=KEY, first_seen="2026-10-14T18:45:03Z"):
    return {"episode": ep, "condition_id": key, "first_seen": first_seen, "outcome": outcome,
            "phase": "settled" if outcome else "dispatched", "plan": "/etc/x/start-inactive.json",
            "opened_at_unix_ms": (T0 + 60) * 1000, "settled_at_unix_ms": (T0 + 90) * 1000 if outcome else None}


def kinds(store, iid):
    return [e["kind"] for e in store.events(iid)]


# ------------------------------------------------------------------ 1. identity / deduplication
def test_identity_repeated_detections_make_one_incident_with_a_stable_id(store):
    for t in range(0, 600, 60):
        inc.sync(store, report("present", True), {}, None, RULES, T0 + t)
    all_ = store.incidents(unresolved_only=False)
    assert len(all_) == 1 and all_[0]["id"] == "inc-" + inc.key_hash(KEY)
    assert all_[0]["key"] == KEY and kinds(store, all_[0]["id"]).count("detected") == 1


def test_identity_distinct_condition_keys_make_distinct_incidents(store):
    inc.sync(store, report("present", True), {}, None, RULES, T0)
    inc.sync(store, report("present", True, key=KEY2), {}, None, RULES, T0 + 60)
    ids = sorted(i["id"] for i in store.incidents())
    assert ids == sorted(["inc-" + inc.key_hash(KEY), "inc-" + inc.key_hash(KEY2)]) and ids[0] != ids[1]


# ------------------------------------------------------------------ 2. idempotency
def test_idempotent_events_attempts_and_repeated_sync(store):
    inc.sync(store, report("present", True), {}, {"active": None, "closed": [episode("sha256:aa", "settled_failure")]}, RULES, T0)
    iid = store.incidents()[0]["id"]
    # operation level: a dedup-keyed event and an (incident, episode) upsert applied twice record once
    assert store.event(iid, inc.iso(T0), "note", {"by": "op", "text": "looking"}, dedup="note:1") is True
    assert store.event(iid, inc.iso(T0), "note", {"by": "op", "text": "looking"}, dedup="note:1") is False
    f = {"opened_at": inc.iso(T0 + 60), "settled_at": inc.iso(T0 + 90), "outcome": "settled_failure", "phase": "settled",
         "verified": None, "plan": "start-inactive.json"}
    assert store.attempt(iid, "sha256:aa", f) == (False, False)     # unchanged re-upsert of the sync-written row
    assert store.attempt(iid, "sha256:aa", f) == (False, False)
    assert len(store.events(iid)) == len(set(json.dumps(e, sort_keys=True) for e in store.events(iid)))
    assert len(store.attempts(iid)) == 1
    # pass level: repeating a sync over unchanged inputs changes nothing
    snapshot = (store.incidents(unresolved_only=False), store.events(iid), store.attempts(iid))
    inc.sync(store, report("present", True), {}, {"active": None, "closed": [episode("sha256:aa", "settled_failure")]}, RULES, T0)
    assert (store.incidents(unresolved_only=False), store.events(iid), store.attempts(iid)) == snapshot


# ------------------------------------------------------------------ 3. unavailable storage
def test_unavailable_storage_fails_visibly_and_claims_nothing(store, tmp_path, request):
    if request.node.callspec.params["store"] == "sqlite":
        d = tmp_path / "ro"; d.mkdir(); os.chmod(d, stat.S_IRUSR | stat.S_IXUSR)
        try:
            with pytest.raises(inc.StoreUnavailable):
                inc.SqliteStore(str(d / "i.sqlite"))
            assert inc.main(["--db", str(d / "i.sqlite"), "ack", "inc-x", "--by", "op"]) == 3
        finally:
            os.chmod(d, stat.S_IRWXU)
    else:
        store.down = True
        with pytest.raises(inc.StoreUnavailable):
            inc.sync(store, report("present", True), {}, None, RULES, T0)
        assert store.down is True
        store.down = False
        assert store.incidents() == [] and store.meta() == {"schema": inc.SCHEMA}   # nothing was written or claimed


def test_a_store_failure_mid_pass_leaves_partial_writes_without_a_caller_transaction(store):
    """F1: sync() is not atomic at the contract layer. main() wraps the SQLite pass in BEGIN IMMEDIATE (rollback on
    failure); the Store base contract has no transaction()/prune() operations at all, so a backend cannot offer —
    and a caller driving sync() directly cannot get — all-or-nothing through the documented interface."""
    s = LostAck(store, "event")
    with pytest.raises(inc.StoreUnavailable):
        inc.sync(s, report("present", True), {}, None, RULES, T0)
    # the incident row from open_incident persisted although the pass failed and the caller saw only StoreUnavailable
    assert len(store.incidents()) == 1
    # recovery through the find-or-open caller pattern converges: no duplicate incident, no duplicate event
    inc.sync(store, report("present", True), {}, None, RULES, T0 + 60)
    i = store.incidents()
    assert len(i) == 1 and kinds(store, i[0]["id"]).count("detected") == 1


# ------------------------------------------------------------------ 4. indeterminate outcomes
def test_indeterminate_remediation_outcome_is_not_verified_recovery(store):
    """An indeterminate REMEDIATION outcome is expressible: it is one of FAILED_OUTCOMES. It must hold the incident
    open and route to the operator, never count as verified recovery."""
    consumer = {"active": None, "closed": [episode("sha256:in", "indeterminate")]}
    inc.sync(store, report("present", True), {}, consumer, RULES, T0)
    i = store.incidents()[0]
    att = store.attempts(i["id"])
    assert len(att) == 1 and att[0]["outcome"] == "indeterminate" and not att[0]["verified"]
    assert i["state"] != "resolved" and i["needs_operator"].startswith("remediation failed (indeterminate)")
    # and it stays open even after the evaluator reports clear + the full confirmation window: the clear path
    # closes on the evaluator's observation, not on the indeterminate attempt — but the failed-attempt obligation persists
    inc.sync(store, report("clear", False), {}, consumer, RULES, T0 + 60)
    assert store.incidents()[0]["state"] == "recovering"
    inc.sync(store, {"conditions": []}, {}, consumer, RULES, T0 + 61 + inc.CONFIRM_SECONDS)
    assert store.incidents() == []          # resolution text attributes recovery to the evaluator, not the attempt
    resolved = [x for x in store.incidents(unresolved_only=False) if x["state"] == "resolved"][0]
    assert resolved["resolution"].startswith("verified recovery") and store.attempts(resolved["id"])[0]["outcome"] == "indeterminate"


def test_unknown_persistence_outcome_retry_safety_is_operation_and_backend_specific(store, request):
    """F2: the shim has no typed outcome-unknown result. After a lost acknowledgment the contract cannot say whether
    the mutation landed; whether a retry is SAFE, REFUSED or DUPLICATE is established here per operation/backend.
    - event with a dedup key / attempt upsert / same-value update: retry is SAFE on every backend (contract
      idempotency, as the Store docstring claims 'where it can be').
    - open_incident retried DIRECTLY: SqliteStore REFUSES (partial unique index one_unresolved_per_key);
      JournalStore silently creates a second unresolved incident. Genuinely indeterminate at the contract layer.
    - open_incident retried through the find-or-open caller pattern (what sync() does): SAFE on every backend.
    """
    backend = request.node.callspec.params["store"]
    inc.sync(store, report("present", True), {}, None, RULES, T0)
    iid = store.incidents()[0]["id"]
    at = inc.iso(T0)

    # event, dedup-keyed: safe
    s = LostAck(store, "event")
    with pytest.raises(inc.StoreUnavailable):
        s.event(iid, at, "note", {"by": "op", "text": "t"}, dedup="n:1")
    assert store.event(iid, at, "note", {"by": "op", "text": "t"}, dedup="n:1") is False     # retry: already there
    assert sum(1 for e in store.events(iid) if e["kind"] == "note") == 1

    # attempt upsert: safe
    f = {"opened_at": at, "settled_at": None, "outcome": None, "phase": "dispatched", "verified": None, "plan": "p.json"}
    with pytest.raises(inc.StoreUnavailable):
        LostAck(store, "attempt").attempt(iid, "sha256:la", f)
    assert store.attempt(iid, "sha256:la", f) == (False, False)
    assert len(store.attempts(iid)) == 1

    # same-value update: safe
    with pytest.raises(inc.StoreUnavailable):
        LostAck(store, "update").update(iid, ack_by="op")
    store.update(iid, ack_by="op")
    assert store.current(KEY)["ack_by"] == "op"

    # direct open_incident retry after a lost ack: refused on sqlite, duplicated on the journal backend
    other = KEY2
    with pytest.raises(inc.StoreUnavailable):
        LostAck(store, "open_incident").open_incident(other, at, at)                          # landed; ack lost
    if backend == "sqlite":
        with pytest.raises(inc.StoreUnavailable):
            store.open_incident(other, at, at)                                              # unique index refuses
        assert len([i for i in store.incidents() if i["key"] == other]) == 1
    else:
        retry_id = store.open_incident(other, at, at)                                       # no guard: duplicates
        open_for_key = [i["id"] for i in store.incidents() if i["key"] == other]
        assert len(open_for_key) == 2 and retry_id == open_for_key[0] + "-2"

    # the find-or-open caller pattern converges on both backends after the same lost ack
    cur = store.current(other)
    if cur is None or cur["state"] == "resolved":
        store.open_incident(other, at, at)
    n = len([i for i in store.incidents() if i["key"] == other])
    assert n == (1 if backend == "sqlite" else 2), "find-or-open adds nothing once current() sees the landed write"


# ------------------------------------------------------------------ 5. verified resolution
def test_only_confirmed_recovery_closes_and_flap_continues_the_incident(store):
    inc.sync(store, report("present", True), {}, None, RULES, T0)
    iid = store.incidents()[0]["id"]
    inc.sync(store, report("clear", False), {}, None, RULES, T0 + 60)
    assert store.incidents()[0]["state"] == "recovering"
    inc.sync(store, report("present", True), {}, None, RULES, T0 + 120)                        # flap inside the window
    assert store.incidents()[0]["state"] == "open" and "recurred" in kinds(store, iid)
    inc.sync(store, report("clear", False), {}, None, RULES, T0 + 180)
    inc.sync(store, {"conditions": []}, {}, None, RULES, T0 + 300)
    assert store.incidents()[0]["state"] == "recovering", "forgotten by the evaluator: still confirming, still open"
    inc.sync(store, {"conditions": []}, {}, None, RULES, T0 + 180 + inc.CONFIRM_SECONDS)
    assert store.incidents() == []
    r = store.incidents(unresolved_only=False)[0]
    assert r["resolution"].startswith("verified recovery") and "resolved" == kinds(store, iid)[-1]


def test_operator_resolve_is_recorded_as_explicitly_unverified(tmp_path):
    """Via the real CLI. F3: main() constructs SqliteStore itself, so the operator path is exercised against SQLite
    only; the shim substitution point is the lifecycle/library layer, not the CLI."""
    db = str(tmp_path / "i.sqlite")
    s = inc.SqliteStore(db)
    inc.sync(s, report("present", True), {}, None, RULES, T0)
    iid = s.incidents()[0]["id"]
    assert inc.main(["--db", db, "resolve", iid, "--by", "op", "--note", "replaced the unit"]) == 0
    r = [x for x in inc.SqliteStore(db).incidents(unresolved_only=False) if x["id"] == iid][0]
    assert r["state"] == "resolved" and "not verified by Constellation" in r["resolution"]
    resolved_events = [e for e in inc.SqliteStore(db).events(iid) if e["kind"] == "resolved"]
    assert json.loads(resolved_events[0]["detail"])["verified"] is False


# ------------------------------------------------------------------ amendment: concurrent find-or-open
def find_or_open(s, key, at, errors):
    """The call pattern sync() uses: current(key), then open_incident if absent."""
    try:
        cur = s.current(key)
        if cur is None or cur["state"] == "resolved":
            s.open_incident(key, at, at)
    except inc.StoreUnavailable as e:
        errors.append(str(e))


class BarrierAfterCurrent:
    """Forces the race deterministically: every racer completes current() before any may open_incident()."""
    def __init__(self, store, barrier):
        self._s, self._b = store, barrier
    def current(self, key):
        out = self._s.current(key)
        self._b.wait(timeout=15)
        return out
    def open_incident(self, key, at, first_seen):
        return self._s.open_incident(key, at, first_seen)


@pytest.mark.parametrize("backend", ["sqlite", "journal"])
def test_concurrent_find_or_open_forced_race(tmp_path, backend):
    """F4: under a forced check-then-act race, one unresolved incident per key is guaranteed by SQLite's partial
    unique index (the loser is REFUSED with StoreUnavailable), not by the shim contract: the journal backend,
    implementing the documented interface, produces TWO unresolved incidents for one condition. Deduplication
    under concurrency is an implementation property of the SQLite backend, not a portable contract guarantee."""
    barrier = threading.Barrier(2)
    errors = []
    if backend == "sqlite":
        path = str(tmp_path / "race.sqlite")
        inc.SqliteStore(path).db.close()                                                     # schema first; connections are per-thread
        def work():
            find_or_open(BarrierAfterCurrent(inc.SqliteStore(path), barrier), KEY, inc.iso(T0), errors)
    else:
        shared = JournalStore()
        def work():
            find_or_open(BarrierAfterCurrent(shared, barrier), KEY, inc.iso(T0), errors)
    threads = [threading.Thread(target=work) for _ in range(2)]
    for t in threads: t.start()
    for t in threads: t.join(timeout=30)
    assert not any(t.is_alive() for t in threads)
    if backend == "sqlite":
        probe = inc.SqliteStore(path)
        unresolved = [i for i in probe.incidents() if i["key"] == KEY]
        assert len(unresolved) == 1, unresolved
        assert len(errors) == 1, "exactly one racer was refused by the unique index: %s" % errors
    else:
        unresolved = [i for i in shared.incidents() if i["key"] == KEY]
        assert len(unresolved) == 2 and [i["id"] for i in unresolved] == ["inc-" + inc.key_hash(KEY),
                                                                          "inc-" + inc.key_hash(KEY) + "-2"]


def test_concurrent_find_or_open_sqlite_never_duplicates_unforced(tmp_path):
    """The SQLite guarantee without interleave forcing: many races, exactly one unresolved incident each round."""
    path = str(tmp_path / "many.sqlite")
    inc.SqliteStore(path).db.close()
    for round_ in range(25):
        errors, barrier = [], threading.Barrier(4)
        def worker():
            s = inc.SqliteStore(path)
            barrier.wait(timeout=15)
            find_or_open(s, KEY, inc.iso(T0), errors)
        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=30)
        assert not any(t.is_alive() for t in threads)
        n = len([i for i in inc.SqliteStore(path).incidents() if i["key"] == KEY])
        assert n == 1, "round %d: %d unresolved incidents for one key" % (round_, n)
        # reset for the next round: resolve the episode directly (test-local cleanup, not a lifecycle claim)
        s = inc.SqliteStore(path)
        s._x("UPDATE incident SET state='resolved', resolved_at=? WHERE key=?", (inc.iso(T0), KEY))
