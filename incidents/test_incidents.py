"""Contract tests for constellation-incidents (cartography #93). The lifecycle runs against the SQLite backend and an
in-memory stub through the same Store interface: the semantics live in sync(), not in a backend."""
import importlib.util, json, os, pathlib, sqlite3, stat
import pytest

HERE = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location("inc", HERE / "constellation-incidents.py")
inc = importlib.util.module_from_spec(spec); spec.loader.exec_module(inc)

KEY = "constellation:labelwatch:service:service-down:attention-canary.service"
RULES = {"service-down": {"id": "service-down", "response_policy": "auto_remediate_then_page",
                          "operator_response": "systemctl status <unit>; restart if failed"},
         "sqlite-health": {"id": "sqlite-health", "response_policy": "observe_only", "operator_response": "inspect the saved check"}}
T0 = 1_792_000_000


class MemoryStore(inc.Store):
    """Alternate backend: proves the lifecycle is not SQLite-specific."""
    def __init__(self): self.inc, self.ev, self.att, self.m, self.n = {}, [], {}, {}, 0
    def open_incident(self, key, at, first_seen):
        n = sum(1 for i in self.inc.values() if i["key"] == key)
        iid = "inc-%s" % inc.key_hash(key) + ("" if n == 0 else "-%d" % (n + 1))
        self.n += 1
        self.inc[iid] = {"id": iid, "key": key, "rule": key.split(":")[3], "subject": ":".join(key.split(":")[4:]), "state": "open",
                         "opened_at": at, "first_seen": first_seen, "last_observed_at": None, "last_observation": None, "recovering_since": None,
                         "resolved_at": None, "resolution": None, "needs_operator": None, "ack_by": None, "ack_note": None, "_n": self.n}
        return iid
    def current(self, key):
        c = [i for i in self.inc.values() if i["key"] == key]
        return dict(max(c, key=lambda i: i["_n"])) if c else None
    def update(self, iid, **f): self.inc[iid].update(f)
    def event(self, iid, at, kind, detail, dedup=None):
        if dedup and any(e[4] == dedup for e in self.ev): return False
        self.ev.append((iid, at, kind, json.dumps(detail), dedup)); return True
    def attempt(self, iid, ep, f):
        old = self.att.get((iid, ep))
        if old is None: self.att[(iid, ep)] = dict(f, episode=ep); return True, False
        ch = any((old.get(k) or None) != (f.get(k) or None) for k in ("settled_at", "outcome", "phase", "verified"))
        old.update(f); return False, ch
    def incidents(self, unresolved_only=True):
        return [dict(i) for i in sorted(self.inc.values(), key=lambda i: i["_n"]) if not unresolved_only or i["state"] != "resolved"]
    def events(self, iid): return [{"at": e[1], "kind": e[2], "detail": e[3]} for e in self.ev if e[0] == iid]
    def attempts(self, iid): return [dict(v, incident=k[0]) for k, v in self.att.items() if k[0] == iid]
    def heartbeat(self, at, ok, note): self.m.update(last_sync_at=at, last_sync_ok="1" if ok else "0", last_sync_note=note)
    def meta(self): return dict(self.m)


@pytest.fixture(params=["sqlite", "memory"])
def store(request, tmp_path):
    return inc.SqliteStore(str(tmp_path / "i.sqlite")) if request.param == "sqlite" else MemoryStore()


def report(obs, active, first_seen="2026-10-14T18:45:03Z", suspended=None, extra=None):
    c = {"id": KEY, "rule": "service-down", "observation": obs, "active": active, "first_seen": first_seen, "note": "x"}
    if suspended: c["suspended"] = suspended
    return {"evaluated_at": "t", "conditions": [c] + (extra or [])}


def state(*intents):
    return {"conditions": {KEY: {"last_intent": {i[0]: {"stable_event_id": i[1], "outcome": "accepted", "route": "operations", "action": i[2]} for i in intents}}}}


def episode(ep, outcome=None, first_seen="2026-10-14T18:45:03Z"):
    return {"episode": ep, "condition_id": KEY, "first_seen": first_seen, "outcome": outcome, "phase": "settled" if outcome else "dispatched",
            "plan": "/etc/x/start-inactive.json", "opened_at_unix_ms": (T0 + 60) * 1000, "settled_at_unix_ms": (T0 + 90) * 1000 if outcome else None}


def kinds(store, iid): return [e["kind"] for e in store.events(iid)]


def test_repeated_failures_make_one_incident_and_notifications_are_recorded_once(store):
    for t in range(0, 600, 60):
        inc.sync(store, report("present", True), state(("notice", "ev-1", "trigger")), None, RULES, T0 + t)
    assert len(store.incidents()) == 1
    iid = store.incidents()[0]["id"]
    assert kinds(store, iid).count("detected") == 1 and kinds(store, iid).count("notified") == 1


def test_failed_remediation_attached_and_escalated_to_the_operator(store):
    inc.sync(store, report("present", True), {}, {"active": episode("sha256:aa"), "closed": []}, RULES, T0)
    i = store.incidents()[0]
    assert i["needs_operator"] is None, "in flight: nothing needed yet"
    inc.sync(store, report("present", True), {}, {"active": None, "closed": [episode("sha256:aa", "settled_failure")]}, RULES, T0 + 120)
    i = store.incidents()[0]
    assert i["needs_operator"].startswith("remediation failed (settled_failure)")
    att = store.attempts(i["id"])
    assert len(att) == 1 and att[0]["outcome"] == "settled_failure" and not att[0]["verified"]


def test_policy_change_suspension_retirement_and_disappearance_never_resolve(store):
    inc.sync(store, report("present", True), {}, None, RULES, T0)
    iid = store.incidents()[0]["id"]
    # a threshold/version change keeps the condition key: same incident
    inc.sync(store, report("present", True, extra=[]), {}, None, RULES, T0 + 60)
    susp = {"owner": "op", "reason": "maintenance", "resume_when": "done", "since": "2026-10-14"}
    inc.sync(store, report("unknown", True, suspended=susp), {}, None, RULES, T0 + 120)
    assert store.incidents()[0]["state"] != "resolved" and "suspended by op" in store.incidents()[0]["needs_operator"]
    inc.sync(store, report("removed", False), {}, None, RULES, T0 + 180)
    inc.sync(store, {"conditions": []}, {}, None, RULES, T0 + 240)
    inc.sync(store, {"conditions": []}, {}, None, RULES, T0 + 4000)
    open_ = store.incidents()
    assert len(open_) == 1 and open_[0]["id"] == iid and open_[0]["state"] != "resolved"
    assert "unobserved" in kinds(store, iid) and "resolved" not in kinds(store, iid)


def test_flap_continues_and_closure_needs_confirmed_recovery(store):
    inc.sync(store, report("present", True), {}, None, RULES, T0)
    iid = store.incidents()[0]["id"]
    inc.sync(store, report("clear", False), {}, None, RULES, T0 + 60)
    assert store.incidents()[0]["state"] == "recovering"
    inc.sync(store, report("present", True), {}, None, RULES, T0 + 120)      # flap inside the window
    assert store.incidents()[0]["state"] == "open" and "recurred" in kinds(store, iid)
    inc.sync(store, report("clear", False), {}, None, RULES, T0 + 180)
    inc.sync(store, {"conditions": []}, {}, None, RULES, T0 + 300)            # evaluator forgot the resolved condition
    assert store.incidents()[0]["state"] == "recovering"
    inc.sync(store, {"conditions": []}, {}, None, RULES, T0 + 180 + inc.CONFIRM_SECONDS)
    assert store.incidents() == [] and kinds(store, iid)[-1] == "resolved"
    # a new failure after closure is a new incident for the same key
    inc.sync(store, report("present", True, first_seen="2026-10-15T00:00:00Z"), {}, None, RULES, T0 + 9000)
    assert store.incidents()[0]["id"] == iid + "-2"


def test_a_remediation_in_flight_holds_closure(store):
    inc.sync(store, report("present", True), {}, None, RULES, T0)
    inc.sync(store, report("clear", False), {}, {"active": episode("sha256:bb"), "closed": []}, RULES, T0 + 60)
    inc.sync(store, {"conditions": []}, {}, {"active": episode("sha256:bb"), "closed": []}, RULES, T0 + 60 + inc.CONFIRM_SECONDS)
    assert store.incidents()[0]["state"] == "recovering"
    inc.sync(store, {"conditions": []}, {}, {"active": None, "closed": [episode("sha256:bb", "completed")]}, RULES, T0 + 70 + inc.CONFIRM_SECONDS)
    assert store.incidents() == []


def test_history_survives_a_restart_and_one_query_tells_the_story(tmp_path):
    db = str(tmp_path / "i.sqlite")
    s = inc.SqliteStore(db)
    inc.sync(s, report("present", True), state(("notice", "ev-1", "trigger")), {"active": None, "closed": [episode("sha256:cc", "settled_failure")]}, RULES, T0)
    s.heartbeat(inc.iso(T0), True, "ok")
    del s
    ro = inc.SqliteStore(db, readonly=True)          # a new process, read-only: what the operator runs
    text = inc.list_view(ro, now=T0 + 10)
    assert "NEEDS YOU (1)" in text and "remediation failed (settled_failure)" in text and "start-inactive.json settled_failure" in text
    show = inc.show_view(ro, ro.incidents()[0]["id"])
    for k in ("detected", "notified", "remediation", "needs-operator"):
        assert k in show


def test_unavailable_store_claims_nothing(tmp_path):
    d = tmp_path / "ro"; d.mkdir(); os.chmod(d, stat.S_IRUSR | stat.S_IXUSR)
    try:
        with pytest.raises(inc.StoreUnavailable):
            inc.SqliteStore(str(d / "i.sqlite"))
        assert inc.main(["--db", str(d / "i.sqlite"), "ack", "inc-x", "--by", "op"]) == 3
    finally:
        os.chmod(d, stat.S_IRWXU)


def test_operator_resolve_is_recorded_as_unverified(tmp_path):
    db = str(tmp_path / "i.sqlite")
    s = inc.SqliteStore(db)
    inc.sync(s, report("present", True), {}, None, RULES, T0)
    iid = s.incidents()[0]["id"]
    assert inc.main(["--db", db, "resolve", iid, "--by", "op", "--note", "replaced the host"]) == 0
    i = [x for x in inc.SqliteStore(db).incidents(unresolved_only=False) if x["id"] == iid][0]
    assert i["state"] == "resolved" and "not verified by Constellation" in i["resolution"]


def test_no_remediation_attempt_by_the_end_of_the_window_needs_the_operator(store):
    r = report("present", True); r["conditions"][0]["remediation_window_until"] = T0 + 300
    inc.sync(store, r, {}, None, RULES, T0)
    assert store.incidents()[0]["needs_operator"] is None
    inc.sync(store, r, {}, None, RULES, T0 + 301)
    assert store.incidents()[0]["needs_operator"].startswith("systemctl status")


def test_incident_id_matches_the_attention_notice_reference():
    # constellation-attention intent::incident_ref pins the same value for the same key.
    assert "inc-" + inc.key_hash(KEY) == "inc-e048fb3e"


def test_a_suspended_incident_is_listed_apart_from_what_needs_the_operator(tmp_path):
    s = inc.SqliteStore(str(tmp_path / "i.sqlite"))
    susp = {"owner": "op", "reason": "paused", "resume_when": "it resumes", "since": "2026-10-14"}
    inc.sync(s, report("unknown", True, suspended=susp), {}, None, RULES, T0)
    text = inc.list_view(s, now=T0)
    assert "NEEDS YOU (0)" in text and "SUSPENDED BY DECISION, STILL OPEN (1)" in text and "failing since 2026-10-14T18:45:03Z" in text


def test_a_resolve_logged_after_the_condition_is_forgotten_lands_in_the_timeline(store):
    log = [{"condition_id": KEY, "stable_event_id": "ev-trigger", "action": "trigger", "outcome": "accepted",
            "route": "operations", "route_role": "notice", "at": inc.iso(T0)}]
    inc.sync(store, report("present", True), {}, None, RULES, T0, log)
    iid = store.incidents()[0]["id"]
    inc.sync(store, report("clear", False), {}, None, RULES, T0 + 60, log)
    log.append({"condition_id": KEY, "stable_event_id": "ev-resolve", "action": "resolve", "outcome": "accepted",
                "route": "operations", "route_role": "notice", "at": inc.iso(T0 + 120)})
    inc.sync(store, {"conditions": []}, {}, None, RULES, T0 + 60 + inc.CONFIRM_SECONDS, log)
    inc.attach_late_notifications(store, log, inc.iso(T0 + 400))
    inc.attach_late_notifications(store, log, inc.iso(T0 + 460))     # idempotent
    notified = [json.loads(e["detail"]) for e in store.events(iid) if e["kind"] == "notified"]
    assert [n["action"] for n in notified] == ["trigger", "resolve"], notified


def test_led_to_action_metrics_per_rule(tmp_path):
    s = inc.SqliteStore(str(tmp_path / "i.sqlite"))
    inc.sync(s, report("present", True), {}, {"active": None, "closed": [episode("sha256:dd", "completed")]}, RULES, T0)
    inc.sync(s, report("clear", False), {}, {"active": None, "closed": [episode("sha256:dd", "completed")]}, RULES, T0 + 60)
    inc.sync(s, {"conditions": []}, {}, {"active": None, "closed": [episode("sha256:dd", "completed")]}, RULES, T0 + 60 + inc.CONFIRM_SECONDS)
    out = tmp_path / "m.prom"
    inc.write_metrics(s, str(out), T0)
    text = out.read_text()
    for o, n in (("incidents", 1), ("remediated", 1), ("remediation_verified", 1), ("needed_operator", 0), ("resolved_verified", 1)):
        assert 'constellation_incidents_by_rule{rule="service-down",outcome="%s"} %d' % (o, n) in text, text
