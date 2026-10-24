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
        iid = inc.next_incident_id(key, list(self.inc))
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
    def adopt(self, row):
        self.n += 1; self.inc[row["id"]] = dict(row, _n=self.n)


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


@pytest.mark.parametrize("recorded_intent", [False, True])
def test_attention_references_are_annotated_with_store_ids(store, recorded_intent):
    fixture = json.loads((HERE / "fixtures/repeated-notice.json").read_text())
    reference = None
    for step in fixture["steps"]:
        now = fixture["start"] + step["offset"]
        first_seen, active = step["first_seen"], step["active"]
        if active:
            reference = "%s@%s" % (fixture["key"], inc.iso(first_seen))
        c = {"id": fixture["key"], "rule": "host-posture-unknown", "active": active,
             "observation": "present" if step["state"] == "unknown" else "clear",
             "first_seen": inc.iso(first_seen) if first_seen else None}
        notice_state = {"conditions": {fixture["key"]: {"last_intent": {"notice": {"action": "trigger"}}}}} if active and recorded_intent else {}
        inc.sync(store, {"conditions": [c]}, notice_state, None, {}, now)
        if reference:
            row = inc.find(store, reference)
            assert row["id"] == step["incident"]
            annotations = [json.loads(e["detail"]) for e in store.events(row["id"]) if e["kind"] == "attention-reference"]
            assert {"reference": reference, "incident_id": row["id"]} in annotations
    # An exact old id must not resolve to its newer suffix.
    base = fixture["steps"][1]["incident"]
    assert inc.find(store, base)["id"] == base
    assert inc.find(store, fixture["key"] + "@2099-01-01T00:00:00Z") is None


def test_missing_reference_explains_sync_timing(store):
    ref = KEY + "@2099-01-01T00:00:00Z"
    assert inc.show_view(store, ref) == "no incident %s (sync has not run yet; last sync never)" % ref
    store.heartbeat(inc.iso(T0), True, "ok")
    assert inc.show_view(store, ref) == (
        "no incident %s (sync may not have observed this reference yet; last sync %s)" % (ref, inc.iso(T0)))


def test_new_attention_epoch_inside_recovery_still_names_the_same_incident(store):
    inc.sync(store, report("present", True), state(("notice", "ev-1", "trigger")), None, RULES, T0)
    iid = store.current(KEY)["id"]
    inc.sync(store, report("clear", False, first_seen=None), {}, None, RULES, T0 + 60)
    since = inc.iso(T0 + 120)
    inc.sync(store, report("present", True, first_seen=since), state(("notice", "ev-2", "trigger")), None, RULES, T0 + 180)
    inc.sync(store, report("present", True, first_seen=since), state(("notice", "ev-2", "trigger")), None, RULES, T0 + 240)
    assert inc.find(store, KEY + "@" + since)["id"] == iid
    assert kinds(store, iid).count("attention-reference") == 2


def test_remediation_history_keeps_the_opening_rule_revision(store):
    e = episode("sha256:rule-bound", "completed")
    revision = json.loads((HERE.parent / "crates/constellation-remediation-consumer/tests/fixtures/rule-revision-v1.json").read_bytes())
    e["rule_revision"] = revision
    inc.sync(store, report("present", True), {}, {"active": None, "closed": [e]}, RULES, T0)
    iid = store.incidents()[0]["id"]
    # A later current rule cannot relabel a historical remediation attempt.
    changed_rules = dict(RULES, **{"service-down": dict(RULES["service-down"], version=3)})
    inc.sync(store, report("present", True), {}, {"active": None, "closed": [e]}, changed_rules, T0 + 60)
    details = [json.loads(ev["detail"]) for ev in store.events(iid) if ev["kind"] == "remediation-definition"]
    assert len(details) == 1 and details[0]["rule_revision"] == revision
    assert len(store.attempts(iid)) == 1


def test_opening_journal_provenance_is_bounded_and_does_not_relabel_legacy_state(tmp_path):
    e = episode("sha256:bound", "completed")
    revision = {"rule": "service-down", "version": 2, "attention_policy_digest": "sha256:" + "a" * 64}
    state_path = tmp_path / "state.json"
    raw = json.dumps({"active": None, "closed": [e]}).encode()
    state_path.write_bytes(raw)
    journal = tmp_path / "journal.jsonl"
    record = {"schema": "constellation.remediation-consumer.journal/v1", "event": "episode_opened", "episode": e["episode"],
              "detail": {"episode": e["episode"], "condition_id": KEY, "first_seen": e["first_seen"], "rule_revision": revision}}
    line = json.dumps(record).encode() + b"\n"
    journal.write_bytes(line)
    assert inc.read_consumer(str(state_path))["closed"][0]["rule_revision"] == revision
    assert state_path.read_bytes() == raw and journal.read_bytes() == line
    for content in [line[:-1], b"{\n", b"x" * 1024 + b"\n", b"", line + line.replace(b'"version": 2', b'"version": 3')]:
        journal.write_bytes(content)
        assert "rule_revision" not in inc.read_consumer(str(state_path), journal_limit=1024)["closed"][0]
    journal.unlink()
    assert "rule_revision" not in inc.read_consumer(str(state_path))["closed"][0]


def test_opening_provenance_is_found_in_sealed_journal_generations_within_the_bound(tmp_path):
    e = episode("sha256:sealed", "completed")
    revision = {"rule": "service-down", "version": 2, "attention_policy_digest": "sha256:" + "b" * 64}
    state_path = tmp_path / "state.json"
    state_path.write_bytes(json.dumps({"active": None, "closed": [e]}).encode())
    record = {"schema": "constellation.remediation-consumer.journal/v1", "event": "episode_opened", "episode": e["episode"],
              "detail": {"episode": e["episode"], "condition_id": KEY, "first_seen": e["first_seen"], "rule_revision": revision}}
    line = json.dumps(record).encode() + b"\n"
    sealing = json.dumps({"schema": "constellation.remediation-consumer.journal/v1", "event": "journal_sealed",
                          "episode": None, "detail": {"predecessor": "journal.sealed.0002.jsonl"}}).encode() + b"\n"
    live = tmp_path / "journal.jsonl"
    live.write_bytes(sealing)
    filler = b"{}\n" * 100
    newest = tmp_path / "journal.sealed.0002.jsonl"
    newest.write_bytes(line + filler)
    # The newest sealed generation's tail is read while the bound lasts.
    assert inc.read_consumer(str(state_path))["closed"][0]["rule_revision"] == revision
    assert inc.read_consumer(str(state_path), journal_limit=len(sealing) + len(line) + len(filler))["closed"][0]["rule_revision"] == revision
    # Bytes beyond the shared bound are not read.
    assert "rule_revision" not in inc.read_consumer(str(state_path), journal_limit=len(sealing) + len(filler))["closed"][0]
    # Older generations follow newer ones; a conflict anywhere leaves it unknown.
    newest.write_bytes(filler)
    (tmp_path / "journal.sealed.0001.jsonl").write_bytes(line)
    assert inc.read_consumer(str(state_path))["closed"][0]["rule_revision"] == revision
    (tmp_path / "journal.sealed.0003.jsonl").write_bytes(line.replace(b'"version": 2', b'"version": 3'))
    assert "rule_revision" not in inc.read_consumer(str(state_path))["closed"][0]
    # Unreadable, missing and foreign names are tolerated, never required.
    (tmp_path / "journal.sealed.0003.jsonl").unlink()
    (tmp_path / "journal.sealed.0004.jsonl").mkdir()
    (tmp_path / "journal.sealed.x.jsonl").write_bytes(line.replace(b'"version": 2', b'"version": 3'))
    (tmp_path / "journal.sealed.0005.jsonl\n").write_bytes(line.replace(b'"version": 2', b'"version": 3'))
    live.unlink()
    assert inc.read_consumer(str(state_path))["closed"][0]["rule_revision"] == revision


def test_definition_binding_can_arrive_after_the_attempt_without_losing_history(store):
    e = episode("sha256:late", "completed")
    consumer = {"active": None, "closed": [e]}
    inc.sync(store, report("present", True), {}, consumer, RULES, T0)
    e["rule_revision"] = {"rule": "service-down", "version": 2, "attention_policy_digest": "sha256:" + "a" * 64}
    inc.sync(store, report("present", True), {}, consumer, RULES, T0 + 60)
    inc.sync(store, report("present", True), {}, consumer, RULES, T0 + 120)
    iid = store.incidents()[0]["id"]
    assert kinds(store, iid).count("remediation") == 1
    assert kinds(store, iid).count("remediation-definition") == 1


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


def test_a_resolved_row_starts_where_the_open_row_did(store):
    """One incident, one start time: the condition's first_seen in both views (found by cartography #94)."""
    inc.sync(store, report("present", True), {}, None, RULES, T0)
    assert "failing since 2026-10-14T18:45:03Z" in inc.list_view(store, now=T0)
    inc.sync(store, report("clear", False), {}, None, RULES, T0 + 60)
    inc.sync(store, {"conditions": []}, {}, None, RULES, T0 + 61 + inc.CONFIRM_SECONDS)
    assert store.incidents() == []
    assert "attention-canary.service 2026-10-14T18:45:03Z -> " in inc.list_view(store, now=T0 + 62 + inc.CONFIRM_SECONDS)


def test_handover_carries_unresolved_incidents_to_a_replacement_host(tmp_path):
    """cartography #94: a rebuilt host must not silently drop obligations, nor claim recovery it did not observe."""
    a, b = MemoryStore(), inc.SqliteStore(str(tmp_path / "b.sqlite"))
    inc.sync(a, report("present", True), state(("notice", "ev-1", "trigger")), None, RULES, T0)
    doc = json.loads(json.dumps(inc.export_unresolved(a, "host-a", T0 + 10)))   # through JSON, as the file is
    adopted, skipped = inc.import_unresolved(b, doc, "host-b", T0 + 20)
    iid = "inc-" + inc.key_hash(KEY)
    assert adopted == [iid] and skipped == []
    i = b.incidents()[0]
    assert i["id"] == iid and i["needs_operator"].startswith("inherited from host-a")
    kinds = [e["kind"] for e in b.events(iid)]
    assert "detected" in kinds and "notified" in kinds and kinds[-1] == "inherited"
    # the replacement's evaluator sees it clear: closure only after this host's own confirmation
    inc.sync(b, report("clear", False), {}, None, RULES, T0 + 60)
    assert b.incidents()[0]["state"] == "recovering"
    inc.sync(b, {"conditions": []}, {}, None, RULES, T0 + 61 + inc.CONFIRM_SECONDS)
    assert b.incidents() == []
    # importing the same handover again does not resurrect it
    assert inc.import_unresolved(b, doc, "host-b", T0 + 999)[0] == []


def test_a_suspension_carries_over_as_a_suspension(tmp_path):
    """Found on production's first handover pull (2026-10-15): the inherited prefix moved a suspended incident under
    NEEDS YOU, so an operator's decision on the old host would have demanded them again on the new one."""
    a, b = MemoryStore(), inc.SqliteStore(str(tmp_path / "b.sqlite"))
    inc.sync(a, report("present", True), state(("notice", "ev-1", "trigger")), None, RULES, T0)
    doc = inc.export_unresolved(a, "host-a", T0 + 10)
    doc["incidents"][0]["incident"]["needs_operator"] = "suspended by op until: the store is replaced"
    inc.import_unresolved(b, doc, "host-b", T0 + 20)
    view = inc.list_view(b, now=T0 + 30)
    suspended = view[view.index("SUSPENDED BY DECISION"):view.index("OPEN, NOTHING NEEDED")]
    assert "inc-" + inc.key_hash(KEY) in suspended and "inherited from host-a" in suspended


def test_import_seeds_a_new_hosts_store_before_any_sync(tmp_path):
    a = MemoryStore()
    inc.sync(a, report("present", True), state(("notice", "ev-1", "trigger")), None, RULES, T0)
    f = tmp_path / "handover.json"; f.write_text(json.dumps(inc.export_unresolved(a, "host-a", T0 + 10)))
    db = str(tmp_path / "fresh" / "incidents.sqlite")                    # no state directory yet
    assert inc.main(["--db", db, "import", str(f)]) == 0
    assert inc.main(["--db", str(tmp_path / "other" / "i.sqlite"), "list"]) != 0   # readers still refuse a missing store


def test_a_recurrence_after_an_inherited_episode_gets_a_fresh_id(tmp_path):
    """cartography #94 (Linode): the replacement adopted inc-<h>-2, it closed, the condition recurred: the next
    episode's id was a count (1 incident -> "-2") and every later sync failed on the unique id."""
    a, b = MemoryStore(), inc.SqliteStore(str(tmp_path / "b.sqlite"))
    for t in (T0, T0 + 1000):                                            # two episodes on the old host
        inc.sync(a, report("present", True), state(("notice", "ev-%d" % t, "trigger")), None, RULES, t)
        inc.sync(a, report("clear", False), {}, None, RULES, t + 60)
        inc.sync(a, {"conditions": []}, {}, None, RULES, t + 61 + inc.CONFIRM_SECONDS)
    inc.sync(a, report("present", True), state(("notice", "ev-3", "trigger")), None, RULES, T0 + 3000)
    iid = "inc-" + inc.key_hash(KEY)
    assert inc.import_unresolved(b, inc.export_unresolved(a, "host-a", T0 + 3010), "host-b", T0 + 3020)[0] == [iid + "-3"]
    inc.sync(b, report("clear", False), {}, None, RULES, T0 + 3060)
    inc.sync(b, {"conditions": []}, {}, None, RULES, T0 + 3061 + inc.CONFIRM_SECONDS)
    inc.sync(b, report("present", True), state(("notice", "ev-4", "trigger")), None, RULES, T0 + 4000)
    assert [i["id"] for i in b.incidents()] == [iid + "-4"]


def test_incident_ids_are_never_reused_by_count():
    k = KEY; base = "inc-" + inc.key_hash(k)
    assert inc.next_incident_id(k, []) == base
    assert inc.next_incident_id(k, [base]) == base + "-2"
    assert inc.next_incident_id(k, [base + "-3"]) == base + "-4"            # earlier episodes pruned
    assert inc.next_incident_id(k, [base + "-2", base + "x-9"]) == base + "-3"


def test_handover_does_not_inherit_recovery_or_close_what_the_new_host_never_sees():
    a, b = MemoryStore(), MemoryStore()
    inc.sync(a, report("present", True), {}, None, RULES, T0)
    inc.sync(a, report("clear", False), {}, None, RULES, T0 + 60)
    assert a.incidents()[0]["state"] == "recovering"
    inc.import_unresolved(b, inc.export_unresolved(a, "host-a", T0 + 70), "host-b", T0 + 80)
    assert b.incidents()[0]["state"] == "open"        # recovery was not observed here
    for t in (T0 + 100, T0 + 100 + 2 * inc.CONFIRM_SECONDS):
        inc.sync(b, {"conditions": []}, {}, None, RULES, t)
    i = b.incidents()[0]
    assert i["state"] == "open" and i["last_observation"] == "unreported" and i["needs_operator"]


def test_handover_never_overwrites_an_incident_the_new_host_already_has():
    a, b = MemoryStore(), MemoryStore()
    inc.sync(a, report("present", True), {}, None, RULES, T0)
    inc.sync(b, report("present", True), {}, None, RULES, T0 + 5)
    adopted, skipped = inc.import_unresolved(b, inc.export_unresolved(a, "host-a", T0 + 10), "host-b", T0 + 20)
    assert adopted == [] and "already exists here" in skipped[0][1]


def test_maintenance_is_visible_but_recovery_and_needs_operator_are_independent(store):
    window = dict(started_at=inc.iso(T0), until=inc.iso(T0 + 1800), reason="upgrade", by="operator")
    current = report("present", True)
    current["conditions"][0]["maintenance"] = window
    for offset in [0, 60]:
        inc.sync(store, current, {}, None, RULES, T0 + offset)
    live = store.incidents()[0]
    assert live["needs_operator"]
    assert kinds(store, live["id"]).count("maintenance") == 1
    view = inc.list_view(store, now=T0 + 60)
    assert "Open — notifications suppressed" in view
    assert "UNDER MAINTENANCE (1)" in view
    assert "NEEDS YOU (0)" in view
    assert "OPEN, NOTHING NEEDED FROM YOU NOW (0)" in view
    assert "recovery unverified" in view
    assert view.count(live["id"]) == 1
    expired = inc.list_view(store, now=T0 + 1800)
    assert "UNDER MAINTENANCE (0)" in expired and "NEEDS YOU (1)" in expired
    assert expired.count(live["id"]) == 1
    recovered = report("clear", False)
    recovered["conditions"][0]["maintenance"] = window
    inc.sync(store, recovered, {}, None, RULES, T0 + 120)
    assert store.current(KEY)["state"] == "recovering"
    assert store.current(KEY)["needs_operator"] is None
    view = inc.list_view(store, now=T0 + 120)
    assert "UNDER MAINTENANCE (1)" in view and "[recovering; recovery unverified]" in view
    assert view.count(live["id"]) == 1
    inc.sync(store, report("clear", False), {}, None, RULES, T0 + 180)
    assert "notifications suppressed" not in inc.list_view(store, now=T0 + 180)


def test_maintenance_section_partitions_mixed_incidents(store):
    ids = []
    for name, needed, maintained in [("bar", "inspect", True), ("baz", "inspect", False),
                                    ("suspended", "suspended by operator", True),
                                    ("other", None, False)]:
        iid = store.open_incident("constellation:labelwatch:service:service-down:" + name,
                                  inc.iso(T0), inc.iso(T0))
        store.update(iid, needs_operator=needed)
        if maintained:
            store.event(iid, inc.iso(T0), "maintenance", {"until": inc.iso(T0 + 1800)})
        ids.append(iid)
    view = inc.list_view(store, now=T0 + 60)
    for heading in ["NEEDS YOU (1)", "SUSPENDED BY DECISION, STILL OPEN (0)",
                    "OPEN, NOTHING NEEDED FROM YOU NOW (1)", "UNDER MAINTENANCE (2)"]:
        assert heading in view
    assert all(view.count(iid) == 1 for iid in ids)
