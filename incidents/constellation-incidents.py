#!/usr/bin/env python3
"""constellation-incidents: incident continuity for one site (cartography #93).

An alert says something happened; an incident says something still needs dealing with. This tool keeps one durable
incident per supervised subject + failure condition, independent of the processes that detect and remediate:

  sync    read the attention evaluator's report/state and the remediation consumer's episodes; open, continue,
          annotate and close incidents (idempotent; run every minute by a timer)
  list    THE operator query: what is broken, what was tried, what worked, what failed, what still needs you
  show    one incident's full timeline (id like inc-1a2b3c4d or inc-1a2b3c4d-2, or a condition key)
  ack / note / resolve   operator actions, recorded as such

Semantics (deliberately conservative):
  * identity is the condition key (site:component:rule:target), never a definition revision: changing a threshold
    continues the same incident; the rule version lives in the event history.
  * no resolution by disappearance: suspended, removed ("no longer evaluated"), unobserved or vanished-while-present
    leave the incident open and say so. It closes only after the evaluator resolved the condition as recovered
    (observation clear) AND it stayed clear for CONFIRM_SECONDS, with no remediation episode still in flight. A
    reappearance inside that window continues the same incident (flap), it does not open a new one.
  * remediation attempts record command outcome separately from verified recovery.
  * the store is its own SQLite file; list/show read it directly, so they work with the evaluator or NQ down. Every
    sync writes a heartbeat (and a textfile metric) so a dead sync is visible from outside.
Retention is bounded: resolved incidents are kept RETAIN_DAYS, and events per incident are capped.
"""
import argparse, datetime, hashlib, json, os, sqlite3, subprocess, sys, tempfile, time

SCHEMA = "constellation.incidents/v1"
CONFIRM_SECONDS = 300
RETAIN_DAYS = 30
MAX_EVENTS = 300
FAILED_OUTCOMES = {"settled_failure", "failed", "refused", "dispatch_unconfirmed", "indeterminate", "abandoned"}


def iso(t=None):
    return datetime.datetime.fromtimestamp(time.time() if t is None else t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(s):
    if not s:
        return None
    return datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def key_hash(key):
    return hashlib.sha256(key.encode()).hexdigest()[:8]


class StoreUnavailable(Exception):
    """The backend could not be read or written; nothing was claimed."""


# ------------------------------------------------------------------ deterministic store interface
class Store:
    """The incident-store shim. Constellation owns identity, lifecycle and closure; a backend only persists.
    Every method is idempotent where it can be (episode upserts, notification events keyed by their id)."""
    def open_incident(self, key, at, first_seen): raise NotImplementedError
    def current(self, key): raise NotImplementedError          # the newest incident for key, or None
    def update(self, inc_id, **fields): raise NotImplementedError
    def event(self, inc_id, at, kind, detail, dedup=None): raise NotImplementedError
    def attempt(self, inc_id, episode, fields): raise NotImplementedError  # returns (new, changed)
    def incidents(self, unresolved_only=True): raise NotImplementedError
    def events(self, inc_id): raise NotImplementedError
    def attempts(self, inc_id): raise NotImplementedError
    def heartbeat(self, at, ok, note): raise NotImplementedError
    def meta(self): raise NotImplementedError


class SqliteStore(Store):
    DDL = """
    CREATE TABLE IF NOT EXISTS incident (
      id TEXT PRIMARY KEY, key TEXT NOT NULL, rule TEXT NOT NULL, subject TEXT NOT NULL,
      state TEXT NOT NULL CHECK (state IN ('open','acknowledged','recovering','resolved')),
      opened_at TEXT NOT NULL, first_seen TEXT, last_observed_at TEXT, last_observation TEXT, recovering_since TEXT,
      resolved_at TEXT, resolution TEXT, needs_operator TEXT, ack_by TEXT, ack_note TEXT, severity TEXT);
    CREATE UNIQUE INDEX IF NOT EXISTS one_unresolved_per_key ON incident(key) WHERE state != 'resolved';
    CREATE TABLE IF NOT EXISTS event (
      incident TEXT NOT NULL REFERENCES incident(id), seq INTEGER PRIMARY KEY AUTOINCREMENT,
      at TEXT NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL, dedup TEXT UNIQUE);
    CREATE TABLE IF NOT EXISTS attempt (
      incident TEXT NOT NULL REFERENCES incident(id), episode TEXT NOT NULL, opened_at TEXT, settled_at TEXT,
      outcome TEXT, phase TEXT, verified TEXT, plan TEXT, PRIMARY KEY (incident, episode));
    CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
    """

    def __init__(self, path, readonly=False):
        try:
            uri = "file:%s%s" % (path, "?mode=ro" if readonly else "")
            self.db = sqlite3.connect(uri, uri=True, timeout=10, isolation_level=None)
            self.db.row_factory = sqlite3.Row
            if not readonly:
                self.db.execute("PRAGMA journal_mode=WAL")
                self.db.executescript(self.DDL)
                self.db.execute("INSERT OR IGNORE INTO meta VALUES ('schema', ?)", (SCHEMA,))
        except sqlite3.Error as e:
            raise StoreUnavailable(str(e))

    def _x(self, sql, args=()):
        try:
            return self.db.execute(sql, args)
        except sqlite3.Error as e:
            raise StoreUnavailable(str(e))

    def transaction(self):
        return self._Tx(self)

    class _Tx:
        def __init__(self, s): self.s = s
        def __enter__(self): self.s._x("BEGIN IMMEDIATE")
        def __exit__(self, et, e, tb):
            self.s._x("COMMIT" if et is None else "ROLLBACK")

    def open_incident(self, key, at, first_seen):
        rule, subject = key.split(":")[3], ":".join(key.split(":")[4:]) or key.split(":")[2]
        n = self._x("SELECT COUNT(*) FROM incident WHERE key=?", (key,)).fetchone()[0]
        inc = "inc-%s" % key_hash(key) + ("" if n == 0 else "-%d" % (n + 1))
        self._x("INSERT INTO incident(id,key,rule,subject,state,opened_at,first_seen) VALUES (?,?,?,?, 'open', ?, ?)",
                (inc, key, rule, subject, at, first_seen))
        return inc

    def current(self, key):
        r = self._x("SELECT * FROM incident WHERE key=? ORDER BY opened_at DESC, rowid DESC LIMIT 1", (key,)).fetchone()
        return dict(r) if r else None

    def update(self, inc_id, **fields):
        if fields:
            cols = ", ".join("%s=?" % k for k in fields)
            self._x("UPDATE incident SET %s WHERE id=?" % cols, (*fields.values(), inc_id))

    def event(self, inc_id, at, kind, detail, dedup=None):
        cur = self._x("INSERT OR IGNORE INTO event(incident,at,kind,detail,dedup) VALUES (?,?,?,?,?)",
                      (inc_id, at, kind, json.dumps(detail, sort_keys=True), dedup))
        return cur.rowcount == 1

    def attempt(self, inc_id, episode, fields):
        old = self._x("SELECT * FROM attempt WHERE incident=? AND episode=?", (inc_id, episode)).fetchone()
        if old is None:
            self._x("INSERT INTO attempt(incident,episode,opened_at,settled_at,outcome,phase,verified,plan) VALUES (?,?,?,?,?,?,?,?)",
                    (inc_id, episode, fields.get("opened_at"), fields.get("settled_at"), fields.get("outcome"),
                     fields.get("phase"), fields.get("verified"), fields.get("plan")))
            return True, False
        changed = any((old[k] or None) != (fields.get(k) or None) for k in ("settled_at", "outcome", "phase", "verified"))
        if changed:
            self._x("UPDATE attempt SET settled_at=?, outcome=?, phase=?, verified=? WHERE incident=? AND episode=?",
                    (fields.get("settled_at"), fields.get("outcome"), fields.get("phase"), fields.get("verified"), inc_id, episode))
        return False, changed

    def incidents(self, unresolved_only=True):
        q = "SELECT * FROM incident" + (" WHERE state != 'resolved'" if unresolved_only else "") + " ORDER BY opened_at"
        return [dict(r) for r in self._x(q)]

    def events(self, inc_id):
        return [dict(r) for r in self._x("SELECT at,kind,detail FROM event WHERE incident=? ORDER BY seq", (inc_id,))]

    def attempts(self, inc_id):
        return [dict(r) for r in self._x("SELECT * FROM attempt WHERE incident=? ORDER BY opened_at", (inc_id,))]

    def heartbeat(self, at, ok, note):
        self._x("INSERT OR REPLACE INTO meta VALUES ('last_sync_at', ?)", (at,))
        self._x("INSERT OR REPLACE INTO meta VALUES ('last_sync_ok', ?)", ("1" if ok else "0",))
        self._x("INSERT OR REPLACE INTO meta VALUES ('last_sync_note', ?)", (note[:500],))

    def meta(self):
        return {r["k"]: r["v"] for r in self._x("SELECT k, v FROM meta")}

    def prune(self, now):
        cutoff = iso(now - RETAIN_DAYS * 86400)
        old = [r[0] for r in self._x("SELECT id FROM incident WHERE state='resolved' AND resolved_at < ?", (cutoff,))]
        for inc in old:
            self._x("DELETE FROM event WHERE incident=?", (inc,)); self._x("DELETE FROM attempt WHERE incident=?", (inc,))
            self._x("DELETE FROM incident WHERE id=?", (inc,))
        for (inc,) in self._x("SELECT incident FROM event GROUP BY incident HAVING COUNT(*) > ?", (MAX_EVENTS,)).fetchall():
            self._x("DELETE FROM event WHERE incident=? AND seq NOT IN (SELECT seq FROM event WHERE incident=? ORDER BY seq DESC LIMIT ?)",
                    (inc, inc, MAX_EVENTS))


# ------------------------------------------------------------------ sync: the lifecycle (backend-independent)
def needs_text(rule, rules, policy):
    r = rules.get(rule) or {}
    action = r.get("operator_response") or r.get("operator_action") or "inspect the condition (runbook %s)" % r.get("runbook_anchor", rule)
    return action


def sync(store, report, state, consumer, rules, now, intent_log=()):
    """One idempotent pass. report/state: attention JSON; consumer: remediation consumer state JSON (or None);
    intent_log: the evaluator's intents.jsonl records (every delivery outcome, including resolves of conditions it
    has already forgotten)."""
    at = iso(now)
    conditions = {c["id"]: c for c in report.get("conditions", []) if c.get("observation") != "absent" or c.get("active")}
    last_intents = {k: v.get("last_intent", {}) for k, v in (state or {}).get("conditions", {}).items()}
    episodes = []
    for e in ((consumer or {}).get("closed") or []) + ([consumer["active"]] if (consumer or {}).get("active") else []):
        if isinstance(e, dict) and e.get("condition_id"):
            episodes.append(e)
    keys = set(conditions) | {i["key"] for i in store.incidents()}
    for key in sorted(keys):
        c = conditions.get(key)
        inc = store.current(key)
        live = inc if inc and inc["state"] != "resolved" else None
        if c and c.get("active"):
            # a suspended condition is still an unresolved obligation: it is opened (and shown as suspended)
            if live is None:
                inc_id = store.open_incident(key, at, c.get("first_seen"))
                live = store.current(key)
                store.event(inc_id, at, "detected", {"first_seen": c.get("first_seen"), "rule": c.get("rule"),
                            "observation": c.get("observation"), "note": c.get("note")}, dedup="detected:%s:%s" % (key, c.get("first_seen")))
            elif live["state"] == "recovering":
                store.update(live["id"], state="open", recovering_since=None)
                store.event(live["id"], at, "recurred", {"note": "present again inside the confirmation window; same incident (flap)",
                            "observation": c.get("observation")})
            store.update(live["id"], last_observed_at=at, last_observation=c.get("observation"))
        if live is None:
            continue
        inc_id = live["id"]
        for li in intent_log:
            if li.get("condition_id") == key and li.get("stable_event_id") and (li.get("at") or "") >= live["opened_at"][:10]:
                store.event(inc_id, li.get("at") or at, "notified", {"route": li.get("route"), "role": li.get("route_role"),
                            "action": li.get("action"), "outcome": li.get("outcome"), "event": li.get("stable_event_id")},
                            dedup="notified:%s:%s" % (li.get("stable_event_id"), li.get("outcome")))
        # episodes are keyed by the condition's first_seen, as the remediation consumer keys them
        since = parse_ts(live.get("first_seen")) or parse_ts(live["opened_at"]) or 0
        # notifications sent for this condition (escalation to the operator)
        for role, li in (last_intents.get(key) or {}).items():
            if li.get("outcome") and li.get("stable_event_id"):
                store.event(inc_id, at, "notified", {"route": li.get("route"), "role": role, "action": li.get("action"),
                            "outcome": li.get("outcome"), "event": li.get("stable_event_id")},
                            dedup="notified:%s:%s" % (li.get("stable_event_id"), li.get("outcome")))
        # remediation attempts (command outcome kept apart from verified recovery)
        mine = [e for e in episodes if e["condition_id"] == key and (parse_ts(e.get("first_seen")) or 0) >= since]
        for e in mine:
            verified = "postcondition current after dwell" if e.get("outcome") == "completed" else None
            settled = iso(e["settled_at_unix_ms"] / 1000) if e.get("settled_at_unix_ms") else None
            new, changed = store.attempt(inc_id, e["episode"], {"opened_at": iso(e["opened_at_unix_ms"] / 1000) if e.get("opened_at_unix_ms") else None,
                                         "settled_at": settled, "outcome": e.get("outcome"), "phase": e.get("phase"),
                                         "verified": verified, "plan": os.path.basename(e.get("plan") or "")})
            if new or changed:
                store.event(inc_id, at, "remediation", {"episode": e["episode"][:19], "outcome": e.get("outcome") or "in flight",
                            "phase": e.get("phase"), "plan": os.path.basename(e.get("plan") or ""), "verified": verified})
        in_flight = any(not e.get("outcome") for e in mine)
        latest = max(mine, key=lambda e: e.get("opened_at_unix_ms") or 0) if mine else None
        failed = [latest] if latest and latest.get("outcome") in FAILED_OUTCOMES else []
        verified_fix = bool(latest and latest.get("outcome") == "completed")
        # after a verified remediation the evaluator decides: only a page sent after it settled means "still broken"
        paged_after = verified_fix and any(
            json.loads(e["detail"]).get("role") == "page" and e["at"] >= iso((latest.get("settled_at_unix_ms") or 0) / 1000)
            for e in store.events(inc_id) if e["kind"] == "notified")
        # what the evaluator says now
        if c is None:
            if live["state"] == "recovering":
                pass   # the evaluator forgets a condition it resolved as recovered; the confirmation clock keeps running
            elif live["last_observation"] != "unreported":
                store.update(inc_id, last_observation="unreported")
                store.event(inc_id, at, "unobserved", {"note": "the condition is no longer reported; recovery not observed, incident stays open"})
        elif c.get("suspended"):
            s = c["suspended"]
            store.event(inc_id, at, "suspended", {"owner": s.get("owner"), "reason": s.get("reason"), "resume_when": s.get("resume_when")},
                        dedup="suspended:%s:%s:%s" % (inc_id, s.get("owner"), s.get("since")))
        elif c.get("observation") == "removed":
            store.event(inc_id, at, "unobserved", {"note": "definition no longer evaluated (retired or disabled); recovery not observed, incident stays open"},
                        dedup="removed:%s" % inc_id)
        elif not c.get("active") and c.get("observation") == "clear" and live["state"] in ("open", "acknowledged"):
            store.update(inc_id, state="recovering", recovering_since=at, last_observation="clear")
            store.event(inc_id, at, "recovering", {"note": "evaluator resolved the condition as recovered; confirming for %d s" % CONFIRM_SECONDS})
        live = store.current(key)
        # closure: substantiated recovery only
        if live["state"] == "recovering" and not in_flight and now - (parse_ts(live["recovering_since"]) or now) >= CONFIRM_SECONDS:
            store.update(inc_id, state="resolved", resolved_at=at, needs_operator=None,
                         resolution="verified recovery: clear for %d s after the evaluator's own confirmation" % CONFIRM_SECONDS)
            store.event(inc_id, at, "resolved", {"verified": True, "by": "constellation"})
            continue
        # what still needs the operator
        rule = (rules.get(live["rule"]) or {})
        policy = rule.get("response_policy")
        if live["state"] == "resolved":
            continue
        if failed:
            need = "remediation failed (%s): %s" % (failed[-1].get("outcome"), needs_text(live["rule"], rules, policy))
        elif in_flight:
            need = None
        elif verified_fix and not paged_after:
            need = None   # remediated and verified; waiting for the evaluator's recovery confirmation
        elif c is not None and c.get("suspended"):
            need = "suspended by %s until: %s" % (c["suspended"].get("owner"), c["suspended"].get("resume_when"))
        elif live["state"] == "recovering":
            need = None
        elif policy == "auto_remediate_then_page" and not mine and c is not None and (c.get("remediation_window_until") or 0) > now:
            need = None   # inside the remediation window, nothing attempted yet; past it, the operator is needed
        else:
            need = needs_text(live["rule"], rules, policy)
        if (live.get("needs_operator") or None) != need:
            store.update(inc_id, needs_operator=need)
            if need:
                store.event(inc_id, at, "needs-operator", {"action": need})


def attach_late_notifications(store, intent_log, at):
    """A resolve is usually logged after the incident has gone to recovering or resolved: attach it to the newest
    incident for its condition, deduplicated by event id."""
    for li in intent_log:
        key, ev = li.get("condition_id"), li.get("stable_event_id")
        if not key or not ev:
            continue
        cur = store.current(key)
        if cur and (li.get("at") or "") >= cur["opened_at"]:
            store.event(cur["id"], li.get("at") or at, "notified", {"route": li.get("route"), "role": li.get("route_role"),
                        "action": li.get("action"), "outcome": li.get("outcome"), "event": ev},
                        dedup="notified:%s:%s" % (ev, li.get("outcome")))


def read_intent_log(path, keep_seconds, now):
    out = []
    for p in (path + ".1", path):
        try:
            with open(p) as fh:
                for line in fh:
                    try:
                        d = json.loads(line)
                    except ValueError:
                        continue
                    if (parse_ts(d.get("at")) or 0) >= now - keep_seconds:
                        out.append(d)
        except FileNotFoundError:
            continue
    return out


# ------------------------------------------------------------------ operator views
def summary_line(store, inc):
    atts = store.attempts(inc["id"])
    tried = ", ".join("%s %s" % (a["plan"] or "remediation", a["outcome"] or "in flight") for a in atts) or "nothing"
    return tried


def list_view(store, include_recent=True, now=None):
    now = now or time.time()
    meta = store.meta()
    out = []
    age = now - (parse_ts(meta.get("last_sync_at")) or 0)
    out.append("constellation-incidents  (last sync %s, %s)%s" % (meta.get("last_sync_at", "never"),
               "ok" if meta.get("last_sync_ok") == "1" else "FAILED: " + meta.get("last_sync_note", ""),
               "  WARNING: sync is %d s old; this view may be stale" % age if age > 300 else ""))
    open_ = store.incidents(unresolved_only=True)
    since = lambda i: i.get("first_seen") or i["opened_at"]
    suspended = [i for i in open_ if (i.get("needs_operator") or "").startswith("suspended by ")]
    needs = [i for i in open_ if i.get("needs_operator") and i not in suspended]
    out.append("")
    out.append("NEEDS YOU (%d)" % len(needs))
    for i in needs:
        out.append("  %-14s %-34s failing since %s  [%s]" % (i["id"], "%s %s" % (i["rule"], i["subject"]), since(i), i["state"]))
        out.append("      do: %s" % i["needs_operator"])
        out.append("      tried: %s" % summary_line(store, i))
    out.append("")
    out.append("SUSPENDED BY DECISION, STILL OPEN (%d)" % len(suspended))
    for i in suspended:
        out.append("  %-14s %-34s failing since %s  (%s)" % (i["id"], "%s %s" % (i["rule"], i["subject"]), since(i), i["needs_operator"]))
    others = [i for i in open_ if not i.get("needs_operator")]
    out.append("")
    out.append("OPEN, NOTHING NEEDED FROM YOU NOW (%d)" % len(others))
    for i in others:
        why = {"recovering": "recovering; confirming", "acknowledged": "acknowledged by %s" % i.get("ack_by")}.get(i["state"], "remediation or confirmation in progress")
        out.append("  %-14s %-34s failing since %s  (%s; tried: %s)" % (i["id"], "%s %s" % (i["rule"], i["subject"]), since(i), why, summary_line(store, i)))
    if include_recent:
        cutoff = iso(now - 86400)
        recent = [i for i in store.incidents(unresolved_only=False) if i["state"] == "resolved" and (i["resolved_at"] or "") >= cutoff]
        out.append("")
        out.append("RESOLVED IN THE LAST 24 H (%d)" % len(recent))
        for i in recent:
            out.append("  %-14s %-34s %s -> %s  (tried: %s; %s)" % (i["id"], "%s %s" % (i["rule"], i["subject"]), i["opened_at"], i["resolved_at"],
                       summary_line(store, i), i["resolution"]))
    return "\n".join(out)


def find(store, ref):
    for i in sorted(store.incidents(unresolved_only=False), key=lambda i: i["opened_at"], reverse=True):
        if ref in (i["id"], i["key"]) or i["id"].startswith(ref + "-") or i["id"] == ref:
            return i
    return None


def show_view(store, ref):
    i = find(store, ref)
    if not i:
        return "no incident %s" % ref
    out = ["%s  %s  [%s]" % (i["id"], i["key"], i["state"]),
           "opened %s; last observed %s (%s)%s" % (i["opened_at"], i["last_observed_at"], i["last_observation"],
                                                 "; resolved %s: %s" % (i["resolved_at"], i["resolution"]) if i["resolved_at"] else ""),
           "needs you: %s" % (i["needs_operator"] or "nothing now")]
    out.append("attempts:")
    for a in store.attempts(i["id"]) or []:
        out.append("  %s %-26s outcome=%-16s verified=%s" % (a["opened_at"], a["plan"] or a["episode"][:19], a["outcome"] or "in flight", a["verified"] or "no"))
    if not store.attempts(i["id"]):
        out.append("  none")
    out.append("timeline:")
    for e in store.events(i["id"]):
        d = json.loads(e["detail"])
        out.append("  %s  %-14s %s" % (e["at"], e["kind"], ", ".join("%s=%s" % (k, v) for k, v in d.items() if v not in (None, ""))))
    return "\n".join(out)


def write_metrics(store, path, now):
    open_ = store.incidents(unresolved_only=True)
    led = {}
    for i in store.incidents(unresolved_only=False):
        r = led.setdefault(i["rule"], {"incidents": 0, "remediated": 0, "remediation_verified": 0, "needed_operator": 0, "resolved_verified": 0})
        r["incidents"] += 1
        atts = store.attempts(i["id"])
        r["remediated"] += 1 if atts else 0
        r["remediation_verified"] += 1 if any(a.get("verified") for a in atts) else 0
        kinds = [e["kind"] for e in store.events(i["id"])]
        r["needed_operator"] += 1 if "needs-operator" in kinds else 0
        r["resolved_verified"] += 1 if i["state"] == "resolved" and (i.get("resolution") or "").startswith("verified recovery") else 0
    lines = ["# TYPE constellation_incidents_open gauge", "constellation_incidents_open %d" % len(open_),
             "# TYPE constellation_incidents_needs_operator gauge", "constellation_incidents_needs_operator %d" % sum(1 for i in open_ if i.get("needs_operator")),
             "# TYPE constellation_incidents_last_sync_timestamp_seconds gauge", "constellation_incidents_last_sync_timestamp_seconds %d" % int(now),
             "# HELP constellation_incidents_by_rule Retained incidents per rule (30 d) and what they led to: remediated, remediation verified, needed the operator, resolved by verified recovery.",
             "# TYPE constellation_incidents_by_rule gauge"]
    for rule, counts in sorted(led.items()):
        for outcome, n in counts.items():
            lines.append('constellation_incidents_by_rule{rule="%s",outcome="%s"} %d' % (rule, outcome, n))
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".incidents-")
    with os.fdopen(fd, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    os.chmod(tmp, 0o644); os.replace(tmp, path)


def load(path):
    with open(path) as fh:
        return json.load(fh)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="constellation-incidents", description=__doc__.split("\n\n")[0])
    ap.add_argument("--db", default="/var/lib/constellation-incidents/incidents.sqlite")
    sub = ap.add_subparsers(dest="cmd")
    s = sub.add_parser("sync")
    s.add_argument("--report", default="/var/lib/constellation-attention/report.json")
    s.add_argument("--state", default="/var/lib/constellation-attention/state.json")
    s.add_argument("--consumer", default="/var/lib/constellation-remediation/consumer/state.json")
    s.add_argument("--intent-log", default="/var/lib/constellation-attention/intents.jsonl")
    s.add_argument("--rules", default="/usr/bin/constellation-attention")
    s.add_argument("--metrics", default="/var/lib/prometheus/node-exporter/constellation-incidents.prom")
    sub.add_parser("list")
    sh = sub.add_parser("show"); sh.add_argument("ref")
    ak = sub.add_parser("ack"); ak.add_argument("ref"); ak.add_argument("--by", required=True); ak.add_argument("--note", default="")
    nt = sub.add_parser("note"); nt.add_argument("ref"); nt.add_argument("--by", required=True); nt.add_argument("text")
    rs = sub.add_parser("resolve"); rs.add_argument("ref"); rs.add_argument("--by", required=True); rs.add_argument("--note", required=True)
    a = ap.parse_args(argv)
    cmd = a.cmd or "list"
    try:
        if cmd in ("list", "show"):
            store = SqliteStore(a.db, readonly=True)
            print(list_view(store) if cmd == "list" else show_view(store, a.ref))
            return 0
        store = SqliteStore(a.db)
        now = time.time()
        if cmd == "sync":
            try:
                rules = {r["id"]: r for r in json.loads(subprocess.run([a.rules, "rules"], capture_output=True, check=True, timeout=30).stdout)["rules"]}
                report = load(a.report)
                state = load(a.state)
                consumer = load(a.consumer) if os.path.exists(a.consumer) else None
                intent_log = read_intent_log(a.intent_log, 2 * 86400, now)
                with store.transaction():
                    sync(store, report, state, consumer, rules, now, intent_log)
                    attach_late_notifications(store, intent_log, iso(now))
                    store.prune(now)
                    store.heartbeat(iso(now), True, "report %s" % report.get("evaluated_at"))
            except StoreUnavailable:
                raise
            except Exception as e:  # noqa: BLE001 - inputs unreadable: record the failure, claim nothing
                store.heartbeat(iso(now), False, "%s: %s" % (type(e).__name__, str(e)[:300]))
                print("sync failed: %s" % e, file=sys.stderr)
                return 1
            try:
                write_metrics(store, a.metrics, now)
            except OSError as e:
                print("metrics not written: %s" % e, file=sys.stderr)
            return 0
        inc = find(store, a.ref)
        if not inc:
            print("no incident %s" % a.ref, file=sys.stderr); return 2
        at = iso()
        with store.transaction():
            if cmd == "ack":
                store.update(inc["id"], state="acknowledged" if inc["state"] == "open" else inc["state"], ack_by=a.by, ack_note=a.note)
                store.event(inc["id"], at, "acknowledged", {"by": a.by, "note": a.note})
            elif cmd == "note":
                store.event(inc["id"], at, "note", {"by": a.by, "text": a.text})
            elif cmd == "resolve":
                if inc["state"] == "resolved":
                    print("already resolved", file=sys.stderr); return 2
                store.update(inc["id"], state="resolved", resolved_at=at, needs_operator=None,
                             resolution="closed by operator %s (recovery not verified by Constellation): %s" % (a.by, a.note))
                store.event(inc["id"], at, "resolved", {"verified": False, "by": a.by, "note": a.note})
        print(show_view(store, inc["id"]))
        return 0
    except StoreUnavailable as e:
        print("incident store unavailable: %s (nothing was written or claimed)" % e, file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
