#!/usr/bin/env python3
"""constellation-incidents: incident continuity for one site (cartography #93).

An alert says something happened; an incident says something still needs dealing with. This tool keeps one durable
incident per supervised subject + failure condition, independent of the processes that detect and remediate:

  sync    read the attention evaluator's report/state and the remediation consumer's episodes; open, continue,
          annotate and close incidents (idempotent; run every minute by a timer)
  list    THE operator query: what is broken, what was tried, what worked, what failed, what still needs you
  show    one incident's full timeline (id like inc-1a2b3c4d or inc-1a2b3c4d-2, or a condition key)
  ack / note / resolve   operator actions, recorded as such
  export / import        handover of unresolved incidents to a replacement host (below)

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

Replacement (cartography #94): a rebuilt host starts with an empty store, so unresolved obligations would vanish.
`export` writes the unresolved incidents (timeline and attempts) to a handover file kept off the host; `import` on
the replacement restores each one under its own id (ids derive from the condition key, so they match the new host's
notices) with an `inherited` event naming the predecessor. Nothing is claimed that this host did not observe: an
incident that was recovering is reopened (recovery was not seen here), and from then on the ordinary rules apply:
it closes only after this host's evaluator resolves the condition and it stays clear, and a condition this host never
reports keeps it open for the operator. An unresolved incident already present for the same key is left alone.
"""
import argparse, datetime, hashlib, json, os, re, sqlite3, subprocess, sys, tempfile, time

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


def next_incident_id(key, existing):
    """Episodes of one condition: inc-<hash>, then -2, -3, ... past the highest present. Not a count: adopted
    incidents (cartography #94) and pruning both make the count disagree with the suffixes in use."""
    base = "inc-%s" % key_hash(key)
    used = [1 if i == base else int(i[len(base) + 1:]) for i in existing
            if i == base or (i.startswith(base + "-") and i[len(base) + 1:].isdigit())]
    return base if not used else "%s-%d" % (base, max(used) + 1)


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
    def adopt(self, row): raise NotImplementedError             # insert an incident under its existing id


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
        inc = next_incident_id(key, [r[0] for r in self._x("SELECT id FROM incident WHERE id LIKE ?", ("inc-%s%%" % key_hash(key),))])
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

    def adopt(self, row):
        cols = ("id", "key", "rule", "subject", "state", "opened_at", "first_seen", "last_observed_at", "last_observation",
                "recovering_since", "resolved_at", "resolution", "needs_operator", "ack_by", "ack_note", "severity")
        self._x("INSERT INTO incident(%s) VALUES (%s)" % (",".join(cols), ",".join("?" * len(cols))), tuple(row.get(c) for c in cols))

    def prune(self, now):
        cutoff = iso(now - RETAIN_DAYS * 86400)
        old = [r[0] for r in self._x("SELECT id FROM incident WHERE state='resolved' AND resolved_at < ?", (cutoff,))]
        for inc in old:
            self._x("DELETE FROM event WHERE incident=?", (inc,)); self._x("DELETE FROM attempt WHERE incident=?", (inc,))
            self._x("DELETE FROM incident WHERE id=?", (inc,))
        for (inc,) in self._x("SELECT incident FROM event GROUP BY incident HAVING COUNT(*) > ?", (MAX_EVENTS,)).fetchall():
            self._x("DELETE FROM event WHERE incident=? AND seq NOT IN (SELECT seq FROM event WHERE incident=? ORDER BY seq DESC LIMIT ?)",
                    (inc, inc, MAX_EVENTS))


# ------------------------------------------------------------------ handover to a replacement host (backend-independent)
HANDOVER = "constellation.incidents.handover/v1"


def export_unresolved(store, host, now):
    out = []
    for i in store.incidents(unresolved_only=True):
        out.append({"incident": i, "events": store.events(i["id"]), "attempts": store.attempts(i["id"])})
    return {"schema": HANDOVER, "exported_at": iso(now), "host": host, "incidents": out}


def import_unresolved(store, doc, host, now):
    """Returns (adopted ids, skipped [(id, why)])."""
    if doc.get("schema") != HANDOVER:
        raise ValueError("not a %s document" % HANDOVER)
    at, adopted, skipped = iso(now), [], []
    for item in doc["incidents"]:
        i = dict(item["incident"])
        cur = store.current(i["key"])
        if cur and cur["state"] != "resolved":
            skipped.append((i["id"], "an unresolved incident for this condition already exists here (%s)" % cur["id"])); continue
        if any(x["id"] == i["id"] for x in store.incidents(unresolved_only=False)):
            skipped.append((i["id"], "this id is already in the store")); continue
        was = i["state"]
        if was == "recovering":
            i.update(state="open", recovering_since=None)
        i["last_observation"] = "inherited"
        prior = i.get("needs_operator")
        if (prior or "").startswith("suspended by "):
            # a suspension is the operator's decision, not a fact of the old host: it carries over as a suspension
            i["needs_operator"] = "%s (inherited from %s)" % (prior, doc.get("host"))
        else:
            i["needs_operator"] = "inherited from %s: %s" % (doc.get("host"), prior or "confirm the condition on the replacement host")
        store.adopt(i)
        for e in item.get("events", []):
            store.event(i["id"], e["at"], e["kind"], json.loads(e["detail"]) if isinstance(e["detail"], str) else e["detail"],
                        dedup="inherited:%s:%s:%s:%s" % (i["id"], e["at"], e["kind"], hashlib.sha256(str(e["detail"]).encode()).hexdigest()[:12]))
        for a in item.get("attempts", []):
            store.attempt(i["id"], a["episode"], a)
        store.event(i["id"], at, "inherited", {"from": doc.get("host"), "to": host, "exported_at": doc.get("exported_at"),
                    "state_there": was, "note": "carried across host replacement; recovery on this host is observed afresh"},
                    dedup="inherited:%s:%s" % (i["id"], doc.get("exported_at")))
        adopted.append(i["id"])
    return adopted, skipped


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
            revision = e.get("rule_revision")
            if isinstance(revision, dict) and revision.get("rule") == live["rule"]:
                store.event(inc_id, at, "remediation-definition", {"episode": e["episode"], "rule_revision": revision},
                            dedup="remediation-definition:%s:%s" % (inc_id, e["episode"]))
            verified = "postcondition current after dwell" if e.get("outcome") == "completed" else None
            settled = iso(e["settled_at_unix_ms"] / 1000) if e.get("settled_at_unix_ms") else None
            new, changed = store.attempt(inc_id, e["episode"], {"opened_at": iso(e["opened_at_unix_ms"] / 1000) if e.get("opened_at_unix_ms") else None,
                                         "settled_at": settled, "outcome": e.get("outcome"), "phase": e.get("phase"),
                                         "verified": verified, "plan": os.path.basename(e.get("plan") or "")})
            if new or changed:
                detail = {"episode": e["episode"][:19], "outcome": e.get("outcome") or "in flight",
                          "phase": e.get("phase"), "plan": os.path.basename(e.get("plan") or ""), "verified": verified}
                store.event(inc_id, at, "remediation", detail)
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


CONSUMER_SEALED = re.compile(r"^journal\.sealed\.([0-9]+)\.jsonl$")


def _consumer_journal_tails(directory, journal_limit):
    """Complete lines from the tail of the live consumer journal and, while the
    shared byte budget lasts, of its newest sealed generations
    (journal.sealed.NNNN.jsonl, newest first). Unreadable files are skipped."""
    paths = [os.path.join(directory, "journal.jsonl")]
    try:
        sealed = [(int(m.group(1)), name) for name in os.listdir(directory) for m in [CONSUMER_SEALED.match(name)] if m]
    except OSError:
        sealed = []
    paths += [os.path.join(directory, name) for _, name in sorted(sealed, reverse=True)]
    budget = journal_limit
    for p in paths:
        if budget <= 0:
            break
        try:
            with open(p, "rb") as stream:
                size = os.fstat(stream.fileno()).st_size
                offset = max(0, size - budget)
                stream.seek(offset)
                data = stream.read(budget)
        except OSError:
            continue
        budget -= len(data)
        lines = data.splitlines(keepends=True)
        if offset and lines:
            lines = lines[1:]
        yield lines


def read_consumer(path, journal_limit=16 * 1024 * 1024):
    """Read state and bounded opening provenance without changing either.

    Definition metadata stays in the existing journal, so older consumers can
    still read their unchanged strict state schema after a software rollback.
    Missing, truncated, invalid or conflicting provenance remains unknown.
    """
    consumer = load(path)
    episodes = list(consumer.get("closed", [])) + ([consumer["active"]] if consumer.get("active") else [])
    wanted = {e["episode"]: e for e in episodes}
    revisions = {}
    for lines in _consumer_journal_tails(os.path.dirname(path), journal_limit):
        for line in lines:
            if not line.endswith(b"\n"):
                continue
            try:
                record = json.loads(line)
                if not isinstance(record, dict):
                    continue
                eid = record.get("episode")
                episode = wanted.get(eid)
                if not episode or record.get("schema") != "constellation.remediation-consumer.journal/v1" or record.get("event") != "episode_opened":
                    continue
                detail = record["detail"]
                if not isinstance(detail, dict):
                    continue
                revision = detail.get("rule_revision")
                if (detail.get("episode") != eid or detail.get("condition_id") != episode["condition_id"] or
                        detail.get("first_seen") != episode["first_seen"]):
                    continue
                if not isinstance(revision, dict) or set(revision) != {"rule", "version", "attention_policy_digest"}:
                    continue
                digest = revision["attention_policy_digest"]
                if (not isinstance(revision["version"], int) or isinstance(revision["version"], bool) or
                        not 0 < revision["version"] <= 0xffffffff or revision["rule"] != episode["condition_id"].split(":")[3] or
                        not isinstance(digest, str) or len(digest) != 71 or not digest.startswith("sha256:") or
                        any(c not in "0123456789abcdef" for c in digest[7:])):
                    continue
                if eid in revisions and revisions[eid] != revision:
                    revisions[eid] = None
                else:
                    revisions[eid] = revision
            except (ValueError, KeyError, TypeError, IndexError):
                continue
    for eid, revision in revisions.items():
        if revision is not None:
            wanted[eid]["rule_revision"] = revision
    return consumer


# ------------------------------------------------------------------ bounded read-only machine inspection (cartography #102)
INSPECTION = "constellation.incidents.inspection/v1"
INSPECTION_MAX_BYTES = 16 * 1024 * 1024
INSPECTION_MISSING = ["response_actor", "assignment", "authority_decision", "proposal_state", "dispatch_queue",
                      "next_checkpoint", "service_health", "observation_acquired_at", "last_successful_sync_at",
                      "detection_count", "unpersisted_detections"]


def inspection(store, now, ref=None, source=None):
    """An inspection, never a new lifecycle. Exact retained rows, no synthesized authority or health.
    Call under a backend-consistent read transaction. A bounded refusal is not an empty success.
    """
    meta = store.meta()
    if meta.get("schema") != SCHEMA:
        raise ValueError("unsupported incident store schema")
    rows = store.incidents(unresolved_only=False)
    if ref is not None:
        rows = [i for i in rows if i["id"] == ref]
        if not rows:
            raise ValueError("incident not retained: %s" % ref)
    else:
        rows = [i for i in rows if i["state"] != "resolved" or
                (parse_ts(i.get("resolved_at")) or 0) >= now - 86400]
    if len(rows) > 1000:
        raise ValueError("inspection exceeds 1000 incidents; no partial result returned")
    doc = {"schema": INSPECTION, "read_at": iso(now), "source": source or {"kind": "incident-store/v1"},
           "meta": meta, "missing_fields": INSPECTION_MISSING,
           "scope": {"resolved_window_seconds": 86400 if ref is None else None,
                     "history": "source-retained append order; normally at most 300 events per incident"},
           "incidents": [{"incident": i, "events": store.events(i["id"]), "attempts": store.attempts(i["id"])} for i in rows]}
    return doc


def inspect_readonly(path, now, ref=None):
    from urllib.parse import quote
    # URI-escape names so ?/#/% in an operator-configured path cannot change read mode.
    store = SqliteStore(quote(os.path.abspath(path), safe="/"), readonly=True)
    try:
        store._x("PRAGMA query_only=ON")
        store._x("BEGIN")
        return inspection(store, now, ref, {"kind": "incident-store/v1", "locator": os.path.abspath(path),
                          "implementation_sha256": hashlib.sha256(open(__file__, "rb").read()).hexdigest()})
    finally:
        store.db.close()


def inspect_handover(path, now, ref=None):
    """Inspect an existing off-host export without importing or asserting current host state."""
    with open(path, "rb") as source:
        raw = source.read(INSPECTION_MAX_BYTES + 1)
    if len(raw) > INSPECTION_MAX_BYTES:
        raise ValueError("handover exceeds 16 MiB")
    doc = json.loads(raw)
    if doc.get("schema") != HANDOVER or not isinstance(doc.get("incidents"), list):
        raise ValueError("unsupported handover schema")
    entries = doc["incidents"]
    if ref is not None:
        entries = [e for e in entries if e["incident"]["id"] == ref]
        if not entries:
            raise ValueError("incident not in handover: %s" % ref)
    if len(entries) > 1000:
        raise ValueError("handover exceeds 1000 incidents")
    return {"schema": INSPECTION, "read_at": iso(now), "meta": {}, "incidents": entries,
            "missing_fields": INSPECTION_MISSING + ["sync_health", "recently_resolved"],
            "source": {"kind": "off-host-handover/v1", "locator": os.path.abspath(path),
                       "host": doc.get("host"), "exported_at": doc.get("exported_at"),
                       "implementation_sha256": hashlib.sha256(open(__file__, "rb").read()).hexdigest()},
            "scope": {"resolved_window_seconds": None, "history": "retained unresolved export only; current state unknown"}}


def inspection_json(doc):
    raw = json.dumps(doc, sort_keys=True)
    if len(raw.encode()) > INSPECTION_MAX_BYTES:
        raise ValueError("inspection exceeds 16 MiB; no partial result returned")
    return raw


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
            out.append("  %-14s %-34s %s -> %s  (tried: %s; %s)" % (i["id"], "%s %s" % (i["rule"], i["subject"]), since(i), i["resolved_at"],
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
    ins = sub.add_parser("inspect", help="bounded read-only JSON inspection (incident v1 rows and histories)")
    ins.add_argument("--handover", help="inspect an existing off-host export without importing it; no current health claim")
    ins.add_argument("--id", help="exact retained incident id; default includes open and last-24h resolved")
    sh = sub.add_parser("show"); sh.add_argument("ref")
    ak = sub.add_parser("ack"); ak.add_argument("ref"); ak.add_argument("--by", required=True); ak.add_argument("--note", default="")
    nt = sub.add_parser("note"); nt.add_argument("ref"); nt.add_argument("--by", required=True); nt.add_argument("text")
    rs = sub.add_parser("resolve"); rs.add_argument("ref"); rs.add_argument("--by", required=True); rs.add_argument("--note", required=True)
    ex = sub.add_parser("export"); ex.add_argument("--out", default="-")
    im = sub.add_parser("import"); im.add_argument("file")
    a = ap.parse_args(argv)
    cmd = a.cmd or "list"
    try:
        if cmd == "inspect":
            try:
                doc = inspect_handover(a.handover, time.time(), a.id) if a.handover else inspect_readonly(a.db, time.time(), a.id)
                print(inspection_json(doc))
                return 0
            except (ValueError, KeyError, TypeError, OSError, sqlite3.Error) as e:
                print("incident inspection refused: %s (no result claimed)" % e, file=sys.stderr)
                return 3
        host = open("/etc/machine-id").read().strip() if os.path.exists("/etc/machine-id") else "unknown"
        if cmd == "export":
            doc = json.dumps(export_unresolved(SqliteStore(a.db, readonly=True), host, time.time()), indent=1, sort_keys=True)
            if a.out == "-":
                print(doc)
            else:
                with open(a.out, "w") as fh:
                    fh.write(doc + "\n")
            return 0
        if cmd == "import":
            # seeding a new host's store is import's purpose: it may run before the first sync made the state directory
            os.makedirs(os.path.dirname(a.db), mode=0o755, exist_ok=True)
            store = SqliteStore(a.db)
            with store.transaction():
                adopted, skipped = import_unresolved(store, load(a.file), host, time.time())
            for iid in adopted:
                print("adopted %s" % iid)
            for iid, why in skipped:
                print("skipped %s: %s" % (iid, why))
            return 0
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
                consumer = read_consumer(a.consumer) if os.path.exists(a.consumer) else None
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
