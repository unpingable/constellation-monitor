# constellation-remediation packaging

Bounded Autonomous Remediation v1 (cartography
`architecture/bounded-autonomous-remediation.md`): one condition
(`service-down` of one enrolled unit), one fix (one governed systemd Start of
exactly that unit), decided deterministically. The package carries:

| File | Installed as |
|---|---|
| `constellation-remediation-consumer` | `/usr/bin/` |
| `constellation-nq-unit-resolver` (AG typed-v3 observation resolver over NQ ops-store `nq.systemd_unit` v2 evaluations; `--claim not-active` precondition, `--claim active` postcondition) | `/usr/bin/` |
| `nq-ops-as-nq` (runs `nq` as `nq` in nqd's sandbox over `/var/lib/nq-ops`; used for `nq collect`) | `/usr/libexec/constellation-remediation/` |
| `constellation-remediation-consumer.{service,timer}` | `/lib/systemd/system/` |
| `consumer.toml.example` | `/etc/constellation-remediation/` (conffile) |
| `model-decider.conf` (systemd drop-in example for `--decider model`) | `/usr/share/doc/constellation-remediation/` |

Installation is inert: no configuration, AG profile, catalog, plans, keys,
Docket trust or grant, and the timer is neither enabled nor started.

## Executable identity

Both packaged binaries accept `--build-info`, `--version` and `-V` as a sole
argument before configuration, stdin, state, external commands or any provider
access. `--version` includes the declared source commit. `--build-info` emits
`constellation.remediation.build_info.v1` JSON with version, source commit, build
identity, compiler version, target triple and debug-assertion flag. Missing
development declarations stay JSON null; they are not inferred from Git state.

Export `MONITOR_SOURCE_COMMIT` as the full lowercase 40-digit commit and
`MONITOR_BUILD_IDENTITY` as a unique build label (1..256 printable ASCII bytes
without spaces) during compilation and package assembly. Malformed nonempty
declarations fail compilation. The builder must verify the source export,
lockfile and toolchain correspond to those declarations; reporting does not
independently attest them.

Assembly probes the staged copies of both executables and refuses missing or
mixed source/build identity, inconsistent compiler/target/profile, an unexpected
component/schema or a package version that does not extend the crate version.
The receipt contains the metadata and exact staged SHA-256 hashes, embedded at
`/usr/share/doc/constellation-remediation/build-identity.json` and copied beside
the `.deb` as `.build-identity.json`. Compare both binaries' probes and hashes
with that receipt and the package checksum when inspecting installed bytes.
This AG-independent reporting format grants no authority and changes no
remediation or observation semantics.

Run the package correspondence/refusal fixtures with
`python3 -B -m unittest discover -s packaging/remediation -p test_build_identity.py`.

## Definition revision at episode opening

The existing `episode_opened` journal detail includes `rule_revision` when the
opening evaluator report supplies one unambiguous effective rule version and
a valid policy digest. This is provenance, not an execution prerequisite or
authority input. Missing, malformed and ambiguous provenance is recorded as
unknown and does not change any existing admission decision.

The record binds the rule and effective policy at opening, not the original
detection or a later resume. Resume never rewrites it from a newer report.
The strict consumer state schema is unchanged, so previous consumers can still
read it after rollback; the existing append-only journal retains the metadata.
Incident sync reads at most 16 MiB in total: the tail of the live journal, then
the tails of the newest sealed generations (see Journal capacity) while that
bound lasts. It associates only
matching full episode, condition and first-seen identities. A missing, truncated,
invalid, conflicting or older opening record leaves provenance unknown. Known
bindings are copied once into `remediation-definition` timeline events,
including when the opening record becomes readable after the attempt.
No attempt identity, result, authority, recovery or closure rule changes.

Formalization consideration: tests cover changed reports across restart,
legacy state, optional/malformed provenance, unchanged effect admission and
deduplicated late timeline association. Tests and the shared revision vector
are sufficient for this metadata change. They do not establish portable sync
atomicity, history-safe lost-ack reconciliation or exactly-once effects;
#93's future Store work and current SQLite transaction assumptions remain.

## Journal capacity

Each consumer journal generation has a 64 MiB (67,108,864-byte) application
ceiling. `--check-config` reports `journal_max_bytes`, `journal_max_sealed`
(16) and `journal_sealed_present` (sealed segments now in the state directory,
or null when it cannot be read) without creating, locking or opening state.
These are limits and a count, not a journal-usage or service-health claim.

A full journal is sealed, not truncated. The Store seals before writing a
record in three cases: at open, when less than 1 MiB (1/64 of the bound)
remains, which includes a journal at exactly or over 64 MiB; at open, when the
live journal is still the same inode as a sealed segment (an interrupted seal,
whatever its size); and mid-pass, when the next record would carry a journal
that is at least half full over the bound. A record that would not fit in a
journal under half full is refused, not sealed.

Sealing hard-links `journal.jsonl` as `journal.sealed.NNNN.jsonl` (zero-padded
sequence, 0001 first) and fsyncs the directory, atomically writes the sidecar
`journal.sealed.NNNN.json` (byte length, SHA-256, newline-terminated record
count, torn-tail bytes, first and last `at`, sealing pass, time and trigger),
then writes and fsyncs the successor journal under a temporary name, renames it
over `journal.jsonl` and fsyncs the directory. The successor's first record is
`journal_sealed` carrying the same fields plus `predecessor`, and the pass keeps
appending through the handle it opened on that file, so no record can reach the
sealed inode. Every intermediate state leaves a complete `journal.jsonl`. If a
crash or power loss leaves the live journal linked to a segment (after the link,
or because an unsynced rename was lost), the next open detects the shared inode
and finishes that seal under the same sequence with trigger `resume` before any
append. A sealed name that already exists and is not the live journal's own
regular-file inode (for example a symlink) is never reused; a name that would
need a sequence past the largest one is refused. Any failed seal refuses that
append and every later one in the pass. The chain is replayable backwards from
the live file: each generation's first record names and digests its
predecessor. Sequences stay monotonic after segments are moved away, because the
live journal's first record names its predecessor's sequence. Sealing reads only
the journal: it does not read or write `state.json` or `episodes/`, so pending
obligations (the active episode and its dispatch fence), completed outcomes,
authorization history and the replay fence are exactly what they were. The
consumer itself never reads the journal back.

At most 16 sealed generations are kept beside the live one, about 1.06 GiB in
all. At the 2026-10 cadence, when every idle pass journaled three records
(about 8.2 MB a day), that was roughly four months of history; idle passes no
longer journal (see Journal contract), so the rate now depends on how many
passes are not idle. When 16 are present and a seal is
due at open, the pass is refused at open, before any external command, with
`journal capacity exhausted ... sealed journal generations exhausted ...
history preserved, operator custody required`, leaving the journal, state,
episode IDs, dispatch fences and directory listing unchanged. If the bound is
reached by a mid-pass seal instead, that append and the rest of the pass are
refused, as an append crossing the bound was before this change. The consumer
exits 2 through its existing store-fault path, and the estate supervision of
failed passes remains the operator route. A full journal is not healthy and
does not authorize a retry. Read-only incident inspection and AG/Docket
inspection remain available.

Deploying this release against a full journal seals it on the first pass:
a 67,108,673-byte journal (about 190 bytes short of the bound, less than the
1 MiB open headroom) becomes `journal.sealed.0001.jsonl` with its sidecar, a
new `journal.jsonl` starts with `journal_sealed`, and the pass then proceeds
from the unchanged `state.json` as an ordinary pass.

This bounds the journal only, not per-episode inputs or AG, Docket and NQ stores.

Formalization consideration (Monitor private-history #6 / finding 94-22;
implementation Codex, owner unpingable): while cooperating writers hold the
existing exclusive Store lock, admitted appends satisfy
`used + encoded_record_bytes <= journal_max_bytes` within each generation, and
at most `journal_max_sealed` sealed generations are present before refusal.
Tests cover sealing on append and at open (byte-identical segments, sidecar and
first-record digests, unchanged state and fence), an interrupted seal resuming
under its own name (including below the open headroom, without growing the
segment), a symlinked segment name never standing in for the journal, sequence
space exhaustion and refusal after a failed seal, sequence continuity after segments are moved away, a
production-shaped 67,108,673-byte journal sealing on an idle pass, a full
journal with a dispatch fence sealing and then never dispatching again, refusal
at the generation bound before every external call with nothing renamed, and
configuration inspection without state creation. Practical tests and checked
arithmetic suffice for this bounded change. This does not establish atomic
writes under arbitrary I/O failure, exclusion of uncooperating writers,
automatic retirement or deletion, or history-safe reconciliation. The state
schema and authority/remediation transitions are unchanged; the journal gains
one event kind, `journal_sealed`.

### Segment custody and retention

Who and when: the operator. The prompt is `--status` reporting
`remediation.journal.generations-headroom` `ABSENT` (12 sealed segments
present), which the estate collector turns into a `DEGRADED`
`remediation-consumer` and the `service-not-doing-its-job` notice;
`generations-critical` joins it at 15, and the consumer refuses at 16. Custody
may be done earlier at any time. Work oldest segment first, one segment and its
sidecar at a time.

What: a segment is ready for custody only when it has its sidecar and a link
count of 1 (`stat -c %h` prints `1`); a link count above 1 is an interrupted
seal that the next pass finishes, so leave it. Its length and digest must equal
the sidecar's `bytes` and `sha256`. A segment that is ready is never written
again, so checking and copying it need no lock. On labelwatch-host, as root, in
`/var/lib/constellation-remediation/consumer`:

```sh
seg=journal.sealed.0001.jsonl; car=journal.sealed.0001.json
verify() {  # verify DIR: the segment in DIR matches its sidecar
  b=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["bytes"])' "$1/$car")
  h=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sha256"])' "$1/$car")
  [ "$(stat -c %h "$1/$seg")" = 1 ] && [ "$(stat -c %s "$1/$seg")" = "$b" ] &&
    [ "sha256:$(sha256sum < "$1/$seg" | cut -d' ' -f1)" = "$h" ]
}
verify . && echo verified
```

Where: copy the segment and its sidecar to crow under
`/data/git/backups/remediation-journal/<site>/` (`<site>` is
`enrollment.site`, `labelwatch` today), for example from crow with
`scp root@labelwatch-host:/var/lib/constellation-remediation/consumer/journal.sealed.0001.json{l,} /data/git/backups/remediation-journal/labelwatch/`.
Verify again there with the same check (`verify /data/git/backups/remediation-journal/labelwatch`)
and make both copies read-only (`chmod 0444`). A name that already exists on
crow with different bytes is a conflict to resolve by hand, never overwrite.

Then remove the on-host segment and its sidecar together, only after the crow
copy verified, while holding the consumer's lock (or with
`constellation-remediation-consumer.timer` stopped and no pass running), and
re-verify inside the lock so nothing changed in between:

```sh
( flock -w 60 9 && verify . && rm -- "$seg" "$car" ) 9<lock
```

Never edit, truncate or reorder a segment, never touch `journal.jsonl`,
`state.json`, `last-pass.json` or `episodes/`, and do not clear a campaign,
discard an unresolved attempt or reset its fence to make space. What stays on
the host is the chain: the live journal's first record (`journal_sealed`)
names the newest sealed predecessor with its length and SHA-256, and every
segment's own first record names its predecessor, so the off-host copies can
be checked against the host and against each other. Sequences stay monotonic
after removal. The next pass seals normally once fewer than 16 segments are
present, and `--status` reports headroom again below 12. Incident provenance
for episodes whose opening record left with a moved segment becomes unknown,
as for any record past its read bound.

Retention: sealed segments are retained off-host, on crow, indefinitely for
now; the owner may set a limit later. Nothing is ever deleted on the host
before a verified off-host copy exists, and the consumer itself never deletes
or moves a segment.

## Journal contract: idle passes, repeated abstentions and `last-pass.json`

The journal is the durable record of what the consumer judged and did, not a
heartbeat. A pass is *idle* when all of these hold, judged from `state.json`
and the report alone before anything is journaled or run:

- no episode is open (before the pass, and so after it: an idle pass opens
  none);
- in model mode, no Linear Accountant settlement is owed (the LA restart sweep
  would run no command);
- report selection abstains with `observation_not_present` and the enrolled
  condition's `observation` is `clear`: a fresh, well-formed report whose NQ
  inputs are all `ok` says the watched condition does not hold.

An idle pass runs no external command and appends no `pass_started`,
`abstained` or `pass_finished` record. These abstentions are not idle: an
unreadable, malformed or stale report; an NQ input not `ok`
(`nq_input_not_ok`); an `unknown` or `removed` observation; a condition missing
from the report (the evaluator reports clear conditions explicitly, so absence
means it is not watching); an enrolment or policy mismatch; a condition present
but not held (`page_not_deferred`) or with too little window left; and every
abstention after selection (attempted episode, previous window, plan,
precondition, model key, prior campaign, LA recovery failure). Busy passes and
refusals at open write nothing, as before.

A non-idle abstention can still be a *repeated abstention*: the pass meets the
first two conditions above (so it runs no external command), and it abstains,
before any command, with the same `reason` and the same normalized detail as
the immediately preceding pass. That covers the report and NQ-input
abstentions, every selection abstention, `episode_already_attempted` and
`attempt_within_previous_window`; abstentions reached after a command (plan,
precondition, model key, prior campaign, LA recovery) always journal in full.
The first pass of such a streak journals exactly as before (`pass_started`,
`abstained`, `pass_finished`), so the onset and its full detail are durable.
Every later pass of the streak appends nothing of its own. The normalized
detail is the abstention's detail without the keys that change from pass to
pass for the same cause: `age_seconds` (`report_stale`), `remaining_seconds`
(`window_too_short`) and `report_evaluated_at` (the candidate of
`episode_already_attempted` and `attempt_within_previous_window`), at any
depth. For `nq_input_not_ok` the failing inputs (`label` and `status` each)
are compared as a set. Everything else is kept, including the report path and
error of `report_unreadable`, the offending field of `report_malformed`, the
stale report's own `evaluated_at` (a new stale report is a new cause), the
input count, and the condition's observation, first seen, window end and held
page. A different failing input, a different status or a different reason
starts a new streak with a new full record.

Episode transitions, decisions, attempted actions, outcomes and custody
changes are all non-idle and journaled. Sealing is unaffected: an idle pass
that opens a journal due for sealing (full, or an interrupted seal) seals it,
so the live journal then holds only `journal_sealed`.

Idle streaks reach the journal as `idle_summary` records (no episode fields):
`trigger` (`hourly` or `streak_ended`), `count` (idle passes this record
covers), `first_at`/`last_at` (and `_unix_ms`) of those passes, `last_reason`,
`consecutive_idle_passes` and `idle_since` of the streak. One is appended
during a streak when the oldest idle pass not yet summarized is at least an
hour old (so at most one per hour; the first idle pass of a streak never
summarizes), and one before `pass_started` of the first journaled pass after
idle passes not yet summarized. A summary written by a later pass carries that
pass's `pass` id and `at`.

Repeated abstentions reach the journal as `abstention_summary` records (no
episode fields): `trigger` (`hourly` or `streak_ended`), `reason`, the
normalized `detail`, `count` (repeated passes this record covers; the
journaled first pass is not counted), `first_at`/`last_at` (and `_unix_ms`) of
those passes, `repeat_since` (the `at` of the streak's journaled first pass)
and `repeat_count` (passes in the streak so far, first included; null when a
fault ended the streak first). One is appended during a streak when the oldest
repeat not yet summarized is at least an hour old, and one when the streak
ends: the reason or normalized detail changes, an episode opens, a pass is not
eligible (an episode open, a command run), or the pass is idle. A transition
between an idle streak and a repeated-abstention streak ends one, with its
summary, and starts the other.

Every pass that holds the lock atomically replaces `last-pass.json` (0600,
`constellation.remediation-consumer.last-pass/v1`) in the state directory:
`pass`, `at`/`at_unix_ms`, `result` (the summary's result, or `fault` when the
pass failed on its own state after taking the lock, with `error`),
`abstain_reason`, `idle`, `consecutive_idle_passes`, `idle_since` (the `at` of
the streak's first idle pass), `idle_unsummarized` (the idle passes not yet in
a summary), `repeat_reason`, `repeat_detail`, `repeat_count` and
`repeat_since` (and `_unix_ms`) of the current repeated-abstention streak (null
and 0 outside one), `repeat_unsummarized` (the repeats not yet in a summary),
`journal_bytes`, `sealed_segments`, `journal_max_bytes` and
`max_sealed_journals`. It is the consumer's liveness and health surface: it
distinguishes "nothing required action" (a recent idle or judged pass) from "I
have not successfully checked" (a `fault`, or no recent pass at all). It is not
history: it is overwritten every pass, and only the journal is evidence of what
happened. Refusals at open (busy, a state directory that is not private, sealed
generations exhausted) do not update it; the file then grows old, which is the
signal. `state.json` and its schema are unchanged; streak state lives only in
`last-pass.json`, and a missing or unreadable one starts a new streak.

## Status (`--status`)

`constellation-remediation-consumer --config PATH --status` prints one
`project.ops.status/v1` document (schema-valid against
`schemas/project.ops.status.v1.schema.json`) for the estate collector's
`project-ops-status` status kind, and exits 0 whenever it printed one (2 only
for a configuration fault). It takes no lock and opens nothing for writing: it
reads `last-pass.json`, lists `journal.sealed.*` and stats `journal.jsonl`, so
it answers while a pass holds the lock and never creates the state directory.
Every concern is `required`, observed with `valid_for_seconds` 120:

| Concern | `PRESENT` when |
|---|---|
| `remediation.consumer.pass-fresh` | the last pass that held the lock ended within 120 s |
| `remediation.consumer.pass-succeeding` | that pass's `result` is a judged result, not `fault` (`observed_at` is the pass's own `at`, so the collector marks it `STALE` once older than 120 s) |
| `remediation.journal.generations-headroom` | fewer than 12 sealed segments are present (custody due at 12) |
| `remediation.journal.generations-critical` | fewer than 15 sealed segments are present (the consumer refuses at 16) |
| `remediation.consumer.inputs-ok` | the last pass did not abstain for an input failure (`nq_input_not_ok`, `report_unreadable`, `report_malformed`, `report_stale`); `UNKNOWN` after a `fault`; `observed_at` is the pass's own `at` |

A missing or unparsable `last-pass.json` makes the pass and input concerns
`ABSENT` with the read error as the reason, never `PRESENT`. A judged
abstention keeps `pass-succeeding` `PRESENT` (its reason names the repeat
reason, count and since), while an input outage makes `inputs-ok` `ABSENT` on
the first pass that sees it, so the service row degrades within one collector
run instead of staying silent. An unreadable state
directory makes the generation concerns `UNKNOWN`. Informational fields (last
result, `idle`, `consecutive_idle_passes`, `idle_since`, `repeat_reason`,
`repeat_count`, `repeat_since`, `repeat_detail`, `sealed_segments`,
`journal_bytes`, the bounds and thresholds) are under
`extensions."constellation.remediation-consumer"`. The `manifest` member names
the envelope's fixed `.ops/concerns.toml` path; this package ships no such file.

In the estate registry the `remediation-consumer` service declares
`{"kind": "project-ops-status", "argv": ["/usr/bin/constellation-remediation-consumer",
"--config", "/etc/constellation-remediation/consumer.toml", "--status"],
"timeout_seconds": 10}` with no `user`: the collector runs as root, as the
consumer does, and the state directory is root 0700. Any concern not
`PRESENT` makes the service `DEGRADED`, which the attention rule
`service-not-doing-its-job` turns into a Slack notice after 600 s. There is no
separate page for the critical threshold: it adds a second named failing
concern to the same notice.

## Model decider (v2, opt-in)

`--decider model` (cartography `architecture/agentic-remediation-v2/DESIGN.md`
sections 2 and 3) adds one reasoning phase to the same consumer, before
`ag init`; the default stays deterministic. Every v1 gate runs first (report,
NQ input, observation, held page, current bound precondition), and model mode
needs at least 210 s of remediation window. Then, in order: the episode is
saved; Linear Accountant `reserve`; per call a saved call record, LA
`begin-call`, the saved send permission, one HTTPS call, LA `settle`, the
saved settlement and decision; on `start_canary`/`current_down` only: LA
`close`, a fresh report, window (175 s) and precondition check, then the v1
AG/Docket path from the pinned plan. `abstain` and `escalate` close the
episode without any AG work; the held page goes out if the condition persists.
One fresh retry follows a malformed answer, a provider error or a proven
unsent request; a timeout, an uncertain send, a budget refusal or an LA fault
ends the episode. There is no deterministic fallback in model mode.

The model sees an explicit projection only: the resolver's status, id, basis
type, currentness and freshness bound, the checked prestate, the canary
label, seven report fields, the remaining seconds, the three candidates, and
the condition's `summary` (at most 512 bytes) labelled
`untrusted_narration`. The evaluator does not emit `summary` today, so it is
empty unless a qualification fixture supplies it. The answer must be exactly
`{"decision","reason"}` with closed enums; anything else is malformed.

- **LA.** `la_inference` (linear-accountant) runs as a child like every other
  command; `[model].la_arguments` selects its store. Each model-mode pass
  first settles, through LA `recover`, any call this consumer's state shows
  begun but unsettled (never sent: `cancelled_unsent`; possibly sent:
  `crash_unknown` at its ceiling, never re-sent), and fails closed for new
  reasoning while LA is unavailable. Reconcile with `la_inference reconcile
  --milestone ID`.
- **Provider.** One POST to `https://openrouter.ai/api/v1/chat/completions`
  (`google/gemini-2.5-flash-lite`, `provider.only = ["google-vertex"]`, no
  fallbacks, `require_parameters`, `data_collection = "deny"`, `max_price`,
  temperature 0, 256 tokens, reasoning disabled, strict JSON schema). 3 s
  connect and 15 s total deadline, no redirects, no proxy from the
  environment. The input is bounded before the send by the UTF-8 bytes of
  its message contents and response schema plus 256 for the chat template
  (a byte-level or byte-fallback tokenizer emits at most one token per byte);
  over 4096 the call is not sent. The reported usage is checked against the
  ceilings afterwards.
- **Key.** `/etc/constellation-remediation/openrouter.env`, root 0600, one
  `OPENROUTER_API_KEY=` line. The adapter reads it inside its own thread for
  each call; it is never in the environment, configuration, state, journal or
  any child. A key file readable by group or others is refused before
  anything is spent.
- **Sandbox.** Install `model-decider.conf` as a drop-in: it adds
  `--decider model`, `AF_INET`/`AF_INET6` (unit-wide; children stay
  env-cleared with fixed argv) and `/var/lib/linear-accountant` to the
  writable paths. Without the drop-in nothing has network access.
- **Records.** Each episode directory keeps `evidence-N.json` (the exact
  projection) and `response-N.json` (the provider's answer) in the private
  state directory; LA holds only typed accounting metadata.

### Qualification fixture credentials and closeout

Ordinary builds accept only the exact enrolled OpenRouter HTTPS endpoint.
Loopback HTTP requires the explicit `qualification-loopback` Cargo feature;
record that feature in the qualification artifact identity and remove that
artifact from the host at closeout. Run model fixture tests with
`cargo test -p constellation-remediation-consumer --features qualification-loopback`.
For a fixture destination the adapter never opens the configured provider key
file: it sends only `CONSTELLATION_QUALIFICATION_ONLY_NOT_A_PROVIDER_KEY`.
The real HTTPS path retains the private-file check and reads the owner key.

Synthetic provider scripts must accept only this public marker, suppress header
and body logging, and record counts or modes only. Configure a separate
synthetic credential path for fixture cases; switch both `endpoint` and
`key_file` together when selecting a real case. Prove isolation with the real
key file absent, and prove a default production build rejects loopback.
Never use a real credential as the fake-provider prerequisite.

On the live host, retain the original production configuration and grant before
qualification. Every induced escalation uses the dedicated TEST PagerDuty
service, with a verified distinct route and accepted TEST receipt. At closeout,
restore the original production routes, configuration and grant pin; remove the
qualification model drop-in and fixture endpoint; stop the exact fake-provider
unit and remove its restart or activation paths. Verify the fake has no process
or listener, model mode is disabled, the canary is healthy, and the original
grant's use/revocation state is reconciled. The historical v1 closeout script
issues a new grant and omits model/fake cleanup: it must not be reused for this
v2 restoration. Retain failed occurrences and independently reviewed records.

Record bounded credential-retention inspection without displaying matching
bytes, and the separate credential rotation/disposition decision. A stopped
fixture proves neither absent disk retention nor provider-side revocation.

## Build (hermetic, Ubuntu 22.04)

The provider adapter links `ureq` with `rustls` and `ring`; vendoring covers
them and `ring` builds its C and assembly parts with the image's `cc`.

As for `packaging/attention` (see its README): vendor a `git archive`
export on the host, then build inside `jammy-packager:1` with
`--network none`:

```sh
commit=$(git rev-parse HEAD); src=$(mktemp -d)
git archive "$commit" | tar -x -C "$src"
( cd "$src" && mkdir -p .cargo && \
  CARGO_NET_OFFLINE=true cargo +1.94.0 vendor --locked vendor > .cargo/config.toml )
docker run --rm --network none -v "$src":/work -w /work \
  -e MONITOR_SOURCE_COMMIT="$commit" \
  -e MONITOR_BUILD_IDENTITY="remediation-$commit" \
  -e SOURCE_DATE_EPOCH="$(git log -1 --format=%ct "$commit")" \
  jammy-packager:1 bash -c '
    cargo build --release --locked --offline \
      -p constellation-remediation-consumer -p constellation-remediation-resolver &&
    packaging/remediation/build-deb.sh 0.1.0 amd64 target/release dist;
    rc=$?; chown -R '"$(id -u):$(id -g)"' /work; exit $rc'
```

## What a completion asserts

AG `completed` (and the consumer's `completed`) means: Docket settled the
one start as success, and an NQ ops-store evaluation taken at least
`postcondition_dwell_seconds` (default 15) after that settlement, and within
the resolver's 60 s freshness bound when AG asked, showed the unit loaded and
active. A unit that dies inside the dwell is never claimed (the episode
closes `postcondition_not_proven` at window end and the held page goes out).
It does not assert durable recovery: the evaluator resolves the condition only
after 120 s of continuous clear, and a relapse before that sends the held
page at window expiry.

## Runtime premises (declared)

- **Same root.** The unit runs `User=root`: the consumer, AG's issuer key,
  Docket's state, the grant journal and `ag-effectd` are all root on one
  host. The consumer holds no authority of its own; AG admits only the
  owner-pinned plan digests (`admitted_plans`), Docket derives standing only
  from the owner's bounded grant. Root can replace all of it.
- **Sandbox.** `ProtectSystem=strict`; writable: `/var/lib/constellation-remediation`
  (consumer state, AG campaign and archive, Docket state, executor attempt
  store, grant use journal) and `/var/lib/nq-ops` (SQLite `-shm` for the
  resolvers' reads). `/etc/constellation-remediation` and `/etc/nq` are
  read-only. Only `AF_UNIX` (the systemd bus); the model decider's drop-in adds
  `AF_INET`/`AF_INET6`.
- **Campaign lifecycle.** One AG campaign per condition episode at the path
  `ag-effectd.deployment.json` pins (`ag.database`). Before opening the next
  episode the consumer archives a finished campaign (completed, halted,
  settled, or observation pending) to `<database dir>/archive/<ms>-<pass>/`.
  `ag-effectd` refuses any issuance whose campaign is not the one at the
  pinned path, so an archived campaign's issuance can never execute. A
  completed occurrence cannot be continued, so continuation occurrences in
  one campaign are not used across episodes.
- **Refused dispatch wedges.** When Docket refuses custody (grant exhausted,
  revoked, expired) AG stays at `authorization_consumed`: AG has no halt from
  that state and the consumer never archives spent, unresolved authority.
  Later episodes abstain (`prior_campaign_unresolved`) and the evaluator
  pages at window expiry until the operator archives the campaign by hand
  (stop the timer; move `campaign.sqlite*` to `archive/`). Declared limit.
- **The sandbox can write what bounds it (review F3).** The writable paths
  cover the grant use journal, Docket custody state, the AG campaign
  database, the executor attempt store and the NQ ops store that holds the
  pre- and postcondition evidence, and the process tree reads the AG issuer
  key. `docket` takes its standing resolver from argv (only `ag-loopctl`
  checks it against the profile). So `max_uses`, revocation and the
  independence of the postcondition hold only while the consumer binary is
  the reviewed one. The profile pins the resolver wrappers' bytes, not
  `constellation-nq-unit-resolver` or `nq`. Not yet mitigated: running the
  resolvers as `nq` via `systemd-run` (so `/var/lib/nq-ops` leaves
  `ReadWritePaths`) and Docket pinning its own standing resolver.
- **Torn grant journal entry (review F5).** A crash between the `O_EXCL`
  create and the write of `use-NNNNNN.json` leaves an empty entry; every
  later derivation then refuses (`journal-entry-document`) and remediation
  stops (fail closed, the evaluator pages). Repair is an owner step: enroll a
  new grant with a new, empty journal and a new pin (Docket
  `execution-standing-enrollment.md`, "Torn journal entry").
- **D-Bus address from the environment (review F6).** `ag-effectd` connects
  with `Connection::system()`, which honours `DBUS_SYSTEM_BUS_ADDRESS`. The
  consumer clears the environment of every command, which is the only thing
  pinning the executor to `unix:path=/run/dbus/system_bus_socket` today.
- **Grant has no rate limit.** Per-episode attempts are bounded by the
  consumer and by `max_uses`; choose a small `max_uses` and a short validity.
- **Start only.** v1 starts a not-active unit (prestates enrolled per plan);
  it never restarts an active-but-wedged unit.

### Canary collection cadence

Before host qualification, inspect the `svc-attention-canary` watcher's
`[watchers.schedule]` in `/etc/nq/nqd-ops.toml`. Use `interval_seconds = 30`
for the profile's 60-second testimony reliance. A 60-second sleep after
collection allows the freshness sweep to publish `cannot_evaluate` before
the next collection completes (#71). Keep the testimony reliance and the
enrolled resolver's evaluation recency unchanged. Collection failures or
long delays must still refuse authorization; this cadence is not a guarantee
of continuously qualified evidence. Preserve other watcher schedules.

The retained #71 evaluation was at 05:36:39.403Z, with a 90-second resolver
recency bound. The subsequent 05:37:09.693Z evaluation expired testimony
observed at 05:36:09.654Z (age 60.039 seconds). The earlier inferred
future-sample diagnosis used the wrong recency bound and is withdrawn.

### Consumer cadence and the held-page window (#90, 2026-10-17)

The packaged timer polls 10 seconds after the previous pass finishes. A real
canary drill exposed a phase-dependent miss with the former 30-second interval:
first seen 23:47:02Z, deferred report published 23:51:23.67Z, window ending 23:52:02Z.
The poll at 23:51:20 read the previous non-deferred report; the next at 23:51:50
had 12 seconds left and correctly refused the unchanged 25-second safety margin.
The notice and subsequent page were accepted, but no remediation episode opened.
The test canary was restored by the operator; that run remains incomplete.

A 10-second interval removes this observed 30-second scheduling gap without
changing the page hold, admission margin, grants, targets, action selection or
postcondition verification. Longer producer/transport delays can still consume
the window, in which case the existing refusal and escalation remain correct.
Do not describe a successful no-op pass as successful remediation.

Formalization consideration: the bounded timing counterexample is the recorded
publication/poll sequence above. Replaying that sequence at 10-second cadence
admits at 23:51:30 (32 seconds remaining) rather than23:51:50 (12 seconds).
This is a scheduling-budget calculation, not a general liveness proof or a
qualification verdict. Existing selection tests retain the margin and deferred
page predicates. A new live drill has a new run identity; the failed original
is retained. Decision owner: unpingable; implementation: Codex. Source evidence:
managed-definitions run 374040ae, canary run f9b3218c. No #93 Store semantics change.
