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
Incident sync reads at most the last 16 MiB of that journal and associates only
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

Each consumer journal has a 64 MiB (67,108,864-byte) application ceiling.
`--check-config` reports `journal_max_bytes` without creating or opening state;
that value is a limit, not a journal-usage or service-health claim.

The Store refuses a full or already oversized journal before a pass starts.
Each append checks that the complete encoded record fits before writing any
of it. Capacity refusal preserves existing journal bytes, state, episode IDs
and dispatch fences. The consumer exits 2 through its existing store-fault path;
the existing estate supervision of the consumer's failed passes remains the
operator route. A full journal is not healthy and does not authorize a retry.
Read-only incident inspection and AG/Docket inspection remain available.

There is no automatic rotation, truncation or history deletion. Exhaustion needs
operator custody and disposition under the existing recovery procedure. Do not
clear a campaign, discard an unresolved attempt or reset its fence to make space.
This bounds this journal only, not per-episode inputs or AG, Docket and NQ stores.

Formalization consideration (Monitor private-history #6 / finding 94-22;
implementation Codex, owner unpingable): while cooperating writers hold the
existing exclusive Store lock, admitted appends satisfy
`used + encoded_record_bytes <= journal_max_bytes`, with overflow refused.
Tests cover an exact-boundary append followed by byte-preserving refusal, an
already-full journal preventing every external call while retaining a dispatch
fence, and configuration inspection without state creation. Practical tests and
checked arithmetic suffice for this bounded change. This does not establish
atomic writes under arbitrary I/O failure, exclusion of uncooperating writers,
automatic retirement, or history-safe reconciliation. Existing JSON schemas and
authority/remediation transitions are unchanged.

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
