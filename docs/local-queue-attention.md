# Read a queue and decide whether it needs attention

This external-caller example connects Monitor, NQ, Pulse and Nightshift. It
creates a disposable SQLite queue with twenty rows, reads its depth through
Monitor, and asks NQ to check the existing compiled `queue.depth >= 18` rule.
A separate process reads the same database for Pulse. Nightshift records the
operator's decision that this current proposition warrants attention. NQ then
retains an intentionally refused notification because network delivery is off.

These are real local reads and real component entry points, not substituted
verifier responses. The queue is a demonstration, not a production service.
Both observation roles use the same script under one operator. Pulse establishes
only its declared source/identity/currentness relation; this is not independent
administration, remote attestation, or proof that the implementation is correct.

## Prerequisites and tested combination

Linux x86-64, Python 3.12 with `cryptography` 41.0.7, and Rust/Cargo 1.94.0 were
used. Install the Python dependency into a local virtual environment if it is
not supplied by your OS: `python3 -m venv .venv`, then
`.venv/bin/python -m pip install cryptography==41.0.7`. The two observation roles
use `/usr/bin/python3` and the standard library only; the top-level caller uses
the selected Python interpreter for signing. No API key or messaging credential
is required or read. The ephemeral signing key is generated in memory and is
not printed or retained; retained signed evidence can still be replayed.

Select these component sources, not arbitrary current heads:

| Component | Source and entry point |
|---|---|
| Monitor and Pulse | The accompanying source cut records the canonical revision and exact files in `SOURCE-PROVENANCE.json`. Build its two packages; use `monitor-concerns` and `pulse-project-predicate-support`. |
| NQ | Public `constellation-nq` at `ad7dd887b52269c6e8c9dd7ffd10829861de4596`; `cargo build --locked -p nq-app --bin nq`. |
| Nightshift | Public `constellation-nightshift` at `d8e03c04847cc0e8d7b8fd57ef0896959e73f89f`; `cargo build --locked --manifest-path runtime/Cargo.toml -p nightshiftd --bin nightshift`. |

This is a tested development-source combination, not a family-wide release.
Use debug builds for this same-account disposable qualification. NQ production
builds retain separate-account verifier enrollment requirements; this example
does not qualify production identity isolation. No constituent version or
existing suite release is replaced by running it.

```sh
# In the accompanying Monitor/Pulse source cut:
cargo build --locked -p monitor-project-concerns -p pulse-project-predicate-support --bins
python3 examples/local-queue-attention.py \
  --root /tmp/queue-attention-example \
  --monitor "$PWD/target/debug/monitor-concerns" \
  --pulse "$PWD/target/debug/pulse-project-predicate-support" \
  --nq /absolute/public-nq/target/debug/nq \
  --nightshift /absolute/public-nightshift/runtime/target/debug/nightshift
```

The root must be absent. Replace the two absolute executable locations with the
actual public builds. If using a virtual environment, invoke its Python for the
top-level command. The script records executable hashes; a hash of an arbitrary
supplied executable does not qualify its compatibility. Use the profile's source
pins and verify those builds before selecting paths. Different build environments
can produce different binary hashes from the same source.

```mermaid
sequenceDiagram
    participant Caller
    participant Monitor
    participant Queue as Disposable SQLite queue
    participant NQ
    participant Pulse
    participant Nightshift
    Caller->>Monitor: Collect operator-selected producer
    Monitor->>Queue: Primary read
    Monitor-->>Caller: Validated inventory and source bindings
    Caller->>NQ: Admit exact inventory under compiled predicate
    Caller->>Queue: Separate support-process read
    Caller->>Pulse: Signed support, source policy and NQ receipt
    Pulse->>NQ: Replay primary and check support facts
    Caller->>Nightshift: Ingest Pulse receipt under attention policy
    Nightshift->>Pulse: Replay exact support
    Nightshift-->>Caller: Durable attention decision and replay bundle
    Caller->>NQ: Exact attention intent, network disabled
    NQ->>Nightshift: Read-only replay
    NQ-->>Caller: Retained delivery refusal
```

The central handoffs are the real `collect`, `bounded-predicate admit`,
`qualify`, `attention ingest`, `attention evaluate`, `attention replay`, and
`notification submit/inspect` commands. The longer accompanying script includes
the otherwise necessary setup, signing, bounded subprocess handling and controls;
it is not an invented SDK or a hidden background service.

## Results and failures

Success prints `"result": "qualified"`. Inspect `result.json`, `commands.jsonl`,
the actual `inventory.json` and `support.json`, and owner receipts under the root.
The script requires an accepted Nightshift event followed by duplicate-evidence
convergence, exact attention replay, and one refused notification event despite
duplicate submission. It also requires a changed catalog to refuse and explicitly
checks the exclusive freshness boundary with a future-time negative control.
Those future evaluations do not refresh or change the original observations.

`ATTENTION_REQUIRED` is about the policy's proposition, not objective completion,
permission to change the queue, or message delivery. The example makes no AG or
Docket execution claim. NQ `refused` is expected here: no endpoint is resolved
or contacted. It is not a pending send that later becomes billable or deliverable.
Do not relabel this example as restored Slack/Discord notification.

## After interruption or a later restart

Keep the root. There is no automatic restart or resume-everything operation.
Each command has a thirty-second bound and bounded output; process-group cleanup
and a command record follow a caught timeout/interruption. A supervisor or host
loss can still leave an incomplete transcript. Inspect retained owner state,
not just the last printed line. Do not run the create-only example over that root.

If `attention.json` exists, replay it without changing observation time:

```sh
nightshift --store /tmp/queue-attention-example/attention.sqlite \
  attention replay --bundle /tmp/queue-attention-example/attention.json
```

Use the configured executable corresponding to the tested source pin. When a
notification ID appears in `commands.jsonl`, inspect it with
`nq --config /tmp/queue-attention-example/nq.toml notification inspect --notification-id ID`.
A claimed attempt without a terminal record is unknown, not permission to retry.
The standalone saved-check guide documents its distinct evaluation-replay rules.

Keep configuration, policy/receipt JSON, the SQLite stores and their WAL-related
files together for investigation. Do not copy a live SQLite file in isolation and
claim a consistent backup. This example has no long-running producer after its
commands exit; verify that condition before backing up or removing its exact
disposable root. The code deliberately does not delete records. Restore, migration
and rollback of a complete recurring deployment are not qualified here.

This composition has no recurring scheduler, automatic saved-check maintenance
overlay, retention policy, live notification, acknowledgment, objective completion,
or governed external effect. Those are separate capabilities, not implied by
successful transport or this worked example. Existing production services and
their retirement remain outside the example's authority.
