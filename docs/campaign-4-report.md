# Qualified-generation binding campaign report

Status: qualified local experimental result on 2026-08-03. Repository,
certificate, and record names remain provisional.

## Baseline, inspected scope, and milestones

The campaign began from exact clean commit
`3cd15b7a1e7f424f6fd57c09b30fa4790947eca2` on `main`, with no remote. The
baseline passed formatting, strict workspace Clippy, and all 97 tests.
Reconnaissance read every required runtime/document/artifact surface and found
that generation strings were caller supplied even though policy body content
was already exact. The current/history split was sound enough to add a live,
non-serializable activation premise without persisting standing.

The implementation sequence before this report/artifact commit is:

```text
a12d747 Define qualified-generation binding contract
78c980f Gate reliance on qualified artifact activation
da78615 Qualify exact artifacts and activation custody
06ba3b8 Preserve canonical package bytes in artifacts
```

The exact source commit qualified by the checked package is
`06ba3b8a007686cf4c793148a6439841916b5182`, Git tree
`f96cc79e4bd9e42e618ac6bd31ed47866b9e892a`. The final report/artifact commit
is necessarily identified by Git rather than embedding its own content hash
in this file; the completion handoff names it.

The permitted neighboring comparison remained read-only:

- NQ-NG `59abd3bcb2d0cc30657a659b3ebc57b981289d9f`;
- Witness `e3d22f9bef8dc248e58e0fa5b7fa474b2dd78c5d`;
- Nightshift `500f4b7bd4f066c7ca43963d192f314559cdbc83`;
- Docket `3ce07f9bb3be6ba86ca65f3b521f807970b56119`;
  and
- Synesthesia `d1a731c383d4fce8f9bc21f40b63af5dbae2aa94`.

Exact inspected paths and the limited principles retained are recorded in
`campaign-4-reconnaissance.md`. No neighboring repository was modified, no
schema or authority model was imported, no remote was created, and nothing
was pushed.

## Architecture

The deterministic evaluator, receiver scheduler, local monotonic reactor, and
append-only journal remain intact. Campaign 4 inserts one per-consumer
qualified-generation gate between declared runtime context and positive
support:

```text
declared generation set
        !=
canonical exact artifact manifest
        + checked machine-readable qualification report
        -> local unsigned exact qualification certificate
        !=
fresh process-local measurements + local lifecycle acceptance
        -> activation receipt + non-serializable accepted activation
        -> only then may fresh evidence earn CURRENT
```

`ReceiverSchedulerRuntime` stores the accepted activation as an opaque token
that owns an opened executable handle. It cannot be cloned, serialized, or
constructed from an activation receipt. Before issuing `CURRENT`, the runtime
requires token/context equality, recomputes the canonical identities of its
owned policy/profile/observer/observation/configuration values, checks the
retained executable object, and puts exact manifest, certificate, receipt,
process occurrence, and generation-set identities into the bounded support
certificate. Any missing, ambiguous, superseded, revoked, or mismatched state
produces a non-positive certificate and no support deadline.

Binding transitions reuse the existing deterministic generation barrier.
They do not create a second event scheduler. Installing a package or applying
an accepted lifecycle fact withdraws inherited standing immediately for only
the affected subject/consumer. Evidence can be reconsidered only by an
explicit evaluation under the exact new activation.

## Exact artifact roles

The closed V1 manifest contains each role exactly once in this canonical order:

1. `running_executable` — exact bytes exposed by the opened executable handle;
2. `evaluator_implementation` — embedded evaluator marker and semantic
   generation;
3. `reliance_policy` — canonical exact owned policy value;
4. `consumer_profile` — canonical consumer/scope/profile premise;
5. `observer_set` — canonical required observer/failure-domain law;
6. `observation_policy` — canonical profile, generation, and admitted coverage;
7. `runtime_configuration` — canonical receiver and every runtime bound;
8. `semantic_contracts` — exact embedded evaluator/binding/support contracts;
9. `qualification_corpus` — exact checked hostile-corpus bytes; and
10. `qualification_results` — exact checked command-result bytes.

The first eight are measured at activation. Corpus and result identities are
qualification evidence, not active runtime inputs. A manifest missing a role,
duplicating/swapping roles, using an ambiguous logical path, or naming its
corpus inconsistently is refused.

## Canonicalization and digest law

Closed Rust structures with `deny_unknown_fields` serialize as compact UTF-8
JSON in declaration order, without insignificant whitespace or a trailing
newline. Order-insensitive collections are sorted and duplicate-free before
encoding. Maps in active policy values become sorted vectors; floating-point
tolerances are encoded by exact IEEE-754 bit pattern. A decoder enforces the
2 MiB package bound, rejects malformed/invalid UTF-8 and unknown or duplicate
fields, validates every semantic bound, re-encodes, and requires byte equality.
Thus pretty JSON, key reordering, repeated keys, and trailing bytes are not
alternate valid encodings.

Content identity is lowercase, nonzero `sha256:<64 hex>`. Manifest, report,
certificate, lifecycle fact, activation receipt, generation set, and support
certificate use separate domain-separated, length-framed SHA-256 transcripts.
Unsupported algorithms, uppercase/noncanonical hex, all-zero digests, digest
substitution, and body/digest disagreement are refused. SHA-256 establishes
content identity under collision-resistance assumptions; it does not establish
authorship, authority, freshness, qualification, or authenticity.

Checked package identities:

```text
manifest       sha256:63ecf5d031b0eb77c20c8bcbc891d0a23339c46a148faebbca3ad5ebed0d414c
report         sha256:2675110ec3e96191f50c4d6e037e4f9ce89365bd5ad2f19ef0505510e627d2d0
certificate    sha256:33bdd57879a7b0a8602aaa5558e2ba52f02dc41093a131ebdd8c906bd0ae2b80
activation     sha256:863e0a3176c6ed99e872395875cd627632c21c0d20afa816e53136ebfc0627d1
executable     sha256:8a51001e23b67f1d1fbc7e209c44a1399533ed5269297a7e1f0cfc420035c5f2
```

## Executable and owned-value measurement

On the qualified Linux path, activation opens `/proc/self/exe`, requires a
nonempty regular file no larger than 128 MiB, reads the exact opened object,
checks stable device/inode/length around the read, records content digest and
byte length, and retains that handle in the accepted token. The checked
executable was 41,457,464 bytes. Invocation path and `/proc/self/exe` link text
are provenance only.

Within one process, the exact content digest is cached only while newly opened
handles retain the same device, inode, length, modification time, and change
time. Every accepted token owns its own handle. Positive-use revalidation
checks retained metadata and performs a full reread/digest comparison after
an ordinary metadata change. Rename/unlink/path replacement cannot substitute
another object through the retained handle.

This establishes the bytes one process observed through that handle. It does
not prove what the kernel originally executed, in-memory code-page integrity,
loader/kernel/host correctness, or independence. Policy, profile, observer
set, observation policy, configuration, evaluator marker, and contract values
are immutable owned/embedded values hashed from canonical semantics rather
than paths, debug text, map iteration, memory layout, or caller labels.

## Qualification evidence model

`pulse-qualification qualify <new-directory>` is a narrow local tool, not a
build system. It first requires a clean Git source occurrence and observes the
exact commit/tree, Cargo.lock digest, Rust toolchain report, target triple,
profile, feature posture, platform assumptions, corpus bytes, and executable.
It then runs and captures the exact three required commands. Command argv,
exit status, stdout/stderr digests, and parsed test count are encoded in the
canonical `QualificationResultsArtifactV1`. Package construction decodes those
exact bytes and refuses if separate caller fields disagree.

The report must exactly match the manifest's artifact, source, build,
contract, corpus, claim, and nonclaim identities. Its earned claims must be a
subset of declared claims. The certificate must exactly copy the checked
report and manifest bindings; it cannot add a claim. Changing a qualification
artifact after certification or pairing an old certificate with a new
manifest/report is detected.

The V1 certificate is intentionally unsigned and records
`local_unsigned_exact_bytes`. A configured local acceptance record names its
exact digest and one local lifecycle-authority identifier. Internal package
consistency is not issuing-environment trust, organizational approval, signer
authorization, or source-to-binary correspondence.

## Activation, supersession, and revocation

Activation decodes and cross-verifies the bounded package, checks exact local
acceptance/lifecycle status, measures every required role, emits exact mismatch
reasons, and creates the opaque token only for `QualifiedAndMatched`.
`Unbound`, `BindingPending`, missing/unsupported package states, every role
mismatch, missing measurement, mutable-after-activation, superseded, revoked,
and ambiguous states cannot support `CURRENT`.

V1 implements a narrow local lifecycle boundary. A canonical fact names the
configured authority identifier, exact certificate, strictly newer fact
sequence, reason, and either an exact successor manifest/certificate pair or
revocation with no implied successor. An arbitrary `revoked=true` or wrong
authority is refused. Accepted supersession and revocation both withdraw
positive standing and cancel deadlines; historical package/receipt facts
remain past evidence. There is no pinned-superseded exception and no global
revocation authority.

## Crash and restart behavior

After restart:

```text
binding state = Unbound
current standing = UNKNOWN
supporting evidence = 0
active deadlines = 0
active escalation authority = none
```

Historical manifests, certificates, activation receipts, binding failures,
support transitions, contradictions, and diagnostic receipts may be recovered
as history. The executable handle and accepted token are never serialized. A
new process must verify, measure, and emit a new receipt, then receive fresh
evidence.

The Linux child harness used real `SIGKILL` at 12 executed boundaries:
before/during measurement; after measurement before binding commit; after
binding before receipt journaling; during receipt framing; frame-written
before sync; data-synced before commit; commit-synced before acknowledgement;
after fully synced receipt; after binding before evidence; while `CURRENT`;
and after mismatch detection. Torn/uncommitted first receipts were refused as
damaged history; committed receipts and one historical `CURRENT` were recovered
cleanly. Every restart was `Unbound`/`UNKNOWN` with zero support/deadlines.

One requested point was explicitly refused: “sync activation receipt, then
activate.” An activation receipt states what was activated, so persisting it
first would create a durable false claim if killed between steps. V1 commits
ephemeral binding before journaling the receipt. This is a deliberate negative
result, not a papered-over test omission.

## Earned claims

This campaign earns exactly these local claims:

1. Runtime generation labels cannot independently authorize `CURRENT`.
2. Exact manifest identity is distinct from checked qualification, and both
   are distinct from process-local activation.
3. The locally opened executable identity participates in active reliance.
4. Exact evaluator, policy, consumer profile, observer set, observation
   policy, runtime configuration, and semantic-contract identities participate
   in active reliance.
5. Mismatching any activation-required role prevents `CURRENT` and creates no
   support deadline.
6. `CURRENT` support certificates name the exact accepted manifest,
   certificate, activation receipt, process occurrence, and generation set.
7. Equal content under a new generation, rollback, and ABA cannot inherit the
   first standing; a new exact package, activation, and explicit evaluation are
   required.
8. A prior activation receipt remains history after restart and cannot
   construct the live token, support, or deadline.
9. Accepted supersession and revocation withdraw positive standing; an
   unconfigured revocation assertion is not authority.
10. Manifest/certificate/report corruption, truncation, noncanonical encoding,
    duplicate fields/roles, role swapping, missing roles, unknown fields,
    algorithm downgrade, and package cross-pairing are detected or refused.
11. Qualification claims cannot exceed the checked exact machine-readable
    command/corpus evidence.
12. Caller-supplied-only or unavailable required measurement cannot be reduced
    to a warning while `CURRENT` remains possible.
13. Binding-slot identity churn reaches an explicit fixed bound and refuses
    without silent eviction.
14. Process death at every executed activation/journal boundary cannot preserve
    or reconstruct binding or reliance.
15. Every emitted authority field remains `none`; no object grants
    continuation, diagnostic execution, deployment, signing, revocation, or
    mutation authority.

Each claim is backed by a named test and/or checked artifact. A digest proves
only content identity under the stated assumptions, and local self-measurement
is explicitly not independent attestation.

## Exact nonclaims

The campaign does not claim reproducible builds, source-to-binary
correspondence, compiler correctness, toolchain trustworthiness, exact loaded
system-library provenance, kernel or loader integrity, host integrity, secure
boot, TPM-backed measurement, remote attestation, signer authorization, global
certificate or revocation authority, artifact freshness, organizational
approval, supply-chain security, malware absence, observer truthfulness or
independence, complete coverage, subject health, hard-real-time behavior,
physical-media durability, qualified network transport, production deployment
viability, product-plane status, continuation authority, diagnostic-execution
authority, deployment authority, signing authority, revocation authority, or
mutation authority.

It also does not claim a general build/package system, PKI, transparency log,
deployment orchestrator, TPM framework, network attestation protocol, mutable
file-watcher, or complete contradiction-resolution language.

## Qualification results and artifacts

The exact checked commands all exited zero:

```text
cargo fmt --all -- --check                                           PASS
cargo clippy --workspace --all-targets --all-features -- -D warnings PASS
cargo test --workspace --all-targets --all-features                 PASS (125)
```

The 125 tests are the 97 starting tests, five additional closed-type/binding
tests in `pulse-types`, and 23 `pulse-qualification` tests: one tool parser,
one Linux child-process crash integration, and 21 canonicalization,
substitution, lifecycle, restart, authority, bound, and property tests.
Property coverage includes arbitrary package truncation, single-byte report
mutation, activation-receipt truncation, generation changes, role uniqueness,
and existing ordering/duplication properties.

The canonical package and receipt plus all deterministic demo, mismatch,
authority-laundering, lifecycle, restart, and crash records are indexed in
[`artifacts/qualified-generation-binding`](../artifacts/qualified-generation-binding).
`qualification-summary.json` binds exact argv/status/output digests and the
125-test total. Canonical package/receipt files contain no trailing newline;
display artifacts are pretty JSON.

## Deterministic demo traces

Exact matched activation:

```text
runtime starts Unbound
certificate + manifest + checked report verified
executable and seven semantic artifacts measured exactly
binding QualifiedAndMatched; judgment UNKNOWN; evidence=0; deadlines=0
fresh evidence evaluated
CURRENT; evidence=1; deadlines=1
support certificate names exact manifest/certificate/receipt/generation set
```

Executable and policy substitution:

```text
valid checked package; executable bytes differ
binding ExecutableMismatch; judgment UNKNOWN; deadlines=0

qualified executable matches; generation label unchanged; policy bytes differ
binding PolicyMismatch; judgment UNKNOWN; deadlines=0
```

Restart:

```text
QualifiedAndMatched -> CURRENT
process occurrence ends
historical activation receipt recovered=1
binding Unbound; judgment UNKNOWN; evidence=0; deadlines=0
new local measurement and receipt required
```

Supersession/revocation:

```text
QualifiedAndMatched/CURRENT
accepted exact lifecycle fact
Superseded or Revoked / UNKNOWN
deadlines=0; historical evidence preserved; standing_preserved=false
```

Runnable commands:

```text
cargo run -p pulse-qualification -- demo
cargo run -p pulse-qualification -- crash-demo
```

## Hostile scenarios covered

The qualification covers equal labels/versions with different executable or
policy bytes; every other activation-required role substitution; source,
toolchain, and feature identity package mismatch; old/new manifest,
certificate, report, and receipt pairing; changed qualification corpus/results;
duplicate/swapped/omitted roles; path traversal; unknown/duplicate fields;
pretty/reordered/malformed encodings; digest downgrade/zero/corruption;
manifest/certificate/receipt truncation; report byte mutation; missing package
components; ambiguous lifecycle status; wrong revocation authority; equal-body
new generation; restart receipt replay; caller-supplied measurement; binding
identity churn; and all activation/journal crash points described above.

The existing 97-test runtime/replay/reactor/journal corpus also continues to
cover expiry, deterministic generation ordering, overload, contradiction
custody, diagnostic non-resolution, historical `CURRENT`, journal damage, and
no mutation authority.

## Known semantic and engineering gaps

1. The package binds exact source/tree/toolchain/feature/Cargo.lock identities,
   but no source-to-binary or reproducible-build claim connects them to the
   measured executable.
2. V1 does not independently measure exact loaded libc/loader/libgcc bytes.
   Their behavior, the kernel, vDSO, filesystem metadata, and loader remain
   named platform/host assumptions and explicit nonclaims.
3. Executable revalidation relies on ordinary Linux inode/length/mtime/ctime
   behavior. Raw-device mutation, hostile kernel metadata, process-memory
   modification, and loaded-code attestation are outside the claim.
4. All non-executable runtime inputs in this slice are immutable owned or
   embedded values. V1 does not qualify a mutable file-backed policy/config
   watcher or a deployment handoff.
5. Certificate provenance is unsigned. The local configured lifecycle
   authority is an exact identifier/acceptance rule, not proof that an actor
   is organizationally authorized.
6. Qualification command output is content-digested and summarized rather
   than retained as a general build log. The exact machine result record is
   bounded and sufficient only for the claims named here.
7. No certificate expiry/calendar requalification ceremony exists. Reuse is
   trigger-based on exact identity/assumption change, hostile invalidation,
   supersession, or revocation.
8. Activation receipt journaling is commit-after-activation. A crash can lose
   historical receipt custody after an ephemeral activation occurred; it
   cannot preserve standing. The opposite ordering is intentionally refused.
9. Qualification is local to one process. No receiver-boundary transport or
   multi-host observation custody has been attempted.

No earlier earned claim was weakened. The binding gate strengthens the premise
for `CURRENT`; all prior expiry, contradiction, restart, reactor, journal, and
no-authority tests continue to pass. No campaign stopping condition requiring
termination was reached. The receipt-before-activation crash point was refused
because implementing it would falsify receipt semantics, not because the
campaign needed broader machinery.

## Category assessment and next campaign

This remains a useful runtime component. Exact local qualification and
activation make the component substantially less nominal, but they do not
establish a separate product plane, independent attestation, deployment
viability, or multi-host custody. A successful demo does not change that
judgment.

The single most defensible next campaign is a bounded two-host transport and
observation-custody canary that carries the exact qualified generation,
activation occurrence, pulse provenance, receiver annotation, and refusal
semantics across one authenticated receiver boundary. It should test loss,
replay, endpoint restart, identity substitution, and bounded queue failure
without beginning distributed consensus, general telemetry ingestion,
remediation, or platform integration.
