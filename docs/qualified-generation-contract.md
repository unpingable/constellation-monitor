# Local qualified-generation binding contract

Status: normative for campaign 4. Names and formats remain provisional.

## Owned question and three judgments

This campaign owns one local question:

> Does one named consumer's active reliance context exactly match a locally
> accepted qualification certificate, its exact manifest, and the artifacts
> this process measured and loaded for that context?

It keeps three judgments separate:

```text
declared generation identifier
!= exact artifacts qualified under stated assumptions
!= exact artifacts locally observed and activated by this process occurrence
```

A declared identity, artifact digest, canonical manifest, certificate, prior
receipt, source commit, or passing-test report alone cannot permit `CURRENT`.
Only the closed `QualifiedAndMatched` state produced by a fresh local activation
gate may satisfy the new certificate premise. This remains consumer-indexed;
binding Consumer A neither activates nor transitions Consumer B.

## Canonical encoding law

The manifest, checked qualification report, certificate, lifecycle fact, and
activation receipt use closed Rust structs serialized as canonical JSON bytes.
V1 canonical JSON is exactly the compact UTF-8 byte string emitted by the
version-pinned encoder from a validated value:

- no byte-order mark, insignificant whitespace, or trailing bytes;
- object members in schema declaration order;
- closed lowercase enum spellings and no unknown members;
- no generic maps in an identity-bearing schema;
- arrays sorted and duplicate-free where order is not semantic;
- command results ordered by their explicit sequence where order is semantic;
- integers in shortest base-10 form; no floating-point values;
- JSON booleans and `null` only where the schema names them;
- encoder-standard shortest string escaping over valid UTF-8; and
- optional members omitted only where the schema explicitly marks them
  optional.

Decoding is bounded, rejects duplicate or unknown fields, validates semantic
bounds, re-encodes the value, and requires byte-for-byte equality. Reordered
members, alternate whitespace/escaping, and otherwise equivalent JSON are
therefore valid JSON but noncanonical package encodings and are refused. A
digest is SHA-256 over a domain-separated, length-delimited transcript whose
sole payload is the canonical bytes of the appropriate body. Lowercase
`sha256:` is the only V1 algorithm spelling; uppercase, unsupported, empty,
wrong-length, and all-zero values are refused.

SHA-256 is used as content identity under its collision-resistance assumption.
It establishes neither authorship, authority, freshness, qualification,
malware absence, nor runtime activation.

## Artifact manifest

`QualifiedArtifactManifestV1` is a self-identifying envelope around one
`ArtifactManifestBodyV1`. Its exact bounded artifact roles are:

1. `running_executable` — bytes exposed through the runtime's stable executable
   measurement handle;
2. `evaluator_implementation` — the exact embedded evaluator semantic artifact
   observed by the runtime, not a claim that source describes binary behavior;
3. `reliance_policy` — canonical bytes of the exact owned policy value;
4. `consumer_profile` — canonical bytes of the exact owned consumer premise
   profile value;
5. `observer_set` — canonical bytes of the exact required observer/failure-
   domain value;
6. `observation_policy` — canonical bytes of the admitted profile, collection
   generation, and coverage value;
7. `runtime_configuration` — canonical bytes of the load-bearing runtime
   configuration and bounds;
8. `semantic_contracts` — the exact closed contract inventory used by the
   evaluator/runtime boundary;
9. `qualification_corpus` — exact hostile and regression corpus inventory; and
10. `qualification_results` — exact checked machine-readable result artifact.

Every role occurs exactly once. Entries are sorted by closed role tag and bind
one bounded logical name, one normalized relative logical path, media type,
exact byte length, exact content digest, and whether activation must measure
the role. Paths must be nonempty UTF-8 with `/` separators, must not be
absolute, and may contain neither empty, `.` nor `..` components. They are
provenance labels, never path-only identity. Role swapping, duplicate/unknown
roles, missing roles, symbolic-only identities, and unbounded values are
refused.

The body additionally binds the exact subject/consumer generation set (without
the single-use activation occurrence), source commit and tree digest, toolchain
identity, target, build profile, sorted feature set, sorted runtime dependency
identities, semantic contract identities, required platform assumptions,
qualification corpus identities, declared claim identifiers, fixed nonclaims,
supersession references, and the locally configured lifecycle-authority
identity. Every field has one of four purposes: establish active semantic
identity, bind qualification evidence, make an assumption explicit, or prevent
authority/claim broadening.

Source, toolchain, feature, target, and build fields say what the qualification
package names. Unless separate evidence earns it, they do not prove
source-to-binary correspondence, reproducibility, compiler correctness, or
toolchain trust.

## Qualification certificate

`QualificationCertificateV1` is a self-identifying envelope around one exact
manifest digest and a checked `QualificationEvidenceReportV1`. The report
binds the same manifest and artifact inventory, exact qualification commands
and argument vectors, exit status and output digests, exact test totals, corpus
digests, hostile scenario identifiers, earned claim identifiers, and
nonclaims. It contains no executable command authority.

Issuance verifies rather than copies:

- manifest and report canonical identities;
- exact manifest/report artifact inventory equality;
- exact source/build/contract identities;
- every required command is present once and reports exit status zero;
- reported test totals meet the certificate's exact checked total;
- corpus and hostile identifiers are bounded, sorted, and exact; and
- every certificate claim is present in both the manifest declaration and the
  checked report. A certificate cannot add or generalize a report claim.

The certificate records an issuance identity and `local_unsigned_exact_bytes`
provenance. It has no signature in V1. This avoids implying signer
authorization, public-key infrastructure, organizational approval, or a
trustworthy issuing environment. An accepted certificate proves only that the
local verifier found its exact bounded package internally consistent and that
the deployment's explicit local acceptance policy names its exact digest.

## Activation receipt and executable measurement

Activation always performs a new local check. It does not deserialize an
accepted token. The gate:

```text
bounded canonical manifest decode and identity check
-> bounded canonical certificate decode and evidence consistency check
-> exact local acceptance/lifecycle-policy check
-> stable `/proc/self/exe` handle open and bounded byte measurement
-> canonical measurement of each owned active semantic value
-> exact role-by-role comparison
-> canonical activation receipt
-> non-serializable accepted activation only on exact match
```

On Linux V1 opens `/proc/self/exe`, requires a regular file, retains the opened
handle for the accepted activation, reads at most the declared executable
bound, and records the digest, byte count, device/inode provenance, and
`/proc/self/exe` link label. The content identity is the bytes exposed by that
opened handle. The invocation path, symlink text, inode, mode, timestamps, and
other metadata do not contribute to content identity. Rename, replacement, or
unlink of the invocation pathname does not substitute another object through
the retained handle. This does not prove which bytes the kernel executed,
loader correctness, immutable mappings, host integrity, or independence.
Measurement unavailability or ambiguity refuses activation.

Within one process, an exact executable content measurement may be reused only
when a newly opened `/proc/self/exe` handle has the same device, inode, length,
modification time, and change time as the cached opened object. Every accepted
activation retains its own handle. Point-of-positive-use revalidation compares
that retained handle's metadata; any ordinary metadata change triggers a full
bounded reread and digest comparison. This optimization assumes ordinary Linux
filesystem metadata semantics. Undetectable raw-device mutation, kernel
misreporting, and hostile host control remain explicit host-integrity
nonclaims.

Policy, consumer-profile, observer-set, observation-policy, and configuration
values are canonicalized from the exact owned Rust values the runtime stores.
They are not digests of debug output, map iteration order, memory layout,
filesystem metadata, or a caller's generation label. The evaluator semantic
and contract artifacts are exact embedded bytes observed from the running
build. The receipt marks each source and whether any value was merely supplied
by a caller. Any required caller-asserted-only measurement refuses acceptance.

`ActivationReceiptV1` binds certificate and manifest digests; every measured
role; process id; Linux boot/process-start provenance; a fresh process-local
activation occurrence; receiver incarnation and clock identity; runtime
version and target; exact result state and mismatch reasons; completeness;
mutability posture; and structural no-continuation, no-diagnostic-execution,
no-deployment, no-signing, no-revocation, and no-mutation authority. It is local
self-measurement, not independent attestation.

## Runtime binding state

The closed V1 states are:

```text
Unbound
BindingPending
QualifiedAndMatched
MissingCertificate
UnsupportedCertificate
ManifestMismatch
ExecutableMismatch
EvaluatorMismatch
PolicyMismatch
ProfileMismatch
ObserverSetMismatch
ObservationPolicyMismatch
ConfigurationMismatch
ContractMismatch
QualificationEvidenceMissing
Superseded
Revoked
MutableAfterActivation
MeasurementUnavailable
Ambiguous
```

Only `QualifiedAndMatched` may satisfy the binding premise for `CURRENT`.
Every other state produces or preserves an explicit non-positive certificate,
cancels positive deadlines for the affected consumer, and emits a sparse
binding transition/refusal. A binding failure is not monitor blindness and a
timer/journal failure is not a binding failure; the classes remain distinct.

An accepted activation is a non-serializable, non-cloneable capability held by
one live consumer state. It names the exact manifest, certificate, activation
receipt, generation set, measured artifacts, and process occurrence. The
runtime independently recomputes policy/configuration identities at the point
of use. A generation label, package object, or serialized receipt cannot
construct this capability.

## Support-certificate law

Every support certificate gains an optional exact
`QualifiedGenerationBindingV1`. A `CURRENT` certificate requires it and binds:

- exact manifest digest;
- exact qualification-certificate digest;
- exact activation-receipt digest;
- exact process/activation occurrence; and
- the same generation set as `RelianceContextV1`.

The binding is included in the support-certificate identity transcript.
Non-positive certificates may name a failed receipt for explanation but carry
no accepted binding. Equal content under a new generation still crosses the
existing barrier and requires a newly qualified manifest/certificate if the
generation set changed, followed by a new activation receipt and explicit
evidence evaluation. Rollback and ABA cannot reuse a prior support certificate
or accepted activation.

## Change and mutability law

Owned typed values become private immutable runtime values after activation.
Any API transition that supplies a changed policy, profile, observer set,
observation policy, configuration, semantic contract, or generation must first
install a new exact accepted binding. Otherwise the barrier withdraws standing
and the subsequent evaluation remains `UNKNOWN` with a binding mismatch.

The accepted executable retains its measurement handle. The runtime checks
that handle before issuing any new positive certificate. A changed or
unreadable object invalidates the binding. V1 does not watch unrelated paths
because path replacement is not active-object replacement. Runtime code-page
mutation outside this owned interface is a host-integrity nonclaim.

## Local supersession and revocation

V1 has no global revocation authority. The manifest and local acceptance
policy name one exact local lifecycle-authority identity. A bounded canonical
`GenerationLifecycleFactV1` binds that authority, one exact certificate,
monotonic fact sequence, reason, and either:

- `superseded` with an exact successor manifest/certificate reference; or
- `revoked` with no successor authority implied.

The runtime accepts a fact only when the configured authority and target
certificate match exactly. Signature validity is not implemented or implied.
Unknown lifecycle status refuses new activation. V1 deliberately does not
support a pinned-consumer exception: both an accepted supersession and an
accepted revocation prevent new activation and withdraw a continuing positive
certificate. Historical manifests, certificates, receipts, and support events
remain valid statements about their past occurrence; they do not activate the
successor. Revocation authority is only the configured local policy boundary,
not organizational or global authority.

## Restart and crash law

The crash-fault law is unchanged. After restart:

```text
runtime binding state = Unbound
current standing = UNKNOWN
supporting evidence = 0
active deadlines = 0
active escalation authority = none
```

Historical manifests, certificates, receipts, failures, contradictions, and
diagnostic receipts may remain in the journal or artifact directory. The
accepted activation capability, opened executable handle, active binding,
support, deadline, and lifecycle lease are never serialized. A new process
occurrence must reopen and measure its executable, canonicalize its active
values, verify the accepted package and current local lifecycle policy, emit a
new receipt, and then receive fresh evidence before `CURRENT` is possible.

Crash before measurement, during measurement, before/after receipt journaling,
after activation but before evidence, while `CURRENT`, or after mismatch cannot
reconstruct activation from history. A prior receipt replay has the wrong
activation occurrence and lacks the live accepted capability.

Because the record is called an activation receipt, V1 commits the ephemeral
binding before journaling the receipt. It explicitly refuses to sync a receipt
before activation: a crash in that ordering would leave a durable false claim.
The qualified crash corpus covers both sides of binding commit and every
journal write/sync boundary; the refused receipt-before-activation point is a
recorded negative result rather than a simulated success.

## Authority and exact nonclaims

No manifest, report, certificate, lifecycle fact, activation receipt, accepted
binding, support certificate, sparse record, escalation object, or diagnostic
receipt grants continuation, diagnostic execution, deployment, signing,
revocation, organizational approval, or mutation authority.

This contract does not establish reproducible builds, source-to-binary
correspondence, compiler/toolchain trust, kernel/loader or host integrity,
secure boot, TPM measurement, remote attestation, signer or global certificate
authority, global revocation authority, artifact freshness, supply-chain
security, malware absence, observer truthfulness/independence, complete
coverage, subject health, hard-real-time behavior, physical-media durability,
qualified network transport, production viability, or product-plane status.
