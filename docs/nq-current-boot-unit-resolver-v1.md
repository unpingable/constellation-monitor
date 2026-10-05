# Current-boot systemd v3 present reliance

The ordinary Monitor binary `constellation-nq-boot-unit-resolver` reads exact NQ
custody and decides one bounded present-reliance claim. It is a separately named
consumer. Existing `constellation-nq-unit-resolver`, systemd-v2 basis identities,
settings, judgement law, tests and optional model consumer remain unchanged.
The new interface is source work pending the enclosing lane's exact build,
qualification and independent acceptance; presence here is not qualification.

## Owned proposition

One enrolled logical machine/unit has NQ system-manager evidence acquired in the
same boot as this Monitor read. Both its source observation and its detector
evaluation are strictly less than 60,000 milliseconds old at resolution. For
`--claim not-active`, the current detector supports required unit state other
than loaded/active. For `--claim active`, it supports loaded/active. These are
independent precondition/postcondition bases. Neither asserts HTTP response,
application health, outage, cause, effect attribution or authority to restart.

The exact compiled source is `nq.systemd_unit` version **3**, descriptor digest:

```text
sha256:25fbbdd320248701b79b3e5f6c3109667b6aa9388ed113678ee0e6ba3c04a853
```

The scope is `nq.systemd_unit_scope.v3`; its subject is stable
`systemd-unit:<machine-id>/<unit>`. Enrollment and basis identity bind the logical
machine/unit, instance and profile descriptor; they do not pin an old boot.
Boot is per-acquisition testimony that the reliance consumer compares with
current local boot, read from `/proc/sys/kernel/random/boot_id` before and after
its bounded native queries. Unreadable/malformed current boot fails the read;
a changed boot refuses the judgement. A valid observation from another boot is
stale. No clock/currentness law from retired M2 support is reused.

## Normal owner read commands

```sh
constellation-nq-boot-unit-resolver \
  --config /etc/nq/ops.toml --instance-id enrolled-unit \
  --machine-id EXACT32LOWERHEX --unit example.service \
  --resolver-id installed-monitor-unit --inspect
```

`--nq-program` selects the separately installed, trusted native NQ executable.
`--profile-digest` is optional and refuses any value different from the exact
compiled descriptor above. Source execution clears ambient environment and uses
the existing bounded NQ read process helper (five-second per-query deadline,
finite frozen window, at most 16 MiB per evaluation page, 1 MiB export).
Installed wrapper argv, executable hash and source/build standing must be
retained by the deployment owner. An executable path alone is not authentication
or proof of read-only behavior.

`--print-basis` requires only machine/unit/instance inputs, reads no boot, NQ
configuration, store or evidence, and outputs the typed basis plus its AG
normalized-precondition digest. It does not enroll anything.

Without `--inspect` or `--print-basis`, the command accepts the unchanged
`ag.governed-loop.observation-request/v1` on stdin and outputs exactly
`ag.governed-loop.observation-resolution/v3`. Its basis types are:

- `constellation.remediation.current-boot-systemd-not-active/v1`
- `constellation.remediation.current-boot-systemd-active/v1`

Witness hashing uses the existing AG domain framing under the distinct domain
`constellation.remediation.nq-boot-unit-currentness/v1`. The witness includes
exact frozen evaluation and verified export, both boot reads, evaluation window,
resolution time, profile digest and reliance bound. A witness is provenance,
not authority. AG owns permission, issuance/spend and execution; this program
provides no effects. Existing v2 `ResolutionFields` consumers deliberately do
not accept these new basis types without separately admitted owner work.

## Exact custody join and currentness law

Monitor reads `nq --config CONFIG --json evaluations export` through the existing
frozen, bounded window reader. The newest evaluation for the exact instance
must carry systemd-v3 descriptor, logical subject, local vantage, exact scope
and expected detector condition. Determinate support requires exactly one
five-field existing `DetectorEvidence` reference:

```text
report_id, report_sequence, report_digest, observation_ordinal, observed_at
```

The normal query `nq --config CONFIG --json observations export --reference FILE`
returns `nq.admitted-observation-export/v1`. Monitor joins all five exact fields,
profile ID/string-version/digest, instance, subject/scope/vantage, ordinal and
source timestamp. It compares native payload machine/unit/boot and required
manager states with the detector condition. Custody's
`historical_custody_only` standing remains custody, never present support.
Reference files are owner-only, unique, bounded temporary read inputs. Normal
exit retires only the same exact inode/device/single-link file. Uncertain local
custody retains the file and refuses; it never triggers broad cleanup.

Let `o` be source observation time, `e` evaluation time, and `n` resolution time.
Future or malformed times refuse; the source may not postdate its evaluation.
The expiry is `min(o,e) + 60000`, and `n >= expiry` is stale. A recent
reevaluation of old source evidence cannot change that source expiry. Old boot
is stale regardless of recent evaluation. Missing instance is `absent`;
`cannot_evaluate`/indeterminate detector states are `unsupported`; invalid
profile, subject, custody join, payload or boot transition is `refused`.
Contradicting a well-formed fresh enrolled claim is `contradictory`, not a read
error. These are the existing AG typed status vocabulary, not a new global
lifecycle enum. Native query/transport errors exit nonzero; they do not become
current support. A fresh read of prior evidence performs no collection,
reevaluation, enrollment or refresh.

## Workbench projection interface

`--inspect` emits `monitor.live-unit-read/v1` with owner, logical subject,
instance, current boot, pre-read boot, read time, window sequence, native
evaluation/export, selected claim/basis/judgement, opposite basis/judgement,
currentness digest and witness. Both claim directions refer to the same native
read. ECAD composes these normal owner bytes with other components; Monitor
therefore does not become a cross-component cohort or authority owner.

The judgement contains `status`, typed `reason`, and `fresh_until_unix_ms`.
Reopening Workbench may request a new owner read; it cannot replace source time,
boot or expiry. A selected old-boot artifact is not a current observation even
when its report remains present in the NQ store. Live read success is separate
from claim support and from permission to act.

## Shared vectors and qualification

Exact shared NQ/Monitor consumer fixture:
`operational-contract/fixtures/systemd-unit-v3/observation-export-vectors.v1.json`
SHA-256 `0d432519959d917a727d2da111a801ce1e93c25f4cf6aad6732a0bfe72def7df`.
It is copied byte-for-byte from the owning NQ export fixture, never independently
regenerated. Its eight cases cover current-down, old boot, expiry, wrong subject,
wrong profile, changed evidence reference, malformed boot and future source.

Focused Rust tests also exercise exact expiry boundaries, reevaluation of an old
source, changed/malformed local boot, missing export, payload/detector mismatch,
absent/indeterminate input, separate logical bases and no-acquisition basis read.
The enclosing campaign retains exact commands and results. Until that producer
completes, no Rust build/test pass is asserted by this document.

## Formalization consideration

Source baseline is Monitor `f1003030015070db3bbd66fe7aaf331e847f3fac` and NQ
export/profile fixture above; final source/test identities are in the enclosing
lane receipts. Decision owner: primary current-forward ECAD integrator.
Proposition: under a trusted installed NQ reader and correct local Linux boot
identity, a `current` judgement requires one exact native custody join, same
current boot and both ages below the exclusive 60-second boundary. Distinct
logical pre/postcondition bases remain separate from effect authority.

The finite pure judgement function, eight shared conformance vectors, expiry
boundary controls and live reboot/read campaign are the selected practical
formalization for this bounded consumer. They establish stated cases and actual
source-to-runtime correspondence, not a general distributed-time theorem.
Assumptions include admitted custody/export correctness, canonical timestamps,
trusted kernel boot identity, fixed wrapper/executable, and the AG request clock.
Counterexamples outside this claim include an incorrect NQ reader, host-clock
changes invalidating time correspondence, unauthenticated cross-host reads,
restored VM snapshots reusing identities, a caller substituting current boot
without invoking the normal reader, or model consumers accepting a different
basis law. A small model of acquisition/boot/reevaluation transitions may be
valuable when multiple current consumers adopt this contract; no such broader
model or authority service is introduced here.
