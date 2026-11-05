# One bounded engineering build observation

`observe.py` is an optional Python 3.10+ Linux source helper. It observes one
owner-accepted engineering build through the existing
[project concern envelope](../docs/project-concern-contract.md) and
[estate status command](../estate/README.md#status-command-output-contract).
It launches, retries, interrupts and authorizes no work. It adds no service or
timer and changes no existing package. Its current consumer is the ordinary
bounded build workflow owned by the Constellation campaign steward. It is
separate from the interactive [P7 diagnostic](../diagnostic/README.md).

Run on the machine that actually hosts the declared native worker. The caller
must already have read access to its bound source files and `systemctl show`.
Use a separate observer identity from the build worker. A status declaration
grants neither access nor execution authority. Missing access produces explicit
required `UNKNOWN` observations, never empty work or successful output.

```sh
python3 -B /opt/monitor-work-observation/observe.py \
  --binding /etc/constellation-work/job/binding.json \
  --history /var/lib/constellation-work-observer/previous.json
```

These paths are an installation example, not an assertion that this helper has
been installed. The deployment owner installs a pinned source copy in an
optional prefix and creates the observer-owned history directory beforehand.
The current Monitored package is not replaced or bypassed. The existing estate
registry can use that exact argv as `status_command` with its already approved
non-root `status_user` and a timeout exceeding the helper's ten-second reader
deadline. The collector's schedule remains responsible for acquisition and its
normal stale/missing-producer behavior. Route the six named required concerns
through the existing declaration and attention policy; fixture tests do not
prove scheduled collection, notice delivery, recovery or coverage of any site.

## Source binding and custody

The selected binding's directory is the explicit trusted evidence root. The
binding, owner checkpoint, optional admission/launch records, independent
receipt and publication must be root-owned, not group/other writable, without
symlink components, and contained in that directory. The operator must place
this directory outside every worker-writable prefix, with root-controlled
ancestors and read permissions appropriate to the observer. An independently
qualified verifier writes its receipt there, or the steward copies a pinned
receipt there after checking its exact bytes and actual verifier outcome.
The helper does not turn a worker-writable receipt into independent evidence.
Changing these paths or granting custody is an owner operation.

The binding is a small configuration for this checkpoint adapter:

```json
{
  "owner": "/etc/constellation-work/job/OWNER.json",
  "admission": "/etc/constellation-work/job/ADMISSION-RELEASED.json",
  "launch": "/etc/constellation-work/job/LAUNCH.json",
  "verification": "/etc/constellation-work/job/verification.json",
  "publication": "/etc/constellation-work/job/publication.json",
  "boot_id": "THE-RECORDED-ACTUAL-WORKER-BOOT-ID",
  "max_age": 60,
  "progress_budget": 300
}
```

It consumes the existing campaign checkpoint fields, not a new queue or job
protocol. The immutable `OWNER.json` identifies `job_id`, `state`,
`accepted_at_epoch`, `updated_at_epoch`, `deadline_at_epoch`,
`source.commit`, `source.capsule_sha256`, `native_unit`,
`native_source_paths.cargo_messages` and `expected_output.package`.
Its explicit admission object may record `state = BLOCKED` with a reason.
A separate admission record names the same job, `accepted_record_sha256`,
`epoch` and `decision = ADMITTED_AFTER_PREFLIGHT`. Missing admission does not
mean admitted. Neither decision is inferred from load, available memory or a
running process; the observer has no authority to start the work.

The separate `LAUNCH.json` names `job_id`, `unit`, `source_commit`,
`accepted_record_sha256`, timezone-aware `at`, the original `invocation_id`, and `boot_id` captured
at launch. These must match the accepted bytes, pinned boot and actual kernel
boot/systemd InvocationID. Unit name and PID alone cannot establish identity.
An old checkpoint lacking the original boot binding cannot provide this
current identity proof. Historical records are preserved unchanged.
Hash comparisons reuse the exact bytes consumed in this acquisition, rather
than rereading a path that may now name a different checkpoint.

The trusted independent receipt retains the actual verifier's `job_id`,
`source_commit`, `source_capsule_sha256`, `native_producer.InvocationID`,
`verified_at`, `package_sha256`, positive `verified` disposition and nonempty
`scope`. That disposition is trusted only because of the separately established
verifier/custody boundary. The helper also requires the bound native process
to have exited successfully and independently rehashes the actual current
artifact. Native success or a worker boolean supplies no independent result.
The scope is repeated in observation facts; artifact verification establishes
neither task/business success nor installation, release or owner acceptance.

The separate publication names `job_id`, `native_invocation_id`,
`accepted_record_sha256`, `verification_sha256` and `package_sha256`.
It must refer to the exact current trusted receipt and artifact. Publication
cannot repair a failed/missing verification or erase the native outcome.

## Required observations and history

Every invocation emits all six required concerns, with the same stable
metadata as [concerns.toml](concerns.toml). The shared envelope is unchanged;
adapter replay material lives only below `extensions`.

| Concern | Bounded observation |
| --- | --- |
| `work.obligation` | Explicit accepted obligation, or fresh explicit `no_assigned_work`. A missing/stale source is unknown. The observer never discharges an obligation. |
| `work.admission` | Owner-declared resource hold, explicit admission, or unknown. A visible legitimate hold satisfies decision visibility. |
| `work.worker` | Accepted but not started, original worker running, native success/failure, missing bound worker, unresponsive worker, or unknown identity. |
| `work.progress` | No observed breach of the authored progress budget. Underlying append advancement can remain unknown inside the budget. |
| `work.outcome` | Independent artifact support when due or explicitly claimed. Before then the independent outcome remains explicitly unknown. |
| `work.publication` | Exact publication when due or already claimed. Missing publication before the fixed deadline is not a breach. |

These are conditional required duties. Existing estate/Attention consumes
`local_state` and `reason`, so intermediate absence is not encoded as a failed
service. A valid first running capture within the original launch's progress
budget has progress domain `UNKNOWN`, local `PRESENT` for the unbreached duty,
and a reason explicitly saying that advancement is unknown. The same initial
launch rule applies when persisted history contains the same accepted but not
started worker, with no prior invocation or Cargo baseline. It does not grant a
new grace period to a replaced worker or a rewritten stream. Missing/invalid
progress source remains local `UNKNOWN`. Native success with independent
verification still pending before the fixed deadline has domain
`NATIVE_SUCCESS_OUTCOME_UNKNOWN`, local `PRESENT` for the not-yet-due duty,
and an explicit unknown-outcome reason. This does not label the artifact
verified or the task successful.

The optional root-custodied owner field `completion_claimed = true` can record
an explicit completed-task claim already present at acceptance. After admission
or launch, preserve those accepted OWNER bytes: their hash is bound by both
records. A later claim belongs in a separate root-custodied checkpoint selected
by optional binding key `completion_claim`, for example:

```json
{
  "job_id": "THE-ORIGINAL-JOB",
  "completion_claimed": true,
  "accepted_record_sha256": "SHA256-OF-UNCHANGED-OWNER-BYTES",
  "source_commit": "ORIGINAL-40-HEX-COMMIT",
  "source_capsule_sha256": "ORIGINAL-64-HEX-CAPSULE-HASH",
  "native_invocation_id": "ORIGINAL-32-HEX-INVOCATION",
  "boot_id": "ORIGINAL-WORKER-BOOT-ID",
  "at": "2026-11-05T10:00:00+00:00"
}
```

The claim time must be between the original launch and current acquisition.
It is a persistent assertion for those exact identities, so its age alone does
not expire it. Create the checkpoint before selecting its path in the binding.
A selected missing, malformed, stale-before-launch, future, wrongly bound or
worker-controlled checkpoint makes the outcome observation `UNKNOWN` while
preserving independently known obligation and native worker facts. Omit the
binding key when no later assertion is selected; removing selected input cannot
silently restore a healthy pending duty. The current consumer of this optional
input is the Constellation qualification workflow, not a cross-project job
protocol. Keep a separate binding, trusted directory and observer history for
each worker. A result for one worker never supplies another worker's support.

A valid completion claim without independent support breaches `work.outcome`
immediately, even before the original fixed deadline. It supplies no verifier,
publication, owner acceptance, settlement or discharge authority. An existing
publication that does not name the exact independent result breaches
`work.publication`; ordinary absent publication is due only at the original
fixed deadline. Lost/failed workers, measured stale progress and overdue
unsettled results remain failures. Missing source/identity remains unknown.
Recovery and history-cache replacement never move the owner's deadline.

The first capture cannot prove advancement. Later captures compare the original
job/source/boot/unit/InvocationID, prior complete-byte prefix hash and actual
compiler-artifact count. Rewrite, shrink, counter reset, identity substitution,
missing source and a comparison gap over one hour cannot prove progress.
Incomplete final Cargo lines are ignored; malformed complete records are input
faults. Unit active state, PID, filename, file mtime and a fresh reader clock
never prove progress. No additional compiler artifacts inside an unexpired
budget leaves underlying progress unknown while the conditional duty is not
breached. Once a comparable stream exceeds the budget since the
first baseline or last actual observed append, it is `STALE_PROGRESS`.
Non-compiler phases require their own meaningful source before this helper can
claim their progress; it does not infer that a quiet build is stuck.

`--history` changes only its own bounded observational cache. Its parent must
already be owned by the invoking observer and not writable by group/other.
An exclusive mode-0600 lock prevents overlapping writers; a mode-0600 temporary
file is fsynced and atomically replaces the prior capture. The cache establishes
no outcome, custody, owner decision or authority. Worker write access to this
cache invalidates the observation trust assumptions. A corrupt/unavailable
cache yields unknown; it does not refresh progress or create a result.
For externally retained captures, `--previous PATH` reads one prior
observer-owned capture without writing it. Without either option the helper is
fully stateless and cannot establish advancement.

Each concern has producer observation time and a validity duration; the default
source-age limit is 60 seconds (configured 1–300). Reader time is acquisition
time, never a substitute for actual worker advancement. Facts retain source
paths/IDs, SHA-256, byte counts, acquisition times, available original source
times, worker binding, native state, progress counts and verifier scope. Owner
acceptance/admission and a verified immutable receipt do not expire merely
because their record time is old; current reads/native identity/artifact hash
are checked again. Explicit no-work source must itself be fresh. Source loss
or collector disappearance leaves required observations unknown/stale; it
never settles the owner's obligation.

JSON/checkpoint/cache files are capped at 1 MiB; Cargo at 16 MiB and 20,000
complete records; the current artifact readback at 256 MiB. Each native query
has a three-second timeout, and the dedicated CLI has a ten-second SIGALRM
deadline. It runs in the main Python thread without another alarm user.
Unsupported size, permissions, malformed data and missing identity become
unknown. Exit zero means an observation document, including unknowns, never
healthy work. No source file, native unit, receipt, store or owner checkpoint
is written by the helper.
Only the Cargo read tolerates concurrent append. Artifact, checkpoint, receipt
and history reads require unchanged size/metadata across the read; hashing an
old prefix of a growing artifact cannot qualify the actual current output.

## Native checks and delivered scope

```sh
python3 -B -m unittest discover -s work_observation -v
```

Run this on the admitted Verifier VM, from the source root, using its ordinary
native Python and systemd. The suite creates bounded transient fixture units
and retires those exact units. It requires root for its root-custody fixtures;
the deployed observer itself need not run as root. The source suite exercises
real files, actual systemctl reads, a separate CLI process and the existing
estate document validator and evaluator, including normal pending duties
versus actual deadline and unsupported-completion breaches. All test jobs/Cargo streams are substitution
fixtures, not accepted useful builds or live alert acceptance evidence.

The campaign lane records the exact source/evidence identities and RED/GREEN
logs separately. The state-transition proposition is deliberately finite:
source/identity gaps cannot mint progress or an independently verified result,
and observer loss cannot discharge an obligation. Explicit cases and native
consumer checks suffice for this adapter; they do not prove a distributed
scheduler, a verifier's domain implementation or future workload semantics.
The root steward owns test artifacts and retires owned scratch only after
review and replay dependencies end. Deployment and the real scheduled
collector → evaluation → captured notice → recovery drill remain separate
root-coordinated work.
