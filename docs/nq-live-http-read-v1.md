# Boot-enrolled controller HTTP read v1

Monitor's ordinary `scripts/nq_live_http_read.py` installs as
`/usr/bin/constellation-nq-live-http-reader`. It queries native NQ committed
evaluation and exact observation custody; it does not send HTTP traffic,
collect, reevaluate, enroll, authorize or remediate. Its output is
`monitor.live-http-read/v1`, separate from the systemd-v3 AG resolver and
separate from Workbench's cross-component composition wrapper.

```sh
constellation-nq-live-http-reader --inspect \
  --settings /etc/constellation/http-reliance.json \
  --config /etc/nq/ops.toml --nq-program /usr/bin/nq
```

The closed settings schema `monitor.http-reliance-settings/v1` includes:

```text
schema, instance_id, profile_digest, subject, scope, vantage,
observer_machine_id, observer_boot_id, service_subject, threshold_policy
```

`scope` and `vantage` are the exact native `nq.http_endpoint` version-1 values.
The controller-vantage identity is
`controller:<32-lowercase-machine-id>:<canonical-current-boot-UUID>`. This is an
explicit enrolled opaque identity allowed by the existing profile; it does not
change that profile or manufacture an acquired `boot_id` absent from HTTP/v1.
Monitor reads current local machine and boot before and after the query and
compares them with that installed enrollment. An observer reboot requires a
fresh explicitly admitted enrollment/configuration; old data cannot be silently
rebound. Target reboot does not itself change controller enrollment.

`service_subject` is the exact normal NQ closed fixture preimage:
`constellation.operator_beta.service_subject.v1`, campaign
`constellation-operator-beta-2026`, a new fixture UUID, exact target machine,
literal `constellation-beta-http-fixture.service`, and its unit-file digest.
The reader recomputes the existing domain-framed service-subject digest and
refuses another subject/unit/domain. It introduces no arbitrary HTTP subject
compiler or profile extension. The profile digest is pinned by installed
settings and must match native evaluation and export. Native
`threshold_policy` ID/string-version/digest is pinned separately so changed
external postcondition meaning refuses rather than becoming the same result.
The full actual NQ policy remains in its normal owner enrollment/configuration
custody; an identity alone is not its content or a grant.

The newest evaluation for the enrolled instance comes from a complete frozen
300-record `nq.evaluation_history.v1` window. Its exact subject, scope, vantage,
profile and threshold-policy identity must match installation. Its single
existing detector reference is joined against the ordinary
`nq --json observations export --reference FILE` output, including report ID,
sequence, digest, ordinal and time, exact native profile/binding and payload
vantage/endpoint/request/basis. This is a read, never acquisition.

Present reliance expires exclusively at
`min(source_observation_time, evaluation_time) + 60000ms`. Fresh evaluation does
not refresh source evidence. Future, malformed or mismatched input refuses;
old observer enrollment is stale; missing evaluation is absent; native
`cannot_evaluate` remains unsupported. NQ owns the HTTP postcondition decision:
`explicitly_absent` supports the exact native HTTP postcondition, `present`
contradicts it. No process/unit presence, status code alone, service outage,
effect causation or general application health is inferred.

The output retains the native evaluation and observation export, exact current
observer, read time, frozen sequence, judgement, structured witness and its
compact sorted-JSON SHA-256. This witness hash is byte correspondence under this
owner serialization, not authentication, authority or the AG/JCS witness wire.
It is not substituted into an AG basis. Transport/read failure exits nonzero,
with no success record. Each native query clears ambient environment, has a
five-second deadline and 2 MiB file/output ceiling. Only the same exact
owner-only temporary reference inode/device/single-link file is retired; custody
uncertainty refuses and retains it. No arbitrary path or command is supplied by
a Workbench client.

Focused verification command:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s scripts -p 'test_nq_live_http_read.py' -v
```

Eight cases cover current/contradictory/indeterminate native outcomes, exclusive
source-age expiry and reevaluation, observer reboot/transition, exact bindings,
missing custody, closed fixture/settings, frozen-window movement/duplicate
records, and read-only query/temporary-file cleanup. Actual installed VM and
browser qualification belongs to the enclosing lane receipts; these focused
cases do not establish an acquired live HTTP response.

Formalization consideration: source basis Monitor
`bd6504454a629a21511669f50a0a912665e40194`, NQ
`7f74dd94c7aa997645e25050dafef80c0fec28ff`, and existing closed HTTP/v1 contracts.
Decision owner is the primary live-ECAD integrator. Proposition: under honest
installed NQ custody and boot-enrolled controller identity, current support
requires exact evaluation/reference/export bindings and both ages below the
exclusive 60-second boundary; it grants no effects. Focused finite boundary
cases and an independently observed live cohort exercise are chosen instead of
a broader distributed-time model. Assumptions include correct local kernel and
machine identity, trusted fixed NQ executable/settings, native custody
verification and clock correspondence. Unknowns/counterexamples include lying
source commands, VM snapshot identity reuse, unqualified clock changes, changed
policy content behind a dishonest digest, and a caller replacing the normal
reader with direct fabricated inputs. Cross-host transport, independent
remediation verification and authority consumption require their own evidence.

## Native fractional timestamps on Ubuntu 22.04

The current-forward live cohort exposed a reader portability defect: its native
NQ observation `2026-10-04T19:12:48.755624919Z` had nine fractional digits, while
the initial age parser delegated the full value to `datetime.fromisoformat`.
Host Python 3.12 accepted that value; Ubuntu Python 3.10 refused it. The initial
live `source_or_evaluation_timestamp_invalid` result is retained independently.

The parser now accepts the finite native uppercase RFC3339 spelling, validates
the calendar and explicit UTC/numeric offset at whole-second precision, parses
one through nine fractional digits separately, and retains their exact integer
nanoseconds. Milliseconds are the integer floor of that exact time. It uses no
floating-point timestamp, fraction truncation by a runtime parser, or tolerance
interval. Missing offset, invalid calendar/offset/seconds, more than nine
fractional digits, negative Unix time, and trailing text refuse. Leap-second
spelling remains unsupported as in the initial Python parser. Existing native
versus evaluation-millisecond reference joins, exclusive age boundary, profile
bindings, observer enrollment, and refusal semantics remain unchanged.

Formalization consideration: source start
`f586cb829ad3155e931648ae6333f24ae87428b2`; the proposition is that the accepted
native timestamp denotes the same exact integer nanoseconds on Python 3.10 and
3.12, and millisecond projection is floor division by one million. Fixed exact
native/offset vectors, invalid-input controls, a real nine-digit source sample,
and both runtimes suffice for this bounded parser; no distributed clock or leap
second model is added. Source and result hashes are retained in the enclosing
lane receipts. The installed reference reader was not modified during testing.

All 11 focused tests pass on host Python 3.12 and the admitted immutable Ubuntu
22.04 image running Python 3.10.12. The latter uses an offline disposable container
with only the reader/test files mounted read-only, a 256 MiB memory ceiling,
32-process ceiling, and 16 MiB temporary filesystem. These results establish
runtime portability and the exact join regression; the successor installed
live cohort baseline remains separate qualification.
