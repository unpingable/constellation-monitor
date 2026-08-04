# Qualified-generation binding campaign reconnaissance

Status: completed read-only on 2026-08-03 before campaign implementation.

## Exact baseline

The standalone repository was clean on `main` at
`3cd15b7a1e7f424f6fd57c09b30fa4790947eca2`, with no configured remote. Its
history ended with the four local crash-fault milestones:

```text
61257b5 Define local crash-fault custody contract
1d29d1b Implement local crash-fault reactor and journal
693d0cc Qualify crash recovery and reactor failure paths
3cd15b7 Document and artifact crash-fault qualification
```

The baseline passed `cargo fmt`, strict workspace Clippy, and all 97 tests. The
README, architecture, receiver/scheduler contract, crash-fault contract,
campaign-2 and campaign-3 reports, every checked-in qualification/demo artifact,
all `pulse-runtime` public APIs and tests, and the generation/support types were
inspected.

## Existing representation findings

- `RelianceContextV1` names one activation plus reliance-policy generation and
  body digest, consumer-profile generation, evaluator-semantic generation,
  observer-set generation, and observation-policy generation. All except the
  policy body digest are caller-supplied identities.
- `validate_policy_context` binds the exact typed `ReliancePolicyV1` body to its
  policy and observation generations. It does not bind the other generations
  to semantic values, an executable, a qualification result, or a deployed
  artifact set.
- A `CURRENT` `RelianceSupportCertificateV1` names the reliance context but no
  manifest, qualification certificate, activation receipt, executable
  measurement, or certificate lifecycle state.
- Policies enter as owned typed Rust values. Consumer-profile and observer-set
  generations otherwise enter only as identity strings. Observation profile
  identity and observation-policy generation enter both policy and pulse
  records. Runtime configuration is one owned `RuntimeConfigV1`. The evaluator
  implementation is compiled into the process and currently self-identifies
  only through a caller-provided semantic generation.
- Current certificates, hot evidence, schedules, receiver continuity, request
  ownership, and active deduplication remain ephemeral. Historical state and
  the journal contain only sparse records, contradiction custody, and receipts.
  Recovery therefore can retain a prior activation receipt as history without
  making it active.
- `run_until` and the local reactor already preserve generation barriers before
  inclusive expiry. A binding change can use the same barrier without inventing
  a second scheduler or event order.
- On the qualified Linux target, `/proc/self/exe` can be opened and read through
  one stable file handle. The defensible claim is the digest of bytes exposed by
  that opened handle at measurement time. It is not proof of loader, kernel,
  source, build, or host integrity. Invocation path and filesystem metadata are
  provenance, not executable content identity.

No stopping condition was reached. The existing current/history split permits
a fresh, non-serializable activation proof while preserving restart `UNKNOWN`.

## Bounded neighboring precedent

Only previously authorized conceptual surfaces were rechecked. No schema,
source, or authority model was copied.

| project | exact clean commit | inspected paths | retained principle |
|---|---|---|---|
| NQ-NG | `59abd3bcb2d0cc30657a659b3ebc57b981289d9f` | `docs/NORTH_STAR.md` static-profile-cohort section; `diagnostic-contract-v2/README.md` manifest boundary | A cohort seals independent build, evaluator, profile, protocol, qualification, and lifecycle identities. An inner manifest or schema does not establish outer release identity or consumer reliance. |
| Witness | `e3d22f9bef8dc248e58e0fa5b7fa474b2dd78c5d` | commit and cleanliness recheck only, as authorized by prior reconnaissance | Occurrence-local evidence identity does not mint current standing. |
| Nightshift | `500f4b7bd4f066c7ca43963d192f314559cdbc83` | commit and cleanliness recheck only, as authorized by prior reconnaissance | Receiver-owned custody and exact generations do not extend freshness or create authority. |
| Docket | `3ce07f9bb3be6ba86ca65f3b521f807970b56119` | `normative-packet/implementation-plan.md`; `normative-packet/proved-negatives.md` | Identity is distinct from content; exact artifact admission precedes attempt identity; immutable history and a digest alone do not reconstruct reliance or authority. |
| Synesthesia | `d1a731c383d4fce8f9bc21f40b63af5dbae2aa94` | commit and cleanliness recheck only, as authorized by prior reconnaissance | Loss and boundedness remain explicit; presentation cannot define activation law. |

All five neighboring trees were clean before and after the read-only pass. No
neighboring repository was modified.
