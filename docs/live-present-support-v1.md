# Bounded live present-support export v1

Status: candidate contract, implemented and qualified at the local Pulse
reactor boundary.

## Question and owner

The export answers one question:

> Does this operational receiver presently retain this exact support
> certificate for this exact consumer, subject/scope, reliance context,
> qualified generation, evidence window, and receiver epoch? If so, how much
> receiver-owned lifetime remains?

Pulse owns the answer because the live reactor owns the installed certificate,
the earliest-expiry schedule, and the process-local monotonic clock. The answer
does not establish service health, admit new evidence, qualify a generation,
authorize work, or extend the support certificate.

The request and response schemas are:

- `pulse.live_present_support_request.v1`
- `pulse.live_present_support_response.v1`

Their Rust definitions are re-exported by `pulse-types`. Unknown fields,
unsupported schemas, malformed identities, mismatched digests, noncanonical
JSON, empty frames, and oversized frames are refused.

## Request binding

`LivePresentSupportRequestV1` binds:

- a caller-generated request nonce;
- consumer and exact subject/incarnation/scope;
- the complete `RelianceContextV1` and its identity digest;
- exact support-certificate and evidence-window identities;
- exact qualified-generation identity digest;
- receiver, receiver incarnation, monotonic epoch, and clock identities.

The nonce and request digest bind a response to one outstanding query. They
are identity bindings, not caller authentication or permission to act.

## Response and dispositions

The actor processes due runtime work before evaluating a query. It measures
the answer on its own `std::time::Instant` lineage and returns one of:

| Disposition | Meaning |
| --- | --- |
| `supported_current` | The exact requested certificate is installed and `CURRENT`, every selector and receiver lineage matches, and at least one conservatively rounded millisecond remains. |
| `expired` | The exact certificate is still installed, but no usable interval remains at response measurement. |
| `unsupported` | The operational receiver definitively does not retain the exact requested support. This includes selector, context, generation, evidence-window, or judgment mismatch. |
| `indeterminate` | The actor cannot make a live statement because temporal custody is unavailable. |

Only `supported_current` carries `remaining_lifetime_ms_at_response`. A
one-millisecond source margin removes the possible low rounding from
`Instant::elapsed().as_millis()`. At equality, and when only that rounding
margin remains, the response is `expired`.

Absolute receiver ticks remain provenance only. Another process must not
compare them with its own monotonic or wall clock.

A response from a different receiver incarnation, epoch, or clock lineage
fails caller validation and is treated as indeterminate transport/source
selection, not as a statement that the requested support is absent.

## Caller time rule

The caller records `t_send` on its own monotonic clock before transmitting the
request. After it receives and validates the response, it computes:

```text
usable_remaining =
    remaining_lifetime_ms_at_response
    - elapsed_since_t_send
    - any later local wait
```

Subtraction is saturating. Zero means no current support. The provided local
stream client rounds elapsed time upward to milliseconds. This v1 transport is
qualified only for a local Unix process boundary; it makes no cross-host clock
comparison or remote transport claim.

The source clock is process-local. Receiver restart, clock-lineage change, or
loss of the caller's original timing anchor makes a retained response
unusable. Platform suspend behavior remains part of the receiver clock's
existing semantics; v1 does not translate it into wall time.

## Normative replay rule

Possession, storage, serialization, deserialization, retransmission, or later
observation of a prior `LivePresentSupportResponseV1` does not refresh or
extend its remaining lifetime.

A caller may rely on a response only when:

1. it is the first accepted response for the outstanding nonce;
2. the canonical request digest and every echoed request field match;
3. the response source lineage matches the requested receiver epoch;
4. the exchange completed within the caller's configured bound; and
5. positive remaining lifetime survives subtraction from the original
   `t_send` anchor.

A new answer requires a new query to the live actor. A repeated query is a new
measurement occurrence; it is not a refresh of retained response bytes.

## Reactor and process boundary

`LocalCrashReactor::query_live_present_support` uses a separate bounded query
lane. Query saturation or timeout does not latch Pulse blindness, enqueue a
`RuntimeInputV1`, or otherwise supply new evidence. Before measuring the
answer, the actor applies the same ordinary time-driven transitions it would
apply without a query. An already-due expiry may therefore withdraw support
and append its normal lifecycle record; that is source-owned currentness, not
a mutation requested by the caller.

`query_live_present_support_canonical` is the canonical byte boundary.
On Unix, `serve_live_present_support_stream` and
`query_live_present_support_stream` implement one length-prefixed canonical
exchange over an already connected stream. They impose byte and duration
bounds but create no listener, pathname, daemon, store, retry loop, or server
loop. The embedding owner remains responsible for listener ownership,
pathname permissions, peer identity where required, and connection lifecycle.

Response digests detect field substitution and corruption. They are not
signatures and do not authenticate the endpoint. Authentication is a transport
or deployment property and does not change the read-only response into
authority.

## Nonclaims

- The export is not a health API.
- `CURRENT` is not healthy.
- The response does not grant authority or permission.
- The response does not upgrade qualification or evidence.
- Historical journal or qualification records cannot answer the live query.
- The response is not safe to persist or forward as current support.
- No remote or cross-host transport is qualified by v1.

## Conformance

Machine-readable vectors live in
`artifacts/live-present-support-v1/conformance-vectors.json`. The owning tests
exercise positive bounded support, expiry arithmetic, request/selector
substitution, canonical encoding, replay non-refresh, separate query-lane
failure behavior, and one bounded local Unix-stream exchange.
