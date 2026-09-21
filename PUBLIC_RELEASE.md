# Public source and provenance

`unpingable/constellation-monitor` is the canonical public source for
Constellation Monitor and its hosted Pulse subsystem. Pulse does not have a
separate product repository.

This repository is a reviewed product-only source cut. The preserved
development repository contains unrelated or non-public material and therefore
was not made public in place. No public release commit is asserted to preserve
that repository's private history.

## Source cut

The initial public tree was derived from:

- source commit: `d741ca74171bcf4ffec910e124aa17f24173dbb7`
- source tree: `7523ef0071b04e656b3e22fe02b607c86a63afa5`
- source-cut manifest: [`SOURCE-PROVENANCE.json`](SOURCE-PROVENANCE.json)

The cut retained Monitor and Pulse Rust source, tests, public schemas,
synthetic fixtures, product documentation, packaging metadata, and public
qualification artifacts. It excluded private reconnaissance, campaign plans
and reports, consumer-specific contract locks and handoffs, machine-specific
operational records, credentials, private endpoints, and unrelated material.
Public-facing documentation and licensing were then added to the cut before
its complete-tree review and qualification.

The mechanical procedure was:

1. export the exact source tree with `git archive`;
2. exclude the categories and exact paths recorded in
   `SOURCE-PROVENANCE.json`;
3. add the public README, operator/interface documentation, license, notices,
   provenance record, and bounded qualification-fixture scheduling repairs
   found while testing the cut;
4. scan the complete tree for excluded path, credential, endpoint, and
   consumer-specific material;
5. run formatting, linting, and all workspace tests;
6. create one public root commit and verify an anonymous clone from that exact
   commit.

Future public changes are ordinary descendants of that public root commit.
The public repository, not a compatibility export in another repository, is
the canonical source for new consumers.

## Compatibility exports

Constellation Nightshift has previously carried pinned Monitor/Pulse source
cuts used by exact qualified compositions. Those files remain historical or
compatibility surfaces for their named consumers. Their provenance documents
must name this repository and the exact source revision. They are not a second
mutable source of truth, and immutable Constellation release manifests are not
retagged or rewritten by this publication.

## License

User-authored material in this source cut is licensed under Apache-2.0. No
third-party source is vendored. Rust dependencies are resolved from the exact
`Cargo.lock` and retain their upstream licenses; see
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
