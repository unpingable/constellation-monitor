# Working in Constellation Monitor

Monitor owns bounded discovery and consumer-indexed present reliance. Pulse
owns the repository's evidence records, receiver custody, freshness, and replay
mechanics. Do not collapse these into NQ diagnostic judgment, Nightshift
consequence handling, Docket mutation, or action authorization.

Preserve existing crate names, binary names, wire schemas, and protocol
identities. Prefer the smallest relevant command from `HOWTO.md`; inspect
source-defined usage before documenting flags.
Do not add a generic execution or provider framework to connect components.

Discovery output is not acquired evidence. Signed evidence is not receiver
custody. Custody is not currentness. Current support is scoped, expires, and
does not authorize action. Tool availability and transport locators are not an
authority boundary.

For an existing campaign, inspect its durable checkpoint, exact producer
identity, journal/log advancement, artifacts, and terminal record before doing
new work. Resume supervision of the original producer when possible. Do not
restart, duplicate, or replace it based only on supervisor loss. If state cannot
be reconciled, preserve the evidence and use the campaign's indeterminate
fallback.

For code changes, the repository's standard checks are:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
```

Documentation-only work may use lightweight source and diff checks without a
build. Never claim an unrun check passed.

Public changes must not include credentials, private endpoints, operational
inventories, private campaign records, or consumer-specific private material.
Pulse remains a hosted subsystem of this repository; do not split it into a
separate product repository.
