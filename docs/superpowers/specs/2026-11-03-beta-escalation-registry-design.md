# Attention escalation registry export

The installed NQ policy must be checked against the notification tuples this
attention build can produce. Add `constellation-attention escalation-registry`
to print NQ's strict `nq.escalation_registry.v1` shape without configuration,
database access, subprocesses or secrets. This is a description, not an
authorization or a policy change.

Derive one anchor from every compiled `registry::RULES` entry, including
disabled entries. Preserve each rule's actual component. For the evaluator
input-fault rule, derive the possible components from the existing input kinds,
sharing their component mapping with the runtime input reports. Page rules can
also emit attention-class notices after downgrade or removal, so export both
classes; other rules export attention only. Keep the output deterministic.

The legacy NQ anchor mirror includes historical identities without current
producers, so it is not the export source. Exporting only configured rules would
miss disabled page capabilities. Neither alternative satisfies this interface.

Scope is Monitor `3d7396d`, checked against NQ `2c1749f`'s strict registry
reader. NQ still validates installed policy, tuples and page route delivery.
Existing evaluation behavior and policy digests remain unchanged. Practical
tests of the finite registry, CLI refusal and NQ consumer suffice for this
bounded serialization claim; the root integration owner owns acceptance.
