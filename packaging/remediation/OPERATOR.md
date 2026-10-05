# Constellation installed remediation

The prepared combined candidate targets Ubuntu 22.04 amd64. Use its source-free
[operator guide](https://github.com/unpingable/unpingable-site/blob/dev/operator-beta/constellation/combined-candidate/README.md) for download verification, exact package installation,
separate enrollment, Workbench, currentness and day-two recovery. It is a neutral
owner-review candidate; BC1 is not tagged or published. Component source alone
does not install the composed product or grant authority.

Deterministic v1 is the reference/default remediation policy. Explicit observation,
AG/Docket/executor enrollment and a finite exact-target grant must precede timer
activation. Package installation activates none of them.

Optional agentic v2 uses LA for finite inference expenditure, reservation/send
fence and settlement/reconciliation. AG/Docket remain the effect boundary, and
fresh observation decides recovery. No model credential or budget ships. See
`model-decider.conf` for the optional service override, not default activation.

Use `constellation-remediation-consumer --version` and `--check-config` with the
existing owner-selected config. Inspect its journal, exact AG/Docket outcome
and current observation. Stop `constellation-remediation-consumer.timer` and
`.service` before upgrade/removal. Preserve state/grants and reconcile pending
attempts; retries and restarts cannot widen or renew authority.
