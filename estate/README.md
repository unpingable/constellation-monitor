# Estate supervision

Constellation's operational promise for a host, in four parts:

1. Know which services it is responsible for: `estate.<host>.json`, the estate
   registry. A service missing from it is unsupervised.
2. Know whether each one is doing its job: `constellation-estate-collect.py`
   combines runtime state (systemd or Docker) with the project's own status
   contract. That contract is the `.ops/observation.toml` producer emitting
   `project.ops.status/v1`, a Labelwatch-recent watcher report, or an HTTP
   probe. A required concern that is not `PRESENT` makes the service
   `DEGRADED`, including a missing observation. A container that Docker calls
   healthy is not thereby doing its job.
3. Fix what it is authorized to fix: the remediation consumer (unchanged here).
4. Say when it cannot: the attention evaluator reads `[inputs.estate]`. Its
   `service-not-doing-its-job` rule sends a Slack notice after 600 s, giving the
   service's own reason. The daily digest restates every open condition and
   every declared pause.

A deliberate pause is declared in the registry (`"declared": {"state":
"paused", "since", "reason"}`). The service then shows as `PAUSED`: never an
alert, always visible on the dashboard and in the digest.

Install on the host:

    install -D -m 0755 constellation-estate-collect.py /usr/local/lib/constellation-estate/constellation-estate-collect.py
    install -D -m 0644 estate.labelwatch-host.json /etc/constellation-estate/estate.json
    install -m 0644 constellation-estate-collect.{service,timer} /etc/systemd/system/
    systemctl daemon-reload && systemctl enable --now constellation-estate-collect.timer
    # attention.toml:  [inputs.estate]  path = "/var/lib/constellation-estate/estate.json"
