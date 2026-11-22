# Duty-scoped host availability

The off-host operator assigns availability duty to a registered host
incarnation for a named workload and an explicit deadline. A registered host
can be online or offline without an assignment. Boot changes update observed
session identity while the assigned duty stays with the same incarnation.
Disappearance and recorded shutdown claims leave outstanding duties open.
An elapsed deadline makes a duty overdue until the operator settles or
transfers it.

## Build and install

Build from the Monitor Git checkout with `dpkg-deb` available. The Debian
package uses Python 3.10 or newer and OpenSSH. `BUILDINFO` records the Git HEAD
and worktree state at build start. A dirty build carries that HEAD as context.
The installed `SHA256SUMS` records the bytes copied into the package, including
its control files. Check it from the top of a `dpkg-deb -R` extraction.

```sh
packaging/host-duty/build-deb.sh 0.1.0 /tmp/host-duty-packages
cd /tmp/host-duty-packages
sha256sum -c constellation-host-duty_0.1.0_all.deb.sha256
sudo apt install ./constellation-host-duty_0.1.0_all.deb
```

Installation creates the `constellation-duty` system account and its mode-0700
state directory, `/var/lib/constellation-host-duty`. Activation and ledger
initialization are explicit operator steps. Keep the ledger, collector timer,
probe configuration, and observer's private SSH identity on the observer.
On a target, the sampler requires its installed command and the site's approved
SSH login. The same package supplies the sampler on Debian-based targets.
Retain the ledger as operator state across removal, purge and upgrades.

## Assignment and disposition

Run these commands on the observer using the dedicated account. Initialize
once for a new observer. Use the existing database when returning to service.
The mode-0600 file is owned by `constellation-duty`. The shell function below
sets the installed executable and ledger path for the examples.

```sh
duty() {
    sudo -u constellation-duty /usr/bin/constellation-host-duty \
        --database /var/lib/constellation-host-duty/ledger.sqlite "$@"
}
duty init
duty register fatbot fatbot-incarnation-a
deadline=$(date -u -d '+1 hour' +%s)
duty assign duty-a build-a fatbot --deadline "$deadline" --reason 'operator assigned build-a'
duty status fatbot --freshness-seconds 60 --grace-seconds 30
duty list --host fatbot
duty events --limit 20
```

A shutdown claim records what was reported and leaves the original
observation time and duty in place. Use `release` when the operator withdraws
an assignment, or select `cancelled` when the operator cancels the work.

```sh
duty observe-claim fatbot fatbot-incarnation-a --reason 'target reported a shutdown'
duty release duty-a released --reason 'operator withdrew the assignment'
```

To attest completion of an outstanding assignment, name the retained evidence
file and pass its SHA-256 with explicit confirmation. The ledger records
`operator_attestation`. Independent verification of a build or workload result
belongs to that workload's verification procedure.

```sh
evidence_sha256=$(sha256sum ./retained-result | cut -d ' ' -f 1)
duty release duty-a completed --reason 'operator accepted the retained result' \
    --confirm-completed --evidence-sha256 "$evidence_sha256"
```

For an outstanding `duty-a`, register the receiving incarnation first. Transfer
settles the old assignment and creates the successor for the same workload in
one transaction. Replace a host incarnation only after settling or transferring
all its duties. The new incarnation starts without a current observation and
requires a fresh explicit assignment to take on duty. Historical records remain
in the ledger. Update the probe
configuration to match the new incarnation and its identity pins before
resuming collection for that host.

```sh
duty register gojira gojira-incarnation-a
duty transfer duty-a duty-b gojira --deadline "$deadline" --reason 'operator moved build-a'
duty replace fatbot fatbot-incarnation-b --reason 'operator registered the replacement'
```

## Configure and supervise the observer

Start with `/usr/share/constellation-host-duty/probes.example.json`. Replace the
example incarnation, documentation IP address, SSH user and paths, and all-zero
machine digest with the exact approved target and observer identities. Use the
same numeric endpoint and port in the TCP fields and fixed SSH argv. Obtain
the expected machine digest and SSH host key through the approved target access
path. On the target, the following command prints the digest as
`machine_identity_sha256` in the sample.

```sh
/usr/bin/constellation-host-sample --nonce "$(printf '%064d' 0)"
```

Place the dedicated observer identity and pinned `known_hosts` under
`/var/lib/constellation-host-duty`, readable by `constellation-duty`. Protect
the private identity with mode 0600. The service's `ProtectHome` requires
paths outside home directories. Use the approved SSH identity lifecycle and
target login authorized for sampling. The example enables strict host-key
checking, uses the dedicated key directly, and disables agent use and forwarding.
The collector appends `--nonce` and a new random value to the fixed sampler argv.
The sample must echo the nonce and match the pinned machine digest. The sampler
returns boot identity and basic CPU, memory, swap, uptime and root filesystem
telemetry. These are bounded external observations of the target and path.

Copy the reviewed configuration as an owner-only regular file. The total of all
target timeouts must fit the 30-second acquisition budget. The pass uses a shared
monotonic deadline and the systemd oneshot has a 45-second startup timeout.
An unreachable TCP endpoint is an observation from this observer. A reachable
endpoint with a missing or invalid sample gives unknown presence. A skipped or
refused observation leaves the previous source time to age.
Local acquisition failures, such as exhausted file descriptors or a denied
socket, also give unknown presence; they do not establish target unreachability.

```sh
sudo install -o constellation-duty -g constellation-duty -m 0600 \
    ./probes.json /etc/constellation-host-duty/probes.json
sudo -u constellation-duty /usr/bin/constellation-host-duty collect \
    --config /etc/constellation-host-duty/probes.json
sudo systemctl enable --now constellation-host-duty.timer
systemctl status constellation-host-duty.timer
systemctl show constellation-host-duty.service -p Result -p ExecMainStatus -p ExecMainExitTimestamp
journalctl -u constellation-host-duty.service -n 20
```

The timer starts about 10 seconds after boot or when armed after that deadline,
then schedules a pass 15 seconds after each completed service run. The
supervised runtime is the active **timer**. A successful **oneshot service**
returns to inactive between runs. Use its exit result, the last completion
time, and the per-target status together. Pass success means the collector
returned results, which can include unknown or refused observations.

## Estate declarations and alert response

Adapt `/usr/share/constellation-host-duty/estate.example.toml` in the existing
deployment inventory. Its status argv runs the installed CLI as
`constellation-duty` against the observer's absolute database path. Set
`contract.sha256` to `sha256:` followed by the hexadecimal digest from
`sha256sum /usr/share/constellation-host-duty/concerns.toml`. For example,
use `sha256:0123...` with the complete 64-character digest. Replace
`first_result_due_at` with the actual activation's first-result deadline in UTC.
Keep the timer result check and `max_success_age_seconds = 90`. Render and pin
the declaration with the estate collector's `--render-registry` flow and use
the approved Attention and incident routes. The Monitor checkout's
`estate/README.md` documents registry rendering and timer evaluation.

The status document uses `project.ops.status/v1` and emits three required
concerns. The defaults are 60 seconds of source freshness and 30 seconds of
grace from assignment. Query time does not extend the life of a reachability
sample. `PRESENT` can mean an unbreached conditional duty, including
`NOT_REQUIRED` when the operator has no outstanding assignment. Consult the
presence facts and reason for the observed condition. Off-duty status carries
no assertion of physical host health.

| Concern | Operator response |
| --- | --- |
| `duty.availability` | After grace, fresh unreachable observations breach the active duty. Check the observer-to-target transport and the registered incarnation. |
| `duty.observation` | After grace, missing, stale or indeterminate observations breach the observation duty. Check the timer, configuration, endpoint, identity pins and sampler. |
| `duty.deadline` | An elapsed deadline breaches an outstanding duty. Inspect the workload and record an explicit operator disposition or transfer if warranted. |

If the ledger is missing, unreadable or corrupt, status reports all three
concerns `UNKNOWN`. Check observer custody and restore the trusted ledger using
the site's recovery procedure. Reconcile later operator decisions before
accepting a recovered ledger as current. Initialization is for new ledgers.

Before adopting a route, observe the scheduled pass and inspect the rendered
estate result. Use a disposable assigned target to confirm a fresh reachability
loss after grace, then a separate collector or sampler gap. Confirm notice
delivery and recovery through the actual route. Check that an idle target can
disappear while its conditional duty remains `NOT_REQUIRED`. This drill tests
the monitoring path. Operator decisions still control assignment and settlement.

Before an upgrade, stop the timer, then stop the service. Pause ledger mutations
and retain the current ledger and exact prior package as rollback inputs.
After installing, verify the package and probe config, check the existing
ledger, then explicitly start the timer again. On removal the package disarms
its timer and retains the ledger, configuration and account. Retire the scoped
SSH identity through its existing lifecycle when sampling ends.
