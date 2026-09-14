#!/usr/bin/env python3
"""Acquire a disposable queue twice and retain a real four-component attention decision.

Linux, Python 3.10+, cryptography, and explicitly selected Monitor, NQ, Pulse and
Nightshift executables are required. This is an external caller, not a scheduler.
The queue is disposable; observations are real SQLite reads, not saved receipts.
Network delivery is deliberately disabled. All records remain under --root.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import pwd
import selectors
import signal
import sqlite3
import subprocess
import sys
import time


def now():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def canonical(value):
    # This example's signed objects use ASCII keys/strings, integers and bools.
    # It is not a general-purpose replacement for the components' JCS encoder.
    def check(item):
        if isinstance(item, str):
            item.encode("ascii")
        elif isinstance(item, dict):
            for key, part in item.items():
                check(key)
                check(part)
        elif isinstance(item, list):
            for part in item:
                check(part)
        elif item is not None and not isinstance(item, (int, bool)):
            raise ValueError("example canonicalization accepts no floating-point values")
    check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def file_digest(path):
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    with path.open("xb") as stream:
        stream.write(canonical(value))


def observe(database):
    with sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True, timeout=2) as conn:
        depth = conn.execute("SELECT count(*) FROM pending_work").fetchone()[0]
    return {"facts": {"queue": {"depth": depth}}, "observed_at": now()}


def producer(database):
    observation = observe(database)
    return {
        "schema": "project.ops.status/v1", "project": "local-queue-demo",
        "generated_at": observation["observed_at"],
        "manifest": {"schema": "project.concerns/v1", "path": ".ops/concerns.toml"},
        "producer": {"id": "local-queue.primary"}, "authority": {},
        "concerns": [{
            "id": "queue.needs-attention", "question": "queue.depth-at-least-18/v1",
            "profile": "queue.depth-high/v1", "required": True,
            "description": "Is the observed queue depth at least eighteen?",
            "observation": {"observation_present": True, "local_state": "OBSERVED",
                "domain_state": None, "observed_at": observation["observed_at"],
                "valid_for_seconds": 120, "reason": "Read the disposable SQLite queue",
                "facts": observation["facts"]},
        }],
    }


def invoke(root, label, argv, expected=0):
    command = [str(value) for value in argv]
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, cwd=root, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        start_new_session=True)
    output = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + 30
    failure = None
    try:
        with selectors.DefaultSelector() as selector:
            for name, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
                selector.register(pipe, selectors.EVENT_READ, name)
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise RuntimeError("command timed out; no automatic retry")
                for key, _ in selector.select(0.1):
                    block = os.read(key.fileobj.fileno(), 8192)
                    if not block:
                        selector.unregister(key.fileobj)
                    else:
                        output[key.data].extend(block)
                        if len(output[key.data]) > 1024 * 1024:
                            raise RuntimeError("command output exceeded 1 MiB")
        process.wait(timeout=max(0.01, deadline - time.monotonic()))
    except BaseException as error:
        failure = error
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
    finally:
        process.stdout.close()
        process.stderr.close()
    record = {"label": label, "argv": command, "exit_code": process.returncode,
        "supervision_error": type(failure).__name__ if failure else None,
        **{name: value.decode("utf-8", "replace") for name, value in output.items()}}
    with (root / "commands.jsonl").open("a") as stream:
        stream.write(json.dumps(record, sort_keys=True) + "\n")
    if failure is not None:
        raise failure
    if (expected == 0 and process.returncode != 0) or (expected != 0 and process.returncode == 0):
        raise RuntimeError(f"{label}: unexpected exit {process.returncode}; inspect commands.jsonl")
    return json.loads(record["stdout"]) if expected == 0 and record["stdout"].strip() else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--produce", type=Path)
    parser.add_argument("--support-observe", type=Path)
    parser.add_argument("--root", type=Path)
    for component in ("monitor", "nq", "pulse", "nightshift"):
        parser.add_argument("--" + component, type=Path)
    args = parser.parse_args()
    if args.produce or args.support_observe:
        if args.produce and args.support_observe:
            parser.error("choose exactly one observation role")
        print(json.dumps(producer(args.produce) if args.produce else observe(args.support_observe)))
        return
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    if not args.root or not args.root.is_absolute() or not args.root.name.startswith("queue-attention-"):
        parser.error("--root must be an absent absolute queue-attention-* directory")
    for component in ("monitor", "nq", "pulse", "nightshift"):
        path = getattr(args, component)
        if not path or not path.is_absolute() or not path.is_file():
            parser.error(f"--{component} must be an absolute executable path")
    root = args.root
    root.mkdir(mode=0o700)
    project = root / "project"
    (project / ".ops").mkdir(parents=True, mode=0o700)
    database = project / "queue.sqlite"
    with sqlite3.connect(database) as conn:
        conn.execute("CREATE TABLE pending_work(id INTEGER PRIMARY KEY)")
        conn.executemany("INSERT INTO pending_work VALUES(?)", [(i,) for i in range(20)])
    script = Path(__file__).resolve()
    manifest = '''schema = "project.concerns/v1"
project = "local-queue-demo"
[[concerns]]
id = "queue.needs-attention"
question = "queue.depth-at-least-18/v1"
profile = "queue.depth-high/v1"
required = true
description = "Is the observed queue depth at least eighteen?"
'''
    (project / ".ops/concerns.toml").write_text(manifest)
    (project / ".ops/observation.toml").write_text(
        'schema = "project.observation-binding/v1"\nproducer = "local-queue.primary"\n'
        'output_schema = "project.ops.status/v1"\nkind = "exec/v1"\nargv = '
        + json.dumps(["/usr/bin/python3", str(script), "--produce", str(database)]) + '\n')
    inventory = invoke(root, "monitor-acquire", [args.monitor, "collect", project,
        "--trusted-root", root, "--allow-exec", "--json", "--timeout-ms", "5000"])
    require(inventory["acquisition"]["disposition"] == "ACQUIRED_AND_VALIDATED", "Monitor did not acquire valid input")
    write(root / "inventory.json", inventory)
    profile = {"schema": "nq.project-predicate-profile/v1", "id": "local.queue-high/v1",
        "question": "queue.depth-at-least-18/v1", "declaration_profile": "queue.depth-high/v1",
        "subject": {"project": "local-queue-demo", "concern": "queue.needs-attention"},
        "accepted_producers": ["local-queue.primary"],
        "accepted_manifest_digests": [inventory["acquisition"]["manifest_digest"]],
        "input_schema": [{"path": "queue.depth", "type": "u64"}],
        "predicate": {"operator": "compare", "fact": "queue.depth", "comparator": "ge",
            "value": {"type": "u64", "value": 18}}, "max_observation_age_seconds": 120}
    catalog = {"schema": "nq.project-predicate-profile-catalog/v1", "profiles": [profile]}
    write(root / "catalog.json", catalog)
    invoke(root, "nq-admit", [args.nq, "bounded-predicate", "admit", "--inventory", root / "inventory.json",
        "--profiles", root / "catalog.json", "--catalog-digest", digest(catalog), "--concern",
        "queue.needs-attention", "--evaluated-at", now(), "--output", root / "admission.json"])
    # Separate process/source read: it does not consume primary status or receipt.
    support = invoke(root, "independent-source-read", ["/usr/bin/python3", script,
        "--support-observe", database])
    key = Ed25519PrivateKey.generate()
    evidence = {"schema": "pulse.project-predicate-support-evidence/v1", "acquisition_id": "local-support:1",
        "producer_id": "local-queue.support", "producer_key_id": "local-support-key",
        "source_id": "local-queue.sqlite", "dependency_ids": ["direct:local-queue.sqlite"],
        "subject_id": "local-queue:disposable", "vantage_id": "local-support-process",
        "observed_at": support["observed_at"], "valid_for_seconds": 120,
        "facts": support["facts"], "local_state": "OBSERVED"}
    evidence["evidence_id"] = digest(evidence)
    envelope = {"schema": "pulse.project-predicate-support-envelope/v1", "evidence": evidence,
        "signature_hex": key.sign(b"pulse/project-predicate-support/evidence/v1\0" + canonical(evidence)).hex()}
    write(root / "support.json", envelope)
    target = {"project": "local-queue-demo", "concern": "queue.needs-attention",
        "question": profile["question"], "declaration_profile": profile["declaration_profile"],
        "predicate_profile": profile["id"], "catalog_digest": digest(catalog),
        "profile_digest": digest(profile), "input_schema_digest": digest(profile["input_schema"]),
        "primary_producer": "local-queue.primary", "subject_id": evidence["subject_id"]}
    policy = {"schema": "pulse.project-predicate-support-policy/v1", "policy_id": "local-queue-support/v1",
        "target": target, "support_source": {"producer_id": evidence["producer_id"],
            "producer_key_id": evidence["producer_key_id"], "producer_public_key_hex":
                key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
            "source_id": evidence["source_id"], "vantage_id": evidence["vantage_id"],
            "dependency_ids": evidence["dependency_ids"]},
        "currentness": {"maximum_primary_age_seconds": 120, "maximum_support_age_seconds": 120,
            "maximum_primary_support_skew_seconds": 30}, "nq_verifier_executable_digest": file_digest(args.nq)}
    policy["policy_digest"] = digest(policy)
    write(root / "pulse-policy.json", policy)
    pulse_args = ["--policy", root / "pulse-policy.json", "--nq-executable", args.nq,
        "--nq-receipt", root / "admission.json", "--inventory", root / "inventory.json",
        "--catalog", root / "catalog.json", "--support-evidence", root / "support.json"]
    invoke(root, "pulse-qualify", [args.pulse, "qualify", *pulse_args, "--at", now(),
        "--output", root / "pulse.json"])
    qualified = json.loads((root / "pulse.json").read_bytes())
    require(qualified["disposition"] == "SUPPORTED_CURRENT", "Pulse did not establish current support")
    changed = json.loads(json.dumps(catalog))
    changed["profiles"][0]["accepted_producers"] = ["unapproved-producer"]
    write(root / "changed-catalog.json", changed)
    invoke(root, "changed-catalog-refused", [args.nq, "bounded-predicate", "replay",
        "--receipt", root / "admission.json", "--inventory", root / "inventory.json",
        "--profiles", root / "changed-catalog.json", "--output", "-"], expected=1)
    # A future evaluation is an explicit negative control, not a refreshed observation.
    stale_at = (dt.datetime.fromisoformat(qualified["primary_observed_at"].replace("Z", "+00:00"))
        + dt.timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%SZ")
    invoke(root, "stale-support-control", [args.pulse, "qualify", *pulse_args,
        "--at", stale_at, "--output", root / "stale-pulse.json"])
    stale = json.loads((root / "stale-pulse.json").read_bytes())
    require(stale["disposition"] == "PRIMARY_STALE", "Exclusive freshness boundary was not enforced")
    attention_target = {key: target[key] for key in
        ("project", "concern", "question", "declaration_profile", "predicate_profile", "subject_id")}
    attention_target.update({"nq_catalog_digest": target["catalog_digest"],
        "nq_profile_digest": target["profile_digest"], "nq_input_schema_digest": target["input_schema_digest"],
        "pulse_support_policy_id": policy["policy_id"], "pulse_support_policy_digest": policy["policy_digest"]})
    attention = {"schema": "nightshift.project-predicate-attention-policy/v1", "policy_id": "local-queue-attention/v1",
        "target": attention_target, "pulse_verifier_executable_digest": file_digest(args.pulse),
        "trigger": {"kind": "PROPOSITION_ATTENTION"},
        "recurrence": {"required_distinct_occurrences": 1, "within_seconds": 120}, "reset": "HORIZON_EXPIRY"}
    attention["policy_digest"] = digest(attention)
    write(root / "attention-policy.json", attention)
    ns = [args.nightshift, "--store", root / "attention.sqlite", "attention"]
    ingest = [*ns, "ingest", "--policy", root / "attention-policy.json", "--pulse-receipt", root / "pulse.json",
        "--pulse-program", args.pulse, "--pulse-support-policy", root / "pulse-policy.json",
        "--nq-executable", args.nq, "--nq-receipt", root / "admission.json", "--inventory", root / "inventory.json",
        "--catalog", root / "catalog.json", "--support-evidence", root / "support.json"]
    accepted = invoke(root, "nightshift-ingest", ingest)
    duplicate = invoke(root, "nightshift-duplicate", ingest)
    require(accepted["disposition"] == "ACCEPTED" and duplicate["disposition"] == "DUPLICATE_EVIDENCE_OCCURRENCE",
        "Nightshift did not converge on the existing evidence occurrence")
    invoke(root, "nightshift-evaluate", [*ns, "evaluate", "--policy", root / "attention-policy.json",
        "--evaluated-at", now(), "--output", root / "attention.json"])
    bundle = json.loads((root / "attention.json").read_bytes())
    require(bundle["receipt"]["disposition"] == "ATTENTION_REQUIRED", "Expected explicit operator-policy attention")
    replay = invoke(root, "nightshift-replay", [*ns, "replay", "--bundle", root / "attention.json"])
    require(replay["matches"], "Nightshift replay mismatch")
    invoke(root, "nightshift-reopen-stale", [*ns, "evaluate", "--policy", root / "attention-policy.json",
        "--evaluated-at", stale_at, "--output", root / "stale-attention.json"])
    stale_attention = json.loads((root / "stale-attention.json").read_bytes())
    require(stale_attention["receipt"]["disposition"] == "INPUT_NOT_CURRENT", "Stale input advanced attention")
    config = root / "nq.toml"
    config.write_text(f'''schema = "nq.config.v1"
database_path = "{root / 'nq.sqlite'}"
socket_path = "{root / 'nqd.sock'}"
admissions_dir = "{root / 'admissions'}"
helper_runtime_dir = "{root / 'helpers'}"
[[notification_routes]]
reference = "local-demo"
transport = "slack"
endpoint_secret_locator = "NQ_LOCAL_DEMO_UNSET_URL"
timeout_ms = 10000
max_response_bytes = 32768
[notification_routes.nightshift_attention_replay]
executable = "{args.nightshift}"
executable_sha256 = "{file_digest(args.nightshift)}"
store_locator = "{root / 'attention.sqlite'}"
approved_policy_digest = "{attention['policy_digest']}"
execution_account = "{pwd.getpwuid(os.getuid()).pw_name}"
''')
    nq = [args.nq, "--config", config]
    invoke(root, "nq-init", [*nq, "init"])
    receipt = bundle["receipt"]
    intent = {"schema": "nq.notification_delivery_intent.v1", "attention_kind": "nightshift_receipt",
        "stable_event_id": receipt["receipt_digest"], "attention_receipt_digest": receipt["receipt_digest"],
        "attention_policy_id": attention["policy_id"], "attention_policy_digest": attention["policy_digest"],
        "transition_id": receipt["receipt_digest"], "route_reference": "local-demo",
        "destination_identity": "local-unconfigured-demo", "summary": "The disposable queue has twenty pending rows; inspect its records.",
        "inspection_reference": "local:attention.json", "owner_receipt": bundle}
    write(root / "intent.json", intent)
    submit = [*nq, "notification", "submit", "--intent", root / "intent.json", "--route", "local-demo"]
    delivered = invoke(root, "notification-no-network", submit)
    require(delivered["delivery_state"] == "refused", "No-network submission did not refuse delivery")
    require(invoke(root, "notification-duplicate", submit) == delivered, "Delivery duplicate diverged")
    inspected = invoke(root, "notification-inspect", [*nq, "notification", "inspect", "--notification-id", delivered["notification_id"]])
    require(inspected[0]["event_count"] == 1, "Duplicate created another delivery event")
    result = {"schema": "constellation.local-queue-attention-example/v1", "result": "qualified",
        "actual_components": ["Monitor", "NQ", "Pulse", "Nightshift"],
        "real_sqlite_reads": 2, "nightshift_duplicate_converged": True,
        "changed_catalog_refused": True, "stale_support_refused": True,
        "reopened_attention_does_not_refresh_evidence": True,
        "notification_state": "refused", "network_enabled": False,
        "limitations": ["Disposable queue, not production state", "One operator supplies policy and both producer implementations",
            "Source-path independence only; not independent organizations or attested hardware",
            "No recurring scheduler, maintenance overlay, live delivery or governed execution"],
        "executables": {name: file_digest(getattr(args, name)) for name in ("monitor", "nq", "pulse", "nightshift")}}
    write(root / "result.json", result)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
