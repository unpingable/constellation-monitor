#!/usr/bin/python3
"""Read-only projection of one explicitly bound engineering build.

This is not an executor. Its source adapter reads ordinary owner checkpoints,
the original systemd invocation and Cargo's actual compiler-artifact stream.
The only emitted public envelope is existing project.ops.status/v1.
"""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import tempfile
import time


DESCRIPTIONS = {
    "obligation": "The owner explicitly identifies assigned work or fresh no assigned work.",
    "admission": "The owner's resource admission decision is observable.",
    "worker": "The original source-bound native worker is observable while its obligation is unsettled.",
    "progress": "The bound worker has no observed breach of its authored compiler-progress budget.",
    "outcome": "Any explicit completion claim or due result has independent source-bound artifact support.",
    "publication": "Any published or due result names the exact independent receipt and artifact.",
}

FIELDS = ("LoadState", "ActiveState", "SubState", "MainPID", "InvocationID", "Result",
          "ExecMainCode", "ExecMainStatus", "ExecMainStartTimestamp", "ExecMainExitTimestamp", "ControlGroup")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source_time(value):
    if not isinstance(value, str):
        raise ValueError("source timestamp must be a timezone-aware ISO datetime")
    parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("source timestamp has no timezone")
    return parsed.timestamp()


def validate_previous(previous):
    if (not isinstance(previous, dict) or previous.get("schema") != "project.ops.status/v1"
            or not isinstance(previous.get("producer"), dict)
            or previous["producer"].get("id") != "monitor.native-build-observation"
            or not isinstance(previous.get("extensions"), dict)):
        raise ValueError("previous capture is not this observer's envelope")
    extension = previous["extensions"]
    capture, clock = extension.get("capture"), extension.get("progress_clock")
    if not isinstance(capture, dict) or not isinstance(clock, dict) or type(capture.get("at")) is not int:
        raise ValueError("previous capture or progress clock malformed")
    if type(clock.get("baseline_at")) is not int or not 0 <= clock["baseline_at"] <= capture["at"]:
        raise ValueError("previous baseline timestamp invalid")
    last = clock.get("last_advance_at")
    if last is not None and (type(last) is not int or not clock["baseline_at"] <= last <= capture["at"]):
        raise ValueError("previous advancement timestamp invalid")
    progress = capture.get("progress")
    if progress is not None:
        if not isinstance(progress, dict) or any(type(progress.get(key)) is not int or not 0 <= progress[key] <= 16777216 for key in ("bytes", "compiler_artifacts", "complete_lines")):
            raise ValueError("previous Cargo counts invalid")
        if not isinstance(progress.get("sha256"), str) or not re.fullmatch("[0-9a-f]{64}", progress["sha256"]):
            raise ValueError("previous Cargo digest invalid")


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    def invalid(value):
        raise ValueError("nonfinite JSON value")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def read_file(path, limit, trusted_root=None, allow_append=False):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("source path must be absolute")
    if trusted_root is not None:
        root = Path(trusted_root)
        relative = path.relative_to(root)
        if ".." in relative.parts or root.resolve() != root or path.resolve() != path:
            raise ValueError("trusted source escapes its explicitly selected evidence directory")
        for current in [root] + [root.joinpath(*relative.parts[:i]) for i in range(1, len(relative.parts) + 1)]:
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
                raise ValueError("trusted source is not root-controlled: " + str(current))
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError("source is not a bounded regular file: " + str(path))
        data = stream.read(before.st_size)
        after = os.fstat(stream.fileno())
        if (len(data) != before.st_size or after.st_size < before.st_size
                or (not allow_append and (after.st_size, after.st_mtime_ns, after.st_ctime_ns) !=
                    (before.st_size, before.st_mtime_ns, before.st_ctime_ns))
                or (after.st_size == before.st_size and after.st_mtime_ns != before.st_mtime_ns)):
            raise ValueError("source changed during bounded read")
    return data


def acquire(binding_path, previous=None):
    """Read one authorized binding. Never execute its content or alter sources.

    Root custody below the explicitly selected binding directory is the trust
    source for owner decisions and independent receipts. Cargo/artifact paths
    remain untrusted worker content; actual bytes are independently read back.
    """
    at = int(time.time())
    sample = {"at": at, "source_ok": False, "errors": [], "sources": [], "owner": {},
              "identity_matches": False, "launch_present": False, "native": {}, "progress": None,
              "verification": "missing", "publication": "missing"}
    root = Path(binding_path).parent
    consumed_hashes = {}

    def source(path, trusted=True, optional=False, limit=1048576, allow_append=False):
        try:
            data = read_file(path, limit, root if trusted else None, allow_append=allow_append)
            consumed_hashes[str(path)] = sha(data)
            sample["sources"].append({"id": str(path), "sha256": sha(data), "bytes": len(data),
                                      "acquired_at": timestamp(at), "trust": "root-custodied" if trusted else "worker-content-readback"})
            return data
        except FileNotFoundError:
            if optional:
                return None
            raise

    def document(path, optional=False):
        raw = source(path, optional=optional)
        if raw is None:
            return None
        value = decode(raw)
        if not isinstance(value, dict):
            raise ValueError("checkpoint must be a JSON object")
        return value

    try:
        binding = document(binding_path)
        for key, default, maximum in (("max_age", 60, 300), ("progress_budget", 300, 3600)):
            value = binding.get(key, default)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError("invalid " + key)
            sample[key] = value
        owner = document(binding["owner"])
        owner_hash = consumed_hashes[str(binding["owner"])]
        sample["owner"] = owner
        if "completion_claimed" in owner and type(owner["completion_claimed"]) is not bool:
            raise ValueError("explicit completion claim must be a boolean")
        sample["completion_claim"] = owner.get("completion_claimed") is True
        updated = owner.get("updated_at_epoch")
        if type(updated) is not int or updated > at:
            raise ValueError("owner timestamp invalid or future")
        sample["sources"][-1]["source_at"] = timestamp(updated)
        if owner.get("state") == "no_assigned_work":
            sample["source_ok"] = True
            return sample
        if not isinstance(owner.get("job_id"), str) or not owner["job_id"] or len(owner["job_id"]) > 128:
            raise ValueError("accepted job identity missing")
        for key in ("accepted_at_epoch", "deadline_at_epoch"):
            if type(owner.get(key)) is not int:
                raise ValueError("invalid owner " + key)
        if owner["accepted_at_epoch"] > at or owner["deadline_at_epoch"] < owner["accepted_at_epoch"]:
            raise ValueError("invalid acceptance/deadline order")
        source_binding = owner["source"]
        if not re.fullmatch("[0-9a-f]{40}", source_binding["commit"]) or not re.fullmatch("[0-9a-f]{64}", source_binding["capsule_sha256"]):
            raise ValueError("source commit/capsule binding invalid")
        unit = owner["native_unit"]
        if not re.fullmatch(r"[A-Za-z0-9_.@:-]{1,200}\.service", unit):
            raise ValueError("native unit invalid")
        admission = document(binding["admission"], optional=True)
        if admission is None:
            sample["admission"] = "BLOCKED" if owner.get("admission", {}).get("state") == "BLOCKED" and owner["admission"].get("reason") else "UNKNOWN"
            sample["admission_at"] = updated
        else:
            if admission["job_id"] != owner["job_id"] or admission["accepted_record_sha256"] != owner_hash or type(admission["epoch"]) is not int or not owner["accepted_at_epoch"] <= admission["epoch"] <= at:
                raise ValueError("admission source binding invalid")
            sample["admission"], sample["admission_at"] = admission["decision"], admission["epoch"]
        launch = document(binding["launch"], optional=True)
        sample["launch_present"] = launch is not None
        if launch is not None:
            started_at = source_time(launch.get("at"))
            if not owner["accepted_at_epoch"] <= started_at <= time.time():
                raise ValueError("launch time invalid or future")
            sample["started_at"] = started_at
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        sample["host_matches"] = boot == binding["boot_id"]
        sample["sources"].append({"id": "/proc/sys/kernel/random/boot_id", "sha256": sha(boot.encode()), "bytes": len(boot), "acquired_at": timestamp(at), "trust": "native-kernel"})
        result = subprocess.run(["systemctl", "show", unit] + ["--property=" + field for field in FIELDS],
                                capture_output=True, timeout=3, check=False)
        if len(result.stdout) > 65536 or len(result.stderr) > 65536:
            raise ValueError("native query output exceeded bound")
        native = dict(line.split("=", 1) for line in result.stdout.decode().splitlines() if "=" in line)
        if result.returncode != 0 and native.get("LoadState") != "not-found":
            raise ValueError("native query failed")
        if not native.get("LoadState") or not str(native.get("MainPID", "0")).isdigit():
            raise ValueError("native query incomplete")
        sample["native"] = native
        sample["sources"].append({"id": "systemctl-show:" + unit, "sha256": sha(result.stdout), "bytes": len(result.stdout), "acquired_at": timestamp(at), "trust": "native-systemd"})
        identity = {"job_id": owner["job_id"], "source_commit": source_binding["commit"],
                    "source_capsule_sha256": source_binding["capsule_sha256"], "boot_id": binding["boot_id"],
                    "unit": unit, "invocation_id": launch.get("invocation_id") if launch else None}
        sample["identity"] = identity
        sample["identity_matches"] = bool(launch and boot == binding["boot_id"] == launch.get("boot_id")
            and launch.get("job_id") == owner["job_id"] and launch.get("unit") == unit
            and launch.get("source_commit") == source_binding["commit"]
            and launch.get("accepted_record_sha256") == owner_hash
            and re.fullmatch("[0-9a-f]{32}", launch.get("invocation_id", ""))
            and native.get("InvocationID") == launch["invocation_id"])
        sample["source_ok"] = True
        cargo = source(owner["native_source_paths"]["cargo_messages"], trusted=False, optional=True, limit=16777216, allow_append=True)
        if cargo is not None:
            # Ignore only an unfinished final record from the concurrent writer.
            complete = cargo[:cargo.rfind(b"\n") + 1]
            if complete.count(b"\n") > 20000:
                raise ValueError("Cargo complete record count exceeded bound")
            records = [decode(line) for line in complete.splitlines()]
            if any(not isinstance(record, dict) for record in records):
                raise ValueError("Cargo stream has non-object complete records")
            old = (previous or {}).get("extensions", {}).get("capture", {}).get("progress") or {}
            prefix = type(old.get("bytes")) is int and 0 <= old["bytes"] <= len(complete) and sha(complete[:old["bytes"]]) == old.get("sha256")
            sample["progress"] = {"bytes": len(complete), "sha256": sha(complete), "prefix_matches": prefix,
                                  "compiler_artifacts": sum(record.get("reason") == "compiler-artifact" for record in records),
                                  "complete_lines": len(records)}
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, subprocess.SubprocessError) as error:
        sample["errors"].append(str(error)[:500])
        sample["source_ok"] = False
        return sample

    try:
        receipt = document(binding["verification"], optional=True)
        if receipt is not None:
            sample["verification"] = "invalid"
            verified_at = source_time(receipt.get("verified_at"))
            if not owner["accepted_at_epoch"] <= verified_at <= time.time():
                raise ValueError("independent verification timestamp invalid or future")
            sample["sources"][-1]["source_at"] = receipt["verified_at"]
            artifact = source(owner["expected_output"]["package"], trusted=False, limit=268435456)
            if (sample["identity_matches"] and native.get("MainPID") == "0"
                    and native.get("ExecMainCode") == "1" and native.get("ExecMainStatus") == "0" and native.get("Result") == "success"
                    and receipt.get("verified") is True
                    and receipt.get("job_id") == owner["job_id"] and receipt.get("source_commit") == source_binding["commit"]
                    and receipt.get("source_capsule_sha256") == source_binding["capsule_sha256"]
                    and receipt.get("native_producer", {}).get("InvocationID") == identity["invocation_id"]
                    and receipt.get("package_sha256") == sha(artifact) and isinstance(receipt.get("scope"), str) and receipt["scope"].strip()):
                sample["verification"] = "verified"
                sample["verification_scope"] = receipt["scope"][:2000]
        publication = document(binding["publication"], optional=True)
        if publication is not None:
            sample["publication"] = "invalid"
            if (receipt and sample["verification"] == "verified" and publication.get("job_id") == owner["job_id"]
                    and publication.get("native_invocation_id") == identity["invocation_id"]
                    and publication.get("accepted_record_sha256") == owner_hash
                    and publication.get("verification_sha256") == consumed_hashes[str(binding["verification"])]
                    and publication.get("package_sha256") == receipt["package_sha256"]):
                sample["publication"] = "published"
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError) as error:
        sample["verification"] = "unknown"
        sample["publication"] = "unknown"
        sample["errors"].append(str(error)[:500])
    return sample


def timestamp(epoch):
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).isoformat()


def project(sample, previous=None, now=None):
    """Project acquired facts, preserving all source/identity gaps as unknown.

    Internal samples are replay material, not an interoperable job protocol.
    Only acquire() may supply the trusted verification/publication dispositions.
    """
    now = sample["at"] if now is None else now
    owner, native = sample.get("owner") or {}, sample.get("native") or {}
    max_age, budget = sample.get("max_age", 60), sample.get("progress_budget", 300)
    current = (sample.get("source_ok") is True and 0 <= now - sample["at"] <= max_age)
    identity_ok = sample.get("identity_matches") is True
    sources = sample.get("sources", [])
    capture = {key: sample.get(key) for key in ("at", "identity", "progress")}
    clock = {"baseline_at": sample["at"], "last_advance_at": None}
    concerns = []

    def add(name, domain, reason, local="PRESENT"):
        concerns.append({"id": "work." + name, "question": "work." + name + "/v1",
                         "profile": "work.native-build/v1", "required": True,
                         "description": DESCRIPTIONS[name],
                         "observation": {"observation_present": True, "local_state": local,
                                         "domain_state": domain, "observed_at": timestamp(sample["at"]),
                                         "valid_for_seconds": max_age, "reason": reason,
                                         "facts": {"job_id": owner.get("job_id"), "sources": sources,
                                                   "identity": sample.get("identity"), "native": native,
                                                   "owner_source_at_epoch": owner.get("updated_at_epoch"),
                                                   "deadline_at_epoch": owner.get("deadline_at_epoch"),
                                                   "completion_claimed": sample.get("completion_claim", False),
                                                   "admission_source_at_epoch": sample.get("admission_at"),
                                                   "progress": sample.get("progress"),
                                                   "verification_scope": sample.get("verification_scope")}}})

    if not current:
        for name in DESCRIPTIONS:
            add(name, "UNKNOWN", "Source acquisition missing, stale, future or invalid: " + "; ".join(sample.get("errors", [])), "UNKNOWN")
    elif owner.get("state") == "no_assigned_work":
        fresh = 0 <= now - owner.get("updated_at_epoch", -1e30) <= max_age
        for name in DESCRIPTIONS:
            add(name, "NO_ASSIGNED_WORK" if fresh else "UNKNOWN",
                "Explicit owner source declares no assigned work." if fresh else "No assigned work source is stale.",
                "PRESENT" if fresh else "UNKNOWN")
    else:
        add("obligation", "ASSIGNED", "Accepted owner obligation remains recorded; this observer cannot discharge it.")
        admission = sample.get("admission")
        add("admission", "RESOURCE_BLOCKED" if admission == "BLOCKED" else "ADMITTED" if admission == "ADMITTED_AFTER_PREFLIGHT" else "UNKNOWN",
            "Owner resource decision: " + str(admission) + "; observation grants no execution authority.",
            "PRESENT" if admission in ("BLOCKED", "ADMITTED_AFTER_PREFLIGHT") else "UNKNOWN")
        launched = sample.get("launch_present") is True
        missing = native.get("LoadState") == "not-found"
        running = identity_ok and not missing and native.get("ActiveState") in ("active", "activating") and int(native.get("MainPID") or "0") > 0
        terminal = identity_ok and not missing and native.get("MainPID") == "0" and native.get("ExecMainCode") == "1"
        success = terminal and native.get("ExecMainStatus") == "0" and native.get("Result") == "success"
        if sample.get("host_matches", True) is False:
            worker = "UNKNOWN"
        elif not launched and missing:
            worker = "ACCEPTED_NOT_STARTED"
        elif launched and missing:
            worker = "MISSING_BOUND_WORKER"
        elif not identity_ok:
            worker = "UNKNOWN"
        elif running:
            worker = "RUNNING"
        elif terminal:
            worker = "NATIVE_SUCCEEDED" if success else "NATIVE_FAILED"
        else:
            worker = "UNRESPONSIVE_WORKER"
        add("worker", worker, "Declared unit, original invocation, boot and source binding determine worker identity; PID alone does not.",
            "PRESENT" if worker in ("ACCEPTED_NOT_STARTED", "RUNNING", "NATIVE_SUCCEEDED") else "UNKNOWN" if worker == "UNKNOWN" else "DEGRADED")

        progress, old = sample.get("progress"), (previous or {}).get("extensions", {}).get("capture")
        comparable = (running and progress and old and old.get("identity") == sample.get("identity")
                      and isinstance(old.get("at"), (int, float)) and 0 < sample["at"] - old["at"] <= 3600
                      and isinstance(old.get("progress"), dict))
        advancing = False
        if comparable:
            earlier = old["progress"]
            comparable = (progress.get("prefix_matches") is True and progress["bytes"] >= earlier["bytes"]
                          and progress["compiler_artifacts"] >= earlier["compiler_artifacts"]
                          and progress["complete_lines"] >= earlier["complete_lines"])
            if comparable:
                clock = dict((previous or {}).get("extensions", {}).get("progress_clock", clock))
                advancing = (progress["bytes"] > earlier["bytes"] and progress["compiler_artifacts"] > earlier["compiler_artifacts"])
                if advancing:
                    clock["last_advance_at"] = sample["at"]
        if not running:
            pstate = "NOT_RUNNING" if worker != "UNKNOWN" else "UNKNOWN"
        elif advancing:
            pstate = "ADVANCING"
        elif comparable and now - (clock.get("last_advance_at") or clock["baseline_at"]) > budget:
            pstate = "STALE_PROGRESS"
        else:
            pstate = "UNKNOWN"
        # A pre-launch capture has no invocation or Cargo baseline to compare.
        # Treat only the same accepted, not-started worker as an initial launch;
        # a rewrite or replacement of an already bound worker remains unknown.
        initial_launch = bool(old and old.get("progress") is None
            and old.get("identity") == dict(sample.get("identity") or {}, invocation_id=None)
            and old.get("at", float("inf")) <= sample.get("started_at", float("-inf"))
            and any(c.get("id") == "work.worker" and
                    c.get("observation", {}).get("domain_state") == "ACCEPTED_NOT_STARTED"
                    for c in (previous or {}).get("concerns", [])))
        grace = (running and progress is not None and pstate == "UNKNOWN" and
                 (((previous is None or initial_launch) and
                   0 <= now - sample.get("started_at", owner.get("accepted_at_epoch", sample["at"])) <= budget)
                  or comparable))
        add("progress", pstate, "Progress %s; compiler artifacts=%s; last observed append=%s; budget=%ss. %s Only a bound append proves sampled progress." %
            (pstate, (progress or {}).get("compiler_artifacts"), clock.get("last_advance_at"), budget,
             "Progress duty not breached within the authored budget." if grace else "No task-success claim."),
            "PRESENT" if grace or pstate in ("ADVANCING", "NOT_RUNNING") else "DEGRADED" if pstate == "STALE_PROGRESS" else "UNKNOWN")

        verified = identity_ok and sample.get("verification") == "verified"
        overdue = now > owner.get("deadline_at_epoch", float("inf"))
        claim = sample.get("completion_claim") is True
        unbound_pending = worker == "ACCEPTED_NOT_STARTED"
        outcome = ("UNKNOWN" if (not identity_ok and not unbound_pending) or sample.get("verification") == "unknown" else "ARTIFACT_VERIFIED" if verified else
                   "COMPLETION_WITHOUT_INDEPENDENT_OUTCOME" if claim else "NATIVE_SUCCESS_OUTCOME_UNKNOWN" if success else "INDEPENDENT_OUTCOME_MISSING")
        add("outcome", outcome, "Independent outcome %s. %s Native exit alone does not claim task completion or verify output." %
            ("ARTIFACT_VERIFIED" if verified else "UNKNOWN", "Required support is due or explicitly claimed." if overdue or claim else "Independent result duty is not due before the fixed deadline."),
            "UNKNOWN" if outcome == "UNKNOWN" else "PRESENT" if verified or not (overdue or claim) else "DEGRADED")
        published = verified and sample.get("publication") == "published"
        publication = ("UNKNOWN" if (not identity_ok and not unbound_pending) or sample.get("publication") == "unknown" else "RESULT_PUBLISHED" if published else
                       "UNSUPPORTED_PUBLICATION" if sample.get("publication") == "invalid" else "RESULT_OVERDUE" if overdue else "RESULT_NOT_PUBLISHED")
        add("publication", publication, "%s; fixed deadline=%s. Publication and independent outcome remain separate; missing publication never erases the native outcome." %
            ("Result publication is not yet due" if publication == "RESULT_NOT_PUBLISHED" else publication, owner.get("deadline_at_epoch")),
            "UNKNOWN" if publication == "UNKNOWN" else "PRESENT" if published or publication == "RESULT_NOT_PUBLISHED" else "DEGRADED")

    return {"schema": "project.ops.status/v1", "project": "bounded-engineering-work",
            "generated_at": timestamp(now), "manifest": {"schema": "project.concerns/v1", "path": ".ops/concerns.toml"},
            "producer": {"id": "monitor.native-build-observation", "version": "1"},
            "authority": {"scope": "read-only source observations; no execution, acceptance, settlement or publication authority"},
            "concerns": concerns, "extensions": {"capture": capture, "progress_clock": clock,
                                                    "errors": sample.get("errors", []), "sources": sources}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binding", required=True, type=Path, help="Root-custodied source binding JSON; its directory is the explicit trusted evidence root")
    history_args = parser.add_mutually_exclusive_group()
    history_args.add_argument("--previous", type=Path, help="Read a prior captured projection without writing it")
    history_args.add_argument("--history", type=Path, help="Read/update only this observer-owned bounded capture cache; parent must already exist")
    args = parser.parse_args()
    lock = None
    temporary = None
    now = int(time.time())
    previous = None

    def deadline(signum, frame):
        raise TimeoutError("observation acquisition exceeded ten-second deadline")

    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(10)
    try:
        previous_path = args.history or args.previous
        if args.history:
            parent = args.history.parent
            metadata = parent.lstat()
            if (not args.history.is_absolute() or stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode)
                    or metadata.st_uid != os.getuid() or metadata.st_mode & 0o022):
                raise ValueError("history directory must be observer-owned and not group/other writable")
            lock_path = args.history.with_name(args.history.name + ".lock")
            descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            lock = os.fdopen(descriptor, "r+")
            metadata = os.fstat(lock.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
                raise ValueError("history lock must be observer-owned mode0600")
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if previous_path:
            try:
                metadata = previous_path.lstat()
                if metadata.st_uid != os.getuid() or metadata.st_mode & 0o022:
                    raise ValueError("previous capture must be observer-owned and not group/other writable")
                previous = decode(read_file(previous_path, 1048576))
                validate_previous(previous)
            except FileNotFoundError:
                pass  # A first capture cannot prove advancement.
        sample = acquire(args.binding, previous)
        result = project(sample, previous)
        encoded = json.dumps(result, allow_nan=False, sort_keys=True) + "\n"
        if len(encoded.encode()) > 1048576:
            raise ValueError("observation output exceeded one MiB")
        if args.history:
            descriptor, temporary = tempfile.mkstemp(prefix=".observation-", dir=args.history.parent)
            with os.fdopen(descriptor, "w") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, args.history)
            temporary = None
        print(encoded, end="")
    except (OSError, ValueError, KeyError, TypeError, AttributeError, OverflowError, RecursionError, subprocess.SubprocessError) as error:
        # Source/collector loss cannot clear the owner's obligation or create an outcome.
        sample = {"at": now, "source_ok": False, "errors": [str(error)[:500]], "sources": []}
        print(json.dumps(project(sample, now=int(time.time())), allow_nan=False, sort_keys=True))
    finally:
        signal.alarm(0)
        if temporary is not None:
            os.unlink(temporary)
        if lock is not None:
            lock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
