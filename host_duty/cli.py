"""Trusted off-host duty operations and conditional availability status.

Completed dispositions record an explicit operator attestation. Presence
samples do not independently verify work results or authorize host actions.
"""
import argparse
import json
import math
import os
import re
import sqlite3
import sys

from .core import Ledger, status_document, unknown_document
from .probe import collect_config
from .snapshot import publish_snapshot


def _seconds(value):
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise argparse.ArgumentTypeError("seconds must be finite and nonnegative")
    return number


def _parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", help="absolute path of the owner-only off-host ledger")
    parser.add_argument("--status", action="store_true", help="emit project.ops.status/v1; requires --host")
    parser.add_argument("--host", help="host for the --status form")
    parser.add_argument("--freshness-seconds", type=_seconds, default=60)
    parser.add_argument("--grace-seconds", type=_seconds, default=30)
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("init", help="create a new owner-only ledger; never overwrite")
    register = commands.add_parser("register", help="register a host incarnation without assigning duty")
    register.add_argument("host_id")
    register.add_argument("instance_id")
    assign = commands.add_parser("assign", help="assign an explicit workload duty")
    assign.add_argument("duty_id")
    assign.add_argument("work_id")
    assign.add_argument("host_id")
    assign.add_argument("--deadline", required=True, type=_seconds, help="operator-authored epoch seconds")
    assign.add_argument("--reason", default="")
    release = commands.add_parser("release", help="record an explicit operator disposition")
    release.add_argument("duty_id")
    release.add_argument("disposition", choices=("released", "cancelled", "completed"))
    release.add_argument("--reason", required=True)
    release.add_argument("--evidence-sha256")
    release.add_argument("--confirm-completed", action="store_true",
        help="explicitly attest completion as operator; this does not perform independent verification")
    transfer = commands.add_parser("transfer", help="atomically transfer outstanding work to a successor duty")
    transfer.add_argument("duty_id")
    transfer.add_argument("successor_id")
    transfer.add_argument("host_id")
    transfer.add_argument("--deadline", required=True, type=_seconds)
    transfer.add_argument("--reason", required=True)
    replace = commands.add_parser("replace", help="replace a host incarnation once old duties are settled")
    replace.add_argument("host_id")
    replace.add_argument("instance_id")
    replace.add_argument("--reason", required=True)
    claim = commands.add_parser("observe-claim", help="record a shutdown claim; retains duty and source age")
    claim.add_argument("host_id")
    claim.add_argument("instance_id")
    claim.add_argument("--reason", required=True)
    collect = commands.add_parser("collect", help="acquire bounded samples from an explicit owner-only config")
    collect.add_argument("--config", required=True)
    export = commands.add_parser("export-observation", help="publish one read-only SQLite observer head separately from the duty ledger")
    export.add_argument("host_id")
    export.add_argument("--output", required=True, help="absolute snapshot path in an owned protected directory")
    status = commands.add_parser("status", help="emit conditional duty concerns without a host-health assertion")
    status.add_argument("host_id")
    status.add_argument("--freshness-seconds", type=_seconds, default=argparse.SUPPRESS)
    status.add_argument("--grace-seconds", type=_seconds, default=argparse.SUPPRESS)
    listing = commands.add_parser("list", help="list registered hosts and explicit duty history")
    listing.add_argument("--host", dest="filter_host")
    events = commands.add_parser("events", help="list bounded audit events")
    events.add_argument("--limit", type=int, default=100)
    return parser


def _emit(document):
    print(json.dumps(document, allow_nan=False, sort_keys=True, separators=(",", ":")))


def main(argv=None):
    parser = _parser()
    args = parser.parse_args(argv)
    if args.status:
        if args.command or not args.host:
            parser.error("--status requires --host and no subcommand")
        args.command, args.host_id = "status", args.host
    elif not args.command:
        parser.error("choose a command or --status --host HOST")
    elif args.host:
        parser.error("global --host is only valid with --status")
    if args.command == "collect":
        if args.database:
            parser.error("collect uses only the database explicitly named in --config")
        try:
            observations = collect_config(args.config)
            _emit({"observations":observations})
            if any(row.get("snapshot_error") for row in observations):
                print("host-duty collect failed: one or more snapshot publications failed", file=sys.stderr)
                return 2
            return 0
        except (OSError, ValueError, sqlite3.Error) as exc:
            print("host-duty collect refused: " + str(exc), file=sys.stderr)
            return 2
    if not args.database or not os.path.isabs(args.database):
        parser.error("--database must name an absolute owner-only ledger path")
    try:
        if args.command == "status":
            try:
                with Ledger(args.database, readonly=True) as ledger:
                    document = status_document(ledger, args.host_id, args.freshness_seconds, args.grace_seconds)
            except (OSError, ValueError, sqlite3.Error) as exc:
                document = unknown_document(args.host_id, str(exc))
            _emit(document)
            return 0
        if args.command == "init":
            with Ledger.create(args.database):
                pass
            _emit({"database":args.database, "created":True})
            return 0
        readonly = args.command in {"list", "events", "export-observation"}
        with Ledger(args.database, readonly=readonly) as ledger:
            if args.command == "register":
                ledger.register(args.host_id, args.instance_id)
            elif args.command == "assign":
                ledger.assign(args.duty_id, args.work_id, args.host_id, args.deadline, args.reason)
            elif args.command == "release":
                if args.disposition == "completed" and (not args.confirm_completed or not args.evidence_sha256):
                    raise ValueError("completed requires --confirm-completed and --evidence-sha256; records operator attestation only")
                if args.confirm_completed and args.disposition != "completed":
                    raise ValueError("--confirm-completed is valid only for a completed disposition")
                if args.evidence_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", args.evidence_sha256):
                    raise ValueError("evidence hash must be 64 lowercase hexadecimal SHA-256 characters")
                ledger.release(args.duty_id, args.disposition, args.reason, evidence_sha256=args.evidence_sha256)
            elif args.command == "transfer":
                ledger.transfer(args.duty_id, args.successor_id, args.host_id, args.deadline, args.reason)
            elif args.command == "replace":
                ledger.replace(args.host_id, args.instance_id, args.reason)
            elif args.command == "observe-claim":
                ledger.shutdown_claim(args.host_id, args.instance_id, args.reason)
            elif args.command == "export-observation":
                _emit(publish_snapshot(ledger, args.host_id, args.output))
                return 0
            elif args.command == "list":
                hosts = ledger.hosts()
                if args.filter_host:
                    hosts = [host for host in hosts if host["host_id"] == args.filter_host]
                _emit({"hosts":hosts, "duties":ledger.duties(args.filter_host)})
                return 0
            elif args.command == "events":
                _emit({"events":ledger.events(args.limit)})
                return 0
        _emit({"ok":True, "command":args.command})
        return 0
    except (OSError, ValueError, sqlite3.Error) as exc:
        print("host-duty %s refused: %s" % (args.command, exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
