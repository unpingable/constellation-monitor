"""Linux telemetry sampler; prints one nonce-bound JSON object and exits."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys


def sample(nonce):
    if not re.fullmatch(r"[0-9a-f]{64}", nonce):
        raise ValueError("nonce must be 64 lowercase hexadecimal characters")
    machine = Path("/etc/machine-id").read_text().strip()
    if not re.fullmatch(r"[0-9a-f]{32}", machine):
        raise ValueError("machine identity unavailable")
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot):
        raise ValueError("boot identity unavailable")
    memory = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[2] == "kB":
            memory[fields[0].rstrip(":")] = int(fields[1]) * 1024
    load = [float(value) for value in Path("/proc/loadavg").read_text().split()[:3]]
    uptime = float(Path("/proc/uptime").read_text().split()[0])
    filesystem = os.statvfs("/")
    telemetry = {"uptime_seconds":uptime, "load1":load[0], "load5":load[1], "load15":load[2],
        "memory_total_bytes":memory["MemTotal"], "memory_available_bytes":memory["MemAvailable"],
        "swap_total_bytes":memory["SwapTotal"], "swap_free_bytes":memory["SwapFree"],
        "cpu_count":os.cpu_count(), "root_total_bytes":filesystem.f_blocks * filesystem.f_frsize,
        "root_available_bytes":filesystem.f_bavail * filesystem.f_frsize}
    if any(type(value) not in (int, float) or not math.isfinite(value) or value < 0 for value in telemetry.values()):
        raise ValueError("invalid local telemetry")
    return {"schema":"constellation.host_duty_sample.v1", "nonce":nonce,
        "machine_identity_sha256":hashlib.sha256(machine.encode()).hexdigest(),
        "boot_id":boot, "telemetry":telemetry}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nonce", required=True)
    args = parser.parse_args(argv)
    try:
        raw = json.dumps(sample(args.nonce), allow_nan=False, separators=(",", ":"))
        if len(raw.encode()) + 1 > 65536:
            raise ValueError("sample exceeds output bound")
        print(raw)
    except (OSError, ValueError, KeyError, IndexError) as exc:
        print("host-duty sample unavailable: " + str(exc)[:300], file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
