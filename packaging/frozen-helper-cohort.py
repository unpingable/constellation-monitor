#!/usr/bin/env python3
"""Freeze/check the four selected helper executables, using existing identities.

This is a bounded packaging receipt helper, not qualification or an orchestrator.
The owning qualifier supplies the actual final Cargo output and recorded argv.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile

SPEC = importlib.util.spec_from_file_location('helper_identity', Path(__file__).with_name('record-build-identity.py'))
identity = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(identity)
NAMES = ('constellation-host-posture', *identity.BINARIES)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def freeze(cargo_json, expected_hp, production_target, bin_dir, receipt_path, argv_json):
    production_target, bin_dir = Path(production_target).resolve(), Path(bin_dir).resolve()
    if bin_dir.is_relative_to(production_target) or production_target.is_relative_to(bin_dir):
        raise ValueError('frozen cohort must be outside mutable production Cargo target')
    records = [json.loads(line) for line in Path(cargo_json).read_text().splitlines() if line.strip()]
    if not records or records[-1].get('reason') != 'build-finished' or records[-1].get('success') is not True:
        raise ValueError('final owning production build did not finish successfully')
    selected = {}
    for record in records:
        if record.get('reason') == 'compiler-artifact' and record.get('executable') and record.get('target', {}).get('name') in NAMES:
            name = record['target']['name']
            if name in selected or 'bin' not in record['target']['kind']:
                raise ValueError('selected executable origin is not unique')
            selected[name] = record
    if set(selected) != set(NAMES):
        raise ValueError('actual final build did not identify the whole selected helper cohort')
    if Path(expected_hp).resolve() != Path(selected['constellation-host-posture']['executable']).resolve():
        raise ValueError('BIN does not name the owning final build HP executable')
    bin_dir.mkdir(mode=0o700)  # Existing output requires reconciliation, never replacement.
    origins = {}
    for name in NAMES:
        record = selected[name]
        source = Path(record['executable'])
        if source.is_symlink() or not source.resolve().is_relative_to(production_target) or not source.is_file():
            raise ValueError('selected origin is not an ordinary file in the production target')
        before = digest(source)
        destination = bin_dir / name
        shutil.copyfile(source, destination, follow_symlinks=False)
        destination.chmod(0o555)
        if before != digest(destination) or before != digest(source) or destination.stat().st_nlink != 1 or (source.stat().st_dev, source.stat().st_ino) == (destination.stat().st_dev, destination.stat().st_ino):
            raise ValueError('frozen file is not an independent exact ordinary copy')
        origins[name] = {'sha256': before, 'source': str(source.resolve()), 'compiler_artifact': record, 'uid': destination.stat().st_uid, 'mode': '0o555'}
    for alias in identity.ALIASES:
        (bin_dir / alias).symlink_to('pulse-nq-load-support')
    probe = subprocess.run([str(bin_dir / 'pulse-nq-filesystem-support'), '--build-info'], check=True, capture_output=True)
    info = json.loads(probe.stdout)
    target = info['target']
    architecture = 'amd64' if target.startswith('x86_64-') else 'arm64' if target.startswith('aarch64-') else None
    if architecture is None:
        raise ValueError('unsupported selected helper architecture')
    existing_identity = identity.record(bin_dir, info['version'], architecture)
    bin_dir.chmod(0o555)
    receipt = {'schema_version': 1, 'frozen_bin_dir': str(bin_dir), 'production_target': str(production_target),
               'production_argv': json.loads(Path(argv_json).read_text()), 'production_argv_sha256': digest(argv_json),
               'production_stdout_sha256': digest(cargo_json), 'executables': origins,
               'existing_build_identity': existing_identity}
    with Path(receipt_path).open('x') as out:
        json.dump(receipt, out, indent=2)
        out.write('\n')
        out.flush()
        os.fsync(out.fileno())
    verify(receipt_path, bin_dir)
    return receipt


def verify(receipt_path, bin_dir):
    receipt = json.loads(Path(receipt_path).read_text())
    directory = Path(bin_dir)
    if directory.is_symlink() or directory.resolve() != Path(receipt['frozen_bin_dir']) or stat.S_IMODE(directory.stat().st_mode) != 0o555:
        raise ValueError('package/check must select the same frozen BIN_DIR')
    if set(receipt['executables']) != set(NAMES):
        raise ValueError('frozen receipt is not the whole selected cohort')
    for name, expected in receipt['executables'].items():
        path = directory / name
        m = path.lstat()
        if not stat.S_ISREG(m.st_mode) or m.st_nlink != 1 or m.st_uid != expected['uid'] or stat.S_IMODE(m.st_mode) != 0o555 or digest(path) != expected['sha256']:
            raise ValueError(f'selected frozen executable changed: {name}')
    for name in identity.ALIASES:
        if not (directory / name).is_symlink() or os.readlink(directory / name) != 'pulse-nq-load-support':
            raise ValueError('selected frozen role alias changed')
    return receipt


def verify_payload(receipt_path, payload_root):
    receipt = json.loads(Path(receipt_path).read_text())
    for name, expected in receipt['executables'].items():
        path = Path(payload_root) / name
        if path.is_symlink() or digest(path) != expected['sha256']:
            raise ValueError(f'package staged payload differs from selected frozen executable: {name}')


def verify_package(receipt_path, package):
    receipt = json.loads(Path(receipt_path).read_text())
    expected = {name: item['sha256'] for name, item in receipt['executables'].items()}
    seen = {}
    process = subprocess.Popen(['dpkg-deb', '--fsys-tarfile', str(package)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
        for member in archive:
            parts = member.name.removeprefix('./').split('/')
            if len(parts) == 3 and parts[:2] == ['usr', 'bin'] and parts[-1] in expected:
                if not member.isfile() or parts[-1] in seen:
                    raise ValueError('package selected executable is not one ordinary file')
                h = hashlib.sha256()
                with archive.extractfile(member) as source:
                    for block in iter(lambda: source.read(1024 * 1024), b''):
                        h.update(block)
                seen[parts[-1]] = h.hexdigest()
    process.stdout.close()
    error = process.stderr.read()
    if process.wait() != 0 or seen != expected:
        raise ValueError('actual package selected payload differs from frozen identities: ' + error.decode(errors='replace'))
    return {'package_sha256': digest(package), 'selected_executables': seen}


if __name__ == '__main__':
    command, *arguments = sys.argv[1:]
    if command == 'freeze' and len(arguments) == 6:
        freeze(*arguments)
    elif command == 'check' and len(arguments) == 2:
        verify(*arguments)
    elif command == 'payload' and len(arguments) == 2:
        verify_payload(*arguments)
    elif command == 'package' and len(arguments) == 2:
        print(json.dumps(verify_package(*arguments), sort_keys=True))
    else:
        sys.exit('usage: frozen-helper-cohort.py freeze CARGO_JSON EXPECTED_HP PRODUCTION_TARGET BIN_DIR RECEIPT ARGV_JSON | check RECEIPT BIN_DIR | payload RECEIPT STAGED_BIN | package RECEIPT DEB')
