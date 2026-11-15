#!/usr/bin/env python3
"""Explicit native qualification case; never provisions users or runs at import.

Run only on the admitted disposable qualification VM as its operator, with
three existing non-root accounts and a fresh campaign-owned configuration.
This executes the actual frozen adapter, including real filesystem acquisition.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import time


def check(condition, message):
    if not condition:
        raise ValueError(message)


def main(binary, config_path, query_path, root_path, producer, receiver, resolver):
    check(os.geteuid() == 0, 'native principal proof requires the admitted VM operator, not a same-UID substitute')
    root, binary = Path(root_path).resolve(), Path(binary).resolve()
    check(root.is_dir() and root != Path('/') and not Path(root_path).is_symlink(), 'fresh explicit proof root required')
    check(root.stat().st_uid == 0 and stat.S_IMODE(root.stat().st_mode) == 0o2750, 'proof ancestry must remain operator-controlled 02750 common-reader custody')
    roles = {name: pwd.getpwnam(user) for name, user in [('producer', producer), ('receiver', receiver), ('resolver', resolver)]}
    check(len({p.pw_uid for p in roles.values()}) == 3 and all(p.pw_uid != 0 for p in roles.values()), 'three distinct non-root real UIDs required')
    config_file=Path(config_path)
    check(not config_file.is_symlink() and config_file.stat().st_uid == 0 and stat.S_IMODE(config_file.stat().st_mode) == 0o640, 'configuration must remain operator-owned 0640 outside all runtime writers')
    check(binary.stat().st_uid not in {p.pw_uid for p in roles.values()} and binary.stat().st_mode & 0o222 == 0, 'selected frozen executable must be outside runtime writer ownership and have no write bits')
    check(binary.parent.stat().st_uid not in {p.pw_uid for p in roles.values()} and binary.parent.stat().st_mode & 0o222 == 0, 'selected frozen directory must remain outside runtime writer ownership')
    config = json.loads(config_file.read_bytes())
    outgoing = Path(config['outgoing_directory'])
    receipt = Path(config['receipt_directory'])
    key = Path(config['producer_private_key_path'])
    for path in [outgoing, receipt, key]:
        check(path.is_absolute() and path.resolve().is_relative_to(root) and not path.is_symlink(), 'only fresh proof-owned paths may be exercised')
    for path, writer, reader in [(outgoing, 'producer', 'receiver'), (receipt, 'receiver', 'resolver')]:
        meta = path.stat()
        check(stat.S_IMODE(meta.st_mode) == 0o2750 and meta.st_uid == roles[writer].pw_uid, 'publication directory requires exact writer ownership and 02750 mode')
        check(meta.st_gid in os.getgrouplist(roles[reader].pw_name, roles[reader].pw_gid), 'next reader lacks the enrolled read group')
    check(key.stat().st_uid == roles['producer'].pw_uid and stat.S_IMODE(key.stat().st_mode) == 0o600, 'signing key must remain producer-only 0600')
    for path in [Path(config_path), Path(query_path)]:
        check(not path.resolve().is_relative_to(outgoing) and not path.resolve().is_relative_to(receipt), 'configuration/query cannot live in runtime writer custody')
    calls = []

    def run(role, argv, expected=True, stdin=None):
        command = ['runuser', '-u', roles[role].pw_name, '--', *map(str, argv)]
        result = subprocess.run(command, input=stdin, capture_output=True, timeout=20)
        calls.append({'role': role, 'uid': roles[role].pw_uid, 'argv': command, 'exit': result.returncode})
        check((result.returncode == 0) == expected, f'{role}: unexpected command disposition: {argv[0]}')
        return result

    def cannot_write(role, directory):
        run(role, [sys.executable, '-B', '-c', 'import pathlib,sys; pathlib.Path(sys.argv[1]).open("xb").close()', directory / 'forbidden-principal-proof'], expected=False)

    def cannot_read_key(role):
        run(role, [sys.executable, '-B', '-c', 'import pathlib,sys; pathlib.Path(sys.argv[1]).read_bytes()', key], expected=False)

    def metadata(path):
        m = path.stat()
        return {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'uid': m.st_uid, 'gid': m.st_gid, 'mode': oct(stat.S_IMODE(m.st_mode))}

    for role in roles:
        observed = run(role, ['id', '-u']).stdout.decode().strip()
        real = run(role, ['id', '-ru']).stdout.decode().strip()
        check(int(observed) == roles[role].pw_uid and int(real) == roles[role].pw_uid, 'runuser did not establish the intended real and effective UID')
        cannot_write(role, Path(config_path).parent)
        cannot_write(role, binary.parent)
    cannot_read_key('receiver')
    cannot_read_key('resolver')
    cannot_write('producer', receipt)
    cannot_write('receiver', outgoing)
    cannot_write('resolver', outgoing)
    cannot_write('resolver', receipt)
    turns = []
    for turn in range(2):
        if turn:
            time.sleep(0.02)  # Distinct source starts beyond the centisecond clock cut.
        acquisition = f'principal-proof:{os.getpid()}:{turn}'
        run('producer', [binary, 'produce', '--config', config_path, '--acquisition-id', acquisition])
        envelope = outgoing / 'current-envelope.json'
        check(stat.S_IMODE(envelope.stat().st_mode) == 0o640 and envelope.stat().st_gid == outgoing.stat().st_gid, 'replacement lost envelope reader handoff')
        run('receiver', [binary, 'ingest', '--config', config_path, '--acquisition-id', acquisition])
        current = receipt / 'current-receipt.json'
        check(stat.S_IMODE(current.stat().st_mode) == 0o640 and current.stat().st_gid == receipt.stat().st_gid, 'replacement lost receipt reader handoff')
        support = json.loads(run('resolver', [binary, 'resolve', '--config', config_path], stdin=Path(query_path).read_bytes()).stdout)
        check(support['standing'] in ['current', 'contradictory'], 'fresh actual observation did not produce an evaluable support result')
        turns.append({'envelope': metadata(envelope), 'receipt': metadata(current), 'standing': support['standing']})
    before = {str(p): metadata(p) for p in [outgoing / 'current-envelope.json', receipt / 'current-receipt.json']}
    run('resolver', [binary, 'produce', '--config', config_path, '--acquisition-id', 'forbidden:resolver'], expected=False)
    check({str(p):metadata(p) for p in [outgoing/'current-envelope.json',receipt/'current-receipt.json']} == before, 'resolver acquisition refusal changed custody')
    for path, role in [(outgoing, 'producer'), (receipt, 'receiver')]:
        try:
            os.chmod(path, 0o2770)
            if role == 'producer':
                run(role, [binary, 'produce', '--config', config_path, '--acquisition-id', 'forbidden:group-write'], expected=False)
            else:
                # Replay is read-only and can return its old receipt. A fresh
                # acquisition is required to exercise refused publication.
                run('producer', [binary, 'produce', '--config', config_path, '--acquisition-id', 'proof:permission-negative'])
                run(role, [binary, 'ingest', '--config', config_path, '--acquisition-id', 'proof:permission-negative'], expected=False)
        finally:
            os.chmod(path, 0o2750)
    check(metadata(receipt / 'current-receipt.json') == before[str(receipt / 'current-receipt.json')], 'permission refusal replaced receiver custody')
    print(json.dumps({'disposition': 'PASS_NATIVE_DISTINCT_UID_HANDOFF', 'roles': {k: {'uid': v.pw_uid, 'primary_gid': v.pw_gid} for k, v in roles.items()}, 'turns': turns, 'calls': calls, 'scope': 'two actual native acquisitions/replacements, distinct read handoffs and permission refusals; no Nightshift recurrence acceptance', 'custody': 'Root retains this fresh proof root and receipt through acceptance; no cleanup performed'}, indent=2))


if __name__ == '__main__':
    if len(sys.argv) != 8:
        sys.exit('usage: test_fs_principal_handoff.py FROZEN_BINARY CONFIG QUERY FRESH_PROOF_ROOT PRODUCER RECEIVER RESOLVER')
    main(*sys.argv[1:])
