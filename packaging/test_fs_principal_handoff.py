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


def validate_operator_ancestry(paths, root, operator_uid=0):
    for path in paths:
        check(path.resolve().is_relative_to(root), 'all custody/enrollment must be below explicit proof ancestry')
        for parent in path.parents:
            check(not parent.is_symlink() and parent.stat().st_uid == operator_uid and parent.stat().st_mode & 0o022 == 0, 'accepted and custody directory entries need operator-controlled ancestry')
            if parent == root:
                break


def validate_request_inputs(slots, root, operator_uid=0):
    paths=[p for pair in slots for p in pair]
    for path in paths:
        check(path.is_absolute() and not path.is_symlink() and path.stat().st_uid==operator_uid and stat.S_IMODE(path.stat().st_mode)==0o640, 'per-slot inputs must remain immutable operator-owned 0640 proof files')
    validate_operator_ancestry(paths,root,operator_uid)


def main(binary, config_path, realization_path, request_a, query_a, request_b, query_b, root_path, producer, receiver, resolver):
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
    realization_file=Path(realization_path)
    check(not realization_file.is_symlink() and realization_file.stat().st_uid == 0 and stat.S_IMODE(realization_file.stat().st_mode) == 0o640, 'realization must remain operator-owned 0640')
    config = json.loads(config_file.read_bytes())
    check('expected_diagnostic' not in config, 'static enrollment must not contain a per-slot basis')
    check(json.loads(realization_file.read_bytes()) == config['realization'], 'separate accepted realization differs from static enrollment')
    slots=[(Path(request_a),Path(query_a)),(Path(request_b),Path(query_b))]
    requests=[json.loads(p.read_bytes()) for p,q in slots]
    check(requests[0]['inputs']['inputs_id'] != requests[1]['inputs']['inputs_id'], 'two distinct actual diagnostic bases required')
    outgoing = Path(config['outgoing_directory'])
    receipt = Path(config['receipt_directory'])
    key = Path(config['producer_private_key_path'])
    for path in [outgoing, receipt, key]:
        check(path.is_absolute() and path.resolve().is_relative_to(root) and not path.is_symlink(), 'only fresh proof-owned paths may be exercised')
    for path, writer, reader in [(outgoing, 'producer', 'receiver'), (receipt, 'receiver', 'resolver')]:
        meta = path.stat()
        check(stat.S_IMODE(meta.st_mode) == 0o2750 and meta.st_uid == roles[writer].pw_uid, 'publication directory requires exact writer ownership and 02750 mode')
        check(meta.st_gid in os.getgrouplist(roles[reader].pw_name, roles[reader].pw_gid), 'next reader lacks the enrolled read group')
    validate_operator_ancestry([outgoing,receipt,config_file,realization_file],root)
    validate_request_inputs(slots,root)
    check(key.stat().st_uid == roles['producer'].pw_uid and stat.S_IMODE(key.stat().st_mode) == 0o600, 'signing key must remain producer-only 0600')
    for path in [config_file, realization_file, *[p for pair in slots for p in pair]]:
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

    accepted_paths=[config_file,realization_file,*[p for pair in slots for p in pair]]
    accepted_before={str(p):metadata(p) for p in accepted_paths}
    for role in roles:
        observed = run(role, ['id', '-u']).stdout.decode().strip()
        real = run(role, ['id', '-ru']).stdout.decode().strip()
        check(int(observed) == roles[role].pw_uid and int(real) == roles[role].pw_uid, 'runuser did not establish the intended real and effective UID')
        cannot_write(role, config_file.parent)
        cannot_write(role, realization_file.parent)
        cannot_write(role, root)
        for accepted in accepted_paths:
            run(role,[sys.executable,'-B','-c','import pathlib,sys; pathlib.Path(sys.argv[1]).open("r+b")',accepted],expected=False)
        cannot_write(role, binary.parent)
    cannot_read_key('receiver')
    cannot_read_key('resolver')
    cannot_write('producer', receipt)
    cannot_write('receiver', outgoing)
    cannot_write('resolver', outgoing)
    cannot_write('resolver', receipt)
    turns = []
    # Resolver is also an ordinary caller: no private-key or accepted-config
    # write authority is granted for a new diagnostic request.
    for turn,(request_path,query_path) in enumerate(slots):
        if turn:
            time.sleep(0.02)  # Distinct source starts beyond the centisecond clock cut.
        acquisition = f'principal-proof:{os.getpid()}:{turn}'
        if turn:
            previous=json.loads(run('resolver',[binary,'resolve','--config',config_path,'--request',request_path],stdin=query_path.read_bytes()).stdout)
            check(previous['standing']=='unsupported','old receipt was retold as new-basis support')
        else:
            missing=json.loads(run('resolver',[binary,'resolve','--config',config_path,'--request',request_path],stdin=query_path.read_bytes()).stdout)
            check(missing['standing']=='unknown','missing custody became support')
        other_query=slots[1-turn][1]
        run('resolver',[binary,'resolve','--config',config_path,'--request',request_path],stdin=other_query.read_bytes(),expected=False)
        run('producer', [binary, 'produce', '--config', config_path, '--request', request_path, '--acquisition-id', acquisition])
        envelope = outgoing / 'current-envelope.json'
        check(stat.S_IMODE(envelope.stat().st_mode) == 0o640 and envelope.stat().st_gid == outgoing.stat().st_gid, 'replacement lost envelope reader handoff')
        run('receiver', [binary, 'ingest', '--config', config_path, '--request', request_path, '--acquisition-id', acquisition])
        current = receipt / 'current-receipt.json'
        check(stat.S_IMODE(current.stat().st_mode) == 0o640 and current.stat().st_gid == receipt.stat().st_gid, 'replacement lost receipt reader handoff')
        support = json.loads(run('resolver', [binary, 'resolve', '--config', config_path, '--request', request_path], stdin=Path(query_path).read_bytes()).stdout)
        check(support['standing'] in ['current', 'contradictory'], 'fresh actual observation did not produce an evaluable support result')
        check({str(p):metadata(p) for p in accepted_paths} == accepted_before,'runtime basis changed accepted configuration/realization')
        turns.append({'request_sha256':hashlib.sha256(request_path.read_bytes()).hexdigest(),'basis':requests[turn]['inputs']['inputs_id'],'envelope': metadata(envelope), 'receipt': metadata(current), 'standing': support['standing']})
    before = {str(p): metadata(p) for p in [outgoing / 'current-envelope.json', receipt / 'current-receipt.json']}
    run('resolver', [binary, 'produce', '--config', config_path, '--request', request_b, '--acquisition-id', 'forbidden:resolver'], expected=False)
    check({str(p):metadata(p) for p in [outgoing/'current-envelope.json',receipt/'current-receipt.json']} == before, 'resolver acquisition refusal changed custody')
    for path, role in [(outgoing, 'producer'), (receipt, 'receiver')]:
        try:
            os.chmod(path, 0o2770)
            if role == 'producer':
                run(role, [binary, 'produce', '--config', config_path, '--request', request_b, '--acquisition-id', 'forbidden:group-write'], expected=False)
            else:
                # Replay is read-only and can return its old receipt. A fresh
                # acquisition is required to exercise refused publication.
                run('producer', [binary, 'produce', '--config', config_path, '--request', request_b, '--acquisition-id', 'proof:permission-negative'])
                run(role, [binary, 'ingest', '--config', config_path, '--request', request_b, '--acquisition-id', 'proof:permission-negative'], expected=False)
        finally:
            os.chmod(path, 0o2750)
    check(metadata(receipt / 'current-receipt.json') == before[str(receipt / 'current-receipt.json')], 'permission refusal replaced receiver custody')
    check({str(p):metadata(p) for p in accepted_paths} == accepted_before,'permission negatives changed accepted records')
    print(json.dumps({'disposition': 'PASS_NATIVE_DISTINCT_UID_TWO_BASES_STATIC_ENROLLMENT', 'accepted_unchanged':accepted_before, 'roles': {k: {'uid': v.pw_uid, 'primary_gid': v.pw_gid} for k, v in roles.items()}, 'turns': turns, 'calls': calls, 'scope': 'two distinct diagnostic bases, actual native acquisitions/replacements, immutable accepted config/realization, old receipt Unsupported, cross-pair refusals and distinct reader UIDs; no Nightshift recurrence acceptance', 'custody': 'Root retains this fresh proof root and receipt through acceptance; no cleanup performed'}, indent=2))


def old_prepare_regression(binary, request, nq_config, instance, state, realization, caller):
    """Behavioral RED on the separately identified old source, never usage RED.

    The operator supplies the old ELF's own matching realization and actual
    watcher/request. This checks the demonstrated secret-access failure before
    requiring the ordinary caller's requested preparation to succeed.
    """
    check(os.geteuid()==0,'admitted VM operator required')
    account=pwd.getpwnam(caller)
    check(account.pw_uid!=0,'ordinary non-root caller required')
    key=Path(state)/'producer.key'
    config=Path(state)/'filesystem-support.json'
    check(key.stat().st_uid!=account.pw_uid and stat.S_IMODE(key.stat().st_mode)==0o600,'old producer-only key precondition absent')
    probe=subprocess.run([binary,'--build-info'],capture_output=True,check=True,timeout=20)
    build=json.loads(probe.stdout);record=json.loads(Path(realization).read_bytes())
    check(build['source_commit']=='0b7f7b3b44a5d5fcf7e41a1e6c7c722d4744c95b' and record['monitor_source_commit']==build['source_commit'],'old-source reproduction must identify its own complete frozen source')
    check(record['executable_sha256']=='sha256:'+hashlib.sha256(Path(binary).read_bytes()).hexdigest(),'old-source realization does not bind old ELF')
    for path in [request,nq_config,realization]:
        readable=subprocess.run(['runuser','-u',caller,'--',sys.executable,'-B','-c','import pathlib,sys; pathlib.Path(sys.argv[1]).read_bytes()',path],capture_output=True,timeout=20)
        check(readable.returncode==0,'old caller cannot read a pre-key public input; apparatus not ready')
    private=subprocess.run(['runuser','-u',caller,'--',sys.executable,'-B','-c','import pathlib,sys; pathlib.Path(sys.argv[1]).open("rb").close()',str(key)],capture_output=True,timeout=20)
    check(private.returncode!=0 and b'Permission denied' in private.stderr,'old caller unexpectedly has producer-key access')
    before=hashlib.sha256(config.read_bytes()).hexdigest() if config.exists() else None
    argv=['runuser','-u',caller,'--',binary,'prepare','--request',request,'--nq-config',nq_config,'--instance',instance,'--state',state,'--realization',realization]
    result=subprocess.run(argv,capture_output=True,timeout=20)
    check(b'Permission denied' in result.stderr and b'usage:' not in result.stderr,'old failure did not reproduce real private-key permission failure')
    after=hashlib.sha256(config.read_bytes()).hexdigest() if config.exists() else None
    check(before==after,'old refused preparation changed configuration')
    print(json.dumps({'disposition':'BEHAVIORAL_RED_OLD_PREPARATION_REQUIRES_SECRET','argv':argv,'uid':account.pw_uid,'exit':result.returncode,'stderr':result.stderr.decode(),'configuration_unchanged':True}),flush=True)
    check(result.returncode==0,'old source cannot prepare a fresh basis as ordinary caller without producer secret/config-write authority')


if __name__ == '__main__':
    if len(sys.argv)==9 and sys.argv[1]=='--old-prepare':
        old_prepare_regression(*sys.argv[2:])
    elif len(sys.argv)==12:
        main(*sys.argv[1:])
    else:
        sys.exit('usage: test_fs_principal_handoff.py FROZEN_BINARY CONFIG REALIZATION REQUEST_A QUERY_A REQUEST_B QUERY_B FRESH_PROOF_ROOT PRODUCER RECEIVER RESOLVER; --old-prepare OLD_BINARY REQUEST NQ_CONFIG INSTANCE STATE OLD_REALIZATION CALLER')
