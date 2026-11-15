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


def inventory_preimage(inventory):
    return json.dumps({k:v for k,v in inventory.items() if k!='sha256'},sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def load_release(cargo_json, argv_json):
    raw=Path(cargo_json).read_bytes()
    try:
        records=[json.loads(line) for line in raw.splitlines() if line.strip()]
        argv=json.loads(Path(argv_json).read_bytes())
    except (ValueError,UnicodeError) as error:
        raise ValueError('malformed or truncated production Cargo JSON') from error
    return validate_release(records,argv)


def validate_release(records,argv):
    if not isinstance(argv,list) or not argv or any(not isinstance(a,str) for a in argv) or argv[:2]!=['cargo','build'] or any(a not in argv for a in ['--locked','--release','--message-format=json']):
        raise ValueError('actual owning production Cargo argv required')
    packages=[argv[i+1] for i,arg in enumerate(argv[:-1]) if arg=='-p']
    if packages!=['constellation-host-posture','constellation-status-projection','pulse-nq-load-support','pulse-nq-filesystem-support'] or '--bins' not in argv:
        raise ValueError('exact owning four-helper production selection required')
    if not records or any(not isinstance(row,dict) or not isinstance(row.get('reason'),str) for row in records):
        raise ValueError('complete production Cargo stream required')
    finished=[row for row in records if row['reason']=='build-finished']
    if len(finished)!=1 or records[-1] is not finished[0] or finished[0].get('success') is not True:
        raise ValueError('production Cargo stream is unsuccessful or truncated')
    selected={}
    for index,row in enumerate(records):
        if row['reason']=='compiler-artifact':
            if not isinstance(row.get('package_id'),str) or not isinstance(row.get('target'),dict) or not isinstance(row.get('profile'),dict) or not isinstance(row.get('features'),list):
                raise ValueError('malformed actual compiler artifact')
            if row.get('executable') and row['target'].get('name') in NAMES:
                name=row['target']['name']
                if name in selected or row['target'].get('kind')!=['bin'] or row['profile'].get('test') is not False or row['profile'].get('opt_level')!='3' or row['profile'].get('debug_assertions') is not False:
                    raise ValueError('missing/duplicate or nonproduction selected compiler artifact')
                selected[name]={'record_index':index,'compiler_artifact':row}
        elif row['reason']=='build-script-executed':
            if not isinstance(row.get('package_id'),str) or not isinstance(row.get('out_dir'),str):
                raise ValueError('malformed actual build-script record')
    if set(selected)!=set(NAMES):
        raise ValueError('actual production stream lacks the whole four-helper cohort')
    return records,argv,selected


def production_source_inputs():
    values={key:os.environ.get(key,'') for key in ['MONITOR_SOURCE_COMMIT','MONITOR_BUILD_IDENTITY','CONSTELLATION_HOST_POSTURE_SOURCE_TREE_DIGEST','CONSTELLATION_HOST_POSTURE_CARGO_LOCK_DIGEST','CONSTELLATION_HOST_POSTURE_TOOLCHAIN_IDENTITY']}
    if not identity.re.fullmatch(r'[0-9a-f]{40}',values['MONITOR_SOURCE_COMMIT']) or not values['MONITOR_BUILD_IDENTITY']:
        raise ValueError('actual product source/build inputs required')
    for key in ['CONSTELLATION_HOST_POSTURE_SOURCE_TREE_DIGEST','CONSTELLATION_HOST_POSTURE_CARGO_LOCK_DIGEST']:
        if not identity.re.fullmatch(r'sha256:[0-9a-f]{64}',values[key]):
            raise ValueError('actual product tree/lock input required')
    if not values['CONSTELLATION_HOST_POSTURE_TOOLCHAIN_IDENTITY'].startswith('rustc '):
        raise ValueError('actual compiler identity required')
    return values


def inventory_from_observed(cargo_json,argv_json,observed_hashes):
    """Complete ordered public Cargo stream, deliberately a cohort superset."""
    records,argv,selected=load_release(cargo_json,argv_json)
    if set(observed_hashes)!=set(NAMES) or any(not identity.re.fullmatch(r'[0-9a-f]{64}',value) for value in observed_hashes.values()):
        raise ValueError('exact observed whole-cohort ELF hashes required')
    cohort={name:{**row,'sha256':observed_hashes[name]} for name,row in selected.items()}
    inventory={'schema_version':1,'scope':'Complete actual owning four-helper production Cargo inventory; cohort superset, not minimal FS reachability or NQ realization equivalence','collector_source_sha256':digest(__file__),'production_argv':argv,'production_argv_sha256':digest(argv_json),'production_stdout_sha256':digest(cargo_json),'source_inputs':production_source_inputs(),'records':records,'selected_cohort':cohort}
    inventory['sha256']=hashlib.sha256(inventory_preimage(inventory)).hexdigest()
    return inventory


def production_inventory(cargo_json,argv_json,production_target):
    records,argv,selected=load_release(cargo_json,argv_json)
    target=Path(production_target).resolve()
    observed={}
    for name,row in selected.items():
        path=Path(row['compiler_artifact']['executable'])
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(target):
            raise ValueError('selected output must be an ordinary production target file')
        observed[name]=digest(path)
    return inventory_from_observed(cargo_json,argv_json,observed)


def verify_inventory(inventory,executables):
    if hashlib.sha256(inventory_preimage(inventory)).hexdigest()!=inventory['sha256'] or set(inventory['selected_cohort'])!=set(NAMES):
        raise ValueError('actual production inventory digest/cohort changed')
    if inventory.get('schema_version')!=1:
        raise ValueError('unsupported production inventory schema')
    records,argv,selection=validate_release(inventory['records'],inventory['production_argv'])
    for name in NAMES:
        selected=inventory['selected_cohort'][name];expected=executables[name]
        matches=[i for i,row in enumerate(records) if row.get('reason')=='compiler-artifact' and row.get('executable') and row.get('target',{}).get('name')==name]
        if matches!=[selected['record_index']] or records[selected['record_index']]!=expected['compiler_artifact'] or selected['compiler_artifact']!=expected['compiler_artifact'] or selected['sha256']!=expected['sha256']:
            raise ValueError('selected FS/whole-cohort record or ELF binding differs')


def verify_production_inputs(receipt):
    origin=receipt['production_inputs']
    if set(origin)!={'argv','stdout','stderr','exit'}:
        raise ValueError('complete inherited production inputs required')
    for name,row in origin.items():
        path=Path(row['path'])
        if path.is_symlink() or not path.is_file() or path.stat().st_size!=row['bytes'] or digest(path)!=row['sha256']:
            raise ValueError('inherited actual production input changed: '+name)
    if Path(origin['exit']['path']).read_text().strip()!='0':
        raise ValueError('inherited production command did not pass')
    records,argv,selected=load_release(origin['stdout']['path'],origin['argv']['path'])
    inventory=receipt['executables']['pulse-nq-filesystem-support']['production_dependency_inventory']
    if records!=inventory['records'] or digest(origin['stdout']['path'])!=inventory['production_stdout_sha256'] or digest(origin['argv']['path'])!=inventory['production_argv_sha256'] or production_source_inputs()!=inventory['source_inputs']:
        raise ValueError('inherited production/source inputs differ from frozen inventory')
    return receipt


def stage_production_inputs(inputs,out_dir):
    bundle=Path(out_dir)/'production-input';bundle.mkdir(mode=0o700)
    staged={}
    for name in ('argv','stdout','stderr','exit'):
        row=inputs[name];suffix='.argv.json' if name=='argv' else '.'+name
        relative='production-input/production'+suffix
        destination=Path(out_dir)/relative
        shutil.copyfile(row['path'],destination)
        if digest(destination)!=row['sha256'] or destination.stat().st_size!=row['bytes']:
            raise ValueError('production input changed during evidence staging: '+name)
        staged[name]={**row,'packaged_path':relative}
    return staged


def verify_staged_inputs(receipt_path,out_dir):
    receipt=json.loads(Path(receipt_path).read_bytes())
    inputs=receipt['production_inputs']
    if set(inputs)!={'argv','stdout','stderr','exit'}:
        raise ValueError('complete actual production input bundle required')
    for name,row in inputs.items():
        suffix='.argv.json' if name=='argv' else '.'+name
        relative='production-input/production'+suffix
        path=Path(out_dir)/relative
        if row.get('packaged_path')!=relative or path.is_symlink() or not path.is_file() or path.stat().st_size!=row['bytes'] or digest(path)!=row['sha256']:
            raise ValueError('staged actual production input changed: '+name)
    if (Path(out_dir)/inputs['exit']['packaged_path']).read_text().strip()!='0':
        raise ValueError('staged actual production command did not pass')
    inventory=receipt['executables']['pulse-nq-filesystem-support']['production_dependency_inventory']
    records,argv,selected=load_release(Path(out_dir)/inputs['stdout']['packaged_path'],Path(out_dir)/inputs['argv']['packaged_path'])
    verify_inventory(inventory,receipt['executables'])
    if records!=inventory['records'] or argv!=inventory['production_argv'] or inputs['stdout']['sha256']!=inventory['production_stdout_sha256'] or inputs['argv']['sha256']!=inventory['production_argv_sha256']:
        raise ValueError('staged actual production stream differs from frozen inventory')
    return receipt


def reuse(receipt_path,bin_dir,out_dir):
    """Verify inherited data; never pretend the producer's Cargo ran again."""
    receipt=verify(receipt_path,bin_dir);verify_production_inputs(receipt)
    copied=dict(receipt)
    copied['production_inputs']=stage_production_inputs(receipt['production_inputs'],out_dir)
    copied['selection_inherited_from']={'path':str(Path(receipt_path).resolve()),'sha256':digest(receipt_path),'scope':'Prior actual production/freeze data; not commands executed by this continuation'}
    with (Path(out_dir)/'frozen-cohort.json').open('x') as out:json.dump(copied,out,indent=2);out.write('\n')
    print(json.dumps({'frozen_bin_dir':str(Path(bin_dir).resolve()),'selection_inherited_from':copied['selection_inherited_from']}))


def freeze(cargo_json, expected_hp, production_target, bin_dir, receipt_path, argv_json):
    production_target, bin_dir = Path(production_target).resolve(), Path(bin_dir).resolve()
    if bin_dir.is_relative_to(production_target) or production_target.is_relative_to(bin_dir):
        raise ValueError('frozen cohort must be outside mutable production Cargo target')
    records,argv,selected_rows=load_release(cargo_json,argv_json)
    selected={name:row['compiler_artifact'] for name,row in selected_rows.items()}
    inventory=production_inventory(cargo_json,argv_json,production_target)
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
    origins['pulse-nq-filesystem-support']['production_dependency_inventory']=inventory
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
    prefix=Path(cargo_json).with_suffix('')
    inputs={'stdout':Path(cargo_json),'argv':Path(argv_json),'stderr':prefix.with_suffix('.stderr'),'exit':prefix.with_suffix('.exit')}
    if any(not path.is_file() for path in inputs.values()) or inputs['exit'].read_text().strip()!='0':
        raise ValueError('actual successful production argv/stdout/stderr/exit required')
    production_inputs={name:{'path':str(path.resolve()),'sha256':digest(path),'bytes':path.stat().st_size} for name,path in inputs.items()}
    production_inputs=stage_production_inputs(production_inputs,Path(receipt_path).parent)
    receipt = {'schema_version': 1, 'frozen_bin_dir': str(bin_dir), 'production_target': str(production_target),
               'production_argv': json.loads(Path(argv_json).read_text()), 'production_argv_sha256': digest(argv_json),
               'production_stdout_sha256': digest(cargo_json), 'production_inputs':production_inputs, 'executables': origins,
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
    fs_origin=receipt['executables']['pulse-nq-filesystem-support']
    verify_inventory(fs_origin['production_dependency_inventory'],receipt['executables'])
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
    elif command == 'inventory' and len(arguments)==4:
        cargo_json,argv_json,target,output=arguments
        inventory=production_inventory(cargo_json,argv_json,target)
        with Path(output).open('x') as out:json.dump(inventory,out,indent=2);out.write('\n')
    elif command=='reuse' and len(arguments)==3:
        reuse(*arguments)
    elif command=='input-data' and len(arguments)==2:
        verify_staged_inputs(*arguments)
    elif command == 'check' and len(arguments) == 2:
        verify(*arguments)
    elif command == 'payload' and len(arguments) == 2:
        verify_payload(*arguments)
    elif command == 'package' and len(arguments) == 2:
        print(json.dumps(verify_package(*arguments), sort_keys=True))
    else:
        sys.exit('usage: frozen-helper-cohort.py freeze CARGO_JSON EXPECTED_HP PRODUCTION_TARGET BIN_DIR RECEIPT ARGV_JSON | inventory CARGO_JSON ARGV_JSON PRODUCTION_TARGET OUTPUT | reuse RECEIPT BIN_DIR OUT_DIR | input-data RECEIPT OUT_DIR | check RECEIPT BIN_DIR | payload RECEIPT STAGED_BIN | package RECEIPT DEB')
