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


def fingerprint_units(profile_directory):
    """Read Cargo 1.94's observed JSON/16-hex format; never metadata features."""
    root=Path(profile_directory)/'.fingerprint'
    units={}
    by_hash={}
    for path in sorted(root.glob('*/*.json')):
        if path.is_symlink() or path.parent.is_symlink():
            raise ValueError('fingerprint input must be ordinary owned build output')
        raw=path.read_bytes();row=json.loads(raw)
        token=path.with_suffix('').read_bytes()
        if len(token)!=16 or any(b not in b'0123456789abcdef' for b in token):
            raise ValueError('unsupported Cargo self fingerprint format')
        deps=row.get('deps')
        if not isinstance(deps,list) or any(not isinstance(d,list) or len(d)!=4 or not isinstance(d[0],int) or not isinstance(d[1],str) or not isinstance(d[2],bool) or not isinstance(d[3],int) for d in deps):
            raise ValueError('unsupported Cargo dependency fingerprint format')
        features=json.loads(row['features']) if row['features'] else None
        if features is not None and (not isinstance(features,list) or any(not isinstance(f,str) for f in features)):
            raise ValueError('unsupported Cargo unit features')
        key=str(path.relative_to(root));self_hash=int.from_bytes(bytes.fromhex(token.decode()),'little')
        units[key]={'fingerprint_json':row,'fingerprint_json_sha256':hashlib.sha256(raw).hexdigest(),'self_fingerprint':token.decode(),'self_hash_u64':self_hash,'features':features}
        by_hash.setdefault(self_hash,[]).append(key)
    if not units:
        raise ValueError('production Cargo fingerprints missing')
    return units,by_hash


def trace_fingerprint_units(profile_directory, selected_unit):
    """Follow only exact selected-unit edges, including build/proc-macro units."""
    available,index=fingerprint_units(profile_directory)
    if selected_unit not in available:
        raise ValueError('selected executable fingerprint missing')
    seen={};edges=[];active=set()
    def visit(key):
        if key in active:
            raise ValueError('cyclic Cargo fingerprint input')
        if key in seen:
            return
        active.add(key);unit=available[key];seen[key]=unit
        for package_hash,name,public,dependency_hash in unit['fingerprint_json']['deps']:
            matches=index.get(dependency_hash,[])
            if len(matches)!=1:
                raise ValueError(f'missing or ambiguous selected dependency fingerprint: {key} -> {name}')
            dependency=matches[0]
            edges.append({'from':key,'to':dependency,'dependency_name':name,'package_hash':package_hash,'public':public,'dependency_fingerprint_u64':dependency_hash})
            visit(dependency)
        active.remove(key)
    visit(selected_unit)
    return {'selected_unit':selected_unit,'units':dict(sorted(seen.items())),'edges':sorted(edges,key=lambda e:(e['from'],e['to'],e['dependency_name']))}


def compiler_record_for_unit(key, unit, records):
    """Join actual compiler/build-script records by Cargo's selected unit hash."""
    directory,filename=key.split('/')
    unit_hash=directory.rsplit('-',1)[-1]
    if filename.startswith('run-build-script-'):
        matches=[r for r in records if r.get('reason')=='build-script-executed' and Path(r.get('out_dir','')).parent.name==directory]
    else:
        if filename.startswith(('test-','example-')):
            raise ValueError('test/example unit reached from selected production executable')
        matches=[]
        for record in records:
            if record.get('reason')!='compiler-artifact' or record.get('profile',{}).get('test') is not False or sorted(record.get('features',[]))!=sorted(unit['features'] or []):
                continue
            name=record.get('target',{}).get('name','')
            target_matches=(filename=='lib-'+name+'.json' or filename=='bin-'+name+'.json' or filename=='build-script-'+name+'.json')
            if not target_matches:
                continue
            if any(Path(p).stem.endswith('-'+unit_hash) or directory in Path(p).parts for p in record.get('filenames',[])):
                matches.append(record)
    if len(matches)!=1:
        raise ValueError(f'missing or ambiguous actual production compiler record: {key}')
    return matches[0]


def footprint_preimage(footprint):
    """Private receipt encoding, not NQ/JCS: preserve Cargo's exact u64 ints."""
    return json.dumps({k:v for k,v in footprint.items() if k!='sha256'},sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def production_dependency_footprint(records, production_target, selected):
    """One selected FS ELF, not the all-features workspace or metadata graph."""
    target=Path(production_target).resolve();profile=target/'release';executable=Path(selected['executable'])
    if selected.get('target',{}).get('name')!='pulse-nq-filesystem-support' or selected['target'].get('kind')!=['bin'] or selected.get('profile',{}).get('test') is not False or selected['profile'].get('opt_level')!='3' or selected['profile'].get('debug_assertions') is not False:
        raise ValueError('selected FS artifact is not an actual final production binary record')
    if executable.is_symlink() or not executable.resolve().is_relative_to(profile) or not executable.is_file():
        raise ValueError('selected production FS executable is outside release output')
    roots=[]
    name=selected['target']['name']
    for path in sorted((profile/'.fingerprint').glob('*/bin-'+name+'.json')):
        suffix=path.parent.name.rsplit('-',1)[-1]
        hashed=profile/'deps'/(name.replace('-','_')+'-'+suffix)
        if hashed.is_file() and not hashed.is_symlink() and os.path.samefile(hashed,executable):
            roots.append(str(path.relative_to(profile/'.fingerprint')))
    if len(roots)!=1:
        raise ValueError('selected FS ELF has missing or ambiguous Cargo output/fingerprint binding')
    graph=trace_fingerprint_units(profile,roots[0])
    for key,unit in graph['units'].items():
        record=selected if key==roots[0] else compiler_record_for_unit(key,unit,records)
        if key==roots[0] and sorted(record['features'])!=sorted(unit['features'] or []):
            raise ValueError('selected FS features differ from actual compiler fingerprint')
        unit['compiler_record']=record
    footprint={'scope':'Exact selected native release FS compiler units; no metadata-only/dev/test feature union or NQ realization-equivalence claim','collector_source_sha256':digest(__file__),'production_target':str(target),'selected_executable_sha256':digest(executable),'selected_compiler_artifact':selected,**graph}
    footprint['sha256']=hashlib.sha256(footprint_preimage(footprint)).hexdigest()
    return footprint


def verify_footprint(footprint, expected):
    if hashlib.sha256(footprint_preimage(footprint)).hexdigest()!=footprint['sha256'] or footprint['selected_executable_sha256']!=expected['sha256'] or footprint['selected_compiler_artifact']!=expected['compiler_artifact'] or footprint['selected_unit'] not in footprint['units']:
        raise ValueError('selected FS production dependency footprint changed')


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
    origins['pulse-nq-filesystem-support']['production_dependency_footprint']=production_dependency_footprint(records,production_target,selected['pulse-nq-filesystem-support'])
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
    fs_origin=receipt['executables']['pulse-nq-filesystem-support']
    verify_footprint(fs_origin['production_dependency_footprint'],fs_origin)
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
    elif command == 'footprint' and len(arguments) == 4:
        cargo_json,target,selected_binary,output=arguments
        records=[json.loads(line) for line in Path(cargo_json).read_text().splitlines() if line.strip()]
        if not records or records[-1].get('reason')!='build-finished' or records[-1].get('success') is not True:
            raise ValueError('owning production build did not finish successfully')
        selected=[r for r in records if r.get('reason')=='compiler-artifact' and r.get('executable') and Path(r['executable']).resolve()==Path(selected_binary).resolve()]
        if len(selected)!=1:raise ValueError('selected production compiler artifact is missing or ambiguous')
        footprint=production_dependency_footprint(records,target,selected[0])
        with Path(output).open('x') as out:json.dump(footprint,out,indent=2);out.write('\n')
    elif command == 'check' and len(arguments) == 2:
        verify(*arguments)
    elif command == 'payload' and len(arguments) == 2:
        verify_payload(*arguments)
    elif command == 'package' and len(arguments) == 2:
        print(json.dumps(verify_package(*arguments), sort_keys=True))
    else:
        sys.exit('usage: frozen-helper-cohort.py freeze CARGO_JSON EXPECTED_HP PRODUCTION_TARGET BIN_DIR RECEIPT ARGV_JSON | footprint CARGO_JSON PRODUCTION_TARGET SELECTED_FS OUTPUT | check RECEIPT BIN_DIR | payload RECEIPT STAGED_BIN | package RECEIPT DEB')
