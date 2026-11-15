#!/usr/bin/env python3
"""Check exact shared source vectors; does not execute or qualify the Rust adapter.

The wire fixtures deliberately contain ASCII strings and safe integers only.
This small-domain encoder is not a general NQ/JCS implementation. NQ-owned
canonical vectors are executed through nq_protocol by the deferred Rust tests.
"""
import hashlib
import json
from pathlib import Path
import sys


def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def canonical_fixture(value):
    def check(x):
        if isinstance(x, str):
            if not x.isascii():
                raise ValueError('wire fixture leaves its ASCII-only domain')
        elif isinstance(x, bool) or x is None:
            pass
        elif isinstance(x, int):
            if abs(x) > 9_007_199_254_740_991:
                raise ValueError('wire fixture integer is not exact I-JSON')
        elif isinstance(x, list):
            for child in x:
                check(child)
        elif isinstance(x, dict):
            for key, child in x.items():
                check(key)
                check(child)
        else:
            raise ValueError('wire fixture leaves its exact encoder domain')
    check(value)
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def identity(value, field):
    return digest(canonical_fixture({k: v for k, v in value.items() if k != field}))


def verify(root):
    manifest = json.loads((root / 'conformance.json').read_bytes())
    objects = {}
    for name, expected in manifest['files'].items():
        raw = (root / name).read_bytes()
        if digest(raw) != expected:
            raise ValueError(f'{name}: fixture digest differs')
        value = json.loads(raw)
        if canonical_fixture(value) != raw:
            raise ValueError(f'{name}: fixture is not its exact canonical bytes')
        objects[name] = value
    config, query, support = (objects[n] for n in ['config.json', 'query.json', 'support-current.json'])
    realization = config['realization']
    if realization != objects['realization.json'] or identity(realization, 'realization_id') != realization['realization_id']:
        raise ValueError('realization fixture preimage differs')
    if 'expected_diagnostic' in config:
        raise ValueError('static enrollment contains a dynamic basis')
    template = {k: v for k, v in config.items() if k != 'realization'}
    if digest(canonical_fixture(template)) != realization['configuration_digest']:
        raise ValueError('configuration is not the accepted static enrollment')
    if identity(query, 'query_id') != query['query_id'] or identity(support, 'support_id') != support['support_id']:
        raise ValueError('query/support fixture preimage differs')
    for field in ['subject_id', 'scope_id']:
        if config[field] != query[field]:
            raise ValueError(f'{field}: query differs from config')
    for suffix,query_name in [('a','query.json'),('b','query-b.json')]:
        request=objects[f'request-{suffix}.json'];q=objects[query_name];inputs=request['inputs'];artifact=inputs['inputs'][0]['artifact']
        if identity(request,'request_id') != request['request_id'] or identity(inputs,'inputs_id') != inputs['inputs_id'] or identity(artifact,'artifact_id') != artifact['artifact_id']:
            raise ValueError('request/input/native artifact fixed ASCII preimage differs')
        if q['diagnostic_inputs_id'] != inputs['inputs_id'] or q['artifact_ids'] != [artifact['artifact_id']] or q['observation_id'] != request['observation_id']:
            raise ValueError('query differs from selected request diagnostic basis')
        if artifact['subject']['id']!=config['subject_id'] or artifact['subject']['scope']['digest']!=config['scope_id'] or request['policy']['subject']!=artifact['subject']:
            raise ValueError('request differs from static subject/scope enrollment')
        if artifact['profile_semantic_id']!=config['profile_semantic_id'] or identity(q,'query_id')!=q['query_id']:
            raise ValueError('request profile/query preimage differs')
    if objects['request-a.json']['inputs']['inputs_id']==objects['request-b.json']['inputs']['inputs_id']:
        raise ValueError('two distinct request bases required')
    for name,expected in manifest['negative_contexts'].items():
        request=objects[name+'-request.json'];q=objects[name+'-query.json'];support_negative=objects[name+'-support.json']
        inputs=request['inputs'];row=inputs['inputs'][0]
        if identity(request,'request_id')!=request['request_id'] or identity(inputs,'inputs_id')!=inputs['inputs_id'] or identity(q,'query_id')!=q['query_id']:
            raise ValueError('negative request/input/query preimage differs')
        artifacts=[row['artifact']['artifact_id']] if row['status']=='delivered' else []
        if artifacts!=q['artifact_ids'] or len(artifacts)!=expected['artifact_count'] or q['diagnostic_inputs_id']!=inputs['inputs_id'] or q['observation_id']!=request['observation_id']:
            raise ValueError('negative query differs from exact diagnostic context')
        if row['key']['subject_id']!=config['subject_id'] or row['key']['vantage_id']!=config['diagnostic_vantage_id'] or q['scope_id']!=config['scope_id']:
            raise ValueError('negative context differs from enrolled key/scope')
        if support_negative['standing']!='unknown' or support_negative['evidence_refs'] or support_negative['contradiction_refs'] or support_negative['expiry'] is not None or identity(support_negative,'support_id')!=support_negative['support_id']:
            raise ValueError('negative context fabricated positive support')
        if any(support_negative[field]!=q[field] for field in q if field!='schema'):
            raise ValueError('negative support differs from query')
    original=objects['nightshift-correspondence-negative-family/SOURCE.json']
    for name,row in original['files'].items():
        if digest((root/'nightshift-correspondence-negative-family'/name).read_bytes())!='sha256:'+row['sha256']:
            raise ValueError('original owning negative family changed')
    for field in query:
        if field != 'schema' and query[field] != support[field]:
            raise ValueError(f'{field}: support differs from query')
    if support['authority_id'] != config['authority_id']:
        raise ValueError('support authority differs from enrollment')
    if digest(canonical_fixture(objects['nq-scope-preimage.json'])) != manifest['scope_id'] or config['scope_id'] != manifest['scope_id']:
        raise ValueError('NQ fixed ASCII scope golden differs')
    return len(objects), len(manifest['capacity_vectors']), len(manifest['nq_canonical_vectors'])


if __name__ == '__main__':
    root = Path(sys.argv[1]) if len(sys.argv) == 2 else Path(__file__).resolve().parents[1] / 'artifacts/nightshift-filesystem-support-v1'
    files, laws, canonical = verify(root)
    print(f'PASS source-vector integrity: {files} exact wire files, {laws} deferred native law cases, {canonical} deferred NQ canonicalization cases; no native qualification claim')
