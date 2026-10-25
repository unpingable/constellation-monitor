"""Malformed producer documents must not poison a concurrent host pass."""
import copy
import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from test_collect import c

GOOD = {"schema": "project.ops.status/v1", "concerns": [
    {"id": "demo.ready", "required": True,
     "observation": {"local_state": "PRESENT", "reason": "ready"}}]}
MISSING = object()


@pytest.mark.parametrize('path,value', [
    ('document', None), ('document', []), ('schema', None),
    ('concerns', MISSING), ('concerns', None), ('concerns', {}), ('concerns', 'bad'),
    ('concerns[0]', None), ('concerns[0]', []), ('concerns[0]', 1),
    *[('id', v) for v in (MISSING, None, 1, False, [], {}, '', 'x' * 257)],
    *[('required', v) for v in (MISSING, None, 1, 'true', [], {})],
    *[('observation', v) for v in ([], '', False, 1)],
    *[('observation.local_state', v) for v in (MISSING, None, [], {}, 1, 'bogus', 'x' * 10000)],
    *[('observation.reason', v) for v in (None, [], {}, 1, 'x' * 4097)],
    *[('observation.observed_at', v) for v in ([], {}, True, -1, float('inf'), 'x' * 129)],
    *[('observation.valid_for_seconds', v) for v in (True, 0, -1, '60', [], {}, float('nan'))],
])
def test_bad_document_isolated(monkeypatch, path, value):
    doc = copy.deepcopy(GOOD)
    if path == 'document':
        doc = value
    elif path == 'concerns[0]':
        doc['concerns'][0] = value
    else:
        target = doc if path in ('schema', 'concerns') else doc['concerns'][0]
        keys = path.split('.')
        for key in keys[:-1]:
            target = target[key]
        if value is MISSING:
            del target[keys[-1]]
        else:
            target[keys[-1]] = value
    assert_isolated(monkeypatch, json.dumps(doc).encode(), path)


def assert_isolated(monkeypatch, raw, field):
    monkeypatch.setattr(c, 'runtime_state', lambda *a: {'up': True})
    monkeypatch.setattr(c, 'run', lambda argv, *a, **k:
                        (0, raw if argv == ['bad'] else json.dumps(GOOD).encode(), ''))
    services = [{'name': name, 'runtime': {}, '_has_declaration': True,
                 'status': {'kind': 'project-ops-status', 'argv': [name]}}
                for name in ('bad', 'healthy')]
    with ThreadPoolExecutor(max_workers=2) as pool:
        bad, healthy = list(pool.map(lambda svc: c.evaluate(svc, 1), services))
    assert bad['verdict'] == 'UNKNOWN'
    assert 'producer input fault' in bad['reason']
    assert field in bad['reason']
    assert len(bad['reason']) <= 400
    assert all(x['id'] == 'declaration.drift' for x in bad['concerns'])
    assert healthy['verdict'] == 'OK'
    assert healthy['concerns'][0]['id'] == 'demo.ready'


@pytest.mark.parametrize('raw', [b'{', b'null trailing', b'\xff', b'[' * 2000,
                                     b' ' * ((1 << 20) + 1)])
def test_invalid_json_or_oversize_isolated(monkeypatch, raw):
    assert_isolated(monkeypatch, raw, 'document')


def test_extra_fields_and_optional_observation_fields(monkeypatch):
    doc = copy.deepcopy(GOOD)
    doc['extension'] = {'anything': [None, 1]}
    doc['concerns'][0]['extension'] = False
    doc['concerns'][0]['observation']['extension'] = ['ignored']
    monkeypatch.setattr(c, 'run', lambda *a, **k: (0, json.dumps(doc).encode(), ''))
    concerns, error = c.project_status({'argv': ['producer']}, 1)
    assert error is None and concerns[0]['state'] == 'PRESENT'
    for observation in (None, {'local_state': 'PRESENT'}):
        doc['concerns'][0]['observation'] = observation
        concerns, error = c.project_status({'argv': ['producer']}, 1)
        assert error is None
