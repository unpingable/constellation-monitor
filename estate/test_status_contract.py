"""Malformed producer documents must not poison a concurrent host pass."""
import copy
import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from test_collect import c

GOOD = {"schema": "project.ops.status/v1", "concerns": [
    {"id": "demo.ready",
     "observation": {"local_state": "PRESENT", "reason": "ready"}}]}
MISSING = object()


@pytest.mark.parametrize('path,value', [
    ('document', None), ('document', []), ('schema', None),
    ('concerns', MISSING), ('concerns', None), ('concerns', {}), ('concerns', 'bad'),
    ('concerns[0]', None), ('concerns[0]', []), ('concerns[0]', 1),
    *[('id', v) for v in (MISSING, None, 1, False, [], {}, '', '  ', 'x' * 257)],
    *[('required', v) for v in (None, 1, 'true', [], {})],
    *[('observation', v) for v in ([], '', False, 1)],
    *[('observation.local_state', v) for v in ([], {}, 1, '', '  ', 'x' * 65)],
    *[('observation.reason', v) for v in (None, [], {}, 1, 'x' * 4097)],
    *[('observation.observed_at', v) for v in ('x' * 129,)],
    *[('observation.valid_for_seconds', v) for v in ('x' * 129,)],
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
        bad, healthy = list(pool.map(lambda svc: c.evaluate_safely(svc, 1), services))
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


@pytest.mark.parametrize('state', ['REFUSED', 'DRIFT_OBSERVED', 'FUTURE_PROJECT_STATE', 'x' * 64])
def test_opaque_state_and_default_required_preserved(monkeypatch, state):
    doc = copy.deepcopy(GOOD)
    doc['concerns'][0]['observation']['local_state'] = state
    monkeypatch.setattr(c, 'runtime_state', lambda *a: {'up': True})
    monkeypatch.setattr(c, 'run', lambda argv, *a, **k:
                        (0, json.dumps(doc if argv == ['failing'] else GOOD).encode(), ''))
    services = [{'name': name, 'runtime': {},
                 'status': {'kind': 'project-ops-status', 'argv': [name]}}
                for name in ('failing', 'healthy')]
    with ThreadPoolExecutor(max_workers=2) as pool:
        failing, healthy = list(pool.map(lambda svc: c.evaluate_safely(svc, 1), services))
    assert failing['concerns'][0]['state'] == state
    assert failing['concerns'][0]['required'] is True
    assert failing['verdict'] == 'DEGRADED'
    assert failing['failing'] == ['demo.ready']
    assert healthy['verdict'] == 'OK'
    assert healthy['concerns'][0]['state'] == 'PRESENT'


@pytest.mark.parametrize('item', [
    {'id': 'demo.ready'}, {'id': 'demo.ready', 'observation': None},
    {'id': 'demo.ready', 'observation': {}},
    {'id': 'demo.ready', 'observation': {'local_state': None}},
    {'id': 'demo.ready', 'observation_present': False,
     'observation': {'local_state': 'PRESENT'}},
    {'id': 'demo.ready', 'observation': {'observation_present': False, 'local_state': 'PRESENT'}},
])
def test_absence_fallback(monkeypatch, item):
    doc = {'concerns': [item]}
    monkeypatch.setattr(c, 'run', lambda *a, **k: (0, json.dumps(doc).encode(), ''))
    concerns, error = c.project_status({'argv': ['producer']}, 1)
    assert error is None
    assert concerns[0]['state'] == 'ABSENT'
    assert concerns[0]['required'] is True


@pytest.mark.parametrize('validity', [None, True, False, 0, -1, '60', [], {}, float('nan'), float('inf')])
def test_invalid_validity_has_no_bound(monkeypatch, validity):
    doc = copy.deepcopy(GOOD)
    doc['concerns'][0]['observation'].update(observed_at='2020-01-01T00:00:00Z',
                                            valid_for_seconds=validity)
    monkeypatch.setattr(c, 'run', lambda *a, **k: (0, json.dumps(doc).encode(), ''))
    concerns, error = c.project_status({'argv': ['producer']}, 1)
    assert error is None
    assert concerns[0]['state'] == 'PRESENT'


@pytest.mark.parametrize('validity', [None, 60])
def test_nan_observed_at_only_makes_its_concern_unknown(monkeypatch, validity):
    doc = copy.deepcopy(GOOD)
    bad = copy.deepcopy(doc['concerns'][0])
    bad['id'] = 'demo.nan'
    bad['observation'].update(observed_at=float('nan'), valid_for_seconds=validity)
    doc['concerns'].append(bad)
    monkeypatch.setattr(c, 'run', lambda *a, **k: (0, json.dumps(doc).encode(), ''))
    concerns, error = c.project_status({'argv': ['producer']}, 1)
    assert error is None
    assert [x['state'] for x in concerns] == ['PRESENT', 'UNKNOWN']


def test_rehearsal_17_null_id(monkeypatch):
    assert_isolated(monkeypatch, b'{"concerns": [{"id": null}]}', 'id')


def test_unexpected_evaluator_exception_does_not_stop_host(tmp_path, monkeypatch):
    registry, report = tmp_path / 'registry.json', tmp_path / 'estate.json'
    registry.write_text(json.dumps({'schema': 'constellation.estate_registry/v1',
                                   'services': [{'name': name, 'runtime': {'systemd': name + '.service'}}
                                                for name in ('bad', 'healthy')]}))
    original = c.evaluate

    def injected(svc, timeout):
        if svc['name'] == 'bad':
            raise RuntimeError('injected ' + 'x' * 10000)
        return original(svc, timeout)

    monkeypatch.setattr(c, 'evaluate', injected)
    monkeypatch.setattr(c, 'runtime_state', lambda *a: {'up': True})
    monkeypatch.setattr(c, 'coverage', lambda *a: [])
    assert c.main(['--registry', str(registry), '--output', str(report)]) == 0
    services = {s['name']: s for s in json.loads(report.read_text())['services']}
    assert services['bad']['verdict'] == 'UNKNOWN'
    assert services['bad']['reason'].startswith('service evaluation failed: RuntimeError: injected')
    assert len(services['bad']['reason']) <= 400
    assert services['healthy']['verdict'] == 'OK'
    assert services['estate-coverage']['verdict'] == 'OK'
