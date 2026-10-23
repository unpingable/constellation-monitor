"""Versioned, bounded, read-only JSON inspection over the existing incident shim."""
import importlib.util
import json
from pathlib import Path
import hashlib
import subprocess
import sys
import pytest

spec = importlib.util.spec_from_file_location('incident_owner_inspection', Path(__file__).with_name('constellation-incidents.py'))
inc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inc)
spec2 = importlib.util.spec_from_file_location('incident_fixture_generator', Path(__file__).with_name('generate_board_fixture.py'))
generator = importlib.util.module_from_spec(spec2)
spec2.loader.exec_module(generator)
NOW = generator.NOW


@pytest.fixture
def store(tmp_path):
    s = inc.SqliteStore(str(tmp_path / 'incidents.sqlite'))
    for e in generator.generate()['incidents']:
        s.adopt(e['incident'])
        for a in e['attempts']:
            s.attempt(e['incident']['id'], a['episode'], a)
        for event in e['events']:
            s.event(e['incident']['id'], event['at'], event['kind'], json.loads(event['detail']))
    s.heartbeat(inc.iso(NOW), True, 'fixture')
    yield s
    s.db.close()


def test_inspection_preserves_exact_rows_attempts_append_history_and_meta(store):
    doc = inc.inspection(store, NOW)
    assert doc['schema'] == 'constellation.incidents.inspection/v1'
    assert len(doc['incidents']) == 9
    assert doc['meta'] == store.meta()
    for e in doc['incidents']:
        identity = e['incident']['id']
        assert e['attempts'] == store.attempts(identity)
        assert e['events'] == store.events(identity)
    assert 'authority_decision' in doc['missing_fields']
    assert 'last_successful_sync_at' in doc['missing_fields']


def test_recent_and_old_resolved_window_and_exact_id(store):
    resolved = next(i for i in store.incidents(False) if i['state'] == 'resolved')
    store.update(resolved['id'], resolved_at=inc.iso(NOW - 90000))
    doc = inc.inspection(store, NOW)
    assert resolved['id'] not in {e['incident']['id'] for e in doc['incidents']}
    assert inc.inspection(store, NOW, resolved['id'])['incidents'][0]['incident']['id'] == resolved['id']
    with pytest.raises(ValueError, match='not retained'): inc.inspection(store, NOW, 'missing')


def test_readonly_uri_preserves_state_and_handles_uri_characters(tmp_path):
    original = tmp_path / 'original.sqlite'
    s = inc.SqliteStore(str(original))
    key = 'site:demo:service:down:unit'
    identity = s.open_incident(key, inc.iso(NOW), inc.iso(NOW))
    s.db.close()
    path = tmp_path / 'i ?#%.sqlite'
    original.rename(path)
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    first = inc.inspect_readonly(path, NOW)
    second = inc.inspect_readonly(path, NOW)
    assert first == second
    assert first['incidents'][0]['incident']['id'] == identity
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before
    assert set(p.name for p in tmp_path.iterdir()) <= {path.name, path.name + '-wal', path.name + '-shm'}
    missing = tmp_path / 'missing.sqlite'
    with pytest.raises(inc.StoreUnavailable): inc.inspect_readonly(missing, NOW)
    assert not missing.exists()


def test_failure_returns_nonzero_without_json_success(tmp_path):
    path = tmp_path / 'missing.sqlite'
    result = subprocess.run([sys.executable, inc.__file__, '--db', str(path), 'inspect'], capture_output=True)
    assert result.returncode == 3
    assert result.stdout == b''
    assert not path.exists()


def test_handover_inspection_never_imports_or_implies_sync_health(tmp_path, store):
    path = tmp_path / 'latest.json'
    doc = inc.export_unresolved(store, 'predecessor', NOW)
    path.write_text(json.dumps(doc))
    before = path.read_bytes()
    result = inc.inspect_handover(path, NOW)
    assert [{k: e[k] for k in ('incident', 'events', 'attempts')} for e in result['incidents']] == doc['incidents']
    assert all(e['metric_links'] == {} for e in result['incidents'])
    assert not result['meta']
    assert result['source']['kind'] == 'off-host-handover/v1'
    assert 'recently_resolved' in result['missing_fields']
    assert path.read_bytes() == before


def test_inspection_size_refuses_instead_of_truncating():
    with pytest.raises(ValueError, match='16 MiB'):
        inc.inspection_json({'text': 'x' * inc.INSPECTION_MAX_BYTES})


def test_contract_fixture_is_deterministic():
    assert generator.generate() == generator.generate()
    assert generator.generate() == json.loads((Path(__file__).parent / 'fixtures/inspection-v1-demo.json').read_text())


def test_inspection_is_one_snapshot_with_a_concurrent_writer(tmp_path, monkeypatch):
    path = tmp_path / 'concurrent.sqlite'
    writer = inc.SqliteStore(str(path))
    identity = writer.open_incident('site:demo:service:down:unit', inc.iso(NOW), inc.iso(NOW))
    writer.event(identity, inc.iso(NOW), 'detected', {'note': 'before'})
    writer.heartbeat(inc.iso(NOW), True, 'before')
    original = inc.SqliteStore
    wrote = []

    class DuringRead(original):
        def events(self, identity):
            if not wrote:
                writer.update(identity, needs_operator='after')
                writer.event(identity, inc.iso(NOW + 1), 'note', {'text': 'after'})
                writer.heartbeat(inc.iso(NOW + 1), True, 'after')
                wrote.append(True)
            return super().events(identity)

    monkeypatch.setattr(inc, 'SqliteStore', DuringRead)
    try:
        snapshot = inc.inspect_readonly(path, NOW)
        assert snapshot['meta']['last_sync_note'] == 'before'
        assert snapshot['incidents'][0]['incident']['needs_operator'] is None
        assert len(snapshot['incidents'][0]['events']) == 1
        latest = inc.inspect_readonly(path, NOW + 1)
        assert latest['meta']['last_sync_note'] == 'after'
        assert latest['incidents'][0]['incident']['needs_operator'] == 'after'
        assert len(latest['incidents'][0]['events']) == 2
    finally:
        writer.db.close()


def test_incident_limit_fails_without_a_partial_projection(store, monkeypatch):
    monkeypatch.setattr(store, 'incidents', lambda unresolved_only=True: [store.current('site:demo:service:service-down:api-gateway')] * 1001)
    with pytest.raises(ValueError, match='1000 incidents'):
        inc.inspection(store, NOW)
