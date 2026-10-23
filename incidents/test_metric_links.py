"""Graph navigation preserves incident identity and configured scrape labels."""
import importlib.util
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


links = module('metric_links_test', 'metric_links.py')
inc = module('incidents_links_test', 'constellation-incidents.py')
FIRST = '2026-10-22T18:00:00Z'
AT = 1792692000
CONFIG = {'grafana': {'site': 'a site', 'host': 'machine&1', 'base_url': 'https://metrics.example/grafana/'}}


def test_stable_uids_encoding_and_minimum_window():
    result = links.incident_metric_links({'first_seen': FIRST, 'last_observed_at': FIRST}, **CONFIG['grafana'])
    assert set(result) == {'host', 'services', 'alerts'}
    for name, url in result.items():
        parsed = urlsplit(url)
        assert parsed.path == '/grafana/d/constellation-' + name
        assert parse_qs(parsed.query) == {'orgId': ['1'], 'var-site': ['a site'], 'var-host': ['machine&1'],
            'from': [str((AT - 1800) * 1000)], 'to': [str((AT + 1800) * 1000)]}
    assert links.metric_link(FIRST, site='a', host='b', now=AT) == links.metric_link('2026-10-22T20:00:00+02:00', site='a', host='b', now=AT)
    assert 'from=0' in links.metric_link(10, site='a', host='b', now=10)


@pytest.mark.parametrize('last,now,end', [(AT + 7200, AT + 9000, AT + 7200), (None, AT + 9000, AT + 9000), (AT + 60, AT + 9000, AT + 1800)])
def test_upper_window_uses_last_observation_or_now(last, now, end):
    result = links.incident_metric_links({'first_seen': FIRST, 'last_observed_at': last}, site='a', host='b', now=now)
    assert parse_qs(urlsplit(result['host']).query)['to'] == [str(end * 1000)]


@pytest.mark.parametrize('first', [None, '', True, -1, float('nan'), float('inf'), '2026-10-22T18:00:00', 'bad'])
def test_missing_or_invalid_first_seen_is_never_replaced(first):
    with pytest.raises(ValueError):
        links.metric_link(first, site='a', host='b')


@pytest.mark.parametrize('base', ['file:///etc/passwd', 'https://user:secret@example.org', 'https://example.org?x=y', 'https://example.org#x', '/relative'])
def test_bad_base_urls_are_refused(base):
    with pytest.raises(ValueError):
        links.metric_link(FIRST, site='a', host='b', base_url=base)


def test_show_and_inspect_share_links_without_changing_retained_rows(tmp_path, capsys):
    path = tmp_path / 'incidents.sqlite'
    store = inc.SqliteStore(str(path))
    identity = store.open_incident('site:demo:service:down:unit', FIRST, FIRST)
    store.update(identity, last_observed_at=inc.iso(AT + 7200))
    before = store.incidents(False)
    doc = inc.inspection(store, AT + 9000, config=CONFIG)
    entry = doc['incidents'][0]
    assert entry['incident'] == before[0]
    view = inc.show_view(store, identity, CONFIG, AT + 9000)
    for url in entry['metric_links'].values():
        assert url in view
    assert store.incidents(False) == before
    assert 'unavailable' in inc.show_view(store, identity, now=AT)
    config = tmp_path / 'incidents.json'
    config.write_text(json.dumps(CONFIG))
    assert inc.main(['--db', str(path), '--config', str(config), 'inspect']) == 0
    result = json.loads(capsys.readouterr().out)
    assert result['incidents'][0]['metric_links'] == entry['metric_links']
    assert inc.main(['--db', str(path), '--config', str(config), 'show', identity]) == 0
    assert entry['metric_links']['host'] in capsys.readouterr().out
    store.db.close()


def test_incomplete_config_and_invalid_observation_preserve_inspection(tmp_path):
    store = inc.SqliteStore(str(tmp_path / 'i.sqlite'))
    identity = store.open_incident('site:demo:service:down:unit', FIRST, None)
    entry = inc.inspection(store, AT, config=CONFIG)['incidents'][0]
    assert entry['metric_links'] == {}
    assert entry['incident']['first_seen'] is None
    store.update(identity, first_seen=FIRST, last_observed_at='invalid')
    assert inc.inspection(store, AT, config=CONFIG)['incidents'][0]['metric_links'] == {}
    store.db.close()


def test_malformed_optional_config_keeps_incident_inspection_available(tmp_path, capsys):
    path = tmp_path / 'i.sqlite'
    store = inc.SqliteStore(str(path))
    store.open_incident('site:demo:service:down:unit', FIRST, FIRST)
    store.db.close()
    config = tmp_path / 'bad.json'
    config.write_text('invalid')
    assert inc.main(['--db', str(path), '--config', str(config), 'inspect']) == 0
    entry = json.loads(capsys.readouterr().out)['incidents'][0]
    assert entry['metric_links'] == {}
    assert 'config could not be read' in entry['metric_links_status']
