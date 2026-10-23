"""Exercise the B2-1 release renderer offline against its labelwatch fixture."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from unittest import mock

import pytest
from test_monitored import m, NOW, HERE

SITE = Path('/data/git/.worktrees/cartography-b2-install-20261022/architecture/site')
COLLECTOR = Path(os.environ.get('SITE_TEST_COLLECTOR', '/data/git/.worktrees/monitor-testbed-reader-20261022/estate/constellation-estate-collect.py'))


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


@pytest.mark.skipif(not SITE.is_dir() or not COLLECTOR.is_file(), reason='read-only B2-1 fixture/collector unavailable')
def test_labelwatch_derived_declarations_keep_acquired_verdicts(tmp_path):
    common = module('site_common', SITE / 'lib/common.py')
    with mock.patch.dict('sys.modules', {'common': common}):
        renderer = module('site_renderer', SITE / 'lib/render.py')
        rendered = tmp_path / 'release'
        registry = renderer.render(renderer.load(SITE / 'tests/fixtures/labelwatch.toml'),
                                   json.loads((SITE / 'tests/fixtures/facts.json').read_text()), rendered, COLLECTOR)
    assert len(registry['services']) >= 37
    derived = [s for s in registry['services'] if s != m.tomllib.loads((rendered / 'services.d' / (s['name'] + '.toml')).read_text())]
    assert len(derived) >= 9
    estate = {'schema': 'constellation.estate/v1', 'site': registry['site'],
              'generated_at': '2026-10-22T21:00:00Z',
              'registry_sha256': hashlib.sha256((rendered / 'estate.json').read_bytes()).hexdigest(),
              'services': [dict(name=s['name'], verdict='OK', reason='synthetic acquisition for declaration join test') for s in registry['services']]}
    (tmp_path / 'estate.json').write_text(json.dumps(estate))
    args = m.parser().parse_args(['--registry', str(rendered / 'estate.json'), '--estate', str(tmp_path / 'estate.json'),
        '--services-dir', str(rendered / 'services.d'), '--attention-config', str(rendered / 'attention.toml'),
        '--attention-report', str(HERE / 'fixtures/report.json'), '--policy', str(HERE / 'fixtures/policy.json'),
        '--metric-alerts', str(HERE / 'fixtures/metrics.json'), '--receipts-index', str(HERE / 'fixtures/receipts/index.json'), 'list'])
    doc = m.build(args, NOW)
    assert len(doc['services']) == len(registry['services'])
    assert all(s['verdict'] == 'OK' for s in doc['services'])
    assert all(s['revision'].startswith('sha256:') for s in doc['services'])
    assert not any('declaration differs' in str(s) for s in doc['services'])


@pytest.mark.skipif(not SITE.is_dir(), reason='read-only Cartography renderer unavailable')
def test_cartography_status_link_patch_applies_and_renders_offline(tmp_path):
    import subprocess
    import shutil
    path = Path('architecture/beta-observability/mvp/status-site/render_status.py')
    source = SITE.parent / 'beta-observability/mvp/status-site/render_status.py'
    target = tmp_path / path
    target.parent.mkdir(parents=True)
    shutil.copyfile(source, target)
    patch = HERE.parent / 'packaging/monitored/status-site-monitored-link.patch'
    subprocess.run(['patch', '-p1', '--input', str(patch)], cwd=tmp_path, check=True, capture_output=True)
    output = tmp_path / 'out'
    # All missing inputs exercise the unavailable path without contacting a host.
    subprocess.run([os.sys.executable, str(target), '--out', str(output), '--no-tls',
                    '--posture-root', str(tmp_path / 'missing'), '--attention-dir', str(tmp_path / 'missing'),
                    '--saved-checks', str(tmp_path / 'missing'), '--nightshift-db', str(tmp_path / 'missing')],
                   env=dict(os.environ, PATH='/nonexistent', PYTHONDONTWRITEBYTECODE='1'),
                   check=True, capture_output=True)
    assert 'href="monitored.html"' in (output / 'index.html').read_text()
