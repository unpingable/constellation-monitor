"""Offline operator journeys and fail-unknown boundaries; no live host access."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import shutil
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('monitored', HERE / 'constellation-monitored.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
spec = importlib.util.spec_from_file_location('subset', HERE / 'toml_subset.py')
toml_subset = importlib.util.module_from_spec(spec)
spec.loader.exec_module(toml_subset)
NOW = m.stamp('2026-10-22T21:01:00Z')


class MonitoredTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'inputs'
        shutil.copytree(HERE / 'fixtures', self.root)
        self.argv = []
        for flag, filename in [('registry', 'registry.json'), ('estate', 'estate.json'), ('services-dir', 'services.d'), ('attention-config', 'attention.toml'), ('attention-report', 'report.json'), ('policy', 'policy.json'), ('metric-alerts', 'metrics.json'), ('coverage-evidence', 'coverage.json')]:
            self.argv += ['--' + flag, str(self.root / filename)]
        self.argv += ['--ledger', str(HERE / 'COVERAGE-FAMILIES.md'), '--now', '2026-10-22T21:01:00Z']
        self.args = m.parser().parse_args(self.argv + ['list'])

    def edit(self, name, change):
        path = self.root / name
        doc = json.loads(path.read_text())
        change(doc)
        path.write_text(json.dumps(doc))

    def build(self):
        return m.build(self.args, NOW)

    def rule(self, name='HostIoPressureHigh'):
        return next(r for r in self.build()['rules'] if r['rule'] == name)

    def service(self, name='web'):
        return next(r for r in self.build()['services'] if r['service'] == name)

    def family(self):
        return next(r for r in self.build()['coverage'] if r['family'] == 'block I/O pressure')

    def receipts(self):
        def populate(doc):
            doc['families']['block I/O pressure'] = {p: {'holds': True, 'evidence': ['fixture://example/history-trigger-recovery#' + p]} for p in ('observed', 'routed', 'runbook', 'drilled')}
        self.edit('coverage.json', populate)

    def test_operator_finds_degraded_service_and_what_would_tell_them(self):
        row = self.service()
        self.assertEqual(row['verdict'], 'DEGRADED')
        self.assertIn('HTTP 503', row['concern'])
        self.assertIn('systemd=web.service', row['runtime'])
        self.assertIn('operations via slack', row['route'])
        self.assertIn('600s', row['route'])
        self.assertIn('present: HTTP 503', row['state'])
        self.assertIn('21:00:00', row['acquisition'])

    def test_all_sections_and_glossary_are_in_terminal_and_html(self):
        doc = self.build()
        text, found = m.terminal(doc)
        self.assertTrue(found)
        page = m.render(doc)
        for section in ('services', 'rules', 'producers', 'components', 'coverage', 'not monitored', 'sources'):
            self.assertTrue(doc[section], section)
            self.assertIn(section.upper(), text)
            self.assertIn('id="%s"' % section.replace(' ', '-'), page)
        self.assertNotIn('<script', page)
        for term in m.GLOSSARY:
            self.assertIn('id="g-' + term + '"', page)
        for link in re.findall(r'href="#([^"]+)"', page):
            self.assertIn('id="' + link + '"', page)

    def test_product_includes_compiled_attention_rules(self):
        self.assertIn('600s', self.rule('service-not-doing-its-job')['hold'])
        self.assertIn('present: HTTP 503', self.rule('service-not-doing-its-job')['state'])

    def test_rule_has_summary_route_runbook_and_effective_identity(self):
        row = self.rule()
        self.assertEqual(row['family'], 'block I/O pressure')
        self.assertIn('stall', row['observation'])
        self.assertIn('operations', row['route'])
        self.assertEqual(row['handler'], 'slack')
        self.assertIn('#host-pressure', row['runbook'])
        self.assertIn('registry pins sha256:', row['revision'])
        self.assertTrue(row['state'].startswith('inactive'))

    def test_probe_producer_and_own_supervision(self):
        doc = self.build()
        self.assertTrue(any('http:' in r['probe'] for r in doc['producers']))
        self.assertTrue(any(r['producer'] == 'web-refresh.timer' for r in doc['producers']))
        self.assertTrue(any(r['service'] == 'attention' for r in doc['components']))
        self.assertTrue(any('independent host-loss witness unknown' in r.get('supervision', '') for r in doc['components']))

    def test_gaps_include_units_declarations_and_uncovered_families(self):
        gaps = self.build()['not monitored']
        for item in ('systemd:stray.service', 'local-only', 'worker', 'kernel filesystem errors'):
            self.assertTrue(any(r['item'] == item for r in gaps), item)
        self.assertTrue(any('explicitly excluded' in r['reason'] for r in gaps))
        self.assertIn('declared but not acquired', self.service('worker')['verdict'])

    def test_value_code_acquisition_failure_cannot_be_present(self):
        row = self.rule('HostSwapExhausted')
        self.assertIn('unknown-held', row['state'])
        self.assertIn('code 2 acquisition failed', row['state'])
        self.assertFalse(row['_usable'])

    def test_every_value_code_and_pending_semantics(self):
        rule = json.loads((self.root / 'metrics.json').read_text())['rules'][1]
        for code, meaning in m.CODES.items():
            with self.subTest(code=code):
                rule['value_code_counts'][0]['value'] = str(code)
                for state in ('pending', 'firing'):
                    rule['value_code_counts'][0]['state'] = state
                    text, usable = m.rule_state(rule, None, NOW, 300, 'example')
                    self.assertIn(meaning, text)
                    self.assertIn(state, text)
                    self.assertEqual(usable, code == 1)

    def test_unmarked_numeric_two_retains_raw_meaning(self):
        rule = copy.deepcopy(json.loads((self.root / 'metrics.json').read_text())['rules'][1])
        rule['labels'].pop('constellation_value_codes')
        rule.pop('value_code_counts')
        rule['instances'][0]['summary'] = ''
        rule['instances'][0]['value'] = '2'
        text, usable = m.rule_state(rule, None, NOW, 300, 'example')
        self.assertTrue(usable)
        self.assertIn('value=2', text)
        self.assertNotIn('acquisition failed', text)

    def test_complete_counts_control_even_when_details_are_truncated(self):
        def change(doc):
            r = doc['rules'][1]
            r['instances'] = []
            r['value_code_counts'] += [{'site': 'example', 'state': 'firing', 'value': '1', 'count': 40}]
        self.edit('metrics.json', change)
        self.assertIn('unknown-held', self.rule('HostSwapExhausted')['state'])

    def test_invalid_or_absent_complete_codes_are_unknown(self):
        base = json.loads((self.root / 'metrics.json').read_text())['rules'][1]
        for value in ('6', 'NaN', '1.5', '', None):
            rule = copy.deepcopy(base)
            rule['value_code_counts'][0]['value'] = value
            self.assertFalse(m.rule_state(rule, None, NOW, 300, 'example')[1])
        for key in ('value_code_counts',):
            rule = copy.deepcopy(base)
            rule.pop(key)
            self.assertIn('unknown', m.rule_state(rule, None, NOW, 300, 'example')[0])
        rule = copy.deepcopy(base)
        rule['labels']['constellation_value_codes'] = 'v2'
        self.assertIn('unsupported', m.rule_state(rule, None, NOW, 300, 'example')[0])

    def test_other_host_instance_does_not_establish_local_state(self):
        self.edit('metrics.json', lambda d: d['rules'][1]['value_code_counts'][0].update(site='elsewhere'))
        self.assertIn('no complete value-code evidence for this host', self.rule('HostSwapExhausted')['state'])

    def test_zero_series_and_failed_health_cannot_clear(self):
        for field, value in [('last_series_fetched', 0), ('health', 'err'), ('last_evaluation', None)]:
            with self.subTest(field=field):
                original = (self.root / 'metrics.json').read_text()
                self.edit('metrics.json', lambda d: d['rules'][0].update({field: value}))
                self.assertTrue(self.rule()['state'].startswith('unknown'))
                (self.root / 'metrics.json').write_text(original)

    def test_missing_and_corrupt_required_inputs_never_report_healthy(self):
        for name in ('registry.json', 'estate.json', 'report.json', 'policy.json', 'metrics.json', 'attention.toml'):
            for content in (None, 'malformed'):
                with self.subTest(name=name, content=content):
                    path = self.root / name
                    original = path.read_bytes()
                    path.unlink() if content is None else path.write_text(content)
                    doc = self.build()
                    self.assertTrue(any('unknown:' in str(r) for r in doc['sources']))
                    if name in ('registry.json', 'estate.json'):
                        self.assertFalse(any(r['verdict'] == 'OK' for r in doc['services']))
                    if name in ('policy.json', 'metrics.json'):
                        self.assertFalse(any(r['_usable'] for r in doc['rules'] if not r['identity'].startswith('attention/')))
                    path.write_bytes(original)

    def test_every_input_missing_still_renders_a_page(self):
        shutil.rmtree(self.root)
        doc = self.build()
        self.assertIn('unknown:', re.sub('<[^>]+>', '', m.render(doc)))
        self.assertFalse(any(r['coverage'] == 'closed on this host' for r in doc['coverage']))

    def test_stale_future_and_wrong_site_estate(self):
        for changes, reason in [({'generated_at': '2020-01-01T00:00:00Z'}, 'stale'), ({'generated_at': '2030-01-01T00:00:00Z'}, 'future'), ({'site': 'other'}, 'site')]:
            original = (self.root / 'estate.json').read_bytes()
            self.edit('estate.json', lambda d: d.update(changes))
            self.assertIn(reason, self.service('attention')['verdict'])
            (self.root / 'estate.json').write_bytes(original)

    def test_fresh_collection_does_not_refresh_expired_concern(self):
        self.edit('estate.json', lambda d: d['services'][0]['concerns'][0].update(observed_at='2020-01-01T00:00:00Z', state='PRESENT'))
        self.assertIn('unknown: stale', self.service()['verdict'])
        self.assertIn('UNKNOWN', self.service()['concern'])

    def test_registry_byte_drift_invalidates_old_ok_acquisition(self):
        with (self.root / 'registry.json').open('a') as stream:
            stream.write('\n')
        self.assertIn('does not match current registry', self.service('attention')['verdict'])

    def test_changed_declaration_does_not_inherit_acquisition(self):
        (self.root / 'services.d/attention.toml').write_text('name="attention"\nrole="changed"\n')
        self.assertIn('differs', self.service('attention')['verdict'])

    def test_optional_declarations_directory_absent(self):
        shutil.rmtree(self.root / 'services.d')
        self.assertEqual(self.service()['verdict'], 'DEGRADED')
        self.assertFalse(any(r['service'] == 'local-only' for r in self.build()['services']))

    def test_malformed_declaration_is_a_visible_gap(self):
        (self.root / 'services.d/broken.toml').write_text('runtime = {')
        self.assertTrue(any('broken.toml' in str(r) and 'unknown:' in str(r) for r in self.build()['not monitored']))

    def test_effective_policy_must_match_local_declaration_and_pin(self):
        for field, value in [('policy_sha256', 'sha256:bad'), ('declared_policy_sha256', None), ('policy_matches_declared', False)]:
            original = (self.root / 'metrics.json').read_bytes()
            self.edit('metrics.json', lambda d: d.update({field: value}))
            self.assertIn('do not all match', self.rule()['state'])
            (self.root / 'metrics.json').write_bytes(original)
        self.edit('registry.json', lambda d: d.update(definitions=[]))
        self.assertIn('do not all match', self.rule()['state'])

    def test_rejected_rule_does_not_appear_usable(self):
        self.edit('report.json', lambda d: d['inputs'][1].update(rejected_rules=[{'name': 'HostIoPressureHigh', 'reason': 'untargetable'}]))
        self.assertIn('rejected', self.rule()['state'])

    def test_missing_runtime_rule_and_runtime_only_rule(self):
        self.edit('metrics.json', lambda d: d['rules'].pop(0))
        self.assertIn('declared but not acquired', self.rule()['state'])
        self.edit('metrics.json', lambda d: d['rules'].append({**d['rules'][0], 'name': 'Undeclared'}))
        self.assertIn('absent from declared policy', self.rule('Undeclared')['state'])

    def test_ledger_has_all_46_families_and_no_source_status_closes_one(self):
        coverage = self.build()['coverage']
        self.assertEqual(len(coverage), 46)
        self.assertTrue(all(r['coverage'] == 'open on this host' for r in coverage))
        row = self.family()
        self.assertTrue(row['declared'].startswith('yes:'))
        for part in ('observed', 'routed', 'runbook', 'drilled'):
            self.assertTrue(row[part].startswith('unknown:'))

    def test_closure_requires_all_five_host_revision_scoped_receipts(self):
        self.receipts()
        self.assertEqual(self.family()['coverage'], 'closed on this host')
        for part in ('observed', 'routed', 'runbook', 'drilled'):
            original = (self.root / 'coverage.json').read_bytes()
            self.edit('coverage.json', lambda d: d['families']['block I/O pressure'][part].update(holds=False))
            self.assertEqual(self.family()['coverage'], 'open on this host')
            (self.root / 'coverage.json').write_bytes(original)
        for field in ('site', 'policy_sha256'):
            original = (self.root / 'coverage.json').read_bytes()
            self.edit('coverage.json', lambda d: d.update({field: 'wrong'}))
            self.assertEqual(self.family()['coverage'], 'open on this host')
            (self.root / 'coverage.json').write_bytes(original)

    def test_receipt_cannot_override_failed_acquisition_or_dry_run(self):
        self.receipts()
        self.edit('metrics.json', lambda d: d['rules'][0].update(health='err'))
        self.assertEqual(self.family()['coverage'], 'open on this host')
        self.edit('report.json', lambda d: d.update(dry_run=True))
        self.assertTrue(self.family()['routed'].startswith('unknown:'))

    def test_missing_receipt_pointer_cannot_close(self):
        self.receipts()
        self.edit('coverage.json', lambda d: d['families']['block I/O pressure']['drilled'].update(evidence=[]))
        self.assertEqual(self.family()['coverage'], 'open on this host')

    def test_disabled_network_drop_and_local_inbox_never_close_route(self):
        self.receipts()
        path = self.root / 'attention.toml'
        original = path.read_text()
        for text in (original.replace('network_enabled = true', 'network_enabled = false'), original.replace('"operations"', '"drop"'), original.replace('"slack"', '"local_file"')):
            path.write_text(text)
            self.assertTrue(self.family()['routed'].startswith('unknown:'))
        path.write_text(original)

    def test_unpublished_runbook_remains_unknown(self):
        self.receipts()
        path = self.root / 'attention.toml'
        path.write_text(path.read_text().replace('https://operator.example/runbooks.html', ''))
        self.assertIn('unpublished runbook anchor host-pressure', self.rule()['runbook'])
        self.assertTrue(self.family()['runbook'].startswith('unknown:'))

    def test_html_escapes_authored_text_and_only_uses_safe_links(self):
        self.edit('registry.json', lambda d: d['services'][0].update(role='<script>alert(1)</script>', status={'kind': 'http', 'url': 'https://user:password@local.test/health?token=secret'}))
        row = self.service()
        self.assertNotIn('password', row['observation'])
        self.assertNotIn('token', row['observation'])
        page = m.render(self.build())
        self.assertNotIn('<script>', page)
        self.assertIn('&lt;script&gt;', page)
        self.assertNotIn('href="javascript:', page)

    def test_cli_show_missing_and_atomic_render_permissions(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(m.main(self.argv + ['show', 'web']), 0)
        self.assertIn('HTTP 503', output.getvalue())
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(m.main(self.argv + ['show', 'nonexistent']), 1)
            out = Path(self.temp.name) / 'page/monitored.html'
            self.assertEqual(m.main(self.argv + ['render', '--out', str(out)]), 0)
            self.assertEqual(m.main(self.argv + ['render', '--out', str(out)]), 0)
        self.assertEqual(out.stat().st_mode & 0o777, 0o644)
        self.assertEqual(list(out.parent.glob('.monitored-*')), [])

    def test_attention_family_receipts_require_its_own_policy_revision(self):
        report = json.loads((self.root / 'report.json').read_text())
        rule = dict(report['rules'][0], id='host-disk')
        report['rules'].append(rule)
        report['conditions'].append({'id': 'constellation:example:host_posture:host-disk:root', 'rule': 'host-disk', 'observation': 'clear', 'note': 'current capacity observation'})
        (self.root / 'report.json').write_text(json.dumps(report))
        self.edit('registry.json', lambda d: d['definitions'].append({'kind': 'attention-policy', 'config': str(self.args.attention_config), 'digest': report['attention_policy_digest']}))
        receipt = {p: {'holds': True, 'evidence': ['fixture://capacity-history-trigger-recovery#' + p]} for p in ('observed', 'routed', 'runbook', 'drilled')}
        self.edit('coverage.json', lambda d: d['families'].update({'disk capacity (bytes)': receipt}))
        def capacity():
            return next(r for r in self.build()['coverage'] if r['family'] == 'disk capacity (bytes)')
        self.assertEqual(capacity()['coverage'], 'open on this host')
        self.edit('coverage.json', lambda d: d.update(attention_policy_digest=report['attention_policy_digest']))
        self.assertEqual(capacity()['coverage'], 'closed on this host')
        self.edit('report.json', lambda d: d.update(attention_policy_digest='sha256:other'))
        self.assertEqual(capacity()['coverage'], 'open on this host')

    def test_disabled_metric_rule_and_report_network_disable_prevent_routing(self):
        self.receipts()
        self.edit('report.json', lambda d: d['rules'][1].update(enabled=False))
        self.assertIn('disabled', self.rule()['route'])
        self.assertTrue(self.family()['routed'].startswith('unknown:'))
        self.edit('report.json', lambda d: d['rules'][1].update(enabled=True))
        self.edit('report.json', lambda d: d.update(network_enabled=False))
        self.assertTrue(self.family()['routed'].startswith('unknown:'))

    def test_paused_down_and_unknown_estate_verdicts(self):
        for verdict in ('PAUSED', 'DOWN', 'UNKNOWN'):
            self.edit('estate.json', lambda d: d['services'][0].update(verdict=verdict))
            self.assertEqual(self.service()['verdict'], verdict)
            if verdict == 'PAUSED':
                self.assertIn('suppressed', self.service()['route'])

    def test_missing_required_concern_is_an_explicit_gap(self):
        self.edit('estate.json', lambda d: d['services'][0]['concerns'][0].update(state='MISSING_REQUIRED_OBSERVATION'))
        self.assertTrue(any(r['item'] == 'web:web.http' and 'MISSING_REQUIRED' in r['reason'] for r in self.build()['not monitored']))

    def test_timezone_offsets_and_malformed_structure(self):
        self.assertEqual(m.stamp('2026-10-22T17:01:00-04:00'), NOW)
        self.edit('estate.json', lambda d: d['services'][0].update(concerns='invalid'))
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(m.main(self.argv + ['list']), 0)
        self.assertIn('unknown: malformed input structure', output.getvalue())

    def test_duplicate_rule_identity_is_unknown(self):
        self.edit('metrics.json', lambda d: d['rules'].append(d['rules'][0]))
        self.assertTrue(any('duplicate' in str(r) for r in self.build()['sources']) or not self.build()['rules'])

    def test_unsupported_schema_is_unknown(self):
        self.edit('estate.json', lambda d: d.update(schema='future/v99'))
        self.assertIn('unknown:', self.service('attention')['verdict'])

    def test_isolated_reader_uses_python310_fallback_without_import_path_help(self):
        spec = importlib.util.spec_from_file_location('reader_without_tomllib', HERE / 'constellation-monitored.py')
        reader = importlib.util.module_from_spec(spec)
        with mock.patch.dict('sys.modules', {'tomllib': None}):
            spec.loader.exec_module(reader)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(reader.main(self.argv + ['show', 'web']), 0)
        self.assertIn('DEGRADED', output.getvalue())

    def test_python310_subset_matches_native_parser_on_real_declarations(self):
        for path in [self.root / 'attention.toml', *(self.root / 'services.d').glob('*.toml')]:
            text = path.read_text()
            self.assertEqual(toml_subset.loads(text), m.tomllib.loads(text))
        commented = 'x = [\n 1, # number\n 2,\n]\ny="literal#hash" # comment\n'
        self.assertEqual(toml_subset.loads(commented), m.tomllib.loads(commented))
        text = '[[inputs.host_posture]]\nlabel="root"\n["rules"."service-down"]\nclass="notice"\n'
        self.assertEqual(toml_subset.loads(text), m.tomllib.loads(text))
        for text in ('x=1\nx=2', 'x="""unsupported"""', 'x=not-a-value'):
            with self.assertRaises(ValueError):
                toml_subset.loads(text)


if __name__ == '__main__':
    unittest.main()
