"""Focused normal-owner HTTP currentness and exact-join controls."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('monitor_http_read', Path(__file__).with_name('nq_live_http_read.py'))
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)
MACHINE = '1a5b08928e884e73bf4f60a3c73ef497'
BOOT = '7e3e2a67-f95e-437a-b6c6-d2bf99d44e0c'
STAMP = '2026-10-04T12:00:00Z'
NOW = reader.milliseconds(STAMP)


def fixture():
    service_subject = {'schema': 'constellation.operator_beta.service_subject.v1', 'campaign_id': 'constellation-operator-beta-2026',
                       'fixture_run_id': BOOT, 'target_machine_identity': MACHINE,
                       'unit_name': 'constellation-beta-http-fixture.service', 'unit_file_sha256': 'sha256:'+'b'*64}
    domain = b'constellation/operator-beta/service-subject/v1'; raw = reader.canonical(service_subject)
    subject = 'sha256:' + hashlib.sha256(b'ag-ng\0digest\0v1\0' + len(domain).to_bytes(16, 'big') + domain + len(raw).to_bytes(16, 'big') + raw).hexdigest()
    controller = 'controller:' + MACHINE + ':' + BOOT
    scope = {'kind': 'http_endpoint', 'value': {'schema': 'nq.operator_beta.http_endpoint_scope.v1', 'subject_identity': subject,
             'controller_vantage_identity': controller, 'endpoint': 'http://172.27.42.2:18080/healthz', 'method': 'GET', 'redirect_policy': 'refuse', 'max_response_bytes': 4096}}
    vantage = {'kind': 'controller_http', 'value': {'controller_vantage_identity': controller}}
    settings = {'schema': 'monitor.http-reliance-settings/v1', 'instance_id': 'http-fixture', 'profile_digest': 'sha256:'+'d'*64,
                'subject': subject, 'scope': scope, 'vantage': vantage, 'observer_machine_id': MACHINE, 'observer_boot_id': BOOT, 'service_subject': service_subject,
                'threshold_policy': {'id': 'nq.http_endpoint.postcondition.threshold_policy', 'version': BOOT, 'digest': 'sha256:'+'e'*64}}
    evidence = {'report_id': 'report-http', 'report_sequence': 7, 'report_digest': 'sha256:'+'c'*64, 'observation_ordinal': 0, 'observed_at': STAMP}
    evaluation = {'schema': 'nq.evaluation_envelope.v2', 'profile': {'profile': {'id': 'nq.http_endpoint', 'version': 1}, 'profile_digest': settings['profile_digest']},
                  'threshold_policy': settings['threshold_policy'],
                  'context': {'instance_id': settings['instance_id'], 'subject': subject, 'scope': scope, 'vantage': vantage}, 'evaluated_at': STAMP,
                  'result': {'condition': 'http_endpoint_postcondition_not_met', 'state': 'explicitly_absent', 'evidence': [evidence]}}
    payload = dict({key: scope['value'][key] for key in ('controller_vantage_identity', 'endpoint', 'method', 'redirect_policy')},
                   evidence_basis={'scope': scope, 'vantage': vantage}, status=200, body_sha256='sha256:'+'a'*64, body_bytes=20)
    export = {'schema': 'nq.admitted-observation-export/v1', 'standing': 'historical_custody_only', 'reference_time_basis': 'native_observation_time', 'instance_id': settings['instance_id'], 'evidence': evidence,
              'profile': {'id': 'nq.http_endpoint', 'version': '1', 'digest': settings['profile_digest']},
              'binding': {'subject': subject, 'scope': scope, 'vantage': vantage}, 'report_status': 'complete',
              'observation': {'kind': 'http_response', 'subject': subject, 'ordinal': 0, 'observed_at': STAMP, 'payload': payload}}
    return [settings, evaluation, export, {'machine_id': MACHINE, 'boot_id': BOOT}]


class HttpReadTests(unittest.TestCase):
    def grade(self, values, now=NOW+1000):
        settings, evaluation, export, identity = values
        return reader.judge(settings, evaluation, export, identity, identity, now)

    def test_current_and_nonhealthy_native_http_condition_remain_separate(self):
        values = fixture()
        self.assertEqual(self.grade(values)['status'], 'current')
        values[1]['result']['state'] = 'present'
        result = self.grade(values)
        self.assertEqual(result['status'], 'contradictory')
        self.assertEqual(result['reason'], 'native_http_postcondition_not_met')
        values[1]['result']['state'] = 'cannot_evaluate'
        self.assertEqual(self.grade(values)['status'], 'unsupported')

    def test_actual_nine_digit_native_timestamp_is_portable_and_exact(self):
        native='2026-10-04T19:12:48.755624919Z'
        self.assertEqual(reader.milliseconds(native),1791141168755)
        self.assertEqual(reader.exact_nanoseconds(native),1791141168755624919)
        self.assertEqual(reader.exact_nanoseconds('2026-10-04T21:12:48.755624919+02:00'),1791141168755624919)
        values=fixture()
        values[2]['observation']['observed_at']=native
        values[1]['result']['evidence'][0]['observed_at']='2026-10-04T19:12:48.755Z'
        values[2]['reference_time_basis']='evaluation_millisecond_projection'
        values[1]['evaluated_at']='2026-10-04T19:12:48.781Z'
        verdict=self.grade(values,1791141169000)
        self.assertEqual(verdict['status'],'current')
        self.assertEqual(verdict['fresh_until_unix_ms'],1791141228755)
        self.assertEqual(self.grade(values,1791141228755)['status'],'stale')
        values[1]['result']['evidence'][0]['observed_at']='2026-10-04T19:12:48.755624918Z'
        self.assertEqual(self.grade(values,1791141169000)['status'],'refused')

    def test_fraction_parser_rejects_invalid_or_unbounded_spelling(self):
        for value in [None,0,'2026-10-04T19:12:48.7556249190Z',
                      '2026-10-04T19:12:48.Z','2026-10-04 19:12:48Z',
                      '2026-02-30T19:12:48Z','2026-10-04T19:12:60Z',
                      '2026-10-04T19:12:48+24:00','2026-10-04T19:12:48+01:60',
                      '2026-10-04T19:12:48','1969-12-31T23:59:59.999999999Z',
                      '2026-10-04T19:12:48Z\n']:
            with self.subTest(value=value), self.assertRaises(reader.Refusal):
                reader.exact_nanoseconds(value)
        for digits, nanos in [('1',100000000),('123456',123456000),('123456789',123456789)]:
            self.assertEqual(reader.exact_nanoseconds('1970-01-01T00:00:00.'+digits+'Z'),nanos)
            self.assertEqual(reader.milliseconds('1970-01-01T00:00:00.'+digits+'Z'),nanos//1000000)

    def test_exact_declared_timestamp_projection_preserves_native_precision(self):
        values = fixture()
        values[2]['observation']['observed_at'] = STAMP.replace('00Z', '00.123456789Z')
        ref = values[1]['result']['evidence'][0]
        ref['observed_at'] = STAMP.replace('00Z', '00.123Z')
        values[2]['reference_time_basis'] = 'evaluation_millisecond_projection'
        values[1]['evaluated_at'] = STAMP.replace('00Z', '01Z')
        self.assertEqual(self.grade(values, NOW+1000)['status'], 'current')
        ref['observed_at'] = STAMP.replace('00Z', '00.123999Z')
        self.assertEqual(self.grade(values, NOW+1000)['status'], 'refused')

    def test_source_age_exclusive_and_reevaluation_cannot_refresh_it(self):
        values = fixture(); values[1]['evaluated_at'] = '2026-10-04T12:00:59Z'
        self.assertEqual(self.grade(values, NOW+59999)['status'], 'current')
        expired = self.grade(values, NOW+60000)
        self.assertEqual(expired['status'], 'stale')
        self.assertEqual(expired['fresh_until_unix_ms'], NOW+60000)
        self.assertEqual(self.grade(values, NOW-1)['status'], 'refused')

    def test_observer_reboot_and_transition_require_fresh_enrollment(self):
        settings, evaluation, export, identity = fixture()
        new = dict(identity, boot_id='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
        self.assertEqual(reader.judge(settings, evaluation, export, new, new, NOW+1000)['status'], 'stale')
        self.assertEqual(reader.judge(settings, evaluation, export, identity, new, NOW+1000)['status'], 'refused')

    def test_wrong_subject_profile_vantage_and_reference_refuse(self):
        for component, field in ((2, 'evidence'), (2, 'profile'), (2, 'binding'), (1, 'context'), (1, 'threshold_policy')):
            values = fixture(); values[component][field] = {}
            self.assertEqual(self.grade(values)['status'], 'refused')
        values = fixture(); values[2]['observation']['payload']['controller_vantage_identity'] = 'another-controller'
        self.assertEqual(self.grade(values)['status'], 'refused')
        values = fixture(); values[2]['observation']['observed_at'] = '2026-10-04T12:00:01Z'
        self.assertEqual(self.grade(values)['status'], 'refused')

    def test_missing_evaluation_and_export_do_not_support_currentness(self):
        values = fixture(); values[1] = None
        self.assertEqual(self.grade(values)['status'], 'absent')
        values = fixture(); values[2] = None
        self.assertEqual(self.grade(values)['status'], 'refused')

    def test_unbound_closed_fixture_or_currentness_config_refuses(self):
        for field, replacement in (('observer_boot_id', 'invented'), ('subject', 'sha256:'+'f'*64), ('vantage', {})):
            values = fixture(); values[0][field] = replacement
            with self.assertRaises(reader.Refusal):
                self.grade(values)
        values = fixture(); values[0]['service_subject']['unit_name'] = 'unrelated.service'
        with self.assertRaises(reader.Refusal):
            self.grade(values)
        values = fixture(); values[0]['threshold_policy']['version'] = '1'
        with self.assertRaises(reader.Refusal):
            self.grade(values)
        values = fixture(); values[0]['hidden_oracle'] = 'truth'
        with self.assertRaises(reader.Refusal):
            reader.settings(values[0])

    def test_frozen_window_rejects_movement_duplicates_and_omission(self):
        values = fixture()
        valid = {'schema': 'nq.evaluation_history.v1', 'through_sequence': 9, 'complete': True,
                 'records': [{'sequence': 9, 'result': values[1]}]}
        probe = {'schema': 'nq.evaluation_history.v1', 'through_sequence': 9}
        with mock.patch.object(reader, 'query', side_effect=[probe, valid]):
            through, evaluation = reader.newest('/usr/bin/nq', '/etc/nq/ops.toml', 'http-fixture')
        self.assertEqual(through, 9); self.assertEqual(evaluation, values[1])
        for field, replacement in (('through_sequence', 10), ('complete', False), ('records', [valid['records'][0]]*2)):
            bad = dict(valid); bad[field] = replacement
            with mock.patch.object(reader, 'query', side_effect=[probe, bad]):
                with self.assertRaises(reader.Refusal):
                    reader.newest('/usr/bin/nq', '/etc/nq/ops.toml', 'http-fixture')

    def test_query_calls_only_native_custody_reads(self):
        values = fixture()
        with mock.patch.object(reader, 'identity', return_value=values[3]), mock.patch.object(reader, 'newest', return_value=(9, values[1])), mock.patch.object(reader, 'query', return_value=values[2]) as query, mock.patch.object(reader.time, 'time_ns', return_value=(NOW+1000)*1000000):
            result = reader.read(values[0], '/usr/bin/nq', '/etc/nq/ops.toml')
        self.assertEqual(result['judgment']['status'], 'current')
        self.assertEqual(query.call_args.args[2:5], ('observations', 'export', '--reference'))
        self.assertFalse(Path(query.call_args.args[5]).exists())
        self.assertNotIn('authority', result)


if __name__ == '__main__':
    unittest.main()
