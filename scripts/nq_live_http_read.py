#!/usr/bin/env python3
"""Monitor owner read for exact boot-enrolled controller HTTP/v1 testimony.

Queries only native NQ committed evaluation/observation custody. This neither
acquires an HTTP response nor grants effect authority. Observer boot is a
separately enrolled identity carried in the native opaque controller vantage.
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any

MAX_BYTES = 2 * 1024 * 1024
RELIANCE_MS = 60000
DIGEST = re.compile(r'sha256:[a-f0-9]{64}')
BOOT = re.compile(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}')


class Refusal(ValueError):
    pass


def load(raw: bytes):
    if len(raw) > MAX_BYTES:
        raise Refusal('read_byte_bound')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Refusal('duplicate_json_field')
            result[key] = value
        return result
    def number(_):
        raise Refusal('non_integer_numeric_token')
    try:
        return json.loads(raw, object_pairs_hook=unique, parse_float=number, parse_constant=number)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Refusal('malformed_owner_json') from error


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def valid_boot(value):
    return isinstance(value, str) and BOOT.fullmatch(value) and value != '00000000-0000-0000-0000-000000000000'


def identity():
    machine = Path('/etc/machine-id').read_text().removesuffix('\n')
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().removesuffix('\n')
    if not re.fullmatch('[a-f0-9]{32}', machine) or not valid_boot(boot):
        raise Refusal('current_observer_identity_invalid')
    return {'machine_id': machine, 'boot_id': boot}


def settings(value):
    expected = {'schema', 'instance_id', 'profile_digest', 'subject', 'scope', 'vantage', 'observer_machine_id', 'observer_boot_id', 'service_subject', 'threshold_policy'}
    if not isinstance(value, dict) or set(value) != expected or value['schema'] != 'monitor.http-reliance-settings/v1':
        raise Refusal('settings_schema_mismatch')
    for name in ('instance_id', 'profile_digest', 'subject', 'observer_machine_id', 'observer_boot_id'):
        if not isinstance(value[name], str) or not value[name] or len(value[name]) > 512:
            raise Refusal('settings_identity_malformed')
    if not DIGEST.fullmatch(value['profile_digest']) or not DIGEST.fullmatch(value['subject']):
        raise Refusal('settings_digest_malformed')
    if not re.fullmatch('[a-f0-9]{32}', value['observer_machine_id']) or not valid_boot(value['observer_boot_id']):
        raise Refusal('enrolled_observer_identity_malformed')
    subject = value['service_subject']
    subject_fields = {'schema', 'campaign_id', 'fixture_run_id', 'target_machine_identity', 'unit_name', 'unit_file_sha256'}
    if not isinstance(subject, dict) or set(subject) != subject_fields:
        raise Refusal('service_subject_malformed')
    if subject['schema'] != 'constellation.operator_beta.service_subject.v1' or subject['campaign_id'] != 'constellation-operator-beta-2026' or subject['unit_name'] != 'constellation-beta-http-fixture.service':
        raise Refusal('service_subject_outside_closed_fixture')
    if not valid_boot(subject['fixture_run_id']) or not isinstance(subject['target_machine_identity'], str) or not re.fullmatch('[a-f0-9]{32}', subject['target_machine_identity']) or not isinstance(subject['unit_file_sha256'], str) or not DIGEST.fullmatch(subject['unit_file_sha256']):
        raise Refusal('service_subject_identity_malformed')
    domain = b'constellation/operator-beta/service-subject/v1'
    raw_subject = canonical(subject)
    framed = b'ag-ng\0digest\0v1\0' + len(domain).to_bytes(16, 'big') + domain + len(raw_subject).to_bytes(16, 'big') + raw_subject
    if value['subject'] != 'sha256:' + hashlib.sha256(framed).hexdigest():
        raise Refusal('service_subject_preimage_mismatch')
    policy = value['threshold_policy']
    if not isinstance(policy, dict) or set(policy) != {'id', 'version', 'digest'} or policy['id'] != 'nq.http_endpoint.postcondition.threshold_policy' or policy['version'] != subject['fixture_run_id'] or not isinstance(policy['digest'], str) or not DIGEST.fullmatch(policy['digest']):
        raise Refusal('enrolled_http_threshold_policy_malformed')
    controller = 'controller:' + value['observer_machine_id'] + ':' + value['observer_boot_id']
    if value['vantage'] != {'kind': 'controller_http', 'value': {'controller_vantage_identity': controller}}:
        raise Refusal('enrolled_controller_vantage_not_boot_bound')
    scope = value['scope']
    if not isinstance(scope, dict) or set(scope) != {'kind', 'value'} or scope['kind'] != 'http_endpoint':
        raise Refusal('enrolled_http_scope_malformed')
    fields = {'schema', 'subject_identity', 'controller_vantage_identity', 'endpoint', 'method', 'redirect_policy', 'max_response_bytes'}
    if not isinstance(scope['value'], dict) or set(scope['value']) != fields:
        raise Refusal('enrolled_http_scope_malformed')
    if scope['value']['schema'] != 'nq.operator_beta.http_endpoint_scope.v1' or scope['value']['subject_identity'] != value['subject'] or scope['value']['controller_vantage_identity'] != controller:
        raise Refusal('enrolled_http_scope_binding_mismatch')
    return value


def exact_nanoseconds(value):
    """Parse the finite native RFC3339 spelling without runtime fraction truncation."""
    if not isinstance(value, str):
        raise Refusal('timestamp_absent')
    match = re.fullmatch(
        r'([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})'
        r'(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})', value)
    if not match:
        raise Refusal('timestamp_invalid')
    try:
        offset = match[8]
        zone = dt.timezone.utc
        if offset != 'Z':
            hours, minutes = int(offset[1:3]), int(offset[4:6])
            if hours > 23 or minutes > 59:
                raise ValueError()
            seconds = (hours * 3600 + minutes * 60) * (-1 if offset[0] == '-' else 1)
            zone = dt.timezone(dt.timedelta(seconds=seconds))
        # Calendar/offset validation sees whole seconds only on Python3.10;
        # the native fraction remains an independently parsed exact integer.
        parsed = dt.datetime(*(int(match[n]) for n in range(1, 7)), tzinfo=zone)
        epoch = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
        delta = parsed - epoch
        result = (delta.days * 86400 + delta.seconds) * 1000000000 + int((match[7] or '').ljust(9, '0'))
        if result < 0:
            raise ValueError()
        return result
    except (ValueError, OverflowError) as error:
        raise Refusal('timestamp_invalid') from error


def milliseconds(value):
    """Floor the exact native timestamp to the existing reliance millisecond unit."""
    return exact_nanoseconds(value) // 1000000


def reference_time_matches(source, reference, basis):
    try: source, reference = exact_nanoseconds(source), exact_nanoseconds(reference)
    except Refusal: return False
    if basis == 'native_observation_time': return source == reference
    if basis == 'evaluation_millisecond_projection':
        return source != reference and source // 1000000 * 1000000 == reference
    return False


def judge(spec, evaluation, export, before, after, now):
    spec = settings(spec)
    def answer(state, reason, expiry=None):
        return {'status': state, 'reason': reason, 'fresh_until_unix_ms': now + 1 if expiry is None else expiry}
    enrolled = {'machine_id': spec['observer_machine_id'], 'boot_id': spec['observer_boot_id']}
    if before != after or before.get('machine_id') != enrolled['machine_id'] or not valid_boot(before.get('boot_id')):
        return answer('refused', 'current_observer_identity_changed_or_mismatched')
    if before != enrolled:
        return answer('stale', 'observer_boot_requires_fresh_enrollment')
    if evaluation is None:
        return answer('absent', 'no_instance_evaluation')
    profile = {'id': 'nq.http_endpoint', 'version': 1}
    if evaluation.get('schema') != 'nq.evaluation_envelope.v2' or evaluation.get('profile', {}).get('profile') != profile or evaluation.get('profile', {}).get('profile_digest') != spec['profile_digest']:
        return answer('refused', 'evaluation_profile_mismatch')
    if evaluation.get('threshold_policy') != spec['threshold_policy']:
        return answer('refused', 'evaluation_threshold_policy_mismatch')
    context = {'instance_id': spec['instance_id'], 'subject': spec['subject'], 'scope': spec['scope'], 'vantage': spec['vantage']}
    if evaluation.get('context') != context:
        return answer('refused', 'evaluation_subject_scope_vantage_mismatch')
    result = evaluation.get('result', {})
    if result.get('condition') != 'http_endpoint_postcondition_not_met':
        return answer('refused', 'native_http_condition_mismatch')
    if result.get('state') not in {'present', 'explicitly_absent'}:
        return answer('unsupported', 'native_http_indeterminate_or_refused')
    evidence = result.get('evidence')
    if not isinstance(evidence, list) or len(evidence) != 1 or not isinstance(evidence[0], dict) or set(evidence[0]) != {'report_id', 'report_sequence', 'report_digest', 'observation_ordinal', 'observed_at'}:
        return answer('refused', 'exact_http_observation_reference_missing')
    reference = evidence[0]
    if not isinstance(export, dict) or export.get('schema') != 'nq.admitted-observation-export/v1' or export.get('standing') != 'historical_custody_only' or export.get('instance_id') != spec['instance_id'] or export.get('evidence') != reference:
        return answer('refused', 'observation_custody_reference_mismatch')
    binding = {'subject': spec['subject'], 'scope': spec['scope'], 'vantage': spec['vantage']}
    if export.get('profile') != {'id': 'nq.http_endpoint', 'version': '1', 'digest': spec['profile_digest']} or export.get('binding') != binding or export.get('report_status') != 'complete':
        return answer('refused', 'observation_profile_subject_scope_vantage_mismatch')
    observation = export.get('observation', {})
    if observation.get('kind') != 'http_response' or observation.get('subject') != spec['subject'] or observation.get('ordinal') != reference.get('observation_ordinal') or not reference_time_matches(observation.get('observed_at'), reference.get('observed_at'), export.get('reference_time_basis')):
        return answer('refused', 'http_observation_ordinal_subject_or_time_mismatch')
    payload = observation.get('payload', {})
    for key in ('controller_vantage_identity', 'endpoint', 'method', 'redirect_policy'):
        if payload.get(key) != spec['scope']['value'][key]:
            return answer('refused', 'native_http_payload_binding_mismatch')
    basis = payload.get('evidence_basis', {})
    if basis.get('scope') != spec['scope'] or basis.get('vantage') != spec['vantage']:
        return answer('refused', 'native_http_payload_basis_mismatch')
    try:
        observed = milliseconds(observation.get('observed_at'))
        evaluated = milliseconds(evaluation.get('evaluated_at'))
    except Refusal:
        return answer('refused', 'source_or_evaluation_timestamp_invalid')
    if observed > evaluated or observed > now or evaluated > now:
        return answer('refused', 'source_or_evaluation_timestamp_future')
    expiry = min(observed, evaluated) + RELIANCE_MS
    if now >= expiry:
        return answer('stale', 'source_or_evaluation_expired', expiry)
    # NQ owns the exact external postcondition policy. Monitor does not turn
    # process presence or an HTTP status alone into application health.
    return answer('current' if result['state'] == 'explicitly_absent' else 'contradictory',
                  'native_http_postcondition_met' if result['state'] == 'explicitly_absent' else 'native_http_postcondition_not_met', expiry)


def query(program, config, *args):
    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_BYTES, MAX_BYTES))
    with tempfile.TemporaryFile() as stdout:
        process = subprocess.Popen([program, '--config', config, '--json', *args], stdin=subprocess.DEVNULL,
                                   stdout=stdout, stderr=subprocess.DEVNULL, start_new_session=True,
                                   preexec_fn=limits, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
        try:
            status = process.wait(timeout=5)
            if status != 0:
                raise Refusal('native_nq_query_failed')
            stdout.seek(0)
            raw = stdout.read(MAX_BYTES + 1)
            return load(raw)
        except subprocess.TimeoutExpired as error:
            raise Refusal('native_nq_query_timeout') from error
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)


def newest(program, config, instance):
    probe = query(program, config, 'evaluations', 'export', '--limit', '1')
    if probe.get('schema') != 'nq.evaluation_history.v1' or type(probe.get('through_sequence')) is not int:
        raise Refusal('evaluation_window_malformed')
    through = probe['through_sequence']
    if through == 0:
        return 0, None
    page = query(program, config, 'evaluations', 'export', '--limit', '300', '--after', str(max(0, through - 300)), '--through', str(through))
    if page.get('schema') != 'nq.evaluation_history.v1' or page.get('through_sequence') != through or page.get('complete') is not True or not isinstance(page.get('records'), list) or len(page['records']) > 300:
        raise Refusal('evaluation_window_moving_or_incomplete')
    previous = max(0, through - 300)
    selected = None
    for record in page['records']:
        sequence = record.get('sequence')
        if type(sequence) is not int or not previous < sequence <= through or not isinstance(record.get('result'), dict):
            raise Refusal('evaluation_sequence_or_envelope_malformed')
        previous = sequence
        if record['result'].get('context', {}).get('instance_id') == instance:
            selected = record['result']
    return through, selected


def read(spec, program, config):
    spec = settings(spec)
    before = identity()
    through, evaluation = newest(program, config, spec['instance_id'])
    export = None
    evidence = None if evaluation is None else evaluation.get('result', {}).get('evidence')
    if isinstance(evidence, list) and len(evidence) == 1:
        reference = tempfile.NamedTemporaryFile(prefix='monitor-http-observation-reference-', suffix='.json', delete=False)
        reference_identity = os.fstat(reference.fileno())
        try:
            reference.write(canonical(evidence[0])); reference.flush(); os.fsync(reference.fileno())
            export = query(program, config, 'observations', 'export', '--reference', reference.name)
        finally:
            reference.close()
            current = os.lstat(reference.name)
            if not os.path.isfile(reference.name) or os.path.islink(reference.name) or current.st_dev != reference_identity.st_dev or current.st_ino != reference_identity.st_ino or current.st_nlink != 1 or current.st_uid != os.getuid():
                raise Refusal('temporary_reference_custody_changed_retained')
            os.unlink(reference.name)
    after = identity()
    now = time.time_ns() // 1000000
    judgment = judge(spec, evaluation, export, before, after, now)
    witness = {'settings': spec, 'evaluation': evaluation, 'observation_export': export,
               'observer_before': before, 'observer_after': after, 'resolution_at_unix_ms': now, 'reliance_ms': RELIANCE_MS}
    return {'schema': 'monitor.live-http-read/v1', 'owner': 'Monitor', 'subject': spec['subject'], 'instance_id': spec['instance_id'],
            'current_observer': after, 'read_at_unix_ms': now, 'through_sequence': through,
            'evaluation': evaluation, 'observation_export': export, 'judgment': judgment, 'witness': witness,
            'witness_sha256': hashlib.sha256(canonical(witness)).hexdigest(),
            'nonclaims': ['Native HTTP postcondition only; not process, unit or global application health',
                          'Custody and present reliance grant no effect authority']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--settings', type=Path, required=True)
    parser.add_argument('--config', required=True)
    parser.add_argument('--nq-program', default='/usr/bin/nq')
    parser.add_argument('--inspect', action='store_true', required=True)
    args = parser.parse_args(argv)
    try:
        spec = settings(load(args.settings.read_bytes()))
        print(json.dumps(read(spec, args.nq_program, args.config), sort_keys=True))
        return 0
    except (Refusal, OSError) as error:
        print('monitor HTTP read refused: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
