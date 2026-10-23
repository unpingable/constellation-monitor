#!/usr/bin/env python3
"""Generate deterministic fixtures using the real incident lifecycle; never touches a live store."""
import json
import tempfile
from pathlib import Path
import argparse
import importlib.util
spec = importlib.util.spec_from_file_location('incident_owner', Path(__file__).with_name('constellation-incidents.py'))
inc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inc)

T0 = inc.parse_ts('2026-10-16T12:00:00Z')
NOW = T0 + 3600


def generate():
    with tempfile.TemporaryDirectory(prefix='operations-board-demo-') as tmp:
        db, s, entries = None, None, []

        def condition(subject, observation='present', active=True, policy='page'):
            key = 'site:demo:service:service-down:' + subject
            rules = {'service-down': {'response_policy': policy, 'operator_response': 'Inspect ' + subject + '; review runbook before acting'}}
            report = {'conditions': [{'id': key, 'rule': 'service-down', 'observation': observation, 'active': active,
                                     'first_seen': inc.iso(T0), 'note': 'Deterministic fixture: failure condition observed'}]}
            return key, report, rules

        def start(subject, policy='page', at=T0):
            nonlocal db, s
            if s is not None:
                s.db.close()
                entries.extend(inc.inspect_readonly(db, NOW, config={'grafana': {'site': 'demo', 'host': 'demo-host'}})['incidents'])
            db = Path(tmp) / (subject + '.sqlite')
            s = inc.SqliteStore(str(db))
            key, report, rules = condition(subject, policy=policy)
            inc.sync(s, report, {}, None, rules, at)
            return s.current(key), report, rules

        i, report, rules = start('api-gateway')
        # Repeated detections remain one established row. Refresh does not append progress.
        for delta in (60, 120, 180):
            inc.sync(s, report, {}, None, rules, T0 + delta)
        s.update(i['id'], ack_by='Alex / operations', state='acknowledged')
        s.event(i['id'], inc.iso(T0 + 240), 'acknowledged', {'by': 'Alex / operations', 'note': 'Looking at dependency failures'})
        i, _, _ = start('collector-observation-gap')
        s.update(i['id'], last_observation='unreported')
        s.event(i['id'], inc.iso(T0 + 120), 'unobserved', {'note': 'Observation acquisition lost; service health unknown'})
        i, _, _ = start('worker-pool')
        s.attempt(i['id'], 'demo-attempt-failed', {'opened_at': inc.iso(T0 + 30), 'settled_at': inc.iso(T0 + 60), 'plan': 'restart-worker.json', 'phase': 'settled', 'outcome': 'settled_failure'})
        s.attempt(i['id'], 'demo-attempt-unknown', {'opened_at': inc.iso(T0 + 120), 'plan': 'restart-worker.json', 'phase': 'settled', 'outcome': 'indeterminate'})
        s.event(i['id'], inc.iso(T0 + 120), 'remediation', {'episode': 'demo-attempt-unknown', 'outcome': 'indeterminate', 'verified': None})
        s.event(i['id'], inc.iso(T0 + 140), 'notified', {'role': 'page', 'outcome': 'accepted', 'route': 'demo-operator', 'action': 'trigger'})
        i, report, rules = start('ingest-service', policy='auto_remediate_then_page', at=NOW - 120)
        s.update(i['id'], needs_operator=None)
        s.attempt(i['id'], 'demo-authorized-attempt', {'opened_at': inc.iso(NOW - 90), 'plan': 'start-inactive.json', 'phase': 'dispatched'})
        s.event(i['id'], inc.iso(NOW - 100), 'demo-authority', {'fixture_only': True, 'actor': 'demo remediation consumer', 'decision': 'authorized for start-inactive fixture plan', 'receipt': 'demo-authority-001', 'note': 'This receipt is fixture-only; incident v1 does not export live authority decisions'})
        s.event(i['id'], inc.iso(NOW - 90), 'remediation', {'episode': 'demo-authorized-attempt', 'phase': 'dispatched'})
        i, _, _ = start('storage-maintenance', at=NOW - 80)
        s.update(i['id'], needs_operator='suspended by Morgan until: replacement storage is reviewed')
        s.event(i['id'], inc.iso(NOW - 70), 'suspended', {'owner': 'Morgan', 'reason': 'review needed', 'resume_when': 'replacement storage is reviewed'})
        i, report, rules = start('queue-backlog', at=NOW - 240)
        key = i['key']
        report['conditions'][0].update(active=False, observation='clear')
        inc.sync(s, report, {}, None, rules, NOW - 60)
        i, report, rules = start('edge-cache', at=NOW - 600)
        report['conditions'][0].update(active=False, observation='clear')
        inc.sync(s, report, {}, None, rules, NOW - 500)
        inc.sync(s, {'conditions': []}, {}, None, rules, NOW - 200)
        # Unverified operator closure must not render as verified recovery.
        i, _, _ = start('retired-worker', at=NOW - 180)
        s.update(i['id'], state='resolved', resolved_at=inc.iso(NOW - 60), resolution='closed by operator; recovery not verified by Constellation')
        s.event(i['id'], inc.iso(NOW - 60), 'resolved', {'verified': False, 'by': 'demo operator'})
        i, _, _ = start('deployment-proposal', at=NOW - 100)
        s.event(i['id'], inc.iso(NOW - 80), 'demo-proposal', {'fixture_only': True, 'action': 'increase worker limit', 'status': 'proposed; review required; no execution'})
        s.attempt(i['id'], 'demo-refused-attempt', {'opened_at': inc.iso(NOW - 70), 'outcome': 'refused', 'phase': 'settled', 'plan': 'increase-worker-limit.json'})
        s.event(i['id'], inc.iso(NOW - 70), 'remediation', {'episode': 'demo-refused-attempt', 'outcome': 'refused', 'note': 'Proposal exceeds fixture authority; operator review required'})
        s.heartbeat(inc.iso(NOW), True, 'deterministic fixture sync, never live estate data')
        s.db.close()
        doc = inc.inspect_readonly(db, NOW, config={'grafana': {'site': 'demo', 'host': 'demo-host'}})
        doc['incidents'] = entries + doc['incidents']
        doc['source'] = {'kind': 'deterministic-fixture/v1', 'owner': 'constellation-incidents', 'production_baseline': 'a42822f', 'note': 'generated by real shim; authority and checkpoint examples fixture-only'}
        doc.update(demo_at=inc.iso(NOW), pending_detections=[{'id': 'demo:condition:unassociated', 'observation': 'present', 'at': inc.iso(NOW - 30), 'note': 'Detection exists; incident persistence outcome unavailable', 'association': 'pending / failed unknown — not an established incident'}])
        doc['incidents'][0]['demo_checkpoint'] = inc.iso(NOW - 300)
        return doc


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    args.out.write_text(json.dumps(generate(), indent=2) + '\n')
