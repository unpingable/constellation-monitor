#!/usr/bin/env python3
"""Explain this host's monitoring from local declarations and acquired reports.

Read-only projection: executes no producers, queries no network and reads no
route credentials. Missing, stale and mismatched inputs remain unknown.
"""
import argparse
import datetime as dt
import hashlib
import importlib.util
import html
import json
import math
import os
from pathlib import Path
import re
import socket
import sys
import tempfile
from urllib.parse import urlsplit, urlunsplit

try:
    import tomllib
except ImportError:  # Ubuntu 22.04's Python 3.10
    spec = importlib.util.spec_from_file_location('toml_subset', Path(__file__).resolve().with_name('toml_subset.py'))
    tomllib = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tomllib)

LIMIT = 8 << 20
HERE = Path(__file__).resolve().parent
CODES = {1: 'present (threshold met / violation)', 2: 'acquisition failed',
         3: 'missing (no series)', 4: 'stale or future timestamp',
         5: 'invalid or warming (no history, counter reset or invalid limit)'}
GLOSSARY = {
    'ok': 'The current estate acquisition found its declared runtime and required concerns satisfied. This does not establish undeclared application health.',
    'degraded': 'A required concern is not satisfied, including a missing required observation.',
    'down': 'The acquired runtime was not up.',
    'paused': 'The operator declared a pause. Estate notices are suppressed and the pause stays visible.',
    'present': 'A concern holds. For an alert condition, the fault is present; read which kind of row this is.',
    'absent': 'A required application concern does not hold.',
    'firing': 'A detector has met its hold. Check value codes before treating it as a measured violation.',
    'pending': 'A detector is active but has not yet met its hold.',
    'inactive': 'No active alert instance. Missing or unusable evidence still makes this unknown.',
    'stale': 'The observation exceeded its validity or acquisition age bound.',
    'warming': 'The detector lacks sufficient valid history to evaluate yet.',
    'not-applicable': 'The producer explicitly reports that this concern does not apply. Missing data cannot establish this.',
    'attention': 'The evaluator that turns acquired observations into persistent operator conditions and requests notification delivery.',
    'estate': 'The host service registry and the collector that observes its declared workloads.',
    'nq': 'The evidence and notification subsystem. This page reads no NQ store or route secrets.',
    'nightshift': 'The component that schedules and records observation cycles.',
    'vmalert': 'The detector engine evaluating metric rules against the metric store.',
    'victoriametrics': 'The host-local store of metric time series.',
    'node_exporter': 'The collector exposing Linux host metrics, including declared textfile observations.',
    'systemd': 'The Linux service manager. Its unit state is one observation of execution.',
    'policy': 'The declared set of detector definitions and configuration, compared by digest.',
    'digest': 'A content-derived identity used to compare revisions. It is not approval or action authority.',
    'persistence': 'The required duration of definite observations before a condition notifies.',
    'slack': 'A configured external notification transport; receipt still requires delivery evidence.',
    'pagerduty': 'A configured paging transport; a named route does not prove that a page reached someone.',
    'discord': 'A configured external notification transport; receipt still requires delivery evidence.',
    'service': 'A workload named in the host registry or a local declaration.',
    'role': 'The job the service is expected to do.',
    'runtime': 'The systemd unit or container whose execution is observed. Running alone does not prove useful work.',
    'observation': 'A collected fact about runtime, application work, or a probe. Discovery alone is not acquisition.',
    'acquisition': 'When a collector last read its inputs. An acquired report can still contain missing or stale observations.',
    'verdict': 'The estate collector’s judgment: OK, DEGRADED, DOWN, PAUSED or UNKNOWN. It is shown only for a current, matching report.',
    'concern': 'An application obligation. PRESENT means its required observation holds; ABSENT means it does not. Missing required observations degrade the service.',
    'rule': 'A declared detector. Its summary says what it measures; its hold determines how long a fault must persist.',
    'family': 'A coverage obligation from the committed coverage ledger. Similar rule names do not establish equivalence.',
    'route': 'A named notification destination. Configuration alone does not establish delivery or operator receipt.',
    'handler': 'The configured transport, such as Slack, Discord, PagerDuty or a local qualification inbox. Secrets are never read here.',
    'runbook': 'Instructions at a document anchor. A label alone does not prove that a published anchor is reachable.',
    'revision': 'The digest pinned by the registry and compared with the effective policy. A digest is identity, not authorization.',
    'state': 'Firing means the detector is active; pending means its hold is still running; inactive can mean clear only with current, healthy evidence.',
    'value-code': 'Only rules marked constellation_value_codes=v1 use codes 1–5. Code 1 is present when firing; 2–5 hold unknown. Unmarked values retain raw numeric meaning.',
    'probe': 'A bounded endpoint check from the configured vantage. A successful probe is not proof of useful application work.',
    'producer': 'A collector, status command, saved check or scheduled job that supplies observations. This page never runs it.',
    'supervision': 'How a component’s failure is detected. A timer declaration alone does not prove a failure reaches an operator.',
    'coverage': 'Closed on this host only when observed, declared and pinned, routed, linked to a runbook, and drilled all have evidence.',
    'observed': 'Fresh acquisition and evaluation with usable evidence, plus a host-scoped history receipt for the family’s full scope.',
    'declared': 'A rule is loaded under the exact locally declared policy and registry pin.',
    'routed': 'A configured effective route and a host/revision-scoped delivery receipt. Drop is never a route.',
    'drilled': 'A retained trigger and recovery exercise receipt for this host and policy revision.',
    'unknown': 'Constellation cannot establish the result. The cause is shown; missing data never means clear.',
    'not-current': 'An input is too old, from the future, from another site, or bound to another declaration.',
    'refused': 'A producer or evaluator declined the operation. Inspect its reason; refusal does not establish recovery.',
    'identity': 'The file, group and name that identify a rule; names alone can be ambiguous.',
    'evidence': 'A source file, report entry or retained receipt supporting this row. Pointers are claims, not cryptographic verification.',
    'reason': 'The producer’s explanation or the cause of an unknown result.',
    'hold': 'How long a condition must persist before notification. Recovery also needs confirmation.',
    'home': 'The usual observation mechanism named by the coverage ledger.',
    'source-status': 'The ledger’s source-development status. This never establishes host coverage.',
    'input': 'A local file used to build this page.',
    'path': 'The local input pathname; the page does not publish its raw contents.',
    'item': 'A workload, excluded unit pattern, missing observation or coverage gap.',
    'needs-you': 'An incident requires operator attention. Inspect it with constellation-incidents; this page authorizes no action.',
}
# Exact names from the deployed host-pressure/substrate policies. New families
# use an explicit constellation_family label or the host evidence rule map.
FAMILIES = {
    'HostIoPressureHigh': 'block I/O pressure', 'HostIoPressureSevere': 'block I/O pressure',
    'HostMemoryPressureHigh': 'OOM / memory pressure events',
    'HostSwapExhausted': 'swap_thrashing (second-pass candidate)',
    'HostClockUnsynchronised': 'clock skew / NTP failure',
    'HostClockOffsetHigh': 'clock skew / NTP failure',
    'HostNetworkErrorsHigh': 'network interface errors / drops',
    'HostCpuBusyHigh': 'CPU saturation / scheduler pressure',
    'HostCpuPressureHigh': 'CPU saturation / scheduler pressure',
    'HostFilesystemSpaceLow': 'disk capacity (bytes)',
    'HostFilesystemInodesLow': 'inode exhaustion',
    'HostFilesystemReadOnly': 'mount state (ro/remount/missing)',
    'HostConntrackHigh': 'conntrack / socket table pressure',
    'HostRebooted': 'reboot / unexpected uptime reset',
    'HostFileDescriptorsHigh': 'file descriptor exhaustion',
    'HostClockUnsynced': 'clock skew / NTP failure',
    'HostConntrackNearLimit': 'conntrack / socket table pressure',
    'HostFileDescriptorsNearLimit': 'file descriptor exhaustion',
    'HostFilesystemNearFull': 'disk capacity (bytes)',
    'HostInodesNearExhausted': 'inode exhaustion',
    'HostFilesystemDeviceError': 'mount state (ro/remount/missing)',
    'HostInterfaceDrops': 'network interface errors / drops',
    'HostInterfaceErrors': 'network interface errors / drops',
    'HostLinkFlapping': 'network interface errors / drops',
    'HostOomKill': 'OOM / memory pressure events',
}


ATTENTION_FAMILIES = {
    'host-disk': 'disk capacity (bytes)',
    'memory-pressure': 'OOM / memory pressure events',
    'io-pressure': 'block I/O pressure',
    'service-down': 'process presence',
    'service-not-doing-its-job': 'coverage honesty (operational vs declared)',
    'nq-no-fresh-acquisition': 'witness silence',
    'nightshift-recurrence-missing': 'scheduled_job_freshness (candidate)',
}
ATTENTION_MEANINGS = {
    'host-posture-unknown': 'Host posture cannot supply a current recognized observation.',
    'host-disk': 'Filesystem available space is at or below the detector’s declared capacity threshold.',
    'nq-no-fresh-acquisition': 'No fresh NQ acquisition within the configured age bound.',
    'service-down': 'A watched systemd unit is not active.',
    'memory-pressure': 'Memory full-stall pressure exceeds the detector’s bound.',
    'io-pressure': 'I/O full-stall pressure exceeds the detector’s bound.',
    'nightshift-recurrence-missing': 'No closed Nightshift observation cycle within the configured age bound.',
    'sqlite-health': 'A declared SQLite saved check reports failure.',
    'service-not-doing-its-job': 'A service is DOWN or DEGRADED because required observations do not hold.',
    'remediation-journal-critical': 'The remediation journal has at least 15 sealed segments; custody is due before refusal at 16.',
    'metric-alert-firing': 'An opted-in vmalert detector is firing under its declared policy; value codes 2–5 hold unknown.',
    'evaluator-input-unavailable': 'A configured monitoring input is unreadable, not current, indeterminate or rejected.',
    'docket-unsettled': 'A Docket attempt has not settled within its age bound.',
    'ag-executor-unavailable': 'The governed action executor is unavailable.',
}


def stamp(value):
    try:
        parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00')) if isinstance(value, str) else None
        return parsed.timestamp() if parsed is not None and parsed.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None


def freshness(value, now, maximum):
    at = stamp(value)
    if at is None:
        return 'unknown: missing or invalid acquisition time'
    if at > now + 60:
        return 'unknown: future timestamp'
    if now - at > maximum:
        return 'unknown: stale (age %ds exceeds %ds)' % (now - at, maximum)
    return None


def digest(doc):
    return 'sha256:' + hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def read(path, fmt='json', schema=None):
    try:
        with Path(path).open('rb') as stream:
            raw = stream.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise ValueError('input exceeds 8 MiB')
        doc = json.loads(raw) if fmt == 'json' else tomllib.loads(raw.decode()) if fmt == 'toml' else raw.decode()
        if fmt != 'text' and not isinstance(doc, dict):
            raise ValueError('expected an object')
        if schema and doc.get('schema') != schema:
            return {}, 'unknown: %s: unsupported schema (expected %s)' % (path, schema), raw
        return doc, None, raw
    except (OSError, ValueError, SyntaxError, UnicodeError) as error:
        # Do not echo input fragments: configuration could accidentally contain secrets.
        return {} if fmt != 'text' else '', 'unknown: %s: %s' % (path, type(error).__name__), b''


def rows(doc, key):
    value = doc.get(key, [])
    if not isinstance(value, list) or any(not isinstance(x, dict) for x in value):
        raise ValueError('%s must be a list of objects' % key)
    return value


def safe_url(value):
    if not isinstance(value, str):
        return ''
    try:
        url = urlsplit(value)
        if url.scheme not in ('http', 'https') or not url.hostname:
            return ''
        # Exclude credentials, query parameters and fragments from probe targets.
        return urlunsplit((url.scheme, url.netloc.split('@')[-1], url.path, '', ''))
    except ValueError:
        return ''


def source_pointer(path, fragment):
    return '%s#%s' % (path, fragment)


def ledger_rows(text):
    found, result = False, []
    for line in text.splitlines():
        if line.startswith('| May audit family |'):
            found = True
            continue
        if found:
            if not line.startswith('|'):
                break
            cells = [x.strip() for x in line.strip().strip('|').split('|')]
            if cells[0].startswith('---'):
                continue
            if len(cells) != 4:
                raise ValueError('unsupported coverage ledger row')
            result.append(dict(zip(('family', 'home', 'source_status', 'owner'), cells)))
    if not result:
        raise ValueError('coverage family table not found')
    return result


def keyed_rules(doc, declared=False):
    result = {}
    groups = rows(doc, 'groups') if declared else [dict(rules=rows(doc, 'rules'))]
    for group in groups:
        for rule in rows(group, 'rules'):
            key = (group.get('file', rule.get('file', '')), group.get('name', rule.get('group', '')), rule.get('name', ''))
            if not all(isinstance(x, str) and x for x in key) or key in result:
                raise ValueError('missing or duplicate rule identity')
            for field in ('labels', 'annotations'):
                if field in rule and not isinstance(rule[field], dict):
                    raise ValueError('invalid rule %s' % field)
            result[key] = rule
    return result


def rule_state(rule, fault, now, max_age, site):
    if fault:
        return fault, False
    if not rule:
        return 'unknown: declared but not acquired', False
    fault = freshness(rule.get('last_evaluation'), now, max_age)
    if fault or rule.get('health') != 'ok':
        return fault or 'unknown: evaluation health %s (%s)' % (rule.get('health', 'missing'), rule.get('last_error', '')), False
    state = rule.get('state')
    if state not in ('inactive', 'pending', 'firing'):
        return 'unknown: invalid rule state', False
    marker = rule.get('labels', {}).get('constellation_value_codes')
    if marker is not None:
        if marker != 'v1':
            return 'unknown: unsupported value-code marker', False
        counts = rule.get('value_code_counts')
        if not isinstance(counts, list) or any(not isinstance(x, dict) for x in counts):
            return 'unknown: missing or malformed complete value-code counts', False
        local = [x for x in counts if x.get('site') in ('', site) and x.get('state') in ('pending', 'firing')]
        meanings, usable = [], True
        for item in local:
            try:
                code = float(item['value'])
                count = item['count']
                if not math.isfinite(code) or code not in CODES or type(count) is not int or count < 1:
                    raise ValueError('invalid value code/count')
                meanings.append('%s × %d: code %d %s' % (item['state'], count, code, CODES[code]))
                usable &= code == 1
            except (KeyError, ValueError, TypeError, OverflowError):
                return 'unknown: invalid value-code/count', False
        if meanings:
            prefix = 'unknown-held; ' if not usable else ''
            return prefix + '; '.join(meanings), usable
        if state != 'inactive':
            return 'unknown: no complete value-code evidence for this host', False
    # A global firing state cannot establish this host's state in a multi-site document.
    instances = rows(rule, 'instances')
    local = [x for x in instances if x.get('labels', {}).get('site', site) in ('', site)]
    if state != 'inactive':
        if not local:
            return 'unknown: no acquired instance for this host', False
        return '; '.join('%s: %s' % (x.get('state', state), x.get('summary') or 'value=' + str(x.get('value', '?'))) for x in local), True
    fetched = rule.get('last_series_fetched')
    if type(fetched) not in (int, float) or fetched <= 0:
        return 'unknown: no series acquired or acquisition count missing', False
    return 'inactive (current healthy evaluation; no active instance)', True


def build(args, now):
    sources, faults, data, raw = [], [], {}, {}
    specs = (
        ('registry', args.registry, 'json', 'constellation.estate_registry/v1'),
        ('estate', args.estate, 'json', 'constellation.estate/v1'),
        ('attention_config', args.attention_config, 'toml', 'constellation.attention_config.v1'),
        ('attention_report', args.attention_report, 'json', 'constellation.attention_report.v1'),
        ('policy', args.policy, 'json', 'constellation.vmalert_policy/v1'),
        ('metrics', args.metric_alerts, 'json', 'constellation.metric_alerts/v1'),
        ('ledger', args.ledger, 'text', None),
        ('evidence', args.coverage_evidence, 'json', 'constellation.monitored_coverage/v1'),
    )
    for name, path, fmt, schema in specs:
        doc, error, content = read(path, fmt, schema)
        data[name], raw[name] = doc, content
        faults.append((name, error))
        sources.append({'input': name, 'path': str(path), 'state': error or 'read (currentness checked below)'})
    fault = dict(faults)
    reg, estate, config, report, policy, metrics = (data[k] for k in ('registry', 'estate', 'attention_config', 'attention_report', 'policy', 'metrics'))
    site = args.site or reg.get('site') or config.get('site') or socket.gethostname()
    inputs = config.get('inputs') or {}
    if not isinstance(inputs, dict):
        inputs = {}
        fault['attention_config'] = 'unknown: malformed attention inputs'
    for name, doc, timekey, maximum in (
        ('estate', estate, 'generated_at', (inputs.get('estate') or {}).get('max_age_seconds', args.max_age)),
        ('metrics', metrics, 'generated_at', (inputs.get('metric_alerts') or {}).get('max_age_seconds', args.max_age)),
        ('attention_report', report, 'evaluated_at', args.max_age),
    ):
        fault[name] = fault[name] or freshness(doc.get(timekey), now, maximum)
        if not fault[name] and doc.get('site') != site:
            fault[name] = 'unknown: %s site does not match %s' % (name, site)
    if not fault['registry'] and reg.get('site') != site:
        fault['registry'] = 'unknown: registry site does not match %s' % site
    if fault['registry']:
        fault['estate'] = fault['registry']
    elif estate.get('registry_sha256') != hashlib.sha256(raw['registry']).hexdigest():
        fault['estate'] = 'unknown: acquisition does not match current registry bytes'
    if report.get('dry_run'):
        fault['attention_report'] = 'unknown: report is a dry run'
    for name, key in (('registry', 'services'), ('estate', 'services'), ('attention_report', 'conditions')):
        try:
            rows(data[name], key)
        except ValueError as error:
            fault[name] = 'unknown: %s' % error
            data[name][key] = []
    services = {}
    for svc in reg.get('services', []):
        if isinstance(svc.get('name'), str):
            services[svc['name']] = (svc, str(args.registry))
    declaration_dir = Path(args.services_dir)
    try:
        files = sorted(declaration_dir.glob('*.toml')) if declaration_dir.is_dir() else []
        if declaration_dir.exists() and not declaration_dir.is_dir():
            raise OSError('not a directory')
        sources.append({'input': 'declarations', 'path': str(declaration_dir), 'state': '%d optional declaration files' % len(files)})
        for path in files:
            svc, error, _ = read(path, 'toml')
            name = svc.get('name')
            if not error and not isinstance(name, str):
                error = 'unknown: declaration has no service name'
            sources.append({'input': 'declaration', 'path': str(path), 'state': error or 'read'})
            if error:
                services['unreadable declaration: ' + path.name] = ({'name': path.name, '_error': error}, str(path))
            elif name in services and svc != services[name][0]:
                # Display the local declaration, but never attach a registry acquisition to changed data.
                svc['_error'] = 'unknown: declaration differs from acquired registry entry'
                services[name] = (svc, str(path))
            else:
                services[name] = (svc, str(path))
    except OSError:
        sources.append({'input': 'declarations', 'path': str(declaration_dir), 'state': 'unknown: cannot list declarations'})
    acquired = {s.get('name'): s for s in estate.get('services', [])}
    for name, svc in acquired.items():
        if name not in services:
            services[name] = ({'name': name, 'role': svc.get('role'), '_error': None if name in ('estate-coverage', 'estate-definitions') else 'unknown: acquired but not declared'}, str(args.estate))
    routes = config.get('routes') or {}
    notice = routes.get('notice_route', 'unknown: no notice route')
    transport = routes.get('notice_transport', 'slack')
    route_text = '%s via %s; network %s; delivery/receipt unverified' % (notice, transport, 'enabled' if routes.get('network_enabled') else 'disabled')
    if fault['attention_config']:
        route_text = fault['attention_config']
    service_rows, producers, components, gaps = [], [], [], []
    for name, (svc, pointer) in sorted(services.items()):
        obs = acquired.get(name, {})
        error = svc.get('_error') or fault['estate'] or fault['registry'] or (None if obs else 'unknown: declared but not acquired')
        status = svc.get('status') or {}
        runtime = svc.get('runtime') or {}
        concerns = []
        concern_fault = None
        for c in rows(obs, 'concerns'):
            if c.get('required'):
                concern_error = error
                if c.get('observed_at') and c.get('valid_for_seconds'):
                    concern_error = concern_error or freshness(c['observed_at'], now, c['valid_for_seconds'])
                concern_fault = concern_fault or concern_error
                concerns.append('%s: %s — %s (observed %s)' % (c.get('id'), 'UNKNOWN' if concern_error else c.get('state', 'UNKNOWN'), concern_error or c.get('reason', ''), c.get('observed_at') or 'unknown'))
                if c.get('state') in ('MISSING_REQUIRED_OBSERVATION', 'UNKNOWN', 'STALE') or concern_error:
                    gaps.append({'item': name + ':' + str(c.get('id')), 'reason': concern_error or c.get('state'), 'evidence': source_pointer(args.estate, name)})
        contract = svc.get('contract') or {}
        if not concerns:
            concerns = ['unknown: required concerns not acquired' if error else ('unknown: contract supplied but no required observations' if contract.get('concerns') else 'no required concerns in acquisition (runtime alone is not application health)')]
        timers = svc.get('timers') or []
        observation = status.get('kind', 'runtime only')
        if status.get('url'):
            observation += ': ' + safe_url(status['url'])
        if contract.get('concerns'):
            observation += '; contract ' + str(contract['concerns'])
        condition = [c for c in report.get('conditions', []) if str(c.get('id', '')).endswith(':' + name)]
        estate_rule = next((r for r in rows(report, 'rules') if r.get('id') == 'service-not-doing-its-job'), {})
        tells = route_text + '; service-not-doing-its-job after %ss; inspect constellation-incidents' % estate_rule.get('persistence_seconds', '600 by default')
        if estate_rule and (not estate_rule.get('enabled') or not estate_rule.get('input_configured')):
            tells = 'unknown: service-not-doing-its-job disabled or input not configured'
        if not estate_rule:
            tells = 'unknown: effective service rule missing from attention report'
        if obs.get('verdict') == 'PAUSED':
            tells = 'declared pause: estate notice suppressed; pause remains visible in the daily digest'
        if not inputs.get('estate') or fault['attention_report']:
            tells = 'unknown: estate attention input absent' if not inputs.get('estate') else fault['attention_report']
        row = {'service': name, 'role': svc.get('role') or 'unknown: no role declared',
               'runtime': ', '.join('%s=%s' % (k, v) for k, v in runtime.items()) or str(obs.get('runtime', 'unknown: runtime not declared')),
               'observation': observation, 'acquisition': estate.get('generated_at', 'unknown'),
               'verdict': error or concern_fault or obs.get('verdict', 'UNKNOWN'), 'reason': error or obs.get('reason', 'unknown'),
               'concern': '\n'.join(concerns), 'route': tells, 'revision': str(contract.get('sha256', 'unknown: no contract revision pinned')),
               'supervision': 'timers: ' + ', '.join(t if isinstance(t, str) else t.get('unit', '?') for t in timers) if timers else 'runtime acquisition only; no timer declared',
               'evidence': source_pointer(pointer, name),
               'state': fault['attention_report'] or '; '.join(str(c.get('observation', 'unknown')) + ': ' + str(c.get('note', '')) for c in condition) or 'unknown: no attention condition matched'}
        service_rows.append(row)
        if error:
            gaps.append({'item': name, 'reason': error, 'evidence': pointer})
        if status:
            producers.append({'producer': name + ' status', 'probe': observation if status.get('kind') == 'http' else 'not an endpoint probe', 'supervision': row['supervision'], 'acquisition': row['acquisition'], 'state': row['verdict'], 'evidence': row['evidence']})
        for timer in timers:
            producers.append({'producer': timer if isinstance(timer, str) else timer.get('unit', '?'), 'probe': 'scheduled producer', 'supervision': name + '; ' + row['concern'], 'acquisition': row['acquisition'], 'state': row['verdict'], 'evidence': row['evidence']})
        if str(svc.get('role', '')).lower().startswith('constellation:') or any('constellation-' in str(v) for v in runtime.values()) or name in ('node-exporter', 'victoria-metrics', 'vmalert', 'nightshift', 'estate-coverage', 'estate-definitions'):
            components.append({k: row[k] for k in ('service', 'role', 'runtime', 'supervision', 'verdict', 'concern', 'evidence')})
    coverage_acq = acquired.get('estate-coverage', {})
    if fault['estate'] or coverage_acq.get('verdict') == 'UNKNOWN' or 'unregistered' not in coverage_acq:
        gaps.append({'item': 'unregistered units', 'reason': fault['estate'] or coverage_acq.get('reason') or 'unknown: estate inventory result missing', 'evidence': str(args.estate)})
    else:
        for unit in coverage_acq.get('unregistered', []):
            gaps.append({'item': unit, 'reason': 'unregistered and not excluded', 'evidence': source_pointer(args.estate, 'estate-coverage')})
    for kind, exclusions in (reg.get('unsupervised') or {}).items():
        for exclusion in exclusions:
            gaps.append({'item': kind + ':' + exclusion.get('match', '?'), 'reason': 'explicitly excluded: ' + exclusion.get('reason', 'unknown'), 'evidence': str(args.registry)})
    # These components can fail without appearing as registered services.
    for name, producer in (('estate', 'constellation-estate-collect.timer'), ('attention_report', 'constellation-attention.timer'), ('metrics', 'constellation-metric-alerts-collect.timer')):
        components.append({'service': producer, 'supervision': 'acquired output freshness; independent host-loss witness unknown', 'state': fault[name] or 'output current (does not prove independent notification)', 'evidence': sources[[s[0] for s in specs].index(name)]['path']})
    for kind, entries in inputs.items():
        for entry in entries if isinstance(entries, list) else [entries]:
            if not isinstance(entry, dict):
                continue
            reports = [r for r in rows(report, 'inputs') if r.get('kind') == kind and r.get('label') == entry.get('label', r.get('label'))]
            producers.append({'producer': '%s: %s' % (kind, entry.get('label', entry.get('reference', kind))), 'probe': 'attention input', 'supervision': 'evaluator-input-unavailable after 300s by default', 'acquisition': report.get('evaluated_at', 'unknown'), 'state': fault['attention_report'] or '; '.join(str(r.get('status')) + ': ' + str(r.get('error') or '') for r in reports) or 'unknown: input not reported', 'evidence': str(entry.get('path') or entry.get('publication_root') or entry.get('store_path') or args.attention_config)})
    expected = digest(policy) if not fault['policy'] else None
    pins = [d.get('digest') for d in rows(reg, 'definitions') if d.get('kind') == 'vmalert-policy']
    policy_ok = bool(expected and expected in pins and metrics.get('policy_sha256') == expected and metrics.get('declared_policy_sha256') == expected and metrics.get('policy_matches_declared') is True and not fault['registry'])
    metric_fault = fault['metrics'] or (None if policy_ok else 'unknown: effective policy, local declaration and registry pin do not all match')
    try:
        declared, running = keyed_rules(policy, True), keyed_rules(metrics)
    except ValueError as error:
        declared, running = {}, {}
        metric_fault = 'unknown: %s' % error
        fault['metrics'] = metric_fault
    manifest = data['evidence']
    manifest_ok = not fault['evidence'] and manifest.get('site') == site and manifest.get('policy_sha256') == expected
    families_evidence = manifest.get('families', {}) if manifest_ok else {}
    rule_rows = []
    effective_metric_rule = next((r for r in rows(report, 'rules') if r.get('id') == 'metric-alert-firing'), {})
    metric_route_enabled = effective_metric_rule.get('enabled') is True and effective_metric_rule.get('input_configured') is True
    rejected = {r.get('name') or r.get('rule') for i in rows(report, 'inputs') for r in rows(i, 'rejected_rules')}
    for key in sorted(set(declared) | set(running)):
        definition, live = declared.get(key, {}), running.get(key, {})
        labels = definition.get('labels') or live.get('labels') or {}
        family = labels.get('constellation_family') or FAMILIES.get(key[2])
        for family_name, entry in families_evidence.items():
            if list(key) in entry.get('rules', []):
                family = family_name
        state, usable = rule_state(live, metric_fault, now, (inputs.get('metric_alerts') or {}).get('max_evaluation_age_seconds', args.max_age), site)
        if definition and live and definition.get('labels', {}) != live.get('labels', {}):
            state, usable = 'unknown: acquired labels differ from declared rule', False
        if key[2] in rejected:
            state, usable = 'unknown: rule rejected by attention admission', False
        if not definition:
            state, usable = 'unknown: loaded rule absent from declared policy; ' + state, False
        route = route_text if labels.get('attention') == 'true' and inputs.get('metric_alerts') else ('Alertmanager route: ' + str(labels.get('notify')) + '; handler and delivery unknown' if labels.get('notify') and labels.get('notify') != 'drop' else 'unknown: no effective route declared (possible drop)')
        anchor = str(labels.get('runbook') or definition.get('annotations', {}).get('runbook_url') or '')
        rb_url = safe_url(anchor) if anchor.startswith(('https://', 'http://')) else safe_url((config.get('runbooks') or {}).get('cartography_url', ''))
        # Only http(s) document links; labels without a published base stay visibly unresolved.
        runbook = (rb_url + '#' + (urlsplit(anchor).fragment if anchor.startswith(('https://', 'http://')) else anchor.lstrip('#'))) if rb_url and anchor else 'unknown: unpublished runbook anchor ' + (anchor or '(missing)')
        if not metric_route_enabled and labels.get('attention') == 'true':
            route = 'unknown: effective metric-alert-firing rule disabled, unconfigured or missing from report; ' + route
        evidence = source_pointer(args.metric_alerts, '/'.join(key))
        rule_rows.append({'rule': key[2], 'identity': '/'.join(key), 'family': family or 'unknown: no explicit family mapping', 'observation': definition.get('annotations', {}).get('summary', 'unknown: summary not acquired'), 'state': state, 'acquisition': live.get('last_evaluation') or 'unknown: never evaluated', 'route': route, 'handler': transport if labels.get('attention') == 'true' else 'unknown: Alertmanager config not an input', 'runbook': runbook, 'revision': '%s; registry pins %s' % (metrics.get('policy_sha256', 'unknown'), ', '.join(pins) or 'unknown'), 'hold': str(definition.get('duration_seconds', '?')) + 's vmalert hold; attention metric notice default 60s', 'value-code': ('v1: ' + '; '.join('%d=%s' % item for item in CODES.items()) if labels.get('constellation_value_codes') == 'v1' else 'unknown: unsupported marker ' + str(labels['constellation_value_codes'])) if 'constellation_value_codes' in labels else 'unmarked: raw numeric values', 'evidence': evidence, '_usable': usable, '_declared': bool(definition) and bool(live) and definition.get('labels', {}) == live.get('labels', {}) and policy_ok and not fault['metrics'], '_route': metric_route_enabled and report.get('network_enabled') is True and labels.get('attention') == 'true' and bool(inputs.get('metric_alerts')) and not fault['attention_config'] and not fault['attention_report'] and bool(routes.get('network_enabled')) and notice != 'drop' and transport != 'local_file', '_runbook': not runbook.startswith('unknown:')})
    attention_pins = [d.get('digest') for d in rows(reg, 'definitions') if d.get('kind') == 'attention-policy' and d.get('config') == str(args.attention_config)]
    attention_revision = '%s; registry pin %s' % (report.get('attention_policy_digest', 'unknown'), ', '.join(attention_pins) or 'unknown: absent')
    attention_revision += '; matched' if report.get('attention_policy_digest') in attention_pins else '; unknown: not verified against registry pin'
    # Compiled attention rules are described by the evaluator's own report.
    # Do not execute the evaluator or invent a missing report's rule roster.
    for rule in rows(report, 'rules'):
        name = rule.get('id', 'unknown')
        conditions = [c for c in rows(report, 'conditions') if c.get('rule') == name]
        rb_base = safe_url((config.get('runbooks') or {}).get('monitor_url' if name in ('metric-alert-firing', 'evaluator-input-unavailable', 'service-not-doing-its-job', 'remediation-journal-critical', 'memory-pressure', 'io-pressure', 'sqlite-health') else 'cartography_url', ''))
        rb_link = rb_base + '#' + name if rb_base else 'unknown: unpublished runbook anchor #' + name
        route = route_text
        if rule.get('class') == 'page':
            route += '; page route %s via pagerduty (delivery/receipt unverified)' % routes.get('page_route', 'unknown: absent')
        state = fault['attention_report'] or '; '.join('%s: %s' % (c.get('observation', 'unknown'), c.get('note', '')) for c in conditions) or 'unknown: no acquired condition (absence is not clear)'
        if rule.get('enabled') is False or rule.get('input_configured') is False:
            state = 'not monitored: disabled or input not configured; ' + state
        rule_rows.append({'rule': name, 'identity': 'attention/' + name, 'family': ATTENTION_FAMILIES.get(name, 'attention ' + str(rule.get('input', 'unknown'))), 'observation': ATTENTION_MEANINGS.get(name, 'unknown: rule summary absent from report') if report.get('registry') == 'constellation.attention_registry.v7' else 'unknown: unsupported attention registry meaning', 'state': state, 'acquisition': report.get('evaluated_at', 'unknown'), 'route': route, 'handler': transport + (' + pagerduty' if rule.get('class') == 'page' else ''), 'runbook': rb_link, 'revision': attention_revision, 'hold': '%ss persistence; threshold %s' % (rule.get('persistence_seconds', '?'), rule.get('threshold_seconds', '?')), 'value-code': 'not a value-coded metric rule', 'evidence': source_pointer(args.attention_report, 'rules/' + name), '_usable': not fault['attention_report'] and bool(conditions) and all(c.get('observation') in ('clear', 'present') for c in conditions), '_declared': not fault['registry'] and not fault['attention_config'] and not fault['attention_report'] and report.get('attention_policy_digest') in attention_pins, '_route': report.get('network_enabled') is True and not fault['attention_report'] and not fault['attention_config'] and bool(routes.get('network_enabled')) and notice != 'drop' and transport != 'local_file', '_runbook': bool(rb_base), '_attention': True, '_enabled': rule.get('enabled') is True and rule.get('input_configured') is True})
    try:
        families = ledger_rows(data['ledger'])
    except ValueError as error:
        families = []
        fault['ledger'] = 'unknown: %s' % error
        gaps.append({'item': 'coverage families', 'reason': fault['ledger'], 'evidence': str(args.ledger)})
    coverage_rows = []
    for family in families:
        members = [r for r in rule_rows if r['family'] == family['family'] and r.get('_enabled', True)]
        receipt = families_evidence.get(family['family'], {})
        if any(r.get('_attention') for r in members) and manifest.get('attention_policy_digest') != report.get('attention_policy_digest'):
            receipt = {}
        row = {'family': family['family'], 'home': family['home'], 'rule': ', '.join(r['rule'] for r in members) or 'none on this host', 'evidence': source_pointer(args.ledger, family['family']), 'source-status': family['source_status'] + ' (source only)'}
        tests = {'observed': bool(members) and all(r['_usable'] for r in members), 'declared': bool(members) and all(r['_declared'] for r in members), 'routed': bool(members) and all(r['_route'] for r in members), 'runbook': bool(members) and all(r['_runbook'] for r in members), 'drilled': bool(members)}
        # Receipts must cover the family scope, not just one conveniently working rule.
        for part, holds in tests.items():
            evidence = receipt.get(part, {})
            attested = isinstance(evidence, dict) and evidence.get('holds') is True and isinstance(evidence.get('evidence'), list) and bool(evidence['evidence']) and all(isinstance(p, str) and p.strip() for p in evidence['evidence'])
            if part == 'declared':
                attested = True  # mechanically verified from three matching identities
            ok = holds and attested
            detail = '; '.join(evidence.get('evidence', [])) if isinstance(evidence, dict) and isinstance(evidence.get('evidence'), list) else ''
            if part == 'declared' and holds:
                detail = str(args.registry) + '; ' + '; '.join(r['evidence'] + '; ' + r['revision'] for r in members)
            row[part] = ('yes: ' if ok else 'unknown: ') + (detail or ('no rule on this host' if not members else 'family scope receipt or current supporting input missing'))
        row['coverage'] = 'closed on this host' if all(row[p].startswith('yes:') for p in tests) else 'open on this host'
        coverage_rows.append(row)
        if not members:
            gaps.append({'item': family['family'], 'reason': 'no mapped rule on this host; source status does not establish observation', 'evidence': str(args.ledger)})
    for item in sources:
        if fault.get(item['input']):
            item['state'] = fault[item['input']]
    return {'host': site, 'rendered_at': dt.datetime.fromtimestamp(now, dt.timezone.utc).isoformat(), 'sources': sources, 'services': service_rows, 'rules': rule_rows, 'producers': producers, 'components': components, 'coverage': coverage_rows, 'not monitored': gaps}


def public(row):
    return {k: v for k, v in row.items() if not k.startswith('_')}


def terminal(doc, target=None):
    out = ['What is monitored on %s — rendered %s' % (doc['host'], doc['rendered_at']), 'Unknown never means clear. This projection authorizes no action.']
    found = False
    for section in ('services', 'rules', 'producers', 'components', 'coverage', 'not monitored', 'sources'):
        items = doc[section]
        if target:
            items = [r for r in items if target in (r.get('service'), r.get('rule'), r.get('identity'))]
        if items:
            found = True
            out.append('\n' + section.upper())
            for row in items:
                out.append('\n'.join('  %s: %s' % (k, v) for k, v in public(row).items()))
                out.append('')
    if target and not found:
        out.append('unknown: no service or rule named %s in readable inputs' % target)
    out.append('\nGLOSSARY\n' + '\n'.join('%s: %s' % item for item in GLOSSARY.items()))
    return '\n'.join(out) + '\n', found


def cell(value):
    text = str(value)
    if text.startswith(('http://', 'https://')) and ' ' not in text:
        return '<a href="%s">%s</a>' % (html.escape(text, quote=True), html.escape(text))
    escaped = html.escape(text)
    terms = '|'.join(re.escape(k) for k in sorted(GLOSSARY, key=len, reverse=True))
    escaped = re.sub(r'(?<![\w-])(' + terms + r')(?![\w-])', lambda m: '<a href="#g-%s">%s</a>' % (m.group().lower(), m.group()), escaped, flags=re.IGNORECASE)
    return escaped.replace('\n', '<br>')


def render(doc):
    out = ['<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>What is monitored</title><style>body{font:16px/1.5 system-ui,sans-serif;max-width:90rem;margin:auto;padding:1rem;color:#17212b;background:#fff}a{color:#154f91}table{border-collapse:collapse;width:100%}th,td{text-align:left;vertical-align:top;border:1px solid #aaa;padding:.5rem;overflow-wrap:anywhere;min-width:9rem}.scroll{overflow:auto}dt{font-weight:bold}section{margin:2rem 0}details{border:1px solid #aaa;border-radius:.3rem;padding:.6rem;margin:.5rem 0}summary{cursor:pointer;font-weight:bold}dl.fields{display:grid;grid-template-columns:minmax(7rem,12rem) 1fr;gap:.4rem}dd{margin:0;overflow-wrap:anywhere}summary:focus-visible,a:focus-visible{outline:3px solid #154f91}@media(max-width:40rem){dl.fields{display:block}dd{margin-bottom:1rem}}caption{text-align:left}nav a{margin-right:1rem}</style><body>', '<h1>What is monitored on %s</h1>' % html.escape(doc['host']), '<p>Rendered %s. Scheduled every 5 minutes; if this timestamp stops advancing, current monitoring is <a href="#g-unknown">unknown</a>. This is a read-only projection and authorizes no action. Missing data never means clear.</p>' % html.escape(doc['rendered_at']), '<p>Start with your service, read how it is observed and what would tell you, then check coverage and the gaps below. <a href="index.html">Host status</a></p>', '<nav>' + ''.join('<a href="#%s">%s</a>' % (s.replace(' ', '-'), html.escape(s.title())) for s in ('services', 'rules', 'producers', 'components', 'coverage', 'not monitored', 'sources', 'glossary')) + '</nav>']
    for section in ('services', 'rules', 'producers', 'components', 'coverage', 'not monitored', 'sources'):
        items = [public(r) for r in doc[section]]
        out.append('<section id="%s"><h2>%s</h2>' % (section.replace(' ', '-'), section.title()))
        if not items:
            out.append('<p>Unknown: no entries from readable inputs; this does not establish completeness.</p></section>')
            continue
        if section in ('services', 'rules'):
            for row in items:
                title = row.get('service') or row.get('rule')
                headline = '%s — %s' % (title, row.get('verdict') or row.get('state'))
                out.append('<details><summary>%s</summary><dl class="fields">' % html.escape(headline))
                for key, value in row.items():
                    out.append('<dt><a href="#g-%s">%s</a></dt><dd>%s</dd>' % (key, html.escape(key.title()), cell(value)))
                out.append('</dl></details>')
            out.append('</section>')
            continue
        columns = ['family', 'observed', 'declared', 'routed', 'runbook', 'drilled', 'coverage'] if section == 'coverage' else list(dict.fromkeys(k for row in items for k in row))
        out.append('<div class="scroll" tabindex="0"><table><caption>%s on this host</caption><thead><tr>' % html.escape(section.title()))
        for key in columns:
            label = '<a href="#g-%s">%s</a>' % (key, html.escape(key.title())) if key in GLOSSARY else html.escape(key.title())
            out.append('<th scope="col">%s</th>' % label)
        out.append('</tr></thead><tbody>')
        for row in items:
            values = []
            for key in columns:
                value = row.get(key, 'unknown: not supplied')
                if section == 'coverage' and key == 'family':
                    context = ''.join('<dt><a href="#g-%s">%s</a></dt><dd>%s</dd>' % (k, html.escape(k.title()), cell(row[k])) for k in ('home', 'rule', 'evidence', 'source-status'))
                    values.append('<td>%s<details><summary>Scope and sources</summary><dl>%s</dl></details></td>' % (cell(value), context))
                elif section == 'coverage' and key in ('observed', 'declared', 'routed', 'runbook', 'drilled'):
                    label = 'yes' if str(value).startswith('yes:') else 'unknown'
                    values.append('<td><details><summary>%s</summary>%s</details></td>' % (label, cell(value)))
                else:
                    values.append('<td>%s</td>' % cell(value))
            out.append('<tr>' + ''.join(values) + '</tr>')
        out.append('</tbody></table></div></section>')
    out.append('<section id="glossary"><h2>Glossary</h2><dl>')
    for term, meaning in GLOSSARY.items():
        out.append('<dt id="g-%s">%s</dt><dd>%s</dd>' % (term, html.escape(term.replace('-', ' ')), html.escape(meaning)))
    out.append('</dl></section></body></html>\n')
    return ''.join(out)


def atomic_write(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.monitored-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--registry', default='/etc/constellation-estate/estate.json')
    p.add_argument('--estate', default='/var/lib/constellation-estate/estate.json')
    p.add_argument('--services-dir', default='/etc/constellation/services.d')
    p.add_argument('--attention-config', default='/etc/constellation-attention/attention.toml')
    p.add_argument('--attention-report', default='/var/lib/constellation-attention/report.json')
    p.add_argument('--policy', default='/etc/constellation-metric-alerts/declared-vmalert-policy.json')
    p.add_argument('--metric-alerts', default='/var/lib/constellation-metric-alerts/metric-alerts.json')
    p.add_argument('--ledger', default=str(HERE / 'COVERAGE-FAMILIES.md'))
    p.add_argument('--coverage-evidence', default='/etc/constellation-monitored/coverage.json')
    p.add_argument('--site', help='expected registry site (otherwise use the local registry)')
    p.add_argument('--max-age', type=int, default=600, help='report freshness in seconds; estate/metrics config bounds take precedence')
    p.add_argument('--now', help='RFC3339 time for reproducible offline inspection')
    sub = p.add_subparsers(dest='command', required=True)
    sub.add_parser('list', help='all sections and glossary')
    show = sub.add_parser('show', help='one service or rule, by exact name or file/group/name')
    show.add_argument('target')
    page = sub.add_parser('render', help='write the static HTML page atomically')
    page.add_argument('--out', default='/var/www/constellation-status/monitored.html', help='HTML filename')
    return p


def main(argv=None):
    p = parser()
    args = p.parse_args(argv)
    now = stamp(args.now) if args.now else dt.datetime.now(dt.timezone.utc).timestamp()
    if now is None or args.max_age <= 0:
        p.error('use an RFC3339 --now and positive --max-age')
    try:
        doc = build(args, now)
    except (ValueError, TypeError, KeyError, AttributeError) as error:
        # A malformed nested input must still publish an explicit unknown page.
        doc = {'host': args.site or socket.gethostname(), 'rendered_at': dt.datetime.fromtimestamp(now, dt.timezone.utc).isoformat(), **{k: [] for k in ('services', 'rules', 'producers', 'components', 'coverage', 'not monitored')}, 'sources': [{'input': 'projection', 'state': 'unknown: malformed input structure (%s); check input schemas' % type(error).__name__}]}
    if args.command == 'render':
        atomic_write(args.out, render(doc))
        print(args.out)
        return 0
    text, found = terminal(doc, getattr(args, 'target', None))
    print(text, end='')
    return 0 if found or args.command == 'list' else 1


if __name__ == '__main__':
    sys.exit(main())
