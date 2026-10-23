#!/usr/bin/env python3
"""Render the committed offline sample; never reads deployed paths."""
import argparse
import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('monitored', HERE / 'constellation-monitored.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', default='/tmp/monitored-sample.html')
    args = parser.parse_args()
    argv = []
    for flag, name in [('registry', 'registry.json'), ('estate', 'estate.json'), ('services-dir', 'services.d'), ('attention-config', 'attention.toml'), ('attention-report', 'report.json'), ('policy', 'policy.json'), ('metric-alerts', 'metrics.json'), ('coverage-evidence', 'coverage.json')]:
        argv.extend(['--' + flag, str(HERE / 'fixtures' / name)])
    argv.extend(['--ledger', str(HERE / 'COVERAGE-FAMILIES.md'), '--now', '2026-10-22T21:01:00Z', 'render', '--out', args.out])
    return m.main(argv)


if __name__ == '__main__':
    raise SystemExit(main())
