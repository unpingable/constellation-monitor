"""Real temporary filesystem checks; no users, native binary or VM required."""
import importlib.util
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import tempfile
import unittest

SPEC=importlib.util.spec_from_file_location('principal',Path(__file__).with_name('test_fs_principal_handoff.py'))
principal=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(principal)


class PrincipalInputAncestryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o2750)
        self.inputs=self.root/'inputs';self.inputs.mkdir(mode=0o750)
        self.paths=[]
        for name in ['request-a','query-a','request-b','query-b']:
            path=self.inputs/name;path.write_bytes(b'{}');path.chmod(0o640);self.paths.append(path)
        self.slots=[tuple(self.paths[:2]),tuple(self.paths[2:])]

    def test_same_owned_read_only_inputs_under_operator_ancestry_pass(self):
        principal.validate_request_inputs(self.slots,self.root,os.geteuid())

    def test_read_only_request_in_group_writable_parent_refuses(self):
        self.inputs.chmod(0o770)
        self.assertEqual(self.paths[0].stat().st_mode & 0o777,0o640)
        with self.assertRaisesRegex(ValueError,'ancestry'):
            principal.validate_request_inputs(self.slots,self.root,os.geteuid())

    def test_query_parent_is_checked_independently_of_request_parent(self):
        writable=self.root/'query-writer';writable.mkdir(mode=0o770)
        writable.chmod(0o770)
        moved=writable/'query-b';self.paths[3].rename(moved)
        slots=[self.slots[0],(self.paths[2],moved)]
        with self.assertRaisesRegex(ValueError,'ancestry'):
            principal.validate_request_inputs(slots,self.root,os.geteuid())


@unittest.skipUnless(os.geteuid() == 0 and os.environ.get('NATIVE_PRINCIPAL_TEST_USER'),
                     'requires admitted VM operator and explicit existing non-root caller')
class OldPrepareEntryTests(unittest.TestCase):
    """Actual runuser entry controls; the tiny CLI is apparatus, not an adapter."""

    def setUp(self):
        self.caller = os.environ['NATIVE_PRINCIPAL_TEST_USER']
        self.assertNotEqual(pwd.getpwnam(self.caller).pw_uid, 0)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o755)
        self.binary = self.root / 'entry-fixture'
        self.binary.write_text('''#!/usr/bin/python3
import json, pathlib, sys
if sys.argv[1:] == ['--build-info']:
    print(json.dumps({'source_commit': '0b7f7b3b44a5d5fcf7e41a1e6c7c722d4744c95b'}))
else:
    (pathlib.Path(sys.argv[sys.argv.index('--state')+1])/'producer.key').read_bytes()
''')
        self.binary.chmod(0o755)
        self.state = self.root / 'state'
        self.state.mkdir(mode=0o755)
        self.state.chmod(0o755)
        key = self.state / 'producer.key'
        key.write_bytes(b'nonsecret apparatus fixture')
        key.chmod(0o600)
        self.request, self.config = self.root / 'request.json', self.root / 'nq.json'
        for path in [self.request, self.config]:
            path.write_bytes(b'{}')
            path.chmod(0o644)
        self.realization = self.root / 'realization.json'
        self.realization.write_text(json.dumps({
            'monitor_source_commit': '0b7f7b3b44a5d5fcf7e41a1e6c7c722d4744c95b',
            'executable_sha256': 'sha256:'+hashlib.sha256(self.binary.read_bytes()).hexdigest()}))
        self.realization.chmod(0o644)

    def invoke(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(ValueError) as error:
            principal.old_prepare_regression(str(self.binary), str(self.request),
                str(self.config), 'fixture', str(self.state), str(self.realization), self.caller)
        return output.getvalue(), str(error.exception)

    def test_pre_exec_refusal_is_not_reported_as_old_prepare_behavior(self):
        self.binary.chmod(0o744)
        output, _ = self.invoke()
        self.assertNotIn('BEHAVIORAL_RED', output)

    def test_entered_cli_key_denial_is_reported_as_the_intended_behavior(self):
        output, error = self.invoke()
        self.assertIn('BEHAVIORAL_RED_OLD_PREPARATION_REQUIRES_SECRET', output)
        self.assertIn('without producer secret', error)


if __name__=='__main__':unittest.main()
