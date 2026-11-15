"""Real temporary filesystem checks; no users, native binary or VM required."""
import importlib.util
import os
from pathlib import Path
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
        moved=writable/'query-b';self.paths[3].rename(moved)
        slots=[self.slots[0],(self.paths[2],moved)]
        with self.assertRaisesRegex(ValueError,'ancestry'):
            principal.validate_request_inputs(slots,self.root,os.geteuid())


if __name__=='__main__':unittest.main()
