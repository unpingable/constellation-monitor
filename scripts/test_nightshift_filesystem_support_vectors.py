"""Real consumers of the exact shared source-vector integrity check."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1] / 'artifacts/nightshift-filesystem-support-v1'
SPEC = importlib.util.spec_from_file_location('vectors', Path(__file__).with_name('verify-nightshift-filesystem-support-vectors.py'))
vectors = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vectors)


class SharedFilesystemVectors(unittest.TestCase):
    def changed(self, name, mutate):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for p in ROOT.iterdir():
            if p.is_file():
                shutil.copyfile(p, root / p.name)
        p = root / name
        p.write_bytes(mutate(p.read_bytes()))
        manifest = json.loads((root / 'conformance.json').read_bytes())
        manifest['files'][name] = vectors.digest(p.read_bytes())
        (root / 'conformance.json').write_text(json.dumps(manifest))
        return root

    def test_shared_exact_bytes(self):
        self.assertEqual(vectors.verify(ROOT)[0], 8)

    def test_substituted_config_path_cannot_keep_realization(self):
        def mutate(raw):
            value = json.loads(raw)
            value['outgoing_directory'] = '/other/outgoing'
            return vectors.canonical_fixture(value)
        with self.assertRaisesRegex(ValueError, 'static enrollment'):
            vectors.verify(self.changed('config.json', mutate))

    def test_reidentified_query_cannot_change_scope(self):
        def mutate(raw):
            value = json.loads(raw)
            value['scope_id'] = 'sha256:' + 'f' * 64
            value['query_id'] = vectors.identity(value, 'query_id')
            return vectors.canonical_fixture(value)
        with self.assertRaisesRegex(ValueError, 'query differs from config'):
            vectors.verify(self.changed('query.json', mutate))

    def test_cross_paired_request_query_is_refused(self):
        def mutate(raw):
            value=json.loads(raw)
            b=json.loads((ROOT/'query-b.json').read_bytes())
            for field in ['diagnostic_inputs_id','artifact_ids','observation_id']:
                value[field]=b[field]
            value['query_id']=vectors.identity(value,'query_id')
            return vectors.canonical_fixture(value)
        with self.assertRaisesRegex(ValueError,'selected request'):
            vectors.verify(self.changed('query.json',mutate))

    def test_same_request_basis_cannot_be_claimed_as_two_turns(self):
        with self.assertRaises(ValueError):
            vectors.verify(self.changed('request-b.json',lambda raw:(ROOT/'request-a.json').read_bytes()))

    def test_wire_newline_is_not_accepted_as_exact_bytes(self):
        with self.assertRaisesRegex(ValueError, 'exact canonical bytes'):
            vectors.verify(self.changed('query.json', lambda raw: raw + b'\n'))


if __name__ == '__main__':
    unittest.main()
