"""Selected-edge collection: actual filesystem inputs, no Cargo or binary run."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC=importlib.util.spec_from_file_location('frozen',Path(__file__).with_name('frozen-helper-cohort.py'))
frozen=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(frozen)


class SelectedFingerprintTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.profile=Path(self.temp.name)

    def unit(self,package,unit_hash,name,self_hash,features=(),deps=()):
        directory=self.profile/'.fingerprint'/f'{package}-{unit_hash}'
        directory.mkdir(parents=True)
        key=f'{directory.name}/{name}.json'
        (directory/(name+'.json')).write_text(json.dumps({'features':json.dumps(list(features)),'profile':1,'deps':list(deps)}))
        (directory/name).write_text(self_hash.to_bytes(8,'little').hex())
        return key

    def test_walk_selected_edges_excludes_unused_test_feature_variant(self):
        leaf=self.unit('law','a'*16,'lib-law',1,['production'])
        self.unit('law','b'*16,'lib-law',2,['test-only'])
        root=self.unit('adapter','c'*16,'bin-adapter',3,[],[[7,'law',False,1]])
        result=frozen.trace_fingerprint_units(self.profile,root)
        self.assertEqual(set(result['units']),{root,leaf})
        self.assertEqual(result['units'][leaf]['features'],['production'])
        self.assertEqual(result['edges'][0]['to'],leaf)

    def test_missing_actual_selected_dependency_refuses(self):
        root=self.unit('adapter','c'*16,'bin-adapter',3,[],[[7,'law',False,1]])
        with self.assertRaisesRegex(ValueError,'missing or ambiguous'):
            frozen.trace_fingerprint_units(self.profile,root)

    def test_ambiguous_actual_selected_dependency_refuses(self):
        self.unit('law','a'*16,'lib-law',1)
        self.unit('law','b'*16,'lib-law',1)
        root=self.unit('adapter','c'*16,'bin-adapter',3,[],[[7,'law',False,1]])
        with self.assertRaisesRegex(ValueError,'missing or ambiguous'):
            frozen.trace_fingerprint_units(self.profile,root)

    def test_compiler_binding_uses_selected_hash_and_features_not_union(self):
        key='law-'+'a'*16+'/lib-law.json'
        def record(features,hash='a'*16,test=False):
            return {'reason':'compiler-artifact','target':{'name':'law','kind':['lib']},'profile':{'test':test},'features':features,'filenames':['/actual/release/deps/liblaw-'+hash+'.rlib'],'package_id':'registry+example#law@1'}
        selected=record(['production']);unused=record(['test-only'],'b'*16)
        result=frozen.compiler_record_for_unit(key,{'features':['production']},[unused,selected])
        self.assertEqual(result,selected)
        for records in [[unused],[selected,selected],[record(['production'],test=True)]]:
            with self.assertRaisesRegex(ValueError,'missing or ambiguous'):
                frozen.compiler_record_for_unit(key,{'features':['production']},records)

    def test_shared_private_receipt_preimage_is_exact_with_large_u64_and_unicode(self):
        root=Path(__file__).resolve().parents[1]/'artifacts/host-posture-production-footprint-v1'
        footprint=json.loads((root/'footprint.json').read_bytes())
        expected=json.loads((root/'expected-fs-entry.json').read_bytes())
        self.assertEqual(frozen.footprint_preimage(footprint),(root/'preimage.json').read_bytes())
        frozen.verify_footprint(footprint,expected)
        unit=footprint['units'][footprint['selected_unit']]
        self.assertEqual(unit['self_hash_u64'],18446744073709551615)
        unit['features']=['test-only']
        with self.assertRaisesRegex(ValueError,'footprint changed'):
            frozen.verify_footprint(footprint,expected)

    def test_build_script_run_binds_actual_out_directory(self):
        key='build-law-'+'a'*16+'/run-build-script-build-script-build.json'
        selected={'reason':'build-script-executed','package_id':'registry+example#build-law@1','out_dir':'/actual/release/build/build-law-'+'a'*16+'/out'}
        self.assertEqual(frozen.compiler_record_for_unit(key,{'features':None},[selected]),selected)
        with self.assertRaisesRegex(ValueError,'missing or ambiguous'):
            frozen.compiler_record_for_unit(key,{'features':None},[])


if __name__=='__main__':unittest.main()
