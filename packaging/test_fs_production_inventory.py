"""Public Cargo record inventory conformance; no native execution inferred."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC=importlib.util.spec_from_file_location('frozen',Path(__file__).with_name('frozen-helper-cohort.py'))
frozen=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(frozen)
ROOT=Path(__file__).resolve().parents[1]/'artifacts/host-posture-production-inventory-v1'

class ProductionInventoryTests(unittest.TestCase):
    def setUp(self):
        self.inventory=json.loads((ROOT/'inventory.json').read_bytes())
        self.cohort=json.loads((ROOT/'expected-cohort.json').read_bytes())
    def validate_records(self,records):
        return frozen.validate_release(records,self.inventory['production_argv'])
    def test_shared_exact_preimage_and_whole_cohort_binding(self):
        self.assertEqual(frozen.inventory_preimage(self.inventory),(ROOT/'preimage.json').read_bytes())
        frozen.verify_inventory(self.inventory,self.cohort)
    def test_all_variants_and_build_script_rows_remain_ordered_without_union(self):
        records,argv,selected=frozen.load_release(ROOT/'cargo.stdout',ROOT/'cargo.argv.json')
        self.assertEqual(records,self.inventory['records'])
        self.assertEqual([r['features'] for r in records[:2]],[['ordinary'],['extra']])
        self.assertEqual(records[2]['reason'],'build-script-executed')
    def test_missing_and_duplicate_selected_records_refuse(self):
        records=self.inventory['records'];index=self.inventory['selected_cohort']['pulse-nq-filesystem-support']['record_index']
        for changed in [records[:index]+records[index+1:],records[:-1]+[records[index],records[-1]]]:
            with self.assertRaises(ValueError): self.validate_records(changed)
    def test_unsuccessful_and_truncated_records_refuse(self):
        for records in [self.inventory['records'][:-1],self.inventory['records'][:-1]+[{'reason':'build-finished','success':False}],self.inventory['records']+[{'reason':'build-finished','success':True}]]:
            with self.assertRaises(ValueError): self.validate_records(records)
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'stream';p.write_bytes((ROOT/'cargo.stdout').read_bytes()[:-9])
            with self.assertRaisesRegex(ValueError,'malformed or truncated'): frozen.load_release(p,ROOT/'cargo.argv.json')
    def test_substituted_selected_bytes_or_record_refuses(self):
        for name in frozen.NAMES:
            cohort=copy.deepcopy(self.cohort);cohort[name]['sha256']='0'*64
            with self.assertRaises(ValueError):frozen.verify_inventory(self.inventory,cohort)
        inventory=copy.deepcopy(self.inventory);inventory['records'][0]['features']=['changed']
        with self.assertRaises(ValueError):frozen.verify_inventory(inventory,self.cohort)
    def test_ambiguous_selection_refuses_even_with_recomputed_inventory_digest(self):
        inventory=copy.deepcopy(self.inventory);index=inventory['selected_cohort']['pulse-nq-filesystem-support']['record_index']
        inventory['records'].insert(-1,inventory['records'][index]);inventory['sha256']=hashlib.sha256(frozen.inventory_preimage(inventory)).hexdigest()
        with self.assertRaises(ValueError):frozen.verify_inventory(inventory,self.cohort)
    def test_different_owning_build_selection_refuses(self):
        argv=self.inventory['production_argv'][:];argv[argv.index('constellation-host-posture')]='foreign-package'
        with self.assertRaises(ValueError):frozen.validate_release(self.inventory['records'],argv)

if __name__=='__main__':unittest.main()
