"""Offline checks of the qualification helper's actual metadata-producing block."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HELPER = Path(__file__).with_name("host-posture-qualify.sh")
CASES = [
    "tests::build_probe_never_invents_an_unset_identity",
    "tests::packaged_example_decodes_with_the_owner_schema",
    "tests::service_local_custody_and_withdrawal_bounds_fail_closed",
]


class QualificationMetadataTests(unittest.TestCase):
    def produce(self, focused, focused_exit=0, order=None, filesystem_output=None):
        # Exercise the embedded producer itself, without running Cargo or an ELF.
        program = HELPER.read_text().split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            run = out / "run"
            run.mkdir()
            names = order or ["release", "freeze", "fmt", "clippy", "focused", "workspace", "filesystem-cli"]
            fs_cases = ["cli_missing_current_replay_contradiction_and_new_basis_use_real_files", "cli_source_expiry_and_previous_boot_do_not_become_current", "cli_bad_signature_and_equal_acquisition_are_refused", "same_declared_semantics_wrong_runtime_realization_cannot_establish_current", "cli_exact_negative_context_is_unknown_without_receipt_or_acquisition"]
            fs_output = "".join(f"test {case} ... ok\n" for case in fs_cases) + "test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
            if filesystem_output is not None: fs_output = filesystem_output
            for number, name in enumerate(names, 1):
                stem = run / f"{number}-{name}"
                Path(str(stem) + ".argv.json").write_text(json.dumps(["cargo", name]))
                Path(str(stem) + ".stdout").write_text(focused if name == "focused" else fs_output if name == "filesystem-cli" else "")
                Path(str(stem) + ".stderr").write_text("")
                Path(str(stem) + ".exit").write_text(str(focused_exit if name == "focused" else 0))
            result = subprocess.run([sys.executable, "-", str(run), str(out), "a" * 40],
                                    input=program, text=True, capture_output=True)
            corpus = out / "hostile-corpus.json"
            return result, json.loads(corpus.read_text()) if corpus.exists() else None

    def passing_output(self):
        return "\n".join(f"test {case} ... ok" for case in CASES) + "\n"

    def test_exact_passed_case_names_are_emitted(self):
        result, corpus = self.produce(self.passing_output())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(corpus["hostile_scenarios"], CASES)

    def test_filesystem_missing_ignored_duplicate_or_zero_count_refuses(self):
        cases = ["cli_missing_current_replay_contradiction_and_new_basis_use_real_files", "cli_source_expiry_and_previous_boot_do_not_become_current", "cli_bad_signature_and_equal_acquisition_are_refused", "same_declared_semantics_wrong_runtime_realization_cannot_establish_current", "cli_exact_negative_context_is_unknown_without_receipt_or_acquisition"]
        output = "".join(f"test {case} ... ok\n" for case in cases) + "test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
        bad = [output.replace(f"test {cases[0]} ... ok\n", ""), output.replace(f"{cases[0]} ... ok", f"{cases[0]} ... ignored"), output + f"test {cases[0]} ... ok\n", output.replace("5 passed", "0 passed")]
        for stream in bad:
            result, corpus = self.produce(self.passing_output(), filesystem_output=stream)
            self.assertNotEqual(result.returncode,0)
            self.assertIsNone(corpus)

    def test_reordered_focused_record_keeps_exact_case_evidence(self):
        result, corpus = self.produce(self.passing_output(), order=["focused", "release", "freeze", "fmt", "clippy", "filesystem-cli", "workspace"])
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(corpus["hostile_scenarios"],CASES)

    def test_each_missing_case_refuses(self):
        for case in CASES:
            with self.subTest(case=case):
                result, corpus = self.produce(self.passing_output().replace(f"test {case} ... ok\n", ""))
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(corpus)

    def test_old_wrong_case_prefix_refuses(self):
        result, corpus = self.produce(self.passing_output().replace("test tests::", "test executed::tests::"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(corpus)

    def test_ignored_or_failed_case_refuses(self):
        for status in ["ignored", "ignored, requires a fixture", "FAILED"]:
            with self.subTest(status=status):
                result, corpus = self.produce(self.passing_output().replace(f"{CASES[0]} ... ok", f"{CASES[0]} ... {status}"))
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(corpus)

    def test_duplicate_case_refuses_even_if_both_passed(self):
        for status in ["ok", "ignored"]:
            with self.subTest(status=status):
                result, corpus = self.produce(self.passing_output() + f"test {CASES[0]} ... {status}\n")
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(corpus)

    def test_nonzero_focused_exit_refuses(self):
        result, corpus = self.produce(self.passing_output(), focused_exit=101)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(corpus)



# Bounded stand-ins exercise the actual owning shell/identity/packager consumers.
# No Rust compiler, Cargo implementation, native ELF or VM is run by this suite.
class FrozenCohortPipelineTests(unittest.TestCase):
    def setUp(self):
        import shutil
        import os
        import test_build_identity as fixtures
        self.fixture = fixtures.PackageIdentityTests('test_records_exact_staged_bytes_and_complete_cohort')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.prod = self.root / 'production-target'
        self.release = self.prod / 'release'
        self.release.mkdir(parents=True)
        self.names = ('constellation-host-posture', *self.fixture.info.keys())
        self.names = tuple(dict.fromkeys(self.names))
        for name in self.names:
            shutil.copyfile(self.root/name, self.release/name)
            (self.release/name).chmod(0o755)
        self.tools = self.root/'stand-in-tools'
        self.tools.mkdir()
        cargo = self.tools/'cargo'
        cargo.write_text('''#!/usr/bin/env python3
import json,os,pathlib,sys
args=sys.argv[1:];r=pathlib.Path(os.environ['FIXTURE_ROOT']);prod=r/'production-target';release=prod/'release'
with (r/'calls.jsonl').open('a') as f:f.write(json.dumps({'argv':args,'target':os.environ.get('CARGO_TARGET_DIR'),'selected_fs':os.environ.get('PULSE_FS_TEST_BINARY')})+'\\n')
names=['constellation-host-posture','constellation-status','pulse-nq-load-support','pulse-nq-filesystem-support']
if args[0]=='build':
 if (r/'fs-tested').exists():
  p=release/'pulse-nq-filesystem-support';p.write_bytes(p.read_bytes()+b'# late shared production writer\\n')
 for name in names:print(json.dumps({'reason':'compiler-artifact','package_id':'path+file:///fixture#'+name+'@0.1.0','target':{'name':name,'kind':['bin']},'profile':{'opt_level':'3','debug_assertions':False,'test':False},'features':[],'filenames':[str(release/name)],'executable':str(release/name)}))
 print(json.dumps({'reason':'build-finished','success':True}))
elif args[0]=='test':
 if 'cli_custody' in args:
  (r/'fs-tested').touch()
  cases=['cli_missing_current_replay_contradiction_and_new_basis_use_real_files','cli_source_expiry_and_previous_boot_do_not_become_current','cli_bad_signature_and_equal_acquisition_are_refused','same_declared_semantics_wrong_runtime_realization_cannot_establish_current', 'cli_exact_negative_context_is_unknown_without_receipt_or_acquisition']
  mutation=os.environ.get('MUTATE_FROZEN')
  if mutation:
   p=pathlib.Path(os.environ['PULSE_FS_TEST_BINARY']).parent/mutation;p.chmod(0o755);p.write_bytes(p.read_bytes()+b'# selected member substitution\\n')
  if os.environ.get('MUTATE_TEST_OUTPUT'):
   p=pathlib.Path(os.environ['CARGO_TARGET_DIR'])/'release'/'pulse-nq-filesystem-support';p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'unrelated mutable test output')
 elif 'constellation-host-posture' in args:cases=['tests::build_probe_never_invents_an_unset_identity','tests::packaged_example_decodes_with_the_owner_schema','tests::service_local_custody_and_withdrawal_bounds_fail_closed']
 else:cases=['fixture::workspace']
 for case in cases:print('test '+case+' ... ok')
 print('test result: ok. '+str(len(cases))+' passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s')
''')
        cargo.chmod(0o755)
        rustc = self.tools/'rustc'
        rustc.write_text('#!/bin/sh\nif [ "$1" = "-vV" ]; then printf "%s\\n" "rustc 1.95.0 (fixture)" "host: x86_64-unknown-linux-gnu"; else printf "%s\\n" "rustc 1.95.0 (fixture)"; fi\n')
        rustc.chmod(0o755)
        self.env = dict(os.environ, FIXTURE_ROOT=str(self.root), CARGO_TARGET_DIR=str(self.prod), PATH=str(self.tools)+os.pathsep+os.environ['PATH'])
        self.out = self.root/'qualification'

    def run_pipeline(self, **extra):
        for name in ['fs-tested','calls.jsonl']:
            (self.root/name).unlink(missing_ok=True)
        return subprocess.run(['bash', str(HELPER), str(self.root), str(self.release/'constellation-host-posture'), str(self.out), self.fixture.info['constellation-host-posture']['source_commit']], env=dict(self.env, **extra), text=True, capture_output=True)

    def calls(self):
        return [json.loads(line) for line in (self.root/'calls.jsonl').read_text().splitlines()]

    def test_final_production_build_precedes_tests_and_no_later_shared_writer(self):
        import hashlib
        hp_before=hashlib.sha256((self.release/'constellation-host-posture').read_bytes()).hexdigest()
        fs_before=hashlib.sha256((self.release/'pulse-nq-filesystem-support').read_bytes()).hexdigest()
        result=self.run_pipeline()
        self.assertEqual(result.returncode,0,result.stderr)
        frozen=json.loads((self.out/'frozen-cohort.json').read_text())
        self.assertIn('production_dependency_inventory',frozen['executables']['pulse-nq-filesystem-support'],'selected FS freeze lacks its own actual production Cargo inventory')
        self.assertEqual(hashlib.sha256((self.release/'constellation-host-posture').read_bytes()).hexdigest(),hp_before)
        calls=self.calls();build=[i for i,x in enumerate(calls) if x['argv'][0]=='build'];tests=[i for i,x in enumerate(calls) if x['argv'][0]=='test']
        self.assertEqual(len(build),1)
        self.assertLess(build[0],min(tests),'old qualifier accepts an FS-only late production replacement while HP stays unchanged')
        self.assertEqual(hashlib.sha256((self.release/'pulse-nq-filesystem-support').read_bytes()).hexdigest(),fs_before)

    def test_five_missing_hp_declarations_refuse_before_any_cargo(self):
        variables=['CONSTELLATION_HOST_POSTURE_SOURCE_REPOSITORY','CONSTELLATION_HOST_POSTURE_SOURCE_COMMIT','CONSTELLATION_HOST_POSTURE_TARGET_TRIPLE','CONSTELLATION_HOST_POSTURE_BUILD_PROFILE','CONSTELLATION_HOST_POSTURE_ENABLED_FEATURES_JSON']
        for number,variable in enumerate(variables):
            with self.subTest(variable=variable):
                self.out=self.root/('omitted-'+str(number))
                result=self.run_pipeline(**{variable:''})
                self.assertNotEqual(result.returncode,0,'missing HP declaration reached compiler/qualification')
                self.assertFalse((self.root/'calls.jsonl').exists(),'readiness guard ran after Cargo')

    def test_verified_production_reuse_runs_no_cargo_build_and_preserves_origins(self):
        result=self.run_pipeline()
        self.assertEqual(result.returncode,0,result.stderr)
        original=self.out/'frozen-cohort.json'
        self.out=self.root/'continuation'
        result=self.run_pipeline(QUAL_REUSE_FROZEN_COHORT=str(original))
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse(any(row['argv'][0]=='build' for row in self.calls()),'continuation rebuilt selected production bytes')
        receipt=json.loads((self.out/'frozen-cohort.json').read_text())
        self.assertEqual(receipt['selection_inherited_from']['path'],str(original))
        results=json.loads((self.out/'results.json').read_text())
        self.assertFalse(any(row['argv'][:2]==['cargo','build'] for row in results['command_results']))
        self.assertTrue((self.out/'production-input/production.stdout').is_file())
        for name,row in receipt['production_inputs'].items():
            import hashlib
            self.assertEqual(hashlib.sha256((self.out/row['packaged_path']).read_bytes()).hexdigest(),row['sha256'])

    def test_changed_inherited_production_stream_refuses_before_any_cargo(self):
        result=self.run_pipeline()
        self.assertEqual(result.returncode,0,result.stderr)
        original=self.out/'frozen-cohort.json'
        receipt=json.loads(original.read_text())
        raw=Path(receipt['production_inputs']['stdout']['path'])
        raw.write_bytes(raw.read_bytes()+b'{}\n')
        self.out=self.root/'changed-continuation'
        result=self.run_pipeline(QUAL_REUSE_FROZEN_COHORT=str(original))
        self.assertNotEqual(result.returncode,0)
        self.assertFalse((self.root/'calls.jsonl').exists(),'changed inherited production evidence reached Cargo')

    def test_existing_qualification_output_refuses_before_new_production_writer(self):
        import hashlib
        result=self.run_pipeline()
        self.assertEqual(result.returncode,0,result.stderr)
        before=hashlib.sha256((self.out/'frozen-cohort.json').read_bytes()).hexdigest()
        retry=self.run_pipeline()
        self.assertNotEqual(retry.returncode,0)
        self.assertIn('original-producer reconciliation',retry.stderr)
        self.assertFalse((self.root/'calls.jsonl').exists())
        self.assertEqual(hashlib.sha256((self.out/'frozen-cohort.json').read_bytes()).hexdigest(),before)

    def test_every_selected_member_substitution_refuses_even_when_other_members_stay(self):
        # One fresh output per subtest; no qualification occurrence is overwritten.
        for name in self.names:
            with self.subTest(name=name):
                previous=self.out;self.out=self.root/('refusal-'+name)
                result=self.run_pipeline(MUTATE_FROZEN=name)
                self.assertNotEqual(result.returncode,0)
                errors=''.join(p.read_text() for p in (self.out/'run').glob('*.stderr'))
                self.assertIn('selected frozen executable changed',errors)
                self.assertIn(name,errors)
                import hashlib
                frozen=json.loads((self.out/'frozen-cohort.json').read_text())
                for member,expected in frozen['executables'].items():
                    actual=hashlib.sha256((self.out/'frozen-bin'/member).read_bytes()).hexdigest()
                    if member==name:self.assertNotEqual(actual,expected['sha256'])
                    else:self.assertEqual(actual,expected['sha256'])
                self.out=previous

    def test_substituted_packaged_production_data_refuses(self):
        result=self.run_pipeline()
        self.assertEqual(result.returncode,0,result.stderr)
        raw=self.out/'production-input/production.stdout'
        raw.write_bytes(raw.read_bytes()+b'{}\n')
        package_out=self.root/'substituted-evidence-package'
        package=subprocess.run(['bash',str(HELPER.with_name('build-deb.sh')),'0.1.0+test.1','amd64',str(self.out/'frozen-bin'),str(package_out)],env=dict(self.env,QUAL_INPUT_DIR=str(self.out)),capture_output=True,text=True)
        self.assertNotEqual(package.returncode,0)
        self.assertIn('staged actual production input changed',package.stderr)
        self.assertFalse(list(package_out.glob('*.deb')))

    def test_mutable_test_outputs_do_not_change_frozen_selected_package_bytes(self):
        import hashlib,os
        result=self.run_pipeline(MUTATE_TEST_OUTPUT='1')
        self.assertEqual(result.returncode,0,result.stderr)
        receipt=json.loads((self.out/'frozen-cohort.json').read_text())
        frozen=self.out/'frozen-bin'
        self.assertFalse(frozen.is_relative_to(self.prod))
        for call in self.calls():
            if call['argv'][0] != 'build':self.assertEqual(call['target'],str(self.out/'test-target'))
            if 'cli_custody' in call['argv']:self.assertEqual(call['selected_fs'],str(frozen/'pulse-nq-filesystem-support'))
        package_out=self.root/'packages'
        package=subprocess.run(['bash',str(HELPER.with_name('build-deb.sh')),'0.1.0+test.1','amd64',str(frozen),str(package_out)],env=dict(self.env,QUAL_INPUT_DIR=str(self.out)),capture_output=True,text=True)
        self.assertEqual(package.returncode,0,package.stderr)
        sidecar=json.loads((package_out/'constellation-host-posture_0.1.0+test.1_amd64.build-identity.json').read_text())
        for name,item in receipt['executables'].items():self.assertEqual(sidecar['executables'][name]['sha256'],item['sha256'])
        wrong=subprocess.run(['bash',str(HELPER.with_name('build-deb.sh')),'0.1.0+test.1','amd64',str(self.release),str(self.root/'wrong-package')],env=dict(self.env,QUAL_INPUT_DIR=str(self.out)),capture_output=True,text=True)
        self.assertNotEqual(wrong.returncode,0)
        self.assertFalse(list((self.root/'wrong-package').glob('*.deb')))


if __name__ == "__main__":
    unittest.main()
