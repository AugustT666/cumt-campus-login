"""Public test selection and delivery-scope evidence use only temporary fixtures."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from research import verification_context as verification
from research import run_offline_tests as runner


class PublicVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cumt-public-evidence-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in verification.RUNTIME_SOURCES | {'research/verification_context.py', 'test_fixture.py'}:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('synthetic verification input\n', encoding='utf-8')
        (self.root / 'test_protocol_hardening.py').write_text(
            'class CapturedPortalHardeningTests:\n'
            '    def test_first(self): pass\n'
            '    def test_second(self): pass\n', encoding='utf-8')

    def context(self, kind='unit', scope=verification.PUBLIC_SCOPE):
        return verification.finish_verification(
            verification.begin_verification(kind, self.root, unit_scope=scope), self.root)

    def report(self, scope=verification.PUBLIC_SCOPE):
        captured = verification.captured_test_ids(self.root)
        local = scope == verification.CAPTURE_SCOPE
        return {'success':True, 'test_scope':scope, 'run':3 if local else 1,
                'discovered_tests':3, 'skipped':0,
                'excluded_test_ids':[] if local else captured,
                'excluded_test_count':0 if local else len(captured),
                'local_capture_tests_executed':local,
                'local_capture_test_count':len(captured) if local else 0,
                'verification':self.context(scope=scope)}

    def captures(self):
        for name in verification.TEST_INPUTS:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('synthetic local-only capture\n', encoding='utf-8')

    def test_retired_probes_notes_and_report_outputs_do_not_change_identity(self):
        before = verification.capture_source(self.root)
        for name in ('research/retired_probe.py','research/session.json',
                     'docs/private-notes.md','assets/retired-prompts.json'):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('untracked local archive\n', encoding='utf-8')
        self.assertEqual(before, verification.capture_source(self.root))

    def test_maintained_script_changes_do_change_identity(self):
        before = verification.capture_source(self.root)
        path = self.root / 'research/verification_context.py'
        path.write_text('changed maintained script', encoding='utf-8')
        self.assertNotEqual(before, verification.capture_source(self.root))

    def test_added_discovered_test_is_bound_to_source_identity(self):
        before = verification.capture_source(self.root)
        (self.root / 'test_new.py').write_text('new regression\n', encoding='utf-8')
        self.assertNotEqual(before, verification.capture_source(self.root))

    def test_public_identity_does_not_read_or_require_local_captures(self):
        before = verification.capture_source(self.root)
        self.captures()
        self.assertEqual(before, verification.capture_source(self.root))
        self.assertFalse(set(verification.TEST_INPUTS) & set(before['files']))

    def test_public_scope_lists_exact_exclusions_and_claims_no_capture_execution(self):
        report = self.report()
        verification.validate_unit_scope(report, self.root)
        self.assertEqual(report['excluded_test_count'],2)
        self.assertFalse(report['local_capture_tests_executed'])

    def test_arbitrary_omitted_test_cannot_be_called_a_capture_exclusion(self):
        report = self.report()
        report['excluded_test_ids'][0] = 'test_other.Case.test_security'
        with self.assertRaisesRegex(ValueError,'coverage exclusions'):
            verification.validate_unit_scope(report, self.root)

    def test_scope_is_bound_to_verification_command(self):
        report = self.report()
        report['verification']['unit_scope'] = verification.CAPTURE_SCOPE
        with self.assertRaisesRegex(ValueError,'scope is not bound'):
            verification.validate_unit_scope(report, self.root)

    def test_coverage_count_tampering_is_rejected(self):
        report = self.report()
        report['discovered_tests'] += 1
        with self.assertRaisesRegex(ValueError,'coverage counts'):
            verification.validate_unit_scope(report,self.root)

    def test_capture_mode_fails_when_any_required_file_is_missing(self):
        with self.assertRaisesRegex(ValueError,'requires all six'):
            verification.begin_verification('unit',self.root,unit_scope=verification.CAPTURE_SCOPE)
        self.captures()
        next(iter(self.root / name for name in verification.TEST_INPUTS)).unlink()
        with self.assertRaisesRegex(ValueError,'requires all six'):
            verification.local_capture_inputs(self.root)

    def test_capture_scope_records_all_input_hashes_and_rejects_changes(self):
        self.captures()
        report = self.report(verification.CAPTURE_SCOPE)
        verification.validate_unit_scope(report,self.root)
        context = report['verification']
        self.assertEqual(len(context['local_capture_start']),6)
        self.assertEqual(context['command'][-1],'--with-local-captures')
        (self.root / sorted(verification.TEST_INPUTS)[0]).write_text('changed',encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'changed since qualification'):
            verification.validate_unit_scope(report,self.root)

    def test_capture_change_during_run_prevents_stable_evidence(self):
        self.captures()
        start = verification.begin_verification('unit',self.root,unit_scope=verification.CAPTURE_SCOPE)
        (self.root / sorted(verification.TEST_INPUTS)[0]).write_text('changed',encoding='utf-8')
        self.assertFalse(verification.finish_verification(start,self.root)['source_stable'])

    def test_skipped_tests_still_fail_delivery_gate(self):
        for kind,name in verification.REPORT_FILES.items():
            path = self.root/name
            path.parent.mkdir(parents=True,exist_ok=True)
            report = self.report() if kind=='unit' else {'success':True,'verification':self.context(kind)}
            if kind=='unit':report['skipped']=1
            path.write_text(json.dumps(report),encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'Skipped unit tests'):
            verification.validate_test_reports(self.root,verification.capture_source(self.root))

    def test_selector_excludes_only_declared_capture_ids_in_public_mode(self):
        expected = verification.captured_test_ids(runner.ROOT)
        class NamedCase(unittest.TestCase):
            def __init__(self,name):
                super().__init__('runTest')
                self.name=name
            def id(self):return self.name
            def runTest(self):pass
        full=unittest.TestSuite(NamedCase(name) for name in expected+['test_other.Case.test_public'])
        chosen,total,excluded,captured=runner.select_suite(full)
        self.assertEqual(total,len(expected)+1)
        self.assertEqual(chosen.countTestCases(),1)
        self.assertEqual(excluded,expected)
        self.assertEqual(captured,len(expected))
        full=unittest.TestSuite(NamedCase(name) for name in expected+['test_other.Case.test_public'])
        chosen,total,excluded,captured=runner.select_suite(full,True)
        self.assertEqual(chosen.countTestCases(),len(expected)+1)
        self.assertEqual(excluded,[])


if __name__=='__main__':
    unittest.main()
