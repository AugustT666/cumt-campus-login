"""Delivery evidence tests use synthetic projects, never the user's store/EXE."""
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from research import package_current as package
from research import verification_context as verification
from research import slim_distribution as slim
from research.build_and_verify import run_smoke_process


class DeliveryHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cumt-evidence-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in verification.RUNTIME_SOURCES | verification.TEST_INPUTS | {"test_fixture.py", "research/verification_context.py"}:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("synthetic source\n", encoding="utf-8")
        (self.root / "campus_core.py").write_text("VERSION = '9.8.7'\n", encoding="utf-8")
        self.version = "9.8.7"
        self.write_reports()
        self.write_build()

    def evidence(self, kind):
        return verification.finish_verification(verification.begin_verification(kind, self.root), self.root)

    def write_reports(self):
        for kind, name in verification.REPORT_FILES.items():
            report = {"version": self.version, "success": True, "verification": self.evidence(kind)}
            if kind == "unit":
                report.update(run=1, failures=0, errors=0, skipped=0, real_credentials_read=False,
                              test_scope=verification.PUBLIC_SCOPE, discovered_tests=1,
                              excluded_test_count=0, excluded_test_ids=[],
                              local_capture_test_count=0, local_capture_tests_executed=False)
            (self.root / name).write_text(json.dumps(report), encoding="utf-8")

    def write_build(self):
        exe = self.root / f".local/dist/矿大校园网登录器_v{self.version}.exe"
        exe.parent.mkdir(parents=True, exist_ok=True)
        exe.write_bytes(b"synthetic executable; never run")
        smoke = {name: True for name in ("success", "runtime_log_ready", "diagnostic_zip_verified",
                 "window_restore_verified", "online_identity_display", "ui_logo_loaded")}
        smoke.update(version=self.version, native_icon={"verified": True})
        smoke['webview2_compatibility'] = {
            'engine': 'webview2', 'success': True,
            'request_interception_verified': True, 'single_submission_verified': True,
            'duplicate_attempt_blocked': True,
            'trusted_input_verified': True, 'frame_transport_verified': True,
            'desktop_viewport_verified': True,
            'campus_requests': 0, 'network_changes': False,
        }
        self.inventory = {
            'size_bytes': exe.stat().st_size,
            'files': sorted(slim.REQUIRED_FILES | {'pywebview-6.2.1.dist-info/licenses/LICENSE'}),
            'python_modules': sorted(slim.REQUIRED_MODULES),
            'compressed_groups': {},
        }
        self.manifest = {
            "version": self.version, "source_stable_during_build": True,
            "unit_test_coverage": verification.unit_test_coverage(
                json.loads((self.root / verification.REPORT_FILES["unit"]).read_text("utf-8"))),
            "packaged_smoke": smoke, "brand_assets_bundled": True,
            "embedded_icon_verified": True, "windows_versions_verified": True,
            "verification": self.evidence("build"),
            "test_evidence_sha256": {name: verification.file_sha256(self.root / name)
                                     for name in verification.REPORT_FILES.values()},
            "source_sha256_before_and_after_build": {
                name: verification.file_sha256(self.root / name)
                for name in verification.runtime_source_names(self.root)},
            "size_bytes": exe.stat().st_size, "sha256": verification.file_sha256(exe),
            'package_inventory': copy.deepcopy(self.inventory),
            'distribution_verification': slim.verify_inventory(
                self.inventory, smoke['webview2_compatibility']),
        }
        self.save_manifest()

    def save_manifest(self):
        name = f"research/build_manifest_v{self.version.replace('.', '_')}.json"
        (self.root / name).write_text(json.dumps(self.manifest), encoding="utf-8")

    def validate(self):
        with patch.object(package, "ROOT", self.root), \
                patch.object(package, 'inspect_archive', return_value=copy.deepcopy(self.inventory)):
            return package.validate(self.version)

    def test_build_manifest_cannot_misstate_public_coverage(self):
        self.manifest['unit_test_coverage']['test_scope'] = verification.CAPTURE_SCOPE
        self.save_manifest()
        with self.assertRaisesRegex(ValueError, 'coverage scope differs'):
            self.validate()

    def test_unit_report_without_explicit_scope_cannot_qualify(self):
        path = self.root / verification.REPORT_FILES['unit']
        report = json.loads(path.read_text('utf-8'))
        del report['test_scope']
        path.write_text(json.dumps(report), encoding='utf-8')
        self.write_build()
        with self.assertRaisesRegex(ValueError, 'coverage scope'):
            self.validate()

    def test_matching_sources_tests_and_build_are_accepted_without_personal_paths(self):
        manifest, reports, _ = self.validate()
        self.assertEqual(reports["unit"]["run"], 1)
        self.assertNotIn(str(self.root), json.dumps(manifest))
        files = manifest["verification"]["source_end"]["files"]
        for name in ("campus_ui.html", "assets/icon.ico", "test_fixture.py", "research/verification_context.py",
                     'build_support/hooks/hook-webview.py', 'campus_webview2.py'):
            self.assertIn(name, files)

    def test_same_version_product_change_and_new_build_cannot_reuse_old_reports(self):
        with (self.root / "campus_ui.html").open("a") as stream:
            stream.write("changed after tests\n")
        self.write_build()
        with self.assertRaisesRegex(ValueError, "changed since unit verification"):
            self.validate()

    def test_test_content_change_and_new_build_cannot_reuse_old_reports(self):
        (self.root / "test_fixture.py").write_text("new test expectations\n")
        self.write_build()
        with self.assertRaisesRegex(ValueError, "changed since unit verification"):
            self.validate()

    def test_new_test_file_invalidates_prior_evidence(self):
        (self.root / "test_added.py").write_text("new safety regression\n")
        with self.assertRaisesRegex(ValueError, "changed since build verification"):
            self.validate()

    def test_changed_runtime_resource_is_part_of_the_source_identity(self):
        (self.root / "assets/logo.png").write_text("changed bundled resource\n")
        with self.assertRaisesRegex(ValueError, "changed since build verification"):
            self.validate()

    def test_missing_context_and_unfinished_run_are_rejected(self):
        original = copy.deepcopy(self.manifest)
        for context in (None, verification.begin_verification("build", self.root)):
            with self.subTest(context=context is None):
                self.manifest = copy.deepcopy(original)
                self.manifest["verification"] = context
                self.save_manifest()
                with self.assertRaises(ValueError):
                    self.validate()

    def test_sources_changing_during_test_cannot_claim_stability(self):
        start = verification.begin_verification("unit", self.root)
        (self.root / "test_fixture.py").write_text("changed during a running test\n")
        evidence = verification.finish_verification(start, self.root)
        self.assertFalse(evidence["source_stable"])
        evidence["source_stable"] = True
        with self.assertRaisesRegex(ValueError, "changed during unit"):
            verification.validate_verification(evidence, verification.capture_source(self.root), "unit")

    def test_report_content_is_bound_to_build_even_if_source_is_unchanged(self):
        path = self.root / verification.REPORT_FILES["unit"]
        report = json.loads(path.read_text("utf-8"))
        report["run"] = 2
        report["discovered_tests"] = 2
        path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "reports changed after build"):
            self.validate()

    def test_legacy_success_report_without_fingerprint_is_rejected(self):
        path = self.root / verification.REPORT_FILES["unit"]
        report = json.loads(path.read_text("utf-8"))
        del report["verification"]
        path.write_text(json.dumps(report), encoding="utf-8")
        self.write_build()
        with self.assertRaisesRegex(ValueError, "Missing unit verification"):
            self.validate()

    def test_excluded_local_capture_changes_do_not_change_public_source_identity(self):
        before = verification.capture_source(self.root)
        path = self.root / sorted(verification.TEST_INPUTS)[0]
        path.write_text('changed excluded local capture', encoding='utf-8')
        self.assertEqual(before, verification.capture_source(self.root))
        path.unlink()
        self.assertEqual(before, verification.capture_source(self.root))

    def test_skipped_portal_regressions_cannot_be_delivered_as_full_success(self):
        path=self.root/verification.REPORT_FILES['unit']
        report=json.loads(path.read_text('utf-8'))
        report['skipped']=1
        path.write_text(json.dumps(report),encoding='utf-8')
        self.write_build()
        with self.assertRaisesRegex(ValueError,'Skipped unit tests'):
            self.validate()

    def test_small_archive_with_node_playwright_or_build_modules_is_rejected(self):
        smoke = self.manifest['packaged_smoke']['webview2_compatibility']
        for file, module in (
                ('playwright/driver/node.exe', None),
                ('unexpected/NODE.EXE', None),
                ('playwright-1.64.0.dist-info/METADATA', None),
                (None, 'playwright.sync_api'), (None, 'PyInstaller.archive.readers'),
                (None, 'setuptools'), (None, 'test_auth_regressions')):
            with self.subTest(file=file, module=module):
                inventory = copy.deepcopy(self.inventory)
                if file:
                    inventory['files'].append(file)
                if module:
                    inventory['python_modules'].append(module)
                with self.assertRaisesRegex(ValueError, 'Forbidden'):
                    slim.verify_inventory(inventory, smoke)

    def test_small_file_is_not_enough_without_actual_webview2_backend_check(self):
        original = self.manifest['packaged_smoke']['webview2_compatibility']
        for field, value in (('success', False), ('engine', 'mock'),
                             ('request_interception_verified', False),
                             ('single_submission_verified', False),
                             ('duplicate_attempt_blocked', False),
                             ('trusted_input_verified', False),
                             ('frame_transport_verified', False),
                             ('desktop_viewport_verified', False),
                             ('campus_requests', 1), ('network_changes', True)):
            with self.subTest(field=field):
                bad = dict(original, **{field: value})
                with self.assertRaises(ValueError):
                    slim.verify_inventory(self.inventory, bad)
        incomplete = dict(original)
        del incomplete['duplicate_attempt_blocked']
        with self.assertRaisesRegex(ValueError, 'duplicate_attempt_blocked'):
            slim.verify_inventory(self.inventory, incomplete)
        missing = copy.deepcopy(self.inventory)
        missing['python_modules'].remove('campus_webview2')
        with self.assertRaisesRegex(ValueError, 'omits required'):
            slim.verify_inventory(missing, original)

    def test_manifest_inventory_cannot_replace_facts_read_from_the_executable(self):
        self.inventory['files'].append('playwright/driver/node.exe')
        with self.assertRaisesRegex(ValueError, 'inventory changed'):
            self.validate()

    def test_oversize_file_cannot_claim_the_15_mb_target_by_metadata_alone(self):
        exe = self.root / f'.local/dist/矿大校园网登录器_v{self.version}.exe'
        with exe.open('wb') as stream:
            stream.truncate(slim.MAX_DISTRIBUTION_BYTES + 1)
        self.manifest['size_bytes'] = exe.stat().st_size
        self.manifest['sha256'] = verification.file_sha256(exe)
        self.inventory['size_bytes'] = exe.stat().st_size
        self.manifest['package_inventory'] = copy.deepcopy(self.inventory)
        self.save_manifest()
        with self.assertRaisesRegex(ValueError, '15 MB size target'):
            self.validate()

    def test_every_loader_probed_by_webview_import_is_required(self):
        smoke = self.manifest['packaged_smoke']['webview2_compatibility']
        for architecture in ('win-x64', 'win-x86', 'win-arm64'):
            with self.subTest(architecture=architecture):
                incomplete = copy.deepcopy(self.inventory)
                incomplete['files'].remove(
                    f'webview/lib/runtimes/{architecture}/native/WebView2Loader.dll')
                with self.assertRaisesRegex(ValueError, 'omits required'):
                    slim.verify_inventory(incomplete, smoke)

    def test_packaged_timeout_ends_owned_child_tree_and_preserves_original_error(self):
        console = self.root / 'portable-console.log'
        child = "import time; time.sleep(60)"
        parent = ('import subprocess,sys,time; '
                  f'p=subprocess.Popen([sys.executable,"-c",{child!r}]); '
                  'print("OWNED_CHILD="+str(p.pid),flush=True); time.sleep(60)')
        with self.assertRaises(subprocess.TimeoutExpired):
            run_smoke_process([sys.executable, '-c', parent], self.root,
                              dict(os.environ), console, timeout=1.5)
        failure = json.loads(console.with_suffix('.failure.json').read_text('utf-8'))
        self.assertEqual(failure['error_type'], 'TimeoutExpired')
        self.assertIn('TimeoutExpired', failure['traceback'])
        match = re.search(r'OWNED_CHILD=(\d+)', console.read_text('utf-8'))
        self.assertIsNotNone(match, 'The child-tree canary must have started')
        if os.name == 'nt':
            import ctypes
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
            kernel.OpenProcess.restype = ctypes.c_void_p
            kernel.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
            kernel.CloseHandle.argtypes = [ctypes.c_void_p]
            handle = kernel.OpenProcess(0x1000, False, int(match.group(1)))
            if handle:
                try:
                    code = ctypes.c_ulong()
                    self.assertTrue(kernel.GetExitCodeProcess(handle, ctypes.byref(code)))
                    self.assertNotEqual(code.value, 259, 'Owned child survived timeout cleanup')
                finally:
                    kernel.CloseHandle(handle)
            self.assertTrue(any(item.get('tree_exit_code') == 0
                                for item in failure['termination']))


if __name__ == "__main__":
    unittest.main()
