"""Delivery evidence tests use synthetic projects, never the user's store/EXE."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from research import package_current as package
from research import verification_context as verification


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
        }
        self.save_manifest()

    def save_manifest(self):
        name = f"research/build_manifest_v{self.version.replace('.', '_')}.json"
        (self.root / name).write_text(json.dumps(self.manifest), encoding="utf-8")

    def validate(self):
        with patch.object(package, "ROOT", self.root):
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
        for name in ("campus_ui.html", "assets/icon.ico", "test_fixture.py", "research/verification_context.py"):
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


if __name__ == "__main__":
    unittest.main()
