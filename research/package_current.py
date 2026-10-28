"""Validate the current build, update the stable EXE, optionally archive Git sources.

This script never reads the user's store or performs a network request. All
outputs stay inside the project; an archive is created only with --archive.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import zipfile

if __package__:
    from .verification_context import (RUNTIME_SOURCES, capture_source, runtime_source_names,
                                       validate_test_reports, validate_verification, unit_test_coverage)
else:
    from verification_context import (RUNTIME_SOURCES, capture_source, runtime_source_names,
                                      validate_test_reports, validate_verification, unit_test_coverage)

ROOT = Path(__file__).resolve().parent.parent


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def project_file(name: str) -> Path:
    relative = Path(name)
    require(not relative.is_absolute() and ".." not in relative.parts,
            f"Project-relative path required: {name}")
    path = (ROOT / relative).resolve()
    require(path.is_relative_to(ROOT.resolve()), f"Path leaves project: {name}")
    require(path.is_file(), f"Missing file: {name}")
    return path


def read_json(name: str) -> dict:
    return json.loads(project_file(name).read_text(encoding="utf-8"))


def current_version() -> str:
    # Read the literal without importing application code or opening its store.
    tree = ast.parse(project_file("campus_core.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == "VERSION"
                for target in node.targets):
            version = ast.literal_eval(node.value)
            require(isinstance(version, str) and all(part.isdigit() for part in version.split(".")),
                    "Invalid application version")
            return version
    raise ValueError("Missing application VERSION")


def validate(version: str) -> tuple[dict, dict, Path]:
    manifest_name = f"research/build_manifest_v{version.replace('.', '_')}.json"
    manifest = read_json(manifest_name)
    require(manifest.get("version") == version, "Build manifest version mismatch")
    require(manifest.get("source_stable_during_build") is True,
            "Build source stability was not verified")
    current = capture_source(ROOT)
    validate_verification(manifest.get("verification"), current, "build")
    smoke = manifest.get("packaged_smoke", {})
    require(smoke.get("version") == version and smoke.get("success") is True,
            "Current packaged smoke test did not pass")
    require(smoke.get("runtime_log_ready") is True and smoke.get("diagnostic_zip_verified") is True,
            "Packaged runtime logging and diagnostic ZIP were not verified")
    require(smoke.get("window_restore_verified") is True and smoke.get("online_identity_display") is True,
            "Packaged window restoration and server identity display were not verified")
    require(smoke.get("ui_logo_loaded") is True and smoke.get("native_icon", {}).get("verified") is True,
            "Packaged UI and native window icons were not verified")
    require(all(manifest.get(key) is True for key in ("brand_assets_bundled", "embedded_icon_verified", "windows_versions_verified")),
            "Embedded branding and Windows version resources were not verified")

    reports, report_hashes = validate_test_reports(ROOT, current)
    require(manifest.get("test_evidence_sha256") == report_hashes,
            "Test reports changed after build or were not bound to this build")
    require(manifest.get('unit_test_coverage') == unit_test_coverage(reports['unit']),
            'Build manifest unit test coverage scope differs from the reports')
    for label, report in reports.items():
        require(report.get("version") == version and report.get("success") is True,
                f"Current {label} test did not pass")
    unit = reports["unit"]
    require(isinstance(unit.get("run"), int) and unit["run"] > 0
            and unit.get("failures") == 0 and unit.get("errors") == 0,
            "Invalid unit test result")
    require(unit.get("real_credentials_read") is False, "Unit store isolation was not verified")

    sources = manifest.get("source_sha256_before_and_after_build", {})
    require(runtime_source_names(ROOT) <= sources.keys(), "Build manifest omits a required runtime source")
    for name, expected in sources.items():
        require(sha(project_file(name)) == expected, f"Source changed after build: {name}")
    exe = project_file(f".local/dist/矿大校园网登录器_v{version}.exe")
    require(exe.stat().st_size == manifest.get("size_bytes"), "EXE size mismatch")
    require(sha(exe) == manifest.get("sha256"), "EXE hash mismatch")
    return manifest, reports, exe


def tracked_sources() -> list[str]:
    names = subprocess.check_output(
        ["git", "ls-files", "-z"], cwd=ROOT).decode("utf-8").split("\0")
    files = []
    for name in filter(None, names):
        path = ROOT / name
        if not path.exists():  # A tracked deletion is absent from the new archive.
            continue
        parts = Path(name).parts
        forbidden = (
            path.suffix.lower() in {".dpapi", ".exe", ".zip", ".jsonl"}
            or path.name in {"settings.json", "settings.json.tmp", ".env"}
            or path.name.startswith(".env.") and path.name != ".env.example"
            or any(part in {".git", ".local", "test-logs", "logs", "diagnostics", "live_assets"}
                   or part.startswith(".venv") for part in parts)
        )
        require(not forbidden, f"Local/private file is tracked; archive refused: {name}")
        project_file(name)
        files.append(name)
    require(runtime_source_names(ROOT) <= set(files),
            "Track all runtime sources with Git before creating an archive")
    return files


def archive_sources(version: str, exe: Path, files: list[str], expected_hash: str) -> Path:
    directory = ROOT / ".local" / "delivery"
    directory.mkdir(parents=True, exist_ok=True)
    archive = directory / f"矿大校园网登录器_v{version}_源码与程序.zip"
    temporary = archive.with_suffix(".zip.tmp")
    try:
        with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED) as bundle:
            for name in files:
                bundle.write(project_file(name), name)
            bundle.write(exe, "校园网登录器.exe")
        with zipfile.ZipFile(temporary) as bundle:
            require(bundle.testzip() is None, "Archive CRC verification failed")
            require(hashlib.sha256(bundle.read("校园网登录器.exe")).hexdigest() == expected_hash,
                    "Archived EXE hash mismatch")
        temporary.replace(archive)
    finally:
        temporary.unlink(missing_ok=True)
    return archive


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", action="store_true",
                        help="also archive Git-tracked sources and the verified EXE in .local/delivery")
    args = parser.parse_args(argv)
    try:
        version = current_version()
        manifest, reports, built_exe = validate(version)
        files = tracked_sources() if args.archive else []
        destination = ROOT / "校园网登录器.exe"
        if not destination.is_file() or sha(destination) != manifest["sha256"]:
            temporary = destination.with_suffix(".exe.tmp")
            try:
                shutil.copy2(built_exe, temporary)
                require(sha(temporary) == manifest["sha256"], "Copied EXE hash mismatch")
                temporary.replace(destination)
            finally:
                temporary.unlink(missing_ok=True)
        check = {
            "version": version, "file": destination.name,
            "bytes": destination.stat().st_size, "sha256": manifest["sha256"],
            "source_sha256": manifest["source_sha256_before_and_after_build"],
            "verification": manifest["verification"],
            "test_evidence_sha256": manifest["test_evidence_sha256"],
            "offline_tests_passed": reports["unit"]["run"],
            "unit_test_coverage": unit_test_coverage(reports["unit"]),
            "ui_smoke_success": True, "hidden_smoke_success": True,
            "packaged_smoke_success": True, "runtime_logging_and_export_verified": True,
            "native_window_restore_verified": True, "server_identity_display_verified": True,
            "branding_verified": True, "windows_resources": manifest["windows_resources"],
            "current_version_field_test_verified": False,
            "historical_field_evidence": {
                "1.5": f"Current AP login/logout/status/reconnect evidence in research; not a {version} field test",
                "1.4_guanshanfu": "User confirmed success; not a current-version field test",
                "1.5.1_guanshanfu": "User confirmed the client recovered after logging out through the school self-service portal",
            },
            "credentials_in_delivery": False,
        }
        checksum = ROOT / "程序校验.json"
        temporary_check = checksum.with_suffix(".json.tmp")
        try:
            temporary_check.write_text(json.dumps(check, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            temporary_check.replace(checksum)
        finally:
            temporary_check.unlink(missing_ok=True)
        archive = archive_sources(version, destination, files, manifest["sha256"]) if args.archive else None
        print(json.dumps({"version": version, "executable": str(destination),
                          "checksum": str(checksum), "exe_sha256": manifest["sha256"],
                          "archive": str(archive) if archive else None,
                          "archived_source_files": len(files)}, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError, zipfile.BadZipFile) as exc:
        parser.exit(1, f"Packaging stopped: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
