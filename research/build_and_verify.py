"""Build current sources and verify a copied, isolated Windows executable.

The packaged self-test reads no real profile and makes no campus requests or
network changes. Branding is checked both in PE resources and in the live window.
"""
from pathlib import Path
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import traceback

from PyInstaller.archive.readers import CArchiveReader
import PyInstaller
import pefile

ROOT = Path(__file__).resolve().parent.parent
if __package__:
    from .verification_context import (begin_verification, finish_verification,
                                       runtime_source_names, validate_test_reports, unit_test_coverage)
    from .slim_distribution import inspect_archive, verify_inventory
else:
    from verification_context import (begin_verification, finish_verification,
                                      runtime_source_names, validate_test_reports, unit_test_coverage)
    from slim_distribution import inspect_archive, verify_inventory
SOURCES = sorted(runtime_source_names(ROOT))
BRAND_ASSETS = ('assets/logo.png', 'assets/icon.ico')
ICON_SIZES = {16, 24, 32, 48, 64, 128, 256}


def run_smoke_process(command, directory, env, console_path, timeout=90):
    """Keep the original PID until its whole PyInstaller process tree is stopped.

    subprocess.run(timeout=...) kills only the onefile parent on Windows. Its
    child can retain the EXE and modal error dialog, masking the original error
    with a temporary-directory PermissionError during context cleanup.
    """
    console_path = Path(console_path)
    console_path.parent.mkdir(parents=True, exist_ok=True)
    flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
    process = None
    with console_path.open('wb') as console:
        try:
            process = subprocess.Popen(command, cwd=directory, env=env, stdout=console,
                                       stderr=subprocess.STDOUT, creationflags=flags)
            returncode = process.wait(timeout=timeout)
        except BaseException as exc:
            cleanup = []
            if process is not None and process.poll() is None:
                if os.name == 'nt':
                    try:
                        stopped = subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10,
                            creationflags=flags)
                        cleanup.append({'tree_exit_code': stopped.returncode,
                                        'output': stopped.stdout.decode('utf-8', 'replace')})
                    except BaseException as stop_error:
                        cleanup.append({'tree_error': type(stop_error).__name__, 'message': str(stop_error)})
                try:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=10)
                except BaseException as stop_error:
                    cleanup.append({'wait_error': type(stop_error).__name__, 'message': str(stop_error)})
            failure = {'error_type': type(exc).__name__, 'message': str(exc),
                       'traceback': traceback.format_exc(),
                       'process_id': process.pid if process is not None else None,
                       'termination': cleanup}
            try:
                console_path.with_suffix('.failure.json').write_text(
                    json.dumps(failure, ensure_ascii=False, indent=2), encoding='utf-8')
            except OSError:
                pass  # Preserve the triggering error even if its log cannot be written.
            raise
    if returncode != 0:
        raise RuntimeError(f'Packaged self-test exited with code {returncode}; see {console_path}')
    return subprocess.CompletedProcess(command, returncode)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def icon_frames(path):
    """Read exact ICO frame payloads without relying on a display icon cache."""
    data = path.read_bytes()
    reserved, kind, count = struct.unpack_from('<HHH', data)
    assert reserved == 0 and kind == 1 and count > 0, 'Invalid ICO header'
    frames = {}
    for index in range(count):
        width, height, _, _, _, bits, size, offset = struct.unpack_from('<BBBBHHII', data, 6 + index * 16)
        width, height = width or 256, height or 256
        assert size > 0 and offset >= 6 + 16 * count and offset + size <= len(data), 'Invalid ICO frame'
        payload = data[offset:offset + size]
        key = (width, height)
        assert key not in frames, 'Duplicate ICO frame size'
        frames[key] = {'bits': bits, 'bytes': size, 'sha256': hashlib.sha256(payload).hexdigest()}
    assert {(size, size) for size in ICON_SIZES} <= frames.keys(), 'Missing expected ICO sizes'
    return frames


def inspect_windows_resources(exe, version, icon_path):
    """Read PE data only; prove embedded icons match the project's ICO frames."""
    frames = icon_frames(icon_path)
    numeric = tuple(int(part) for part in version.split('.'))
    numeric += (0,) * (4 - len(numeric))
    with pefile.PE(str(exe)) as pe:
        resources = {entry.id: entry for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries}
        assert 3 in resources and 14 in resources and 16 in resources, 'Missing icon/version PE resources'
        images = {}
        for entry in resources[3].directory.entries:
            for language in entry.directory.entries:
                info = language.data.struct
                images[(entry.id, language.id)] = pe.get_data(info.OffsetToData, info.Size)
        observed = set()
        for group in resources[14].directory.entries:
            for language in group.directory.entries:
                info = language.data.struct
                data = pe.get_data(info.OffsetToData, info.Size)
                reserved, kind, count = struct.unpack_from('<HHH', data)
                assert reserved == 0 and kind == 1, 'Invalid embedded icon group'
                for index in range(count):
                    width, height, _, _, _, bits, size, resource_id = struct.unpack_from('<BBBBHHIH', data, 6 + index * 14)
                    key = (width or 256, height or 256)
                    expected = frames[key]
                    image = images.get((resource_id, language.id))
                    if image is None:
                        image = next(blob for (identifier, _), blob in images.items() if identifier == resource_id)
                    assert size == len(image) == expected['bytes'], 'Embedded icon frame size changed'
                    assert bits == expected['bits'], 'Embedded icon bit depth changed'
                    assert hashlib.sha256(image).hexdigest() == expected['sha256'], 'Embedded icon payload differs from source'
                    observed.add(key)
        assert observed == set(frames), 'Embedded icon sizes differ from source'
        fixed = pe.VS_FIXEDFILEINFO[0]
        def version_tuple(prefix):
            high, low = getattr(fixed, prefix + 'MS'), getattr(fixed, prefix + 'LS')
            return (high >> 16, high & 0xffff, low >> 16, low & 0xffff)
        assert version_tuple('FileVersion') == numeric, 'Numeric file version mismatch'
        assert version_tuple('ProductVersion') == numeric, 'Numeric product version mismatch'
        strings = {}
        for group in pe.FileInfo:
            for item in group:
                for table in getattr(item, 'StringTable', []):
                    for key, value in table.entries.items():
                        strings[key.decode('utf-8')] = value.decode('utf-8')
        assert strings.get('FileVersion') == version, 'Display file version mismatch'
        assert strings.get('ProductVersion') == version, 'Display product version mismatch'
    return {'icon_sizes': [list(size) for size in sorted(observed)],
            'icon_frames_match_source': True, 'file_version': strings['FileVersion'],
            'product_version': strings['ProductVersion'], 'numeric_version': list(numeric)}


def main():
    os.chdir(ROOT)
    verification = begin_verification('build', ROOT)
    reports, evidence_hashes = validate_test_reports(ROOT, verification['source_start'])
    before = {name: sha(ROOT / name) for name in SOURCES}
    work = ROOT / '.local/build'
    work.mkdir(parents=True, exist_ok=True)
    with (work / 'build-console.log').open('w', encoding='utf-8') as stream:
        built = subprocess.run([sys.executable, '-m', 'PyInstaller', '--noconfirm',
                                '--workpath', str(work), '--distpath', str(ROOT / '.local/dist'),
                                str(ROOT / '矿大校园网助手.spec')], stdout=stream, stderr=subprocess.STDOUT)
    if built.returncode:
        raise RuntimeError('Build failed; see .local/build/build-console.log')
    assert before == {name: sha(ROOT / name) for name in SOURCES}, 'Sources changed during build'
    sys.path.insert(0, str(ROOT))
    import campus_core as core
    assert all(report.get('version') == core.VERSION for report in reports.values()), 'Test report version mismatch'
    exe = ROOT / '.local/dist' / f'矿大校园网登录器_v{core.VERSION}.exe'
    resources = inspect_windows_resources(exe, core.VERSION, ROOT / 'assets/icon.ico')
    # A cleanup failure must never replace the actual process/verification error.
    with tempfile.TemporaryDirectory(prefix='cumt-portable-exe-', ignore_cleanup_errors=True) as temporary:
        independent = Path(temporary)
        copied = independent / '校园网登录器.exe'
        shutil.copy2(exe, copied)
        assert sha(copied) == sha(exe), 'Portable executable copy changed'
        env = dict(os.environ)
        env.pop('PYTHONPATH', None)
        env['LOCALAPPDATA'] = str(independent / 'LocalData')
        smoke = run_smoke_process([str(copied), '--smoke-test'], independent, env,
                                  work / 'portable-smoke-console.log')
        report_path = independent / 'packaged_smoke_results.json'
        if not report_path.is_file():
            raise RuntimeError('Packaged self-test exited without a result; see '
                               + str(work / 'portable-smoke-console.log'))
        result = json.loads(report_path.read_text('utf-8'))
        assert smoke.returncode == 0 and result['success'] and result['runtime_log_ready'] and result['diagnostic_zip_verified'] and result['window_restore_verified'] and result['online_identity_display'], result
        assert result['ui_logo_loaded'] and result['native_icon']['verified'], 'Runtime branding validation failed'
        assert result['network_check_entry'], 'Network check bridge and UI entry are missing'
        assert result['native_icon']['asset_sha256'] == before['assets/icon.ico'], 'Runtime ICO differs from source'
    if result.get('ip'):
        result['ip'] = '<wifi-ip>'
    if result.get('wifi_index'):
        result['wifi_index'] = '<wifi-interface-index>'
    archive = CArchiveReader(str(exe))
    pyz = archive.open_embedded_archive('PYZ.pyz')
    files = list(archive.toc)
    assert all(module in pyz.toc for module in ('campus_core', 'campus_protocol', 'campus_logging', 'campus_network', 'campus_selfservice'))
    normalized = {name.replace('\\', '/'): name for name in files}
    assert 'campus_ui.html' in normalized
    bundled_assets = {}
    for name in BRAND_ASSETS:
        assert name in normalized, f'Missing bundled branding asset: {name}'
        digest = hashlib.sha256(archive.extract(normalized[name])).hexdigest()
        assert digest == before[name], f'Bundled asset differs from source: {name}'
        bundled_assets[name] = digest
    private = [name for name in files if any(key in name.lower() for key in
               ('credentials.dpapi', 'settings.json', 'diagnostic-', 'test-logs', 'test_logging', 'test_runtime_logging'))]
    assert not private, private
    assert not any(name.startswith('test_') for name in pyz.toc), 'Test modules bundled'
    inventory = inspect_archive(exe)
    distribution_verification = verify_inventory(inventory, result.get('webview2_compatibility'))
    assert before == {name: sha(ROOT / name) for name in SOURCES}, 'Sources changed during packaged validation'
    verification = finish_verification(verification, ROOT)
    assert verification['source_stable'], 'Product or verification sources changed during build'
    _, final_evidence_hashes = validate_test_reports(ROOT, verification['source_end'])
    assert final_evidence_hashes == evidence_hashes, 'Test reports changed during build'
    manifest = {'version': core.VERSION, 'executable': '<project>/.local/dist/' + exe.name,
                'size_bytes': exe.stat().st_size, 'sha256': sha(exe),
                'source_sha256_before_and_after_build': before, 'source_stable_during_build': True,
                'verification': verification, 'test_evidence_sha256': evidence_hashes,
                'unit_test_coverage': unit_test_coverage(reports['unit']),
                'build_python': '<project>/.venv/Scripts/python.exe', 'pyinstaller_version': PyInstaller.__version__,
                'packaged_smoke': result,
                'smoke_store_isolation': 'Fresh temporary working directory outside source tree; temporary LOCALAPPDATA and built-in temporary Store/log root; no real credentials read',
                'smoke_exit_code': smoke.returncode, 'portable_copy_without_source_verified': True,
                'archive_entries': len(files), 'campus_protocol_bundled': True,
                'campus_logging_bundled': True, 'campus_ui_bundled': True,
                'private_store_or_test_files_bundled': private,
                'brand_assets_bundled': True, 'bundled_brand_assets_sha256': bundled_assets,
                'embedded_icon_verified': True, 'windows_versions_verified': True,
                'windows_resources': resources}
    manifest.update(package_inventory=inventory,
                    distribution_verification=distribution_verification)
    (ROOT / 'research' / ('build_manifest_v' + core.VERSION.replace('.', '_') + '.json')).write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps({'version': core.VERSION, 'sha256': manifest['sha256'],
                      'bytes': manifest['size_bytes'], 'packaged_smoke': result,
                      'windows_resources': resources, 'source_stable': True}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
