"""Inspect the shipped archive and reject slimming that removes compatibility."""
from __future__ import annotations

from pathlib import Path


MAX_DISTRIBUTION_BYTES = 15_000_000
BASELINE_V164_BYTES = 52_099_045
FORBIDDEN_MODULE_ROOTS = {
    'playwright', 'greenlet', 'pyee', 'PyInstaller', '_pyinstaller_hooks_contrib',
    'setuptools', 'pkg_resources', 'pefile', 'altgraph',
}
REQUIRED_MODULES = {
    'campus_core', 'campus_protocol', 'campus_selfservice', 'campus_status', 'campus_logging', 'campus_network', 'campus_browser',
    'campus_webview2', 'webview.platforms.winforms', 'webview.platforms.edgechromium',
    'pythonnet',
}
REQUIRED_FILES = {
    'campus_ui.html', 'assets/logo.png', 'assets/icon.ico',
    'webview/lib/Microsoft.Web.WebView2.Core.dll',
    'webview/lib/Microsoft.Web.WebView2.WinForms.dll',
    'webview/lib/runtimes/win-x64/native/WebView2Loader.dll',
    'webview/lib/runtimes/win-x86/native/WebView2Loader.dll',
    'webview/lib/runtimes/win-arm64/native/WebView2Loader.dll',
    'webview/js/api.js', 'webview/js/finish.js',
}


def inspect_archive(executable: Path) -> dict:
    # Build tools are used by the verifier only, never imported by the product.
    from PyInstaller.archive.readers import CArchiveReader

    executable = Path(executable)
    archive = CArchiveReader(str(executable))
    modules = archive.open_embedded_archive('PYZ.pyz').toc
    groups = {}
    for name, (_, compressed, original, _, _) in archive.toc.items():
        path = name.replace('\\', '/')
        group = path.split('/')[0] if '/' in path else '<root>'
        values = groups.setdefault(group, {'compressed_bytes': 0, 'original_bytes': 0, 'entries': 0})
        values['compressed_bytes'] += compressed
        values['original_bytes'] += original
        values['entries'] += 1
    return {
        'size_bytes': executable.stat().st_size,
        'files': sorted(name.replace('\\', '/') for name in archive.toc),
        'python_modules': sorted(modules),
        'compressed_groups': groups,
    }


def verify_compatibility_smoke(report: dict) -> None:
    if not isinstance(report, dict) or report.get('engine') != 'webview2':
        raise ValueError('The packaged WebView2 compatibility backend was not verified')
    for name in ('success', 'request_interception_verified', 'single_submission_verified',
                 'duplicate_attempt_blocked', 'trusted_input_verified',
                 'frame_transport_verified', 'desktop_viewport_verified'):
        if report.get(name) is not True:
            raise ValueError('The packaged WebView2 compatibility check failed: ' + name)
    if type(report.get('campus_requests')) is not int or report['campus_requests'] != 0:
        raise ValueError('The packaged compatibility check must make zero campus requests')
    if report.get('network_changes') is not False:
        raise ValueError('The packaged compatibility check must not change the network')


def verify_inventory(inventory: dict, compatibility_smoke: dict) -> dict:
    """Validate facts extracted from the EXE, including its actual module list."""
    verify_compatibility_smoke(compatibility_smoke)
    size = inventory.get('size_bytes')
    if type(size) is not int or not 0 < size <= MAX_DISTRIBUTION_BYTES:
        raise ValueError('The distribution exceeds the 15 MB size target')
    files = {str(name).replace('\\', '/') for name in inventory.get('files', [])}
    modules = set(inventory.get('python_modules', []))
    forbidden_files = sorted(name for name in files if
        any(part.casefold().startswith('playwright') for part in name.split('/'))
        or Path(name).name.casefold() in {'node.exe', 'node.dll', 'chrome.exe',
            'msedge.exe', 'firefox.exe', 'headless_shell.exe'}
        or name.casefold().endswith('.dpapi')
        or Path(name).name.casefold() in {'settings.json', 'settings.json.tmp'}
        or any(part.casefold().startswith('test_') for part in name.split('/')))
    forbidden_modules = sorted(name for name in modules if
        name.split('.')[0] in FORBIDDEN_MODULE_ROOTS
        or name.startswith('webview.__pyinstaller')
        or name.split('.')[0].startswith('test_'))
    if forbidden_files or forbidden_modules:
        raise ValueError('Forbidden browser driver, build/test module or private file in EXE: '
                         + ', '.join(forbidden_files + forbidden_modules))
    missing = (REQUIRED_FILES - files) | (REQUIRED_MODULES - modules)
    if missing:
        raise ValueError('The slim distribution omits required runtime files/modules: '
                         + ', '.join(sorted(missing)))
    if not any(name.casefold().startswith('pywebview-') and
               name.casefold().endswith('/licenses/license') for name in files):
        raise ValueError('The bundled pywebview license is missing')
    return {
        'size_limit_bytes': MAX_DISTRIBUTION_BYTES,
        'actual_size_bytes': size,
        'baseline_v1_6_4_bytes': BASELINE_V164_BYTES,
        'saved_bytes': BASELINE_V164_BYTES - size,
        'reduction_percent': round((1 - size / BASELINE_V164_BYTES) * 100, 2),
        'size_target_met': True,
        'playwright_and_node_absent': True,
        'build_and_test_modules_absent': True,
        'webview2_backend_bundled': True,
        'webview2_compatibility_verified': True,
        'system_webview2_runtime_required': True,
        'required_runtime_files_present': True,
    }
