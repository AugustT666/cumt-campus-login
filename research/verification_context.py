"""Verification inputs and explicit public versus local-capture coverage."""
from __future__ import annotations

import ast
import datetime as dt
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNTIME_SOURCES = {'campus_core.py', 'campus_ui.html', '矿大校园网助手.spec', 'requirements.txt', 'campus_network.py', 'assets/icon.ico', 'assets/logo.png', 'assets/logo-master.png', 'campus_logging.py', 'campus_protocol.py', 'campus_app.py', 'requirements-build-lock.txt'}
MAINTENANCE_INPUTS = {'research/run_offline_tests.py', 'research/ui_smoke.py', 'research/verification_context.py', 'research/package_current.py', 'research/build_and_verify.py', 'research/install_desktop_shortcut.ps1', 'research/generate_icons.py'}
OPTIONAL_INPUTS = {'requirements-dev.txt'}
REPORT_COMMANDS = {
    'unit': ['<python>', 'research/run_offline_tests.py'],
    'ui': ['<python>', 'research/ui_smoke.py'],
    'hidden': ['<python>', 'research/ui_smoke.py', '--hidden'],
    'build': ['<python>', 'research/build_and_verify.py'],
}
REPORT_FILES = {'unit': 'research/unit_results.json',
                'ui': 'research/ui_smoke_results.json',
                'hidden': 'research/hidden_smoke_results.json'}
TEST_INPUTS = {'.local/deep-audit/live-capture/' + name
               for name in ('a41.js', 'a42.js', 'config.js', 'loginbox.js', 'pc.js')
               } | {'.local/portal-logout-audit/a79.htm'}
PUBLIC_SCOPE = 'public-synthetic'
CAPTURE_SCOPE = 'with-local-captures'
CAPTURE_CLASS = 'test_protocol_hardening.CapturedPortalHardeningTests.'


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def _input(root, name):
    path = Path(root) / name
    if path.is_symlink() or not path.resolve().is_relative_to(Path(root).resolve()):
        raise ValueError('Linked source is not permitted: ' + name)
    return path


def runtime_source_names(root: Path = ROOT) -> set[str]:
    return set(RUNTIME_SOURCES)


def capture_source(root: Path = ROOT) -> dict:
    """Only maintained product/build inputs and discovered test modules count.

    Archived probes, notes, report JSONs and local portal captures do not enter
    public source identity. Explicit capture qualification is bound separately.
    """
    root = Path(root).resolve()
    names = runtime_source_names(root)
    names.update(name for name in MAINTENANCE_INPUTS | OPTIONAL_INPUTS
                 if (root / name).is_file())
    names.update(path.relative_to(root).as_posix()
                 for path in root.glob('test*.py') if path.is_file())
    files = {name: file_sha256(_input(root, name)) for name in sorted(names)}
    canonical = json.dumps(files, ensure_ascii=False, sort_keys=True,
                           separators=(',', ':')).encode('utf-8')
    return {'format_version': 2, 'algorithm': 'sha256', 'files': files,
            'sha256': hashlib.sha256(canonical).hexdigest()}


def local_capture_inputs(root: Path = ROOT) -> dict:
    result = {}
    missing = []
    for name in sorted(TEST_INPUTS):
        path = _input(root, name)
        if not path.is_file():
            missing.append(name)
        else:
            result[name] = file_sha256(path)
    if missing:
        raise ValueError('Local capture qualification requires all six files; missing: '
                         + ', '.join(missing))
    return result


def captured_test_ids(root: Path = ROOT) -> list[str]:
    path = Path(root) / 'test_protocol_hardening.py'
    if not path.is_file():
        return []
    tree = ast.parse(path.read_text('utf-8'))
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef)
               and node.name == 'CapturedPortalHardeningTests']
    return sorted(CAPTURE_CLASS + node.name for cls in classes for node in cls.body
                  if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                  and node.name.startswith('test_'))


def _now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='milliseconds')


def begin_verification(kind: str, root: Path = ROOT, *, unit_scope=PUBLIC_SCOPE):
    if unit_scope not in (PUBLIC_SCOPE, CAPTURE_SCOPE):
        raise ValueError('Unknown unit test scope')
    command = list(REPORT_COMMANDS[kind])
    if kind == 'unit' and unit_scope == CAPTURE_SCOPE:
        command.append('--with-local-captures')
    result = {'command': command, 'started_at': _now(), 'source_start': capture_source(root)}
    if kind == 'unit':
        result['unit_scope'] = unit_scope
        if unit_scope == CAPTURE_SCOPE:
            result['local_capture_start'] = local_capture_inputs(root)
    return result


def finish_verification(start: dict, root: Path = ROOT):
    end = capture_source(root)
    result = {**start, 'finished_at': _now(), 'source_end': end,
              'source_stable': start['source_start'] == end}
    if start.get('unit_scope') == CAPTURE_SCOPE:
        result['local_capture_end'] = local_capture_inputs(root)
        result['source_stable'] = (result['source_stable'] and
            start.get('local_capture_start') == result['local_capture_end'])
    return result


def validate_verification(evidence: dict, current: dict, kind: str):
    if not isinstance(evidence, dict):
        raise ValueError(f'Missing {kind} verification context')
    command = list(REPORT_COMMANDS[kind])
    if kind == 'unit' and evidence.get('unit_scope') == CAPTURE_SCOPE:
        command.append('--with-local-captures')
    if evidence.get('command') != command:
        raise ValueError(f'Unexpected {kind} verification command')
    try:
        started = dt.datetime.fromisoformat(evidence['started_at'])
        finished = dt.datetime.fromisoformat(evidence['finished_at'])
        valid_time = started.tzinfo is not None and finished.tzinfo is not None and finished >= started
    except (KeyError, TypeError, ValueError):
        valid_time = False
    if not valid_time:
        raise ValueError(f'Incomplete {kind} verification timestamps')
    if evidence.get('source_stable') is not True or evidence.get('source_start') != evidence.get('source_end'):
        raise ValueError(f'Sources changed during {kind} verification')
    if evidence.get('source_end') != current:
        raise ValueError(f'Source or test code changed since {kind} verification')


def unit_test_coverage(report):
    fields = ('test_scope', 'discovered_tests', 'run', 'excluded_test_count',
              'excluded_test_ids', 'local_capture_test_count', 'local_capture_tests_executed')
    return {name: report.get(name) for name in fields}


def validate_unit_scope(report, root):
    scope = report.get('test_scope')
    if scope not in (PUBLIC_SCOPE, CAPTURE_SCOPE):
        raise ValueError('Missing or unknown unit test coverage scope')
    expected = captured_test_ids(root)
    excluded = report.get('excluded_test_ids')
    correct_excluded = expected if scope == PUBLIC_SCOPE else []
    if excluded != correct_excluded or report.get('excluded_test_count') != len(correct_excluded):
        raise ValueError('Unit test coverage exclusions differ from the maintained capture suite')
    if (type(report.get('run')) is not int or report['run'] <= 0
            or type(report.get('discovered_tests')) is not int
            or report['discovered_tests'] != report['run'] + len(correct_excluded)):
        raise ValueError('Invalid unit test coverage counts')
    captured = scope == CAPTURE_SCOPE
    if (report.get('local_capture_tests_executed') is not captured
            or report.get('local_capture_test_count') != (len(expected) if captured else 0)):
        raise ValueError('Invalid local capture execution claim')
    context = report.get('verification') or {}
    if context.get('unit_scope') != scope:
        raise ValueError('Unit test scope is not bound to its verification command')
    if captured:
        actual = local_capture_inputs(root)
        if (context.get('local_capture_start') != actual
                or context.get('local_capture_end') != actual):
            raise ValueError('Local capture inputs changed since qualification')


def validate_test_reports(root: Path, current: dict):
    reports, hashes = {}, {}
    for kind, name in REPORT_FILES.items():
        path = Path(root) / name
        report = json.loads(path.read_text('utf-8'))
        if not isinstance(report, dict) or report.get('success') is not True:
            raise ValueError(f'Current {kind} test did not pass')
        if kind == 'unit' and (type(report.get('skipped')) is not int or report['skipped'] != 0):
            raise ValueError('Skipped unit tests cannot satisfy delivery verification')
        validate_verification(report.get('verification'), current, kind)
        if kind == 'unit':
            validate_unit_scope(report, root)
        reports[kind] = report
        hashes[name] = file_sha256(path)
    return reports, hashes
