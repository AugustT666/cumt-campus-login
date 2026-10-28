"""Run public synthetic tests, optionally qualifying separately with local captures.

No test may be skipped to qualify. Public mode excludes only the explicit
CapturedPortalHardeningTests class and records every excluded test ID.
"""
from pathlib import Path
import argparse
import json
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
if __package__:
    from .verification_context import (begin_verification, finish_verification,
        captured_test_ids, local_capture_inputs, PUBLIC_SCOPE, CAPTURE_SCOPE)
else:
    from verification_context import (begin_verification, finish_verification,
        captured_test_ids, local_capture_inputs, PUBLIC_SCOPE, CAPTURE_SCOPE)


def cases(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from cases(item)
        else:
            yield item


def select_suite(suite, with_local_captures=False):
    all_cases = list(cases(suite))
    expected = set(captured_test_ids(ROOT))
    captured = {case.id() for case in all_cases if case.id() in expected}
    if captured != expected:
        raise ValueError('Discovered local-capture suite differs from its source declarations')
    excluded = sorted(captured) if not with_local_captures else []
    selected = [case for case in all_cases if case.id() not in excluded]
    return unittest.TestSuite(selected), len(all_cases), excluded, len(captured)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--with-local-captures', action='store_true',
        help='also run captured-portal qualification; all six local inputs are required')
    args = parser.parse_args(argv)
    scope = CAPTURE_SCOPE if args.with_local_captures else PUBLIC_SCOPE
    report_path = ROOT / 'research/unit_results.json'
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps({'success': False, 'test_scope': scope}), encoding='utf-8')
    try:
        verification = begin_verification('unit', ROOT, unit_scope=scope)
    except (OSError, ValueError) as exc:
        report_path.write_text(json.dumps({'success':False, 'test_scope':scope,
            'run':0, 'discovered_tests':0, 'skipped':0, 'error':str(exc),
            'excluded_test_ids':[], 'excluded_test_count':0,
            'local_capture_test_count':0, 'real_credentials_read':False,
            'local_capture_tests_executed':False}, ensure_ascii=False, indent=2), encoding='utf-8')
        print(str(exc), file=sys.stderr)
        return 1
    report_path.write_text(json.dumps({'success':False, 'test_scope':scope,
                                      'verification':verification}), encoding='utf-8')
    import campus_core as core
    original_connect = socket.socket.connect
    def local_ipc_only(sock, address):
        if isinstance(address, tuple) and address[0] in ('127.0.0.1', '::1'):
            return original_connect(sock, address)
        raise AssertionError('offline test attempted a non-loopback socket connection')
    with tempfile.TemporaryDirectory(dir=ROOT / 'research') as temporary:
        with patch.object(core, 'data_root', return_value=Path(temporary)), \
             patch.object(socket.socket, 'connect', new=local_ipc_only):
            discovered = unittest.defaultTestLoader.discover(str(ROOT), pattern='test_*.py', top_level_dir=str(ROOT))
            suite, total, excluded, captured_count = select_suite(discovered, args.with_local_captures)
            result = unittest.TextTestRunner(verbosity=2).run(suite)
    verification = finish_verification(verification, ROOT)
    report = {
        'version':core.VERSION, 'test_scope':scope, 'discovered_tests':total,
        'run':result.testsRun, 'failures':len(result.failures), 'errors':len(result.errors),
        'skipped':len(result.skipped), 'excluded_test_count':len(excluded),
        'excluded_test_ids':excluded,
        'local_capture_test_count':captured_count if args.with_local_captures else 0,
        'local_capture_tests_executed':args.with_local_captures,
        'success':result.wasSuccessful() and not result.skipped and verification['source_stable'],
        'verification':verification,
        'store_isolation':'temporary directory, including any default Store instance',
        'network_isolation':'non-loopback Python sockets rejected; browser requests mocked or aborted',
        'real_credentials_read':False,
        'failed_cases':[case.id() for case,_ in result.failures],
        'error_cases':[case.id() for case,_ in result.errors],
    }
    report_path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n', encoding='utf-8')
    print(json.dumps({key:report[key] for key in ('version','test_scope','run','excluded_test_count','skipped','success')}))
    return 0 if report['success'] else 1


if __name__ == '__main__':
    sys.exit(main())
