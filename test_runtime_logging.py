"""Application logging integration; synthetic credentials, temporary files, no sockets."""
import base64
import hashlib
import html
import json
from pathlib import Path
import re
import socket
import sys
import tempfile
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import quote, quote_plus, unquote
import zipfile

import campus_app as app
import campus_core as core
from campus_logging import RuntimeLog


WIFI = core.Wifi(core.STU, 'runtime-log-fixture', 7, '10.52.141.23',
                 '00-11-22-33-44-55', '10.52.191.254', ('10.2.1.10',))
PORTAL = 'http://10.2.5.251/a79.htm'
ACCOUNT = 'offline-集成+&<user>-987654'
PASSWORD = 'offline-秘密 P&<pass>\\"-987654!'


class RuntimeLoggingIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(app, 'stable_autostart_configured', return_value=False))
        self.enterContext(patch.object(app, 'stable_instance_running', return_value=False))
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.store = core.Store(self.root)
        self.enterContext(patch.object(core, 'data_root', return_value=self.root))
        self.enterContext(patch.object(core, 'Store', return_value=self.store))
        self.enterContext(patch.object(core, 'read_wifi', return_value=WIFI))
        self.enterContext(patch.object(core, 'BoundHTTP', side_effect=AssertionError('Unexpected HTTP access')))
        self.enterContext(patch.object(socket.socket, 'connect', side_effect=AssertionError('Unexpected socket access')))
        self.enterContext(patch.object(app.App, 'started', side_effect=AssertionError('Unexpected monitor startup')))
        self.client = self.make_client()

    def make_client(self, runtime_log=None):
        client = app.App(runtime_log=runtime_log)
        self.addCleanup(client.runtime_log.close)
        client.wifi = WIFI
        client.portal = PORTAL
        client.settings['quiet_hours'] = False
        self.assertEqual(client.store.root, self.root)
        return client

    def rows(self, client=None):
        log = (client or self.client).runtime_log
        log.flush()
        return [json.loads(line) for path in sorted(log.logs_dir.glob('*.jsonl*'))
                for line in path.read_text(encoding='utf-8').splitlines()]

    def bundle(self, client=None):
        client = client or self.client
        result = app.Bridge(client).diagnostic()
        self.assertTrue(result['ok'], result)
        path = Path(result['path'])
        self.assertTrue(path.is_relative_to(self.root))
        self.assertEqual(path.suffix, '.zip')
        with zipfile.ZipFile(path) as archive:
            files = {name: archive.read(name) for name in archive.namelist()}
        rows = [json.loads(line) for name, data in files.items() if name.startswith('logs/')
                for line in data.decode('utf-8').splitlines()]
        return files, rows, json.loads(files['snapshot.json']), json.loads(files['manifest.json'])

    def execute(self, trigger):
        # Exercise the real acceptance/worker/error/finally path deterministically;
        # no background thread may outlive the temporary Store or test patches.
        with patch.object(app.threading, 'Thread') as thread:
            result = trigger()
            self.assertTrue(result['ok'], result)
            self.assertTrue(self.client.busy)
            operation_id = self.client.operation_id
            self.assertTrue(operation_id)
            thread.assert_called_once()
            thread.return_value.start.assert_called_once()
            thread.call_args.kwargs['target']()
        self.assertFalse(self.client.busy)
        self.assertEqual(self.client.operation, '')
        return operation_id

    def test_login_failure_keeps_full_correlated_stack_and_state_in_zip(self):
        engine = MagicMock()
        engine.status.return_value = {'state': 'offline', 'matched_ip': True}
        self.client.session_engine = MagicMock(return_value=engine)
        self.client.save_profile = MagicMock(return_value={'ok': True})

        def failing_authentication(*args):
            self.client.auth_diagnostic = {'operation': 'login', 'phase': 'fixture_failure'}
            core.trace('fixture.step', detail='before transport failure')
            def failing_transport_step():
                raise ValueError('fixture transport failure')
            failing_transport_step()

        self.client.run_authentication = failing_authentication
        operation_id = self.execute(lambda: self.client.login(ACCOUNT, PASSWORD, 'campus'))
        self.assertIn('连接认证服务器失败', self.client.get_state()['status'])
        files, rows, snapshot, manifest = self.bundle()
        errors = [row for row in rows if row['event'] == 'operation.error']
        self.assertEqual(len(errors), 1)
        error = errors[0]
        self.assertEqual(error['fields']['exception_type'], 'ValueError')
        for fragment in ('Traceback', 'failing_transport_step', 'failing_authentication', 'job', 'fixture transport failure'):
            self.assertIn(fragment, error['fields']['traceback'])
        for event in ('operation.accepted', 'operation.started', 'fixture.step', 'operation.error', 'operation.finished'):
            selected = [row for row in rows if row['event'] == event]
            self.assertTrue(selected, event)
            self.assertTrue(all(row['operation_id'] == operation_id for row in selected), event)
        self.assertEqual(snapshot['authentication']['phase'], 'fixture_failure')
        self.assertEqual(snapshot['session']['state'], 'offline')
        self.assertEqual(snapshot['wifi']['ip'], WIFI.ip)
        self.assertEqual(snapshot['wifi']['mac'], WIFI.mac)
        self.assertFalse(snapshot['network_configuration_changes'])
        self.assertEqual(manifest['version'], core.VERSION)
        self.assertIn('README.txt', files)

    def test_expected_operation_error_keeps_user_reason_and_traceback(self):
        def rejected_status():
            raise RuntimeError('fixture status rejected')
        operation_id = self.execute(lambda: self.client.start_job('status', rejected_status))
        self.assertEqual(self.client.get_state()['status'], 'fixture status rejected')
        error = next(row for row in self.rows() if row['event'] == 'operation.error')
        self.assertEqual(error['operation_id'], operation_id)
        self.assertEqual(error['fields']['exception_type'], 'RuntimeError')
        self.assertIn('rejected_status', error['fields']['traceback'])

    def test_ui_history_limit_does_not_truncate_persistent_timeline(self):
        for number in range(95):
            self.client.message(f'fixture timeline marker {number:03}')
        self.assertEqual(len(self.client.messages), 60)
        self.assertFalse(any('marker 000' in row['text'] for row in self.client.messages))
        files, rows, snapshot, manifest = self.bundle()
        timeline = [row['fields']['text'] for row in rows if row['event'] == 'app.message']
        self.assertIn('fixture timeline marker 000', timeline)
        self.assertIn('fixture timeline marker 094', timeline)
        self.assertEqual(len(snapshot['messages']), 60)
        current = next(item for item in manifest['sessions'] if item['session_id'] == self.client.runtime_log.session_id)
        self.assertEqual(current['missing_sequence_ranges'], [])
        self.assertTrue(any(name.startswith('logs/') for name in files))

    def test_reopened_app_exports_prior_and_current_process_timelines(self):
        first = self.client
        first.message('fixture first process marker')
        first.runtime_log.close()
        self.client = self.make_client()
        self.client.message('fixture reopened process marker')
        self.assertNotEqual(first.runtime_log.session_id, self.client.runtime_log.session_id)
        _, rows, _, manifest = self.bundle()
        self.assertIn(first.runtime_log.session_id, {row['session_id'] for row in rows})
        self.assertIn(self.client.runtime_log.session_id, {row['session_id'] for row in rows})
        messages = [row['fields']['text'] for row in rows if row['event'] == 'app.message']
        self.assertIn('fixture first process marker', messages)
        self.assertIn('fixture reopened process marker', messages)
        self.assertEqual(len(manifest['sessions']), 2)

    def test_app_registered_credential_encodings_never_leak_to_disk_or_zip(self):
        # The bridge accepts promptly; the worker registers secrets and rejects
        # invalid selection before any persistence or authentication request.
        with patch.object(self.client,'run_authentication') as authenticate, \
                patch.object(self.client,'save_profile') as save:
            self.execute(lambda:self.client.login(ACCOUNT, PASSWORD, 'invalid-selection'))
            authenticate.assert_not_called()
            save.assert_not_called()
        variants = set()
        for secret in (ACCOUNT, PASSWORD):
            variants.update((secret, html.escape(secret, quote=True), quote(secret, safe=''),
                             quote_plus(secret, safe=''), json.dumps(secret, ensure_ascii=True)[1:-1],
                             secret.encode('unicode_escape').decode('ascii')))
            for encoding in ('utf-8', 'utf-16-le'):
                raw = secret.encode(encoding)
                variants.update((base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode().rstrip('=')))
        variants.update(quote(value, safe='') for value in tuple(variants))
        for variant in variants:
            self.client.message('fixture encoded credential: ' + variant)
        self.client.auth_diagnostic = {'password': PASSWORD, 'user_account': ACCOUNT,
                                       'response_headers': {'Set-Cookie': 'unregistered-cookie-marker'}}
        self.client.session_cookies = [{'name': 'session', 'value': 'memory-cookie-never-export'}]
        self.store.path.write_text('{"password":"settings-file-never-export"}', encoding='utf-8')
        self.store.credentials.write_bytes(b'credential-file-never-export')
        files, _, snapshot, _ = self.bundle()
        disk = b'\n'.join(path.read_bytes() for path in self.client.runtime_log.logs_dir.glob('*.jsonl*')).decode('utf-8')
        exported = b'\n'.join(files.values()).decode('utf-8')
        for content in (disk, exported):
            for secret in variants | {'unregistered-cookie-marker', 'memory-cookie-never-export',
                                      'settings-file-never-export', 'credential-file-never-export'}:
                self.assertNotIn(secret, content)
                self.assertNotIn(json.dumps(secret, ensure_ascii=False)[1:-1], content)
            self.assertNotIn(ACCOUNT, json.dumps(snapshot, ensure_ascii=False))
        self.assertIn(WIFI.ip, exported)
        self.assertIn(WIFI.mac, exported)
        self.assertTrue(all('settings' not in name and 'credentials' not in name for name in files))

    def test_long_mixed_percent_password_is_filtered_before_protocol_result_or_ui_truncation(self):
        password = '私密测试口令' + '长编码回归凭据' * 35 + '&+end!'
        self.assertGreater(len(password), 200)
        parts = iter(range(10000))
        encoded = re.sub(r'%[0-9A-F]{2}',
                         lambda match: match[0].lower() if next(parts) % 2 else match[0],
                         quote(password, safe=''))
        self.assertNotEqual(encoded, quote(password, safe=''))
        self.client.save_profile = MagicMock(return_value={'ok': True})
        for outcome in (False, True):
            with self.subTest(authentication_success=outcome):
                detail = app.protocol.Engine._redact('fixture decision: ' + encoded + ' fixture complete-result-tail', ACCOUNT, password)
                # The protocol layer must retain the complete encoding until the
                # central filter can match it, rather than leak a clipped prefix.
                self.assertGreater(len(detail), 200)
                self.assertTrue(detail.endswith('fixture complete-result-tail'))
                trace = {'operation': 'login', 'phase': 'response_received',
                         'authentication_requests': 1, 'http_status': 200, 'result': outcome,
                         'response': {'result': '1' if outcome else '0', 'msg': detail}}
                engine = MagicMock()
                engine.status.side_effect = ([{'state':'offline','matched_ip':True},
                                             {'state':'online','matched_ip':True}]
                                            if outcome else [{'state':'offline','matched_ip':True},
                                                             {'state':'offline','matched_ip':True}])
                def fake_authenticate(*args, **kwargs):
                    core.trace('protocol.authentication_result', result=trace)
                    return outcome, trace
                engine.authenticate.side_effect = fake_authenticate
                self.client.session_engine = MagicMock(return_value=engine)
                self.execute(lambda: self.client.login(ACCOUNT, password, 'campus'))
                engine.prepare.assert_called_once()
                engine.authenticate.assert_called_once()
                self.assertEqual(self.client.session_state, 'online' if outcome else 'offline')
                diagnostic = self.client.auth_diagnostic
                self.assertIs(diagnostic['result'], outcome)
                self.assertEqual(diagnostic['authentication_requests'], 1)
                self.assertEqual(diagnostic['phase'], 'response_received')
                self.assertTrue(diagnostic['response']['msg'].endswith('fixture complete-result-tail'))
                files, rows, snapshot, _ = self.bundle()
                self.assertIs(snapshot['authentication']['result'], outcome)
                recorded = [row for row in rows if row['event'] == 'protocol.authentication_result'][-1]
                self.assertIs(recorded['fields']['result']['result'], outcome)
                disk = self.client.runtime_log.path.read_text(encoding='utf-8')
                exported = b'\n'.join(files.values()).decode('utf-8')
                ui = json.dumps({'status': self.client.get_state()['status'], 'messages': self.client.messages,
                                 'authentication': diagnostic}, ensure_ascii=False)
                for content in (disk, exported, ui):
                    for length in (3, 8, 24):
                        prefix = password[:length]
                        self.assertNotIn(prefix, content)
                        self.assertNotIn(prefix, unquote(content))
                        self.assertNotIn(quote(prefix, safe='').casefold(), content.casefold())
                    self.assertNotIn(encoded[:180].casefold(), content.casefold())

    def test_export_io_failure_returns_visible_message_and_records_stack(self):
        self.client.register_secrets(PASSWORD)
        with patch.object(self.client.runtime_log, 'export_bundle', side_effect=PermissionError('fixture denied ' + PASSWORD)):
            result = app.Bridge(self.client).diagnostic()
        self.assertFalse(result['ok'])
        self.assertTrue(result['message'])
        self.assertIn('无法保存诊断包', result['message'])
        self.assertNotIn('path', result)
        row = next(row for row in self.rows() if row['event'] == 'diagnostic.export_error')
        self.assertIn('Traceback', row['fields']['traceback'])
        self.assertIn('PermissionError', row['fields']['traceback'])
        self.assertNotIn(PASSWORD, row['fields']['traceback'])

    def test_uninitialized_logger_export_has_explicit_failure(self):
        self.client.runtime_log = None
        result = app.Bridge(self.client).diagnostic()
        self.assertFalse(result['ok'])
        self.assertIn('运行日志未初始化', result['message'])

    def test_disk_logging_failure_is_visible_without_breaking_app_state(self):
        blocked = self.root / 'blocked-log-root'
        blocked.write_text('fixture occupied', encoding='utf-8')
        self.client = self.make_client(RuntimeLog(blocked, core.VERSION))
        self.client.message('fixture app remains usable')
        state = app.Bridge(self.client).get_state()
        self.assertTrue(state['logging_error'])
        self.assertEqual(state['status'], 'fixture app remains usable')
        self.assertFalse(state['busy'])
        self.assertFalse(app.Bridge(self.client).diagnostic()['ok'])

    def test_core_http_trace_contains_metadata_and_hash_without_body_or_cookie(self):
        body = b'<html>unregistered-response-body-marker</html>'
        response = MagicMock(status=200)
        response.read.return_value = body
        headers = {'Content-Type': 'text/html; charset=utf-8', 'Set-Cookie': 'unregistered-wire-cookie-marker'}
        response.getheaders.return_value = list(headers.items())
        response.getheader.side_effect = lambda name, default=None: headers.get(name, default)
        connection = MagicMock()
        connection.getresponse.return_value = response
        captured = []
        def trace_sink(event, level='DEBUG', **fields):
            captured.append({'event': event, 'fields': fields})
            self.client.record(event, level=level, **fields)
        with patch.object(core, 'BoundHTTP', return_value=connection), core.trace_scope(trace_sink):
            status, _, text = core.fetch(PORTAL, WIFI, reader=lambda: WIFI)
        self.assertEqual(status, 200)
        self.assertIn('unregistered-response-body-marker', text)
        connection.close.assert_called_once()
        raw_trace = json.dumps(captured)
        files, rows, _, _ = self.bundle()
        for content in (raw_trace, b''.join(files.values()).decode('utf-8')):
            self.assertNotIn('unregistered-response-body-marker', content)
            self.assertNotIn('unregistered-wire-cookie-marker', content)
        metadata = next(row['fields'] for row in rows if row['event'] == 'http.response')
        self.assertEqual(metadata['decoded_bytes'], len(body))
        self.assertEqual(metadata['body_sha256'], hashlib.sha256(body).hexdigest())
        self.assertEqual(metadata['status'], 200)
        self.assertIn('elapsed_ms', metadata)

    def test_core_http_error_is_correlated_with_operation_stack_and_closes_connection(self):
        connection = MagicMock()
        connection.getresponse.side_effect = ConnectionResetError('fixture transport disconnected')
        with patch.object(core, 'BoundHTTP', return_value=connection):
            operation_id = self.execute(lambda: self.client.start_job('status', lambda: core.fetch(PORTAL, WIFI, reader=lambda: WIFI)))
        connection.close.assert_called_once()
        _, rows, _, _ = self.bundle()
        for event in ('http.request', 'http.error', 'operation.error', 'operation.finished'):
            row = next(row for row in rows if row['event'] == event)
            self.assertEqual(row['operation_id'], operation_id)
            if event.endswith('error'):
                self.assertIn('ConnectionResetError', row['fields']['traceback'])
                self.assertIn('fetch', row['fields']['traceback'])

    def test_core_exception_object_keeps_html_error_stack_without_exporting_html(self):
        failures = []
        def fixture_html_transport_step():
            raise RuntimeError('<html><body>fixture-private-html-response-marker</body></html>')
        def traced_html_failure():
            try:
                fixture_html_transport_step()
            except RuntimeError as exc:
                failures.append(exc)
                core.trace('http.error', level='ERROR', _exception=exc, url=PORTAL,
                           error_type=type(exc).__name__, error=str(exc), traceback=traceback.format_exc())
        with patch.object(self.client.runtime_log, 'exception', wraps=self.client.runtime_log.exception) as exception_sink:
            operation_id = self.execute(lambda: self.client.start_job('status', traced_html_failure))
        exception_sink.assert_called_once()
        self.assertIs(exception_sink.call_args.args[1], failures[0])
        self.assertEqual(exception_sink.call_args.kwargs['operation_id'], operation_id)
        files, exported_rows, _, _ = self.bundle()
        for rows in (self.rows(), exported_rows):
            error = next(row for row in rows if row['event'] == 'http.error')
            self.assertEqual(error['operation_id'], operation_id)
            self.assertEqual(error['fields']['exception_type'], 'RuntimeError')
            self.assertNotIn('_exception', error['fields'])
            for fragment in ('Traceback', 'RuntimeError', 'fixture_html_transport_step', 'traced_html_failure'):
                self.assertIn(fragment, error['fields']['traceback'])
        disk = self.client.runtime_log.path.read_text(encoding='utf-8')
        exported = b'\n'.join(files.values()).decode('utf-8')
        for content in (disk, exported):
            self.assertNotIn('fixture-private-html-response-marker', content)
            self.assertNotIn('<html>', content)
            self.assertNotIn('<body>', content)

    def test_main_startup_failure_is_logged_and_process_hooks_are_restored(self):
        captured = []
        previous_hook = app.threading.excepthook
        previous_root = core.data_root
        import logging
        previous_handlers = list(logging.getLogger().handlers)
        def fake_run_main(log):
            captured.append(log)
            raise RuntimeError('fixture main startup failed')
        with patch.object(sys, 'argv', ['campus_app.py']), \
             patch.object(app.platform, 'platform', return_value='offline-platform'), \
             patch.object(app, 'run_main', side_effect=fake_run_main):
            with self.assertRaisesRegex(RuntimeError, 'fixture main startup failed'):
                app.main()
        self.assertEqual(len(captured), 1)
        self.assertIs(core.data_root, previous_root)
        self.assertIs(app.threading.excepthook, previous_hook)
        self.assertEqual(logging.getLogger().handlers, previous_handlers)
        rows = [json.loads(line) for line in captured[0].path.read_text(encoding='utf-8').splitlines()]
        error = next(row for row in rows if row['event'] == 'app.unhandled_exception')
        self.assertIn('fake_run_main', error['fields']['traceback'])
        self.assertIn('fixture main startup failed', error['fields']['traceback'])
        self.assertEqual(rows[-1]['event'], 'session_closed')

    def test_main_executable_hash_failure_keeps_startup_and_records_traceback(self):
        captured = []
        def fake_run_main(log):
            captured.append(log)
            log.event('fixture.main_reached')
        with patch.object(sys, 'argv', ['campus_app.py']), \
             patch.object(sys, 'frozen', True, create=True), \
             patch.object(Path, 'read_bytes', side_effect=PermissionError('fixture exe hash read denied')), \
             patch.object(app.platform, 'platform', return_value='offline-platform'), \
             patch.object(app, 'run_main', side_effect=fake_run_main) as run_main:
            app.main()
        run_main.assert_called_once()
        rows = [json.loads(line) for line in captured[0].path.read_text(encoding='utf-8').splitlines()]
        error = next(row for row in rows if row['event'] == 'startup.environment_error')
        self.assertIn('Traceback', error['fields']['traceback'])
        self.assertIn('fixture exe hash read denied', error['fields']['traceback'])
        self.assertTrue(any(row['event'] == 'fixture.main_reached' for row in rows))
        self.assertEqual(rows[-1]['event'], 'session_closed')

    def test_packaged_smoke_startup_failure_writes_report_and_exits_without_dialog(self):
        output = self.root / 'isolated-smoke-output'
        output.mkdir()
        executable = output / 'fictional-client.exe'
        secret = 'fictional-smoke-startup-private-value'

        def failed_startup(log):
            log.register_secrets(secret)
            raise RuntimeError(secret)

        previous_root = core.data_root
        with patch.object(sys, 'argv', ['campus_app.py', '--smoke-test']), \
                patch.object(sys, 'executable', str(executable)), \
                patch.object(app.platform, 'platform', return_value='offline-platform'), \
                patch.object(app, 'run_main', side_effect=failed_startup):
            with self.assertRaises(SystemExit) as exited:
                app.main()
        self.assertEqual(exited.exception.code, 1)
        self.assertIs(core.data_root, previous_root)
        report = json.loads((output / 'packaged_smoke_results.json').read_text('utf-8'))
        self.assertFalse(report['success'])
        self.assertEqual(report['version'], core.VERSION)
        self.assertEqual(report['error_type'], 'RuntimeError')
        preserved = (output / 'packaged_smoke_failure.jsonl').read_text('utf-8')
        self.assertIn('failed_startup', preserved)
        self.assertIn('Traceback', preserved)
        self.assertNotIn(secret, preserved)
        self.assertNotIn(secret, json.dumps(report))

    def test_main_unwritable_data_root_uses_recovery_and_restores_original_root(self):
        captured = []
        recovery_name = ('CumtCampusLoginExperimental-Recovery' if app.EXPERIMENTAL
                         else 'CumtCampusLogin-Recovery')
        recovery = self.root / 'fixture-temp-base' / recovery_name
        def fake_run_main(log):
            captured.append(log)
            self.assertEqual(core.data_root(), recovery)
            self.assertTrue(log.location_warning)
            log.event('fixture.recovery_main_reached')
        with patch.object(sys, 'argv', ['campus_app.py']), \
             patch.object(core, 'data_root', side_effect=PermissionError('fixture normal data denied')) as blocked_root, \
             patch.object(app.tempfile, 'gettempdir', return_value=str(recovery.parent)), \
             patch.object(app.platform, 'platform', return_value='offline-platform'), \
             patch.object(app, 'run_main', side_effect=fake_run_main):
            app.main()
            self.assertIs(core.data_root, blocked_root)
        self.assertEqual(captured[0].root, recovery)
        self.assertTrue(captured[0].path.is_relative_to(self.root))
        rows = [json.loads(line) for line in captured[0].path.read_text(encoding='utf-8').splitlines()]
        error = next(row for row in rows if row['event'] == 'startup.data_directory_error')
        self.assertIn('PermissionError', error['fields']['traceback'])
        self.assertIn('fixture normal data denied', error['fields']['traceback'])
        self.assertEqual(Path(error['fields']['recovery_root']), recovery)
        self.assertTrue(any(row['event'] == 'fixture.recovery_main_reached' for row in rows))

    def test_main_thread_exception_hook_keeps_stack_and_restores_previous_hook(self):
        captured = []
        previous_hook = MagicMock()
        def failing_thread_step():
            raise LookupError('fixture worker failed')
        def fake_run_main(log):
            captured.append(log)
            try:
                failing_thread_step()
            except LookupError as exc:
                args = SimpleNamespace(exc_type=type(exc), exc_value=exc, exc_traceback=exc.__traceback__,
                                       thread=SimpleNamespace(name='fixture-worker-thread'))
                app.threading.excepthook(args)
        with patch.object(sys, 'argv', ['campus_app.py']), \
             patch.object(app.threading, 'excepthook', previous_hook), \
             patch.object(app.platform, 'platform', return_value='offline-platform'), \
             patch.object(app, 'run_main', side_effect=fake_run_main):
            app.main()
            self.assertIs(app.threading.excepthook, previous_hook)
        previous_hook.assert_called_once()
        rows = [json.loads(line) for line in captured[0].path.read_text(encoding='utf-8').splitlines()]
        error = next(row for row in rows if row['event'] == 'thread.unhandled_exception')
        self.assertEqual(error['fields']['thread_name'], 'fixture-worker-thread')
        self.assertEqual(error['fields']['exception_type'], 'LookupError')
        self.assertIn('failing_thread_step', error['fields']['traceback'])
        self.assertIn('fixture worker failed', error['fields']['traceback'])


if __name__ == '__main__':
    unittest.main()
