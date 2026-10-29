"""Transport failures stay visible without submitting or retrying authentication."""
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import zipfile

import campus_app as app
import campus_core as core
import campus_protocol as protocol
import campus_selfservice as selfservice
from test_protocol import MemoryPortal, documents, fixture_fingerprints


WIFI = core.Wifi(core.STU, 'network-feedback-fixture', 11, '10.52.7.23',
                 '00-11-22-33-44-55')
PORTAL = 'http://10.2.5.251/a79.htm'
ACCOUNT, PASSWORD = 'fictional-network-user', 'fictional-network-password'


def denied():
    error = PermissionError('fictional socket access denied')
    error.winerror = 10013
    error.errno = 13
    error._campus_phase = 'connect'
    return error


def denied_status():
    return {'state': 'unknown', 'detail': 'status_unreachable',
            'network_error': core.network_error_details(denied())}


class ProtocolNetworkFeedbackTests(unittest.TestCase):
    def test_status_preserves_connect_phase_and_numeric_error(self):
        getter = MagicMock(side_effect=denied())
        engine = protocol.Engine(WIFI, PORTAL, reader=lambda: WIFI, getter=getter)
        report = engine.status()
        self.assertEqual(report['state'], 'unknown')
        self.assertEqual(report['detail'], 'status_unreachable')
        self.assertEqual(report['network_error']['code'], 'permission_denied')
        self.assertEqual(report['network_error']['winerror'], 10013)
        self.assertEqual(report['network_error']['phase'], 'connect')
        getter.assert_called_once()

    def test_bad_response_is_not_misreported_as_windows_network_denial(self):
        engine = protocol.Engine(WIFI, PORTAL, reader=lambda: WIFI,
                                 getter=MagicMock(side_effect=ValueError('bad response body')))
        report = engine.status()
        self.assertEqual(report['state'], 'unknown')
        self.assertNotIn('network_error', report)

    def test_permission_denied_preparation_does_not_become_browser_fallback(self):
        engine = protocol.Engine(WIFI, PORTAL, reader=lambda: WIFI,
                                 getter=MagicMock(side_effect=denied()))
        client = app.App.__new__(app.App)
        client.session_engine = MagicMock(return_value=engine)
        client.authenticate = MagicMock()
        client.auth_diagnostic = {}
        with self.assertRaisesRegex(core.PortalNetworkError, '10013') as caught:
            client.run_authentication(WIFI, ACCOUNT, PASSWORD, 'campus', 'login', False, lambda: None)
        self.assertIsInstance(caught.exception.__cause__, PermissionError)
        client.authenticate.assert_not_called()
        engine.getter.assert_called_once()

    def test_network_failure_after_submission_keeps_unknown_and_single_request(self):
        docs = documents()
        portal = MemoryPortal(docs)
        portal.auth_exception = TimeoutError('response never arrived')
        engine = protocol.Engine(WIFI, PORTAL, reader=lambda: WIFI, getter=portal.get)
        with patch.dict(protocol.KNOWN_SCRIPTS, fixture_fingerprints(docs), clear=True):
            result, diagnostic = engine.authenticate(ACCOUNT, PASSWORD, 'campus')
        self.assertIsNone(result)
        self.assertEqual(diagnostic['phase'], 'response_unconfirmed')
        self.assertEqual(diagnostic['authentication_requests'], 1)
        self.assertEqual(diagnostic['network_error']['code'], 'timeout')
        self.assertEqual(len(portal.submissions), 1)


class AppNetworkFeedbackTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(app, 'stable_autostart_configured', return_value=False))
        self.enterContext(patch.object(app, 'stable_instance_running', return_value=False))
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = core.Store(self.root)
        with patch.object(core, 'Store', return_value=self.store):
            self.client = app.App()
        self.client.wifi = WIFI
        self.client.settings['quiet_hours'] = False
        self.engine = MagicMock()
        self.engine.status.return_value = denied_status()
        self.client.session_engine = MagicMock(return_value=self.engine)
        self.client.run_authentication = MagicMock(return_value=True)
        self.client.save_profile = MagicMock(return_value={'ok': True})
        self.client.start_job = lambda kind, job, automatic=False: (job() or {'ok': True})
        self.enterContext(patch.object(core, 'read_wifi', return_value=WIFI))
        self.enterContext(patch.object(core, 'discover', side_effect=AssertionError('No discovery allowed')))
        self.enterContext(patch.object(socket.socket, 'connect', side_effect=AssertionError('No live sockets')))
        self.tick = 100.0
        self.enterContext(patch.object(app.time, 'monotonic', side_effect=lambda: self.tick))
        self.client._logout_wait = lambda seconds: setattr(self, 'tick', self.tick + seconds)
        self.enterContext(patch.object(core, 'internet_check', return_value={'online': False, 'checks': []}))
        self.service_client = self.enterContext(patch.object(selfservice, 'Client',
            side_effect=AssertionError('No live self-service in network feedback tests')))

    def tearDown(self):
        self.client.runtime_log.close()
        self.temporary.cleanup()

    def login(self, automatic=False):
        return self.client.login(ACCOUNT, PASSWORD, 'campus', automatic=automatic)

    def real_worker(self, trigger):
        self.client.start_job = app.App.start_job.__get__(self.client, app.App)
        with patch.object(app.threading, 'Thread') as thread:
            result = trigger()
            if result['ok']:
                thread.call_args.kwargs['target']()
        return result

    def test_manual_login_stops_before_discovery_and_clears_stale_authentication(self):
        self.client.auth_diagnostic = {'authentication_requests': 1, 'phase': 'old_success'}
        self.assertTrue(self.login()['ok'])
        self.assertIn('10013', self.client.status)
        self.assertIn('本次未发送认证请求', self.client.status)
        self.assertNotIn('未找到真实认证页面', self.client.status)
        self.client.run_authentication.assert_not_called()
        self.client.session_engine.assert_called_once_with(WIFI, False)
        self.assertEqual(self.client.auth_diagnostic['authentication_requests'], 0)
        self.assertEqual(self.client.auth_diagnostic['phase'], 'network_blocked')
        self.assertEqual(self.client.session_state, 'unknown')

    def test_automatic_login_stops_with_actual_error_and_no_submission(self):
        self.client.settings['stu_autostart'] = True
        self.assertTrue(self.login(automatic=True)['ok'])
        self.assertIn('10013', self.client.status)
        self.assertIn('自动登录已停止', self.client.status)
        self.client.run_authentication.assert_not_called()
        self.assertEqual(self.client.auth_diagnostic['authentication_requests'], 0)

    def test_refresh_keeps_network_error_and_unknown_session(self):
        self.client.refresh_status()
        self.assertIn('10013', self.client.status)
        self.assertIn('刷新', self.client.status)
        self.assertFalse(self.client.logged_in)
        self.assertEqual(self.client.session_diagnostic['network_error']['phase'], 'connect')
        self.client.run_authentication.assert_not_called()

    def test_logout_unknown_keeps_denial_without_sending_logout(self):
        self.client.logout()
        self.assertIn('10013', self.client.status)
        self.assertIn('尚未确认', self.client.status)
        self.client.run_authentication.assert_not_called()
        self.service_client.assert_not_called()
        self.assertEqual(self.client.auth_diagnostic['authentication_requests'], 0)
        self.assertEqual(self.client.auth_diagnostic['selfservice_logout_requests'], 0)
        self.assertEqual(self.client.session_state, 'unknown')
        self.assertEqual(self.client.session_diagnostic['network_error']['winerror'], 10013)
        self.assertNotEqual(self.client.logout_diagnostic['outcome'], 'offline_confirmed')

    def test_other_unknown_status_still_allows_explicit_manual_attempt(self):
        self.engine.status.return_value = {'state': 'unknown',
            'network_error': core.network_error_details(socket.gaierror(11001, 'fictional DNS failure'))}
        self.client.run_authentication.return_value = None
        self.login()
        self.client.run_authentication.assert_called_once()
        self.assertEqual(self.client.session_state, 'unknown')
        self.assertIn('避免重复提交', self.client.status)

    def test_submission_timeout_keeps_network_reason_and_no_retry_warning(self):
        self.engine.status.return_value = {'state': 'offline'}
        def submit(*args):
            self.client.auth_diagnostic = {'operation': 'login', 'authentication_requests': 1,
                'phase': 'response_unconfirmed', 'network_error': core.network_error_details(TimeoutError())}
            return None
        self.client.run_authentication.side_effect = submit
        self.login()
        self.assertIn('超时', self.client.status)
        self.assertIn('避免重复提交', self.client.status)
        self.assertNotIn('未发送', self.client.status)
        self.assertEqual(self.client.auth_diagnostic['authentication_requests'], 1)
        self.client.run_authentication.assert_called_once()

    def test_accepted_login_with_failed_readback_keeps_acceptance_and_network_reason(self):
        self.engine.status.side_effect = [{'state': 'offline'}, denied_status()]
        def submit(*args):
            self.client.auth_diagnostic = {'operation': 'login', 'authentication_requests': 1,
                                           'phase': 'response_received'}
            return True
        self.client.run_authentication.side_effect = submit
        self.login()
        self.assertIn('10013', self.client.status)
        self.assertIn('已接受登录', self.client.status)
        self.assertIn('未再次提交', self.client.status)
        self.assertNotIn('未发送', self.client.status)
        self.assertEqual(self.client.auth_diagnostic['authentication_requests'], 1)
        self.client.run_authentication.assert_called_once()

    def test_worker_socket_error_keeps_numeric_reason_and_traceback(self):
        def failure():
            raise denied()
        self.real_worker(lambda: self.client.start_job('status', failure))
        self.assertIn('10013', self.client.status)
        rows = [json.loads(row) for row in self.client.runtime_log.path.read_text('utf-8').splitlines()]
        error = next(row for row in rows if row['event'] == 'operation.error')
        self.assertEqual(error['fields']['network_error']['winerror'], 10013)
        self.assertIn('failure', error['fields']['traceback'])

    def test_worker_error_after_attempt_does_not_suggest_zero_submissions(self):
        self.engine.status.return_value = {'state': 'offline'}
        def submit(*args):
            self.client.auth_diagnostic = {'operation': 'login', 'authentication_requests': 1}
            raise TimeoutError('response timeout')
        self.client.run_authentication.side_effect = submit
        self.real_worker(self.login)
        self.assertIn('超时', self.client.status)
        self.assertIn('避免重复提交', self.client.status)
        self.assertNotIn('未发送', self.client.status)
        self.assertEqual(self.client.auth_diagnostic['authentication_requests'], 1)

    def test_network_check_keeps_previous_authentication_and_exports_separate_report(self):
        old = {'operation': 'login', 'authentication_requests': 1, 'phase': 'response_received'}
        self.client.auth_diagnostic = dict(old)
        report = {'summary': 'fixture connection check completed', 'checks': [],
                  'authentication_requests': 0, 'network_changes': False}
        with patch.object(app.campus_network, 'run_check', return_value=report) as check:
            self.assertTrue(app.Bridge(self.client).network_check()['ok'])
        self.assertEqual(check.call_args.args[0], WIFI)
        self.assertEqual(self.client.auth_diagnostic, old)
        self.assertEqual(self.client.network_diagnostic, report)
        self.client.run_authentication.assert_not_called()
        exported = self.client.diagnostic()
        self.assertTrue(exported['ok'], exported)
        with zipfile.ZipFile(exported['path']) as archive:
            snapshot = json.loads(archive.read('snapshot.json'))
        self.assertEqual(snapshot['authentication'], old)
        self.assertEqual(snapshot['network_check'], report)
        self.assertEqual(self.client.status, report['summary'])

    def test_network_check_respects_busy_worker_without_running_check(self):
        self.client.start_job = app.App.start_job.__get__(self.client, app.App)
        self.client.busy = True
        with patch.object(app.campus_network, 'run_check') as check:
            result = self.client.network_check()
        self.assertFalse(result['ok'])
        check.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
