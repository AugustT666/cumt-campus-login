"""Rejected authentication and the device's live session are separate facts."""
import copy
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import campus_app as app
import campus_core as core


WIFI = core.Wifi(core.STU, 'rejection-readback-fixture', 7, '10.52.7.23',
                 '00-11-22-33-44-55')
ACCOUNT, PASSWORD = 'fictional-readback-user', 'fictional-readback-password'


class LoginRejectionReadbackTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = core.Store(Path(self.temporary.name))
        with patch.object(core, 'Store', return_value=self.store):
            self.client = app.App()
        self.addCleanup(self.client.runtime_log.close)
        self.client.wifi = WIFI
        self.client.settings['quiet_hours'] = False
        self.client.save_profile = MagicMock(return_value={'ok': True})
        self.client.start_job = lambda kind, job, automatic=False: (job() or {'ok': True})
        self.engine = MagicMock()
        self.engine.status.side_effect = [{'state': 'offline'}, {'state': 'online',
            'matched_ip': True, 'binding': 'mac_verified', 'online_account': ACCOUNT}]
        self.client.session_engine = MagicMock(return_value=self.engine)
        self.original_authentication = {'operation': 'login', 'backend': 'verified_drcom_http',
            'phase': 'response_received', 'authentication_requests': 1, 'result': False,
            'response': {'result': '0', 'ret_code': '2', 'msg': ''}}

        def reject(*args):
            self.client.auth_diagnostic = copy.deepcopy(self.original_authentication)
            return False

        self.client.run_authentication = MagicMock(side_effect=reject)
        self.wifi_reader = self.enterContext(patch.object(core, 'read_wifi', return_value=WIFI))
        self.enterContext(patch.object(socket.socket, 'connect',
            side_effect=AssertionError('No actual network connection in this test')))

    def login(self):
        return self.client.login(ACCOUNT, PASSWORD, 'campus')

    def assert_one_rejected_request_preserved(self):
        self.client.run_authentication.assert_called_once()
        self.assertEqual(self.client.auth_diagnostic, self.original_authentication)
        self.assertIs(self.client.auth_diagnostic['result'], False)
        self.assertEqual(self.client.auth_diagnostic['response']['ret_code'], '2')

    def test_rejected_request_with_confirmed_online_session_keeps_online(self):
        self.assertTrue(self.login()['ok'])
        self.assertEqual(self.engine.status.call_count, 2)
        self.assertTrue(self.client.logged_in)
        self.assertEqual(self.client.session_state, 'online')
        self.assertEqual(self.client.online_account, ACCOUNT)
        self.assertIn('已在线', self.client.status)
        self.assertIn('未再次提交', self.client.status)
        self.assertNotIn('密码', self.client.status)
        self.assert_one_rejected_request_preserved()

    def test_rejected_request_with_confirmed_offline_session_stays_offline(self):
        self.engine.status.side_effect = [{'state': 'offline'}, {'state': 'offline',
            'detail': 'server_confirmed', 'matched_ip': True}]
        self.login()
        self.assertEqual(self.engine.status.call_count, 2)
        self.assertFalse(self.client.logged_in)
        self.assertEqual(self.client.session_state, 'offline')
        self.assertIn('未接受', self.client.status)
        self.assertNotIn('密码', self.client.status)
        self.assert_one_rejected_request_preserved()

    def test_online_identity_comes_from_readback_not_the_rejected_account(self):
        server_identity = 'fictional-existing-session-user'
        self.engine.status.side_effect = [{'state': 'offline'}, {'state': 'online',
            'matched_ip': True, 'binding': 'mac_verified', 'online_account': server_identity}]
        self.login()
        self.assertTrue(self.client.logged_in)
        self.assertEqual(self.client.online_account, server_identity)
        self.assertNotEqual(self.client.online_account, ACCOUNT)
        self.assertEqual(self.client.identity_source, 'server')
        self.assert_one_rejected_request_preserved()

    def test_unknown_readback_does_not_invent_offline_or_online(self):
        self.engine.status.side_effect = [{'state': 'offline'}, {'state': 'unknown',
            'detail': 'unrecognized_status_response'}]
        self.login()
        self.assertFalse(self.client.logged_in)
        self.assertEqual(self.client.session_state, 'unknown')
        self.assertIn('尚未确认', self.client.status)
        self.assertIn('刷新', self.client.status)
        self.assertIn('未再次提交', self.client.status)
        self.assert_one_rejected_request_preserved()

    def test_network_readback_exception_keeps_actual_reason_and_unknown(self):
        denied = PermissionError('fictional access denied')
        denied.winerror = 10013
        denied._campus_phase = 'connect'
        self.engine.status.side_effect = [{'state': 'offline'}, denied]
        self.login()
        self.assertEqual(self.client.session_state, 'unknown')
        self.assertIn('10013', self.client.status)
        self.assertIn('未再次提交', self.client.status)
        self.assertEqual(self.client.session_diagnostic['network_error']['phase'], 'connect')
        self.assert_one_rejected_request_preserved()

    def test_already_online_before_login_sends_no_authentication(self):
        self.engine.status.side_effect = None
        self.engine.status.return_value = {'state': 'online', 'matched_ip': True,
            'binding': 'mac_verified', 'online_account': ACCOUNT}
        self.login()
        self.assertTrue(self.client.logged_in)
        self.client.run_authentication.assert_not_called()
        self.engine.status.assert_called_once()
        self.assertEqual(self.client.auth_diagnostic['authentication_requests'], 0)

    def test_actual_rejection_message_remains_visible_after_readback(self):
        self.engine.status.side_effect = [{'state': 'offline'}, {'state': 'offline'}]
        def reject(*args):
            self.client.auth_diagnostic = copy.deepcopy(self.original_authentication)
            self.client.message('认证提示：fictional server account restriction')
            return False
        self.client.run_authentication.side_effect = reject
        self.login()
        self.assertIn('认证提示：fictional server account restriction', self.client.status)
        self.assert_one_rejected_request_preserved()

    def test_conflicting_status_evidence_does_not_become_online(self):
        for detail, flags in [('session_mac_mismatch', {'mac_conflict': True}),
                              ('session_ip_mismatch', {'ip_conflict': True})]:
            with self.subTest(detail=detail):
                self.engine.status.side_effect = [{'state': 'offline'},
                    {'state': 'unknown', 'detail': detail, 'binding': 'conflict', **flags}]
                self.login()
                self.assertFalse(self.client.logged_in)
                self.assertEqual(self.client.session_state, 'unknown')
                self.assertEqual(self.client.session_diagnostic['binding'], 'conflict')
                self.assertFalse(self.client.auth_diagnostic['result'])
        self.assertEqual(self.client.run_authentication.call_count, 2)

    def test_network_change_during_readback_stops_status_application(self):
        changed = core.Wifi(core.STU, WIFI.guid, WIFI.index, '10.52.7.24', WIFI.mac)
        def readback():
            self.wifi_reader.return_value = changed
            return {'state': 'online', 'matched_ip': True, 'binding': 'mac_verified'}
        calls = iter((lambda: {'state': 'offline'}, readback))
        self.engine.status.side_effect = lambda: next(calls)()
        with self.assertRaises(RuntimeError):
            self.login()
        self.assertFalse(self.client.logged_in)
        self.assert_one_rejected_request_preserved()

    def test_cancellation_during_readback_cannot_restore_online(self):
        def readback():
            self.client.cancel.set()
            return {'state': 'online', 'matched_ip': True, 'binding': 'mac_verified'}
        calls = iter((lambda: {'state': 'offline'}, readback))
        self.engine.status.side_effect = lambda: next(calls)()
        with self.assertRaises(RuntimeError):
            self.login()
        self.assertFalse(self.client.logged_in)
        self.assert_one_rejected_request_preserved()


if __name__ == '__main__':
    unittest.main()
