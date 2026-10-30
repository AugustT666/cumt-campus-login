"""Verified user-visible outcomes across explicit state, login and logout.

All credentials and endpoint reports are synthetic. The shared fixture blocks
real sockets, credential storage and unbounded legacy status/readback helpers.
"""
from dataclasses import replace
from unittest.mock import patch
import time
import unittest

import campus_app as app
import campus_core as core
import campus_protocol as protocol
import campus_selfservice as service
from test_logout_recovery import LogoutRecoveryFixture, ACCOUNT, PASSWORD


OTHER_ACCOUNT = 'fictional-other-online-account'


class VerifiedStatusActionTests(LogoutRecoveryFixture):
    SSID = core.STU

    def setUp(self):
        super().setUp()
        self.probe = self.enterContext(patch.object(app.status_checks, 'probe'))
        self.confirm = self.enterContext(patch.object(app.status_checks, 'confirm_logout'))
        self.probe.return_value = self.state_report('online')
        self.confirm.return_value = self.logout_report('offline')

    def state_report(self, state, account=ACCOUNT):
        online = state == 'online'
        known = state in ('online', 'offline')
        return {'state': state, 'binding': 'mac_verified' if online else 'source_ip_only' if known else 'unconfirmed',
                'matched_ip': known, 'ip_conflict': False, 'mac_conflict': False,
                'server_ip': self.wifi.ip if known else '',
                'server_mac': protocol._session_mac(self.wifi.mac) if online else '',
                'online_account': account if online else '', 'identity_hint': '',
                'detail': 'server_confirmed' if known else 'short_check_timeout',
                'source': 'portal_query', 'verification_performed': True, 'elapsed_ms': 10}

    def logout_report(self, state, account=ACCOUNT):
        outcome = {'offline': 'confirmed_offline', 'online': 'still_online'}.get(state, 'unknown')
        return {'state': state, 'outcome': outcome,
                'device_presence': 'absent' if state == 'offline' else 'present' if state == 'online' else 'unavailable',
                'status': self.state_report(state, account), 'verification_performed': True,
                'elapsed_ms': 700, 'samples': [
                    {'state': state, 'elapsed_ms': 0}, {'state': state, 'elapsed_ms': 700}]}

    def arrange_login(self, result=True, code=None):
        def authenticate(*args, **kwargs):
            response = {'result': '1' if result is True else '0'}
            if code is not None:
                response['ret_code'] = code
            self.client.auth_diagnostic = {'operation': 'login', 'backend': 'fixture',
                'authentication_requests': 1, 'result': result, 'response': response}
            return result
        self.client.run_authentication.side_effect = authenticate

    def login(self, account=ACCOUNT):
        return self.execute(lambda: self.client.login(account, PASSWORD, 'campus', 'own-profile'))

    def arrange_no_session(self):
        self.web.summary['device_queries'] = 1
        self.web.submit_error = service.NoMatchingDevice('Fictional account has no matching current session')

    def changed_context(self):
        newer = replace(self.wifi, ip='10.61.55.10')
        self.current = newer
        self.client._observe_portal_network(newer)
        with self.client.lock:
            self.client.wifi = newer
            self.client.status = 'Fictional newer-network feedback'
            self.client.session_state = 'online'
            self.client.logged_in = True
            self.client.online_account = OTHER_ACCOUNT
            self.client.identity_source = 'verified_status'
            self.client.auth_key = newer.key

    def assert_new_context_preserved(self):
        self.assertEqual(self.client.status, 'Fictional newer-network feedback')
        self.assertEqual(self.client.online_account, OTHER_ACCOUNT)
        self.assertTrue(self.client.logged_in)
        self.assertEqual(self.client.auth_key, self.current.key)

    def test_explicit_status_is_a_read_only_worker_action(self):
        self.assertTrue(self.execute(self.client.refresh_status)['ok'])
        self.probe.assert_called_once()
        self.client.run_authentication.assert_not_called()
        self.service_factory.assert_not_called()
        self.confirm.assert_not_called()
        self.assertTrue(self.client.logged_in)
        self.assertEqual(self.client.online_account, ACCOUNT)
        self.assertEqual(self.client.identity_source, 'verified_status')

    def test_bridge_schedules_status_without_synchronous_network_work(self):
        bridge = app.Bridge(self.client)
        with patch.object(app.threading, 'Thread') as thread:
            result = bridge.refresh_status()
            self.assertTrue(result['ok'])
            self.assertEqual(self.client.operation, 'status')
            self.probe.assert_not_called()
            thread.assert_called_once()
            thread.call_args.kwargs['target']()
        self.assertFalse(self.client.busy)
        self.probe.assert_called_once()
        self.assertFalse(hasattr(bridge, 'cancel_operation'))
        self.assertFalse(hasattr(bridge, 'network_check'))

    def test_status_unknown_cannot_retain_stale_online_identity(self):
        self.client.logged_in = True
        self.client.online_account = OTHER_ACCOUNT
        self.client.session_state = 'online'
        self.probe.return_value = self.state_report('unknown')
        self.execute(self.client.refresh_status)
        self.assertFalse(self.client.logged_in)
        self.assertEqual(self.client.online_account, '')
        self.assertEqual(self.client.session_state, 'unknown')

    def test_status_check_is_not_available_on_a_hotspot(self):
        self.current = replace(self.wifi, ssid='Fictional hotspot')
        self.execute(self.client.refresh_status)
        self.probe.assert_not_called()
        self.service_factory.assert_not_called()

    def test_login_acceptance_with_verified_online_uses_server_identity(self):
        self.arrange_login()
        self.login()
        self.probe.assert_called()
        self.assertIs(self.client.auth_diagnostic['request_accepted'], True)
        self.assertTrue(self.client.logged_in)
        self.assertEqual(self.client.online_account, ACCOUNT)
        self.assertEqual(self.client.identity_source, 'verified_status')
        self.assertIn('成功', self.client.status)
        self.client.run_authentication.assert_called_once()

    def test_login_acceptance_with_offline_effect_does_not_report_success(self):
        self.arrange_login()
        self.probe.return_value = self.state_report('offline')
        self.login()
        self.assertIs(self.client.auth_diagnostic['request_accepted'], True)
        self.assertFalse(self.client.logged_in)
        self.assertNotIn('登录成功', self.client.status)
        self.client.run_authentication.assert_called_once()

    def test_login_acceptance_with_unknown_effect_does_not_report_success(self):
        self.arrange_login()
        self.probe.return_value = self.state_report('unknown')
        self.login()
        self.assertIs(self.client.auth_diagnostic['request_accepted'], True)
        self.assertFalse(self.client.logged_in)
        self.assertEqual(self.client.session_state, 'unknown')
        self.assertNotIn('登录成功', self.client.status)
        self.client.run_authentication.assert_called_once()

    def test_login_acceptance_with_other_account_does_not_claim_entered_account_success(self):
        self.arrange_login()
        self.probe.return_value = self.state_report('online', OTHER_ACCOUNT)
        self.login()
        self.assertIs(self.client.auth_diagnostic['request_accepted'], True)
        self.assertEqual(self.client.online_account, OTHER_ACCOUNT)
        self.assertNotEqual(self.client.online_account, ACCOUNT)
        self.assertNotIn('登录成功', self.client.status)
        self.client.run_authentication.assert_called_once()

    def test_authentication_timeout_can_report_verified_same_account_without_rewriting_receipt(self):
        self.arrange_login(False, '8')
        self.login()
        self.probe.assert_called()
        self.assertIs(self.client.auth_diagnostic['request_accepted'], False)
        self.assertIs(self.client.auth_diagnostic['result'], False)
        self.assertTrue(self.client.logged_in)
        self.assertEqual(self.client.online_account, ACCOUNT)
        self.assertEqual(self.client.identity_source, 'verified_status')
        self.assertNotIn('失败', self.client.status)
        self.client.run_authentication.assert_called_once()

    def test_timeout_with_other_account_does_not_report_entered_account_login_success(self):
        self.arrange_login(False, '8')
        self.probe.return_value = self.state_report('online', OTHER_ACCOUNT)
        self.login()
        self.assertIs(self.client.auth_diagnostic['request_accepted'], False)
        self.assertEqual(self.client.online_account, OTHER_ACCOUNT)
        self.assertNotIn('登录成功', self.client.status)
        self.client.run_authentication.assert_called_once()

    def delayed_matching_status(self, result, code=None):
        self.arrange_login(result, code)
        self.probe.side_effect = [self.state_report('online', OTHER_ACCOUNT), self.state_report('online')]
        self.login()
        self.assertEqual(self.probe.call_count, 2)
        self.client.run_authentication.assert_called_once()
        self.assertIs(self.client.auth_diagnostic['request_accepted'], result)
        self.assertTrue(self.client.auth_diagnostic['verified_account_matches'])
        self.assertEqual(self.client.online_account, ACCOUNT)
        self.assertEqual(self.client.identity_source, 'verified_status')
        self.assertNotIn('未确认登录账号', self.client.status)

    def test_accepted_login_waits_briefly_for_old_uid_to_be_replaced(self):
        self.delayed_matching_status(True)
        self.assertIn('登录成功', self.client.status)

    def test_authentication_timeout_waits_briefly_for_matching_uid_without_resubmission(self):
        self.delayed_matching_status(False, '8')
        self.assertIn('登录成功', self.client.status)

    def test_unknown_receipt_does_not_discard_a_subsequently_verified_matching_uid(self):
        self.delayed_matching_status(None)
        self.assertTrue(self.client.logged_in)

    def test_authentication_timeout_with_unknown_status_is_not_called_explicit_rejection(self):
        self.arrange_login(False, '8')
        self.probe.return_value = self.state_report('unknown')
        self.login()
        self.assertIs(self.client.auth_diagnostic['request_accepted'], False)
        self.assertFalse(self.client.logged_in)
        self.assertIn('超时', self.client.status)
        self.assertNotIn('服务器未接受', self.client.status)
        self.assertNotIn('登录成功', self.client.status)
        self.client.run_authentication.assert_called_once()

    def test_logout_accepted_and_confirmed_offline_reports_success_once(self):
        started = time.monotonic()
        self.logout()
        self.confirm.assert_called_once()
        deadline = self.confirm.call_args.kwargs['deadline']
        self.assertGreaterEqual(deadline, started)
        self.assertLessEqual(deadline, started + 6.1)
        self.assertIs(self.client.auth_diagnostic['request_accepted'], True)
        self.assertIn('注销成功', self.client.status)
        self.assertFalse(self.client.logged_in)
        self.assertEqual(self.client.session_state, 'offline')
        self.assertEqual(self.web.summary['disconnect_requests'], 1)
        self.assertEqual(self.web.submit_calls, 1)
        self.assertEqual(self.web.close_calls, 1)

    def test_logout_accepted_but_still_online_reports_failure_without_second_pod(self):
        self.confirm.return_value = self.logout_report('online')
        self.logout()
        self.assertIs(self.client.auth_diagnostic['request_accepted'], True)
        self.assertNotIn('注销成功', self.client.status)
        self.assertRegex(self.client.status, '失败|未成功')
        self.assertEqual(self.web.summary['disconnect_requests'], 1)
        self.assertEqual(self.web.submit_calls, 1)
        self.confirm.assert_called_once()

    def test_logout_unknown_effect_does_not_turn_accepted_receipt_into_success(self):
        self.confirm.return_value = self.logout_report('unknown')
        self.logout()
        self.assertIs(self.client.auth_diagnostic['request_accepted'], True)
        self.assertNotIn('注销成功', self.client.status)
        self.assertEqual(self.client.session_state, 'unknown')
        self.assertEqual(self.web.summary['disconnect_requests'], 1)
        self.confirm.assert_called_once()

    def test_no_matching_session_with_device_offline_can_end_successfully_without_pod(self):
        self.arrange_no_session()
        self.logout()
        self.confirm.assert_called_once()
        self.assertIn('已下线', self.client.status)
        self.assertNotIn('未发现本机在线会话', self.client.status)
        self.assertEqual(self.client.session_state, 'offline')
        self.assertEqual(self.web.summary['disconnect_requests'], 0)
        self.assertIsNone(self.client.auth_diagnostic['request_accepted'])
        self.assertEqual(self.web.close_calls, 1)

    def test_no_matching_session_with_another_account_online_is_not_logout_success(self):
        self.arrange_no_session()
        self.confirm.return_value = self.logout_report('online', OTHER_ACCOUNT)
        self.store.profiles.reset_mock()
        self.store.selected_profile.reset_mock()
        self.logout()
        self.confirm.assert_called_once()
        self.assertNotIn('注销成功', self.client.status)
        self.assertEqual(self.web.summary['disconnect_requests'], 0)
        self.assertEqual(self.web.login_calls, [(ACCOUNT, PASSWORD)])
        self.store.profiles.assert_not_called()
        self.store.selected_profile.assert_not_called()
        self.client.run_authentication.assert_not_called()

    def test_explicit_status_result_after_network_change_cannot_replace_new_context(self):
        def changed(*args, **kwargs):
            result = self.state_report('offline')
            self.changed_context()
            return result
        self.probe.side_effect = changed
        self.execute(self.client.refresh_status)
        self.assert_new_context_preserved()

    def test_login_check_after_network_change_cannot_replace_new_context(self):
        self.arrange_login()
        def changed(*args, **kwargs):
            result = self.state_report('online')
            self.changed_context()
            return result
        self.probe.side_effect = changed
        self.login()
        self.assert_new_context_preserved()
        self.assertIs(self.client.auth_diagnostic['request_accepted'], True)

    def test_logout_confirmation_after_network_change_cannot_mark_new_context_offline(self):
        def changed(*args, **kwargs):
            result = self.logout_report('offline')
            self.changed_context()
            return result
        self.confirm.side_effect = changed
        self.logout()
        self.assert_new_context_preserved()
        self.assertIs(self.client.auth_diagnostic['request_accepted'], True)
        self.assertEqual(self.web.summary['disconnect_requests'], 1)

    def test_no_match_confirmation_after_network_change_cannot_replace_new_context(self):
        self.arrange_no_session()
        def changed(*args, **kwargs):
            result = self.logout_report('offline')
            self.changed_context()
            return result
        self.confirm.side_effect = changed
        self.logout()
        self.assert_new_context_preserved()
        self.assertEqual(self.web.summary['disconnect_requests'], 0)

    def poll_a_changed_network(self):
        """Use the real monitor path; do not manufacture replacement feedback."""
        next_ssid = core.TEC if self.wifi.student else core.STU
        self.current = replace(self.wifi, ssid=next_ssid, ip='10.61.55.10')
        self.client.poll_wifi()

    def seed_verified_previous_state(self):
        self.client.logged_in = True
        self.client.session_state = 'online'
        self.client.online_account = ACCOUNT
        self.client.identity_source = 'verified_status'
        self.client.auth_key = self.wifi.key

    def assert_polled_change_ends_without_stale_progress(self):
        snapshot = self.client.get_state()
        self.assertFalse(self.client.busy)
        self.assertFalse(snapshot['busy'])
        self.assertEqual(self.client.wifi, self.current)
        self.assertEqual(snapshot['ssid'], self.current.ssid)
        self.assertEqual(snapshot['session_state'], 'unknown')
        self.assertFalse(snapshot['logged_in'])
        self.assertEqual(snapshot['online_account'], '')
        for progress in ('正在确认', '正在检测', '正在登录', '正在注销'):
            self.assertNotIn(progress, snapshot['status'])

    def test_real_wifi_poll_during_login_confirmation_clears_stale_progress(self):
        self.seed_verified_previous_state()
        self.arrange_login()
        def changed(*args, **kwargs):
            result = self.state_report('online')
            self.poll_a_changed_network()
            return result
        self.probe.side_effect = changed
        self.login()
        self.assert_polled_change_ends_without_stale_progress()
        self.assertIs(self.client.auth_diagnostic['request_accepted'], True)
        self.client.run_authentication.assert_called_once()

    def test_real_wifi_poll_during_logout_confirmation_clears_stale_progress(self):
        self.seed_verified_previous_state()
        def changed(*args, **kwargs):
            result = self.logout_report('offline')
            self.poll_a_changed_network()
            return result
        self.confirm.side_effect = changed
        self.logout()
        self.assert_polled_change_ends_without_stale_progress()
        self.assertIs(self.client.auth_diagnostic['request_accepted'], True)
        self.assertEqual(self.web.summary['disconnect_requests'], 1)
        self.assertEqual(self.web.submit_calls, 1)

    def test_real_wifi_poll_during_manual_status_clears_stale_progress_and_keeps_old_receipt(self):
        self.seed_verified_previous_state()
        self.client.auth_diagnostic = {'operation': 'login', 'result': True, 'request_accepted': True}
        def changed(*args, **kwargs):
            result = self.state_report('online')
            self.poll_a_changed_network()
            return result
        self.probe.side_effect = changed
        self.execute(self.client.refresh_status)
        self.assert_polled_change_ends_without_stale_progress()
        self.assertIs(self.client.auth_diagnostic['request_accepted'], True)
        self.assertIs(self.client.auth_diagnostic['result'], True)
        self.client.run_authentication.assert_not_called()
        self.service_factory.assert_not_called()

    def no_session_with_unconfirmed_aggregate(self, account):
        self.arrange_no_session()
        self.probe.return_value = self.state_report('online', account)
        conflicting = self.logout_report('unknown')
        conflicting['status'] = self.state_report('online', account)
        self.confirm.return_value = conflicting
        self.logout()
        self.confirm.assert_called_once()
        self.assertEqual(self.client.session_state, 'unknown')
        self.assertFalse(self.client.logged_in)
        self.assertEqual(self.client.online_account, '')
        self.assertIn('无法确认', self.client.status)
        self.assertNotIn('设备仍在线', self.client.status)
        self.assertNotIn('注销成功', self.client.status)
        self.assertEqual(self.client.logout_diagnostic['outcome'], 'unknown')
        self.assertEqual(self.web.summary['disconnect_requests'], 0)
        self.assertIsNone(self.client.auth_diagnostic['request_accepted'])
        self.assertEqual(self.web.login_calls, [(ACCOUNT, PASSWORD)])

    def test_no_session_same_uid_portal_online_does_not_override_unknown_aggregate(self):
        self.no_session_with_unconfirmed_aggregate(ACCOUNT)

    def test_no_session_unidentified_portal_online_does_not_override_unknown_aggregate(self):
        self.no_session_with_unconfirmed_aggregate('')

    def test_get_state_remains_an_in_memory_snapshot(self):
        for _ in range(5):
            self.client.get_state()
        self.probe.assert_not_called()
        self.confirm.assert_not_called()
        self.reader.assert_not_called()
        self.service_factory.assert_not_called()


class TeacherVerifiedStatusActionTests(VerifiedStatusActionTests):
    SSID = core.TEC


if __name__ == '__main__':
    unittest.main()
