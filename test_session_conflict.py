"""Conflicting session evidence must never authorize a blind repeat submission.

All identities, addresses and responses are fictional. Store, WLAN and probes
are mocked; the real logger writes only to an isolated temporary directory.
"""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import zipfile

import campus_app as app
import campus_core as core
import campus_selfservice as selfservice
from campus_logging import RuntimeLog


TEC = core.Wifi(core.TEC, 'conflict-fixture', 7, '10.61.20.8',
                '00-11-22-33-44-55')
ACCOUNT, PASSWORD = 'fictional-selected-account', 'fictional-selected-password'


def conflict(detail='session_ip_mismatch'):
    return {'state': 'unknown', 'matched_ip': True, 'binding': 'conflict',
            'detail': detail, 'ip_conflict': True, 'mac_conflict': False,
            'online_account': 'fictional-unverified-server-account'}


def offline():
    return {'state': 'offline', 'matched_ip': True, 'binding': 'source_ip_only',
            'detail': 'server_confirmed'}


def online():
    return {'state': 'online', 'matched_ip': True, 'binding': 'mac_verified',
            'detail': 'server_confirmed',
            'online_account': 'fictional-confirmed-server-account'}


class ConflictFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.store = MagicMock()
        self.store.root = Path(temporary.name)
        self.store.load.return_value = {
            'quiet_hours': False, 'stu_autostart': True, 'operator': '',
            'trusted_hosts': [core.KNOWN_HOST], 'portal_hint': ''}
        self.store.profiles.return_value = {'selected': '', 'profiles': []}
        self.reader = self.enterContext(patch.object(core, 'read_wifi', return_value=TEC))
        self.enterContext(patch.object(app, 'stable_autostart_configured', return_value=False))
        self.enterContext(patch.object(app, 'stable_instance_running', return_value=False))
        self.log = RuntimeLog(self.store.root, core.VERSION)
        self.addCleanup(self.log.close)
        with patch.object(core, 'Store', return_value=self.store):
            self.client = app.App(runtime_log=self.log)
        self.client.wifi = TEC
        self.client.window = MagicMock()
        self.client.save_profile = MagicMock(return_value={'ok': True})
        self.engine = MagicMock()
        self.engine.status.return_value = conflict()
        self.client.session_engine = MagicMock(return_value=self.engine)
        self.client.run_authentication = MagicMock(side_effect=self.accept)
        self.client.check_internet_later = MagicMock()
        self.client.check_unconfirmed_internet_later = MagicMock()
        self.client.operation_id = 'fixture-initial'
        self.jobs = 0
        self.client.start_job = self.inline_job
        self.client._launch_logout_verification = MagicMock()
        self.tick = 100.0
        self.enterContext(patch.object(app.time, 'monotonic', side_effect=lambda: self.tick))
        self.client._logout_wait = lambda seconds: setattr(self, 'tick', self.tick + seconds)
        self.enterContext(patch.object(core, 'internet_check', return_value={'online': False, 'checks': []}))
        self.service_client = self.enterContext(patch.object(selfservice, 'Client',
            side_effect=AssertionError('No live self-service in conflict tests')))
        self.enterContext(patch.object(socket.socket, 'connect',
            side_effect=AssertionError('No live sockets in conflict tests')))

    def inline_job(self, kind, job, automatic=False):
        self.jobs += 1
        self.client.operation_id = 'fixture-operation-' + str(self.jobs)
        self.client.auto_job = automatic
        self.client.cancel.clear()
        job()
        self.client.auto_job = False
        return {'ok': True}

    def accept(self, *args):
        self.client.auth_diagnostic = {
            'operation': 'login', 'backend': 'verified_drcom_http',
            'phase': 'response_received', 'authentication_requests': 1,
            'result': True, 'response': {'result': '1', 'msg': '认证成功'}}
        return True

    def login(self, automatic=False):
        return self.client.login(ACCOUNT, PASSWORD, '', automatic=automatic,
                                 expected=TEC if automatic else None)

    def events(self, name):
        return [row for line in self.log.path.read_text(encoding='utf-8').splitlines()
                if (row := json.loads(line)).get('event') == name]


class SessionConflictTests(ConflictFixture):
    def test_only_unknown_conflict_evidence_triggers_binding_gate(self):
        for report in (conflict(), conflict('session_mac_mismatch'),
                       conflict('status_ip_mismatch'),
                       {'state': 'unknown', 'binding': 'conflict'},
                       {'state': 'unknown', 'detail': 'session_ip_mismatch'}):
            with self.subTest(report=report):
                self.assertTrue(app.App.session_binding_conflict(report))
        for report in (offline(), online(), {'state': 'unknown'},
                       {'state': 'unknown', 'detail': 'status_unreachable'}):
            with self.subTest(report=report):
                self.assertFalse(app.App.session_binding_conflict(report))

    def test_manual_conflict_preflight_sends_nothing_and_explains_next_step(self):
        self.client.auth_diagnostic = {'authentication_requests': 1, 'phase': 'old_attempt'}
        self.assertTrue(self.login()['ok'])
        self.client.run_authentication.assert_not_called()
        self.assertEqual(self.client.auth_diagnostic['authentication_requests'], 0)
        self.assertEqual(self.client.session_state, 'unknown')
        self.assertFalse(self.client.logged_in)
        self.assertIn('自助服务', self.client.status)
        self.assertIn('未发送', self.client.status)
        self.assertNotIn('密码错误', self.client.status)

    def test_automatic_conflict_preflight_also_sends_nothing(self):
        self.assertTrue(self.login(automatic=True)['ok'])
        self.client.run_authentication.assert_not_called()
        self.assertEqual(self.client.auth_diagnostic['authentication_requests'], 0)
        self.assertIn('自助服务', self.client.status)

    def test_all_explicit_conflict_details_block_authentication(self):
        for detail in ('session_ip_mismatch', 'session_mac_mismatch', 'status_ip_mismatch'):
            with self.subTest(detail=detail):
                self.engine.status.return_value = conflict(detail)
                self.login()
                self.client.run_authentication.assert_not_called()

    def test_refresh_conflict_does_not_adopt_unverified_server_identity(self):
        self.client.refresh_status()
        self.assertEqual(self.client.session_state, 'unknown')
        self.assertEqual(self.client.online_account, '')
        self.assertEqual(self.client.identity_source, '')
        self.assertIn('自助服务', self.client.status)
        self.client.run_authentication.assert_not_called()

    def test_conflict_is_exposed_to_the_ui_without_claiming_online(self):
        self.client.refresh_status()
        with patch.object(app.App, 'startup_enabled', return_value=False):
            state = self.client.get_state()
        self.assertTrue(state['session_conflict'])
        self.assertFalse(state['logged_in'])
        self.assertEqual(state['online_account'], '')

    def test_plain_unknown_still_allows_one_explicit_manual_attempt(self):
        self.engine.status.return_value = {'state': 'unknown', 'detail': 'status_unconfirmed'}
        self.client.run_authentication.side_effect = lambda *args: None
        self.login()
        self.client.run_authentication.assert_called_once()
        self.assertEqual(self.client.session_state, 'unknown')

    def test_plain_unknown_automatic_attempt_still_stops(self):
        self.engine.status.return_value = {'state': 'unknown', 'detail': 'status_unconfirmed'}
        self.login(automatic=True)
        self.client.run_authentication.assert_not_called()

    def test_already_online_remains_status_only(self):
        self.engine.status.return_value = online()
        self.login()
        self.client.run_authentication.assert_not_called()
        self.assertTrue(self.client.logged_in)
        self.assertEqual(self.client.online_account, online()['online_account'])

    def test_genuinely_offline_session_can_authenticate_normally(self):
        self.engine.status.side_effect = [offline(), online()]
        self.login()
        self.client.run_authentication.assert_called_once()
        self.assertEqual(self.client.session_state, 'online')
        self.client.check_unconfirmed_internet_later.assert_not_called()

    def test_conflict_logout_sends_no_logout_and_records_preflight_block(self):
        self.client.auth_diagnostic = {'authentication_requests': 1, 'operation': 'login'}
        self.client.logout()
        self.client.run_authentication.assert_not_called()
        self.service_client.assert_not_called()
        self.assertEqual(self.client.auth_diagnostic['authentication_requests'], 0)
        self.assertEqual(self.client.auth_diagnostic['selfservice_logout_requests'], 0)
        self.assertNotEqual(self.client.logout_diagnostic['outcome'], 'offline_confirmed')
        self.assertIn('本次未发送注销请求', self.client.status)
        self.assertIn('自助服务', self.client.status)
        rows = self.events('logout.preflight_blocked')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['fields']['authentication_requests'], 0)

    def test_accepted_then_conflicting_status_retains_acceptance_not_online(self):
        self.engine.status.side_effect = [offline(), conflict()]
        self.login()
        self.client.run_authentication.assert_called_once()
        self.assertEqual(self.client.auth_diagnostic['authentication_requests'], 1)
        self.assertIs(self.client.auth_diagnostic['result'], True)
        self.assertFalse(self.client.logged_in)
        self.assertEqual(self.client.session_state, 'unknown')
        self.assertEqual(self.client.online_account, '')
        self.assertEqual(self.client.identity_source, '')
        self.assertIn('已接受登录', self.client.status)
        self.client.check_unconfirmed_internet_later.assert_called_once_with(TEC, True)

    def test_second_click_after_accepted_conflict_does_not_resubmit(self):
        self.engine.status.side_effect = [offline(), conflict(), conflict()]
        self.login()
        self.login()
        self.client.run_authentication.assert_called_once()
        self.assertEqual(self.client.auth_diagnostic['authentication_requests'], 0)

    def test_accepted_plain_unknown_does_not_start_conflict_probe(self):
        self.engine.status.side_effect = [offline(), {'state': 'unknown', 'detail': 'status_unconfirmed'}]
        self.login()
        self.assertFalse(self.client.logged_in)
        self.assertEqual(self.client.session_state, 'unknown')
        self.assertIs(self.client.auth_diagnostic['result'], True)
        self.client.check_unconfirmed_internet_later.assert_not_called()

    def test_ret_code_two_and_conflict_never_become_authentication_success(self):
        self.engine.status.side_effect = [offline(), conflict()]
        def reject(*args):
            self.client.auth_diagnostic = {
                'operation': 'login', 'authentication_requests': 1, 'result': False,
                'response': {'result': '0', 'ret_code': '2', 'msg': ''}}
            return False
        self.client.run_authentication.side_effect = reject
        self.login()
        self.assertIs(self.client.auth_diagnostic['result'], False)
        self.assertEqual(self.client.auth_diagnostic['response']['ret_code'], '2')
        self.assertEqual(self.client.session_state, 'unknown')
        self.assertFalse(self.client.logged_in)
        self.client.check_unconfirmed_internet_later.assert_not_called()


class UnconfirmedConnectivityTests(ConflictFixture):
    def start_probe(self):
        self.client.session_state = 'unknown'
        self.client.session_diagnostic = conflict()
        self.client.online_account = ''
        self.client.identity_source = ''
        self.client.auth_key = None
        self.client.logged_in = False
        self.client.unconfirmed_connectivity = {}
        self.client.operation_id = 'fixture-accepted-operation'
        method = app.App.check_unconfirmed_internet_later.__get__(self.client, app.App)
        with patch.object(app.threading, 'Thread') as thread:
            method(TEC, True)
            target = thread.call_args.kwargs['target']
        return target

    def test_successful_probe_is_diagnostic_only_and_uses_original_operation(self):
        target = self.start_probe()
        original_status = self.client.status
        def probe(wifi, reader, allow_tec):
            self.assertEqual(wifi, TEC)
            self.assertTrue(allow_tec)
            self.assertEqual(reader(), TEC)
            return {'online': True, 'checks': [{'ok': True}]}
        with patch.object(core, 'internet_check', side_effect=probe):
            target()
        self.assertTrue(self.client.unconfirmed_connectivity['result']['online'])
        self.assertTrue(self.client.unconfirmed_connectivity['authentication_accepted'])
        self.assertEqual(self.client.session_state, 'unknown')
        self.assertFalse(self.client.logged_in)
        self.assertEqual(self.client.online_account, '')
        self.assertEqual(self.client.identity_source, '')
        self.assertEqual(self.client.status, original_status)
        rows = self.events('internet.unconfirmed_result')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['operation_id'], 'fixture-accepted-operation')

    def test_failed_probe_also_cannot_change_session_or_identity(self):
        target = self.start_probe()
        with patch.object(core, 'internet_check', return_value={'online': False, 'checks': []}):
            target()
        self.assertFalse(self.client.unconfirmed_connectivity['result']['online'])
        self.assertEqual(self.client.session_state, 'unknown')
        self.assertFalse(self.client.logged_in)

    def test_probe_evidence_is_exported_separately_in_diagnostic_snapshot(self):
        target = self.start_probe()
        with patch.object(core, 'internet_check', return_value={'online': True, 'checks': []}):
            target()
        exported = self.client.diagnostic()
        self.assertTrue(exported['ok'])
        with zipfile.ZipFile(exported['path']) as bundle:
            snapshot = json.loads(bundle.read('snapshot.json'))
        self.assertTrue(snapshot['unconfirmed_connectivity']['result']['online'])
        self.assertEqual(snapshot['session']['state'], 'unknown')

    def test_probe_exception_is_recorded_without_claiming_connectivity(self):
        target = self.start_probe()
        with patch.object(core, 'internet_check', side_effect=TimeoutError('fictional timeout')):
            target()
        self.assertEqual(self.client.unconfirmed_connectivity, {})
        self.assertFalse(self.client.logged_in)
        self.assertFalse(self.events('internet.unconfirmed_result'))

    def test_preexisting_cancel_exit_or_new_operation_prevents_probe(self):
        for mutation in (lambda: self.client.cancel.set(), lambda: self.client.closed.set(),
                         lambda: setattr(self.client, 'operation_id', 'fixture-next-operation')):
            with self.subTest(mutation=mutation):
                self.client.cancel.clear()
                self.client.closed.clear()
                target = self.start_probe()
                mutation()
                with patch.object(core, 'internet_check') as probe:
                    target()
                probe.assert_not_called()
                self.assertEqual(self.client.unconfirmed_connectivity, {})

    def test_inflight_cancel_exit_or_new_operation_discards_result(self):
        for mutation in (lambda: self.client.cancel.set(), lambda: self.client.closed.set(),
                         lambda: setattr(self.client, 'operation_id', 'fixture-next-operation')):
            with self.subTest(mutation=mutation):
                self.client.cancel.clear()
                self.client.closed.clear()
                target = self.start_probe()
                def probe(*args, **kwargs):
                    mutation()
                    return {'online': True, 'checks': []}
                before = deepcopy(self.client.unconfirmed_connectivity)
                with patch.object(core, 'internet_check', side_effect=probe):
                    target()
                self.assertEqual(self.client.unconfirmed_connectivity, before)
                self.assertFalse(self.client.logged_in)
                self.assertEqual(self.client.session_state, 'unknown')

    def test_inflight_monitor_network_change_discards_result(self):
        target = self.start_probe()
        def probe(*args, **kwargs):
            self.client.wifi = replace(TEC, ip='10.61.20.9')
            return {'online': True, 'checks': []}
        with patch.object(core, 'internet_check', side_effect=probe):
            target()
        self.assertEqual(self.client.unconfirmed_connectivity, {})
        self.assertFalse(self.client.logged_in)

    def test_os_network_change_before_monitor_tick_discards_result(self):
        target = self.start_probe()
        def probe(*args, **kwargs):
            self.reader.return_value = replace(TEC, ip='10.61.20.9')
            return {'online': True, 'checks': []}
        with patch.object(core, 'internet_check', side_effect=probe):
            target()
        self.assertEqual(self.client.unconfirmed_connectivity, {})
        self.assertFalse(self.client.logged_in)

    def test_os_ssid_change_with_same_ip_before_monitor_tick_discards_result(self):
        target = self.start_probe()
        def probe(*args, **kwargs):
            self.reader.return_value = replace(TEC, ssid=core.STU)
            return {'online': True, 'checks': []}
        with patch.object(core, 'internet_check', side_effect=probe):
            target()
        self.assertEqual(self.client.unconfirmed_connectivity, {})
        self.assertFalse(self.client.logged_in)


if __name__ == '__main__':
    unittest.main()
