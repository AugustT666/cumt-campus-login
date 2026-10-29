"""Campus-wide reminders and one-attempt automation, with fictional local fixtures.

No real Store, registry, WiFi interface, credential file or authentication is used.
"""
from dataclasses import replace
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import campus_app as app
import campus_core as core


HOTSPOT = core.Wifi('Fictional hotspot', 'campus-both-fixture', 7,
                    '10.221.10.8', '00-11-22-33-44-55', '10.221.10.1')
STU = replace(HOTSPOT, ssid=core.STU, ip='10.52.140.8', gateway='10.52.140.1')
TEC = replace(HOTSPOT, ssid=core.TEC, ip='10.61.140.8', gateway='10.61.140.1')
ACCOUNT, PASSWORD = 'fictional-campus-user', 'fictional-campus-password'


class CampusBothFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.store = MagicMock()
        self.store.root = Path(temporary.name)
        self.store.load.return_value = {
            'operator': 'campus', 'stu_autostart': True, 'quiet_hours': False,
            'trusted_hosts': [core.KNOWN_HOST], 'portal_hint': ''}
        self.store.selected_profile.return_value = {
            'id': 'fictional-profile', 'account': ACCOUNT,
            'password': PASSWORD, 'operator': 'campus'}
        with patch.object(core, 'Store', return_value=self.store):
            self.client = app.App(runtime_log=MagicMock())
        self.client.window = MagicMock()
        self.client.window.native = None
        self.client.wifi = HOTSPOT
        self.enterContext(patch.object(app, 'stable_autostart_configured', return_value=False))
        self.enterContext(patch.object(app, 'stable_instance_running', return_value=False))
        self.enterContext(patch.object(socket.socket,'connect',
            side_effect=AssertionError('No real sockets in campus automation tests')))
        self.probes=self.enterContext(patch.object(core,'internet_check',
            side_effect=AssertionError('No network effect checks in the application')))


class CampusBothPopupTests(CampusBothFixture):
    def setUp(self):
        super().setUp()
        self.client.login = MagicMock(return_value={'ok': True})

    def poll(self, *snapshots):
        with patch.object(core, 'read_wifi', side_effect=snapshots):
            for _ in snapshots:
                self.client.poll_wifi()

    def test_teacher_connection_shows_and_uses_selected_profile_once(self):
        self.poll(TEC, TEC, TEC)
        self.client.window.show.assert_called_once()
        self.client.login.assert_called_once_with(
            ACCOUNT, PASSWORD, 'campus', 'fictional-profile', automatic=True, expected=TEC)

    def test_teacher_selected_profile_can_have_empty_operator(self):
        self.store.selected_profile.return_value['operator'] = ''
        self.poll(TEC, TEC)
        self.client.login.assert_called_once_with(
            ACCOUNT, PASSWORD, '', 'fictional-profile', automatic=True, expected=TEC)

    def test_teacher_disabled_option_never_shows_or_reads_profile(self):
        self.client.settings['stu_autostart'] = False
        self.poll(TEC, STU, HOTSPOT, TEC)
        self.client.window.show.assert_not_called()
        self.client.login.assert_not_called()
        self.store.selected_profile.assert_not_called()

    def test_teacher_without_profile_still_shows_but_does_not_authenticate(self):
        self.store.selected_profile.return_value = {}
        self.poll(TEC, TEC, TEC)
        self.client.window.show.assert_called_once()
        self.client.login.assert_not_called()
        self.store.selected_profile.assert_called_once()

    def test_teacher_rejected_attempt_is_not_repeated_by_polling(self):
        self.client.login.return_value = {'ok': False, 'message': 'fictional rejection'}
        self.poll(TEC, TEC, TEC, TEC)
        self.client.login.assert_called_once()
        self.assertTrue(self.client.auto_attempted)

    def test_teacher_busy_operation_does_not_prevent_popup_or_consume_attempt(self):
        self.client.busy = True
        self.poll(TEC, TEC)
        self.client.window.show.assert_called_once()
        self.client.login.assert_not_called()
        self.assertFalse(self.client.auto_attempted)
        self.client.busy = False
        self.poll(TEC, TEC)
        self.client.login.assert_called_once()
        self.client.window.show.assert_called_once()

    def test_teacher_dhcp_renewal_is_not_a_second_connection(self):
        renewed = replace(TEC, ip='10.61.140.9')
        self.poll(TEC, TEC, renewed, renewed)
        self.client.window.show.assert_called_once()
        self.client.login.assert_called_once()

    def test_same_interface_stu_teacher_transitions_each_get_one_attempt(self):
        self.poll(STU, STU, TEC, TEC, STU, STU)
        self.assertEqual(self.client.window.show.call_count, 3)
        self.assertEqual(self.client.login.call_count, 3)
        self.assertEqual([call.kwargs['expected'].ssid
                          for call in self.client.login.call_args_list],
                         [core.STU, core.TEC, core.STU])

    def test_ssid_transition_with_reused_address_is_still_a_new_connection(self):
        teacher_same_lease = replace(STU, ssid=core.TEC)
        self.poll(STU, STU, teacher_same_lease, teacher_same_lease, STU, STU)
        self.assertEqual(self.client.window.show.call_count, 3)
        self.assertEqual(self.client.login.call_count, 3)

    def test_teacher_same_ssid_reconnect_waits_for_stability_then_attempts_once(self):
        self.client.wifi = TEC
        self.client.auto_attempted = True
        self.client.notifications = MagicMock()
        self.client.notifications.drain.side_effect = [
            [(20, TEC.guid), (21, TEC.guid), (10, TEC.guid)], [], []]
        self.poll(TEC)
        self.client.window.show.assert_called_once()
        self.client.login.assert_not_called()
        self.poll(TEC, TEC)
        self.client.window.show.assert_called_once()
        self.client.login.assert_called_once()

    def test_enabling_while_already_on_teacher_network_does_not_submit(self):
        self.client.settings['stu_autostart'] = False
        self.client.wifi = core.Wifi()
        key = MagicMock()
        key.__enter__.return_value = key
        with patch.object(core, 'read_wifi', return_value=TEC), \
             patch.object(app.winreg, 'CreateKey', return_value=key), \
             patch.object(app.winreg, 'SetValueEx'):
            self.assertTrue(self.client.set_startup(True)['ok'])
            self.client.poll_wifi()
            self.client.poll_wifi()
        self.client.window.show.assert_not_called()
        self.client.login.assert_not_called()

    def test_teacher_carried_hotspot_lease_waits_before_authentication(self):
        carried = replace(HOTSPOT, ssid=core.TEC)
        self.poll(carried, carried)
        self.client.window.show.assert_called_once()
        self.client.login.assert_not_called()
        self.assertFalse(self.client.auto_attempted)
        self.poll(TEC, TEC)
        self.client.login.assert_called_once()


class CampusBothLoginGuardTests(CampusBothFixture):
    def setUp(self):
        super().setUp()
        self.current = TEC
        self.client.wifi = TEC
        self.engine = MagicMock()
        self.engine.status.side_effect=AssertionError('No retired status preflight')
        self.client.session_engine = MagicMock(return_value=self.engine)
        self.client.run_authentication = MagicMock(return_value=False)
        self.client.save_profile = MagicMock(return_value={'ok': True})

        def run_job(kind, job, automatic=False):
            self.client.auto_job = automatic
            try:
                job()
                return {'ok': True}
            finally:
                self.client.auto_job = False
        self.client.start_job = run_job
        self.enterContext(patch.object(core, 'read_wifi', side_effect=lambda: self.current))

    def login(self, operator='', **kwargs):
        return self.client.login(ACCOUNT, PASSWORD, operator,
                                 automatic=True, expected=self.current, **kwargs)

    def test_teacher_expected_network_guard_allows_exact_teacher_network(self):
        self.assertTrue(self.login()['ok'])
        self.client.run_authentication.assert_called_once()
        self.assertEqual(self.client.run_authentication.call_args.args[:6],
                         (TEC, ACCOUNT, PASSWORD, '', 'login', True))
        self.client.save_profile.assert_not_called()

    def test_teacher_effective_operator_is_empty_even_for_saved_carrier_profile(self):
        self.assertTrue(self.login(operator='telecom')['ok'])
        self.assertEqual(self.client.run_authentication.call_args.args[3], '')

    def test_teacher_is_not_blocked_by_student_quiet_hours(self):
        self.client.settings['quiet_hours'] = True
        with patch.object(core, 'quiet_hours', return_value=True):
            self.assertTrue(self.login()['ok'])
        self.client.run_authentication.assert_called_once()

    def test_student_quiet_hours_still_block_automatic_submission(self):
        self.current = STU
        self.client.wifi = STU
        self.client.settings['quiet_hours'] = True
        with patch.object(core, 'quiet_hours', return_value=True):
            with self.assertRaisesRegex(RuntimeError, '不可认证时间'):
                self.login(operator='campus', quiet_override=True)
        self.client.run_authentication.assert_not_called()

    def test_disabled_teacher_authorization_stops_before_preflight(self):
        self.client.settings['stu_autostart'] = False
        self.assertFalse(self.login()['ok'])
        self.client.session_engine.assert_not_called()
        self.client.run_authentication.assert_not_called()

    def test_non_campus_network_never_gets_teacher_automatic_permission(self):
        self.current = HOTSPOT
        self.client.wifi = HOTSPOT
        self.assertFalse(self.login()['ok'])
        self.client.run_authentication.assert_not_called()

    def test_teacher_login_sends_one_action_without_querying_status(self):
        self.assertTrue(self.login()['ok'])
        self.client.run_authentication.assert_called_once()
        self.engine.status.assert_not_called()
        self.probes.assert_not_called()

    def preflight_mutation(self, mutate):
        wire=[]
        def authenticate(*args,before_submit=None,**kwargs):
            mutate()
            before_submit()
            wire.append('credential-submission')
            return False,{'operation':'login','authentication_requests':1,'result':False}
        self.engine.authenticate.side_effect=authenticate
        self.client.run_authentication=MagicMock(wraps=app.App.run_authentication.__get__(self.client,app.App))
        with self.assertRaises(RuntimeError):
            self.login()
        self.client.run_authentication.assert_called_once()
        self.engine.prepare.assert_called_once()
        self.engine.authenticate.assert_called_once()
        self.engine.status.assert_not_called()
        self.probes.assert_not_called()
        self.assertEqual(wire,[])

    def test_cancel_during_teacher_preflight_stops_before_submission(self):
        self.preflight_mutation(self.client.cancel.set)

    def test_quit_during_teacher_preflight_stops_before_submission(self):
        self.preflight_mutation(self.client.closed.set)

    def test_authorization_withdrawn_during_teacher_preflight_stops_submission(self):
        self.preflight_mutation(lambda: self.client.settings.update(stu_autostart=False))

    def test_ssid_change_during_teacher_preflight_stops_submission(self):
        self.preflight_mutation(lambda: setattr(self, 'current', STU))

    def test_address_change_during_teacher_preflight_stops_submission(self):
        self.preflight_mutation(lambda: setattr(self, 'current', replace(TEC, ip='10.61.140.9')))

    def test_mac_change_before_teacher_wire_stops_submission(self):
        changed=replace(TEC,mac='00-11-22-33-44-66')
        self.assertEqual(changed.key,TEC.key)
        self.preflight_mutation(lambda:setattr(self,'current',changed))

    def test_gateway_change_before_teacher_wire_stops_submission(self):
        changed=replace(TEC,gateway='10.61.140.2')
        self.assertEqual(changed.key,TEC.key)
        self.preflight_mutation(lambda:setattr(self,'current',changed))


if __name__ == '__main__':
    unittest.main()
