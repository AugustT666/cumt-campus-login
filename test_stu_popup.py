"""STU connection reminders; fake WLAN/window/store, no real network or account."""
from dataclasses import replace
import os
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, call, patch

import campus_app as app
import campus_core as core


HOTSPOT=core.Wifi('Fixture hotspot','fixture-interface',7,'10.221.10.8',
                  '00-11-22-33-44-55','10.221.10.1')
STU=core.Wifi(core.STU,HOTSPOT.guid,HOTSPOT.index,'10.52.140.8',
              HOTSPOT.mac,'10.52.140.1')


class StuPopupTests(unittest.TestCase):
    def setUp(self):
        self.client=app.App.__new__(app.App)
        self.client.lock=threading.RLock()
        self.client.closed=threading.Event()
        self.client.cancel=threading.Event()
        self.client.wifi=HOTSPOT
        self.client.window=MagicMock()
        self.client.startup=False
        self.client.settings={'stu_autostart':True}
        self.client.busy=False
        self.client.auto_job=False
        self.client.auto_attempted=False
        self.client.auth_key=None
        self.client.portal_key=None
        self.client.session_cookies=[]
        self.client.notifications=None
        self.client.reconnecting=set()
        self.client.status=''
        self.client.messages=[]
        self.client.store=MagicMock()
        self.client.store.selected_profile.return_value={
            'id':'fixture-profile','account':'fixture-user',
            'password':'fixture-password','operator':'campus'}
        self.client.login=MagicMock(return_value={'ok':True})
        self.client.record=MagicMock()
        self.client.record_exception=MagicMock()

    def poll(self,*snapshots):
        with patch.object(core,'read_wifi',side_effect=snapshots):
            for _ in snapshots:
                self.client.poll_wifi()

    def test_connection_popup_does_not_wait_for_busy_authentication(self):
        self.client.busy=True
        self.poll(STU,STU)
        self.client.window.show.assert_called_once()
        self.client.login.assert_not_called()
        self.assertFalse(self.client.auto_attempted)
        self.client.busy=False
        self.poll(STU)
        self.client.login.assert_called_once()
        self.client.window.show.assert_called_once()

    def test_popup_does_not_require_a_saved_profile(self):
        self.client.store.selected_profile.return_value={}
        self.poll(STU,STU)
        self.client.window.show.assert_called_once()
        self.client.login.assert_not_called()
        self.client.store.selected_profile.assert_called_once()
        self.assertTrue(any(c.args[0]=='network.auto_login_skipped'
                            for c in self.client.record.call_args_list))

    def test_profile_read_error_cannot_prevent_the_popup(self):
        self.client.store.selected_profile.side_effect=RuntimeError('fixture store unavailable')
        self.poll(STU)
        self.client.window.show.assert_called_once()
        self.client.login.assert_not_called()
        self.client.record_exception.assert_called_once()

    def test_disabled_option_never_shows_or_authenticates(self):
        self.client.settings['stu_autostart']=False
        self.poll(STU,HOTSPOT,STU)
        self.client.window.show.assert_not_called()
        self.client.login.assert_not_called()
        self.client.store.selected_profile.assert_not_called()

    def test_manual_launch_on_stu_preserves_its_existing_visible_window(self):
        self.client.wifi=core.Wifi()
        self.poll(STU,STU)
        self.client.window.show.assert_not_called()
        self.client.window.restore.assert_not_called()

    def test_hidden_windows_startup_shows_on_initial_stu(self):
        self.client.wifi=core.Wifi()
        self.client.startup=True
        self.poll(STU,STU)
        self.client.window.show.assert_called_once()
        self.client.window.restore.assert_called_once()

    def test_window_not_created_keeps_the_connection_reminder_pending(self):
        self.client.window=None
        self.poll(STU)
        self.assertTrue(self.client._stu_popup_pending)
        self.client.window=MagicMock()
        self.poll(STU,STU)
        self.client.window.show.assert_called_once()
        self.assertFalse(self.client._stu_popup_pending)

    def test_dhcp_change_does_not_show_or_submit_twice(self):
        renewed=replace(STU,ip='10.52.140.9')
        self.poll(STU,renewed,renewed)
        self.client.window.show.assert_called_once()
        self.client.login.assert_called_once()

    def test_new_connection_shows_once_even_if_address_is_reused(self):
        self.poll(STU,HOTSPOT,STU,STU)
        self.assertEqual(self.client.window.show.call_count,2)
        self.assertEqual(self.client.login.call_count,2)

    def test_notification_reconnect_shows_before_auth_address_is_stable(self):
        self.client.wifi=STU
        self.client.auto_attempted=True
        self.client.notifications=MagicMock()
        self.client.notifications.drain.side_effect=[
            [(20,STU.guid),(21,STU.guid),(10,STU.guid)],[],[]]
        self.poll(STU)
        self.client.window.show.assert_called_once()
        self.client.login.assert_not_called()
        self.assertFalse(self.client.auto_attempted)
        self.poll(STU,STU)
        self.client.window.show.assert_called_once()
        self.client.login.assert_called_once()

    def test_disconnect_pending_does_not_show_or_consume_auto_attempt(self):
        self.client.wifi=STU
        self.client.auto_attempted=True
        self.client.notifications=MagicMock()
        self.client.notifications.drain.side_effect=[[(21,STU.guid)],[(10,STU.guid)],[]]
        self.poll(STU)
        self.client.window.show.assert_not_called()
        self.client.login.assert_not_called()
        self.poll(STU)
        self.client.window.show.assert_called_once()
        self.client.login.assert_not_called()
        self.poll(STU)
        self.client.login.assert_called_once()

    def test_carried_hotspot_private_address_does_not_consume_authentication(self):
        carried=replace(HOTSPOT,ssid=core.STU)
        self.poll(carried,carried,carried)
        self.client.window.show.assert_called_once()
        self.client.login.assert_not_called()
        self.assertFalse(self.client.auto_attempted)
        self.assertTrue(self.client._stu_network_pending)
        self.poll(STU)
        self.client.login.assert_not_called()
        self.poll(STU)
        self.client.login.assert_called_once()
        self.client.window.show.assert_called_once()
        self.assertFalse(self.client._stu_network_pending)

    def test_carried_gateway_waits_for_complete_dhcp_context(self):
        partial=replace(STU,gateway=HOTSPOT.gateway)
        self.poll(partial,partial)
        self.client.login.assert_not_called()
        self.assertFalse(self.client.auto_attempted)
        self.poll(STU,STU)
        self.client.login.assert_called_once()

    def test_public_or_missing_stu_address_still_shows_without_authentication(self):
        for ip in ('','8.8.8.8','169.254.5.8'):
            with self.subTest(ip=ip):
                self.client.wifi=HOTSPOT
                self.client.auto_attempted=False
                self.client._stu_popup_connection=None
                self.client.window.reset_mock()
                invalid=replace(STU,ip=ip)
                self.poll(invalid,invalid)
                self.client.window.show.assert_called_once()
                self.client.login.assert_not_called()
                self.assertFalse(self.client.auto_attempted)

    def test_option_can_enable_reminders_without_reading_credentials(self):
        key=MagicMock()
        key.__enter__.return_value=key
        self.client.settings['stu_autostart']=False
        self.client.store.selected_profile.return_value={}
        with patch.object(core,'read_wifi',return_value=HOTSPOT), \
             patch.object(app.winreg,'CreateKey',return_value=key), \
             patch.object(app.winreg,'SetValueEx') as write:
            self.assertTrue(self.client.set_startup(True)['ok'])
        self.assertTrue(self.client.settings['stu_autostart'])
        self.client.store.selected_profile.assert_not_called()
        self.assertIn('--startup',write.call_args.args[-1])

    def test_enabling_while_already_on_stu_does_not_popup_or_authenticate(self):
        self.client.wifi=core.Wifi()
        key=MagicMock()
        key.__enter__.return_value=key
        with patch.object(core,'read_wifi',return_value=STU), \
             patch.object(app.winreg,'CreateKey',return_value=key), \
             patch.object(app.winreg,'SetValueEx'):
            self.assertTrue(self.client.set_startup(True)['ok'])
            self.client.poll_wifi()
        self.client.window.show.assert_not_called()
        self.client.login.assert_not_called()

    def native_user(self,owner=None):
        self.client.window.native=SimpleNamespace(Handle=31337)
        user=MagicMock()
        def owner_pid(hwnd,pid):
            pid._obj.value=os.getpid() if owner is None else owner
            return 7
        user.GetWindowThreadProcessId.side_effect=owner_pid
        user.IsWindowVisible.return_value=True
        user.IsIconic.return_value=False
        user.GetForegroundWindow.return_value=31337
        return user

    def test_show_window_verifies_native_visibility_and_foreground(self):
        user=self.native_user()
        with patch.object(app.ctypes,'WinDLL',return_value=user):
            result=self.client.show_window()
        self.assertTrue(result['native_verified'])
        self.assertTrue(result['visible'])
        self.assertTrue(result['foreground'])
        user.ShowWindow.assert_not_called()
        self.assertEqual(self.client.window.method_calls[:2],[call.restore(),call.show()])

    def test_one_native_recovery_restores_a_minimized_or_hidden_window(self):
        user=self.native_user()
        user.IsWindowVisible.side_effect=[False,True]
        user.IsIconic.side_effect=[True,False]
        user.GetForegroundWindow.side_effect=[0,31337]
        with patch.object(app.ctypes,'WinDLL',return_value=user):
            result=self.client.show_window()
        self.assertTrue(result['recovery_attempted'])
        self.assertTrue(result['visible'])
        self.assertTrue(result['foreground'])
        self.assertFalse(result['minimized'])
        user.ShowWindow.assert_called_once_with(31337,9)
        user.BringWindowToTop.assert_called_once_with(31337)
        user.SetForegroundWindow.assert_called_once_with(31337)

    def test_windows_focus_denial_is_reported_without_repeated_recovery(self):
        user=self.native_user()
        user.GetForegroundWindow.return_value=99
        with patch.object(app.ctypes,'WinDLL',return_value=user):
            result=self.client.show_window()
        self.assertTrue(result['visible'])
        self.assertFalse(result['foreground'])
        user.ShowWindow.assert_called_once()
        completed=next(c for c in self.client.record.call_args_list if c.args[0]=='window.show_completed')
        self.assertEqual(completed.kwargs['level'],'WARNING')

    def test_foreign_native_handle_is_not_restored_or_activated(self):
        user=self.native_user(owner=os.getpid()+1)
        with patch.object(app.ctypes,'WinDLL',return_value=user):
            result=self.client.show_window()
        self.assertFalse(result['native_verified'])
        user.ShowWindow.assert_not_called()
        user.SetForegroundWindow.assert_not_called()

    def test_window_or_native_probe_errors_are_recorded_without_crashing_monitor(self):
        self.client.window.restore.side_effect=RuntimeError('fixture UI failure')
        self.assertFalse(self.client.show_window()['shown'])
        self.client.record_exception.assert_called_once()
        self.client.record_exception.reset_mock()
        self.client.window.restore.side_effect=None
        self.client.window.native=SimpleNamespace(Handle=31337)
        with patch.object(app.ctypes,'WinDLL',side_effect=OSError('fixture native API unavailable')):
            self.assertTrue(self.client.show_window()['shown'])
        self.client.record_exception.assert_called_once()


if __name__=='__main__':
    unittest.main()
