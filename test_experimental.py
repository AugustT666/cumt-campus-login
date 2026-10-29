"""Experimental data must not use the user's stable profile directory."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

import campus_core as core
import campus_app as app


class ExperimentalProfileTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(app, 'EXPERIMENTAL', True))
        self.enterContext(patch.object(app, 'STARTUP_VALUE_NAME', 'CumtCampusLoginExperimental'))
        self.enterContext(patch.object(app, 'stable_autostart_configured', return_value=False))
        self.enterContext(patch.object(app, 'stable_instance_running', return_value=False))
    def actual_data_root(self, temporary, experimental):
        # The complete offline runner deliberately mocks the parent process's
        # data_root. A fresh process exercises the real function with an
        # explicitly temporary LOCALAPPDATA and imports no GUI or Store.
        environment = dict(os.environ, LOCALAPPDATA=temporary, PYTHONIOENCODING='utf-8')
        script = ('import campus_core as core; '
                  f'core.EXPERIMENTAL_BUILD={experimental!r}; print(core.data_root())')
        result = subprocess.run([sys.executable, '-c', script],
                                cwd=Path(core.__file__).parent, env=environment,
                                capture_output=True, text=True, encoding='utf-8',
                                check=True, timeout=10)
        return Path(result.stdout.strip())

    def test_experimental_build_creates_only_its_own_directory(self):
        with tempfile.TemporaryDirectory() as temporary, \
                patch.dict(os.environ, {'LOCALAPPDATA': temporary}), \
                patch.object(core, 'EXPERIMENTAL_BUILD', True):
            root = self.actual_data_root(temporary, True)
            self.assertEqual(root, Path(temporary) / 'CumtCampusLoginExperimental')
            self.assertTrue(root.is_dir())
            self.assertFalse((Path(temporary) / 'CumtCampusLogin').exists())

    def test_nonexperimental_mode_retains_stable_directory_name(self):
        with tempfile.TemporaryDirectory() as temporary, \
                patch.dict(os.environ, {'LOCALAPPDATA': temporary}), \
                patch.object(core, 'EXPERIMENTAL_BUILD', False):
            self.assertEqual(self.actual_data_root(temporary, False),
                             Path(temporary) / 'CumtCampusLogin')
            self.assertFalse((Path(temporary) / 'CumtCampusLoginExperimental').exists())

    def test_experimental_autostart_writes_only_its_separate_registry_value(self):
        with tempfile.TemporaryDirectory() as temporary:
            client = app.App.__new__(app.App)
            client.store = core.Store(Path(temporary))
            client.settings = {'stu_autostart': False}
            client.record = MagicMock()
            client.record_exception = MagicMock()
            client.busy = False
            client.auto_job = False
            wifi = core.Wifi(core.STU, 'experimental-profile-fixture', 1,
                             '10.52.1.2', '00-11-22-33-44-55')
            with patch.object(core, 'read_wifi', return_value=wifi), \
                    patch.object(app.winreg, 'CreateKey'), \
                    patch.object(app.winreg, 'SetValueEx') as write:
                result = client._set_startup(True)
            self.assertTrue(result['ok'])
            self.assertEqual(write.call_args.args[1], 'CumtCampusLoginExperimental')
            self.assertIn('--experimental', write.call_args.args[-1])
            self.assertTrue(client.settings['stu_autostart'])


class CoexistenceDetectionTests(unittest.TestCase):
    def registry(self, value=None, kind=app.winreg.REG_SZ, error=None):
        self.enterContext(patch.object(app.winreg, 'OpenKey'))
        return self.enterContext(patch.object(app.winreg, 'QueryValueEx',
            side_effect=error, return_value=(value, kind)))

    def test_stable_run_value_is_read_only_and_uses_only_the_stable_name(self):
        query = self.registry('"C:/Stable/campus.exe" --startup')
        with patch.object(app.winreg, 'SetValueEx') as write, \
                patch.object(app.winreg, 'DeleteValue') as delete:
            self.assertTrue(app.stable_autostart_configured())
        self.assertEqual(query.call_args.args[1], 'CumtCampusLogin')
        write.assert_not_called()
        delete.assert_not_called()

    def test_absent_empty_or_nonstring_run_value_is_not_a_conflict(self):
        self.registry(error=FileNotFoundError('fictional absent Run value'))
        self.assertFalse(app.stable_autostart_configured())
        for value in ('', '  ', 1):
            with patch.object(app.winreg, 'QueryValueEx', return_value=(value, app.winreg.REG_SZ)):
                self.assertFalse(app.stable_autostart_configured())

    def test_run_read_failure_is_unconfirmed_not_an_installed_software_claim(self):
        self.registry(error=PermissionError('fictional read denied'))
        with self.assertRaisesRegex(RuntimeError, '无法检查') as caught:
            app.stable_autostart_configured()
        self.assertIsInstance(caught.exception.__cause__, PermissionError)
        self.assertNotIn('正在运行', str(caught.exception))

    def kernel(self, handle, error):
        kernel = MagicMock()
        kernel.OpenMutexW.return_value = handle
        self.enterContext(patch.object(app.ctypes, 'WinDLL', return_value=kernel))
        self.enterContext(patch.object(app.ctypes, 'set_last_error'))
        self.enterContext(patch.object(app.ctypes, 'get_last_error', return_value=error))
        return kernel

    def test_stable_instance_probe_opens_and_closes_without_creating_a_mutex(self):
        kernel = self.kernel(123, 0)
        self.assertTrue(app.stable_instance_running())
        kernel.OpenMutexW.assert_called_once_with(0x00100000, False, r'Local\CumtCampusLoginDesktopV1')
        kernel.CloseHandle.assert_called_once_with(123)
        kernel.CreateMutexW.assert_not_called()

    def test_missing_mutex_is_clear_but_unreadable_probe_stops_automatic_action(self):
        self.kernel(0, 2)
        self.assertFalse(app.stable_instance_running())
        with patch.object(app.ctypes, 'get_last_error', return_value=5):
            self.assertTrue(app.stable_instance_running())
        with patch.object(app.ctypes, 'get_last_error', return_value=87):
            with self.assertRaisesRegex(RuntimeError, '无法检查'):
                app.stable_instance_running()


class ExperimentalCoexistenceTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(app, 'EXPERIMENTAL', True))
        self.enterContext(patch.object(app, 'STARTUP_VALUE_NAME', 'CumtCampusLoginExperimental'))
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = core.Store(self.root)
        with patch.object(core, 'Store', return_value=self.store):
            self.client = app.App()
        self.client.settings.update(stu_autostart=True, quiet_hours=False)
        self.wifi = core.Wifi(core.STU, 'coexistence-fixture', 7,
                              '10.52.7.23', '00-11-22-33-44-55')
        self.client.wifi = self.wifi
        self.enterContext(patch.object(core, 'read_wifi', return_value=self.wifi))
        self.autostart = self.enterContext(patch.object(app, 'stable_autostart_configured', return_value=False))
        self.running = self.enterContext(patch.object(app, 'stable_instance_running', return_value=False))
        self.client.save_profile = MagicMock(return_value={'ok': True})
        engine = MagicMock()
        engine.status.return_value = {'state': 'offline'}
        self.client.session_engine = MagicMock(return_value=engine)
        self.requests = []

        def authenticate(*arguments):
            arguments[-1]()
            self.requests.append('fictional-authentication')
            return None

        self.client.run_authentication = MagicMock(side_effect=authenticate)

    def tearDown(self):
        self.client.closed.set()
        self.client.runtime_log.close()
        self.temporary.cleanup()

    def wait_idle(self):
        deadline = time.monotonic() + 3
        while self.client.busy and time.monotonic() < deadline:
            time.sleep(.005)
        self.assertFalse(self.client.busy, 'The isolated job did not finish')

    def test_enabling_with_stable_run_configuration_changes_neither_run_value_nor_settings(self):
        self.client.settings['stu_autostart'] = False
        self.autostart.return_value = True
        with patch.object(self.store, 'write_settings') as save, \
                patch.object(app.winreg, 'CreateKey') as create, \
                patch.object(app.winreg, 'SetValueEx') as write, \
                patch.object(app.winreg, 'DeleteValue') as delete:
            result = self.client.set_startup(True)
        self.assertFalse(result['ok'])
        self.assertIn('启动项配置', result['message'])
        self.assertNotIn('正在运行', result['message'])
        self.assertFalse(self.client.settings['stu_autostart'])
        save.assert_not_called()
        create.assert_not_called()
        write.assert_not_called()
        delete.assert_not_called()

    def test_enabling_without_conflict_writes_only_the_trial_run_value(self):
        with patch.object(app.winreg, 'CreateKey'), patch.object(app.winreg, 'SetValueEx') as write:
            result = self.client.set_startup(True)
        self.assertTrue(result['ok'])
        self.assertEqual(write.call_args.args[1], 'CumtCampusLoginExperimental')

    def test_configuration_read_failure_is_a_controlled_bridge_result_before_writes(self):
        self.autostart.side_effect = RuntimeError('暂时无法检查稳定版启动项配置')
        with patch.object(self.store, 'write_settings') as save, \
                patch.object(app.winreg, 'CreateKey') as create:
            result = self.client.set_startup(True)
        self.assertFalse(result['ok'])
        self.assertIn('无法检查', result['message'])
        save.assert_not_called()
        create.assert_not_called()

    def test_old_dual_run_configuration_stops_trial_in_worker_before_authentication(self):
        self.autostart.return_value = True
        self.client.auth_diagnostic = {'operation': 'login', 'authentication_requests': 1}
        result = self.client.login('fictional-user', 'fictional-password', 'campus', automatic=True)
        self.assertTrue(result['ok'])
        self.wait_idle()
        self.assertIn('启动项配置', self.client.status)
        self.client.session_engine.assert_not_called()
        self.client.run_authentication.assert_not_called()
        self.assertEqual(self.requests, [])
        self.assertFalse(self.client.busy)
        self.assertEqual(self.client.auth_diagnostic['authentication_requests'], 0)
        self.assertEqual(self.client.auth_diagnostic['phase'], 'coexistence_blocked')

    def test_stable_instance_appearing_immediately_before_submission_stops_the_send(self):
        self.running.side_effect = [False, False, False, True]
        result = self.client.login('fictional-user', 'fictional-password', 'campus', automatic=True)
        self.assertTrue(result['ok'])
        self.wait_idle()
        self.assertEqual(self.requests, [])
        self.assertIn('稳定版正在运行', self.client.status)
        self.assertEqual(self.client.auth_diagnostic['authentication_requests'], 0)

    def test_stable_run_configuration_appearing_before_submission_also_stops_the_send(self):
        self.autostart.side_effect = [False, False, False, True]
        self.assertTrue(self.client.login('fictional-user', 'fictional-password',
                                          'campus', automatic=True)['ok'])
        self.wait_idle()
        self.assertEqual(self.requests, [])
        self.assertIn('启动项配置', self.client.status)
        self.assertEqual(self.client.auth_diagnostic['authentication_requests'], 0)

    def test_disabling_trial_autostart_remains_available_while_stable_is_configured(self):
        self.autostart.return_value = True
        with patch.object(app.winreg, 'CreateKey'), patch.object(app.winreg, 'DeleteValue') as delete:
            result = self.client.set_startup(False)
        self.assertTrue(result['ok'])
        self.assertFalse(self.client.settings['stu_autostart'])
        self.autostart.assert_not_called()
        self.assertEqual(delete.call_args.args[1], 'CumtCampusLoginExperimental')

    def test_browser_resource_guard_rechecks_running_stable_instance(self):
        self.client.auto_job = True
        self.running.return_value = True
        with self.assertRaisesRegex(RuntimeError, '稳定版正在运行'):
            self.client.checked_wifi(self.wifi, False)

    def test_no_conflict_allows_one_automatic_attempt(self):
        result = self.client.login('fictional-user', 'fictional-password', 'campus', automatic=True)
        self.assertTrue(result['ok'])
        self.wait_idle()
        self.assertEqual(self.requests, ['fictional-authentication'])

    def test_explicit_manual_login_does_not_require_stopping_unrelated_stable_state(self):
        self.autostart.return_value = True
        self.running.return_value = True
        result = self.client.login('fictional-user', 'fictional-password', 'campus')
        self.assertTrue(result['ok'])
        self.wait_idle()
        self.assertEqual(self.requests, ['fictional-authentication'])
        self.autostart.assert_not_called()
        self.running.assert_not_called()


if __name__ == '__main__':
    unittest.main()
