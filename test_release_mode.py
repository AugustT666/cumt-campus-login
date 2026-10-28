"""Daily-mode promotion preserves the old namespace and encrypted profile.

Fresh child processes use explicitly temporary LOCALAPPDATA. Native registry,
mutex creation, GUI initialization and authentication are never performed.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import campus_app as app
import campus_core as core


ROOT = Path(__file__).resolve().parent
WIFI = core.Wifi(core.STU, 'daily-mode-fixture', 7, '10.52.7.23',
                 '00-11-22-33-44-55')


CHILD_PROBE = r'''
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

experimental = sys.argv[1] == 'experimental'
sys.argv = ['campus_app.py'] + (['--experimental'] if experimental else [])
import campus_core as core
assert core.EXPERIMENTAL_BUILD is False, 'The daily build must default to stable mode'

# Seed the legacy schema directly, rather than using the current writer to
# manufacture a success. The encrypted bytes use actual Windows user DPAPI,
# with fictional data and only a newly created private temporary directory.
base = Path(os.environ['LOCALAPPDATA'])
stable = base / 'CumtCampusLogin'
stable.mkdir()
settings_path = stable / 'settings.json'
credentials_path = stable / 'credentials.dpapi'
settings = {'operator':'campus','stu_autostart':True,'quiet_hours':True,
            'trusted_hosts':['10.2.5.251'],'portal_hint':'http://10.2.5.251/a79.htm'}
legacy = {'schema':2,'selected':'legacy-profile','profiles':[{
    'id':'legacy-profile','account':'fictional-existing-account',
    'password':'fictional-existing-password','operator':'campus'}]}
settings_path.write_bytes(json.dumps(settings).encode('utf-8'))
credentials_path.write_bytes(core.protect(json.dumps(legacy).encode('utf-8')))
before = (settings_path.read_bytes(), credentials_path.read_bytes())

import campus_app as app
namespace = {'experimental':app.EXPERIMENTAL,
             'startup_value':app.STARTUP_VALUE_NAME,
             'app_id':app.APP_USER_MODEL_ID}

# Capture the actual argument passed to CreateMutexW, then stop before any
# real kernel object, Store or window is constructed by run_main.
class ProbeComplete(Exception):
    pass

class MutexProbe:
    def __call__(self, security, owner, name):
        namespace['mutex_name'] = name
        raise ProbeComplete()

class SilentLog:
    def event(self, *args, **kwargs):
        pass

with patch.object(app.ctypes, 'WinDLL', return_value=SimpleNamespace(CreateMutexW=MutexProbe())):
    try:
        app.run_main(SilentLog())
    except ProbeComplete:
        pass

captured = {}
def inspect_profile(log):
    store = core.Store()
    loaded = store.load()
    selected = store.selected_profile()
    captured.update(directory=store.root.name,
                    selected_existing=selected.get('id') == 'legacy-profile',
                    account_restored=selected.get('account') == legacy['profiles'][0]['account'],
                    password_restored=selected.get('password') == legacy['profiles'][0]['password'],
                    settings_restored=all(loaded.get(k) == v for k,v in settings.items()))

with patch.object(app, 'run_main', side_effect=inspect_profile), \
     patch.object(app.platform, 'platform', return_value='isolated-mode-probe'):
    app.main()

namespace.update(captured)
namespace['legacy_bytes_unchanged'] = before == (settings_path.read_bytes(), credentials_path.read_bytes())
namespace['experimental_credentials_created'] = (base / 'CumtCampusLoginExperimental' / 'credentials.dpapi').exists()
print(json.dumps(namespace))
'''


class ReleaseModeTests(unittest.TestCase):
    def probe(self, experimental=False):
        with tempfile.TemporaryDirectory(prefix='cumt-daily-mode-test-') as temporary:
            environment = dict(os.environ, LOCALAPPDATA=temporary, PYTHONIOENCODING='utf-8')
            result = subprocess.run([sys.executable, '-c', CHILD_PROBE,
                                     'experimental' if experimental else 'daily'],
                                    cwd=ROOT, env=environment, capture_output=True,
                                    text=True, encoding='utf-8', timeout=15, check=True)
            return json.loads(result.stdout)

    def test_daily_defaults_keep_legacy_identity_and_restore_existing_profile_without_rewriting(self):
        result = self.probe()
        self.assertIs(result['experimental'], False)
        self.assertEqual(result['directory'], 'CumtCampusLogin')
        self.assertEqual(result['startup_value'], 'CumtCampusLogin')
        self.assertEqual(result['app_id'], 'AugustT666.CumtCampusLogin')
        self.assertEqual(result['mutex_name'], r'Local\CumtCampusLoginDesktopV1')
        for field in ('selected_existing', 'account_restored', 'password_restored',
                      'settings_restored', 'legacy_bytes_unchanged'):
            self.assertTrue(result[field], field)
        self.assertFalse(result['experimental_credentials_created'])

    def test_explicit_experimental_option_still_uses_separate_identity_and_never_inherits_legacy_secrets(self):
        result = self.probe(experimental=True)
        self.assertTrue(result['experimental'])
        self.assertEqual(result['directory'], 'CumtCampusLoginExperimental')
        self.assertEqual(result['startup_value'], 'CumtCampusLoginExperimental')
        self.assertEqual(result['app_id'], 'AugustT666.CumtCampusLogin.Experimental')
        self.assertEqual(result['mutex_name'], r'Local\CumtCampusLoginExperimentalDesktopV1')
        for field in ('selected_existing', 'account_restored', 'password_restored'):
            self.assertFalse(result[field], field)
        self.assertTrue(result['legacy_bytes_unchanged'])
        self.assertFalse(result['experimental_credentials_created'])

    def test_daily_autostart_reuses_the_stable_value_without_experimental_conflict_checks(self):
        with tempfile.TemporaryDirectory() as temporary:
            client = app.App.__new__(app.App)
            client.store = core.Store(Path(temporary))
            client.settings = {'stu_autostart': False}
            client.record = MagicMock()
            client.record_exception = MagicMock()
            client.busy = False
            client.auto_job = False
            with patch.object(app, 'EXPERIMENTAL', False), \
                    patch.object(app, 'STARTUP_VALUE_NAME', 'CumtCampusLogin'), \
                    patch.object(core, 'read_wifi', return_value=WIFI), \
                    patch.object(app, 'stable_autostart_configured', side_effect=AssertionError('Own startup is not a conflict')) as configured, \
                    patch.object(app, 'stable_instance_running', side_effect=AssertionError('Own instance is not a conflict')) as running, \
                    patch.object(app.winreg, 'CreateKey'), \
                    patch.object(app.winreg, 'SetValueEx') as write:
                self.assertTrue(client._set_startup(True)['ok'])
                client._ensure_exclusive_auto()
            self.assertEqual(write.call_args.args[1], 'CumtCampusLogin')
            self.assertIn('--startup', write.call_args.args[-1])
            self.assertNotIn('--experimental', write.call_args.args[-1])
            configured.assert_not_called()
            running.assert_not_called()


if __name__ == '__main__':
    unittest.main()
