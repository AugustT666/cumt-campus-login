"""Adversarial regressions: fictional accounts, temporary store, in-memory HTTP."""
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import urlsplit

import campus_app as app
import campus_core as core
from test_auth_regressions import MemoryResponse

WIFI = core.Wifi(core.STU, 'hardening-fixture', 11, '10.52.140.8',
                 '00-11-22-33-44-55', '10.52.140.1')
ACCOUNT, PASSWORD = 'fictional-review-user', 'fictional-review-password'


class AppHardeningTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(app, 'stable_autostart_configured', return_value=False))
        self.enterContext(patch.object(app, 'stable_instance_running', return_value=False))
        self.temp = tempfile.TemporaryDirectory()
        self.store = core.Store(Path(self.temp.name))
        with patch.object(core, 'Store', return_value=self.store):
            self.client = app.App()
        self.client.wifi = WIFI
        self.client.settings['quiet_hours'] = False
        self.engine = MagicMock()
        self.client.session_engine = MagicMock(return_value=self.engine)
        self.client.run_authentication = MagicMock(return_value=True)
        self.client.save_profile = MagicMock(return_value={'ok': True})
        self.client.start_job = lambda kind, job, automatic=False: (job() or {'ok': True})
        self.wifi_patch = patch.object(core, 'read_wifi', return_value=WIFI)
        self.wifi_patch.start()

    def tearDown(self):
        self.wifi_patch.stop()
        self.client.runtime_log.close()
        self.temp.cleanup()

    def login(self, **kwargs):
        return self.client.login(ACCOUNT, PASSWORD, 'campus', **kwargs)

    def test_visible_switch_matches_authorization_when_startup_registration_is_missing(self):
        self.client.settings['stu_autostart'] = True
        with patch.object(self.client, 'startup_enabled', return_value=False):
            boot = self.client.boot()
        self.assertIs(boot['startup'], True)
        self.assertIs(boot['startup_registered'], False)

    def test_non_boolean_auto_authorization_is_disabled_in_every_path(self):
        self.client.settings['stu_autostart'] = 'false'
        with patch.object(self.client, 'startup_enabled', return_value=True):
            self.assertIs(self.client.boot()['startup'], False)
        result = self.login(automatic=True)
        self.assertFalse(result['ok'])
        self.client.run_authentication.assert_not_called()
        self.assertTrue(self.client.on_closing())

    def test_success_response_cannot_override_explicit_offline_readback(self):
        self.engine.status.side_effect = [{'state': 'offline'}, {'state': 'offline'}]
        self.login()
        self.assertFalse(self.client.logged_in)
        self.assertEqual(self.client.session_state, 'offline')
        self.assertEqual(self.client.session_diagnostic['state'], 'offline')
        self.assertIn('已接受', self.client.status)
        self.assertIn('离线', self.client.status)
        self.client.run_authentication.assert_called_once()

    def test_success_response_with_unknown_or_failed_readback_never_claims_online(self):
        for after in ({'state': 'unknown'}, RuntimeError('fixture status unavailable')):
            with self.subTest(after=type(after).__name__):
                self.engine.status.side_effect = [{'state': 'offline'}, after]
                self.login()
                self.assertFalse(self.client.logged_in)
                self.assertEqual(self.client.session_state, 'unknown')
                self.assertIn('尚未确认', self.client.status)
        self.assertEqual(self.client.run_authentication.call_count, 2)

    def test_success_response_with_online_readback_confirms_server_identity(self):
        self.engine.status.side_effect = [{'state': 'offline'},
            {'state': 'online', 'online_account': 'fictional-server-identity'}]
        self.login()
        self.assertTrue(self.client.logged_in)
        self.assertEqual(self.client.online_account, 'fictional-server-identity')

    def test_quiet_override_is_one_manual_attempt_and_never_applies_to_automatic_jobs(self):
        self.client.settings.update(quiet_hours=True, stu_autostart=True)
        self.engine.status.return_value = {'state': 'offline'}
        with patch.object(core, 'quiet_hours', return_value=True):
            self.login(quiet_override=True)
            self.client.run_authentication.assert_called_once()
            with self.assertRaisesRegex(RuntimeError, '不可认证时间'):
                self.login(automatic=True, quiet_override=True)
        self.client.run_authentication.assert_called_once()
        self.assertTrue(self.client.settings['quiet_hours'])


class BrowserGateTests(unittest.TestCase):
    def run_portal(self, early='', duplicate=False, ambiguous=False, json_submit=False):
        requests = []
        button = '<button type="button" onclick="normal()">登录</button>'
        send = ("const x=new XMLHttpRequest();x.open('POST','/session',false);"
                "x.setRequestHeader('Content-Type','application/json');"
                "x.send(JSON.stringify({a:'login',username:document.querySelector('[name=DDDDD]').value,"
                "password:document.querySelector('[name=upass]').value}));") if json_submit else (
                "const x=new XMLHttpRequest();x.open('GET','/eportal/?a=login',false);x.send();")
        html = ('<!doctype html><meta charset="utf-8"><link rel="icon" href="data:,"><form onsubmit="return false">'
                '<input name="DDDDD"><input name="upass" type="password" onchange="early()">'
                + button * (2 if ambiguous else 1) + '</form><script>'
                'function early(){' + early + '}function normal(){' + send
                + (send.replace('const x=', 'const y=').replace('x.', 'y.') if duplicate else '')
                + '}</script>')

        class Connection:
            def __init__(self, *args):
                pass

            def request(self, method, target, body=None, headers=None):
                path = urlsplit(target).path
                requests.append((method, path, body))
                content = html if path == '/a79.htm' else '{"result":1}'
                kind = 'text/html; charset=utf-8' if path == '/a79.htm' else 'application/json'
                self.response = MemoryResponse(content.encode(), {'Content-Type': kind})

            def getresponse(self):
                return self.response

            def close(self):
                pass

        helper = app.App.__new__(app.App)
        helper.portal = 'http://10.2.5.251/a79.htm'
        helper.wifi = WIFI
        helper.lock = threading.RLock()
        helper.closed = threading.Event()
        helper.cancel = threading.Event()
        helper.auto_job = False
        helper.settings = {'stu_autostart': False}
        helper.notifications = None
        helper.session_cookies = []
        helper.messages = []
        caught = None
        with patch.object(core, 'read_wifi', return_value=WIFI), \
             patch.object(core, 'BoundHTTP', Connection), \
             patch.object(core, 'Store', side_effect=AssertionError('No real store')):
            try:
                outcome = helper.authenticate(WIFI, ACCOUNT, PASSWORD, 'campus', 'login', False)
            except RuntimeError as exc:
                outcome, caught = None, str(exc)
        return outcome, requests, helper.auth_diagnostic, caught

    def test_json_posts_on_fill_are_never_transmitted_and_stop_form_submission(self):
        early = ("for(let n=0;n<2;n++){const x=new XMLHttpRequest();"
                 "x.open('POST','/api/session',false);x.setRequestHeader('Content-Type','application/json');"
                 "try{x.send(JSON.stringify({username:document.querySelector('[name=DDDDD]').value,"
                 "password:document.querySelector('[name=upass]').value}));}catch(e){}}")
        outcome, requests, trace, error = self.run_portal(early=early)
        self.assertEqual([r[1] for r in requests], ['/a79.htm'])
        self.assertEqual(trace['authentication_requests'], 0)
        self.assertIsNone(outcome)
        self.assertIsNotNone(error)

    def test_unknown_get_during_fill_is_not_treated_as_a_resource(self):
        early = "const x=new XMLHttpRequest();x.open('GET','/collect?x=opaque',false);try{x.send();}catch(e){}"
        _, requests, trace, error = self.run_portal(early=early)
        self.assertEqual([r[1] for r in requests], ['/a79.htm'])
        self.assertEqual(trace['authentication_requests'], 0)
        self.assertIsNotNone(error)

    def test_ambiguous_button_is_rejected_before_filling_or_dispatching_events(self):
        early = "throw new Error('Credentials must never be filled for ambiguous controls')"
        _, requests, trace, error = self.run_portal(early=early, ambiguous=True)
        self.assertEqual(len(requests), 1)
        self.assertEqual(trace['authentication_requests'], 0)
        self.assertFalse(trace['page_errors'])
        self.assertIsNotNone(error)

    def test_original_get_login_still_sends_once_even_when_handler_duplicates(self):
        outcome, requests, trace, error = self.run_portal(duplicate=True)
        self.assertTrue(outcome)
        self.assertEqual([r[1] for r in requests].count('/eportal/'), 1)
        self.assertEqual(trace['authentication_requests'], 1)
        self.assertIsNone(error)

    def test_explicit_json_login_is_classified_and_confirmed_once(self):
        outcome, requests, trace, error = self.run_portal(json_submit=True)
        self.assertTrue(outcome)
        sent = [r for r in requests if r[1] == '/session']
        self.assertEqual(len(sent), 1)
        self.assertEqual(json.loads(sent[0][2])['password'], PASSWORD)
        self.assertEqual(trace['authentication_requests'], 1)
        self.assertIsNone(error)


class QuietOverrideUiTests(unittest.TestCase):
    def test_cancel_sends_nothing_and_confirmation_is_not_reused(self):
        from playwright.sync_api import sync_playwright
        html=(Path(__file__).parent/'campus_ui.html').read_text('utf-8')
        with sync_playwright() as playwright:
            browser=playwright.chromium.launch(channel='msedge',headless=True,
                args=['--no-proxy-server','--disable-background-networking'])
            context=browser.new_context(service_workers='block')
            context.route('**/*',lambda route:route.abort())
            page=context.new_page()
            page.set_content(html)
            page.evaluate('''() => {
                window.calls=[];
                window.fixture={version:'test',ssid:'CUMT_Stu',campus:true,
                    session_state:'offline',busy:false,quiet_hours_active:true,status:'未登录'};
                state=window.fixture;
                api={login:async(...args)=>{window.calls.push(args);return {ok:true}},
                    get_state:async()=>window.fixture,
                    boot:async()=>({version:'test',selected:'',profiles:[],account:'fake',
                        password:'fake',operator:'campus',startup:false,portal_hint:''})};
                document.getElementById('account').value='fake';
                document.getElementById('password').value='fake';
                document.getElementById('operator').value='campus';
            }''')
            page.locator('#login-button').click()
            self.assertTrue(page.locator('#quiet-confirm').is_visible())
            self.assertEqual(page.evaluate('window.calls.length'),0)
            page.locator('#quiet-confirm .plain').click()
            self.assertEqual(page.evaluate('window.calls.length'),0)
            page.locator('#login-button').click()
            page.locator('#quiet-confirm .primary').click()
            page.wait_for_function('window.calls.length===1&&!actionBusy')
            self.assertIs(page.evaluate('window.calls[0][4]'),True)
            page.locator('#login-button').click()
            self.assertTrue(page.locator('#quiet-confirm').is_visible())
            self.assertEqual(page.evaluate('window.calls.length'),1)
            page.locator('#quiet-confirm .plain').click()
            page.evaluate("window.fixture.session_state='online';state=window.fixture")
            page.locator('#login-button').click()
            page.wait_for_function('window.calls.length===2&&!actionBusy')
            self.assertIs(page.evaluate('window.calls[1][4]'),False)
            context.close()
            browser.close()


if __name__ == '__main__':
    unittest.main()
