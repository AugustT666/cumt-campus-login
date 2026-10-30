"""Adversarial regressions: fictional accounts, temporary store, in-memory HTTP."""
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
from types import SimpleNamespace
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
        self.engine.status.side_effect = AssertionError('Status checks are not part of login')
        self.probes = self.enterContext(patch.object(core,'internet_check',
            side_effect=AssertionError('No effect probes in the application')))
        self.enterContext(patch.object(socket.socket,'connect',
            side_effect=AssertionError('No real sockets in App hardening tests')))
        self.client.session_engine = MagicMock(return_value=self.engine)
        self.client.run_authentication = MagicMock(return_value=True)
        self.client.save_profile = MagicMock(return_value={'ok': True})
        self._now = time.monotonic()
        self.clock = SimpleNamespace(monotonic=lambda:self._now,perf_counter=lambda:self._now,
            sleep=lambda delay:setattr(self,'_now',self._now+delay))
        self.enterContext(patch.object(app,'time',self.clock))
        self.observation = {'state':'online','binding':'mac_verified','matched_ip':True,
            'mac_conflict':False,'ip_conflict':False,'online_account':ACCOUNT,
            'server_mac':'001122334455','server_ip':WIFI.ip,'verification_performed':True}
        def bounded_probe(wifi,reader,**kwargs):
            self.assertEqual(wifi,WIFI)
            reader()
            return dict(self.observation)
        self.bounded_probe = self.enterContext(patch.object(app.status_checks,'probe',side_effect=bounded_probe))
        def execute_job(kind,job,automatic=False):
            with patch.object(app.threading,'Thread') as thread:
                result=app.App.start_job(self.client,kind,job,automatic)
                if result['ok']:thread.call_args.kwargs['target']()
                return result
        self.client.start_job=execute_job
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

    def test_success_ack_is_separate_from_the_bounded_verified_state(self):
        self.login()
        self.assertTrue(self.client.logged_in)
        self.assertEqual(self.client.session_state, 'online')
        self.assertEqual(self.client.session_diagnostic['source'], 'portal_query')
        self.assertTrue(self.client.session_diagnostic['verification_performed'])
        self.assertIn('登录成功', self.client.status)
        self.client.run_authentication.assert_called_once()
        self.engine.status.assert_not_called()
        self.probes.assert_not_called()
        self.bounded_probe.assert_called_once()

    def test_rejected_and_unknown_acks_keep_receipts_without_fabricating_online_state(self):
        self.observation.update(state='unknown',binding='unconfirmed',matched_ip=False,online_account='')
        for result in (False,None):
            with self.subTest(result=result):
                self.client.run_authentication.return_value=result
                self.login()
                self.assertFalse(self.client.logged_in)
                self.assertEqual(self.client.session_state, 'unknown')
                self.assertIn('失败' if result is False else '无法确认', self.client.status)
                self.assertNotIn('登录成功',self.client.status)
                self.assertIs(self.client.auth_diagnostic['request_accepted'],result)
        self.assertEqual(self.client.run_authentication.call_count, 2)
        self.engine.status.assert_not_called()
        self.probes.assert_not_called()

    def test_success_identity_comes_from_the_server_observation(self):
        self.login()
        self.assertTrue(self.client.logged_in)
        self.assertEqual(self.client.online_account, ACCOUNT)
        self.assertEqual(self.client.identity_source,'verified_status')
        self.assertNotEqual(self.client.identity_source,'request_ack')
        self.engine.status.assert_not_called()
        self.probes.assert_not_called()

    def test_quiet_override_is_one_manual_attempt_and_never_applies_to_automatic_jobs(self):
        self.client.settings.update(quiet_hours=True, stu_autostart=True)
        with patch.object(core, 'quiet_hours', return_value=True):
            self.login(quiet_override=True)
            self.client.run_authentication.assert_called_once()
            self.assertTrue(self.login(automatic=True, quiet_override=True)['ok'])
            self.assertIn('不可认证',self.client.status)
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
            self.assertTrue(page.locator('#quiet-confirm').is_visible())
            self.assertEqual(page.evaluate('window.calls.length'),1)
            page.locator('#quiet-confirm .primary').click()
            page.wait_for_function('window.calls.length===2&&!actionBusy')
            self.assertIs(page.evaluate('window.calls[1][4]'),True)
            context.close()
            browser.close()


if __name__ == '__main__':
    unittest.main()
