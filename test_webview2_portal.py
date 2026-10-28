"""Real WebView2 portal tests with fictional credentials and in-memory HTTP.

The production backend must operate without importing Playwright.  Native
browser escape attempts are observed by a loopback-only TCP canary; they never
target a campus server or transmit real credentials.
"""
import builtins
from contextlib import ExitStack
import importlib
import importlib.util
import json
import socketserver
import threading
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import campus_app as app
import campus_core as core
from test_auth_regressions import MemoryResponse


WIFI = core.Wifi(core.STU, 'webview2-test-fixture', 11, '10.52.7.23',
                 '00-11-22-33-44-55', '10.52.7.1')
PORTAL = 'http://10.2.5.251/a79.htm'
ACCOUNT = 'fictional-webview2-账号+&'
PASSWORD = 'fictional-webview2-密码+&='


class PortalFixture:
    """Original-page handlers run in the real browser, transport stays local."""
    def __init__(self, html, responses=None, result=1, after_request=None):
        self.html = html
        self.responses = dict(responses or {})
        self.root_response = None
        self.result = result
        self.auth_headers = {}
        self.after_request = after_request
        self.current_wifi = WIFI
        self.requests = []
        self.submissions = []
        self.connections_closed = 0
        self.client = app.App.__new__(app.App)
        self.client.portal = PORTAL
        self.client.wifi = WIFI
        self.client.lock = threading.RLock()
        self.client.closed = threading.Event()
        self.client.cancel = threading.Event()
        self.client.auto_job = False
        self.client.settings = {'stu_autostart': False}
        self.client.notifications = None
        self.client.session_cookies = []
        self.client.messages = []

    @staticmethod
    def response(text, kind='text/html; charset=utf-8', status=200, headers=None):
        raw = text.encode('utf-8') if isinstance(text, str) else text
        return MemoryResponse(raw, {'Content-Type': kind, **(headers or {})}, status)

    def run(self, operation='login', expect_error=False, result_timeout=.6, ready_timeout=3.0):
        fixture = self

        class Connection:
            def __init__(self, host, port, wifi, secure=False):
                if host != '10.2.5.251' or port not in (80, 801):
                    raise AssertionError('The fake transport must not serve another origin')
                if wifi.key != WIFI.key:
                    raise AssertionError('A physical-WiFi binding was lost')

            def request(self, method, target, body=None, headers=None):
                parsed = urlsplit(target)
                query = parse_qs(parsed.query, keep_blank_values=True)
                item = {'method': method, 'path': parsed.path, 'query': query,
                        'body': body, 'headers': dict(headers or {})}
                fixture.requests.append(item)
                if parsed.path in ('/eportal/', '/session'):
                    fixture.submissions.append(item)
                    payload = json.dumps({'result': fixture.result}, ensure_ascii=False)
                    self.response = fixture.response('dr1003(' + payload + ')',
                        'application/javascript; charset=utf-8', headers=fixture.auth_headers)
                elif parsed.path == '/a79.htm':
                    self.response = fixture.root_response or fixture.response(fixture.html)
                else:
                    self.response = fixture.responses.get(parsed.path,
                        fixture.response('', 'text/plain', 404))
                if fixture.after_request:
                    fixture.after_request(item)

            def getresponse(self):
                return self.response

            def close(self):
                fixture.connections_closed += 1

        original_import = builtins.__import__

        def without_playwright(name, *args, **kwargs):
            if name == 'playwright' or name.startswith('playwright.'):
                raise AssertionError('Production WebView2 authentication imported Playwright')
            return original_import(name, *args, **kwargs)

        error = None
        with patch.object(core, 'read_wifi', side_effect=lambda: fixture.current_wifi), \
                patch.object(core, 'BoundHTTP', Connection), \
                patch.object(core, 'Store', side_effect=AssertionError('No real Store')), \
                patch.object(app, 'stable_autostart_configured', return_value=False, create=True), \
                patch.object(app, 'stable_instance_running', return_value=False, create=True), \
                patch.object(builtins, '__import__', side_effect=without_playwright), \
                ExitStack() as tuning:
            # Only test deadlines change.  The renderer, DOM, request gate and
            # transport integration remain production code.
            for name in ('campus_browser', 'campus_webview2'):
                if importlib.util.find_spec(name) is None:
                    continue
                module = importlib.import_module(name)
                for option, value in (('READY_TIMEOUT', ready_timeout), ('RESULT_TIMEOUT', result_timeout)):
                    if hasattr(module, option):
                        tuning.enter_context(patch.object(module, option, value))
            try:
                outcome = self.client.authenticate(WIFI, ACCOUNT, PASSWORD,
                                                  'campus', operation, False)
            except RuntimeError as exc:
                outcome, error = None, exc
        if error is not None and not expect_error:
            raise error
        return outcome, error


def login_page(extra_script='', handler=None):
    handler = handler or '''const f=document.forms.loginForm;
        const q=new URLSearchParams({a:'login',user_account:f.elements.DDDDD.value,
          user_password:f.elements.upass.value,
          bridge:typeof window.pywebview});
        const s=document.createElement('script');s.src='/eportal/?'+q;
        document.head.appendChild(s);return false;'''
    return '''<!doctype html><meta charset="utf-8"><link rel="icon" href="data:,">
      <form name="loginForm" onsubmit="return submitPortal()">
      <input name="DDDDD"><input type="password" name="upass">
      <button type="submit">登录</button></form>
      <select name="ISP_select"><option value="">校园网</option></select>
      <script>function dr1003(){};function submitPortal(){''' + handler + '''}
      ''' + extra_script + '</script>'


class NativeLoopbackCanary:
    """A passive local TCP listener detects native browser bypasses."""
    def __enter__(self):
        self.accepted = []
        accepted = self.accepted

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                accepted.append(True)

        self.server = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)


class WebView2PortalTests(unittest.TestCase):
    def test_real_dom_login_without_playwright_or_application_bridge(self):
        fixture = PortalFixture(login_page())
        result, error = fixture.run()
        self.assertIs(result, True)
        self.assertIsNone(error)
        self.assertEqual(len(fixture.submissions), 1)
        query = fixture.submissions[0]['query']
        self.assertEqual(query['user_account'], [ACCOUNT])
        self.assertEqual(query['user_password'], [PASSWORD])
        self.assertEqual(query['bridge'], ['undefined'])
        self.assertEqual(fixture.client.auth_diagnostic['authentication_requests'], 1)

    def test_native_logout_confirmation_is_accepted_once(self):
        html = '''<!doctype html><meta charset="utf-8">
          <button onclick="if(confirm('确定注销?'))sendLogout()">注 销</button>
          <script>function dr1003(){};function sendLogout(){
            const s=document.createElement('script');s.src='/eportal/?a=logout';
            document.head.appendChild(s);}</script>'''
        fixture = PortalFixture(html)
        result, _ = fixture.run(operation='logout')
        self.assertIs(result, True)
        self.assertEqual(len(fixture.submissions), 1)
        self.assertEqual(fixture.submissions[0]['query']['a'], ['logout'])
        self.assertEqual(fixture.client.auth_diagnostic.get('confirmation'), 'native')

    def test_unrelated_native_confirmation_does_not_submit(self):
        html = '''<!doctype html><meta charset="utf-8">
          <button onclick="if(confirm('是否覆盖设置?'))sendLogout()">注销</button>
          <script>function sendLogout(){fetch('/eportal/?a=logout')};</script>'''
        fixture = PortalFixture(html)
        result, _ = fixture.run(operation='logout')
        self.assertIsNone(result)
        self.assertEqual(fixture.submissions, [])

    def test_unknown_authentication_result_is_not_retried(self):
        fixture = PortalFixture(login_page(), result='pending')
        result, _ = fixture.run()
        self.assertIsNone(result)
        self.assertEqual(len(fixture.submissions), 1)
        self.assertEqual(fixture.client.auth_diagnostic['authentication_requests'], 1)

    def test_concurrent_dom_submissions_cannot_both_pass_the_send_gate(self):
        handler = '''for(let n=0;n<2;n++){
          fetch('/eportal/?a=login&attempt='+n+'&attempted=2');}
          return false;'''
        fixture = PortalFixture(login_page(handler=handler))
        rendezvous = threading.Barrier(2)
        both_past_initial_gate = threading.Event()

        def record(event, **fields):
            if event == 'browser.http_request' and fields.get('authentication_request'):
                # The old gate checked count before this event, outside the
                # send lock. Force both real request workers past that check.
                # An atomic admission gate may reject the second earlier, so
                # the first must also proceed when no partner can arrive.
                try:
                    rendezvous.wait(timeout=.6)
                    both_past_initial_gate.set()
                except threading.BrokenBarrierError:
                    pass
        fixture.client.record = record
        result, _ = fixture.run(result_timeout=1.2)
        self.assertIs(result, True)
        self.assertEqual(len(fixture.submissions), 1,
                         'Concurrent request workers consumed more than one authorization')
        self.assertEqual(fixture.submissions[0]['query']['attempted'], ['2'])
        self.assertEqual(fixture.client.auth_diagnostic['authentication_requests'], 1)

    def test_fill_request_queued_until_armed_does_not_become_a_click_submission(self):
        import campus_webview2 as native
        early_arrived, armed, early_done = (threading.Event() for _ in range(3))
        captured = []
        script = '''let sent=false;document.querySelector('[name=DDDDD]').addEventListener('input',()=>{
          if(!sent){sent=true;fetch('/eportal/?a=login&source=fill')}});'''
        handler = "fetch('/eportal/?a=login&source=click');return false;"
        fixture = PortalFixture(login_page(script, handler))
        original_init = native.WebView2Host.__init__
        original_evaluate = native.WebView2Host.evaluate

        def initialize(instance, request_handler, dialog_handler=None, **options):
            provider = options['context_provider']

            def phase():
                value = provider()
                if value[0]:
                    armed.set()
                return value

            def delayed(request):
                source = parse_qs(urlsplit(request.url).query).get('source')
                if source == ['fill']:
                    captured.append(request.arrival_context)
                    early_arrived.set()
                    if not armed.wait(3):
                        raise AssertionError('The late-worker fixture did not reach the armed phase')
                    try:
                        return request_handler(request)
                    finally:
                        early_done.set()
                if source == ['click']:
                    if not early_done.wait(3):
                        raise AssertionError('The early worker did not drain before the click request')
                return request_handler(request)
            options['context_provider'] = phase
            original_init(instance, delayed, dialog_handler, **options)

        def evaluate(host, expression, arg=None):
            value = original_evaluate(host, expression, arg)
            if expression == core.FILL_JS:
                self.assertTrue(early_arrived.wait(3), 'The real fill event never reached resource capture')
            return value

        # Deliberately model a delayed worker beyond the idle barrier.  This
        # checks the independent immutable arrival-phase authorization: even
        # if a drain reports success, queued fill traffic cannot consume click
        # authorization. The browser, phase capture and actual gate are real.
        with patch.object(native.WebView2Host, '__init__', initialize), \
                patch.object(native.WebView2Host, 'evaluate', evaluate), \
                patch.object(native.WebView2Host, 'wait_idle', return_value=True):
            result, _ = fixture.run(result_timeout=1.2)
        self.assertIs(result, True)
        self.assertEqual(captured, [(False, True)])
        self.assertEqual(len(fixture.submissions), 1)
        self.assertEqual(fixture.submissions[0]['query']['source'], ['click'])
        self.assertEqual(fixture.client.auth_diagnostic['authentication_requests'], 1)

    def test_pending_fill_worker_timeout_stops_before_formal_submission(self):
        import campus_webview2 as native
        import time
        early_arrived = threading.Event()
        script = '''let sent=false;document.querySelector('[name=DDDDD]').addEventListener('input',()=>{
          if(!sent){sent=true;fetch('/eportal/?a=login&source=fill')}});'''
        fixture = PortalFixture(login_page(script))
        original_init = native.WebView2Host.__init__
        original_evaluate = native.WebView2Host.evaluate

        def initialize(instance, request_handler, dialog_handler=None, **options):
            def delayed(request):
                if parse_qs(urlsplit(request.url).query).get('source') == ['fill']:
                    early_arrived.set()
                    time.sleep(1)
                return request_handler(request)
            original_init(instance, delayed, dialog_handler, **options)

        def evaluate(host, expression, arg=None):
            value = original_evaluate(host, expression, arg)
            if expression == core.FILL_JS:
                self.assertTrue(early_arrived.wait(3))
            return value

        with patch.object(native.WebView2Host, '__init__', initialize), \
                patch.object(native.WebView2Host, 'evaluate', evaluate):
            result, error = fixture.run(expect_error=True)
        self.assertIsNone(result)
        self.assertIsNotNone(error)
        self.assertEqual(fixture.submissions, [])
        self.assertEqual(fixture.client.auth_diagnostic['authentication_requests'], 0)

    def test_basic_authentication_challenge_does_not_retry_or_submit(self):
        fixture = PortalFixture('')
        fixture.root_response = fixture.response('', status=401,
            headers={'WWW-Authenticate': 'Basic realm="fictional-offline-test"'})
        result, error = fixture.run(expect_error=True, ready_timeout=.6)
        self.assertIsNone(result)
        self.assertIsNotNone(error)
        self.assertEqual(fixture.submissions, [])
        self.assertEqual(len(fixture.requests), 1)

    def test_private_portal_cookie_is_carried_to_following_logout(self):
        fixture = PortalFixture(login_page())
        fixture.auth_headers = {'Set-Cookie': 'offline-session=fictional-cookie; Path=/; HttpOnly'}
        result, _ = fixture.run()
        self.assertIs(result, True)
        self.assertTrue(any(c.get('name') == 'offline-session' and
                            c.get('value') == 'fictional-cookie'
                            for c in fixture.client.session_cookies))
        fixture.html = '''<!doctype html><meta charset="utf-8">
          <button onclick="fetch('/eportal/?a=logout')">注销</button>'''
        fixture.auth_headers = {}
        result, _ = fixture.run(operation='logout')
        self.assertIs(result, True)
        self.assertEqual(len(fixture.submissions), 2)
        headers = {k.lower(): v for k, v in fixture.submissions[-1]['headers'].items()}
        self.assertIn('offline-session=fictional-cookie', headers.get('cookie', ''))

    def test_redirect_stays_in_the_same_bound_transport(self):
        fixture = PortalFixture('')
        fixture.responses['/portal.htm'] = fixture.response(login_page())
        fixture.root_response = fixture.response('', headers={'Location': '/portal.htm'}, status=302)
        result, _ = fixture.run()
        self.assertIs(result, True)
        self.assertEqual([r['path'] for r in fixture.requests[:2]], ['/a79.htm', '/portal.htm'])
        self.assertEqual(len(fixture.submissions), 1)

    def test_cancel_before_navigation_has_no_authentication_submission(self):
        fixture = PortalFixture(login_page())
        fixture.client.cancel.set()
        result, _ = fixture.run(expect_error=True)
        self.assertIsNone(result)
        self.assertEqual(fixture.submissions, [])

    def test_network_change_during_page_load_stops_before_submit(self):
        fixture = PortalFixture(login_page())

        def change_network(item):
            if item['path'] == '/a79.htm':
                fixture.current_wifi = core.Wifi(core.STU, WIFI.guid, WIFI.index,
                                                '10.52.7.24', WIFI.mac)
        fixture.after_request = change_network
        result, _ = fixture.run(expect_error=True)
        self.assertIsNone(result)
        self.assertEqual(fixture.submissions, [])

    def test_disabling_automatic_authorization_during_load_sends_nothing(self):
        fixture = PortalFixture(login_page())
        fixture.client.auto_job = True
        fixture.client.settings['stu_autostart'] = True

        def disable(item):
            if item['path'] == '/a79.htm':
                fixture.client.settings['stu_autostart'] = False
        fixture.after_request = disable
        result, _ = fixture.run(expect_error=True)
        self.assertIsNone(result)
        self.assertEqual(fixture.submissions, [])

    def test_worker_websocket_popup_download_and_external_frame_cannot_bypass_transport(self):
        import campus_webview2 as native
        cancelled_downloads = []
        original_download = native.WebView2Host._download

        def download(instance, sender, args):
            original_download(instance, sender, args)
            cancelled_downloads.append(bool(args.Cancel))

        with NativeLoopbackCanary() as canary:
            local = f'http://127.0.0.1:{canary.port}'
            script = '''window.page={load_js_css:true};window.login={ready:false};
              window.attempts=[];
              try{window.attempts.push('worker');new Worker('/worker.js')}catch(e){}
              try{window.attempts.push('websocket');new WebSocket(LOCAL.replace('http:','ws:')+'/socket')}catch(e){}
              try{window.attempts.push('popup');window.open(LOCAL+'/popup')}catch(e){}
              try{window.attempts.push('frame');const f=document.createElement('iframe');
                  f.src=LOCAL+'/frame';document.body.appendChild(f)}catch(e){}
              try{window.attempts.push('download');const a=document.createElement('a');
                  a.href='/download';a.download='fictional-cancelled-download.txt';
                  document.body.appendChild(a);a.click()}catch(e){}
              try{window.attempts.push('serviceworker');navigator.serviceWorker.register('/sw.js').catch(()=>{})}catch(e){}
              setTimeout(()=>window.login.ready=true,250);'''.replace('LOCAL', json.dumps(local))
            handler = '''const q=new URLSearchParams({a:'login',attempts:window.attempts.join(',')});
              const s=document.createElement('script');s.src='/eportal/?'+q;
              document.head.appendChild(s);return false;'''
            fixture = PortalFixture(login_page(script, handler))
            fixture.responses['/worker.js'] = fixture.response(
                "fetch(" + json.dumps(local + '/worker') + ")", 'application/javascript')
            fixture.responses['/download'] = fixture.response(b'fictional cancelled download',
                'application/octet-stream', headers={
                    'Content-Disposition': 'attachment; filename="fictional-cancelled-download.txt"'})
            with patch.object(native.WebView2Host, '_download', download):
                result, _ = fixture.run()
            self.assertIs(result, True)
            self.assertEqual(len(fixture.submissions), 1)
            attempts = fixture.submissions[0]['query']['attempts'][0]
            for marker in ('worker', 'websocket', 'popup', 'frame', 'serviceworker', 'download'):
                self.assertIn(marker, attempts)
            self.assertEqual(cancelled_downloads, [True], 'The actual native download event was not cancelled')
            self.assertEqual(canary.accepted, [], 'The native browser bypassed the fixed bound transport')
            self.assertNotIn('/worker.js', [r['path'] for r in fixture.requests])
            self.assertNotIn('/sw.js', [r['path'] for r in fixture.requests])


if __name__ == '__main__':
    unittest.main(verbosity=2)
