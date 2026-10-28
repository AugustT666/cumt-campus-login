"""Restore the independently witnessed portal behavior without a Node driver.

All pages and HTTP responses are fictional. The actual WebView2 runs the DOM,
while PortalFixture supplies every accepted request through an in-memory
physical-WiFi transport and refuses access to a user Store.
"""
import json
from html import escape
import time
import unittest
from urllib.parse import parse_qs, quote, urlsplit

from campus_webview2 import Response, WebView2Host

from test_webview2_portal import (
    ACCOUNT, PASSWORD, NativeLoopbackCanary, PortalFixture,
)


DOCUMENT = '<!doctype html><meta charset="utf-8"><link rel="icon" href="data:,">'
SEND = r'''
function dr1003(){}
function sendLogin(e){
  const f=document.forms.loginForm;
  const q=new URLSearchParams({a:'login',user_account:f.elements.user_account.value,
    user_password:f.elements.user_password.value,trusted:String(e.isTrusted),
    viewport:innerWidth+'x'+innerHeight});
  const s=document.createElement('script');s.src='/eportal/?'+q;
  document.head.appendChild(s);return false;
}
function sendLogout(e){
  const s=document.createElement('script');
  s.src='/eportal/?a=logout&trusted='+e.isTrusted;
  document.head.appendChild(s);return false;
}
'''
FIELDS = '<input name="user_account"><input name="user_password" type="password">'


class WebView2ParityTests(unittest.TestCase):
    def assert_single_success(self, fixture, operation='login'):
        result, error = fixture.run(operation=operation, result_timeout=1.0)
        self.assertIs(result, True, fixture.client.auth_diagnostic)
        self.assertIsNone(error)
        self.assertEqual(len(fixture.submissions), 1)
        self.assertEqual(fixture.client.auth_diagnostic['authentication_requests'], 1)
        self.assertEqual(fixture.submissions[0]['query']['a'], [operation])
        return fixture.submissions[0]

    def test_login_click_is_trusted_browser_input(self):
        html = (DOCUMENT + '<form name="loginForm">' + FIELDS +
            '<button type="submit" onclick="if(!event.isTrusted)return false;'
            'return sendLogin(event)">登录</button></form><script>' + SEND + '</script>')
        item = self.assert_single_success(PortalFixture(html))
        self.assertEqual(item['query']['trusted'], ['true'])
        self.assertEqual(item['query']['user_account'], [ACCOUNT])
        self.assertEqual(item['query']['user_password'], [PASSWORD])

    def test_logout_click_is_trusted_browser_input(self):
        html = (DOCUMENT + '<button onclick="if(event.isTrusted)sendLogout(event)">'
            '注销</button><script>' + SEND + '</script>')
        item = self.assert_single_success(PortalFixture(html), 'logout')
        self.assertEqual(item['query']['trusted'], ['true'])

    def test_login_waits_for_button_reenabled_after_fill(self):
        fields = ('<input name="user_account" oninput="holdButton()">'
                  '<input name="user_password" type="password" oninput="holdButton()">')
        html = (DOCUMENT + '<form name="loginForm" onsubmit="return false">' + fields +
            '<button id="submitButton" type="submit" onclick="return sendLogin(event)">'
            '登录</button></form><script>' + SEND + r'''
            let pending;
            function holdButton(){
              const b=document.getElementById('submitButton');b.disabled=true;
              clearTimeout(pending);pending=setTimeout(()=>b.disabled=false,600);
            }
            </script>''')
        item = self.assert_single_success(PortalFixture(html))
        self.assertEqual(item['query']['trusted'], ['true'])

    def test_waits_for_late_installed_click_handler(self):
        html = (DOCUMENT + '<form name="loginForm" onsubmit="return false">' + FIELDS +
            '<button id="submitButton" type="submit">登录</button></form><script>' +
            SEND + '''setTimeout(()=>document.getElementById('submitButton').onclick=
                (e)=>sendLogin(e),450);</script>''')
        self.assert_single_success(PortalFixture(html))

    def test_same_origin_hidden_frame_form_target_posts_once(self):
        for action in ('/eportal/?a=login', 'http://10.2.5.251:801/eportal/?a=login'):
            with self.subTest(action=action):
                html = (DOCUMENT + '<iframe name="replyFrame" style="display:none"></iframe>'
                    '<form name="loginForm" method="post" target="replyFrame" '
                    'action="' + action + '">' + FIELDS +
                    '<button type="submit">登录</button></form>')
                item = self.assert_single_success(PortalFixture(html))
                self.assertEqual(item['method'], 'POST')
                fields = parse_qs(item['body'].decode('utf-8'), keep_blank_values=True)
                self.assertEqual(fields['user_account'], [ACCOUNT])
                self.assertEqual(fields['user_password'], [PASSWORD])

    def test_desktop_viewport_preserves_1280_by_720_css_pixels(self):
        html = (DOCUMENT + '<style>@media(max-width:999px){form{display:none}}</style>'
            '<form name="loginForm">' + FIELDS +
            '<button type="submit" onclick="return sendLogin(event)">登录</button>'
            '</form><script>' + SEND + '</script>')
        item = self.assert_single_success(PortalFixture(html))
        self.assertEqual(item['query']['viewport'], ['1280x720'])


class WebView2FrameIsolationTests(unittest.TestCase):
    def test_frame_authentication_still_shares_the_single_submission_gate(self):
        html = (DOCUMENT + '<iframe id="child" src="/safe-frame.htm" style="display:none"></iframe>'
            '<form name="loginForm" onsubmit="return false">' + FIELDS +
            '<button type="submit" onclick="document.getElementById(\'child\').contentWindow.'
            'postMessage(\'submit\',location.origin);return false">登录</button></form>')
        frame = (DOCUMENT + '''<script>parent.childReady=true;
            addEventListener('message',e=>{if(e.data==='submit'){
              for(let n=0;n<2;n++)fetch('/eportal/?a=login&source=child&attempt='+n);
            }});</script>''')
        fixture = PortalFixture(html, {'/safe-frame.htm': PortalFixture.response(frame)})
        result, error = fixture.run(result_timeout=1.0)
        self.assertIs(result, True, fixture.client.auth_diagnostic)
        self.assertIsNone(error)
        self.assertIn('/safe-frame.htm', [r['path'] for r in fixture.requests])
        self.assertEqual(len(fixture.submissions), 1)
        self.assertEqual(fixture.submissions[0]['query']['source'], ['child'])
        self.assertEqual(fixture.client.auth_diagnostic['authentication_requests'], 1)
        self.assertGreaterEqual(fixture.client.auth_diagnostic['blocked_requests'], 1)

    def test_early_frame_authentication_cannot_consume_parent_click_authorization(self):
        html = (DOCUMENT + '<iframe src="/safe-frame.htm" style="display:none"></iframe>'
            '<form name="loginForm">' + FIELDS +
            '<button type="submit" onclick="return sendLogin(event)">登录</button>'
            '</form><script>' + SEND + '</script>')
        frame = (DOCUMENT + '''<script>
            fetch('/eportal/?a=login&source=unarmed-child').catch(()=>{});
            </script>''')
        fixture = PortalFixture(html, {'/safe-frame.htm': PortalFixture.response(frame)})
        result, error = fixture.run(result_timeout=1.0)
        self.assertIs(result, True, fixture.client.auth_diagnostic)
        self.assertIsNone(error)
        self.assertIn('/safe-frame.htm', [r['path'] for r in fixture.requests])
        self.assertEqual(len(fixture.submissions), 1)
        self.assertEqual(fixture.submissions[0]['query']['user_account'], [ACCOUNT])
        self.assertNotIn('source', fixture.submissions[0]['query'])
        self.assertGreaterEqual(fixture.client.auth_diagnostic['blocked_requests'], 1)

    def test_same_origin_secure_frame_cannot_escape_to_native_network_or_bridge(self):
        with NativeLoopbackCanary() as canary:
            outside = f'https://127.0.0.1:{canary.port}'
            parent = DOCUMENT + '<iframe src="/safe-frame.htm"></iframe>'
            child = (DOCUMENT + '''<script>
                const p={ran:true,secure:isSecureContext,bridge:typeof window.pywebview,
                  attempts:[],serviceWorkerAvailable:!!navigator.serviceWorker};
                try{p.attempts.push('worker');new Worker('/child-worker.js')}catch(e){}
                try{p.attempts.push('websocket');new WebSocket(OUTSIDE.replace('https:','wss:')+'/socket')}catch(e){}
                try{p.attempts.push('fetch');fetch(OUTSIDE+'/fetch').catch(()=>{})}catch(e){}
                try{p.attempts.push('popup');window.open(OUTSIDE+'/popup')}catch(e){}
                try{p.attempts.push('serviceworker');
                  ServiceWorkerContainer.prototype.register.call(navigator.serviceWorker,'/child-sw.js').catch(()=>{})
                }catch(e){}
                parent.childProbe=p;
                </script>''').replace('OUTSIDE', json.dumps(outside))
            requests = []

            def handle(request):
                p = urlsplit(request.url)
                requests.append((request.method, p.hostname, p.path))
                if request.method != 'GET' or p.scheme != 'https' or p.hostname != '10.2.5.251':
                    return None
                if p.path == '/a79.htm':
                    body = parent
                elif p.path == '/safe-frame.htm':
                    body = child
                else:
                    return None
                return Response(200, {'Content-Type': 'text/html; charset=utf-8'},
                                body.encode('utf-8'))

            with WebView2Host(handle, host='10.2.5.251') as page:
                page.navigate('https://10.2.5.251/a79.htm')
                until = time.monotonic() + 4
                probe = None
                while time.monotonic() < until:
                    probe = page.evaluate('window.childProbe||null')
                    if probe:
                        break
                    time.sleep(.04)
                self.assertIsNotNone(probe, 'The approved child frame did not actually execute')
                self.assertTrue(probe['ran'])
                self.assertTrue(probe['secure'], 'The Service Worker probe requires a secure context')
                self.assertTrue(probe['serviceWorkerAvailable'])
                self.assertEqual(probe['bridge'], 'undefined')
                for channel in ('worker', 'websocket', 'fetch', 'popup', 'serviceworker'):
                    self.assertIn(channel, probe['attempts'])
                page.wait_idle(1.0)
                time.sleep(.15)
            self.assertIn(('GET', '10.2.5.251', '/safe-frame.htm'), requests)
            self.assertNotIn(('GET', '10.2.5.251', '/child-worker.js'), requests)
            self.assertNotIn(('GET', '10.2.5.251', '/child-sw.js'), requests)
            self.assertEqual(canary.accepted, [], 'A child frame used native browser networking')

    def test_opaque_javascript_and_external_frames_cannot_escape_network_or_bridge(self):
        with NativeLoopbackCanary() as canary:
            outside = f'http://127.0.0.1:{canary.port}'
            attempt = ('''parent.postMessage({probe:'untrusted-frame',bridge:typeof window.pywebview},'*');
                try{new WebSocket(OUTSIDE.replace('http:','ws:')+'/socket')}catch(e){}
                try{fetch(OUTSIDE+'/fetch').catch(()=>{})}catch(e){}
                try{window.open(OUTSIDE+'/popup')}catch(e){}
                ''').replace('OUTSIDE', json.dumps(outside))
            payload = ('<img src="/missing-frame-probe.png" onerror="' +
                       escape(attempt, quote=True) + '">')
            srcdoc_literal = json.dumps(payload)
            javascript = 'javascript:(()=>{' + attempt + '})();void 0'
            static_markup = (
                '<iframe style="display:none" src="' + escape(javascript, quote=True) + '"></iframe>'
                '<iframe style="display:none" srcdoc="' + escape(payload, quote=True) + '"></iframe>'
                '<iframe style="display:none" src="' + escape('data:text/html,' + quote(payload), quote=True) + '"></iframe>')
            tracking = '''window.frameReports=[];
                addEventListener('message',e=>{if(e.data&&e.data.probe==='untrusted-frame')
                  frameReports.push(e.data)});'''
            extra = '''
                function addFrame(configure){const f=document.createElement('iframe');
                  f.style.display='none';try{configure(f);document.body.appendChild(f)}catch(e){}}
                addFrame(f=>f.src=OUTSIDE+'/frame');
                addFrame(f=>f.src=DATA);
                addFrame(f=>f.srcdoc=SRCDOC);
                addFrame(f=>f.setAttribute('src',JAVASCRIPT));
                document.body.insertAdjacentHTML('beforeend',MARKUP);
                '''.replace('OUTSIDE', json.dumps(outside)).replace(
                    'DATA', json.dumps('data:text/html,' + quote(payload))).replace(
                    'SRCDOC', srcdoc_literal).replace('JAVASCRIPT', json.dumps(javascript)).replace(
                    'MARKUP', json.dumps(static_markup))
            handler = SEND.replace("viewport:innerWidth+'x'+innerHeight",
                                   "bridge_leak:String(window.frameReports.some(r=>r.bridge!=='undefined'))")
            html = (DOCUMENT + '<script>' + tracking + '</script>' + static_markup +
                '<form name="loginForm">' + FIELDS +
                '<button type="submit" onclick="return sendLogin(event)">登录</button>'
                '</form><script>' + handler + extra + '</script>')
            fixture = PortalFixture(html)
            result, error = fixture.run(result_timeout=1.0)
            self.assertIs(result, True, fixture.client.auth_diagnostic)
            self.assertIsNone(error)
            self.assertEqual(len(fixture.submissions), 1)
            self.assertEqual(fixture.submissions[0]['query']['bridge_leak'], ['false'])
            self.assertEqual(canary.accepted, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
