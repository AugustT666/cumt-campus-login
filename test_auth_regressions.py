"""Offline regressions for the real Dr.COM compression and readiness failures.

All portal HTTP traffic is handled in memory through a fake BoundHTTP.  The
browser tests execute actual Edge/Chrome JavaScript but never read credentials,
create a Store, change WiFi, or contact the campus server.
"""
import base64
import gzip
import json
import threading
import unittest
import zlib
from urllib.parse import parse_qs, urlsplit
from unittest.mock import MagicMock, patch

import campus_app as app
import campus_core as core


WIFI = core.Wifi('CUMT_Stu', 'offline-test-guid', 11, '10.3.16.74',
                 '00-11-22-33-44-55', '10.3.16.1')
PORTAL = 'http://10.2.5.251/a79.htm'
ACCOUNT = 'offline&+@测试账号'
PASSWORD = 'offline-password&+='


class MemoryResponse:
    def __init__(self, body, headers, status=200):
        self.body = body
        self.headers = headers
        self.status = status

    def read(self, limit=None):
        return self.body if limit is None else self.body[:limit]

    def getheaders(self):
        return list(self.headers.items())

    def getheader(self, name, default=None):
        return next((v for k, v in self.headers.items()
                     if k.casefold() == name.casefold()), default)


class ResponseDecodingTests(unittest.TestCase):
    def test_gzip_is_decoded_and_wire_only_headers_removed(self):
        raw = '校园网认证'.encode('utf-8')
        headers = {'Content-Encoding': 'gzip', 'Content-Length': '99',
                   'Transfer-Encoding': 'chunked', 'Connection': 'close',
                   'Content-Type': 'text/html; charset=utf-8',
                   'Set-Cookie': 'offline-session=1'}
        decoded, forwarded = core.decode_http_body(gzip.compress(raw), headers)
        self.assertEqual(decoded, raw)
        self.assertEqual({k.lower() for k in forwarded},
                         {'content-type', 'set-cookie'})
        self.assertEqual(forwarded['Set-Cookie'], 'offline-session=1')
        self.assertIn('Content-Encoding', headers, 'Do not mutate caller headers')

    def test_deflate_accepts_zlib_and_raw_streams(self):
        raw = b'window.page = {load_js_css: true};'
        compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
        raw_stream = compressor.compress(raw) + compressor.flush()
        for body in (zlib.compress(raw), raw_stream):
            with self.subTest(raw_stream=body == raw_stream):
                decoded, forwarded = core.decode_http_body(
                    body, {'cOnTeNt-EnCoDiNg': 'DEFLATE', 'content-length': '9'})
                self.assertEqual(decoded, raw)
                self.assertEqual(forwarded, {})

    def test_stacked_encodings_are_decoded_in_reverse_order(self):
        raw = b'var portal = "ready";'
        encoded = zlib.compress(gzip.compress(raw))
        decoded, _ = core.decode_http_body(
            encoded, {'Content-Encoding': 'gzip, deflate'})
        self.assertEqual(decoded, raw)

    def test_identity_keeps_bytes_and_content_type(self):
        raw = b'<html>unchanged</html>'
        decoded, headers = core.decode_http_body(
            raw, {'content-encoding': 'identity', 'content-type': 'text/html'})
        self.assertEqual(decoded, raw)
        self.assertEqual(headers, {'content-type': 'text/html'})

    def test_http_charset_gb2312(self):
        text = '<html>校园网认证：中国矿业大学</html>'
        self.assertEqual(core.decode_text(text.encode('gb2312'),
                         {'Content-Type': 'text/html; charset="gb2312"'}), text)

    def test_html_meta_gb2312_without_http_charset(self):
        text = '<meta charset="gb2312"><p>请选择运营商：校园网</p>'
        self.assertEqual(core.decode_text(text.encode('gb2312'),
                         {'content-type': 'text/html'}), text)

    def test_legacy_http_equiv_meta_charset(self):
        text = ('<meta http-equiv="Content-Type" '
                'content="text/html; charset=gb2312"><p>学生认证页面</p>')
        self.assertEqual(core.decode_text(text.encode('gb2312'), {}), text)

    def test_http_charset_takes_precedence_over_meta(self):
        text = '<meta charset="gb2312"><p>校园网</p>'
        self.assertEqual(core.decode_text(text.encode('utf-8'),
                         {'Content-Type': 'text/html; charset=utf-8'}), text)

    def test_fetch_decodes_gzip_and_meta_charset_before_discovery(self):
        html = '<meta charset="gb2312"><p>校园网认证，请选择运营商</p>'
        response = MemoryResponse(gzip.compress(html.encode('gb2312')),
                                  {'Content-Type': 'text/html',
                                   'Content-Encoding': 'gzip'})
        connection = MagicMock()
        connection.getresponse.return_value = response
        with patch.object(core, 'BoundHTTP', return_value=connection), \
             patch.object(core, 'Store', side_effect=AssertionError('No Store')):
            status, location, text = core.fetch(PORTAL, WIFI, reader=lambda: WIFI)
        self.assertEqual((status, location, text), (200, '', html))
        connection.request.assert_called_once()
        connection.close.assert_called_once()


class ResultEvidenceTests(unittest.TestCase):
    def test_actual_jsonp_ok_and_numeric_success(self):
        for result in (1, '1', 'ok'):
            with self.subTest(result=result):
                body = 'dr1003(' + json.dumps({'result': result}) + ')'
                self.assertIs(app.authentication_result(
                    body, 'http://10.2.5.251:801/eportal/?a=Login', 'login'), True)

    def test_unknown_result_is_inconclusive(self):
        for result in ('pending', 'unexpected', None, 2):
            with self.subTest(result=result):
                self.assertIsNone(app.authentication_result(
                    json.dumps({'result': result}),
                    'http://10.2.5.251:801/eportal/?a=login', 'login'))

    def test_login_evidence_cannot_confirm_logout(self):
        self.assertIsNone(app.authentication_result(
            'dr1003({"result":"ok"})',
            'http://10.2.5.251:801/eportal/?a=login', 'logout'))


class PortalBrowserRegressions(unittest.TestCase):
    """Real browser, gzip script/CSS, deferred controls, and original handlers."""

    def run_portal(self, result=1, compressed=True, controls_delay=80,
                   ready_delay=180, operation='login', duplicate=False,
                   logout_confirmation=None, response_fields=None):
        requests = []
        submissions = []
        html = '''<!doctype html><meta charset="utf-8">
        <style>#login-shell {display:none}</style>
        <link rel="stylesheet" href="/b82.css">
        <script src="/a41.js"></script>
        <div style="display:none"><form name="f0">
          <input name="DDDDD" type="hidden"><input name="upass" type="hidden">
        </form></div><div id="login-shell"></div>'''
        controls = '''<form name="f3" onsubmit="return ee(3)">
          <input type="submit" name="0MKKey" value="登  录">
          <input type="text" name="DDDDD"><input type="password" name="upass">
        </form><select name="ISP_select">
          <option value="-1">请选择运营商</option>
          <option value="@telecom">中国电信</option>
          <option value="">校园网</option></select>'''
        # Match the real portal's asynchronous page/login objects.  Controls
        # exist before initialization, which clears their values and installs
        # the original ee handler.  Filling early therefore cannot succeed.
        script = '''window.page={load_js_css:true};
        window.dr1003=function(data) {window.lastResponse=data;};
        setTimeout(function() {
          document.getElementById('login-shell').innerHTML=__CONTROLS__;
        }, __CONTROLS_DELAY__);
        setTimeout(function() {
          document.forms.f3.elements.DDDDD.value='';
          document.forms.f3.elements.upass.value='';
          window.ee=function() {
            const f=document.forms.f3;
            const selector=document.querySelector('select[name=ISP_select]');
            const params=new URLSearchParams({a:'login',
              user_account:f.elements.DDDDD.value+selector.value,
              user_password:f.elements.upass.value,
              selected_operator:selector.value,
              hidden_user:document.forms.f0.elements.DDDDD.value,
              hidden_password:document.forms.f0.elements.upass.value,
              ready:String(window.login.ready)});
            const send=function() {
              const jsonp=document.createElement('script');
              jsonp.src='http://10.2.5.251:801/eportal/?'+params;
              document.head.appendChild(jsonp);
            };
            send(); DUPLICATE
            return false;
          };
          window.login={ready:true};
        }, __READY_DELAY__);'''.replace('__CONTROLS__', json.dumps(controls)) \
           .replace('__CONTROLS_DELAY__', str(controls_delay)) \
           .replace('__READY_DELAY__', str(ready_delay)) \
           .replace('DUPLICATE', 'send();' if duplicate else '')
        if operation == 'logout':
            html = '''<!doctype html><meta charset="utf-8">
            <input type="button" value="注  销" onclick="quitPortal()">
            <script>function sendLogout() {
              const s=document.createElement('script');
              s.src='/eportal/?a=logout'; document.head.appendChild(s);
            } function quitPortal() {sendLogout();}
            function dr1003() {}</script>'''
            if logout_confirmation:
                prompt = ('确定注销?' if logout_confirmation == 'boxy'
                          else '是否覆盖设置?')
                boxy = ("<div class='c-pop c-confirm boxy-wrapper'>"
                        '<p>' + prompt + '</p>'
                        "<form class='answers'><input type=button class=boxy-btn1 "
                        "value=确认 onclick='sendLogout()'>"
                        '<input type=button value=取消></form></div>')
                html = html.replace('function quitPortal() {sendLogout();}',
                                    'function quitPortal() {document.body.insertAdjacentHTML('
                                    "'beforeend'," + json.dumps(boxy) + ');}')

        def response(body, kind, encode=False):
            data = body.encode('utf-8')
            headers = {'Content-Type': kind, 'Connection': 'close'}
            if encode:
                data = gzip.compress(data)
                headers['Content-Encoding'] = 'gzip'
            headers['Content-Length'] = str(len(data))
            return MemoryResponse(data, headers)

        class Connection:
            def __init__(self, *args):
                pass

            def request(self, method, target, body=None, headers=None):
                requests.append((method, target))
                path = urlsplit(target).path
                if path == '/a79.htm':
                    self.response = response(html, 'text/html; charset=utf-8')
                elif path == '/a41.js':
                    self.response = response(script, 'application/javascript; charset=utf-8', compressed)
                elif path == '/b82.css':
                    self.response = response('#login-shell {display:block}', 'text/css', compressed)
                elif path == '/eportal/':
                    submissions.append(parse_qs(urlsplit(target).query, keep_blank_values=True))
                    self.response = response('dr1003(' + json.dumps({'result': result,**(response_fields or {})}) + ')',
                                             'application/javascript; charset=utf-8', compressed)
                else:
                    self.response = MemoryResponse(b'', {'Content-Type': 'text/plain'}, 404)

            def getresponse(self):
                return self.response

            def close(self):
                pass

        helper = app.App.__new__(app.App)
        helper.portal = PORTAL
        helper.wifi = WIFI
        helper.lock = threading.RLock()
        helper.closed = threading.Event()
        helper.cancel = threading.Event()
        helper.auto_job = False
        helper.settings = {'stu_autostart': False}
        helper.notifications = None
        helper.session_cookies = []
        helper.messages = []
        with patch.object(core, 'read_wifi', return_value=WIFI), \
             patch.object(core, 'BoundHTTP', Connection), \
             patch.object(core, 'Store', side_effect=AssertionError('No Store')):
            outcome = helper.authenticate(WIFI, ACCOUNT, PASSWORD, 'campus', operation, False)
        return outcome, submissions, requests, helper.auth_diagnostic

    def assert_login_fields(self, submissions):
        self.assertEqual(len(submissions), 1)
        self.assertEqual(submissions[0]['user_account'], [ACCOUNT])
        self.assertEqual(submissions[0]['user_password'], [PASSWORD])
        self.assertEqual(submissions[0]['selected_operator'], [''])
        self.assertEqual(submissions[0]['hidden_user'], [''])
        self.assertEqual(submissions[0]['hidden_password'], [''])
        self.assertEqual(submissions[0]['ready'], ['true'])

    def test_gzip_script_css_and_jsonp_login_success_once(self):
        outcome, submissions, requests, diagnostic = self.run_portal()
        self.assertIs(outcome, True, diagnostic)
        self.assert_login_fields(submissions)
        self.assertTrue(any(urlsplit(target).path == '/a41.js' for _, target in requests))
        self.assertTrue(any(urlsplit(target).path == '/b82.css' for _, target in requests))
        self.assertEqual(diagnostic['page_errors'], [])
        self.assertEqual(diagnostic['resource_errors'], [])

    def test_delayed_initialization_is_ready_before_fill(self):
        outcome, submissions, _, diagnostic = self.run_portal(
            compressed=False, controls_delay=120, ready_delay=1400)
        self.assertIs(outcome, True, diagnostic)
        self.assert_login_fields(submissions)
        self.assertEqual(diagnostic['page_errors'], [])

    def test_gzip_ok_response_is_explicit_success(self):
        outcome, submissions, _, diagnostic = self.run_portal(result='ok')
        self.assertIs(outcome, True, diagnostic)
        self.assert_login_fields(submissions)

    def test_second_portal_submission_is_blocked(self):
        outcome, submissions, _, diagnostic = self.run_portal(result=0, duplicate=True)
        self.assertIs(outcome, False, diagnostic)
        self.assertEqual(len(submissions), 1)

    def test_browser_encoded_rejection_is_readable_and_redacted_without_resubmitting(self):
        detail='Authentication Fail ErrCode=16 '+ACCOUNT+' '+PASSWORD
        encoded=base64.b64encode(detail.encode()).decode()
        outcome,submissions,_,diagnostic=self.run_portal(
            result=0,response_fields={'ret_code':'1','msg':encoded})
        self.assertIs(outcome,False)
        self.assertEqual(len(submissions),1)
        self.assertIn('Authentication Fail ErrCode=16',diagnostic['response']['msg'])
        for secret in (ACCOUNT,PASSWORD,encoded):
            self.assertNotIn(secret,json.dumps(diagnostic,ensure_ascii=False))

    def test_spaced_chinese_logout_uses_original_button_once(self):
        outcome, submissions, _, diagnostic = self.run_portal(operation='logout')
        self.assertIs(outcome, True, diagnostic)
        self.assertEqual(submissions, [{'a': ['logout']}])
        self.assertEqual(diagnostic['page_errors'], [])

    def test_spaced_logout_confirms_original_boxy_dialog(self):
        outcome, submissions, _, diagnostic = self.run_portal(
            operation='logout', logout_confirmation='boxy')
        self.assertIs(outcome, True, diagnostic)
        self.assertEqual(submissions, [{'a': ['logout']}])
        self.assertEqual(diagnostic['page_errors'], [])

    def test_unknown_boxy_prompt_is_not_confirmed(self):
        outcome, submissions, _, _ = self.run_portal(
            operation='logout', logout_confirmation='unrelated')
        self.assertIsNone(outcome)
        self.assertEqual(submissions, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
