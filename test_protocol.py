"""Isolated protocol regressions: no sockets, credentials, or real WiFi reads."""
import base64
from dataclasses import replace
import http.client
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, quote, urlsplit
import zipfile

import campus_core as core
from campus_logging import RuntimeLog
import campus_protocol as protocol

WIFI = core.Wifi(core.STU, 'offline-protocol', 9, '10.52.151.131',
                 '00-11-22-33-44-55', '10.52.191.254')
PORTAL = 'http://10.2.5.251/a79.htm?wlanacname=DORM-NAS&nasip=10.2.4.1&vlan=42'
ACCOUNT, PASSWORD = 'offline+&账号', 'offline-password+&='


def _function(name):
    return name + ': function() { return "' + name + '"; }'


def documents():
    a41 = '''var jsVersion='3.0'; var accountSuffix=""; var machineno="";
var accountPrefix=0; var enPerceive=0; var autoPerceive=0; var eportalv6=0;
var enHttps=0; var enMd5=0; var enableR3=0; var unBindmac=0; var acLogout=0;
var page = {kind:'pc',name:'site-custom',
eportal:window.location.protocol + '//' + window.location.hostname + ':801/eportal/',
''' + _function('setArgs') + '''};
var term = {''' + _function('init') + '};'
    names = ('login_portal', 'logout_portal', 'portal_login', 'portal_logout',
             'setISP', 'getTempAccountSuffix')
    a42 = 'var login = {' + ','.join(_function(name) for name in names) + '};'
    config = '''var pageSetting=2;
ipPageAry[0]="Default|0.0.0.0|255.255.255.255|||1|0";
ipPageAry[1]="Disabled legacy|10.52.0.1|10.52.255.254|||0|0";
ipPageAry[2]="Dynamic dorm|10.3.0.1;10.52.0.1|10.4.255.254;10.52.255.254|||1|1";
ipPageAry[3]="Empty disabled|0.0.0.0|0.0.0.0|||0";
'''
    for name in ('getMatchPage', 'getLoginMethod', 'getPageType', 'getVirtualMachineno', 'compareIP'):
        config += 'function ' + name + '(){return "' + name + '";}\n'
    html = '''<form name="f3" onsubmit="return ee(3)">
<input name="DDDDD"><input name="upass" type="password"></form>
<select name="ISP_select"><option value="-1">请选择运营商</option>
<option value="@telecom">中国电信</option><option value="@unicom">中国联通</option>
<option value="@cmcc">中国移动</option><option value="">校园网</option></select>'''
    # JSON string syntax is also a supported JS string literal.
    pc = 'var bodyContent=' + json.dumps(html, ensure_ascii=False) + ';'
    return {'a79.htm': '<!--Dr.COMWebLoginID_0.htm--><script src="a41.js"></script><script>vlanid="0";</script>',
            'a41.js': a41, 'a42.js': a42, 'config.js': config,
            'loginbox.js': 'var password_cut=0;', 'pc.js': pc}


def fixture_fingerprints(docs):
    return {kind: protocol._script_fingerprint(docs[kind + '.js'], kind)
            for kind in ('a41', 'a42', 'config', 'loginbox')}


def add_ip_row(docs, row):
    # Dynamic rows belong to the existing data block, before executable logic.
    docs['config.js'] = docs['config.js'].replace('function getMatchPage', row + '\nfunction getMatchPage', 1)


class MemoryPortal:
    def __init__(self, docs=None):
        self.docs = docs or documents()
        self.requests = []
        self.submissions = []
        self.response = {'result': 1, 'msg': '认证成功'}
        self.status_response = {'result': 0, 'v46ip': WIFI.ip, 'ss5': WIFI.ip}
        self.auth_exception = None

    def get(self, url, wifi, **kw):
        self.requests.append(url)
        p = urlsplit(url)
        if p.path == '/drcom/chkstatus':
            return 200, '', 'campus_status(' + json.dumps(self.status_response) + ');'
        if p.path == '/eportal/':
            self.submissions.append(parse_qs(p.query, keep_blank_values=True))
            if self.auth_exception:
                raise self.auth_exception
            callback = self.submissions[-1]['callback'][0]
            return 200, '', callback + '(' + json.dumps(self.response, ensure_ascii=False) + ')'
        name = p.path.rsplit('/', 1)[-1]
        if name in ('config.js', 'pc.js', 'loginbox.js'):
            assert p.port == 801, 'Configuration resources must use official eportal port'
            assert p.path.startswith('/eportal/extern/site-custom/'), 'Use actual page name, not a fixed number'
        if name in self.docs:
            return 200, '', self.docs[name]
        return 404, '', ''


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.docs = documents()
        self.whitelist = patch.dict(protocol.KNOWN_SCRIPTS, fixture_fingerprints(self.docs), clear=True)
        self.whitelist.start()
        self.memory = MemoryPortal(self.docs)
        self.engine = protocol.Engine(WIFI, PORTAL, reader=lambda: WIFI, getter=self.memory.get)
        self.store_protection = patch.object(core, 'Store', side_effect=AssertionError('No real credential store'))
        self.store_protection.start()

    def tearDown(self):
        self.store_protection.stop()
        self.whitelist.stop()

    def test_dynamic_scheme_and_ip_row_are_read_from_actual_config(self):
        plan = self.engine.prepare()
        self.assertEqual(plan['page_index'], 2)
        self.assertEqual(plan['endpoint'], 'http://10.2.5.251:801/eportal/')
        self.assertEqual(plan['ac_name'], 'DORM-NAS')
        self.assertEqual(plan['ac_ip'], '', 'NAS IP must not be used as AC IP')
        self.assertEqual(plan['vlan'], '42')
        self.assertIn('/eportal/extern/site-custom/ip/2/pc.js', self.memory.requests[-2])

    def test_last_enabled_matching_ip_row_wins(self):
        add_ip_row(self.docs, 'ipPageAry[8]="Later|10.52.0.1|10.52.255.254|||1|1";')
        plan = self.engine.prepare()
        self.assertEqual(plan['page_index'], 8)

    def test_disabled_later_local_protocol_does_not_override(self):
        add_ip_row(self.docs, 'ipPageAry[8]="Disabled|10.52.0.1|10.52.255.254|||0|0";')
        self.assertEqual(self.engine.prepare()['page_index'], 2)

    def test_unknown_local_protocol_falls_back_before_submitting(self):
        add_ip_row(self.docs, 'ipPageAry[8]="Local|10.52.0.1|10.52.255.254|||1|0";')
        with self.assertRaises(protocol.UnsupportedPortal):
            self.engine.authenticate(ACCOUNT, PASSWORD, 'campus')
        self.assertEqual(self.memory.submissions, [])

    def test_other_page_setting_requires_browser(self):
        self.docs['config.js'] = self.docs['config.js'].replace('pageSetting=2', 'pageSetting=3')
        with self.assertRaises(protocol.UnsupportedPortal):
            self.engine.prepare()

    def test_changed_protocol_function_fails_fingerprint_before_submission(self):
        self.docs['a42.js'] = self.docs['a42.js'].replace('return "login_portal"', 'return "changed"')
        with self.assertRaises(protocol.UnsupportedPortal):
            self.engine.authenticate(ACCOUNT, PASSWORD, 'campus')
        self.assertEqual(self.memory.submissions, [])

    def test_numeric_security_flag_requires_browser(self):
        self.docs['a41.js'] = self.docs['a41.js'].replace('enMd5=0', 'enMd5=1')
        with self.assertRaises(protocol.UnsupportedPortal):
            self.engine.prepare()

    def test_campus_empty_suffix_and_special_characters_are_preserved(self):
        result, trace = self.engine.authenticate(ACCOUNT, PASSWORD, 'campus')
        self.assertIs(result, True)
        self.assertEqual(len(self.memory.submissions), 1)
        params = self.memory.submissions[0]
        self.assertEqual(params['user_account'], [ACCOUNT])
        self.assertEqual(params['user_password'], [PASSWORD])
        self.assertEqual(params['wlan_user_ip'], [WIFI.ip])
        self.assertEqual(params['wlan_user_mac'], ['001122334455'])
        self.assertEqual(params['wlan_ac_name'], ['DORM-NAS'])
        self.assertEqual(trace['authentication_requests'], 1)
        self.assertNotIn(ACCOUNT, json.dumps(trace, ensure_ascii=False))
        self.assertNotIn(PASSWORD, json.dumps(trace, ensure_ascii=False))

    def test_operator_suffix_is_taken_from_real_option(self):
        self.docs['pc.js'] = self.docs['pc.js'].replace('@telecom', '@actual-isp')
        self.engine.authenticate(ACCOUNT, PASSWORD, 'telecom')
        self.assertEqual(self.memory.submissions[0]['user_account'], [ACCOUNT + '@actual-isp'])

    def test_missing_operator_option_stops_before_submission(self):
        self.docs['pc.js'] = self.docs['pc.js'].replace('中国电信', 'Unspecified').replace('@telecom', '@unknown')
        with self.assertRaises(protocol.UnsupportedPortal):
            self.engine.authenticate(ACCOUNT, PASSWORD, 'telecom')
        self.assertEqual(self.memory.submissions, [])

    def test_captcha_requires_original_browser_flow(self):
        html = '<input name="DDDDD"><input name="upass"><input name="captcha">'
        self.docs['pc.js'] = 'var bodyContent=' + json.dumps(html) + ';'
        with self.assertRaises(protocol.UnsupportedPortal):
            self.engine.prepare()

    def test_custom_form_script_requires_original_browser_flow(self):
        self.docs['pc.js'] += 'password_cut=1;'
        with self.assertRaises(protocol.UnsupportedPortal):
            self.engine.prepare()

    def test_before_submit_cancellation_sends_no_authentication(self):
        def stop():
            raise RuntimeError('cancelled')
        with self.assertRaisesRegex(RuntimeError, 'cancelled'):
            self.engine.authenticate(ACCOUNT, PASSWORD, 'campus', before_submit=stop)
        self.assertEqual(self.memory.submissions, [])

    def test_network_changes_invalidate_cached_plan(self):
        self.engine.prepare()
        self.engine.reader = lambda: replace(WIFI, ip='10.52.151.132')
        with self.assertRaises(RuntimeError):
            self.engine.authenticate(ACCOUNT, PASSWORD, 'campus')
        self.assertEqual(self.memory.submissions, [])

    def test_timeout_after_submission_is_unknown_and_does_not_retry(self):
        self.memory.auth_exception = TimeoutError('may have reached server')
        result, trace = self.engine.authenticate(ACCOUNT, PASSWORD, 'campus')
        self.assertIsNone(result)
        self.assertEqual(len(self.memory.submissions), 1)
        self.assertEqual(trace['phase'], 'response_unconfirmed')
        self.assertEqual(trace['error'], 'TimeoutError')

    def reply_without_late_wifi_read(self, response, expected, *, changed=False,
                                    http_status=200, location=''):
        memory = MemoryPortal(self.docs)
        memory.response = response
        arrived = False
        late_reads = []
        def reader():
            if arrived:
                late_reads.append(True)
                if changed:
                    return replace(WIFI, ip='10.52.151.132')
                raise RuntimeError('Fictional WLAN read failed after reply')
            return WIFI
        def getter(url, wifi, **kwargs):
            nonlocal arrived
            reply = memory.get(url, wifi, **kwargs)
            if urlsplit(url).path == '/eportal/':
                arrived = True
                return http_status, location, reply[2]
            return reply
        engine = protocol.Engine(WIFI, PORTAL, reader=reader, getter=getter)
        result, trace = engine.authenticate(ACCOUNT, PASSWORD, 'campus')
        self.assertIs(result, expected)
        self.assertIs(trace['result'], expected)
        self.assertEqual(trace['phase'], 'response_received' if expected is not None else 'response_unconfirmed')
        self.assertEqual(late_reads, [], 'A received reply must not depend on a later native WLAN read')
        self.assertEqual(len(memory.submissions), 1)
        self.assertEqual(trace['authentication_requests'], 1)
        self.assertNotIn('error', trace)

    def test_received_success_survives_later_native_read_failure(self):
        self.reply_without_late_wifi_read({'result': 1}, True)

    def test_received_rejection_and_unknown_are_preserved_without_native_reads(self):
        for response, expected in (({'result': 0, 'msg': '认证失败'}, False),
                                   ({'result': 'pending'}, None),
                                   ({'unrecognized': 1}, None)):
            with self.subTest(response=response):
                self.reply_without_late_wifi_read(response, expected)

    def test_network_change_after_reply_does_not_rewrite_received_ack(self):
        # The application separately scopes feedback to retained network state;
        # the protocol layer must preserve the fact that this request was ACKed.
        self.reply_without_late_wifi_read({'result': 1}, True, changed=True)

    def test_unconfirmed_http_reply_is_not_upgraded_by_skipping_late_wifi_read(self):
        for status, location in ((500, ''), (200, '/a79.htm')):
            with self.subTest(status=status, location=location):
                self.reply_without_late_wifi_read({'result': 1}, None,
                                                 http_status=status, location=location)

    def test_network_change_before_submit_still_blocks_credentials(self):
        def changed():
            self.engine.reader = lambda: replace(WIFI, ip='10.52.151.132')
        with self.assertRaises(RuntimeError):
            self.engine.authenticate(ACCOUNT, PASSWORD, 'campus', before_submit=changed)
        self.assertEqual(self.memory.submissions, [])

    def test_explicit_failure_is_not_retried(self):
        self.memory.response = {'result': 0, 'msg': '认证失败'}
        result, trace = self.engine.authenticate(ACCOUNT, PASSWORD, 'campus')
        self.assertIs(result, False)
        self.assertEqual(len(self.memory.submissions), 1)
        self.assertEqual(trace['response']['msg'], '认证失败')

    def test_jsonp_ok_success_and_unknown_result(self):
        for value, expected in (('ok', True), ('pending', None), (2, None)):
            with self.subTest(value=value):
                self.memory.response = {'result': value}
                result, _ = self.engine.authenticate(ACCOUNT, PASSWORD, 'campus')
                self.assertIs(result, expected)

    def test_logout_uses_official_placeholder_and_current_context_without_secret(self):
        result, trace = self.engine.authenticate('', '', '', operation='logout')
        self.assertIs(result, True)
        params = self.memory.submissions[0]
        self.assertEqual(params['a'], ['logout'])
        self.assertEqual(params['user_account'], ['drcom'])
        self.assertEqual(params['user_password'], ['123'])
        self.assertEqual(params['wlan_vlan_id'], ['42'])
        self.assertEqual(params['wlan_user_ip'], [WIFI.ip])
        self.assertEqual(trace['authentication_requests'], 1)

    def test_credentials_in_server_message_are_redacted_in_all_common_forms(self):
        encoded = base64.b64encode(PASSWORD.encode()).decode()
        self.memory.response = {'result': 0, 'msg': ACCOUNT + ' ' + PASSWORD + ' ' + quote(PASSWORD, safe='') + ' ' + encoded}
        _, trace = self.engine.authenticate(ACCOUNT, PASSWORD, 'campus')
        text = json.dumps(trace, ensure_ascii=False)
        for secret in (ACCOUNT, PASSWORD, quote(PASSWORD, safe=''), encoded):
            self.assertNotIn(secret, text)

    def test_official_encoded_error_branches_are_decoded_before_redaction(self):
        for code,encoding in (('1','utf-8'),('4','gb18030')):
            with self.subTest(code=code):
                message='认证失败 Authentication Fail ErrCode=16 '+ACCOUNT+' '+PASSWORD
                self.memory.response={'result':0,'ret_code':code,
                                      'msg':base64.b64encode(message.encode(encoding)).decode()}
                result,trace=self.engine.authenticate(ACCOUNT,PASSWORD,'campus')
                self.assertIs(result,False)
                self.assertIn('认证失败 Authentication Fail ErrCode=16',trace['response']['msg'])
                for secret in (ACCOUNT,PASSWORD,self.memory.response['msg']):
                    self.assertNotIn(secret,json.dumps(trace,ensure_ascii=False))
        self.assertEqual(len(self.memory.submissions),2)

    def test_message_decoding_does_not_guess_error_meanings_or_decode_other_branches(self):
        encoded=base64.b64encode(b'Authentication Fail ErrCode=16').decode()
        self.assertEqual(protocol.decode_portal_message(encoded,'1'),'Authentication Fail ErrCode=16')
        self.assertEqual(protocol.decode_portal_message(encoded,'4'),'Authentication Fail ErrCode=16')
        for code in ('0','2','3','5',None):
            self.assertEqual(protocol.decode_portal_message(encoded,code),encoded)

    def test_invalid_noncanonical_binary_or_plain_text_message_is_preserved(self):
        for message in ('认证失败','not base64!?','YWJj=',base64.b64encode(b'\x00\x01\x02').decode(),'',None):
            with self.subTest(message=message):
                self.assertEqual(protocol.decode_portal_message(message,'1'),message)

    def test_status_reads_current_wifi_without_prepare_or_credentials(self):
        result = self.engine.status()
        self.assertEqual(result['state'], 'offline')
        self.assertTrue(result['matched_ip'])
        self.assertEqual(len(self.memory.requests), 1)
        self.assertEqual(self.memory.submissions, [])

    def test_online_status_preserves_server_identity_without_a_raw_uid_field(self):
        self.memory.status_response = {'result': 1, 'v46ip': '  ' + WIFI.ip + ' ', 'uid': ' fixture-online-user '}
        result = self.engine.status()
        self.assertEqual(result['state'], 'online')
        self.assertEqual(result['online_account'], 'fixture-online-user')
        self.assertEqual(result['binding'], 'source_ip_only')
        self.assertNotIn('uid', result)

    def test_status_identity_tracks_the_server_account_instead_of_a_previous_account(self):
        for account in ('fixture-user-A@unicom', 'fixture-user-B', 'fixture-user-C@telecom'):
            with self.subTest(account=account):
                self.memory.status_response = {'result': 1, 'v46ip': WIFI.ip, 'uid': account}
                self.assertEqual(self.engine.status()['online_account'], account)
        self.memory.status_response = {'result': 1, 'v46ip': WIFI.ip}
        self.assertEqual(self.engine.status()['online_account'], '')

    def test_invalid_or_placeholder_server_identity_is_not_presented_as_an_account(self):
        for value in (None, 123, False, [], {}, '', '   ', '12345678901234567890123456',
                      'fixture\nuser', 'fixture\tuser', 'fixture\x00user', 'fixture\u202euser', 'x' * 129):
            with self.subTest(value=value):
                self.memory.status_response = {'result': 1, 'v46ip': WIFI.ip, 'uid': value}
                result = self.engine.status()
                self.assertEqual(result['state'], 'online')
                self.assertEqual(result['online_account'], '')

    def test_offline_status_does_not_reuse_an_old_server_identity(self):
        self.memory.status_response = {'result': 0, 'v46ip': WIFI.ip, 'uid': 'fixture-stale-account'}
        result = self.engine.status()
        self.assertEqual(result['state'], 'offline')
        self.assertEqual(result['online_account'], '')

    def test_session_mac_conflict_rejects_an_ip_echo_as_online_proof(self):
        for fields in ({'olmac': '66-77-88-99-AA-BB'}, {'ss4': '66778899aabb'},
                       {'olmac': WIFI.mac, 'ss4': '66:77:88:99:aa:bb'}):
            with self.subTest(fields=fields):
                self.memory.status_response = {'result': 1, 'v46ip': WIFI.ip,
                                               'uid': 'fixture-other-device', **fields}
                result = self.engine.status()
                self.assertEqual(result['state'], 'unknown')
                self.assertEqual(result['detail'], 'session_mac_mismatch')
                self.assertTrue(result['matched_ip'])
                self.assertTrue(result['mac_conflict'])
                self.assertEqual(result['binding'], 'conflict')
                self.assertEqual(self.memory.submissions, [])

    def test_reported_session_ip_can_differ_when_the_reported_mac_is_current(self):
        self.memory.status_response = {'result': 1, 'v46ip': WIFI.ip, 'ss5': WIFI.ip,
                                       'uid': 'fixture-current-user', 'olip': '10.52.1.123',
                                       'olmac': '00:11:22:33:44:55'}
        result = self.engine.status()
        self.assertEqual(result['state'], 'online')
        self.assertTrue(result['ip_conflict'])
        self.assertFalse(result['mac_conflict'])
        self.assertEqual(result['binding'], 'mac_verified')
        self.assertEqual(result['server_mac'], '001122334455')
        self.assertEqual(result['server_ip'], '10.52.1.123')

    def test_different_session_ip_without_a_matching_mac_is_unconfirmed(self):
        self.memory.status_response = {'result': 1, 'v46ip': WIFI.ip, 'ss5': WIFI.ip,
                                       'olip': '10.52.1.123', 'olmac': '000000000000'}
        result = self.engine.status()
        self.assertEqual(result['state'], 'unknown')
        self.assertEqual(result['detail'], 'session_ip_mismatch')
        self.assertTrue(result['ip_conflict'])
        self.assertEqual(self.memory.submissions, [])

    def test_zero_and_malformed_session_mac_values_do_not_create_false_conflicts(self):
        for value in ('00:00:00:00:00:00', '', 'not-a-mac', None, 123, '00:11:22:33:44'):
            with self.subTest(value=value):
                self.memory.status_response = {'result': 1, 'v46ip': WIFI.ip,
                                               'olmac': value, 'ss4': value}
                result = self.engine.status()
                self.assertEqual(result['state'], 'online')
                self.assertFalse(result['mac_conflict'])
                self.assertEqual(result['server_mac'], '')

    def test_status_trace_carries_identity_only_in_a_sensitive_structured_field(self):
        events = []
        self.memory.status_response = {'result': 1, 'v46ip': WIFI.ip, 'uid': 'fixture-sensitive-identity'}
        with core.trace_scope(lambda event, **fields: events.append((event, fields))):
            self.engine.status()
        results = [fields['result'] for event, fields in events if event == 'protocol.status_result']
        self.assertEqual(results[0]['online_account'], 'fixture-sensitive-identity')
        for event, fields in events:
            self.assertNotIn('uid', fields)
            if event != 'protocol.status_result':
                self.assertNotIn('fixture-sensitive-identity', json.dumps(fields))

    def test_status_identity_is_hidden_in_disk_logs_and_diagnostic_export(self):
        identity = 'fixture-online-private-identity'
        self.memory.status_response = {'result': 1, 'v46ip': WIFI.ip, 'uid': identity}
        with tempfile.TemporaryDirectory() as temporary:
            log = RuntimeLog(Path(temporary), core.VERSION)
            try:
                # No stored profile or secret registration: sensitive field names
                # alone must protect a server account first seen after reopening.
                with core.trace_scope(log.event):
                    result = self.engine.status()
                self.assertEqual(result['online_account'], identity)
                self.assertNotIn(identity, log.path.read_text('utf-8'))
                bundle = log.export_bundle({'session': result})
                with zipfile.ZipFile(bundle) as archive:
                    for name in archive.namelist():
                        self.assertNotIn(identity.encode(), archive.read(name), name)
                    snapshot = json.loads(archive.read('snapshot.json'))
                    self.assertEqual(snapshot['session']['online_account'], '[REDACTED]')
            finally:
                log.close()

    def test_wrong_missing_or_conflicting_ip_keeps_status_unknown(self):
        for data in ({'result': 1}, {'result': 1, 'v46ip': '10.2.1.2'},
                     {'result': 1, 'v46ip': WIFI.ip, 'ss5': '10.2.1.2'}):
            with self.subTest(data=data):
                self.memory.status_response = data
                self.assertEqual(self.engine.status()['state'], 'unknown')

    def test_status_unknown_result_does_not_assume_offline(self):
        self.memory.status_response = {'result': 'unknown', 'ss5': WIFI.ip}
        self.assertEqual(self.engine.status()['state'], 'unknown')

    def test_status_transport_exception_is_unknown(self):
        self.engine.getter = lambda *args, **kwargs: (_ for _ in ()).throw(http.client.RemoteDisconnected())
        self.assertEqual(self.engine.status()['state'], 'unknown')


class ParsingTests(unittest.TestCase):
    def test_jsonp_rejects_generic_html_and_extra_code(self):
        for text in ('<p>认证成功</p>', 'callback({"result":1}); alert(1)', '[1]', 'callback({broken})'):
            with self.subTest(text=text):
                self.assertIsNone(protocol.parse_jsonp(text))
        self.assertEqual(protocol.parse_jsonp(' callback({"result":1}); '), {'result': 1})

    def test_fingerprint_preserves_comments_token_spacing_and_semantic_newlines(self):
        self.assertNotEqual(protocol._fingerprint('{ return "hello world"; }'),
                            protocol._fingerprint('{/*note*/return "hello world";}'))
        self.assertNotEqual(protocol._fingerprint('{return "hello world";}'),
                            protocol._fingerprint('{return "helloworld";}'))
        self.assertNotEqual(protocol._fingerprint('{return value;}'),
                            protocol._fingerprint('{return\nvalue;}'))
        self.assertNotEqual(protocol._fingerprint('{return value;}'),
                            protocol._fingerprint('{returnvalue;}'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
