"""Offline adversarial protocol regressions; no sockets or credential store."""
import json
from pathlib import Path
import socket
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import campus_core as core
import campus_protocol as protocol


WIFI = core.Wifi(core.STU, 'protocol-hardening-fixture', 9, '10.52.151.131',
                 '00-11-22-33-44-55', '10.52.191.254')
ROOT = Path(__file__).resolve().parent
CAPTURE = ROOT / '.local' / 'deep-audit' / 'live-capture'
PORTAL = 'http://10.2.5.251/a79.htm'


class OfflineTests(unittest.TestCase):
    def setUp(self):
        self.network = patch.object(socket.socket, 'connect', side_effect=AssertionError('No network'))
        self.storage = patch.object(core, 'Store', side_effect=AssertionError('No real Store'))
        self.network.start()
        self.storage.start()
        self.addCleanup(self.network.stop)
        self.addCleanup(self.storage.stop)


class JSONPHardeningTests(OfflineTests):
    def status_for(self, body):
        return protocol.Engine(WIFI, PORTAL, reader=lambda: WIFI,
                               getter=lambda *args, **kwargs: (200, '', body)).status()

    def test_deep_status_is_unknown_without_raising(self):
        body = '{"result":1,"v46ip":"' + WIFI.ip + '","extra":' + '[' * 20000 + '0' + ']' * 20000 + '}'
        self.assertIsNone(protocol.parse_jsonp(body))
        self.assertEqual(self.status_for(body)['state'], 'unknown')

    def test_oversized_status_is_unknown_without_raising(self):
        body = json.dumps({'result': 1, 'v46ip': WIFI.ip, 'msg': 'x' * (128 * 1024)})
        self.assertIsNone(protocol.parse_jsonp(body))
        self.assertEqual(self.status_for(body)['state'], 'unknown')

    def test_wrong_input_types_are_rejected(self):
        for value in (None, b'{"result":1}', [], 1, {}):
            with self.subTest(value=value):
                self.assertIsNone(protocol.parse_jsonp(value))
                self.assertEqual(self.status_for(value)['state'], 'unknown')

    def test_duplicate_keys_and_nonfinite_numbers_are_rejected(self):
        for body in ('{"result":0,"result":1}', '{"result":1,"extra":NaN}',
                     '{"result":1,"extra":Infinity}', '{"result":1,"extra":-Infinity}',
                     '{"result":1,"extra":1e999}'):
            with self.subTest(body=body):
                self.assertIsNone(protocol.parse_jsonp(body))

    def test_json_string_brackets_do_not_count_as_nested_objects(self):
        body = json.dumps({'result': 1, 'v46ip': WIFI.ip, 'msg': '[{' * 100 + '\\"'})
        self.assertEqual(self.status_for(body)['state'], 'online')

    def test_non_string_requester_ip_fields_cannot_confirm_session(self):
        for key in ('v46ip', 'ss5'):
            for invalid in ({}, [], 123, True, None):
                with self.subTest(key=key, value=invalid):
                    data = {'result': 1, 'v46ip': WIFI.ip, key: invalid}
                    self.assertEqual(self.status_for(json.dumps(data))['state'], 'unknown')

    def test_unsupported_status_resource_is_unknown(self):
        engine = protocol.Engine(WIFI, PORTAL, reader=lambda: WIFI,
                                 getter=lambda *args, **kwargs: (_ for _ in ()).throw(ValueError('bad encoding')))
        self.assertEqual(engine.status()['state'], 'unknown')

    def test_string_literal_escapes_do_not_adopt_python_semantics(self):
        self.assertEqual(protocol._literal(r'"a\/b"'), 'a/b')
        self.assertEqual(protocol._literal(r'"a\\/b"'), 'a\\/b')
        self.assertEqual(protocol._literal(r'"a\\N"'), 'a\\N')
        for value in (r'"\N{LATIN CAPITAL LETTER A}"', r'"\07"', r'"\uD800"'):
            with self.subTest(value=value), self.assertRaises(protocol.UnsupportedPortal):
                protocol._literal(value)


@unittest.skipUnless(all((CAPTURE / name).is_file() for name in
                        ('a41.js', 'a42.js', 'config.js', 'loginbox.js', 'pc.js')),
                     'Local public-script capture not available')
class CapturedPortalHardeningTests(OfflineTests):
    """These tests use production fingerprints unchanged, not fixture whitelists."""
    def setUp(self):
        super().setUp()
        self.docs = {name: (CAPTURE / name).read_text('utf-8')
                     for name in ('a41.js', 'a42.js', 'config.js', 'loginbox.js', 'pc.js')}
        self.docs['a79.htm'] = '<!--Dr.COMWebLoginID_0.htm--><script src="a41.js"></script><script>vlanid="0";</script>'
        self.requests = []
        self.submissions = []
        self.auth_body = 'offline_callback({"result":1})'

        def getter(url, wifi, **kwargs):
            self.requests.append(url)
            parts = urlsplit(url)
            if parts.path == '/eportal/':
                self.submissions.append(parse_qs(parts.query, keep_blank_values=True))
                return 200, '', self.auth_body
            return 200, '', self.docs[parts.path.rsplit('/', 1)[-1]]

        self.engine = protocol.Engine(WIFI, PORTAL, reader=lambda: WIFI, getter=getter)

    def assert_rejected_before_submission(self):
        with self.assertRaises(protocol.UnsupportedPortal):
            self.engine.authenticate('offline-account', 'offline-password-over-16-characters', 'campus')
        self.assertEqual(self.submissions, [])

    def test_real_captured_scripts_keep_native_plan_without_whitelist_patches(self):
        plan = self.engine.prepare()
        self.assertEqual(plan['page_index'], 2)
        self.assertEqual(plan['endpoint'], 'http://10.2.5.251:801/eportal/')

    def test_real_root_page_is_supported_without_whitelist_patches(self):
        path = ROOT / '.local' / 'portal-logout-audit' / 'a79.htm'
        if not path.is_file():
            self.skipTest('Local public root-page capture not available')
        self.docs['a79.htm'] = path.read_text('utf-8')
        self.assertEqual(self.engine.prepare()['page_index'], 2)

    def wire_root(self):
        path = ROOT / '.local' / 'portal-logout-audit' / 'a79.htm'
        if not path.is_file():
            self.skipTest('Local public root-page capture not available')
        # This already fingerprint-bound capture has CRCRLF from a Windows
        # text write. Model the reviewed wire response's single CRLF without
        # requiring the new private live capture in the regression suite.
        captured = path.read_text('utf-8')
        return captured.replace('\n\n', '\n').replace('\n', '\r\n')

    def test_live_wire_root_keeps_native_plan_without_whitelist_patches(self):
        self.docs['a79.htm'] = self.wire_root()
        self.assertEqual(self.engine.prepare()['page_index'], 2)
        self.assertEqual(self.submissions, [])

    def test_live_wire_root_rejects_unknown_inline_logic_before_submission(self):
        self.docs['a79.htm'] = self.wire_root() + '<script>enMd5=1;</script>'
        self.assert_rejected_before_submission()

    def test_live_wire_root_keeps_semantic_return_newline_rejected(self):
        self.docs['a79.htm'] = self.wire_root()
        original = self.docs['config.js']
        self.docs['config.js'] = original.replace('return paraArr[l];', 'return\nparaArr[l];')
        self.assertNotEqual(self.docs['config.js'], original)
        self.assert_rejected_before_submission()

    def test_unreviewed_inline_blank_line_variant_is_not_generally_normalized(self):
        original = self.wire_root()
        self.docs['a79.htm'] = original.replace('\tpage.run();', '\r\n\tpage.run();')
        self.assertNotEqual(self.docs['a79.htm'], original)
        self.assert_rejected_before_submission()

    def test_post_declaration_flags_are_rejected(self):
        self.docs['a41.js'] += '\nenMd5=1; enHttps=1;\n'
        self.assert_rejected_before_submission()

    def test_post_declaration_password_transform_is_rejected(self):
        self.docs['loginbox.js'] += '\npassword_cut=1;\n'
        self.assert_rejected_before_submission()

    def test_config_alias_assignment_is_rejected(self):
        self.docs['config.js'] += '\nipPageAry["2"]="changed|0.0.0.0|255.255.255.255|||1|0";\n'
        self.assert_rejected_before_submission()

    def test_function_replacement_outside_hashed_body_is_rejected(self):
        self.docs['a42.js'] += '\nlogin.portal_login=function(){return false;};\n'
        self.assert_rejected_before_submission()

    def test_semantic_return_newline_is_rejected(self):
        original = self.docs['config.js']
        self.docs['config.js'] = original.replace('return paraArr[l];', 'return\nparaArr[l];')
        self.assertNotEqual(self.docs['config.js'], original)
        self.assert_rejected_before_submission()

    def test_additional_root_script_is_rejected(self):
        self.docs['a79.htm'] += '<script src="new-auth-rules.js"></script>'
        self.assert_rejected_before_submission()

    def test_additional_inline_root_logic_is_rejected(self):
        self.docs['a79.htm'] += '<script>enMd5=1;</script>'
        self.assert_rejected_before_submission()

    def test_root_redirects_and_embedded_pages_are_rejected(self):
        original = self.docs['a79.htm']
        for extra in ('<meta http-equiv="refresh" content="0;url=http://10.2.7.251/new.htm">',
                      '<iframe src="http://10.2.7.251/extra.htm"></iframe>',
                      '<iframe srcdoc="&lt;script&gt;enMd5=1&lt;/script&gt;"></iframe>'):
            with self.subTest(extra=extra):
                self.docs['a79.htm'] = original + extra
                self.assert_rejected_before_submission()

    def test_duplicate_attributes_cannot_hide_an_active_page_or_form_event(self):
        self.docs['a79.htm'] += '<iframe src="http://10.2.7.251/extra.htm" src=""></iframe>'
        self.assert_rejected_before_submission()
        self.docs['a79.htm'] = '<!--Dr.COMWebLoginID_0.htm--><script src="a41.js"></script>'
        self.docs['pc.js'] = self.docs['pc.js'].replace(
            'onsubmit="return ee(3)"', 'onsubmit="enMd5=1" onsubmit="return ee(3)"')
        self.assert_rejected_before_submission()

    def test_form_input_event_logic_is_rejected(self):
        self.docs['pc.js'] = self.docs['pc.js'].replace('name="upass"', 'name="upass" onchange="enMd5=1"')
        self.assert_rejected_before_submission()

    def test_safe_dynamic_configuration_is_preserved(self):
        self.docs['a41.js'] = self.docs['a41.js'].replace("name:'123'", "name:'different-safe-site'")
        self.docs['config.js'] = self.docs['config.js'].replace('学生_new|10.3.0.1', 'Updated dorm|10.3.0.1')
        self.docs['pc.js'] = self.docs['pc.js'].replace('@telecom', '@safe-operator')
        plan = self.engine.prepare()
        self.assertTrue(any('/extern/different-safe-site/' in url for url in self.requests))
        self.assertEqual(plan['operators']['telecom'], '@safe-operator')

    def test_safe_dynamic_ip_row_is_used(self):
        self.docs['config.js'] = self.docs['config.js'].replace(
            'ipPageAry[17]="";', 'ipPageAry[17]="Later dorm|10.52.0.1|10.52.255.254|||1|1";')
        self.assertEqual(self.engine.prepare()['page_index'], 17)

    def test_huge_numeric_configuration_requires_browser_before_submission(self):
        self.docs['a41.js'] = self.docs['a41.js'].replace('var enMd5=0;', 'var enMd5=' + '9' * 5000 + ';')
        self.assert_rejected_before_submission()

    def set_portal_query(self, query):
        self.engine = protocol.Engine(WIFI, PORTAL + '?' + query, reader=lambda: WIFI, getter=self.engine.getter)

    def test_original_query_helper_uses_only_its_first_alias_even_if_empty(self):
        for query in ('acip=10.2.1.2&sysname=SECONDARY&vlanid=99',
                      'wlanacip=&acip=10.2.1.2&wlanacname=&sysname=SECONDARY&vlan=&vlanid=99'):
            with self.subTest(query=query):
                self.set_portal_query(query)
                plan = self.engine.prepare()
                self.assertEqual(plan['ac_ip'], '')
                self.assertEqual(plan['ac_name'], '')
                self.assertEqual(plan['vlan'], '0', 'Empty first alias uses the HTML default')

    def test_duplicate_critical_query_keys_require_browser(self):
        self.set_portal_query('wlanacip=10.2.1.2&WLANACIP=10.2.3.4')
        self.assert_rejected_before_submission()

    def test_ambiguous_original_unescape_encodings_require_browser(self):
        for query in ('wlanacname=DORM+NAS', 'wlanacname=%E4%B8%AD%E6%96%87',
                      'wlanacname=%u0041', 'wlanacname=%ZZ'):
            with self.subTest(query=query):
                self.set_portal_query(query)
                self.assert_rejected_before_submission()

    def test_ascii_percent_encoding_keeps_the_original_query_value(self):
        self.set_portal_query('wlanacname=DORM%2DNAS&wlanacip=10.2.1.2&vlan=42')
        plan = self.engine.prepare()
        self.assertEqual(plan['ac_name'], 'DORM-NAS')
        self.assertEqual(plan['ac_ip'], '10.2.1.2')
        self.assertEqual(plan['vlan'], '42')

    def test_later_operation_revalidates_scripts(self):
        self.engine.authenticate('offline-account', 'offline-password', 'campus')
        self.docs['a42.js'] += '\nlogin.portal_login=function(){return false;};\n'
        with self.assertRaises(protocol.UnsupportedPortal):
            self.engine.authenticate('offline-account', 'offline-password', 'campus')
        self.assertEqual(len(self.submissions), 1)

    def test_malformed_response_after_submission_never_falls_back_or_resubmits(self):
        self.auth_body = '{"result":1,"extra":' + '[' * 20000 + '0' + ']' * 20000 + '}'
        result, trace = self.engine.authenticate('offline-account', 'offline-password', 'campus')
        self.assertIsNone(result)
        self.assertEqual(trace['phase'], 'response_unconfirmed')
        self.assertEqual(len(self.submissions), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
