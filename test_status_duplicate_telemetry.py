"""Status-only accommodation for the kernel's duplicated olno counter.

All values and identities below are fictional. Tests use in-memory replies,
never a Store, credential file or real network.
"""
import json
import unittest
from unittest.mock import MagicMock

import campus_app as app
import campus_core as core
import campus_protocol as protocol


WIFI = core.Wifi(core.STU, 'duplicate-status-fixture', 7,
                 '10.52.1.2', '00-11-22-33-44-55')
PORTAL = 'http://10.2.5.251/a79.htm'


def jsonp_pairs(pairs):
    return 'campus_status({' + ','.join(
        json.dumps(key) + ':' + json.dumps(value) for key, value in pairs) + '});'


def online_reply():
    # Shape follows a kernel online reply; identifiers and counters are all
    # synthetic. In particular the repeated counter is not a result or an
    # identity/binding field, and Engine.status never consumes it.
    pairs = [
        ('result', 1), ('time', 12), ('flow', 34), ('fsele', 0), ('fee', 0),
        ('m46', 0), ('v46ip', WIFI.ip), ('myv6ip', ''), ('oltime', 12),
        ('olflow', 34), ('lip', '10.2.5.251'), ('stime', '00:00:00'),
        ('etime', '00:00:12'), ('uid', 'fictional-status-user'), ('v6af', 0),
        ('v6df', 0), ('v46m', 0), ('v4ip', WIFI.ip), ('v6ip', ''),
        ('AC', 'fictional-ac'), ('ss5', WIFI.ip), ('ss6', ''), ('vid', 1),
        ('ss1', ''), ('ss4', '001122334455'), ('cvid', 1), ('pvid', 1),
        ('hotel', 0), ('aolno', 1), ('eport', 0), ('eclass', 0),
        ('zxopt', 0), ('NID', 'fictional-node'), ('olno', 7),
        ('udate', '2026-01-01'), ('olno', 7), ('olmac', '001122334455'),
        ('ollm', 0), ('olm1', ''), ('olm2', ''), ('olm3', 0), ('olmm', 0),
        ('olm5', 0), ('gid', 0), ('olip', '10.52.1.99'), ('oaf', 0),
        ('oat', 0), ('actM', 0), ('actt', 0), ('actdf', 0), ('actuf', 0),
        ('act6df', 0), ('act6uf', 0), ('allfm', 0), ('d1', 0), ('u1', 0),
        ('d2', 0), ('u2', 0), ('o1', 0), ('nd1', 0), ('nu1', 0),
        ('nd2', 0), ('nu2', 0), ('no1', 0),
    ]
    return jsonp_pairs(pairs)


class StatusDuplicateTelemetryTests(unittest.TestCase):
    def engine_status(self, reply):
        getter = MagicMock(return_value=(200, '', reply))
        engine = protocol.Engine(WIFI, PORTAL, reader=lambda: WIFI, getter=getter)
        result = engine.status()
        getter.assert_called_once()
        return result

    def test_real_shape_with_identical_top_counter_confirms_online_binding(self):
        report = self.engine_status(online_reply())
        self.assertEqual(report['state'], 'online')
        self.assertEqual(report['detail'], 'server_confirmed')
        self.assertTrue(report['matched_ip'])
        self.assertEqual(report['binding'], 'mac_verified')
        self.assertFalse(report['mac_conflict'])
        self.assertTrue(report['ip_conflict'], 'Different server IP evidence must remain visible')

    def test_zero_and_more_than_two_identical_counters_are_unambiguous(self):
        for value in (0, 7):
            with self.subTest(value=value):
                parsed = protocol.parse_status_jsonp(jsonp_pairs(
                    [('result', 1), ('olno', value), ('olno', value), ('olno', value)]))
                self.assertEqual(parsed, {'result': 1, 'olno': value})

    def test_ordinary_offline_status_remains_supported(self):
        report = self.engine_status(jsonp_pairs([('result', 0), ('v46ip', WIFI.ip)]))
        self.assertEqual(report['state'], 'offline')
        self.assertTrue(report['matched_ip'])

    def test_generic_authentication_and_browser_parser_stays_strict(self):
        reply = online_reply()
        self.assertIsNone(protocol.parse_jsonp(reply))
        self.assertIsNone(app.authentication_result(
            reply, 'http://10.2.5.251:801/eportal/?a=login', 'login'))

    def test_conflicting_counter_is_rejected_and_status_remains_unknown(self):
        reply = jsonp_pairs([('result', 1), ('v46ip', WIFI.ip), ('olno', 0), ('olno', 1)])
        self.assertIsNone(protocol.parse_status_jsonp(reply))
        self.assertEqual(self.engine_status(reply)['state'], 'unknown')

    def test_repeated_counter_requires_exact_nonnegative_integer_types(self):
        for first, second in ((-1, -1), (True, True), (1, True), (False, 0),
                              ('1', '1'), (1.0, 1.0), (1, 1.0), (None, None)):
            with self.subTest(first=first, second=second):
                self.assertIsNone(protocol.parse_status_jsonp(jsonp_pairs(
                    [('result', 1), ('olno', first), ('olno', second)])))

    def test_critical_and_unknown_duplicates_are_rejected_even_if_equal(self):
        fields = [('result', 1), ('ret_code', 2), ('uid', 'fictional-user'),
                  ('v46ip', WIFI.ip), ('ss5', WIFI.ip), ('olip', WIFI.ip),
                  ('olmac', '001122334455'), ('ss4', '001122334455'), ('unknown', 1)]
        for field, value in fields:
            with self.subTest(field=field):
                self.assertIsNone(protocol.parse_status_jsonp(jsonp_pairs(
                    [(field, value), (field, value), ('olno', 7), ('olno', 7)])))

    def test_nested_duplicates_are_rejected_in_objects_and_arrays(self):
        for nested in ('{"olno":7,"olno":7}', '[{"olno":7,"olno":7}]',
                       '{"result":1,"result":1}'):
            with self.subTest(nested=nested):
                reply = '{"result":1,"olno":7,"olno":7,"nested":' + nested + '}'
                self.assertIsNone(protocol.parse_status_jsonp(reply))
        self.assertIsNone(protocol.parse_status_jsonp('[{"olno":7,"olno":7}]'))

    def test_array_and_unique_nested_fields_do_not_gain_special_meaning(self):
        payload = '{"result":1,"olno":7,"olno":7,"nested":[{"olno":8},1]}'
        self.assertEqual(protocol.parse_status_jsonp(payload)['nested'], [{'olno': 8}, 1])
        self.assertIsNone(protocol.parse_status_jsonp('[{"result":1}]'))

    def test_existing_size_depth_and_nonfinite_limits_still_apply(self):
        invalid = [
            '{"olno":1,"olno":1,"value":NaN}',
            '{"olno":1,"olno":1,"value":Infinity}',
            '{"olno":1,"olno":1,"value":1e999}',
            '{"olno":1,"olno":1,"value":' + '[' * 33 + '0' + ']' * 33 + '}',
            '{"olno":1,"olno":1,"value":"' + 'a' * protocol.MAX_JSONP_BYTES + '"}',
            'campus_status({"olno":1,"olno":1});otherCall()',
            '{"olno":1,"olno":1,"value":}',
        ]
        for payload in invalid:
            with self.subTest(length=len(payload)):
                self.assertIsNone(protocol.parse_status_jsonp(payload))

    def test_counter_exception_does_not_relax_ip_or_mac_binding(self):
        parsed = protocol.parse_status_jsonp(online_reply())
        parsed['olmac'] = '001122334499'
        report = self.engine_status(json.dumps(parsed))
        self.assertEqual(report['state'], 'unknown')
        self.assertTrue(report['mac_conflict'])
        self.assertEqual(report['binding'], 'conflict')


if __name__ == '__main__':
    unittest.main()
