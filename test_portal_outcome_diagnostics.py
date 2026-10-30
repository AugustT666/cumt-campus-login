"""Synthetic portal semantics and private-safe device selection diagnostics."""
import json
import socket
import unittest
from unittest.mock import patch

import campus_core as core
import campus_protocol as protocol
import campus_selfservice as service
import test_protocol as portal_fixture
import test_selfservice as self_fixture


class PortalResponseOutcomeTests(unittest.TestCase):
    def test_canonical_already_online_and_timeout_codes(self):
        for result_value in (0, '0'):
            for code, expected in ((2, 'already_online'), ('2', 'already_online'),
                                   (8, 'authentication_timeout'), ('8', 'authentication_timeout')):
                with self.subTest(result_value=result_value, code=code):
                    response = {'result': result_value, 'ret_code': code, 'msg': ''}
                    self.assertEqual(protocol.portal_response_outcome(False, response), expected)
                    self.assertIs(protocol._result(response), False)

    def test_noncanonical_results_codes_and_messages_cannot_invent_semantics(self):
        for value in (False, 0.0, '00', ' 0', None, 1, '1'):
            self.assertIsNone(protocol.portal_response_outcome(False, {'result': value, 'ret_code': '8'}))
        for code in (True, 2.0, 8.0, '08', ' 8', '8 ', 1, '1', None):
            self.assertIsNone(protocol.portal_response_outcome(False, {'result': '0', 'ret_code': code}))
        for result in (True, None, 0, 1):
            self.assertIsNone(protocol.portal_response_outcome(result, {'result': '0', 'ret_code': '8'}))
        for response in (None, [], {}, {'result': '0', 'msg': 'authentication timeout QUM5OTk='}):
            self.assertIsNone(protocol.portal_response_outcome(False, response))

    def test_engine_keeps_timeout_false_receipt_and_sends_once(self):
        docs = portal_fixture.documents()
        memory = portal_fixture.MemoryPortal(docs)
        memory.response = {'result': '0', 'ret_code': '8', 'msg': ''}
        with patch.dict(protocol.KNOWN_SCRIPTS, portal_fixture.fixture_fingerprints(docs), clear=True), \
             patch.object(core, 'Store', side_effect=AssertionError('No credential store')), \
             patch.object(socket.socket, 'connect', side_effect=AssertionError('No network')):
            engine = protocol.Engine(portal_fixture.WIFI, portal_fixture.PORTAL,
                                     reader=lambda: portal_fixture.WIFI, getter=memory.get)
            result, trace = engine.authenticate(portal_fixture.ACCOUNT, portal_fixture.PASSWORD, 'campus')
        self.assertIs(result, False)
        self.assertIs(trace['result'], False)
        self.assertEqual(trace['response_outcome'], 'authentication_timeout')
        self.assertEqual(trace['response']['ret_code'], '8')
        self.assertEqual(trace['authentication_requests'], 1)
        self.assertEqual(len(memory.submissions), 1)

    def test_logout_code_eight_does_not_acquire_login_timeout_semantics(self):
        docs = portal_fixture.documents()
        memory = portal_fixture.MemoryPortal(docs)
        memory.response = {'result': '0', 'ret_code': '8', 'msg': ''}
        with patch.dict(protocol.KNOWN_SCRIPTS, portal_fixture.fixture_fingerprints(docs), clear=True):
            engine = protocol.Engine(portal_fixture.WIFI, portal_fixture.PORTAL,
                                     reader=lambda: portal_fixture.WIFI, getter=memory.get)
            result, trace = engine.authenticate('', '', '', operation='logout')
        self.assertIs(result, False)
        self.assertNotIn('response_outcome', trace)
        self.assertEqual(len(memory.submissions), 1)


class DeviceMatchDiagnosticTests(unittest.TestCase):
    KEYS = {'exact_matches', 'current_ip_matches', 'current_mac_matches',
            'zero_mac_candidates', 'ip_other_mac_matches'}

    def setUp(self):
        self.enterContext(patch.object(core, 'Store', side_effect=AssertionError('No credential store')))
        self.enterContext(patch.object(socket.socket, 'connect', side_effect=AssertionError('No real network')))
        self.h = self_fixture.Harness()
        self.client = self.h.client()
        self.client.login(self_fixture.ACCOUNT, self_fixture.PASSWORD)
        self.addCleanup(self.client.close)

    def counts(self, rows, error=None):
        self.h.devices = rows
        devices = self.client.list_online_devices()
        if error is None:
            self.client.select_current_session(devices)
        else:
            with self.assertRaises(error):
                self.client.select_current_session(devices)
        last = next(fields for event, fields in reversed(self.h.traces)
                    if event == 'selfservice.device_match_counts')
        self.assertEqual(set(last), self.KEYS)
        self.assertTrue(all(type(v) is int and v >= 0 for v in last.values()))
        self.assertEqual(self.client.safe_summary()['matching_counts'], last)
        serialized = json.dumps(last)
        for private in (self_fixture.ACCOUNT, self_fixture.PASSWORD, self_fixture.WIFI.ip,
                        self_fixture.WIFI.mac, self_fixture.OWN['sessionId']):
            self.assertNotIn(private, serialized)
        self.assertEqual(self.h.count(service.DISCONNECT), 0)
        return last

    def test_exact_match_is_counted_without_mutation(self):
        counts = self.counts([self_fixture.OWN, self_fixture.OTHER])
        self.assertEqual(counts, {'exact_matches': 1, 'current_ip_matches': 1,
                                 'current_mac_matches': 1, 'zero_mac_candidates': 0,
                                 'ip_other_mac_matches': 0})

    def test_empty_list_is_distinguished_from_address_mismatch(self):
        self.assertEqual(self.counts([], service.NoMatchingDevice), dict.fromkeys(self.KEYS, 0))

    def test_current_ip_with_other_mac_is_not_relaxed(self):
        row = dict(self_fixture.OTHER, ip=self_fixture.WIFI.ip)
        counts = self.counts([row], service.NoMatchingDevice)
        self.assertEqual(counts['current_ip_matches'], 1)
        self.assertEqual(counts['ip_other_mac_matches'], 1)
        self.assertEqual(counts['exact_matches'], 0)
        self.assertEqual(counts['current_mac_matches'], 0)

    def test_current_mac_with_different_ip_is_not_relaxed(self):
        row = dict(self_fixture.OWN, ip=self_fixture.OTHER['ip'])
        counts = self.counts([row], service.NoMatchingDevice)
        self.assertEqual(counts['current_mac_matches'], 1)
        self.assertEqual(counts['current_ip_matches'], 0)
        self.assertEqual(counts['exact_matches'], 0)

    def test_zero_mac_candidate_still_requires_original_nas_proof(self):
        row = dict(self_fixture.OWN, mac='000000000000')
        with patch.object(service, 'observe_nas_binding', side_effect=service.SelfServiceError('Synthetic missing proof')) as observe:
            counts = self.counts([row], service.SelfServiceError)
        observe.assert_called_once()
        self.assertEqual(counts['zero_mac_candidates'], 1)
        self.assertEqual(counts['exact_matches'], 0)

    def test_duplicate_exact_matches_stay_ambiguous(self):
        rows = [self_fixture.OWN, dict(self_fixture.OWN, sessionId='fictional-duplicate')]
        counts = self.counts(rows, service.AmbiguousDevice)
        self.assertEqual(counts['exact_matches'], 2)

    def test_summary_does_not_expose_mutable_matching_counters(self):
        self.counts([self_fixture.OWN])
        summary = self.client.safe_summary()
        summary['matching_counts']['exact_matches'] = 1000
        self.assertEqual(self.client.safe_summary()['matching_counts']['exact_matches'], 1)


if __name__ == '__main__':
    unittest.main()
