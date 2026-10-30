"""Transport failures stay visible without submitting or retrying authentication."""
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch
import zipfile

import campus_app as app
import campus_core as core
import campus_protocol as protocol
import campus_selfservice as selfservice
from test_protocol import MemoryPortal, documents, fixture_fingerprints


WIFI = core.Wifi(core.STU, 'network-feedback-fixture', 11, '10.52.7.23',
                 '00-11-22-33-44-55')
PORTAL = 'http://10.2.5.251/a79.htm'
ACCOUNT, PASSWORD = 'fictional-network-user', 'fictional-network-password'


def denied():
    error = PermissionError('fictional socket access denied')
    error.winerror = 10013
    error.errno = 13
    error._campus_phase = 'connect'
    return error


def denied_status():
    return {'state': 'unknown', 'detail': 'status_unreachable',
            'network_error': core.network_error_details(denied())}


class ProtocolNetworkFeedbackTests(unittest.TestCase):
    def test_status_preserves_connect_phase_and_numeric_error(self):
        getter = MagicMock(side_effect=denied())
        engine = protocol.Engine(WIFI, PORTAL, reader=lambda: WIFI, getter=getter)
        report = engine.status()
        self.assertEqual(report['state'], 'unknown')
        self.assertEqual(report['detail'], 'status_unreachable')
        self.assertEqual(report['network_error']['code'], 'permission_denied')
        self.assertEqual(report['network_error']['winerror'], 10013)
        self.assertEqual(report['network_error']['phase'], 'connect')
        getter.assert_called_once()

    def test_bad_response_is_not_misreported_as_windows_network_denial(self):
        engine = protocol.Engine(WIFI, PORTAL, reader=lambda: WIFI,
                                 getter=MagicMock(side_effect=ValueError('bad response body')))
        report = engine.status()
        self.assertEqual(report['state'], 'unknown')
        self.assertNotIn('network_error', report)

    def test_permission_denied_preparation_does_not_become_browser_fallback(self):
        engine = protocol.Engine(WIFI, PORTAL, reader=lambda: WIFI,
                                 getter=MagicMock(side_effect=denied()))
        client = app.App.__new__(app.App)
        client.session_engine = MagicMock(return_value=engine)
        client.authenticate = MagicMock()
        client.auth_diagnostic = {}
        with self.assertRaisesRegex(core.PortalNetworkError, '10013') as caught:
            client.run_authentication(WIFI, ACCOUNT, PASSWORD, 'campus', 'login', False, lambda: None)
        self.assertIsInstance(caught.exception.__cause__, PermissionError)
        client.authenticate.assert_not_called()
        engine.getter.assert_called_once()

    def test_network_failure_after_submission_keeps_unknown_and_single_request(self):
        docs = documents()
        portal = MemoryPortal(docs)
        portal.auth_exception = TimeoutError('response never arrived')
        engine = protocol.Engine(WIFI, PORTAL, reader=lambda: WIFI, getter=portal.get)
        with patch.dict(protocol.KNOWN_SCRIPTS, fixture_fingerprints(docs), clear=True):
            result, diagnostic = engine.authenticate(ACCOUNT, PASSWORD, 'campus')
        self.assertIsNone(result)
        self.assertEqual(diagnostic['phase'], 'response_unconfirmed')
        self.assertEqual(diagnostic['authentication_requests'], 1)
        self.assertEqual(diagnostic['network_error']['code'], 'timeout')
        self.assertEqual(len(portal.submissions), 1)


from test_logout_recovery import LogoutRecoveryFixture,ACCOUNT,PASSWORD,unknown

class AppNetworkFeedbackTests(LogoutRecoveryFixture):
    def login(self):return self.execute(lambda:self.client.login(ACCOUNT,PASSWORD,'campus','own-profile'))
    def test_permission_refusal_preserves_the_real_transport_reason(self):
        cause=PermissionError(10013,'Fictional Windows refusal');cause.winerror=10013
        self.client.run_authentication.side_effect=core.PortalNetworkError(cause)
        self.login()
        self.assertIn('10013',self.client.status)
        self.assertFalse(self.client.logged_in)
        self.status_query.assert_not_called();self.internet.assert_not_called()
    def test_unknown_reply_after_one_attempt_is_checked_but_never_retried(self):
        self.probe_observation=unknown()
        self.native_result=None;self.login()
        self.client.run_authentication.assert_called_once()
        self.assertIn('无法确认',self.client.status)
        self.assertIsNone(self.client.auth_diagnostic['request_accepted'])
        self.status_query.assert_not_called();self.internet.assert_not_called()
    def test_worker_error_is_retained_without_an_automatic_recovery_action(self):
        self.client.run_authentication.side_effect=RuntimeError('Fictional transport rejection')
        self.login()
        self.assertIn('Fictional transport rejection',self.client.status)
        self.service_factory.assert_not_called()
        self.status_query.assert_not_called();self.internet.assert_not_called()
    def test_management_connection_failure_does_not_submit_a_pod(self):
        cause=PermissionError(10013,'Fictional management refusal');cause.winerror=10013
        self.web.login_error=cause;self.logout()
        self.assertEqual(self.web.submit_calls,0);self.assertEqual(self.web.close_calls,1)
        self.assertNotIn('注销成功',self.client.status)
        self.status_query.assert_not_called();self.internet.assert_not_called()
