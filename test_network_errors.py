"""Transport regressions using fake sockets and portal responses only."""
import errno
import socket
import ssl
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlsplit

import campus_core as core


WIFI = core.Wifi(core.STU, 'synthetic-guid', 11, '10.52.160.42',
                 '00-11-22-33-44-55')
ADDRESS = (core.KNOWN_HOST, 80)
RESOLVED = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ADDRESS)]
HTML = '<html><input name="DDDDD"><input name="upass"></html>'


def permission_error():
    error = PermissionError(errno.EACCES, 'synthetic connection refusal')
    error.winerror = 10013
    return error


class NetworkErrorDetailsTests(unittest.TestCase):
    def test_windows_permission_error_preserves_real_numeric_code_and_phase(self):
        error = permission_error()
        error._campus_phase = 'connect'
        details = core.network_error_details(error)
        self.assertEqual(details['code'], 'permission_denied')
        self.assertEqual(details['winerror'], 10013)
        self.assertEqual(details['errno'], errno.EACCES)
        self.assertEqual(details['error_type'], 'PermissionError')
        self.assertEqual(details['phase'], 'connect')
        self.assertIn('10013', details['message'])

    def test_permission_errors_without_10013_do_not_invent_windows_code(self):
        for error in (PermissionError('synthetic refusal'),
                      PermissionError(errno.EACCES, 'synthetic refusal'),
                      PermissionError(errno.EPERM, 'synthetic refusal')):
            with self.subTest(error=repr(error)):
                details = core.network_error_details(error)
                self.assertEqual(details['code'], 'permission_denied')
                self.assertNotIn('10013', details['message'])
                self.assertNotIn('winerror', details)

    def test_dns_timeout_and_other_connection_failures_are_distinct(self):
        cases = [(socket.gaierror(11001, 'synthetic DNS failure'), 'dns_failed'),
                 (TimeoutError('synthetic timeout'), 'timeout'),
                 (OSError(errno.ETIMEDOUT, 'synthetic timeout'), 'timeout'),
                 (ssl.SSLError(1, 'synthetic TLS failure'), 'connection_failed'),
                 (ConnectionRefusedError(errno.ECONNREFUSED, 'synthetic refusal'), 'connection_failed')]
        for error, code in cases:
            with self.subTest(code=code, error=repr(error)):
                self.assertEqual(core.network_error_details(error)['code'], code)

    def test_wrapped_transport_cause_is_retained(self):
        error = permission_error()
        error._campus_phase = 'connect'
        wrapper = RuntimeError('discovery wrapper')
        wrapper.__cause__ = error
        self.assertEqual(core.network_error_details(wrapper), core.network_error_details(error))

    def test_non_network_exceptions_and_cause_cycles_are_safe(self):
        self.assertEqual(core.network_error_details(ValueError('bad page')), {})
        cyclic = RuntimeError('cycle')
        cyclic.__cause__ = cyclic
        self.assertEqual(core.network_error_details(cyclic), {})

    def test_portal_error_exposes_details_without_sharing_returned_dictionary(self):
        error = core.PortalNetworkError(permission_error())
        self.assertIn('10013', str(error))
        details = core.network_error_details(error)
        details['code'] = 'modified'
        self.assertEqual(error.network_error['code'], 'permission_denied')


class BoundTransportFailureTests(unittest.TestCase):
    def test_each_connection_stage_retains_original_exception_and_is_logged(self):
        for stage in ('resolve', 'socket', 'setsockopt', 'bind', 'connect', 'tls'):
            with self.subTest(stage=stage):
                error = ssl.SSLError(1, 'synthetic TLS failure') if stage == 'tls' else permission_error()
                sock, context, events = MagicMock(), MagicMock(), []
                if stage in ('setsockopt', 'bind', 'connect'):
                    getattr(sock, stage).side_effect = error
                if stage == 'tls':
                    context.wrap_socket.side_effect = error
                def capture(event, **fields):
                    events.append((event, fields))
                with patch.object(core.os, 'name', 'nt'), \
                     patch.object(core.socket, 'getaddrinfo', side_effect=error if stage == 'resolve' else None,
                                  return_value=RESOLVED), \
                     patch.object(core.socket, 'socket', side_effect=error if stage == 'socket' else None,
                                  return_value=sock) as factory, \
                     patch.object(core.ssl, 'create_default_context', return_value=context), \
                     core.trace_scope(capture):
                    connection = core.BoundHTTP(core.KNOWN_HOST, 80, WIFI, secure=stage == 'tls')
                    with self.assertRaises(type(error)) as raised:
                        connection.connect()
                self.assertIs(raised.exception, error)
                self.assertEqual(error._campus_phase, stage)
                failures = [fields for event, fields in events if event == 'http.connect_error']
                self.assertEqual(len(failures), 1)
                self.assertEqual(failures[0]['phase'], stage)
                self.assertEqual(failures[0]['error_type'], type(error).__name__)
                self.assertEqual(failures[0].get('winerror'), getattr(error, 'winerror', None))
                self.assertIsNone(connection.sock)
                if stage == 'resolve':
                    factory.assert_not_called()
                elif stage != 'socket':
                    sock.close.assert_called_once()

    def test_permission_refusal_does_not_retry_another_dns_address(self):
        sock = MagicMock()
        error = permission_error()
        sock.connect.side_effect = error
        with patch.object(core.socket, 'getaddrinfo', return_value=RESOLVED * 2), \
             patch.object(core.socket, 'socket', return_value=sock) as factory:
            with self.assertRaises(PermissionError) as raised:
                core.BoundHTTP(core.KNOWN_HOST, 80, WIFI).connect()
        self.assertIs(raised.exception, error)
        factory.assert_called_once()
        sock.connect.assert_called_once_with(ADDRESS)

    def test_other_connection_failure_can_try_next_address_with_same_wifi_binding(self):
        failed, good = MagicMock(), MagicMock()
        failed.connect.side_effect = ConnectionRefusedError(errno.ECONNREFUSED, 'synthetic refusal')
        second = (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.2.5.252', 80))
        with patch.object(core.os, 'name', 'nt'), \
             patch.object(core.socket, 'getaddrinfo', return_value=RESOLVED + [second]), \
             patch.object(core.socket, 'socket', side_effect=[failed, good]):
            connection = core.BoundHTTP(core.KNOWN_HOST, 80, WIFI)
            connection.connect()
        self.assertIs(connection.sock, good)
        for sock in (failed, good):
            sock.bind.assert_called_once_with((WIFI.ip, 0))
            sock.setsockopt.assert_called_once_with(socket.IPPROTO_IP, 31, socket.htonl(WIFI.index))
        failed.close.assert_called_once()
        good.close.assert_not_called()

    def test_socket_cleanup_error_does_not_hide_the_connection_error(self):
        sock, error = MagicMock(), permission_error()
        sock.connect.side_effect = error
        sock.close.side_effect = OSError('synthetic cleanup failure')
        with patch.object(core.socket, 'getaddrinfo', return_value=RESOLVED), \
             patch.object(core.socket, 'socket', return_value=sock):
            with self.assertRaises(PermissionError) as raised:
                core.BoundHTTP(core.KNOWN_HOST, 80, WIFI).connect()
        self.assertIs(raised.exception, error)


class DiscoveryTransportFailureTests(unittest.TestCase):
    def discover(self, getter, hint=''):
        return core.discover(WIFI, hint, reader=lambda: WIFI, getter=getter)

    def test_public_denial_continues_to_known_campus_before_dns(self):
        calls = []
        def getter(url, wifi, **kwargs):
            calls.append(url)
            if urlsplit(url).hostname == core.KNOWN_HOST:
                return 200, '', HTML
            raise permission_error()
        portal, _ = self.discover(getter)
        self.assertEqual(urlsplit(portal).hostname, core.KNOWN_HOST)
        self.assertEqual([urlsplit(url).hostname for url in calls],
                         ['9.9.9.9', '1.1.1.1', core.KNOWN_HOST])

    def test_public_redirect_retains_actual_ac_parameters_before_hints(self):
        calls = []
        def getter(url, wifi, **kwargs):
            calls.append(url)
            if urlsplit(url).hostname == '9.9.9.9':
                return 302, 'http://10.2.7.251/a79.htm?wlanacname=ACTUAL-AC&wlanuserip=10.0.0.1', ''
            return 200, '', HTML
        portal, _ = self.discover(getter, 'http://10.2.8.251/a79.htm')
        self.assertEqual(len(calls), 2)
        self.assertEqual(urlsplit(portal).hostname, '10.2.7.251')
        self.assertEqual(parse_qs(urlsplit(portal).query)['wlanacname'], ['ACTUAL-AC'])
        self.assertEqual(parse_qs(urlsplit(portal).query)['wlanuserip'], [WIFI.ip])

    def test_known_campus_permission_denial_retains_cause_and_skips_domain(self):
        calls, error = [], permission_error()
        error._campus_phase = 'connect'
        def getter(url, wifi, **kwargs):
            calls.append(url)
            raise error
        with self.assertRaises(core.PortalNetworkError) as raised:
            self.discover(getter)
        self.assertIs(raised.exception.__cause__, error)
        self.assertEqual(raised.exception.network_error['winerror'], 10013)
        self.assertNotIn('go.cumt.edu.cn', [urlsplit(url).hostname for url in calls])
        self.assertEqual(len(calls), 3)
        self.assertNotIn('复制', str(raised.exception))

    def test_hint_is_tried_before_known_campus_and_domain(self):
        calls = []
        def getter(url, wifi, **kwargs):
            calls.append(urlsplit(url).hostname)
            if calls[-1] == '10.2.7.251':
                return 200, '', HTML
            raise OSError('synthetic unreachable')
        self.discover(getter, 'http://10.2.7.251/a79.htm')
        self.assertEqual(calls, ['9.9.9.9', '1.1.1.1', '10.2.7.251'])

    def test_campus_connection_failure_is_not_masked_by_later_dns_error(self):
        error = ConnectionRefusedError(errno.ECONNREFUSED, 'synthetic campus refusal')
        error._campus_phase = 'connect'
        def getter(url, wifi, **kwargs):
            host = urlsplit(url).hostname
            if host == core.KNOWN_HOST:
                raise error
            if host == 'go.cumt.edu.cn':
                raise socket.gaierror(11001, 'synthetic DNS failure')
            raise TimeoutError('synthetic public timeout')
        with self.assertRaises(core.PortalNetworkError) as raised:
            self.discover(getter)
        self.assertIs(raised.exception.__cause__, error)
        self.assertEqual(raised.exception.network_error['code'], 'connection_failed')

    def test_dns_error_retained_if_no_campus_transport_cause_exists(self):
        error = socket.gaierror(11001, 'synthetic DNS failure')
        def getter(url, wifi, **kwargs):
            if urlsplit(url).hostname == core.KNOWN_HOST:
                raise ValueError('synthetic malformed transfer')
            raise error
        with self.assertRaises(core.PortalNetworkError) as raised:
            self.discover(getter)
        self.assertIs(raised.exception.__cause__, error)
        self.assertEqual(raised.exception.network_error['code'], 'dns_failed')

    def test_unknown_reachable_campus_page_is_not_mislabeled_as_network_denial(self):
        def getter(url, wifi, **kwargs):
            if urlsplit(url).hostname == core.KNOWN_HOST:
                return 200, '', '<html>unknown layout</html>'
            raise permission_error()
        with self.assertRaises(RuntimeError) as raised:
            self.discover(getter)
        self.assertNotIsInstance(raised.exception, core.PortalNetworkError)
        self.assertEqual(core.network_error_details(raised.exception), {})


if __name__ == '__main__':
    unittest.main()
