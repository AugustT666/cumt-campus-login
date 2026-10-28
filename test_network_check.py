"""The diagnostic compares TCP sockets only; no HTTP or credentials are sent."""
import errno
import socket
import unittest
from unittest.mock import MagicMock, patch

import campus_core as core
import campus_network as network


WIFI = core.Wifi('CUMT_Stu', 'tcp-check-fixture', 11, '10.52.1.2', '00-11-22-33-44-55')


class NetworkCheckTests(unittest.TestCase):
    def sockets(self):
        sockets = [MagicMock() for _ in range(3)]
        for sock in sockets:
            sock.getsockname.return_value = (WIFI.ip, 50000)
        return sockets

    def run_checks(self, sockets, reader=lambda: WIFI):
        with patch.object(network.socket, 'socket', side_effect=sockets), \
                patch.object(network.os, 'name', 'nt'):
            return network.run_check(WIFI, reader=reader)

    def assert_no_payload(self, sockets):
        for sock in sockets:
            sock.send.assert_not_called()
            sock.sendall.assert_not_called()
            sock.sendto.assert_not_called()

    def test_binding_modes_use_only_fixed_target_and_close_without_send(self):
        sockets = self.sockets()
        reader = MagicMock(return_value=WIFI)
        result = self.run_checks(sockets, reader)
        self.assertEqual(reader.call_count, 6)
        self.assertEqual([item['mode'] for item in result['checks']], list(network.MODES))
        self.assertTrue(all(item['success'] for item in result['checks']))
        sockets[0].setsockopt.assert_called_once_with(socket.IPPROTO_IP, 31,
                                                    socket.htonl(WIFI.index))
        sockets[0].bind.assert_called_once_with((WIFI.ip, 0))
        sockets[1].setsockopt.assert_not_called()
        sockets[1].bind.assert_called_once_with((WIFI.ip, 0))
        sockets[2].setsockopt.assert_not_called()
        sockets[2].bind.assert_not_called()
        for sock in sockets:
            sock.connect.assert_called_once_with((core.KNOWN_HOST, 80))
            self.assertLessEqual(sock.settimeout.call_args.args[0], 2.0)
            sock.close.assert_called_once()
        self.assert_no_payload(sockets)
        self.assertEqual(result['authentication_requests'], 0)
        self.assertIs(result['network_changes'], False)
        self.assertNotIn('guid', str(result))
        self.assertNotIn(WIFI.mac, str(result))
        self.assertIn('TCP', result['summary'])

    def test_permission_errors_preserve_phase_and_numeric_code(self):
        sockets = self.sockets()
        error = PermissionError(errno.EACCES, 'synthetic access denied')
        error.winerror = 10013
        for sock in sockets:
            sock.connect.side_effect = error
        result = self.run_checks(sockets)
        for item, sock in zip(result['checks'], sockets):
            self.assertFalse(item['success'])
            self.assertEqual(item['phase'], 'connect')
            self.assertEqual(item['winerror'], 10013)
            self.assertEqual(item['network_error']['code'], 'permission_denied')
            sock.close.assert_called_once()
        self.assertIn('权限拒绝', result['summary'])
        self.assert_no_payload(sockets)

    def test_bind_failure_is_not_misreported_as_connect(self):
        sockets = self.sockets()
        sockets[0].bind.side_effect = PermissionError(errno.EACCES, 'synthetic denied')
        result = self.run_checks(sockets)
        self.assertEqual(result['checks'][0]['phase'], 'bind')
        sockets[0].connect.assert_not_called()
        sockets[0].close.assert_called_once()
        self.assertIn('仅绑定源地址', result['summary'])
        self.assert_no_payload(sockets)

    def test_source_paths_fail_but_default_success_has_specific_summary(self):
        sockets = self.sockets()
        for sock in sockets[:2]:
            sock.connect.side_effect = TimeoutError('synthetic timeout')
        result = self.run_checks(sockets)
        self.assertEqual(result['checks'][0]['network_error']['code'], 'timeout')
        self.assertIn('系统默认路径可连接', result['summary'])
        self.assertIn('校园 WiFi 的绑定连接失败', result['summary'])
        self.assert_no_payload(sockets)

    def test_all_timeouts_remain_network_errors(self):
        sockets = self.sockets()
        for sock in sockets:
            sock.connect.side_effect = TimeoutError('synthetic timeout')
        result = self.run_checks(sockets)
        self.assertTrue(all(item['network_error']['code'] == 'timeout'
                            for item in result['checks']))
        self.assertIn('三种路径均未连接', result['summary'])
        self.assert_no_payload(sockets)

    def test_network_change_after_first_check_stops_next_socket(self):
        sockets = self.sockets()
        changed = core.Wifi('CUMT_Stu', WIFI.guid, WIFI.index, '10.52.1.3', WIFI.mac)
        reader = MagicMock(side_effect=[WIFI, changed])
        with patch.object(network.socket, 'socket', side_effect=sockets) as factory:
            result = network.run_check(WIFI, reader=reader)
        self.assertEqual(factory.call_count, 1)
        self.assertEqual(result['aborted'], 'network_context_changed_or_unavailable')
        self.assertEqual(len(result['checks']), 1)
        sockets[0].close.assert_called_once()
        self.assert_no_payload(sockets)

    def test_missing_wifi_makes_no_socket(self):
        with patch.object(network.socket, 'socket') as factory:
            result = network.run_check(core.Wifi(), reader=lambda: core.Wifi())
        factory.assert_not_called()
        self.assertEqual(result['aborted'], 'wifi_not_ready')
        self.assertEqual(result['checks'], [])

    def test_guard_rejects_before_first_probe(self):
        with patch.object(network.socket, 'socket') as factory:
            result = network.run_check(WIFI, reader=lambda: core.Wifi())
        factory.assert_not_called()
        self.assertEqual(result['aborted'], 'network_context_changed_or_unavailable')

    def test_tec_is_allowed_for_manual_read_only_diagnostic(self):
        tec = core.Wifi(core.TEC, 'tec-fixture', WIFI.index, WIFI.ip, WIFI.mac)
        sockets = self.sockets()
        with patch.object(network.socket, 'socket', side_effect=sockets):
            result = network.run_check(tec, reader=lambda: tec)
        self.assertEqual(len(result['checks']), 3)
        self.assertNotIn('aborted', result)

    def test_default_reader_is_resolved_when_called(self):
        sockets = self.sockets()
        with patch.object(core, 'read_wifi', return_value=WIFI) as reader, \
                patch.object(network.socket, 'socket', side_effect=sockets):
            result = network.run_check(WIFI)
        self.assertEqual(reader.call_count, 6)
        self.assertEqual(len(result['checks']), 3)

    def test_shared_deadline_prevents_additional_connections(self):
        sockets = self.sockets()
        with patch.object(network.socket, 'socket', side_effect=sockets) as factory, \
                patch.object(network.time, 'monotonic', side_effect=[0, 0, 0, 2.1, 6.1, 6.1]):
            result = network.run_check(WIFI, reader=lambda: WIFI)
        self.assertEqual(factory.call_count, 1)
        self.assertEqual(result['aborted'], 'time_budget_exhausted')
        self.assertEqual(len(result['checks']), 1)
        sockets[0].close.assert_called_once()
        self.assert_no_payload(sockets)

    def test_setsockopt_failure_closes_socket_before_any_connect(self):
        sockets = self.sockets()
        sockets[0].setsockopt.side_effect = PermissionError(errno.EACCES, 'synthetic denied')
        result = self.run_checks(sockets)
        self.assertEqual(result['checks'][0]['phase'], 'setsockopt')
        sockets[0].bind.assert_not_called()
        sockets[0].connect.assert_not_called()
        sockets[0].close.assert_called_once()
        self.assert_no_payload(sockets)


if __name__ == '__main__':
    unittest.main()
