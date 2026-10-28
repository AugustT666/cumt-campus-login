"""Isolated core regressions; no real store, network requests or registry writes."""
from pathlib import Path
import gzip
import json
import tempfile
import tracemalloc
import unittest
from unittest.mock import MagicMock, patch
import zlib

import campus_core as core


class SettingsRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = core.Store(self.root)

    def tearDown(self):
        self.temporary.cleanup()

    def test_invalid_json_and_root_types_recover_without_destroying_original(self):
        for raw in (b'{', b'null', b'42', b'[null]'):
            with self.subTest(raw=raw):
                self.store.path.write_bytes(raw)
                settings = self.store.load()
                self.assertIs(settings['stu_autostart'], False)
                self.assertTrue(self.store.settings_warning)
                self.assertEqual(Path(self.store.settings_backup).read_bytes(), raw)
                self.assertEqual(self.store.path.read_bytes(), raw)
                self.store.write_settings(settings)
                self.assertEqual(Path(self.store.settings_backup).read_bytes(), raw)
                self.assertIs(json.loads(self.store.path.read_text('utf-8'))['stu_autostart'], False)

    def test_wrong_field_type_disables_automatic_behavior_and_uses_safe_defaults(self):
        payload = {'stu_autostart': 'false', 'auto_enabled': True,
                   'auto_submit': True, 'quiet_hours': 'false',
                   'trusted_hosts': None, 'portal_hint': 42, 'operator': 'unknown'}
        self.store.path.write_text(json.dumps(payload), encoding='utf-8')
        settings = self.store.load()
        for key in ('stu_autostart', 'auto_enabled', 'auto_submit'):
            self.assertIs(settings[key], False)
        self.assertIs(settings['quiet_hours'], True)
        self.assertEqual(settings['trusted_hosts'], [core.KNOWN_HOST])
        self.assertEqual(settings['portal_hint'], '')
        self.assertEqual(settings['operator'], '')

    def test_valid_settings_and_custom_trusted_host_are_retained(self):
        payload = {'stu_autostart': True, 'quiet_hours': False,
                   'operator': 'telecom', 'trusted_hosts': ['10.2.7.251'],
                   'portal_hint': 'http://10.2.7.251/a79.htm'}
        self.store.path.write_text(json.dumps(payload), encoding='utf-8')
        settings = self.store.load()
        for key, value in payload.items():
            self.assertEqual(settings[key], value)
        self.assertEqual(self.store.settings_warning, '')

    def test_failed_backup_prevents_overwriting_damaged_source(self):
        original = b'null'
        self.store.path.write_bytes(original)
        with patch.object(Path, 'write_bytes', side_effect=OSError('read only')):
            settings = self.store.load()
            with self.assertRaises(OSError):
                self.store.write_settings(settings)
        self.assertEqual(self.store.path.read_bytes(), original)

    def test_untrusted_host_or_malformed_portal_hint_is_recovered(self):
        for payload in ({'trusted_hosts': ['evil.example'], 'stu_autostart': True},
                        {'portal_hint': 'http://evil.example/', 'stu_autostart': True}):
            self.store.path.write_text(json.dumps(payload), encoding='utf-8')
            settings = self.store.load()
            self.assertIs(settings['stu_autostart'], False)
            self.assertTrue(self.store.settings_warning)


class CredentialSchemaTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.store = core.Store(Path(self.temporary.name))
        self.original = b'synthetic ciphertext, never a real credential'
        self.store.credentials.write_bytes(self.original)

    def tearDown(self):
        self.temporary.cleanup()

    def test_bad_payloads_are_controlled_errors_and_original_is_retained(self):
        valid = {'id': 'p', 'account': 'fake', 'password': 'fake', 'operator': 'telecom'}
        for payload in ([], None, 42,
                        {'schema': 2, 'profiles': [valid], 'selected': []},
                        {'schema': 2, 'profiles': [valid], 'selected': 'missing'},
                        {'schema': 2, 'profiles': [dict(valid, operator='bad')], 'selected': 'p'},
                        {'account': ['bad'], 'password': 'fake'}):
            with self.subTest(payload=payload):
                with patch.object(core, 'protect', return_value=json.dumps(payload).encode()):
                    with self.assertRaises(RuntimeError):
                        self.store.profiles()
                self.assertEqual(self.store.credentials.read_bytes(), self.original)

    def test_missing_selection_is_normalized_without_choosing_an_account(self):
        payload = {'schema': 2, 'profiles': [
            {'id': 'p', 'account': 'fake', 'password': 'fake', 'operator': 'telecom'}]}
        with patch.object(core, 'protect', return_value=json.dumps(payload).encode()):
            self.assertEqual(self.store.profiles()['selected'], '')
            self.assertEqual(self.store.selected_profile(), {})
        self.assertEqual(self.store.credentials.read_bytes(), self.original)

    def test_empty_existing_ciphertext_is_not_silently_overwritten(self):
        self.store.credentials.write_bytes(b'')
        with self.assertRaises(RuntimeError):
            self.store.save_profile('', 'fake', 'fake', '')
        self.assertEqual(self.store.credentials.read_bytes(), b'')


def adapter(guid, index, ips):
    return {'guid': guid, 'index': index, 'ip': ips, 'mac': '',
            'gateway': [], 'dns': [], 'up': True, 'name': guid}


class WifiSelectionTests(unittest.TestCase):
    def read(self, entries, adapters):
        with patch.object(core, 'native_wifi', return_value=entries), \
             patch.object(core, 'adapter_snapshot', return_value=adapters):
            return core.read_wifi()

    def test_teacher_network_is_selected_before_unrelated_wlan(self):
        selected = self.read([('Home', 'home'), (core.TEC, 'tec')],
                             [adapter('home', 1, ['192.168.1.10']),
                              adapter('tec', 2, ['10.2.1.10'])])
        self.assertEqual(selected.ssid, core.TEC)
        self.assertEqual(selected.index, 2)
        self.assertTrue(selected.ready)

    def test_ready_teacher_network_wins_over_student_without_an_address(self):
        selected = self.read([(core.STU, 'stu'), (core.TEC, 'tec')],
                             [adapter('stu', 1, ['169.254.1.1']),
                              adapter('tec', 2, ['10.2.1.10'])])
        self.assertEqual(selected.ssid, core.TEC)

    def test_ready_student_network_is_preferred_when_both_are_ready(self):
        selected = self.read([(core.TEC, 'tec'), (core.STU, 'stu')],
                             [adapter('tec', 1, ['10.2.1.10']),
                              adapter('stu', 2, ['10.2.1.11'])])
        self.assertEqual(selected.ssid, core.STU)

    def test_address_selection_skips_invalid_addresses_and_prefers_campus_ip(self):
        selected = self.read([(core.STU, 'stu')], [adapter('stu', 2, [
            '0.0.0.0', '127.0.0.1', '169.254.1.1', '224.0.0.1',
            '255.255.255.255', '192.168.1.10', '10.2.1.10'])])
        self.assertEqual(selected.ip, '10.2.1.10')
        for address in ('0.0.0.0', '127.0.0.1', '169.254.1.1',
                        '224.0.0.1', '255.255.255.255', 'not an ip'):
            self.assertFalse(core.Wifi(core.STU, 'g', 2, address).ready)

    def test_powershell_fallback_uses_the_same_teacher_priority_and_ip_filter(self):
        with patch.object(core, 'native_wifi', return_value=[('Home', 'home'), (core.TEC, 'tec')]), \
             patch.object(core, 'powershell_json', side_effect=[
                 {'index': 1, 'ip': ['192.168.1.10']},
                 {'index': 2, 'ip': ['0.0.0.0', '10.2.1.10']} ]):
            selected = core.read_wifi_powershell_fallback()
        self.assertEqual((selected.ssid, selected.index, selected.ip),
                         (core.TEC, 2, '10.2.1.10'))


class BoundedDecodingTests(unittest.TestCase):
    def decode(self, body, encoding):
        return core.decode_http_body(body, {'Content-Encoding': encoding})[0]

    def test_gzip_and_deflate_expansion_is_bounded_before_full_allocation(self):
        payload = b'x' * (4 * 1024 * 1024)
        for encoding, compressed in [('gzip', gzip.compress(payload)),
                                     ('deflate', zlib.compress(payload))]:
            with self.subTest(encoding=encoding):
                with patch.object(core, 'MAX_HTTP_DECODED_BYTES', 65536, create=True):
                    tracemalloc.start()
                    try:
                        with self.assertRaises(ValueError):
                            self.decode(compressed, encoding)
                        _, peak = tracemalloc.get_traced_memory()
                    finally:
                        tracemalloc.stop()
                self.assertLess(peak, 1024 * 1024)

    def test_truncated_invalid_and_gzip_crc_errors_are_value_errors(self):
        good = gzip.compress(b'portal content')
        damaged = good[:-8] + bytes([good[-8] ^ 1]) + good[-7:]
        for encoding, body in [('gzip', good[:-1]), ('gzip', damaged),
                               ('gzip', b'bad'), ('deflate', b'bad'),
                               ('deflate', zlib.compress(b'portal')[:-1])]:
            with self.subTest(encoding=encoding, body=body):
                with self.assertRaises(ValueError):
                    self.decode(body, encoding)

    def test_layered_encodings_raw_deflate_and_multiple_gzip_members_still_work(self):
        raw = b'legacy portal content'
        raw_deflater = zlib.compressobj(wbits=-zlib.MAX_WBITS)
        encoded = raw_deflater.compress(raw) + raw_deflater.flush()
        self.assertEqual(self.decode(encoded, 'deflate'), raw)
        self.assertEqual(self.decode(zlib.compress(gzip.compress(raw)), 'gzip, deflate'), raw)
        self.assertEqual(self.decode(gzip.compress(b'one') + gzip.compress(b'two'), 'gzip'), b'onetwo')

    def test_excessive_encoding_layers_and_members_are_rejected(self):
        body = b'portal'
        for _ in range(5):
            body = gzip.compress(body)
        with self.assertRaises(ValueError):
            self.decode(body, ','.join(['gzip'] * 5))
        with self.assertRaises(ValueError):
            self.decode(gzip.compress(b'') * 33, 'gzip')

    def test_size_limit_applies_to_combined_members_and_exact_limit_is_valid(self):
        with patch.object(core, 'MAX_HTTP_DECODED_BYTES', 65536):
            self.assertEqual(len(self.decode(gzip.compress(b'x' * 65536), 'gzip')), 65536)
            with self.assertRaises(ValueError):
                self.decode(gzip.compress(b'x' * 40000) + gzip.compress(b'y' * 40000), 'gzip')
            with self.assertRaises(ValueError):
                self.decode(b'x' * 65537, 'identity')

    def test_fetch_rejects_wire_limit_before_decoding_a_truncated_resource(self):
        response = MagicMock()
        response.read.return_value = b'x' * 65
        connection = MagicMock()
        connection.getresponse.return_value = response
        wifi = core.Wifi(core.STU, 'synthetic', 2, '10.2.1.10')
        with patch.object(core, 'MAX_HTTP_WIRE_BYTES', 64), \
             patch.object(core, 'BoundHTTP', return_value=connection):
            with self.assertRaises(ValueError):
                core.fetch('http://10.2.5.251/a79.htm', wifi, reader=lambda: wifi)
        response.read.assert_called_once_with(65)
        connection.close.assert_called_once()


if __name__ == '__main__':
    unittest.main(verbosity=2)
