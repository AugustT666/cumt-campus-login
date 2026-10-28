"""Native WebView2 lifetime and cookie round trips without external traffic."""
from pathlib import Path
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import campus_webview2 as native
from campus_webview2 import WebView2Host


class WebView2CookieTests(unittest.TestCase):
    def test_session_persistent_expired_and_same_site_cookies_round_trip(self):
        expires = int(time.time()) + 3600
        cookies = [
            {'name': 'session', 'value': 'fictional-session', 'domain': '10.2.5.251',
             'path': '/', 'expires': -1, 'sameSite': 'Lax', 'httpOnly': True, 'secure': False},
            {'name': 'persistent', 'value': 'fictional-persistent', 'domain': '10.2.5.251',
             'path': '/', 'expires': expires, 'sameSite': 'Strict', 'httpOnly': True, 'secure': True},
            {'name': 'cross-site', 'value': 'fictional-cross-site', 'domain': '10.2.5.251',
             'path': '/', 'expires': expires, 'sameSite': 'None', 'httpOnly': False, 'secure': True},
            {'name': 'expired', 'value': 'must-not-be-revived', 'domain': '10.2.5.251',
             'path': '/', 'expires': int(time.time()) - 60, 'sameSite': 'Lax', 'secure': False},
        ]
        with WebView2Host(lambda request: None, host='10.2.5.251') as host:
            host.add_cookies(cookies)
            snapshot = host.cookies()
        actual = {cookie['name']: cookie for cookie in snapshot}
        self.assertEqual(set(actual), {'session', 'persistent', 'cross-site'})
        self.assertEqual(actual['session']['expires'], -1)
        self.assertEqual(actual['session']['sameSite'], 'Lax')
        self.assertIs(actual['session']['httpOnly'], True)
        self.assertIs(actual['session']['secure'], False)
        self.assertAlmostEqual(actual['persistent']['expires'], expires, delta=1)
        self.assertEqual(actual['persistent']['sameSite'], 'Strict')
        self.assertEqual(actual['cross-site']['sameSite'], 'None')
        self.assertIs(actual['cross-site']['secure'], True)

        # A fresh private control gets the saved compatibility cookie fields,
        # without requiring a persistent profile or touching the user's one.
        with WebView2Host(lambda request: None, host='10.2.5.251') as following:
            following.add_cookies(snapshot)
            restored = {cookie['name']: cookie for cookie in following.cookies()}
        self.assertEqual(set(restored), set(actual))
        for name, expected in actual.items():
            with self.subTest(name=name):
                for field in ('value', 'domain', 'path', 'httpOnly', 'secure', 'sameSite'):
                    self.assertEqual(restored[name][field], expected[field])
                self.assertAlmostEqual(restored[name]['expires'], expected['expires'], delta=1)


class WebView2LifetimeTests(unittest.TestCase):
    def fake_host(self):
        host = WebView2Host.__new__(WebView2Host)
        host._closed, host._closing, host._ended = (threading.Event() for _ in range(3))
        host._thread_started = True
        host._thread = SimpleNamespace(ManagedThreadId=2)
        host.Thread = SimpleNamespace(CurrentThread=SimpleNamespace(ManagedThreadId=1))
        host._form, host._view, host._pool, host._proxy_socket = (MagicMock() for _ in range(4))
        host._deferrals = {}
        host._response = lambda response: object()
        host._invoke = lambda function: function()
        host._remove_profile = MagicMock()
        host.Application = SimpleNamespace(ExitThread=MagicMock(side_effect=host._ended.set))
        return host

    def test_bad_deferral_does_not_skip_other_deferrals_or_native_disposal(self):
        host = self.fake_host()

        class BrokenResponse:
            @property
            def Response(self):
                return None

            @Response.setter
            def Response(self, value):
                raise ValueError('fictional response cleanup failure')

        broken, following = MagicMock(), MagicMock()
        broken.Complete.side_effect = OSError('fictional deferral failure')
        host._deferrals = {1: (BrokenResponse(), broken),
                           2: (SimpleNamespace(Response=None), following)}
        host._view.Dispose.side_effect = RuntimeError('fictional disposal failure')
        host._form.Close.side_effect = LookupError('fictional form cleanup failure')
        host.close()
        broken.Complete.assert_called_once()
        following.Complete.assert_called_once()
        host._view.Dispose.assert_called_once()
        host._form.Close.assert_called_once()
        host.Application.ExitThread.assert_called_once()
        self.assertEqual(host._deferrals, {})
        self.assertTrue(host.close_report['sta_ended'])
        self.assertTrue(host.close_report['proxy_released'])
        self.assertEqual(set(host.close_report['errors']),
                         {'ValueError', 'OSError', 'RuntimeError', 'LookupError'})
        host._proxy_socket.close.assert_called_once()
        host._remove_profile.assert_called_once()

    def test_unfinished_native_thread_keeps_proxy_guard_reserved(self):
        host = self.fake_host()
        host._form = None
        host._ended = MagicMock()
        host._ended.is_set.return_value = False
        host._ended.wait.return_value = False
        with patch.object(native, '_unfinished_hosts', []) as retained:
            host.close()
            self.assertIn(host, retained)
        self.assertFalse(host.close_report['sta_ended'])
        self.assertFalse(host.close_report['proxy_released'])
        host._proxy_socket.close.assert_not_called()
        host._remove_profile.assert_not_called()

    def test_proxy_reservation_failure_cleans_profile_before_loading_runtime(self):
        created = []
        original_mkdtemp = native.tempfile.mkdtemp

        def temporary(*args, **kwargs):
            value = original_mkdtemp(*args, **kwargs)
            created.append(Path(value))
            return value

        with patch.object(native.tempfile, 'mkdtemp', side_effect=temporary), \
                patch.object(native.socket, 'socket', side_effect=OSError('fictional reserve failure')), \
                patch.object(WebView2Host, '_load_runtime') as load:
            with self.assertRaisesRegex(OSError, 'reserve failure'):
                WebView2Host(lambda request: None, host='10.2.5.251')
        load.assert_not_called()
        self.assertEqual(len(created), 1)
        self.assertFalse(created[0].exists(), 'A failed constructor left its private profile behind')


if __name__ == '__main__':
    unittest.main(verbosity=2)
