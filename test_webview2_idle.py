"""A brief completed request must reset the browser's quiet interval."""
from types import SimpleNamespace
import threading
import unittest
from unittest.mock import patch

import campus_webview2 as native


class ResourceQuietWindowTests(unittest.TestCase):
    def test_request_between_polls_restarts_the_full_quiet_window(self):
        host = native.WebView2Host.__new__(native.WebView2Host)
        host._pending_lock = threading.Lock()
        host._pending = 0
        host._last_resource_activity = 0.0
        clock = [0.0]
        arrived = [False]

        def sleep(duration):
            previous = clock[0]
            clock[0] += duration
            # Request starts at .205 and finishes at .206, entirely between
            # the .20 and .21 polls: pending is zero at every observation.
            if not arrived[0] and previous < .206 <= clock[0]:
                arrived[0] = True
                with host._pending_lock:
                    host._last_resource_activity = .206

        with patch.object(native, 'time', SimpleNamespace(
                monotonic=lambda: clock[0], sleep=sleep)):
            self.assertTrue(host.wait_idle(timeout=1.0, quiet_period=.5))
        self.assertTrue(arrived[0])
        self.assertGreaterEqual(clock[0], .706)
        self.assertLess(clock[0], .73)


if __name__ == '__main__':
    unittest.main()
