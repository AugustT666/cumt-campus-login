"""Manual state inspection is available without cancel or network self-tests."""
from pathlib import Path
import unittest

class ActionSurfaceTests(unittest.TestCase):
    def test_manual_status_and_primary_actions_remain_without_retired_controls(self):
        html=Path(__file__).with_name('campus_ui.html').read_text(encoding='utf-8')
        for token in ('id="network-check"','id="cancel-operation"','async function cancelOperation','async function checkNetwork'):
            self.assertNotIn(token,html)
        for token in ('id="status-refresh"','async function refreshStatus','id="login-button"','id="logout-button"'):
            self.assertIn(token,html)
