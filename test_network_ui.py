"""Retired checking controls cannot return to the simple action UI."""
from pathlib import Path
import unittest

class TwoActionSurfaceTests(unittest.TestCase):
    def test_no_product_effect_checking_or_cancel_controls(self):
        html=Path(__file__).with_name('campus_ui.html').read_text(encoding='utf-8')
        for token in ('id="status-refresh"','id="network-check"','id="cancel-operation"','async function cancelOperation','async function refreshStatus','async function checkNetwork'):
            self.assertNotIn(token,html)
        self.assertIn('id="login-button"',html)
        self.assertIn('id="logout-button"',html)
