"""Rejected login replies stay replies: no hidden readback, retry or fallback."""
import campus_core as core
from test_logout_recovery import LogoutRecoveryFixture,ACCOUNT,PASSWORD,offline

class LoginReplyHandlingTests(LogoutRecoveryFixture):
    def test_rejected_login_keeps_its_receipt_after_a_short_status_check(self):
        self.probe_observation=offline()
        self.native_result=False
        self.execute(lambda:self.client.login(ACCOUNT,PASSWORD,'campus','own-profile'))
        self.client.run_authentication.assert_called_once()
        self.status_query.assert_not_called();self.internet.assert_not_called();self.service_factory.assert_not_called()
        self.assertFalse(self.client.logged_in)
    def test_previous_online_cache_does_not_suppress_a_new_explicit_click(self):
        self.client.logged_in=True;self.client.session_state='online';self.native_result=False
        self.execute(lambda:self.client.login(ACCOUNT,PASSWORD,'campus','own-profile'))
        self.client.run_authentication.assert_called_once()
        self.status_query.assert_not_called();self.internet.assert_not_called()
    def test_new_manual_request_after_rejection_is_one_new_request(self):
        self.native_result=False
        for _ in range(2):self.execute(lambda:self.client.login(ACCOUNT,PASSWORD,'campus','own-profile'))
        self.assertEqual(self.client.run_authentication.call_count,2)
        self.status_query.assert_not_called();self.internet.assert_not_called()

class StudentLoginReplyHandlingTests(LoginReplyHandlingTests):SSID=core.STU
