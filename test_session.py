"""One authentication plus bounded verification; memory reads do not poll."""
from unittest.mock import patch
import campus_app as app
import campus_core as core
from test_logout_recovery import LogoutRecoveryFixture,ACCOUNT,PASSWORD,offline,unknown

class LoginActionTests(LogoutRecoveryFixture):
    def login(self,automatic=False):
        return self.execute(lambda:self.client.login(ACCOUNT,PASSWORD,'campus','own-profile',automatic=automatic))
    def test_success_uses_one_authentication_and_the_bounded_status_observation(self):
        self.login()
        self.client.run_authentication.assert_called_once()
        self.assertEqual(self.client.run_authentication.call_args.args[4],'login')
        self.assertTrue(self.client.logged_in)
        self.assertEqual(self.client.identity_source,'verified_status')
        self.assertEqual(self.client.online_account,ACCOUNT)
        self.status_query.assert_not_called();self.internet.assert_not_called();self.service_factory.assert_not_called()
        self.bounded_probe.assert_called_once()
    def test_rejection_is_not_retried_after_the_bounded_check(self):
        self.native_result=False;self.probe_observation=offline();self.login()
        self.client.run_authentication.assert_called_once()
        self.assertFalse(self.client.logged_in)
        self.assertIs(self.client.auth_diagnostic['request_accepted'],False)
        self.bounded_probe.assert_called_once()
        self.status_query.assert_not_called();self.internet.assert_not_called()
    def test_unknown_reply_remains_unknown_without_retry(self):
        self.native_result=None;self.probe_observation=unknown();self.login()
        self.client.run_authentication.assert_called_once()
        self.assertFalse(self.client.logged_in)
        self.assertIn('无法确认',self.client.status)
        self.assertIsNone(self.client.auth_diagnostic['request_accepted'])
        self.status_query.assert_not_called();self.internet.assert_not_called()
    def test_each_new_explicit_click_is_an_action_not_a_cached_status_check(self):
        self.login();self.login()
        self.assertEqual(self.client.run_authentication.call_count,2)
        self.status_query.assert_not_called()
    def test_automatic_connection_action_attempts_only_the_supplied_account(self):
        self.client.settings['stu_autostart']=True
        self.login(automatic=True)
        self.client.run_authentication.assert_called_once()
        self.assertEqual(self.client.run_authentication.call_args.args[1:3],(ACCOUNT,PASSWORD))
        self.store.profiles.assert_not_called()
    def test_empty_password_never_becomes_a_status_request(self):
        self.execute(lambda:self.client.login(ACCOUNT,'','campus'))
        self.client.run_authentication.assert_not_called();self.status_query.assert_not_called()
    def test_interface_change_before_submission_sends_nothing(self):
        from dataclasses import replace
        def changed(*args,**kwargs):
            self.current=replace(self.wifi,ip='10.61.55.10')
            args[-1]()
        self.client.run_authentication.side_effect=changed
        self.login()
        self.assertNotIn('登录成功',self.client.status)
    def test_state_reads_do_not_poll_the_server_after_login(self):
        self.login()
        checked=self.bounded_probe.call_count
        for _ in range(20):self.client.get_state()
        self.status_query.assert_not_called();self.internet.assert_not_called()
        self.assertEqual(self.bounded_probe.call_count,checked)

class StudentLoginActionTests(LoginActionTests):SSID=core.STU
