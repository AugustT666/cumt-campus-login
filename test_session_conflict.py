"""Cached identities do not override fresh, bounded device observations."""
from dataclasses import replace
import campus_core as core
from test_logout_recovery import LogoutRecoveryFixture,ACCOUNT,PASSWORD

class ReplyIdentityTests(LogoutRecoveryFixture):
    def test_reopened_app_does_not_infer_online_identity_from_saved_accounts(self):
        state=self.client.get_state()
        self.assertFalse(state['logged_in']);self.assertEqual(state['online_account'],'')
        self.status_query.assert_not_called()
    def test_stale_conflicting_snapshot_does_not_block_an_explicit_login(self):
        self.client.session_diagnostic={'state':'unknown','binding':'conflict','detail':'session_ip_mismatch'}
        self.execute(lambda:self.client.login(ACCOUNT,PASSWORD,'campus','own-profile'))
        self.client.run_authentication.assert_called_once()
        self.assertEqual(self.client.identity_source,'verified_status')
        self.status_query.assert_not_called()
        self.bounded_probe.assert_called_once()
    def test_new_observation_never_claims_the_entered_account_logged_in_when_another_is_online(self):
        self.client.online_account='fictional-old-server-account';self.client.identity_source='server';self.client.session_state='online'
        self.probe_observation=dict(self.probe_observation,online_account='fictional-other-online-account')
        self.execute(lambda:self.client.login(ACCOUNT,PASSWORD,'campus','own-profile'))
        self.assertEqual(self.client.online_account,'fictional-other-online-account')
        self.assertEqual(self.client.identity_source,'verified_status')
        self.assertNotIn('登录成功',self.client.status)
    def test_typed_logout_is_not_overridden_by_a_previous_identity(self):
        self.client.online_account='fictional-old-server-account';self.client.identity_source='server';self.client.session_state='online'
        self.logout('fictional-current-input','fictional-current-password')
        self.assertEqual(self.web.login_calls,[('fictional-current-input','fictional-current-password')])
        self.client.run_authentication.assert_not_called()
    def test_no_completed_logout_callback_launches_new_work(self):
        self.logout()
        checks=self.bounded_confirm.call_count
        for _ in range(20):self.client.get_state()
        self.assertEqual(self.web.submit_calls,1);self.assertEqual(self.web.close_calls,1)
        self.status_query.assert_not_called();self.internet.assert_not_called()
        self.assertEqual(checks,1);self.assertEqual(self.bounded_confirm.call_count,checks)
    def test_network_change_discards_cached_acknowledged_identity(self):
        self.execute(lambda:self.client.login(ACCOUNT,PASSWORD,'campus','own-profile'))
        self.current=replace(self.wifi,ip='10.61.55.10')
        self.client.poll_wifi()
        self.assertEqual(self.client.get_state()['online_account'],'')
        self.status_query.assert_not_called()
