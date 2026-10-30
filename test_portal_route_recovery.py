"""A rejected login releases stale routes for the next explicit action only."""
from dataclasses import replace
from unittest.mock import MagicMock, patch

import campus_app as app
import campus_core as core
from test_logout_recovery import LogoutRecoveryFixture, ACCOUNT, PASSWORD, offline


class PortalRouteRecoveryTests(LogoutRecoveryFixture):
    SSID=core.STU

    def setUp(self):
        super().setUp()
        self.stale_engine=object()
        self.seed_route()

    def seed_route(self):
        self.token=self.client._observe_portal_network(self.wifi)
        self.client.portal=f'http://{core.KNOWN_HOST}/a79.htm?wlanuserip={self.wifi.ip}'
        self.client.portal_key=self.wifi.key
        self.client._portal_discovered=True
        self.client._engine=self.stale_engine

    def arrange_reply(self,result=False,code='1',after_reply=None):
        def authenticate(*args,**kwargs):
            self.client.auth_diagnostic={'operation':'login','backend':'fixture',
                'authentication_requests':1,'result':result,'response':{
                    'result':'1' if result is True else '0','ret_code':code,'msg':'Fictional portal reply'}}
            if after_reply:after_reply()
            return result
        self.client.run_authentication.side_effect=authenticate

    def login(self):
        return self.execute(lambda:self.client.login(ACCOUNT,PASSWORD,'campus','own-profile'))

    def test_rejection_is_committed_before_releasing_cache_without_changing_scope(self):
        self.arrange_reply()
        commit=self.client._commit_observed_state_locked
        observed=[]
        def commit_observer(*args,**kwargs):
            observed.append((self.client._engine,self.client.portal_key,self.client._portal_discovered))
            self.assertIs(self.client.auth_diagnostic['request_accepted'],False)
            return commit(*args,**kwargs)
        self.client._commit_observed_state_locked=commit_observer
        self.login()
        self.assertEqual(observed,[(self.stale_engine,self.wifi.key,True)])
        self.assertIsNone(self.client._engine)
        self.assertIsNone(self.client.portal_key)
        self.assertFalse(self.client._portal_discovered)
        self.assertEqual(self.client._observe_portal_network(self.wifi),self.token)
        self.assertIs(self.client.auth_diagnostic['result'],False)
        self.assertIs(self.client.auth_diagnostic['request_accepted'],False)
        self.assertTrue(self.client.auth_diagnostic['response_context_current'])
        self.assertTrue(self.client.auth_diagnostic['next_login_rediscovery'])
        self.assertIn('登录失败',self.client.status)
        self.client.run_authentication.assert_called_once()
        self.status_query.assert_not_called();self.internet.assert_not_called()

    def test_next_explicit_click_rediscovers_before_one_new_submission(self):
        self.arrange_reply()
        with patch.object(core,'discover',side_effect=AssertionError('Unexpected discovery during reply')):
            self.login()
        fresh_portal=f'http://{core.KNOWN_HOST}/a79.htm?wlanuserip={self.wifi.ip}&wlanacname=FictionalFreshAC'
        engine=MagicMock()
        engine.wifi=self.wifi;engine.portal=fresh_portal
        engine.authenticate.return_value=(True,{'operation':'login','authentication_requests':1,
            'result':True,'response':{'result':'1','msg':'Fictional accepted reply'}})
        self.client.run_authentication.side_effect=lambda *a,**k:app.App.run_authentication(self.client,*a,**k)
        with patch.object(core,'discover',return_value=(fresh_portal,'Fictional page')) as discover, \
             patch.object(app.protocol,'Engine',return_value=engine):
            self.login()
        discover.assert_called_once()
        self.assertEqual(discover.call_args.args[0],self.wifi)
        engine.authenticate.assert_called_once()
        self.assertEqual(self.client.portal,fresh_portal)
        self.assertIs(self.client._engine,engine)
        self.assertTrue(self.client._portal_discovered)
        self.assertEqual(self.client.portal_key,self.wifi.key)
        self.assertEqual(self.client._observe_portal_network(self.wifi),self.token)
        self.assertEqual(self.client.status,'登录成功')
        self.assertEqual(self.client.run_authentication.call_count,2)
        self.status_query.assert_not_called();self.internet.assert_not_called()

    def test_populated_ac_route_is_also_released_after_true_rejection(self):
        self.client.portal+='&wlanacname=FictionalOldAC'
        self.arrange_reply()
        self.login()
        self.assertIsNone(self.client._engine)
        self.assertIsNone(self.client.portal_key)
        self.assertFalse(self.client._portal_discovered)
        self.assertIn('FictionalOldAC',self.client.portal)

    def test_already_online_does_not_discard_route_or_add_another_request(self):
        self.arrange_reply(False,'2')
        self.login()
        self.assertIs(self.client._engine,self.stale_engine)
        self.assertEqual(self.client.portal_key,self.wifi.key)
        self.assertTrue(self.client._portal_discovered)
        self.assertNotIn('next_login_rediscovery',self.client.auth_diagnostic)
        self.assertEqual(self.client._observe_portal_network(self.wifi),self.token)
        self.client.run_authentication.assert_called_once()

    def test_accepted_and_unknown_replies_do_not_trigger_rejected_route_recovery(self):
        for result in (True,None):
            with self.subTest(result=result):
                self.seed_route();self.arrange_reply(result)
                self.login()
                self.assertIs(self.client._engine,self.stale_engine)
                self.assertEqual(self.client.portal_key,self.wifi.key)
                self.assertTrue(self.client._portal_discovered)
                self.assertNotIn('next_login_rediscovery',self.client.auth_diagnostic)

    def test_old_rejection_cannot_release_new_network_route(self):
        newer=replace(self.wifi,ip='10.61.55.10')
        fresh_engine=object()
        def changed():
            self.client._observe_portal_network(newer)
            self.client.wifi=newer
            self.client.portal_key=newer.key
            self.client._portal_discovered=True
            self.client._engine=fresh_engine
            self.client.status='Fictional new-network feedback'
        self.arrange_reply(after_reply=changed)
        self.login()
        self.assertIs(self.client._engine,fresh_engine)
        self.assertEqual(self.client.portal_key,newer.key)
        self.assertTrue(self.client._portal_discovered)
        self.assertFalse(self.client.auth_diagnostic['response_context_current'])
        self.assertNotIn('next_login_rediscovery',self.client.auth_diagnostic)
        self.assertEqual(self.client.status,'Fictional new-network feedback')

    def test_rejection_superseded_during_verification_does_not_release_new_route(self):
        self.arrange_reply()
        newer=replace(self.wifi,ip='10.61.55.10')
        fresh_engine=object()
        def changed_during_probe(*args,**kwargs):
            self.current=newer
            self.client._observe_portal_network(newer)
            self.client.wifi=newer
            self.client._engine=fresh_engine
            self.client.portal_key=newer.key
            self.client._portal_discovered=True
            self.client.status='Fictional newer verification-scope feedback'
            return offline()
        self.bounded_probe.side_effect=changed_during_probe
        self.login()
        self.assertIs(self.client._engine,fresh_engine)
        self.assertEqual(self.client.portal_key,newer.key)
        self.assertTrue(self.client._portal_discovered)
        self.assertFalse(self.client.auth_diagnostic['response_context_current'])
        self.assertNotIn('next_login_rediscovery',self.client.auth_diagnostic)
        self.assertEqual(self.client.status,'Fictional newer verification-scope feedback')

    def test_closed_app_does_not_discard_route_from_a_late_rejection(self):
        self.arrange_reply(after_reply=self.client.closed.set)
        self.login()
        self.assertIs(self.client._engine,self.stale_engine)
        self.assertEqual(self.client.portal_key,self.wifi.key)
        self.assertTrue(self.client._portal_discovered)
        self.assertFalse(self.client.auth_diagnostic['response_context_current'])


class TeacherPortalRouteRecoveryTests(PortalRouteRecoveryTests):
    SSID=core.TEC
