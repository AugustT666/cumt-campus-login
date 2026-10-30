"""Already-online and no-session replies require bounded current-device evidence.

Every endpoint and credential is synthetic. Shared fixtures poison legacy status,
connectivity, developer readback helpers and all real socket connections.
"""
from copy import deepcopy
from dataclasses import replace
from unittest.mock import MagicMock
import unittest

import campus_app as app
import campus_core as core
import campus_selfservice as service
from test_logout_recovery import LogoutRecoveryFixture, ACCOUNT, PASSWORD, online, offline, unknown, confirmation


ALREADY_ONLINE='当前设备已登录，无需重复登录。'
NO_SESSION='当前设备已下线，无需重复注销。'


class AlreadyOnlineClassificationTests(unittest.TestCase):
    def diagnostic(self,result='0',code='2'):
        return {'operation':'login','response':{'result':result,'ret_code':code,'msg':'QUM5OTk='}}

    def test_only_explicit_rejected_login_with_exact_code_two_is_classified(self):
        for result in (0,'0'):
            for code in (2,'2'):
                self.assertTrue(app.login_already_online(False,self.diagnostic(result,code)))
        for result in (None,False,0.0,'00',' 0',1,'1'):
            with self.subTest(result=result):
                self.assertFalse(app.login_already_online(False,self.diagnostic(result,'2')))
        for code in (None,True,2.0,'02',' 2',1,'1',3,'3'):
            with self.subTest(code=code):
                self.assertFalse(app.login_already_online(False,self.diagnostic('0',code)))
        for reply in (None,True):
            self.assertFalse(app.login_already_online(reply,self.diagnostic()))
        for diagnostic in (None,{},[],{'operation':'logout','response':self.diagnostic()['response']},
                           {'operation':'login','response':[]}):
            self.assertFalse(app.login_already_online(False,diagnostic))


class ActionNoopFeedbackTests(LogoutRecoveryFixture):
    SSID=core.STU

    def login(self,account=ACCOUNT):
        return self.execute(lambda:self.client.login(account,PASSWORD,'campus','own-profile'))

    def arrange_already_online(self,after_reply=None):
        def authenticate(*args,**kwargs):
            self.client.auth_diagnostic={'operation':'login','backend':'fixture','authentication_requests':1,
                'result':False,'response':{'result':'0','ret_code':'2','msg':'QUM5OTk='}}
            if after_reply:after_reply()
            return False
        self.client.run_authentication.side_effect=authenticate

    def arrange_no_session(self):
        self.web.summary['device_queries']=1
        self.web.submit_error=service.NoMatchingDevice('Fictional unmatched current device')
        self.probe_observation=offline()

    def test_repeated_login_preserves_received_acceptance_and_original_identity(self):
        self.login()
        self.assertTrue(self.client.logged_in)
        self.arrange_already_online()
        self.login()
        self.assertEqual(self.client.status,ALREADY_ONLINE)
        self.assertTrue(self.client.logged_in)
        self.assertEqual(self.client.online_account,ACCOUNT)
        self.assertEqual(self.client.identity_source,'verified_status')
        self.assertIs(self.client.auth_diagnostic['request_accepted'],False)
        self.assertEqual(self.client.auth_diagnostic['response_outcome'],'already_online')
        self.assertEqual(self.client.run_authentication.call_count,2)
        self.status_query.assert_not_called();self.internet.assert_not_called()

    def test_already_online_does_not_claim_newly_typed_account_logged_in(self):
        self.login()
        self.arrange_already_online()
        self.login('fictional-different-account')
        self.assertIn('其他账号',self.client.status)
        self.assertEqual(self.client.online_account,ACCOUNT)
        self.assertNotEqual(self.client.online_account,'fictional-different-account')
        self.assertIs(self.client.auth_diagnostic['request_accepted'],False)

    def test_fresh_app_already_online_reply_does_not_invent_account_identity(self):
        self.probe_observation=unknown()
        self.arrange_already_online()
        self.login()
        self.assertIn('无法确认',self.client.status)
        self.assertEqual(self.client.online_account,'')
        self.assertNotEqual(self.client.identity_source,'request_ack')
        self.assertEqual(self.client.session_state,'unknown')

    def test_native_already_online_reply_does_not_briefly_display_raw_error(self):
        engine=MagicMock()
        engine.authenticate.return_value=(False,{'operation':'login','response':{
            'result':'0','ret_code':'2','msg':'QUM5OTk='}})
        self.client.session_engine=MagicMock(return_value=engine)
        self.client.message=MagicMock()
        self.client._observe_portal_network(self.wifi)
        result=app.App.run_authentication(self.client,self.wifi,ACCOUNT,PASSWORD,'campus','login',
                                          self.wifi.ssid==core.TEC,lambda:None)
        self.assertIs(result,False)
        self.client.message.assert_not_called()
        engine.authenticate.assert_called_once()

    def test_true_server_rejection_remains_failure_without_extra_requests(self):
        def rejected(*args,**kwargs):
            self.client.auth_diagnostic={'operation':'login','response':{
                'result':'0','ret_code':'1','msg':'Mac, IP, NASip, PORT err(2)!'}}
            self.client.message('认证提示：Mac, IP, NASip, PORT err(2)!')
            return False
        self.client.run_authentication.side_effect=rejected
        self.probe_observation=offline()
        self.login()
        self.assertIn('登录失败',self.client.status)
        self.assertNotIn('response_outcome',self.client.auth_diagnostic)
        self.client.run_authentication.assert_called_once()
        self.status_query.assert_not_called();self.internet.assert_not_called()

    def test_old_network_already_online_reply_cannot_replace_current_feedback(self):
        newer=replace(self.wifi,ip='10.61.55.10')
        def changed():
            self.current=newer
            self.client._observe_portal_network(newer)
            self.client.wifi=newer
            self.client.status='Fictional newer-network feedback'
        self.arrange_already_online(changed)
        self.login()
        self.assertEqual(self.client.status,'Fictional newer-network feedback')
        self.assertFalse(self.client.auth_diagnostic['response_context_current'])
        self.assertIs(self.client.auth_diagnostic['request_accepted'],False)

    def test_no_matching_session_is_neutral_and_sends_no_disconnect(self):
        self.arrange_no_session()
        self.logout()
        self.assertEqual(self.client.status,NO_SESSION)
        self.assertEqual(self.client.logout_diagnostic['outcome'],'confirmed_offline')
        self.assertTrue(self.client.logout_diagnostic['no_matching_session'])
        self.assertEqual(self.client.auth_diagnostic['phase'],'confirmed_offline')
        self.assertIsNone(self.client.auth_diagnostic['request_accepted'])
        self.assertEqual(self.web.summary['disconnect_requests'],0)
        self.assertEqual(self.web.close_calls,1)
        self.assertEqual(self.web.submit_calls,1)
        self.status_query.assert_not_called();self.internet.assert_not_called()

    def test_unmatched_account_does_not_mark_other_account_offline_or_scan_profiles(self):
        self.login()
        old_identity=(self.client.session_state,self.client.logged_in,self.client.online_account,
                      self.client.identity_source,self.client.auth_key)
        self.store.selected_profile.reset_mock();self.store.profiles.reset_mock()
        self.arrange_no_session()
        self.probe_observation=online();self.logout_confirmation=confirmation('online')
        self.logout('fictional-different-account',PASSWORD)
        self.assertIn('在线账号与填写账号不同',self.client.status)
        self.assertEqual(self.client.logout_diagnostic['outcome'],'account_mismatch')
        self.assertEqual((self.client.session_state,self.client.logged_in,self.client.online_account,
                          self.client.identity_source,self.client.auth_key),old_identity)
        self.assertEqual(self.web.login_calls,[('fictional-different-account',PASSWORD)])
        self.assertEqual(self.web.submit_calls,1)
        self.assertEqual(self.web.summary['disconnect_requests'],0)
        self.store.selected_profile.assert_not_called();self.store.profiles.assert_not_called()

    def test_no_match_after_context_change_cannot_overwrite_current_network(self):
        self.arrange_no_session()
        def changed():
            newer=replace(self.wifi,ip='10.61.55.10')
            self.current=newer
            self.client._observe_portal_network(newer)
            self.client.wifi=newer
            self.client.status='Fictional newer-network feedback'
        # The check callback still reads the original interface; the retained
        # generation changes just before the synthetic response is raised.
        original=self.web.submit_current
        def no_match(*args,**kwargs):
            try:return original(*args,**kwargs)
            finally:changed()
        self.web.submit_current=no_match
        self.logout()
        self.assertEqual(self.client.status,'Fictional newer-network feedback')
        self.assertEqual(self.web.summary['disconnect_requests'],0)
        self.assertFalse(self.client.auth_diagnostic['response_context_current'])

    def test_unknown_or_already_sent_lookup_errors_remain_errors(self):
        self.arrange_no_session()
        for change in ({'device_queries':0},{'device_queries':True},{'device_queries':'1'},
                       {'disconnect_requests':1},{'disconnect_requests':False}):
            with self.subTest(change=change):
                self.web.summary.update(device_queries=1,disconnect_requests=0)
                self.web.summary.update(change)
                self.logout()
                self.assertEqual(self.client.logout_diagnostic['outcome'],'error')
                self.assertNotEqual(self.client.status,NO_SESSION)

    def test_ambiguity_is_still_an_error_and_never_becomes_no_session(self):
        self.web.summary['device_queries']=1
        self.web.submit_error=service.AmbiguousDevice('Fictional ambiguous session')
        self.logout()
        self.assertEqual(self.client.logout_diagnostic['outcome'],'error')
        self.assertEqual(self.web.summary['disconnect_requests'],0)
        self.assertNotEqual(self.client.status,NO_SESSION)


class TeacherActionNoopFeedbackTests(ActionNoopFeedbackTests):
    SSID=core.TEC


if __name__=='__main__':unittest.main()
