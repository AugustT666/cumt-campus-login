"""Session recovery uses explicit server state, never saved client flags."""
import datetime as dt
import json
from itertools import chain, repeat
import socket
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import zipfile
import campus_core as core
import campus_app as app
import campus_selfservice as selfservice

WIFI=core.Wifi('CUMT_Stu','session-fixture',5,'10.52.1.2','00-11-22-33-44-55')

class SessionTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(app, 'stable_autostart_configured', return_value=False))
        self.enterContext(patch.object(app, 'stable_instance_running', return_value=False))
        self.temp=tempfile.TemporaryDirectory()
        self.store=core.Store(Path(self.temp.name))
        with patch.object(core,'Store',return_value=self.store):
            self.app=app.App()
        self.app.wifi=WIFI
        self.app.portal='http://'+core.KNOWN_HOST+'/a79.htm'
        self.app.settings['quiet_hours']=False
        self.engine=MagicMock()
        self.engine.status.return_value={'state':'offline','matched_ip':True}
        self.app.session_engine=MagicMock(return_value=self.engine)
        self.app.run_authentication=MagicMock(return_value=True)
        self.app.save_profile=MagicMock(return_value={'ok':True})
        self.app.start_job=lambda kind,job,automatic=False:(job() or {'ok':True})
        self.app._launch_logout_verification=MagicMock()
        self.enterContext(patch.object(app.protocol,'Engine',return_value=self.engine))
        self.wifi_patch=patch.object(core,'read_wifi',return_value=WIFI)
        self.wifi_patch.start()
        self.tick=100.0
        self.enterContext(patch.object(app.time,'monotonic',side_effect=lambda:self.tick))
        self.app._logout_wait=lambda seconds:setattr(self,'tick',self.tick+seconds)
        self.app._logout_watch_wait=lambda watch,seconds:setattr(self,'tick',self.tick+seconds)
        self.enterContext(patch.object(core,'internet_check',return_value={'online':False,'checks':[]}))
        self.service_client=self.enterContext(patch.object(selfservice,'Client',
            side_effect=AssertionError('No live self-service in session tests')))
        self.enterContext(patch.object(socket.socket,'connect',
            side_effect=AssertionError('No live sockets in session tests')))
    def tearDown(self):
        self.wifi_patch.stop()
        self.app.runtime_log.close()
        self.temp.cleanup()
    def login(self,automatic=False):
        return self.app.login('fake-account','fake-password','campus','',automatic=automatic)
    def logout_reports(self,*reports):
        # Authentication can settle slowly. Keep the final synthetic report
        # available throughout read-only observation; never sleep in a test.
        self.engine.status.side_effect=chain(reports,repeat(reports[-1]))

    def logout_result(self,result,response=None):
        def submit(*args,**kwargs):
            self.app.auth_diagnostic={'operation':'logout','backend':'fixture-portal',
                'authentication_requests':1,'result':result,'phase':'response_received'}
            if response is not None:self.app.auth_diagnostic['response']=response
            return result
        self.app.run_authentication.side_effect=submit
    def test_reopen_recovers_online_session_without_authentication(self):
        self.assertFalse(self.app.logged_in)
        self.engine.status.return_value={'state':'online','matched_ip':True}
        self.assertTrue(self.app.refresh_status()['ok'])
        self.assertTrue(self.app.logged_in)
        self.assertEqual(self.app.auth_key,WIFI.key)
        self.assertEqual(self.app.get_state()['session_state'],'online')
        self.app.run_authentication.assert_not_called()
    def test_repeat_login_while_online_never_submits_again(self):
        self.engine.status.return_value={'state':'online','matched_ip':True}
        for _ in range(3): self.assertTrue(self.login()['ok'])
        self.assertTrue(self.app.logged_in)
        self.app.run_authentication.assert_not_called()
        self.assertEqual(self.app.auth_diagnostic['authentication_requests'],0)
    def test_recovered_session_can_logout_without_saved_credentials(self):
        self.logout_reports({'state':'online','matched_ip':True},
                            {'state':'offline','matched_ip':True})
        start=self.tick
        self.assertTrue(self.app.logout()['ok'])
        self.app.run_authentication.assert_called_once()
        self.assertEqual(self.app.run_authentication.call_args.args[4],'logout')
        self.assertFalse(self.app.logged_in)
        self.assertEqual(self.app.session_state,'offline')
        self.assertGreater(self.engine.status.call_count,2)
        self.assertLess(self.tick-start,3.0)
        self.assertEqual(self.app.logout_diagnostic['outcome'],'verification_pending')
        self.app._run_logout_verification(self.app._logout_watch)
        self.assertEqual(self.app.logout_diagnostic['outcome'],'offline_confirmed')
        self.service_client.assert_not_called()
    def test_logout_offline_sends_no_authentication(self):
        self.assertTrue(self.app.logout()['ok'])
        self.app.run_authentication.assert_not_called()
    def test_unknown_status_never_allows_blind_logout(self):
        self.engine.status.return_value={'state':'unknown','matched_ip':False}
        self.assertTrue(self.app.logout()['ok'])
        self.assertFalse(self.app.logged_in)
        self.app.run_authentication.assert_not_called()
        self.service_client.assert_not_called()
        self.assertEqual(self.app.auth_diagnostic['authentication_requests'],0)
        self.assertNotEqual(self.app.logout_diagnostic['outcome'],'offline_confirmed')
    def test_explicit_offline_clears_previous_online_flag(self):
        self.app.logged_in=True;self.app.auth_key=WIFI.key
        self.app.refresh_status()
        self.assertFalse(self.app.logged_in)
        self.assertIsNone(self.app.auth_key)
    def test_unknown_does_not_claim_online(self):
        self.engine.status.return_value={'state':'unknown'}
        self.app.refresh_status()
        self.assertEqual(self.app.session_state,'unknown')
        self.assertFalse(self.app.logged_in)
    def test_manual_offline_login_uses_one_authentication(self):
        self.engine.status.side_effect=[{'state':'offline'},{'state':'online'}]
        self.assertTrue(self.login()['ok'])
        self.app.run_authentication.assert_called_once()
        self.assertTrue(self.app.logged_in)
        self.assertEqual(self.app.session_state,'online')
    def test_auto_unknown_stops_without_submitting(self):
        self.app.settings['stu_autostart']=True
        self.engine.status.return_value={'state':'unknown'}
        self.assertTrue(self.login(automatic=True)['ok'])
        self.app.run_authentication.assert_not_called()
    def test_success_is_not_blocked_on_internet_probe(self):
        self.engine.status.side_effect=[{'state':'offline'},{'state':'online'}]
        with patch.object(core,'internet_check',side_effect=AssertionError('synchronous probe')):
            self.assertTrue(self.login()['ok'])
        self.assertTrue(self.app.logged_in)
    def test_unknown_authentication_requires_status_refresh(self):
        self.app.run_authentication.return_value=None
        self.login()
        self.assertEqual(self.app.session_state,'unknown')
        self.assertIn('刷新状态',self.app.status)
    def test_network_change_rejects_stale_status(self):
        changed=core.Wifi('CUMT_Stu','session-fixture',5,'10.52.1.3',WIFI.mac)
        with patch.object(core,'read_wifi',return_value=changed):
            with self.assertRaises(RuntimeError):
                self.app.apply_session(WIFI,{'state':'online'})
        self.assertFalse(self.app.logged_in)
    def test_cancelled_status_cannot_restore_login(self):
        self.app.cancel.set()
        with self.assertRaises(RuntimeError):self.app.apply_session(WIFI,{'state':'online'})
        self.assertFalse(self.app.logged_in)
    def test_already_online_allows_check_without_password(self):
        self.app.logged_in=True
        self.engine.status.return_value={'state':'online','matched_ip':True}
        self.assertTrue(self.app.login('','','campus')['ok'])
        self.app.run_authentication.assert_not_called()
    def test_quiet_hours_prevent_submission_but_allow_status(self):
        self.app.settings['quiet_hours']=True
        with patch.object(core,'quiet_hours',return_value=True):
            self.app.refresh_status()
            with self.assertRaisesRegex(RuntimeError,'当前处于学生网络常规不可认证时间.*07:00.*节假日'):
                self.login()
        self.app.run_authentication.assert_not_called()

    def test_quiet_schedule_boundaries_and_resume_day(self):
        for moment, expected in (
                (dt.datetime(2026,10,26,23,29),''),
                (dt.datetime(2026,10,26,23,30),'次日07:00'),
                (dt.datetime(2026,10,27,0,15),'今日07:00'),
                (dt.datetime(2026,10,27,6,59),'今日07:00'),
                (dt.datetime(2026,10,27,7,0),''),
                (dt.datetime(2026,10,23,23,40),''),
                (dt.datetime(2026,10,24,6,59),''),
                (dt.datetime(2026,10,25,23,40),'次日07:00')):
            with self.subTest(moment=moment):
                notice=app.student_auth_time_notice(WIFI,moment)
                if expected:
                    self.assertIn(expected,notice)
                    self.assertIn('节假日以学校安排为准',notice)
                else:self.assertEqual(notice,'')
        teacher=core.Wifi('CUMT_Tec',WIFI.guid,WIFI.index,WIFI.ip,WIFI.mac)
        self.assertEqual(app.student_auth_time_notice(teacher,dt.datetime(2026,10,26,23,40)),'')

    def test_legacy_quiet_disabled_still_explains_server_rejection_at_night(self):
        self.app.settings['quiet_hours']=False
        def reject(*args):
            self.app.message('认证提示：Authentication Fail ErrCode=16')
            return False
        self.app.run_authentication.side_effect=reject
        with patch.object(core,'quiet_hours',return_value=True):self.login()
        self.app.run_authentication.assert_called_once()
        self.assertEqual(self.app.session_state,'offline')
        self.assertIn('当前处于学生网络常规不可认证时间',self.app.status)
        self.assertIn('Authentication Fail ErrCode=16',self.app.status)
        self.assertNotIn('ErrCode=16代表',self.app.status)

    def test_night_unknown_automatic_status_stops_with_time_notice(self):
        self.app.settings['stu_autostart']=True
        self.engine.status.return_value={'state':'unknown'}
        with patch.object(core,'quiet_hours',return_value=True):self.login(automatic=True)
        self.assertIn('不可认证时间',self.app.status)
        self.assertIn('自动登录已停止',self.app.status)
        self.app.run_authentication.assert_not_called()

    def test_already_online_at_night_is_not_reported_as_a_time_failure(self):
        self.app.settings['quiet_hours']=True
        self.engine.status.return_value=self.online()
        with patch.object(core,'quiet_hours',return_value=True):self.login()
        self.assertTrue(self.app.logged_in)
        self.assertNotIn('不可认证时间',self.app.status)
        self.app.run_authentication.assert_not_called()

    def test_night_unknown_submission_preserves_no_retry_warning(self):
        self.app.run_authentication.return_value=None
        with patch.object(core,'quiet_hours',return_value=True):self.login()
        self.assertEqual(self.app.session_state,'unknown')
        self.assertIn('不可认证时间',self.app.status)
        self.assertIn('避免重复提交',self.app.status)
        self.app.run_authentication.assert_called_once()

    def test_page_discovery_failure_retains_actual_exception_in_logs_with_time_notice(self):
        self.app.run_authentication.side_effect=RuntimeError('未找到真实认证页面。')
        real_start=app.App.start_job.__get__(self.app,app.App)
        def inline(kind,job,automatic=False):
            with patch.object(app.threading,'Thread') as thread:
                result=real_start(kind,job,automatic)
                thread.call_args.kwargs['target']()
            return result
        self.app.start_job=inline
        with patch.object(core,'quiet_hours',return_value=True):self.login()
        self.assertIn('不可认证时间',self.app.status)
        self.assertIn('未找到真实认证页面',self.app.status)
        rows=[json.loads(line) for line in self.app.runtime_log.path.read_text('utf-8').splitlines()]
        error=next(row for row in rows if row['event']=='operation.error')
        self.assertIn('RuntimeError: 未找到真实认证页面。',error['fields']['traceback'])
        self.app.run_authentication.assert_called_once()

    def test_daytime_failure_and_teacher_failure_have_no_time_notice(self):
        self.app.run_authentication.return_value=False
        with patch.object(core,'quiet_hours',return_value=False):self.login()
        self.assertNotIn('不可认证时间',self.app.status)
        teacher=core.Wifi('CUMT_Tec',WIFI.guid,WIFI.index,WIFI.ip,WIFI.mac)
        with patch.object(core,'read_wifi',return_value=teacher), \
             patch.object(core,'quiet_hours',return_value=True):
            self.app.login('fake-account','fake-password','')
        self.assertNotIn('不可认证时间',self.app.status)
    def test_unknown_post_submission_never_falls_back_to_browser(self):
        # run_authentication uses the engine once; an unknown response is final.
        real=app.App.run_authentication.__get__(self.app,app.App)
        self.engine.authenticate.return_value=(None,{'phase':'unknown','authentication_requests':1})
        self.app.authenticate=MagicMock()
        self.assertIsNone(real(WIFI,'fake','secret','campus','login',False,lambda:None))
        self.engine.authenticate.assert_called_once()
        self.app.authenticate.assert_not_called()
    def test_unsupported_before_submission_uses_browser_once(self):
        real=app.App.run_authentication.__get__(self.app,app.App)
        self.engine.prepare.side_effect=app.protocol.UnsupportedPortal('unsupported')
        self.app.authenticate=MagicMock(return_value=True)
        self.assertTrue(real(WIFI,'fake','secret','campus','login',False,lambda:None))
        self.engine.authenticate.assert_not_called()
        self.app.authenticate.assert_called_once()

    def online(self,account='fixture-server-online-user'):
        return {'state':'online','matched_ip':True,'online_account':account,
                'binding':'mac_verified','server_mac':'001122334455'}

    def test_ui_state_identifies_the_account_reported_by_the_server(self):
        self.engine.status.return_value=self.online()
        self.app.refresh_status()
        state=self.app.get_state()
        self.assertEqual(state['online_account'],'fixture-server-online-user')
        self.assertEqual(state['identity_source'],'server')
        self.assertEqual(state['session_binding'],'mac_verified')
        self.app.run_authentication.assert_not_called()

    def test_selecting_a_different_profile_does_not_change_the_online_identity(self):
        self.app.apply_session(WIFI,self.online())
        profiles={'schema':2,'selected':'profile-a','profiles':[
            {'id':'profile-a','account':'fixture-future-account-a','password':'fixture-password-a','operator':'campus'},
            {'id':'profile-b','account':'fixture-future-account-b','password':'fixture-password-b','operator':'unicom'}]}
        def choose(profile_id):
            profiles['selected']=profile_id
        with patch.object(self.store,'profiles',return_value=profiles), \
             patch.object(self.store,'select_profile',side_effect=choose), \
             patch.object(self.app,'startup_enabled',return_value=False):
            result=self.app.select_profile('profile-b')
        self.assertTrue(result['ok'])
        self.assertEqual(result['data']['account'],'fixture-future-account-b')
        self.assertEqual(result['data']['operator'],'unicom')
        self.assertEqual(self.app.get_state()['online_account'],'fixture-server-online-user')
        self.assertEqual(self.app.get_state()['identity_source'],'server')
        self.app.run_authentication.assert_not_called()

    def test_offline_and_unknown_clear_the_previously_reported_online_identity(self):
        for state in ('offline','unknown'):
            with self.subTest(state=state):
                self.app.apply_session(WIFI,self.online())
                self.app.apply_session(WIFI,{'state':state,'online_account':'fixture-stale-server-user'})
                self.assertEqual(self.app.online_account,'')
                self.assertEqual(self.app.get_state()['online_account'],'')
                self.assertEqual(self.app.get_state()['identity_source'],'')
                self.assertFalse(self.app.logged_in)

    def test_online_without_server_identity_does_not_guess_the_selected_account(self):
        self.engine.status.return_value={'state':'online','matched_ip':True}
        self.assertTrue(self.login()['ok'])
        self.assertEqual(self.app.get_state()['online_account'],'')
        self.assertEqual(self.app.get_state()['identity_source'],'')
        self.assertNotIn('fake-account',str(self.app.get_state()))
        self.app.run_authentication.assert_not_called()

    def test_new_login_uses_post_login_server_identity_instead_of_submitted_profile(self):
        self.engine.status.side_effect=[{'state':'offline','matched_ip':True},self.online('fixture-post-login-server-user')]
        self.assertTrue(self.login()['ok'])
        self.app.run_authentication.assert_called_once()
        self.assertEqual(self.app.get_state()['online_account'],'fixture-post-login-server-user')
        self.assertEqual(self.app.get_state()['identity_source'],'server')
        self.assertEqual(self.engine.status.call_count,2)

    def test_server_identity_is_visible_in_memory_but_hidden_in_logs_and_zip(self):
        identity='fixture-first-seen-private-server-user'
        self.app.apply_session(WIFI,self.online(identity))
        # apply_session must register a newly observed server identity before a
        # subsequent exception/message can mention it in free text.
        self.app.message('fixture server detail for '+identity)
        self.assertEqual(self.app.get_state()['online_account'],identity)
        exported=self.app.diagnostic()
        self.assertTrue(exported['ok'],exported)
        self.assertNotIn(identity,self.app.runtime_log.path.read_text('utf-8'))
        with zipfile.ZipFile(exported['path']) as archive:
            for name in archive.namelist():
                self.assertNotIn(identity.encode(),archive.read(name),name)
            snapshot=json.loads(archive.read('snapshot.json'))
            self.assertEqual(snapshot['session']['query']['online_account'],'[REDACTED]')

    def test_explicit_logout_rejection_retains_identity_and_reason_when_no_safe_fallback_credentials(self):
        self.logout_reports(self.online(),self.online())
        self.logout_result(False,{'result':'0','msg':'注销失败'})
        self.app.authenticate=MagicMock(side_effect=AssertionError('No blind browser retry allowed'))
        self.assertTrue(self.app.logout()['ok'])
        self.app.run_authentication.assert_called_once()
        self.app.authenticate.assert_not_called()
        self.service_client.assert_not_called()
        self.assertEqual(self.engine.status.call_count,2)
        self.assertTrue(self.app.logged_in)
        self.assertEqual(self.app.get_state()['online_account'],'fixture-server-online-user')
        self.assertEqual(self.app.get_state()['identity_source'],'server')
        self.assertEqual(self.app.auth_diagnostic['response']['msg'],'注销失败')
        self.assertFalse(self.app.auth_diagnostic['result'])
        self.assertEqual(self.app.auth_diagnostic['authentication_requests'],1)
        self.assertEqual(self.app.auth_diagnostic['selfservice_logout_requests'],0)
        self.assertEqual(self.app.logout_diagnostic['fallback_reason'],'portal_rejected')
        self.assertIn('注销尚未确认',self.app.status)
        self.assertNotIn('已退出登录',self.app.status)

    def test_unknown_logout_response_never_resubmits_portal_and_retains_uncertainty(self):
        self.logout_reports(self.online(),self.online())
        self.logout_result(None)
        self.app.authenticate=MagicMock(side_effect=AssertionError('No blind browser retry allowed'))
        self.assertTrue(self.app.logout()['ok'])
        self.app.run_authentication.assert_called_once()
        self.app.authenticate.assert_not_called()
        self.service_client.assert_not_called()
        self.assertGreater(self.engine.status.call_count,2)
        self.assertTrue(self.app.logged_in)
        self.assertEqual(self.app.get_state()['online_account'],'fixture-server-online-user')
        self.assertIsNone(self.app.auth_diagnostic['result'])
        self.assertEqual(self.app.auth_diagnostic['authentication_requests'],1)
        self.assertEqual(self.app.logout_diagnostic['fallback_reason'],'still_online')
        self.assertTrue(self.app.get_state()['logout_recovery_needed'])
        self.assertIn('尚未确认',self.app.status)
        self.assertNotIn('已退出登录',self.app.status)

    def test_accepted_logout_with_online_readback_does_not_claim_logged_out(self):
        self.logout_reports(self.online(),self.online())
        self.logout_result(True)
        self.assertTrue(self.app.logout()['ok'])
        self.app.run_authentication.assert_called_once()
        self.service_client.assert_not_called()
        self.assertGreater(self.engine.status.call_count,2)
        self.assertTrue(self.app.logged_in)
        self.assertEqual(self.app.get_state()['online_account'],'fixture-server-online-user')
        self.assertTrue(self.app.auth_diagnostic['result'])
        self.assertEqual(self.app.logout_diagnostic['fallback_reason'],'still_online')
        self.assertIn('尚未确认',self.app.status)
        self.assertNotIn('已退出登录',self.app.status)

    def test_explicit_rejection_with_unknown_readback_clears_identity_and_keeps_rejection(self):
        self.logout_reports(self.online(),{'state':'unknown','matched_ip':False})
        self.logout_result(False,{'result':'0','msg':'注销失败'})
        self.assertTrue(self.app.logout()['ok'])
        self.app.run_authentication.assert_called_once()
        self.service_client.assert_not_called()
        self.assertEqual(self.app.get_state()['session_state'],'unknown')
        self.assertEqual(self.app.get_state()['online_account'],'')
        self.assertFalse(self.app.auth_diagnostic['result'])
        self.assertEqual(self.app.auth_diagnostic['response']['msg'],'注销失败')
        self.assertIn('尚未确认',self.app.status)
        self.assertTrue(self.app.get_state()['logout_recovery_needed'])

    def test_sustained_offline_readback_confirms_session_even_if_response_was_rejected(self):
        self.logout_reports(self.online(),{'state':'offline','matched_ip':True})
        self.logout_result(False)
        start=self.tick
        self.assertTrue(self.app.logout()['ok'])
        self.app.run_authentication.assert_called_once()
        self.service_client.assert_not_called()
        self.assertLess(self.tick-start,3.0)
        self.assertEqual(self.app.logout_diagnostic['outcome'],'verification_pending')
        self.app._run_logout_verification(self.app._logout_watch)
        self.assertEqual(self.app.logout_diagnostic['outcome'],'offline_confirmed')
        self.assertFalse(self.app.logged_in)
        self.assertEqual(self.app.get_state()['online_account'],'')
        self.assertEqual(self.app.get_state()['identity_source'],'')
        self.assertFalse(self.app.auth_diagnostic['result'])
        self.assertEqual('已退出登录',self.app.status)

if __name__=='__main__':unittest.main()
