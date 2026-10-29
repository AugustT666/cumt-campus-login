"""STU/TEC use ordinary logout first, with one precise self-service fallback.

All identities, routes, sessions and web responses are synthetic. The App uses
a mock Store and a temporary real logger; no real network or registry is used.
"""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch

import campus_app as app
import campus_core as core
import campus_selfservice as service
from campus_logging import RuntimeLog


WIFI=core.Wifi(core.TEC,'logout-recovery-fixture',7,'10.61.55.9',
               '00-11-22-33-44-55','10.61.55.1')
HOTSPOT=replace(WIFI,ssid='Fictional hotspot',ip='10.221.55.9',gateway='10.221.55.1')
ACCOUNT='fictional-online-account'
PASSWORD='fictional-online-password'
MAC='001122334455'
OWN=service.DeviceSession('fictional-own-session',WIFI.ip,MAC,71)
OTHER=service.DeviceSession('fictional-other-session','10.61.55.10','66778899AABB',71)


def online():
    return {'state':'online','matched_ip':True,'binding':'mac_verified',
        'detail':'server_confirmed','online_account':ACCOUNT,'server_ip':WIFI.ip,
        'server_mac':MAC,'ip_conflict':False,'mac_conflict':False}


def offline():
    return {'state':'offline','matched_ip':True,'binding':'source_ip_only',
        'detail':'server_confirmed','online_account':'','ip_conflict':False,'mac_conflict':False}


class FakeWebClient:
    def __init__(self,wifi):
        self.wifi=wifi
        self.devices=[OWN,OTHER]
        self.device_sequence=[]
        self.device_last=None
        self.login_calls=[]
        self.disconnect_calls=[]
        self.close_calls=0
        self.authenticated=False
        self.disconnected=False
        self.login_error=None
        self.disconnect_error=None
        self.on_login=None
        self.on_disconnect=None
        self.closed=False
        self.summary={'login_attempted':False,'login_confirmed':False,'device_queries':0,
            'disconnect_requests':0,'request_accepted':None,'session_removed':None,
            'current_device_offline':None,'device_reappeared':False,
            'web_logout_attempted':False,'web_logout_confirmed':False}

    def login(self,account,password):
        self.login_calls.append((account,password))
        self.summary['login_attempted']=True
        if self.login_error:raise self.login_error
        self.authenticated=True
        self.summary['login_confirmed']=True
        if self.on_login:self.on_login()
        return self.safe_summary()

    def list_online_devices(self):
        if not self.authenticated:raise service.AuthenticationError('Fictional unauthenticated session')
        self.summary['device_queries']+=1
        if self.device_sequence:
            self.device_last=self.device_sequence.pop(0)
        devices=self.device_last if self.device_last is not None else self.devices
        return list(devices)

    def select_current_session(self,devices,session_info=None):
        return service.select_current_session(devices,self.wifi,session_info)

    def disconnect_current(self,session_info=None,before_disconnect=None):
        if self.disconnect_calls:raise service.SelfServiceError('Fictional duplicate disconnect')
        selected=self.select_current_session(self.list_online_devices(),session_info)
        verified=self.select_current_session(self.list_online_devices(),session_info)
        if selected!=verified:raise service.AmbiguousDevice('Fictional changed target')
        if before_disconnect:before_disconnect()
        self.disconnect_calls.append(selected.session_id)
        self.summary['disconnect_requests']=1
        if self.disconnect_error:raise self.disconnect_error
        self.disconnected=True
        self.devices=[device for device in self.devices if device.session_id!=selected.session_id]
        self.device_last=None
        absent=not any(device.mac==MAC for device in self.devices)
        self.summary.update(request_accepted=True,session_removed=True,
                            current_device_offline=absent)
        if self.on_disconnect:self.on_disconnect()
        return self.safe_summary()

    def safe_summary(self):
        return dict(self.summary)

    def close(self):
        self.close_calls+=1
        self.closed=True
        self.summary['web_logout_attempted']=bool(self.login_calls)
        self.summary['web_logout_confirmed']=bool(self.login_calls)
        self.authenticated=False
        return self.safe_summary()


class LogoutRecoveryFixture(unittest.TestCase):
    SSID=core.TEC

    def setUp(self):
        temporary=tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.store=MagicMock()
        self.store.root=Path(temporary.name)
        self.store.load.return_value={'operator':'','quiet_hours':False,
            'stu_autostart':True,'trusted_hosts':[core.KNOWN_HOST],'portal_hint':''}
        self.profiles={'selected':'other-profile','profiles':[
            {'id':'other-profile','account':'fictional-selected-other','password':'fictional-other-password','operator':''},
            {'id':'own-profile','account':ACCOUNT,'password':PASSWORD,'operator':''}]}
        self.store.profiles.side_effect=lambda:deepcopy(self.profiles)
        self.store.selected_profile.side_effect=lambda:deepcopy(next(
            (p for p in self.profiles['profiles'] if p['id']==self.profiles['selected']),{}))
        self.log=RuntimeLog(self.store.root,core.VERSION)
        self.addCleanup(self.log.close)
        with patch.object(core,'Store',return_value=self.store):
            self.client=app.App(runtime_log=self.log)
        self.wifi=replace(WIFI,ssid=self.SSID)
        self.current=self.wifi
        self.reader=self.enterContext(patch.object(core,'read_wifi',side_effect=lambda:self.current))
        self.enterContext(patch.object(socket.socket,'connect',
            side_effect=AssertionError('No real network in App recovery tests')))
        self.enterContext(patch.object(app,'stable_autostart_configured',return_value=False))
        self.enterContext(patch.object(app,'stable_instance_running',return_value=False))
        self.client.wifi=self.wifi
        self.client.portal='http://'+core.KNOWN_HOST+'/a79.htm'
        self.client.window=MagicMock()
        self.client.window.native=None
        self.job_number=0
        def run_job(kind,job,automatic=False):
            if self.client.busy:return {'ok':False,'message':'Fictional busy'}
            self.job_number+=1
            self.client.busy=True
            self.client.operation=kind
            self.client.operation_id='fictional-job-'+str(self.job_number)
            self.client.cancel.clear()
            try:
                job()
                return {'ok':True}
            finally:
                self.client.busy=False
                self.client.operation=''
        self.client.start_job=run_job
        self.launch=self.client._launch_logout_verification=MagicMock()
        self.client.save_profile=MagicMock(return_value={'ok':True})
        self.tick=100.0
        self.enterContext(patch.object(app.time,'monotonic',side_effect=lambda:self.tick))
        self.client._logout_wait=lambda seconds:self.advance(seconds)
        self.client._logout_watch_wait=lambda watch,seconds:self.advance(seconds)
        self.internet_check=self.enterContext(patch.object(core,'internet_check',
            return_value={'online':False,'checks':[{'ok':False}]}))
        self.events=[]
        self.web=FakeWebClient(self.wifi)
        def service_client(*args,**kwargs):
            self.events.append('selfservice')
            return self.web
        self.web_factory=self.enterContext(patch.object(service,'Client',side_effect=service_client))
        self.nas_observer=self.enterContext(patch.object(service,'observe_nas_binding',
            side_effect=service.UnsupportedService('Fictional NAS proof unavailable')))
        self.engine=MagicMock()
        self.kernel_sequence=[]
        self.kernel_after_disconnect_online=False
        self.engine.status.side_effect=self.kernel_status
        self.client.session_engine=MagicMock(return_value=self.engine)
        self.background_engine=self.enterContext(patch.object(app.protocol,'Engine',return_value=self.engine))
        self.native={'operation':'logout','phase':'response_received','backend':'verified_drcom_http',
            'authentication_requests':1,'result':False,'response':{'result':'0','msg':'Fictional rejected'}}
        self.native_result=False
        self.portal_ran=False
        self.portal_started=None
        self.on_primary=None
        def primary(*args,**kwargs):
            self.events.append('portal')
            self.portal_ran=True
            self.portal_started=self.tick
            self.client.auth_diagnostic=deepcopy(self.native)
            if self.on_primary:self.on_primary()
            if isinstance(self.native_result,BaseException):raise self.native_result
            return self.native_result
        self.client.run_authentication=MagicMock(side_effect=primary)

    def advance(self,seconds):
        self.tick+=max(float(seconds),.01)
        return False

    def kernel_status(self):
        if self.kernel_sequence:return deepcopy(self.kernel_sequence.pop(0))
        if self.web.disconnected and not self.kernel_after_disconnect_online:return offline()
        return online()

    def check_allowed(self):
        if self.client.cancel.is_set() or self.client.closed.is_set():
            raise RuntimeError('Fictional cancelled operation')
        return self.client.checked_wifi(self.wifi,self.wifi.ssid==core.TEC)

    @staticmethod
    def recovered(value):
        return value[0] is True if isinstance(value,tuple) else value is True

    def recover(self,report=None):
        return self.client._recover_logout(self.wifi,online() if report is None else report,self.check_allowed)

    def run_background(self):
        watch=self.client._logout_watch
        self.assertIsNotNone(watch)
        self.launch.assert_called_once_with(watch)
        self.client._run_logout_verification(watch)
        return watch


class CampusLogoutRecoveryTests(LogoutRecoveryFixture):
    def assert_portal_then_fallback(self,requests=1):
        self.client.run_authentication.assert_called_once()
        self.assertEqual(self.events,['portal','selfservice'])
        self.assertEqual(self.web.login_calls,[(ACCOUNT,PASSWORD)])
        self.assertEqual(self.web.disconnect_calls,[OWN.session_id])
        self.assertIn(OTHER,self.web.devices)
        self.assertEqual(self.web.close_calls,1)
        self.assertEqual(self.client.auth_diagnostic['operation'],'logout')
        self.assertEqual(self.client.auth_diagnostic['authentication_requests'],requests)
        self.assertEqual(self.client.auth_diagnostic['selfservice_logout_requests'],1)
        self.assertTrue(self.client.logout_diagnostic.get('fallback_reason'))
        self.assertEqual(self.client.auth_diagnostic['fallback_reason'],
                         self.client.logout_diagnostic['fallback_reason'])
        self.assertEqual(self.client.logout_diagnostic['outcome'],'offline_confirmed')
        self.assertEqual(self.client.session_state,'offline')
        call=self.client.run_authentication.call_args
        self.assertEqual(call.args[0].ssid,self.SSID)
        self.assertEqual(call.args[4],'logout')
        self.assertIs(call.args[5],self.SSID==core.TEC)

    def accepted_portal(self):
        self.native_result=True
        self.native.update(result=True,response={'result':'1'})

    def stable_portal_status(self):
        return offline() if self.portal_ran else online()

    def test_initial_offline_without_prior_failure_does_not_contact_either_backend(self):
        self.engine.status.side_effect=lambda:offline()
        self.assertTrue(self.client.logout()['ok'])
        self.client.run_authentication.assert_not_called()
        self.web_factory.assert_not_called()
        self.assertEqual(self.client.logout_diagnostic['outcome'],'already_offline')
        self.assertEqual(self.client.auth_diagnostic['authentication_requests'],0)

    def test_initial_offline_with_prior_failure_uses_only_precise_fallback(self):
        self.client._logout_recovery_needed=True
        self.profiles['selected']='own-profile'
        self.kernel_sequence=[offline()]
        self.assertTrue(self.client.logout()['ok'])
        self.client.run_authentication.assert_not_called()
        self.assertEqual(self.events,['selfservice'])
        self.assertEqual(self.web.login_calls,[(ACCOUNT,PASSWORD)])
        self.assertEqual(self.web.disconnect_calls,[OWN.session_id])
        self.assertIn(OTHER,self.web.devices)
        self.assertEqual(self.client.logout_diagnostic['outcome'],'offline_confirmed')
        self.assertEqual(self.web.close_calls,1)

    def test_initial_offline_with_prior_failure_and_no_record_never_claims_success(self):
        self.client._logout_recovery_needed=True
        self.profiles['selected']='own-profile'
        self.engine.status.side_effect=lambda:offline()
        self.web.devices=[OTHER]
        start=self.tick
        self.assertTrue(self.client.logout()['ok'])
        self.client.run_authentication.assert_not_called()
        self.assertEqual(self.web.disconnect_calls,[])
        self.assertNotEqual(self.client.logout_diagnostic['outcome'],'offline_confirmed')
        self.assertGreaterEqual(self.tick-start,app.LOGOUT_SESSION_LOOKUP_TIMEOUT)
        self.assertLessEqual(self.tick-start,app.LOGOUT_SESSION_LOOKUP_TIMEOUT+1.0)
        self.assertEqual(self.client.session_state,'offline')
        self.assertTrue(self.client.get_state()['logout_recovery_needed'])
        self.assertEqual(self.web.close_calls,1)

    def test_late_account_service_record_after_portal_failure_is_waited_for(self):
        self.web.device_sequence=[[],[],[OWN,OTHER]]
        start=self.tick
        self.assertTrue(self.client.logout()['ok'])
        self.assert_portal_then_fallback()
        self.assertGreaterEqual(self.tick-start,
            min(4.0,app.LOGOUT_SESSION_LOOKUP_TIMEOUT)+app.LOGOUT_STABLE_SECONDS)
        self.assertLessEqual(self.tick-start,
            app.LOGOUT_SESSION_LOOKUP_TIMEOUT+app.LOGOUT_CONFIRM_TIMEOUT)

    def test_initial_unknown_uses_precise_fallback_without_blind_portal_mutation(self):
        self.profiles['selected']='own-profile'
        self.kernel_sequence=[{'state':'unknown','matched_ip':True,'binding':'conflict',
            'detail':'session_ip_mismatch','online_account':'','ip_conflict':True}]
        self.assertTrue(self.client.logout()['ok'])
        self.client.run_authentication.assert_not_called()
        self.assertEqual(self.events,['selfservice'])
        self.assertEqual(self.web.disconnect_calls,[OWN.session_id])
        self.assertEqual(self.client.logout_diagnostic['outcome'],'offline_confirmed')

    def test_only_unique_saved_account_matching_server_identity_is_used(self):
        result=self.recover()
        self.assertTrue(self.recovered(result))
        self.assertEqual(self.web.login_calls,[(ACCOUNT,PASSWORD)])
        self.assertEqual(self.web.disconnect_calls,[OWN.session_id])
        self.assertIn(OTHER,self.web.devices)
        self.assertEqual(self.web.close_calls,1)

    def test_missing_portal_context_is_tried_before_fallback_without_blind_submission(self):
        self.native.update(phase='logout_context_missing',backend='status_only',
                           authentication_requests=0,result=None)
        self.native.pop('response',None)
        self.native_result=app.LogoutContextUnavailable('Fictional no AC route')
        self.assertTrue(self.client.logout()['ok'])
        self.assert_portal_then_fallback(requests=0)
        self.assertEqual(self.client.auth_diagnostic['backend'],'status_only')
        self.assertNotIn('response',self.client.auth_diagnostic)

    def test_portal_rejection_uses_one_fallback_and_preserves_primary_diagnostic(self):
        self.assertTrue(self.client.logout()['ok'])
        self.assert_portal_then_fallback()
        self.assertEqual(self.client.auth_diagnostic['backend'],'verified_drcom_http')
        self.assertFalse(self.client.auth_diagnostic['result'])
        self.assertEqual(self.client.auth_diagnostic['logout_requests'],2)

    def test_successful_portal_logout_never_logs_into_selfservice(self):
        self.accepted_portal()
        self.engine.status.side_effect=self.stable_portal_status
        start=self.tick
        self.assertTrue(self.client.logout()['ok'])
        self.assertLess(self.tick-start,3.0)
        self.assertFalse(self.client.busy)
        self.assertEqual(self.client.logout_diagnostic['outcome'],'verification_pending')
        self.assertTrue(self.client.get_state()['logout_recovery_needed'])
        self.internet_check.assert_not_called()
        self.run_background()
        self.client.run_authentication.assert_called_once()
        self.assertEqual(self.events,['portal'])
        self.web_factory.assert_not_called()
        self.assertEqual(self.web.login_calls,[])
        self.assertEqual(self.web.disconnect_calls,[])
        self.assertEqual(self.client.logout_diagnostic['outcome'],'offline_confirmed')
        self.assertFalse(self.client.get_state()['logout_recovery_needed'])

    def test_rejected_response_but_sustained_offline_does_not_unnecessarily_use_fallback(self):
        self.engine.status.side_effect=self.stable_portal_status
        start=self.tick
        self.assertTrue(self.client.logout()['ok'])
        self.assertLess(self.tick-start,3.0)
        self.assertEqual(self.client.logout_diagnostic['outcome'],'verification_pending')
        self.run_background()
        self.client.run_authentication.assert_called_once()
        self.web_factory.assert_not_called()
        self.assertEqual(self.client.logout_diagnostic['outcome'],'offline_confirmed')
        self.assertFalse(self.client.auth_diagnostic['result'])
        self.assertFalse(self.client.auth_diagnostic['selfservice_login_attempted'])
        self.assertEqual(self.client.auth_diagnostic['selfservice_logout_requests'],0)

    def test_normal_success_probes_only_the_bound_campus_interface(self):
        self.accepted_portal()
        self.engine.status.side_effect=self.stable_portal_status
        def probe(wifi,reader,allow_tec):
            self.assertEqual(wifi,self.wifi)
            self.assertEqual(reader(),self.wifi)
            self.assertIs(allow_tec,self.SSID==core.TEC)
            self.assertFalse(self.client.busy)
            return {'online':False,'checks':[{'ok':False}]}
        self.internet_check.side_effect=probe
        self.assertTrue(self.client.logout()['ok'])
        self.internet_check.assert_not_called()
        self.run_background()
        self.assertEqual(self.internet_check.call_count,2)
        self.web_factory.assert_not_called()
        self.assertEqual(self.client.logout_diagnostic['outcome'],'offline_confirmed')

    def test_normal_success_keeps_manual_logout_hold_during_background_verification(self):
        self.accepted_portal()
        self.engine.status.side_effect=self.stable_portal_status
        self.profiles['selected']='own-profile'
        self.profiles['profiles'][1]['operator']='campus'
        self.assertTrue(self.client.logout()['ok'])
        self.assertTrue(self.client._logout_auto_suppressed(self.wifi))
        self.client.login=MagicMock(return_value={'ok':True})
        self.client.notifications=MagicMock()
        notices=[[(21,self.wifi.guid),(10,self.wifi.guid)]]
        self.client.notifications.drain.side_effect=lambda:notices.pop(0) if notices else []
        for _ in range(3):self.client.poll_wifi()
        self.client.login.assert_not_called()
        self.web_factory.assert_not_called()

    def test_apparent_offline_with_working_external_access_uses_one_fallback(self):
        self.accepted_portal()
        self.engine.status.side_effect=self.stable_portal_status
        self.internet_check.return_value={'online':True,'checks':[{'ok':True}]}
        self.assertTrue(self.client.logout()['ok'])
        self.web_factory.assert_not_called()
        self.run_background()
        self.assert_portal_then_fallback()
        self.assertEqual(self.client.logout_diagnostic['fallback_reason'],'access_still_online')
        self.internet_check.assert_called_once()

    def test_status_reappearing_during_final_access_probe_uses_one_fallback(self):
        self.accepted_portal()
        self.engine.status.side_effect=self.stable_portal_status
        def change_status(*args,**kwargs):
            self.engine.status.side_effect=self.kernel_status
            return {'online':False,'checks':[]}
        self.internet_check.side_effect=change_status
        self.assertTrue(self.client.logout()['ok'])
        self.run_background()
        self.assert_portal_then_fallback()
        self.assertEqual(self.client.logout_diagnostic['fallback_reason'],'session_reappeared')

    def test_cancellation_during_final_access_probe_never_starts_fallback(self):
        self.accepted_portal()
        self.engine.status.side_effect=self.stable_portal_status
        def cancel(*args,**kwargs):
            self.client.cancel.set()
            return {'online':False,'checks':[]}
        self.internet_check.side_effect=cancel
        self.assertTrue(self.client.logout()['ok'])
        self.run_background()
        self.client.run_authentication.assert_called_once()
        self.internet_check.assert_called_once()
        self.web_factory.assert_not_called()
        self.assertNotEqual(self.client.logout_diagnostic['outcome'],'offline_confirmed')

    def test_network_change_during_final_access_probe_never_starts_fallback(self):
        self.accepted_portal()
        self.engine.status.side_effect=self.stable_portal_status
        def change_network(*args,**kwargs):
            self.current=replace(self.wifi,ip='10.61.55.11')
            return {'online':False,'checks':[]}
        self.internet_check.side_effect=change_network
        self.assertTrue(self.client.logout()['ok'])
        self.run_background()
        self.client.run_authentication.assert_called_once()
        self.internet_check.assert_called_once()
        self.web_factory.assert_not_called()
        self.assertNotEqual(self.client.logout_diagnostic['outcome'],'offline_confirmed')

    def test_normal_success_does_not_require_saved_selfservice_credentials(self):
        self.accepted_portal()
        self.profiles['profiles']=[]
        self.engine.status.side_effect=self.stable_portal_status
        self.assertTrue(self.client.logout()['ok'])
        self.run_background()
        self.web_factory.assert_not_called()
        self.assertEqual(self.client.logout_diagnostic['outcome'],'offline_confirmed')

    def test_portal_success_but_unchanged_online_state_uses_fallback(self):
        self.accepted_portal()
        start=self.tick
        self.assertTrue(self.client.logout()['ok'])
        self.assert_portal_then_fallback()
        self.assertGreaterEqual(self.tick-start,2.0)
        self.assertLess(self.tick-start,15.0)

    def test_transient_offline_then_online_uses_fallback_without_green_success(self):
        self.accepted_portal()
        self.kernel_sequence=[online(),offline(),online()]
        self.assertTrue(self.client.logout()['ok'])
        self.assert_portal_then_fallback()

    def test_forty_second_reappearance_triggers_background_fallback_after_fast_return(self):
        self.accepted_portal()
        def late_reappearance():
            if not self.portal_ran:return online()
            if self.web.disconnected:return offline()
            return offline() if self.tick-self.portal_started<40.0 else online()
        self.engine.status.side_effect=late_reappearance
        start=self.tick
        self.assertTrue(self.client.logout()['ok'])
        self.assertLess(self.tick-start,3.0)
        self.web_factory.assert_not_called()
        self.assertEqual(self.client.logout_diagnostic['outcome'],'verification_pending')
        self.run_background()
        self.assert_portal_then_fallback()
        self.assertGreaterEqual(self.tick-start,40.0)
        self.assertLess(self.tick-start,65.0)

    def test_unconfirmed_status_after_portal_success_uses_fallback(self):
        self.accepted_portal()
        self.kernel_sequence=[online(),{'state':'unknown','detail':'Fictional unavailable'}]
        self.assertTrue(self.client.logout()['ok'])
        self.assert_portal_then_fallback()

    def test_portal_exception_uses_fallback_once(self):
        self.native_result=OSError('Fictional dropped response')
        self.assertTrue(self.client.logout()['ok'])
        self.assert_portal_then_fallback()

    def test_portal_unknown_response_uses_fallback_once(self):
        self.native_result=None
        self.native.update(result=None)
        self.assertTrue(self.client.logout()['ok'])
        self.assert_portal_then_fallback()

    def test_original_online_identity_is_kept_when_portal_now_reports_offline(self):
        self.accepted_portal()
        self.kernel_sequence=[online(),offline(),{'state':'unknown','detail':'Fictional unavailable'}]
        self.assertTrue(self.client.logout()['ok'])
        self.assert_portal_then_fallback()
        self.assertNotEqual(self.web.login_calls[0][0],'fictional-selected-other')

    def test_cancellation_during_primary_exception_does_not_start_fallback(self):
        self.native_result=OSError('Fictional dropped response')
        self.on_primary=self.client.cancel.set
        with self.assertRaises(RuntimeError):self.client.logout()
        self.client.run_authentication.assert_called_once()
        self.web_factory.assert_not_called()

    def test_network_change_during_primary_exception_does_not_start_fallback(self):
        self.native_result=OSError('Fictional dropped response')
        self.on_primary=lambda:setattr(self,'current',replace(self.wifi,ip='10.61.55.11'))
        with self.assertRaises(RuntimeError):self.client.logout()
        self.client.run_authentication.assert_called_once()
        self.web_factory.assert_not_called()

    def test_cancel_while_confirming_normal_success_does_not_start_fallback(self):
        self.accepted_portal()
        self.engine.status.side_effect=self.stable_portal_status
        def cancel_later(seconds):
            self.advance(seconds)
            self.client.cancel.set()
        self.client._logout_wait=cancel_later
        with self.assertRaises(RuntimeError):self.client.logout()
        self.web_factory.assert_not_called()
        self.launch.assert_not_called()

    def test_manual_login_intent_during_the_primary_response_cancels_old_logout_without_fallback(self):
        self.accepted_portal()
        self.engine.status.side_effect=self.stable_portal_status
        requested=[]
        self.on_primary=lambda:requested.append(self.client.login(ACCOUNT,PASSWORD,'campus'))
        with self.assertRaises(RuntimeError):self.client.logout()
        self.assertEqual(len(requested),1)
        self.assertFalse(requested[0]['ok'])
        self.assertIsNone(self.client._logout_watch)
        self.client.run_authentication.assert_called_once()
        self.web_factory.assert_not_called()
        self.launch.assert_not_called()

    def test_stale_login_diagnostic_is_reset_before_unknown_logout_preflight(self):
        self.client.auth_diagnostic={'operation':'login','backend':'Fictional stale',
            'authentication_requests':99,'result':True}
        self.profiles['selected']='own-profile'
        self.kernel_sequence=[{'state':'unknown','detail':'Fictional unavailable'}]
        self.assertTrue(self.client.logout()['ok'])
        self.client.run_authentication.assert_not_called()
        self.assertEqual(self.client.auth_diagnostic['operation'],'logout')
        self.assertEqual(self.client.auth_diagnostic['authentication_requests'],0)

    def test_no_matching_saved_credentials_never_uses_selected_other_account(self):
        self.profiles['profiles']=self.profiles['profiles'][:1]
        self.assertTrue(self.client.logout()['ok'])
        self.client.run_authentication.assert_called_once()
        self.assertNotEqual(self.client.logout_diagnostic['outcome'],'offline_confirmed')
        self.assertEqual(self.web.login_calls,[])
        self.assertEqual(self.web.disconnect_calls,[])

    def test_initial_offline_retry_without_selected_password_sends_no_requests(self):
        self.client._logout_recovery_needed=True
        self.profiles['selected']='own-profile'
        self.profiles['profiles'][1]['password']=''
        self.engine.status.side_effect=lambda:offline()
        self.assertTrue(self.client.logout()['ok'])
        self.client.run_authentication.assert_not_called()
        self.assertEqual(self.web.login_calls,[])
        self.assertEqual(self.web.disconnect_calls,[])
        self.assertNotEqual(self.client.logout_diagnostic['outcome'],'offline_confirmed')

    def test_ambiguous_passwords_for_the_same_online_account_are_not_guessed(self):
        self.profiles['profiles'].append({'id':'ambiguous-profile','account':ACCOUNT,
            'password':'fictional-different-password','operator':''})
        self.assertFalse(self.recovered(self.recover()))
        self.assertEqual(self.web.login_calls,[])
        self.assertEqual(self.web.disconnect_calls,[])

    def test_absent_or_masked_online_identity_does_not_authorize_selected_credentials(self):
        for identity in ('','***1234','[已隐藏]'):
            with self.subTest(identity=identity):
                report=online();report['online_account']=identity
                self.assertFalse(self.recovered(self.recover(report)))
        self.assertEqual(self.web.login_calls,[])
        self.assertEqual(self.web.disconnect_calls,[])

    def test_web_login_failure_does_not_report_success_and_always_closes(self):
        self.web.login_error=service.AuthenticationError('Fictional invalid login')
        self.assertTrue(self.client.logout()['ok'])
        self.client.run_authentication.assert_called_once()
        self.assertEqual(self.events,['portal','selfservice'])
        self.assertNotEqual(self.client.logout_diagnostic['outcome'],'offline_confirmed')
        self.assertEqual(self.web.disconnect_calls,[])
        self.assertEqual(self.web.close_calls,1)

    def test_visible_captcha_stops_without_device_mutation_and_closes(self):
        self.web.login_error=service.CaptchaRequired('Fictional captcha required')
        self.assertTrue(self.client.logout()['ok'])
        self.client.run_authentication.assert_called_once()
        self.assertEqual(self.events,['portal','selfservice'])
        self.assertNotEqual(self.client.logout_diagnostic['outcome'],'offline_confirmed')
        self.assertEqual(self.web.disconnect_calls,[])
        self.assertEqual(self.web.close_calls,1)

    def test_no_matching_device_never_disconnects_another_saved_session(self):
        self.web.devices=[OTHER]
        self.assertFalse(self.recovered(self.recover()))
        self.assertEqual(self.web.disconnect_calls,[])
        self.assertEqual(self.web.close_calls,1)

    def test_duplicate_matching_device_sessions_stop_without_bulk_disconnect(self):
        self.web.devices=[OWN,service.DeviceSession('fictional-duplicate',OWN.ip,OWN.mac,OWN.user_id),OTHER]
        self.assertFalse(self.recovered(self.recover()))
        self.assertEqual(self.web.disconnect_calls,[])
        self.assertEqual(self.web.close_calls,1)

    def test_same_mac_at_an_unverified_other_ip_is_not_chosen(self):
        self.web.devices=[service.DeviceSession('fictional-other-address','10.62.55.11',MAC,71)]
        self.assertFalse(self.recovered(self.recover()))
        self.assertEqual(self.web.disconnect_calls,[])
        self.assertEqual(self.web.close_calls,1)

    def test_mac_verified_kernel_address_may_identify_the_same_current_device(self):
        alternate=service.DeviceSession('fictional-verified-address','10.62.55.11',MAC,71)
        self.web.devices=[alternate,OTHER]
        report=online();report['server_ip']=alternate.ip;report['ip_conflict']=True
        self.assertTrue(self.recovered(self.recover(report)))
        self.assertEqual(self.web.disconnect_calls,[alternate.session_id])
        self.assertIn(OTHER,self.web.devices)

    def test_unconfirmed_kernel_address_cannot_authorize_an_alternate_session(self):
        alternate=service.DeviceSession('fictional-unverified-address','10.62.55.11',MAC,71)
        self.web.devices=[alternate,OTHER]
        report=online();report.update(state='unknown',binding='conflict',server_ip=alternate.ip)
        self.assertFalse(self.recovered(self.recover(report)))
        self.assertEqual(self.web.disconnect_calls,[])

    def test_disconnect_exception_is_not_retried_and_web_session_is_closed(self):
        self.web.disconnect_error=OSError('Fictional lost acknowledgement')
        self.assertFalse(self.recovered(self.recover()))
        self.assertEqual(len(self.web.disconnect_calls),1)
        self.assertEqual(self.web.close_calls,1)

    def test_cancellation_after_web_login_stops_device_request_but_closes_web_session(self):
        self.web.on_login=self.client.cancel.set
        try:result=self.recover()
        except RuntimeError:result=False
        self.assertFalse(self.recovered(result))
        self.assertEqual(self.web.disconnect_calls,[])
        self.assertEqual(self.web.close_calls,1)

    def test_network_change_after_web_login_stops_device_request_and_closes(self):
        self.web.on_login=lambda:setattr(self,'current',replace(WIFI,ip='10.61.55.11'))
        try:result=self.recover()
        except RuntimeError:result=False
        self.assertFalse(self.recovered(result))
        self.assertEqual(self.web.disconnect_calls,[])
        self.assertEqual(self.web.close_calls,1)

    def test_cancel_after_disconnect_does_not_claim_confirmation_and_closes(self):
        self.web.on_disconnect=self.client.cancel.set
        try:result=self.recover()
        except RuntimeError:result=False
        self.assertFalse(self.recovered(result))
        self.assertEqual(len(self.web.disconnect_calls),1)
        self.assertEqual(self.web.close_calls,1)

    def test_final_summary_contains_no_credentials_or_session_identifier(self):
        self.assertTrue(self.recovered(self.recover()))
        import json
        summary=json.dumps(self.client.logout_diagnostic)
        for value in (ACCOUNT,PASSWORD,OWN.session_id,OTHER.session_id):
            self.assertNotIn(value,summary)
        self.assertTrue(self.web.closed)

    def test_failed_recovery_is_visible_to_the_ui_without_faking_offline(self):
        self.web.login_error=service.AuthenticationError('Fictional invalid login')
        self.assertTrue(self.client.logout()['ok'])
        self.assertTrue(self.client.get_state()['logout_recovery_needed'])
        self.assertNotEqual(self.client.session_state,'offline')


class CampusLogoutConfirmationTests(LogoutRecoveryFixture):
    def confirm(self):
        self.web.authenticated=True
        return self.client._confirm_logout(self.wifi,self.web,self.check_allowed)

    def test_absent_service_record_and_sustained_kernel_offline_are_both_required(self):
        self.web.devices=[]
        self.web.disconnected=True
        start=self.tick
        success,last=self.confirm()
        self.assertTrue(success)
        self.assertEqual(last['state'],'offline')
        self.assertGreaterEqual(self.tick-start,5.0)
        self.assertTrue(all(call.args[1] is (self.SSID==core.TEC)
                            for call in self.client.session_engine.call_args_list))

    def test_kernel_offline_does_not_override_same_mac_still_in_service_list(self):
        self.web.disconnected=True
        self.assertFalse(self.confirm()[0])

    def test_new_session_id_with_current_mac_is_not_mistaken_for_disconnection(self):
        self.web.devices=[service.DeviceSession('fictional-reappeared-session',WIFI.ip,MAC,71)]
        self.web.disconnected=True
        self.assertFalse(self.confirm()[0])

    def test_service_list_absence_does_not_override_kernel_online(self):
        self.web.devices=[]
        self.web.disconnected=True
        self.kernel_after_disconnect_online=True
        self.assertFalse(self.confirm()[0])

    def test_one_offline_sample_before_online_is_not_confirmed(self):
        self.web.devices=[]
        self.kernel_sequence=[offline(),online()]
        self.kernel_after_disconnect_online=True
        self.assertFalse(self.confirm()[0])

    def test_only_other_device_remaining_allows_current_device_confirmation(self):
        self.web.devices=[OTHER]
        self.web.disconnected=True
        self.assertTrue(self.confirm()[0])

    def late_current_ip_entry(self,mac):
        # The module's first six seconds may already have looked clean. A new
        # record at second seven must still prevent the App's final success.
        self.tick+=6
        appears=self.tick+1
        ghost=service.DeviceSession('fictional-late-ip-session',self.wifi.ip,mac,71)
        self.web.disconnected=True
        self.web.list_online_devices=MagicMock(side_effect=lambda:
            [OTHER,ghost] if self.tick>=appears else [OTHER])
        success,last=self.confirm()
        self.assertFalse(success)
        self.assertEqual(last['state'],'offline')
        self.assertFalse(self.client.logout_diagnostic['verification']['account_device_absent'])

    def test_late_current_ip_record_without_mac_prevents_offline_confirmation(self):
        self.late_current_ip_entry('')

    def test_late_current_ip_record_with_different_valid_mac_prevents_confirmation(self):
        self.late_current_ip_entry('66778899AABB')


class PortalLogoutConfirmationTests(LogoutRecoveryFixture):
    def confirm(self,report=None):
        return self.client._confirm_portal_logout(self.wifi,self.SSID==core.TEC,
                                                 self.check_allowed,report)

    def test_normal_offline_returns_quickly_without_selfservice_or_external_probe(self):
        self.engine.status.side_effect=lambda:offline()
        start=self.tick
        success,last=self.confirm()
        self.assertTrue(success)
        self.assertEqual(last['state'],'offline')
        self.assertGreaterEqual(self.tick-start,.5)
        self.assertLess(self.tick-start,3.0)
        self.assertGreaterEqual(self.engine.status.call_count,2)
        self.web_factory.assert_not_called()
        self.internet_check.assert_not_called()
        self.assertTrue(all(call.args[1] is (self.SSID==core.TEC)
                            for call in self.client.session_engine.call_args_list))

    def test_brief_propagation_is_followed_by_two_fast_offline_samples(self):
        start=self.tick
        self.engine.status.side_effect=lambda:online() if self.tick-start<1.0 else offline()
        success,last=self.confirm()
        self.assertTrue(success)
        self.assertEqual(last['state'],'offline')
        self.assertGreaterEqual(self.tick-start,1.5)
        self.assertLess(self.tick-start,3.0)
        self.web_factory.assert_not_called()
        self.internet_check.assert_not_called()

    def test_still_online_at_propagation_deadline_is_not_confirmed(self):
        self.engine.status.side_effect=lambda:online()
        start=self.tick
        success,last=self.confirm()
        self.assertFalse(success)
        self.assertEqual(last['state'],'online')
        self.assertGreaterEqual(self.tick-start,2.0)
        self.assertLess(self.tick-start,3.0)
        self.web_factory.assert_not_called()

    def test_possible_late_reappearance_does_not_block_the_foreground(self):
        start=self.tick
        self.engine.status.side_effect=lambda:offline() if self.tick-start<40.0 else online()
        success,last=self.confirm()
        self.assertTrue(success)
        self.assertEqual(last['state'],'offline')
        self.assertLess(self.tick-start,3.0)
        self.internet_check.assert_not_called()
        self.web_factory.assert_not_called()

    def test_unknown_readback_never_claims_normal_success(self):
        self.engine.status.side_effect=lambda:{'state':'unknown','detail':'Fictional unavailable'}
        success,last=self.confirm()
        self.assertFalse(success)
        self.assertEqual(last['state'],'unknown')
        self.web_factory.assert_not_called()

    def test_cancelled_confirmation_stops_without_selfservice(self):
        self.client.cancel.set()
        with self.assertRaises(RuntimeError):self.confirm()
        self.web_factory.assert_not_called()


class BackgroundLogoutVerificationTests(LogoutRecoveryFixture):
    def begin_fast_logout(self):
        self.native_result=True
        self.native.update(result=True,response={'result':'1'})
        self.engine.status.side_effect=lambda:offline() if self.portal_ran else online()
        start=self.tick
        self.assertTrue(self.client.logout()['ok'])
        self.assertLess(self.tick-start,3.0)
        self.assertEqual(self.client.logout_diagnostic['outcome'],'verification_pending')
        self.assertFalse(self.client.busy)
        return self.client._logout_watch

    def test_observer_uses_an_independent_engine_without_reserving_a_foreground_job(self):
        watch=self.begin_fast_logout()
        self.client.session_engine.reset_mock()
        self.run_background()
        self.background_engine.assert_called_once()
        args,kwargs=self.background_engine.call_args
        self.assertEqual(args,(self.wifi,watch['portal']))
        self.assertIs(kwargs['allow_tec'],self.SSID==core.TEC)
        self.assertTrue(callable(kwargs['reader']))
        self.client.session_engine.assert_not_called()
        self.assertFalse(self.client.busy)
        self.web_factory.assert_not_called()

    def test_a_slow_access_probe_does_not_hold_the_ui_busy(self):
        watch=self.begin_fast_logout()
        entered=threading.Event()
        release=threading.Event()
        def probe(*args,**kwargs):
            entered.set()
            self.assertTrue(release.wait(3),'Fictional probe was not released')
            return {'online':False,'checks':[{'ok':False}]}
        self.internet_check.side_effect=probe
        worker=threading.Thread(target=self.client._run_logout_verification,args=(watch,))
        worker.start()
        try:
            self.assertTrue(entered.wait(3))
            self.assertFalse(self.client.busy)
            self.assertEqual(self.client.operation,'')
            self.assertEqual(self.client.logout_diagnostic['outcome'],'verification_pending')
            self.web_factory.assert_not_called()
        finally:
            release.set()
            worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(self.client.logout_diagnostic['outcome'],'offline_confirmed')

    def test_manual_login_during_a_slow_probe_discards_old_results_and_fallback(self):
        watch=self.begin_fast_logout()
        entered=threading.Event()
        release=threading.Event()
        def probe(*args,**kwargs):
            entered.set()
            self.assertTrue(release.wait(3))
            return {'online':True,'checks':[{'ok':True}]}
        self.internet_check.side_effect=probe
        worker=threading.Thread(target=self.client._run_logout_verification,args=(watch,))
        worker.start()
        try:
            self.assertTrue(entered.wait(3))
            self.client.start_job=MagicMock(return_value={'ok':True})
            self.assertTrue(self.client.login(ACCOUNT,PASSWORD,'campus')['ok'])
            self.assertIsNone(self.client._logout_watch)
            self.client.session_state='online'
            self.client.logged_in=True
            self.client.status='Fictional newer login'
            self.client.auth_diagnostic={'operation':'login','result':True}
            self.client._logout_recovery_needed=False
        finally:
            release.set()
            worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(self.client.session_state,'online')
        self.assertTrue(self.client.logged_in)
        self.assertEqual(self.client.status,'Fictional newer login')
        self.assertEqual(self.client.auth_diagnostic,{'operation':'login','result':True})
        self.assertFalse(self.client._logout_recovery_needed)
        self.web_factory.assert_not_called()

    def test_new_logout_intent_during_a_slow_probe_cannot_be_overwritten(self):
        watch=self.begin_fast_logout()
        entered=threading.Event()
        release=threading.Event()
        def probe(*args,**kwargs):
            entered.set()
            self.assertTrue(release.wait(3))
            return {'online':True,'checks':[{'ok':True}]}
        self.internet_check.side_effect=probe
        worker=threading.Thread(target=self.client._run_logout_verification,args=(watch,))
        worker.start()
        try:
            self.assertTrue(entered.wait(3))
            self.assertTrue(self.client.logout()['ok'])
            self.assertIsNot(self.client._logout_watch,watch)
            newest=self.client._logout_watch
            newest_result=deepcopy(self.client.logout_diagnostic)
            newest_requests=list(self.web.disconnect_calls)
            self.client.status='Fictional newer logout'
        finally:
            release.set()
            worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertIs(self.client._logout_watch,newest)
        self.assertEqual(self.client.status,'Fictional newer logout')
        self.assertEqual(self.client.logout_diagnostic,newest_result)
        self.assertEqual(self.web.disconnect_calls,newest_requests)

    def test_readonly_observer_defers_to_a_foreground_job(self):
        self.begin_fast_logout()
        self.engine.status.reset_mock()
        self.client.busy=True
        self.client.operation='status'
        waits=[]
        def defer(watch,seconds):
            waits.append(seconds)
            if len(waits)==1:
                self.assertLessEqual(seconds,.2)
                self.engine.status.assert_not_called()
                self.internet_check.assert_not_called()
                self.client.busy=False
                self.client.operation=''
            return self.advance(seconds)
        self.client._logout_watch_wait=defer
        self.run_background()
        self.assertEqual(self.client.logout_diagnostic['outcome'],'offline_confirmed')
        self.web_factory.assert_not_called()

    def test_unknown_background_state_is_bounded_and_does_not_authorize_selfservice(self):
        watch=self.begin_fast_logout()
        start=self.tick
        self.engine.status.side_effect=lambda:{'state':'unknown','detail':'Fictional unavailable'}
        self.run_background()
        self.assertGreaterEqual(self.tick-start,60.0)
        self.assertLess(self.tick-start,70.0)
        self.assertFalse(watch['verifying'])
        self.assertEqual(self.client.logout_diagnostic['outcome'],'unconfirmed')
        self.assertTrue(self.client._logout_recovery_needed)
        self.internet_check.assert_not_called()
        self.web_factory.assert_not_called()

    def test_unknown_then_recovered_offline_state_restores_the_confirmation_message(self):
        self.begin_fast_logout()
        start=self.tick
        def status():
            elapsed=self.tick-start
            return {'state':'unknown','detail':'Fictional unavailable'} if 3<=elapsed<6 else offline()
        self.engine.status.side_effect=status
        self.run_background()
        self.assertEqual(self.client.logout_diagnostic['outcome'],'offline_confirmed')
        self.assertFalse(self.client._logout_recovery_needed)
        self.assertEqual(self.client.status,'已退出登录')
        self.web_factory.assert_not_called()

    def test_same_address_reconnect_generation_invalidates_the_old_observer(self):
        watch=self.begin_fast_logout()
        def reconnect(*args,**kwargs):
            self.client._invalidate_logout_route('fictional_same_address_reconnect')
            return {'online':True,'checks':[{'ok':True}]}
        self.internet_check.side_effect=reconnect
        self.run_background()
        self.assertFalse(watch['verifying'])
        self.assertNotEqual(self.client.logout_diagnostic['outcome'],'offline_confirmed')
        self.web_factory.assert_not_called()

    def test_mac_change_with_the_same_legacy_key_stops_the_old_observer(self):
        watch=self.begin_fast_logout()
        changed=replace(self.wifi,mac='00-11-22-33-44-66')
        self.assertEqual(changed.key,self.wifi.key)
        def change(*args,**kwargs):
            self.current=changed
            return {'online':True,'checks':[{'ok':True}]}
        self.internet_check.side_effect=change
        self.run_background()
        self.assertFalse(watch['verifying'])
        self.web_factory.assert_not_called()

    def test_an_inflight_probe_finishing_after_the_deadline_can_only_fallback_once(self):
        watch=self.begin_fast_logout()
        def late(*args,**kwargs):
            self.advance(70)
            return {'online':True,'checks':[{'ok':True}]}
        self.internet_check.side_effect=late
        self.run_background()
        self.assertFalse(watch['verifying'])
        self.assertTrue(watch['fallback_started'])
        self.assertEqual(self.client.logout_diagnostic['fallback_reason'],'access_still_online')
        self.assertEqual(self.web.disconnect_calls,[OWN.session_id])
        self.client._run_logout_verification(watch)
        self.assertEqual(self.web.disconnect_calls,[OWN.session_id])

    def test_an_inflight_probe_after_its_intent_is_replaced_cannot_publish_or_disconnect(self):
        watch=self.begin_fast_logout()
        replacement={'ssid':self.SSID.casefold(),'guid':self.wifi.guid,
                     'started':self.tick,'saw_offline':False}
        def late(*args,**kwargs):
            self.advance(70)
            self.client._stop_logout_verification()
            self.client._logout_watch=replacement
            self.client.status='Fictional later intent'
            self.client.session_state='online'
            self.client.logged_in=True
            return {'online':True,'checks':[{'ok':True}]}
        self.internet_check.side_effect=late
        self.run_background()
        self.assertFalse(watch['verifying'])
        self.assertIs(self.client._logout_watch,replacement)
        self.assertEqual(self.client.status,'Fictional later intent')
        self.assertEqual(self.client.session_state,'online')
        self.assertTrue(self.client.logged_in)
        self.web_factory.assert_not_called()

    def test_accepted_automatic_login_replaces_the_watch_even_when_global_cancel_is_clear(self):
        watch=self.begin_fast_logout()
        entered=threading.Event()
        release=threading.Event()
        accepted=threading.Event()
        def probe(*args,**kwargs):
            entered.set()
            self.assertTrue(release.wait(3))
            return {'online':True,'checks':[{'ok':True}]}
        self.internet_check.side_effect=probe
        worker=threading.Thread(target=self.client._run_logout_verification,args=(watch,))
        worker.start()
        try:
            self.assertTrue(entered.wait(3))
            self.client.start_job=app.App.start_job.__get__(self.client,app.App)
            def new_login():
                self.client.session_state='online'
                self.client.logged_in=True
                self.client.status='Fictional accepted automatic login'
                accepted.set()
            self.assertTrue(self.client.start_job('login',new_login,automatic=True)['ok'])
            self.assertTrue(accepted.wait(3))
            self.assertIsNone(self.client._logout_watch)
            self.assertFalse(self.client.cancel.is_set())
        finally:
            release.set()
            worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(self.client.status,'Fictional accepted automatic login')
        self.assertEqual(self.client.session_state,'online')
        self.assertTrue(self.client.logged_in)
        self.web_factory.assert_not_called()

    def test_external_access_reappearing_at_the_end_of_observation_uses_one_fallback(self):
        watch=self.begin_fast_logout()
        start=self.tick
        def probe(*args,**kwargs):
            return {'online':self.tick-start>=55.0,'checks':[]}
        self.internet_check.side_effect=probe
        self.run_background()
        self.assertEqual(self.internet_check.call_count,2)
        self.assertTrue(watch['fallback_started'])
        self.assertEqual(self.client.logout_diagnostic['fallback_reason'],'access_still_online')
        self.assertEqual(self.web.disconnect_calls,[OWN.session_id])
        self.assertGreaterEqual(self.tick-start,55.0)
        self.assertIn(OTHER,self.web.devices)

    def test_closed_app_discards_the_old_probe_without_any_fallback(self):
        watch=self.begin_fast_logout()
        def close(*args,**kwargs):
            self.client.closed.set()
            return {'online':True,'checks':[{'ok':True}]}
        self.internet_check.side_effect=close
        self.run_background()
        self.assertFalse(watch['verifying'])
        self.web_factory.assert_not_called()

    def test_background_fallback_keeps_the_original_account_and_is_at_most_once(self):
        watch=self.begin_fast_logout()
        self.engine.status.side_effect=self.kernel_status
        self.run_background()
        self.assertEqual(self.web.login_calls,[(ACCOUNT,PASSWORD)])
        self.assertEqual(self.web.disconnect_calls,[OWN.session_id])
        self.assertIn(OTHER,self.web.devices)
        self.assertTrue(watch['fallback_started'])
        self.assertFalse(watch['verifying'])
        self.client._run_logout_verification(watch)
        self.assertEqual(self.web.disconnect_calls,[OWN.session_id])
        self.assertEqual(self.web.close_calls,1)


class LogoutAutomaticSuppressionTests(LogoutRecoveryFixture):
    def begin_manual_logout(self):
        self.kernel_sequence=[offline()]
        self.assertTrue(self.client.logout()['ok'])
        self.auto_login=MagicMock(return_value={'ok':True})
        self.client.login=self.auto_login

    def poll(self,*snapshots):
        for snapshot in snapshots:
            self.current=snapshot
            self.client.poll_wifi()

    def test_manual_logout_blocks_same_connection_automatic_login(self):
        self.begin_manual_logout()
        self.poll(WIFI,WIFI,WIFI)
        self.auto_login.assert_not_called()

    def test_expiring_watch_does_not_create_a_new_auto_login_opportunity(self):
        self.begin_manual_logout()
        self.poll(WIFI)
        self.tick+=61
        self.poll(WIFI,WIFI)
        self.auto_login.assert_not_called()

    def test_temporary_empty_ssid_reconnect_does_not_cancel_manual_logout_intent(self):
        self.begin_manual_logout()
        self.poll(core.Wifi(),WIFI,WIFI,WIFI)
        self.auto_login.assert_not_called()

    def test_other_nonempty_ssid_then_return_clears_manual_logout_suppression(self):
        self.begin_manual_logout()
        self.poll(HOTSPOT,WIFI,WIFI,WIFI)
        self.auto_login.assert_called_once()

    def test_same_ssid_notifications_during_watch_do_not_restore_auto_login(self):
        self.begin_manual_logout()
        self.client.notifications=MagicMock()
        notices=[[(21,WIFI.guid),(10,WIFI.guid)]]
        self.client.notifications.drain.side_effect=lambda:notices.pop(0) if notices else []
        self.poll(WIFI,WIFI,WIFI)
        self.auto_login.assert_not_called()

    def test_explicit_manual_login_cancels_the_watch_for_a_subsequent_connection(self):
        self.kernel_sequence=[offline()]
        self.assertTrue(self.client.logout()['ok'])
        self.assertTrue(self.client.login(ACCOUNT,PASSWORD,'campus')['ok'])
        self.auto_login=MagicMock(return_value={'ok':True})
        self.client.login=self.auto_login
        self.client.notifications=MagicMock()
        notices=[[(21,WIFI.guid),(10,WIFI.guid)]]
        self.client.notifications.drain.side_effect=lambda:notices.pop(0) if notices else []
        self.poll(WIFI,WIFI,WIFI)
        self.auto_login.assert_called_once()

    def test_only_a_new_connection_after_watch_expiry_restores_auto_login(self):
        self.begin_manual_logout()
        self.poll(core.Wifi(),WIFI,WIFI)
        self.tick+=61
        self.poll(WIFI,WIFI)
        self.auto_login.assert_not_called()
        self.client.notifications=MagicMock()
        notices=[[(21,WIFI.guid),(10,WIFI.guid)]]
        self.client.notifications.drain.side_effect=lambda:notices.pop(0) if notices else []
        self.poll(WIFI,WIFI,WIFI)
        self.auto_login.assert_called_once()


class StuLogoutRecoveryTests(CampusLogoutRecoveryTests):
    SSID=core.STU


class StuLogoutConfirmationTests(CampusLogoutConfirmationTests):
    SSID=core.STU


class StuPortalLogoutConfirmationTests(PortalLogoutConfirmationTests):
    SSID=core.STU


class StuBackgroundLogoutVerificationTests(BackgroundLogoutVerificationTests):
    SSID=core.STU


if __name__=='__main__':
    unittest.main()
