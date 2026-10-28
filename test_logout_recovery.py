"""TEC logout recovery verifies one owned device and two independent views.

All identities, routes, sessions and web responses are synthetic. The App uses
a mock Store and a temporary real logger; no real network or registry is used.
"""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import socket
import tempfile
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

    def disconnect_current(self,session_info=None,before_disconnect=None):
        if self.disconnect_calls:raise service.SelfServiceError('Fictional duplicate disconnect')
        selected=service.select_current_session(self.list_online_devices(),self.wifi,session_info)
        verified=service.select_current_session(self.list_online_devices(),self.wifi,session_info)
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
        self.current=WIFI
        self.reader=self.enterContext(patch.object(core,'read_wifi',side_effect=lambda:self.current))
        self.enterContext(patch.object(socket.socket,'connect',
            side_effect=AssertionError('No real network in App recovery tests')))
        self.enterContext(patch.object(app,'stable_autostart_configured',return_value=False))
        self.enterContext(patch.object(app,'stable_instance_running',return_value=False))
        self.client.wifi=WIFI
        self.client.window=MagicMock()
        self.client.window.native=None
        self.client.start_job=lambda kind,job,automatic=False:(job() or {'ok':True})
        self.client.save_profile=MagicMock(return_value={'ok':True})
        self.tick=100.0
        self.enterContext(patch.object(app.time,'monotonic',side_effect=lambda:self.tick))
        self.client._logout_wait=lambda seconds:self.advance(seconds)
        self.web=FakeWebClient(WIFI)
        self.web_factory=self.enterContext(patch.object(service,'Client',return_value=self.web))
        self.engine=MagicMock()
        self.kernel_sequence=[]
        self.kernel_after_disconnect_online=False
        self.engine.status.side_effect=self.kernel_status
        self.client.session_engine=MagicMock(return_value=self.engine)
        self.native={'operation':'logout','phase':'response_received','backend':'verified_drcom_http',
            'authentication_requests':1,'result':False,'response':{'result':'0','msg':'Fictional rejected'}}
        self.native_result=False
        def primary(*args,**kwargs):
            self.client.auth_diagnostic=deepcopy(self.native)
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
        self.client.checked_wifi(WIFI,True)

    @staticmethod
    def recovered(value):
        return value[0] is True if isinstance(value,tuple) else value is True

    def recover(self,report=None):
        return self.client._recover_tec_logout(WIFI,online() if report is None else report,self.check_allowed)


class TecLogoutRecoveryTests(LogoutRecoveryFixture):
    def test_initial_portal_offline_still_removes_confirmed_selfservice_device(self):
        self.profiles['selected']='own-profile'
        self.kernel_sequence=[offline()]
        self.assertTrue(self.client.logout()['ok'])
        self.client.run_authentication.assert_not_called()
        self.assertEqual(self.web.login_calls,[(ACCOUNT,PASSWORD)])
        self.assertEqual(self.web.disconnect_calls,[OWN.session_id])
        self.assertIn(OTHER,self.web.devices)
        self.assertEqual(self.client.logout_diagnostic['outcome'],'offline_confirmed')
        self.assertEqual(self.web.close_calls,1)

    def test_initial_offline_without_service_record_waits_without_claiming_success(self):
        self.profiles['selected']='own-profile'
        self.engine.status.side_effect=lambda:offline()
        self.web.devices=[OTHER]
        start=self.tick
        self.assertTrue(self.client.logout()['ok'])
        self.client.run_authentication.assert_not_called()
        self.assertEqual(self.web.disconnect_calls,[])
        self.assertNotEqual(self.client.logout_diagnostic['outcome'],'offline_confirmed')
        self.assertGreaterEqual(self.tick-start,45.0)
        self.assertLessEqual(self.tick-start,46.0)
        self.assertEqual(self.client.session_state,'offline')
        self.assertTrue(self.client.get_state()['logout_recovery_needed'])
        self.assertEqual(self.web.close_calls,1)

    def test_late_account_service_record_is_waited_for_before_one_disconnect(self):
        self.web.device_sequence=[[],[],[OWN,OTHER]]
        start=self.tick
        self.assertTrue(self.client.logout()['ok'])
        self.client.run_authentication.assert_not_called()
        self.assertEqual(self.web.disconnect_calls,[OWN.session_id])
        self.assertEqual(self.client.logout_diagnostic['outcome'],'offline_confirmed')
        self.assertGreaterEqual(self.tick-start,9.0)
        self.assertEqual(self.web.close_calls,1)

    def test_initial_unknown_uses_precise_service_record_without_portal_mutation(self):
        self.profiles['selected']='own-profile'
        self.kernel_sequence=[{'state':'unknown','matched_ip':True,'binding':'conflict',
            'detail':'session_ip_mismatch','online_account':'','ip_conflict':True}]
        self.assertTrue(self.client.logout()['ok'])
        self.client.run_authentication.assert_not_called()
        self.assertEqual(self.web.disconnect_calls,[OWN.session_id])
        self.assertEqual(self.client.logout_diagnostic['outcome'],'offline_confirmed')

    def test_only_unique_saved_account_matching_server_identity_is_used(self):
        result=self.recover()
        self.assertTrue(self.recovered(result))
        self.assertEqual(self.web.login_calls,[(ACCOUNT,PASSWORD)])
        self.assertEqual(self.web.disconnect_calls,[OWN.session_id])
        self.assertIn(OTHER,self.web.devices)
        self.assertEqual(self.web.close_calls,1)

    def test_tec_skips_portal_even_if_its_context_would_be_missing(self):
        self.native.update(phase='logout_context_missing',backend='status_only',
                           authentication_requests=0,result=None)
        self.native_result=app.LogoutContextUnavailable('Fictional no AC route')
        self.assertTrue(self.client.logout()['ok'])
        self.client.run_authentication.assert_not_called()
        self.assertEqual(self.web.disconnect_calls,[OWN.session_id])
        self.assertEqual(self.client.auth_diagnostic['operation'],'logout')
        self.assertEqual(self.client.auth_diagnostic['backend'],'selfservice')
        self.assertEqual(self.client.auth_diagnostic['authentication_requests'],0)
        self.assertIn(self.client.auth_diagnostic.get('result'),(None,))
        self.assertEqual(self.client.session_state,'offline')
        self.assertFalse(self.client.logged_in)

    def test_tec_never_clears_portal_record_before_selfservice_disconnect(self):
        self.assertTrue(self.client.logout()['ok'])
        self.client.run_authentication.assert_not_called()
        self.assertEqual(self.web.disconnect_calls,[OWN.session_id])
        self.assertEqual(self.client.auth_diagnostic['backend'],'selfservice')
        self.assertEqual(self.client.auth_diagnostic['authentication_requests'],0)
        self.assertNotIn('response',self.client.auth_diagnostic)
        self.assertEqual(self.client.session_state,'offline')

    def test_tec_does_not_use_portal_even_if_it_would_return_success(self):
        self.native_result=True
        self.native.update(result=True,response={'result':'1'})
        self.assertTrue(self.client.logout()['ok'])
        self.client.run_authentication.assert_not_called()
        self.assertEqual(self.web.disconnect_calls,[OWN.session_id])
        self.assertEqual(self.client.auth_diagnostic['backend'],'selfservice')
        self.assertEqual(self.client.auth_diagnostic['authentication_requests'],0)
        self.assertNotIn('response',self.client.auth_diagnostic)
        self.assertEqual(self.client.session_state,'offline')

    def test_transient_kernel_offline_does_not_skip_service_mutation(self):
        self.native_result=True
        self.native.update(result=True,response={'result':'1'})
        self.kernel_sequence=[online(),offline(),online()]
        self.assertTrue(self.client.logout()['ok'])
        self.client.run_authentication.assert_not_called()
        self.assertEqual(self.web.disconnect_calls,[OWN.session_id])
        self.assertEqual(self.client.session_state,'offline')

    def test_no_matching_saved_credentials_never_uses_the_selected_other_account(self):
        self.profiles['profiles']=self.profiles['profiles'][:1]
        self.assertTrue(self.client.logout()['ok'])
        self.client.run_authentication.assert_not_called()
        self.assertNotEqual(self.client.logout_diagnostic['outcome'],'offline_confirmed')
        self.assertEqual(self.web.login_calls,[])
        self.assertEqual(self.web.disconnect_calls,[])

    def test_initial_offline_without_selected_saved_password_does_not_use_portal(self):
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
        self.client.run_authentication.assert_not_called()
        self.assertNotEqual(self.client.logout_diagnostic['outcome'],'offline_confirmed')
        self.assertEqual(self.web.disconnect_calls,[])
        self.assertEqual(self.web.close_calls,1)

    def test_visible_captcha_stops_without_device_mutation_and_closes(self):
        self.web.login_error=service.CaptchaRequired('Fictional captcha required')
        self.assertTrue(self.client.logout()['ok'])
        self.client.run_authentication.assert_not_called()
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


class TecLogoutConfirmationTests(LogoutRecoveryFixture):
    def confirm(self):
        self.web.authenticated=True
        return self.client._confirm_tec_logout(WIFI,self.web,self.check_allowed)

    def test_absent_service_record_and_sustained_kernel_offline_are_both_required(self):
        self.web.devices=[]
        self.web.disconnected=True
        start=self.tick
        success,last=self.confirm()
        self.assertTrue(success)
        self.assertEqual(last['state'],'offline')
        self.assertGreaterEqual(self.tick-start,5.0)

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
        self.assertTrue(self.client.login(ACCOUNT,PASSWORD,'')['ok'])
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


if __name__=='__main__':
    unittest.main()
