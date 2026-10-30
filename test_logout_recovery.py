"""One precise self-service submission plus bounded, synthetic effect confirmation."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import socket
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch
import campus_app as app
import campus_core as core
import campus_selfservice as service
from campus_logging import RuntimeLog

WIFI=core.Wifi(core.TEC,'simple-actions-fixture',7,'10.61.55.9','00-11-22-33-44-55','10.61.55.1')
HOTSPOT=replace(WIFI,ssid='Fictional hotspot')
ACCOUNT='fictional-selected-account'
PASSWORD='fictional-selected-password'
def online():return {'state':'online','online_account':ACCOUNT,'binding':'mac_verified','matched_ip':True,
    'mac_conflict':False,'ip_conflict':False,'server_mac':'001122334455','server_ip':WIFI.ip,'detail':'server_confirmed'}
def offline():return {'state':'offline','online_account':'','binding':'source_ip_only','matched_ip':True,
    'mac_conflict':False,'ip_conflict':False,'server_mac':'','server_ip':'','detail':'server_confirmed'}

def unknown():return {'state':'unknown','online_account':'','binding':'unconfirmed','matched_ip':False,
    'mac_conflict':False,'ip_conflict':False,'detail':'short_check_timeout'}

def confirmation(state):
    report={'offline':offline,'online':online}.get(state,unknown)()
    return {'state':state,'outcome':{'offline':'confirmed_offline','online':'still_online'}.get(state,'unknown'),
        'status':report,'verification_performed':True,'device_presence':'absent' if state=='offline' else 'present' if state=='online' else 'unavailable',
        'samples':[{'state':state,'elapsed_ms':0},{'state':state,'elapsed_ms':700}],'elapsed_ms':700}

class FakeWebClient:
    def __init__(self):
        self.login_calls=[];self.submit_calls=0;self.close_calls=0
        self.reader=lambda:WIFI;self.login_error=None;self.submit_error=None;self.on_login=None;self.before_submit=None
        self.ack=True
        self.summary={'login_attempted':False,'login_confirmed':False,'disconnect_requests':0,
            'request_accepted':None,'session_removed':None,'current_device_offline':None,
            'web_logout_attempted':False,'web_logout_confirmed':False}
    def login(self,account,password):
        self.reader();self.login_calls.append((account,password));self.summary['login_attempted']=True
        if self.login_error:raise self.login_error
        self.summary['login_confirmed']=True
        if self.on_login:self.on_login()
    def submit_current(self,session_info=None,before_disconnect=None):
        self.submit_calls+=1
        if self.before_submit:self.before_submit()
        if before_disconnect:before_disconnect()
        self.reader()
        if self.submit_error:raise self.submit_error
        if self.summary['disconnect_requests']:raise AssertionError('Duplicate mutation')
        self.summary.update(disconnect_requests=1,request_accepted=self.ack)
        return self.safe_summary()
    def list_online_devices(self):raise AssertionError('App added an outer lookup or readback')
    def disconnect_current(self,*args,**kwargs):raise AssertionError('Product used developer verification wrapper')
    def safe_summary(self):return dict(self.summary)
    def close(self):
        self.close_calls+=1;self.summary.update(web_logout_attempted=True,web_logout_confirmed=True)
        return self.safe_summary()

class LogoutRecoveryFixture(unittest.TestCase):
    SSID=core.TEC
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.store=MagicMock();self.store.root=Path(tmp.name)
        self.store.load.return_value={'operator':'campus','quiet_hours':False,'stu_autostart':False,'trusted_hosts':[core.KNOWN_HOST],'portal_hint':''}
        self.profile={'id':'own-profile','account':ACCOUNT,'password':PASSWORD,'operator':'campus'}
        self.store.selected_profile.side_effect=lambda:deepcopy(self.profile)
        self.store.profiles.return_value={'selected':'own-profile','profiles':[deepcopy(self.profile)]}
        self.log=RuntimeLog(self.store.root,core.VERSION);self.addCleanup(self.log.close)
        with patch.object(core,'Store',return_value=self.store):self.client=app.App(runtime_log=self.log)
        self.wifi=replace(WIFI,ssid=self.SSID);self.current=self.wifi;self.client.wifi=self.wifi
        self.reader=self.enterContext(patch.object(core,'read_wifi',side_effect=lambda:self.current))
        self.enterContext(patch.object(socket.socket,'connect',side_effect=AssertionError('No real sockets')))
        self.enterContext(patch.object(app,'stable_autostart_configured',return_value=False))
        self.enterContext(patch.object(app,'stable_instance_running',return_value=False))
        self.status_query=self.enterContext(patch.object(app.protocol.Engine,'status',side_effect=AssertionError('Product queried status')))
        self.internet=self.enterContext(patch.object(core,'internet_check',side_effect=AssertionError('Product checked connectivity')))
        # Replace only App's clock, not the global time module used by transport
        # deadline tests. Synthetic status reports never sleep or open a socket.
        self._clock_now=time.monotonic()
        def advance(delay):self._clock_now+=delay
        self.app_clock=SimpleNamespace(monotonic=lambda:self._clock_now,
            perf_counter=lambda:self._clock_now,sleep=advance)
        self.enterContext(patch.object(app,'time',self.app_clock))
        self.probe_observation=online();self.logout_confirmation=confirmation('offline')
        def probe(wifi,reader,*args,**kwargs):
            self.assertEqual(wifi,self.wifi)
            try:reader()
            except RuntimeError:return dict(unknown(),detail='network_context_changed')
            return deepcopy(self.probe_observation)
        def confirm(wifi,reader,*args,**kwargs):
            self.assertEqual(wifi,self.wifi)
            try:reader()
            except RuntimeError:
                result=confirmation('unknown');result['status']['detail']='network_context_changed';return result
            self.assertTrue(callable(kwargs.get('list_devices')),'Confirmation lost the account-scoped read callback')
            self.assertGreater(kwargs['deadline'],self.app_clock.monotonic())
            self.assertLessEqual(kwargs['deadline']-self.app_clock.monotonic(),6.0)
            return deepcopy(self.logout_confirmation)
        self.bounded_probe=self.enterContext(patch.object(app.status_checks,'probe',side_effect=probe))
        self.bounded_confirm=self.enterContext(patch.object(app.status_checks,'confirm_logout',side_effect=confirm))

        self.client.save_profile=MagicMock(return_value={'ok':True})
        self.client.window=MagicMock();self.client.window.native=None
        self.native_result=True
        def authenticate(*args,**kwargs):
            self.client.auth_diagnostic={'operation':'login','backend':'fixture','authentication_requests':1,'result':self.native_result}
            return self.native_result
        self.client.run_authentication=MagicMock(side_effect=authenticate)
        self.web=FakeWebClient()
        def factory(wifi,*args,**kwargs):
            self.assertEqual(wifi,self.wifi);self.web.reader=kwargs['reader'];return self.web
        self.service_factory=self.enterContext(patch.object(service,'Client',side_effect=factory))
    def execute(self,trigger):
        with patch.object(app.threading,'Thread') as thread:
            result=trigger()
            if result['ok']:
                self.assertTrue(self.client.busy)
                self.assertEqual(thread.call_count,1,'An action spawned an additional background worker')
                thread.call_args.kwargs['target']()
            else:thread.assert_not_called()
        self.assertFalse(self.client.busy)
        return result
    def logout(self,account=ACCOUNT,password=PASSWORD):
        return self.execute(lambda:self.client.logout(account,password,'own-profile'))

class SelfServiceOnlyLogoutTests(LogoutRecoveryFixture):
    def test_one_service_submission_then_bounded_confirmation_without_legacy_queries(self):
        self.assertTrue(self.logout()['ok'])
        self.assertEqual(self.web.login_calls,[(ACCOUNT,PASSWORD)])
        self.assertEqual(self.web.submit_calls,1);self.assertEqual(self.web.close_calls,1)
        self.client.run_authentication.assert_not_called();self.status_query.assert_not_called();self.internet.assert_not_called()
        self.assertEqual(self.web.summary['request_accepted'],True)
        self.assertIsNone(self.web.summary['session_removed']);self.assertIsNone(self.web.summary['current_device_offline'])
        self.bounded_confirm.assert_called_once()
        self.assertTrue(self.client.logout_diagnostic['verification_performed'])
        self.assertEqual(self.client.logout_diagnostic['outcome'],'confirmed_offline')
        self.assertEqual(self.client.status,'注销成功')
    def test_typed_credentials_are_not_replaced_by_a_saved_profile(self):
        self.store.selected_profile.reset_mock();self.store.profiles.reset_mock()
        self.logout('fictional-typed-user','fictional-typed-password')
        self.assertEqual(self.web.login_calls,[('fictional-typed-user','fictional-typed-password')])
        self.store.selected_profile.assert_not_called();self.store.profiles.assert_not_called()
    def test_explicit_blank_fields_do_not_fall_back_to_saved_credentials(self):
        self.logout('','')
        self.service_factory.assert_not_called()
        self.assertNotIn('成功',self.client.status)
    def test_no_argument_compatibility_uses_one_selected_profile(self):
        self.execute(self.client.logout)
        self.assertEqual(self.web.login_calls,[(ACCOUNT,PASSWORD)])
        self.store.profiles.assert_not_called()
    def test_no_argument_without_selected_password_submits_nothing(self):
        self.profile['password']=''
        self.execute(self.client.logout);self.service_factory.assert_not_called()
    def test_rejected_ack_does_not_become_success_or_trigger_a_retry(self):
        self.web.ack=False;self.logout_confirmation=confirmation('online');self.logout()
        self.assertEqual(self.web.submit_calls,1);self.assertEqual(self.web.close_calls,1)
        self.assertNotIn('注销成功',self.client.status)
        self.assertIn('未成功',self.client.status)
        self.assertIs(self.client.auth_diagnostic['request_accepted'],False)
        self.assertEqual(self.client.logout_diagnostic['outcome'],'still_online')
    def test_unknown_ack_stays_unknown_and_is_not_retried(self):
        self.web.ack=None;self.logout_confirmation=confirmation('unknown');self.logout()
        self.assertEqual(self.web.submit_calls,1);self.assertEqual(self.web.close_calls,1)
        self.assertIn('无法确认',self.client.status)
        self.assertIsNone(self.client.auth_diagnostic['request_accepted'])
        self.assertNotIn('注销成功',self.client.status)
    def test_no_matching_device_does_not_start_another_strategy(self):
        self.web.submit_error=service.NoMatchingDevice('Fictional no current device')
        self.web.summary['device_queries']=1;self.probe_observation=offline();self.logout()
        self.assertEqual(self.web.submit_calls,1);self.assertEqual(self.web.close_calls,1)
        self.client.run_authentication.assert_not_called()
        self.assertNotIn('注销成功',self.client.status)
    def test_captcha_stops_without_a_pod_and_closes_management_session(self):
        self.web.login_error=service.CaptchaRequired('Fictional captcha');self.logout()
        self.assertEqual(self.web.submit_calls,0);self.assertEqual(self.web.close_calls,1)
    def test_network_change_after_management_login_stops_before_mutation(self):
        self.web.on_login=lambda:setattr(self,'current',replace(self.wifi,ip='10.61.55.10'))
        self.logout();self.assertEqual(self.web.summary['disconnect_requests'],0);self.assertEqual(self.web.close_calls,1)
    def test_internal_shutdown_guard_stops_an_unsent_request(self):
        self.web.on_login=self.client.closed.set
        self.logout();self.assertEqual(self.web.summary['disconnect_requests'],0);self.assertEqual(self.web.close_calls,1)
    def test_a_cached_offline_result_does_not_disable_a_new_explicit_logout(self):
        self.client.session_state='offline';self.client.logged_in=False
        self.logout();self.assertEqual(self.web.submit_calls,1)
    def test_hotspot_never_gets_credentials_or_a_pod(self):
        self.current=HOTSPOT;self.logout();self.service_factory.assert_not_called()
    def test_state_polling_has_no_network_side_effects(self):
        for _ in range(10):self.client.get_state()
        self.reader.assert_not_called();self.status_query.assert_not_called();self.internet.assert_not_called();self.service_factory.assert_not_called()
        self.bounded_probe.assert_not_called();self.bounded_confirm.assert_not_called()
    def test_only_user_requested_action_is_exposed_on_the_bridge(self):
        bridge=app.Bridge(self.client)
        self.assertTrue(callable(bridge.refresh_status))
        for name in ('cancel_operation','network_check'):
            self.assertFalse(hasattr(bridge,name),name)
    def test_wifi_monitor_does_not_schedule_a_status_or_result_check(self):
        self.client.poll_wifi=MagicMock(side_effect=self.client.closed.set)
        self.client.poll_show_event=MagicMock()
        self.client.refresh_status=MagicMock(side_effect=AssertionError('Unexpected status job'))
        self.client.monitor()
        self.client.refresh_status.assert_not_called();self.status_query.assert_not_called();self.internet.assert_not_called()

class StudentSelfServiceOnlyLogoutTests(SelfServiceOnlyLogoutTests):SSID=core.STU

if __name__=='__main__':unittest.main()
