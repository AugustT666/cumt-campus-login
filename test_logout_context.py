"""A logout must not silently replace a verified AC route with a bare page.

All addresses, interface data and accounts are fictional. Discovery and native
authentication are in-memory doubles; no real Store, registry or network is used.
"""
from dataclasses import replace
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlencode, urlsplit

import campus_app as app
import campus_core as core
from campus_logging import RuntimeLog


TEC=core.Wifi(core.TEC,'logout-route-fixture',7,'10.61.23.8',
              '00-11-22-33-44-55','10.61.23.1')
ORIGIN='http://10.2.5.251'


def rich_portal(wifi):
    suffix='tec' if wifi.ssid.casefold()==core.TEC.casefold() else 'stu'
    return ORIGIN+'/a79.htm?'+urlencode({'wlanuserip':wifi.ip,'mac':wifi.mac,
        'wlanacname':'fictional-'+suffix+'-ac','vlan':'1'})


class LogoutRouteContextTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        store=MagicMock()
        store.root=Path(temporary.name)
        store.load.return_value={'operator':'','stu_autostart':False,'quiet_hours':False,
            'trusted_hosts':[core.KNOWN_HOST],'portal_hint':''}
        store.profiles.return_value={'selected':'','profiles':[]}
        self.log=RuntimeLog(store.root,core.VERSION)
        self.addCleanup(self.log.close)
        with patch.object(core,'Store',return_value=store):
            self.client=app.App(runtime_log=self.log)
        self.client.wifi=TEC
        self.client.window=MagicMock()
        self.current=TEC
        self.sent=[]
        self.engines=[]
        self.on_prepare=None
        self.enterContext(patch.object(core,'read_wifi',side_effect=lambda:self.current))
        self.enterContext(patch.object(socket.socket,'connect',
            side_effect=AssertionError('No real network in logout context tests')))
        self.discover=self.enterContext(patch.object(core,'discover',
            side_effect=lambda wifi,*args,**kwargs:(rich_portal(wifi),'<fixture>')))
        self.client.authenticate=MagicMock(side_effect=AssertionError('No browser submission'))
        fixture=self
        class Engine:
            def __init__(self,wifi,portal,reader=None,allow_tec=False,**kwargs):
                self.wifi=wifi;self.portal=core.fresh_url(portal,wifi)
                self.origin=ORIGIN;self.reader=reader;self.allow_tec=allow_tec
                self._plan=None
                fixture.engines.append(self)
            def prepare(self):
                query=parse_qs(urlsplit(self.portal).query,keep_blank_values=True)
                self._plan={'page_index':3 if self.wifi.ssid==core.TEC else 2,
                    'login_method':'1','endpoint':ORIGIN+':801/eportal/',
                    'operators':{},'has_operator_select':False,'ac_logout':'0',
                    'ac_ip':query.get('wlanacip',[''])[0],
                    'ac_name':query.get('wlanacname',[''])[0],
                    'vlan':'1','ipv6':'','js_version':'fictional-version',
                    'plan_key':self.wifi.key}
                if fixture.on_prepare:fixture.on_prepare(self)
                return dict(self._plan)
            def authenticate(self,account,password,operator,operation,before_submit=None):
                if before_submit:before_submit()
                plan=self.prepare()
                fixture.sent.append({'operation':operation,'wifi':self.wifi,
                    'ac_name':plan['ac_name'],'ac_ip':plan['ac_ip'],'ac_logout':plan['ac_logout']})
                return True,{'operation':operation,'phase':'response_received',
                    'authentication_requests':1,'result':True}
        self.enterContext(patch.object(app.protocol,'Engine',Engine))

    def run_auth(self,wifi=None,operation='logout'):
        wifi=wifi or self.current
        tec=wifi.ssid.casefold()==core.TEC.casefold()
        return self.client.run_authentication(wifi,'fictional-user' if operation=='login' else '',
            'fictional-password' if operation=='login' else '','',operation,tec,
            lambda:self.client.checked_wifi(wifi,tec))

    def prime_verified_route(self):
        self.run_auth(operation='login')
        self.sent.clear()
        self.discover.reset_mock()

    def test_logout_without_prior_discovery_acquires_rich_route_before_native_send(self):
        self.run_auth()
        self.discover.assert_called_once()
        self.assertEqual(self.sent[-1]['ac_name'],'fictional-tec-ac')

    def test_bare_status_engine_is_upgraded_before_logout(self):
        self.client.session_engine(TEC,True)
        self.run_auth()
        self.discover.assert_called_once()
        self.assertEqual(self.sent[-1]['ac_name'],'fictional-tec-ac')

    def test_current_verified_route_is_reused_without_public_probes(self):
        self.prime_verified_route()
        self.run_auth()
        self.discover.assert_not_called()
        self.assertEqual(len(self.sent),1)
        self.assertEqual(self.sent[0]['ac_name'],'fictional-tec-ac')
        self.assertEqual(self.sent[0]['ac_logout'],'0')

    def test_readonly_status_does_not_erase_verified_route(self):
        self.prime_verified_route()
        self.client.session_engine(TEC,True)
        self.run_auth()
        self.assertEqual(self.sent[-1]['ac_name'],'fictional-tec-ac')

    def test_discovery_without_any_ac_route_sends_no_native_or_browser_logout(self):
        self.discover.side_effect=lambda wifi,*args,**kwargs:(ORIGIN+'/a79.htm','<fixture>')
        try:self.run_auth()
        except RuntimeError:pass
        self.discover.assert_called_once()
        self.assertEqual(self.sent,[])
        self.client.authenticate.assert_not_called()

    def assert_context_change_reacquires(self,changed):
        self.prime_verified_route()
        self.current=changed
        self.run_auth(changed)
        self.discover.assert_called_once()
        self.assertEqual(self.sent[-1]['wifi'],changed)

    def test_ip_change_does_not_reuse_previous_route(self):
        self.assert_context_change_reacquires(replace(TEC,ip='10.61.23.9'))

    def test_mac_change_with_same_legacy_key_does_not_reuse_previous_route(self):
        changed=replace(TEC,mac='00-11-22-33-44-66')
        self.assertEqual(changed.key,TEC.key)
        self.assert_context_change_reacquires(changed)

    def test_gateway_change_with_same_legacy_key_does_not_reuse_previous_route(self):
        changed=replace(TEC,gateway='10.61.23.2')
        self.assertEqual(changed.key,TEC.key)
        self.assert_context_change_reacquires(changed)

    def test_ssid_change_does_not_reuse_teacher_route(self):
        self.prime_verified_route()
        self.current=replace(TEC,ssid=core.STU,ip='10.52.23.8')
        self.run_auth(self.current)
        self.assertEqual(self.sent[-1]['wifi'],self.current)
        self.assertNotEqual(self.sent[-1]['ac_name'],'fictional-tec-ac')

    def test_same_address_wlan_reconnect_requires_new_route(self):
        self.prime_verified_route()
        self.client.notifications=MagicMock()
        notices=[[(21,TEC.guid),(10,TEC.guid)]]
        self.client.notifications.drain.side_effect=lambda:notices.pop(0) if notices else []
        self.client.consume_notifications()
        self.run_auth()
        self.discover.assert_called_once()
        self.assertEqual(self.sent[-1]['ac_name'],'fictional-tec-ac')

    def test_expired_verified_route_is_not_silently_reused(self):
        tick=[100.0]
        with patch.object(app.time,'monotonic',side_effect=lambda:tick[0]):
            self.prime_verified_route()
            tick[0]+=86400
            self.run_auth()
        self.discover.assert_called_once()

    def test_observed_disconnect_invalidates_route_even_after_same_address_returns(self):
        self.prime_verified_route()
        self.current=core.Wifi()
        with self.assertRaises(RuntimeError):self.client.checked_wifi(TEC,True)
        self.current=TEC
        self.run_auth()
        self.discover.assert_called_once()

    def test_unreadable_network_invalidates_cached_route(self):
        self.prime_verified_route()
        with patch.object(core,'read_wifi',side_effect=RuntimeError('fictional unavailable reader')):
            with self.assertRaises(RuntimeError):self.client.checked_wifi(TEC,True)
        self.run_auth()
        self.discover.assert_called_once()

    def test_mac_changes_during_prepare_stop_before_submission(self):
        self.prime_verified_route()
        self.on_prepare=lambda engine:setattr(self,'current',replace(TEC,mac='00-11-22-33-44-66'))
        with self.assertRaises(RuntimeError):self.run_auth()
        self.assertEqual(self.sent,[])

    def test_gateway_changes_during_prepare_stop_before_submission(self):
        self.prime_verified_route()
        self.on_prepare=lambda engine:setattr(self,'current',replace(TEC,gateway='10.61.23.2'))
        with self.assertRaises(RuntimeError):self.run_auth()
        self.assertEqual(self.sent,[])

    def test_changed_manual_hint_reacquires_and_does_not_replay_its_ac_fields(self):
        self.prime_verified_route()
        self.client.settings['portal_hint']=ORIGIN+'/a79.htm?wlanacname=obsolete-fixture-ac&vlan=7'
        self.run_auth()
        self.discover.assert_called_once()
        hint=self.discover.call_args.args[1]
        self.assertNotIn('wlanacname',parse_qs(urlsplit(hint).query))
        self.assertNotIn('vlan',parse_qs(urlsplit(hint).query))


if __name__=='__main__':
    unittest.main()
