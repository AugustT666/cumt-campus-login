"""Login credentials remain bound to the current physical network context.

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


class LoginRouteContextTests(unittest.TestCase):
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

    def run_auth(self,wifi=None,operation='login'):
        wifi=wifi or self.current
        tec=wifi.ssid.casefold()==core.TEC.casefold()
        return self.client.run_authentication(wifi,'fictional-user' if operation=='login' else '',
            'fictional-password' if operation=='login' else '','',operation,tec,
            lambda:self.client.checked_wifi(wifi,tec))

    def prime_verified_route(self):
        self.run_auth(operation='login')
        self.sent.clear()
        self.discover.reset_mock()

    def test_login_discovers_current_route_before_submission(self):
        self.run_auth()
        self.discover.assert_called_once()
        self.assertEqual(self.sent[0]['operation'],'login')
        self.assertEqual(self.sent[0]['ac_name'],'fictional-tec-ac')
    def test_product_entry_rejects_the_retired_ordinary_logout(self):
        with self.assertRaises((ValueError,RuntimeError)):self.run_auth(operation='logout')
        self.assertEqual(self.sent,[]);self.discover.assert_not_called()
    def test_network_changes_during_prepare_stop_before_credentials(self):
        for field,value in (('ip','10.61.23.9'),('mac','00-11-22-33-44-66'),('gateway','10.61.23.2')):
            with self.subTest(field=field):
                self.current=TEC;self.sent.clear()
                self.on_prepare=lambda engine:setattr(self,'current',replace(TEC,**{field:value}))
                try:
                    with self.assertRaises(RuntimeError):self.run_auth()
                    self.assertEqual(self.sent,[])
                finally:self.on_prepare=None
    def test_unavailable_native_reader_stops_before_submission(self):
        with patch.object(core,'read_wifi',side_effect=RuntimeError('Fictional unavailable WLAN')):
            with self.assertRaises(RuntimeError):self.run_auth()
        self.assertEqual(self.sent,[])
    def test_new_ssid_cannot_reuse_previous_teacher_context(self):
        self.prime_verified_route();self.current=replace(TEC,ssid=core.STU,ip='10.52.23.8')
        self.run_auth(self.current)
        self.assertEqual(self.sent[-1]['wifi'],self.current)
        self.assertEqual(self.sent[-1]['ac_name'],'fictional-stu-ac')
    def test_same_legacy_key_with_new_mac_gets_fresh_discovery(self):
        self.prime_verified_route();self.current=replace(TEC,mac='00-11-22-33-44-66')
        self.assertEqual(self.current.key,TEC.key)
        self.run_auth(self.current);self.discover.assert_called_once()
        self.assertEqual(self.sent[-1]['wifi'],self.current)

if __name__=='__main__':unittest.main()
