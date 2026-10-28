"""Offline tests only: no campus requests, no WiFi switching, no startup changes."""
import datetime as dt
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from urllib.parse import urlsplit, parse_qs
import campus_core as c
import campus_app as a

WIFI = c.Wifi('CUMT_Stu','guid-a',11,'10.52.160.42','0C-DD-24-8A-06-33','10.52.160.1')
TEC = c.Wifi('CUMT_Tec','guid-a',11,'10.52.160.42','0C-DD-24-8A-06-33')
HOTSPOT = c.Wifi('Xiaomi 13 Ultra','guid-a',11,'10.221.208.208','0C-DD-24-8A-06-33')
HTML = '''<!doctype html><meta charset="utf-8"><form>
<input name="DDDDD"><input name="upass" type="password">
<select name="operator"><option value="campus">校园网</option><option value="@telecom">中国电信</option><option value="@unicom">中国联通</option><option value="@cmcc">中国移动</option></select>
<button type="button" onclick="window.clicked=(window.clicked||0)+1">登录</button></form>'''

class SafetyTests(unittest.TestCase):
    def test_hotspot_rejected_even_tec_flag(self):
        for allow in (False, True):
            with self.assertRaises(RuntimeError): c.guard(HOTSPOT,HOTSPOT,allow)
    def test_student_exact_name_casefold(self):
        self.assertEqual(c.STU,'CUMT_Stu')
        self.assertTrue(c.Wifi('CUMT_Stu').student)
        self.assertTrue(c.Wifi('cumt_stu').student)
        for name in ('CUMT_Stu-malicious','CUMT_Stu ','CUMT_Student','Xiaomi 13 Ultra'):
            with self.subTest(name=name):
                self.assertFalse(c.Wifi(name).student)
    def test_incorrect_legacy_hyphen_names_rejected(self):
        for name in ('cumt-STU','cumt-tec'):
            wifi=c.Wifi(name,'g',11,'10.52.160.42')
            self.assertFalse(wifi.campus)
            with self.assertRaises(RuntimeError): c.guard(wifi,wifi,True)
    def test_real_teacher_ssid_is_campus_not_student(self):
        self.assertEqual(c.TEC,'CUMT_Tec')
        for name in ('CUMT_Tec','cumt_tec'):
            wifi=c.Wifi(name,'g',11,'10.52.160.42')
            self.assertTrue(wifi.campus)
            self.assertTrue(wifi.ready)
            self.assertFalse(wifi.student)
            with self.assertRaises(RuntimeError): c.guard(wifi,wifi)
            c.guard(wifi,wifi,True)
    def test_teacher_manual_only(self):
        with self.assertRaises(RuntimeError): c.guard(TEC,TEC)
        c.guard(TEC,TEC,True)
    def test_ip_change_abort(self):
        changed=c.Wifi('CUMT_Stu','guid-a',11,'10.52.160.43',WIFI.mac)
        with self.assertRaises(RuntimeError): c.guard(WIFI,changed)
    def test_ssid_change_abort(self):
        with self.assertRaises(RuntimeError): c.guard(WIFI,HOTSPOT,True)
    def test_linklocal_rejected(self):
        self.assertFalse(c.Wifi('CUMT_Stu','g',11,'169.254.1.2').ready)
    def test_old_url_dynamic_fields_and_special_encoding(self):
        old='http://10.2.5.251/a79.htm?wlanuserip=10.52.152.23&wlanacname=BRAS&url=http://1.1.1.1/&mac=00-00-00-00-00-00'
        p=parse_qs(urlsplit(c.fresh_url(old,WIFI)).query)
        self.assertEqual(p['wlanuserip'],[WIFI.ip]);self.assertEqual(p['mac'],[WIFI.mac])
        self.assertEqual(p['wlanacname'],['BRAS']);self.assertEqual(p['url'],['http://1.1.1.1/'])
    def test_secret_removed_from_hint(self):
        p=c.fresh_url('http://10.2.5.251/a79.htm?user_account=abc&upass=xyz',WIFI)
        self.assertNotIn('abc',p);self.assertNotIn('xyz',p)
    def test_public_host_credentials_and_port_rejected(self):
        for url in ('http://evil.example/a79.htm','http://10.2.5.251.evil.example/','http://a:b@10.2.5.251/','file:///x','http://127.0.0.1/','http://10.2.5.251:9000/'):
            with self.subTest(url=url):
                with self.assertRaises(ValueError): c.portal_origin(url)
    def test_summary_has_no_query(self):
        self.assertEqual(c.safe_summary('http://10.2.5.251/a79.htm?upass=secret'),'http://10.2.5.251/a79.htm')
    def test_quiet_weeknight(self):
        self.assertTrue(c.quiet_hours(dt.datetime(2026,10,22,23,42)))
        self.assertFalse(c.quiet_hours(dt.datetime(2026,10,23,23,42)))
        self.assertTrue(c.quiet_hours(dt.datetime(2026,10,23,6,59)))
        self.assertFalse(c.quiet_hours(dt.datetime(2026,10,23,7,0)))
        self.assertFalse(c.quiet_hours(dt.datetime(2026,10,24,6,59)))
        self.assertTrue(c.quiet_hours(dt.datetime(2026,10,26,6,59)))
    def test_hotspot_discovery_never_sends_requests(self):
        getter=MagicMock()
        with self.assertRaises(RuntimeError): c.discover(HOTSPOT,reader=lambda:HOTSPOT,getter=getter)
        getter.assert_not_called()
    def test_new_dorm_redirect_wins_over_old_server(self):
        requested=[]
        def getter(url,wifi,**kw):
            requested.append(url)
            if url=='http://9.9.9.9/': return (302,'http://10.2.7.251/a79.htm?wlanuserip=10.1.1.1&wlanacname=NEW-DORM', '')
            return (200,'',HTML+'eportal')
        portal,_=c.discover(WIFI,reader=lambda:WIFI,getter=getter)
        self.assertEqual(urlsplit(portal).hostname,'10.2.7.251')
        self.assertEqual(parse_qs(urlsplit(portal).query)['wlanuserip'],[WIFI.ip])
        self.assertEqual(parse_qs(urlsplit(portal).query)['wlanacname'],['NEW-DORM'])
        self.assertEqual(len(requested),2)
    def test_js_redirect_discovered(self):
        self.assertEqual(c.redirected_url('http://9.9.9.9/','',"location.href='http://10.2.8.251/a79.htm'"),'http://10.2.8.251/a79.htm')
    def test_external_redirect_not_followed(self):
        requested=[]
        def getter(url,wifi,**kw):
            requested.append(url)
            return (302,'http://evil.example/a79.htm','')
        with self.assertRaises(RuntimeError): c.discover(WIFI,reader=lambda:WIFI,getter=getter)
        self.assertFalse(any('evil' in url for url in requested))
    def test_redirect_cycle_bounded(self):
        calls=[]
        def getter(url,wifi,**kw):
            calls.append(url)
            return 302,'http://10.2.5.251/a79.htm',''
        with self.assertRaises(RuntimeError): c.discover(WIFI,reader=lambda:WIFI,getter=getter)
        self.assertLessEqual(len(calls),15)
    def test_false_success_not_internet(self):
        result=c.internet_check(WIFI,reader=lambda:WIFI,getter=lambda *a,**k:(200,'',HTML+'认证成功'))
        self.assertFalse(result['online'])
    def test_strict_public_response(self):
        result=c.internet_check(WIFI,reader=lambda:WIFI,getter=lambda *a,**k:(200,'','Microsoft Connect Test'))
        self.assertTrue(result['online'])
    def test_captive_redirect_not_internet(self):
        result=c.internet_check(WIFI,reader=lambda:WIFI,getter=lambda *a,**k:(302,'http://10.2.5.251/',''))
        self.assertFalse(result['online'])
    def test_bound_socket_no_proxy_and_interface(self):
        sock=MagicMock()
        with patch('socket.getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('10.2.5.251',80))]),patch('socket.socket',return_value=sock):
            conn=c.BoundHTTP('10.2.5.251',80,WIFI)
            conn.connect()
            sock.bind.assert_called_once_with((WIFI.ip,0))
            if os.name=='nt': sock.setsockopt.assert_called_once_with(socket.IPPROTO_IP,31,socket.htonl(WIFI.index))
            sock.connect.assert_called_once_with(('10.2.5.251',80))
    @unittest.skipUnless(os.name=='nt','Windows only')
    def test_dpapi_round_trip(self):
        plaintext='{"account":"offline-test","password":"fake-not-a-real-password"}'.encode()
        cipher=c.protect(plaintext)
        self.assertNotIn(b'fake-not-a-real-password',cipher)
        self.assertEqual(c.protect(cipher,True),plaintext)
    @unittest.skipUnless(os.name=='nt','Windows only')
    def test_credentials_never_in_settings(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            store=c.Store(Path(folder))
            store.save(store.load(),'fake-account','fake-password',True)
            self.assertNotIn('fake-account',store.path.read_text('utf-8'))
            self.assertNotIn(b'fake-password',store.credentials.read_bytes())
            self.assertEqual(store.secret()['account'],'fake-account')

@unittest.skipUnless(os.name=='nt','Windows DPAPI')
class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.store=c.Store(Path(self.temp.name))
    def tearDown(self): self.temp.cleanup()
    def test_multiple_profiles_preserve_others(self):
        first=self.store.save_profile('','fake-first','fake-password-one','telecom')
        second=self.store.save_profile('','fake-second','fake-password-two','unicom')
        self.assertEqual(len(self.store.profiles()['profiles']),2)
        self.assertEqual(self.store.selected_profile()['id'],second)
        self.store.select_profile(first)
        self.assertEqual(self.store.secret()['password'],'fake-password-one')
        self.assertNotIn(b'fake-password',self.store.credentials.read_bytes())
        self.assertNotIn(b'fake-first',self.store.credentials.read_bytes())
    def test_modify_only_selected_profile(self):
        first=self.store.save_profile('','fake-first','old','telecom')
        second=self.store.save_profile('','fake-second','keep','unicom')
        self.store.save_profile(first,'fake-first','new','cmcc')
        data=self.store.profiles()['profiles']
        self.assertEqual(len(data),2)
        self.assertEqual(next(p for p in data if p['id']==second)['password'],'keep')
    def test_v12_migration_is_read_only_then_preserved(self):
        raw=c.protect(json.dumps({'account':'legacy-account','password':'legacy-password'}).encode())
        self.store.credentials.write_bytes(raw)
        self.store.write_settings(dict(self.store.load(),operator='telecom'))
        self.assertEqual(self.store.secret()['account'],'legacy-account')
        self.assertEqual(self.store.credentials.read_bytes(),raw)
        self.store.save_profile('','new-fake','new-fake-password','')
        self.assertEqual(len(self.store.profiles()['profiles']),2)
        self.store.select_profile('legacy')
        self.assertEqual(self.store.secret()['password'],'legacy-password')
        self.assertEqual(self.store.secret()['operator'],'telecom')
    def test_delete_selected_does_not_select_another(self):
        first=self.store.save_profile('','fake-first','fake-one','telecom')
        second=self.store.save_profile('','fake-second','fake-two','')
        self.store.delete_profile(second)
        self.assertEqual(self.store.profiles()['selected'],'')
        self.assertEqual(len(self.store.profiles()['profiles']),1)
        self.assertEqual(self.store.profiles()['profiles'][0]['id'],first)
    def test_new_draft_clears_auto_selection_not_saved_accounts(self):
        self.store.save_profile('','fake-first','fake-one','telecom')
        self.store.select_profile('')
        self.assertEqual(self.store.selected_profile(),{})
        self.assertEqual(len(self.store.profiles()['profiles']),1)
    def test_corrupt_credentials_not_overwritten(self):
        raw=b'not-a-dpapi-file';self.store.credentials.write_bytes(raw)
        with self.assertRaises(RuntimeError): self.store.save_profile('','fake','fake','')
        self.assertEqual(self.store.credentials.read_bytes(),raw)
    def test_unknown_candidate_rejected(self):
        self.store.save_profile('','fake-first','fake-one','telecom')
        with self.assertRaises(RuntimeError): self.store.select_profile('unknown')
        with self.assertRaises(RuntimeError): self.store.delete_profile('unknown')
    def test_all_credential_query_keys_redacted(self):
        url=c.fresh_url('http://10.2.5.251/a79.htm?DDDDD=private-account&upass=private-password',WIFI)
        self.assertNotIn('private-account',url);self.assertNotIn('private-password',url)

class ClientTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(a,'stable_autostart_configured',return_value=False))
        self.enterContext(patch.object(a,'stable_instance_running',return_value=False))
        self.helper=a.App.__new__(a.App)
        self.helper.wifi=HOTSPOT
        self.helper.lock=__import__('threading').RLock()
        self.helper.cancel=__import__('threading').Event()
        self.helper.closed=__import__('threading').Event()
        self.helper.busy=False
        self.helper.logged_in=False
        self.helper.auth_key=None
        self.helper.portal_key=HOTSPOT.key
        self.helper.session_cookies=[]
        self.helper.settings={'quiet_hours':True,'auto_enabled':True,'auto_submit':True,'stu_autostart':False,'trusted_hosts':[c.KNOWN_HOST]}
        self.helper.auto_attempted=False
        self.helper.auto_job=False
        self.helper.notifications=None
        self.helper.reconnecting=set()
        self.helper.operation=''
        self.helper.status=''
        self.helper.messages=[]
        self.helper.pending_host=''
        self.helper.store=MagicMock()
        self.helper.store.selected_profile.return_value={'id':'chosen','account':'fake-user','password':'fake-password','operator':'telecom'}
        self.helper.window=MagicMock()
        self.helper.login=MagicMock(return_value={'ok':True})
    def test_student_wifi_change_does_not_popup_or_login(self):
        with patch.object(c,'read_wifi',return_value=WIFI): self.helper.poll_wifi()
        self.assertTrue(self.helper.wifi.student)
        self.helper.window.show.assert_not_called()
        self.helper.window.restore.assert_not_called()
        self.helper.login.assert_not_called()
    def test_teacher_wifi_change_does_not_popup_or_login(self):
        with patch.object(c,'read_wifi',return_value=TEC): self.helper.poll_wifi()
        self.helper.window.show.assert_not_called()
        self.helper.login.assert_not_called()
    def test_network_change_cancels_pending_job(self):
        self.helper.busy=True
        with patch.object(c,'read_wifi',return_value=WIFI): self.helper.poll_wifi()
        self.assertTrue(self.helper.cancel.is_set())
    def test_network_change_clears_previous_login(self):
        self.helper.wifi=WIFI;self.helper.logged_in=True;self.helper.auth_key=WIFI.key
        with patch.object(c,'read_wifi',return_value=HOTSPOT): self.helper.poll_wifi()
        self.assertFalse(self.helper.logged_in);self.assertIsNone(self.helper.auth_key)
    def test_login_result_uses_correct_action(self):
        response='dr1002({"result":"1","msg":"认证成功"})'
        self.assertTrue(a.authentication_result(response,'http://10.2.5.251:801/eportal/?a=login','login'))
        self.assertIsNone(a.authentication_result(response,'http://10.2.5.251:801/eportal/?a=logout','login'))
    def test_logout_result(self):
        self.assertTrue(a.authentication_result('{"result":1}','http://10.2.5.251:801/eportal/?a=logout','logout'))
        self.assertFalse(a.authentication_result('{"result":0}','http://10.2.5.251:801/eportal/?a=logout','logout'))
    def test_http200_not_authentication_success(self):
        self.assertIsNone(a.authentication_result('ordinary page','http://10.2.5.251/a79.htm','login'))
    def test_close_really_exits(self):
        self.assertTrue(self.helper.on_closing())
        self.assertTrue(self.helper.closed.is_set())
    def test_stu_popup_startup_can_be_enabled_without_credentials(self):
        self.helper.store.selected_profile.return_value={}
        key=MagicMock();key.__enter__.return_value=key
        with patch.object(c,'read_wifi',return_value=HOTSPOT),patch.object(a.winreg,'CreateKey',return_value=key),patch.object(a.winreg,'SetValueEx') as write:
            self.assertTrue(self.helper.set_startup(True)['ok'])
            self.assertIn('--startup',write.call_args.args[-1])
        self.helper.login.assert_not_called()
        self.helper.store.selected_profile.assert_not_called()
    def test_stu_startup_registers_background_listener(self):
        key=MagicMock();key.__enter__.return_value=key
        with patch.object(c,'read_wifi',return_value=HOTSPOT),patch.object(a.winreg,'CreateKey',return_value=key),patch.object(a.winreg,'SetValueEx') as write:
            result=self.helper.set_startup(True)
            self.assertTrue(result['ok'])
            self.assertIn('--startup',write.call_args.args[-1])
            self.assertTrue(self.helper.settings['stu_autostart'])
            self.helper.store.save.assert_not_called()
    def test_enabling_on_connected_stu_does_not_submit(self):
        key=MagicMock();key.__enter__.return_value=key
        with patch.object(c,'read_wifi',return_value=WIFI),patch.object(a.winreg,'CreateKey',return_value=key),patch.object(a.winreg,'SetValueEx'):
            self.assertTrue(self.helper.set_startup(True)['ok'])
            self.helper.poll_wifi()
        self.helper.login.assert_not_called()
    def test_enabling_stu_with_uninitialized_wifi_snapshot(self):
        self.helper.wifi=c.Wifi()
        key=MagicMock();key.__enter__.return_value=key
        with patch.object(c,'read_wifi',return_value=WIFI),patch.object(a.winreg,'CreateKey',return_value=key),patch.object(a.winreg,'SetValueEx'):
            self.assertTrue(self.helper.set_startup(True)['ok'])
            self.helper.poll_wifi()
        self.helper.login.assert_not_called()
    def test_disabling_cancels_automatic_job(self):
        self.helper.busy=True;self.helper.auto_job=True
        key=MagicMock();key.__enter__.return_value=key
        with patch.object(a.winreg,'CreateKey',return_value=key),patch.object(a.winreg,'DeleteValue'):
            self.assertTrue(self.helper.set_startup(False)['ok'])
        self.assertTrue(self.helper.cancel.is_set())
    def test_stu_connect_attempts_selected_only_once(self):
        self.helper.settings['stu_autostart']=True
        with patch.object(c,'read_wifi',return_value=WIFI):
            for _ in range(5): self.helper.poll_wifi()
        self.helper.login.assert_called_once_with('fake-user','fake-password','telecom','chosen',automatic=True,expected=WIFI)
        self.helper.window.show.assert_called_once()
    def test_failure_does_not_try_other_profiles(self):
        self.helper.settings['stu_autostart']=True
        self.helper.login.return_value={'ok':False,'message':'fake failure'}
        with patch.object(c,'read_wifi',return_value=WIFI):
            for _ in range(5): self.helper.poll_wifi()
        self.helper.login.assert_called_once()
        self.helper.store.selected_profile.assert_called_once()
    def test_dhcp_change_is_not_retry_permission(self):
        self.helper.settings['stu_autostart']=True
        changed=c.Wifi(c.STU,WIFI.guid,WIFI.index,'10.52.160.43',WIFI.mac)
        with patch.object(c,'read_wifi',side_effect=[WIFI,changed,changed]):
            for _ in range(3): self.helper.poll_wifi()
        self.helper.login.assert_called_once()
    def test_reconnect_allows_one_new_attempt(self):
        self.helper.settings['stu_autostart']=True
        with patch.object(c,'read_wifi',side_effect=[WIFI,HOTSPOT,WIFI,WIFI]):
            for _ in range(4): self.helper.poll_wifi()
        self.assertEqual(self.helper.login.call_count,2)
    def test_teacher_connect_attempts_once_when_enabled(self):
        self.helper.settings['stu_autostart']=True
        with patch.object(c,'read_wifi',return_value=TEC):
            for _ in range(3): self.helper.poll_wifi()
        self.helper.login.assert_called_once_with('fake-user','fake-password','telecom','chosen',automatic=True,expected=TEC)
        self.helper.window.show.assert_called_once()
    def test_passive_wlan_notifications_register_and_close(self):
        listener=c.WifiNotifications()
        try: self.assertEqual(listener.drain(),[])
        finally: listener.close()
    def test_fast_same_ip_reconnect_event_allows_once(self):
        self.helper.settings['stu_autostart']=True
        self.helper.wifi=WIFI;self.helper.auto_attempted=True
        self.helper.notifications=MagicMock()
        self.helper.notifications.drain.return_value=[(20,WIFI.guid),(21,WIFI.guid),(10,WIFI.guid)]
        with patch.object(c,'read_wifi',return_value=WIFI): self.helper.poll_wifi()
        self.helper.login.assert_not_called()
        self.helper.notifications.drain.return_value=[]
        with patch.object(c,'read_wifi',return_value=WIFI): self.helper.poll_wifi()
        self.helper.login.assert_called_once()
    def test_disconnect_event_waits_for_completion(self):
        self.helper.settings['stu_autostart']=True
        self.helper.wifi=WIFI;self.helper.auto_attempted=True
        self.helper.notifications=MagicMock();self.helper.notifications.drain.return_value=[(21,WIFI.guid)]
        with patch.object(c,'read_wifi',return_value=WIFI): self.helper.poll_wifi()
        self.helper.login.assert_not_called()
    def test_read_error_does_not_reset_attempt(self):
        self.helper.auto_attempted=True;self.helper.wifi=WIFI
        with patch.object(c,'read_wifi',side_effect=RuntimeError('temporary')):
            with self.assertRaises(RuntimeError): self.helper.poll_wifi()
        self.assertTrue(self.helper.auto_attempted)
    def test_close_keeps_listener_when_enabled(self):
        self.helper.settings['stu_autostart']=True
        self.assertFalse(self.helper.on_closing())
        self.helper.window.hide.assert_called_once()
        self.assertFalse(self.helper.closed.is_set())
    def test_quit_exits_even_with_listener_enabled(self):
        self.helper.settings['stu_autostart']=True
        self.helper.quit()
        self.assertTrue(self.helper.closed.is_set())
        self.helper.window.destroy.assert_called_once()
    def test_closed_client_rejects_jobs(self):
        self.helper.closed.set()
        job=MagicMock()
        self.assertFalse(self.helper.start_job('login',job)['ok'])
        job.assert_not_called()
    def test_tec_permitted_without_confirmation(self):
        with patch.object(c,'read_wifi',return_value=TEC):
            wifi,tec=self.helper.permitted()
        self.assertEqual(wifi,TEC);self.assertTrue(tec)
    def test_tec_login_without_operator(self):
        del self.helper.login
        self.helper.save_profile=MagicMock(return_value={'ok':True})
        self.helper.authenticate=MagicMock(return_value=False)
        self.helper.run_authentication=MagicMock(return_value=False)
        engine=MagicMock()
        engine.status.return_value={'state':'offline','matched_ip':True}
        self.helper.session_engine=MagicMock(return_value=engine)
        self.helper.portal='http://10.2.5.251/a79.htm';self.helper.portal_key=TEC.key
        self.helper.start_job=lambda kind,job,automatic=False: (job() or {'ok':True})
        with patch.object(c,'read_wifi',return_value=TEC):
            result=self.helper.login('fake-teacher','fake-password','')
        self.assertTrue(result['ok'])
        self.helper.run_authentication.assert_called_once()
        self.assertEqual(self.helper.run_authentication.call_args.args[:6],(TEC,'fake-teacher','fake-password','','login',True))
    def test_logout_requires_current_campus_network(self):
        with patch.object(c,'read_wifi',return_value=HOTSPOT):result=self.helper.logout()
        self.assertFalse(result['ok'])

class BrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from playwright.sync_api import sync_playwright
        cls.pw=sync_playwright().start()
        cls.browser=cls.pw.chromium.launch(channel='msedge',headless=True,args=['--disable-background-networking','--no-proxy-server'])
        cls.context=cls.browser.new_context(service_workers='block')
        cls.context.route('**/*',lambda route:route.abort())
    @classmethod
    def tearDownClass(cls):
        cls.context.close();cls.browser.close();cls.pw.stop()
    def setUp(self):
        self.page=self.context.new_page();self.page.set_content(HTML)
    def tearDown(self):
        self.page.close()
    def fill(self,operator='telecom'):
        return self.page.evaluate(c.FILL_JS,{'account':'test&+@账号','password':'test-password&+=','operator':operator})
    def test_original_fields_filled_special_chars(self):
        result=self.fill()
        self.assertTrue(result['ok']);self.assertTrue(result['can_submit'])
        self.assertEqual(self.page.locator('[name=DDDDD]').input_value(),'test&+@账号')
        self.assertEqual(self.page.locator('[name=upass]').input_value(),'test-password&+=')
        self.assertEqual(self.page.locator('select').input_value(),'@telecom')
    def test_no_auto_click_during_fill(self):
        self.fill();self.assertIsNone(self.page.evaluate('window.clicked'))
    def test_identified_login_button_one_click(self):
        self.fill();self.page.locator('[data-cumt-login-button="1"]').click()
        self.assertEqual(self.page.evaluate('window.clicked'),1)
    def test_missing_operator_no_guessing(self):
        self.page.locator('select').evaluate('(e)=>e.remove()')
        result=self.fill();self.assertFalse(result['ok'])
        self.assertEqual(self.page.locator('[name=upass]').input_value(),'')
    def test_teacher_no_operator_leaves_page_default(self):
        self.page.locator('select').select_option('@cmcc')
        result=self.fill('')
        self.assertTrue(result['ok']);self.assertTrue(result['can_submit'])
        self.assertEqual(self.page.locator('select').input_value(),'@cmcc')
    def test_teacher_page_without_operator(self):
        self.page.locator('select').evaluate('(e)=>e.remove()')
        result=self.fill('')
        self.assertTrue(result['ok']);self.assertTrue(result['can_submit'])
    def test_operator_mismatch_stops_before_password(self):
        self.page.locator('option[value="@telecom"]').evaluate('(e)=>e.remove()')
        result=self.fill();self.assertFalse(result['ok'])
        self.assertEqual(self.page.locator('[name=upass]').input_value(),'')
    def test_unknown_form_not_filled(self):
        self.page.set_content('<input name="random"><input type="password">')
        self.assertFalse(self.fill()['ok'])
    def test_ambiguous_login_not_auto_submitted(self):
        self.page.set_content(HTML+'<button>登录</button>')
        result=self.fill();self.assertFalse(result['ok']);self.assertFalse(result['can_submit'])
        self.assertEqual(self.page.locator('[name=DDDDD]').input_value(),'')
        self.assertEqual(self.page.locator('[name=upass]').input_value(),'')
    def test_portal_wide_common_china_mobile_option(self):
        result=self.fill('cmcc');self.assertTrue(result['ok'])
        self.assertEqual(self.page.locator('select').input_value(),'@cmcc')
    def test_logout_control_is_original_page_button(self):
        self.page.set_content('<button onclick="window.loggedOut=true">注销</button>')
        self.assertTrue(self.page.evaluate(a.LOGOUT_JS))
        self.page.locator('[data-cumt-logout-button="1"]').click()
        self.assertTrue(self.page.evaluate('window.loggedOut'))
    def test_ambiguous_logout_control_not_clicked(self):
        self.page.set_content('<button>注销</button><button>退出登录</button>')
        self.assertFalse(self.page.evaluate(a.LOGOUT_JS))
    def test_hidden_field_not_selected(self):
        self.page.set_content('<input name="DDDDD" style="display:none">'+HTML)
        result=self.fill();self.assertTrue(result['ok'])
        self.assertEqual(self.page.locator('[name=DDDDD]').nth(0).input_value(),'')
        self.assertEqual(self.page.locator('[name=DDDDD]').nth(1).input_value(),'test&+@账号')

class PortalIntegrationTests(unittest.TestCase):
    """Real WebView2 DOM plus an entirely mocked, in-memory HTTP origin."""
    def run_portal(self,result_body,extra_click=False):
        submitted=[];configuration=[]
        page_html='''<!doctype html><meta charset="utf-8">
        <input name="DDDDD"><input name="upass" type="password">
        <script>fetch('/config',{method:'POST',body:'mode=read'});</script>
        <button onclick="fetch('/eportal/?a=login&user_account='+encodeURIComponent(document.querySelector('[name=DDDDD]').value)+'&user_password='+encodeURIComponent(document.querySelector('[name=upass]').value));EXTRA">登录</button>'''.replace('EXTRA',"fetch('/eportal/?a=login&user_account=second');" if extra_click else '')
        class Response:
            status=200
            def __init__(self,body,kind):self.body=body;self.kind=kind
            def read(self,*args):return self.body.encode('utf-8')
            def getheaders(self):return [('Content-Type',self.kind)]
        class Connection:
            def __init__(self,*args):pass
            def request(self,method,target,body=None,headers=None):
                if target.startswith('/eportal/'):
                    submitted.append(target);self.response=Response(result_body,'application/json')
                elif target=='/config':
                    configuration.append(method);self.response=Response('{}','application/json')
                else:self.response=Response(page_html,'text/html; charset=utf-8')
            def getresponse(self):return self.response
            def close(self):pass
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            store=c.Store(Path(folder))
            with patch.object(c,'Store',return_value=store): helper=a.App()
            helper.wifi=WIFI;helper.portal='http://10.2.5.251/a79.htm'
            with patch.object(c,'read_wifi',return_value=WIFI),patch.object(c,'BoundHTTP',Connection):
                result=helper.authenticate(WIFI,'fake-integration-account','fake-integration-password','','login',False)
        return result,submitted,configuration
    def test_unverified_configuration_post_is_blocked_without_consuming_login(self):
        result,submitted,configuration=self.run_portal('{"result":1}')
        self.assertTrue(result);self.assertEqual(len(submitted),1);self.assertEqual(configuration,[])
    def test_portal_repeated_submission_blocked(self):
        result,submitted,_=self.run_portal('{"result":0}',extra_click=True)
        self.assertFalse(result);self.assertEqual(len(submitted),1)
    def test_plain_page_success_phrase_is_not_evidence(self):
        result,submitted,_=self.run_portal('登录成功后可访问校园网')
        self.assertIsNone(result);self.assertEqual(len(submitted),1)

if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    report={'mode':'offline mock only; no actual campus login or WiFi changes',
            'run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),
            'skipped':len(result.skipped),'success':result.wasSuccessful(),
            'version':c.VERSION,
            'coverage':['real CUMT_Stu/CUMT_Tec SSIDs','disabled auto makes no requests','STU selected-only one attempt with no retry','multi-profile migration/DPAPI CRUD',
                        'logout original DOM control','hotspot/SSID safeguards','TEC without warning/operator','IP change cancellation','dynamic new-dorm redirect',
                        'old IP/MAC replacement','credential redaction','DPAPI encrypted storage','night schedule',
                        'source physical WiFi socket binding','false success vs internet response',
                        'real Edge DOM fill, operator selection and one-click control'],
            'not_verified':['real new-dorm page selectors/scripts','real account privileges/operator binding','real campus connectivity']}
    (Path(__file__).parent/'test_results.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    sys.exit(0 if result.wasSuccessful() else 1)
