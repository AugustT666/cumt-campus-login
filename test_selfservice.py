"""Self-service uses synthetic HTML/JSON and a fake bound transport only."""
import copy
from dataclasses import replace
from pathlib import Path
import json
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit, urlencode

import campus_core as core
import campus_selfservice as service


WIFI=core.Wifi(core.TEC,'selfservice-fixture',7,'10.61.42.9','00-11-22-33-44-55')
ACCOUNT='fictional-account'
PASSWORD='fictional-password'
COOKIE='0123456789ABCDEF0123456789ABCDEF'
OWN={'sessionId':'fictional-session-own','ip':WIFI.ip,'mac':'001122334455','userId':52}
OTHER={'sessionId':'fictional-session-other','ip':'10.61.42.10','mac':'66778899AABB','userId':52}


def login_page(action=service.LOGIN_ACTION, hidden=True, tip=''):
    return '''<form method="post" action="ACTION">
      <div style="left:-1000px"><input name="foo"><input name="bar" type="password">
      <input type="hidden" name="checkcode" value="synthetic-hidden"></div>
      <input name="account" id="account"><input name="password" type="password">
      <div id="randomDiv" class="form-group HIDE"><input name="code"></div></form>
      <script>var md5 = false;(function(tip){window.fakeTip=tip;})('TIP');</script>
      <span>验证码</span>'''.replace('ACTION',action).replace('HIDE','hide' if hidden else '').replace('TIP',tip)


DASHBOARD='''<table id="OnlineLisBig"></table><script>
var first={url:"dashboard/getOnlineList"};var second={url:"dashboard/tooffline"};</script>'''


class Response:
    def __init__(self,status=200,body='',headers=None):
        self.status=status
        self.body=body.encode() if isinstance(body,str) else body
        self.headers=[('Content-Type','text/html; charset=UTF-8'),*(headers or [])]
    def read(self,size):return self.body[:size]
    def getheaders(self):return self.headers
    def getheader(self,name,default=''):
        return next((v for k,v in self.headers if k.lower()==name.lower()),default)


class Harness:
    def __init__(self):
        self.requests=[]
        self.devices=[copy.deepcopy(OWN),copy.deepcopy(OTHER)]
        self.list_responses=[]
        self.after_disconnect=None
        self.logout_body={'success':True}
        self.fail_after_disconnect=False
        self.form=login_page()
        self.post_location=service.DASHBOARD
        self.failure_page=login_page(tip='账号或密码错误')
        self.cookie='JSESSIONID='+COOKIE+'; Path=/Self; HttpOnly'
        self.response_headers=[]
        self.post_seen=False
        self.web_closed=False
        self.web_logout_location='/Self/login'
        self.traces=[]
    def trace(self,event,**fields):self.traces.append((event,fields))
    def factory(self,host,port,wifi):
        assert (host,port)==('202.119.196.6',8080)
        assert wifi==WIFI
        outer=self
        class Connection:
            def request(self,method,target,body=None,headers=None):
                self.request_data=(method,target,body,headers or {})
            def getresponse(self):
                method,target,body,headers=self.request_data
                p=urlsplit(target);query=parse_qs(p.query,keep_blank_values=True)
                outer.requests.append((method,p.path,query,body,headers))
                if p.path in ('/Self/login','/Self/login/'):
                    text=outer.failure_page if outer.post_seen else outer.form
                    return Response(body=text,headers=[('Set-Cookie',outer.cookie)])
                if p.path==service.CAPTCHA_IMAGE:return Response(body=b'GIF89a')
                if p.path==service.LOGIN_ACTION:
                    assert method=='POST'
                    values=parse_qs(body.decode(),keep_blank_values=True)
                    assert values['account']==[ACCOUNT] and values['password']==[PASSWORD]
                    assert values['foo']==[''] and values['bar']==['']
                    assert values['code']==[''] and values['checkcode']==['synthetic-hidden']
                    assert 'JSESSIONID='+COOKIE in headers.get('Cookie','')
                    outer.post_seen=True
                    if outer.post_location==service.DASHBOARD:outer.web_closed=False
                    return Response(302,headers=[('Location',outer.post_location)])
                if p.path==service.DASHBOARD:
                    if outer.web_closed:return Response(302,headers=[('Location','/Self/login/?302=LI')])
                    return Response(body=DASHBOARD)
                if p.path==service.ONLINE_LIST:
                    rows=outer.list_responses.pop(0) if outer.list_responses else outer.devices
                    return Response(body=json.dumps(rows))
                if p.path==service.DISCONNECT:
                    assert method=='GET' and set(query)=={'sessionid','_'}
                    target_id=query['sessionid'][0]
                    outer.devices=[d for d in outer.devices if d['sessionId']!=target_id]
                    if outer.after_disconnect is not None:outer.devices=copy.deepcopy(outer.after_disconnect)
                    if outer.fail_after_disconnect:raise TimeoutError('synthetic response timeout')
                    return Response(body=json.dumps(outer.logout_body))
                if p.path==service.WEB_LOGOUT:
                    outer.web_closed=True
                    return Response(302,headers=[('Location',outer.web_logout_location)])
                raise AssertionError('Unexpected test path')
            def close(self):pass
        return Connection()
    def client(self,reader=None,cleanup_reader=None,**kwargs):
        return service.Client(WIFI,reader=reader or (lambda:WIFI),trace=self.trace,
                              connection_factory=self.factory,cleanup_reader=cleanup_reader,sleeper=lambda _:None,**kwargs)
    def count(self,path):return sum(p==path for _,p,*_ in self.requests)


class SelfServiceTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(core,'Store',side_effect=AssertionError('No Store')))
        self.h=Harness()
    def login(self):
        c=self.h.client();self.addCleanup(c.close);self.assertTrue(c.login(ACCOUNT,PASSWORD));return c

    def test_login_initializes_image_then_posts_complete_canonical_form(self):
        c=self.login()
        paths=[p for _,p,*_ in self.h.requests]
        self.assertEqual(paths[:4],['/Self/login/',service.CAPTCHA_IMAGE,service.LOGIN_ACTION,service.DASHBOARD])
        self.assertTrue(c.safe_summary()['login_confirmed'])

    def test_rewritten_form_session_matches_cookie_and_is_not_sent_in_url(self):
        self.h.form=login_page(service.LOGIN_ACTION+';jsessionid='+COOKIE)
        self.login()
        post=next(r for r in self.h.requests if r[0]=='POST')
        self.assertEqual(post[1],service.LOGIN_ACTION)
        self.assertEqual(post[2],{})

    def test_rewritten_session_wrong_missing_extra_or_malformed_is_rejected(self):
        bad=[service.LOGIN_ACTION+';jsessionid='+'F'*32,
             service.LOGIN_ACTION+';jsessionid='+COOKIE+';other=1',
             service.LOGIN_ACTION+';jsessionid=not-hex',service.LOGIN_ACTION+'?jsessionid='+COOKIE]
        for action in bad:
            with self.subTest(action=action),self.assertRaises(service.UnsupportedService):
                service.parse_login_form(login_page(action),session_cookie=COOKIE)
        with self.assertRaises(service.UnsupportedService):
            service.parse_login_form(login_page(service.LOGIN_ACTION+';jsessionid='+COOKIE))

    def test_visible_captcha_stops_before_password_or_image_request(self):
        self.h.form=login_page(hidden=False)
        c=self.h.client()
        with self.assertRaises(service.CaptchaRequired):c.login(ACCOUNT,PASSWORD)
        self.assertEqual(self.h.count(service.LOGIN_ACTION),0)
        self.assertEqual(self.h.count(service.CAPTCHA_IMAGE),0)

    def test_failed_password_page_static_captcha_label_does_not_mask_auth_error(self):
        self.h.post_location='/Self/login/?error=1'
        c=self.h.client();self.addCleanup(c.close)
        with self.assertRaises(service.AuthenticationError) as error:c.login(ACCOUNT,PASSWORD)
        self.assertNotIsInstance(error.exception,service.CaptchaRequired)
        self.assertEqual(self.h.count(service.LOGIN_ACTION),1)

    def test_server_captcha_tip_is_recognized_even_while_group_is_hidden(self):
        self.h.post_location='/Self/login/?error=1'
        self.h.failure_page=login_page(tip='验证码错误')
        c=self.h.client();self.addCleanup(c.close)
        with self.assertRaises(service.CaptchaRequired):c.login(ACCOUNT,PASSWORD)
        self.assertEqual(self.h.count(service.LOGIN_ACTION),1)

    def test_cross_origin_action_stops_before_credentials(self):
        self.h.form=login_page('http://untrusted.invalid/Self/login/verify')
        c=self.h.client()
        with self.assertRaises(service.UnsupportedService):c.login(ACCOUNT,PASSWORD)
        self.assertEqual(self.h.count(service.LOGIN_ACTION),0)

    def test_cross_origin_post_redirect_is_not_followed(self):
        self.h.post_location='http://untrusted.invalid/Self/dashboard'
        c=self.h.client();self.addCleanup(c.close)
        with self.assertRaises(service.UnsupportedService):c.login(ACCOUNT,PASSWORD)
        self.assertEqual(self.h.count(service.DASHBOARD),0)

    def test_control_or_oversized_cookie_fails_without_leaking_value(self):
        for value in ('sensitive-cookie\r\nInjected: bad','x'*8200):
            with self.subTest(case=len(value)):
                self.h=Harness();self.h.cookie='JSESSIONID='+value+'; Path=/Self'
                c=self.h.client()
                with self.assertRaises(service.UnsupportedService) as error:c.login(ACCOUNT,PASSWORD)
                self.assertNotIn('sensitive-cookie',str(error.exception))
                self.assertEqual(self.h.count(service.LOGIN_ACTION),0)

    def test_login_is_never_retried_in_one_client(self):
        c=self.login()
        with self.assertRaises(service.AuthenticationError):c.login(ACCOUNT,PASSWORD)
        self.assertEqual(self.h.count(service.LOGIN_ACTION),1)

    def test_two_concurrent_logins_still_submit_one_password(self):
        barrier=threading.Barrier(2,timeout=.1)
        local=threading.local()
        def reader():
            if not getattr(local,'seen',False):
                local.seen=True
                try:barrier.wait()
                except threading.BrokenBarrierError:pass
            return WIFI
        c=self.h.client(reader=reader);self.addCleanup(c.close)
        results=[];errors=[]
        def attempt():
            try:results.append(c.login(ACCOUNT,PASSWORD))
            except service.SelfServiceError as exc:errors.append(type(exc))
        workers=[threading.Thread(target=attempt) for _ in range(2)]
        for worker in workers:worker.start()
        for worker in workers:worker.join(2);self.assertFalse(worker.is_alive())
        self.assertEqual(len(results),1)
        self.assertEqual(len(errors),1)
        self.assertEqual(self.h.count(service.LOGIN_ACTION),1)

    def test_two_concurrent_disconnects_still_send_one_action(self):
        barrier=threading.Barrier(2,timeout=.1)
        local=threading.local();active=[False]
        def reader():
            if active[0] and not getattr(local,'seen',False):
                local.seen=True
                try:barrier.wait()
                except threading.BrokenBarrierError:pass
            return WIFI
        c=self.h.client(reader=reader);self.addCleanup(c.close);c.login(ACCOUNT,PASSWORD)
        active[0]=True
        results=[];errors=[]
        def attempt():
            try:results.append(c.disconnect_current())
            except service.SelfServiceError as exc:errors.append(type(exc))
        workers=[threading.Thread(target=attempt) for _ in range(2)]
        for worker in workers:worker.start()
        for worker in workers:worker.join(2);self.assertFalse(worker.is_alive())
        self.assertEqual(len(results),1)
        self.assertEqual(len(errors),1)
        self.assertEqual(self.h.count(service.DISCONNECT),1)
        self.assertEqual(c.safe_summary()['disconnect_requests'],1)

    def test_precise_logout_has_two_prechecks_one_action_then_readback(self):
        c=self.login();result=c.disconnect_current()
        self.assertIs(result['request_accepted'],True)
        self.assertIs(result['current_device_offline'],True)
        self.assertEqual(self.h.count(service.ONLINE_LIST),6)
        self.assertEqual(self.h.count(service.DISCONNECT),1)
        self.assertEqual(self.h.devices,[OTHER])
        with self.assertRaises(service.SelfServiceError):c.disconnect_current()
        self.assertEqual(self.h.count(service.DISCONNECT),1)

    def test_other_device_is_never_disconnected(self):
        self.h.devices=[copy.deepcopy(OTHER)]
        c=self.login()
        with self.assertRaises(service.NoMatchingDevice):c.disconnect_current()
        self.assertEqual(self.h.count(service.DISCONNECT),0)
        self.assertEqual(self.h.devices,[OTHER])

    def test_same_mac_other_ip_requires_strong_bound_server_context(self):
        alternate=copy.deepcopy(OWN);alternate['ip']='10.88.42.9'
        devices=service.parse_online_devices(json.dumps([alternate]))
        with self.assertRaises(service.NoMatchingDevice):service.select_current_session(devices,WIFI)
        info={'state':'online','binding':'mac_verified','matched_ip':True,'mac_conflict':False,
              'server_mac':WIFI.mac,'server_ip':alternate['ip']}
        self.assertEqual(service.select_current_session(devices,WIFI,info).session_id,OWN['sessionId'])
        info['binding']='conflict'
        with self.assertRaises(service.NoMatchingDevice):service.select_current_session(devices,WIFI,info)

    def test_current_ip_match_is_preferred_to_other_bound_address(self):
        alternate=copy.deepcopy(OWN);alternate.update(sessionId='another-fictional-session',ip='10.88.42.9')
        devices=service.parse_online_devices(json.dumps([OWN,alternate]))
        info={'state':'online','binding':'mac_verified','matched_ip':True,'mac_conflict':False,
              'server_mac':WIFI.mac,'server_ip':alternate['ip']}
        self.assertEqual(service.select_current_session(devices,WIFI,info).session_id,OWN['sessionId'])

    def test_two_matching_records_or_changed_id_stop_before_mutation(self):
        second=copy.deepcopy(OWN);second['sessionId']='different-fictional-session'
        for rows in ([OWN,second],[OWN]):
            with self.subTest(count=len(rows)):
                self.h=Harness();c=self.login()
                self.h.list_responses=[copy.deepcopy(rows),[copy.deepcopy(second)]]
                with self.assertRaises(service.AmbiguousDevice):c.disconnect_current()
                self.assertEqual(self.h.count(service.DISCONNECT),0)

    def test_before_disconnect_cancellation_never_sends(self):
        c=self.login()
        def stop():raise RuntimeError('synthetic cancel')
        with self.assertRaises(RuntimeError):c.disconnect_current(before_disconnect=stop)
        self.assertEqual(self.h.count(service.DISCONNECT),0)
        self.assertEqual(c.safe_summary()['disconnect_requests'],0)

    def test_last_network_guard_cancellation_is_not_counted_as_submission(self):
        canceled=[False]
        def reader():
            if canceled[0]:raise RuntimeError('synthetic cancellation')
            return WIFI
        c=self.h.client(reader=reader);self.addCleanup(c.close);c.login(ACCOUNT,PASSWORD)
        with self.assertRaises(RuntimeError):c.disconnect_current(before_disconnect=lambda:canceled.__setitem__(0,True))
        self.assertEqual(self.h.count(service.DISCONNECT),0)
        self.assertEqual(c.safe_summary()['disconnect_requests'],0)

    def test_guard_inside_request_also_blocks_without_counting_submission(self):
        remaining=[0]
        def reader():
            if remaining[0]:
                remaining[0]-=1
                if not remaining[0]:raise RuntimeError('last guard canceled')
            return WIFI
        c=self.h.client(reader=reader);self.addCleanup(c.close);c.login(ACCOUNT,PASSWORD)
        with self.assertRaises(RuntimeError):
            c.disconnect_current(before_disconnect=lambda:remaining.__setitem__(0,2))
        self.assertEqual(self.h.count(service.DISCONNECT),0)
        self.assertEqual(c.safe_summary()['disconnect_requests'],0)

    def test_ip_or_mac_change_blocks_list_read(self):
        current=[WIFI]
        c=self.h.client(reader=lambda:current[0]);self.addCleanup(c.close);c.login(ACCOUNT,PASSWORD)
        for changed in (replace(WIFI,ip='10.61.42.11'),replace(WIFI,mac='66-77-88-99-AA-BB')):
            current[0]=changed
            with self.assertRaises(RuntimeError):c.list_online_devices()
        self.assertEqual(self.h.count(service.ONLINE_LIST),0)

    def test_timeout_after_received_disconnect_does_not_retry(self):
        c=self.login();self.h.fail_after_disconnect=True
        result=c.disconnect_current()
        self.assertIsNone(result['request_accepted'])
        self.assertTrue(result['session_removed'])
        self.assertTrue(result['current_device_offline'])
        self.assertEqual(self.h.count(service.DISCONNECT),1)

    def test_removed_id_with_new_current_device_session_is_not_final_offline(self):
        c=self.login();new=copy.deepcopy(OWN);new['sessionId']='synthetic-reappeared-session'
        self.h.after_disconnect=[copy.deepcopy(OTHER),new]
        result=c.disconnect_current()
        self.assertTrue(result['session_removed'])
        self.assertTrue(result['device_reappeared'])
        self.assertFalse(result['current_device_offline'])
        self.assertEqual(self.h.count(service.DISCONNECT),1)

    def test_same_mac_reappearing_at_unrecorded_ip_is_not_final_offline(self):
        c=self.login();new=copy.deepcopy(OWN)
        new.update(sessionId='new-fictional-id',ip='10.99.42.20')
        self.h.after_disconnect=[OTHER,new]
        result=c.disconnect_current()
        self.assertTrue(result['device_reappeared'])
        self.assertFalse(result['current_device_offline'])
        self.assertEqual(self.h.count(service.DISCONNECT),1)

    def test_asynchronous_removal_is_read_back_without_another_disconnect(self):
        c=self.login()
        initial=[copy.deepcopy(OWN),copy.deepcopy(OTHER)]
        self.h.list_responses=[initial,initial,initial,[OTHER],[OTHER],[OTHER]]
        result=c.disconnect_current()
        self.assertTrue(result['current_device_offline'])
        self.assertEqual(self.h.count(service.DISCONNECT),1)
        self.assertEqual(self.h.count(service.ONLINE_LIST),6)

    def test_transient_absence_followed_by_same_id_is_not_final_offline(self):
        c=self.login();initial=[copy.deepcopy(OWN),copy.deepcopy(OTHER)]
        self.h.list_responses=[initial,initial,[OTHER],[OTHER],initial,initial]
        result=c.disconnect_current()
        self.assertTrue(result['device_reappeared'])
        self.assertFalse(result['current_device_offline'])

    def test_trace_and_summary_do_not_include_credentials_cookie_or_session(self):
        c=self.login();c.disconnect_current();c.close()
        output=json.dumps([self.h.traces,c.safe_summary()])
        for value in (ACCOUNT,PASSWORD,COOKIE,OWN['sessionId'],WIFI.ip,WIFI.mac):
            self.assertNotIn(value,output)

    def test_close_logs_out_web_session_once_and_clears_cookie(self):
        c=self.login();result=c.close();c.close()
        self.assertTrue(result['web_logout_confirmed'])
        self.assertEqual(self.h.count(service.WEB_LOGOUT),1)
        self.assertEqual(c._cookies,{})

    def test_web_logout_to_self_root_is_confirmed_by_dashboard_login_redirect(self):
        c=self.login();self.h.web_logout_location='/Self/'
        result=c.close()
        self.assertTrue(result['web_logout_confirmed'])
        self.assertEqual(self.h.count(service.WEB_LOGOUT),1)

    def test_cleanup_reader_allows_web_exit_after_cancel_but_not_wrong_network(self):
        blocked=[False]
        def reader():
            if blocked[0]:raise RuntimeError('operation canceled')
            return WIFI
        c=self.h.client(reader=reader,cleanup_reader=lambda:WIFI);c.login(ACCOUNT,PASSWORD)
        blocked[0]=True
        self.assertTrue(c.close()['web_logout_confirmed'])
        other=self.h.client(reader=lambda:WIFI,cleanup_reader=lambda:replace(WIFI,ip='10.61.42.20'))
        other.login(ACCOUNT,PASSWORD)
        self.assertFalse(other.close()['web_logout_confirmed'])


def nas_target(**changes):
    values={'nasip':'10.61.42.1','ssid':WIFI.ssid,'t':'synthetic-time',
            'url':'http://9.9.9.9/','wlanacname':'synthetic-nas-controller',
            'wlanuserip':WIFI.ip,'mac':WIFI.mac}
    values.update(changes)
    return 'http://10.2.5.251/a79.htm?'+urlencode(values)


class SubmitCurrentTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(core,'Store',side_effect=AssertionError('No Store')))
        self.h=Harness()
        self.tick=100.0
        self.nas_calls=[]
        self.sleeps=[]

    def nas_getter(self,url,wifi,reader,allow_tec):
        self.assertEqual(reader(),WIFI)
        self.nas_calls.append(url)
        return 302,nas_target(),''

    def login(self,reader=None,cleanup_reader=None):
        c=self.h.client(reader=reader,cleanup_reader=cleanup_reader,
            nas_getter=self.nas_getter,clock=lambda:self.tick)
        self.addCleanup(c.close)
        c.login(ACCOUNT,PASSWORD)
        c._sleep=lambda seconds:self.sleeps.append(seconds)
        return c

    def assert_submission_only(self,start):
        self.assertEqual([p for _,p,*_ in self.h.requests[start:]],
                         [service.ONLINE_LIST,service.ONLINE_LIST,service.DISCONNECT])
        self.assertEqual(self.sleeps,[])
        self.assertEqual(self.h.count(service.DISCONNECT),1)
        self.assertEqual(self.h.count(service.ONLINE_LIST),2)

    def test_server_success_returns_ack_without_device_readback_or_sleep(self):
        c=self.login();start=len(self.h.requests)
        result=c.submit_current()
        self.assert_submission_only(start)
        self.assertIs(result['request_accepted'],True)
        self.assertIsNone(result['session_removed'])
        self.assertIsNone(result['current_device_offline'])
        self.assertNotIn('verified',result)
        self.assertEqual(self.h.devices,[OTHER])
        self.assertEqual(self.nas_calls,[])
        self.assertNotIn('selfservice.disconnect_checked',[e for e,_ in self.h.traces])

    def test_rejection_is_not_repaired_by_polling_or_another_submission(self):
        c=self.login();self.h.logout_body={'success':False};start=len(self.h.requests)
        result=c.submit_current()
        self.assert_submission_only(start)
        self.assertIs(result['request_accepted'],False)
        self.assertIsNone(result['session_removed'])
        self.assertIsNone(result['current_device_offline'])
        with self.assertRaises(service.SelfServiceError):c.submit_current()
        with self.assertRaises(service.SelfServiceError):c.disconnect_current()
        self.assert_submission_only(start)

    def test_lost_response_has_unknown_ack_and_is_never_retried(self):
        c=self.login();self.h.fail_after_disconnect=True;start=len(self.h.requests)
        result=c.submit_current()
        self.assert_submission_only(start)
        self.assertIsNone(result['request_accepted'])
        self.assertIsNone(result['current_device_offline'])
        with self.assertRaises(service.SelfServiceError):c.submit_current()
        self.assert_submission_only(start)

    def test_nonboolean_success_is_unknown_without_postchecks(self):
        c=self.login();self.h.logout_body={'success':'true'};start=len(self.h.requests)
        result=c.submit_current()
        self.assert_submission_only(start)
        self.assertIsNone(result['request_accepted'])
        self.assertIsNone(result['session_removed'])
        self.assertIsNone(result['current_device_offline'])

    def test_missing_ack_is_unknown_without_postchecks(self):
        c=self.login();self.h.logout_body={};start=len(self.h.requests)
        result=c.submit_current()
        self.assert_submission_only(start)
        self.assertIsNone(result['request_accepted'])

    def test_cancellation_before_wire_sends_no_action(self):
        c=self.login()
        def stop():raise RuntimeError('Fictional cancelled before request')
        with self.assertRaises(RuntimeError):c.submit_current(before_disconnect=stop)
        self.assertEqual(self.h.count(service.ONLINE_LIST),2)
        self.assertEqual(self.h.count(service.DISCONNECT),0)
        self.assertEqual(c.safe_summary()['disconnect_requests'],0)
        self.assertEqual(self.sleeps,[])

    def test_changed_session_or_owner_in_second_precheck_sends_no_action(self):
        c=self.login()
        self.h.list_responses=[[OWN,OTHER],[dict(OWN,sessionId='fictional-new-session'),OTHER]]
        with self.assertRaises(service.AmbiguousDevice):c.submit_current()
        self.assertEqual(self.h.count(service.DISCONNECT),0)

    def test_another_device_at_current_ip_is_not_selected(self):
        c=self.login();self.h.devices=[dict(OWN,mac=OTHER['mac']),OTHER]
        with self.assertRaises(service.NoMatchingDevice):c.submit_current()
        self.assertEqual(self.h.count(service.DISCONNECT),0)
        self.assertEqual(self.nas_calls,[])

    def test_ghost_submission_keeps_nas_prechecks_but_has_no_readback(self):
        self.h.devices=[dict(OWN,mac='000000000000'),OTHER]
        c=self.login();start=len(self.h.requests)
        result=c.submit_current()
        self.assert_submission_only(start)
        self.assertEqual(len(self.nas_calls),1)
        self.assertIs(result['request_accepted'],True)
        self.assertIsNone(result['session_removed'])
        self.assertIsNone(result['current_device_offline'])
        self.assertEqual(self.h.devices,[OTHER])

    def test_expiry_after_tcp_connect_still_blocks_ghost_submission(self):
        self.h.devices=[dict(OWN,mac='000000000000'),OTHER]
        original=self.h.factory
        def slow_connect(*args):
            conn=original(*args)
            conn.connect=lambda:setattr(self,'tick',self.tick+service.NAS_BINDING_TTL+1)
            return conn
        self.h.factory=slow_connect
        c=self.login()
        with self.assertRaises(service.UnsupportedService):c.submit_current()
        self.assertEqual(self.h.count(service.DISCONNECT),0)
        self.assertEqual(c.safe_summary()['disconnect_requests'],0)

    def test_response_is_not_followed_by_a_native_network_check(self):
        current=[WIFI];after_response=[False];late_reads=[]
        def reader():
            if after_response[0]:late_reads.append(True)
            return current[0]
        original=self.h.factory
        def factory(*args):
            conn=original(*args);getresponse=conn.getresponse
            def receive():
                response=getresponse()
                if urlsplit(conn.request_data[1]).path==service.DISCONNECT:
                    after_response[0]=True
                    current[0]=replace(WIFI,ip='10.61.42.11')
                return response
            conn.getresponse=receive
            return conn
        self.h.factory=factory
        c=self.login(reader=reader,cleanup_reader=lambda:WIFI)
        result=c.submit_current()
        self.assertEqual(late_reads,[])
        self.assertIs(result['request_accepted'],True)
        self.assertIsNone(result['current_device_offline'])

    def test_concurrent_submit_current_calls_send_exactly_once(self):
        c=self.login();barrier=threading.Barrier(2);results=[];errors=[]
        def attempt():
            barrier.wait()
            try:results.append(c.submit_current())
            except service.SelfServiceError as exc:errors.append(type(exc))
        threads=[threading.Thread(target=attempt) for _ in range(2)]
        for thread in threads:thread.start()
        for thread in threads:thread.join(2);self.assertFalse(thread.is_alive())
        self.assertEqual(len(results),1)
        self.assertEqual(len(errors),1)
        self.assertEqual(self.h.count(service.DISCONNECT),1)
        self.assertEqual(self.h.count(service.ONLINE_LIST),2)
        self.assertEqual(self.sleeps,[])


class NasBindingTests(unittest.TestCase):
    def setUp(self):
        self.current=WIFI
        self.tick=100.0
        self.calls=[]
        self.response=(302,nas_target(),'')
        self.on_get=None
        self.enterContext(patch.object(core,'Store',side_effect=AssertionError('No Store')))
        self.enterContext(patch.object(core,'fresh_url',side_effect=AssertionError('Never synthesize NAS proof')))

    def clock(self):return self.tick
    def reader(self):return self.current
    def getter(self,url,wifi,reader,allow_tec):
        self.assertIn(url,service.NAS_PROBES)
        self.assertEqual(wifi,self.current)
        self.assertEqual(reader(),self.current)
        self.assertIs(allow_tec,wifi.ssid==core.TEC)
        self.calls.append(url)
        if self.on_get:self.on_get()
        return self.response
    def observe(self):
        return service.observe_nas_binding(self.current,reader=self.reader,getter=self.getter,clock=self.clock)

    def test_raw_http_redirect_mints_short_lived_context_bound_proof(self):
        proof=self.observe()
        self.assertEqual(proof.portal_url,nas_target())
        self.assertTrue(proof.validate(WIFI,reader=self.reader,clock=self.clock))
        self.assertEqual(self.calls,[service.NAS_PROBES[0]])
        self.tick+=service.NAS_BINDING_TTL+.01
        with self.assertRaises(service.UnsupportedService):proof.validate(WIFI,reader=self.reader,clock=self.clock)

    def test_proof_cannot_be_constructed_from_json_or_copied_with_new_fields(self):
        proof=self.observe()
        forged=service.NasBinding(proof.portal_url,proof.context,proof.observed_at)
        changed=replace(proof,portal_url=proof.portal_url)
        for value in (forged,changed):
            with self.assertRaises(service.UnsupportedService):value.validate(WIFI,reader=self.reader,clock=self.clock)

    def test_proof_expiry_during_final_reader_is_checked_again(self):
        proof=self.observe()
        def slow_reader():self.tick+=11;return WIFI
        with self.assertRaises(service.UnsupportedService):proof.validate(WIFI,reader=slow_reader,clock=self.clock)

    def test_complete_physical_network_context_is_required(self):
        proof=self.observe()
        changes=[replace(WIFI,ssid=core.STU),replace(WIFI,guid='other-fixture'),
                 replace(WIFI,index=19),replace(WIFI,ip='10.61.42.20'),
                 replace(WIFI,mac='66-77-88-99-AA-BB'),replace(WIFI,gateway='10.61.42.1')]
        for changed in changes:
            with self.subTest(field_change=changed!=WIFI),self.assertRaises(RuntimeError):
                proof.validate(WIFI,reader=lambda:changed,clock=self.clock)

    def test_observation_checks_context_before_and_after_raw_response(self):
        self.on_get=lambda:setattr(self,'current',replace(WIFI,gateway='10.61.42.1'))
        with self.assertRaises(RuntimeError):self.observe()

    def test_untrusted_host_or_missing_and_ambiguous_parameters_do_not_authorize(self):
        bad=[nas_target().replace('10.2.5.251','untrusted.invalid'),
             nas_target().replace('http://','http://user@'),
             nas_target()+'&MAC=001122334455',nas_target()+'#ignored',
             nas_target(mac=''),nas_target(mac='000000000000'),
             nas_target(mac='66778899AABB'),nas_target(wlanuserip='10.61.42.20'),
             nas_target(wlanacname=''),nas_target(nasip='0.0.0.0'),
             nas_target(nasip='127.0.0.1'),nas_target(nasip='255.255.255.255'),
             nas_target(nasip='not-an-ip'),nas_target().replace('nasip=','other=')]
        for target in bad:
            with self.subTest(index=bad.index(target)):
                self.response=(302,target,'')
                with self.assertRaises(service.UnsupportedService):self.observe()

    def test_missing_raw_fields_are_not_repaired_from_current_wifi(self):
        self.response=(302,'http://10.2.5.251/a79.htm?wlanacname=fixture&nasip=10.61.42.1','')
        with self.assertRaises(service.UnsupportedService):self.observe()

    def test_literal_js_redirects_are_recognized_without_executing_code(self):
        for script in ("location.href='URL';",'window.location.replace("URL");',"top.location='URL';",
                       "top.self.location.href='URL';",'top.self.location.replace("URL");'):
            self.response=(200,'','<html><script>'+script.replace('URL',nas_target())+'</script></html>')
            self.assertEqual(self.observe().portal_url,nas_target())

    def test_top_self_literal_does_not_authorize_extra_statements_or_expressions(self):
        scripts=["top.self.location.href='URL';fetch('/extra');",
                 "top.self.location.href='URL'+suffix;",
                 "top.self.location.href=chooseUrl();",
                 "top.self.location.href='URL';// extra source",
                 "var text=\"top.self.location.href='URL'\";"]
        for script in scripts:
            with self.subTest(script=script):
                self.response=(200,'','<script>'+script.replace('URL',nas_target())+'</script>')
                with self.assertRaises(service.UnsupportedService):self.observe()

    def test_comments_strings_multiple_scripts_and_nonliteral_js_are_not_proof(self):
        scripts=["// location.href='URL';",'var text="location.href=\'URL\'";',
                 "location.href='URL';doSomething();",'location.href=someVariable;']
        for script in scripts:
            self.response=(200,'','<script>'+script.replace('URL',nas_target())+'</script>')
            with self.assertRaises(service.UnsupportedService):self.observe()
        self.response=(200,'',"<script>location='"+nas_target()+"';</script><script>other()</script>")
        with self.assertRaises(service.UnsupportedService):self.observe()

    def test_raw_observation_does_not_publish_private_urls_through_core_trace(self):
        traces=[]
        original=self.getter
        def traced(*args,**kwargs):
            core.trace('synthetic.nas',url=nas_target())
            return original(*args,**kwargs)
        with core.trace_scope(lambda event,**fields:traces.append((event,fields))):
            service.observe_nas_binding(WIFI,reader=self.reader,getter=traced,clock=self.clock)
        self.assertEqual(traces,[])


class NasGhostSessionTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(core,'Store',side_effect=AssertionError('No Store')))
        self.h=Harness()
        self.ghost=dict(OWN,mac='000000000000')
        self.third=dict(OTHER,sessionId='fictional-third-session',ip='10.61.42.11',mac='AABBCCDDEEFF')
        self.h.devices=[copy.deepcopy(self.ghost),copy.deepcopy(OTHER),copy.deepcopy(self.third)]
        self.tick=100.0
        self.nas_calls=[]
        self.response=(302,nas_target(),'')
    def clock(self):return self.tick
    def getter(self,url,wifi,reader,allow_tec):
        self.assertEqual(reader(),WIFI)
        self.nas_calls.append(url)
        return self.response
    def login(self,**kwargs):
        c=self.h.client(nas_getter=self.getter,clock=self.clock,**kwargs)
        self.addCleanup(c.close);c.login(ACCOUNT,PASSWORD);return c

    def test_unique_current_ip_zero_mac_uses_fresh_nas_proof_and_preserves_other_devices(self):
        c=self.login();result=c.disconnect_current()
        self.assertTrue(result['current_device_offline'])
        self.assertEqual(self.h.count(service.DISCONNECT),1)
        self.assertEqual(self.h.devices,[OTHER,self.third])
        self.assertEqual(self.nas_calls,[service.NAS_PROBES[0]])
        self.assertTrue(all(d['mac']!='000000000000' for d in self.h.devices))

    def test_public_selection_uses_same_authenticated_client_and_rejects_json_proof_injection(self):
        c=self.login();rows=c.list_online_devices()
        self.response=(302,'http://untrusted.invalid/','')
        with self.assertRaises(service.UnsupportedService):
            c.select_current_session(rows,{'nas_binding':{'portal_url':nas_target(),'context':WIFI.key}})
        self.assertEqual(self.h.count(service.DISCONNECT),0)

    def test_valid_different_mac_is_never_replaced_by_ip_only_nas_match(self):
        self.h.devices=[dict(self.ghost,mac='112233445566'),OTHER]
        c=self.login()
        with self.assertRaises(service.NoMatchingDevice):c.disconnect_current()
        self.assertEqual(self.nas_calls,[])
        self.assertEqual(self.h.count(service.DISCONNECT),0)

    def test_duplicate_current_ip_with_missing_mac_is_ambiguous_before_nas_probe(self):
        self.h.devices.append(dict(self.ghost,sessionId='second-fictional-ghost'))
        c=self.login()
        with self.assertRaises(service.AmbiguousDevice):c.disconnect_current()
        self.assertEqual(self.nas_calls,[])
        self.assertEqual(self.h.count(service.DISCONNECT),0)

    def test_changed_ghost_session_id_or_valid_different_mac_stops_before_action(self):
        for changed in (dict(self.ghost,sessionId='new-fictional-id'),dict(self.ghost,mac='112233445566')):
            self.h=Harness();self.h.devices=[self.ghost,OTHER]
            c=self.login();self.h.list_responses=[[self.ghost,OTHER],[changed,OTHER]]
            with self.assertRaises(service.SelfServiceError):c.disconnect_current()
            self.assertEqual(self.h.count(service.DISCONNECT),0)

    def test_same_owner_is_required_across_both_fresh_reads(self):
        c=self.login();self.h.list_responses=[[self.ghost],[dict(self.ghost,userId=999)]]
        with self.assertRaises(service.AuthenticationError):c.disconnect_current()
        self.assertEqual(self.h.count(service.DISCONNECT),0)

    def test_expired_cached_proof_cannot_authorize_a_later_disconnect(self):
        c=self.login();c.select_current_session(c.list_online_devices())
        self.tick+=11
        with self.assertRaises(service.UnsupportedService):c.disconnect_current()
        self.assertEqual(self.h.count(service.DISCONNECT),0)
        self.assertEqual(len(self.nas_calls),1)

    def test_expiry_at_before_disconnect_callback_is_not_a_submission(self):
        c=self.login()
        with self.assertRaises(service.UnsupportedService):
            c.disconnect_current(before_disconnect=lambda:setattr(self,'tick',self.tick+11))
        self.assertEqual(self.h.count(service.DISCONNECT),0)
        self.assertEqual(c.safe_summary()['disconnect_requests'],0)

    def test_slow_tcp_setup_rechecks_ttl_before_sending_or_counting_action(self):
        c=self.login();original=c.connection_factory
        def factory(*args):
            conn=original(*args)
            conn.connect=lambda:setattr(self,'tick',self.tick+11)
            return conn
        c.connection_factory=factory
        with self.assertRaises(service.UnsupportedService):c.disconnect_current()
        self.assertEqual(self.h.count(service.DISCONNECT),0)
        self.assertEqual(c.safe_summary()['disconnect_requests'],0)

    def test_gateway_change_after_precheck_stops_precise_disconnect(self):
        current=[WIFI]
        c=self.login(reader=lambda:current[0],cleanup_reader=lambda:WIFI)
        with self.assertRaises(RuntimeError):
            c.disconnect_current(before_disconnect=lambda:current.__setitem__(0,replace(WIFI,gateway='10.61.42.1')))
        self.assertEqual(self.h.count(service.DISCONNECT),0)

    def test_same_ip_ghost_reappearing_after_removal_is_not_reported_offline(self):
        c=self.login();self.h.after_disconnect=[OTHER,dict(self.ghost,sessionId='reappeared-fictional-ghost')]
        result=c.disconnect_current()
        self.assertTrue(result['device_reappeared'])
        self.assertFalse(result['current_device_offline'])
        self.assertEqual(self.h.count(service.DISCONNECT),1)

    def test_nas_trace_contains_only_proof_type_and_boolean_not_private_fields(self):
        c=self.login();c.disconnect_current()
        traces=json.dumps(self.h.traces)
        for value in (nas_target(),WIFI.ip,WIFI.mac,'10.61.42.1','synthetic-nas-controller',OWN['sessionId']):
            self.assertNotIn(value,traces)
        events=[f for e,f in self.h.traces if e=='selfservice.binding_verified']
        self.assertTrue(events)
        self.assertTrue(all(f=={'proof_type':'nas_current_ip','verified':True} for f in events))


class DeviceListFormatTests(unittest.TestCase):
    def test_direct_array_only_and_critical_fields_are_required(self):
        invalid=[{'rows':[OWN]},[{}],[dict(OWN,sessionId=1)],[dict(OWN,ip=7)],
                 [dict(OWN,mac=3)],[dict(OWN,userId=True)],[dict(OWN,mac='not-a-mac')],
                 [dict(OWN,ip='0.0.0.0')],[OWN,copy.deepcopy(OWN)],
                 [OWN,dict(OTHER,userId=53)]]
        for data in invalid:
            with self.subTest(case=type(data).__name__),self.assertRaises(service.UnsupportedService):
                service.parse_online_devices(json.dumps(data))
        self.assertEqual(service.parse_online_devices('[]'),[])

    def test_duplicate_keys_nonfinite_and_control_session_ids_are_rejected(self):
        invalid=['[{"sessionId":"a","sessionId":"b"}]','[NaN]',
                 json.dumps([dict(OWN,sessionId='bad\r\nidentifier')])]
        for text in invalid:
            with self.assertRaises(service.UnsupportedService):service.parse_online_devices(text)


if __name__=='__main__':unittest.main()
