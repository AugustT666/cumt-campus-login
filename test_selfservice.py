"""Self-service uses synthetic HTML/JSON and a fake bound transport only."""
import copy
from dataclasses import replace
from pathlib import Path
import json
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

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
    def client(self,reader=None,cleanup_reader=None):
        return service.Client(WIFI,reader=reader or (lambda:WIFI),trace=self.trace,
                              connection_factory=self.factory,cleanup_reader=cleanup_reader,sleeper=lambda _:None)
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
