"""Short device checks: synthetic responses, no credential store or campus I/O."""
from dataclasses import replace
import json
import unittest
from unittest.mock import patch

import campus_core as core
import campus_selfservice as service
import campus_status as status


WIFI=core.Wifi(core.STU,'short-status-fixture',9,'10.52.42.8',
               '00-11-22-33-44-55','10.52.42.1')
OWN=service.DeviceSession('fictional-own-session',WIFI.ip,'001122334455',1)
OTHER=service.DeviceSession('fictional-other-session','10.52.42.9','66778899AABB',1)


class Clock:
    def __init__(self):self.now=10.0
    def __call__(self):return self.now
    def sleep(self,delay):self.now+=delay


def report(state,**changes):
    d={'state':state,'binding':'source_ip_only','matched_ip':True,
       'mac_conflict':False,'ip_conflict':False,'detail':'server_confirmed',
       'online_account':'','identity_hint':''}
    d.update(changes);return d


class FakeResponse:
    def __init__(self,fields,status_code=200,location=''):
        self.status=status_code;self.body=json.dumps(fields).encode();self.location=location
    def read(self,limit):return self.body[:limit]
    def getheaders(self):return [('Content-Type','application/json')]
    def getheader(self,key,default=''):return self.location if key=='Location' else default
    def close(self):pass


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(core,'Store',side_effect=AssertionError('No credential store')))
        self.enterContext(patch.object(status.socket,'getaddrinfo',side_effect=AssertionError('No DNS')))
        self.fields={'result':0,'v46ip':WIFI.ip}
        self.conn=self.enterContext(patch.object(status,'DeadlineHTTP')).return_value
        self.conn.getresponse.side_effect=lambda:FakeResponse(self.fields)

    def run_probe(self,reader=None):
        return status.probe(WIFI,reader or (lambda:WIFI))

    def test_explicit_offline_uses_only_one_read_only_status_request(self):
        r=self.run_probe()
        self.assertEqual(r['state'],'offline');self.assertTrue(r['verification_performed'])
        self.assertEqual(r['source'],'portal_query')
        self.conn.request.assert_called_once()
        args=self.conn.request.call_args.args
        self.assertEqual(args[0],'GET');self.assertTrue(args[1].startswith('/drcom/chkstatus?'))
        self.assertNotIn('password',args[1]);self.conn.close.assert_called_once()

    def test_mac_verified_online_keeps_server_identity(self):
        self.fields.update(result=1,olip=WIFI.ip,olmac='001122334455',uid='fictional-server-account')
        r=self.run_probe()
        self.assertEqual(r['state'],'online');self.assertEqual(r['binding'],'mac_verified')
        self.assertEqual(r['online_account'],'fictional-server-account')

    def test_source_ip_echo_does_not_invent_confirmed_account(self):
        self.fields.update(result=1,olip=WIFI.ip,uid='fictional-unverified-account')
        r=self.run_probe()
        self.assertEqual(r['state'],'online');self.assertEqual(r['online_account'],'')
        self.assertEqual(r['identity_hint'],'')

    def test_ghost_or_other_device_is_unknown_and_never_exposes_its_identity(self):
        for mac in ('000000000000','66778899AABB'):
            self.fields.update(result=1,olip='10.52.99.2',olmac=mac,uid='fictional-other-account')
            r=self.run_probe()
            self.assertEqual(r['state'],'unknown');self.assertEqual(r['online_account'],'')

    def test_network_changes_during_read_reject_the_result(self):
        reads=iter((WIFI,replace(WIFI,mac='66-77-88-99-AA-BB')))
        r=self.run_probe(lambda:next(reads))
        self.assertEqual(r['state'],'unknown');self.assertEqual(r['detail'],'network_context_changed')

    def test_timeout_is_unknown_and_is_not_retried(self):
        self.conn.getresponse.side_effect=TimeoutError('fictional timeout')
        r=self.run_probe()
        self.assertEqual(r['state'],'unknown');self.conn.request.assert_called_once()

    def test_non_200_response_is_not_online(self):
        self.conn.getresponse.side_effect=lambda:FakeResponse({'result':1,'v46ip':WIFI.ip},500)
        self.assertEqual(self.run_probe()['state'],'unknown')


class WireSocket:
    def __init__(self,clock,wire,step=0):
        self.clock,self.wire,self.step=clock,bytearray(wire),step
        self.timeouts=[];self.closed=False;self.bound=None;self.destination=None
    def settimeout(self,value):self.timeout=value;self.timeouts.append(value)
    def setsockopt(self,*args):pass
    def bind(self,address):self.bound=address
    def connect(self,address):self.destination=address
    def sendall(self,data):pass
    def recv_into(self,target):
        if self.closed:raise OSError('fictional closed socket')
        if self.step>self.timeout:
            self.clock.sleep(self.timeout);raise TimeoutError('fictional bounded read')
        self.clock.sleep(self.step)
        n=min(len(target),1 if self.step else len(self.wire),len(self.wire))
        target[:n]=self.wire[:n];del self.wire[:n]
        return n
    def close(self):self.closed=True


class DeadlineTransportTests(unittest.TestCase):
    def test_slow_trickled_headers_share_absolute_timeout(self):
        clock=Clock();sock=WireSocket(clock,b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}',.1)
        with patch.object(status.socket,'socket',return_value=sock), \
             patch.object(status.socket,'getaddrinfo',side_effect=AssertionError('No DNS')):
            conn=status.DeadlineHTTP('10.2.5.251',80,WIFI,deadline=10.45,clock=clock)
            try:
                conn.request('GET','/drcom/chkstatus')
                with self.assertRaises(TimeoutError):conn.getresponse()
            finally:conn.close()
        self.assertLessEqual(clock(),10.45+.0001)
        self.assertEqual(sock.bound,(WIFI.ip,0));self.assertEqual(sock.destination,('10.2.5.251',80))
        self.assertTrue(sock.closed)
        self.assertLess(sock.timeouts[-1],sock.timeouts[0])

    def test_connection_close_header_does_not_close_body_reader_early(self):
        clock=Clock();sock=WireSocket(clock,b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}')
        with patch.object(status.socket,'socket',return_value=sock):
            conn=status.DeadlineHTTP('10.2.5.251',80,WIFI,deadline=11,clock=clock)
            conn.request('GET','/drcom/chkstatus');response=conn.getresponse()
            self.assertEqual(response.read(),b'{}')
            response.close();conn.close()
        self.assertTrue(sock.closed)

    def test_hostname_is_rejected_before_any_dns_or_socket(self):
        with patch.object(status.socket,'socket') as sock, \
             patch.object(status.socket,'getaddrinfo') as dns:
            with self.assertRaises(ValueError):
                status.DeadlineHTTP('fictional.example',80,WIFI,deadline=20,clock=lambda:10)
        sock.assert_not_called();dns.assert_not_called()

    def test_selfservice_factory_shares_total_limit_and_per_connection_limit(self):
        clock=Clock();factory=status.connection_factory(10.3,clock=clock)
        conn=factory('202.119.196.6',8080,WIFI)
        self.assertAlmostEqual(conn.timeout,.3)
        clock.sleep(.31)
        with self.assertRaises(TimeoutError):factory('202.119.196.6',8080,WIFI)


class NasGetterTests(unittest.TestCase):
    def setUp(self):
        self.clock=Clock()
        self.enterContext(patch.object(status.time,'monotonic',self.clock))
        self.transport=self.enterContext(patch.object(status,'DeadlineHTTP'))
        self.conn=self.transport.return_value
        self.raw_target='http://10.2.5.251/a79.htm?wlanuserip=10.52.42.8&mac=001122334455&wlanacname=fixture&nasip=10.52.42.1'
        self.conn.getresponse.return_value=FakeResponse({},302,self.raw_target)
        self.get=status.nas_getter(11.5,timeout=1)

    def test_raw_redirect_is_preserved_without_following_or_rewriting(self):
        seen=[]
        r=self.get('http://9.9.9.9/',WIFI,lambda:seen.append(True) or WIFI)
        self.assertEqual(r,(302,self.raw_target,'{}'))
        self.assertEqual(len(seen),2)
        self.conn.request.assert_called_once()
        self.assertEqual(self.conn.request.call_args.args,('GET','/'))
        self.conn.close.assert_called_once()
        self.assertEqual(self.transport.call_args.args,('9.9.9.9',80,WIFI))

    def test_arbitrary_host_query_credentials_and_changed_seed_are_rejected(self):
        urls=('http://9.9.9.9/?account=fictional','http://u:p@9.9.9.9/',
              'http://9.9.9.9:80/','https://9.9.9.9/','http://1.1.1.1/#fragment',
              'http://10.2.5.251/','http://untrusted.invalid/','http://1.1.1.1/other')
        for url in urls:
            with self.subTest(url=url),self.assertRaises(ValueError):
                self.get(url,WIFI,lambda:WIFI)
        self.transport.assert_not_called()

    def test_expired_budget_stops_before_transport(self):
        self.clock.sleep(2)
        with self.assertRaises(TimeoutError):self.get('http://1.1.1.1/',WIFI,lambda:WIFI)
        self.transport.assert_not_called()

    def test_per_request_budget_is_capped_by_shared_deadline(self):
        self.clock.sleep(1)
        self.get('http://1.1.1.1/',WIFI,lambda:WIFI)
        self.assertAlmostEqual(self.transport.call_args.kwargs['deadline'],11.5)

    def test_changed_device_before_or_after_response_blocks_binding(self):
        changed=replace(WIFI,mac='66-77-88-99-AA-BB')
        with self.assertRaises(RuntimeError):self.get('http://9.9.9.9/',WIFI,lambda:changed)
        self.transport.assert_not_called()
        snapshots=iter((WIFI,replace(WIFI,gateway='10.52.42.2')))
        with self.assertRaises(RuntimeError):self.get('http://9.9.9.9/',WIFI,lambda:next(snapshots))
        self.conn.close.assert_called_once()

    def test_teacher_network_requires_explicit_allow_and_hotspot_stays_blocked(self):
        tec=replace(WIFI,ssid=core.TEC)
        with self.assertRaises(RuntimeError):self.get('http://9.9.9.9/',tec,lambda:tec)
        self.transport.assert_not_called()
        self.get('http://9.9.9.9/',tec,lambda:tec,allow_tec=True)
        hotspot=replace(WIFI,ssid='Fictional hotspot')
        with self.assertRaises(RuntimeError):self.get('http://1.1.1.1/',hotspot,lambda:hotspot,allow_tec=True)

    def test_oversized_raw_and_decoded_bodies_are_rejected(self):
        self.conn.getresponse.return_value.body=b'x'*(status.MAX_STATUS_BYTES+1)
        with self.assertRaises(ValueError):self.get('http://1.1.1.1/',WIFI,lambda:WIFI)
        self.conn.getresponse.return_value.body=b'{}'
        with patch.object(core,'decode_http_body',return_value=(b'x'*(status.MAX_STATUS_BYTES+1),{})):
            with self.assertRaises(ValueError):self.get('http://1.1.1.1/',WIFI,lambda:WIFI)

    def test_response_arriving_after_deadline_is_not_binding_evidence(self):
        response=self.conn.getresponse.return_value
        def late_response():self.clock.sleep(1.1);return response
        self.conn.getresponse.side_effect=late_response
        with self.assertRaises(TimeoutError):self.get('http://1.1.1.1/',WIFI,lambda:WIFI)
        self.conn.request.assert_called_once();self.conn.close.assert_called_once()


class LogoutConfirmationTests(unittest.TestCase):
    def setUp(self):
        self.clock=Clock()
        self.enterContext(patch.object(status.time,'monotonic',self.clock))
        self.enterContext(patch.object(status.time,'sleep',self.clock.sleep))
        self.probe=self.enterContext(patch.object(status,'probe',return_value=report('offline')))
        self.enterContext(patch.object(core,'Store',side_effect=AssertionError('No credentials')))
        self.enterContext(patch.object(service.SelfServiceClient,'login',side_effect=AssertionError('No management login')))
        self.enterContext(patch.object(service.SelfServiceClient,'submit_current',side_effect=AssertionError('No mutation')))

    def confirm(self,rows=None,**kwargs):
        callback=(lambda:rows) if rows is not None else None
        return status.confirm_logout(WIFI,lambda:WIFI,list_devices=callback,session_id=OWN.session_id,**kwargs)

    def test_repeated_device_offline_and_target_absence_confirm_logout(self):
        r=self.confirm([OTHER])
        self.assertEqual(r['outcome'],'confirmed_offline');self.assertEqual(r['state'],'offline')
        self.assertGreaterEqual(r['elapsed_ms'],600);self.assertLess(r['elapsed_ms'],1500)
        self.assertGreaterEqual(len(r['samples']),2)
        self.assertNotIn(OWN.session_id,json.dumps(r))

    def test_a_transient_offline_sample_never_confirms_logout(self):
        n=[0]
        def transient(*args,**kwargs):
            n[0]+=1;return report('offline' if n[0]<=2 else 'online')
        self.probe.side_effect=transient
        r=self.confirm([OTHER],timeout=1.2)
        self.assertNotEqual(r['outcome'],'confirmed_offline')

    def test_account_absence_alone_does_not_prove_device_offline(self):
        self.probe.return_value=report('online')
        r=self.confirm([],timeout=1)
        self.assertEqual(r['outcome'],'unknown');self.assertEqual(r['state'],'unknown')

    def test_target_or_reappeared_mac_session_prevents_success(self):
        rebound=replace(OWN,session_id='fictional-rebound-session',ip='10.52.43.8')
        for rows in ([OWN,OTHER],[rebound,OTHER]):
            with self.subTest(rebound=rows[0]!=OWN):
                r=self.confirm(rows,timeout=1)
                self.assertNotEqual(r['outcome'],'confirmed_offline')
                self.assertEqual(r['device_presence'],'present')

    def test_last_consistent_online_sample_reports_still_online(self):
        self.probe.return_value=report('online')
        r=self.confirm([OWN,OTHER],timeout=1)
        self.assertEqual(r['outcome'],'still_online');self.assertEqual(r['state'],'online')

    def test_valid_other_mac_on_current_ip_is_conflicting_not_offline(self):
        other=replace(OTHER,ip=WIFI.ip)
        r=self.confirm([other],timeout=1)
        self.assertEqual(r['outcome'],'unknown');self.assertEqual(r['device_presence'],'conflict')

    def test_unbound_current_ip_record_prevents_offline_confirmation(self):
        ghost=replace(OWN,session_id='fictional-unbound-session',mac='')
        r=self.confirm([ghost],timeout=1)
        self.assertEqual(r['outcome'],'unknown');self.assertEqual(r['device_presence'],'unbound_present')

    def test_failed_list_read_does_not_turn_portal_offline_into_success(self):
        def unavailable():raise TimeoutError('fictional list deadline')
        r=status.confirm_logout(WIFI,lambda:WIFI,list_devices=unavailable,timeout=1)
        self.assertEqual(r['outcome'],'unknown');self.assertEqual(r['device_presence'],'unavailable')

    def test_context_change_stops_before_account_list_read(self):
        self.probe.return_value=report('unknown',detail='network_context_changed')
        def forbidden():raise AssertionError('Stale-network list read')
        r=status.confirm_logout(WIFI,lambda:WIFI,list_devices=forbidden,timeout=1)
        self.assertEqual(r['outcome'],'unknown');self.probe.assert_called_once()

    def test_one_shared_deadline_is_passed_to_every_probe(self):
        self.probe.return_value=report('online')
        self.confirm([OWN],timeout=1.2)
        deadlines={c.kwargs['deadline'] for c in self.probe.call_args_list}
        self.assertEqual(deadlines,{11.2})
        self.assertLessEqual(self.clock(),11.2+.0001)


if __name__=='__main__':unittest.main()
