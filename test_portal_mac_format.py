"""Keep a matching NAS-issued MAC spelling without trusting another adapter."""
from dataclasses import replace
import unittest
from urllib.parse import parse_qs, urlsplit

import campus_core as core
import campus_protocol as protocol


WIFI=core.Wifi(core.TEC,'fictional-mac-format-interface',7,'10.61.22.8',
               'AA-BB-CC-DD-EE-FF','10.61.22.1')
PORTAL='http://'+core.KNOWN_HOST+'/a79.htm'


class PortalMacFormatTests(unittest.TestCase):
    def test_matching_original_nas_case_survives_multiple_refreshes(self):
        url=PORTAL+'?wlanuserip='+WIFI.ip+'&mac=aabbccddeeff'
        for _ in range(3):url=core.fresh_url(url,WIFI)
        self.assertEqual(parse_qs(urlsplit(url).query)['mac'],['aabbccddeeff'])

    def test_other_adapter_mac_is_replaced(self):
        url=core.fresh_url(PORTAL+'?mac=001122334455',WIFI)
        self.assertEqual(parse_qs(urlsplit(url).query)['mac'],[WIFI.mac])

    def test_invalid_or_zero_mac_is_replaced(self):
        for value in ('000000000000','not-a-device','aabbccddeeff00'):
            with self.subTest(value=value):
                url=core.fresh_url(PORTAL+'?mac='+value,WIFI)
                self.assertEqual(parse_qs(urlsplit(url).query)['mac'],[WIFI.mac])

    def test_reconnect_with_different_mac_cannot_reuse_original_spelling(self):
        new=replace(WIFI,mac='11-22-33-44-55-66')
        url=core.fresh_url(PORTAL+'?mac=aabbccddeeff',new)
        self.assertEqual(parse_qs(urlsplit(url).query)['mac'],[new.mac])

    def test_native_login_and_logout_send_the_original_case(self):
        for alias in ('mac','wlanusermac','wlan_user_mac'):
            for operation in ('login','logout'):
                with self.subTest(alias=alias,operation=operation):
                    sent=[]
                    def getter(url,*args,**kwargs):
                        sent.append(parse_qs(urlsplit(url).query))
                        return 200,'','{"result":1}'
                    engine=protocol.Engine(WIFI,PORTAL+'?'+alias+'=aabbccddeeff',
                        reader=lambda:WIFI,allow_tec=True,getter=getter)
                    engine.prepare=lambda:{'login_method':'1','endpoint':'http://'+core.KNOWN_HOST+':801/eportal/',
                        'ac_ip':'','ac_name':'fictional-ac','js_version':'fixture','operators':{},
                        'has_operator_select':False,'ac_logout':'0','ipv6':'','vlan':'1','page_index':3}
                    result,trace=engine.authenticate('fictional-user','fictional-secret','',operation)
                    self.assertTrue(result)
                    self.assertEqual(trace['authentication_requests'],1)
                    self.assertEqual(len(sent),1)
                    self.assertEqual(sent[0]['wlan_user_mac'],['aabbccddeeff'])


if __name__=='__main__':unittest.main()
