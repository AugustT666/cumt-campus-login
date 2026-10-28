"""Status diagnostics preserve ambiguity without retaining malformed values."""
import json
import unittest

import campus_core as core
import campus_protocol as protocol


WIFI=core.Wifi(core.TEC,'status-metadata-fixture',7,'10.61.22.9','00-11-22-33-44-55')


class StatusEvidenceMetadataTests(unittest.TestCase):
    def status(self,fields):
        engine=protocol.Engine(WIFI,'http://10.2.5.251/a79.htm',reader=lambda:WIFI,
            allow_tec=True,getter=lambda *args,**kwargs:(200,'',json.dumps(fields)))
        return engine.status()

    def test_reported_online_does_not_override_missing_device_evidence(self):
        report=self.status({'result':1,'v46ip':WIFI.ip,'ss5':WIFI.ip,
                            'olip':'10.88.22.7','olmac':'000000000000'})
        self.assertTrue(report['server_reported_online'])
        self.assertEqual(report['state'],'unknown')
        self.assertEqual(report['binding'],'conflict')
        self.assertTrue(report['server_mac_fields']['olmac']['present'])
        self.assertFalse(report['server_mac_fields']['olmac']['valid'])
        self.assertFalse(report['server_mac_fields']['ss4']['present'])

    def test_mac_metadata_distinguishes_missing_zero_and_invalid_without_raw_values(self):
        for value in ('', '000000000000', 'fictional-sensitive-invalid-value', None, 7, {}):
            with self.subTest(value=value):
                report=self.status({'result':1,'v46ip':WIFI.ip,'olmac':value})
                metadata=report['server_mac_fields']['olmac']
                self.assertTrue(metadata['present'])
                self.assertEqual(metadata['value_type'],type(value).__name__)
                self.assertFalse(metadata['valid'])
                self.assertNotIn('value',metadata)
                self.assertNotIn('fictional-sensitive-invalid-value',json.dumps(report))

    def test_requester_metadata_records_matches_and_validity_without_adopting_v4ip(self):
        report=self.status({'result':1,'v46ip':WIFI.ip,'ss5':WIFI.ip,'v4ip':'10.88.22.7',
                            'olip':'10.88.22.7'})
        self.assertTrue(report['requester_ip_fields']['v46ip']['matches_current'])
        self.assertTrue(report['requester_ip_fields']['v4ip']['valid'])
        self.assertFalse(report['requester_ip_fields']['v4ip']['matches_current'])
        self.assertEqual(report['state'],'unknown')

    def test_explicit_offline_remains_offline(self):
        report=self.status({'result':0,'v46ip':WIFI.ip})
        self.assertFalse(report['server_reported_online'])
        self.assertEqual(report['state'],'offline')


if __name__=='__main__':
    unittest.main()
