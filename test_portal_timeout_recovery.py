"""Keep complete portal routes through timeouts and release inconclusive ones.

Fictional URLs and accounts only. The shared fixture forbids real sockets and
credential storage, controls status observations, and advances a private clock.
"""
from dataclasses import replace
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, parse_qsl, urlencode, urlsplit
import json
import unittest

import campus_app as app
import campus_core as core
import campus_protocol as protocol
import campus_selfservice as service
from test_logout_recovery import LogoutRecoveryFixture, ACCOUNT, PASSWORD, online, offline, unknown


class PortalTimeoutRecoveryTests(LogoutRecoveryFixture):
    SSID = core.STU

    def setUp(self):
        super().setUp()
        self.seed_route()

    def full_url(self, wifi=None):
        wifi = self.wifi if wifi is None else wifi
        return 'http://' + core.KNOWN_HOST + '/a79.htm?' + urlencode({
            'wlanuserip': wifi.ip, 'mac': protocol._session_mac(wifi.mac).lower(),
            'wlanacname': 'Fictional-Access', 'nasip': '10.2.4.1'})

    def weak_url(self):
        return 'http://' + core.KNOWN_HOST + '/a79.htm?' + urlencode({
            'wlanuserip': self.wifi.ip, 'mac': self.wifi.mac})

    def seed_route(self, complete=True, portal=None):
        self.token = self.client._observe_portal_network(self.wifi)
        self.client.portal = portal or (self.full_url() if complete else self.weak_url())
        self.client.portal_key = self.wifi.key
        self.client._portal_discovered = True
        self.cached_engine = object()
        self.client._engine = self.cached_engine

    def arrange_reply(self, result=False, code='8', after_reply=None):
        self.client.run_authentication.reset_mock()
        def authenticate(*args, **kwargs):
            response = {'result': '1' if result is True else '0'}
            if code is not None:
                response['ret_code'] = code
            self.client.auth_diagnostic = {'operation': 'login', 'backend': 'fixture',
                'authentication_requests': 1, 'result': result, 'response': response}
            if after_reply:
                after_reply()
            return result
        self.client.run_authentication.side_effect = authenticate

    def login(self):
        return self.execute(lambda:self.client.login(ACCOUNT, PASSWORD, 'campus', 'own-profile'))

    def exercise(self, result, code, observation, *, complete=True):
        self.seed_route(complete)
        self.arrange_reply(result, code)
        self.probe_observation = observation
        with patch.object(core, 'discover', side_effect=AssertionError('No discovery after this submitted request')):
            self.assertTrue(self.login()['ok'])
        self.client.run_authentication.assert_called_once()
        self.assertIs(self.client.auth_diagnostic['result'], result)
        self.assertIs(self.client.auth_diagnostic['request_accepted'], result)
        self.assertTrue(self.client.auth_diagnostic['response_context_current'])
        self.assertEqual(self.client.auth_diagnostic['verified_state'], observation['state'])
        self.assertEqual(self.client._observe_portal_network(self.wifi), self.token)
        self.service_factory.assert_not_called()

    def assert_route_retained(self):
        self.assertIs(self.client._engine, self.cached_engine)
        self.assertEqual(self.client.portal_key, self.wifi.key)
        self.assertTrue(self.client._portal_discovered)
        self.assertFalse(self.client.auth_diagnostic.get('next_login_rediscovery', False))

    def assert_route_scheduled(self, backup=False):
        self.assertIsNone(self.client._engine)
        self.assertEqual(self.client.portal_key, self.wifi.key if backup else None)
        self.assertFalse(self.client._portal_discovered)
        self.assertTrue(self.client.auth_diagnostic['next_login_rediscovery'])
        self.assertIs(self.client.auth_diagnostic['access_context_retained'], backup)

    def test_complete_route_timeout_does_not_degrade_next_login_parameters(self):
        for observation in (offline(), unknown()):
            with self.subTest(state=observation['state']):
                self.exercise(False, '8', observation)
                self.assert_route_scheduled(backup=True)
                self.assertIn('Fictional-Access', self.client.portal)
                self.assertNotIn('登录成功', self.client.status)

    def test_weak_route_timeout_without_confirmed_account_is_released(self):
        for observation in (offline(), unknown()):
            with self.subTest(state=observation['state']):
                self.exercise(False, '8', observation, complete=False)
                self.assert_route_scheduled()

    def test_weak_route_timeout_keeps_verified_account_but_schedules_fresh_discovery(self):
        self.exercise(False, '8', online(), complete=False)
        self.assert_route_scheduled()
        self.assertTrue(self.client.logged_in)
        self.assertEqual(self.client.online_account, ACCOUNT)

    def test_already_online_reply_with_offline_or_unknown_effect_always_releases_route(self):
        for complete in (True, False):
            for observation in (offline(), unknown()):
                with self.subTest(complete=complete, state=observation['state']):
                    self.exercise(False, '2', observation, complete=complete)
                    self.assert_route_scheduled(backup=complete)
                    self.assertFalse(self.client.logged_in)

    def test_already_online_with_weak_unbound_identity_releases_route(self):
        report = dict(online(), binding='source_ip_only', online_account='', server_mac='')
        self.exercise(False, '2', report, complete=False)
        self.assert_route_scheduled()
        self.assertEqual(self.client.online_account, '')
        self.assertNotIn('登录成功', self.client.status)

    def test_already_online_with_complete_route_and_unbound_identity_can_be_retained(self):
        report = dict(online(), binding='source_ip_only', online_account='', server_mac='')
        self.exercise(False, '2', report)
        self.assert_route_retained()
        self.assertEqual(self.client.online_account, '')

    def test_already_online_with_strong_current_device_binding_can_keep_weak_route(self):
        for account in (ACCOUNT, 'fictional-different-online-account'):
            with self.subTest(account_matches=account == ACCOUNT):
                self.exercise(False, '2', dict(online(), online_account=account), complete=False)
                self.assert_route_retained()
                self.assertEqual(self.client.online_account, account)

    def test_accepted_or_unknown_receipt_with_weak_unconfirmed_route_is_released(self):
        for result in (True, None):
            for observation in (offline(), unknown(), dict(online(), binding='source_ip_only', online_account='')):
                with self.subTest(result=result, state=observation['state']):
                    self.exercise(result, None, observation, complete=False)
                    self.assert_route_scheduled()

    def test_accepted_or_unknown_receipt_with_complete_route_is_not_discarded(self):
        for result in (True, None):
            with self.subTest(result=result):
                self.exercise(result, None, unknown())
                self.assert_route_retained()

    def test_weak_fallback_is_allowed_when_this_account_is_really_verified_online(self):
        # The observed recovery after a wait succeeded on a weak URL. Do not
        # turn the quality check into a blanket ban on that supported fallback.
        for result in (True, None):
            with self.subTest(result=result):
                self.exercise(result, None, online(), complete=False)
                self.assert_route_retained()
                self.assertTrue(self.client.logged_in)
                self.assertEqual(self.client.online_account, ACCOUNT)

    def test_hard_rejection_keeps_existing_next_click_recovery(self):
        self.exercise(False, '1', offline())
        self.assert_route_scheduled()
        self.assertIn('登录失败', self.client.status)

    def next_click_rediscovers(self, first_complete):
        self.client.portal = ''
        self.client.portal_key = None
        self.client._portal_discovered = False
        self.client._engine = None
        first = self.full_url() if first_complete else self.weak_url()
        second = self.full_url().replace('Fictional-Access', 'Fictional-Fresh-Access')
        engines = []
        def factory(wifi, portal, **kwargs):
            engine = MagicMock()
            engine.wifi, engine.portal = wifi, portal
            accepted = bool(engines)
            response = {'result': '1'} if accepted else {'result': '0', 'ret_code': '2'}
            engine.authenticate.return_value = (accepted, {'operation': 'login',
                'authentication_requests': 1, 'result': accepted, 'response': response})
            engines.append(engine)
            return engine
        self.client.run_authentication.side_effect = lambda *a, **k:app.App.run_authentication(self.client, *a, **k)
        self.probe_observation = offline()
        with patch.object(core, 'discover', side_effect=[(first, 'Fictional first page'),
                                                       (second, 'Fictional fresh page')]) as discovery, \
             patch.object(protocol, 'Engine', side_effect=factory):
            self.assertTrue(self.login()['ok'])
            self.assertEqual(discovery.call_count, 1)
            self.assertEqual(len(engines), 1)
            engines[0].authenticate.assert_called_once()
            self.assertIs(self.client.auth_diagnostic['request_accepted'], False)
            self.assertEqual(self.client.session_state, 'offline')
            self.assertFalse(self.client._portal_discovered)
            self.probe_observation = online()
            self.assertTrue(self.login()['ok'])
            self.assertEqual(discovery.call_count, 2)
            self.assertEqual(len(engines), 2)
            engines[1].authenticate.assert_called_once()
        self.assertEqual(self.client.run_authentication.call_count, 2)
        self.assertEqual(self.client.portal, second)
        self.assertTrue(self.client._portal_discovered)
        self.assertTrue(self.client.logged_in)

    def test_ret2_offline_restarts_discovery_on_next_explicit_click_from_complete_route(self):
        self.next_click_rediscovers(True)

    def test_ret2_offline_restarts_discovery_on_next_explicit_click_from_weak_route(self):
        self.next_click_rediscovers(False)

    def after_timeout_rediscovers(self, candidate, expected):
        self.exercise(False, '8', offline())
        self.assert_route_scheduled(backup=True)
        original_portal = self.client.portal
        engine = MagicMock()
        engine.wifi, engine.portal = self.wifi, expected
        engine.authenticate.return_value = (True, {'operation':'login','authentication_requests':1,
            'result':True,'response':{'result':'1','msg':'Fictional accepted reply'}})
        self.client.run_authentication.side_effect = lambda *a, **k:app.App.run_authentication(self.client, *a, **k)
        self.probe_observation = online()
        with patch.object(core, 'discover', return_value=(candidate, 'Fictional rediscovery')) as discovery, \
             patch.object(protocol, 'Engine', return_value=engine) as factory:
            self.assertTrue(self.login()['ok'])
        discovery.assert_called_once()
        factory.assert_called_once()
        self.assertEqual(factory.call_args.args[1], expected)
        engine.authenticate.assert_called_once()
        self.assertEqual(self.client.run_authentication.call_count, 2)
        self.assertEqual(self.client.portal, expected)
        self.assertTrue(self.client.logged_in)
        self.assertIs(self.client.auth_diagnostic['request_accepted'], True)
        return original_portal

    def test_timeout_rediscovery_does_not_replace_complete_context_with_weaker_same_endpoint(self):
        original = self.full_url()
        self.after_timeout_rediscovers(self.weak_url(), original)

    def test_timeout_rediscovery_prefers_a_new_complete_route_over_the_old_backup(self):
        fresh = self.full_url().replace('Fictional-Access', 'Fictional-New-Access').replace('10.2.4.1', '10.2.4.2')
        self.after_timeout_rediscovers(fresh, fresh)

    def test_timeout_rediscovery_does_not_reuse_backup_across_page_paths(self):
        fresh = self.weak_url().replace('/a79.htm', '/different.htm')
        self.after_timeout_rediscovers(fresh, fresh)

    def test_timeout_backup_cannot_hide_a_new_host_confirmation(self):
        self.exercise(False, '8', offline())
        fresh = self.weak_url().replace(core.KNOWN_HOST, '10.2.5.250')
        self.client.run_authentication.side_effect = lambda *a, **k:app.App.run_authentication(self.client, *a, **k)
        with patch.object(core, 'discover', return_value=(fresh, 'Fictional new host')) as discovery, \
             patch.object(protocol, 'Engine') as factory:
            self.assertTrue(self.login()['ok'])
        discovery.assert_called_once()
        factory.assert_not_called()
        self.assertEqual(self.client.pending_host, '10.2.5.250')
        self.assertEqual(urlsplit(self.client.portal).hostname, '10.2.5.250')
        self.assertEqual(self.client.auth_diagnostic['authentication_requests'], 0)

    def test_same_key_gateway_change_invalidates_a_preserved_complete_backup(self):
        self.exercise(False, '8', offline())
        changed = replace(self.wifi, gateway='10.61.55.2')
        self.current = changed
        self.client.wifi = changed
        fresh = self.weak_url()
        engine = MagicMock()
        engine.wifi, engine.portal = changed, fresh
        with patch.object(core, 'discover', return_value=(fresh, 'Fictional changed gateway')), \
             patch.object(protocol, 'Engine', return_value=engine):
            selected = self.client.session_engine(changed, self.SSID == core.TEC, discover=True)
        self.assertIs(selected, engine)
        self.assertEqual(self.client.portal, fresh)
        self.assertGreater(self.client._portal_route_generation, self.token[1])

    def test_same_key_reconnection_generation_cannot_reuse_preserved_backup(self):
        self.exercise(False, '8', offline())
        self.client.notifications = MagicMock()
        self.client.notifications.drain.return_value = [(10, self.wifi.guid)]
        fresh = self.weak_url()
        engine = MagicMock()
        engine.wifi, engine.portal = self.wifi, fresh
        with patch.object(core, 'discover', return_value=(fresh, 'Fictional reconnected network')), \
             patch.object(protocol, 'Engine', return_value=engine):
            selected = self.client.session_engine(self.wifi, self.SSID == core.TEC, discover=True)
        self.assertIs(selected, engine)
        self.assertEqual(self.client.portal, fresh)
        self.assertGreater(self.client._portal_route_generation, self.token[1])

    def test_complete_access_context_check_is_read_only_and_not_nas_proof(self):
        with patch.object(core, 'read_wifi', side_effect=AssertionError('Quality check must not read WLAN')), \
             patch.object(core, 'discover', side_effect=AssertionError('Quality check must not discover')):
            self.assertTrue(self.client._portal_access_context_complete(self.wifi))
        client = service.SelfServiceClient(self.wifi, reader=lambda:self.wifi)
        client._authenticated, client._owner_id = True, 1
        row = service.DeviceSession('fictional-zero-mac-session', self.wifi.ip, '', 1)
        with patch.object(service, 'observe_nas_binding', side_effect=service.UnsupportedService('Synthetic missing original NAS proof')) as observe:
            with self.assertRaises(service.UnsupportedService):
                client.select_current_session([row])
        observe.assert_called_once()
        self.assertEqual(client.safe_summary()['disconnect_requests'], 0)

    def test_missing_or_invalid_access_fields_do_not_count_as_complete_context(self):
        good = list(parse_qsl(urlsplit(self.full_url()).query))
        for key in ('wlanacname', 'nasip', 'wlanuserip', 'mac'):
            for value in (None, '', ' '):
                with self.subTest(key=key, value=value):
                    pairs = [(k, v) for k, v in good if k != key]
                    if value is not None:
                        pairs.append((key, value))
                    self.client.portal = 'http://' + core.KNOWN_HOST + '/a79.htm?' + urlencode(pairs)
                    self.assertFalse(self.client._portal_access_context_complete(self.wifi))
        for key, value in (('nasip', 'not-an-ip'), ('nasip', '0.0.0.0'),
                           ('wlanuserip', '10.61.55.10'), ('mac', '66778899AABB'),
                           ('mac', '000000000000')):
            with self.subTest(key=key, value=value):
                self.client.portal = 'http://' + core.KNOWN_HOST + '/a79.htm?' + urlencode(
                    [(k, value if k == key else v) for k, v in good])
                self.assertFalse(self.client._portal_access_context_complete(self.wifi))

    def test_duplicate_binding_fields_do_not_count_as_complete_context(self):
        good = list(parse_qsl(urlsplit(self.full_url()).query))
        for key, value in good:
            with self.subTest(key=key):
                self.client.portal = 'http://' + core.KNOWN_HOST + '/a79.htm?' + urlencode([*good, (key, value)])
                self.assertFalse(self.client._portal_access_context_complete(self.wifi))

    def assert_changed_context_stops_before_authentication_submission(self, **changes):
        self.seed_route()
        sent = []
        def changed(*args, **kwargs):
            self.current = replace(self.wifi, **changes)
            args[-1]()
            sent.append(True)
            return True
        self.client.run_authentication.side_effect = changed
        self.login()
        self.assertEqual(sent, [])
        self.assertEqual(self.client.auth_diagnostic['authentication_requests'], 0)
        self.assertNotIn('登录成功', self.client.status)
        self.assertFalse(self.client._portal_discovered)
        self.assertIsNone(self.client._engine)

    def test_changed_mac_cannot_reuse_the_retained_access_context(self):
        self.assert_changed_context_stops_before_authentication_submission(mac='66-77-88-99-AA-BB')

    def test_changed_ip_cannot_reuse_the_retained_access_context(self):
        self.assert_changed_context_stops_before_authentication_submission(ip='10.61.55.10')

    def test_changed_gateway_cannot_reuse_the_retained_access_context(self):
        self.assert_changed_context_stops_before_authentication_submission(gateway='10.61.55.2')

    def test_wlan_notification_generation_cannot_reuse_an_old_access_context(self):
        sent = []
        def disconnected(*args, **kwargs):
            self.client.notifications = MagicMock()
            self.client.notifications.drain.return_value = [(20, self.wifi.guid)]
            args[-1]()
            sent.append(True)
            return True
        self.client.run_authentication.side_effect = disconnected
        self.login()
        self.assertEqual(sent, [])
        self.assertEqual(self.client.auth_diagnostic['authentication_requests'], 0)
        self.assertGreater(self.client._portal_route_generation, self.token[1])
        self.assertFalse(self.client._portal_discovered)
        self.assertIsNone(self.client._engine)

    def test_late_timeout_cannot_clear_a_newly_observed_network_route(self):
        newer = replace(self.wifi, ip='10.61.55.10')
        replacement_engine = object()
        def changed(*args, **kwargs):
            self.current = newer
            self.client._observe_portal_network(newer)
            self.client.wifi = newer
            self.client.portal = self.full_url(newer)
            self.client.portal_key = newer.key
            self.client._portal_discovered = True
            self.client._engine = replacement_engine
            self.client.status = 'Fictional newer-network feedback'
            return offline()
        self.arrange_reply(False, '8')
        self.bounded_probe.side_effect = changed
        self.login()
        self.assertIs(self.client.auth_diagnostic['request_accepted'], False)
        self.assertFalse(self.client.auth_diagnostic['response_context_current'])
        self.assertIs(self.client._engine, replacement_engine)
        self.assertEqual(self.client.portal_key, newer.key)
        self.assertTrue(self.client._portal_discovered)
        self.assertEqual(self.client.status, 'Fictional newer-network feedback')

    def test_soft_timeout_keeps_original_lowercase_mac_spelling_in_the_native_request(self):
        self.wifi = replace(self.wifi, mac='AA-BB-CC-DD-EE-FF')
        self.current = self.wifi
        self.client.wifi = self.wifi
        portal = self.full_url()
        self.seed_route(portal=portal)
        self.probe_observation = offline()
        requests = []
        def getter(url, *args, **kwargs):
            query = parse_qs(urlsplit(url).query)
            requests.append(query)
            return 200, '', query['callback'][0] + '(' + json.dumps({'result':'0', 'ret_code':'8', 'msg':''}) + ')'
        engine = protocol.Engine(self.wifi, portal, reader=lambda:self.current,
                                 allow_tec=self.wifi.ssid == core.TEC, getter=getter)
        engine.prepare = lambda:{'login_method':'1', 'endpoint':'http://' + core.KNOWN_HOST + ':801/eportal/',
            'ac_ip':'', 'ac_name':'Fictional-Access', 'js_version':'fixture', 'operators':{'campus':''},
            'has_operator_select':self.wifi.student, 'ac_logout':'0', 'ipv6':'', 'vlan':'0', 'page_index':2}
        self.cached_engine = engine
        self.client._engine = engine
        self.client.run_authentication.side_effect = lambda *a, **k:app.App.run_authentication(self.client, *a, **k)
        with patch.object(core, 'discover', side_effect=AssertionError('The complete cached route must survive')):
            self.login()
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0]['wlan_user_mac'], ['aabbccddeeff'])
        self.assertIs(self.client.auth_diagnostic['request_accepted'], False)
        self.assert_route_scheduled(backup=True)
        self.assertEqual(parse_qs(urlsplit(self.client.portal).query)['mac'], ['aabbccddeeff'])


class TeacherPortalTimeoutRecoveryTests(PortalTimeoutRecoveryTests):
    SSID = core.TEC


if __name__ == '__main__':
    unittest.main()
