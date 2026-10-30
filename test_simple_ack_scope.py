"""A received reply is retained while bounded effect checks determine state.

All endpoints, identities and services are synthetic; socket access is denied
by the shared fixture. Context changes are represented by retained state only.
"""
from dataclasses import replace
import json

from test_logout_recovery import LogoutRecoveryFixture, ACCOUNT, PASSWORD


class SimpleReplyScopeTests(LogoutRecoveryFixture):
    def arrange_reply(self, operation, after_reply):
        if operation=='login':
            original=self.client.run_authentication.side_effect
            def authenticate(*args,**kwargs):
                reply=original(*args,**kwargs)
                after_reply()
                return reply
            self.client.run_authentication.side_effect=authenticate
        else:
            original=self.web.submit_current
            def submit(*args,**kwargs):
                reply=original(*args,**kwargs)
                after_reply()
                return reply
            self.web.submit_current=submit

    def action(self, operation):
        if operation=='login':
            return self.execute(lambda:self.client.login(ACCOUNT,PASSWORD,'campus','own-profile'))
        return self.logout()

    def status_read_failure_after_reply(self, operation, reply=True):
        after=[False]
        reads_at_reply=[]
        self.native_result=reply
        self.web.ack=reply
        def arrived():
            reads_at_reply.append(self.reader.call_count)
            after[0]=True
        self.arrange_reply(operation,arrived)
        def read():
            if after[0]:raise RuntimeError('Fictional native failure after a received reply')
            return self.current
        self.reader.side_effect=read
        self.assertTrue(self.action(operation)['ok'])
        self.assertGreater(self.reader.call_count,reads_at_reply[0])
        self.assertIs(self.client.auth_diagnostic['result'],reply)
        self.assertIs(self.client.auth_diagnostic['request_accepted'],reply)
        self.assertTrue(self.client.auth_diagnostic['response_context_current'])
        self.assertNotIn('Fictional native failure',self.client.status)
        self.assertFalse(self.client.logged_in)
        self.assertEqual(self.client.session_state,'unknown')
        self.assertNotIn('登录成功',self.client.status)
        self.assertNotIn('注销成功',self.client.status)
        self.assertNotIn('正在确认',self.client.status)

    def test_login_success_receipt_survives_unreadable_status_without_false_success(self):
        self.status_read_failure_after_reply('login')
        self.assertIn('无法确认',self.client.status)

    def test_selfservice_success_receipt_survives_unreadable_status_without_false_success(self):
        self.status_read_failure_after_reply('logout')
        self.assertIn('无法确认',self.client.status)
        self.assertEqual(self.client.logout_diagnostic['outcome'],'unknown')
        self.assertEqual(self.web.close_calls,1)
        self.assertEqual(self.web.summary['disconnect_requests'],1)

    def test_login_rejected_and_unknown_receipts_survive_failed_native_checks(self):
        for reply in (False,None):
            with self.subTest(reply=reply):
                self.status_read_failure_after_reply('login',reply)
                self.assertFalse(self.client.logged_in)
                # Restore the fixture's authentication callback for the next
                # explicit request rather than layering two reply observers.
                self.client.run_authentication.side_effect=lambda *a,**k:self.native_result
                self.reader.side_effect=lambda:self.current

    def changed_context_preserves_ack(self,operation):
        newer=replace(self.wifi,ip='10.61.55.10')
        def changed():
            self.current=newer
            self.client._observe_portal_network(newer)
            with self.client.lock:
                self.client.wifi=newer
                self.client.logged_in=True
                self.client.session_state='online'
                self.client.online_account='fictional-new-network-account'
                self.client.identity_source='request_ack'
                self.client.auth_key=newer.key
                self.client.status='Fictional current-network message'
        self.arrange_reply(operation,changed)
        self.action(operation)
        self.assertIs(self.client.auth_diagnostic['result'],True)
        self.assertIs(self.client.auth_diagnostic['request_accepted'],True)
        self.assertFalse(self.client.auth_diagnostic['response_context_current'])
        self.assertEqual(self.client.online_account,'fictional-new-network-account')
        self.assertTrue(self.client.logged_in)
        self.assertEqual(self.client.auth_key,newer.key)
        self.assertEqual(self.client.status,'Fictional current-network message')

    def test_old_login_reply_cannot_replace_new_network_identity(self):
        self.changed_context_preserves_ack('login')

    def test_old_logout_reply_cannot_mark_new_network_offline(self):
        self.changed_context_preserves_ack('logout')
        self.assertEqual(self.web.summary['disconnect_requests'],1)

    def closed_context_preserves_ack(self,operation):
        def closed():
            self.client.status='Fictional closing state'
            self.client.closed.set()
        self.arrange_reply(operation,closed)
        self.action(operation)
        self.assertIs(self.client.auth_diagnostic['result'],True)
        self.assertIs(self.client.auth_diagnostic['request_accepted'],True)
        self.assertFalse(self.client.auth_diagnostic['response_context_current'])
        self.assertEqual(self.client.status,'Fictional closing state')

    def test_login_ack_is_not_reversed_when_client_closes(self):
        self.closed_context_preserves_ack('login')

    def test_logout_ack_is_not_reversed_when_client_closes(self):
        self.closed_context_preserves_ack('logout')

    def test_management_cleanup_error_cannot_overwrite_accepted_logout(self):
        close=self.web.close
        def cleanup_error():
            close()
            raise RuntimeError('Fictional cleanup logging failure')
        self.web.close=cleanup_error
        self.logout()
        self.assertEqual(self.client.status,'注销成功')
        self.assertIs(self.client.auth_diagnostic['result'],True)
        self.assertIs(self.client.auth_diagnostic['request_accepted'],True)
        self.assertEqual(self.client.logout_diagnostic['outcome'],'confirmed_offline')
        self.assertEqual(self.web.summary['disconnect_requests'],1)

    def test_context_change_during_reply_sanitizing_cannot_publish_old_feedback(self):
        sanitize=self.log.sanitize
        changed=[False]
        def delayed_text(value,*args,**kwargs):
            if value=='登录成功' and not changed[0]:
                changed[0]=True
                newer=replace(self.wifi,ip='10.61.55.10')
                self.current=newer
                self.client._observe_portal_network(newer)
                with self.client.lock:
                    self.client.wifi=newer
                    self.client.status='Fictional current-network message'
                    self.client.session_state='unknown'
                    self.client.logged_in=False
            return sanitize(value,*args,**kwargs)
        self.log.sanitize=delayed_text
        self.action('login')
        self.assertTrue(changed[0])
        self.assertIs(self.client.auth_diagnostic['request_accepted'],True)
        self.assertFalse(self.client.auth_diagnostic['response_context_current'])
        self.assertEqual(self.client.status,'Fictional current-network message')
        self.assertFalse(self.client.logged_in)

    def test_superseded_operation_retains_reply_event_without_overwriting_new_diag(self):
        old_id=[]
        def superseded():
            old_id.append(self.client.operation_id)
            self.client.operation_id='fictional-newer-operation'
            self.client.operation='newer-action'
            self.client.auth_diagnostic={'marker':'newer-action-diagnostic'}
        self.arrange_reply('logout',superseded)
        self.logout()
        self.assertEqual(self.client.auth_diagnostic,{'marker':'newer-action-diagnostic'})
        self.log.flush()
        rows=[json.loads(line) for line in self.log.path.read_text(encoding='utf-8').splitlines()]
        receipt=next(row for row in rows if row['event']=='authentication.reply_received')
        self.assertEqual(receipt['operation_id'],old_id[0])
        self.assertIs(receipt['fields']['request_accepted'],True)
        self.assertFalse(receipt['fields']['response_context_current'])
