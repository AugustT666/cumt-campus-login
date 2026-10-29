"""Bridge and state polling stay responsive when native/profile I/O stalls.

All network access is prohibited by the shared synthetic fixture. Real threads
and events exercise the lock boundaries that instant mocked reads cannot cover.
"""
import threading
import time
import types
from unittest.mock import patch

import campus_app as app
from test_logout_recovery import LogoutRecoveryFixture, ACCOUNT, PASSWORD, offline, online


class UIResponsivenessTests(LogoutRecoveryFixture):
    def real_jobs(self):
        self.client.start_job=types.MethodType(app.App.start_job,self.client)

    def poll_state_while_blocked(self):
        done=threading.Event()
        state={}
        def read():
            state.update(self.client.get_state())
            done.set()
        thread=threading.Thread(target=read)
        thread.start()
        self.assertTrue(done.wait(.3),'get_state waited behind a slow I/O operation')
        thread.join(1)
        return state

    def wait_job(self):
        deadline=time.perf_counter()+3
        while self.client.busy and time.perf_counter()<deadline:
            threading.Event().wait(.01)
        self.assertFalse(self.client.busy,'synthetic job did not finish')

    def blocked_native_bridge(self,kind):
        self.real_jobs()
        entered=threading.Event()
        release=threading.Event()
        main=threading.get_ident()
        def native_read():
            if threading.get_ident()!=main and not release.is_set():
                entered.set()
                release.wait(3)
            return self.current
        self.reader.side_effect=native_read
        try:
            requested=(self.client.login(ACCOUNT,PASSWORD,'campus','own-profile')
                       if kind=='login' else self.client.logout())
            self.assertTrue(requested['ok'])
            self.assertTrue(entered.wait(1))
            state=self.poll_state_while_blocked()
            self.assertTrue(state['busy'])
            self.assertEqual(state['operation'],kind)
            self.assertFalse(self.client.lock._is_owned())
        finally:
            release.set()
            self.wait_job()

    def test_login_bridge_returns_before_native_wlan_preflight(self):
        self.blocked_native_bridge('login')

    def test_logout_bridge_returns_before_native_wlan_preflight(self):
        self.blocked_native_bridge('logout')

    def test_profile_encryption_or_disk_stall_does_not_hold_state_lock(self):
        self.real_jobs()
        self.client.save_profile=types.MethodType(app.App.save_profile,self.client)
        self.enterContext(patch.object(self.client,'startup_enabled',return_value=False))
        entered=threading.Event()
        release=threading.Event()
        def save(*args):
            self.assertFalse(self.client.lock._is_owned())
            entered.set()
            release.wait(3)
        self.store.save_profile.side_effect=save
        try:
            self.assertTrue(self.client.login(ACCOUNT,PASSWORD,'campus','own-profile')['ok'])
            self.assertTrue(entered.wait(1))
            self.assertTrue(self.poll_state_while_blocked()['busy'])
        finally:
            release.set()
            self.wait_job()


    def test_blocked_log_writer_does_not_block_state_polling(self):
        self.client.get_state()
        entered=threading.Event()
        release=threading.Event()
        def writer():
            with self.log._lock:
                entered.set()
                release.wait(3)
        thread=threading.Thread(target=writer)
        try:
            thread.start()
            self.assertTrue(entered.wait(1))
            self.assertEqual(self.poll_state_while_blocked()['version'],app.core.VERSION)
        finally:
            release.set()
            thread.join(3)

    def test_state_snapshot_remains_available_during_legacy_state_lock_io(self):
        expected=self.client.get_state()
        entered=threading.Event()
        release=threading.Event()
        def old_operation():
            with self.client.lock:
                entered.set()
                release.wait(3)
        thread=threading.Thread(target=old_operation)
        try:
            thread.start()
            self.assertTrue(entered.wait(1))
            self.assertEqual(self.poll_state_while_blocked(),expected)
        finally:
            release.set()
            thread.join(3)

    def test_login_and_logout_bridges_do_not_queue_behind_another_state_holder(self):
        self.real_jobs()
        entered=threading.Event()
        release=threading.Event()
        results=[]
        def other_operation():
            with self.client.lock:
                entered.set()
                release.wait(3)
        holder=threading.Thread(target=other_operation)
        done=threading.Event()
        def request():
            results.append(self.client.login(ACCOUNT,PASSWORD,'campus','own-profile'))
            results.append(self.client.logout())
            done.set()
        requester=threading.Thread(target=request)
        try:
            holder.start()
            self.assertTrue(entered.wait(1))
            requester.start()
            self.assertTrue(done.wait(.3),'bridge requests waited for another state holder')
            self.assertEqual([result['ok'] for result in results],[False,False])
        finally:
            release.set()
            holder.join(3)
            requester.join(3)
