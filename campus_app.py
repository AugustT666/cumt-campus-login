"""Windows campus client: selected DPAPI profile, one STU attempt per connection."""
import argparse
import ctypes
import datetime as dt
import json
import hashlib
import http.client
import os
import platform
from pathlib import Path
import re
import sys
import threading
import time
import tempfile
import uuid
import winreg
from urllib.parse import urlsplit, urlunsplit
import campus_core as core
import campus_protocol as protocol
import campus_network
import campus_selfservice as selfservice
from campus_logging import RuntimeLog

ROOT = Path(getattr(sys, '_MEIPASS', Path(__file__).parent))
TITLE = '矿大校园网登录器'
EXPERIMENTAL = bool(getattr(core,'EXPERIMENTAL_BUILD',False) or '--experimental' in sys.argv)
APP_USER_MODEL_ID = 'AugustT666.CumtCampusLogin' + ('.Experimental' if EXPERIMENTAL else '')
STARTUP_VALUE_NAME = 'CumtCampusLoginExperimental' if EXPERIMENTAL else 'CumtCampusLogin'
STABLE_STARTUP_VALUE_NAME = 'CumtCampusLogin'
STABLE_INSTANCE_MUTEX = r'Local\CumtCampusLoginDesktopV1'
LOGOUT_ROUTE_TTL = 300.0
LOGOUT_AUTO_HOLD = 60.0
LOGOUT_CONFIRM_TIMEOUT = 20.0
LOGOUT_STABLE_SECONDS = 5.0
LOGOUT_SESSION_LOOKUP_TIMEOUT = 45.0
LOGOUT_PORTAL_STABLE_SECONDS = 65.0
LOGOUT_PORTAL_SETTLE_SECONDS = 10.0


class LogoutContextUnavailable(RuntimeError):
    """No verified AC route is available; no portal logout was submitted."""


def stable_autostart_configured():
    """Read the stable Run value without changing either client's settings."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r'Software\Microsoft\Windows\CurrentVersion\Run') as key:
            value, kind = winreg.QueryValueEx(key, STABLE_STARTUP_VALUE_NAME)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise RuntimeError('暂时无法检查稳定版自动启动配置，试用版自动登录已停止；请稍后重试或手动登录。') from exc
    return kind in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) and isinstance(value, str) and bool(value.strip())


def stable_instance_running():
    """Check the stable instance's existing named mutex; never create one."""
    try:
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.OpenMutexW.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_wchar_p]
        kernel.OpenMutexW.restype = ctypes.c_void_p
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle.restype = ctypes.c_int
        ctypes.set_last_error(0)
        handle = kernel.OpenMutexW(0x00100000, False, STABLE_INSTANCE_MUTEX)
        if handle:
            kernel.CloseHandle(handle)
            return True
        error = ctypes.get_last_error()
        if error == 2:  # ERROR_FILE_NOT_FOUND: no stable instance object exists.
            return False
        if error == 5:  # Access denied still proves the named object exists.
            return True
        raise OSError(error, 'Cannot inspect the stable instance mutex')
    except OSError as exc:
        raise RuntimeError('暂时无法检查稳定版运行状态，试用版自动登录已停止；请稍后重试或手动登录。') from exc

class Bridge:
    def __init__(self, app): self._app = app
    def boot(self): return self._app.boot()
    def get_state(self): return self._app.get_state()
    def refresh_status(self): return self._app.refresh_status()
    def network_check(self): return self._app.network_check()
    def set_startup(self, enabled): return self._app.set_startup(enabled)
    def login(self, account, password, operator, profile_id='', quiet_override=False):
        return self._app.login(account,password,operator,profile_id,quiet_override=quiet_override)
    def save_profile(self, profile_id, account, password, operator):
        return self._app.save_profile(profile_id,account,password,operator)
    def select_profile(self, profile_id): return self._app.select_profile(profile_id)
    def delete_profile(self, profile_id): return self._app.delete_profile(profile_id)
    def logout(self): return self._app.logout()
    def trust_portal(self): return self._app.trust_portal()
    def save_hint(self, hint): return self._app.save_hint(hint)
    def diagnostic(self): return self._app.diagnostic()
    def quit(self): return self._app.quit()

LOGOUT_JS = r'''() => {
 const visible=e=>e.getClientRects().length&&!e.disabled;
 const controls=Array.from(document.querySelectorAll('button,input[type="submit"],input[type="button"],a')).filter(visible);
 const buttons=controls.filter(e=>/^(注销|注销登录|退出|退出登录|断开|下线|logout)$/i.test((e.innerText||e.value||'').replace(/\s+/g,'')));
 if(buttons.length!==1) return false;
 buttons[0].setAttribute('data-cumt-logout-button','1'); return true;
}'''

LOGOUT_CONFIRM_JS = r'''() => {
 const visible=e=>e&&e.getClientRects().length&&!e.disabled;
 const dialogs=Array.from(document.querySelectorAll('.boxy-wrapper,[role="dialog"],dialog[open]')).filter(visible);
 const confirmations=dialogs.filter(e=>/确定注销|确认注销|确认退出|确定退出|logout/i.test(e.innerText.replace(/\s+/g,'')));
 if(confirmations.length!==1) return false;
 const buttons=Array.from(confirmations[0].querySelectorAll('button,input[type="button"],input[type="submit"]')).filter(visible);
 const yes=buttons.filter(e=>/^(确认|确定|是|ok|yes|confirm)$/i.test((e.innerText||e.value||'').replace(/\s+/g,'')));
 if(yes.length!==1) return false;
 yes[0].setAttribute('data-cumt-logout-confirm','1'); return true;
}'''

def authentication_result(text, url, operation):
    """Recognize only explicit portal responses, never a generic HTTP 200."""
    p=urlsplit(url)
    query=dict(core.parse_qsl(p.query))
    requested=str(query.get('a','')).casefold() or p.path.rstrip('/').split('/')[-1].casefold()
    if requested!=operation:
        return None
    data=protocol.parse_jsonp(text)
    return protocol._result(data) if data is not None else None


def student_auth_time_notice(wifi, now=None):
    """Describe the published weekly schedule without guessing server errors."""
    now = now or dt.datetime.now()
    if not wifi.student or not core.quiet_hours(now):
        return ''
    resume = '今日' if now.hour < 7 else '次日'
    return ('当前处于学生网络常规不可认证时间（周日至周四23:30—次日07:00），'
            f'预计{resume}07:00恢复；节假日以学校安排为准。')


class App:
    def __init__(self, startup=False, runtime_log=None):
        self.store=core.Store()
        self.runtime_log=runtime_log or RuntimeLog(self.store.root,core.VERSION,
                                                   metadata={'platform':platform.platform(),'frozen':bool(getattr(sys,'frozen',False))})
        self.operation_id=''
        self.settings=self.store.load()
        # Only the new explicitly enabled setting may trigger authentication.
        self.settings.update(auto_enabled=False,auto_submit=False)
        self.settings.setdefault('stu_autostart',False)
        self.auto_attempted=False
        self.show_event=None
        self.notifications=None
        self.reconnecting=set()
        self.profile_error=''
        self.wifi=core.Wifi()
        self.window=None
        self.closed=threading.Event()
        self.cancel=threading.Event()
        self.lock=threading.RLock()
        self.busy=False
        self.operation=''
        self.auto_job=False
        self.logged_in=False
        self.status='请连接校园 WiFi 后登录'
        self.messages=[]
        self.portal=''
        self.portal_key=None
        self.pending_host=''
        self.session_cookies=[]
        self.auth_key=None
        self.auth_diagnostic={}
        self.session_diagnostic={}
        self.network_diagnostic={}
        self.unconfirmed_connectivity={}
        self.logout_diagnostic={}
        self._logout_watch=None
        self._logout_recovery_needed=False
        self.session_state='unknown'
        self.online_account=''
        self.identity_source=''
        self.session_checked_at=''
        self.session_checked_key=None
        self.session_checked_monotonic=0.0
        self._engine=None
        self._portal_discovered=False
        self.last_job_elapsed_ms=0
        self.startup=startup
        self.message('客户端已就绪')

    def record(self,event,level='INFO',operation_id=None,**fields):
        log=getattr(self,'runtime_log',None)
        if log is not None:
            identifier=operation_id if operation_id is not None else getattr(self,'operation_id','')
            exc=fields.pop('_exception',None)
            if isinstance(exc,BaseException):
                log.exception(event,exc,operation_id=identifier,**fields)
            else:
                log.event(event,level=level,operation_id=identifier,**fields)

    def record_exception(self,event,exc,**fields):
        log=getattr(self,'runtime_log',None)
        if log is not None:
            log.exception(event,exc,operation_id=getattr(self,'operation_id',''),**fields)

    def register_secrets(self,*values):
        log=getattr(self,'runtime_log',None)
        if log is not None:log.register_secrets(*values)

    def message(self,text):
        log=getattr(self,'runtime_log',None)
        if log is not None:text=log.sanitize(str(text))
        with self.lock:
            self.status=str(text)
            self.messages.append({'time':dt.datetime.now().strftime('%H:%M:%S'),'text':str(text)})
            self.messages=self.messages[-60:]
        self.record('app.message',text=str(text))

    def login_failure_message(self, text, wifi=None):
        notice=student_auth_time_notice(wifi or self.wifi)
        return notice+' '+text if notice and notice not in text else text

    def stu_automation_enabled(self):
        """The displayed authorization and every automatic action share one value."""
        return self.settings.get('stu_autostart',False) is True

    def boot(self):
        try:
            data=self.store.profiles()
            for item in data['profiles']:
                self.register_secrets(item.get('account',''),item.get('password',''))
            self.profile_error=''
        except RuntimeError as exc:
            self.record_exception('profiles.read_error',exc)
            data={'selected':'','profiles':[]}
            self.profile_error=str(exc)
        selected=next((p for p in data['profiles'] if p['id']==data['selected']),{})
        return {'version':core.VERSION,'account':selected.get('account',''),'password':selected.get('password',''),
                'operator':selected.get('operator',''),'selected':data['selected'],
                'profiles':[{'id':p['id'],'account':p['account']} for p in data['profiles']],
                'startup':self.stu_automation_enabled(),'startup_registered':self.startup_enabled(),
                'portal_hint':self.settings.get('portal_hint',''),'profile_error':self.profile_error,
                'settings_warning':getattr(self.store,'settings_warning','')
                    if isinstance(getattr(self.store,'settings_warning',''),str) else ''}

    def save_profile(self,profile_id,account,password,operator):
        self.register_secrets(str(account),str(password))
        self.record('profiles.save_requested',profile_id=str(profile_id),operator=operator)
        with self.lock:
            if self.busy: return {'ok':False,'message':'正在登录，请稍后修改账号。'}
            if not str(account).strip() or not str(password): return {'ok':False,'message':'请输入账号和密码。'}
            if operator not in ('','telecom','unicom','cmcc','campus'):
                return {'ok':False,'message':'请选择有效的登录网络。'}
            try:
                self.store.save_profile(str(profile_id),str(account).strip(),str(password),operator)
                return {'ok':True,'data':self.boot()}
            except (OSError,RuntimeError) as exc:
                self.record_exception('profiles.save_error',exc)
                return {'ok':False,'message':str(exc)}

    def select_profile(self,profile_id):
        self.record('profiles.select_requested',profile_id=str(profile_id))
        with self.lock:
            if self.busy: return {'ok':False,'message':'正在登录，请稍后切换账号。'}
            try:
                self.store.select_profile(str(profile_id))
                return {'ok':True,'data':self.boot()}
            except (OSError,RuntimeError) as exc:
                self.record_exception('profiles.select_error',exc)
                return {'ok':False,'message':str(exc)}

    def delete_profile(self,profile_id):
        self.record('profiles.delete_requested',profile_id=str(profile_id))
        with self.lock:
            if self.busy: return {'ok':False,'message':'正在登录，请稍后修改账号。'}
            try:
                self.store.delete_profile(str(profile_id))
                return {'ok':True,'data':self.boot()}
            except (OSError,RuntimeError) as exc:
                self.record_exception('profiles.delete_error',exc)
                return {'ok':False,'message':str(exc)}

    def get_state(self):
        with self.lock:
            log=getattr(self,'runtime_log',None)
            return {'version':core.VERSION,'ssid':self.wifi.ssid,'ip':self.wifi.ip,'campus':self.wifi.campus,
                    'student':self.wifi.student,'busy':self.busy,'operation':self.operation,
                    'logged_in':self.logged_in,'status':self.status,'pending_host':self.pending_host,
                    'session_state':getattr(self,'session_state','unknown'),
                    'session_conflict':(getattr(self,'session_checked_key',None)==self.wifi.key
                        and self.session_binding_conflict(getattr(self,'session_diagnostic',{}))),
                    'logout_recovery_needed':bool(getattr(self,'_logout_recovery_needed',False)),
                    'online_account':getattr(self,'online_account','') if getattr(self,'session_state','unknown')=='online' else '',
                    'identity_source':getattr(self,'identity_source',''),
                    'session_binding':getattr(self,'session_diagnostic',{}).get('binding','unconfirmed'),
                    'session_checked_at':getattr(self,'session_checked_at',''),
                    'last_job_elapsed_ms':getattr(self,'last_job_elapsed_ms',0),
                    'quiet_hours_active':bool(self.settings.get('quiet_hours',True) is True
                                              and student_auth_time_notice(self.wifi)),
                    'logging_error':(str(log.write_error) or getattr(log,'location_warning','')) if log is not None else ''}

    @staticmethod
    def _portal_network_context(wifi):
        # Wifi.key intentionally remains compatible with existing session/UI
        # code. Routing also depends on the NIC MAC and current gateway.
        mac=re.sub(r'[-:]','',str(wifi.mac or '')).strip().casefold()
        return (wifi.key,mac,str(wifi.gateway or ''))

    def _invalidate_logout_route(self,reason):
        with self.lock:
            self._portal_route_generation=getattr(self,'_portal_route_generation',0)+1
            self._verified_logout_route=None
            self.portal_key=None
            self._portal_discovered=False
            self._engine=None
            self.record('portal.route_invalidated',reason=reason,
                        generation=self._portal_route_generation)

    def _observe_portal_network(self,wifi):
        with self.lock:
            context=self._portal_network_context(wifi)
            previous=getattr(self,'_observed_portal_network',None)
            if previous is not None and previous!=context:
                self._invalidate_logout_route('network_context_changed')
            self._observed_portal_network=context
            return (context,getattr(self,'_portal_route_generation',0))

    def _assert_portal_route(self,wifi,expected):
        with self.lock:
            if (self._portal_network_context(wifi),getattr(self,'_portal_route_generation',0))!=expected:
                raise RuntimeError('无线连接上下文已改变，已停止本次操作；未重用旧接入设备参数。')

    @staticmethod
    def _rich_ac_fields(plan):
        return bool(str(plan.get('ac_name') or '').strip()
                    or protocol._session_ip(plan.get('ac_ip')))

    @staticmethod
    def _logout_discovery_hint(hint):
        if not hint:
            return ''
        core.portal_origin(hint)
        parts=urlsplit(hint)
        routing={'wlanacip','acip','wlanacname','sysname','vlan','vlanid'}
        pairs=[(key,value) for key,value in core.parse_qsl(parts.query,keep_blank_values=True)
               if key.casefold() not in routing]
        return urlunsplit((parts.scheme,parts.netloc,parts.path,core.urlencode(pairs),''))

    def _current_logout_route(self,wifi):
        with self.lock:
            cached=getattr(self,'_verified_logout_route',None)
            if not isinstance(cached,dict):
                return None
            token=(self._portal_network_context(wifi),getattr(self,'_portal_route_generation',0))
            age=time.monotonic()-cached['checked_at']
            hint_hash=hashlib.sha256(str(self.settings.get('portal_hint','')).encode('utf-8')).hexdigest()
            if (cached.get('context')!=token or not 0<=age<=LOGOUT_ROUTE_TTL
                    or cached.get('hint_hash')!=hint_hash or self.portal_key!=wifi.key
                    or not getattr(self,'_portal_discovered',False)):
                self._verified_logout_route=None
                return None
            return cached

    def session_engine(self,wifi,tec,discover=False,for_logout=False):
        """Cache no credentials; a new connection/IP always gets fresh context."""
        with self.lock:
            if getattr(self,'notifications',None):
                self.consume_notifications()
        token=self._observe_portal_network(wifi)
        hint=self.settings.get('portal_hint','')
        if for_logout:
            cached=self._current_logout_route(wifi)
            if cached:
                self.portal=core.fresh_url(cached['portal'],wifi)
                self.portal_key=wifi.key
                self._portal_discovered=True
            elif tec:
                # While already online, public probes can return no captive
                # redirect. A bare page is not proof of the correct NAS route.
                discover=True
                self.portal_key=None
                self._portal_discovered=False
                self._engine=None
                hint=self._logout_discovery_hint(hint)
        if discover and (self.portal_key!=wifi.key or not getattr(self,'_portal_discovered',False)):
            self.record('portal.discovery_started',wifi=core.asdict(wifi))
            portal,_=core.discover(wifi,hint,
                                   reader=lambda:self.checked_wifi(wifi,tec),allow_tec=tec)
            self._assert_portal_route(wifi,token)
            self.portal=portal
            self.portal_key=wifi.key
            self._portal_discovered=True
            self._engine=None
            self.record('portal.discovery_completed',portal=self.portal)
        elif self.portal_key!=wifi.key or not self.portal:
            hint=self.settings.get('portal_hint','') or f'http://{core.KNOWN_HOST}/a79.htm'
            self.portal=core.fresh_url(hint,wifi)
            self.portal_key=wifi.key
            self._portal_discovered=False
            self._engine=None
        if urlsplit(self.portal).hostname not in self.settings['trusted_hosts']:
            self.record('portal.confirmation_required',level='WARNING',portal=self.portal)
            self.pending_host=urlsplit(self.portal).hostname
            raise RuntimeError('请确认新的认证服务器地址')
        engine=getattr(self,'_engine',None)
        if engine is None or engine.wifi.key!=wifi.key or engine.portal!=self.portal:
            def current_route():
                current=self.checked_wifi(wifi,tec)
                self._assert_portal_route(wifi,token)
                return current
            engine=protocol.Engine(wifi,self.portal,reader=current_route,allow_tec=tec)
            self._engine=engine
        return engine

    def apply_session(self,wifi,report,announce=False):
        core.guard(wifi,core.read_wifi(),wifi.ssid.casefold()==core.TEC.casefold())
        with self.lock:
            if self.closed.is_set() or self.cancel.is_set(): raise RuntimeError('本次操作已停止。')
            state=report.get('state','unknown')
            self.session_state=state if state in ('online','offline') else 'unknown'
            self.logged_in=self.session_state=='online'
            self.online_account=str(report.get('online_account','')) if self.logged_in else ''
            self.identity_source='server' if self.online_account else ''
            self.register_secrets(self.online_account)
            self.auth_key=wifi.key if self.logged_in else None
            self.session_checked_key=wifi.key
            self.session_checked_monotonic=time.monotonic()
            self.session_checked_at=dt.datetime.now().strftime('%H:%M:%S')
            self.session_diagnostic=dict(report)
            self.record('session.result',wifi=core.asdict(wifi),result=report)
            if self.session_state=='offline' and self._logout_auto_suppressed(wifi):
                self._logout_watch['saw_offline']=True
            if announce:
                if self.session_state=='online' and self._logout_auto_suppressed(wifi):
                    self._logout_recovery_needed=True
                    reappeared=self._logout_watch.get('saw_offline',False)
                    self.logout_diagnostic['outcome']='session_reappeared' if reappeared else 'still_online'
                    self.record('logout.session_reappeared',elapsed_ms=round(
                        (time.monotonic()-self._logout_watch['started'])*1000))
                    self.message(('注销后服务器再次报告本机在线' if reappeared else '注销仍未确认，服务器继续报告本机在线')
                                 +'，本程序未重新登录；请从“自助服务”核对本机会话。')
                    return
                self.message({'online':'当前无线网已登录，可直接注销',
                              'offline':'当前无线网未登录',
                              'unknown':self.status_failure_message(report,'暂时无法确认登录状态，请先刷新。')}[self.session_state])

    @staticmethod
    def session_binding_conflict(report):
        return (isinstance(report,dict) and report.get('state')=='unknown'
                and (report.get('binding')=='conflict' or report.get('detail') in
                     ('session_ip_mismatch','session_mac_mismatch','status_ip_mismatch')))

    @staticmethod
    def status_failure_message(report,fallback):
        error=report.get('network_error')
        detail=error.get('message','') if isinstance(error,dict) else ''
        if App.session_binding_conflict(report):
            detail=('学校返回的设备会话信息与本机不一致。请打开“自助服务”核对本人的在线设备，'
                    '如有本人的旧连接，可下线后再刷新状态。')
        return (str(detail)+' '+fallback).strip() if detail else fallback

    def refresh_status(self):
        self.record('session.refresh_requested')
        try:
            wifi,tec=self.permitted(logout=True)
        except RuntimeError as exc:
            self.record_exception('session.refresh_rejected',exc)
            return {'ok':False,'message':str(exc)}
        def job():
            self.session_checked_key=wifi.key
            self.session_checked_monotonic=time.monotonic()
            self.message('正在检查登录状态…')
            self.wifi=wifi
            engine=self.session_engine(wifi,tec)
            self.apply_session(wifi,engine.status(),announce=True)
        return self.start_job('status',job)

    def network_check(self):
        self.record('network.check_requested')
        try:
            wifi,tec=self.permitted(logout=True)
        except RuntimeError as exc:
            self.record_exception('network.check_rejected',exc)
            return {'ok':False,'message':str(exc)}
        def job():
            self.wifi=wifi
            self.message('正在检查连接，仅建立测试连接，不发送认证请求…')
            report=campus_network.run_check(wifi,reader=lambda:self.checked_wifi(wifi,tec))
            self.network_diagnostic=report
            self.record('network.check_result',report=report)
            self.message(report['summary'])
        return self.start_job('network_check',job)

    def run_authentication(self,wifi,account,password,operator,operation,tec,check_allowed):
        engine=self.session_engine(wifi,tec,discover=operation=='login',for_logout=operation=='logout')
        token=(self._portal_network_context(wifi),getattr(self,'_portal_route_generation',0))
        def guarded_submit():
            check_allowed()
            self._assert_portal_route(wifi,token)
        try:
            began=time.perf_counter()
            if operation=='logout' and tec:
                try:
                    route=protocol._portal_parameters(engine.portal)
                    rich=self._rich_ac_fields({'ac_name':route.get('wlanacname'),
                                              'ac_ip':route.get('wlanacip')})
                except (ValueError,protocol.UnsupportedPortal):
                    rich=False
                if not rich:
                    self.auth_diagnostic={'operation':'logout','backend':'status_only',
                        'phase':'logout_context_missing','authentication_requests':0}
                    raise LogoutContextUnavailable('当前教师网缺少可核验的接入设备参数，未发送门户注销请求。')
            plan=engine.prepare()
            guarded_submit()
            if operation=='logout' and tec and str(plan.get('login_method'))=='1' and not self._rich_ac_fields(plan):
                self.auth_diagnostic={'operation':'logout','backend':'status_only',
                    'phase':'logout_context_missing','authentication_requests':0}
                raise LogoutContextUnavailable('当前教师网缺少可核验的接入设备参数，未发送门户注销请求。')
            if self._rich_ac_fields(plan):
                with self.lock:
                    self._assert_portal_route(wifi,token)
                    self._verified_logout_route={'context':token,'portal':engine.portal,
                        'checked_at':time.monotonic(),'hint_hash':hashlib.sha256(
                            str(self.settings.get('portal_hint','')).encode('utf-8')).hexdigest()}
            self.record('authentication.plan_ready',backend='verified_drcom_http',operation=operation,
                        elapsed_ms=round((time.perf_counter()-began)*1000))
            result,trace=engine.authenticate(account,password,operator,operation,before_submit=guarded_submit)
        except protocol.UnsupportedPortal as exc:
            self.record_exception('authentication.browser_fallback',exc,operation=operation)
            # A fallback is allowed only before any authentication request.
            result=self.authenticate(wifi,account,password,operator,operation,tec)
            self.auth_diagnostic['backend']='browser'
            self.record('authentication.result',diagnostic=self.auth_diagnostic)
            return result
        trace['backend']='verified_drcom_http'
        log=getattr(self,'runtime_log',None)
        if log is not None:trace=log.sanitize(trace)
        self.auth_diagnostic=trace
        self.record('authentication.result',diagnostic=trace)
        if result is False:
            detail=(trace.get('response') or {}).get('msg') or (trace.get('response') or {}).get('message')
            if detail: self.message('认证提示：'+detail)
        return result

    def check_internet_later(self,wifi,tec):
        """External probes never hold up an explicit authentication success."""
        def run():
            try:
                with core.trace_scope(lambda event,level='DEBUG',**fields:self.record(event,level=level,**fields)):
                    result=core.internet_check(wifi,reader=lambda:self.checked_wifi(wifi,tec),allow_tec=tec)
                self.record('internet.result',result=result,wifi=core.asdict(wifi))
            except Exception as exc:
                self.record_exception('internet.check_error',exc)
                return
            with self.lock:
                if self.closed.is_set() or self.busy or not self.logged_in or self.auth_key!=wifi.key:
                    return
                self.message('已登录，网络连接正常' if result['online'] else '已登录，外网连接尚未确认')
        threading.Thread(target=run,daemon=True).start()

    def check_unconfirmed_internet_later(self,wifi,tec):
        """Record connectivity separately from an unconfirmed device session."""
        operation_id=getattr(self,'operation_id','')
        def current_operation():
            with self.lock:
                if (self.closed.is_set() or self.cancel.is_set()
                        or getattr(self,'operation_id','')!=operation_id or self.wifi.key!=wifi.key):
                    raise RuntimeError('本次网络探测已停止或结果已过期。')
                return self.checked_wifi(wifi,tec)
        def run():
            try:
                current_operation()
                with core.trace_scope(lambda event,level='DEBUG',**fields:
                        self.record(event,level=level,operation_id=operation_id,**fields)):
                    result=core.internet_check(wifi,reader=current_operation,allow_tec=tec)
                with self.lock:
                    current_operation()
                    self.unconfirmed_connectivity={'operation_id':operation_id,
                        'checked_at':dt.datetime.now().isoformat(timespec='seconds'),
                        'authentication_accepted':True,'result':result}
                    self.record('internet.unconfirmed_result',operation_id=operation_id,result=result)
            except Exception as exc:
                self.record('internet.unconfirmed_check_error',level='WARNING',
                            operation_id=operation_id,_exception=exc)
        threading.Thread(target=run,daemon=True).start()

    def startup_enabled(self):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,r'Software\Microsoft\Windows\CurrentVersion\Run') as key:
                value,_=winreg.QueryValueEx(key,STARTUP_VALUE_NAME)
                return str(sys.executable if getattr(sys,'frozen',False) else Path(__file__).resolve()).casefold() in value.casefold()
        except OSError:
            return False

    def _ensure_exclusive_auto(self):
        if not EXPERIMENTAL:
            return
        if stable_autostart_configured():
            raise RuntimeError('检测到稳定版启动项配置，试用版自动登录已停止；请先在稳定版关闭自动启动或清理旧启动配置，也可使用手动登录。')
        if stable_instance_running():
            raise RuntimeError('稳定版正在运行，试用版自动登录已停止；请退出稳定版后重试，或使用手动登录。')

    def set_startup(self,enabled):
        with self.lock:
            return self._set_startup(enabled)

    def _set_startup(self,enabled):
        if type(enabled) is not bool:
            return {'ok':False,'message':'自动启动设置无效，请重新选择。'}
        self.record('startup.setting_requested',enabled=enabled)
        if enabled and EXPERIMENTAL:
            try:
                if stable_autostart_configured():
                    self.record('startup.coexistence_blocked',level='WARNING',reason='stable_autostart')
                    return {'ok':False,'message':'检测到稳定版启动项配置。请先在稳定版关闭“连接校园网（CUMT_Stu/CUMT_Tec）时自动弹出”或清理旧启动配置，再启用试用版；退出旧窗口不会取消其开机启动。'}
            except RuntimeError as exc:
                self.record_exception('startup.coexistence_check_error',exc)
                return {'ok':False,'message':str(exc)}
        try:
            current=core.read_wifi() if enabled else self.wifi
            updated=dict(self.settings,stu_autostart=enabled)
            self.store.write_settings(updated)
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER,r'Software\Microsoft\Windows\CurrentVersion\Run') as key:
                if enabled:
                    if getattr(sys,'frozen',False):
                        command='"'+sys.executable+'" --startup'
                    else:
                        command='"'+sys.executable+'" "'+str(Path(__file__).resolve())+'" --startup'
                    if EXPERIMENTAL:command+=' --experimental'
                    winreg.SetValueEx(key,STARTUP_VALUE_NAME,0,winreg.REG_SZ,command)
                else:
                    try: winreg.DeleteValue(key,STARTUP_VALUE_NAME)
                    except FileNotFoundError: pass
            self.settings=updated
            # Enabling while already connected does not submit unexpectedly.
            if enabled and current.campus:
                self.auto_attempted=True
                self._stu_popup_connection=(current.ssid.casefold(),current.guid,current.index)
                self._stu_popup_pending=False
                self._stu_popup_reset_pending=False
            if not enabled:
                self._stu_popup_pending=False
            if not enabled and self.busy and self.auto_job: self.cancel.set()
            return {'ok':True}
        except OSError as exc:
            self.record_exception('startup.setting_error',exc)
            self.store.write_settings(self.settings)
            return {'ok':False,'message':'无法保存自动启动设置，请稍后重试。'}

    def save_hint(self,hint):
        with self.lock:
            return self._save_hint(hint)

    def _save_hint(self,hint):
        self.record('portal.hint_requested',url=str(hint))
        try:
            hint=str(hint).strip()
            if hint:
                core.portal_origin(hint)
                p=urlsplit(hint)
                pairs=[(k,v) for k,v in core.parse_qsl(p.query,keep_blank_values=True) if k.casefold() not in core.SENSITIVE_KEYS]
                hint=urlunsplit((p.scheme,p.netloc,p.path,core.urlencode(pairs),''))
            self.settings['portal_hint']=hint
            self.store.write_settings(self.settings)
            self.portal_key=None
            return {'ok':True}
        except (ValueError,OSError) as exc:
            self.record_exception('portal.hint_error',exc)
            return {'ok':False,'message':'请输入有效的校内认证页面地址。'}

    def trust_portal(self):
        with self.lock:
            return self._trust_portal()

    def _trust_portal(self):
        self.record('portal.confirm_requested',host=self.pending_host)
        try:
            current=core.read_wifi()
            if current.key!=self.portal_key or not current.ready or not self.pending_host:
                raise RuntimeError('网络已改变，请重新登录。')
            core.portal_origin(self.portal)
            if self.pending_host not in self.settings['trusted_hosts']:
                self.settings['trusted_hosts'].append(self.pending_host)
            self.store.write_settings(self.settings)
            self.pending_host=''
            self.message('认证服务器已确认，请再次点击登录')
            return {'ok':True}
        except (RuntimeError,ValueError,OSError) as exc:
            self.record_exception('portal.confirm_error',exc)
            return {'ok':False,'message':str(exc)}

    def permitted(self,logout=False):
        wifi=core.read_wifi()
        if not wifi.ready:
            raise RuntimeError('请先连接 CUMT_Stu 或 CUMT_Tec。')
        is_tec=wifi.ssid.casefold()==core.TEC.casefold()
        core.guard(wifi,wifi,is_tec)
        notice=student_auth_time_notice(wifi)
        if not logout and self.settings.get('quiet_hours',True) and notice:
            raise RuntimeError(notice)
        return wifi,is_tec

    def start_job(self,kind,job,automatic=False):
        with self.lock:
            if self.closed.is_set(): return {'ok':False,'message':'程序已退出。'}
            if self.busy:
                return {'ok':False,'message':'正在处理，请稍候。'}
            self.busy=True
            self.operation=kind
            self.auto_job=automatic
            self.cancel.clear()
            self.operation_id=uuid.uuid4().hex[:12]
            operation_id=self.operation_id
            self.record('operation.accepted',operation_id=operation_id,kind=kind,automatic=automatic)
        def run():
            began=time.perf_counter()
            try:
                self.record('operation.started',operation_id=operation_id,kind=kind,wifi=core.asdict(self.wifi))
                with core.trace_scope(lambda event,level='DEBUG',**fields:self.record(event,level=level,operation_id=operation_id,**fields)):
                    job()
            except RuntimeError as exc:
                self.record_exception('operation.error',exc,kind=kind,network_error=core.network_error_details(exc))
                self.message(self.login_failure_message(str(exc)) if kind=='login' else str(exc))
            except Exception as exc:
                error=core.network_error_details(exc) if isinstance(exc,(OSError,http.client.HTTPException)) else {}
                self.record_exception('operation.error',exc,kind=kind,network_error=error)
                detail='连接认证服务器失败，请检查网络后重试。'
                if error: detail=error['message']
                if kind in ('login','logout') and self.auth_diagnostic.get('authentication_requests',0)>0:
                    detail+=' 结果尚未确认，请先刷新状态，避免重复提交。'
                self.message(self.login_failure_message(detail) if kind=='login' else detail)
            finally:
                with self.lock:
                    self.busy=False
                    self.operation=''
                    self.auto_job=False
                    self.last_job_elapsed_ms=round((time.perf_counter()-began)*1000)
                    self.record('operation.finished',operation_id=operation_id,kind=kind,
                                cancelled=self.cancel.is_set(),elapsed_ms=self.last_job_elapsed_ms,
                                state=getattr(self,'session_state','unknown'),status=self.status)
        threading.Thread(target=run,daemon=True).start()
        return {'ok':True}

    def login(self,account,password,operator,profile_id='',automatic=False,expected=None,quiet_override=False):
        with self.lock:
            if self.closed.is_set(): return {'ok':False,'message':'程序已退出。'}
            return self._login(account,password,operator,profile_id,automatic,expected,quiet_override)

    def _login(self,account,password,operator,profile_id='',automatic=False,expected=None,quiet_override=False):
        if not automatic:
            self._logout_watch=None
            self._logout_recovery_needed=False
        self.register_secrets(str(account),str(password))
        self.record('login.requested',operator=operator,automatic=automatic)
        account=str(account).strip()
        password=str(password)
        if not account or not password:
            if self.logged_in:
                return self.refresh_status()
            return {'ok':False,'message':'请输入账号和密码。'}
        try:
            wifi,tec=self.permitted(logout=True)
            if automatic and (not wifi.campus or not self.stu_automation_enabled()):
                return {'ok':False,'message':'自动登录已停止。'}
            if automatic and self._logout_auto_suppressed(wifi):
                return {'ok':False,'message':'刚请求注销，已停止本次自动登录。'}
            if automatic:
                try:
                    self._ensure_exclusive_auto()
                except RuntimeError:
                    self.auth_diagnostic={'operation':'login','backend':'status_only',
                                          'phase':'coexistence_blocked','authentication_requests':0}
                    raise
            if expected: core.guard(expected,wifi,tec)
        except RuntimeError as exc:
            self.record_exception('login.rejected',exc)
            return {'ok':False,'message':str(exc)}
        if not tec and operator not in ('telecom','unicom','cmcc','campus'):
            return {'ok':False,'message':'请选择登录网络。'}
        effective_operator='' if tec else operator
        with self.lock:
            if self.busy: return {'ok':False,'message':'正在处理，请稍候。'}
            if not automatic:
                saved=self.save_profile(profile_id,account,password,operator)
                if not saved['ok']: return saved
            if wifi.campus: self.auto_attempted=True
        def check_allowed():
            if self.cancel.is_set() or self.closed.is_set() or (automatic and not self.stu_automation_enabled()):
                raise RuntimeError('本次登录已停止。')
            if automatic:
                self._ensure_exclusive_auto()
            core.guard(wifi,core.read_wifi(),tec)
        def job():
            check_allowed()
            self.auth_diagnostic={'operation':'login','backend':'status_only','phase':'checking_status',
                                  'authentication_requests':0}
            with self.lock:
                self.unconfirmed_connectivity={}
                self.wifi=wifi
                self.settings['operator']=operator
                self.store.write_settings(self.settings)
            self.message('正在检查登录状态…')
            report=self.session_engine(wifi,tec).status()
            self.apply_session(wifi,report)
            if self.logged_in:
                self.auth_diagnostic={'operation':'login','backend':'status_only',
                                      'authentication_requests':0,'phase':'already_online'}
                self.message('服务器报告当前无线网已在线；如需更换账号，请先注销')
                return
            network_error=report.get('network_error') or {}
            if self.session_binding_conflict(report):
                self.auth_diagnostic={'operation':'login','backend':'status_only','phase':'session_conflict',
                                      'authentication_requests':0}
                self.record('authentication.preflight_blocked',diagnostic=self.auth_diagnostic)
                self.message(self.status_failure_message(report,'本次未发送登录请求。'))
                return
            if report.get('state')=='unknown' and network_error.get('code')=='permission_denied':
                self.auth_diagnostic={'operation':'login','backend':'status_only','phase':'network_blocked',
                                      'authentication_requests':0,'network_error':dict(network_error)}
                self.record('authentication.preflight_blocked',diagnostic=self.auth_diagnostic)
                detail=('本次未发送认证请求，自动登录已停止；请排查后刷新状态。' if automatic else
                        '本次未发送认证请求；请排查后刷新状态。')
                self.message(self.login_failure_message(self.status_failure_message(report,detail),wifi))
                return
            if automatic and report.get('state')=='unknown':
                self.message(self.login_failure_message(self.status_failure_message(report,
                             '暂时无法确认登录状态，自动登录已停止；可刷新或手动登录'),wifi))
                return
            notice=student_auth_time_notice(wifi)
            if self.settings.get('quiet_hours',True) is True and notice and not (quiet_override is True and not automatic):
                raise RuntimeError(notice)
            check_allowed()
            self.message('正在登录…')
            result=self.run_authentication(wifi,account,password,effective_operator,'login',tec,check_allowed)
            core.guard(wifi,core.read_wifi(),tec)
            if self.cancel.is_set() or self.closed.is_set(): raise RuntimeError('本次登录已停止。')
            if result is True:
                self.auth_diagnostic['request_accepted']=True
                # Request acceptance and a live session are separate facts.
                report={'state':'unknown','detail':'post_login_status_unconfirmed'}
                try:
                    report=self.session_engine(wifi,tec).status()
                except Exception as exc:
                    self.record_exception('session.identity_check_error',exc)
                    if isinstance(exc,(OSError,http.client.HTTPException)):
                        report['network_error']=core.network_error_details(exc)
                self.apply_session(wifi,report)
                if self.session_state=='online':
                    self.message('已登录校园网' if operator=='campus' else '已登录，正在后台检查外网')
                    if operator!='campus': self.check_internet_later(wifi,tec)
                else:
                    detail=('服务器已接受登录，但复查仍为离线；请稍后刷新状态，未再次提交。'
                            if self.session_state=='offline' else
                            '服务器已接受登录，在线状态尚未确认；请稍后刷新状态，未再次提交。')
                    self.message(self.status_failure_message(report,detail))
                    if self.session_binding_conflict(report):
                        self.check_unconfirmed_internet_later(wifi,tec)
            elif result is False:
                # A rejected request does not prove that this device is offline:
                # the server can reject a second login while it is already online.
                # Keep the original authentication result and read the session once.
                rejection=self.status if self.status.startswith('认证提示：') else ''
                report={'state':'unknown','detail':'post_rejection_status_unconfirmed'}
                try:
                    report=self.session_engine(wifi,tec).status()
                except Exception as exc:
                    self.record_exception('session.rejection_check_error',exc)
                    if isinstance(exc,(OSError,http.client.HTTPException)):
                        report['network_error']=core.network_error_details(exc)
                self.apply_session(wifi,report)
                self.record('login.rejected_status_check',state=self.session_state,
                            request_accepted=False,authentication_requests=
                            self.auth_diagnostic.get('authentication_requests',0))
                if self.session_state=='online':
                    detail='服务器未接受本次登录请求，但复查确认当前无线设备已在线；未再次提交。'
                elif self.session_state=='offline':
                    detail='服务器未接受本次登录请求，复查仍未登录；请核对账号和所选登录网络，未再次提交。'
                else:
                    detail='服务器未接受本次登录请求，当前在线状态尚未确认；请先刷新状态，未再次提交。'
                if rejection:detail=rejection+' '+detail
                detail=self.status_failure_message(report,detail)
                self.message(self.login_failure_message(detail,wifi))
            else:
                self.logged_in=False;self.auth_key=None;self.session_state='unknown'
                self.online_account='';self.identity_source=''
                self.message(self.login_failure_message(self.status_failure_message(self.auth_diagnostic,
                             '未确认登录结果，请先刷新状态，避免重复提交。'),wifi))
        return self.start_job('login',job,automatic=automatic)

    def checked_wifi(self,wifi,tec):
        with self.lock: self.consume_notifications()
        if self.closed.is_set() or self.cancel.is_set(): raise RuntimeError('本次操作已停止。')
        if getattr(self,'auto_job',False):
            self._ensure_exclusive_auto()
        try:
            current=core.read_wifi()
        except (OSError,RuntimeError):
            self._invalidate_logout_route('wifi_read_unavailable')
            raise
        try:
            core.guard(wifi,current,tec)
        except RuntimeError:
            self._observe_portal_network(current)
            raise
        if self._portal_network_context(wifi)!=self._portal_network_context(current):
            self._observe_portal_network(current)
            raise RuntimeError('无线设备或网关参数已改变，已停止本次操作；未重用旧接入设备参数。')
        self._observe_portal_network(current)
        return current

    def _logout_auto_suppressed(self,wifi):
        watch=getattr(self,'_logout_watch',None)
        return bool(watch and 0<=time.monotonic()-watch['started']<LOGOUT_AUTO_HOLD
                    and wifi.ssid.casefold()==watch['ssid'] and wifi.guid==watch['guid'])

    def _logout_wait(self,seconds):
        self.cancel.wait(seconds)

    @staticmethod
    def _service_account(account):
        account=str(account).strip()
        if account.startswith(',0,'):
            account=account[3:]
        head,separator,suffix=account.rpartition('@')
        if separator and suffix.casefold() in ('telecom','unicom','cmcc','campus'):
            account=head
        return account

    def _logout_credentials(self,report):
        if report.get('state')!='online':
            selected=self.store.selected_profile()
            if (isinstance(selected,dict) and isinstance(selected.get('account'),str) and selected['account'].strip()
                    and isinstance(selected.get('password'),str) and selected['password']):
                return self._service_account(selected['account']),selected['password']
            raise RuntimeError('当前会话未确认，且没有选中的已保存账号；未自动提交账号密码。')
        identity=self._service_account(report.get('online_account','')).casefold()
        if not identity:
            raise RuntimeError('服务器未提供可核对的在线账号，请在自助服务手动确认；未自动提交密码。')
        selected=self.store.selected_profile()
        if (isinstance(selected,dict) and self._service_account(selected.get('account','')).casefold()==identity
                and isinstance(selected.get('password'),str) and selected['password']):
            return self._service_account(selected['account']),selected['password']
        data=self.store.profiles()
        profiles=data.get('profiles',[]) if isinstance(data,dict) else []
        matches={(self._service_account(p.get('account','')),p.get('password')) for p in profiles
                 if isinstance(p,dict) and self._service_account(p.get('account','')).casefold()==identity
                 and isinstance(p.get('password'),str) and p['password']}
        if len(matches)!=1:
            raise RuntimeError('未找到当前在线账号对应的唯一已保存密码，请从自助服务手动处理。')
        return next(iter(matches))

    def _confirm_portal_logout(self,wifi,tec,check_allowed,report=None):
        """Observe the ordinary logout without opening an account-service session."""
        started=time.monotonic()
        deadline=started+LOGOUT_PORTAL_SETTLE_SECONDS+LOGOUT_PORTAL_STABLE_SECONDS
        stable_since=None
        samples=0
        while True:
            check_allowed()
            last=report if report is not None else self.session_engine(wifi,tec).status()
            report=None
            self.apply_session(wifi,last)
            now=time.monotonic()
            samples+=1
            state=last.get('state')
            self.logout_diagnostic['portal_verification']={'samples':samples,'state':state,
                'stable_seconds':round(now-stable_since,1) if stable_since is not None else 0}
            if state=='offline':
                if stable_since is None:stable_since=now
                if now-stable_since>=LOGOUT_PORTAL_STABLE_SECONDS:
                    connectivity=core.internet_check(wifi,reader=check_allowed,allow_tec=tec)
                    check_allowed()
                    self.logout_diagnostic['portal_connectivity']=connectivity
                    last=self.session_engine(wifi,tec).status()
                    self.apply_session(wifi,last)
                    if connectivity.get('online'):
                        self.logout_diagnostic['fallback_reason']='access_still_online'
                        return False,last
                    if last.get('state')!='offline':
                        self.logout_diagnostic['fallback_reason']='status_changed'
                        return False,last
                    return True,last
            elif state=='online':
                if stable_since is not None:
                    self.logout_diagnostic['fallback_reason']='session_reappeared'
                    return False,last
                if now-started>=LOGOUT_PORTAL_SETTLE_SECONDS:
                    self.logout_diagnostic['fallback_reason']='still_online'
                    return False,last
            else:
                self.logout_diagnostic['fallback_reason']='status_unconfirmed'
                return False,last
            if now>=deadline:
                self.logout_diagnostic['fallback_reason']='offline_not_sustained'
                return False,last
            self.message('正在确认普通注销结果（约一分钟），请稍候…')
            self._logout_wait(min(2.0,max(0.0,deadline-now)))

    def _confirm_logout(self,wifi,client,check_allowed):
        deadline=time.monotonic()+LOGOUT_CONFIRM_TIMEOUT
        stable_since=None
        last={'state':'unknown','detail':'logout_not_confirmed'}
        samples=0
        target_mac=protocol._session_mac(wifi.mac)
        while True:
            check_allowed()
            last=self.session_engine(wifi,wifi.ssid.casefold()==core.TEC.casefold()).status()
            self.apply_session(wifi,last)
            devices=client.list_online_devices()
            absent=not any(d.mac==target_mac for d in devices)
            samples+=1
            now=time.monotonic()
            self.logout_diagnostic['verification']={'samples':samples,
                'portal_state':last.get('state'),'account_device_absent':absent}
            if absent and last.get('state')=='offline':
                if stable_since is None:stable_since=now
                if now-stable_since>=LOGOUT_STABLE_SECONDS:
                    return True,last
            else:
                stable_since=None
            if now>=deadline:
                return False,last
            self._logout_wait(min(1.0,max(0.0,deadline-now)))

    def _recover_logout(self,wifi,report,check_allowed):
        client=None
        self._logout_recovery_needed=True
        try:
            if not protocol._session_mac(wifi.mac):
                raise RuntimeError('无法核对本机无线设备MAC，未自动提交自助下线。')
            account,password=self._logout_credentials(report)
            self.register_secrets(account,password)
            check_allowed()
            self.message('正在通过校园网自助服务核对并下线本机，不会处理其他设备…')
            client=selfservice.Client(wifi,reader=check_allowed,cleanup_reader=core.read_wifi,trace=self.record)
            client.login(account,password)
            lookup_deadline=time.monotonic()+LOGOUT_SESSION_LOOKUP_TIMEOUT
            while True:
                check_allowed()
                devices=client.list_online_devices()
                try:
                    selfservice.select_current_session(devices,wifi,report)
                except selfservice.NoMatchingDevice:
                    if any(d.mac==protocol._session_mac(wifi.mac) for d in devices):
                        raise selfservice.AmbiguousDevice('自助服务中的本机地址信息无法核对，未下线其他会话。')
                    if time.monotonic()>=lookup_deadline:
                        raise selfservice.NoMatchingDevice('后台未出现可核对的本机会话，未发送下线请求；暂不能确认接入已断开。')
                    self.message('正在等待后台会话可核对，不会重复提交或处理其他设备…')
                    self._logout_wait(min(2.0,max(0.0,lookup_deadline-time.monotonic())))
                    continue
                break
            client.disconnect_current(report,before_disconnect=check_allowed)
            if client.safe_summary().get('device_reappeared'):
                self.logout_diagnostic['outcome']='session_reappeared'
                self.message('自助下线后，本机又出现在线会话；未重复下线，请核对其他客户端或自动认证设置。')
                return False
            self.message('正在持续确认本机已下线，请稍候…')
            confirmed,last=self._confirm_logout(wifi,client,check_allowed)
            if confirmed:
                self.session_cookies=[]
                self._logout_recovery_needed=False
                self.logout_diagnostic['outcome']='offline_confirmed'
                self.message('已下线（自助服务和认证状态已持续确认）')
                return True
            self.logout_diagnostic['outcome']='unconfirmed'
            self.message('已执行注销核对，但仍未确认本机持续离线；未重复提交，请从自助服务检查。')
            return False
        except Exception as exc:
            self.logout_diagnostic['outcome']='recovery_failed'
            self.logout_diagnostic['error_type']=type(exc).__name__
            self.record_exception('logout.recovery_error',exc)
            detail=str(exc) if isinstance(exc,(selfservice.SelfServiceError,RuntimeError)) else '自助服务暂时无法连接。'
            portal_requests=self.auth_diagnostic.get('authentication_requests',0)
            service_requests=client.safe_summary().get('disconnect_requests',0) if client is not None else 0
            prefix=('本次未发送注销请求。' if portal_requests==0 and service_requests==0 else
                    '门户未提交注销，已尝试自助下线；' if portal_requests==0 else '')
            self.message(self.status_failure_message(report,
                prefix+'注销尚未确认。'+detail+' 可打开底部“自助服务”手动核对。'))
            return False
        finally:
            if client is not None:
                client.close()
                self.logout_diagnostic['selfservice']=client.safe_summary()
            service_summary=self.logout_diagnostic.get('selfservice',{})
            self.auth_diagnostic['selfservice_login_attempted']=service_summary.get('login_attempted',False)
            self.auth_diagnostic['selfservice_logout_requests']=service_summary.get('disconnect_requests',0)
            self.auth_diagnostic['logout_requests']=self.logout_diagnostic.get('portal_requests',0)+service_summary.get('disconnect_requests',0)
            self.auth_diagnostic['phase']=self.logout_diagnostic.get('outcome','unconfirmed')
            self.record('logout.recovery_completed',diagnostic=self.logout_diagnostic)

    def logout(self):
        self.record('logout.requested')
        try:
            wifi,tec=self.permitted(logout=True)
        except RuntimeError as exc:
            self.record_exception('logout.rejected',exc)
            return {'ok':False,'message':str(exc)}
        def job():
            self.wifi=wifi
            self.auto_attempted=True
            self._stu_popup_pending=False
            retry_recovery=self._logout_recovery_needed
            self._logout_watch={'ssid':wifi.ssid.casefold(),'guid':wifi.guid,
                                'started':time.monotonic(),'saw_offline':False}
            self._logout_recovery_needed=False
            self.logout_diagnostic={'outcome':'pending','portal_requests':0,'portal_result':None}
            self.auth_diagnostic={'operation':'logout','backend':'portal',
                'phase':'preflight','authentication_requests':0}
            route_token=self._observe_portal_network(wifi)
            def check_allowed():
                current=self.checked_wifi(wifi,tec)
                self._assert_portal_route(wifi,route_token)
                return current
            self.message('正在检查登录状态…')
            try:
                report=self.session_engine(wifi,tec).status()
            except Exception as exc:
                check_allowed()
                self.record_exception('logout.status_error',exc)
                report={'state':'unknown','detail':'status_unavailable'}
            self.apply_session(wifi,report)
            if report.get('state')=='offline' and not retry_recovery:
                self.logout_diagnostic['outcome']='already_offline'
                self.auth_diagnostic['phase']='already_offline'
                self.message('当前无线网未登录，无需注销')
                return
            self._logout_recovery_needed=True
            # Keep the original server identity even if the ordinary interface
            # temporarily clears the online record before its AC has gone down.
            original_report=dict(report)
            if report.get('state')!='online':
                self.logout_diagnostic['fallback_reason']=('previous_logout_unconfirmed'
                    if retry_recovery else 'preflight_unconfirmed')
                self.record('logout.preflight_blocked',state=report.get('state'),
                            reason=report.get('detail','status_unconfirmed'),authentication_requests=0)
            else:
                self.message('正在通过认证页面退出登录…')
                try:
                    result=self.run_authentication(wifi,'','',self.settings.get('operator',''),'logout',tec,check_allowed)
                    self.logout_diagnostic['portal_result']=result
                    check_allowed()
                    report=self.session_engine(wifi,tec).status()
                    self.apply_session(wifi,report)
                    if result is False and report.get('state')!='offline':
                        self.logout_diagnostic['fallback_reason']='portal_rejected'
                    else:
                        confirmed,last=self._confirm_portal_logout(wifi,tec,check_allowed,report)
                        if confirmed:
                            self.session_cookies=[]
                            self._logout_recovery_needed=False
                            self.logout_diagnostic['outcome']='offline_confirmed'
                            self.auth_diagnostic['phase']='offline_confirmed'
                            self.auth_diagnostic['selfservice_login_attempted']=False
                            self.auth_diagnostic['selfservice_logout_requests']=0
                            self._logout_watch['started']=time.monotonic()
                            self.message('已退出登录（普通注销后持续确认离线）')
                            return
                except Exception as exc:
                    # Cancellation, a new connection or a route change is never
                    # permission to start a different authentication channel.
                    check_allowed()
                    self.logout_diagnostic['fallback_reason']=('logout_context_missing'
                        if isinstance(exc,LogoutContextUnavailable) else 'portal_error')
                    self.record_exception('logout.portal_error',exc)
                finally:
                    self.logout_diagnostic['portal_requests']=self.auth_diagnostic.get('authentication_requests',0)
                    self.auth_diagnostic['logout_requests']=self.logout_diagnostic['portal_requests']
            check_allowed()
            self.auth_diagnostic['fallback_reason']=self.logout_diagnostic['fallback_reason']
            self.record('logout.fallback_started',reason=self.logout_diagnostic['fallback_reason'],
                        portal_requests=self.logout_diagnostic['portal_requests'])
            self.message('普通注销未能完成，正在使用自助服务精准下线本机…')
            self._recover_logout(wifi,original_report,check_allowed)
            self._logout_watch['started']=time.monotonic()
        return self.start_job('logout',job)

    def authenticate(self,wifi,account,password,operator,operation,tec):
        """Execute the original portal with the private, bound WebView2 host."""
        from campus_browser import authenticate
        return authenticate(self,wifi,account,password,operator,operation,tec,
                            result_parser=authentication_result,
                            logout_select_js=LOGOUT_JS,logout_confirm_js=LOGOUT_CONFIRM_JS)

    def poll_wifi(self):
        """Show each campus connection independently of its optional authentication."""
        current=core.read_wifi()
        attempt=False
        popup=False
        with self.lock:
            self.consume_notifications()
            previous=self.wifi
            route_changed=self._portal_network_context(current)!=self._portal_network_context(previous)
            self._observe_portal_network(current)
            self.wifi=current
            first_poll=not getattr(self,'_stu_poll_initialized',False)
            self._stu_poll_initialized=True
            if not previous.campus and previous.ip:
                self._stu_previous_network=(previous.ip,previous.gateway,previous.index)
            if not current.campus and current.ip:
                self._stu_previous_network=(current.ip,current.gateway,current.index)
            connection=(current.ssid.casefold(),current.guid,current.index) if current.campus else None
            reset=getattr(self,'_stu_popup_reset_pending',False)
            if not current.campus:
                self._stu_popup_connection=None
                self._stu_popup_pending=False
                self._stu_auth_snapshot=None
                self._stu_auth_stable_count=0
                self._stu_network_pending=False
            elif reset or connection!=getattr(self,'_stu_popup_connection',None):
                # Switching STU/TEC on one adapter is a new connection, but
                # wait for two consistent address snapshots before submitting.
                previous_connection=(previous.ssid.casefold(),previous.guid,previous.index)
                tracked_connection=getattr(self,'_stu_popup_connection',None)
                if (reset or connection!=previous_connection
                        or tracked_connection is not None and connection!=tracked_connection):
                    self.auto_attempted=False
                if previous.campus and connection!=previous_connection:
                    self._stu_auth_requires_stability=True
                self._stu_popup_connection=connection
                self._stu_popup_reset_pending=False
                # A manual launch already has a visible window. A hidden
                # Windows-startup launch must still show when STU is present.
                manual_initial=(first_poll and not getattr(self,'startup',False)
                                and self.window is not None and not reset
                                and (not previous.ssid or previous.campus))
                self._stu_popup_pending=not manual_initial
                self._stu_auth_snapshot=None
                self._stu_auth_stable_count=0
                self.record('network.stu_connection',popup_pending=self._stu_popup_pending,
                            manual_initial=manual_initial,interface_index=current.index)
            # DHCP renewal alone is NOT a new connection/permission to retry.
            if not current.campus or (previous.campus and current.guid!=previous.guid):
                self.auto_attempted=False
            if current.key!=previous.key or route_changed:
                self.unconfirmed_connectivity={}
                self.record('network.changed',previous=core.asdict(previous),current=core.asdict(current))
                self.portal_key=None
                self.pending_host=''
                self._engine=None
                self._portal_discovered=False
                self.session_state='unknown'
                self.session_checked_key=None
                self.session_checked_monotonic=0.0
                if self.busy: self.cancel.set()
                if self.auth_key and (current.key!=self.auth_key or route_changed):
                    self.logged_in=False
                    self.auth_key=None
                    self.session_cookies=[]
                if not self.busy:
                    self.status='未登录' if current.ready else '请连接校园 WiFi 后登录'
            enabled=self.stu_automation_enabled()
            watch=getattr(self,'_logout_watch',None)
            if watch and current.ssid and current.ssid.casefold()!=watch['ssid']:
                self._logout_watch=None
                self._logout_recovery_needed=False
            if self._logout_auto_suppressed(current):
                self.auto_attempted=True
                self._stu_popup_pending=False
                enabled=False
            if (enabled and current.campus and current.guid not in self.reconnecting
                    and getattr(self,'_stu_popup_pending',False) and self.window is not None):
                self._stu_popup_pending=False
                popup=True
            # SSID changes can precede DHCP by several seconds, including a
            # private 10/8 address left over from a phone hotspot. Never consume
            # the one authentication attempt for that stale lease.
            stale=getattr(self,'_stu_previous_network',None)
            carried=bool(stale and (current.ip==stale[0]
                         or (stale[1] and current.gateway==stale[1])))
            network_ready=(current.campus and current.ready and core.campus_host(current.ip)
                           and current.guid not in self.reconnecting and not carried)
            snapshot=(current.ip,current.gateway,current.index)
            if network_ready:
                if snapshot==getattr(self,'_stu_auth_snapshot',None):
                    self._stu_auth_stable_count=getattr(self,'_stu_auth_stable_count',0)+1
                else:
                    self._stu_auth_snapshot=snapshot
                    self._stu_auth_stable_count=1
                if getattr(self,'_stu_auth_requires_stability',False):
                    network_ready=self._stu_auth_stable_count>=2
            else:
                self._stu_auth_snapshot=None
                self._stu_auth_stable_count=0
                if carried and current.campus:
                    self._stu_auth_requires_stability=True
            waiting=bool(current.campus and not network_ready)
            if waiting!=getattr(self,'_stu_network_pending',False):
                self.record('network.stu_address_waiting' if waiting else 'network.stu_address_ready',
                            source_ip=current.ip,gateway=current.gateway,carried_previous_lease=carried)
            self._stu_network_pending=waiting
            if enabled and network_ready and not self.auto_attempted and not self.busy:
                self.auto_attempted=True
                attempt=True
        if popup:
            self.show_window()
        if attempt:
            with self.lock:
                try:
                    selected=self.store.selected_profile()
                    if not selected.get('account') or not selected.get('password'):
                        self.record('network.auto_login_skipped',reason='no_selected_profile')
                        self.message('已连接校园网，请选择或填写账号后登录。')
                    elif current.student and selected.get('operator') not in ('telecom','unicom','cmcc','campus'):
                        self.record('network.auto_login_skipped',reason='operator_not_selected')
                        self.message('已连接学生网，请选择账号对应的登录网络。')
                    else:
                        result=self.login(selected['account'],selected['password'],selected.get('operator',''),
                                          selected.get('id',''),automatic=True,expected=current)
                        if not result['ok']: self.message(result['message'])
                except (RuntimeError,OSError) as exc:
                    self.record_exception('network.auto_login_error',exc)
                    self.message(str(exc))
        return current

    def consume_notifications(self):
        if not self.notifications: return
        for code,guid in self.notifications.drain():
            self.record('network.notification',code=code,guid=guid)
            if code in (20,21):
                self.reconnecting.add(guid)
                if guid==self.wifi.guid:
                    self._invalidate_logout_route('wlan_disconnect')
                    self._stu_popup_reset_pending=True
                    self._stu_auth_requires_stability=True
                    self._stu_auth_snapshot=None
                    self._stu_auth_stable_count=0
                    self.auto_attempted=False
                    self.portal_key=None
                    self.pending_host=''
                    self._engine=None
                    self._portal_discovered=False
                    self.session_state='unknown'
                    self.session_checked_key=None
                    self.session_checked_monotonic=0.0
                    self.logged_in=False
                    self.auth_key=None
                    self.session_cookies=[]
                    if self.busy: self.cancel.set()
            elif code==10:
                if guid==self.wifi.guid:
                    self._invalidate_logout_route('wlan_connected')
                self.reconnecting.discard(guid)

    def show_window(self):
        self.record('window.show_requested')
        self.session_checked_monotonic=0.0
        if self.window is None or self.closed.is_set():
            self.record('window.show_unavailable',level='WARNING',closed=self.closed.is_set())
            return {'shown':False,'native_verified':False}
        result={'shown':False,'native_verified':False}
        try:
            # Activate after restoring, so a minimized window receives the same
            # opportunity to come forward as one which was simply hidden.
            self.window.restore()
            self.window.show()
            result['shown']=True
            native=vars(self.window).get('native')
            if native is not None and os.name=='nt':
                handle=native.Handle
                hwnd=int(handle.ToInt64() if hasattr(handle,'ToInt64') else handle)
                user=ctypes.WinDLL('user32',use_last_error=True)
                user.GetWindowThreadProcessId.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_ulong)]
                user.GetWindowThreadProcessId.restype=ctypes.c_ulong
                owner=ctypes.c_ulong()
                user.GetWindowThreadProcessId(hwnd,ctypes.byref(owner))
                if owner.value!=os.getpid():
                    self.record('window.native_handle_rejected',level='WARNING',reason='different_process')
                else:
                    for name in ('IsWindowVisible','IsIconic','BringWindowToTop','SetForegroundWindow'):
                        fn=getattr(user,name)
                        fn.argtypes=[ctypes.c_void_p]
                        fn.restype=ctypes.c_int
                    user.GetForegroundWindow.argtypes=[]
                    user.GetForegroundWindow.restype=ctypes.c_void_p
                    user.ShowWindow.argtypes=[ctypes.c_void_p,ctypes.c_int]
                    user.ShowWindow.restype=ctypes.c_int
                    visible=bool(user.IsWindowVisible(hwnd))
                    foreground=int(user.GetForegroundWindow() or 0)==hwnd
                    minimized=bool(user.IsIconic(hwnd))
                    recovered=not visible or minimized or not foreground
                    if recovered:
                        # One bounded recovery; Windows may still deny focus.
                        user.ShowWindow(hwnd,9)  # SW_RESTORE
                        user.BringWindowToTop(hwnd)
                        user.SetForegroundWindow(hwnd)
                        visible=bool(user.IsWindowVisible(hwnd))
                        foreground=int(user.GetForegroundWindow() or 0)==hwnd
                        minimized=bool(user.IsIconic(hwnd))
                    result.update(native_verified=True,visible=visible,foreground=foreground,
                                  minimized=minimized,recovery_attempted=recovered)
            self.record('window.show_completed',level='INFO' if result.get('foreground',True) else 'WARNING',**result)
        except Exception as exc:
            self.record_exception('window.show_error',exc)
        return result

    def poll_show_event(self):
        if not self.show_event: return
        kernel=ctypes.WinDLL('kernel32')
        kernel.WaitForSingleObject.argtypes=[ctypes.c_void_p,ctypes.c_uint]
        if kernel.WaitForSingleObject(self.show_event,0)==0: self.show_window()

    def monitor(self):
        while not self.closed.is_set():
            try:
                self.poll_wifi()
                if self.wifi.ready and not getattr(self,'_stu_network_pending',False) and not self.busy and (
                    getattr(self,'session_checked_key',None)!=self.wifi.key or
                    time.monotonic()-getattr(self,'session_checked_monotonic',0)>30):
                    self.refresh_status()
            except Exception as exc:
                self.record_exception('network.monitor_error',exc)
                self.message('暂时无法读取网络状态')
            self.poll_show_event()
            if self.notifications:
                self.notifications.wake.wait(1)
                self.notifications.wake.clear()
            else: self.closed.wait(1)

    def started(self):
        self.record('window.started',hidden=self.startup)
        if self.startup: self.window.hide()
        try: self.notifications=core.WifiNotifications()
        except RuntimeError as exc:
            self.record_exception('network.listener_error',exc)
            self.message('无线事件监听不可用，将通过定时检查网络状态。')
        threading.Thread(target=self.monitor,daemon=True).start()

    def diagnostic(self):
        data={'version':core.VERSION,'time':dt.datetime.now().isoformat(timespec='seconds'),'wifi':core.asdict(self.wifi),
              'portal':core.safe_summary(self.portal) if self.portal else '', 'operator':self.settings.get('operator',''),
              'messages':list(self.messages),'network_configuration_changes':False}
        data['authentication']=self.auth_diagnostic
        data['network_check']=getattr(self,'network_diagnostic',{})
        data['unconfirmed_connectivity']=getattr(self,'unconfirmed_connectivity',{})
        data['logout_recovery']=getattr(self,'logout_diagnostic',{})
        data['session']={'state':self.session_state,'checked_at':self.session_checked_at,
                         'query':self.session_diagnostic}
        data['last_job_elapsed_ms']=self.last_job_elapsed_ms
        self.record('diagnostic.export_requested')
        log=getattr(self,'runtime_log',None)
        if log is None:
            return {'ok':False,'message':'运行日志未初始化，无法导出诊断包。'}
        try:
            data['logging']={'session_id':log.session_id,'log_file':str(log.path),'write_error':log.write_error}
            path=log.export_bundle(data)
            self.record('diagnostic.export_completed',path=str(path))
            return {'ok':True,'path':str(path)}
        except Exception as exc:
            self.record_exception('diagnostic.export_error',exc)
            return {'ok':False,'message':'无法保存诊断包，请检查本机可写空间。'}

    def on_closing(self):
        self.record('window.closing',keeps_background=self.stu_automation_enabled())
        if self.stu_automation_enabled() and not self.closed.is_set():
            self.window.hide()
            return False
        self.closed.set();self.cancel.set()
        return True

    def quit(self):
        self.record('app.quit_requested')
        self.closed.set();self.cancel.set()
        if self.window: self.window.destroy()
        return {'ok':True}


def configure_windows_identity(runtime_log):
    """Set a stable taskbar identity before any native window is created."""
    result={'app_user_model_id':APP_USER_MODEL_ID,'configured':False}
    if os.name!='nt':
        return result
    try:
        setter=ctypes.WinDLL('shell32').SetCurrentProcessExplicitAppUserModelID
        setter.argtypes=[ctypes.c_wchar_p]
        setter.restype=ctypes.c_long
        result['hresult']=int(setter(APP_USER_MODEL_ID))
        result['configured']=result['hresult']==0
        runtime_log.event('window.app_identity',level='INFO' if result['configured'] else 'WARNING',**result)
    except Exception as exc:
        runtime_log.exception('window.app_identity_error',exc)
    return result


def verify_native_icon(window,icon_path):
    """Compare the actual WinForms icon to the same-size bundled source icon."""
    from System.Drawing import Icon
    from System.Drawing.Imaging import ImageFormat
    from System.IO import MemoryStream
    actual_icon=window.native.Icon
    if actual_icon is None:
        raise RuntimeError('The native window has no application icon.')
    expected_icon=Icon(str(icon_path),actual_icon.Size)
    owned=[]
    try:
        digests=[]
        for icon in (actual_icon,expected_icon):
            bitmap=icon.ToBitmap();owned.append(bitmap)
            stream=MemoryStream();owned.append(stream)
            bitmap.Save(stream,ImageFormat.Png)
            digests.append(hashlib.sha256(bytes(stream.ToArray())).hexdigest())
        return {'verified':digests[0]==digests[1],
                'width':int(actual_icon.Width),'height':int(actual_icon.Height),
                'native_png_sha256':digests[0],'expected_png_sha256':digests[1],
                'asset_sha256':hashlib.sha256(Path(icon_path).read_bytes()).hexdigest()}
    finally:
        for resource in reversed(owned):resource.Dispose()
        expected_icon.Dispose()


def run_main(runtime_log):
    parser=argparse.ArgumentParser()
    parser.add_argument('--startup',action='store_true')
    parser.add_argument('--watch',action='store_true',help=argparse.SUPPRESS)
    parser.add_argument('--diagnose',action='store_true')
    parser.add_argument('--smoke-test',action='store_true')
    parser.add_argument('--experimental',action='store_true',help='Use the isolated experimental profile and desktop identity')
    args=parser.parse_args()
    runtime_log.event('startup.options',startup=args.startup,watch=args.watch,smoke_test=args.smoke_test,diagnose=args.diagnose)
    if args.diagnose:
        print(json.dumps(core.asdict(core.read_wifi()),ensure_ascii=False,indent=2));return
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateMutexW.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_wchar_p]
    kernel.CreateMutexW.restype=ctypes.c_void_p
    # Self-test is independent of an old user instance; normal use remains single-instance.
    identity='CumtCampusLoginExperimental' if EXPERIMENTAL else 'CumtCampusLogin'
    mutex_name='Local\\'+identity+('SmokeV13' if args.smoke_test else 'DesktopV1')
    mutex=kernel.CreateMutexW(None,False,mutex_name)
    already_running=ctypes.get_last_error()==183
    runtime_log.event('instance.checked',already_running=already_running)
    kernel.CloseHandle.argtypes=[ctypes.c_void_p]
    kernel.OpenEventW.argtypes=[ctypes.c_uint,ctypes.c_int,ctypes.c_wchar_p]
    kernel.OpenEventW.restype=ctypes.c_void_p
    kernel.CreateEventW.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_int,ctypes.c_wchar_p]
    kernel.CreateEventW.restype=ctypes.c_void_p
    kernel.SetEvent.argtypes=[ctypes.c_void_p]
    kernel.WaitForSingleObject.argtypes=[ctypes.c_void_p,ctypes.c_uint]
    event_name='Local\\'+identity+'ShowV13'
    if already_running:
        runtime_log.event('instance.forwarding_to_running_client')
        event=kernel.OpenEventW(2,False,event_name)
        if event and not (args.startup or args.watch): kernel.SetEvent(event)
        elif not event and not args.startup:
            ctypes.windll.user32.MessageBoxW(None,'程序已在运行，请先退出旧版后再打开新版。',TITLE,0)
        if event: kernel.CloseHandle(event)
        kernel.CloseHandle(mutex)
        return
    show_event=None if args.smoke_test else kernel.CreateEventW(None,False,False,event_name)
    app_identity=configure_windows_identity(runtime_log)
    icon_path=ROOT/'assets'/'icon.ico'
    import webview
    app=App(args.startup or args.watch,runtime_log=runtime_log)
    app.show_event=show_event
    if app.startup and not app.stu_automation_enabled():
        if show_event: kernel.CloseHandle(show_event)
        kernel.CloseHandle(mutex);return
    app.window=webview.create_window(TITLE+'  '+core.VERSION,str(ROOT/'campus_ui.html'),js_api=Bridge(app),width=430,height=690,min_size=(420,670),hidden=app.startup)
    app.window.events.closing+=app.on_closing
    if args.smoke_test:
        app.wifi=core.read_wifi()
        result={'mode':'packaged offline smoke test','version':core.VERSION,'success':False,'campus_requests':0,'network_changes':0,
                'windows_app_identity':app_identity}
        smoke_error=[None]
        def check_ui_checks():
            for _ in range(40):
                time.sleep(.25)
                if app.window.evaluate_js('!!window.clientReady'): break
            result.update(ssid=app.wifi.ssid,wifi_index=app.wifi.index,ip=app.wifi.ip,
                          ui_title=app.window.evaluate_js('document.title'),
                          api_ready=app.window.evaluate_js('typeof window.pywebview.api.get_state'),
                          startup_switch=app.window.evaluate_js("!!document.getElementById('startup')"),
                          single_login_entry=app.window.evaluate_js("document.querySelectorAll('#login-button').length===1 && !document.getElementById('login-switch')"),
                          profiles=app.window.evaluate_js("!!document.getElementById('profiles')"),
                          independent_logout=app.window.evaluate_js("!!document.getElementById('logout-button')"),
                          status_refresh=app.window.evaluate_js("!!document.getElementById('status-refresh')"),
                          network_check_entry=app.window.evaluate_js("!!document.getElementById('network-check') && typeof window.pywebview.api.network_check==='function'"),
                          online_identity_display=app.window.evaluate_js("!!document.getElementById('online-account')"),
                          no_tec_warning=app.window.evaluate_js("!document.getElementById('tec')"),
                          client_ready=app.window.evaluate_js('!!window.clientReady'),
                          ui_logo_loaded=app.window.evaluate_js("(()=>{const image=document.querySelector('.logo img');return !!image&&image.complete&&image.naturalWidth>0})()"),
                          displayed_ssid=app.window.evaluate_js("document.getElementById('ssid').innerText"))
            try:
                from campus_browser import offline_self_test
                result['webview2_compatibility']=offline_self_test()
            except Exception as exc:
                runtime_log.exception('smoke.webview2_compatibility_error',exc)
                result['webview2_compatibility']={'engine':'webview2','success':False,
                                                'error_type':type(exc).__name__}
            try:
                result['native_icon']=verify_native_icon(app.window,icon_path)
            except Exception as exc:
                runtime_log.exception('smoke.native_icon_error',exc)
                result['native_icon']={'verified':False,'error_type':type(exc).__name__}
            # Verify that the frozen EXE writes logs and exports them without a
            # developer environment or real campus requests.
            sample_secret='packaged-smoke-private-value'
            runtime_log.register_secrets(sample_secret)
            try:
                raise RuntimeError('offline self-test '+sample_secret)
            except RuntimeError as exc:
                runtime_log.exception('smoke.expected_error',exc)
            bundle=app.diagnostic()
            import zipfile
            log_export_ok=False
            if bundle['ok']:
                with zipfile.ZipFile(bundle['path']) as archive:
                    names=archive.namelist()
                    contents=[archive.read(name) for name in names]
                    log_export_ok=('manifest.json' in names and 'snapshot.json' in names
                                   and any(name.startswith('logs/') for name in names)
                                   and all(sample_secret.encode() not in data for data in contents)
                                   and any(b'smoke.expected_error' in data and b'Traceback' in data for data in contents))
            # Exercise a real hidden/minimized native window without WLAN
            # changes, a monitor or any credential/portal access.
            app.window.hide();app.window.minimize()
            restored=app.show_window()
            result.update(runtime_log_ready=runtime_log.path.is_file(),diagnostic_zip_verified=log_export_ok,
                          native_window_restore=restored,
                          window_restore_verified=bool(restored.get('shown') and restored.get('native_verified')
                                                      and restored.get('visible') and not restored.get('minimized')))
            result['success']=result['client_ready'] and result['displayed_ssid']==(app.wifi.ssid or '未连接网络') and result['ui_title']==TITLE and result['api_ready']=='function' and result['startup_switch'] and result['single_login_entry'] and result['profiles'] and result['no_tec_warning'] and result['independent_logout'] and result['status_refresh'] and result['network_check_entry'] and result['runtime_log_ready'] and result['diagnostic_zip_verified'] and result['online_identity_display'] and result['window_restore_verified'] and result['ui_logo_loaded'] and result['native_icon']['verified'] and result['webview2_compatibility']['success']
        def check_ui():
            try:
                check_ui_checks()
                if not result.get('success'):
                    raise RuntimeError('Packaged offline smoke checks did not pass.')
                (Path(sys.executable).parent/'packaged_smoke_results.json').write_text(
                    json.dumps(result,ensure_ascii=False,indent=2),'utf-8')
            except BaseException as exc:
                smoke_error[0]=exc
                runtime_log.exception('smoke.check_error',exc)
                try:
                    write_smoke_failure(runtime_log,exc,result)
                except OSError as artifact_error:
                    runtime_log.exception('smoke.failure_artifact_error',artifact_error)
            finally:
                # Exactly one quit attempt, even when any UI/backend assertion
                # fails. A smoke worker must not leave an invisible GUI alive.
                try:
                    app.quit()
                except BaseException as exc:
                    smoke_error[0]=smoke_error[0] or exc
                    runtime_log.exception('smoke.quit_error',exc)
                    try:write_smoke_failure(runtime_log,smoke_error[0],result)
                    except OSError as artifact_error:
                        runtime_log.exception('smoke.failure_artifact_error',artifact_error)
                    try:
                        from System.Windows.Forms import Application
                        Application.Exit()
                    except BaseException:
                        pass
        webview.start(check_ui,gui='edgechromium',debug=False,private_mode=True,icon=str(icon_path))
    else:
        webview.start(app.started,gui='edgechromium',debug=False,private_mode=True,icon=str(icon_path))
    app.closed.set();app.cancel.set()
    app.record('app.shutdown',operation_pending=app.busy,operation=app.operation,
               note='Any operation still pending is cancelled by process exit.')
    if app.notifications: app.notifications.close()
    if app.show_event: kernel.CloseHandle(app.show_event)
    kernel.CloseHandle(mutex)
    if args.smoke_test and (smoke_error[0] is not None or not result.get('success')):
        if smoke_error[0] is not None:raise smoke_error[0]
        raise RuntimeError('Packaged offline smoke checks did not pass.')


def write_smoke_failure(runtime_log,exc,result=None):
    """Persist failure evidence outside the disposable self-test Store."""
    target=Path(sys.executable).parent
    report=dict(result or {})
    report.update(version=core.VERSION,success=False,error_type=type(exc).__name__)
    report=runtime_log.sanitize(report)
    # Re-sanitize stored events with all now-known secrets before retaining
    # them; never copy an unregistered exception string into the JSON report.
    retained=[]
    if runtime_log.path.is_file():
        for line in runtime_log.path.read_text('utf-8').splitlines():
            try:event=json.loads(line)
            except ValueError:event={'event':'smoke.unparsed_log_line','text':line}
            retained.append(json.dumps(runtime_log.sanitize(event),ensure_ascii=False))
    (target/'packaged_smoke_failure.jsonl').write_text('\n'.join(retained)+'\n',encoding='utf-8')
    (target/'packaged_smoke_results.json').write_text(
        json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return report


def main():
    import logging
    smoke_root=tempfile.TemporaryDirectory(prefix='cumt-packaged-smoke-') if '--smoke-test' in sys.argv else None
    previous_data_root=core.data_root
    if smoke_root is not None:
        core.data_root=lambda:Path(smoke_root.name)
    elif EXPERIMENTAL and not getattr(core,'EXPERIMENTAL_BUILD',False):
        def experimental_data_root():
            path=Path(os.environ.get('LOCALAPPDATA',str(Path.home()/'AppData'/'Local')))/STARTUP_VALUE_NAME
            path.mkdir(parents=True,exist_ok=True)
            return path
        core.data_root=experimental_data_root
    root_error=None
    try:
        log_root=core.data_root()
    except OSError as exc:
        # Keep a writable recovery log if the normal user data directory cannot
        # be created. No existing credential/settings file is overwritten.
        root_error=exc
        log_root=Path(tempfile.gettempdir())/(STARTUP_VALUE_NAME+'-Recovery')
        core.data_root=lambda:log_root
    log=RuntimeLog(log_root,core.VERSION,metadata={'python':sys.version,
        'frozen':bool(getattr(sys,'frozen',False)),'executable':str(sys.executable),'pid':os.getpid()})
    log.location_warning=''
    previous_thread_hook=threading.excepthook
    def thread_hook(args):
        log.exception('thread.unhandled_exception',args.exc_value,thread_name=args.thread.name)
        previous_thread_hook(args)
    class LogHandler(logging.Handler):
        def emit(self,record):
            if record.exc_info and record.exc_info[1]:
                log.exception('python.exception',record.exc_info[1],logger=record.name)
            else:
                log.event('python.message',level=record.levelname,logger=record.name,text=record.getMessage())
    handler=LogHandler(level=logging.WARNING)
    logging.getLogger().addHandler(handler)
    threading.excepthook=thread_hook
    try:
        log.event('app.starting')
        if root_error is not None:
            log.location_warning='原数据目录不可写，临时诊断目录：'+str(log_root)
            log.exception('startup.data_directory_error',root_error,recovery_root=str(log_root))
        try:
            metadata={'platform':platform.platform()}
            if getattr(sys,'frozen',False):
                metadata['executable_sha256']=hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()
            log.event('startup.environment',**metadata)
        except Exception as exc:
            log.exception('startup.environment_error',exc)
        run_main(log)
    except BaseException as exc:
        log.exception('app.unhandled_exception',exc)
        if smoke_root is not None:
            try:
                write_smoke_failure(log,exc)
            except OSError as artifact_error:
                log.exception('smoke.failure_artifact_error',artifact_error)
            # SystemExit is handled by the frozen bootloader without a modal
            # unhandled-exception window, releasing the smoke mutex promptly.
            raise SystemExit(1) from None
        raise
    finally:
        threading.excepthook=previous_thread_hook
        logging.getLogger().removeHandler(handler)
        log.close()
        core.data_root=previous_data_root
        if smoke_root is not None:
            smoke_root.cleanup()

if __name__=='__main__': main()
