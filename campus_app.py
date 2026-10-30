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
import campus_status as status_checks
from campus_logging import RuntimeLog

ROOT = Path(getattr(sys, '_MEIPASS', Path(__file__).parent))
TITLE = '矿大校园网登录器'
EXPERIMENTAL = bool(getattr(core,'EXPERIMENTAL_BUILD',False) or '--experimental' in sys.argv)
APP_USER_MODEL_ID = 'AugustT666.CumtCampusLogin' + ('.Experimental' if EXPERIMENTAL else '')
STARTUP_VALUE_NAME = 'CumtCampusLoginExperimental' if EXPERIMENTAL else 'CumtCampusLogin'
STABLE_STARTUP_VALUE_NAME = 'CumtCampusLogin'
STABLE_INSTANCE_MUTEX = r'Local\CumtCampusLoginDesktopV1'
LOGOUT_AUTO_HOLD = 60.0


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
    def set_startup(self, enabled): return self._app.set_startup(enabled)
    def login(self, account, password, operator, profile_id='', quiet_override=False):
        return self._app.login(account,password,operator,profile_id,quiet_override=quiet_override)
    def save_profile(self, profile_id, account, password, operator):
        return self._app.save_profile(profile_id,account,password,operator)
    def select_profile(self, profile_id): return self._app.select_profile(profile_id)
    def delete_profile(self, profile_id): return self._app.delete_profile(profile_id)
    def logout(self,account=None,password=None,profile_id=None): return self._app.logout(account,password,profile_id)
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


def login_already_online(result, diagnostic):
    """Interpret the portal's explicit already-online code without new queries."""
    if result is not False or not isinstance(diagnostic,dict) or diagnostic.get('operation')!='login':
        return False
    response=diagnostic.get('response')
    if not isinstance(response,dict):return False
    return protocol.portal_response_outcome(result,response)=='already_online'


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
        self._profile_io_lock=threading.RLock()
        self._ui_logging_error=''
        self._ui_state_cache=None
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
        self.logout_diagnostic={}
        self._logout_hold=None
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
            self._cache_ui_state_locked()
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

    def save_profile(self,profile_id,account,password,operator,_during_login=False):
        self.register_secrets(str(account),str(password))
        self.record('profiles.save_requested',profile_id=str(profile_id),operator=operator)
        with self.lock:
            if self.busy and not (_during_login and self.operation=='login'):
                return {'ok':False,'message':'正在登录，请稍后修改账号。'}
            if not str(account).strip() or not str(password): return {'ok':False,'message':'请输入账号和密码。'}
            if operator not in ('','telecom','unicom','cmcc','campus'):
                return {'ok':False,'message':'请选择有效的登录网络。'}
        try:
            with getattr(self,'_profile_io_lock',self.lock):
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
            with getattr(self,'_profile_io_lock',self.lock):
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
            with getattr(self,'_profile_io_lock',self.lock):
                self.store.delete_profile(str(profile_id))
                return {'ok':True,'data':self.boot()}
        except (OSError,RuntimeError) as exc:
            self.record_exception('profiles.delete_error',exc)
            return {'ok':False,'message':str(exc)}

    def get_state(self):
        # The UI must never wait behind WLAN, profile or logging I/O. A retained
        # immutable snapshot is preferable to freezing every polling API call.
        log=getattr(self,'runtime_log',None)
        log_lock=getattr(log,'_lock',None)
        if log_lock is not None and log_lock.acquire(blocking=False):
            try:
                self._ui_logging_error=str(log.write_error) or getattr(log,'location_warning','')
            finally:
                log_lock.release()
        if not self.lock.acquire(blocking=False):
            cached=getattr(self,'_ui_state_cache',None)
            return dict(cached) if cached is not None else self._ui_state_fields()
        try:
            return dict(self._cache_ui_state_locked())
        finally:
            self.lock.release()

    def _cache_ui_state_locked(self):
        try:
            self._ui_state_cache=self._ui_state_fields()
        except AttributeError:
            # Partial objects used by isolated host tests have no UI state.
            pass
        return getattr(self,'_ui_state_cache',None) or {}

    def _ui_state_fields(self):
        return {'version':core.VERSION,'ssid':self.wifi.ssid,'ip':self.wifi.ip,'campus':self.wifi.campus,
                    'student':self.wifi.student,'busy':self.busy,'operation':self.operation,
                    'logged_in':self.logged_in,'status':self.status,'pending_host':self.pending_host,
                    'session_state':getattr(self,'session_state','unknown'),
                    'session_conflict':False,
                    'logout_recovery_needed':bool(getattr(self,'_logout_recovery_needed',False)),
                    'online_account':getattr(self,'online_account','') if getattr(self,'session_state','unknown')=='online' else '',
                    'identity_source':getattr(self,'identity_source',''),
                    'session_binding':getattr(self,'session_diagnostic',{}).get('binding','unconfirmed'),
                    'session_checked_at':getattr(self,'session_checked_at',''),
                    'last_job_elapsed_ms':getattr(self,'last_job_elapsed_ms',0),
                    'quiet_hours_active':bool(self.settings.get('quiet_hours',True) is True
                                              and student_auth_time_notice(self.wifi)),
                    'logging_error':getattr(self,'_ui_logging_error','')}

    @staticmethod
    def _portal_network_context(wifi):
        # Wifi.key intentionally remains compatible with existing session/UI
        # code. Routing also depends on the NIC MAC and current gateway.
        mac=re.sub(r'[-:]','',str(wifi.mac or '')).strip().casefold()
        return (wifi.key,mac,str(wifi.gateway or ''))

    def _invalidate_portal_route(self,reason):
        with self.lock:
            self._portal_route_generation=getattr(self,'_portal_route_generation',0)+1
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
                self._invalidate_portal_route('network_context_changed')
            self._observed_portal_network=context
            return (context,getattr(self,'_portal_route_generation',0))

    def _assert_portal_route(self,wifi,expected):
        with self.lock:
            if (self._portal_network_context(wifi),getattr(self,'_portal_route_generation',0))!=expected:
                raise RuntimeError('无线连接上下文已改变，已停止本次操作；未重用旧接入设备参数。')


    def session_engine(self,wifi,tec,discover=False):
        """Cache no credentials; a new connection/IP always gets fresh context."""
        with self.lock:
            if getattr(self,'notifications',None):
                self.consume_notifications()
        token=self._observe_portal_network(wifi)
        hint=self.settings.get('portal_hint','')
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


    def run_authentication(self,wifi,account,password,operator,operation,tec,check_allowed):
        if operation!='login':raise RuntimeError('注销仅使用自助服务，不提交普通门户注销请求。')
        engine=self.session_engine(wifi,tec,discover=True)
        token=(self._portal_network_context(wifi),getattr(self,'_portal_route_generation',0))
        def guarded_submit():
            check_allowed();self._assert_portal_route(wifi,token)
        try:
            began=time.perf_counter();engine.prepare();guarded_submit()
            self.record('authentication.plan_ready',backend='verified_drcom_http',operation=operation,
                        elapsed_ms=round((time.perf_counter()-began)*1000))
            result,trace=engine.authenticate(account,password,operator,operation,before_submit=guarded_submit)
        except protocol.UnsupportedPortal as exc:
            self.record_exception('authentication.browser_fallback',exc,operation=operation)
            self._browser_auth_guard=check_allowed
            try:result=self.authenticate(wifi,account,password,operator,operation,tec)
            finally:self._browser_auth_guard=None
            self.auth_diagnostic['backend']='browser'
            self.record('authentication.result',diagnostic=self.auth_diagnostic)
            return result
        trace['backend']='verified_drcom_http'
        log=getattr(self,'runtime_log',None)
        if log is not None:trace=log.sanitize(trace)
        self.auth_diagnostic=trace;self.record('authentication.result',diagnostic=trace)
        if result is False and not login_already_online(result,trace):
            detail=(trace.get('response') or {}).get('msg') or (trace.get('response') or {}).get('message')
            if detail:self.message('认证提示：'+detail)
        return result


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
        if not self.lock.acquire(blocking=False):
            return {'ok':False,'message':'正在更新状态，请稍后重试。'}
        try:
            if self.closed.is_set(): return {'ok':False,'message':'程序已退出。'}
            if self.busy:
                return {'ok':False,'message':'正在处理，请稍候。'}
            if kind=='login' and not automatic:
                self._logout_hold=None
                self._logout_recovery_needed=False
            self.busy=True
            self.operation=kind
            self.auto_job=automatic
            self.cancel.clear()
            self.operation_id=uuid.uuid4().hex[:12]
            operation_id=self.operation_id
            self._cache_ui_state_locked()
        finally:
            self.lock.release()
        def run():
            began=time.perf_counter()
            try:
                self.record('operation.accepted',operation_id=operation_id,kind=kind,automatic=automatic)
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
                    detail+=' 结果未知，请自行确认连接情况，避免连续提交。'
                self.message(self.login_failure_message(detail) if kind=='login' else detail)
            finally:
                with self.lock:
                    self.busy=False
                    self.operation=''
                    self.auto_job=False
                    self.last_job_elapsed_ms=round((time.perf_counter()-began)*1000)
                    fields={'cancelled':self.cancel.is_set(),'elapsed_ms':self.last_job_elapsed_ms,
                            'state':getattr(self,'session_state','unknown'),'status':self.status}
                    self._cache_ui_state_locked()
                self.record('operation.finished',operation_id=operation_id,kind=kind,**fields)
        threading.Thread(target=run,daemon=True).start()
        return {'ok':True}

    def login(self,account,password,operator,profile_id='',automatic=False,expected=None,quiet_override=False):
        return self._login(account,password,operator,profile_id,automatic,expected,quiet_override)

    def _login(self,account,password,operator,profile_id='',automatic=False,expected=None,quiet_override=False):
        if not self.lock.acquire(blocking=False):
            return {'ok':False,'message':'正在更新状态，请稍后重试。'}
        try:
            if self.closed.is_set(): return {'ok':False,'message':'程序已退出。'}
            if automatic and not self.stu_automation_enabled():
                return {'ok':False,'message':'自动登录已停止。'}
            if automatic and expected is not None and not expected.campus:
                return {'ok':False,'message':'自动认证仅允许校园网。'}
            if not automatic:
                self._logout_hold=None
                self._logout_recovery_needed=False
        finally:
            self.lock.release()
        account=str(account).strip()
        password=str(password)
        if not account or not password:return {'ok':False,'message':'请输入账号和密码。'}
        def job():
            # Native WLAN, credential protection and profile I/O are worker work,
            # not a synchronous bridge call or work under the UI state lock.
            self.register_secrets(account,password)
            self.record('login.requested',operator=operator,automatic=automatic)
            wifi,tec=self.permitted(logout=True)
            if self.cancel.is_set() or self.closed.is_set():
                raise RuntimeError('本次登录已停止。')
            if automatic and (not wifi.campus or not self.stu_automation_enabled()):
                raise RuntimeError('自动登录已停止。')
            if automatic and self._logout_auto_suppressed(wifi):
                raise RuntimeError('刚请求注销，已停止本次自动登录。')
            if automatic:
                try:
                    self._ensure_exclusive_auto()
                except RuntimeError:
                    self.auth_diagnostic={'operation':'login','backend':'status_only',
                                          'phase':'coexistence_blocked','authentication_requests':0}
                    raise
            if expected: core.guard(expected,wifi,tec)
            if not tec and operator not in ('telecom','unicom','cmcc','campus'):
                raise RuntimeError('请选择登录网络。')
            effective_operator='' if tec else operator
            if not automatic:
                saved=self.save_profile(profile_id,account,password,operator,_during_login=True)
                if not saved['ok']: raise RuntimeError(saved['message'])
            with self.lock:
                if wifi.campus:self.auto_attempted=True
            token=self._observe_portal_network(wifi)
            def check_allowed():
                if self.cancel.is_set() or self.closed.is_set() or (automatic and not self.stu_automation_enabled()):
                    raise RuntimeError('本次登录已停止。')
                if automatic:self._ensure_exclusive_auto()
                current=self.checked_wifi(wifi,tec);self._assert_portal_route(wifi,token)
                return current
            with self.lock:
                self.wifi=wifi;self.settings['operator']=operator;settings=dict(self.settings)
                self._cache_ui_state_locked()
            self.store.write_settings(settings)
            self.auth_diagnostic={'operation':'login','backend':'portal','phase':'preflight','authentication_requests':0}
            notice=student_auth_time_notice(wifi)
            if self.settings.get('quiet_hours',True) is True and notice and not (quiet_override is True and not automatic):
                raise RuntimeError(notice)
            check_allowed();self.message('正在登录…')
            action_id=self.operation_id
            result=self.run_authentication(wifi,account,password,effective_operator,'login',tec,check_allowed)
            received=result if result is True or result is False else None
            if self.operation_id==action_id:
                self.auth_diagnostic.update(result=received,request_accepted=received)
            outcome=protocol.portal_response_outcome(received,self.auth_diagnostic.get('response'))
            if not self._scoped_progress(wifi,token,action_id,'login','正在确认登录状态…'):
                if self.operation_id==action_id:self.auth_diagnostic['response_context_current']=False
                self.record('authentication.reply_received',operation_id=action_id,operation='login',
                    request_accepted=received,response_context_current=False,verification_performed=False)
                return
            observation,state,confirmed=self._observed_login(wifi,
                lambda:self.status_wifi(wifi,tec),account,received,outcome)
            if confirmed and (received is True or outcome=='authentication_timeout'):
                reply_text='登录成功'
            elif confirmed and outcome=='already_online':
                reply_text='当前设备已登录，无需重复登录。'
            elif confirmed and received is None:
                reply_text='当前设备已登录；本次认证回执未能确认。'
            elif state=='online' and observation.get('online_account') and not confirmed:
                reply_text='登录未完成：当前设备仍登录其他账号，请先注销原账号。'
            elif state=='online' and (received is True or outcome or received is None):
                reply_text='当前设备已在线，但暂未确认登录账号，请点击检测状态。'
            elif outcome=='authentication_timeout':
                reply_text=('认证超时，当前设备未登录，请稍后重试。' if state=='offline' else
                            '学校响应超时，暂时无法确认登录结果，请点击检测状态。')
            elif received is False and outcome!='already_online':
                response=self.auth_diagnostic.get('response') or {}
                detail=response.get('msg') or response.get('message') or ''
                reply_text=self.login_failure_message(('认证提示：'+detail+' ' if detail else '')+
                            '登录失败，服务器未接受本次请求。',wifi)
            elif state=='offline':
                reply_text='登录未完成，当前设备未登录，请稍后重试。'
            else:
                reply_text='暂时无法确认登录结果，请点击检测状态；本次不会自动重试。'
            log=getattr(self,'runtime_log',None)
            if log is not None:reply_text=log.sanitize(reply_text)
            rediscover_next_login=False
            with self.lock:
                current_reply=self._reply_context_current_locked(wifi,token,action_id,'login')
                if self.operation_id==action_id:
                    self.auth_diagnostic.update(result=received,request_accepted=received,
                        response_context_current=current_reply,verification_performed=True,
                        verified_state=state,verified_account_matches=confirmed)
                    if outcome:self.auth_diagnostic['response_outcome']=outcome
                if current_reply:
                    self._commit_observed_state_locked(wifi,observation,reply_text)
                    if received is False and outcome!='already_online':
                        self._engine=None;self._portal_discovered=False;self.portal_key=None
                        self.auth_diagnostic['next_login_rediscovery']=True
                        rediscover_next_login=True
            self.record('authentication.reply_received',operation_id=action_id,operation='login',
                        request_accepted=received,response_context_current=current_reply,
                        verification_performed=True,verified_state=state)
            if rediscover_next_login:
                self.record('portal.route_cache_discarded',operation_id=action_id,reason='login_rejected')
            if not current_reply:return
            self.record('app.message',operation_id=action_id,text=reply_text)
        return self.start_job('login',job,automatic=automatic)

    def checked_wifi(self,wifi,tec):
        with self.lock: self.consume_notifications()
        if self.closed.is_set() or self.cancel.is_set(): raise RuntimeError('本次操作已停止。')
        if getattr(self,'auto_job',False):
            self._ensure_exclusive_auto()
        try:
            current=core.read_wifi()
        except (OSError,RuntimeError):
            self._invalidate_portal_route('wifi_read_unavailable')
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

    def _reply_context_current_locked(self,wifi,token,action_id,operation):
        """Check only retained intent/network metadata after a server reply."""
        return bool(not self.cancel.is_set() and not self.closed.is_set()
                    and self.operation_id==action_id and self.operation==operation
                    and (self._portal_network_context(wifi),getattr(self,'_portal_route_generation',0))==token
                    and getattr(self,'_observed_portal_network',None)==token[0]
                    and self._portal_network_context(self.wifi)==token[0])

    def _commit_observed_state_locked(self,wifi,observation,message=None):
        """Commit a scoped device observation, never infer state from an ACK."""
        state=status_checks._kernel_state(observation)
        self.session_state=state;self.logged_in=state=='online'
        self.online_account=(observation.get('online_account','')
            if state=='online' and observation.get('binding')=='mac_verified' else '')
        self.identity_source='verified_status'
        self.auth_key=wifi.key if state=='online' else None
        self.session_checked_key=wifi.key;self.session_checked_monotonic=time.monotonic()
        self.session_checked_at=dt.datetime.now().strftime('%H:%M:%S')
        self.session_diagnostic=dict(observation, state=state, source='portal_query',verification_performed=True)
        if message is not None:
            self.status=message
            self.messages.append({'time':dt.datetime.now().strftime('%H:%M:%S'),'text':message})
            self.messages=self.messages[-60:]
        self._cache_ui_state_locked()

    def _scoped_progress(self,wifi,token,action_id,operation,text):
        log=getattr(self,'runtime_log',None)
        if log is not None:text=log.sanitize(text)
        with self.lock:
            if not self._reply_context_current_locked(wifi,token,action_id,operation):return False
            self.status=text
            self.messages.append({'time':dt.datetime.now().strftime('%H:%M:%S'),'text':text})
            self.messages=self.messages[-60:];self._cache_ui_state_locked()
        self.record('app.message',operation_id=action_id,text=text)
        return True

    def status_wifi(self,wifi,tec):
        """Guard read-only checks without invalidating intent on a read error."""
        with self.lock:self.consume_notifications()
        if self.cancel.is_set() or self.closed.is_set():raise RuntimeError('状态检测已停止。')
        current=core.read_wifi()
        try:
            core.guard(wifi,current,tec)
            if self._portal_network_context(wifi)!=self._portal_network_context(current):
                raise RuntimeError('无线设备参数已改变。')
        except RuntimeError:
            self._observe_portal_network(current)
            raise
        return current

    def _observed_login(self,wifi,reader,account,received,response_outcome):
        deadline=time.monotonic()+(3.0 if received is not False or response_outcome else 1.0)
        observation={}
        while time.monotonic()<deadline:
            observation=status_checks.probe(wifi,reader,portal=self.portal,
                deadline=deadline,timeout=min(1.0,max(.001,deadline-time.monotonic())))
            if status_checks._kernel_state(observation)=='online':
                matched=(observation.get('binding')=='mac_verified' and observation.get('online_account')
                    and self._service_account(observation['online_account'])==self._service_account(account))
                if matched or response_outcome=='already_online' or received is False and not response_outcome:break
            if received is False and not response_outcome:break
            if observation.get('detail')=='network_context_changed':break
            delay=min(.25,max(0,deadline-time.monotonic()))
            if delay:time.sleep(delay)
        state=status_checks._kernel_state(observation)
        confirmed=bool(state=='online' and observation.get('binding')=='mac_verified'
            and observation.get('online_account')
            and self._service_account(observation['online_account'])==self._service_account(account))
        return observation,state,confirmed

    def refresh_status(self):
        def job():
            wifi,tec=self.permitted(logout=True)
            with self.lock:self.wifi=wifi;self._cache_ui_state_locked()
            token=self._observe_portal_network(wifi);action_id=self.operation_id
            self.message('正在检测登录状态…')
            observation=status_checks.probe(wifi,lambda:self.status_wifi(wifi,tec),
                portal=self.portal,deadline=time.monotonic()+1.5,timeout=1.5)
            state=status_checks._kernel_state(observation)
            text=('当前设备已登录。' if state=='online' else
                  '当前设备未登录。' if state=='offline' else '暂时无法确认登录状态，请稍后检测。')
            log=getattr(self,'runtime_log',None)
            if log is not None:text=log.sanitize(text)
            with self.lock:
                current=self._reply_context_current_locked(wifi,token,action_id,'status')
                if current:self._commit_observed_state_locked(wifi,observation,text)
            self.record('session.status_checked',operation_id=action_id,diagnostic=observation,
                        response_context_current=current)
        return self.start_job('status',job)

    def _logout_auto_suppressed(self,wifi):
        hold=getattr(self,'_logout_hold',None)
        return bool(hold and 0<=time.monotonic()-hold['started']<LOGOUT_AUTO_HOLD
                    and wifi.ssid.casefold()==hold['ssid'] and wifi.guid==hold['guid'])


    @staticmethod
    def _service_account(account):
        account=str(account).strip()
        if account.startswith(',0,'):
            account=account[3:]
        head,separator,suffix=account.rpartition('@')
        if separator and suffix.casefold() in ('telecom','unicom','cmcc','campus'):
            account=head
        return account

    def _logout_credentials(self,account=None,password=None,profile_id=None):
        if account is not None or password is not None or profile_id is not None:
            account=str(account or '').strip();password=str(password or '')
            if not account or not password:raise RuntimeError('请输入用于自助服务的账号和密码。')
            return self._service_account(account),password
        with getattr(self,'_profile_io_lock',self.lock):selected=self.store.selected_profile()
        if (not isinstance(selected,dict) or not isinstance(selected.get('account'),str)
                or not selected['account'].strip() or not isinstance(selected.get('password'),str)
                or not selected['password']):
            raise RuntimeError('请输入账号密码，或选择一个已保存账号后注销。')
        return self._service_account(selected['account']),selected['password']


    def logout(self,account=None,password=None,profile_id=None):
        def job():
            action_id=self.operation_id
            self.record('logout.requested')
            self.auth_diagnostic={'operation':'logout','backend':'selfservice','phase':'preflight',
                'authentication_requests':0,'selfservice_login_attempted':False,
                'selfservice_logout_requests':0,'logout_requests':0,'result':None}
            self.logout_diagnostic={'outcome':'pending','portal_requests':0,'verification_performed':False}
            wifi,tec=self.permitted(logout=True)
            if self.cancel.is_set() or self.closed.is_set():raise RuntimeError('本次注销已停止。')
            credentials=self._logout_credentials(account,password,profile_id)
            self.register_secrets(*credentials)
            with self.lock:
                self.wifi=wifi;self.auto_attempted=True;self._stu_popup_pending=False
                self._logout_hold={'ssid':wifi.ssid.casefold(),'guid':wifi.guid,'started':time.monotonic()}
                self._logout_recovery_needed=False;self._cache_ui_state_locked()
            token=self._observe_portal_network(wifi)
            def check_allowed():
                current=self.checked_wifi(wifi,tec);self._assert_portal_route(wifi,token)
                return current
            client=None
            try:
                check_allowed();self.message('正在注销…')
                operation_deadline=time.monotonic()+9.0
                client=selfservice.Client(wifi,reader=check_allowed,cleanup_reader=core.read_wifi,trace=self.record,
                    connection_factory=status_checks.connection_factory(operation_deadline,timeout=1.5),
                    nas_getter=status_checks.nas_getter(operation_deadline,timeout=1.0))
                client.login(*credentials)
                no_target=False
                try:
                    summary=client.submit_current(before_disconnect=check_allowed)
                except selfservice.NoMatchingDevice:
                    previous=client.safe_summary()
                    if (type(previous.get('disconnect_requests')) is not int
                            or previous['disconnect_requests']!=0
                            or type(previous.get('device_queries')) is not int
                            or previous['device_queries']<1
                            or previous.get('login_confirmed') is not True):raise
                    no_target=True
                    # Resolve only this account, using fresh, MAC-verified server
                    # evidence. No first POD was sent; this is target preparation.
                    observation=status_checks.probe(wifi,lambda:self.status_wifi(wifi,tec),portal=self.portal,
                        deadline=operation_deadline,timeout=1.0)
                    if (status_checks._kernel_state(observation)=='online'
                            and observation.get('binding')=='mac_verified'
                            and observation.get('online_account')
                            and self._service_account(observation['online_account'])==credentials[0]):
                        try:
                            summary=client.submit_current(session_info=observation,before_disconnect=check_allowed)
                            no_target=False
                        except selfservice.NoMatchingDevice:
                            summary=client.safe_summary()
                            if summary.get('disconnect_requests')!=0:raise
                    else:summary=client.safe_summary()
                accepted=summary.get('request_accepted')
                if accepted is not True and accepted is not False:accepted=None
                if self.operation_id==action_id:
                    self.auth_diagnostic.update(result=accepted,request_accepted=accepted)
                if not self._scoped_progress(wifi,token,action_id,'logout','正在确认注销结果…'):
                    if self.operation_id==action_id:self.auth_diagnostic['response_context_current']=False
                    self.record('authentication.reply_received',operation_id=action_id,operation='logout',
                        request_accepted=accepted,response_context_current=False,verification_performed=False)
                    return
                verify_deadline=min(operation_deadline,time.monotonic()+6.0)
                client.connection_factory=status_checks.connection_factory(verify_deadline,timeout=1.0)
                client.reader=lambda:self.status_wifi(wifi,tec)
                verification=status_checks.confirm_logout(wifi,client.reader,
                    list_devices=client.list_online_devices,deadline=verify_deadline,timeout=6.0)
                observation=verification.get('status') or {}
                outcome=verification.get('outcome','unknown')
                if outcome=='confirmed_offline':
                    reply_text='当前设备已下线，无需重复注销。' if no_target else '注销成功'
                    self.session_cookies=[]
                elif no_target and status_checks._kernel_state(observation)=='online':
                    if (observation.get('binding')=='mac_verified' and observation.get('online_account') and
                            self._service_account(observation['online_account'])!=credentials[0]):
                        reply_text='注销未完成：当前在线账号与填写账号不同，请选择在线账号后注销。'
                        outcome='account_mismatch'
                    else:
                        reply_text='暂时无法确认注销结果：学校显示在线，但自助服务暂未找到本机会话。'
                        outcome='unknown'
                        observation=dict(observation,state='unknown',binding='unconfirmed',online_account='')
                elif outcome=='still_online':
                    reply_text='注销未成功，当前设备仍在线，请稍后重试。'
                else:
                    reply_text='暂时无法确认注销结果，请点击检测状态；本次不会重复提交。'
                    observation=dict(observation,state='unknown',binding='unconfirmed',online_account='')
                log=getattr(self,'runtime_log',None)
                if log is not None:reply_text=log.sanitize(reply_text)
                with self.lock:
                    current_reply=self._reply_context_current_locked(wifi,token,action_id,'logout')
                    if self.operation_id==action_id:
                        self.auth_diagnostic.update(result=accepted,request_accepted=accepted,
                            verification_performed=True,verified_state=observation.get('state','unknown'),
                            response_context_current=current_reply)
                        self.logout_diagnostic.update(outcome=outcome,verification_performed=True,
                            verification=verification,no_matching_session=no_target)
                    if current_reply:
                        self._commit_observed_state_locked(wifi,observation,reply_text)
                        self._logout_recovery_needed=outcome!='confirmed_offline'
                        self._cache_ui_state_locked()
                self.record('authentication.reply_received',operation_id=action_id,operation='logout',
                    request_accepted=accepted,response_context_current=current_reply,
                    verified_outcome=outcome,verification_performed=True)
                if current_reply:self.record('app.message',operation_id=action_id,text=reply_text)
            except Exception as exc:
                self.logout_diagnostic.update(outcome='error',error_type=type(exc).__name__)
                self.record_exception('logout.error',exc)
                log=getattr(self,'runtime_log',None)
                text=str(exc) if isinstance(exc,(selfservice.SelfServiceError,RuntimeError)) else '自助服务连接失败，请稍后重试。'
                if log is not None:text=log.sanitize(text)
                with self.lock:
                    current_reply=self._reply_context_current_locked(wifi,token,action_id,'logout')
                    if current_reply:
                        self._commit_observed_state_locked(wifi,{'state':'unknown','binding':'unconfirmed'},text)
                        self._logout_recovery_needed=True;self._cache_ui_state_locked()
            finally:
                if client is not None:
                    # Management cleanup has a separate short deadline. It must
                    # not extend a failed verification into a minute-long wait.
                    client.connection_factory=status_checks.connection_factory(time.monotonic()+1.2,timeout=.7)
                    try:client.close()
                    except Exception as exc:self.record_exception('logout.management_cleanup_error',exc)
                    summary=client.safe_summary()
                    if self.operation_id==action_id:
                        self.logout_diagnostic['selfservice']=summary
                        self.auth_diagnostic['selfservice_login_attempted']=summary.get('login_attempted',False)
                        self.auth_diagnostic['selfservice_logout_requests']=summary.get('disconnect_requests',0)
                        self.auth_diagnostic['logout_requests']=summary.get('disconnect_requests',0)
                        self.auth_diagnostic['request_accepted']=summary.get('request_accepted')
                if self.operation_id==action_id:self.auth_diagnostic['phase']=self.logout_diagnostic['outcome']
                with self.lock:
                    if self.operation_id==action_id and self._logout_hold is not None:
                        self._logout_hold['started']=time.monotonic()
                    self._cache_ui_state_locked()
                self.record('logout.completed',diagnostic=self.logout_diagnostic)
        return self.start_job('logout',job)

    def authenticate(self,wifi,account,password,operator,operation,tec):
        """Execute the original portal with the private, bound WebView2 host."""
        from campus_browser import authenticate
        return authenticate(self,wifi,account,password,operator,operation,tec,
                            result_parser=authentication_result,
                            logout_select_js=LOGOUT_JS,logout_confirm_js=LOGOUT_CONFIRM_JS,
                            reader=getattr(self,'_browser_auth_guard',None) or
                                   (lambda:self.checked_wifi(wifi,tec)))

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
                self.status=('网络已改变，请重新检测状态或登录。' if current.ready
                             else '请连接校园 WiFi 后登录')
            enabled=self.stu_automation_enabled()
            hold=getattr(self,'_logout_hold',None)
            if hold and current.ssid and current.ssid.casefold()!=hold['ssid']:
                self._logout_hold=None
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
            try:
                with getattr(self,'_profile_io_lock',self.lock):
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
                    self._invalidate_portal_route('wlan_disconnect')
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
                    self.status='无线连接正在变化，请连接稳定后重新检测状态。'
                    self._cache_ui_state_locked()
            elif code==10:
                if guid==self.wifi.guid:
                    self._invalidate_portal_route('wlan_connected')
                    if self.busy:
                        self.status='无线连接已更新，请重新检测状态或登录。'
                        self._cache_ui_state_locked()
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
            try:self.poll_wifi()
            except Exception as exc:
                self.record_exception('network.monitor_error',exc)
                self.message('暂时无法读取网络状态')
            self.poll_show_event()
            if self.notifications:
                self.notifications.wake.wait(1);self.notifications.wake.clear()
            else:self.closed.wait(1)

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
                          manual_status_action=app.window.evaluate_js("!!document.getElementById('status-refresh') && !document.getElementById('network-check') && !document.getElementById('cancel-operation')"),
                          manual_status_api=app.window.evaluate_js("typeof window.pywebview.api.refresh_status==='function' && typeof window.pywebview.api.network_check==='undefined' && typeof window.pywebview.api.cancel_operation==='undefined'"),
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
            result['success']=result['client_ready'] and result['displayed_ssid']==(app.wifi.ssid or '未连接网络') and result['ui_title']==TITLE and result['api_ready']=='function' and result['startup_switch'] and result['single_login_entry'] and result['profiles'] and result['no_tec_warning'] and result['independent_logout'] and result['manual_status_action'] and result['manual_status_api'] and result['runtime_log_ready'] and result['diagnostic_zip_verified'] and result['online_identity_display'] and result['window_restore_verified'] and result['ui_logo_loaded'] and result['native_icon']['verified'] and result['webview2_compatibility']['success']
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
