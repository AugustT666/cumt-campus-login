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
from campus_logging import RuntimeLog

ROOT = Path(getattr(sys, '_MEIPASS', Path(__file__).parent))
TITLE = '矿大校园网登录器'
APP_USER_MODEL_ID = 'AugustT666.CumtCampusLogin'

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
                    'online_account':getattr(self,'online_account','') if getattr(self,'session_state','unknown')=='online' else '',
                    'identity_source':getattr(self,'identity_source',''),
                    'session_binding':getattr(self,'session_diagnostic',{}).get('binding','unconfirmed'),
                    'session_checked_at':getattr(self,'session_checked_at',''),
                    'last_job_elapsed_ms':getattr(self,'last_job_elapsed_ms',0),
                    'quiet_hours_active':bool(self.settings.get('quiet_hours',True) is True
                                              and student_auth_time_notice(self.wifi)),
                    'logging_error':(str(log.write_error) or getattr(log,'location_warning','')) if log is not None else ''}

    def session_engine(self,wifi,tec,discover=False):
        """Cache no credentials; a new connection/IP always gets fresh context."""
        if discover and (self.portal_key!=wifi.key or not getattr(self,'_portal_discovered',False)):
            self.record('portal.discovery_started',wifi=core.asdict(wifi))
            portal,_=core.discover(wifi,self.settings.get('portal_hint',''),
                                   reader=lambda:self.checked_wifi(wifi,tec),allow_tec=tec)
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
            engine=protocol.Engine(wifi,self.portal,reader=lambda:self.checked_wifi(wifi,tec),allow_tec=tec)
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
            if announce:
                self.message({'online':'当前无线网已登录，可直接注销',
                              'offline':'当前无线网未登录',
                              'unknown':self.status_failure_message(report,'暂时无法确认登录状态，请排查后刷新。')
                                        if report.get('network_error') else
                                        '暂时无法确认登录状态，可刷新或手动登录'}[self.session_state])

    @staticmethod
    def status_failure_message(report,fallback):
        error=report.get('network_error')
        detail=error.get('message','') if isinstance(error,dict) else ''
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
        # An online status response already identifies this portal for logout;
        # probing public captive URLs while online adds delays and no context.
        engine=self.session_engine(wifi,tec,discover=operation=='login')
        try:
            began=time.perf_counter()
            engine.prepare()
            self.record('authentication.plan_ready',backend='verified_drcom_http',operation=operation,
                        elapsed_ms=round((time.perf_counter()-began)*1000))
            check_allowed()
            result,trace=engine.authenticate(account,password,operator,operation,before_submit=check_allowed)
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

    def startup_enabled(self):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,r'Software\Microsoft\Windows\CurrentVersion\Run') as key:
                value,_=winreg.QueryValueEx(key,'CumtCampusLogin')
                return str(sys.executable if getattr(sys,'frozen',False) else Path(__file__).resolve()).casefold() in value.casefold()
        except OSError:
            return False

    def set_startup(self,enabled):
        with self.lock:
            return self._set_startup(enabled)

    def _set_startup(self,enabled):
        if type(enabled) is not bool:
            return {'ok':False,'message':'自动启动设置无效，请重新选择。'}
        self.record('startup.setting_requested',enabled=enabled)
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
                    winreg.SetValueEx(key,'CumtCampusLogin',0,winreg.REG_SZ,command)
                else:
                    try: winreg.DeleteValue(key,'CumtCampusLogin')
                    except FileNotFoundError: pass
            self.settings=updated
            # Enabling while already connected does not submit unexpectedly.
            if enabled and current.student:
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
            if automatic and (not wifi.student or not self.stu_automation_enabled()):
                return {'ok':False,'message':'自动登录已停止。'}
            if expected: core.guard(expected,wifi)
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
            if wifi.student: self.auto_attempted=True
        def check_allowed():
            if self.cancel.is_set() or self.closed.is_set() or (automatic and not self.stu_automation_enabled()):
                raise RuntimeError('本次登录已停止。')
            core.guard(wifi,core.read_wifi(),tec)
        def job():
            check_allowed()
            self.auth_diagnostic={'operation':'login','backend':'status_only','phase':'checking_status',
                                  'authentication_requests':0}
            with self.lock:
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
            elif result is False:
                self.logged_in=False;self.auth_key=None;self.session_state='offline'
                self.online_account='';self.identity_source=''
                detail=self.status if self.status.startswith('认证提示：') else (
                    '登录失败，请检查账号和密码。' if tec else '登录失败，请检查账号、密码及运营商绑定。')
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
        current=core.read_wifi()
        core.guard(wifi,current,tec)
        return current

    def logout(self):
        self.record('logout.requested')
        try:
            wifi,tec=self.permitted(logout=True)
        except RuntimeError as exc:
            self.record_exception('logout.rejected',exc)
            return {'ok':False,'message':str(exc)}
        def job():
            self.wifi=wifi
            self.message('正在检查登录状态…')
            report=self.session_engine(wifi,tec).status()
            self.apply_session(wifi,report)
            if report.get('state')=='offline':
                self.message('当前无线网未登录，无需注销')
                return
            if report.get('state')!='online':
                self.message(self.status_failure_message(report,'未确认当前登录状态，请刷新状态后再注销'))
                return
            def check_allowed():
                self.checked_wifi(wifi,tec)
            self.message('正在退出登录…')
            result=self.run_authentication(wifi,'','',self.settings.get('operator',''),'logout',tec,check_allowed)
            check_allowed()
            # The original school page also rejects the reported field
            # session. Preserve that failure and read back status; repeating
            # another logout transport cannot establish success.
            report=self.session_engine(wifi,tec).status()
            self.apply_session(wifi,report)
            if report.get('state')=='offline':
                self.session_cookies=[]
                self.message('已退出登录（服务器状态已确认）')
            elif result is False:
                self.record('logout.rejected',state=report.get('state'),diagnostic=self.auth_diagnostic)
                detail=('学校认证服务器拒绝注销，当前设备仍在线。可从帮助进入自助服务下线后刷新状态。'
                        if report.get('state')=='online' else
                        '学校认证服务器拒绝注销，当前在线状态暂不确定。可从帮助进入自助服务下线后刷新状态。')
                self.message(self.status_failure_message(report,detail))
            elif result is True:
                self.message(self.status_failure_message(report,'服务器已接受注销，当前状态尚未确认，请刷新状态。'))
            else:
                detail=self.status_failure_message(report,'注销结果未知，未再次提交；请刷新状态后再操作。')
                self.message(self.status_failure_message(self.auth_diagnostic,detail))
        return self.start_job('logout',job)

    def authenticate(self,wifi,account,password,operator,operation,tec):
        """Execute the original portal DOM/script. No guessed login/logout API."""
        from playwright.sync_api import sync_playwright
        host=urlsplit(self.portal).hostname
        count=[0]
        submission_started=[False]
        sensitive_phase=[False]
        preparation_blocked=[False]
        results=[]
        trace={'operation':operation,'phase':'loading','authentication_requests':0,
               'resource_errors':[],'page_errors':[],'blocked_requests':0}
        self.auth_diagnostic=trace
        def sanitized(value,limit=200):
            text=protocol.Engine._redact(value,account,password)
            log=getattr(self,'runtime_log',None)
            if log is not None:text=log.sanitize(text)
            return text[:limit] if limit is not None else text
        def intercept(route):
            request=route.request
            p=urlsplit(request.url)
            if p.hostname!=host or p.scheme not in ('http','https') or p.port not in (None,80,443,801,802):
                self.record('browser.request_blocked',level='WARNING',url=request.url,reason='unapproved_origin')
                route.abort();return
            connection=None
            try:
                if self.closed.is_set() or self.cancel.is_set():
                    route.abort();return
                core.guard(wifi,core.read_wifi(),tec)
                query=dict(core.parse_qsl(p.query))
                request_headers=request.all_headers()
                form_values={}
                if request.method=='POST':
                    content_type=next((v for k,v in request_headers.items() if k.lower()=='content-type'),'')
                    if 'application/json' in content_type.lower():
                        parsed=protocol.parse_jsonp(request.post_data or '')
                        if parsed is None:
                            raise ValueError('认证请求JSON格式无效。')
                        form_values=parsed
                    else:
                        form_values=dict(core.parse_qsl(request.post_data or ''))
                action=str(query.get('a',form_values.get('a',''))).casefold() or p.path.rstrip('/').split('/')[-1].casefold()
                credential_keys={'ddddd','dddddd','user_account','user_password','username','account','password','upass'}
                has_credentials=any(k.casefold() in credential_keys for k in (*query,*form_values))
                # Any write method is a submission candidate, including JSON and
                # opaque bodies. Once secrets are filled, no resource request is
                # allowed to smuggle them through an unrecognized GET endpoint.
                auth_request=(request.method not in ('GET','HEAD')
                              or action in ('login','logout') or has_credentials)
                denied=(auth_request and (not submission_started[0] or action!=operation)
                        or sensitive_phase[0] and not auth_request)
                if denied or auth_request and count[0]>=1:
                    trace['blocked_requests']+=1
                    if sensitive_phase[0] and not submission_started[0]:
                        preparation_blocked[0]=True
                    self.record('browser.request_blocked',level='WARNING',url=request.url,
                                reason='duplicate_submission' if auth_request and count[0]>=1 else 'submission_phase')
                    route.abort();return
                resource_started=time.perf_counter()
                self.record('browser.http_request',method=request.method,url=request.url,
                            resource_type=request.resource_type,authentication_request=auth_request)
                connection=core.BoundHTTP(p.hostname,p.port or (443 if p.scheme=='https' else 80),wifi,p.scheme=='https')
                headers={k:v for k,v in request_headers.items() if k.lower() not in ('host','connection','accept-encoding','content-length')}
                headers['Connection']='close'
                target=urlunsplit(('','',p.path or '/',p.query,''))
                if auth_request:
                    with self.lock:
                        self.checked_wifi(wifi,tec)
                        if self.auto_job and not self.stu_automation_enabled():
                            route.abort();return
                        count[0]+=1
                        trace['authentication_requests']=count[0]
                        connection.request(request.method,target,request.post_data_buffer,headers)
                else:
                    self.checked_wifi(wifi,tec)
                    connection.request(request.method,target,request.post_data_buffer,headers)
                response=connection.getresponse()
                wire_body=response.read(core.MAX_HTTP_WIRE_BYTES+1)
                if len(wire_body)>core.MAX_HTTP_WIRE_BYTES:
                    raise ValueError('认证页面资源过大。')
                body,response_headers=core.decode_http_body(wire_body,response.getheaders())
                self.record('browser.http_response',url=request.url,status=response.status,
                            decoded_bytes=len(body),body_sha256=hashlib.sha256(body).hexdigest(),
                            content_type=response_headers.get('Content-Type',''),
                            location=response_headers.get('Location',''),
                            elapsed_ms=round((time.perf_counter()-resource_started)*1000))
                text=core.decode_text(body,response_headers)
                evidence_url=request.url
                if 'a' in form_values and 'a' not in query:
                    evidence_url=urlunsplit((p.scheme,p.netloc,p.path,core.urlencode({'a':form_values['a']}),''))
                evidence=authentication_result(text,evidence_url,operation) if auth_request else None
                if evidence is not None:
                    results.append(evidence)
                    trace['phase']='response_received'
                    trace['result']=evidence
                    data=protocol.parse_jsonp(text)
                    trace['response']={k:sanitized(
                        protocol.decode_portal_message(data[k],data.get('ret_code')) if k=='msg' else data[k],limit=None)
                        for k in ('result','ret_code','msg','message') if k in data}
                    if evidence is False:
                        detail=trace['response'].get('msg') or trace['response'].get('message')
                        if detail: self.message('认证提示：'+detail)
                route.fulfill(status=response.status,headers=response_headers,body=body)
            except Exception as exc:
                if sensitive_phase[0] and not submission_started[0]:
                    preparation_blocked[0]=True
                self.record_exception('browser.resource_error',exc,url=request.url)
                trace['resource_errors'].append({'path':p.path,'error':type(exc).__name__})
                trace['resource_errors']=trace['resource_errors'][-12:]
                route.abort()
            finally:
                if connection: connection.close()

        with sync_playwright() as p:
            browser=None
            for channel in ('msedge','chrome'):
                try:
                    browser=p.chromium.launch(channel=channel,headless=True,args=['--no-proxy-server','--disable-background-networking','--disable-quic','--force-webrtc-ip-handling-policy=disable_non_proxied_udp'])
                    break
                except Exception as exc:
                    self.record_exception('browser.launch_error',exc,channel=channel)
            if not browser:
                raise RuntimeError('未找到可用的 Edge 或 Chrome 浏览器。')
            context=browser.new_context(service_workers='block',accept_downloads=False)
            context.route('**/*',intercept)
            if hasattr(context,'route_web_socket'):
                context.route_web_socket('**/*',lambda ws:ws.close())
            if operation=='logout' and self.session_cookies:
                context.add_cookies(self.session_cookies)
            page=context.new_page()
            page.set_default_timeout(12000)
            def page_error(exc):
                trace['page_errors'].append(sanitized(exc))
                self.record('browser.page_error',level='ERROR',error=sanitized(exc,limit=None))
            page.on('pageerror',page_error)
            page.on('requestfailed',lambda request:self.record('browser.request_failed',level='WARNING',
                    url=request.url,failure=request.failure))
            def dialog(d):
                if (operation=='logout' and submission_started[0] and d.type=='confirm'
                    and re.search(r'注销|退出|logout',d.message,re.I)):
                    trace['confirmation']='native'
                    d.accept()
                    return
                text=sanitized(d.message)
                self.message('认证提示：'+text[:160])
                d.dismiss()
            page.on('dialog',dialog)
            try:
                page.goto(core.fresh_url(self.portal,wifi),wait_until='domcontentloaded',timeout=35000)
                # The real Dr.COM document is initially empty; a41.js loads the
                # form, localization and event handlers asynchronously.
                from playwright.sync_api import TimeoutError as PlaywrightTimeout
                try:
                    page.wait_for_function(r'''operation => {
                      const visible=e=>e&&e.getClientRects().length&&!e.disabled;
                      if (operation==='login') {
                        const user=Array.from(document.querySelectorAll('input[name="DDDDD"],input[name="user_account"],input[name="username"],input[name="account"],input#username,input#user_account')).some(visible);
                        const pass=Array.from(document.querySelectorAll('input[type="password"]')).some(visible);
                        if (!user||!pass) return false;
                      } else {
                        const buttons=Array.from(document.querySelectorAll('button,input[type="submit"],input[type="button"],a')).filter(visible);
                        if (!buttons.some(e=>/^(注销|注销登录|退出|退出登录|断开|下线|logout)$/i.test((e.innerText||e.value||'').replace(/\s+/g,'')))) return false;
                      }
                      return typeof window.page==='undefined'||!window.page.load_js_css||typeof window.login==='object';
                    }''',arg=operation,timeout=25000)
                    # Process pending dynamic scripts before interacting with the form.
                    page.wait_for_load_state('networkidle',timeout=15000)
                except PlaywrightTimeout:
                    trace['phase']='page_not_ready'
                    raise RuntimeError('认证页面加载不完整，未提交账号；请查看诊断后重试。')
                core.guard(wifi,core.read_wifi(),tec)
                if urlsplit(page.url).hostname!=host:
                    raise RuntimeError('认证页面跳转异常，已停止操作。')
                if operation=='login':
                    sensitive_phase[0]=True
                    fields=page.evaluate(core.FILL_JS,{'account':account,'password':password,'operator':operator})
                    self.record('browser.form_inspection',result=fields)
                    if not fields.get('ok') or not fields.get('can_submit'):
                        trace['phase']='form_not_supported'
                        raise RuntimeError(fields.get('reason') or '当前认证页面暂不支持自动登录，请通过浏览器完成认证。')
                    # Drain requests scheduled by input/change handlers before
                    # granting the one explicit button click its send permission.
                    page.wait_for_timeout(100)
                    if preparation_blocked[0]:
                        trace['phase']='form_network_blocked'
                        raise RuntimeError('认证页面在填表期间尝试发送请求，已阻止；未正式提交，请通过浏览器手动登录。')
                    self.checked_wifi(wifi,tec)
                    submission_started[0]=True
                    trace['phase']='submitting'
                    page.locator('[data-cumt-login-button="1"]').click(no_wait_after=True)
                else:
                    if not page.evaluate(LOGOUT_JS):
                        raise RuntimeError('未找到注销入口，请通过校园认证页退出登录。')
                    self.checked_wifi(wifi,tec)
                    sensitive_phase[0]=True
                    submission_started[0]=True
                    trace['phase']='submitting'
                    page.locator('[data-cumt-logout-button="1"]').click(no_wait_after=True)
                confirmed=False
                for _ in range(14):
                    if results or self.cancel.is_set() or self.closed.is_set(): break
                    if operation=='logout' and not confirmed and page.evaluate(LOGOUT_CONFIRM_JS):
                        self.checked_wifi(wifi,tec)
                        page.locator('[data-cumt-logout-confirm="1"]').click(no_wait_after=True)
                        confirmed=True
                        trace['confirmation']='portal_dialog'
                    page.wait_for_timeout(500)
                if operation=='login': self.session_cookies=context.cookies()
                if results: return results[-1]
                # Instructional page text is not proof of authentication.
                return None
            finally:
                context.close();browser.close()

    def poll_wifi(self):
        """Show each STU connection independently of its optional authentication."""
        current=core.read_wifi()
        attempt=False
        popup=False
        with self.lock:
            self.consume_notifications()
            previous=self.wifi
            self.wifi=current
            first_poll=not getattr(self,'_stu_poll_initialized',False)
            self._stu_poll_initialized=True
            if not previous.student and previous.ip:
                self._stu_previous_network=(previous.ip,previous.gateway,previous.index)
            if not current.student and current.ip:
                self._stu_previous_network=(current.ip,current.gateway,current.index)
            connection=(current.ssid.casefold(),current.guid,current.index) if current.student else None
            reset=getattr(self,'_stu_popup_reset_pending',False)
            if not current.student:
                self._stu_popup_connection=None
                self._stu_popup_pending=False
                self._stu_auth_snapshot=None
                self._stu_auth_stable_count=0
                self._stu_network_pending=False
            elif reset or connection!=getattr(self,'_stu_popup_connection',None):
                self._stu_popup_connection=connection
                self._stu_popup_reset_pending=False
                # A manual launch already has a visible window. A hidden
                # Windows-startup launch must still show when STU is present.
                manual_initial=(first_poll and not getattr(self,'startup',False)
                                and self.window is not None and not reset
                                and (not previous.ssid or previous.student))
                self._stu_popup_pending=not manual_initial
                self._stu_auth_snapshot=None
                self._stu_auth_stable_count=0
                self.record('network.stu_connection',popup_pending=self._stu_popup_pending,
                            manual_initial=manual_initial,interface_index=current.index)
            # DHCP renewal alone is NOT a new connection/permission to retry.
            if not current.student or (previous.student and current.guid!=previous.guid):
                self.auto_attempted=False
            if current.key!=previous.key:
                self.record('network.changed',previous=core.asdict(previous),current=core.asdict(current))
                self.portal_key=None
                self.pending_host=''
                self._engine=None
                self._portal_discovered=False
                self.session_state='unknown'
                self.session_checked_key=None
                self.session_checked_monotonic=0.0
                if self.busy: self.cancel.set()
                if self.auth_key and current.key!=self.auth_key:
                    self.logged_in=False
                    self.auth_key=None
                    self.session_cookies=[]
                if not self.busy:
                    self.status='未登录' if current.ready else '请连接校园 WiFi 后登录'
            enabled=self.stu_automation_enabled()
            if (enabled and current.student and current.guid not in self.reconnecting
                    and getattr(self,'_stu_popup_pending',False) and self.window is not None):
                self._stu_popup_pending=False
                popup=True
            # SSID changes can precede DHCP by several seconds, including a
            # private 10/8 address left over from a phone hotspot. Never consume
            # the one authentication attempt for that stale lease.
            stale=getattr(self,'_stu_previous_network',None)
            carried=bool(stale and (current.ip==stale[0]
                         or (stale[1] and current.gateway==stale[1])))
            network_ready=(current.student and current.ready and core.campus_host(current.ip)
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
                if carried and current.student:
                    self._stu_auth_requires_stability=True
            waiting=bool(current.student and not network_ready)
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
                        self.message('已连接学生网，请选择或填写账号后登录。')
                    elif selected.get('operator') not in ('telecom','unicom','cmcc','campus'):
                        self.record('network.auto_login_skipped',reason='operator_not_selected')
                        self.message('已连接学生网，请选择账号对应的登录网络。')
                    else:
                        result=self.login(selected['account'],selected['password'],selected['operator'],
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
    args=parser.parse_args()
    runtime_log.event('startup.options',startup=args.startup,watch=args.watch,smoke_test=args.smoke_test,diagnose=args.diagnose)
    if args.diagnose:
        print(json.dumps(core.asdict(core.read_wifi()),ensure_ascii=False,indent=2));return
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateMutexW.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_wchar_p]
    kernel.CreateMutexW.restype=ctypes.c_void_p
    # Self-test is independent of an old user instance; normal use remains single-instance.
    mutex_name='Local\\CumtCampusLoginSmokeV13' if args.smoke_test else 'Local\\CumtCampusLoginDesktopV1'
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
    event_name='Local\\CumtCampusLoginShowV13'
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
        result={'mode':'packaged offline smoke test','version':core.VERSION,'campus_requests':0,'network_changes':0,
                'windows_app_identity':app_identity}
        def check_ui():
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
            result['success']=result['client_ready'] and result['displayed_ssid']==(app.wifi.ssid or '未连接网络') and result['ui_title']==TITLE and result['api_ready']=='function' and result['startup_switch'] and result['single_login_entry'] and result['profiles'] and result['no_tec_warning'] and result['independent_logout'] and result['status_refresh'] and result['network_check_entry'] and result['runtime_log_ready'] and result['diagnostic_zip_verified'] and result['online_identity_display'] and result['window_restore_verified'] and result['ui_logo_loaded'] and result['native_icon']['verified']
            (Path(sys.executable).parent/'packaged_smoke_results.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),'utf-8')
            app.quit()
        webview.start(check_ui,gui='edgechromium',debug=False,private_mode=True,icon=str(icon_path))
    else:
        webview.start(app.started,gui='edgechromium',debug=False,private_mode=True,icon=str(icon_path))
    app.closed.set();app.cancel.set()
    app.record('app.shutdown',operation_pending=app.busy,operation=app.operation,
               note='Any operation still pending is cancelled by process exit.')
    if app.notifications: app.notifications.close()
    if app.show_event: kernel.CloseHandle(app.show_event)
    kernel.CloseHandle(mutex)

def main():
    import logging
    smoke_root=tempfile.TemporaryDirectory(prefix='cumt-packaged-smoke-') if '--smoke-test' in sys.argv else None
    previous_data_root=core.data_root
    if smoke_root is not None:
        core.data_root=lambda:Path(smoke_root.name)
    root_error=None
    try:
        log_root=core.data_root()
    except OSError as exc:
        # Keep a writable recovery log if the normal user data directory cannot
        # be created. No existing credential/settings file is overwritten.
        root_error=exc
        log_root=Path(tempfile.gettempdir())/'CumtCampusLogin-Recovery'
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
        raise
    finally:
        threading.excepthook=previous_thread_hook
        logging.getLogger().removeHandler(handler)
        log.close()
        core.data_root=previous_data_root
        if smoke_root is not None:
            smoke_root.cleanup()

if __name__=='__main__': main()
