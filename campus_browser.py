"""Bound WiFi portal execution through a private WebView2 control."""
import hashlib
import json
import re
import threading
import time
from urllib.parse import urlsplit,urlunsplit,parse_qs

import campus_core as core
import campus_protocol as protocol
from campus_webview2 import WebView2Host,Response

READY_TIMEOUT=25.0
IDLE_TIMEOUT=15.0
RESULT_TIMEOUT=7.0

def authenticate(self,wifi,account,password,operator,operation,tec,*,result_parser,logout_select_js,logout_confirm_js,
                 reader=None,connection_factory=None):
    """Execute the original portal DOM/script. No guessed login/logout API."""
    host=urlsplit(self.portal).hostname
    reader=core.read_wifi if reader is None else reader
    connection_factory=core.BoundHTTP if connection_factory is None else connection_factory
    count=[0]
    submission_started=[False]
    sensitive_phase=[False]
    preparation_blocked=[False]
    results=[]
    trace={'operation':operation,'transport':'webview2_bound_http','phase':'loading','authentication_requests':0,
           'resource_errors':[],'page_errors':[],'blocked_requests':0}
    self.auth_diagnostic=trace
    def sanitized(value,limit=200):
        text=protocol.Engine._redact(value,account,password)
        log=getattr(self,'runtime_log',None)
        if log is not None:text=log.sanitize(text)
        return text[:limit] if limit is not None else text
    def intercept(request):
        p=urlsplit(request.url)
        if p.hostname!=host or p.scheme not in ('http','https') or p.port not in (None,80,443,801,802):
            self.record('browser.request_blocked',level='WARNING',url=request.url,reason='unapproved_origin')
            return None
        connection=None
        try:
            arrived_armed,arrived_sensitive=(request.arrival_context
                if request.arrival_context is not None else (submission_started[0],sensitive_phase[0]))
            if self.closed.is_set() or self.cancel.is_set():
                return None
            core.guard(wifi,reader(),tec)
            query=dict(core.parse_qsl(p.query))
            request_headers=request.headers
            post_data=(request.body or b'').decode('utf-8','replace')
            form_values={}
            if request.method=='POST':
                content_type=next((v for k,v in request_headers.items() if k.lower()=='content-type'),'')
                if 'application/json' in content_type.lower():
                    parsed=protocol.parse_jsonp(post_data)
                    if parsed is None:
                        raise ValueError('认证请求JSON格式无效。')
                    form_values=parsed
                else:
                    form_values=dict(core.parse_qsl(post_data))
            action=str(query.get('a',form_values.get('a',''))).casefold() or p.path.rstrip('/').split('/')[-1].casefold()
            credential_keys={'ddddd','dddddd','user_account','user_password','username','account','password','upass'}
            has_credentials=any(k.casefold() in credential_keys for k in (*query,*form_values))
            # Any write method is a submission candidate, including JSON and
            # opaque bodies. Once secrets are filled, no resource request is
            # allowed to smuggle them through an unrecognized GET endpoint.
            auth_request=(request.method not in ('GET','HEAD')
                          or action in ('login','logout') or has_credentials)
            denied=(auth_request and (not arrived_armed or not submission_started[0] or action!=operation)
                    or (arrived_sensitive or sensitive_phase[0]) and not auth_request)
            if denied or auth_request and count[0]>=1:
                trace['blocked_requests']+=1
                if sensitive_phase[0] and not submission_started[0]:
                    preparation_blocked[0]=True
                self.record('browser.request_blocked',level='WARNING',url=request.url,
                            reason='duplicate_submission' if auth_request and count[0]>=1 else 'submission_phase')
                return None
            resource_started=time.perf_counter()
            self.record('browser.http_request',method=request.method,url=request.url,
                        resource_type=request.resource_type,authentication_request=auth_request)
            connection=connection_factory(p.hostname,p.port or (443 if p.scheme=='https' else 80),wifi,p.scheme=='https')
            headers={k:v for k,v in request_headers.items() if k.lower() not in ('host','connection','accept-encoding','content-length')}
            headers['Connection']='close'
            target=urlunsplit(('','',p.path or '/',p.query,''))
            if auth_request:
                with self.lock:
                    self.checked_wifi(wifi,tec)
                    if self.auto_job and not self.stu_automation_enabled():
                        return None
                    # WebView2 resource workers are concurrent. Recheck the
                    # complete admission rule while holding the send lock.
                    if (not arrived_armed or not submission_started[0]
                            or action!=operation or count[0]>=1):
                        trace['blocked_requests']+=1
                        self.record('browser.request_blocked',level='WARNING',url=request.url,
                                    reason='duplicate_submission' if count[0]>=1 else 'submission_phase')
                        return None
                    count[0]+=1
                    trace['authentication_requests']=count[0]
                    connection.request(request.method,target,request.body,headers)
            else:
                self.checked_wifi(wifi,tec)
                connection.request(request.method,target,request.body,headers)
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
            evidence=result_parser(text,evidence_url,operation) if auth_request else None
            if evidence is not None:
                results.append(evidence)
                trace['phase']='response_received'
                trace['result']=evidence
                data=protocol.parse_jsonp(text)
                trace['response']={k:sanitized(
                    protocol.decode_portal_message(data[k],data.get('ret_code')) if k=='msg' else data[k],limit=None)
                    for k in ('result','ret_code','msg','message') if k in data}
                if evidence is False:
                    value,code=data.get('result'),data.get('ret_code')
                    rejected=(type(value) is int and value==0) or (type(value) is str and value=='0')
                    already=(type(code) is int and code==2) or (type(code) is str and code=='2')
                    # App presents this exact login reply as already online,
                    # without claiming that the entered account was accepted.
                    # Keep its False receipt and avoid flashing the raw error
                    # before that final feedback. Other rejections stay visible.
                    if not (operation=='login' and rejected and already):
                        detail=trace['response'].get('msg') or trace['response'].get('message')
                        if detail:self.message('认证提示：'+detail)
            return Response(response.status,response_headers,body)
        except Exception as exc:
            if sensitive_phase[0] and not submission_started[0]:
                preparation_blocked[0]=True
            self.record_exception('browser.resource_error',exc,url=request.url)
            trace['resource_errors'].append({'path':p.path,'error':type(exc).__name__})
            trace['resource_errors']=trace['resource_errors'][-12:]
            return None
        finally:
            if connection: connection.close()


    def dialog(kind,message):
        if (operation=='logout' and submission_started[0] and kind=='confirm'
                and re.search(r'注销|退出|logout',message,re.I)):
            trace['confirmation']='native'
            return True
        self.message('认证提示：'+sanitized(message,160))
        return False

    def check():
        self.checked_wifi(wifi,tec)

    def arm_submission():
        # Button readiness/scrolling may run page scripts. Recheck the complete
        # pre-submit state only when trusted input is about to begin.
        with self.lock:
            check()
            if preparation_blocked[0]:
                trace['phase']='form_network_blocked'
                raise RuntimeError('认证页面在填表期间尝试发送请求，已阻止；未正式提交，请通过浏览器手动登录。')
            submission_started[0]=True
            trace['phase']='submitting'

    ready_script=r'''operation => {
      const visible=e=>e&&e.getClientRects().length&&!e.disabled;
      if(operation==='login') {
        const user=Array.from(document.querySelectorAll('input[name="DDDDD"],input[name="user_account"],input[name="username"],input[name="account"],input#username,input#user_account')).some(visible);
        if(!user||!Array.from(document.querySelectorAll('input[type="password"]')).some(visible))return false;
      } else {
        if(!Array.from(document.querySelectorAll('button,input[type="submit"],input[type="button"],a')).filter(visible).some(e=>/^(注销|注销登录|退出|退出登录|断开|下线|logout)$/i.test((e.innerText||e.value||e.getAttribute('aria-label')||'').replace(/\s/g,''))))return false;
      }
      return typeof window.page==='undefined'||!window.page.load_js_css||typeof window.login==='object';
    }'''
    try:
        with WebView2Host(intercept,dialog,host=host,
                         context_provider=lambda:(submission_started[0],sensitive_phase[0])) as page:
            try:
                if operation=='logout' and self.session_cookies:
                    page.add_cookies(self.session_cookies)
                page.navigate(core.fresh_url(self.portal,wifi))
                until=time.monotonic()+READY_TIMEOUT
                while True:
                    check()
                    if page.evaluate(ready_script,operation):break
                    if time.monotonic()>=until:
                        trace['phase']='page_not_ready'
                        raise RuntimeError('认证页面加载不完整，未提交账号；请查看诊断后重试。')
                    time.sleep(.04)
                if not page.wait_idle(IDLE_TIMEOUT,quiet_period=.5):
                    trace['phase']='page_not_ready'
                    raise RuntimeError('认证页面加载不完整，未提交账号；请查看诊断后重试。')
                check()
                if operation=='login':
                    sensitive_phase[0]=True
                    fields=page.evaluate(core.FILL_JS,{'account':account,'password':password,'operator':operator})
                    self.record('browser.form_inspection',result=fields)
                    if not fields.get('ok') or not fields.get('can_submit'):
                        trace['phase']='form_not_supported'
                        raise RuntimeError(fields.get('reason') or '当前认证页面暂不支持自动登录，请通过浏览器完成认证。')
                    # Drain synchronous and short deferred fill-event traffic while the
                    # transport remains disarmed. Such traffic never consumes a send.
                    time.sleep(.1)
                    if not page.wait_idle(.5):
                        preparation_blocked[0]=True
                    if preparation_blocked[0]:
                        trace['phase']='form_network_blocked'
                        raise RuntimeError('认证页面在填表期间尝试发送请求，已阻止；未正式提交，请通过浏览器手动登录。')
                    check()
                    page.click('[data-cumt-login-button="1"]',check=check,
                               before_click=arm_submission)
                else:
                    selected=page.evaluate(logout_select_js)
                    if not selected:
                        raise RuntimeError('未找到唯一的注销按钮，请先刷新状态。')
                    check()
                    sensitive_phase[0]=True
                    page.click('[data-cumt-logout-button="1"]',check=check,
                               before_click=arm_submission)
                confirmed=False
                until=time.monotonic()+RESULT_TIMEOUT
                while time.monotonic()<until:
                    if results or self.cancel.is_set() or self.closed.is_set():break
                    check()
                    if operation=='logout' and not confirmed and page.evaluate(logout_confirm_js):
                        check()
                        page.click('[data-cumt-logout-confirm="1"]',check=check)
                        confirmed=True
                        trace['confirmation']='portal_dialog'
                    time.sleep(.04)
                # Complete already-arrived resource events before reading the final
                # diagnostic; duplicate DOM attempts must be observed as blocked.
                page.wait_idle(.5)
                errors=page.evaluate('window.__cumtPageErrors||[]') or []
                for error in errors[-12:]:
                    trace['page_errors'].append(sanitized(error))
                    self.record('browser.page_error',level='ERROR',error=sanitized(error,limit=None))
                if operation=='login':self.session_cookies=page.cookies()
                if results:return results[-1]
                return None
            finally:
                # Revoke the send permission before control disposal or any
                # timeout cleanup can leave an already-queued worker behind.
                submission_started[0]=False
    except Exception as exc:
        error={'error':type(exc).__name__,'detail':sanitized(str(exc))}
        trace.setdefault('execution_errors',[]).append(error)
        self.record_exception('browser.execution_error',exc)
        if results:
            trace['postprocess_error']=type(exc).__name__
            return results[-1]
        if count[0]>0:
            trace['phase']='response_unconfirmed'
            trace['result']=None
            return None
        raise


def offline_self_test():
    """Exercise the actual native host using a fictional in-memory portal.

    Used only by the packaged self-test; no Store, campus socket or real WiFi
    is touched. The private WebView2 executes real DOM and duplicate attempts.
    """
    wifi=core.Wifi(core.STU,'packaged-webview2-fixture',7,'10.52.1.2','00-11-22-33-44-55')
    account,password='fictional-packaged-user','fictional-packaged-password'
    submissions,bindings=[],[]
    frame_loaded=[False]
    html=b'''<html><body><form onsubmit="send();return false">
      <input name="DDDDD"><input type="password" name="upass">
      <input type="submit" value="Login" onclick="window.trustedClick=event.isTrusted;if(!window.trustedClick)return false"></form>
      <iframe id="reply-frame" src="/frame.htm" style="display:none"></iframe><script>
      window.dr1003=function(data){window.lastResponse=data;};
      function send(){const f=document.forms[0],d=document.getElementById('reply-frame').contentDocument;
        const q=new URLSearchParams({a:'login',user_account:f.DDDDD.value,user_password:f.upass.value,
          trusted:String(window.trustedClick),viewport_width:String(innerWidth),viewport_height:String(innerHeight),
          frame_ready:String(d.defaultView.frameReady===true)});
        for(let i=0;i<2;i++){let s=d.createElement('script');s.src='/eportal/?'+q+'&attempt='+i;d.head.append(s);}}
      </script></body></html>'''
    frame_html=b'<html><head><script>window.frameReady=true;function dr1003(data){window.lastResponse=data;}</script></head><body></body></html>'
    class Reply:
        status=200
        def __init__(self,body,kind):self.body,self.kind=body,kind
        def read(self,limit=None):return self.body if limit is None else self.body[:limit]
        def getheaders(self):return [('Content-Type',self.kind)]
    class Connection:
        def __init__(self,host,port,bound,secure=False):
            bindings.append(bound.key)
            self.reply=None
        def request(self,method,target,body=None,headers=None):
            fields=parse_qs(urlsplit(target).query)
            if fields.get('a')==['login']:
                submissions.append(fields)
                self.reply=Reply(b'dr1003({"result":1})','application/javascript')
            elif urlsplit(target).path=='/frame.htm':
                frame_loaded[0]=True
                self.reply=Reply(frame_html,'text/html; charset=utf-8')
            else:self.reply=Reply(html,'text/html; charset=utf-8')
        def getresponse(self):return self.reply
        def close(self):pass
    class Client:
        portal='http://10.2.5.251/a79.htm'
        closed=threading.Event()
        cancel=threading.Event()
        lock=threading.RLock()
        auto_job=False
        session_cookies=[]
        def checked_wifi(self,wifi,tec):return wifi
        def record(self,*args,**kwargs):pass
        def record_exception(self,*args,**kwargs):pass
        def message(self,*args):pass
    client=Client()
    def parser(text,url,operation):
        return protocol._result(protocol.parse_jsonp(text))
    result=authenticate(client,wifi,account,password,'campus','login',False,
                        result_parser=parser,logout_select_js='',logout_confirm_js='',
                        reader=lambda:wifi,connection_factory=Connection)
    exact=(len(submissions)==1 and submissions[0].get('user_account')==[account]
           and submissions[0].get('user_password')==[password])
    routed=bool(bindings) and all(key==wifi.key for key in bindings)
    duplicate_blocked=client.auth_diagnostic['blocked_requests']>=1
    trusted=exact and submissions[0].get('trusted')==['true']
    frame=exact and frame_loaded[0] and submissions[0].get('frame_ready')==['true']
    viewport=exact and submissions[0].get('viewport_width')==['1280'] and submissions[0].get('viewport_height')==['720']
    report={'engine':'webview2','success':result is True and exact and routed and duplicate_blocked and trusted and frame and viewport,
            'request_interception_verified':routed,
            'single_submission_verified':exact and client.auth_diagnostic['authentication_requests']==1,
            'duplicate_attempt_blocked':duplicate_blocked,
            'trusted_input_verified':trusted,'frame_transport_verified':frame,
            'desktop_viewport_verified':viewport,
            'campus_requests':0,'network_changes':False}
    return report
