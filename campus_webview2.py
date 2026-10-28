"""Private WebView2 portal host with no Python bridge or native network route.

Every HTTP response is supplied by the caller. An unreachable browser proxy is
an additional fail-closed barrier for channels that are not resource events.
The normal application UI uses its own, separate pywebview control.
"""
from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import json
import os
import re
import shutil
import socket
import tempfile
import threading
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit


MAX_REQUEST_BYTES = 4 * 1024 * 1024
PORTAL_VIEWPORT = (1280, 720)
PORTAL_PORTS = (80, 443, 801, 802)
_unfinished_hosts=[]
BOOT_SCRIPT = r'''(() => {
  window.__cumtPageErrors=[];
  window.addEventListener('error',e=>window.__cumtPageErrors.push(String(e.message||'script error')));
  window.addEventListener('unhandledrejection',e=>window.__cumtPageErrors.push(String(e.reason||'unhandled rejection')));
  const denied=function(){throw new Error('This portal channel is disabled');};
  for(const name of ['WebSocket','WebTransport','Worker','SharedWorker','RTCPeerConnection','webkitRTCPeerConnection']) {
    try {Object.defineProperty(window,name,{value:denied,writable:false,configurable:false});}catch(e){}
  }
  try {if(navigator.serviceWorker)Object.defineProperty(navigator.serviceWorker,'register',{value:denied});}catch(e){}
})();'''

@dataclass(frozen=True)
class Request:
    url: str
    method: str
    headers: dict
    body: bytes | None
    resource_type: str
    arrival_context: object = None


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict
    body: bytes


class WebView2Host:
    """Synchronous caller API backed by an independent STA message pump."""

    def __init__(self, request_handler, dialog_handler=None, *, host='', timeout=20,
                 context_provider=None):
        # A native control that has not terminated must not accumulate a new
        # replacement host with another profile and network worker pool.
        for old in list(_unfinished_hosts):
            if old._ended.is_set():
                if old._proxy_socket is not None:old._proxy_socket.close()
                old._remove_profile()
                _unfinished_hosts.remove(old)
        if _unfinished_hosts:
            raise RuntimeError('上一网页兼容控件尚未退出，请退出客户端后重试。')
        self.request_handler = request_handler
        self.dialog_handler = dialog_handler or (lambda kind, message: False)
        self.host = host
        self.context_provider=context_provider or (lambda:None)
        self._ready = threading.Event()
        self._ended = threading.Event()
        self._closed = threading.Event()
        self._closing = threading.Event()
        self._refs = []
        self._error = None
        self._profile = tempfile.mkdtemp(prefix='cumt-webview2-portal-')
        self._thread = None
        self._form = None
        self._view = None
        self._pending = 0
        self._pending_lock = threading.Lock()
        self._last_resource_activity = time.monotonic()
        self._deferrals = {}
        self._slots = threading.BoundedSemaphore(32)
        self._pool = None
        self._proxy_socket = None
        self._thread_started=False
        self.close_report={}
        try:
            self._pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix='portal-http')
            # Reserve an exclusive local TCP port with no listener. No unrelated
            # local proxy can turn this defensive route into a connection leak.
            self._proxy_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            if os.name=='nt':
                self._proxy_socket.setsockopt(socket.SOL_SOCKET,socket.SO_EXCLUSIVEADDRUSE,1)
            self._proxy_socket.bind(('127.0.0.1',0))
            self._proxy_port = self._proxy_socket.getsockname()[1]
            self._load_runtime()
            self._thread = self.Thread(self.ThreadStart(self._run))
            self._thread.SetApartmentState(self.ApartmentState.STA)
            self._thread.IsBackground = True
            self._thread.Start()
            self._thread_started=True
            if not self._ready.wait(timeout):
                raise RuntimeError('WebView2 初始化超时，请检查系统 WebView2 运行环境。')
            if self._error:
                raise RuntimeError('无法启动 WebView2 网页兼容流程：' + str(self._error))
        except BaseException:
            self.close()
            raise

    def _load_runtime(self):
        import clr
        from webview.util import interop_dll_path
        clr.AddReference('System.Windows.Forms')
        clr.AddReference('System.Drawing')
        clr.AddReference(interop_dll_path('Microsoft.Web.WebView2.Core.dll'))
        clr.AddReference(interop_dll_path('Microsoft.Web.WebView2.WinForms.dll'))
        # The native loader is the same x64 loader used by the existing UI.
        loader = interop_dll_path('win-x64')
        if loader not in os.environ.get('PATH', '').split(os.pathsep):
            os.environ['PATH'] += os.pathsep + loader
        from System import Action, Array, Byte, String
        from System.IO import MemoryStream
        from System.Drawing import Size
        from System.Threading import Thread, ThreadStart, ApartmentState
        from System.Threading.Tasks import Task, TaskScheduler
        from System.Windows.Forms import Application, Form, DockStyle
        from Microsoft.Web.WebView2.Core import CoreWebView2WebResourceContext
        from Microsoft.Web.WebView2.WinForms import WebView2, CoreWebView2CreationProperties
        self.Action, self.Array, self.Byte, self.String = Action, Array, Byte, String
        self.MemoryStream = MemoryStream
        self.Size = Size
        self.Thread, self.ThreadStart, self.ApartmentState = Thread, ThreadStart, ApartmentState
        self.Task, self.TaskScheduler = Task, TaskScheduler
        self.Application, self.Form, self.DockStyle = Application, Form, DockStyle
        self.WebView2, self.CreationProperties = WebView2, CoreWebView2CreationProperties
        self.ResourceContext = CoreWebView2WebResourceContext

    def _run(self):
        try:
            form, view = self.Form(), self.WebView2()
            self._form, self._view = form, view
            form.Text = '校园网网页兼容'
            form.ClientSize = self.Size(*PORTAL_VIEWPORT)
            form.Opacity = 0
            form.ShowInTaskbar = False
            props = self.CreationProperties()
            props.UserDataFolder = self._profile
            props.IsInPrivateModeEnabled = True
            props.AdditionalBrowserArguments = (
                f'--proxy-server=http://127.0.0.1:{self._proxy_port} --proxy-bypass-list=<-loopback> '
                '--disable-background-networking --disable-quic '
                '--force-webrtc-ip-handling-policy=disable_non_proxied_udp '
                '--disable-features=WebTransport,MediaRouter')
            view.CreationProperties = props
            view.Dock = self.DockStyle.Fill
            form.Controls.Add(view)

            def initialized(sender, args):
                try:
                    if not args.IsSuccess:
                        raise RuntimeError(str(args.InitializationException))
                    self._scheduler = self.TaskScheduler.FromCurrentSynchronizationContext()
                    engine = view.CoreWebView2
                    settings = engine.Settings
                    settings.AreDefaultScriptDialogsEnabled = False
                    settings.AreDevToolsEnabled = False
                    settings.AreDefaultContextMenusEnabled = False
                    settings.AreHostObjectsAllowed = False
                    settings.IsWebMessageEnabled = False
                    settings.IsStatusBarEnabled = False
                    settings.IsZoomControlEnabled = False
                    try:
                        engine.Profile.DefaultDownloadFolderPath=self._profile
                    except AttributeError:
                        pass
                    engine.AddWebResourceRequestedFilter('*', self.ResourceContext.All)
                    engine.WebResourceRequested += self._resource_requested
                    engine.NewWindowRequested += self._new_window
                    engine.DownloadStarting += self._download
                    engine.PermissionRequested += self._permission
                    engine.BasicAuthenticationRequested += self._basic_authentication
                    engine.ScriptDialogOpening += self._dialog
                    engine.FrameNavigationStarting += self._frame_navigation
                    view.NavigationStarting += self._navigation
                    # Readiness is published only after the document-start guard
                    # has completed, before the caller can navigate a portal.
                    def viewport_ready(task):
                        try:
                            task.Result
                        except BaseException as exc:
                            self._error=exc
                        finally:
                            self._ready.set()
                    def guard_ready(task):
                        try:
                            task.Result
                            callback=self.Action[self.Task[self.String]](viewport_ready)
                            self._refs.append(callback)
                            # CSS viewport must not depend on desktop DPI or the
                            # native window's border/client-size conversion.
                            engine.CallDevToolsProtocolMethodAsync(
                                'Emulation.setDeviceMetricsOverride',json.dumps({
                                    'width':PORTAL_VIEWPORT[0],'height':PORTAL_VIEWPORT[1],
                                    'deviceScaleFactor':1,'mobile':False})).ContinueWith(callback,self._scheduler)
                        except BaseException as exc:
                            self._error=exc
                            self._ready.set()
                    callback = self.Action[self.Task[self.String]](guard_ready)
                    self._refs.append(callback)
                    engine.AddScriptToExecuteOnDocumentCreatedAsync(BOOT_SCRIPT).ContinueWith(callback, self._scheduler)
                except BaseException as exc:
                    self._error = exc
                    self._ready.set()
                    form.Close()

            def loaded(sender, args):
                view.EnsureCoreWebView2Async(None)

            view.CoreWebView2InitializationCompleted += initialized
            form.Load += loaded
            self._refs.extend([initialized, loaded])
            self.Application.Run(form)
        except BaseException as exc:
            self._error = exc
            self._ready.set()
        finally:
            # This finally always runs on the owning STA, even if an earlier
            # resource completion or form-close operation failed.
            try:
                if self._view is not None:self._view.Dispose()
            except BaseException:
                pass
            try:
                if self._form is not None:self._form.Dispose()
            except BaseException:
                pass
            self._ended.set()

    def _invoke(self, function):
        if self._closed.is_set():
            raise RuntimeError('网页兼容流程已关闭。')
        complete, box = threading.Event(), {}

        def run():
            try:
                box['result'] = function()
            except BaseException as exc:
                box['error'] = exc
            finally:
                complete.set()
        delegate = self.Action(run)
        self._form.BeginInvoke(delegate)
        if not complete.wait(10):
            raise RuntimeError('WebView2 窗口响应超时。')
        if 'error' in box:
            raise box['error']
        return box.get('result')

    def _async_task(self, create_task, result_type, transform=lambda value: value, timeout=12):
        complete, box = threading.Event(), {}
        def begin():
            def done(task):
                try:
                    box['result'] = transform(task.Result)
                except BaseException as exc:
                    box['error'] = exc
                finally:
                    complete.set()
            callback = self.Action[self.Task[result_type]](done)
            self._refs.append(callback)
            create_task().ContinueWith(callback, self._scheduler)
        self._invoke(begin)
        if not complete.wait(timeout):
            raise RuntimeError('WebView2 脚本执行超时。')
        if 'error' in box:
            raise box['error']
        return box.get('result')

    def navigate(self, url):
        self._invoke(lambda: self._view.CoreWebView2.Navigate(url))

    def evaluate(self, expression, arg=None):
        if arg is not None:
            script='(' + expression + ')(' + json.dumps(arg, ensure_ascii=True) + ')'
        elif re.match(r'^(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|[\w$]+\s*=>)',expression.strip()):
            script='('+expression+')()'
        else:
            script=expression
        return self._async_task(lambda: self._view.CoreWebView2.ExecuteScriptAsync(script),
                                self.String, lambda value: json.loads(str(value)))

    def call_devtools(self, method, parameters):
        return self._async_task(
            lambda:self._view.CoreWebView2.CallDevToolsProtocolMethodAsync(
                method,json.dumps(parameters,separators=(',',':'))),
            self.String,lambda value:json.loads(str(value)))

    def click(self, selector, timeout=12, check=None, before_click=None):
        """Wait for a unique actionable element, then dispatch trusted input.

        The caller can keep its submission gate closed until the element is
        actually actionable. No JavaScript element.click() is used.
        """
        until=time.monotonic()+timeout
        previous=None
        stable_since=None
        snapshot_script=r'''selector => {
          const nodes=Array.from(document.querySelectorAll(selector));
          if(nodes.length!==1)return {count:nodes.length};
          const element=nodes[0];
          if(!element.isConnected)return {count:0};
          element.scrollIntoView({block:'center',inline:'center',behavior:'instant'});
          const style=getComputedStyle(element),rect=element.getBoundingClientRect();
          const x=Math.max(0,Math.min(innerWidth-1,rect.x+rect.width/2));
          const y=Math.max(0,Math.min(innerHeight-1,rect.y+rect.height/2));
          const hit=document.elementFromPoint(x,y);
          return {count:1,enabled:!element.disabled&&element.getAttribute('aria-disabled')!=='true'&&
              !element.closest('[inert],fieldset[disabled]'),
            visible:rect.width>0&&rect.height>0&&style.visibility!=='hidden'&&style.visibility!=='collapse'&&style.display!=='none',
            receives:!!hit&&(hit===element||element.contains(hit)),
            x,y,left:rect.x,top:rect.y,width:rect.width,height:rect.height};
        }'''
        while time.monotonic()<until:
            if check:check()
            state=self.evaluate(snapshot_script,selector) or {}
            if state.get('count',0)>1:
                raise RuntimeError('认证按钮不唯一，已停止自动操作。')
            actionable=(state.get('count')==1 and state.get('enabled') and
                        state.get('visible') and state.get('receives'))
            position=tuple(round(float(state.get(key,0)),2)
                           for key in ('left','top','width','height'))
            if actionable and previous==position:
                stable_since=stable_since or time.monotonic()
                if time.monotonic()-stable_since>=.05:
                    if check:check()
                    if before_click:before_click()
                    # CDP input is delivered by Chromium as a trusted event,
                    # matching locator-click semantics without a Node driver.
                    point={'x':float(state['x']),'y':float(state['y'])}
                    self.call_devtools('Input.dispatchMouseEvent',{'type':'mouseMoved',**point})
                    if check:check()
                    self.call_devtools('Input.dispatchMouseEvent',{
                        'type':'mousePressed','button':'left','clickCount':1,**point})
                    if check:check()
                    self.call_devtools('Input.dispatchMouseEvent',{
                        'type':'mouseReleased','button':'left','clickCount':1,**point})
                    return
            else:
                stable_since=None
            previous=position if actionable else None
            time.sleep(.025)
        raise RuntimeError('认证按钮尚不可点击，未完成自动操作；请刷新页面后重试。')

    def wait_idle(self, timeout=.3, quiet_period=.1):
        until = time.monotonic() + timeout
        while True:
            with self._pending_lock:
                now=time.monotonic()
                if now>=until:return False
                # Timestamp every arrival and completion, including requests
                # that begin and finish entirely between two polling ticks.
                if self._pending==0 and now-self._last_resource_activity>=quiet_period:
                    return True
            time.sleep(.01)

    def _note_resource_activity(self,pending_delta=0):
        with self._pending_lock:
            self._pending+=pending_delta
            self._last_resource_activity=time.monotonic()

    def add_cookies(self, cookies):
        def add():
            from System import DateTime,DateTimeKind
            from Microsoft.Web.WebView2.Core import CoreWebView2CookieSameSiteKind
            manager = self._view.CoreWebView2.CookieManager
            for item in cookies:
                expires=item.get('expires',-1)
                if isinstance(expires,(int,float)) and expires!=-1 and expires<=time.time():
                    continue
                cookie = manager.CreateCookie(item['name'], item['value'], item['domain'], item.get('path') or '/')
                cookie.IsSecure = bool(item.get('secure'))
                cookie.IsHttpOnly = bool(item.get('httpOnly'))
                if isinstance(expires,(int,float)) and expires>0:
                    cookie.Expires=DateTime(1970,1,1,0,0,0,DateTimeKind.Utc).AddSeconds(expires)
                same_site=item.get('sameSite')
                if same_site in ('None','Lax','Strict'):
                    cookie.SameSite=getattr(CoreWebView2CookieSameSiteKind,same_site)
                manager.AddOrUpdateCookie(cookie)
        self._invoke(add)

    def cookies(self):
        from System.Collections.Generic import List
        from Microsoft.Web.WebView2.Core import CoreWebView2Cookie
        def transform(values):
            result=[]
            for c in values:
                value=c.Expires
                expires=(-1 if c.IsSession else dt.datetime(value.Year,value.Month,value.Day,
                    value.Hour,value.Minute,value.Second,value.Millisecond*1000,
                    tzinfo=dt.timezone.utc).timestamp())
                result.append({'name':c.Name,'value':c.Value,'domain':c.Domain,'path':c.Path,
                    'expires':expires,'sameSite':str(c.SameSite),
                    'secure':c.IsSecure,'httpOnly':c.IsHttpOnly})
            return result
        return self._async_task(lambda:self._view.CoreWebView2.CookieManager.GetCookiesAsync(None),
                                List[CoreWebView2Cookie], transform)

    def _navigation(self, sender, args):
        if not self._allowed_portal_uri(str(args.Uri)):
            args.Cancel = True

    def _allowed_portal_uri(self, uri, *, blank=False):
        if blank and str(uri).strip().casefold() in ('','about:blank'):
            return True
        try:
            p=urlsplit(str(uri))
            return (p.scheme in ('http','https') and p.hostname==self.host and
                    not p.username and not p.password and
                    (p.port or (443 if p.scheme=='https' else 80)) in PORTAL_PORTS)
        except ValueError:
            return False

    def _frame_navigation(self,sender,args):
        # URL navigations remain in the approved portal family. Inherited
        # same-origin script contexts are not a separate privilege boundary:
        # their network still uses the shared handler/proxy and has no Bridge.
        if not self._allowed_portal_uri(str(args.Uri),blank=True):
            args.Cancel=True

    def _new_window(self, sender, args):
        args.Handled = True

    def _download(self, sender, args):
        args.Cancel = True

    def _permission(self, sender, args):
        from Microsoft.Web.WebView2.Core import CoreWebView2PermissionState
        args.State = CoreWebView2PermissionState.Deny

    def _basic_authentication(self,sender,args):
        # Portal HTML must not create a separate native credential prompt.
        args.Cancel=True

    def _dialog(self, sender, args):
        if self.dialog_handler(str(args.Kind).lower(), str(args.Message)):
            args.Accept()

    def _response(self, response):
        body = self.MemoryStream(self.Array[self.Byte](response.body))
        headers = dict(response.headers)
        existing = next((k for k in headers if k.lower() == 'content-security-policy'), None)
        if self.host and re.fullmatch(r'[A-Za-z0-9.-]+',self.host):
            sources=[]
            for scheme in ('http','https'):
                for port in PORTAL_PORTS:
                    default=80 if scheme=='http' else 443
                    sources.append(scheme+'://'+self.host+('' if port==default else ':'+str(port)))
            frames="'self' "+' '.join(sources)
        else:
            frames="'none'"
        restrictive = "worker-src 'none'; frame-src "+frames+"; object-src 'none'"
        # Separate policies are intersected by the browser. Do not weaken an
        # existing portal policy when blocking non-resource channels.
        rendered = ''.join(f'{key}: {value}\r\n' for key,value in headers.items())
        rendered += 'Content-Security-Policy: ' + restrictive + '\r\n'
        rendered += 'Cache-Control: no-store\r\n'
        return self._view.CoreWebView2.Environment.CreateWebResourceResponse(
            body, response.status, 'OK' if response.status < 400 else 'Blocked', rendered)

    def _resource_requested(self, sender, args):
        self._note_resource_activity()
        # The caller publishes only immutable phase flags here. Snapshot them
        # at arrival, before reading a body or queueing work; a delayed worker
        # must never turn a fill-event request into an authorized click.
        arrival_context=self.context_provider()
        deferral = args.GetDeferral()
        acquired=self._slots.acquire(False)
        if acquired:
            # Reading a streamed request body is already in-flight activity;
            # do not publish an idle state before it reaches the IO queue.
            self._note_resource_activity(1)
        def reject(status):
            try:
                args.Response=self._response(Response(status,{},b''))
            finally:
                try:deferral.Complete()
                finally:
                    if acquired:self._slots.release()
                    self._note_resource_activity(-1 if acquired else 0)
        if not acquired:
            reject(429)
            return
        try:
            raw = args.Request
            headers = {str(item.Key):str(item.Value) for item in raw.Headers}
            content = None
            if raw.Content is not None:
                stream = raw.Content
                chunks, size = [], 0
                buffer = self.Array.CreateInstance(self.Byte, 65536)
                while True:
                    count = stream.Read(buffer, 0, len(buffer))
                    if not count:
                        break
                    size += count
                    if size > MAX_REQUEST_BYTES:
                        raise ValueError('网页请求内容过大。')
                    chunks.append(bytes(buffer)[:count])
                content = b''.join(chunks)
            request = Request(str(raw.Uri), str(raw.Method), headers, content,
                              str(args.ResourceContext).lower(),arrival_context)
        except BaseException:
            reject(403)
            return
        if request.resource_type == 'websocket' or any(k.lower() == 'upgrade' for k in headers):
            reject(403)
            return
        key=id(deferral)
        self._deferrals[key]=(args,deferral)
        def worker():
            try:
                response = None if self._closing.is_set() or self._closed.is_set() else self.request_handler(request)
            except BaseException:
                response = None
            def finish():
                current=self._deferrals.pop(key,None)
                if current is None:return
                try:
                    args.Response = self._response(response or Response(403, {}, b''))
                finally:
                    deferral.Complete()
            try:
                self._invoke(finish)
            except BaseException:
                # Closing the control also cancels its outstanding requests.
                pass
            finally:
                self._note_resource_activity(-1)
                self._slots.release()
        self._pool.submit(worker)

    def close(self):
        if self._closed.is_set():
            return
        self._closing.set()
        errors=[]
        on_ui=(getattr(self,'_thread',None) is not None and
               self.Thread.CurrentThread.ManagedThreadId==self._thread.ManagedThreadId)
        # Dispose on the owning STA before rejecting future dispatches.
        if self._form is not None and not self._ended.is_set():
            try:
                def dispose():
                    for args,deferral in list(self._deferrals.values()):
                        try:
                            args.Response=self._response(Response(403,{},b''))
                        except BaseException as exc:
                            errors.append(type(exc).__name__)
                        finally:
                            try:deferral.Complete()
                            except BaseException as exc:errors.append(type(exc).__name__)
                    self._deferrals.clear()
                    try:
                        self._view.Dispose()
                    except BaseException as exc:
                        errors.append(type(exc).__name__)
                    finally:
                        try:self._form.Close()
                        except BaseException as exc:errors.append(type(exc).__name__)
                        finally:self.Application.ExitThread()
                if on_ui:dispose()
                else:self._invoke(dispose)
            except BaseException as exc:
                errors.append(type(exc).__name__)
        self._closed.set()
        if not self._thread_started:self._ended.set()
        if not on_ui:self._ended.wait(4)
        if self._pool is not None:self._pool.shutdown(wait=False,cancel_futures=False)
        ended=self._ended.is_set()
        if ended:
            if self._proxy_socket is not None:self._proxy_socket.close()
            self._remove_profile()
        else:
            # Keep the exclusively reserved proxy port alive if the native
            # control has not demonstrably terminated. It cannot be reused.
            _unfinished_hosts.append(self)
        self.close_report={'sta_ended':ended,'proxy_released':ended,'errors':errors}

    def _remove_profile(self):
        profile=Path(self._profile).resolve()
        temporary=Path(tempfile.gettempdir()).resolve()
        if profile.parent!=temporary or not profile.name.startswith('cumt-webview2-portal-'):
            raise RuntimeError('拒绝清理非本次网页兼容临时目录。')
        for _ in range(15):
            try:
                shutil.rmtree(profile)
                break
            except FileNotFoundError:
                break
            except OSError:
                time.sleep(.1)

    def __enter__(self):
        return self

    def __exit__(self, exc_type,*args):
        self.close()
        if not self._ended.is_set() and exc_type is None:
            raise RuntimeError('WebView2 网页兼容控件未能正常退出，已保留网络保护；请退出客户端后重试。')
