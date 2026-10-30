"""Local desktop UI regression with no campus requests or settings changes."""
from pathlib import Path
import json
import sys
import tempfile
from unittest.mock import patch
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parent.parent
REPORTS=ROOT/'research'
sys.path.insert(0,str(ROOT))
from verification_context import begin_verification, finish_verification
INITIAL_VERIFICATION=(begin_verification('hidden' if '--hidden' in sys.argv else 'ui',ROOT)
                      if __name__=='__main__' else None)
import campus_core as c
import campus_app as a
OFFLINE_WIFI=c.Wifi('OfflineSmokeTest')

def start_report(kind):
    context=INITIAL_VERIFICATION or begin_verification(kind,ROOT)
    name='hidden_smoke_results.json' if kind=='hidden' else 'ui_smoke_results.json'
    (REPORTS/name).write_text(json.dumps({'version':c.VERSION,'success':False,'verification':context}), 'utf-8')
    return context

def main():
    verification=start_report('ui')
    html=(ROOT/'campus_ui.html').read_text('utf-8')
    for unwanted in ('热点保护','第三校区','咱俩','聊天','自动弹窗','auto_enabled','auto_submit',
                     'id="cancel-operation"','id="network-check"',
                     'function cancelOperation','function checkNetwork','cancelBusy'):
        assert unwanted not in html,unwanted
    with sync_playwright() as p:
        browser=p.chromium.launch(channel='msedge',headless=True,args=['--no-proxy-server','--disable-background-networking'])
        context=browser.new_context(viewport={'width':430,'height':680},service_workers='block')
        def local_assets(route):
            resources={'http://offline.invalid/campus_ui.html':('text/html; charset=utf-8',html),
                       'http://offline.invalid/assets/logo.png':('image/png',(ROOT/'assets/logo.png').read_bytes())}
            asset=resources.get(route.request.url)
            if asset:route.fulfill(status=200,content_type=asset[0],body=asset[1])
            else:route.abort()
        context.route('**/*',local_assets)
        page=context.new_page();page.set_default_timeout(8000);errors=[]
        page.on('pageerror',lambda exc:errors.append(str(exc)))
        page.goto('http://offline.invalid/campus_ui.html',wait_until='load')
        assert page.locator('#brand-logo').evaluate('(img)=>img.complete&&img.naturalWidth>0')
        assert page.locator('#startup').get_attribute('role')=='switch'
        assert page.locator('#startup').get_attribute('aria-label')=='连接校园网（CUMT_Stu/CUMT_Tec）时自动弹出'
        assert page.locator('.row .note').inner_text()=='连接后弹出；有已保存账号时自动尝试一次'
        assert page.locator('#online-account').inner_text()=='暂无本次登录记录'
        assert page.locator('#account-switch-note').is_hidden()
        assert page.locator('.session-actions button').all_text_contents()==['登录','注销']
        assert page.locator('#logout-button').is_disabled()
        assert page.locator('#network-check,#cancel-operation').count()==0
        assert page.locator('#status-refresh').inner_text()=='检测状态' and page.locator('#status-refresh').is_disabled()
        assert page.locator('#login-switch,#tec').count()==0
        assert page.locator('#diagnostic-export').inner_text()=='导出诊断包'
        assert page.evaluate('document.documentElement.scrollWidth<=innerWidth&&document.documentElement.scrollHeight<=innerHeight')
        page.locator('.eye').click();assert page.locator('#password').get_attribute('type')=='text'
        page.locator('.eye').click()
        page.evaluate('exportDiagnostic()');assert page.locator('#toast').inner_text()=='请在桌面客户端中导出诊断包'
        page.evaluate("el('toast').style.display='none'")
        page.screenshot(path=str(REPORTS/f'登录器_v{c.VERSION}_界面.png'),full_page=True)
        page.evaluate('''version => {
          window.fakeLog=[];
          window.fakeData={version,selected:'one',account:'fake-account',password:'fake-password',operator:'telecom',startup:false,portal_hint:'',profiles:[{id:'one',account:'fake-account'},{id:'two',account:'fake-second'}]};
          window.fakeState={version,ssid:'CUMT_Tec',campus:true,student:false,busy:false,operation:'',logged_in:false,session_state:'unknown',online_account:'',identity_source:'',status:'请选择账号后登录',pending_host:'',logging_error:''};
          window.fakeDiagnostic={ok:true,path:'C:/Fake/diagnostic-fake.zip'};
          api={boot:async()=>{window.fakeLog.push(['boot']);return window.fakeData},
            get_state:async()=>{window.fakeLog.push(['get_state']);return window.fakeState},
            login:async(...args)=>{window.fakeLog.push(['login',...args]);Object.assign(window.fakeState,{identity_source:'verified_status',online_account:args[0],session_state:'online',logged_in:true,status:'登录成功'});return {ok:true}},
            logout:async(...args)=>{window.fakeLog.push(['logout',...args]);Object.assign(window.fakeState,{identity_source:'',online_account:'',session_state:'offline',logged_in:false,status:'本次注销已完成'});return {ok:true}},
            refresh_status:async(...args)=>{window.fakeLog.push(['status',...args]);Object.assign(window.fakeState,{identity_source:'verified_status',online_account:'checked-account',session_state:'online',logged_in:true,status:'当前设备已登录'});return {ok:true}},
            diagnostic:async()=>{window.fakeLog.push(['diagnostic']);return window.fakeDiagnostic},
            select_profile:async(id)=>{window.fakeLog.push(['select',id]);window.fakeData.selected=id;window.fakeData.account=id==='two'?'fake-second':id?'fake-account':'';window.fakeData.password=id?'fake-password':'';return {ok:true,data:window.fakeData}},
            save_profile:async(...args)=>{window.fakeLog.push(['save',...args]);return {ok:true,data:window.fakeData}},
            delete_profile:async(id)=>{window.fakeLog.push(['delete',id]);window.fakeData.profiles=window.fakeData.profiles.filter(p=>p.id!==id);window.fakeData.selected='';window.fakeData.account='';window.fakeData.password='';return {ok:true,data:window.fakeData}},
            trust_portal:async()=>{window.fakeState.pending_host='';return {ok:true}},
            set_startup:async(on)=>{window.fakeLog.push(['startup',on]);return {ok:true}},
            save_hint:async(value)=>{window.fakeLog.push(['hint',value]);return {ok:true}},
            quit:async()=>{window.fakeLog.push(['quit']);return {ok:true}}};
          applyBoot(window.fakeData);
        }''',c.VERSION)
        page.evaluate('refresh()')
        assert page.locator('#operator-wrap').is_hidden()
        assert page.locator('#online-account').inner_text()=='暂无本次登录记录'
        assert page.locator('#logout-button').is_enabled(), 'Unknown cached state must not block a requested logout'
        before=page.evaluate('window.fakeLog.length')
        page.evaluate('Promise.all([refresh(),refresh(),refresh()])')
        assert page.evaluate('window.fakeLog.slice('+str(before)+').every(x=>x[0]==="get_state")')
        # Status detection is one explicit read-only action, without form data.
        assert page.locator('#status-refresh').is_enabled()
        before=page.evaluate('window.fakeLog.length')
        page.locator('#status-refresh').click();page.wait_for_function("!actionBusy&&window.fakeLog.some(x=>x[0]==='status')")
        assert page.evaluate("window.fakeLog.filter(x=>x[0]==='status')")==[['status']]
        assert page.evaluate('window.fakeLog.slice('+str(before)+').every(x=>x[0]==="status"||x[0]==="get_state")')
        assert page.locator('#online-account').inner_text()=='当前在线账号：checked-account'
        # The outstanding bridge request locks all three network actions.
        page.evaluate("() => {window.savedStatus=api.refresh_status;api.refresh_status=(...args)=>new Promise(resolve=>{window.releaseStatus=async()=>resolve(await window.savedStatus(...args))});refreshStatus();}")
        assert page.locator('#status-refresh').is_disabled() and page.locator('#login-button').is_disabled() and page.locator('#logout-button').is_disabled()
        before=page.evaluate('window.fakeLog.length');page.evaluate('refreshStatus();toggleLogin();logoutSession()')
        assert page.evaluate('window.fakeLog.slice('+str(before)+').every(x=>x[0]==="get_state")')
        page.evaluate('window.releaseStatus()');page.wait_for_function('!actionBusy')
        page.evaluate('() => {api.refresh_status=window.savedStatus;}')
        page.evaluate("Object.assign(window.fakeState,{identity_source:'',online_account:'',session_state:'unknown',logged_in:false,status:'请选择账号后登录'});refresh()")
        # Help, advanced address settings, safe external links and diagnostic feedback.
        page.evaluate('showHelp()')
        assert page.locator('#help-advanced').evaluate('(x)=>!x.open')
        assert page.locator('#portal_hint').is_hidden()
        assert page.evaluate("el('help').scrollHeight<=el('help').clientHeight+1")
        for retired in ('网络自检','取消操作','后台核对','刷新状态'):
            assert retired not in page.locator('#help').inner_text()
        assert '注销时请填写对应账号和密码' in page.locator('#help').inner_text()
        assert '检测状态' in page.locator('#help').inner_text() and '短时确认结果' in page.locator('#help').inner_text()
        page.locator('#help-advanced summary').click();page.locator('#portal_hint').fill('http://10.2.5.251/a79.htm')
        page.locator('#portal-save').click();page.wait_for_function("window.fakeLog.some(x=>x[0]==='hint')")
        page.locator('#help-advanced summary').click();assert page.locator('#portal_hint').is_hidden()
        link=page.locator('#campus-self-service')
        assert link.inner_text()=='校园网自助服务'
        assert link.get_attribute('href')=='http://202.119.196.6:8080/Self/dashboard'
        assert link.get_attribute('target')=='_blank' and set(link.get_attribute('rel').split())=={'noopener','noreferrer'}
        assert link.get_attribute('onclick') is None
        assert page.evaluate("()=>{const r=el('help').getBoundingClientRect();return r.top>=0&&r.bottom<=innerHeight&&r.height<=innerHeight-32}")
        assert page.evaluate("getComputedStyle(el('help')).overflowY==='auto'")
        page.locator('#diagnostic-export').click();page.wait_for_function("!diagnosticBusy&&el('toast').textContent==='诊断包已保存：C:/Fake/diagnostic-fake.zip'")
        assert page.locator('#toast').is_visible()
        assert page.evaluate("()=>{const t=el('toast'),r=t.getBoundingClientRect();return document.elementFromPoint(r.x+r.width/2,r.y+r.height/2)===t}")
        page.evaluate("window.fakeDiagnostic.path='C:/Fake/diagnostic-'+('a'.repeat(160))+'.zip'")
        page.locator('#diagnostic-export').click();page.wait_for_function("!diagnosticBusy&&el('toast').textContent.endsWith(window.fakeDiagnostic.path)")
        assert page.evaluate("el('toast').scrollWidth<=el('toast').clientWidth")
        page.evaluate("window.fakeDiagnostic={ok:false,message:'无法写入诊断包：磁盘空间不足'}")
        page.locator('#diagnostic-export').click();page.wait_for_function("!diagnosticBusy&&el('toast').textContent==='无法写入诊断包：磁盘空间不足'")
        page.evaluate("() => {window.savedDiagnostic=api.diagnostic;api.diagnostic=async()=>{throw Error('fake bridge failure')};}")
        page.locator('#diagnostic-export').click();page.wait_for_function("!diagnosticBusy&&el('toast').textContent==='导出诊断包失败，请重试'")
        assert page.locator('#diagnostic-export').is_enabled()
        page.evaluate("api.diagnostic=window.savedDiagnostic;el('help').close();el('toast').style.display='none'")
        page.evaluate("window.fakeState.logging_error='磁盘只读';refresh()")
        assert page.locator('#status').inner_text()=='请选择账号后登录；运行日志写入失败：磁盘只读'
        page.evaluate("window.fakeState.logging_error='';refresh()")
        # A login is one explicit action. It must not reload old saved credentials.
        page.locator('#account').fill('typed-login-account');page.locator('#password').fill('typed-login-password')
        page.locator('#login-button').click();page.wait_for_function("!actionBusy&&window.fakeLog.filter(x=>x[0]==='login').length===1")
        assert page.evaluate("window.fakeLog.find(x=>x[0]==='login').slice(1)")==['typed-login-account','typed-login-password','telecom','one',False]
        assert not page.evaluate("window.fakeLog.some(x=>x[0]==='boot')"), 'Accepted login must not overwrite the typed form with old profile data'
        assert page.locator('#account').input_value()=='typed-login-account'
        assert page.locator('#password').input_value()=='typed-login-password'
        assert page.locator('#online-account').inner_text()=='当前在线账号：typed-login-account'
        # Logout uses the currently typed credentials, regardless of cached offline/unknown.
        page.locator('#account').fill('typed-logout-account');page.locator('#password').fill('typed-logout-password')
        page.evaluate("window.fakeState.session_state='offline';window.fakeState.logged_in=false;refresh()")
        assert page.locator('#logout-button').is_enabled()
        page.locator('#logout-button').click();page.wait_for_function("!actionBusy&&window.fakeLog.filter(x=>x[0]==='logout').length===1")
        assert page.evaluate("window.fakeLog.find(x=>x[0]==='logout').slice(1)")==['typed-logout-account','typed-logout-password','one']
        assert page.locator('#online-account').inner_text()=='暂无本次登录记录'
        # Explicit blank fields stay blank; the UI never substitutes a stored profile.
        page.locator('#account').fill('');page.locator('#password').fill('')
        page.locator('#logout-button').click();page.wait_for_function("!actionBusy&&window.fakeLog.filter(x=>x[0]==='logout').length===2")
        assert page.evaluate("window.fakeLog.filter(x=>x[0]==='logout')[1].slice(1)")==['','','one']
        # Deferred profile work locks both actions and profile edits.
        page.evaluate("() => {window.savedSelect=api.select_profile;api.select_profile=id=>new Promise(resolve=>{window.releaseSelect=async()=>resolve(await window.savedSelect(id))});el('profiles').value='two';chooseProfile();}")
        assert page.locator('#login-button').is_disabled() and page.locator('#logout-button').is_disabled()
        assert page.locator('#save-profile').is_disabled()
        before=page.evaluate('window.fakeLog.length');page.evaluate('toggleLogin();logoutSession();saveProfile()')
        assert page.evaluate('window.fakeLog.slice('+str(before)+').every(x=>x[0]==="get_state")')
        page.evaluate('window.releaseSelect()');page.wait_for_function("!profileBusy&&el('account').value==='fake-second'")
        page.evaluate('() => {api.select_profile=window.savedSelect;}')
        page.locator('#save-profile').click();page.wait_for_function("!profileBusy&&window.fakeLog.some(x=>x[0]==='save'&&x[1]==='two')")
        page.locator('#delete-profile').click();assert page.locator('#delete-confirm').is_visible()
        page.locator('#delete-confirm .plain').click();assert not page.evaluate("window.fakeLog.some(x=>x[0]==='delete')")
        # Only verified status describes current identity; receipt history is labelled separately.
        page.evaluate("Object.assign(window.fakeState,{identity_source:'server',online_account:'stale-server-account',session_state:'online',logged_in:true});refresh()")
        assert page.locator('#online-account').inner_text()=='暂无本次登录记录'
        page.evaluate("window.fakeState.identity_source='request_ack';window.fakeState.online_account='acknowledged-account';refresh()")
        assert page.locator('#online-account').inner_text()=='本次请求账号：acknowledged-account'
        assert page.locator('#account-switch-note').is_visible()
        page.locator('#account').fill('acknowledged-account');assert page.locator('#account-switch-note').is_hidden()
        page.locator('#account').fill('fake-second')
        page.evaluate("window.fakeState.session_state='unknown';window.fakeState.logged_in=false;refresh()")
        assert page.locator('#online-account').inner_text()=='本次请求账号：acknowledged-account'
        page.evaluate("window.fakeState.online_account='<img src=x onerror=window.fakeIdentityInjected=true>';refresh()")
        assert page.locator('#online-account').inner_text()=='本次请求账号：<img src=x onerror=window.fakeIdentityInjected=true>'
        assert page.locator('#online-account img').count()==0 and not page.evaluate('!!window.fakeIdentityInjected')
        page.evaluate("Object.assign(window.fakeState,{identity_source:'verified_status',online_account:'verified-account',session_state:'online',logged_in:true});refresh()")
        assert page.locator('#online-account').inner_text()=='当前在线账号：verified-account'
        page.locator('#account').fill('verified-account')
        page.evaluate("window.fakeState.online_account=',0,verified-account@unicom';refresh()")
        assert page.locator('#account-switch-note').is_hidden(), 'Carrier suffix must not look like another account'
        page.evaluate("window.fakeState.online_account='verified-account';refresh()")

        page.evaluate("window.fakeState.online_account='';refresh()")
        assert page.locator('#online-account').inner_text()=='当前设备已登录（账号未确认）'
        page.evaluate("window.fakeState.session_state='offline';window.fakeState.logged_in=false;refresh()")
        assert page.locator('#online-account').inner_text()=='当前设备未登录'
        page.evaluate("window.fakeState.session_state='unknown';window.fakeState.online_account='stale-verified-account';refresh()")
        assert page.locator('#online-account').inner_text()=='登录状态未确认'
        page.evaluate("window.fakeState.identity_source='';window.fakeState.online_account='';refresh()")
        assert page.locator('#online-account').inner_text()=='暂无本次登录记录'
        assert page.locator('#account-switch-note').is_hidden()
        # Campus association controls availability; cached authentication state does not.
        for cached in ('unknown','offline','online'):
            page.evaluate("cached=>{window.fakeState.session_state=cached;refresh()}",cached)
            assert page.locator('#logout-button').is_enabled()
        page.evaluate("window.fakeState.campus=false;window.fakeState.ssid='';refresh()")
        assert page.locator('#logout-button').is_disabled() and page.locator('#status-refresh').is_disabled()
        page.evaluate("window.fakeState.campus=true;window.fakeState.ssid='CUMT_Stu';refresh()")
        assert page.locator('#operator-wrap').is_visible()
        # An outstanding login bridge locks both actions and cannot double-submit.
        page.evaluate("() => {window.savedLogin=api.login;api.login=(...args)=>new Promise(resolve=>{window.releaseLogin=async()=>resolve(await window.savedLogin(...args))});toggleLogin();}")
        assert page.locator('#login-button').is_disabled() and page.locator('#logout-button').is_disabled()
        before=page.evaluate('window.fakeLog.length');page.evaluate('toggleLogin();logoutSession()')
        assert page.evaluate('window.fakeLog.length')==before
        page.evaluate('window.releaseLogin()');page.wait_for_function('!actionBusy')
        page.evaluate('() => {api.login=window.savedLogin;}')
        page.evaluate("window.fakeState.busy=true;window.fakeState.operation='login';refresh()")
        assert page.locator('#login-button').inner_text()=='正在登录…'
        assert page.locator('#login-button').is_disabled() and page.locator('#logout-button').is_disabled()
        assert page.locator('#profiles').is_disabled()
        page.evaluate("window.fakeState.operation='logout';refresh()")
        assert page.locator('#logout-button').inner_text()=='正在注销…'
        page.evaluate("window.fakeState.operation='status';refresh()")
        assert page.locator('#status-refresh').inner_text()=='检测中…' and page.locator('#status-refresh').is_disabled()
        assert page.locator('.session-actions button').count()==2
        page.evaluate("window.fakeState.busy=false;window.fakeState.operation='';refresh()")
        # Auto-popup setting, profile creation/deletion and address trust remain usable.
        page.locator('#startup').click();page.wait_for_function("el('startup').getAttribute('aria-checked')==='true'")
        assert page.evaluate("window.fakeLog.some(x=>x[0]==='startup'&&x[1]===true)")
        page.locator('#new-profile').click();page.wait_for_function("!profileBusy&&el('account').value===''")
        assert page.locator('#delete-profile').is_disabled()
        page.locator('#profiles').select_option('two');page.wait_for_function("!profileBusy&&el('account').value==='fake-second'")
        page.locator('#delete-profile').click();page.locator('#delete-confirm .primary').click()
        page.wait_for_function("!profileBusy&&window.fakeLog.some(x=>x[0]==='delete'&&x[1]==='two')")
        page.evaluate("el('toast').style.display='none'")
        page.evaluate("window.fakeState.pending_host='10.2.7.251';refresh()")
        assert page.locator('#trust').is_visible();page.locator('#trust .plain').click()
        page.locator('#account').fill('new-fake-account');page.locator('#password').fill('new-fake-secret')
        page.locator('#operator').select_option('campus')
        page.locator('#login-button').click();page.wait_for_function("el('trust').open")
        page.locator('#trust .primary').click();page.wait_for_function("!el('trust').open")
        page.evaluate("el('toast').style.display='none'")
        # Quiet-hour confirmation is a user choice, not a network probe.
        page.evaluate("window.fakeState.quiet_hours_active=true;refresh()")
        before=page.evaluate("window.fakeLog.filter(x=>x[0]==='login').length")
        page.locator('#login-button').click();assert page.locator('#quiet-confirm').is_visible()
        assert page.evaluate("window.fakeLog.filter(x=>x[0]==='login').length")==before
        page.locator('#quiet-confirm .primary').click();page.wait_for_function('!actionBusy')
        assert page.evaluate("window.fakeLog.filter(x=>x[0]==='login').at(-1).at(-1)") is True
        page.evaluate("window.fakeState.quiet_hours_active=false;window.fakeState.status='本次登录请求已接受';refresh();el('toast').style.display='none'")
        assert page.evaluate('document.documentElement.scrollWidth<=innerWidth&&document.documentElement.scrollHeight<=innerHeight')
        page.screenshot(path=str(REPORTS/f'登录器_v{c.VERSION}_已登录界面.png'),full_page=True)
        # A native 690px window has about 651px of usable WebView height.
        # Exercise both network forms and the longer neutral action replies.
        original_viewport=page.viewport_size
        for height in (651,631):
            page.set_viewport_size({'width':430,'height':height})
            for ssid in ('CUMT_Stu','CUMT_Tec'):
                for feedback in ('当前设备已在线，本次未重新登录；如需切换账号，请先用原账号注销。',
                                 '该账号下未发现本机在线会话，未发送注销请求。'):
                    page.evaluate("([ssid,status])=>{window.fakeState.ssid=ssid;window.fakeState.status=status;refresh()}",[ssid,feedback])
                    assert page.evaluate('document.documentElement.scrollHeight<=innerHeight')
                    assert page.locator('#login-button').is_visible() and page.locator('#logout-button').is_visible()
        page.set_viewport_size(original_viewport)
        page.evaluate("window.fakeState.ssid='CUMT_Stu';window.fakeState.status='本次登录请求已接受';refresh()")

        pause=a.student_auth_time_notice(c.Wifi(c.STU),a.dt.datetime(2026,10,27,0,15))+' 认证提示：Authentication Fail ErrCode=16'
        page.evaluate("text=>{window.fakeState.status=text;refresh()}",pause)
        page.wait_for_function("el('status').textContent.includes('今日07:00')")
        assert page.locator('#status').inner_text()==pause
        assert page.evaluate('document.documentElement.scrollHeight<=innerHeight')
        assert page.locator('#login-button').is_visible() and page.locator('#logout-button').is_visible()
        page.screenshot(path=str(REPORTS/f'登录器_v{c.VERSION}_暂停认证界面.png'),full_page=True)
        page.evaluate('quitApp()');page.wait_for_function("window.fakeLog.some(x=>x[0]==='quit')")
        assert not errors,errors
        print('all mocked login/logout and manual status UI interactions passed',flush=True)
        context.close();browser.close()
    import webview
    temporary=tempfile.TemporaryDirectory(dir=REPORTS);store=c.Store(Path(temporary.name))
    with patch.object(c,'Store',return_value=store):helper=a.App(False)
    helper.wifi=OFFLINE_WIFI
    window=webview.create_window(a.TITLE,str(ROOT/'campus_ui.html'),js_api=a.Bridge(helper),width=430,height=690)
    helper.window=window;result={}
    def inspect():
        import time
        for _ in range(40):
            time.sleep(.25)
            if window.evaluate_js('!!window.clientReady'):break
        result['title']=window.evaluate_js('document.title')
        result['logo_loaded']=window.evaluate_js("(()=>{const img=el('brand-logo');return img.complete&&img.naturalWidth>0})()")
        result['method']=window.evaluate_js('typeof window.pywebview.api.get_state')
        result['ssid']=window.evaluate_js("el('ssid').innerText")
        result['ready']=window.evaluate_js('!!window.clientReady')
        result['boot_error']=window.evaluate_js('window.clientBootError||null')
        result['startup_switch']=window.evaluate_js("el('startup').getAttribute('role')")
        result['actions']=window.evaluate_js("Array.from(document.querySelectorAll('.session-actions button'),x=>x.textContent)")
        result['retired_controls_absent']=window.evaluate_js("!document.querySelector('#cancel-operation,#network-check')")
        result['manual_status_control']=window.evaluate_js("el('status-refresh').textContent==='检测状态'&&el('status-refresh').disabled")
        result['status_method']=window.evaluate_js('typeof window.pywebview.api.refresh_status')
        result['diagnostic_export']=window.evaluate_js("el('diagnostic-export').innerText")
        result['action_identity']=window.evaluate_js("el('online-account').innerText")
        result['logging_isolated']=helper.runtime_log.root==store.root and helper.runtime_log.path.is_file()
        reads_before=getattr(c.read_wifi,'call_count',0)
        window.evaluate_js("window.__snapshotCalls=0;Promise.all(Array.from({length:8},()=>api.get_state().then(()=>window.__snapshotCalls++)));true")
        for _ in range(20):
            if window.evaluate_js('window.__snapshotCalls')==8:break
            time.sleep(.05)
        result['snapshot_api_calls']=window.evaluate_js('window.__snapshotCalls')
        result['memory_poll_no_wlan_reads']=getattr(c.read_wifi,'call_count',0)==reads_before
        window.destroy()
    webview.start(inspect,gui='edgechromium',debug=False,private_mode=True,icon=str(ROOT/'assets/icon.ico'))
    helper.runtime_log.close();temporary.cleanup()
    assert result['title']==a.TITLE and result['method']=='function' and result['logo_loaded'],result
    assert result['ready'] and result['ssid']==helper.wifi.ssid and result['startup_switch']=='switch',result
    assert result['actions']==['登录','注销'] and result['retired_controls_absent'],result
    assert result['manual_status_control'] and result['status_method']=='function',result
    assert result['diagnostic_export']=='导出诊断包' and result['logging_isolated'],result
    assert result['action_identity']=='暂无本次登录记录',result
    assert result['snapshot_api_calls']==8 and result['memory_poll_no_wlan_reads'],result
    report={'version':c.VERSION,'compact_ui':True,'no_conversation_copy':True,'webview_result':result,
            'two_primary_actions_and_manual_status':True,'typed_logout_parameters':True,'explicit_blank_logout_not_replaced':True,
            'memory_snapshot_poll_only':True,'no_user_network_check_controls':True,'busy_locks_both_actions':True,
            'verified_status_and_ack_identity_distinguished':True,'stale_server_identity_ignored':True,'manual_status_no_authentication':True,'manual_status_busy_guard':True,
            'accepted_login_preserves_typed_form':True,'diagnostic_export_feedback':True,'logging_failure_visible':True,
            'profiles_crud_preserved':True,'automatic_popup_control_preserved':True,
            'concise_help_fits_without_scrolling':True,'advanced_address_settings_collapsible':True,
            'quiet_hours_notice_readable_with_actions_visible':True,'self_service_link_inspected_without_navigation':True,
            'campus_requests':0,'network_configuration_changes':0,'success':True}
    report['verification']=finish_verification(verification,ROOT)
    report['success']=report['success'] and report['verification']['source_stable']
    (REPORTS/'ui_smoke_results.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(report,ensure_ascii=False));assert report['success'],'Sources changed during UI verification'

def hidden_test():
    verification=start_report('hidden')
    import ctypes
    import os
    import tempfile
    import threading
    import time
    from unittest.mock import patch
    import webview
    with tempfile.TemporaryDirectory(dir=REPORTS) as folder:
        store=c.Store(Path(folder))
        with patch.object(c,'Store',return_value=store): helper=a.App(True)
        assert helper.runtime_log.root==store.root
        helper.settings['stu_autostart']=True
        helper.wifi=OFFLINE_WIFI
        window=webview.create_window('CumtHiddenOfflineSelfTest',str(ROOT/'campus_ui.html'),js_api=a.Bridge(helper),width=430,height=690,hidden=True)
        helper.window=window
        window.events.closing+=helper.on_closing
        result={'version':c.VERSION,'campus_requests':0,'settings_changes':0,'logging_isolated':True}
        user=ctypes.WinDLL('user32');callback_type=ctypes.WINFUNCTYPE(ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p)
        user.IsWindowVisible.argtypes=[ctypes.c_void_p]
        user.GetWindowThreadProcessId.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_ulong)]
        user.GetWindowTextW.argtypes=[ctypes.c_void_p,ctypes.c_wchar_p,ctypes.c_int]
        def visible():
            found=[]
            def inspect(hwnd,param):
                pid=ctypes.c_ulong();user.GetWindowThreadProcessId(hwnd,ctypes.byref(pid))
                title=ctypes.create_unicode_buffer(256);user.GetWindowTextW(hwnd,title,256)
                if pid.value==os.getpid() and title.value=='CumtHiddenOfflineSelfTest':found.append(bool(user.IsWindowVisible(hwnd)))
                return True
            user.EnumWindows(callback_type(inspect),None)
            return any(found)
        def inspect():
            try:
                for _ in range(40):
                    time.sleep(.25)
                    if window.evaluate_js('!!window.clientReady'):break
                result['ready']=bool(window.evaluate_js('!!window.clientReady'))
                result['starts_hidden']=not visible()
                kernel=ctypes.WinDLL('kernel32')
                kernel.CreateEventW.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_int,ctypes.c_wchar_p]
                kernel.CreateEventW.restype=ctypes.c_void_p
                kernel.SetEvent.argtypes=[ctypes.c_void_p]
                kernel.CloseHandle.argtypes=[ctypes.c_void_p]
                helper.show_event=kernel.CreateEventW(None,False,False,None)
                kernel.SetEvent(helper.show_event)
                helper.poll_show_event();time.sleep(.25)
                result['show_restores']=visible()
                kernel.CloseHandle(helper.show_event);helper.show_event=None
                result['close_keeps_listener']=helper.on_closing() is False and not helper.closed.is_set()
                time.sleep(.25);result['close_hides']=not visible()
                result['success']=all(result[k] for k in ('ready','starts_hidden','show_restores','close_keeps_listener','close_hides'))
            finally:helper.quit()
        webview.start(inspect,gui='edgechromium',debug=False,private_mode=True,icon=str(ROOT/'assets/icon.ico'))
        helper.runtime_log.close()
        result['quit_stops']=helper.closed.is_set()
        result['success']=result.get('success',False) and result['quit_stops']
    result['verification']=finish_verification(verification,ROOT)
    result['success']=result['success'] and result['verification']['source_stable']
    (REPORTS/'hidden_smoke_results.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(result,ensure_ascii=False))
    assert result['success'],result

if __name__=='__main__':
    # Any accidental real HTTP request or WLAN query is a hard test failure.
    with patch.object(c,'read_wifi',return_value=OFFLINE_WIFI), \
         patch.object(c,'BoundHTTP',side_effect=AssertionError('offline UI test attempted network access')), \
         patch.object(a.App,'started',side_effect=AssertionError('offline UI test attempted monitor startup')), \
         patch.object(a.App,'startup_enabled',return_value=False):
        if '--hidden' in sys.argv:hidden_test()
        else:main()
