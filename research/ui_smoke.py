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
    for unwanted in ('热点保护','第三校区','咱俩','聊天','自动弹窗','auto_enabled','auto_submit'):
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
        assert page.locator('#brand-logo').evaluate('(img)=>img.complete && img.naturalWidth>0'), 'Brand asset must load'
        assert page.locator('#startup').get_attribute('role')=='switch'
        assert page.locator('#login-switch').count()==0
        assert page.locator('#tec').count()==0
        assert page.locator('#profiles').count()==1
        assert page.locator('#startup').get_attribute('aria-label')=='连接校园网（CUMT_Stu/CUMT_Tec）时自动弹出'
        assert page.locator('.row .note').inner_text()=='后台监听，连接后弹出；有已保存账号时自动尝试一次'
        assert page.locator('#online-account').inner_text()=='在线账号：尚未确认'
        assert page.locator('#account-switch-note').is_hidden()
        assert page.locator('#login-button').inner_text()=='登录'
        assert page.locator('#logout-button').inner_text()=='注销'
        assert page.locator('#logout-button').is_disabled()
        assert page.locator('#cancel-operation').is_hidden()
        assert page.locator('#status-refresh').count()==1
        assert page.locator('#diagnostic-export').inner_text()=='导出诊断包'
        assert page.locator('#account').count()==1
        assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth')
        assert page.evaluate('document.documentElement.scrollHeight<=window.innerHeight'), 'UI must fit without scrolling'
        page.locator('.eye').click();assert page.locator('#password').get_attribute('type')=='text'
        page.locator('.eye').click()
        page.evaluate('exportDiagnostic()')
        assert page.locator('#toast').inner_text()=='请在桌面客户端中导出诊断包'
        page.evaluate("document.getElementById('toast').style.display='none'")
        page.screenshot(path=str(REPORTS/f'登录器_v{c.VERSION}_界面.png'),full_page=True)
        # All desktop actions below are mocked in memory, not user settings.
        page.evaluate('''version => {
          window.fakeLog=[];
          window.fakeData={version,selected:'one',account:'fake-account',password:'fake-password',operator:'telecom',startup:false,portal_hint:'',profiles:[{id:'one',account:'fake-account'},{id:'two',account:'fake-second'}]};
          window.fakeState={version,ssid:'CUMT_Tec',campus:true,student:false,busy:false,logged_in:false,session_state:'offline',online_account:'',identity_source:'',session_binding:null,status:'未登录',pending_host:'',logging_error:''};
          window.fakeDiagnostic={ok:true,path:'C:/Fake/diagnostic-fake.zip'};
          api={boot:async()=>window.fakeData,get_state:async()=>window.fakeState,
            login:async(...args)=>{window.fakeLog.push(['login',...args]);return {ok:true}},
            logout:async()=>{window.fakeLog.push(['logout']);return {ok:true}},
            cancel_operation:async()=>{window.fakeLog.push(['cancel_operation']);window.fakeState.status='已请求停止';return {ok:true,message:'已请求停止'}},
            refresh_status:async()=>{window.fakeLog.push(['refresh_status']);return {ok:true}},
            diagnostic:async()=>{window.fakeLog.push(['diagnostic']);return window.fakeDiagnostic},
            select_profile:async(id)=>{window.fakeData.selected=id;window.fakeData.account=id==='two'?'fake-second':id?'fake-account':'';window.fakeData.password=id?'fake-password':'';return {ok:true,data:window.fakeData}},
            save_profile:async(...args)=>{window.fakeLog.push(['save',...args]);return {ok:true,data:window.fakeData}},
            delete_profile:async(id)=>{window.fakeLog.push(['delete',id]);return {ok:true,data:window.fakeData}},
            trust_portal:async()=>{window.fakeState.pending_host='';return {ok:true}},
            set_startup:async(on)=>{window.fakeLog.push(['startup',on]);return {ok:true}},
            save_hint:async(value)=>{window.fakeLog.push(['hint',value]);return {ok:true}}};
          applyBoot(window.fakeData);
        }''',c.VERSION)
        page.evaluate('refresh()')
        assert page.locator('#operator-wrap').is_hidden()
        assert page.locator('#online-account').inner_text()=='当前未登录'
        page.evaluate("window.fakeState.logout_recovery_needed=true;refresh()")
        assert page.locator('#online-account').inner_text()=='接入下线尚未确认'
        assert page.locator('#logout-button').is_enabled()
        assert page.locator('#session-recovery').is_visible()
        page.locator('#logout-button').click()
        page.wait_for_function("!actionBusy&&window.fakeLog.filter(x=>x[0]==='logout').length===1")
        page.evaluate("window.fakeLog=window.fakeLog.filter(x=>x[0]!=='logout');window.fakeState.logout_recovery_needed=false;refresh()")
        assert page.locator('#logout-button').is_disabled()
        # Export success, explicit failure and rejected bridge calls must all
        # produce visible feedback, including while the modal help is open.
        page.evaluate('showHelp()')
        assert not page.locator('#help-advanced').evaluate('(element)=>element.open')
        assert page.locator('#portal_hint').is_hidden()
        assert page.evaluate("() => {const d=document.getElementById('help');return d.scrollHeight<=d.clientHeight+1}")
        page.locator('#help-advanced summary').click()
        page.locator('#portal_hint').fill('http://10.2.5.251/a79.htm')
        page.locator('#portal-save').click()
        page.wait_for_function("window.fakeLog.some(x=>x[0]==='hint'&&x[1]==='http://10.2.5.251/a79.htm')")
        page.locator('#help-advanced summary').click()
        assert page.locator('#portal_hint').is_hidden()
        assert page.locator('#portal_hint').input_value()=='http://10.2.5.251/a79.htm'
        page.evaluate("document.getElementById('toast').style.display='none'")
        # Inspect the self-service link without opening any network destination.
        self_service=page.locator('#campus-self-service')
        assert self_service.inner_text()=='校园网自助服务'
        assert self_service.get_attribute('href')=='http://202.119.196.6:8080/Self/dashboard'
        assert self_service.get_attribute('target')=='_blank'
        assert set(self_service.get_attribute('rel').split())=={'noopener','noreferrer'}
        assert self_service.get_attribute('onclick') is None
        assert page.evaluate("() => {const r=document.getElementById('help').getBoundingClientRect();return r.top>=0&&r.bottom<=window.innerHeight&&r.height<=window.innerHeight-32}")
        assert page.evaluate("getComputedStyle(document.getElementById('help')).overflowY==='auto'")
        page.locator('#diagnostic-export').click()
        page.wait_for_function("!diagnosticBusy&&document.getElementById('toast').textContent==='诊断包已保存：C:/Fake/diagnostic-fake.zip'")
        assert page.locator('#toast').is_visible()
        assert page.evaluate("() => {const t=document.getElementById('toast'),r=t.getBoundingClientRect();return document.elementFromPoint(r.x+r.width/2,r.y+r.height/2)===t}")
        page.evaluate("window.fakeDiagnostic.path='C:/Fake/diagnostic-'+('a'.repeat(160))+'.zip'")
        page.locator('#diagnostic-export').click()
        page.wait_for_function("!diagnosticBusy&&document.getElementById('toast').textContent.endsWith(window.fakeDiagnostic.path)")
        assert page.evaluate("() => {const t=document.getElementById('toast');return t.scrollWidth<=t.clientWidth}")
        page.evaluate("window.fakeDiagnostic={ok:false,message:'无法写入诊断包：磁盘空间不足'}")
        page.locator('#diagnostic-export').click()
        page.wait_for_function("!diagnosticBusy&&document.getElementById('toast').textContent==='无法写入诊断包：磁盘空间不足'")
        assert page.locator('#toast').is_visible()
        page.evaluate("() => {window.savedDiagnostic=api.diagnostic;api.diagnostic=async()=>{throw new Error('fake bridge failure')}}")
        page.locator('#diagnostic-export').click()
        page.wait_for_function("!diagnosticBusy&&document.getElementById('toast').textContent==='导出诊断包失败，请重试'")
        assert page.locator('#diagnostic-export').is_enabled()
        page.evaluate("api.diagnostic=window.savedDiagnostic;document.getElementById('help').close()")
        page.evaluate("window.fakeState.logging_error='磁盘只读';refresh()")
        assert page.locator('#status').inner_text()=='未登录；运行日志写入失败：磁盘只读'
        page.evaluate("window.fakeState.logging_error='';refresh()")
        assert page.locator('#status').inner_text()=='未登录'
        page.locator('#login-button').click()
        assert page.locator('dialog[open]').count()==0
        assert page.evaluate("window.fakeLog.filter(x=>x[0]==='login').length")==1
        page.evaluate("() => {window.savedSelect=api.select_profile;api.select_profile=id=>new Promise(resolve=>{window.releaseSelect=async()=>resolve(await window.savedSelect(id))});}")
        page.evaluate("() => {document.getElementById('profiles').value='two';chooseProfile();}")
        print('checking deferred profile selection',flush=True)
        assert page.locator('#login-button').is_disabled()
        assert page.locator('#logout-button').is_disabled()
        assert page.locator('#status-refresh').is_disabled()
        page.evaluate("window.fakeState.campus=true;window.fakeState.session_conflict=true;window.fakeState.session_state='unknown';refresh()")
        assert page.locator('#session-recovery').is_visible()
        assert page.locator('#session-recovery').get_attribute('href')=='http://202.119.196.6:8080/Self/dashboard'
        assert page.locator('#session-recovery').get_attribute('target')=='_blank'
        page.evaluate("window.fakeState.session_conflict=false;refresh()")
        assert page.locator('#session-recovery').is_hidden()
        assert page.locator('#save-profile').is_disabled()
        page.evaluate('toggleLogin();logoutSession();refreshStatus();saveProfile()')
        assert page.evaluate("window.fakeLog.filter(x=>x[0]==='login').length")==1
        assert not page.evaluate("window.fakeLog.some(x=>x[0]==='save')")
        assert not page.evaluate("window.fakeLog.some(x=>x[0]==='logout'||x[0]==='refresh_status')")
        page.evaluate('() => {window.releaseSelect();}')
        print('released deferred profile selection',flush=True)
        page.wait_for_function("document.getElementById('account').value==='fake-second'")
        page.locator('#save-profile').click()
        page.wait_for_function("window.fakeLog.some(x=>x[0]==='save'&&x[1]==='two')")
        page.locator('#delete-profile').click()
        assert page.locator('#delete-confirm').is_visible()
        page.locator('#delete-confirm .plain').click()
        assert not page.evaluate("window.fakeLog.some(x=>x[0]==='delete')")
        page.evaluate("window.fakeState.ssid='CUMT_Stu';refresh()")
        assert page.locator('#operator-wrap').is_visible()
        page.evaluate("window.fakeState.logged_in=true;window.fakeState.session_state='online';window.fakeState.status='当前 WiFi 已登录';refresh()")
        assert page.locator('#login-button').inner_text()=='登录'
        assert page.locator('#logout-button').is_enabled()
        assert page.locator('#status').inner_text()=='当前 WiFi 已登录'
        assert page.locator('#status-refresh').is_enabled()
        # Server identity is independent from the selected/editable credential.
        assert page.locator('#online-account').inner_text()=='在线账号：服务器未提供'
        assert page.locator('#account-switch-note').is_hidden()
        page.evaluate("window.fakeState.online_account='fake-server-online';window.fakeState.identity_source='server';window.fakeState.session_binding=['CUMT_Stu','fake-interface',11,'10.53.3.4'];refresh()")
        assert page.locator('#online-account').inner_text()=='在线账号：fake-server-online（服务器返回）'
        assert page.locator('#account').input_value()=='fake-second'
        assert page.locator('#account-switch-note').is_visible()
        assert page.locator('#account-switch-note').inner_text()=='切换账号请先注销'
        page.locator('#account').fill('fake-local-edited')
        assert page.locator('#online-account').inner_text()=='在线账号：fake-server-online（服务器返回）'
        assert page.locator('#account-switch-note').is_visible()
        page.locator('#account').fill('fake-server-online')
        assert page.locator('#account-switch-note').is_hidden()
        page.locator('#account').fill('fake-second')
        page.evaluate("window.fakeState.identity_source='';refresh()")
        assert page.locator('#online-account').inner_text()=='在线账号：服务器未提供'
        assert page.locator('#account-switch-note').is_hidden()
        page.evaluate("window.fakeState.identity_source='server';window.fakeState.online_account='<img src=x onerror=window.fakeIdentityInjected=true>';refresh()")
        assert page.locator('#online-account').inner_text()=='在线账号：<img src=x onerror=window.fakeIdentityInjected=true>（服务器返回）'
        assert page.locator('#online-account img').count()==0
        assert not page.evaluate('!!window.fakeIdentityInjected')
        page.evaluate("window.fakeState.session_state='unknown';refresh()")
        assert page.locator('#online-account').inner_text()=='在线账号：尚未确认'
        assert page.locator('#account-switch-note').is_hidden()
        page.evaluate("window.fakeState.session_state='offline';refresh()")
        assert page.locator('#online-account').inner_text()=='当前未登录'
        page.evaluate("window.fakeState.session_state='online';window.fakeState.campus=false;refresh()")
        assert page.locator('#online-account').inner_text()=='在线账号：尚未确认'
        assert page.locator('#account-switch-note').is_hidden()
        page.evaluate("window.fakeState.campus=true;window.fakeState.online_account='fake-server-online';refresh()")
        assert page.locator('#online-account').inner_text()=='在线账号：fake-server-online（服务器返回）'
        # An already-online login remains a login/check action, never a logout.
        page.locator('#login-button').click()
        page.wait_for_function("window.fakeLog.filter(x=>x[0]==='login').length===2&&!actionBusy")
        assert not page.evaluate("window.fakeLog.some(x=>x[0]==='logout')")
        page.locator('#status-refresh').click()
        page.wait_for_function("window.fakeLog.some(x=>x[0]==='refresh_status')&&!actionBusy")
        page.evaluate("() => {window.savedRefresh=api.refresh_status;api.refresh_status=()=>new Promise(resolve=>{window.releaseRefresh=async()=>resolve(await window.savedRefresh())});refreshStatus();}")
        assert page.locator('#login-button').is_disabled()
        assert page.locator('#logout-button').is_disabled()
        assert page.locator('#status-refresh').is_disabled()
        page.evaluate('toggleLogin();logoutSession();refreshStatus()')
        assert page.evaluate("window.fakeLog.filter(x=>x[0]==='login').length")==2
        assert not page.evaluate("window.fakeLog.some(x=>x[0]==='logout')")
        page.evaluate('() => {window.releaseRefresh();}')
        page.wait_for_function("!actionBusy")
        page.locator('#logout-button').click()
        page.wait_for_function("window.fakeLog.some(x=>x[0]==='logout')&&!actionBusy")
        assert page.evaluate("window.fakeLog.some(x=>x[0]==='logout')")
        page.evaluate("window.fakeState.busy=true;window.fakeState.operation='status';refresh()")
        assert page.locator('#login-button').is_disabled()
        assert page.locator('#login-button').inner_text()=='正在检查…'
        assert page.locator('#logout-button').is_disabled()
        assert page.locator('#status-refresh').is_disabled()
        assert page.locator('#profiles').is_disabled()
        page.evaluate("window.fakeState.operation='logout';refresh()")
        assert page.locator('#logout-button').inner_text()=='正在注销…'
        assert page.locator('#cancel-operation').is_visible()
        assert page.locator('#cancel-operation').is_enabled()
        # Cancellation must remain available while an operation or profile
        # bridge call is pending; only the cancellation request is deduplicated.
        page.evaluate("() => {actionBusy=true;profileBusy=true;window.savedCancel=api.cancel_operation;api.cancel_operation=()=>{window.fakeLog.push(['cancel_requested']);return new Promise(resolve=>{window.releaseCancel=async()=>resolve(await window.savedCancel())})};updateControls()}")
        assert page.locator('#cancel-operation').is_enabled()
        assert page.locator('#login-button').is_disabled()
        assert page.locator('#logout-button').is_disabled()
        assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth')
        assert page.evaluate('document.documentElement.scrollHeight<=window.innerHeight')
        page.locator('#cancel-operation').click()
        assert page.locator('#cancel-operation').inner_text()=='正在停止…'
        assert page.locator('#cancel-operation').is_disabled()
        page.evaluate('cancelOperation();cancelOperation()')
        assert page.evaluate("window.fakeLog.filter(x=>x[0]==='cancel_requested').length")==1
        assert not page.evaluate("window.fakeLog.some(x=>x[0]==='cancel_operation')")
        page.evaluate('() => {window.releaseCancel();}')
        page.wait_for_function("!cancelBusy&&window.fakeLog.filter(x=>x[0]==='cancel_operation').length===1")
        assert page.locator('#toast').inner_text()=='已请求停止'
        assert page.evaluate('state.busy'), 'Requesting cancellation must not pretend the job already stopped'
        assert page.locator('#cancel-operation').is_enabled()
        page.evaluate("() => {api.cancel_operation=window.savedCancel;actionBusy=false;profileBusy=false;document.getElementById('toast').style.display='none';updateControls()}")
        page.evaluate("window.fakeState.busy=false;window.fakeState.operation='';window.fakeState.logged_in=false;window.fakeState.session_state='unknown';refresh()")
        assert page.locator('#cancel-operation').is_hidden()
        assert page.locator('#logout-button').is_enabled()
        assert page.locator('#online-account').inner_text()=='在线账号：尚未确认'
        page.evaluate("window.fakeState.session_state='offline';refresh()")
        assert page.locator('#logout-button').is_disabled()
        assert page.locator('#online-account').inner_text()=='当前未登录'
        page.evaluate("window.fakeState.ssid='';window.fakeState.campus=false;window.fakeState.session_state='unknown';refresh()")
        assert page.locator('#logout-button').is_disabled()
        assert page.locator('#status-refresh').is_disabled()
        page.evaluate("window.fakeState.ssid='CUMT_Stu';window.fakeState.campus=true;window.fakeState.pending_host='10.2.7.251';refresh()")
        assert page.locator('#trust').is_visible()
        page.locator('#trust .plain').click()
        page.locator('#login-button').click()
        page.wait_for_function("document.getElementById('trust').open")
        page.locator('#trust .primary').click()
        page.wait_for_function("!document.getElementById('trust').open")
        page.evaluate("window.fakeState.logged_in=true;window.fakeState.session_state='online';window.fakeState.status='当前 WiFi 已登录';refresh()")
        assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth')
        assert page.evaluate('document.documentElement.scrollHeight<=window.innerHeight')
        page.evaluate("document.getElementById('toast').style.display='none';document.getElementById('operator').value='campus'")
        page.screenshot(path=str(REPORTS/f'登录器_v{c.VERSION}_已登录界面.png'),full_page=True)
        pause=a.student_auth_time_notice(c.Wifi(c.STU),a.dt.datetime(2026,10,27,0,15))
        pause+=' 认证提示：Authentication Fail ErrCode=16'
        page.evaluate("text=>{Object.assign(window.fakeState,{logged_in:false,session_state:'offline',status:text});refresh()}",pause)
        page.wait_for_function("document.getElementById('status').textContent.includes('今日07:00')")
        assert page.locator('#status').inner_text()==pause
        assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth')
        assert page.evaluate('document.documentElement.scrollHeight<=window.innerHeight'), 'Pause notice must fit without hiding actions'
        assert page.locator('#login-button').is_visible()
        page.screenshot(path=str(REPORTS/f'登录器_v{c.VERSION}_暂停认证界面.png'),full_page=True)
        assert not errors,errors
        print('all mocked UI interactions passed',flush=True)
        context.close();browser.close()
    import webview
    # App() normally reads the user's saved profiles. Keep this entire test
    # isolated, including the asynchronous bridge calls made by the webview.
    temporary=tempfile.TemporaryDirectory(dir=REPORTS)
    store=c.Store(Path(temporary.name))
    with patch.object(c,'Store',return_value=store): helper=a.App(False)
    assert helper.runtime_log.root==store.root
    helper.wifi=OFFLINE_WIFI
    window=webview.create_window(a.TITLE,str(ROOT/'campus_ui.html'),js_api=a.Bridge(helper),width=430,height=690)
    helper.window=window;result={}
    def inspect():
        import time
        for _ in range(40):
            time.sleep(.25)
            if window.evaluate_js('!!window.clientReady'): break
        result['title']=window.evaluate_js('document.title')
        result['logo_loaded']=window.evaluate_js("(()=>{const img=document.getElementById('brand-logo');return img.complete&&img.naturalWidth>0})()")
        result['method']=window.evaluate_js('typeof window.pywebview.api.get_state')
        result['ssid']=window.evaluate_js("document.getElementById('ssid').innerText")
        result['ready']=window.evaluate_js('!!window.clientReady')
        result['boot_error']=window.evaluate_js('window.clientBootError||null')
        result['startup_switch']=window.evaluate_js("document.getElementById('startup').getAttribute('role')")
        result['logout_button']=window.evaluate_js("document.getElementById('logout-button').innerText")
        result['cancel_operation_api']=window.evaluate_js('typeof window.pywebview.api.cancel_operation')
        result['cancel_operation_button']=window.evaluate_js("document.getElementById('cancel-operation').innerText")
        result['status_refresh']=window.evaluate_js("!!document.getElementById('status-refresh')")
        result['diagnostic_export']=window.evaluate_js("document.getElementById('diagnostic-export').innerText")
        result['online_identity']=window.evaluate_js("document.getElementById('online-account').innerText")
        result['logging_isolated']=helper.runtime_log.root==store.root and helper.runtime_log.path.is_file()
        window.destroy()
    webview.start(inspect,gui='edgechromium',debug=False,private_mode=True,icon=str(ROOT/'assets/icon.ico'))
    helper.runtime_log.close()
    temporary.cleanup()
    assert result['title']==a.TITLE and result['method']=='function' and result['logo_loaded'],result
    assert result['ssid']==helper.wifi.ssid and result['startup_switch']=='switch',result
    assert result['logout_button']=='注销' and result['status_refresh'],result
    assert result['cancel_operation_api']=='function' and result['cancel_operation_button']=='取消操作',result
    assert result['diagnostic_export']=='导出诊断包' and result['logging_isolated'],result
    assert result['online_identity']=='在线账号：尚未确认',result
    report={'version':c.VERSION,'compact_ui':True,'no_conversation_copy':True,'webview_result':result,
            'separate_logout':True,'online_login_does_not_logout':True,'manual_status_refresh':True,
            'session_state_controls':True,'diagnostic_export_feedback':True,'logging_failure_visible':True,
            'cancellation_available_while_busy':True,'cancellation_request_deduplicated':True,
            'server_identity_separate_from_selected_profile':True,'server_identity_text_only':True,
            'unknown_offline_disconnect_clear_identity':True,'account_switch_requires_logout_notice':True,
            'concise_help_fits_without_scrolling':True,'advanced_address_settings_collapsible':True,
            'quiet_hours_notice_readable_with_actions_visible':True,
            'self_service_link_inspected_without_navigation':True,'help_fits_viewport_with_scrolling':True,
            'campus_requests':0,'network_configuration_changes':0,'success':True}
    report['verification']=finish_verification(verification,ROOT)
    report['success']=report['success'] and report['verification']['source_stable']
    (REPORTS/'ui_smoke_results.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(report,ensure_ascii=False))
    assert report['success'], 'Sources changed during UI verification'
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
