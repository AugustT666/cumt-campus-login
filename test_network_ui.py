"""Network check uses its own bridge action and never the login fields."""
from pathlib import Path
import unittest

from playwright.sync_api import sync_playwright


class NetworkCheckUiTests(unittest.TestCase):
    def test_help_check_action_has_busy_guard_and_displays_final_status(self):
        html = Path(__file__).with_name('campus_ui.html').read_text('utf-8')
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel='msedge', headless=True,
                args=['--no-proxy-server', '--disable-background-networking'])
            context = browser.new_context(viewport={'width': 430, 'height': 680})
            context.route('**/*', lambda route: route.abort())
            page = context.new_page()
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.set_content(html)
            page.evaluate('''() => {
                window.checkCalls=0;window.loginCalls=0;
                window.fixture={campus:true,ssid:'CUMT_Stu',session_state:'unknown',
                    busy:false,version:'test',status:'待检查'};state=window.fixture;
                api={network_check:()=>{window.checkCalls++;return new Promise(resolve=>window.acceptCheck=resolve)},
                    login:async()=>{window.loginCalls++;return {ok:true}},
                    get_state:async()=>window.fixture};
                document.getElementById('account').value='private-test-account';
                document.getElementById('password').value='private-test-password';
                updateControls();showHelp();
            }''')
            page.locator('#network-check').click()
            page.wait_for_function('window.checkCalls===1')
            self.assertTrue(page.locator('#network-check').is_disabled())
            page.evaluate('checkNetwork()')
            self.assertEqual(page.evaluate('window.checkCalls'), 1)
            page.evaluate('''() => {
                window.fixture={...window.fixture,busy:true,operation:'network_check',status:'正在自检'};
                window.acceptCheck({ok:true});
            }''')
            page.wait_for_function('!actionBusy && state.busy')
            self.assertFalse(page.locator('#help').is_visible())
            self.assertEqual(page.locator('#login-button').inner_text(), '正在检查…')
            self.assertTrue(page.locator('#login-button').is_disabled())
            page.evaluate('''async() => {
                window.fixture={...window.fixture,busy:false,operation:'',status:'校园连接已恢复，可刷新状态'};
                await refresh();
            }''')
            self.assertIn('连接已恢复', page.locator('#status').inner_text())
            page.evaluate("state={...state,campus:false};updateControls();showHelp()")
            self.assertTrue(page.locator('#network-check').is_disabled())
            page.evaluate('checkNetwork()')
            self.assertEqual(page.evaluate('window.checkCalls'), 1)
            self.assertEqual(page.evaluate('window.loginCalls'), 0)
            self.assertEqual(errors, [])
            context.close()
            browser.close()


if __name__ == '__main__':
    unittest.main()
