# 开发说明

## 版本与环境

当前版本为 v1.7.9。版本用途及分支约定见 [版本说明](VERSIONS.md)。日常改进以 `main` 为起点。

需要 Windows、Python 3.12 和 WebView2 Runtime。v1.6.4 的门户兼容还需要系统已有 Edge 或 Chrome；当前 Windows 生产包使用独立 WebView2 控件。

在仓库根目录执行：

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe campus_app.py
```

## 校园网注销

门户认证沿用学校原页面的 MAC 参数格式，不用状态接口返回的空值或全零 MAC 替换当前网卡地址。接入证据完整时，异常会话不会永久阻止用户发起一次手动操作；请求仍受当前无线环境与取消状态校验。

学生网与教师网均先执行普通注销，短确认后释放前台操作，再在后台核对认证状态与绑定当前 Wi-Fi 的严格外网探测。证据确认下线后显示已退出，并在有限时间内复查会话是否恢复；不再固定阻塞前台等待一分钟。普通注销正常完成时，不登录或查询自助服务。

只有普通流程无法完成注销时，才使用已保存的对应账号登录自助服务，精准下线本机对应的单一会话，不批量下线其他设备。后台发现会话恢复时，同一次注销最多执行一次精准兜底。兜底后同时核对自助服务设备列表和认证状态，无法确认时不报成功。出现验证码或无法唯一核对设备时停止自动处理，操作结束后退出自助网页会话。

新的手动登录、注销、切网或退出会使旧的后台复查失效。后台结果返回后，须重新核对注销意图与完整网络上下文；旧结果不能覆盖新操作的状态或继续下线新会话。

对于自助服务中当前 IP 唯一、MAC 缺失或全零的会话，仅在取得新鲜 NAS 绑定证明后允许精准下线。证明来自绑定当前物理校园网网卡读取的原始学校门户重定向，必须核对本机 IP、MAC、接入设备名称及 NAS 地址；不得用补写或改写后的 URL 充当证据。证明关联完整无线环境，最多有效 10 秒；同账号设备列表须二次读取同一会话，并在提交前再次验证。有效但不同的 MAC、重复 IP 或证明不足时拒绝自动处理，不批量下线其他设备。

## 界面响应与取消

网络预检、接入发现、状态查询和认证请求均在应用状态锁外执行。锁只用于保存快照及提交结果；写回前重新核对操作标识、取消状态和完整网络上下文，防止慢请求阻塞界面或覆盖新操作。

“取消操作”撤销当前操作意图并阻止后续提交；已发给服务器的请求不能撤回，应通过状态回读确认最终结果。自助服务网页会话仍需尽力清理，取消不得触发新的认证或下线请求。

## 自动化检查

先安装开发或构建依赖，再运行公开仓库自带的合成测试：

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe research/run_offline_tests.py
.\.venv\Scripts\python.exe research/ui_smoke.py
.\.venv\Scripts\python.exe research/ui_smoke.py --hidden
```

默认测试不读取真实账号、不提交校园网认证。它明确排除25项依赖本机门户抓取的集成检查，并在结果中逐项列出排除范围；实际运行的测试有任何跳过、失败或错误都不能满足交付条件。

维护者若自行准备所需六份本地门户素材，可显式运行：

```powershell
.\.venv\Scripts\python.exe research/run_offline_tests.py --with-local-captures
```

素材位于 `.local/deep-audit/live-capture/` 下五份脚本及 `.local/portal-logout-audit/a79.htm`。缺失时此模式会明确失败，不会自动访问校园网或把未执行的检查算作通过。素材和生成报告均不进入 Git。

## 构建

源码检查通过后再构建。以下过程会验证冻结 EXE、图标、日志导出和当前源码指纹：

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-build-lock.txt
.\.venv\Scripts\python.exe research/build_and_verify.py
.\.venv\Scripts\python.exe research/package_current.py
```

报告与构建清单保留在本机，包含实际测试范围；应用能启动或合成测试通过，不代表所有校区、教师账号和运营商均已现场验证。修改产品或维护输入后，需重新生成匹配的检查结果。

请勿提交个人账号、设置、诊断包、原始门户抓取、生成截图、构建环境或现场记录。仅保留可复用测试及维护脚本。
