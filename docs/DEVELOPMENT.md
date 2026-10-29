# 开发说明

## 版本与环境

当前版本为 v1.7.8。版本用途及分支约定见 [版本说明](VERSIONS.md)。日常改进以 `main` 为起点。

需要 Windows、Python 3.12 和 WebView2 Runtime。v1.6.4 的门户兼容还需要系统已有 Edge 或 Chrome；当前 Windows 生产包使用独立 WebView2 控件。

在仓库根目录执行：

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe campus_app.py
```

## 校园网注销

学生网与教师网均先执行普通注销，短确认后释放前台操作，再在后台核对认证状态与绑定当前 Wi-Fi 的严格外网探测。证据确认下线后显示已退出，并在有限时间内复查会话是否恢复；不再固定阻塞前台等待一分钟。普通注销正常完成时，不登录或查询自助服务。

只有普通流程无法完成注销时，才使用已保存的对应账号登录自助服务，精准下线本机对应的单一会话，不批量下线其他设备。后台发现会话恢复时，同一次注销最多执行一次精准兜底。兜底后同时核对自助服务设备列表和认证状态，无法确认时不报成功。出现验证码或无法唯一核对设备时停止自动处理，操作结束后退出自助网页会话。

新的手动登录、注销、切网或退出会使旧的后台复查失效。后台结果返回后，须重新核对注销意图与完整网络上下文；旧结果不能覆盖新操作的状态或继续下线新会话。

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
