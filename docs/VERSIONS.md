# 版本与开发方向

公开仓库保留两个版本：

| 标记 | 用途 |
| --- | --- |
| `v1.6.4` | Playwright 历史基线，适合研究浏览器兼容路线并继续开发 |
| `v1.8.1` / `main` | 当前 Windows 版，使用系统 WebView2；学生网与教师网统一通过自助服务精准注销，登录、注销按接口回执结束 |
| `feature/macos-port` | 面向未来的 Mac 适配方向，技术方案尚未确定，暂不继续实现 |

两份源码在首次公开整理时移除了私人目录信息、内部过程记录及生成结果，公开提交哈希与原私有历史不同。当前 Windows 版在此基础上继续更新。

如需基于旧版继续开发，可执行 `git switch -c feature/your-feature v1.6.4`；日常改进以 `main` 为起点。历史基线没有包含新版全部修复，应先核对功能差异。Mac 和 Linux 版计划中。

合并完成的临时分支应删除，固定版本由标签保留。源码查看入口为 [提交历史](https://github.com/AugustT666/cumt-campus-login/commits/main/)。
