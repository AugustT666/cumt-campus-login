"""Credential-free TCP checks for diagnosing blocked campus connections.

The alternate binding modes only compare TCP reachability. They must never be
used as authentication transports or send application data.
"""
from __future__ import annotations

import os
import socket
import time

import campus_core as core


MODES = ('bound_interface', 'bound_source', 'system_route')


def present_summary(checks):
    """Describe the observed paths without guessing which filter caused them."""
    by_mode = {item['mode']: item for item in checks}
    strict = by_mode.get('bound_interface', {})
    source = by_mode.get('bound_source', {})
    system = by_mode.get('system_route', {})
    if strict.get('success'):
        detail = '校园 WiFi 的 TCP 连接已通，请刷新登录状态。'
    elif source.get('success'):
        detail = ('仅绑定源地址时可连接，绑定校园 WiFi 接口时失败；'
                  + core.NETWORK_ACCESS_HINT)
    elif system.get('success'):
        detail = ('系统默认路径可连接，但校园 WiFi 的绑定连接失败；'
                  + core.NETWORK_ACCESS_HINT)
    elif any(item.get('network_error', {}).get('code') == 'permission_denied'
             for item in checks):
        detail = '连接自检仍遇到系统权限拒绝。' + core.NETWORK_ACCESS_HINT
    else:
        detail = '三种路径均未连接到认证服务器，请检查校园 WiFi 后再刷新状态。'
    return detail + '自检未提交账号密码，也未更改网络。'


def run_check(wifi, reader=None):
    """Compare three fixed TCP paths, closing every socket without any send.

    No settings or credential store is accessed. A changed WiFi/IP stops the
    comparison before another path is tried. Each socket has at most two
    seconds, and the three connections share a six-second deadline.
    """
    reader = core.read_wifi if reader is None else reader
    started = time.monotonic()
    deadline = started + 6.0
    target = (core.KNOWN_HOST, 80)
    report = {'target': {'host': target[0], 'port': target[1]}, 'checks': [],
              'authentication_requests': 0, 'network_changes': False}
    allow_tec = wifi.ssid.casefold() == core.TEC.casefold()

    def finish(summary):
        report['summary'] = summary
        report['elapsed_ms'] = round((time.monotonic() - started) * 1000)
        return report

    def same_network():
        try:
            core.guard(wifi, reader(), allow_tec=allow_tec)
            return True
        except (OSError, RuntimeError):
            report['aborted'] = 'network_context_changed_or_unavailable'
            return False

    if not wifi.ready:
        report['aborted'] = 'wifi_not_ready'
        return finish('请先连接 CUMT_Stu 或 CUMT_Tec，等待无线地址就绪后再检查连接。')

    for mode in MODES:
        if not same_network():
            return finish('WiFi 或 IP 已改变或无法读取，连接自检已停止；未提交账号密码。')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            report['aborted'] = 'time_budget_exhausted'
            return finish('连接自检已达到等待上限；未提交账号密码，也未更改网络。')
        item = {'mode': mode, 'success': False, 'phase': 'socket'}
        attempt_started = time.monotonic()
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(min(2.0, remaining))
            if mode == 'bound_interface' and os.name == 'nt':
                item['phase'] = 'setsockopt'
                sock.setsockopt(socket.IPPROTO_IP, 31, socket.htonl(wifi.index))
            if mode != 'system_route':
                item['phase'] = 'bind'
                sock.bind((wifi.ip, 0))
            item['phase'] = 'connect'
            sock.connect(target)
            item['local_ip'] = sock.getsockname()[0]
            item['success'] = True
        except OSError as exc:
            # Keep the phase of this check rather than a previous transport's
            # metadata; the shared classifier supplies numeric codes/message.
            details = core.network_error_details(exc)
            details['phase'] = item['phase']
            item['network_error'] = details
            for field in ('error_type', 'winerror', 'errno'):
                if field in details:
                    item[field] = details[field]
        finally:
            if sock is not None:
                sock.close()
            item['elapsed_ms'] = round((time.monotonic() - attempt_started) * 1000)
        report['checks'].append(item)
        if not same_network():
            return finish('WiFi 或 IP 已改变或无法读取，连接自检已停止；未提交账号密码。')
    return finish(present_summary(report['checks']))
