"""Campus login: read-only networking, source-interface probes and DPAPI storage."""
from __future__ import annotations
import base64
from contextlib import contextmanager
from contextvars import ContextVar
import ctypes as C
from ctypes import wintypes as W
from dataclasses import dataclass, asdict
import datetime as dt
import errno
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import threading
import time
import traceback
import uuid
import queue
import zlib
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode, urljoin

VERSION = '1.7.9'
EXPERIMENTAL_BUILD = False
STU = 'CUMT_Stu'
TEC = 'CUMT_Tec'
KNOWN_HOST = '10.2.5.251'
NETWORK_ACCESS_HINT = ('可检查防火墙或安全软件的出站设置；'
                       '若正在使用 Tailscale Exit Node、其他 VPN 或代理，'
                       '也可尝试暂时停用相关功能后重试；未使用则跳过此项。')
CREATE_NO_WINDOW = 0x08000000
MAX_HTTP_WIRE_BYTES = 4 * 1024 * 1024
MAX_HTTP_DECODED_BYTES = 8 * 1024 * 1024
MAX_CONTENT_ENCODING_LAYERS = 4
MAX_GZIP_MEMBERS = 32


def usable_ipv4(address):
    try:
        ip = ipaddress.IPv4Address(address)
        return not (ip.is_unspecified or ip.is_loopback or ip.is_link_local
                    or ip.is_multicast or ip.is_reserved or int(ip) < 0x01000000)
    except (ValueError, TypeError):
        return False


def preferred_ipv4(addresses):
    candidates = [address for address in addresses if usable_ipv4(address)]
    return next((address for address in candidates if campus_host(address)),
                next(iter(candidates), ''))

_trace_sink = ContextVar('campus_trace_sink', default=None)

@contextmanager
def trace_scope(sink):
    token = _trace_sink.set(sink)
    try:
        yield
    finally:
        _trace_sink.reset(token)

def trace(event, level='DEBUG', **fields):
    sink = _trace_sink.get()
    if sink is not None:
        try:
            sink(event, level=level, **fields)
        except Exception:
            pass  # Recording must not turn a network result into a new failure.

@dataclass(frozen=True)
class Wifi:
    ssid: str = ''
    guid: str = ''
    index: int = 0
    ip: str = ''
    mac: str = ''
    gateway: str = ''
    dns: tuple = ()
    virtual_adapters: tuple = ()

    @property
    def campus(self):
        return self.ssid.casefold() in (STU.casefold(), TEC.casefold())

    @property
    def student(self):
        return self.ssid.casefold() == STU.casefold()

    @property
    def ready(self):
        return self.campus and self.index > 0 and usable_ipv4(self.ip)

    @property
    def key(self):
        return (self.ssid, self.guid, self.index, self.ip)

class GUID(C.Structure):
    _fields_ = [('a', W.DWORD), ('b', W.WORD), ('c', W.WORD), ('d', C.c_ubyte * 8)]
    def text(self):
        return f'{self.a:08x}-{self.b:04x}-{self.c:04x}-{bytes(self.d[:2]).hex()}-{bytes(self.d[2:]).hex()}'

class SSID(C.Structure):
    _fields_ = [('length', W.ULONG), ('value', C.c_ubyte * 32)]

class ASSOC(C.Structure):
    _fields_ = [('ssid', SSID), ('bss', W.DWORD), ('bssid', C.c_ubyte * 6),
                ('phy', W.DWORD), ('phy_index', W.ULONG), ('signal', W.ULONG),
                ('rx', W.ULONG), ('tx', W.ULONG)]

class SECURITY(C.Structure):
    _fields_ = [('enabled', W.BOOL), ('onex', W.BOOL), ('auth', W.DWORD), ('cipher', W.DWORD)]

class CONNECTION(C.Structure):
    _fields_ = [('state', W.DWORD), ('mode', W.DWORD), ('profile', W.WCHAR * 256),
                ('assoc', ASSOC), ('security', SECURITY)]

class INTERFACE(C.Structure):
    _fields_ = [('guid', GUID), ('description', W.WCHAR * 256), ('state', W.DWORD)]

def native_wifi():
    if os.name != 'nt':
        return []
    wlan = C.WinDLL('wlanapi')
    handle, version = W.HANDLE(), W.DWORD()
    wlan.WlanOpenHandle.argtypes = [W.DWORD, C.c_void_p, C.POINTER(W.DWORD), C.POINTER(W.HANDLE)]
    wlan.WlanEnumInterfaces.argtypes = [W.HANDLE, C.c_void_p, C.POINTER(C.c_void_p)]
    wlan.WlanQueryInterface.argtypes = [W.HANDLE, C.POINTER(GUID), W.DWORD, C.c_void_p,
                                     C.POINTER(W.DWORD), C.POINTER(C.c_void_p), C.POINTER(W.DWORD)]
    wlan.WlanFreeMemory.argtypes = [C.c_void_p]
    wlan.WlanCloseHandle.argtypes = [W.HANDLE, C.c_void_p]
    if wlan.WlanOpenHandle(2, None, C.byref(version), C.byref(handle)):
        raise RuntimeError('暂时无法读取 WLAN 状态。')
    ptr = C.c_void_p()
    out = []
    try:
        if wlan.WlanEnumInterfaces(handle, None, C.byref(ptr)):
            raise RuntimeError('暂时无法枚举 WLAN 接口。')
        count = C.cast(ptr, C.POINTER(W.DWORD))[0]
        entries = C.cast(ptr.value + 8, C.POINTER(INTERFACE))
        for i in range(count):
            item = entries[i]
            if item.state != 1:
                continue
            data, size, kind = C.c_void_p(), W.DWORD(), W.DWORD()
            if wlan.WlanQueryInterface(handle, C.byref(item.guid), 7, None, C.byref(size), C.byref(data), C.byref(kind)) == 0:
                try:
                    conn = C.cast(data, C.POINTER(CONNECTION)).contents
                    raw = bytes(conn.assoc.ssid.value[:conn.assoc.ssid.length])
                    out.append((raw.decode('utf-8', 'replace'), item.guid.text()))
                finally:
                    wlan.WlanFreeMemory(data)
            else:
                raise RuntimeError('暂时无法查询当前 WLAN 连接。')
    finally:
        if ptr.value:
            wlan.WlanFreeMemory(ptr)
        wlan.WlanCloseHandle(handle, None)
    return out

class WLAN_NOTICE(C.Structure):
    _fields_=[('source',W.DWORD),('code',W.DWORD),('guid',GUID),('size',W.DWORD),('data',C.c_void_p)]

class WifiNotifications:
    """Passive ACM notifications; callback only copies events into a queue."""
    def __init__(self):
        self.events=queue.SimpleQueue()
        self.wake=threading.Event()
        self.handle=W.HANDLE()
        self.wlan=C.WinDLL('wlanapi')
        self.wlan.WlanOpenHandle.argtypes=[W.DWORD,C.c_void_p,C.POINTER(W.DWORD),C.POINTER(W.HANDLE)]
        self.wlan.WlanCloseHandle.argtypes=[W.HANDLE,C.c_void_p]
        self.wlan.WlanRegisterNotification.argtypes=[W.HANDLE,W.DWORD,W.BOOL,C.c_void_p,C.c_void_p,C.c_void_p,C.c_void_p]
        callback_type=C.WINFUNCTYPE(None,C.POINTER(WLAN_NOTICE),C.c_void_p)
        def callback(pointer,context):
            notice=pointer.contents
            # Public ACM codes: complete=10, disconnecting=20, disconnected=21.
            if notice.source & 8 and notice.code in (10,20,21,0x100a,0x1014,0x1015):
                self.events.put((notice.code & 0xfff,notice.guid.text()))
                self.wake.set()
        self.callback=callback_type(callback)
        version=W.DWORD()
        if self.wlan.WlanOpenHandle(2,None,C.byref(version),C.byref(self.handle)):
            raise RuntimeError('无法启动无线连接监听。')
        if self.wlan.WlanRegisterNotification(self.handle,8,False,C.cast(self.callback,C.c_void_p),None,None,None):
            self.wlan.WlanCloseHandle(self.handle,None)
            self.handle=W.HANDLE()
            raise RuntimeError('无法注册无线连接监听。')
    def drain(self):
        events=[]
        while True:
            try: events.append(self.events.get_nowait())
            except queue.Empty: return events
    def close(self):
        if self.handle:
            self.wlan.WlanRegisterNotification(self.handle,0,False,None,None,None,None)
            self.wlan.WlanCloseHandle(self.handle,None)
            self.handle=W.HANDLE()


def powershell_json(script):
    command = "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); " + script
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', command],
                            capture_output=True, timeout=18, creationflags=CREATE_NO_WINDOW)
    if result.returncode:
        raise RuntimeError('无法只读查询网卡信息。')
    return json.loads(result.stdout.decode('utf-8-sig').strip() or 'null')

class SOCKET_ADDRESS(C.Structure):
    _fields_ = [('ptr', C.c_void_p), ('length', C.c_int)]

class ADDRESS_NODE(C.Structure):
    pass
ADDRESS_NODE._fields_ = [('alignment', C.c_ulonglong), ('next', C.POINTER(ADDRESS_NODE)), ('address', SOCKET_ADDRESS)]

class ADAPTER(C.Structure):
    pass
ADAPTER._fields_ = [('length', W.ULONG), ('index', W.DWORD), ('next', C.POINTER(ADAPTER)),
    ('name', C.c_char_p), ('unicast', C.POINTER(ADDRESS_NODE)), ('anycast', C.c_void_p),
    ('multicast', C.c_void_p), ('dns', C.POINTER(ADDRESS_NODE)), ('suffix', W.LPWSTR),
    ('description', W.LPWSTR), ('friendly', W.LPWSTR), ('mac', C.c_ubyte * 8),
    ('mac_length', W.DWORD), ('flags', W.DWORD), ('mtu', W.DWORD), ('iftype', W.DWORD),
    ('status', W.DWORD), ('ipv6_index', W.DWORD), ('zones', W.DWORD * 16),
    ('prefix', C.c_void_p), ('tx_speed', C.c_ulonglong), ('rx_speed', C.c_ulonglong),
    ('wins', C.c_void_p), ('gateway', C.POINTER(ADDRESS_NODE)),
    ('ipv4_metric', W.ULONG), ('ipv6_metric', W.ULONG)]

def addresses(node):
    result, visited = [], set()
    while node and len(visited) < 100:
        at = C.addressof(node.contents)
        if at in visited:
            break
        visited.add(at)
        value = node.contents
        if value.address.ptr and value.address.length >= 8:
            family = C.cast(value.address.ptr, C.POINTER(C.c_ushort))[0]
            if family == socket.AF_INET:
                result.append(socket.inet_ntoa(C.string_at(value.address.ptr + 4, 4)))
        node = value.next
    return result

def adapter_snapshot():
    iphlp = C.WinDLL('iphlpapi')
    fn = iphlp.GetAdaptersAddresses
    fn.argtypes = [W.ULONG, W.ULONG, C.c_void_p, C.POINTER(ADAPTER), C.POINTER(W.ULONG)]
    size = W.ULONG(65536)
    for _ in range(3):
        buffer = C.create_string_buffer(size.value)
        node = C.cast(buffer, C.POINTER(ADAPTER))
        code = fn(socket.AF_INET, 0x86, None, node, C.byref(size))
        if code == 111:
            continue
        if code:
            raise RuntimeError('无法只读读取物理 WiFi 的 IP 信息。')
        result = []
        while node:
            value = node.contents
            result.append({'guid': (value.name or b'').decode('ascii','replace').strip('{}').casefold(),
                           'index': value.index, 'ip': addresses(value.unicast),
                           'mac': '-'.join(f'{b:02X}' for b in value.mac[:value.mac_length]),
                           'gateway': addresses(value.gateway), 'dns': addresses(value.dns),
                           'name': value.friendly or '', 'up': value.status == 1})
            node = value.next
        return result
    raise RuntimeError('网卡地址读取缓冲区不足。')

def preferred_wifi(candidates):
    # Preserve an address-pending campus interface for the DHCP waiting state,
    # but use a ready campus interface before one that cannot yet send traffic.
    return min(candidates, key=lambda wifi: (
        0 if wifi.ready else 1 if wifi.campus else 2,
        0 if wifi.student else 1), default=Wifi())


def read_wifi():
    entries = native_wifi()
    if not entries:
        return Wifi()
    items = adapter_snapshot()
    virtual = tuple(x['name'] for x in items if x['up'] and re.search(r'Tailscale|ZeroTier|tap|VPN|Clash',x['name'],re.I))
    candidates = []
    for ssid, guid in entries:
        adapter = next((x for x in items if x['guid'] == guid.casefold() and x['up']), None)
        if not adapter:
            candidates.append(Wifi(ssid=ssid, guid=guid))
            continue
        candidates.append(Wifi(ssid, guid, adapter['index'], preferred_ipv4(adapter['ip']),
                               adapter['mac'], next(iter(adapter['gateway']), ''),
                               tuple(adapter['dns']), virtual))
    return preferred_wifi(candidates)

def read_wifi_powershell_fallback():
    entries = native_wifi()
    if not entries:
        return Wifi()
    # Select by WLAN GUID, never by first IP (VPN/virtual adapters may precede WiFi).
    candidates = []
    for ssid, guid in entries:
        script = "$a=Get-NetAdapter | Where-Object {$_.InterfaceGuid.ToString().Trim('{}') -eq '" + guid + "'}; "
        script += "if ($a) {$c=Get-NetIPConfiguration -InterfaceIndex $a.ifIndex; "
        script += "[pscustomobject]@{index=$a.ifIndex; ip=@($c.IPv4Address.IPAddress); mac=$a.MacAddress; gateway=@($c.IPv4DefaultGateway.NextHop); dns=@(($c.DNSServer | Where-Object {$_.AddressFamily -eq 2}).ServerAddresses); virtual=@(Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.Name -match 'Tailscale|ZeroTier|tap|VPN|Clash'} | ForEach-Object {$_.Name})} | ConvertTo-Json -Compress -Depth 4}"
        data = powershell_json(script)
        if not data:
            candidates.append(Wifi(ssid=ssid, guid=guid))
            continue
        candidates.append(Wifi(ssid, guid, int(data['index']), preferred_ipv4(data.get('ip') or []),
                               data.get('mac') or '', next(iter(data.get('gateway') or []), ''),
                               tuple(data.get('dns') or []), tuple(data.get('virtual') or [])))
    return preferred_wifi(candidates)

def guard(expected, current, allow_tec=False):
    if not current.ready or current.key != expected.key:
        trace('network.guard_rejected',level='WARNING',expected=asdict(expected),current=asdict(current))
        raise RuntimeError('WiFi 或 IP 已改变，已停止本次操作；不会切换网络。')
    if not current.student and not (allow_tec and current.ssid.casefold() == TEC.casefold()):
        raise RuntimeError('自动认证仅允许 CUMT_Stu；热点及其他网络禁止发送认证请求。')

def quiet_hours(now=None):
    now = now or dt.datetime.now()
    if now.hour < 7:
        previous = now - dt.timedelta(days=1)
        return previous.weekday() in (6, 0, 1, 2, 3)
    return now.weekday() in (6, 0, 1, 2, 3) and (now.hour, now.minute) >= (23, 30)

def campus_host(host):
    try:
        return ipaddress.IPv4Address(host) in ipaddress.IPv4Network('10.0.0.0/8')
    except ValueError:
        return False

def portal_origin(url):
    parts = urlsplit(url)
    if parts.scheme not in ('http', 'https') or not campus_host(parts.hostname or '') or parts.username or parts.password:
        raise ValueError('认证地址必须是校内 10.x.x.x 的 HTTP/HTTPS 地址，不接受外网地址。')
    if parts.port not in (None, 80, 443, 801, 802):
        raise ValueError('认证地址端口未获允许。')
    return urlunsplit((parts.scheme, parts.netloc, '', '', ''))

DYNAMIC_KEYS = {'wlanuserip', 'wlan_user_ip', 'userip', 'clientip', 'ip', 'mac', 'wlanusermac', 'wlan_user_mac'}
SENSITIVE_KEYS = {'user_account', 'user_password', 'password', 'upass', 'ddddd', 'dddddd', 'username', 'account', 'token', 'cookie'}

def fresh_url(url, wifi):
    p = urlsplit(url)
    portal_origin(url)
    pairs = []
    found_ip, found_mac = False, False
    for key, value in parse_qsl(p.query, keep_blank_values=True):
        low = key.casefold()
        if low in SENSITIVE_KEYS:
            continue
        if low in DYNAMIC_KEYS:
            if 'mac' in low:
                # A live NAS may use case-sensitive device keys. Keep its exact
                # spelling only when it still identifies this physical adapter.
                normalized=re.sub(r'[-:]','',value).casefold()
                current=re.sub(r'[-:]','',wifi.mac).casefold()
                if not re.fullmatch(r'[0-9a-f]{12}',normalized) or normalized!=current:
                    value=wifi.mac
                found_mac=True
            else:
                value, found_ip = wifi.ip, True
        pairs.append((key, value))
    if not found_ip:
        pairs.append(('wlanuserip', wifi.ip))
    if not found_mac:
        pairs.append(('mac', wifi.mac))
    return urlunsplit((p.scheme, p.netloc, p.path or '/a79.htm', urlencode(pairs), ''))

def safe_summary(url):
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path, '', ''))


def network_error_details(exc):
    """Describe a transport failure without guessing which local rule caused it."""
    chain, seen = [], set()
    while isinstance(exc, BaseException) and id(exc) not in seen and len(chain) < 16:
        seen.add(id(exc))
        chain.append(exc)
        saved = getattr(exc, 'network_error', None)
        if isinstance(saved, dict) and saved.get('code') in (
                'permission_denied', 'dns_failed', 'timeout', 'connection_failed'):
            return dict(saved)
        exc = exc.__cause__ or (None if exc.__suppress_context__ else exc.__context__)
    transport = next((error for error in reversed(chain) if isinstance(error, OSError)), None)
    if transport is None:
        return {}
    phase = next((getattr(error, '_campus_phase', '') for error in chain
                  if getattr(error, '_campus_phase', '')), '')
    details = {'error_type': type(transport).__name__, 'phase': phase}
    for name in ('winerror', 'errno'):
        value = getattr(transport, name, None)
        if type(value) is int:
            details[name] = value
    winerror, error_number = details.get('winerror'), details.get('errno')
    # SSL/gaierror errno values use their own namespaces (SSL_ERROR_SSL is 1,
    # also POSIX EPERM); do not mistake those numbers for socket permission.
    if isinstance(transport, socket.gaierror):
        code = 'dns_failed'
    elif isinstance(transport, ssl.SSLError):
        code = 'connection_failed'
    elif winerror == 10013 or error_number in (errno.EACCES, errno.EPERM) or isinstance(transport, PermissionError):
        code = 'permission_denied'
    elif isinstance(transport, TimeoutError) or winerror == 10060 or error_number == errno.ETIMEDOUT:
        code = 'timeout'
    else:
        code = 'connection_failed'
    number = (f'（WinError {winerror}）' if winerror is not None else
              f'（errno {error_number}）' if error_number is not None else '')
    if code == 'permission_denied':
        message = f'系统拒绝网络连接{number}。' + NETWORK_ACCESS_HINT
    elif code == 'dns_failed':
        message = (f'无法解析认证地址的域名{number}。请检查当前无线网卡的DNS和网络状态；'
                   '可使用学校提供的认证服务器IP地址。')
    elif code == 'timeout':
        message = f'连接认证服务器超时{number}。请检查校园网连接，稍后刷新状态。'
    elif phase in ('setsockopt', 'bind'):
        message = (f'无法绑定当前无线网卡{number}。请检查校园Wi-Fi是否仍已连接、IP地址是否变化，'
                   '再刷新状态。')
    elif phase == 'tls':
        message = (f'认证服务器的安全连接建立失败{number}。请检查系统时间与认证地址，'
                   '并查看诊断日志中的原始错误。')
    else:
        message = (f'无法连接认证服务器{number}。请检查校园网连接与认证地址，'
                   '并查看诊断日志中的原始错误。')
    details.update(code=code, message=message)
    return details


class PortalNetworkError(RuntimeError):
    """Discovery failed because transport failed, rather than an unknown page."""
    def __init__(self, error):
        self.network_error = network_error_details(error)
        super().__init__(self.network_error.get('message') or '无法连接校园网认证服务器。')


class BoundHTTP(http.client.HTTPConnection):
    def __init__(self, host, port, wifi, secure=False):
        super().__init__(host, port=port, timeout=5, source_address=(wifi.ip, 0))
        self.wifi, self.secure = wifi, secure
    def connect(self):
        # IPv4 probes always originate from the current physical WiFi, no proxy env.
        def record_failure(exc, phase, destination):
            exc._campus_phase = phase
            trace('http.connect_error',level='ERROR',_exception=exc,source_ip=self.wifi.ip,
                  interface_index=self.wifi.index,destination=destination,
                  error=str(exc),traceback=traceback.format_exc(),**network_error_details(exc))
        try:
            addresses = socket.getaddrinfo(self.host, self.port, socket.AF_INET, socket.SOCK_STREAM)
        except OSError as exc:
            record_failure(exc, 'resolve', (self.host, self.port))
            raise
        last = None
        for _, _, _, _, address in addresses:
            sock, phase = None, 'socket'
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                if os.name == 'nt':
                    phase = 'setsockopt'
                    sock.setsockopt(socket.IPPROTO_IP, 31, socket.htonl(self.wifi.index))
                phase = 'bind'
                sock.bind((self.wifi.ip, 0))
                phase = 'connect'
                sock.connect(address)
                trace('http.connected',source_ip=self.wifi.ip,interface_index=self.wifi.index,
                      destination=address,tls=self.secure)
                if self.secure:
                    phase = 'tls'
                    sock = ssl.create_default_context().wrap_socket(sock, server_hostname=self.host)
                self.sock = sock
                return
            except OSError as exc:
                record_failure(exc, phase, address)
                last = exc
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass  # Preserve the original connection failure.
                # A local permission refusal is not fixed by cycling DNS answers.
                if network_error_details(exc).get('code') == 'permission_denied':
                    raise
        if last is not None:
            raise last
        error = OSError('认证地址没有可用的IPv4地址。')
        record_failure(error, 'resolve', (self.host, self.port))
        raise error

def _inflate_limited(body, wbits, multiple_members=False):
    chunks, total, members = [], 0, 0
    while True:
        members += 1
        if members > MAX_GZIP_MEMBERS:
            raise ValueError('认证页面压缩成员过多。')
        decoder = zlib.decompressobj(wbits)
        # max_length caps allocation inside zlib, before materializing output.
        chunk = decoder.decompress(body, MAX_HTTP_DECODED_BYTES - total + 1)
        total += len(chunk)
        if total > MAX_HTTP_DECODED_BYTES:
            raise ValueError('认证页面资源过大。')
        if not decoder.eof:
            raise ValueError('认证页面压缩数据不完整。')
        chunks.append(chunk)
        trailing = decoder.unused_data
        if multiple_members:
            # gzip permits concatenated members and trailing zero padding.
            body = trailing.lstrip(b'\0')
            if body:
                continue
        elif trailing:
            raise ValueError('认证页面压缩数据包含多余内容。')
        return b''.join(chunks)


def decode_http_body(body, headers):
    """Playwright fulfills decoded bytes; Dr.COM may gzip even without negotiation."""
    headers = dict(headers)
    coding = next((v for k, v in headers.items() if k.lower() == 'content-encoding'), '')
    if not isinstance(coding, str) or len(coding) > 128:
        raise ValueError('认证页面压缩声明无效。')
    encodings = [encoding.strip() for encoding in coding.lower().split(',')]
    if len(encodings) > MAX_CONTENT_ENCODING_LAYERS:
        raise ValueError('认证页面压缩层数过多。')
    try:
        for encoding in reversed(encodings):
            if encoding == 'gzip':
                body = _inflate_limited(body, zlib.MAX_WBITS | 16, multiple_members=True)
            elif encoding == 'deflate':
                try:
                    body = _inflate_limited(body, zlib.MAX_WBITS)
                except zlib.error:
                    body = _inflate_limited(body, -zlib.MAX_WBITS)
            elif encoding not in ('', 'identity'):
                raise ValueError('认证页面使用了不支持的压缩格式。')
            if len(body) > MAX_HTTP_DECODED_BYTES:
                raise ValueError('认证页面资源过大。')
    except (zlib.error, EOFError) as exc:
        raise ValueError('认证页面压缩数据损坏。') from exc
    headers = {k: v for k, v in headers.items() if k.lower() not in
               ('content-encoding', 'content-length', 'transfer-encoding', 'connection')}
    return body, headers


def decode_text(body, headers):
    content_type = next((v for k, v in dict(headers).items() if k.lower() == 'content-type'), '')
    charset = re.search(r'charset\s*=\s*["\x27]?([\w-]+)', content_type, re.I)
    if not charset:
        charset = re.search(rb'<meta\b[^>]*charset\s*=\s*["\x27]?([\w-]+)', body[:4096], re.I)
    encoding = charset.group(1) if charset else 'utf-8'
    if isinstance(encoding, bytes):
        encoding = encoding.decode('ascii')
    if encoding.lower() in ('gb2312', 'gbk'):
        encoding = 'gb18030'
    try:
        return body.decode(encoding)
    except (UnicodeError, LookupError):
        return body.decode('gb18030' if not charset else 'utf-8', 'replace')


def fetch(url, wifi, reader=read_wifi, allow_tec=False):
    started = time.perf_counter()
    guard(wifi, reader(), allow_tec)
    p = urlsplit(url)
    if p.scheme not in ('http', 'https') or p.username or p.password:
        raise ValueError('不支持的 URL')
    connection = BoundHTTP(p.hostname, p.port or (443 if p.scheme == 'https' else 80), wifi, p.scheme == 'https')
    trace('http.request',method='GET',url=url,source_ip=wifi.ip,interface_index=wifi.index)
    try:
        connection.request('GET', urlunsplit(('', '', p.path or '/', p.query, '')),
                           headers={'User-Agent': 'CampusLogin/1.0', 'Cache-Control': 'no-cache', 'Connection': 'close'})
        response = connection.getresponse()
        wire_body = response.read(MAX_HTTP_WIRE_BYTES + 1)
        if len(wire_body) > MAX_HTTP_WIRE_BYTES:
            raise ValueError('认证页面资源过大。')
        raw, headers = decode_http_body(wire_body, response.getheaders())
        text = decode_text(raw, headers)
        trace('http.response',url=url,status=response.status,
              location=response.getheader('Location',''),decoded_bytes=len(raw),
              content_type=response.getheader('Content-Type',''),
              content_encoding=response.getheader('Content-Encoding',''),
              body_sha256=hashlib.sha256(raw).hexdigest(),
              elapsed_ms=round((time.perf_counter()-started)*1000))
        return response.status, response.getheader('Location', ''), text
    except Exception as exc:
        trace('http.error',level='ERROR',_exception=exc,url=url,error_type=type(exc).__name__,
              error=str(exc),traceback=traceback.format_exc(),
              elapsed_ms=round((time.perf_counter()-started)*1000))
        raise
    finally:
        connection.close()

LOGIN_MARKERS = ('dddddd', 'upass', 'user_account', 'drcom', 'eportal', '校园网认证', '运营商')

def redirected_url(url, location, text):
    if location:
        return urljoin(url, location)
    match = re.search(r'(?:location(?:\.href)?\s*=|location\.replace\s*\()\s*[\"\x27]([^\"\x27]+)', text, re.I)
    if not match:
        match = re.search(r'http-equiv=[\"\x27]?refresh[^>]*content=[\"\x27][^\"\x27]*?url=([^\"\x27>]+)', text, re.I)
    return urljoin(url, match.group(1)) if match else ''

def discover(wifi, hint='', reader=read_wifi, getter=fetch, allow_tec=False):
    guard(wifi, reader(), allow_tec)
    seeds = ['http://9.9.9.9/', 'http://1.1.1.1/']
    if hint.strip():
        portal_origin(hint.strip())
        seeds.append(fresh_url(hint.strip(), wifi))
    seeds.append(f'http://{KNOWN_HOST}/a79.htm?wlanuserip={wifi.ip}&mac={wifi.mac}')
    seeds.append('http://go.cumt.edu.cn/')
    failure, failure_priority, campus_page_received = None, -1, False
    for seed in seeds:
        trace('portal.seed',url=seed)
        url, visited = seed, set()
        for _ in range(5):
            if url in visited:
                break
            visited.add(url)
            try:
                status, location, text = getter(url, wifi, reader=reader, allow_tec=allow_tec)
                if campus_host(urlsplit(url).hostname or ''):
                    campus_page_received = True
                nxt = redirected_url(url, location, text)
                if nxt:
                    trace('portal.redirect',source=url,destination=nxt,status=status)
                    parts = urlsplit(nxt)
                    if campus_host(parts.hostname or ''):
                        portal_origin(nxt)
                        url = fresh_url(nxt, wifi)
                        continue
                    break  # no automatic external redirect chains
                if status == 200 and campus_host(urlsplit(url).hostname or '') and any(marker in text.lower() for marker in LOGIN_MARKERS):
                    trace('portal.discovered',url=url,status=status)
                    return fresh_url(url, wifi), text
                trace('portal.candidate_rejected',url=url,status=status,reason='no_recognized_login_page')
                break
            except (OSError, ValueError, http.client.HTTPException) as exc:
                trace('portal.discovery_error',level='WARNING',_exception=exc,url=url,
                      error_type=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
                details = network_error_details(exc)
                if details:
                    is_campus = campus_host(urlsplit(url).hostname or '')
                    if is_campus and details['code'] == 'permission_denied':
                        raise PortalNetworkError(exc) from exc
                    # The actual campus endpoint is more useful than public probes;
                    # retain a DNS cause only if no campus transport cause exists.
                    priority = 3 if is_campus else 2 if details['code'] == 'dns_failed' else 1
                    if priority > failure_priority:
                        failure, failure_priority = exc, priority
                break
    if failure is not None and (failure_priority == 3 or not campus_page_received):
        raise PortalNetworkError(failure) from failure
    raise RuntimeError('未找到真实认证页面。请从浏览器复制当前认证网址到本程序，再点发现页面；当前不会重试登录。')

def internet_check(wifi, reader=read_wifi, getter=fetch, allow_tec=False):
    checks = [('http://www.msftconnecttest.com/connecttest.txt', 200, 'Microsoft Connect Test'),
              ('http://connectivitycheck.gstatic.com/generate_204', 204, '')]
    results = []
    for url, expected_code, expected_text in checks:
        try:
            code, location, text = getter(url, wifi, reader=reader, allow_tec=allow_tec)
            ok = code == expected_code and not location and text.strip() == expected_text
            results.append({'target': urlsplit(url).hostname, 'ok': ok, 'status': code})
        except (OSError, RuntimeError, http.client.HTTPException) as exc:
            trace('internet.probe_error',level='WARNING',_exception=exc,url=url,error_type=type(exc).__name__,
                  error=str(exc),traceback=traceback.format_exc())
            results.append({'target': urlsplit(url).hostname, 'ok': False, 'status': 'unreachable'})
    return {'online': any(x['ok'] for x in results), 'checks': results,
            'note': '严格匹配外网探测响应；失败不等于账号密码错误，也不据此重复认证。'}

class BLOB(C.Structure):
    _fields_ = [('size', W.DWORD), ('data', C.POINTER(C.c_ubyte))]

def protect(raw, decrypt=False):
    if os.name != 'nt':
        raise RuntimeError('凭据保存只支持 Windows 当前用户 DPAPI。')
    crypt = C.WinDLL('crypt32', use_last_error=True)
    kernel = C.WinDLL('kernel32', use_last_error=True)
    kernel.LocalFree.argtypes = [C.c_void_p]
    buffer = (C.c_ubyte * len(raw)).from_buffer_copy(raw)
    incoming, outgoing = BLOB(len(raw), buffer), BLOB()
    if decrypt:
        fn = crypt.CryptUnprotectData
        fn.argtypes = [C.POINTER(BLOB), C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p, W.DWORD, C.POINTER(BLOB)]
        ok = fn(C.byref(incoming), None, None, None, None, 1, C.byref(outgoing))
    else:
        fn = crypt.CryptProtectData
        fn.argtypes = [C.POINTER(BLOB), W.LPCWSTR, C.c_void_p, C.c_void_p, C.c_void_p, W.DWORD, C.POINTER(BLOB)]
        ok = fn(C.byref(incoming), 'CampusLogin credentials', None, None, None, 1, C.byref(outgoing))
    if not ok:
        raise RuntimeError('Windows 凭据保护失败；未保存明文密码。')
    try:
        return C.string_at(outgoing.data, outgoing.size)
    finally:
        kernel.LocalFree(outgoing.data)

def data_root():
    directory = 'CumtCampusLoginExperimental' if EXPERIMENTAL_BUILD else 'CumtCampusLogin'
    root = Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / directory
    root.mkdir(parents=True, exist_ok=True)
    return root

class Store:
    def __init__(self, root=None):
        self.root = root or data_root()
        self.path = self.root / 'settings.json'
        self.credentials = self.root / 'credentials.dpapi'
        self.settings_warning = ''
        self.settings_backup = ''
        self._damaged_settings = None
        self._settings_read_failed = False

    @staticmethod
    def _settings(data):
        defaults = {'operator': '', 'auto_submit': False, 'auto_enabled': False,
                    'stu_autostart': False, 'quiet_hours': True,
                    'portal_hint': '', 'trusted_hosts': [KNOWN_HOST]}
        if not isinstance(data, dict):
            return defaults, True
        invalid = False
        for key in ('auto_submit', 'auto_enabled', 'stu_autostart', 'quiet_hours'):
            if key in data:
                if type(data[key]) is bool:
                    defaults[key] = data[key]
                else:
                    invalid = True
        if 'operator' in data:
            if isinstance(data['operator'], str) and data['operator'] in ('', 'telecom', 'unicom', 'cmcc', 'campus'):
                defaults['operator'] = data['operator']
            else:
                invalid = True
        if 'portal_hint' in data:
            hint = data['portal_hint']
            try:
                if not isinstance(hint, str) or len(hint) > 8192:
                    raise ValueError('invalid hint')
                if hint:
                    portal_origin(hint)
                defaults['portal_hint'] = hint
            except ValueError:
                invalid = True
        if 'trusted_hosts' in data:
            hosts = data['trusted_hosts']
            if (isinstance(hosts, list) and len(hosts) <= 50
                    and all(isinstance(host, str) and campus_host(host) for host in hosts)):
                defaults['trusted_hosts'] = list(dict.fromkeys(hosts))
            else:
                invalid = True
        if invalid:
            # Partly damaged configuration never carries permission to submit.
            defaults.update(stu_autostart=False, auto_enabled=False, auto_submit=False)
        return defaults, invalid

    def _backup_settings(self):
        if self._damaged_settings is None:
            return
        raw = self._damaged_settings
        digest = hashlib.sha256(raw).hexdigest()[:16]
        backup = self.root / f'settings.invalid-{digest}.json'
        if backup.exists() and backup.read_bytes() != raw:
            backup = self.root / f'settings.invalid-{digest}-{uuid.uuid4().hex}.json'
        if not backup.exists():
            backup.write_bytes(raw)
        self.settings_backup = str(backup)
        self._damaged_settings = None

    def load(self):
        self.settings_warning = ''
        self.settings_backup = ''
        self._damaged_settings = None
        self._settings_read_failed = False
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            return self._settings({})[0]
        except OSError:
            self._settings_read_failed = True
            self.settings_warning = '无法读取设置，已关闭自动行为；原设置未覆盖，请检查文件权限。'
            return self._settings({})[0]
        try:
            settings, invalid = self._settings(json.loads(raw))
        except (ValueError, RecursionError):
            settings, invalid = self._settings(None)
        if invalid:
            self._damaged_settings = raw
            try:
                self._backup_settings()
                self.settings_warning = '设置格式异常，已关闭自动行为并保留原设置备份。'
            except OSError:
                self.settings_warning = '设置格式异常，已关闭自动行为；备份失败，原设置将保留且暂不覆盖。'
        return settings

    def write_settings(self, settings):
        # Replace only this client's own settings, never credentials in plaintext.
        settings, invalid = self._settings(settings)
        if invalid:
            raise ValueError('设置格式无效；未覆盖原设置。')
        if self._settings_read_failed:
            raise OSError('原设置暂时无法读取，已停止覆盖。')
        self._backup_settings()
        temporary=self.path.with_suffix('.json.tmp')
        temporary.write_text(json.dumps(settings,ensure_ascii=False,indent=2),'utf-8')
        temporary.replace(self.path)

    @staticmethod
    def _profile_data(data):
        if (not isinstance(data, dict) or type(data.get('schema')) is not int
                or data['schema'] != 2 or not isinstance(data.get('profiles'), list)
                or len(data['profiles']) > 50):
            raise ValueError('invalid credential schema')
        selected = data.get('selected', '')
        if not isinstance(selected, str):
            raise ValueError('invalid selection')
        ids, profiles = set(), []
        for item in data['profiles']:
            if not isinstance(item, dict) or not all(isinstance(item.get(key), str)
                    for key in ('id', 'account', 'password', 'operator')):
                raise ValueError('invalid profile')
            if (not item['id'] or item['id'] in ids
                    or item['operator'] not in ('', 'telecom', 'unicom', 'cmcc', 'campus')):
                raise ValueError('invalid profile identity or operator')
            ids.add(item['id'])
            profiles.append({key: item[key] for key in ('id', 'account', 'password', 'operator')})
        if selected and selected not in ids:
            raise ValueError('invalid selection')
        return {'schema': 2, 'selected': selected, 'profiles': profiles}

    def profiles(self):
        try:
            if not self.credentials.exists():
                return {'schema':2,'selected':'','profiles':[]}
            data=json.loads(protect(self.credentials.read_bytes(),decrypt=True))
            if not isinstance(data, dict):
                raise ValueError('invalid credential object')
            if 'profiles' not in data and data.get('account'):
                # v1.2 migration is read-only until the next explicit save.
                item={'id':'legacy','account':data['account'],'password':data.get('password',''),
                      'operator':self.load().get('operator','')}
                data = {'schema':2,'selected':'legacy','profiles':[item]}
            return self._profile_data(data)
        except (RuntimeError,ValueError,OSError,TypeError,RecursionError) as exc:
            raise RuntimeError('无法读取已保存账号；原凭据文件已保留，请勿覆盖。') from exc

    def write_profiles(self, data):
        try:
            data = self._profile_data(data)
        except (ValueError, TypeError) as exc:
            raise RuntimeError('账号格式无效；未覆盖原凭据。') from exc
        cipher=protect(json.dumps(data,ensure_ascii=False).encode('utf-8'))
        temporary=self.credentials.with_suffix('.dpapi.tmp')
        temporary.write_bytes(cipher)
        temporary.replace(self.credentials)

    def selected_profile(self):
        data=self.profiles()
        return next((p.copy() for p in data['profiles'] if p['id']==data['selected']),{})

    def save_profile(self, profile_id, account, password, operator):
        data=self.profiles()
        item=next((p for p in data['profiles'] if p['id']==profile_id),None)
        if profile_id and item is None: raise RuntimeError('已保存账号不存在，请重新选择。')
        if item is None:
            if len(data['profiles'])>=50: raise RuntimeError('最多保存 50 组账号。')
            item={'id':uuid.uuid4().hex}
            data['profiles'].append(item)
        item.update(account=account,password=password,operator=operator)
        data['selected']=item['id']
        self.write_profiles(data)
        return item['id']

    def select_profile(self, profile_id):
        data=self.profiles()
        if profile_id and not any(p['id']==profile_id for p in data['profiles']):
            raise RuntimeError('已保存账号不存在。')
        data['selected']=profile_id
        self.write_profiles(data)

    def delete_profile(self, profile_id):
        data=self.profiles()
        if not any(p['id']==profile_id for p in data['profiles']): raise RuntimeError('已保存账号不存在。')
        data['profiles']=[p for p in data['profiles'] if p['id']!=profile_id]
        if data['selected']==profile_id: data['selected']=''
        self.write_profiles(data)

    def save(self, settings, account, password, remember):
        self.write_settings(settings)
        if remember:
            self.save_profile(self.profiles()['selected'],account,password,settings.get('operator',''))

    def secret(self):
        return self.selected_profile()

# JS is evaluated only on the exact approved portal host, never on public sites.
FILL_JS = r'''({account,password,operator}) => {
 const visible = e => e && e.getClientRects().length && !e.disabled;
 const findAll = sels => [...new Set(sels.flatMap(s=>Array.from(document.querySelectorAll(s))))].filter(visible);
 const users = findAll(['input[name="DDDDD"]','input[name="user_account"]','input[name="username"]','input[name="account"]','input#username','input#user_account']);
 const passes = findAll(['input[name="upass"]','input[name="user_password"]','input[name="password"]','input[type="password"]']);
 if(users.length!==1 || passes.length!==1 || users[0]===passes[0]) return {ok:false,can_submit:false,reason:'用户名或密码字段不唯一或未识别，请使用浏览器手动登录。'};
 const buttons=Array.from(document.querySelectorAll('button,input[type="submit"],input[type="button"],a')).filter(visible);
 const login=buttons.filter(e=>/^(登录|登陆|login|signin)$/i.test((e.innerText||e.value||'').replace(/\s+/g,'')));
 if(login.length!==1) return {ok:false,can_submit:false,reason:'登录按钮不唯一或未识别，请使用浏览器手动登录。'};
 const user=users[0],pass=passes[0];
 const labels = {telecom:['电信','telecom'],unicom:['联通','unicom'],cmcc:['移动','cmcc'],campus:['校园网','校园','校内']};
 let matched = null;
 const selects = Array.from(document.querySelectorAll('select')).filter(visible);
 for(const select of (operator ? selects : [])) {
   const options=Array.from(select.options);
   if(!options.some(o=>/电信|联通|移动|校园|telecom|unicom|cmcc/i.test(o.text+' '+o.value))) continue;
   const choice=options.find(o=>(labels[operator]||[]).some(x=>(o.text+' '+o.value).toLowerCase().includes(x)));
   if(!choice) return {ok:false,reason:'页面运营商选项与配置不一致，已停止，未提交。'};
   select.value=choice.value; select.dispatchEvent(new Event('change',{bubbles:true})); matched=choice.text.trim(); break;
 }
 if(operator && operator!=='campus' && !matched) return {ok:false,reason:'页面没有可识别的运营商选择框，拒绝猜测账号后缀。请手动选择后登录。'};
 for(const [e,value] of [[user,account],[pass,password]]) {
   const setter=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;
   setter.call(e,value); e.dispatchEvent(new Event('input',{bubbles:true})); e.dispatchEvent(new Event('change',{bubbles:true}));
 }
 login[0].setAttribute('data-cumt-login-button','1');
 return {ok:true,operator:matched,can_submit:true,reason:'已填写原网页字段，沿用网页自身认证逻辑。'};
}'''
