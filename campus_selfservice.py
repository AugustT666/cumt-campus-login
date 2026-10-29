"""Single-device Self-service submission, with fixed origin and no credential store.

The endpoints and form semantics follow the school's observed Self pages.
Only a fresh authenticated cookie jar may list and disconnect its own session.
No request, cookie, password, device identifier or response body is logged here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import wraps
from html.parser import HTMLParser
from http.cookies import SimpleCookie, CookieError
import http.client
import ipaddress
import json
import math
import re
import time
import threading
from urllib.parse import urlencode, urljoin, urlsplit, parse_qsl

import campus_core as core
import campus_protocol as protocol


ORIGIN = 'http://202.119.196.6:8080'
LOGIN_PAGE = '/Self/login/?302=LI'
LOGIN_ACTION = '/Self/login/verify'
DASHBOARD = '/Self/dashboard'
CAPTCHA_IMAGE = '/Self/login/randomCode'
ONLINE_LIST = '/Self/dashboard/getOnlineList'
DISCONNECT = '/Self/dashboard/tooffline'
WEB_LOGOUT = '/Self/login/logout'
MAX_BODY = 2 * 1024 * 1024
MAX_DEVICES = 128
NAS_BINDING_TTL = 10.0
NAS_PROBES = ('http://9.9.9.9/', 'http://1.1.1.1/')
NAS_PORTAL_HOSTS = frozenset(('10.2.5.251',))
_NAS_PROOF_ISSUER = object()


class SelfServiceError(RuntimeError):
    pass


class AuthenticationError(SelfServiceError):
    pass


class CaptchaRequired(AuthenticationError):
    pass


class UnsupportedService(SelfServiceError):
    pass


class NoMatchingDevice(SelfServiceError):
    pass


class AmbiguousDevice(SelfServiceError):
    pass


def _network_context(wifi):
    return (wifi.ssid, wifi.guid, wifi.index, _ip(wifi.ip), _mac(wifi.mac), str(wifi.gateway or ''))


def _nas_context_guard(wifi, reader):
    current = reader()
    core.guard(wifi, current, wifi.ssid.casefold() == core.TEC.casefold())
    if _network_context(current) != _network_context(wifi):
        raise UnsupportedService('无线设备或接入参数已改变，未使用旧的设备证明。')
    return current


def _nas_target_matches(target, wifi):
    """Validate original router parameters; never fill or rewrite missing values."""
    if (not isinstance(target, str) or len(target) > 8192
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in target)):
        return False
    try:
        parts = urlsplit(target)
        if (parts.scheme not in ('http', 'https') or parts.hostname not in NAS_PORTAL_HOSTS
                or parts.port not in (None, 80, 443, 801, 802)
                or parts.username or parts.password or parts.fragment):
            return False
        fields = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True,
                           encoding='utf-8', errors='strict', max_num_fields=128)
        critical = {'wlanuserip', 'mac', 'wlanacname', 'nasip'}
        values = {}
        for key, value in fields:
            key = key.casefold()
            if key not in critical:
                continue
            if key in values or '%' in value or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
                return False
            values[key] = value
        if set(values) != critical:
            return False
        nas = _ip(values['nasip'])
        if (not nas or nas == '255.255.255.255' or ipaddress.IPv4Address(nas).is_loopback
                or ipaddress.IPv4Address(nas).is_link_local):
            return False
        return (bool(_ip(wifi.ip)) and bool(_mac(wifi.mac))
                and _ip(values['wlanuserip']) == _ip(wifi.ip)
                and _mac(values['mac']) == _mac(wifi.mac)
                and 0 < len(values['wlanacname'].strip()) <= 256)
    except (ValueError, UnicodeError):
        return False


class _NasScripts(HTMLParser):
    def __init__(self):
        super().__init__()
        self.blocks, self.current, self.invalid = [], None, False

    def handle_starttag(self, tag, attrs):
        if tag == 'script':
            attrs = dict(attrs)
            if self.current is not None or attrs.get('src') or attrs.get('type', '').casefold() not in (
                    '', 'text/javascript', 'application/javascript'):
                self.invalid = True
            self.current = []

    def handle_data(self, data):
        if self.current is not None:
            self.current.append(data)

    def handle_endtag(self, tag):
        if tag == 'script' and self.current is not None:
            self.blocks.append(''.join(self.current))
            self.current = None


def _raw_nas_target(seed, status, location, text):
    if status in (301, 302, 303, 307, 308) and isinstance(location, str) and location:
        return urljoin(seed, location)
    if status != 200 or location or not isinstance(text, str) or len(text) > MAX_BODY:
        return ''
    # Recognize literal location assignments/replacements only, without running JS
    # or consulting a page URL synthesized by the portal-discovery machinery.
    literal = r'''(?:'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*")'''
    script = text
    if '<' in text:
        parser = _NasScripts()
        parser.feed(text)
        if parser.invalid or parser.current is not None or len(parser.blocks) != 1:
            return ''
        script = parser.blocks[0]
    prefix = r'(?:(?:window|top|self)\.){0,3}location'
    match = re.fullmatch(r'\s*(?:' + prefix + r'(?:\.href)?\s*=\s*(' + literal + r')|'
                         + prefix + r'\.replace\s*\(\s*(' + literal + r')\s*\))\s*;?\s*', script)
    if match is None:
        return ''
    try:
        return urljoin(seed, protocol._literal(next(value for value in match.groups() if value is not None)))
    except protocol.UnsupportedPortal:
        return ''


def _fetch_raw_nas_redirect(url, wifi, reader, allow_tec):
    parts = urlsplit(url)
    reader()
    conn = core.BoundHTTP(parts.hostname, 80, wifi)
    try:
        conn.request('GET', '/', headers={'User-Agent':'CampusLogin/1.0',
            'Cache-Control':'no-cache', 'Connection':'close', 'Accept-Encoding':'identity'})
        response = conn.getresponse()
        raw = response.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            raise UnsupportedService('接入设备返回内容过大，未确认设备绑定。')
        location = response.getheader('Location', '')
        raw, headers = core.decode_http_body(raw, response.getheaders())
        text = core.decode_text(raw, headers)
        reader()
        return response.status, location, text
    finally:
        conn.close()


@dataclass(frozen=True, repr=False)
class NasBinding:
    portal_url: str
    context: tuple
    observed_at: float
    _issuer: object = field(default=None, init=False, repr=False)

    def validate(self, wifi, reader=None, clock=None):
        reader = core.read_wifi if reader is None else reader
        clock = time.monotonic if clock is None else clock
        if (self._issuer is not _NAS_PROOF_ISSUER or self.context != _network_context(wifi)
                or not 0 <= clock() - self.observed_at <= NAS_BINDING_TTL
                or not _nas_target_matches(self.portal_url, wifi)):
            raise UnsupportedService('接入设备绑定证明已失效，未执行下线。')
        _nas_context_guard(wifi, reader)
        if not 0 <= clock() - self.observed_at <= NAS_BINDING_TTL:
            raise UnsupportedService('接入设备绑定证明已过期，未执行下线。')
        return True


def observe_nas_binding(wifi, reader=None, getter=None, clock=None):
    """Observe one bound NAS redirect, without authentication or URL rewriting."""
    reader = core.read_wifi if reader is None else reader
    getter = _fetch_raw_nas_redirect if getter is None else getter
    clock = time.monotonic if clock is None else clock
    if not wifi.ready or not _mac(wifi.mac):
        raise UnsupportedService('当前无线设备信息不完整，未确认接入绑定。')
    guarded = lambda:_nas_context_guard(wifi, reader)
    with core.trace_scope(None):
        guarded()
        for seed in NAS_PROBES:
            observed_at = clock()
            try:
                status, location, text = getter(seed, wifi, reader=guarded,
                    allow_tec=wifi.ssid.casefold() == core.TEC.casefold())
            except (OSError, http.client.HTTPException):
                guarded()
                continue
            guarded()
            target = _raw_nas_target(seed, status, location, text)
            if _nas_target_matches(target, wifi):
                proof = NasBinding(target, _network_context(wifi), observed_at)
                object.__setattr__(proof, '_issuer', _NAS_PROOF_ISSUER)
                proof.validate(wifi, reader=reader, clock=clock)
                return proof
    raise UnsupportedService('接入设备未提供完整的本机绑定证明，未自动下线。')


def _serialized(method):
    @wraps(method)
    def call(self, *args, **kwargs):
        with self._operation_lock:
            return method(self, *args, **kwargs)
    return call


def _mac(value):
    if not isinstance(value, str):
        return ''
    value = re.sub(r'[-:]', '', value.strip())
    return value.upper() if re.fullmatch(r'[0-9A-Fa-f]{12}', value) and value != '000000000000' else ''


def _ip(value):
    if not isinstance(value, str):
        return ''
    try:
        result = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        return ''
    return '' if result.is_unspecified or result.is_multicast else str(result)


def _json(text):
    if not isinstance(text, str) or len(text) > MAX_BODY:
        raise UnsupportedService('自助服务响应过大或格式无效，未继续操作。')
    def unique(pairs):
        result = {}
        for k, v in pairs:
            if k in result:
                raise ValueError('duplicate field')
            result[k] = v
        return result
    def finite(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError('nonfinite')
        return number
    def constant(value):
        raise ValueError('nonfinite')
    try:
        return json.loads(text, object_pairs_hook=unique, parse_float=finite,
                          parse_constant=constant)
    except (ValueError, TypeError, RecursionError):
        raise UnsupportedService('自助服务响应格式无法确认，未继续操作。') from None


@dataclass(frozen=True, repr=False)
class DeviceSession:
    session_id: str
    ip: str
    mac: str
    user_id: int


def parse_online_devices(text):
    """The observed getOnlineList response is a direct JSON array."""
    data = _json(text)
    if not isinstance(data, list) or len(data) > MAX_DEVICES:
        raise UnsupportedService('自助服务设备列表格式已改变，未选择设备。')
    devices, ids, owners = [], set(), set()
    for row in data:
        if not isinstance(row, dict) or not {'sessionId', 'ip', 'mac', 'userId'} <= row.keys():
            raise UnsupportedService('自助服务设备信息不完整，未选择设备。')
        session = row['sessionId']
        if (not isinstance(session, str) or not 1 <= len(session) <= 512
                or session != session.strip() or any(ord(ch) < 33 or ord(ch) > 126 for ch in session)
                or session in ids):
            raise UnsupportedService('自助服务会话标识无法确认，未选择设备。')
        address = _ip(row['ip'])
        if not address or not isinstance(row['mac'], str):
            raise UnsupportedService('自助服务设备地址无法确认，未选择设备。')
        mac = _mac(row['mac'])
        if row['mac'].strip() and not mac and re.sub(r'[-:]', '', row['mac'].strip()) != '000000000000':
            raise UnsupportedService('自助服务设备地址无法确认，未选择设备。')
        owner = row['userId']
        if type(owner) is not int or owner < 0:
            raise UnsupportedService('自助服务账号归属无法确认，未选择设备。')
        owners.add(owner)
        ids.add(session)
        devices.append(DeviceSession(session, address, mac, owner))
    if len(owners) > 1:
        raise UnsupportedService('自助服务列表的账号归属不一致，未选择设备。')
    return devices


def select_current_session(devices, wifi, session_info=None):
    """Match current IP+MAC first; use a MAC-verified bound server IP only second."""
    mac, address = _mac(wifi.mac), _ip(wifi.ip)
    if not mac or not address:
        raise NoMatchingDevice('当前无线设备地址无法确认，未执行自助下线。')
    if not isinstance(devices, list) or not all(isinstance(d, DeviceSession) for d in devices):
        raise UnsupportedService('自助服务设备列表无法确认，未选择设备。')
    matches = [d for d in devices if d.mac == mac and d.ip == address]
    if len(matches) > 1:
        raise AmbiguousDevice('当前设备对应多个会话，未自动下线；请到自助服务核对。')
    if len(matches) == 1:
        return matches[0]
    info = session_info if isinstance(session_info, dict) else {}
    alternate = _ip(info.get('server_ip'))
    if (info.get('state') == 'online' and info.get('binding') == 'mac_verified'
            and info.get('matched_ip') is True and info.get('mac_conflict') is False
            and _mac(info.get('server_mac')) == mac and alternate):
        matches = [d for d in devices if d.mac == mac and d.ip == alternate]
        if len(matches) > 1:
            raise AmbiguousDevice('当前设备对应多个会话，未自动下线；请到自助服务核对。')
        if len(matches) == 1:
            return matches[0]
    raise NoMatchingDevice('自助服务中未找到与当前无线设备一致的会话，未下线其他设备。')


class _LoginForm(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms, self.controls, self.captcha = [], [], []
        self.script = False
        self.scripts = []
    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == 'form':
            self.forms.append(d)
        if tag == 'input':
            self.controls.append(d)
        if d.get('id') == 'randomDiv':
            self.captcha.append(d)
        if tag == 'script':
            self.script = 'src' not in d
    def handle_endtag(self, tag):
        if tag == 'script':
            self.script = False
    def handle_data(self, data):
        if self.script:
            self.scripts.append(data)


def _captcha_hidden(attrs):
    return ('hide' in attrs.get('class', '').split() or 'hidden' in attrs
            or bool(re.search(r'\bdisplay\s*:\s*none\b', attrs.get('style', ''), re.I)))


def _captcha_requested(text):
    parser = _LoginForm()
    parser.feed(text)
    if len(parser.captcha) == 1 and not _captcha_hidden(parser.captcha[0]):
        return True
    # Static validation labels mention captcha even when it is disabled. Only
    # inspect the server's error-tip argument, never the ordinary form labels.
    literal = r'''(?:'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*")'''
    for script in parser.scripts:
        for match in re.finditer(r'\}\)\(\s*(' + literal + r')\s*\)\s*;', script):
            try:
                tip = protocol._literal(match.group(1))
            except protocol.UnsupportedPortal:
                continue
            if '验证码' in tip or 'captcha' in tip.lower():
                return True
    return False


def parse_login_form(text, session_cookie=None):
    parser = _LoginForm()
    parser.feed(text)
    if len(parser.forms) != 1:
        raise UnsupportedService('自助服务登录表单无法确认。')
    form = parser.forms[0]
    action = urlsplit(urljoin(ORIGIN, form.get('action', '')))
    path = action.path
    rewritten = re.fullmatch(re.escape(LOGIN_ACTION) + r';jsessionid=([0-9A-Fa-f]{32})', path)
    if rewritten:
        if (not isinstance(session_cookie, str) or rewritten.group(1) != session_cookie):
            raise UnsupportedService('自助服务登录入口的会话不一致，未提交账号。')
        path = LOGIN_ACTION
    if (form.get('method', '').lower() != 'post'
            or (action.scheme, action.hostname, action.port, path) !=
               ('http', '202.119.196.6', 8080, LOGIN_ACTION)
            or action.query or action.fragment or action.username or action.password):
        raise UnsupportedService('自助服务登录入口已改变，未提交账号。')
    names = [d.get('name') for d in parser.controls if d.get('name')]
    if any(names.count(k) != 1 for k in ('account', 'password', 'code')):
        raise UnsupportedService('自助服务登录字段无法确认，未提交账号。')
    if len(parser.captcha) != 1:
        raise CaptchaRequired('自助服务验证码状态无法确认，请在浏览器手动登录。')
    captcha = parser.captcha[0]
    if not _captcha_hidden(captcha):
        raise CaptchaRequired('自助服务需要验证码，请在浏览器手动处理；未自动提交。')
    scripts = '\n'.join(parser.scripts)
    flags = re.findall(r'\bvar\s+md5\s*=\s*(true|false)\s*;', scripts)
    if flags != ['false']:
        raise UnsupportedService('自助服务密码处理方式已改变，未提交账号。')
    fields = {}
    for d in parser.controls:
        name = d.get('name')
        if not name or name in ('account', 'password', 'code'):
            continue
        if name in fields or len(fields) >= 32:
            raise UnsupportedService('自助服务登录字段重复或过多，未提交账号。')
        if d.get('type', '').lower() == 'hidden':
            value = d.get('value', '')
            if len(name) > 128 or len(value) > 4096:
                raise UnsupportedService('自助服务登录字段过大，未提交账号。')
            fields[name] = value
        elif name in ('foo', 'bar'):
            fields[name] = ''
    fields['code'] = ''
    return fields


class SelfServiceClient:
    def __init__(self, wifi, reader=None, trace=None, connection_factory=None,
                 cleanup_reader=None, sleeper=None, nas_getter=None, clock=None):
        self.wifi = wifi
        self.reader = core.read_wifi if reader is None else reader
        self.cleanup_reader = self.reader if cleanup_reader is None else cleanup_reader
        self.connection_factory = core.BoundHTTP if connection_factory is None else connection_factory
        self.trace = trace
        self._sleep = time.sleep if sleeper is None else sleeper
        self._clock = time.monotonic if clock is None else clock
        self._nas_getter = nas_getter
        self._operation_lock = threading.RLock()
        self._submission_lock = threading.Lock()
        self._key = wifi.key
        self._mac = _mac(wifi.mac)
        self._context = _network_context(wifi)
        self._owner_id = None
        self._nas_binding = None
        self._pending_nas_binding = None
        self._cookies = {}
        self._authenticated = False
        self._closed = False
        self._login_attempted = False
        self._disconnect_attempted = False
        self._pending_session = None
        self._summary = {'login_attempted':False, 'login_confirmed':False,
            'device_queries':0, 'disconnect_requests':0, 'request_accepted':None,
            'session_removed':None, 'current_device_offline':None,
            'device_reappeared':False, 'web_logout_attempted':False,
            'web_logout_confirmed':False}

    def safe_summary(self):
        return dict(self._summary)

    def _record(self, event, **fields):
        if self.trace is not None:
            self.trace(event, **fields)

    def _guard(self, cleanup=False):
        if (self._closed or self.wifi.key != self._key or not self._mac
                or _network_context(self.wifi) != self._context):
            raise SelfServiceError('自助服务操作上下文已失效。')
        current = (self.cleanup_reader if cleanup else self.reader)()
        core.guard(self.wifi, current, self.wifi.ssid.casefold() == core.TEC.casefold())
        if _network_context(current) != self._context:
            raise SelfServiceError('无线设备或网关参数已改变，自助服务操作已停止。')
        return current

    @staticmethod
    def _url(path):
        if (not isinstance(path, str) or len(path) > 8192
                or any(ord(ch) < 32 or ord(ch) == 127 for ch in path)):
            raise UnsupportedService('自助服务地址格式无法确认，未继续操作。')
        p = urlsplit(urljoin(ORIGIN, path))
        if ((p.scheme, p.hostname, p.port) != ('http', '202.119.196.6', 8080)
                or p.username or p.password or p.fragment):
            raise UnsupportedService('自助服务跳转超出已确认入口，未继续操作。')
        return p

    @staticmethod
    def _cookie_valid(name, value):
        return (isinstance(name, str) and 1 <= len(name) <= 128
                and bool(re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", name))
                and isinstance(value, str) and len(value) <= 4096
                and all(33 <= ord(ch) <= 126 and ch not in '\",;\\' for ch in value))

    def _cookie_header(self, path):
        values = []
        for name, (value, cookie_path, secure) in self._cookies.items():
            if not self._cookie_valid(name, value):
                raise UnsupportedService('自助服务会话格式无法确认，未继续操作。')
            if not secure and (path == cookie_path or path.startswith(cookie_path.rstrip('/') + '/')):
                values.append(name + '=' + value)
        return '; '.join(values)

    def _request(self, path, method='GET', fields=None, params=None, cleanup=False):
        p = self._url(path)
        allowed = {'/Self', '/Self/', '/Self/login', '/Self/login/', DASHBOARD, CAPTCHA_IMAGE,
                   ONLINE_LIST, DISCONNECT, WEB_LOGOUT, LOGIN_ACTION}
        if p.path not in allowed or (method == 'POST') != (p.path == LOGIN_ACTION):
            raise UnsupportedService('自助服务请求入口无法确认，未继续操作。')
        if method not in ('GET', 'POST') or (fields is not None and method != 'POST'):
            raise UnsupportedService('自助服务请求方式无法确认。')
        if p.path == DISCONNECT and (self._disconnect_attempted or not self._pending_session
                or not isinstance(params, dict) or params.get('sessionid') != self._pending_session):
            raise SelfServiceError('自助下线未完成当前设备核对或已经提交，未重复发送。')
        self._guard(cleanup)
        query = p.query
        if params:
            query += ('&' if query else '') + urlencode(params)
        target = p.path + ('?' + query if query else '')
        headers = {'User-Agent':'Mozilla/5.0', 'Connection':'close',
                   'Accept-Encoding':'identity', 'Referer':ORIGIN + (LOGIN_PAGE if method == 'POST' else DASHBOARD)}
        cookie = self._cookie_header(p.path)
        if cookie:
            headers['Cookie'] = cookie
        body = None
        if fields is not None:
            headers.update({'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8',
                            'Origin':ORIGIN})
            body = urlencode(fields).encode('utf-8')
        conn = self.connection_factory('202.119.196.6', 8080, self.wifi)
        started = time.monotonic()
        try:
            if p.path == DISCONNECT:
                # Finish TCP setup before the last short-lived proof check; an
                # address-only device must not be authorized by a stale proof
                # while a slow connection is still being established.
                connect = getattr(conn, 'connect', None)
                if callable(connect):
                    connect()
                self._guard(cleanup)
                if self._pending_nas_binding is not None:
                    self._pending_nas_binding.validate(self.wifi, reader=self.reader, clock=self._clock)
                with self._submission_lock:
                    if (self._disconnect_attempted or not self._pending_session
                            or not isinstance(params, dict)
                            or params.get('sessionid') != self._pending_session):
                        raise SelfServiceError('自助下线已经提交或会话已改变，未重复发送。')
                    self._disconnect_attempted = True
                    self._summary['disconnect_requests'] = 1
                self._record('selfservice.disconnect_submitted', requests=1)
            conn.request(method, target, body=body, headers=headers)
            response = conn.getresponse()
            raw = response.read(MAX_BODY + 1)
            if len(raw) > MAX_BODY:
                raise UnsupportedService('自助服务响应过大，已停止。')
            pairs = response.getheaders()
            for key, value in pairs:
                if key.lower() != 'set-cookie':
                    continue
                parsed = SimpleCookie()
                if len(value) > 8192 or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
                    raise UnsupportedService('自助服务会话格式无法确认。')
                try:
                    parsed.load(value)
                except CookieError:
                    raise UnsupportedService('自助服务会话格式无法确认。') from None
                for name, item in parsed.items():
                    if not self._cookie_valid(name, item.value):
                        raise UnsupportedService('自助服务会话格式无法确认。')
                    domain = item['domain'].lstrip('.').lower()
                    if domain and domain != '202.119.196.6':
                        raise UnsupportedService('自助服务会话域已改变。')
                    cookie_path = item['path'] or '/Self'
                    if not cookie_path.startswith('/'):
                        raise UnsupportedService('自助服务会话路径无法确认。')
                    if item['max-age'] == '0' or not item.value:
                        self._cookies.pop(name, None)
                    else:
                        self._cookies[name] = (item.value, cookie_path, bool(item['secure']))
            location = response.getheader('Location', '')
            if location:
                self._url(location)
            raw, clean = core.decode_http_body(raw, dict(pairs))
            if len(raw) > MAX_BODY:
                raise UnsupportedService('自助服务响应过大，已停止。')
            text = core.decode_text(raw, clean)
            # The mutation is already sent and its response has arrived. Return
            # its acknowledgment directly; later device verification belongs to
            # explicit developer checks, not the production submission path.
            if p.path != DISCONNECT:
                self._guard(cleanup)
            self._record('selfservice.http_result', path=p.path, method=method,
                         status=response.status, elapsed_ms=round((time.monotonic()-started)*1000))
            return response.status, location, text
        finally:
            conn.close()

    @_serialized
    def login(self, account, password):
        if self._login_attempted:
            raise AuthenticationError('自助服务登录已尝试过，未重复提交密码。')
        if not isinstance(account, str) or not account or not isinstance(password, str) or not password:
            raise AuthenticationError('没有可用的自助服务账号密码，未执行下线。')
        status, location, page = self._request(LOGIN_PAGE)
        if status != 200 or location:
            raise UnsupportedService('自助服务登录页无法确认，未提交账号。')
        session_cookie = self._cookies.get('JSESSIONID', ('', '/Self', False))[0]
        fields = parse_login_form(page, session_cookie=session_cookie)
        # The official page initializes this image even while its group is hidden.
        status, location, _ = self._request(CAPTCHA_IMAGE, params={'t':time.time_ns()})
        if status != 200 or location:
            raise UnsupportedService('自助服务登录会话初始化未完成，未提交账号。')
        if 'JSESSIONID=' not in self._cookie_header(LOGIN_ACTION):
            raise UnsupportedService('自助服务登录会话未建立，未提交账号。')
        # A rewritten action is valid only for the still-current cookie.
        fields = parse_login_form(page, session_cookie=self._cookies.get('JSESSIONID', ('',))[0])
        fields.update(account=account, password=password)
        with self._submission_lock:
            if self._login_attempted:
                raise AuthenticationError('自助服务登录已尝试过，未重复提交密码。')
            self._login_attempted = True
            self._summary['login_attempted'] = True
        try:
            status, location, response = self._request(LOGIN_ACTION, 'POST', fields=fields)
        finally:
            fields['password'] = ''
        if status not in (302, 303) or not location or self._url(location).path != DASHBOARD:
            if location and self._url(location).path in ('/Self/login', '/Self/login/'):
                _, _, response = self._request(location)
            if _captcha_requested(response):
                raise CaptchaRequired('自助服务登录要求验证码，请在浏览器手动处理。')
            raise AuthenticationError('自助服务登录未通过，请核对该服务的账号密码；未执行下线。')
        status, location, dashboard = self._request(location)
        if (status != 200 or location or not re.search(r'id=["\']OnlineLisBig["\']', dashboard)
                or not re.search(r'url\s*:\s*["\']dashboard/getOnlineList["\']', dashboard)
                or not re.search(r'url\s*:\s*["\']dashboard/tooffline["\']', dashboard)):
            raise AuthenticationError('自助服务登录状态未能确认，未执行下线。')
        self._authenticated = True
        self._summary['login_confirmed'] = True
        self._record('selfservice.login_confirmed')
        return True

    @_serialized
    def list_online_devices(self):
        if not self._authenticated:
            raise AuthenticationError('自助服务尚未登录，未查询设备。')
        status, location, text = self._request(ONLINE_LIST, params={'_':time.time_ns()})
        if location:
            self._authenticated = False
            raise AuthenticationError('自助服务登录已失效，未继续下线。')
        if status != 200:
            raise UnsupportedService('自助服务设备列表暂不可读取，未继续下线。')
        devices = parse_online_devices(text)
        owners = {d.user_id for d in devices}
        if owners:
            owner = next(iter(owners))
            if self._owner_id is not None and owner != self._owner_id:
                raise AuthenticationError('自助服务设备归属已改变，未继续操作。')
            self._owner_id = owner
        self._summary['device_queries'] += 1
        self._record('selfservice.device_list_read', count=len(devices))
        return devices

    @_serialized
    def select_current_session(self, devices, session_info=None):
        if not self._authenticated:
            raise AuthenticationError('自助服务尚未登录，未选择设备。')
        self._guard()
        if (not isinstance(devices, list) or not all(isinstance(d, DeviceSession) for d in devices)
                or len({d.session_id for d in devices}) != len(devices)
                or len({d.user_id for d in devices}) > 1
                or devices and {d.user_id for d in devices} != {self._owner_id}):
            raise UnsupportedService('自助服务设备归属或会话列表无法确认，未选择设备。')
        try:
            return select_current_session(devices, self.wifi, session_info)
        except NoMatchingDevice:
            candidates = [d for d in devices if d.ip == _ip(self.wifi.ip)]
            if len(candidates) > 1:
                raise AmbiguousDevice('本机地址对应多个会话，未自动下线。') from None
            if len(candidates) != 1 or candidates[0].mac:
                raise
            if self._nas_binding is None:
                self._nas_binding = observe_nas_binding(self.wifi, reader=self.reader,
                    getter=self._nas_getter, clock=self._clock)
            self._nas_binding.validate(self.wifi, reader=self.reader, clock=self._clock)
            self._record('selfservice.binding_verified', proof_type='nas_current_ip', verified=True)
            return candidates[0]

    def _submit_current(self, session_info=None, before_disconnect=None):
        """Resolve one current device and submit once; callers hold the operation lock."""
        if self._disconnect_attempted:
            raise SelfServiceError('本次自助下线已经提交过，未重复发送。')
        selected = self.select_current_session(self.list_online_devices(), session_info)
        # Do not send an identifier that disappeared or changed while preparing.
        verified = self.select_current_session(self.list_online_devices(), session_info)
        if selected != verified:
            raise AmbiguousDevice('自助服务会话已变化，未发送过期下线请求。')
        if before_disconnect is not None:
            before_disconnect()
        self._guard()
        if not selected.mac:
            self._nas_binding.validate(self.wifi, reader=self.reader, clock=self._clock)
            self._pending_nas_binding = self._nas_binding
        self._pending_session = selected.session_id
        try:
            status, location, body = self._request(DISCONNECT,
                params={'sessionid':selected.session_id, '_':time.time_ns()})
            if location:
                raise AuthenticationError('自助服务登录已失效，下线结果尚未确认。')
            if status == 200:
                data = _json(body)
                if isinstance(data, dict) and type(data.get('success')) is bool:
                    self._summary['request_accepted'] = data['success']
        except (OSError, http.client.HTTPException, SelfServiceError):
            # A timeout may follow a received request. Only read back; never retry.
            if not self._disconnect_attempted:
                raise
        finally:
            self._pending_session = None
            self._pending_nas_binding = None
        return selected

    @_serialized
    def submit_current(self, session_info=None, before_disconnect=None):
        """Return the server's single-request acknowledgment without post-checks."""
        self._submit_current(session_info, before_disconnect)
        return self.safe_summary()

    @_serialized
    def disconnect_current(self, session_info=None, before_disconnect=None):
        """Development verification helper; production uses submit_current."""
        selected = self._submit_current(session_info, before_disconnect)
        absent_samples, seen_absent = 0, False
        for delay in (0, 1, 2, 3):  # elapsed 0/1/3/6 seconds, reads only
            try:
                if delay:
                    self._guard()
                    self._sleep(delay)
                remaining = self.list_online_devices()
                removed = not any(d.session_id == selected.session_id for d in remaining)
                same_mac = [d for d in remaining if d.mac == self._mac
                            or not selected.mac and d.ip == _ip(self.wifi.ip)]
                self._summary['session_removed'] = removed
                if same_mac:
                    if seen_absent or removed:
                        self._summary['device_reappeared'] = True
                    absent_samples = 0
                elif removed:
                    seen_absent = True
                    absent_samples += 1
                else:
                    absent_samples = 0
                self._summary['current_device_offline'] = False
                # An explicit rejection is not repaired by polling or resending.
                if self._summary['request_accepted'] is False and same_mac:
                    break
            except (OSError, http.client.HTTPException, SelfServiceError):
                self._summary['current_device_offline'] = None
                break
            except RuntimeError:
                self._summary['current_device_offline'] = None
                raise
        else:
            self._summary['current_device_offline'] = (
                absent_samples >= 2 and self._summary['session_removed'] is True
                and not self._summary['device_reappeared'])
        self._record('selfservice.disconnect_checked', **self.safe_summary())
        return self.safe_summary()

    def _web_session_is_closed(self):
        status, location, page = self._request(DASHBOARD, cleanup=True)
        for _ in range(3):
            if status in (302, 303) and location:
                path = self._url(location).path
                if path in ('/Self/login', '/Self/login/'):
                    return True
                if path in ('/Self', '/Self/'):
                    status, location, page = self._request(location, cleanup=True)
                    continue
                return False
            if status == 200:
                if re.search(r'id=["\']OnlineLisBig["\']', page):
                    return False
                parser = _LoginForm()
                parser.feed(page)
                if len(parser.forms) == 1:
                    action = self._url(parser.forms[0].get('action', ''))
                    rewritten = re.fullmatch(re.escape(LOGIN_ACTION) + r';jsessionid=([0-9A-Fa-f]{32})', action.path)
                    known_action = (action.path == LOGIN_ACTION or
                        rewritten is not None and rewritten.group(1) == self._cookies.get('JSESSIONID', ('',))[0])
                    return (known_action and not action.query and
                            {d.get('name') for d in parser.controls} >= {'account','password'})
            return False
        return False

    @_serialized
    def close(self):
        if self._closed:
            return self.safe_summary()
        try:
            if self._login_attempted and self._cookies:
                self._summary['web_logout_attempted'] = True
                self._request(WEB_LOGOUT, cleanup=True)
                self._summary['web_logout_confirmed'] = self._web_session_is_closed()
        except Exception:
            self._summary['web_logout_confirmed'] = False
        finally:
            self._cookies.clear()
            self._authenticated = False
            self._closed = True
        self._record('selfservice.web_session_closed',
                     confirmed=self._summary['web_logout_confirmed'])
        return self.safe_summary()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


Client = SelfServiceClient
