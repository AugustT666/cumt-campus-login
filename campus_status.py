"""Short, read-only device-state checks with a shared network deadline.

This module never authenticates, disconnects a device, or starts a monitor.
Account-scoped self-service absence is not device-offline evidence by itself.
"""
from __future__ import annotations

import http.client
import io
import ipaddress
import math
import os
import socket
import ssl
import time
from urllib.parse import urlsplit, urlunsplit

import campus_core as core
import campus_protocol as protocol


MAX_STATUS_BYTES = 128 * 1024
OFFLINE_SAMPLE_SPAN = .6
SAMPLE_INTERVAL = .35
_NAS_PROBE_URLS = frozenset(('http://9.9.9.9/', 'http://1.1.1.1/'))


def _stop_at(deadline, timeout, clock):
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError('A finite, positive status timeout is required')
    stop = clock() + timeout
    if deadline is not None:
        if not isinstance(deadline, (int, float)) or isinstance(deadline, bool) or not math.isfinite(deadline):
            raise ValueError('A finite status deadline is required')
        stop = min(stop, deadline)
    return stop


def _remaining(deadline, clock):
    remaining = deadline - clock()
    if remaining <= 0:
        raise TimeoutError('The short status-check deadline expired')
    return remaining


class _DeadlineReader(io.RawIOBase):
    def __init__(self, owner):
        super().__init__()
        self._owner = owner

    def readable(self):
        return True

    def readinto(self, target):
        return self._owner.recv_into(target)

    def close(self):
        if not self.closed:
            self._owner._release_file()
        super().close()


class _DeadlineSocket:
    """Make HTTPResponse's buffered header/body reads share one absolute limit."""
    def __init__(self, sock, deadline, clock):
        self._sock, self._deadline, self._clock = sock, deadline, clock
        self._files, self._closed = 0, False

    def sendall(self, data):
        self._sock.settimeout(_remaining(self._deadline, self._clock))
        return self._sock.sendall(data)

    def makefile(self, mode='rb', buffering=None):
        if mode != 'rb':
            raise ValueError('The status transport only exposes a binary reader')
        if self._closed:
            raise OSError('The short status connection is closed')
        self._files += 1
        return io.BufferedReader(_DeadlineReader(self))

    def recv_into(self, target):
        self._sock.settimeout(_remaining(self._deadline, self._clock))
        return self._sock.recv_into(target)

    def _release_file(self):
        self._files -= 1
        if self._closed and not self._files:
            self._sock.close()

    def close(self):
        self._closed = True
        if not self._files:
            self._sock.close()

    def __getattr__(self, name):
        return getattr(self._sock, name)


class DeadlineHTTP(http.client.HTTPConnection):
    """Physical-WLAN transport for numeric-IP HTTP(S), without DNS or proxies."""
    def __init__(self, host, port, wifi, secure=False, *, deadline, clock=None):
        self._clock = time.monotonic if clock is None else clock
        self._deadline = deadline
        # A resolver has its own OS timeout and cannot obey this short budget.
        # Portal and self-service endpoints used here already have numeric IPs.
        self._address = str(ipaddress.IPv4Address(host))
        self.wifi, self.secure = wifi, bool(secure)
        super().__init__(self._address, port=port,
                         timeout=_remaining(deadline, self._clock),
                         source_address=(wifi.ip, 0))

    def connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(_remaining(self._deadline, self._clock))
            if os.name == 'nt':
                sock.setsockopt(socket.IPPROTO_IP, 31, socket.htonl(self.wifi.index))
            sock.bind((self.wifi.ip, 0))
            sock.settimeout(_remaining(self._deadline, self._clock))
            sock.connect((self._address, self.port))
            if self.secure:
                context = ssl.create_default_context()
                sock.settimeout(_remaining(self._deadline, self._clock))
                sock = context.wrap_socket(sock, server_hostname=self._address)
            _remaining(self._deadline, self._clock)
            self.sock = _DeadlineSocket(sock, self._deadline, self._clock)
        except BaseException:
            sock.close()
            raise


def connection_factory(deadline, timeout=1.0, *, clock=None):
    """Return a factory usable by SelfServiceClient for bounded readbacks.

    Each connection has at most ``timeout`` seconds, within the shared deadline.
    The caller should use this factory only for the short read-only phase.
    """
    clock = time.monotonic if clock is None else clock
    # Validate once even if the returned factory is never invoked.
    _stop_at(deadline, timeout, clock)
    def create(host, port, wifi, secure=False):
        return DeadlineHTTP(host, port, wifi, secure,
                            deadline=_stop_at(deadline, timeout, clock), clock=clock)
    return create


def _context(wifi):
    return (wifi.key, protocol._session_mac(wifi.mac), str(wifi.gateway or ''))


def _guard(wifi, reader):
    current = reader()
    core.guard(wifi, current, wifi.ssid.casefold() == core.TEC.casefold())
    if _context(current) != _context(wifi):
        raise RuntimeError('无线设备或网关已改变，状态检测已停止。')
    return current


def _unknown(detail):
    return {'state':'unknown', 'binding':'unconfirmed', 'matched_ip':False,
            'online_account':'', 'identity_hint':'', 'detail':detail,
            'ip_conflict':False, 'mac_conflict':False}


def _read_reply(conn):
    response = conn.getresponse()
    try:
        body = response.read(MAX_STATUS_BYTES + 1)
        if len(body) > MAX_STATUS_BYTES:
            raise ValueError('Status response is too large')
        body, headers = core.decode_http_body(body, response.getheaders())
        if len(body) > MAX_STATUS_BYTES:
            raise ValueError('Decoded status response is too large')
        return response.status, response.getheader('Location', ''), core.decode_text(body, headers)
    finally:
        response.close()


def nas_getter(deadline, timeout=1.0):
    """Build a bounded raw-NAS reader for SelfServiceClient's binding proof.

    Only the two exact public numeric-IP seed URLs may be requested. Redirects
    are returned verbatim for the self-service proof parser; never followed or
    repaired from local interface values.
    """
    clock = time.monotonic
    _stop_at(deadline, timeout, clock)
    def get(url, wifi, reader, allow_tec=False):
        if not isinstance(url,str) or url not in _NAS_PROBE_URLS:
            raise ValueError('Only the fixed raw NAS probe URLs are allowed')
        stop = _stop_at(deadline, timeout, clock)
        _remaining(stop, clock)
        if not wifi.student and not (allow_tec is True and wifi.ssid.casefold() == core.TEC.casefold()):
            raise RuntimeError('当前无线网络不允许读取校园接入绑定。')
        _guard(wifi, reader)
        _remaining(stop, clock)
        parts = urlsplit(url)
        conn = DeadlineHTTP(parts.hostname, 80, wifi, deadline=stop, clock=clock)
        try:
            conn.request('GET','/',headers={'User-Agent':'CampusLogin/1.0',
                'Cache-Control':'no-cache','Connection':'close','Accept-Encoding':'identity'})
            result = _read_reply(conn)
            _remaining(stop, clock)
            _guard(wifi, reader)
            _remaining(stop, clock)
            return result
        finally:
            conn.close()
    return get


def probe(wifi, reader, portal='', deadline=None, timeout=1.0):
    """Read one structured portal status, bound to the current physical Wi-Fi."""
    clock = time.monotonic
    started = clock()
    stop = _stop_at(deadline, timeout, clock)
    try:
        _remaining(stop, clock)
        def checked_reader():
            _remaining(stop, clock)
            current = _guard(wifi, reader)
            _remaining(stop, clock)
            return current
        def get(url, wifi, **kwargs):
            p = urlsplit(url)
            core.portal_origin(url)
            conn = DeadlineHTTP(p.hostname, p.port or (443 if p.scheme == 'https' else 80),
                                wifi, p.scheme == 'https', deadline=stop, clock=clock)
            try:
                conn.request('GET', urlunsplit(('', '', p.path or '/', p.query, '')),
                    headers={'User-Agent':'CampusLogin/1.0','Cache-Control':'no-cache',
                             'Connection':'close','Accept-Encoding':'identity'})
                return _read_reply(conn)
            finally:
                conn.close()
        engine = protocol.Engine(wifi, portal or 'http://' + core.KNOWN_HOST + '/a79.htm',
                                 reader=checked_reader,
                                 allow_tec=wifi.ssid.casefold() == core.TEC.casefold(), getter=get)
        report = engine.status()
        checked_reader()
    except TimeoutError:
        report = _unknown('short_check_timeout')
    except RuntimeError:
        report = _unknown('network_context_changed')
    except (OSError, ValueError, http.client.HTTPException):
        report = _unknown('short_check_unavailable')
    report['elapsed_ms'] = round((clock() - started) * 1000)
    report['source'] = 'portal_query'
    report['verification_performed'] = True
    # Echoed source IP alone must not be presented as a confirmed account.
    if report.get('binding') != 'mac_verified' or report.get('state') != 'online':
        report['online_account'] = ''
        report['identity_hint'] = ''
    return report


def _kernel_state(report):
    if not isinstance(report, dict) or report.get('matched_ip') is not True:
        return 'unknown'
    if report.get('mac_conflict') is not False:
        return 'unknown'
    binding, state = report.get('binding'), report.get('state')
    if binding not in ('mac_verified', 'source_ip_only') or state not in ('online','offline'):
        return 'unknown'
    if report.get('ip_conflict') is True and not (state == 'online' and binding == 'mac_verified'):
        return 'unknown'
    return state


def _presence(devices, wifi, session_id):
    if not isinstance(devices, list):
        raise ValueError('A parsed device list is required')
    mac, address = protocol._session_mac(wifi.mac), protocol._session_ip(wifi.ip)
    if not mac or not address:
        return 'conflict'
    found = 'absent'
    seen = set()
    for device in devices:
        session = getattr(device, 'session_id', None)
        ip = protocol._session_ip(getattr(device, 'ip', None))
        raw_mac = getattr(device, 'mac', None)
        device_mac = protocol._session_mac(raw_mac)
        if not isinstance(session, str) or not session or session in seen or not ip or not isinstance(raw_mac, str):
            raise ValueError('Invalid parsed device list')
        seen.add(session)
        if session_id is not None and session == session_id:
            if device_mac and device_mac != mac:
                return 'conflict'
            found = 'present'
        if device_mac == mac:
            found = 'present'
        elif ip == address:
            if device_mac:
                return 'conflict'
            if found != 'present':
                found = 'unbound_present'
    return found


def confirm_logout(wifi, reader, list_devices=None, session_id=None,
                   deadline=None, timeout=6.0):
    """Quickly confirm stable offline evidence; never submit a disconnect.

    ``list_devices`` must be a read-only callback whose network connections use
    ``connection_factory(deadline)``. An absent row belongs only to that account;
    it cannot substitute for the current device's structured offline response.
    """
    clock = time.monotonic
    started = clock()
    stop = _stop_at(deadline, timeout, clock)
    samples, streak, first_offline, last_report = [], 0, None, _unknown('not_checked')
    last_kind, last_presence = 'unknown', 'not_requested'
    while clock() < stop:
        report = probe(wifi, reader, deadline=stop, timeout=min(1.0, stop-clock()))
        kind, presence = _kernel_state(report), 'not_requested'
        if report.get('detail') == 'network_context_changed':
            last_report = report
            break
        if list_devices is not None:
            try:
                _remaining(stop, clock)
                presence = _presence(list_devices(), wifi, session_id)
            except (OSError, RuntimeError, ValueError, http.client.HTTPException):
                presence = 'unavailable'
        now = clock()
        if now > stop:
            last_kind, last_presence = 'unknown', 'unavailable'
            break
        last_report, last_kind, last_presence = report, kind, presence
        samples.append({'elapsed_ms':round((now-started)*1000), 'state':kind,
                        'binding':report.get('binding','unconfirmed'),
                        'detail':report.get('detail',''), 'device_presence':presence})
        absent = presence in ('absent','not_requested')
        if kind == 'offline' and absent:
            streak += 1
            if first_offline is None:
                first_offline = now
            if streak >= 2 and now - first_offline >= OFFLINE_SAMPLE_SPAN:
                return {'state':'offline','outcome':'confirmed_offline','samples':samples,
                        'device_presence':presence,'status':report,
                        'verification_performed':True,'elapsed_ms':round((now-started)*1000)}
        else:
            streak, first_offline = 0, None
        delay = min(SAMPLE_INTERVAL, max(0,stop-clock()))
        if delay:
            time.sleep(delay)
    # Conflicting or unavailable evidence never turns into a definite failure.
    still_online = last_kind == 'online' and last_presence in ('present','unbound_present','not_requested')
    return {'state':'online' if still_online else 'unknown',
            'outcome':'still_online' if still_online else 'unknown', 'samples':samples,
            'device_presence':last_presence,'status':last_report,
            'verification_performed':True,'elapsed_ms':round((clock()-started)*1000)}
