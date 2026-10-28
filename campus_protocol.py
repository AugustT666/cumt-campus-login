"""Small Dr.COM adapter derived from the portal's verified, current scripts.

No JavaScript is executed here. Complete known scripts are fingerprinted with
only explicit literal configuration slots excluded. Unknown portal revisions
must use the original browser flow before any submission.
Only the current physical WiFi is used, and one authenticate() call sends at most
one login/logout request.  It never retries after a request may have been sent.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import http.client
from html.parser import HTMLParser
import ipaddress
import json
import math
import re
import time
from urllib.parse import parse_qsl, quote, quote_plus, urlencode, urljoin, urlsplit, urlunsplit

import campus_core as core


class UnsupportedPortal(RuntimeError):
    """Raised only before submitting credentials; browser fallback is permitted."""


# Complete static script shapes captured on 2026-10-24. This deliberately
# preserves comments, token boundaries, and newlines, including JS automatic
# semicolon insertion. A formatting-only revision may require browser fallback.
KNOWN_SCRIPTS = {
    'a41': '5452dc6e62d88061da9fc077dbada541e06a251b6f8befe2dea5f39d94d288d8',
    'a42': 'ae4961bfffb8f157af77b9461592d89928f149171c0020be11dc5c57f0bf40c9',
    'config': '919f88c5643cbb2b04698bb33ffddd041e5d56fb02a572ec9f78e062125fc2c1',
    'loginbox': 'b807a321ce7064a943f03effa6407d09e2bd371042f68eb1bd6d23d207a39d27',
}

KNOWN_INLINE_SCRIPTS = frozenset((
    # The original Windows HTML capture contains CRCRLF from text-mode writes,
    # which becomes double LF on read. Keep those reviewed fixture shapes.
    '327f73cf601b5124ee8db531075a77e043b3b4b4fd54651c7755e36cdfe3c2d9',
    'c8c9f0a3322246e8361863b0c76b9de8849e5bb2306742610531d17b8447fede',
    '40d1b693c95b2141b6250827577efd83e08565841f06b1d2689c7b39ebbd08d3',
    # Real wire HTML reviewed on 2026-10-27 uses ordinary CRLF. These three
    # complete bodies are otherwise byte-for-byte equal after removing only
    # the capture's duplicated blank lines. Do not normalize other whitespace:
    # newline changes can alter JavaScript automatic semicolon insertion.
    '1edeaaddea36cda20ae016c12b09287f3e0b21d5759b1061c3b9a38749cb014d',
    '6fb8074e42b8bd8fb86a666079822ae4a5bbb28e00a3eb34ea652a40c8361e60',
    '48bf99f808662debc98880fb3d5b0676e56fafd9a019fa745c1a73e56ade2b59',
))

MAX_SCRIPT_CHARS = 1024 * 1024
MAX_JSONP_BYTES = 64 * 1024
MAX_JSON_DEPTH = 32

JS_STRING = '''(?:"(?:ESC.|[^"ESC])*"|'(?:ESC.|[^'ESC])*')'''.replace('ESC', chr(92) * 2)


def _literal(value):
    """Read a JS string literal from a constrained configuration assignment."""
    if not isinstance(value, str) or len(value) < 2 or value[0] not in "'\"" or value[-1] != value[0]:
        raise UnsupportedPortal('门户字符串配置类型不匹配。')
    # This only recognizes string escapes, not JavaScript statements. Reject
    # Python-only/legacy escapes instead of silently giving them new semantics.
    converted, position = [value[0]], 1
    while position < len(value) - 1:
        ch = value[position]
        if ch in '\r\n':
            raise UnsupportedPortal('门户字符串包含未转义的换行。')
        if ch != '\\':
            converted.append(ch)
            position += 1
            continue
        escaped = value[position + 1]
        if escaped == '/':
            converted.append('/')
            position += 2
            continue
        if escaped in "\\'\"bfnrtv":
            width = 2
        elif escaped == '0' and not value[position + 2:position + 3].isdigit():
            width = 2
        elif escaped in ('x', 'u'):
            width = 4 if escaped == 'x' else 6
            if not re.fullmatch(r'[0-9a-fA-F]{' + str(width - 2) + r'}', value[position + 2:position + width]):
                raise UnsupportedPortal('门户字符串转义不受支持。')
        else:
            raise UnsupportedPortal('门户字符串转义不受支持。')
        converted.append(value[position:position + width])
        position += width
    converted.append(value[-1])
    try:
        result = ast.literal_eval(''.join(converted))
    except (ValueError, SyntaxError) as exc:
        raise UnsupportedPortal('门户字符串配置无法识别。') from exc
    if not isinstance(result, str):
        raise UnsupportedPortal('门户字符串配置类型不匹配。')
    try:
        result.encode('utf-8')
    except UnicodeError as exc:
        raise UnsupportedPortal('门户字符串包含不支持的Unicode转义。') from exc
    return result


def _body(text, marker):
    """Extract a known function's brace body without evaluating portal code."""
    try:
        start = text.index('{', text.index(marker))
    except ValueError as exc:
        raise UnsupportedPortal('门户脚本缺少已验证的认证逻辑。') from exc
    depth, position, string, escape, comment = 0, start, None, False, None
    while position < len(text):
        ch, pair = text[position], text[position:position + 2]
        if comment == 'line':
            if ch in '\r\n':
                comment = None
        elif comment == 'block':
            if pair == '*/':
                comment = None
                position += 1
        elif string:
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == string:
                string = None
        elif pair == '//':
            comment = 'line'
            position += 1
        elif pair == '/*':
            comment = 'block'
            position += 1
        elif ch in "'\"`":
            string = ch
        elif ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return text[start:position + 1]
        position += 1
    raise UnsupportedPortal('门户脚本结构不完整。')


def _fingerprint(body):
    try:
        normalized = body.replace('\r\n', '\n').replace('\r', '\n').encode('utf-8')
    except UnicodeError as exc:
        raise UnsupportedPortal('门户脚本包含不支持的Unicode内容。') from exc
    return hashlib.sha256(normalized).hexdigest()


def _script_fingerprint(text, kind):
    """Mask a narrow data grammar, then hash all remaining source verbatim.

    This is a template check, not a JavaScript parser. Any added statement,
    assignment, function replacement, or unrecognized syntax stays in the hash.
    """
    if not isinstance(text, str) or len(text) > MAX_SCRIPT_CHARS:
        raise UnsupportedPortal('门户脚本类型或大小不受支持。')
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    names = {
        'a41': ('jsVersion', 'accountSuffix', 'machineno', 'accountPrefix', 'enPerceive',
                'autoPerceive', 'eportalv6', 'enHttps', 'enMd5', 'enableR3', 'unBindmac', 'acLogout'),
        'config': ('pageSetting',),
        'loginbox': ('password_cut',),
        'a42': (),
    }.get(kind)
    if names is None:
        raise UnsupportedPortal('门户脚本种类无法识别。')
    for name in names:
        pattern = (r'(\bvar[ \t]+' + re.escape(name) + r'[ \t]*=[ \t]*)('
                   + JS_STRING + r'|[0-9]{1,16})([ \t]*;)')
        text, count = re.subn(pattern, lambda m: m[1] + '__LITERAL__' + m[3], text)
        if count != 1:
            raise UnsupportedPortal('门户配置定义不唯一或不是字面量：' + name)
    if kind == 'a41':
        pattern = (r'(\bvar\s+page\s*=\s*\{\s*kind\s*:\s*' + JS_STRING
                   + r'\s*,\s*name\s*:\s*)(' + JS_STRING + r')')
        text, count = re.subn(pattern, lambda m: m[1] + '__SITE_NAME__', text)
        if count != 1:
            raise UnsupportedPortal('门户方案定义无法识别。')
    elif kind == 'config':
        # Only one contiguous block of primitive IP rows is data. A second
        # block, an alias, a function call, or an expression remains unsupported.
        row = r'ipPageAry\[(?:0|[1-9]\d{0,3})\][ \t]*=[ \t]*' + JS_STRING + r'[ \t]*;[ \t]*(?:\n|$)'
        text, count = re.subn(r'(?m)^(?:[ \t]*' + row + r')+', '__IP_ROWS__\n', text)
        if count != 1:
            raise UnsupportedPortal('门户IP配置必须是单一连续的字面量数据区。')
    return _fingerprint(text)


def _verify(text, kind):
    observed = _script_fingerprint(text, kind)
    expected = KNOWN_SCRIPTS.get(kind)
    if observed != expected:
        core.trace('protocol.fingerprint_mismatch', level='WARNING', script_kind=kind,
                   expected_sha256=expected, observed_sha256=observed)
        raise UnsupportedPortal('门户认证脚本已变化，将使用原网页兼容流程。')


def _number(text, name):
    matches = re.findall(r'\bvar\s+' + re.escape(name) + r'\s*=\s*([0-9]{1,16})\s*;', text)
    if len(matches) != 1:
        raise UnsupportedPortal('门户数值配置无法识别：' + name)
    return int(matches[0])


def _string(text, name):
    matches = re.findall(r'\bvar\s+' + re.escape(name) + r'\s*=\s*(' + JS_STRING + r')\s*;', text)
    if len(matches) != 1:
        raise UnsupportedPortal('门户字符串配置无法识别：' + name)
    return _literal(matches[0])


def parse_jsonp(text):
    """Accept JSON or a single JSONP call, never generic success page text."""
    return _parse_jsonp(text)


def parse_status_jsonp(text):
    """Allow the kernel's repeated, identical top-level olno telemetry only.

    Live online status responses repeat this unused counter. Authentication
    responses and every other duplicate remain subject to parse_jsonp's
    strict rules; a conflicting or nested counter is never accepted.
    """
    return _parse_jsonp(text, allow_status_telemetry=True)


def _parse_jsonp(text, *, allow_status_telemetry=False):
    if not isinstance(text, str) or len(text) > MAX_JSONP_BYTES:
        return None
    try:
        if len(text.encode('utf-8')) > MAX_JSONP_BYTES:
            return None
    except UnicodeError:
        return None
    text = text.strip().lstrip('\ufeff')
    if text.startswith('{'):
        payload = text
    else:
        match = re.fullmatch(r'[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\s*\(\s*(\{.*\})\s*\)\s*;?', text, re.S)
        if not match:
            return None
        payload = match.group(1)
    # Bound nesting before the decoder allocates containers or reaches its
    # platform recursion limit. Brackets inside JSON strings are inert.
    depth, in_string, escaped = 0, False, False
    for ch in payload:
        if in_string:
            if escaped:
                escaped = False
            elif ch == '\\':
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in '{[':
            depth += 1
            if depth > MAX_JSON_DEPTH:
                return None
        elif ch in '}]':
            depth -= 1
    repeated_counter_objects = []
    def unique_object(pairs):
        result = {}
        repeated_counter = False
        for key, value in pairs:
            if key in result:
                if (allow_status_telemetry and key == 'olno'
                        and type(result[key]) is int and type(value) is int
                        and result[key] >= 0 and result[key] == value):
                    repeated_counter = True
                else:
                    raise ValueError('Duplicate JSON field')
            result[key] = value
        if repeated_counter:
            repeated_counter_objects.append(result)
        return result
    def finite_number(value):
        result = float(value)
        if not math.isfinite(result):
            raise ValueError('Non-finite JSON number')
        return result
    def reject_constant(value):
        raise ValueError('Non-JSON constant')
    try:
        data = json.loads(payload, object_pairs_hook=unique_object,
                          parse_float=finite_number, parse_constant=reject_constant)
    except (ValueError, TypeError, RecursionError):
        return None
    # object_pairs_hook runs from the leaves upward. Compare the actual object
    # identity after decoding to ensure the exception applies only to the root
    # status object, never to an identically named field in a nested container.
    if any(item is not data for item in repeated_counter_objects):
        return None
    return data if isinstance(data, dict) else None


def _result(data):
    if not isinstance(data, dict):
        return None
    value = data.get('result')
    if type(value) is int and value == 1 or isinstance(value, str) and value.casefold() in ('1', 'ok'):
        return True
    if type(value) is int and value == 0 or value == '0':
        return False
    return None


def decode_portal_message(value, ret_code):
    """Decode only the message branches encoded by the original portal script.

    This is presentation only: it never interprets an error number or changes
    the result. Callers must redact the returned text before displaying/logging.
    """
    if str(ret_code) not in ('1', '4') or not isinstance(value, str):
        return value
    try:
        raw = base64.b64decode(value, validate=True)
        if base64.b64encode(raw).decode('ascii') != value:
            return value
    except (ValueError, TypeError):
        return value
    for encoding in ('utf-8', 'gb18030'):
        try:
            text = raw.decode(encoding)
        except UnicodeError:
            continue
        if text.strip() and all(ch.isprintable() or ch in '\r\n\t' for ch in text):
            return text
    return value


def _session_account(value):
    """An identity reported by the server, never a selected/saved account."""
    if not isinstance(value, str) or len(value) > 128 or not value.isprintable():
        return ''
    value = value.strip()
    if not value or value == '12345678901234567890123456':
        return ''
    return value


def _session_mac(value):
    if not isinstance(value, str):
        return ''
    value = re.sub(r'[-:]', '', value.strip())
    if not re.fullmatch(r'[0-9A-Fa-f]{12}', value) or value == '000000000000':
        return ''
    return value.upper()


def _session_ip(value):
    if not isinstance(value, str):
        return ''
    try:
        address = ipaddress.IPv4Address(value.strip())
    except ipaddress.AddressValueError:
        return ''
    return '' if address.is_unspecified else str(address)


def _page_index(config, ip):
    if _number(config, 'pageSetting') != 2:
        raise UnsupportedPortal('当前门户不是已验证的IPv4分流配置。')
    rows = {}
    for match in re.finditer(r'\bipPageAry\[(\d+)\]\s*=\s*(' + JS_STRING + r')\s*;', config):
        index = int(match.group(1))
        if index in rows:
            raise UnsupportedPortal('门户存在重复分流配置。')
        rows[index] = _literal(match.group(2))
    if 0 not in rows:
        raise UnsupportedPortal('门户缺少默认分流配置。')
    current, selected = ipaddress.IPv4Address(ip), 0
    for index in sorted(rows):
        if not index or not rows[index]:
            continue
        parts = rows[index].split('|')
        if len(parts) < 6 or not parts[1] or not parts[2]:
            raise UnsupportedPortal('门户分流配置不完整。')
        starts, ends = parts[1].split(';'), parts[2].split(';')
        if len(starts) != len(ends):
            raise UnsupportedPortal('门户IP分流区间不成对。')
        # getMatchPage breaks only its INNER loop.  A later enabled matching
        # row overwrites an earlier row, so selecting the first would be wrong.
        try:
            matches = any(ipaddress.IPv4Address(begin) <= current <= ipaddress.IPv4Address(end)
                          for begin, end in zip(starts, ends))
        except ipaddress.AddressValueError as exc:
            raise UnsupportedPortal('门户IP分流区间无法识别。') from exc
        if parts[5] == '1' and matches:
            selected = index
    row = rows[selected].split('|')
    if len(row) < 6 or row[-1] != '1':
        raise UnsupportedPortal('当前网段不是已验证的Portal认证协议。')
    if row[3]:
        raise UnsupportedPortal('当前网段使用虚拟账号后缀，请使用原网页流程。')
    return selected


_BOOTSTRAP_FIELDS = frozenset(('sv', 'sv1', 'v6', 'myv6ip', 'v4serip', 'm46', 'v46ip',
                              'vid', 'mip', 'Gno', 'vlanid', 'AC', 'ipm', 'ss1', 'ss2',
                              'ss3', 'ss4', 'ss5', 'ss6', 'timet', 'osele', 'domain',
                              'zxopt', 'hidm', 'hidn', 'aolno'))
_ZERO_BOOTSTRAP_FIELDS = frozenset(('sv', 'sv1', 'm46', 'osele', 'zxopt', 'hidm', 'hidn'))


def _unsupported_active_content(tag, attrs):
    return (tag in ('base', 'object', 'embed', 'applet') or
            tag == 'meta' and (attrs.get('http-equiv') or '').strip().casefold() == 'refresh' or
            tag == 'iframe' and (attrs.get('src') or 'srcdoc' in attrs))


def _bootstrap_data(text, seen):
    """Recognize only the portal's primitive server-data assignment block."""
    position, found, delimiter = 0, False, ''
    assignment = re.compile(r'([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(' + JS_STRING + r'|[0-9]{1,32})\s*([,;])')
    while position < len(text):
        whitespace = re.match(r'\s+', text[position:])
        if whitespace:
            position += whitespace.end()
            continue
        if text.startswith('//', position):
            end = text.find('\n', position + 2)
            position = len(text) if end < 0 else end
            continue
        if text.startswith('/*', position):
            end = text.find('*/', position + 2)
            if end < 0:
                return False
            position = end + 2
            continue
        match = assignment.match(text, position)
        if not match:
            return False
        name, literal, delimiter = match.groups()
        if name not in _BOOTSTRAP_FIELDS or name in seen:
            return False
        value = _literal(literal) if literal[0] in "'\"" else int(literal)
        if name in _ZERO_BOOTSTRAP_FIELDS and value != 0:
            return False
        seen.add(name)
        found = True
        position = match.end()
    return found and delimiter == ';'


class _PageScripts(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts = []
        self.current = None
        self.blocked = False

    def handle_starttag(self, tag, attrs):
        if len(dict(attrs)) != len(attrs):
            self.blocked = True
        if any(name.lower().startswith('on') for name, _ in attrs):
            self.blocked = True
        if _unsupported_active_content(tag, dict(attrs)):
            self.blocked = True
        if tag == 'script':
            if self.current is not None or len(dict(attrs)) != len(attrs):
                self.blocked = True
            self.current = [dict(attrs), '']

    def handle_data(self, data):
        if self.current is not None:
            self.current[1] += data

    def handle_endtag(self, tag):
        if tag == 'script' and self.current is not None:
            self.scripts.append(self.current)
            self.current = None


def _verify_page_scripts(html):
    if not isinstance(html, str) or len(html) > MAX_SCRIPT_CHARS:
        raise UnsupportedPortal('门户页面类型或大小不受支持。')
    parser = _PageScripts()
    parser.feed(html)
    if parser.blocked or parser.current is not None:
        raise UnsupportedPortal('门户包含未知页面事件或不完整脚本。')
    loaded, inline, fields = set(), set(), set()
    for attrs, body in parser.scripts:
        if set(attrs) - {'type', 'src'} or (attrs.get('type') or '').casefold() not in ('', 'text/javascript', 'application/javascript'):
            raise UnsupportedPortal('门户包含未验证的脚本属性。')
        if 'src' in attrs:
            source = attrs['src']
            if source not in ('a41.js', 'a42.js') or source in loaded or body.strip():
                raise UnsupportedPortal('门户包含额外或重复的认证脚本。')
            loaded.add(source)
            continue
        fingerprint = _fingerprint(body)
        if fingerprint in KNOWN_INLINE_SCRIPTS:
            if fingerprint in inline:
                raise UnsupportedPortal('门户重复执行了页面脚本。')
            inline.add(fingerprint)
            # The known document.write fragment loads this exact resource.
            if 'document.write' in body:
                if 'a41.js' in loaded:
                    raise UnsupportedPortal('门户重复加载了认证脚本。')
                loaded.add('a41.js')
        elif not _bootstrap_data(body, fields):
            raise UnsupportedPortal('门户包含未知内联认证逻辑。')
    if 'a41.js' not in loaded:
        raise UnsupportedPortal('门户缺少已验证的认证脚本入口。')


class _Form(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_select = False
        self.option = None
        self.options = []
        self.blocked = False
        self.inputs = set()

    def handle_starttag(self, tag, attrs):
        if len(dict(attrs)) != len(attrs):
            self.blocked = True
        attrs = dict(attrs)
        for name, value in attrs.items():
            if name.startswith('on') and not (tag == 'form' and name == 'onsubmit' and
                    re.fullmatch(r'\s*return\s+ee\(\s*3\s*\)\s*;?\s*', value or '')):
                self.blocked = True
            if name in ('href', 'src', 'action') and (value or '').strip().casefold().startswith('javascript:'):
                self.blocked = True
        if tag == 'script' or _unsupported_active_content(tag, attrs) or (tag == 'form' and attrs.get('action')):
            self.blocked = True
        if tag == 'select':
            self.in_select = attrs.get('name') == 'ISP_select'
        elif tag == 'option' and self.in_select:
            self.option = {'value': attrs.get('value', ''), 'text': ''}
        elif tag == 'input':
            self.inputs.add(attrs.get('name', ''))
            if attrs.get('name') in ('captcha', 'C1', 'authorize') or (
                    (attrs.get('type') or '').lower() in ('checkbox', 'radio') and 'required' in attrs):
                self.blocked = True

    def handle_data(self, data):
        if self.option is not None:
            self.option['text'] += data

    def handle_endtag(self, tag):
        if tag == 'option' and self.option is not None:
            self.options.append(self.option)
            self.option = None
        elif tag == 'select':
            self.in_select = False


def _form_options(script):
    if not re.fullmatch(r'\s*var\s+bodyContent\s*=\s*' + JS_STRING + r'\s*;\s*', script):
        raise UnsupportedPortal('门户表单带有未识别的附加脚本。')
    html = _string(script, 'bodyContent')
    if re.search(r'<script\b', html, re.I):
        raise UnsupportedPortal('门户表单包含自定义脚本，需原网页流程。')
    parser = _Form()
    parser.feed(html)
    if parser.blocked or not {'DDDDD', 'upass'}.issubset(parser.inputs):
        raise UnsupportedPortal('门户包含验证码、条款或未识别表单，请使用原网页。')
    options = {}
    labels = {'campus': ('校园网', '校园用户', '校内'), 'telecom': ('电信', 'telecom'),
              'unicom': ('联通', 'unicom'), 'cmcc': ('移动', 'cmcc')}
    for operator, names in labels.items():
        found = [option['value'] for option in parser.options
                 if any(name in (option['text'] + ' ' + option['value']).lower() for name in names)]
        if len(found) == 1:
            options[operator] = found[0]
    return options, bool(parser.options)


def _portal_parameters(url):
    """Recognize only query values whose meaning matches legacy unescape().

    The captured getQueryString has an early return even for an absent/empty
    first alias. It does not proceed to acip/sysname/vlanid. Do not repair that
    school-script behavior implicitly, or choose one of duplicate values.
    """
    critical = {'wlanacip', 'acip', 'wlanacname', 'sysname', 'vlan', 'vlanid'}
    values = {}
    for field in urlsplit(url).query.split('&'):
        pairs = parse_qsl(field, keep_blank_values=True)
        if not pairs:
            continue
        key, value = pairs[0]
        key = key.casefold()
        if key not in critical:
            continue
        raw_value = field.partition('=')[2]
        if key in values or '+' in raw_value or '%' in value or any(not 32 <= ord(ch) < 127 for ch in value):
            raise UnsupportedPortal('门户AC或VLAN参数重复或编码含义不明确，请使用原网页流程。')
        values[key] = value
    return values


class Engine:
    """One current WiFi/portal context; no persistent credentials or cookies."""
    def __init__(self, wifi, portal, reader=None, allow_tec=False, getter=None):
        self.wifi = wifi
        self.reader = reader if reader is not None else core.read_wifi
        self.allow_tec = allow_tec
        self.getter = getter if getter is not None else core.fetch
        self.portal = core.fresh_url(portal, wifi)
        self.origin = core.portal_origin(self.portal)
        self._plan = None
        self._key = wifi.key

    def _guard(self):
        if self.wifi.key != self._key:
            raise RuntimeError('WiFi上下文已改变，已停止认证。')
        core.guard(self.wifi, self.reader(), self.allow_tec)

    def _get(self, url):
        self._guard()
        core.portal_origin(url)
        if urlsplit(url).hostname != urlsplit(self.portal).hostname:
            raise UnsupportedPortal('门户资源跨主机，需原网页确认。')
        return self.getter(url, self.wifi, reader=self.reader, allow_tec=self.allow_tec)

    def _resource(self, url):
        try:
            status, location, text = self._get(url)
        except (OSError, ValueError, http.client.HTTPException) as exc:
            if isinstance(exc, OSError):
                error = core.network_error_details(exc)
                if error.get('code') == 'permission_denied':
                    # A local transport denial cannot be repaired by executing
                    # the same page through another authentication backend.
                    raise core.PortalNetworkError(exc) from exc
            raise UnsupportedPortal('门户资源暂不可读取，将使用原网页兼容流程。') from exc
        if status != 200 or location or not isinstance(text, str) or len(text) > MAX_SCRIPT_CHARS:
            raise UnsupportedPortal('门户资源读取失败，将使用原网页兼容流程。')
        return text

    def status(self):
        """Read real kernel status for this WiFi; no credentials are required."""
        started = time.monotonic()
        result = {'state': 'unknown', 'matched_ip': False, 'detail': 'status_unconfirmed',
                  'online_account': '', 'identity_hint': '', 'server_ip': '', 'server_mac': '',
                  'binding': 'unconfirmed', 'ip_conflict': False, 'mac_conflict': False}
        url = self.origin + '/drcom/chkstatus?' + urlencode({'callback': 'campus_status', '_': time.time_ns()})
        try:
            status, location, text = self._get(url)
            data = parse_status_jsonp(text) if status == 200 and not location else None
            core.trace('protocol.status_response',status=status,
                       response_fields=sorted(data) if data else [],recognized=data is not None)
            if data is None:
                result['detail'] = 'unrecognized_status_response'
            else:
                evidence = _result(data)
                if evidence is True:
                    result['online_account'] = _session_account(data.get('uid'))
                    base=result['online_account'].split('@',1)[0]
                    result['identity_hint']=('***'+base[-4:]) if len(base)>4 else ('***' if base else '')
                server_ip = _session_ip(data.get('olip'))
                reported_macs = [mac for key in ('olmac', 'ss4')
                                 if (mac := _session_mac(data.get(key)))]
                current_mac = _session_mac(self.wifi.mac)
                mac_conflict = bool(current_mac and any(mac != current_mac for mac in reported_macs))
                mac_matches = bool(current_mac and reported_macs and not mac_conflict)
                ip_conflict = bool(server_ip and server_ip != self.wifi.ip)
                result.update(server_ip=server_ip, server_mac=next(iter(reported_macs), ''),
                              mac_conflict=mac_conflict, ip_conflict=ip_conflict)
                ips = [data[key] for key in ('v46ip', 'ss5') if key in data]
                matched = bool(ips) and all(isinstance(value, str) and value.strip() == self.wifi.ip
                                            for value in ips)
                result['matched_ip'] = matched
                if mac_conflict:
                    result.update(detail='session_mac_mismatch', binding='conflict')
                elif not matched:
                    result['detail'] = 'status_ip_mismatch'
                elif evidence is True and ip_conflict and not mac_matches:
                    # v46ip/ss5 may echo the requester. A different online IP
                    # without matching MAC evidence cannot identify this device.
                    result.update(detail='session_ip_mismatch', binding='conflict')
                else:
                    if evidence is not None:
                        result.update(state='online' if evidence else 'offline', detail='server_confirmed',
                                      binding='mac_verified' if mac_matches else 'source_ip_only')
        except (OSError, ValueError, http.client.HTTPException) as exc:
            if isinstance(exc, (OSError, http.client.HTTPException)):
                result['network_error'] = core.network_error_details(exc)
            core.trace('protocol.status_error',level='WARNING',_exception=exc,error_type=type(exc).__name__,
                       error=str(exc),network_error=result.get('network_error',{}))
            result['detail'] = 'status_unreachable'
        result['elapsed_ms'] = round((time.monotonic() - started) * 1000)
        core.trace('protocol.status_result',result=result)
        return result

    def prepare(self):
        """Validate official scripts and derive the actual IP-selected plan."""
        self._guard()
        if self._plan is not None:
            return dict(self._plan)
        html = self._resource(self.portal)
        if 'Dr.COMWebLoginID_' not in html or not re.search(r'\ba41\.js\b', html):
            raise UnsupportedPortal('当前页面不是已验证的Dr.COM门户。')
        _verify_page_scripts(html)
        a41 = self._resource(urljoin(self.portal, 'a41.js'))
        _verify(a41, 'a41')
        for name in ('accountPrefix', 'enPerceive', 'autoPerceive', 'eportalv6', 'enHttps', 'enMd5', 'enableR3', 'unBindmac'):
            if _number(a41, name) != 0:
                raise UnsupportedPortal('门户开启了需原网页执行的认证选项：' + name)
        if _string(a41, 'accountSuffix') or _string(a41, 'machineno'):
            raise UnsupportedPortal('门户使用额外账号后缀，需原网页流程。')
        if not re.search(r"eportal\s*:\s*window\.location\.protocol\s*\+\s*'//'\s*\+\s*window\.location\.hostname\s*\+\s*':801/eportal/'", a41):
            raise UnsupportedPortal('门户认证入口定义无法识别。')
        name_match = re.search(r'\bvar\s+page\s*=\s*\{\s*kind\s*:\s*' + JS_STRING + r'\s*,\s*name\s*:\s*(' + JS_STRING + r')', a41)
        if not name_match:
            raise UnsupportedPortal('门户方案编号无法识别。')
        name = _literal(name_match.group(1))
        if not re.fullmatch(r'[\w-]{1,64}', name):
            raise UnsupportedPortal('门户方案编号不合法。')
        parts = urlsplit(self.portal)
        eportal = urlunsplit((parts.scheme, parts.hostname + ':801', '/eportal/', '', ''))
        program = eportal + 'extern/' + name + '/'
        config = self._resource(program + 'config.js')
        _verify(config, 'config')
        index = _page_index(config, self.wifi.ip)
        loginbox = self._resource(program + 'ip/' + str(index) + '/loginbox.js')
        _verify(loginbox, 'loginbox')
        if _number(loginbox, 'password_cut') != 0:
            raise UnsupportedPortal('门户需密码转换，请使用原网页流程。')
        page_script = self._resource(program + 'ip/' + str(index) + '/pc.js')
        operators, has_select = _form_options(page_script)
        a42 = self._resource(urljoin(self.portal, 'a42.js'))
        _verify(a42, 'a42')
        query = _portal_parameters(self.portal)
        # Match the original helper's first-alias-only behavior. NAS IP is not
        # substituted for AC IP; they mean different things.
        vlan = query.get('vlan', '')
        if not vlan:
            vlan_match = re.search(r'\bvlanid\s*=\s*(' + JS_STRING + r'|\d+)', html)
            vlan = _literal(vlan_match.group(1)) if vlan_match and vlan_match.group(1)[0] in "'\"" else vlan_match.group(1) if vlan_match else '1'
        self._plan = {'page_index': index, 'login_method': '1', 'endpoint': eportal,
                      'js_version': _string(a41, 'jsVersion'), 'operators': operators,
                      'has_operator_select': has_select, 'ac_logout': str(_number(a41, 'acLogout')),
                      'ac_ip': query.get('wlanacip', ''), 'ac_name': query.get('wlanacname', ''),
                      'vlan': vlan, 'ipv6': '', 'plan_key': self._key}
        core.trace('protocol.plan_validated',plan=self._plan)
        return dict(self._plan)

    @staticmethod
    def _redact(value, account, password):
        text = str(value)
        values = set()
        for secret in (account, password):
            if secret:
                values.update((secret, quote(secret, safe=''), quote_plus(secret),
                               base64.b64encode(secret.encode()).decode(),
                               base64.urlsafe_b64encode(secret.encode()).decode()))
        for secret in sorted(values, key=len, reverse=True):
            text = text.replace(secret, '[已隐藏]')
        # Keep complete encoded values until the application's comprehensive
        # diagnostic filter runs. Truncation here can expose a secret prefix.
        return re.sub(r'https?://[^\s]+', '[认证地址]', text)

    def authenticate(self, account, password, operator, operation='login', before_submit=None):
        started = time.monotonic()
        if operation not in ('login', 'logout'):
            raise ValueError('operation must be login or logout')
        plan = self.prepare()  # Any unsupported-page fallback occurs BEFORE submission.
        # Preflight and submission may share one plan, but a later operation
        # must re-read the server scripts even when the WiFi/IP is unchanged.
        self._plan = None
        self._guard()
        params = {'c': 'Portal', 'a': operation, 'callback': 'dr' + str(time.time_ns()),
                  'login_method': plan['login_method'], 'wlan_user_ip': self.wifi.ip,
                  'wlan_user_mac': re.sub(r'[-:]', '', self.wifi.mac),
                  'wlan_ac_ip': plan['ac_ip'], 'wlan_ac_name': plan['ac_name'],
                  'jsVersion': plan['js_version']}
        if operation == 'login':
            if not account or not password:
                raise ValueError('请输入账号和密码。')
            if operator:
                if operator not in plan['operators']:
                    raise UnsupportedPortal('页面运营商与配置不匹配，需原网页流程。')
                suffix = plan['operators'][operator]
            elif plan['has_operator_select']:
                raise UnsupportedPortal('页面要求明确选择运营商，需原网页流程。')
            else:
                suffix = ''
            params.update(user_account=account + suffix, user_password=password)
        else:
            # These dummy values are the original official logout implementation,
            # not a user account and password.  No saved secret is needed to logout.
            params.update(user_account='drcom', user_password='123', ac_logout=plan['ac_logout'],
                          wlan_user_ipv6=plan['ipv6'], wlan_vlan_id=plan['vlan'])
        if before_submit is not None:
            before_submit()
        self._guard()
        trace = {'operation': operation, 'transport': 'verified_drcom_http', 'phase': 'submitting',
                 'endpoint': core.safe_summary(plan['endpoint']), 'authentication_requests': 1,
                 'parameter_names': list(params), 'page_index': plan['page_index']}
        core.trace('protocol.submission',operation=operation,endpoint=core.safe_summary(plan['endpoint']),
                   parameter_names=list(params),page_index=plan['page_index'])
        # From here onward, even a timeout can mean the server received the
        # request.  Return inconclusive evidence; NEVER fall back and resubmit.
        try:
            status, location, text = self._get(plan['endpoint'] + '?' + urlencode(params))
            self._guard()
            data = parse_jsonp(text) if status == 200 and not location else None
            result = _result(data)
            trace.update(phase='response_received' if result is not None else 'response_unconfirmed',
                         http_status=status, result=result)
            if data is not None:
                trace['response'] = {key: self._redact(
                                     decode_portal_message(data[key], data.get('ret_code'))
                                     if key == 'msg' else data[key], account, password)
                                     for key in ('result', 'ret_code', 'msg', 'message') if key in data}
        except Exception as exc:
            if isinstance(exc, (OSError, http.client.HTTPException)):
                trace['network_error'] = core.network_error_details(exc)
            core.trace('protocol.authentication_error',level='ERROR',_exception=exc,
                       operation=operation,error_type=type(exc).__name__,network_error=trace.get('network_error',{}))
            trace.update(phase='response_unconfirmed', error=type(exc).__name__)
            result = None
        trace['elapsed_ms'] = round((time.monotonic() - started) * 1000)
        core.trace('protocol.authentication_result',result=trace)
        return result, trace
