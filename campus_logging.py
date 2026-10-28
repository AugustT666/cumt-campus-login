"""Bounded, secret-aware runtime diagnostics; depends only on the standard library.

The data root is supplied by the application, so the same module works in a frozen
EXE.  No settings, credential files, network interfaces, or process hooks are read.
Logging is best effort; explicit diagnostic export may raise an ordinary IO error.
"""
from __future__ import annotations

import base64
from collections import deque
import datetime as dt
import hashlib
import html
import json
import os
from pathlib import Path
import re
import threading
import time
import traceback
from urllib.parse import parse_qsl, quote, quote_plus, urlencode, urlsplit, urlunsplit
import uuid
import zipfile


REDACTED = "[REDACTED]"
_LOG_NAME = re.compile(r"^run-(\d{8}T\d{12}Z-\d+-[0-9a-f]{12})\.jsonl(?:\.(\d+))?$")
_URL = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s<>\"']+")
_HTML = re.compile(r"(?is)<\s*(?:!doctype\s+html|html\b|head\b|body\b|form\b|input\b|script\b)")
_SENSITIVE_PARTS = (
    "password", "passwd", "passphrase", "token", "cookie", "authorization",
    "useraccount", "ddddd", "upass", "account", "username", "credential",
    "secret", "apikey", "privatekey", "sessionid", "sessionkey",
)
_RAW_KEYS = {
    "body", "requestbody", "responsebody", "authbody", "html", "rawhtml",
    "rawresponse", "responsetext", "requestdata", "formdata", "payload",
    "portalhtml", "portaltext", "rawcapture", "raw", "headers",
}
_TEXT_KEYS = (
    r"user[_-]?account|user[_-]?name|user[_-]?id|login[_-]?name|user|uid|ddddd|upass|password|passwd|"
    r"passphrase|(?:access[_-]?|refresh[_-]?|id[_-]?)?token|"
    r"(?:set[_-]?)?cookie|authorization|proxy[_-]?authorization|"
    r"account|credentials?|secret|api[_-]?key|session[_-]?(?:id|key)"
)
_KEY_VALUE = re.compile(
    rf"(?i)(?P<prefix>[\"']?(?:{_TEXT_KEYS})[\"']?\s*[:=]\s*)"
    r"(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;&}\]]+)"
)
_AUTH_HEADER = re.compile(
    r"(?im)\b(?:set-cookie|cookie|authorization|proxy-authorization)\s*:\s*[^\r\n]*"
)


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def _normal_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.casefold())


def _sensitive_key(key: str) -> bool:
    normal = _normal_key(key)
    return normal in {"uid", "userid", "user", "login", "loginname", "pwd", "pass", "auth", "dpassword", "dpass"} or any(
        part in normal for part in _SENSITIVE_PARTS
    ) or normal in _RAW_KEYS or "html" in normal or normal.endswith("body")


def _missing_ranges(sequences: set[int], last_seq: int) -> list[list[int]]:
    """Represent gaps compactly, without allocating a range as large as the log."""
    missing = []
    previous = 0
    for number in sorted(n for n in sequences if 0 < n <= last_seq):
        if number > previous + 1:
            missing.append([previous + 1, number - 1])
        previous = number
    if previous < last_seq:
        missing.append([previous + 1, last_seq])
    return missing


class RuntimeLog:
    """One process run, one unique session, serialized JSONL writes.

    ``max_backup_count`` is the number of rotation files in addition to the
    current file. ``session_limit`` includes this session. ``retention_bytes``
    caps both retained historical logs and bytes of logs in one export. An
    individual record may exceed the rotation threshold; export still obeys its
    hard byte budget. Files are opened only for individual operations.
    """

    def __init__(self, root: Path, version: str, metadata: dict | None = None, *,
                 max_bytes: int = 5 * 1024 * 1024, max_backup_count: int = 3,
                 session_limit: int = 8, retention_bytes: int = 50 * 1024 * 1024):
        self.root = Path(root)
        self.version = str(version)
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        self._session_id = f"{stamp}-{os.getpid()}-{uuid.uuid4().hex[:12]}"
        self.logs_dir = self.root / "logs"
        self._path = self.logs_dir / f"run-{self._session_id}.jsonl"
        self.max_bytes = max(1, int(max_bytes))
        self.max_backup_count = max(0, int(max_backup_count))
        self.session_limit = max(1, int(session_limit))
        self.retention_bytes = max(1, int(retention_bytes))
        self._lock = threading.RLock()
        self._secrets: set[str] = set()
        self._ordered_secrets: tuple[str, ...] = ()
        self._ordered_percent_secrets: tuple[str, ...] = ()
        self._started = time.monotonic_ns()
        self._seq = 0
        self._closed = False
        self._write_error = ""
        self._io_errors: deque[str] = deque(maxlen=16)
        self._write_failures = 0
        self._rotations = 0
        self._dropped_rotation_bytes = 0
        self._fallback: deque[dict] = deque(maxlen=128)
        self._fallback_evicted = 0
        self.event("session_started", metadata=metadata or {}, pid=os.getpid())
        with self._lock:
            self._prune()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def write_error(self) -> str:
        with self._lock:
            return self._sanitize_text(self._write_error)

    def register_secrets(self, *values) -> None:
        """Register values and common encodings; values never enter diagnostics."""
        with self._lock:
            for value in values:
                if value is None:
                    continue
                secret = str(value)
                if not secret:
                    continue
                variants = {secret, html.escape(secret, quote=True)}
                for encoding in ("utf-8", "utf-16-le"):
                    raw = secret.encode(encoding, errors="replace")
                    variants.update((base64.b64encode(raw).decode("ascii"),
                                     base64.urlsafe_b64encode(raw).decode("ascii")))
                variants.update(v.rstrip("=") for v in list(variants) if v.endswith("="))
                variants.update((quote(secret, safe=""), quote_plus(secret, safe=""),
                                 json.dumps(secret, ensure_ascii=True)[1:-1],
                                 json.dumps(secret, ensure_ascii=False)[1:-1],
                                 secret.encode("unicode_escape").decode("ascii")))
                for variant in list(variants):
                    variants.add(quote(variant, safe=""))
                    variants.add(quote_plus(variant, safe=""))
                    variants.add(re.sub(r"%[0-9A-F]{2}", lambda m: m[0].lower(), variant))
                    variants.add(variant.replace("\\", "\\\\"))
                self._secrets.update(v for v in variants if v)
            self._ordered_secrets = tuple(sorted(self._secrets, key=len, reverse=True))
            self._ordered_percent_secrets = tuple(sorted({
                self._normalize_percent(value) for value in self._secrets if "%" in value
            }, key=len, reverse=True))

    @staticmethod
    def _normalize_percent(value: str) -> str:
        # Hex digits in URL escapes are case insensitive, independently for
        # every escape; literal password letters must remain case sensitive.
        return re.sub(r"%[0-9a-fA-F]{2}", lambda match: match[0].upper(), value)

    def _replace_secrets(self, text: str) -> str:
        for secret in self._ordered_secrets:
            text = text.replace(secret, REDACTED)
        if "%" in text:
            text = self._normalize_percent(text)
            for secret in self._ordered_percent_secrets:
                text = text.replace(secret, REDACTED)
        return text

    def _html_safe_exception(self, exc, seen=None, depth=0) -> str:
        """Rebuild stack frames separately from HTML-bearing exception text.

        Sanitizing one combined traceback as HTML would discard all its frames.
        Conversely, line-by-line message filtering can leak text between HTML
        tags. Only stack objects supply frame content here; the entire exception
        message is sanitized as one value, including multiline HTML.
        """
        seen = set() if seen is None else seen
        if id(exc) in seen or depth > 24:
            return "[EXCEPTION_CHAIN_LIMIT]\n"
        seen.add(id(exc))
        parts = []
        cause = getattr(exc, "__cause__", None)
        context = getattr(exc, "__context__", None)
        if cause is not None:
            parts.append(self._html_safe_exception(cause, seen, depth + 1))
            parts.append("\nThe above exception was the direct cause of the following exception:\n\n")
        elif context is not None and not getattr(exc, "__suppress_context__", False):
            parts.append(self._html_safe_exception(context, seen, depth + 1))
            parts.append("\nDuring handling of the above exception, another exception occurred:\n\n")
        frames = traceback.extract_tb(exc.__traceback__)
        if frames:
            parts.append("Traceback (most recent call last):\n")
        for frame in frames:
            parts.append(self._sanitize_text(f'  File "{frame.filename}", line {frame.lineno}, in {frame.name}') + "\n")
            if frame.line:
                parts.append("    " + self._sanitize_text(frame.line) + "\n")
        exception_type = type(exc).__qualname__
        try:
            message = self._sanitize_text(str(exc))
        except Exception:
            message = "[unprintable exception]"
        parts.append(f"{exception_type}: {message}\n")
        # Preserve contained stacks when Python reports an ExceptionGroup.
        for index, child in enumerate(getattr(exc, "exceptions", ())):
            parts.append(f"\nContained exception {index + 1}:\n")
            parts.append(self._html_safe_exception(child, seen, depth + 1))
        return "".join(parts)

    def _sanitize_url(self, match: re.Match) -> str:
        raw = match[0]
        try:
            url = urlsplit(raw)
            host = url.netloc.rsplit("@", 1)[-1]
            query = [(key, REDACTED if _sensitive_key(key) else self._replace_secrets(value))
                     for key, value in parse_qsl(url.query, keep_blank_values=True)]
            fragment = url.fragment
            if "=" in fragment:
                fragment = urlencode([(key, REDACTED if _sensitive_key(key) else self._replace_secrets(value))
                                      for key, value in parse_qsl(fragment, keep_blank_values=True)])
            elif fragment:
                fragment = self._replace_secrets(fragment)
            return urlunsplit((url.scheme, host, self._replace_secrets(url.path),
                               urlencode(query), fragment))
        except (ValueError, UnicodeError):
            return "[REDACTED_URL]"

    def _sanitize_text(self, value: str) -> str:
        if _HTML.search(value):
            return "[REDACTED_HTML]"
        text = self._replace_secrets(value)
        # JSON encoded inside an exception or message is still structured data.
        # Parsing it also exposes escaped URL separators and Unicode key names.
        if text.lstrip().startswith(("{", "[")):
            try:
                parsed = json.loads(text)
                if isinstance(parsed, (dict, list)):
                    return json.dumps(self._sanitize(parsed, set(), 0), ensure_ascii=False, allow_nan=False)
            except (ValueError, TypeError, RecursionError):
                pass
        text = text.replace("\\/", "/")
        text = _AUTH_HEADER.sub(lambda m: m[0].split(":", 1)[0] + ": " + REDACTED, text)
        text = _URL.sub(self._sanitize_url, text)
        text = _KEY_VALUE.sub(lambda m: m["prefix"] + REDACTED, text)
        return self._replace_secrets(text)

    def sanitize(self, value):
        """Return detached, JSON-serializable, recursively redacted diagnostics."""
        with self._lock:
            return self._sanitize(value, set(), 0)

    def _sanitize(self, value, seen: set[int], depth: int):
        if depth > 24:
            return "[MAX_DEPTH]"
        if value is None or isinstance(value, (bool, int)):
            return value
        if isinstance(value, float):
            return value if value == value and abs(value) != float("inf") else str(value)
        if isinstance(value, str):
            return self._sanitize_text(value)
        if isinstance(value, (bytes, bytearray, memoryview)):
            return "[REDACTED_BINARY]"
        if id(value) in seen:
            return "[CIRCULAR]"
        if isinstance(value, (dict, list, tuple, set, frozenset)):
            seen.add(id(value))
            try:
                if isinstance(value, dict):
                    result = {}
                    for key, item in value.items():
                        key = str(key)
                        clean_key = self._sanitize_text(key)
                        result[clean_key] = REDACTED if _sensitive_key(key) else self._sanitize(item, seen, depth + 1)
                    return result
                return [self._sanitize(item, seen, depth + 1) for item in value]
            finally:
                seen.discard(id(value))
        try:
            return self._sanitize_text(str(value))
        except Exception:
            return "[UNPRINTABLE]"

    def _remember_error(self, action: str, exc: Exception) -> None:
        message = self._sanitize_text(f"{action}: {type(exc).__name__}: {exc}")
        self._write_error = message
        self._io_errors.append(message)

    def _matching_files(self) -> dict[str, list[Path]]:
        sessions: dict[str, list[Path]] = {}
        if not self.logs_dir.is_dir() or self.logs_dir.is_symlink():
            return sessions
        for path in self.logs_dir.iterdir():
            match = _LOG_NAME.fullmatch(path.name)
            if match and path.is_file() and not path.is_symlink():
                sessions.setdefault(match[1], []).append(path)
        return sessions

    def _prune(self) -> None:
        try:
            sessions = self._matching_files()
            ordered = [self._session_id] + sorted((s for s in sessions if s != self._session_id), reverse=True)
            used = 0
            for index, session in enumerate(ordered):
                paths = sessions.get(session, [])
                size = sum(p.stat().st_size for p in paths)
                keep = session == self._session_id or (index < self.session_limit and used + size <= self.retention_bytes)
                if keep:
                    used += size
                else:
                    for path in paths:
                        path.unlink(missing_ok=True)
        except OSError as exc:
            self._remember_error("retention", exc)

    def _rotate(self) -> None:
        if self.max_backup_count:
            last = Path(str(self._path) + f".{self.max_backup_count}")
            if last.exists():
                self._dropped_rotation_bytes += last.stat().st_size
                last.unlink()
            for index in range(self.max_backup_count - 1, 0, -1):
                source = Path(str(self._path) + f".{index}")
                if source.exists():
                    source.replace(Path(str(self._path) + f".{index + 1}"))
            self._path.replace(Path(str(self._path) + ".1"))
        else:
            self._dropped_rotation_bytes += self._path.stat().st_size
            self._path.unlink()
        self._rotations += 1
        self._prune()

    def event(self, name, level="INFO", operation_id="", **fields) -> None:
        with self._lock:
            if self._closed:
                return
            self._seq += 1
            try:
                record = {
                    "timestamp": _utc_now(), "elapsed_ms": (time.monotonic_ns() - self._started) // 1_000_000,
                    "seq": self._seq, "session_id": self._session_id, "version": self._sanitize_text(self.version),
                    "event": self._sanitize_text(str(name)), "level": self._sanitize_text(str(level)),
                    "operation_id": self._sanitize_text(str(operation_id)),
                    "fields": self._sanitize(fields, set(), 0),
                }
                data = (json.dumps(record, ensure_ascii=False, allow_nan=False, separators=(",", ":")) + "\n").encode("utf-8")
                self.logs_dir.mkdir(parents=True, exist_ok=True)
                if self.logs_dir.is_symlink() or self._path.is_symlink():
                    raise OSError("Refusing linked log location")
                if self._path.exists() and self._path.stat().st_size and self._path.stat().st_size + len(data) > self.max_bytes:
                    self._rotate()
                with self._path.open("ab") as stream:
                    stream.write(data)
                    stream.flush()
            except Exception as exc:
                self._write_failures += 1
                self._remember_error("write", exc)
                if "record" in locals():
                    if len(self._fallback) == self._fallback.maxlen:
                        self._fallback_evicted += 1
                    self._fallback.append(record)

    def exception(self, name, exc, operation_id="", **fields) -> None:
        with self._lock:
            try:
                formatted = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
                if _HTML.search(formatted):
                    formatted = self._html_safe_exception(exc)
            except Exception:
                formatted = f"{type(exc).__name__}: [unprintable exception]"
            fields = dict(fields)
            fields["exception_type"] = type(exc).__name__
            fields["traceback"] = formatted
            self.event(name, level="ERROR", operation_id=operation_id, **fields)

    def flush(self) -> None:
        with self._lock:
            try:
                if self._path.is_file() and not self._path.is_symlink():
                    with self._path.open("ab") as stream:
                        stream.flush()
                        os.fsync(stream.fileno())
            except OSError as exc:
                self._remember_error("flush", exc)

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self.event("session_closed", emitted_before_close=self._seq)
                self.flush()
                self._closed = True

    @staticmethod
    def _json_bytes(value) -> bytes:
        return (json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2) + "\n").encode("utf-8")

    def export_bundle(self, snapshot: dict, destination_dir: Path | None = None) -> Path:
        """Export an allowlist of sanitized logs, snapshot, README and manifest.

        No recursive directory copying is performed. The manifest names every
        included fragment and reports missing sequence ranges and byte limits.
        The current session has first claim on the byte budget. Re-sanitization
        also protects old fragments using secrets registered during this run.
        """
        with self._lock:
            self.flush()
            self._prune()
            payloads: dict[str, bytes] = {}
            entries = []
            sessions_info = []
            excluded = []
            used = 0
            try:
                sessions = self._matching_files()
            except OSError as exc:
                self._remember_error("list_for_export", exc)
                sessions = {}
            ordered = [self._session_id] + sorted((s for s in sessions if s != self._session_id), reverse=True)
            for session_index, session in enumerate(ordered):
                paths = sessions.get(session, [])
                if session_index >= self.session_limit:
                    excluded.append({"session_id": session, "reason": "session_limit"})
                    continue
                sequences: set[int] = set()
                observed_last_seq = self._seq if session == self._session_id else 0
                session_info = {"session_id": session, "available_file_count": len(paths), "included_file_count": 0}
                # Newest records take priority when a user injects a small budget.
                paths.sort(key=lambda p: int(_LOG_NAME.fullmatch(p.name)[2] or 0))
                for path in paths:
                    if used >= self.retention_bytes:
                        excluded.append({"file": path.name, "reason": "byte_limit"})
                        continue
                    try:
                        raw_size = path.stat().st_size
                        # Retain only a bounded tail even for an externally oversized file.
                        read_limit = self.retention_bytes - used
                        with path.open("rb") as stream:
                            offset = max(0, raw_size - read_limit)
                            stream.seek(offset)
                            raw = stream.read(min(read_limit, raw_size - offset))
                        truncated = offset > 0
                        if offset:
                            _, _, raw = raw.partition(b"\n")
                        rows = []
                        line_sequences = []
                        invalid_lines = 0
                        for line in raw.splitlines():
                            try:
                                record = json.loads(line)
                                if not isinstance(record, dict):
                                    raise ValueError("JSONL record is not an object")
                                # Sanitizing the original object would redact the schema's
                                # session_id; only public diagnostic contents are filtered.
                                clean = self._sanitize(record, set(), 0)
                                if record.get("session_id") == session:
                                    clean["session_id"] = session
                                number = record.get("seq")
                                line_sequences.append(number if type(number) is int and number > 0 else None)
                                if type(number) is int and number > 0:
                                    observed_last_seq = max(observed_last_seq, number)
                                rows.append((json.dumps(clean, ensure_ascii=False, allow_nan=False, separators=(",", ":")) + "\n").encode("utf-8"))
                            except (ValueError, TypeError, UnicodeError):
                                # Never carry unparseable raw material into diagnostics.
                                invalid_lines += 1
                        # Redaction markers can expand short values. Drop whole oldest
                        # records, preserving valid JSONL and matching sequence accounting.
                        total_bytes = sum(map(len, rows))
                        first = 0
                        while first < len(rows) and total_bytes > self.retention_bytes - used:
                            total_bytes -= len(rows[first])
                            first += 1
                            truncated = True
                        rows = rows[first:]
                        line_sequences = [number for number in line_sequences[first:] if number is not None]
                        data = b"".join(rows)
                        archive_name = "logs/" + path.name
                        payloads[archive_name] = data
                        used += len(data)
                        sequences.update(line_sequences)
                        session_info["included_file_count"] += 1
                        entries.append({"archive_path": archive_name, "source_name": path.name,
                                        "source_bytes": raw_size, "bytes": len(data), "record_count": len(rows),
                                        "seq_start": min(line_sequences, default=None), "seq_end": max(line_sequences, default=None),
                                        "truncated": truncated, "invalid_lines_omitted": invalid_lines})
                    except OSError as exc:
                        self._remember_error("read_for_export", exc)
                        excluded.append({"file": path.name, "reason": "read_error", "error": self._sanitize_text(str(exc))})
                if session == self._session_id and self._fallback:
                    rows = []
                    fallback_sequences = []
                    for record in reversed(self._fallback):
                        clean = self._sanitize(record, set(), 0)
                        clean["session_id"] = self._session_id
                        row = (json.dumps(clean, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
                        if used + sum(map(len, rows)) + len(row) > self.retention_bytes:
                            continue
                        rows.append(row)
                        fallback_sequences.append(record["seq"])
                    rows.reverse()
                    fallback_sequences.reverse()
                    data = b"".join(rows)
                    name = f"logs/run-{self._session_id}.memory.jsonl"
                    payloads[name] = data
                    entries.append({"archive_path": name, "bytes": len(data), "record_count": len(rows),
                                    "seq_start": min(fallback_sequences, default=None), "seq_end": max(fallback_sequences, default=None),
                                    "truncated": len(rows) < len(self._fallback), "source": "memory_after_write_failure"})
                    sequences.update(fallback_sequences)
                    used += len(data)
                    session_info["included_file_count"] += 1
                session_info.update({"last_seq": observed_last_seq,
                                     "included_record_count": len(sequences),
                                     "missing_sequence_ranges": _missing_ranges(sequences, observed_last_seq),
                                     "tail_complete": (self._seq in sequences) if session == self._session_id else any(
                                         b'"event":"session_closed"' in payloads.get("logs/" + p.name, b"") for p in paths)})
                sessions_info.append(session_info)

            payloads["snapshot.json"] = self._json_bytes(self._sanitize(snapshot, set(), 0))
            readme = (
                f"校园网助手运行诊断 / Campus network runtime diagnostics\n"
                f"Version: {self._sanitize_text(self.version)}\nSession: {self._session_id}\n"
                "范围：本次运行和限额内的近期运行 JSONL、当前状态快照，以及本清单。\n"
                "仅按日志文件名白名单读取，不复制设置、凭据、原始网页或其他目录。\n"
                "已过滤账号、密码、令牌、Cookie、认证头、网页和请求/响应正文；已登记秘密的常见编码亦被过滤。\n"
                "网络诊断中的 IP、MAC、SSID、网关、DNS 等会保留，属于敏感网络元数据，请仅分享给可信维护人员。\n"
                "manifest.json 列明每个片段的记录数、序号、SHA-256、遗漏范围、写入错误及截断。\n"
                "日志按文件大小轮转并按数量/总字节清理；缺失序号表示早期轮转或限额造成的缺段。\n"
                "历史会话未出现 session_closed 时，最后一个已观察序号不代表完整运行。\n"
                "写入失败时附带有限内存记录；完整性以清单为准。日志无进程钩子，由程序显式接入。\n"
            )
            payloads["README.txt"] = readme.encode("utf-8")
            by_name = {entry["archive_path"]: entry for entry in entries}
            for name, data in payloads.items():
                entry = by_name.get(name)
                if entry is None:
                    entry = {"archive_path": name, "bytes": len(data)}
                    entries.append(entry)
                entry["sha256"] = hashlib.sha256(data).hexdigest()
            manifest = {
                "format_version": 1, "created_at": _utc_now(), "version": self._sanitize_text(self.version),
                "session_id": self._session_id, "write_error": self.write_error,
                "io_errors": self._sanitize(list(self._io_errors), set(), 0), "write_failures": self._write_failures,
                "rotations": self._rotations, "rotation_bytes_discarded": self._dropped_rotation_bytes,
                "memory_records_evicted": self._fallback_evicted, "sessions": sessions_info,
                "policy": {"max_file_bytes": self.max_bytes, "max_backup_count": self.max_backup_count,
                           "session_limit": self.session_limit, "log_bytes_limit": self.retention_bytes},
                "log_bytes": used, "files_count": len(entries), "archive_entry_count": len(entries) + 1,
                "files": entries, "excluded": excluded,
                "truncated": bool(excluded or self._fallback_evicted or any(
                    item.get("truncated") or item.get("invalid_lines_omitted") for item in entries)
                    or any(item["missing_sequence_ranges"] for item in sessions_info)),
            }
            payloads["manifest.json"] = self._json_bytes(manifest)
            destination = Path(destination_dir) if destination_dir is not None else self.root / "diagnostics"
            destination.mkdir(parents=True, exist_ok=True)
            bundle = destination / f"diagnostic-{self._session_id}-{uuid.uuid4().hex[:8]}.zip"
            temporary = bundle.with_suffix(".zip.tmp")
            try:
                with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                    for name, data in payloads.items():
                        archive.writestr(name, data)
                temporary.replace(bundle)
            except Exception:
                temporary.unlink(missing_ok=True)
                raise
            return bundle
