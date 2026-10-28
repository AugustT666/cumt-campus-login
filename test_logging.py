"""Runtime diagnostics tests use only temporary files; no credentials/network."""
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import quote, quote_plus
import zipfile

from campus_logging import REDACTED, RuntimeLog


class RuntimeLogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def bundle(self, log, snapshot=None):
        result = log.export_bundle(snapshot or {})
        with zipfile.ZipFile(result) as archive:
            files = {name: archive.read(name) for name in archive.namelist()}
        return result, files, json.loads(files["manifest.json"])

    def test_sessions_survive_restart_and_concurrent_sequences_are_total_ordered(self):
        first = RuntimeLog(self.root, "1.5")
        first.event("first_run", ip="10.52.1.2")
        first.close()
        second = RuntimeLog(self.root, "1.5")
        self.assertNotEqual(first.session_id, second.session_id)
        with ThreadPoolExecutor(max_workers=8) as workers:
            list(workers.map(lambda number: second.event("work", operation_id=str(number)), range(160)))
        second.flush()
        rows = [json.loads(line) for line in second.path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([row["seq"] for row in rows], list(range(1, 162)))
        self.assertEqual([row["elapsed_ms"] for row in rows], sorted(row["elapsed_ms"] for row in rows))
        self.assertTrue(all(row["session_id"] == second.session_id and row["version"] == "1.5" for row in rows))
        _, files, manifest = self.bundle(second)
        self.assertEqual(len(manifest["sessions"]), 2)
        self.assertTrue(any(first.session_id in name for name in files))
        second.close()
        size = second.path.stat().st_size
        second.event("after_close")
        self.assertEqual(second.path.stat().st_size, size)

    def test_secret_variants_nested_values_urls_headers_and_traceback_are_redacted(self):
        log = RuntimeLog(self.root, "1.5")
        account = "学生甲-2026001234"
        password = '密 P@ss&\\"词-987!'
        log.register_secrets(account, password)
        variants = []
        for secret in (account, password):
            variants.extend((secret, quote(secret, safe=""), quote_plus(secret, safe=""),
                             base64.b64encode(secret.encode()).decode(),
                             base64.urlsafe_b64encode(secret.encode()).decode().rstrip("="),
                             json.dumps(secret, ensure_ascii=True)[1:-1]))
        for variant in variants:
            log.event("variant", message=variant)
        log.event("structured", data={"USER_ACCOUNT": account, "deep": [{"Password": password}],
                                      "access_TOKEN": "unregistered-token-456", "uid": "another-uid", "DDDDD": "unknown-user"},
                  response_headers={"Set-Cookie": "unregistered-cookie=xyz"},
                  raw_body="arbitrary auth content", html="<html>should be absent</html>",
                  message="Cookie: unregistered-cookie=xyz\nAuthorization: Bearer unknown-bearer",
                  json_message=json.dumps({"uid": "nested-json-uid", "UserName": "nested-json-name", "url": "http://nested-user:nested-pass@10.2.5.251/path"}).replace("/", "\\/"),
                  endpoint="http://userinfo:private-pass@10.2.5.251/eportal?uid=private-id&username=private-name&password=private-pwd&ip=10.52.1.2",
                  address={"ip": "10.52.1.2", "mac": "00-11-22-33-44-55"})
        try:
            raise RuntimeError("failure with " + password + " and " + account)
        except RuntimeError as exc:
            log.exception("unexpected", exc)
        _, files, _ = self.bundle(log, {"version": "1.5", "network": {"ip": "10.52.1.2"}, "password": password})
        disk = b"\n".join(path.read_bytes() for path in log.logs_dir.glob("*.jsonl*"))
        exported = b"\n".join(files.values())
        for content in (disk, exported):
            decoded = content.decode("utf-8")
            # Check both actual strings and their JSON escaped representation.
            for secret in variants + ["unregistered-token-456", "another-uid", "unknown-user", "unregistered-cookie", "unknown-bearer",
                                      "userinfo", "private-pass", "private-id", "private-name", "private-pwd", "arbitrary auth content",
                                      "nested-json-uid", "nested-json-name", "nested-user", "nested-pass"]:
                self.assertNotIn(secret, decoded)
                self.assertNotIn(json.dumps(secret, ensure_ascii=False)[1:-1], decoded)
            self.assertIn("10.52.1.2", decoded)
        self.assertIn("00-11-22-33-44-55", disk.decode())
        self.assertIn("RuntimeError", exported.decode())
        self.assertIn("Traceback", exported.decode())
        log.close()

    def test_sanitize_does_not_mutate_snapshot_and_handles_non_json_values(self):
        log = RuntimeLog(self.root, "1.5")
        original = {"ok": True, "ip": "10.1.2.3", "user_account": "sensitive", "bytes": b"raw secret", "path": self.root}
        clean = log.sanitize(original)
        self.assertEqual(original["user_account"], "sensitive")
        self.assertEqual(clean["user_account"], REDACTED)
        self.assertEqual(clean["bytes"], "[REDACTED_BINARY]")
        cyclic = {}; cyclic["itself"] = cyclic
        self.assertIn("CIRCULAR", json.dumps(log.sanitize(cyclic)))
        json.dumps(clean, allow_nan=False)
        log.close()

    def test_mixed_case_percent_encoded_secrets_are_hidden_in_text_traceback_and_zip(self):
        log = RuntimeLog(self.root, "1.5")
        secret = "Aa/密?+ z%"
        log.register_secrets(secret)
        encoded = quote(secret, safe="")
        mixed = encoded.replace("%2F", "%2f").replace("%E5", "%e5")
        self.assertNotEqual(encoded, mixed)
        log.event("mixed_encoding", message="rejected " + mixed)
        try:
            raise ValueError("encoded credential rejected " + mixed)
        except ValueError as exc:
            log.exception("mixed_exception", exc)
        _, files, _ = self.bundle(log, {"message": mixed})
        content = b"\n".join(files.values()).decode("utf-8")
        disk = log.path.read_text(encoding="utf-8")
        for text in (disk, content):
            self.assertNotIn(secret, text)
            self.assertNotIn(mixed, text)
            self.assertNotIn(encoded, text)
        # Do not accidentally make ordinary password letters case insensitive.
        self.assertEqual(log.sanitize("aa/密?+ z%"), "aa/密?+ z%")
        log.close()

    def test_html_exception_keeps_chained_stacks_but_omits_entire_html_message(self):
        log = RuntimeLog(self.root, "1.5")
        def failing_leaf():
            raise ValueError("<html>\n<body>private-html-body\nopaque-inside-body</body>\n</html>")
        def exception_chain():
            try:
                failing_leaf()
            except ValueError as inner:
                raise RuntimeError("outer diagnostic context") from inner
        try:
            exception_chain()
        except RuntimeError as exc:
            log.exception("html_exception", exc)
        rows = [json.loads(line) for line in log.path.read_text(encoding="utf-8").splitlines()]
        trace = rows[-1]["fields"]["traceback"]
        self.assertIn("Traceback", trace)
        self.assertIn("failing_leaf", trace)
        self.assertIn("exception_chain", trace)
        self.assertIn("ValueError:", trace)
        self.assertIn("RuntimeError: outer diagnostic context", trace)
        self.assertIn("direct cause", trace)
        self.assertIn("REDACTED_HTML", trace)
        _, files, _ = self.bundle(log)
        for content in (log.path.read_bytes(), b"\n".join(files.values())):
            self.assertNotIn(b"private-html-body", content)
            self.assertNotIn(b"opaque-inside-body", content)
            self.assertNotIn(b"<html>", content)
            self.assertIn(b"failing_leaf", content)
        log.close()

    def test_export_allowlist_rotation_sequence_gaps_and_hashes(self):
        log = RuntimeLog(self.root, "1.5", max_bytes=700, max_backup_count=2)
        (self.root / "settings.json").write_text('{"password":"never-copy-settings"}')
        (log.logs_dir / "credentials.dpapi").write_text("never-copy-credentials")
        nested = log.logs_dir / "other-directory"; nested.mkdir()
        (nested / "raw.html").write_text("never-copy-html")
        (log.logs_dir / "run-fake.jsonl").write_text("never-copy-untrusted")
        for number in range(50):
            log.event("rotation", number=number, message="x" * 120)
        _, files, manifest = self.bundle(log, {"version": "1.5", "state": "offline"})
        jsonl = [name for name in files if name.startswith("logs/")]
        self.assertLessEqual(len(jsonl), 3)
        self.assertGreater(manifest["rotations"], 0)
        self.assertGreater(manifest["rotation_bytes_discarded"], 0)
        self.assertTrue(manifest["truncated"])
        self.assertTrue(manifest["sessions"][0]["missing_sequence_ranges"])
        self.assertEqual(manifest["archive_entry_count"], len(files))
        self.assertEqual(manifest["files_count"], len(files) - 1)
        for entry in manifest["files"]:
            self.assertEqual(hashlib.sha256(files[entry["archive_path"]]).hexdigest(), entry["sha256"])
            self.assertEqual(len(files[entry["archive_path"]]), entry["bytes"])
        for secret in ("never-copy-settings", "never-copy-credentials", "never-copy-html", "never-copy-untrusted"):
            self.assertNotIn(secret, b"".join(files.values()).decode())
        self.assertEqual(json.loads(files["snapshot.json"])["version"], "1.5")
        log.close()

    def test_retention_keeps_current_and_recent_sessions_and_obeys_export_budget(self):
        ids = []
        for number in range(5):
            log = RuntimeLog(self.root, "1.5", session_limit=3, retention_bytes=2200)
            ids.append(log.session_id)
            log.event("history", number=number)
            log.close()
        _, files, manifest = self.bundle(log)
        self.assertIn(log.session_id, [item["session_id"] for item in manifest["sessions"]])
        self.assertLessEqual(len(manifest["sessions"]), 3)
        self.assertLessEqual(manifest["log_bytes"], 2200)
        self.assertFalse(any(ids[0] in name for name in files))
        # A tiny hard export budget drops complete records and declares the gap.
        log.retention_bytes = 100
        _, files, manifest = self.bundle(log)
        self.assertLessEqual(sum(len(data) for name, data in files.items() if name.startswith("logs/")), 100)
        self.assertTrue(manifest["truncated"])
        for name, data in files.items():
            if name.startswith("logs/"):
                for line in data.splitlines():
                    json.loads(line)

    def test_expanded_export_keeps_latest_whole_records_and_exact_sequence_accounting(self):
        log = RuntimeLog(self.root, "review", retention_bytes=6500)
        records = [{"seq": number, "session_id": log.session_id, "event": "fixture",
                    "fields": {"text": "a" * 100}} for number in range(1, 21)]
        # Invalid sequence metadata must stay aligned with its own record when
        # removing old rows, instead of shifting the remaining sequence list.
        records.insert(17, {"seq": None, "session_id": log.session_id, "event": "fixture",
                            "fields": {"text": "a" * 100}})
        log.path.write_text("".join(json.dumps(row) + "\n" for row in records), encoding="utf-8")
        log.register_secrets("a")
        _, files, manifest = self.bundle(log)
        rows = [json.loads(line) for name, data in files.items() if name.startswith("logs/")
                for line in data.splitlines()]
        sequences = [row["seq"] for row in rows if type(row.get("seq")) is int]
        self.assertEqual(sequences, list(range(min(sequences), 21)))
        self.assertEqual(manifest["sessions"][0]["included_record_count"], len(sequences))
        fragment = next(entry for entry in manifest["files"] if entry["archive_path"].startswith("logs/"))
        self.assertEqual(fragment["seq_start"], min(sequences))
        self.assertEqual(fragment["seq_end"], 20)
        self.assertEqual(fragment["record_count"], len(rows))
        self.assertLessEqual(manifest["log_bytes"], 6500)
        self.assertTrue(manifest["truncated"])

    def test_write_failure_does_not_escape_and_export_explains_lost_disk_records(self):
        blocked = self.root / "not-a-directory"
        blocked.write_text("occupied")
        log = RuntimeLog(blocked, "1.5")
        log.register_secrets("disk-error-secret")
        log.event("critical", message="disk-error-secret")
        try:
            raise ValueError("disk-error-secret")
        except ValueError as exc:
            log.exception("failure", exc)
        self.assertTrue(log.write_error)
        result = log.export_bundle({"state": "error"}, self.root / "share")
        with zipfile.ZipFile(result) as archive:
            manifest = json.loads(archive.read("manifest.json"))
            all_data = b"".join(archive.read(name) for name in archive.namelist())
        self.assertGreaterEqual(manifest["write_failures"], 3)
        self.assertTrue(manifest["write_error"])
        self.assertTrue(any(entry.get("source") == "memory_after_write_failure" for entry in manifest["files"]))
        self.assertNotIn(b"disk-error-secret", all_data)
        log.close()

    def test_exception_formatting_and_export_read_errors_are_safe(self):
        log = RuntimeLog(self.root, "1.5")
        with patch("campus_logging.traceback.format_exception", side_effect=RuntimeError("format fail")):
            log.exception("unprintable", RuntimeError("private"))
        original = Path.open
        def broken_read(path, mode="r", *args, **kwargs):
            if path == log.path and mode == "rb":
                raise PermissionError("test read denied")
            return original(path, mode, *args, **kwargs)
        with patch.object(Path, "open", broken_read):
            _, _, manifest = self.bundle(log)
        self.assertTrue(any(item["reason"] == "read_error" for item in manifest["excluded"]))
        self.assertTrue(manifest["truncated"])
        log.close()


if __name__ == "__main__":
    unittest.main()
