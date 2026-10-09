"""Synthetic regressions from a second, static review; no real release inputs."""
import contextlib
import hashlib
import io
import os
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest import mock
import zipfile
import zlib

from release_bundle_guard import cli
from release_bundle_guard.policy import Policy
from release_bundle_guard.scanner import Scanner, scan_archive

ROOT = Path(__file__).resolve().parents[1]

class HardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="synthetic-hardening-", dir=ROOT / "tests")
        self.root = Path(self.temp.name)
        self.archive = self.root / "fixture.zip"
        self.policy_path = self.root / "policy.json"
        self.policy_path.write_text('{"version":1,"allow":["*"]}')
        self.policy = Policy.from_dict({"version": 1, "allow": ["*"]})

    def tearDown(self):
        self.temp.cleanup()

    def write_zip(self, entries):
        with zipfile.ZipFile(self.archive, "w") as target:
            for name, content in entries:
                target.writestr(name, content)

    def write_raw_name(self, name, flags=0):
        data = b"synthetic fixture"
        crc = zlib.crc32(data)
        local = struct.pack("<4s5H3I2H", b"PK\x03\x04", 20, flags, 0, 0, 0, crc,
                            len(data), len(data), len(name), 0) + name + data
        central = struct.pack("<4s6H3I5H2I", b"PK\x01\x02", 20, 20, flags, 0, 0, 0, crc,
                              len(data), len(data), len(name), 0, 0, 0, 0, 0, 0) + name
        end = struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, 1, 1, len(central), len(local), 0)
        self.archive.write_bytes(local + central + end)

    def test_nonascii_legacy_name_is_unsupported(self):
        # CP437 treats these bytes as ordinary characters; UTF-8 yields C1 U+0085.
        # This demonstrates decoder disagreement, not an extractor exploit.
        self.write_raw_name(b"\xc2\x85.txt")
        report = scan_archive(self.archive, self.policy)
        self.assertEqual(report.status, "incomplete")
        self.assertIn("unsupported_zip", {item["code"] for item in report.findings})

    def test_explicit_utf8_name_still_supported(self):
        self.write_raw_name("caf\u00e9.txt".encode(), flags=0x800)
        self.assertEqual(scan_archive(self.archive, self.policy).status, "pass")

    def test_pass_binds_whole_archive(self):
        self.write_zip([("a.txt", b"synthetic fixture")])
        expected = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        report = scan_archive(self.archive, self.policy)
        self.assertEqual(report.as_dict().get("archive_sha256"), expected)

    def test_failed_secret_scan_publishes_no_hashes(self):
        marker = b"-----BEGIN PRIVATE KEY-----"
        self.write_zip([("a.txt", marker), ("b.txt", b"ordinary fixture")])
        report = scan_archive(self.archive, self.policy)
        self.assertEqual(report.status, "fail")
        self.assertEqual(report.hashes, [])
        self.assertIsNone(report.as_dict().get("archive_sha256"))
        self.assertNotIn(hashlib.sha256(marker).hexdigest(), report.render("json"))

    def test_setid_permissions_rejected(self):
        for permission in (stat.S_ISUID, stat.S_ISGID):
            info = zipfile.ZipInfo("program")
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o755 | permission) << 16
            self.write_zip([(info, b"synthetic fixture")])
            self.assertEqual(scan_archive(self.archive, self.policy).status, "fail")

    def test_partial_report_write_never_publishes_destination(self):
        self.write_zip([("a.txt", b"synthetic fixture")])
        destination = self.root / "result.txt"
        real_fdopen = os.fdopen
        class FailingWriter:
            def __init__(self, stream):
                self.stream = stream
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.stream.close()
            def write(self, text):
                self.stream.write(text.split("\n", 1)[0] + "\n")
                self.stream.flush()
                raise OSError("synthetic write failure")
        def fdopen(fd, mode="r", *args, **kwargs):
            stream = real_fdopen(fd, mode, *args, **kwargs)
            return FailingWriter(stream) if mode == "w" else stream
        with mock.patch.object(cli.os, "fdopen", side_effect=fdopen), contextlib.redirect_stdout(io.StringIO()) as output:
            code = cli.main([str(self.archive), "--policy", str(self.policy_path), "--report", str(destination)])
        self.assertEqual(code, 2)
        self.assertIn("INCOMPLETE", output.getvalue())
        self.assertFalse(destination.exists())

    def test_dotless_i_is_conservatively_collision_checked(self):
        self.write_zip([("f\u0131le.txt", b"first"), ("FILE.txt", b"second")])
        report = scan_archive(self.archive, self.policy)
        self.assertEqual(report.status, "fail")
        self.assertIn("name_collision", {item["code"] for item in report.findings})

    def test_com_zero_and_lpt_zero_are_conservatively_reserved(self):
        for name in ("COM0", "LPT0.txt"):
            self.write_zip([(name, b"synthetic fixture")])
            self.assertEqual(scan_archive(self.archive, self.policy).status, "fail")

    def test_sticky_and_world_writable_modes_rejected(self):
        for permission in (stat.S_ISVTX, stat.S_IWOTH):
            info = zipfile.ZipInfo("program")
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644 | permission) << 16
            self.write_zip([(info, b"synthetic fixture")])
            self.assertEqual(scan_archive(self.archive, self.policy).status, "fail")

    def test_declared_size_mismatch_stops_at_declared_plus_one(self):
        self.write_zip([("a", b"x" * 1000)])
        data = bytearray(self.archive.read_bytes())
        central = data.index(b"PK\x01\x02")
        struct.pack_into("<I", data, 22, 1)
        struct.pack_into("<I", data, central + 24, 1)
        self.archive.write_bytes(data)
        report = scan_archive(self.archive, self.policy)
        self.assertEqual(report.status, "incomplete")
        self.assertEqual(report.bytes_scanned, 2)

    def test_abbreviated_help_is_usage_error(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["--he"]), 2)

    def test_short_report_write_never_publishes_destination(self):
        destination = self.root / "short-result.txt"
        real_fdopen = os.fdopen
        class ShortWriter:
            def __init__(self, stream):
                self.stream = stream
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.stream.close()
            def write(self, text):
                return self.stream.write(text[:10])
            def flush(self):
                self.stream.flush()
            def fileno(self):
                return self.stream.fileno()
        def fdopen(fd, *args, **kwargs):
            return ShortWriter(real_fdopen(fd, *args, **kwargs))
        with mock.patch.object(cli.os, "fdopen", side_effect=fdopen):
            with self.assertRaises(OSError):
                cli.write_new_report(destination, "Release bundle check: PASS\n" + "x" * 100)
        self.assertFalse(destination.exists())

    def test_archive_digest_covers_metadata(self):
        self.write_zip([("a.txt", b"synthetic fixture")])
        first = scan_archive(self.archive, self.policy)
        with zipfile.ZipFile(self.archive, "a") as target:
            target.comment = b"benign synthetic comment"
        second = scan_archive(self.archive, self.policy)
        self.assertEqual(first.hashes, second.hashes)
        self.assertNotEqual(first.archive_sha256, second.archive_sha256)
        self.assertEqual(second.archive_sha256, hashlib.sha256(self.archive.read_bytes()).hexdigest())
        self.assertEqual(second.archive_bytes, self.archive.stat().st_size)

    def test_report_failure_clears_all_api_and_rendered_hashes(self):
        self.write_zip([("a.txt", b"synthetic fixture")])
        report = scan_archive(self.archive, self.policy)
        self.assertTrue(report.archive_sha256)
        self.assertTrue(report.hashes)
        report.add("report_error", incomplete=True)
        self.assertEqual(report.hashes, [])
        self.assertIsNone(report.archive_sha256)
        self.assertIsNone(report.archive_bytes)
        self.assertNotIn("SHA256", report.render())

    def test_input_change_after_archive_hash_clears_all_hashes(self):
        self.write_zip([("a.txt", b"synthetic fixture")])
        original = Scanner.bind_archive
        def change_after_binding(scanner):
            original(scanner)
            old = self.archive.stat()
            os.utime(self.archive, ns=(old.st_atime_ns, old.st_mtime_ns + 1000000000))
        with mock.patch.object(Scanner, "bind_archive", change_after_binding):
            report = scan_archive(self.archive, self.policy)
        self.assertEqual(report.status, "incomplete")
        self.assertIn("input_changed", {item["code"] for item in report.findings})
        self.assertEqual(report.hashes, [])
        self.assertIsNone(report.archive_sha256)

    def test_report_symlinks_are_not_followed(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks unavailable")
        for target_exists in (False, True):
            target = self.root / ("existing.txt" if target_exists else "absent.txt")
            if target_exists:
                target.write_text("preserve this synthetic file")
            link = self.root / ("existing-link.txt" if target_exists else "dangling-link.txt")
            link.symlink_to(target)
            with self.assertRaises(OSError):
                cli.write_new_report(link, "synthetic report")
            self.assertTrue(link.is_symlink())
            if target_exists:
                self.assertEqual(target.read_text(), "preserve this synthetic file")
            else:
                self.assertFalse(target.exists())

    def test_fsync_and_link_failure_never_publish(self):
        for operation in ("fsync", "link"):
            target = self.root / (operation + ".txt")
            with mock.patch.object(cli.os, operation, side_effect=OSError("synthetic failure")):
                with self.assertRaises(OSError):
                    cli.write_new_report(target, "Release bundle check: PASS\n")
            self.assertFalse(target.exists())
            self.assertEqual(list(self.root.glob(".release-bundle-guard-*.tmp")), [])

    def test_prepended_zip_and_reused_local_header_rejected(self):
        self.write_zip([("a", b"fixture")])
        self.archive.write_bytes(b"prefix" + self.archive.read_bytes())
        self.assertEqual(scan_archive(self.archive, self.policy).status, "incomplete")
        self.write_zip([("a", b"fixture"), ("b", b"fixture")])
        data = bytearray(self.archive.read_bytes())
        first = data.index(b"PK\x01\x02")
        second = data.index(b"PK\x01\x02", first + 4)
        struct.pack_into("<I", data, second + 42, 0)
        self.archive.write_bytes(data)
        self.assertEqual(scan_archive(self.archive, self.policy).status, "incomplete")

    def test_zip_signature_bytes_inside_member_are_data(self):
        self.write_zip([("nested.bin", b"payload PK\x05\x06 PK\x01\x02 payload")])
        self.assertEqual(scan_archive(self.archive, self.policy).status, "pass")

    def test_help_is_non_scan_success(self):
        with mock.patch.object(cli, "scan_archive") as scan, contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(SystemExit) as result:
                cli.main(["--help"])
        self.assertEqual(result.exception.code, 0)
        scan.assert_not_called()
        self.assertNotIn("Release bundle check: PASS", output.getvalue())

    def test_case_sensitive_patterns_are_explicit(self):
        self.write_zip([("UPPER.TXT", b"synthetic fixture")])
        policy = Policy.from_dict({"version": 1, "allow": ["*"], "forbidden": ["*.txt"]})
        self.assertEqual(scan_archive(self.archive, policy).status, "pass")

    def test_appended_second_eocd_is_rejected(self):
        self.write_zip([("a.txt", b"synthetic fixture")])
        data = self.archive.read_bytes()
        self.archive.write_bytes(data + data[-22:])
        self.assertEqual(scan_archive(self.archive, self.policy).status, "incomplete")

if __name__ == "__main__":
    unittest.main()
