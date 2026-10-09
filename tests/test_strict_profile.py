"""Synthetic strict-profile regressions; no external extractor assumptions."""
import contextlib
import hashlib
import io
import os
import stat
import struct
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

from release_bundle_guard import cli
from release_bundle_guard.policy import CAPS, DEFAULTS, ConfigurationError, Policy
from release_bundle_guard.scanner import Scanner, scan_archive

ROOT = Path(__file__).resolve().parents[1]

class StrictProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="synthetic-strict-", dir=ROOT / "tests")
        self.root = Path(self.temp.name)
        self.archive = self.root / "fixture.zip"
        self.policy = Policy.from_dict({"version": 1, "allow": ["*"]})

    def tearDown(self):
        self.temp.cleanup()

    def write_zip(self, name="a.txt", data=b"synthetic fixture", *, archive_comment=b"", member_comment=b""):
        info = zipfile.ZipInfo(name)
        info.comment = member_comment
        with zipfile.ZipFile(self.archive, "w") as target:
            target.comment = archive_comment
            target.writestr(info, data)

    def test_all_nonascii_names_are_outside_profile(self):
        for name in ("caf\u00e9.txt", "\uff23\uff2f\uff2e.txt", "f\u0131le.txt"):
            self.write_zip(name)
            report = scan_archive(self.archive, self.policy)
            self.assertEqual(report.status, "incomplete")
            self.assertIn("unsupported_zip", {item["code"] for item in report.findings})

    def test_archive_and_member_comments_are_outside_profile(self):
        for kwargs in ({"archive_comment": b"synthetic comment"}, {"member_comment": b"synthetic comment"}):
            self.write_zip(**kwargs)
            self.assertEqual(scan_archive(self.archive, self.policy).status, "incomplete")

    def test_forbidden_patterns_ignore_ascii_case(self):
        self.write_zip("assets/server.PEM")
        policy = Policy.from_dict({"version": 1, "allow": ["assets/*"], "forbidden": ["*.pem"]})
        report = scan_archive(self.archive, policy)
        self.assertEqual(report.status, "fail")
        self.assertIn("forbidden", {item["code"] for item in report.findings})

    def test_help_has_distinct_nonaccepting_exit(self):
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as result:
                cli.main(["--help"])
        self.assertEqual(result.exception.code, 3)

    def test_scan_and_hash_use_immutable_captured_bytes(self):
        self.write_zip(data=b"original fixture")
        original_bytes = self.archive.read_bytes()
        original_run = Scanner.run
        def replace_source_after_capture(scanner):
            self.write_zip(data=b"replaced fixture")
            original_run(scanner)
        with mock.patch.object(Scanner, "run", replace_source_after_capture):
            report = scan_archive(self.archive, self.policy)
        self.assertEqual(report.status, "pass")
        self.assertEqual(report.archive_sha256, hashlib.sha256(original_bytes).hexdigest())
        self.assertNotEqual(report.archive_sha256, hashlib.sha256(self.archive.read_bytes()).hexdigest())

    def test_symlink_dotdot_report_parent_is_rejected(self):
        (self.root / "real" / "inner").mkdir(parents=True)
        (self.root / "shortcut").symlink_to(self.root / "real" / "inner", target_is_directory=True)
        ambiguous = self.root / "shortcut" / ".." / "result.txt"
        with self.assertRaises((OSError, ValueError)):
            cli.write_new_report(ambiguous, "synthetic report")
        self.assertFalse((self.root / "real" / "result.txt").exists())
        self.assertFalse((self.root / "result.txt").exists())

    def test_hidden_eocd_inside_member_comment_is_rejected(self):
        earlier_eocd = struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, 0, 0, 0, 0, 22)
        self.write_zip(member_comment=earlier_eocd)
        report = scan_archive(self.archive, self.policy)
        self.assertEqual(report.status, "incomplete")
        self.assertIn("unsupported_zip", {item["code"] for item in report.findings})

    def test_allow_and_required_patterns_remain_case_sensitive(self):
        self.write_zip("UPPER.TXT")
        for values, expected in (({"allow": ["*.txt"]}, "not_allowed"),
                                 ({"allow": ["*"], "required": ["*.txt"]}, "required_missing")):
            policy = Policy.from_dict({"version": 1, **values})
            report = scan_archive(self.archive, policy)
            self.assertIn(expected, {item["code"] for item in report.findings})

    def test_snapshot_archive_cap_is_small_and_fixed(self):
        self.assertEqual(DEFAULTS["max_archive_bytes"], 16 * 1024**2)
        self.assertEqual(CAPS["max_archive_bytes"], 32 * 1024**2)
        with self.assertRaises(ConfigurationError):
            Policy.from_dict({"version": 1, "allow": ["*"],
                              "limits": {"max_archive_bytes": 32 * 1024**2 + 1}})

    def test_change_during_snapshot_capture_is_incomplete(self):
        from release_bundle_guard import scanner as scanner_module
        self.write_zip()
        original_open = scanner_module.open_regular
        @contextlib.contextmanager
        def changing_open(path):
            with original_open(path) as stream:
                class ChangingReader:
                    def fileno(self):
                        return stream.fileno()
                    def read(inner, amount):
                        result = stream.read(amount)
                        before = self.archive.stat()
                        os.utime(self.archive, ns=(before.st_atime_ns, before.st_mtime_ns + 1000000000))
                        return result
                yield ChangingReader()
        with mock.patch.object(scanner_module, "open_regular", changing_open):
            report = scan_archive(self.archive, self.policy)
        self.assertEqual(report.status, "incomplete")
        self.assertIn("input_changed", {item["code"] for item in report.findings})
        self.assertFalse(report.hashes)
        self.assertIsNone(report.archive_sha256)

    def test_link_then_error_is_incomplete_without_unsafe_rollback(self):
        self.write_zip()
        policy = self.root / "policy.json"
        policy.write_text('{"version":1,"allow":["*"]}')
        target = self.root / "result.txt"
        real_link = cli.os.link
        def uncertain_link(*args, **kwargs):
            real_link(*args, **kwargs)
            raise OSError("synthetic lost success acknowledgement")
        with mock.patch.object(cli.os, "link", uncertain_link), contextlib.redirect_stdout(io.StringIO()) as output:
            code = cli.main(["--policy", str(policy), "--report", str(target), "--", str(self.archive)])
        self.assertEqual(code, 2)
        self.assertIn("INCOMPLETE", output.getvalue())
        self.assertNotIn("SHA256", output.getvalue())
        self.assertTrue(target.read_text().startswith("Release bundle check: PASS\n"))

    def test_cleanup_failure_can_leave_private_full_staging_report(self):
        target = self.root / "result.txt"
        with mock.patch.object(cli.os, "unlink", side_effect=OSError("synthetic cleanup failure")):
            cli.write_new_report(target, "synthetic complete report")
        leftovers = list(self.root.glob(".release-bundle-guard-*.tmp"))
        self.assertEqual(len(leftovers), 1)
        self.assertEqual(leftovers[0].read_text(), "synthetic complete report")
        self.assertEqual(stat.S_IMODE(leftovers[0].stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_both_help_spellings_and_double_dash(self):
        for option in ("-h", "--help"):
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as result:
                    cli.main([option])
            self.assertEqual(result.exception.code, 3)
        self.write_zip()
        with mock.patch.object(cli, "scan_archive", return_value=scan_archive(self.archive, self.policy)) as scan:
            policy = self.root / "policy.json"
            policy.write_text('{"version":1,"allow":["*"]}')
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["--policy", str(policy), "--", "--help"]), 0)
            self.assertEqual(scan.call_args.args[0], "--help")

    def test_reserved_basename_spaces_before_extension_rejected(self):
        for name in ("CON .txt", "NUL .tar.gz", "assets/COM1  .txt"):
            self.write_zip(name)
            report = scan_archive(self.archive, self.policy)
            self.assertEqual(report.status, "fail")
            self.assertIn("unsafe_name", {item["code"] for item in report.findings})
        self.write_zip("ordinary .txt")
        self.assertEqual(scan_archive(self.archive, self.policy).status, "pass")

    def test_forbidden_lowercase_preserves_original_ascii_ranges(self):
        self.write_zip("assets/_.txt")
        policy = Policy.from_dict({"version": 1, "allow": ["assets/*"],
                                  "forbidden": ["assets/[A-z].txt"]})
        report = scan_archive(self.archive, policy)
        self.assertEqual(report.status, "fail")
        self.assertIn("forbidden", {item["code"] for item in report.findings})

    def test_old_64_mib_archive_policy_fails_closed(self):
        self.write_zip()
        policy = self.root / "old-policy.json"
        policy.write_text('{"version":1,"allow":["*"],"limits":{"max_archive_bytes":67108864}}')
        with mock.patch.object(cli, "scan_archive") as scan, contextlib.redirect_stdout(io.StringIO()) as output:
            code = cli.main(["--policy", str(policy), "--", str(self.archive)])
        self.assertEqual(code, 2)
        self.assertIn("configuration_error", output.getvalue())
        scan.assert_not_called()

    def test_symlink_report_parent_is_rejected(self):
        real = self.root / "real"
        real.mkdir()
        shortcut = self.root / "shortcut"
        shortcut.symlink_to(real, target_is_directory=True)
        with self.assertRaises((OSError, ValueError)):
            cli.write_new_report(shortcut / "result.txt", "synthetic report")
        self.assertFalse((real / "result.txt").exists())

if __name__ == "__main__":
    unittest.main()
