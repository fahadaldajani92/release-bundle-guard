"""Small synthetic fixtures only. No network, extraction, real tokens or assets."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
import unittest
import warnings
import zipfile
import zlib

from release_bundle_guard.cli import main
from release_bundle_guard.policy import ConfigurationError, Policy, load_manifest, valid_name
from release_bundle_guard.scanner import scan_archive, CHUNK

ROOT = Path(__file__).resolve().parents[1]

class GuardTests(unittest.TestCase):
    def setUp(self):
        # Test-only writes stay inside the explicitly created project directory.
        self.temp = tempfile.TemporaryDirectory(prefix="synthetic-", dir=ROOT / "tests")
        self.root = Path(self.temp.name)
        self.archive = self.root / "fixture.zip"
        self.policy_path = self.root / "policy.json"
        self.policy_path.write_text(json.dumps({"version": 1, "allow": ["*"]}))

    def tearDown(self):
        self.temp.cleanup()

    def policy(self, **kwargs):
        return Policy.from_dict({"version": 1, "allow": ["*"], **kwargs})

    def make_zip(self, entries, compression=zipfile.ZIP_STORED):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(self.archive, "w", compression=compression) as target:
                for name, data in entries:
                    target.writestr(name, data)
        return self.archive

    def run_scan(self, entries=None, **kwargs):
        if entries is not None:
            self.make_zip(entries)
        return scan_archive(self.archive, kwargs.pop("policy", self.policy()), **kwargs)

    def codes(self, report):
        return {item["code"] for item in report.findings}

    def patch(self, changes):
        data = bytearray(self.archive.read_bytes())
        central = data.index(b"PK\x01\x02")
        end = data.rindex(b"PK\x05\x06")
        for base, offset, format, value in changes:
            origin = {"local": 0, "central": central, "end": end}[base]
            struct.pack_into(format, data, origin + offset, value)
        self.archive.write_bytes(data)

    def test_stored_pass_hash(self):
        report = self.run_scan([("README.txt", b"synthetic release\n")])
        self.assertEqual(report.status, "pass")
        self.assertEqual(report.exit_code, 0)
        self.assertEqual(report.hashes[0]["sha256"], hashlib.sha256(b"synthetic release\n").hexdigest())

    def test_deflate_and_empty_members(self):
        self.make_zip([("README.txt", bytes(range(128)) * 50), ("empty.txt", b"")], zipfile.ZIP_DEFLATED)
        self.assertEqual(self.run_scan().status, "pass")

    def test_empty_archive(self):
        self.make_zip([])
        self.assertEqual(self.run_scan().status, "pass")
        self.assertIn("required_missing", self.codes(self.run_scan(policy=self.policy(required=["README.txt"]))))

    def test_allow_required_forbidden(self):
        report = self.run_scan([("private.key", b"fixture")], policy=self.policy(
            allow=["assets/*"], required=["README.txt"], forbidden=["*.key"]))
        self.assertEqual(report.status, "fail")
        self.assertEqual(self.codes(report), {"not_allowed", "required_missing", "forbidden"})

    def test_required_directory_does_not_count(self):
        report = self.run_scan([("assets/", b"")], policy=self.policy(required=["assets/"]))
        self.assertEqual(report.status, "fail")

    def test_unsafe_names(self):
        for name in ("../escape", "/absolute", "C:drive", "a\\b", "a/../b", "a//b", "./a",
                     "trailing.", "NUL.txt", "control\x1b.txt", "a?b", "a|b", "a<b"):
            with self.subTest(name=repr(name)):
                report = self.run_scan([(name, b"fixture")])
                self.assertIn("unsafe_name", self.codes(report))

    def test_collisions(self):
        for names in (("a.txt", "a.txt"), ("A.txt", "a.txt"),
                      ("a", "a/"), ("a", "a/b")):
            with self.subTest(names=names):
                self.assertIn("name_collision", self.codes(self.run_scan([(name, b"") for name in names])))

    def test_symlink_and_special_file(self):
        for mode in (stat.S_IFLNK, stat.S_IFIFO, stat.S_IFCHR, stat.S_IFSOCK):
            info = zipfile.ZipInfo("entry")
            info.create_system = 3
            info.external_attr = (mode | 0o600) << 16
            self.make_zip([(info, b"target")])
            self.assertIn("special_file", self.codes(self.run_scan()))

    def test_crc_corruption(self):
        self.make_zip([("a", b"fixture")])
        data = bytearray(self.archive.read_bytes())
        data[31] ^= 1
        self.archive.write_bytes(data)
        report = self.run_scan()
        self.assertEqual(report.status, "incomplete")
        self.assertIn("corrupt_zip", self.codes(report))
        self.assertEqual(report.hashes, [])

    def test_local_central_mismatch(self):
        self.make_zip([("a", b"fixture")])
        self.patch([("local", 8, "<H", 8)])
        self.assertIn("corrupt_zip", self.codes(self.run_scan()))

    def test_encryption_descriptor_zip64_multidisk_and_method(self):
        for changes, expected in (
            ([("central", 8, "<H", 1)], "encrypted_member"),
            ([("central", 8, "<H", 8)], "unsupported_zip"),
            ([("central", 10, "<H", 99)], "unsupported_zip"),
            ([("end", 10, "<H", 65535), ("end", 8, "<H", 65535)], "unsupported_zip"),
            ([("end", 4, "<H", 1)], "unsupported_zip"),
        ):
            self.make_zip([("a", b"fixture")])
            self.patch(changes)
            self.assertIn(expected, self.codes(self.run_scan()))

    def test_header_size_limits(self):
        self.make_zip([("a", b"12345"), ("b", b"67890")])
        for limits, code in (({"max_archive_bytes": 1}, "archive_size_limit"),
                             ({"max_members": 1}, "member_count_limit"),
                             ({"max_member_bytes": 4}, "member_size_limit"),
                             ({"max_total_bytes": 9}, "total_size_limit")):
            self.assertIn(code, self.codes(self.run_scan(policy=self.policy(limits=limits))))

    def test_actual_deflate_limit_with_lying_headers(self):
        self.make_zip([("a", b"X" * 8192)], zipfile.ZIP_DEFLATED)
        self.patch([("local", 22, "<I", 128), ("central", 24, "<I", 128)])
        report = self.run_scan(policy=self.policy(limits={"max_member_bytes": 128, "max_ratio": 1000}))
        self.assertIn("member_size_limit", self.codes(report))
        self.assertEqual(report.bytes_scanned, 129)
        self.assertFalse(report.hashes)

    def test_actual_stored_limit_with_lying_headers(self):
        self.make_zip([("a", b"X" * 8192)])
        self.patch([("local", 22, "<I", 128), ("central", 24, "<I", 128)])
        report = self.run_scan(policy=self.policy(limits={"max_member_bytes": 128}))
        self.assertIn("member_size_limit", self.codes(report))
        self.assertEqual(report.bytes_scanned, 129)

    def test_ratio_limit(self):
        self.make_zip([("a", b"X" * 8192)], zipfile.ZIP_DEFLATED)
        self.assertIn("ratio_limit", self.codes(self.run_scan()))

    def test_cooperative_deadline(self):
        self.make_zip([("a", b"fixture")])
        calls = iter(range(100))
        report = self.run_scan(policy=self.policy(limits={"max_seconds": 1}), clock=lambda: next(calls))
        self.assertIn("time_limit", self.codes(report))

    def test_redacted_secret_and_home_path_across_chunk(self):
        marker = b"-----BEGIN PRIVATE KEY-----"
        content = b"x" * (CHUNK - 10) + marker + b"\n/home/synthetic_fixture/project/\n"
        report = self.run_scan([("sensitive\x1b-name.txt", content)])
        self.assertIn("secret_indicator", self.codes(report))
        self.assertIn("private_path_indicator", self.codes(report))
        for rendered in (report.render(), report.render("json")):
            self.assertNotIn("PRIVATE KEY", rendered)
            self.assertNotIn("synthetic_fixture", rendered)
            self.assertNotIn("sensitive", rendered)
            self.assertNotIn("\x1b", rendered)
            self.assertNotIn(str(self.root), rendered)

    def test_external_manifest_exact_match_and_mismatch(self):
        self.make_zip([("a", b"fixture")])
        expected = {"a": hashlib.sha256(b"fixture").hexdigest()}
        self.assertEqual(self.run_scan(manifest=expected).status, "pass")
        self.assertIn("manifest_mismatch", self.codes(self.run_scan(manifest={})))
        self.assertIn("manifest_mismatch", self.codes(self.run_scan(manifest={**expected, "missing": "0" * 64})))

    def test_archive_policy_never_overrides_external(self):
        report = self.run_scan([("policy.json", b'{"allow":["*"]}')], policy=self.policy(allow=["README.txt"]))
        self.assertIn("not_allowed", self.codes(report))

    def test_configuration_validation(self):
        invalid = ({"version": 1, "allow": []}, {"version": True, "allow": ["*"]},
                   {"version": 1, "allow": ["*"], "unexpected": 1},
                   {"version": 1, "allow": ["*"], "limits": {"max_members": True}},
                   {"version": 1, "allow": ["*"], "limits": {"max_members": 10**1000}},
                   {"version": 1, "allow": ["*"], "limits": {"max_seconds": float("nan")}})
        for obj in invalid:
            with self.assertRaises(ConfigurationError):
                Policy.from_dict(obj)
        self.policy_path.write_text('{"version":1,"allow":["*"],"allow":["a"]}')
        with self.assertRaises(ConfigurationError):
            Policy.load(self.policy_path)

    def test_manifest_surrogate_rejected(self):
        path = self.root / "manifest.json"
        path.write_text(json.dumps({"version": 1, "sha256": {"\ud800": "0" * 64}}))
        with self.assertRaises(ConfigurationError):
            load_manifest(path)

    def test_cli_pass_fail_incomplete_and_new_report(self):
        self.make_zip([("a", b"fixture")])
        output_path = self.root / "report.json"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main([str(self.archive), "--policy", str(self.policy_path), "--format", "json", "--report", str(output_path)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "pass")
        first = output_path.read_bytes()
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = main([str(self.archive), "--policy", str(self.policy_path), "--report", str(output_path)])
        self.assertEqual(code, 2)
        self.assertEqual(output_path.read_bytes(), first)
        self.make_zip([("../unsafe", b"")])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main([str(self.archive), "--policy", str(self.policy_path)]), 1)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main([str(self.root / "missing"), "--policy", str(self.policy_path)]), 2)
        self.assertNotIn(str(self.root), output.getvalue())

    def test_invalid_cli_arguments_redacted(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["--format", "json", "--unknown-private-argument"]), 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "incomplete")
        self.assertNotIn("unknown-private", output.getvalue())

    def test_no_extraction_or_default_report_write(self):
        self.make_zip([("new-file.txt", b"fixture")])
        before = sorted(p.name for p in self.root.iterdir())
        report = self.run_scan()
        self.assertEqual(report.status, "pass")
        self.assertEqual(before, sorted(p.name for p in self.root.iterdir()))

    def test_nonzip_truncation_and_appended_data(self):
        for content in (b"not a zip", b"PK\x05\x06", b"", b"x" * 100):
            self.archive.write_bytes(content)
            self.assertEqual(self.run_scan().status, "incomplete")
        self.make_zip([("a", b"fixture")])
        self.archive.write_bytes(self.archive.read_bytes() + b"trailing")
        self.assertEqual(self.run_scan().status, "incomplete")

    def raw_deflate_fixture(self, raw, declared=None, crc=None):
        name = b"a"
        data = b"synthetic payload" * 8
        size = len(data) if declared is None else declared
        checksum = zlib.crc32(data) if crc is None else crc
        local = struct.pack("<4s5H3I2H", b"PK\x03\x04", 20, 0, 8, 0, 0, checksum, len(raw), size, 1, 0) + name + raw
        central = struct.pack("<4s6H3I5H2I", b"PK\x01\x02", 20, 20, 0, 8, 0, 0, checksum, len(raw), size, 1, 0, 0, 0, 0, 0, 0) + name
        end = struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, 1, 1, len(central), len(local), 0)
        self.archive.write_bytes(local + central + end)

    def test_deflate_eof_trailing_concatenated_and_size(self):
        data = b"synthetic payload" * 8
        compressor = zlib.compressobj(wbits=-15)
        raw = compressor.compress(data) + compressor.flush()
        self.raw_deflate_fixture(raw)
        self.assertEqual(self.run_scan().status, "pass")
        for malformed in (raw[:-1], raw + b"extra", raw + raw, b"", b"invalid"):
            self.raw_deflate_fixture(malformed)
            report = self.run_scan()
            self.assertEqual(report.status, "incomplete")
            self.assertFalse(report.hashes)
        self.raw_deflate_fixture(raw, declared=1, crc=zlib.crc32(data[:1]))
        self.assertIn("corrupt_zip", self.codes(self.run_scan()))

    def test_actual_total_and_ratio_limits(self):
        self.make_zip([("a", b"A" * 128), ("b", b"B" * 128)])
        blob = bytearray(self.archive.read_bytes())
        position = 0
        while True:
            position = blob.find(b"PK\x03\x04", position)
            if position < 0:
                break
            struct.pack_into("<I", blob, position + 22, 64)
            position += 4
        position = 0
        while True:
            position = blob.find(b"PK\x01\x02", position)
            if position < 0:
                break
            struct.pack_into("<I", blob, position + 24, 64)
            position += 4
        # A valid first member is needed to reach the second stream.
        struct.pack_into("<I", blob, 22, 128)
        struct.pack_into("<I", blob, blob.find(b"PK\x01\x02") + 24, 128)
        self.archive.write_bytes(blob)
        report = self.run_scan(policy=self.policy(limits={"max_total_bytes": 192}))
        self.assertIn("total_size_limit", self.codes(report))
        self.assertEqual(report.bytes_scanned, 193)
        self.make_zip([("a", b"X" * 8192)], zipfile.ZIP_DEFLATED)
        compressed = struct.unpack_from("<I", self.archive.read_bytes(), 18)[0]
        self.patch([("local", 22, "<I", compressed * 2), ("central", 24, "<I", compressed * 2)])
        report = self.run_scan(policy=self.policy(limits={"max_ratio": 2}))
        self.assertIn("ratio_limit", self.codes(report))
        compressed = struct.unpack_from("<I", self.archive.read_bytes(), 18)[0]
        self.assertEqual(report.bytes_scanned, compressed * 2 + 1)

    def test_every_extra_field_rejected(self):
        for kind in (0x9999, 0x0001, 0x7075, 0x5455, 0x000d):
            info = zipfile.ZipInfo("a")
            info.extra = struct.pack("<HH", kind, 0)
            self.make_zip([(info, b"fixture")])
            self.assertIn("unsupported_zip", self.codes(self.run_scan()))

    def test_offsets_and_understated_member_count(self):
        self.make_zip([("a", b"fixture")])
        self.patch([("central", 42, "<I", 1)])
        self.assertIn("corrupt_zip", self.codes(self.run_scan()))
        self.make_zip([("a", b"fixture"), ("b", b"fixture")])
        self.patch([("end", 8, "<H", 1), ("end", 10, "<H", 1)])
        self.assertIn("corrupt_zip", self.codes(self.run_scan()))

    def test_special_file_not_hashed_or_required(self):
        info = zipfile.ZipInfo("a")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o600) << 16
        self.make_zip([(info, b"target")])
        report = self.run_scan(policy=self.policy(required=["a"]))
        self.assertIn("special_file", self.codes(report))
        self.assertIn("required_missing", self.codes(report))
        self.assertFalse(report.hashes)

    def test_malformed_manifest_api_is_incomplete(self):
        self.make_zip([("a", b"fixture")])
        self.assertIn("configuration_error", self.codes(self.run_scan(manifest={"a": "invalid"})))

    def test_unknown_creator_and_dos_special_metadata(self):
        self.make_zip([("a", b"fixture")])
        self.patch([("central", 4, "<H", (222 << 8) | 20)])
        self.assertIn("unsupported_zip", self.codes(self.run_scan()))
        for host in (0, 3):
            for attributes in (0x08, 0x40, 0x80, 0x100):
                self.make_zip([("a", b"fixture")])
                self.patch([("central", 4, "<H", (host << 8) | 20),
                            ("central", 38, "<I", attributes)])
                report = self.run_scan()
                self.assertIn("special_file", self.codes(report))
                self.assertFalse(report.hashes)

    def test_rejected_comments_are_redacted(self):
        info = zipfile.ZipInfo("a")
        info.comment = b"-----BEGIN PRIVATE KEY-----"
        with zipfile.ZipFile(self.archive, "w") as target:
            target.comment = b"/home/synthetic_comment/project/"
            target.writestr(info, b"fixture")
        report = self.run_scan()
        self.assertEqual(report.status, "incomplete")
        self.assertIn("unsupported_zip", self.codes(report))
        self.assertFalse(report.hashes)
        self.assertNotIn("synthetic_comment", report.render("json"))

    def test_json_equal_option_configuration_failure(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main([str(self.archive), "--policy", str(self.root / "missing"), "--format=json"]), 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "incomplete")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_input_symlink_rejected_where_supported(self):
        if not hasattr(os, "O_NOFOLLOW"):
            self.skipTest("O_NOFOLLOW unavailable")
        self.make_zip([("a", b"fixture")])
        link = self.root / "link.zip"
        link.symlink_to(self.archive)
        self.assertEqual(scan_archive(link, self.policy()).status, "incomplete")

if __name__ == "__main__":
    unittest.main()
