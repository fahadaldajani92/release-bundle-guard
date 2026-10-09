"""Restricted ZIP32 scanner: bounded reads, no extraction and no execution."""
from dataclasses import dataclass
import fnmatch
import hashlib
import os
import re
import stat
import struct
import time
import zlib

from .policy import (ConfigurationError, Policy, manifest_from_dict, MAX_NAME_BYTES, MAX_EXTRA_BYTES, MAX_CENTRAL_BYTES,
                     open_regular, valid_name, name_key)
from .report import Report

CHUNK = 64 * 1024
EOCD = struct.Struct("<4s4H2IH")
CENTRAL = struct.Struct("<4s6H3I5H2I")
LOCAL = struct.Struct("<4s5H3I2H")
SECRET = re.compile(
    rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
    rb"|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"
    rb"|\bgh[pousr]_[A-Za-z0-9]{36}\b"
    rb"|\bgithub_pat_[A-Za-z0-9_]{50,200}\b"
    rb"|(?i:\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|password)"
    rb"\s{0,16}[:=]\s{0,16}[\"']?[A-Za-z0-9_+/=\-]{16,256})")
PRIVATE_PATH = re.compile(rb"/(?:Users|home)/[A-Za-z0-9_.-]{1,128}/"
                          rb"|[A-Za-z]:\\Users\\[A-Za-z0-9_. -]{1,128}\\")

class StopScan(Exception):
    def __init__(self, code, member=None):
        self.code, self.member = code, member

@dataclass
class Member:
    ident: str
    name: str
    raw_name: bytes
    flags: int
    method: int
    crc: int
    compressed: int
    size: int
    offset: int
    version: int
    mtime: int
    mdate: int
    external: int
    directory: bool
    data_offset: int = 0

    @property
    def is_regular(self):
        return (not self.directory and stat.S_IFMT(self.external >> 16) in (0, stat.S_IFREG)
                and not self.external & 0xFFD8)

class Scanner:
    def __init__(self, data, policy, manifest, report, clock, *, start=None):
        if type(data) is not bytes:
            raise TypeError("immutable bytes required")
        self.data, self.policy, self.manifest = data, policy, manifest
        self.report, self.clock = report, clock
        self.start = clock() if start is None else start
        self.deadline = self.start + policy.limits["max_seconds"]
        self.size = len(data)

    def tick(self):
        if self.clock() >= self.deadline:
            raise StopScan("time_limit")

    def read(self, offset, count):
        self.tick()
        if offset < 0 or count < 0 or offset + count > self.size:
            raise StopScan("corrupt_zip")
        data = self.data[offset:offset + count]
        self.tick()
        if len(data) != count:
            raise StopScan("corrupt_zip")
        return data

    def extras(self, value):
        if len(value) > MAX_EXTRA_BYTES:
            raise StopScan("metadata_limit")
        offset = 0
        while offset < len(value):
            self.tick()
            if len(value) - offset < 4:
                raise StopScan("corrupt_zip")
            kind, size = struct.unpack_from("<HH", value, offset)
            offset += 4
            if offset + size > len(value):
                raise StopScan("corrupt_zip")
            # Even apparently benign extensions can alter another reader's
            # filename or type semantics. This MVP supports no extra fields.
            raise StopScan("unsupported_zip")

    def directory(self):
        limits = self.policy.limits
        if self.size > limits["max_archive_bytes"]:
            raise StopScan("archive_size_limit")
        if self.size < EOCD.size:
            raise StopScan("corrupt_zip")
        tail_size = min(self.size, 65535 + EOCD.size)
        tail = self.read(self.size - tail_size, tail_size)
        index = tail.rfind(b"PK\x05\x06")
        if index < 0 or index + EOCD.size > len(tail):
            raise StopScan("corrupt_zip")
        _, disk, cd_disk, on_disk, count, cd_size, cd_start, comment_size = EOCD.unpack_from(tail, index)
        end_offset = self.size - tail_size + index
        if index + EOCD.size + comment_size != len(tail):
            raise StopScan("corrupt_zip")
        if comment_size:
            raise StopScan("unsupported_zip")
        if disk or cd_disk or on_disk != count or count == 0xFFFF or cd_size == 0xFFFFFFFF or cd_start == 0xFFFFFFFF:
            raise StopScan("unsupported_zip")
        if count > limits["max_members"]:
            raise StopScan("member_count_limit")
        if cd_size > MAX_CENTRAL_BYTES:
            raise StopScan("metadata_limit")
        if cd_start + cd_size != end_offset:
            raise StopScan("corrupt_zip")
        # Even an empty ZIP must have no unparsed prefix or payload.
        if count == 0 and cd_start != 0:
            raise StopScan("corrupt_zip")
        members, position, total_declared = [], cd_start, 0
        for number in range(count):
            self.tick()
            if position + CENTRAL.size > end_offset:
                raise StopScan("corrupt_zip")
            values = CENTRAL.unpack(self.read(position, CENTRAL.size))
            (signature, made, version, flags, method, mtime, mdate, crc,
             compressed, size, name_size, extra_size, comment_size, disk,
             internal, external, offset) = values
            ident = f"member-{number + 1:04d}"
            self.report.member_count += 1
            if comment_size:
                raise StopScan("unsupported_zip", ident)
            if signature != b"PK\x01\x02":
                raise StopScan("corrupt_zip", ident)
            if flags & 1:
                raise StopScan("encrypted_member", ident)
            if (made >> 8) not in (0, 3) or version > 20 or disk or method not in (0, 8) or flags & ~0x806:
                raise StopScan("unsupported_zip", ident)
            if method == 0 and flags & 6:
                raise StopScan("unsupported_zip", ident)
            if compressed == 0xFFFFFFFF or size == 0xFFFFFFFF or offset == 0xFFFFFFFF:
                raise StopScan("unsupported_zip", ident)
            if not 0 < name_size <= MAX_NAME_BYTES or extra_size > MAX_EXTRA_BYTES:
                raise StopScan("metadata_limit", ident)
            next_position = position + CENTRAL.size + name_size + extra_size + comment_size
            if next_position > end_offset:
                raise StopScan("corrupt_zip", ident)
            raw_name = self.read(position + CENTRAL.size, name_size)
            if not raw_name.isascii():
                # The strict profile supports ASCII only, regardless of flags.
                raise StopScan("unsupported_zip", ident)
            try:
                name = raw_name.decode("ascii")
            except UnicodeError:
                raise StopScan("corrupt_zip", ident) from None
            self.extras(self.read(position + CENTRAL.size + name_size, extra_size))
            if size > limits["max_member_bytes"]:
                raise StopScan("member_size_limit", ident)
            total_declared += size
            if total_declared > limits["max_total_bytes"]:
                raise StopScan("total_size_limit", ident)
            if size > max(compressed, 1) * limits["max_ratio"]:
                raise StopScan("ratio_limit", ident)
            member = Member(ident, name, raw_name, flags, method, crc, compressed,
                            size, offset, version, mtime, mdate, external, name.endswith("/"))
            members.append(member)
            position = next_position
        if position != end_offset:
            raise StopScan("corrupt_zip")
        expected_offset = 0
        for member in sorted(members, key=lambda item: item.offset):
            self.tick()
            if member.offset != expected_offset or member.offset + LOCAL.size > cd_start:
                raise StopScan("corrupt_zip", member.ident)
            values = LOCAL.unpack(self.read(member.offset, LOCAL.size))
            signature, version, flags, method, mtime, mdate, crc, compressed, size, name_size, extra_size = values
            if signature != b"PK\x03\x04" or (version, flags, method, mtime, mdate, crc, compressed, size) != (
                    member.version, member.flags, member.method, member.mtime, member.mdate,
                    member.crc, member.compressed, member.size):
                raise StopScan("corrupt_zip", member.ident)
            if name_size != len(member.raw_name) or extra_size > MAX_EXTRA_BYTES:
                raise StopScan("corrupt_zip", member.ident)
            data_start = member.offset + LOCAL.size + name_size + extra_size
            if data_start + compressed > cd_start:
                raise StopScan("corrupt_zip", member.ident)
            if self.read(member.offset + LOCAL.size, name_size) != member.raw_name:
                raise StopScan("corrupt_zip", member.ident)
            self.extras(self.read(member.offset + LOCAL.size + name_size, extra_size))
            member.data_offset = data_start
            expected_offset = data_start + compressed
        if expected_offset != cd_start:
            raise StopScan("corrupt_zip")
        return members

    def policies(self, members):
        seen, file_keys = {}, set()
        for member in members:
            self.tick()
            name, ident = member.name, member.ident
            if not valid_name(name):
                self.report.add("unsafe_name", ident)
            key = name_key(name.rstrip("/"))
            if key in seen:
                self.report.add("name_collision", ident)
            seen[key] = ident
            if not member.directory:
                file_keys.add(key)
            mode = member.external >> 16
            kind = stat.S_IFMT(mode)
            if mode & 0o7002:
                self.report.add("unsafe_permissions", ident)
            expected = stat.S_IFDIR if member.directory else stat.S_IFREG
            if (kind not in (0, expected) or member.external & 0xFFC8
                    or (member.external & 0x10 and not member.directory)):
                self.report.add("special_file", ident)
            if member.directory and member.size:
                raise StopScan("corrupt_zip", ident)
            if not any(fnmatch.fnmatchcase(name, pattern) for pattern in self.policy.allow):
                self.report.add("not_allowed", ident)
            if any(fnmatch.fnmatchcase(name.lower(), pattern.lower()) for pattern in self.policy.forbidden):
                self.report.add("forbidden", ident)
            self.indicators(name.encode("utf-8"), ident)
        for member in members:
            self.tick()
            key = name_key(member.name.rstrip("/"))
            components = key.split("/")
            if any("/".join(components[:index]) in file_keys for index in range(1, len(components))):
                self.report.add("name_collision", member.ident)
        for number, pattern in enumerate(self.policy.required, 1):
            self.tick()
            if not any(item.is_regular and fnmatch.fnmatchcase(item.name, pattern) for item in members):
                self.report.add("required_missing", rule=f"required-{number:04d}")

    def indicators(self, data, ident):
        if SECRET.search(data):
            self.report.add("secret_indicator", ident)
        if PRIVATE_PATH.search(data):
            self.report.add("private_path_indicator", ident)

    def content(self, member):
        limits, actual, crc, tail = self.policy.limits, 0, 0, b""
        digest = hashlib.sha256()
        def output_limit():
            return max(1, min(CHUNK, member.size - actual + 1,
                              limits["max_member_bytes"] - actual + 1,
                              limits["max_total_bytes"] - self.report.bytes_scanned + 1,
                              int(max(member.compressed, 1) * limits["max_ratio"]) - actual + 1))
        def consume(block):
            nonlocal actual, crc, tail
            self.tick()
            actual += len(block)
            self.report.bytes_scanned += len(block)
            if actual > limits["max_member_bytes"]:
                raise StopScan("member_size_limit", member.ident)
            if self.report.bytes_scanned > limits["max_total_bytes"]:
                raise StopScan("total_size_limit", member.ident)
            if actual > max(member.compressed, 1) * limits["max_ratio"]:
                raise StopScan("ratio_limit", member.ident)
            if actual > member.size:
                raise StopScan("corrupt_zip", member.ident)
            digest.update(block)
            crc = zlib.crc32(block, crc)
            self.indicators(tail + block, member.ident)
            # Every indicator has a finite match width under 512 bytes.
            tail = (tail + block)[-512:]
        remaining, position = member.compressed, member.data_offset
        inflater = zlib.decompressobj(-15) if member.method == 8 else None
        while remaining:
            self.tick()
            amount = min(CHUNK, remaining, output_limit()) if inflater is None else min(CHUNK, remaining)
            block = self.read(position, amount)
            position += amount
            remaining -= amount
            if inflater is None:
                consume(block)
                continue
            while block:
                self.tick()
                previous = len(block)
                decoded = inflater.decompress(block, output_limit())
                consume(decoded)
                if inflater.unused_data or (inflater.eof and remaining):
                    raise StopScan("corrupt_zip", member.ident)
                block = inflater.unconsumed_tail
                if block and len(block) == previous and not decoded:
                    raise StopScan("corrupt_zip", member.ident)
        if inflater is not None:
            while not inflater.eof:
                self.tick()
                decoded = inflater.decompress(b"", output_limit())
                if not decoded:
                    raise StopScan("corrupt_zip", member.ident)
                consume(decoded)
            if inflater.unused_data or inflater.unconsumed_tail:
                raise StopScan("corrupt_zip", member.ident)
        if actual != member.size or crc != member.crc or (member.method == 0 and member.size != member.compressed):
            raise StopScan("corrupt_zip", member.ident)
        self.tick()
        if member.is_regular:
            hexdigest = digest.hexdigest()
            if self.report.status == "pass":
                self.report.hashes.append({"member": member.ident, "sha256": hexdigest, "bytes": actual})
            if self.manifest is not None and self.manifest.get(member.name) != hexdigest:
                self.report.add("manifest_mismatch", member.ident)

    def bind_archive(self):
        """Hash the complete compressed artifact only after a passing scan."""
        digest = hashlib.sha256()
        for position in range(0, self.size, CHUNK):
            digest.update(self.read(position, min(CHUNK, self.size - position)))
        self.tick()
        self.report.archive_sha256 = digest.hexdigest()
        self.report.archive_bytes = self.size

    def run(self):
        members = self.directory()
        self.policies(members)
        for member in members:
            self.content(member)
        if self.manifest is not None and {item.name for item in members if item.is_regular} != set(self.manifest):
            self.report.add("manifest_mismatch")
        self.tick()


def scan_archive(path, policy, manifest=None, *, clock=time.monotonic):
    """Scan one explicit regular-file ZIP. Errors become redacted reports.

    Library deadlines are cooperative, not an OS CPU/memory sandbox. Callers
    should create Policy with from_dict/load; configuration never comes from ZIP.
    """
    report = Report()
    try:
        # Revalidate library-created policy objects rather than trusting limits.
        policy = Policy.from_dict({"version": 1, "allow": list(policy.allow),
                                   "required": list(policy.required), "forbidden": list(policy.forbidden),
                                   "limits": policy.limits})
        if manifest is not None:
            manifest = manifest_from_dict({"version": 1, "sha256": manifest})
        # Capture one immutable bounded byte string. Parsing, decompression and
        # the artifact digest use only this copy, never another filesystem read.
        start = clock()
        deadline = start + policy.limits["max_seconds"]
        with open_regular(path) as stream:
            before = os.fstat(stream.fileno())
            if before.st_size > policy.limits["max_archive_bytes"]:
                raise StopScan("archive_size_limit")
            if clock() >= deadline:
                raise StopScan("time_limit")
            data = stream.read(before.st_size + 1)
            after = os.fstat(stream.fileno())
            if clock() >= deadline:
                raise StopScan("time_limit")
            if len(data) > policy.limits["max_archive_bytes"]:
                raise StopScan("archive_size_limit")
            if len(data) != before.st_size or (
                    before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise StopScan("input_changed")
        scanner = Scanner(data, policy, manifest, report, clock, start=start)
        scanner.run()
        if report.status == "pass":
            scanner.bind_archive()
    except StopScan as exc:
        report.add(exc.code, exc.member, incomplete=True)
    except ConfigurationError:
        report.add("configuration_error", incomplete=True)
    except OSError:
        report.add("input_error", incomplete=True)
    except (zlib.error, struct.error, UnicodeError):
        report.add("corrupt_zip", incomplete=True)
    except Exception:
        # Do not leak exception messages, filenames, paths, or archive bytes.
        report.add("scan_error", incomplete=True)
    if report.status != "pass":
        report.clear_hashes()
    return report
