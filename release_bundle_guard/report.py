"""Privacy-preserving report contract. Never include paths or matched content."""
from dataclasses import dataclass, field
import json

MESSAGES = {
    "input_error": "An explicitly supplied input could not be read as a regular file.",
    "configuration_error": "Trusted configuration is invalid or exceeds its limits.",
    "archive_size_limit": "The archive exceeds the configured compressed size limit.",
    "member_count_limit": "The archive exceeds the configured member count limit.",
    "member_size_limit": "A member exceeds the configured uncompressed size limit.",
    "total_size_limit": "The archive exceeds the configured total uncompressed size limit.",
    "ratio_limit": "A member exceeds the configured compression ratio limit.",
    "time_limit": "The cooperative scan deadline was reached.",
    "metadata_limit": "ZIP metadata exceeds a fixed parser limit.",
    "unsupported_zip": "An unsupported ZIP feature was encountered.",
    "encrypted_member": "Encrypted members are unsupported.",
    "corrupt_zip": "ZIP structure, stream, size, or CRC verification failed.",
    "input_changed": "The archive changed during the scan.",
    "unsafe_name": "A member name violates the portable relative-path rules.",
    "name_collision": "Member names collide exactly or without ASCII case, or file/directory paths conflict.",
    "unsafe_permissions": "A member has set-ID, sticky, or world-writable mode bits forbidden by this profile.",
    "special_file": "A member is a symlink, special file, or has inconsistent type metadata.",
    "not_allowed": "A member does not match the allowlist.",
    "forbidden": "A member matches a forbidden pattern.",
    "required_missing": "A required file pattern has no regular-file match.",
    "secret_indicator": "A narrow secret-like text indicator was detected; matched text is withheld.",
    "private_path_indicator": "A private home-path text indicator was detected; matched text is withheld.",
    "manifest_mismatch": "A file hash or file set differs from the external trusted manifest.",
    "scan_error": "An unexpected scanner error prevented a complete result.",
    "report_error": "Complete publication of the requested new report could not be confirmed.",
}

@dataclass
class Report:
    findings: list = field(default_factory=list)
    hashes: list = field(default_factory=list)
    archive_sha256: str | None = None
    archive_bytes: int | None = None
    member_count: int = 0
    bytes_scanned: int = 0
    incomplete: bool = False
    _finding_keys: set = field(default_factory=set, repr=False)

    def clear_hashes(self):
        self.hashes.clear()
        self.archive_sha256 = None
        self.archive_bytes = None

    def add(self, code, member=None, *, incomplete=False, rule=None):
        # No failed or partial result publishes content fingerprints, including
        # failures found after hashing (input changes or report publication).
        self.clear_hashes()
        self.incomplete |= incomplete
        finding = {"code": code, "message": MESSAGES[code]}
        if member is not None:
            finding["member"] = member
        if rule is not None:
            finding["rule"] = rule
        key = (code, member, rule)
        if key not in self._finding_keys:
            self._finding_keys.add(key)
            self.findings.append(finding)

    @property
    def status(self):
        return "incomplete" if self.incomplete else "fail" if self.findings else "pass"

    @property
    def exit_code(self):
        return {"pass": 0, "fail": 1, "incomplete": 2}[self.status]

    def as_dict(self):
        return {"schema_version": 2, "status": self.status,
                "scope": "Restricted ZIP structure, policy, hashes, and narrow text indicators only.",
                "members_seen": self.member_count, "bytes_scanned": self.bytes_scanned,
                "archive_sha256": self.archive_sha256 if self.status == "pass" else None,
                "archive_bytes": self.archive_bytes if self.status == "pass" else None,
                "hashes": self.hashes if self.status == "pass" else [], "findings": self.findings}

    def render(self, format="human"):
        if format == "json":
            return json.dumps(self.as_dict(), ensure_ascii=True, sort_keys=True, indent=2) + "\n"
        lines = [f"Release bundle check: {self.status.upper()}",
                 "Scope: restricted ZIP structure, policy, hashes, and narrow text indicators only.",
                 f"Members seen: {self.member_count}; bytes scanned: {self.bytes_scanned}"]
        for finding in self.findings:
            target = finding.get("member", finding.get("rule", "archive"))
            lines.append(f"- {target}: {finding['code']}: {finding['message']}")
        if self.status == "pass" and self.archive_sha256 is not None:
            lines.append(f"ARCHIVE SHA256 {self.archive_sha256} ({self.archive_bytes} bytes)")
        for item in self.hashes if self.status == "pass" else []:
            lines.append(f"SHA256 {item['member']} {item['sha256']} ({item['bytes']} bytes)")
        return "\n".join(lines) + "\n"
