# Security

Release Bundle Guard is an early-stage, offline ZIP release-policy checker. It
is not an antivirus engine, a sandbox, a general secret scanner, or a guarantee
that a release is safe to distribute or run. No production security assurance
or independent security audit is claimed.

A `pass` result only means the implemented checks completed and found no
violations of the supplied policy. An `incomplete` result is a rejection for a
release gate, even if no policy violation was reported. A `fail` result also
rejects the release. See [the threat model](THREAT_MODEL.md) for boundaries and
remaining risks.

## Run on untrusted files with care

- Use a maintained Python runtime and run without elevated privileges.
- Keep the policy outside the archive, under separate review. Do not accept a
  policy supplied by an untrusted release producer as proof of compliance.
- Use a disposable, low-privilege environment for hostile or unknown archives.
  Apply operating-system or container memory, CPU, wall-clock, and filesystem
  limits as appropriate. Application-level byte limits are not a sandbox.
- Do not give the process unnecessary credentials, writable directories, or
  access to sensitive files. An offline tool does not make its runtime immune
  to parser or decompressor defects.
- Treat reports and manifests as potentially sensitive. Manifests contain member paths, and
  report hashes, sizes, counts, and categories can still disclose information.
  Redaction is not a confidentiality guarantee.
- For a scan, require exit 0 and schema-2 JSON `status: pass` with archive identity
  fields. Help exits 0 without scanning and is never an accepting scan result.
  Use fixed trusted options and place `--` before the artifact filename.
- Preserve the exact checked artifact and verify its reported whole-archive
  SHA-256 before distribution. The digest establishes byte identity, not
  authenticity or protection against later replacement. Detection of concurrent
  mutation is best effort.
- Report hashes are emitted only after a complete passing scan. Failed and
  incomplete outputs suppress every hash, but passing reports may still expose
  undetected secrets through candidate fingerprinting. Review before sharing.
- Put requested reports in a directory whose writers you trust. Atomic no-clobber
  publication requires hard-link support; unsupported filesystems fail closed.
  Temporary files may remain after interruption or failed cleanup.

The checker does not extract archive members or execute their contents. That
reduces some risks; it does not make subsequent extraction, installation, or
execution safe.

## Reporting a potential vulnerability

No private vulnerability-reporting endpoint is currently configured for this
prototype. There is no reporting email address or enabled GitHub private
reporting channel asserted by this document.

Do not post live secrets, private release bundles, or identifying project data
in a public issue. Prepare a minimal synthetic reproducer and a description of
the affected behavior. A maintainer must establish and verify a private
reporting channel before accepting sensitive reports. If a future repository
offers GitHub private vulnerability reporting, verify that it is enabled on
that repository before using it.

No response-time commitment, supported-version schedule, bounty, or coordinated
vulnerability-disclosure program is currently offered.
