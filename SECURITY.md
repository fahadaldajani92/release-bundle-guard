# Security

Release Bundle Guard is an early-stage offline ZIP policy checker. It is not
antivirus, a sandbox, a general secret scanner, or a guarantee of safe release,
extraction, or execution. No production assurance, certification, or comprehensive
independent audit is claimed.

A pass means the implemented checks completed under the supplied external
configuration. All other scan statuses reject the release. Exact help requests
exit 3 without scanning. Require exit 0 and schema-2 JSON status `pass`, then
verify the reported archive identity against the bytes being distributed.

## Operational boundaries

- Use a maintained runtime without elevated privileges. Run hostile inputs in
  a disposable, low-privilege environment with external memory/CPU/time limits.
- Keep policy and optional manifest outside the archive and under separate
  review. Retain their exact contents and the checker/runtime used. The archive
  digest does not bind configuration, source code, or publisher identity.
- Supply fixed trusted CLI options and `--` before the artifact filename.
- The compressed archive is captured once into immutable memory, with 16 MiB
  default/32 MiB hard size limits. Parse and hash use that same copy; this is
  not an atomic filesystem snapshot or protection against later replacement.
- Compare the reported whole-archive SHA-256 with the exact distributed bytes.
  Source-file mutations after capture do not alter or automatically invalidate
  the captured result. A changing original path is not monitored or locked.
- ASCII-only names and zero comments/extras are intentional strict-profile
  restrictions. No general ZIP-reader or target-filesystem equivalence is claimed.
- Reports always disclose some counts/categories/aggregate bytes. Passing
  reports include hashes that can fingerprint undetected secrets. Review before
  sharing; failed/incomplete current reports suppress every content hash.
- For `--report`, use a trusted local filesystem and directory whose writers
  you trust, outside release staging. No symlink parent or dot/dot-dot/empty
  path component is accepted. Unsupported anchored/link operations fail closed.
- Report linking never deliberately overwrites an existing entry. A failed
  link can have an uncertain result on some filesystems, leaving a complete
  report despite exit 2. Do not accept a file alone or assume rollback.
- Hidden mode-0600 temporary reports can remain after interruption or failed
  cleanup and may contain passing hashes. Review leftovers before distribution.

The checker does not extract or execute archive contents. Subsequent extraction,
installation, or execution needs its own protections. See [THREAT_MODEL.md](THREAT_MODEL.md)
and [PRIVACY.md](PRIVACY.md) for detailed limits.

## Potential vulnerabilities

No private security-reporting endpoint is configured for this prototype. No
reporting email address or enabled repository vulnerability-reporting channel
is asserted here. Do not post real secrets, private artifacts, or identifying
project details in public issues. Prepare a minimal synthetic reproducer.
A maintainer must establish and verify a private channel before accepting
sensitive reports.

No response-time promise, supported-version schedule, bounty, or disclosure
program is offered.
