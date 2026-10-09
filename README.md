# Release Bundle Guard

An offline, standard-library-only Python checker for ZIP release policies.
It checks whether a supported ZIP stays within a separately reviewed path
allowlist and resource budget, flags selected unsafe metadata and narrow
secret indicators, and records SHA-256 hashes for fully inspected files.
An optional external hash manifest can pin the expected file set and contents.

**Status: early prototype.** This is not antivirus, a general secret scanner,
a safe-extraction tool, or a guarantee that a release is safe or secret-free.
A passing report means only that this implementation completed its checks
under the supplied policy. No production adoption or independent audit is
claimed.

## What it does

- Reads ZIP metadata and member streams without extracting or executing them.
- Applies an external allowlist and optional required/forbidden path patterns.
- Rejects unsafe or ambiguous supported ZIP metadata and unsupported ZIP forms.
- Enforces configured archive, member-count, expanded-byte, ratio, and elapsed-
  time checks, with actual streamed-byte accounting.
- Looks for a deliberately small set of ASCII secret and private-path indicators.
- Emits member IDs, categories, sizes, and hashes rather than matched values,
  source excerpts, or member names.
- Optionally compares all regular-file paths and hashes with an external
  manifest.

The application makes no network requests and has no runtime dependencies
outside the Python standard library. It does not download signatures, upload
artifacts, repair archives, or inspect nested archives recursively.

## Run from the source directory

No package installation is needed for source-tree execution. Use a maintained
Python 3.10 or newer (the current test run uses Python 3.12).

Create `release-policy.json` alongside, and outside, the release ZIP:

```json
{
  "version": 1,
  "allow": ["README.txt", "assets/*.txt"],
  "required": ["README.txt"],
  "forbidden": [],
  "limits": {
    "max_archive_bytes": 67108864,
    "max_members": 1000,
    "max_member_bytes": 8388608,
    "max_total_bytes": 67108864,
    "max_ratio": 100,
    "max_seconds": 10
  }
}
```

Check a local artifact from the source directory:

```sh
python -B -m release_bundle_guard demo-release.zip --policy release-policy.json
```

Use `--format json` for a machine-readable report. Use `--report new-report.json`
to request a report file, and select JSON explicitly if desired:

```sh
python -B -m release_bundle_guard demo-release.zip --policy release-policy.json --format json --report new-report.json
```

`--report` creates a new file and refuses to overwrite any existing path.
Input files must be regular files; final-component symlinks are refused on
platforms that support `O_NOFOLLOW`.

The `-B` switch disables Python bytecode-cache writes. The application itself
only writes a report when `--report` is requested. Shell redirection, CI logging,
and other software may independently save output.

All filenames and policy examples here are synthetic. Keep real policies and
reports outside distributed artifacts, and review reports before sharing.

## Policy patterns and trust

`allow` is required and must not be empty. `required`, `forbidden`, and individual
limits are optional. Patterns are case-sensitive Python `fnmatchcase` patterns,
not regular expressions or filesystem traversal expressions. In particular,
`*` can match `/`: `assets/*.txt` can match nested paths beneath `assets/`.
The policy applies to archive entries; required patterns are satisfied by
regular files, not directory placeholders.

Review patterns against the intended release layout. A broad pattern such as
`*` is permissive and should not be mistaken for a curated release policy.
A permitted name does not make the bytes inside that member trustworthy.

Keep the policy under independent review. Do not let an untrusted archive
provide or choose its own acceptance policy. Changing the policy can change the
answer; a pass is meaningful only with the exact policy that was used.

## Optional expected-hash manifest

`--manifest expected-manifest.json` reads an external JSON manifest. It is an
input for verification, not a command to generate a trusted reference.
The format is:

```json
{
  "version": 1,
  "sha256": {
    "README.txt": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  }
}
```

This synthetic manifest expects exactly one regular file, an empty
`README.txt`. It will reject a nonempty file or a different regular-file set.
Directory entries are not part of the expected regular-file set.

```sh
python -B -m release_bundle_guard demo-release.zip --policy release-policy.json --manifest expected-manifest.json --format json
```

Create and review the reference through a trusted process. Hash comparison
establishes agreement with that reference; it does not authenticate a publisher,
prove provenance, or detect malicious bytes already present in the reference.
An attacker who can replace both archive and manifest can make them agree.

## Outcomes and release gates

| Status | Exit code | Meaning |
| --- | --- | --- |
| `pass` | `0` | Supported checks completed; no policy violations were reported. |
| `fail` | `1` | Inspection completed and found one or more policy violations. |
| `incomplete` | `2` | Required inspection did not complete; reject the artifact. |

Only exit `0` is an accepting result. Unsupported input, corruption, encryption,
or resource-limit failures must not be treated as a pass, even if no secret
indicator is reported or some file hashes are available. A partial report is
not a complete inventory or a guarantee about the uninspected bytes.

Use the process exit code in automation. Do not ignore nonzero exits or infer
success merely from the presence of a report file. Command-line usage errors
also produce a nonzero exit.

## Supported ZIP scope

The prototype intentionally accepts a narrow subset: single-disk ZIP32 archives
with stored or deflated members, FAT/Unix creator metadata, and no extra fields. ZIP64, split/multidisk
archives, encryption, data descriptors, unsupported compression, unfamiliar
flags, unknown creator hosts, and every nonempty extra-field block are rejected as incomplete. Some valid ZIPs
produced by other tools are therefore outside scope.

Do not automatically repackage rejected files just to obtain a pass: review why
they were rejected and preserve the identity of the actual artifact being
released. The checker does not recurse into archive files stored as members.
Their raw bytes may be hashed, but their contained files are not inspected.

## Indicator and resource limits

The indicators look for a narrow selection of ASCII private-key headers,
AWS-style access-key identifiers, GitHub-style tokens, obvious secret
assignments, and Unix/Windows home-path strings. These byte-pattern checks apply
to member contents, decoded names, and archive/member comments. They do not verify credentials
or determine whether a match is live. Test data may trigger them. Encoded,
obfuscated, unfamiliar, and application-specific secrets may go undetected.
A pass is not a privacy review.

Byte, count, ratio, and elapsed-time limits reduce exposure to some hostile
archives. Time checks are cooperative; the process is not an OS-enforced
sandbox, memory quota, CPU quota, or guaranteed wall-clock deadline. Parsing
and decompression can consume resources before the next check. For hostile
inputs, run with low privileges and external process or container limits.
Do not increase limits blindly after an incomplete result.

Reports use member IDs instead of paths and omit matched content. Hashes,
sizes, counts, and finding categories can still disclose information. Treat
reports and external manifests as potentially sensitive. See
[PRIVACY.md](PRIVACY.md), [SECURITY.md](SECURITY.md), and the detailed
[threat model](THREAT_MODEL.md).

### Fixed and configurable bounds

| Limit | Default | Hard maximum |
| --- | --- | --- |
| Compressed archive | 64 MiB | 256 MiB |
| Members | 1,000 | 10,000 |
| Expanded bytes per member | 8 MiB | 64 MiB |
| Expanded bytes across archive | 64 MiB | 256 MiB |
| Expanded/compressed ratio per member | 100 | 1,000 |
| Cooperative elapsed seconds | 10 | 60 |

All values must be positive; byte and count limits must be integers. The ratio
uses compressed member bytes with a denominator of at least one. A stream may
produce at most one byte beyond a configured byte or ratio budget to establish
that it exceeds that budget, then inspection stops. Stream output is processed
in chunks no larger than 64 KiB. Limits are not an OS memory guarantee.

Fixed bounds include an 8 MiB central directory, 1,024-byte member names, a
64 KiB external policy, a 2 MiB external manifest, and at most 128 patterns per
pattern group, with at most 512 characters per pattern. Unknown configuration
keys, duplicate JSON keys, non-finite values, and invalid limits are rejected.

ZIP member names must use relative slash-separated paths. Controls, backslashes,
colons, empty/dot/dot-dot components, Windows-invalid characters and reserved
names, trailing dots/spaces, NFC/case-fold collisions, and file/directory prefix
conflicts are rejected. This is a deliberately conservative policy, not a
complete model of every filesystem. Policies match original decoded names;
normalization is used for collision checks rather than silently renaming files.

## Tests

```sh
python -B -m unittest discover -s tests -v
```

Tests create small synthetic temporary fixtures inside the project's `tests`
directory and clean them up. No private artifact, real credential, extraction,
network service, or dependency install is needed.

## Development and license

The prototype is designed for synthetic fixtures and local verification before
any use as a release gate. A passing test suite is not evidence of production
adoption, comprehensive coverage, or the absence of vulnerabilities.

A license has not been selected for this prototype. No copyright identity,
maintenance commitment, or security-reporting endpoint is established by this
repository.
