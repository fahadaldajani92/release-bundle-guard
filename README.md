# Release Bundle Guard

An offline, standard-library-only Python checker for a deliberately restricted
ZIP release profile. It applies an external allowlist, required/forbidden
patterns, resource budgets, selected metadata checks, narrow text indicators,
and an optional external SHA-256 manifest.

**Early prototype.** This is not antivirus, a general secret scanner, a safe
extractor, or a guarantee that a release is safe or secret-free. A pass means
only that the implemented checks completed under the supplied configuration.
No production adoption, security certification, or comprehensive audit is claimed.

## Supported profile

- Single-disk ZIP32 with stored or raw-deflated members and FAT/Unix creator metadata
- ASCII-only member names, including when the ZIP UTF-8 flag is set
- No archive comments, member comments, or nonempty extra fields
- Relative slash-separated names; no controls, backslashes, colons, empty/dot/
  dot-dot components, trailing spaces/dots, or Windows-invalid ASCII characters
- No duplicate/ASCII-case collisions, file/directory path conflicts, symlinks,
  special files, inconsistent types, set-ID/sticky/world-writable mode bits,
  or unsupported DOS attributes
- Conservative reserved-name exclusions, including COM0–COM9 and LPT0–LPT9;
  the zero forms are this tool's policy, not a Microsoft naming claim

Non-ASCII names are outside scope rather than normalized or interpreted using
an assumed code page. This excludes ordinary international filenames as well
as compatibility look-alikes. Name checks use ASCII rules, not a runtime Unicode
database or a claimed model of NTFS, APFS, or every extractor.

ZIP64, split archives, encryption, data descriptors, unknown compression,
unsupported creator hosts/flags, comments, and extra fields are incomplete
results. Some valid ZIPs from common tools therefore cannot pass this profile.
Do not silently repackage a rejected release just to obtain a pass.

The checker never extracts or executes members, makes no application network
requests, and does not recurse into nested archives. ZIP signatures within a
member's payload are ordinary bytes. Comments are rejected entirely, including
comments that contain an earlier EOCD record. These restrictions reduce
ambiguous metadata; they do not prove how every other ZIP reader behaves.

## Run from the source directory

Use maintained Python 3.10 or newer. No installation or runtime dependencies
outside the standard library are needed. Tests must be run in the intended
environment; the version requirement does not imply CI or cross-platform coverage.

```sh
python -B -m release_bundle_guard --policy examples/policy.json -- demo-release.zip
python -B -m release_bundle_guard --policy examples/policy.json --format json --report new-report.json -- demo-release.zip
```

Use fixed trusted options and put `--` before the artifact name so a filename
beginning with `-` cannot become a CLI option. Do not forward untrusted extra
arguments. `-B` disables Python bytecode-cache writes.

By default the application writes only stdout. Explicit `--report` requests a
new report plus a private temporary staging file. Shell redirection, CI logs,
editors, backup agents, and the operating system may independently save data.
All examples and fixtures in this repository are synthetic.

## External policy

The policy must be selected independently of the archive. An embedded policy
never configures this checker.

```json
{
  "version": 1,
  "allow": ["README.txt", "assets/", "assets/*"],
  "required": ["README.txt"],
  "forbidden": ["*.pem", "*.key", "*.env", ".git/*", "*/.git/*"],
  "limits": {
    "max_archive_bytes": 16777216,
    "max_members": 1000,
    "max_member_bytes": 8388608,
    "max_total_bytes": 67108864,
    "max_ratio": 100,
    "max_seconds": 10
  }
}
```

`allow` must be nonempty. `required`, `forbidden`, and individual limits are
optional. Patterns are ASCII Python `fnmatchcase` globs, not regular expressions:

- `allow` and `required` are case-sensitive
- `forbidden` is ASCII case-insensitive, by comparing lowercase names/patterns
- `*` spans `/`; `assets/*.txt` can match nested paths
- Required patterns need regular files, not directory placeholders

Thus `*.pem` forbids `assets/server.PEM`, but an allow pattern `assets/*.txt`
does not allow `assets/FILE.TXT`. Top-level `.git/*` and nested `*/.git/*` are
separate patterns. A broad allowlist such as `*` remains permissive, even with
a few forbidden suffixes. A permitted name does not approve its contents.

Retain the exact policy, optional manifest, checker source/version, and runtime
used for a result. The report's archive hash does not identify or authenticate
those external inputs. Configuration identity and preservation are the caller's
responsibility; the tool does not publish extra configuration fingerprints.

## Optional trusted hash manifest

`--manifest expected-manifest.json` verifies an external reference; it does not
generate a trusted reference. The exact regular-file set must match:

```json
{
  "version": 1,
  "sha256": {
    "README.txt": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  }
}
```

This example expects exactly one empty regular file named `README.txt`.
Directory placeholders are not part of the manifest set. Reference names must
satisfy the ASCII profile. Hashes establish agreement with the reference, not
publisher authenticity, provenance, or malware absence. An attacker who can
replace both artifact and manifest can make them agree.

```sh
python -B -m release_bundle_guard --policy examples/policy.json --manifest expected-manifest.json --format json -- demo-release.zip
```

## Outcomes and report schema

| Outcome | Exit | Meaning |
| --- | --- | --- |
| `pass` | 0 | Supported checks completed with no reported violations |
| `fail` | 1 | Completed inspection found one or more violations |
| `incomplete` | 2 | Required inspection or requested report publication could not complete |
| Help only | 3 | `-h` or `--help`; no scan and no JSON scan result |

Only a scan with exit 0 and a schema-2 JSON report whose status is `pass` is an
accepting result. Verify the identity fields below. Help never exits 0, and
abbreviated options such as `--he` are rejected. Usage errors return 2.

Do not infer success from a human PASS line, the presence of an output file, or
a report from another invocation. Reject every nonzero exit, including a link
operation whose outcome is uncertain. Unsupported, corrupt, encrypted, or
over-budget input is never an accepting result.

Schema 2 uses opaque member IDs, fixed finding categories, aggregate
`members_seen` and `bytes_scanned`, and these identity fields:

- On pass: `archive_sha256`, `archive_bytes`, and regular-member `hashes`
- On fail/incomplete: archive identity fields are null and `hashes` is empty

All content hashes are cleared on any failure, including a later publication
error. Member names, local paths, matching secret text, and exception messages
are not printed. Counts and aggregate scanned-byte totals still disclose
information on failed checks. Schema 2 intentionally differs from the earlier
prototype's schema 1, which exposed hashes on failed/partial results.

Passing reports can still identify secret-bearing bytes that these narrow
indicators missed. A digest allows candidate guessing. Review all reports before
sharing; PASS-only hash disclosure is not a confidentiality guarantee.

## One immutable captured archive

The checker reads a bounded immutable byte copy into memory, then closes the
input. Structure parsing, decompression, member hashes, and the archive digest
all use this same copy. The digest covers every captured compressed byte,
including names and accepted metadata; it does not come from a second read of
the potentially changing file.

Before/after size/time checks during capture reject detected changes. Capture
is not an atomic filesystem snapshot or a lock: a writer could change the source
while it is being read, or immediately afterward. Whatever bytes were captured
are the bytes parsed and hashed. Later changes to the original path do not
change the captured result and are not monitored. Before distribution, compare
the reported archive hash with the exact bytes being distributed.

This consistency choice deliberately spends memory and limits archive size:

| Limit | Default | Hard maximum |
| --- | --- | --- |
| Compressed captured archive | 16 MiB | 32 MiB |
| Members | 1,000 | 10,000 |
| Expanded bytes per member | 8 MiB | 64 MiB |
| Expanded bytes total | 64 MiB | 256 MiB |
| Expanded/compressed ratio per member | 100 | 1,000 |
| Cooperative elapsed seconds | 10 | 60 |

The compressed archive copy, metadata, reports, and transient buffers consume
memory; a 32 MiB archive limit is not a 32 MiB process-memory quota. No default
disk snapshot is created. Capture requests at most the initial file size plus
one byte, after checking that size against the configured bound. Detected growth
or inconsistent capture fails closed. Expanded data is streamed in chunks up
to 64 KiB, with at most one byte past a declared size, byte budget, or ratio
budget to establish rejection. The ratio denominator is at least one byte.

Fixed bounds include an 8 MiB central directory, 1,024-byte names, a 64 KiB policy,
a 2 MiB manifest, and at most 128 patterns per group of at most 512 ASCII
characters each. Unknown configuration keys, duplicate JSON keys, non-finite
values, invalid types, and excessive limits are rejected.

Elapsed-time checks cover capture, parsing, decompression, and archive hashing.
They are cooperative, cannot interrupt an ongoing I/O/library call, and are not
an OS CPU, memory, or wall-clock guarantee. Trusted configuration loading and
report output are outside the scan deadline. Use a maintained runtime and
external process limits for hostile inputs. Do not raise limits blindly.

## Requested report files

File publication requires POSIX directory-relative operations, no-follow
parent-directory opens, and same-directory hard links. Unsupported platforms
or filesystems return incomplete; stdout-only scans remain available. There
is no non-atomic overwrite fallback.

Use a trusted local filesystem and a directory whose writers you trust. The
report path must have no empty, `.` or `..` components and no symlink parent
components. A relative name such as `new-report.json` is supported. Parent
walking, private staging, final link, and cleanup use the same opened directory
anchor; different lexical and symlink resolutions are not mixed.

The staging file is mode 0600. The entire report is written, checked for short
writes, flushed, fsynced, and closed before the final no-clobber link. Existing
entries, including dangling symlinks, are not overwritten. A write/flush/sync/
close failure before linking publishes no new final file.

A link call can have an uncertain outcome, particularly on a network filesystem:
a complete final report may exist even when stdout says incomplete and exit is 2.
The tool does not delete that target or claim rollback. Check the exit code and
current JSON result, never the final file alone. No general power-loss durability
or network-filesystem transaction guarantee is offered.

Cleanup is best effort. Interruption or cleanup failure can leave a hidden
`.release-bundle-guard-*.tmp` containing a full passing report and its hashes,
even after failed publication. Keep report directories outside release staging
and review leftovers after interrupted runs. See [PRIVACY.md](PRIVACY.md),
[SECURITY.md](SECURITY.md), and [THREAT_MODEL.md](THREAT_MODEL.md).

## Indicator limits

The scanner looks for a small selection of ASCII private-key headers, AWS-style
access-key identifiers, GitHub-style tokens, obvious secret assignments, and
Unix/Windows home-path strings in member contents and names. It does not verify
credentials or determine whether a match is live. Synthetic strings may trigger
it. Encoding, obfuscation, novel formats, and nested archives can evade it.
A pass is not a privacy, legal, licensing, or general release-content review.

## Tests and license

```sh
python -B -m unittest discover -s tests -v
```

Tests use small synthetic temporary fixtures inside `tests` and clean them up.
They require no real artifacts, credentials, network service, or dependency
install. They do not establish real extractor behavior, production adoption,
comprehensive coverage, or the absence of vulnerabilities.

A license has not been selected for this prototype. No copyright identity,
maintenance commitment, or security-reporting endpoint is established here.
