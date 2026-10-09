# Privacy

## Local processing

Release Bundle Guard processes the supplied ZIP and a separate policy locally.
It does not send archives, policies, findings, or hashes to a server. The checker
has no telemetry, remote signature feed, account sign-in, or network scanning.
Its runtime uses the Python standard library.

This describes the checker itself. A shell, editor, CI service, terminal logger,
backup service, or wrapper around it can independently record or upload inputs
and outputs. Review those systems before checking confidential material.

## Reports are still sensitive

Secret indicators are deliberately narrow. Findings identify a rule and an
opaque member ID without printing the matched secret value, source excerpt, or
member name.
This redaction is not a guarantee that output contains no sensitive data:

- External expected-hash manifests contain member paths and SHA-256 hashes;
  those paths may themselves contain identifiers or secrets.
- Reports contain IDs, sizes, hashes, counts, and categories that can expose
  unreleased project details.
- Hashes can let someone who already has candidate bytes recognize those bytes.

Review every report and manifest before sharing it. Do not publish private
artifacts or raw reports as examples. Use synthetic files and credentials for
bug reports and tests.

## Files and retention

The checker does not extract archive members, modify their contents, or create
a persistent scanning database. Command-line output can be saved by the caller, and `--report` explicitly
requests a report file. The caller controls where output goes and how long it
is retained. Python may write bytecode caches unless invoked with `-B`. Keep
policies and reports outside the release archive.

Deleting a report does not remove copies retained by CI logs, shell history,
backups, or other software. This project does not provide secure deletion or
retention enforcement.

## Detection limits

A release can contain personal data or credentials without triggering an
indicator. Encoded, obfuscated, novel, or application-specific secrets can be
missed, and ordinary test strings can trigger false positives. Review release
contents and build inputs separately. A `pass` result is not a privacy review,
consent check, or guarantee that a bundle is secret-free.
