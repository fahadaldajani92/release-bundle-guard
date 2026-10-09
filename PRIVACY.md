# Privacy

## Local processing

Release Bundle Guard reads an explicitly selected ZIP, external policy, and
optional external manifest. It makes no application network requests, uploads,
telemetry calls, or account connections. The standard-library implementation
captures one bounded immutable in-memory archive copy and does not extract or
execute its contents. Operating-system file access can still involve mounted
filesystems; use trusted local storage.

Shells, CI services, terminal loggers, editors, backup agents, and wrappers can
independently save or upload inputs and outputs. Review those systems before
using confidential material.

## Reports and fingerprints

Findings use opaque member IDs and fixed categories. They do not print member
names, local paths, matched values, source excerpts, or exception text.

All reports, including failed/incomplete ones, can expose member counts,
aggregate `bytes_scanned`, and finding categories. Passing reports additionally
contain member sizes/hashes and the whole captured archive's size/hash. Those
hashes let someone recognize or guess candidate bytes.

Report schema 2 withholds every member/archive hash when the result is fail or
incomplete, including known secret/private-path findings and report-publication
errors. This avoids intentionally publishing known-rejected content fingerprints
in the current result. It does not make passing reports nonsensitive: narrow
indicators miss secrets, and an apparently benign archive digest can still
confirm a guess about secret-bearing content.

External manifests contain filenames and expected hashes. Policies may expose
release structure. Retain the exact configuration and checker used privately;
the report's archive digest does not identify the external policy or manifest.
Review every report and reference before sharing. Use synthetic data for tests
and bug reports, never live credentials or private release bundles.

## Report files and retention

By default the application writes stdout only. Explicit `--report` requests a
new report and private same-directory staging file. The report directory must
be trusted and outside release staging. Symlink parents and ambiguous path
components are rejected, and publication is anchored to one opened directory.
The final no-clobber link requires supported POSIX/local-filesystem operations.

A write, short write, flush, sync, or close failure before linking does not
publish a partial final target. A link error can have an uncertain outcome:
a complete PASS file may exist while stdout/exit report incomplete. The tool
does not roll back a possibly unrelated target. Always check the current exit
code and JSON result instead of a file's presence or first line.

Cleanup is best effort. Interruption or cleanup failure may leave a hidden
`.release-bundle-guard-*.tmp` file containing the complete report and its hashes,
even if final publication failed and current stdout suppresses hashes. Staging
files are mode 0600, but are not encrypted or securely erased. Review and remove
unneeded leftovers through your normal trusted workflow before packaging files.

The tool does not maintain a scanning database or persistent archive snapshot.
Python may create bytecode caches unless run with `-B`. The caller controls
output retention; deleting one copy does not remove CI logs, backups, or other
copies. No secure-deletion or retention enforcement is provided.

## Detection limits

Non-ASCII names and all ZIP comments are rejected by the strict profile; this
is a compatibility restriction, not a full personal-data detector. Content
indicators are narrow ASCII byte patterns. Personal data, encoded or novel
credentials, and application-specific secrets can pass undetected, while
ordinary synthetic examples can trigger findings. A pass is not consent,
a privacy review, or a guarantee that a bundle is secret-free.
