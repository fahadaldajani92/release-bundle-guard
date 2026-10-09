# Threat model

## Purpose, assets, and trust

Release Bundle Guard is a local gate for selected properties of a deliberately
restricted ZIP32 profile. Protected interests include release contents,
operator credentials, external acceptance policy, and correct interpretation
of the resulting report. The archive can be entirely attacker-controlled:
bytes, names, metadata, ordering, compression, and malformed records.

The caller, checker source, Python runtime, operating system, external policy,
optional manifest, and invocation are trusted. Report directories and their
writers must be trusted. A compromised host or configuration is outside scope.
Archive content is data, never an instruction to execute.

## Data flow

1. Open the explicitly selected regular-file ZIP without following the final
   symlink where supported, reject excessive initial size, and capture at most
   that size plus one byte into immutable memory.
2. Check size/time metadata around capture and reject detected changes or
   excess bytes. Close the source. No disk snapshot is made.
3. Parse, validate, decompress, and hash only the immutable captured bytes,
   applying the external policy, actual-output budgets, and narrow indicators.
4. Compare any external expected-hash manifest. On complete pass only, report
   member hashes plus a hash and size covering the complete captured artifact.
5. Write stdout. If requested, stage a private report and attempt no-clobber
   publication within one opened trusted directory.

There is no extraction, execution, installation, repair, recursive nested-
archive inspection, signature download, upload, or application network lookup.

## Unwanted files and policy mistakes

Allow and required globs are case-sensitive. Forbidden globs deny an original
match or an ASCII-lowercased match, preserving original range semantics as well
as case-insensitive coverage. `*` spans path separators. These deliberate semantics must
be reviewed with the release layout. A broad allowlist plus a few denied suffixes
is not comprehensive content approval. Required patterns need regular files.

The archive never supplies or selects its own policy. Retain the exact external
policy, optional manifest, and checker/runtime used: the artifact hash does not
identify those inputs. An attacker who controls both archive and reference
can make their hashes agree. No publisher identity is authenticated.

## Name, metadata, and reader ambiguity

The profile accepts ASCII names only, irrespective of UTF-8 flags. It rejects
all non-ASCII names rather than relying on a legacy code page, Unicode database,
normalization convention, best-fit conversion, or heuristic filesystem model.
This includes legitimate international names and reduces compatibility.

Names must be portable relative slash-separated paths under the documented
conservative rules. Duplicate/case-insensitive conflicts, file/directory-prefix
conflicts, symlinks, special files, unsupported DOS metadata, and set-ID/sticky/
world-writable mode bits cannot pass. COM0/LPT0 are conservative policy
exclusions rather than asserted operating-system reserved names. ASCII trailing
spaces in the basename before its first dot are ignored for this reservation
check, as a conservative policy rather than a tested extractor exploit.

Every archive/member comment and nonempty extra field is unsupported. This
also excludes earlier EOCD records hidden in comments. Contiguous local and
central records, exact header agreement, and end-record lengths must account
for the captured ZIP. Signatures within regular member payloads are ordinary
bytes and remain allowed; nested archives are not recursively checked.
These restrictions are not proof that every other reader chooses the same view.
The checker never extracts; a pass is not permission to trust an extractor.

## Consistency and artifact identity

The same immutable byte copy supplies every parse, decoded stream, and complete
archive digest. A second read of a changing file cannot substitute different
hash input after inspection. Capture itself is not a locked, atomic filesystem
snapshot: source bytes can change while being read, and metadata checks are
best effort. Whatever bytes were captured are the bytes validated and hashed.

The original path may change after capture without changing the result. No
ongoing monitoring or lock is provided. Compare the report's archive digest
with the exact bytes distributed and preserve them. A hash establishes byte
identity, not provenance, benign behavior, reproducibility, or authenticity.

## Resource exhaustion

Capture has a 16 MiB default and 32 MiB hard compressed-archive cap. Parsing
bounds member counts, central-directory size, names and other metadata.
Decompression checks actual bytes, declared size, per-member/total budgets,
ratio, EOF, trailing data, and CRC. At most one extra byte is decoded to prove
a declared-size or budget breach, with output chunks no larger than 64 KiB.

A full compressed copy resides in memory alongside metadata, stream buffers,
and report objects; the compressed cap is not a process-memory quota. There
can be additional transient allocation. Time checks include capture, parsing,
decompression, and artifact hashing, but are cooperative and cannot interrupt
an ongoing I/O/library operation. Configuration loading and report publication
are outside that deadline. No OS CPU/memory/wall-clock isolation is provided.
Use low privileges and external process limits for hostile data.

## Confidentiality and narrow indicators

Only a small set of ASCII byte-pattern indicators is implemented. False
positives and negatives are expected. Encoded, obfuscated, novel, non-ASCII,
and application-specific secrets, including nested content, can be missed.
No general personal-data, copyright, license, legal, or compliance review occurs.

Current fail/incomplete reports omit every member/archive hash, including when
a later report operation fails. Names, matches, paths, and exception text are
not printed. Aggregate counts, scanned-byte totals, and categories still
reveal information. Passing hashes can identify secret-bearing candidate bytes
that the indicators missed. External manifests also expose names and hashes.
Review all outputs before sharing.

## Invocation and report publication

Only exit 0 plus a valid schema-2 JSON pass report is scan acceptance. Exact
`-h`/`--help` exit 3 and do not scan; abbreviated options are errors. Use fixed
trusted options and `--` before the artifact name.

File reports require supported POSIX directory-relative/no-follow operations
and a trusted local filesystem with hard links. Symlink parents and empty,
dot, or dot-dot path components are rejected. Parent traversal, mode-0600
staging, linking, and cleanup share the same opened directory anchor.
Unsupported primitives fail closed; there is no overwrite fallback.

A staged report is fully written, checked for short writes, flushed, fsynced,
and closed before linking. Failures before link do not publish a partial final
file. The no-clobber link does not deliberately overwrite existing entries.
Some filesystems, notably remote ones, can complete a link but return an error.
Then a complete PASS report can exist while the current result is incomplete
and the exit is 2. The checker does not delete that target or claim rollback;
a consumer must reject the current nonzero result. This is not a distributed
transaction or general power-loss durability guarantee.

Cleanup is best effort. Interrupted or failed cleanup can leave a private
hidden staging file, potentially containing a full report and passing hashes.
Keep report directories outside release staging and review leftovers. No
secure deletion, encryption, or retention enforcement is provided.

## Runtime defects and verification limits

The checker, Python, and zlib can contain defects causing crashes, incorrect
results, or resource overuse. Synthetic tests and bounded checks do not prove
the absence of vulnerabilities. No real-world extractor conversion, filesystem
normalization, network-filesystem transaction, or cross-platform behavior is
asserted merely from these tests. Keep the runtime maintained and use host
isolation when inputs are untrusted.

This prototype has no claimed production deployment, security certification,
or comprehensive audit. A pass is evidence only for the implemented strict
profile and chosen trusted configuration.
