# Threat model

## Purpose and assets

Release Bundle Guard provides a repeatable, local gate for selected properties
of ZIP release artifacts. Its useful assets are the release contents, the
operator's machine and credentials, the separately reviewed policy, and the
integrity and interpretation of the resulting report.

The attacker may control every byte of an archive: member contents, file names,
metadata, compression streams, ordering, and malformed structures. A benign
build can also accidentally include unwanted files or credentials. Archive
names and file contents are data, never instructions to execute.

The policy, checker source, Python runtime, invocation, and host operating
system are trusted inputs. A party able to alter the policy or checker can
change what is accepted. A compromised host is outside this tool's protection.

## Boundaries

1. The operator selects a local archive and a policy stored outside that archive.
2. The checker parses ZIP metadata and checks supported names and entry types.
3. It reads supported member streams under configured limits, hashes bytes, and
   applies narrow byte-pattern secret indicators.
4. It optionally compares completed regular-file hashes against an external
   expected-hash manifest, then emits a report for the operator to interpret.

There is no extraction, installation, execution, repair, nested application
launch, or network lookup. The tool does not trust an archive-embedded policy
or a claimed publisher identity. Reports use opaque member IDs and redact matching contents. External
expected-hash manifests still contain member paths.

## Threats and controls

### Unwanted release files

A separately supplied allowlist narrows the paths permitted in a release.
Policy mistakes remain possible: a permissive pattern can allow unwanted
files, and a permitted file can contain malicious or confidential content.
Review policy changes alongside release-layout changes. Passing the allowlist
is not content approval.

### Unsafe or ambiguous ZIP metadata

The checker rejects names or member types its safety checks regard as unsafe,
including traversal-like paths and link-like entries. Unsupported, encrypted,
or corrupt input cannot produce a passing result. These checks do not promise
compatibility with every ZIP reader, target filesystem, installer, or operating
system. Consumers may interpret the same archive differently.

The checker never extracts members. A result is not authorization to extract an
archive into a sensitive directory, overwrite files, follow links, or run a
program. The downstream extractor still needs its own protections.

### Resource exhaustion

Archive bytes, metadata counts and sizes, declared uncompressed sizes, ratios,
and actual streamed bytes can be constrained by the implementation. Declared
metadata is not proof of actual decompressed size, so actual reads must also
stay within the stream budgets.

These are application-level checks, not hard operating-system quotas. Parsing,
allocation, and decompression occur within Python and its compression
libraries. Some work occurs before a limit can be detected; bounded input size
does not imply a small or precisely bounded CPU or memory cost. Elapsed-time checks are cooperative and cannot interrupt an ongoing library
operation. The checker has no process-level memory limit, CPU quota, or
guaranteed deadline.

For attacker-controlled archives, use a low-privilege, disposable environment
with external memory, CPU, and wall-clock limits. Keep unrelated sensitive data
and credentials out of that environment. Resource-limit rejection means the
check is incomplete, not that the unseen remainder is safe.

### Secret and private-data leakage

Only the implemented secret indicators are checked. They are heuristics,
not validation that a credential exists or is live. False positives and false
negatives are expected. Encoding, obfuscation, unsupported content, novel token
formats, and secrets split across an application's own containers can evade
these indicators. Nested archive contents are not recursively inspected.

Findings omit matched values, source excerpts, and member names. External
expected-hash manifests contain paths, which can include private information or
secrets placed there by an attacker. Report hashes, sizes, counts, and categories
can also reveal information. Restrict and review reports before publication. The checker
does not perform a general personal-data, copyright, license, or compliance
review.

### Misleading integrity claims

Reported SHA-256 hashes record fully read member bytes. An external
expected-hash manifest is a reference, not a signature or proof of publisher
identity. An attacker who can replace both artifact and manifest can supply
matching values. Hashes do not establish provenance, malware absence,
or reproducibility. Do not treat partial member hashes from an incomplete check as a complete
inventory.

A result concerns the artifact as observed during that invocation. Keep inputs
stable while checking, and preserve and distribute the exact checked artifact.
Concurrent writes or later replacement are outside the release guarantee.

### Runtime or implementation vulnerabilities

ZIP handling and decompression depend on the Python runtime and its underlying
libraries. Defects in them or in this checker may cause crashes, excess resource
use, incorrect reports, or other failures. Synthetic regression tests do not
prove the absence of vulnerabilities. Keep the runtime updated and use host
isolation when the archive's producer is untrusted.

## Interpreting outcomes

- `pass`: supported checks completed and found no reported policy violations.
  It is only a result under that policy and implementation.
- `fail`: one or more violations were found during a completed check.
- `incomplete`: required inspection could not complete, including unsupported,
  corrupt, encrypted, or over-budget input. Treat this as a rejected release.

Do not turn a nonzero exit into success because a report has few findings, a
hash list exists, or part of the archive was readable. If limits must change,
review the cause and policy first; blindly increasing limits defeats the gate.

## Explicit non-goals

- Antivirus, behavioral analysis, exploit detection, or execution sandboxing
- General secret discovery or a guarantee of no credentials or personal data
- Recursive inspection of nested archives or application-specific containers
- Authenticating a publisher, verifying signatures, or establishing provenance
- Reproducible builds, dependency auditing, or supply-chain attestation
- Safe extraction or execution of a release after checking
- Hard process-level CPU, memory, or execution-time isolation
- Proving any legal, licensing, regulatory, or distribution requirement

This prototype has no claimed production deployment, independent audit, or
security certification. Expand this model only alongside implemented and
verified controls.
