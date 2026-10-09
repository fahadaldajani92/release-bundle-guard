"""Read-only by default CLI; the optional report must be a new file."""
import argparse
import os
import sys
import tempfile

from .policy import ConfigurationError, Policy, load_manifest
from .report import Report
from .scanner import scan_archive

class PrivateParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default error embeds caller-supplied paths/options.
        raise ConfigurationError("invalid command line")

def parser():
    result = PrivateParser(prog="release-bundle-guard", allow_abbrev=False, description=(
        "Offline restricted ZIP checks. No extraction, execution, or network. "
        "PASS is not a malware verdict."))
    result.add_argument("archive", metavar="ARCHIVE")
    result.add_argument("--policy", required=True, metavar="POLICY", help="external trusted JSON policy")
    result.add_argument("--manifest", metavar="MANIFEST", help="external trusted SHA-256 comparison manifest")
    result.add_argument("--format", choices=("human", "json"), default="human")
    result.add_argument("--report", metavar="NEW_FILE", help="also create a new report file; never overwrite")
    return result

def write_new_report(path, text):
    """Publish a complete report atomically, refusing all existing destinations.

    Hard-link publication is required. There is no overwrite/rename fallback.
    Temporary files are private, same-directory, and cleaned up best effort;
    a crash or cleanup failure can leave a temporary file, never a partial final
    destination. The caller trusts the destination directory and its writers.
    """
    directory = os.path.dirname(os.path.abspath(path))
    fd, temporary = tempfile.mkstemp(prefix=".release-bundle-guard-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            if stream.write(text) != len(text):
                raise OSError("incomplete report write")
            stream.flush()
            os.fsync(stream.fileno())
        # A new hard link is atomic and fails if any destination already exists,
        # including a symlink. No partially written final file is ever visible.
        os.link(temporary, path, follow_symlinks=False)
    finally:
        try:
            os.unlink(temporary)
        except OSError:
            pass


def main(argv=None):
    try:
        args = parser().parse_args(argv)
        policy = Policy.load(args.policy)
        manifest = load_manifest(args.manifest) if args.manifest else None
        report = scan_archive(args.archive, policy, manifest)
    except ConfigurationError:
        report = Report()
        report.add("configuration_error", incomplete=True)
        # Best effort to honor a valid format without echoing invalid arguments.
        words = list(sys.argv[1:] if argv is None else argv)
        format = "json" if "--format=json" in words or any(
            words[i:i + 2] == ["--format", "json"] for i in range(len(words))) else "human"
        sys.stdout.write(report.render(format))
        return report.exit_code
    if args.report:
        try:
            write_new_report(args.report, report.render(args.format))
        except (OSError, ValueError, UnicodeError, NotImplementedError):
            report.add("report_error", incomplete=True)
    sys.stdout.write(report.render(args.format))
    return report.exit_code
