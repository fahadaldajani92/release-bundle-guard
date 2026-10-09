"""Read-only by default CLI; the optional report must be a new file."""
import argparse
import os
import sys
import secrets

from .policy import ConfigurationError, Policy, load_manifest
from .report import Report
from .scanner import scan_archive

class NonScanHelp(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        parser.print_help()
        parser.exit(3)

class PrivateParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default error embeds caller-supplied paths/options.
        raise ConfigurationError("invalid command line")

def parser():
    result = PrivateParser(prog="release-bundle-guard", allow_abbrev=False, add_help=False, description=(
        "Offline restricted ZIP checks. No extraction, execution, or network. "
        "PASS is not a malware verdict."))
    result.add_argument("-h", "--help", action=NonScanHelp, nargs=0, help="show help and exit 3 without scanning")
    result.add_argument("archive", metavar="ARCHIVE")
    result.add_argument("--policy", required=True, metavar="POLICY", help="external trusted JSON policy")
    result.add_argument("--manifest", metavar="MANIFEST", help="external trusted SHA-256 comparison manifest")
    result.add_argument("--format", choices=("human", "json"), default="human")
    result.add_argument("--report", metavar="NEW_FILE", help="also create a new report file; never overwrite")
    return result

_ANCHORED_REPORT_SUPPORTED = (
    os.name == "posix" and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW")
    and all(function in os.supports_dir_fd for function in (os.open, os.link, os.unlink))
)


def write_new_report(path, text):
    """Write and publish in one anchored, trusted local directory.

    Parent symlinks, empty/dot/dot-dot components and unsupported platforms are
    rejected. The final hard link never clobbers another entry. A link error can
    have an uncertain outcome on some filesystems; never try to delete a target
    after such an error. A private temporary report may survive failed cleanup.
    """
    if not _ANCHORED_REPORT_SUPPORTED:
        raise NotImplementedError("anchored publication unavailable")
    path = os.fspath(path)
    if not isinstance(path, str) or not path:
        raise ValueError("invalid report path")
    absolute = path.startswith(os.sep)
    parts = path.split(os.sep)[1:] if absolute else path.split(os.sep)
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError("ambiguous report path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory_fd = os.open(os.sep if absolute else ".", flags)
    temporary = None
    try:
        for component in parts[:-1]:
            next_fd = os.open(component, flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        for _ in range(16):
            candidate = ".release-bundle-guard-" + secrets.token_hex(12) + ".tmp"
            try:
                fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory_fd)
            except FileExistsError:
                continue
            temporary = candidate
            break
        else:
            raise OSError("temporary name unavailable")
        try:
            stream = os.fdopen(fd, "w", encoding="utf-8", newline="\n")
        except BaseException:
            os.close(fd)
            raise
        with stream:
            if stream.write(text) != len(text):
                raise OSError("incomplete report write")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, parts[-1], src_dir_fd=directory_fd, dst_dir_fd=directory_fd,
                follow_symlinks=False)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except OSError:
                pass
        os.close(directory_fd)


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
