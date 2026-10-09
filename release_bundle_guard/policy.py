"""Bounded external configuration loading; archive content never supplies policy."""
from dataclasses import dataclass, field
import json
import math
import os
import re
import stat
import unicodedata

DEFAULTS = {"max_archive_bytes": 64 * 1024**2, "max_members": 1000,
            "max_member_bytes": 8 * 1024**2, "max_total_bytes": 64 * 1024**2,
            "max_ratio": 100, "max_seconds": 10}
CAPS = {"max_archive_bytes": 256 * 1024**2, "max_members": 10000,
        "max_member_bytes": 64 * 1024**2, "max_total_bytes": 256 * 1024**2,
        "max_ratio": 1000, "max_seconds": 60}
MAX_NAME_BYTES = 1024
MAX_CENTRAL_BYTES = 8 * 1024**2
MAX_EXTRA_BYTES = 4096
MAX_PATTERNS = 128

class ConfigurationError(ValueError):
    pass

def open_regular(path):
    """Do not follow the final symlink or block opening a FIFO where supported."""
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("regular file required")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise

def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ConfigurationError("duplicate key")
        result[key] = value
    return result

def read_json(path, limit):
    try:
        with open_regular(path) as stream:
            if os.fstat(stream.fileno()).st_size > limit:
                raise ConfigurationError("configuration limit")
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ConfigurationError("configuration limit")
        result = json.loads(data.decode("utf-8"), object_pairs_hook=_object,
                            parse_constant=lambda _: (_ for _ in ()).throw(ConfigurationError()))
        if type(result) is not dict:
            raise ConfigurationError("object required")
        return result
    except (OSError, UnicodeError, ValueError, RecursionError, OverflowError) as exc:
        raise ConfigurationError("invalid configuration") from exc

def valid_name(name):
    if not name or any(unicodedata.category(char).startswith("C") for char in name):
        return False
    if len(name.encode("utf-8")) > MAX_NAME_BYTES:
        return False
    if name.startswith("/") or any(char in name for char in '\\:*?|<>"'):
        return False
    parts = name[:-1].split("/") if name.endswith("/") else name.split("/")
    if any(part in ("", ".", "..") or part.endswith((" ", ".")) for part in parts):
        return False
    reserved = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", *(f"COM{i}" for i in range(0, 10)),
                *(f"LPT{i}" for i in range(0, 10)),
                *(f"COM{i}" for i in "¹²³"), *(f"LPT{i}" for i in "¹²³")}
    return not any(part.split(".")[0].upper() in reserved for part in parts)

def name_key(name):
    # Deliberately conservative: add uppercase folding, including dotless i.
    # This is a release policy, not an exact model of any filesystem.
    return unicodedata.normalize("NFC", unicodedata.normalize("NFC", name).casefold().upper())

@dataclass(frozen=True)
class Policy:
    allow: tuple
    required: tuple = ()
    forbidden: tuple = ()
    limits: dict = field(default_factory=lambda: DEFAULTS.copy())

    @classmethod
    def from_dict(cls, obj):
        if type(obj) is not dict or set(obj) - {"version", "allow", "required", "forbidden", "limits"}:
            raise ConfigurationError("invalid fields")
        if type(obj.get("version")) is not int or obj["version"] != 1:
            raise ConfigurationError("invalid version")
        groups = {}
        for key in ("allow", "required", "forbidden"):
            value = obj.get(key, [] if key != "allow" else None)
            if type(value) is not list or len(value) > MAX_PATTERNS or (key == "allow" and not value):
                raise ConfigurationError("invalid patterns")
            for pattern in value:
                if type(pattern) is not str or not pattern or len(pattern) > 512:
                    raise ConfigurationError("invalid pattern")
                if any(unicodedata.category(c).startswith("C") for c in pattern):
                    raise ConfigurationError("invalid pattern")
            groups[key] = tuple(value)
        requested = obj.get("limits", {})
        if type(requested) is not dict or set(requested) - set(DEFAULTS):
            raise ConfigurationError("invalid limits")
        limits = DEFAULTS.copy()
        for key, value in requested.items():
            kind = (int, float) if key in ("max_ratio", "max_seconds") else (int,)
            if type(value) not in kind or not 0 < value <= CAPS[key] or not math.isfinite(value):
                raise ConfigurationError("invalid limit")
            limits[key] = value
        return cls(**groups, limits=limits)

    @classmethod
    def load(cls, path):
        return cls.from_dict(read_json(path, 64 * 1024))

def manifest_from_dict(obj):
    if type(obj) is not dict:
        raise ConfigurationError("invalid manifest")
    if set(obj) != {"version", "sha256"} or type(obj["version"]) is not int or obj["version"] != 1:
        raise ConfigurationError("invalid manifest")
    values = obj["sha256"]
    if type(values) is not dict or len(values) > CAPS["max_members"]:
        raise ConfigurationError("invalid manifest")
    normalized = set()
    for name, digest in values.items():
        if not valid_name(name) or name.endswith("/") or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            raise ConfigurationError("invalid manifest entry")
        key = name_key(name)
        if key in normalized:
            raise ConfigurationError("manifest collision")
        normalized.add(key)
    return {name: digest.lower() for name, digest in values.items()}


def load_manifest(path):
    return manifest_from_dict(read_json(path, 2 * 1024**2))
