"""Secret-read denial: block reads of sensitive paths.

Matching is done against the ``~``-expanded path AND the basename, so both
absolute paths (``~/.ssh/id_rsa``) and bare filenames (``id_rsa``) are caught.
Paths and patterns are normalized to forward slashes and ``~``-expanded on
both sides so matching is consistent across platforms.
"""

from __future__ import annotations

import os
import shlex
from fnmatch import fnmatch
from typing import Iterable, Optional

# Full-path globs (matched against the ~-expanded, normalized path).
DEFAULT_PATH_PATTERNS: tuple[str, ...] = (
    "~/.ssh/*",
    "~/.aws/*",
    "~/.config/*",
    "~/.gnupg/*",
    "~/.kube/*",
    "~/.docker/*",
    "~/Library/Keychains/*",
    "*/Keychains/*",
)

# Basename patterns (matched against the final path component).
DEFAULT_BASENAME_PATTERNS: tuple[str, ...] = (
    "id_rsa",
    "id_rsa.*",
    "id_ed25519",
    "id_ed25519.*",
    "id_ecdsa",
    "id_ecdsa.*",
    "id_dsa",
    "id_dsa.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.ppk",
    ".env",
    ".env.*",
    ".git-credentials",
    ".netrc",
    "*.tfstate",
    "*keychain*",
)


def _expand(path: str) -> str:
    return os.path.expanduser(path).replace(os.sep, "/")


def _normalize(path: str) -> str:
    return os.path.normpath(os.path.expanduser(path)).replace(os.sep, "/")


def _norm_pattern(pat: str) -> str:
    return os.path.expanduser(pat).replace(os.sep, "/")


def is_secret_path(
    path: str,
    extra_patterns: Iterable[str] = (),
) -> bool:
    """Return True if ``path`` matches a sensitive-path glob."""
    if not path or not isinstance(path, str):
        return False

    normalized = _normalize(path)
    raw = path.replace(os.sep, "/")
    basename = normalized.rstrip("/").split("/")[-1]

    # Case-insensitive matching: secret names are not case-sensitive in
    # practice (e.g. ".ENV", "ID_RSA"), so treat them as a boundary to block.
    for pat in DEFAULT_PATH_PATTERNS:
        p = _norm_pattern(pat)
        if fnmatch(normalized.lower(), p.lower()) or fnmatch(raw.lower(), pat.lower()):
            return True
    for pat in DEFAULT_BASENAME_PATTERNS:
        if fnmatch(basename.lower(), pat.lower()):
            return True
    for pat in extra_patterns:
        p = _norm_pattern(pat)
        if (
            fnmatch(normalized.lower(), p.lower())
            or fnmatch(basename.lower(), p.lower())
            or fnmatch(raw.lower(), pat.lower())
        ):
            return True
    return False


def check_secret_path(
    path: str,
    extra_patterns: Iterable[str] = (),
) -> Optional[str]:
    """Return a block reason if ``path`` is sensitive, else None."""
    if is_secret_path(path, extra_patterns):
        return f"secret path read blocked: {path}"
    return None


def scan_command(
    command: str,
    extra_patterns: Iterable[str] = (),
) -> Optional[str]:
    """Best-effort detection of secret paths referenced by a shell command.

    Tokenizes the command and checks each token against the secret globs, which
    catches reads like ``cat ~/.ssh/id_rsa``, ``cp .env /tmp``, etc.
    """
    if not command or not isinstance(command, str):
        return None
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()
    for tok in tokens:
        reason = check_secret_path(tok, extra_patterns)
        if reason:
            return reason
    return None
