"""Deterministic shell-policy analysis.

Blocks destructive shell commands regardless of prompt justification:

- ``rm -rf`` / ``rm -f`` targeting dangerous paths (absolute, ``~``, wildcards)
- ``DROP TABLE`` / ``DROP DATABASE`` / ``TRUNCATE`` / ``DELETE FROM`` (SQL)
- ``find ... -delete`` / ``-exec rm``
- ``mkfs``, ``dd``, ``shred``, ``fdisk`` and other raw-disk/system utilities
- fork bombs
- ``chmod -R 000`` (deny-all permissions)

Prefers structural parsing — AST for Python code blocks, ``shlex`` tokenization
for shell — with regex fallbacks for resilience.
"""

from __future__ import annotations

import ast
import re
import shlex
from typing import Iterable, Optional

# ---------------------------------------------------------------------------
# Always-blocked executables (matched on the basename of the first token).
# These are inherently destructive or system-affecting regardless of args.
# ---------------------------------------------------------------------------
ALWAYS_BLOCKED_COMMANDS = frozenset(
    {
        "mkfs",
        "mkfs.ext2",
        "mkfs.ext3",
        "mkfs.ext4",
        "mkfs.btrfs",
        "mkfs.xfs",
        "mkfs.vfat",
        "mkfs.fat",
        "mkfs.ntfs",
        "mkfs.cramfs",
        "mkfs.jffs2",
        "mkfs.exfat",
        "mkdosfs",
        "mkswap",
        "dd",
        "shred",
        "wipefs",
        "blockdev",
        "fdisk",
        "gdisk",
        "sfdisk",
        "cfdisk",
        "parted",
        "reboot",
        "poweroff",
        "halt",
        "shutdown",
    }
)

# Python callables treated as destructive when invoked (AST analysis).
DESTRUCTIVE_PYTHON_CALLS = frozenset(
    {
        "os.remove",
        "os.unlink",
        "os.rmdir",
        "os.removedirs",
        "shutil.rmtree",
        "pathlib.Path.unlink",
        "pathlib.Path.rmdir",
    }
)

# Subprocess-style callables whose string argument is re-analyzed as shell.
SUBPROCESS_CALLS = frozenset(
    {
        "os.system",
        "os.popen",
        "subprocess.call",
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.check_call",
        "subprocess.check_output",
    }
)


def _tokenize(command: str) -> list[str]:
    """Tokenize a shell command, degrading to whitespace split on failure."""
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return command.split()


def _is_dangerous_target(target: str) -> bool:
    """True if ``target`` is a broad/destructive path for ``rm``.

    Conservative line: absolute paths (anywhere on the system), home-relative
    paths, and glob targets are considered dangerous; relative paths within the
    workspace (e.g. ``rm -rf node_modules``) are allowed.
    """
    t = target.strip()
    if not t:
        return True
    if t in {"/", "~", "..", ".", "*", "./", "../", "~/*", "/*"}:
        return True
    if t.startswith("/") or t.startswith("~"):
        return True
    if "*" in t or "?" in t:
        return True
    return False


def _fork_bomb(command: str) -> bool:
    """Detect classic fork-bomb patterns."""
    c = re.sub(r"\s+", "", command)
    patterns = (
        r":\(\)\{:\|:&\};:",   # :(){ :|:& };:
        r":\(\)\{:\|:&};:",    # :(){ :|:& };:  (without trailing colon)
        r"whiletrue;do.*;done",
        r"fork\(\)",
        r"while\(1\)",
    )
    return any(re.search(p, c) for p in patterns)


def _call_name(func: ast.expr) -> Optional[str]:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        base = _call_name(func.value)
        return f"{base}.{func.attr}" if base else func.attr
    return None


def _analyze_python(code: str) -> Optional[str]:
    """AST-based destructive-call detection for Python code blocks."""
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError):
        return None
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            if name in DESTRUCTIVE_PYTHON_CALLS:
                return f"destructive Python call blocked: {name}"
            if name in SUBPROCESS_CALLS:
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        inner = _analyze_shell(arg.value)
                        if inner:
                            return inner
    return None


def _partition(args: list[str]) -> tuple[set[str], list[str]]:
    flags: set[str] = set()
    targets: list[str] = []
    for a in args:
        if a.startswith("-") and a != "-":
            flags.update(a.lstrip("-"))
        else:
            targets.append(a)
    return flags, targets


def _deny_all_permissions(tokens: list[str]) -> bool:
    """Detect ``chmod``/``chown`` to ``000``/``0000`` (deny all permissions)."""
    for tok in tokens[1:]:
        if re.fullmatch(r"0{3,4}", tok):
            return True
    return False


def _is_device(path: str) -> bool:
    return path == "/dev" or path.startswith("/dev/")


def _analyze_shell(command: str) -> Optional[str]:
    """Block destructive shell commands; return a reason string or None."""
    if not command or not command.strip():
        return None

    stripped = command.strip()

    # Fork bombs
    if _fork_bomb(stripped):
        return "fork bomb pattern blocked"

    # SQL destructive statements (case-insensitive)
    upper = stripped.upper()
    if re.search(r"\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX)\b", upper):
        return "SQL DROP statement blocked"
    if re.search(r"\bTRUNCATE\s+(TABLE\s+)?", upper):
        return "SQL TRUNCATE statement blocked"
    if re.search(r"\bDELETE\s+FROM\b", upper):
        return "SQL DELETE FROM blocked"

    tokens = _tokenize(stripped)
    if not tokens:
        return None

    # Skip leading env-var assignments (e.g. "FOO=bar rm -rf /")
    base = tokens[0]
    while "=" in base and base.split("=", 1)[0].isidentifier():
        tokens.pop(0)
        if not tokens:
            return None
        base = tokens[0]

    name = base.rsplit("/", 1)[-1].lower()

    if name in ALWAYS_BLOCKED_COMMANDS:
        return f"destructive command blocked: {name}"

    if name == "rm":
        flags, targets = _partition(tokens[1:])
        # Case-insensitive flag matching: -rf / -fr / -Rf / -rF / -RF all
        # count as recursive+force (re.IGNORECASE handles the R/F casing).
        flag_blob = "".join(flags)
        recursive = re.search(r"r", flag_blob, re.IGNORECASE) is not None
        force = re.search(r"f", flag_blob, re.IGNORECASE) is not None
        if recursive or force:
            for t in targets:
                if _is_dangerous_target(t):
                    return f"rm targeting dangerous path: {t}"

    if name == "find" and (
        "-delete" in tokens or ("-exec" in tokens and "rm" in tokens)
    ):
        return "find with -delete/-exec rm blocked"

    if name in {"chmod", "chown"} and _deny_all_permissions(tokens):
        return f"{name} deny-all permissions blocked"

    if name == "dd" and any(
        t.startswith("of=") and _is_device(t[3:]) for t in tokens
    ):
        return "dd writing to block device blocked"

    # Redirection that clobbers a block device
    if re.search(r">\s*/dev/(sd|nvme|hd|vd|md|dm-|mapper)", stripped):
        return "write to block device blocked"

    return None


def evaluate_shell(
    command: str,
    extra_patterns: Iterable[str] = (),
) -> Optional[str]:
    """Evaluate a command/code string; return a block reason or None.

    Runs the shell analyzer first, then the Python AST analyzer (which only
    fires for strings that actually parse as Python and contain a destructive
    call), then any user-supplied regex patterns.
    """
    if not isinstance(command, str) or not command.strip():
        return None

    reason = _analyze_shell(command)
    if reason:
        return reason

    reason = _analyze_python(command)
    if reason:
        return reason

    for pat in extra_patterns:
        if re.search(pat, command):
            return f"matches destructive pattern: {pat}"

    return None
