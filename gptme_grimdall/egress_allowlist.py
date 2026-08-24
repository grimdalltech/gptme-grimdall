"""Egress allowlist: deny network egress to undeclared hosts.

The allowlist starts empty (deny all). A host is permitted if it exactly
matches an allowlist entry or is a subdomain of one (``api.example.com`` is
allowed by ``example.com``). Any detected egress to an undeclared host is
blocked, which stops secret exfiltration via ``curl``/``wget`` and friends.
"""

from __future__ import annotations

import re
from typing import Iterable, Optional
from urllib.parse import urlparse

# Tools that imply outbound network egress.
EGRESS_TOOLS = frozenset(
    {
        "curl",
        "wget",
        "nc",
        "netcat",
        "ncat",
        "socat",
        "telnet",
        "ftp",
        "ssh",
        "scp",
        "sftp",
        "rsync",
        "git",
        "pip",
        "pip3",
        "pipx",
        "npm",
        "npx",
        "yarn",
        "cargo",
        "gh",
        "docker",
        "podman",
        "iwr",
        "irm",
        "invoke-webrequest",
        "invoke-restmethod",
    }
)

_URL_RE = re.compile(r"https?://([^\s/\"'`<>]+)", re.IGNORECASE)

# ssh/scp/sftp/rsync target of the form [user@]host[:path]
_SSH_HOST_RE = re.compile(
    r"\b(?:ssh|scp|sftp|rsync)\b(?:\s+-\S+)*\s+"
    r"(?:[a-zA-Z0-9._-]+@)?([a-zA-Z0-9.-]+)(?=:|\s|$)",
)


def _bare_host(host: str) -> str:
    # Strip port and userinfo.
    host = host.split("@")[-1]
    if ":" in host and not host.startswith("["):
        host = host.rsplit(":", 1)[0]
    return host.strip("[]").lower()


def extract_hosts(command: str) -> set[str]:
    """Extract outbound hostnames from a shell command."""
    hosts: set[str] = set()
    if not command or not isinstance(command, str):
        return hosts

    for m in _URL_RE.finditer(command):
        hosts.add(_bare_host(m.group(1)))

    for m in _SSH_HOST_RE.finditer(command):
        hosts.add(m.group(1).lower())

    return hosts


def _host_allowed(host: str, allowlist: set[str]) -> bool:
    for allowed in allowlist:
        if host == allowed or host.endswith("." + allowed):
            return True
    return False


def check_egress(
    command: str,
    allowlist: Iterable[str] = (),
) -> Optional[str]:
    """Return a block reason if ``command`` targets an undeclared host.

    Empty allowlist = deny all detected egress.
    """
    hosts = extract_hosts(command)
    if not hosts:
        return None

    allowed = {h.strip().lower() for h in allowlist if h and h.strip()}
    for host in sorted(hosts):
        if not _host_allowed(host, allowed):
            return f"egress blocked: host not allowlisted: {host}"
    return None


def _url_host(url: str) -> Optional[str]:
    """Parse a single URL and return its host (helper for tests)."""
    try:
        parsed = urlparse(url)
        return parsed.hostname.lower() if parsed.hostname else None
    except ValueError:
        return None
