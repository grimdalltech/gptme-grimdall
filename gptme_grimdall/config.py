"""Configuration for gptme-grimdall.

Shadow mode is ON by default: the plugin logs what it *would* block but allows
execution, so behavior is unchanged until enforcement is explicitly enabled.

Configuration is read from ``GRIMDALL_*`` environment variables:

- ``GRIMDALL_SHADOW_MODE``  — "0"/"false"/"no"/"off" enables enforcement
- ``GRIMDALL_EGRESS_ALLOWLIST`` — comma-separated host allowlist (default empty)
- ``GRIMDALL_SECRET_PATTERNS`` — comma-separated extra secret globs
- ``GRIMDALL_DESTRUCTIVE_PATTERNS`` — comma-separated extra destructive regexes
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _split_env_list(raw: str | None) -> set[str]:
    if not raw:
        return set()
    return {item.strip() for item in raw.split(",") if item.strip()}


@dataclass
class Config:
    """Runtime configuration for the grimdall security policy."""

    # Log-only, allow everything (zero behavior change). Default True.
    shadow_mode: bool = True

    # Egress allowlist: hosts permitted for outbound network access.
    # Empty means deny-all — any detected egress to a host is blocked.
    egress_allowlist: set[str] = field(default_factory=set)

    # Extra secret path globs, merged with the built-in defaults.
    extra_secret_patterns: set[str] = field(default_factory=set)

    # Extra destructive command patterns (regex), merged with built-ins.
    extra_destructive_patterns: set[str] = field(default_factory=set)

    @classmethod
    def from_env(cls) -> "Config":
        """Build a :class:`Config` from ``GRIMDALL_*`` environment variables."""
        return cls(
            shadow_mode=os.environ.get("GRIMDALL_SHADOW_MODE", "1").lower()
            not in {"0", "false", "no", "off"},
            egress_allowlist=_split_env_list(
                os.environ.get("GRIMDALL_EGRESS_ALLOWLIST")
            ),
            extra_secret_patterns=_split_env_list(
                os.environ.get("GRIMDALL_SECRET_PATTERNS")
            ),
            extra_destructive_patterns=_split_env_list(
                os.environ.get("GRIMDALL_DESTRUCTIVE_PATTERNS")
            ),
        )


# Module-level default config; replace at runtime to reconfigure.
config = Config.from_env()
