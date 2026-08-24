"""gptme-grimdall — deterministic pre-execution security guardrails for gptme.

This package is deliberately importable *without* gptme installed: the pure
policy/check modules (``config``, ``shell_policy``, ``secret_denial``,
``egress_allowlist``) have no gptme dependency, so they can be unit-tested in
isolation. Only ``plugin`` (the gptme entry point) imports gptme.
"""

from .config import Config, config
from .egress_allowlist import check_egress, extract_hosts
from .secret_denial import check_secret_path, is_secret_path, scan_command
from .shell_policy import evaluate_shell

__version__ = "0.1.0"

__all__ = [
    "Config",
    "config",
    "check_egress",
    "extract_hosts",
    "check_secret_path",
    "is_secret_path",
    "scan_command",
    "evaluate_shell",
    "__version__",
]
