"""gptme-grimdall plugin: deterministic pre-execution security guardrails.

Registers a ``TOOL_CONFIRM`` hook (gptme's canonical blocking confirm/deny
decision point — see ``gptme.hooks.confirm``) that evaluates shell commands,
file reads, and network egress against deterministic policies.

Hook semantics (gptme's ``get_confirmation`` tries hooks in priority order,
highest first; returning ``None`` falls through to the next hook; the first
non-``None`` result wins):

- **allow**               -> return ``None`` (fall through to gptme's normal
                             CLI/server/auto confirmation). Never auto-approves.
- **deny** + enforcement  -> return ``ConfirmationResult.skip(reason)``.
- **deny** + shadow mode  -> log the "would-block" receipt, return ``None``.
- **evaluation error**    -> classify as deny (fail closed), then apply the
                             same shadow/enforcement logic above.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any

from gptme.hooks import HookType, register_hook
from gptme.hooks.confirm import ConfirmationResult
from gptme.plugins.plugin import GptmePlugin

from .config import config as grimdall_config
from .egress_allowlist import check_egress
from .secret_denial import check_secret_path, scan_command
from .shell_policy import evaluate_shell

logger = logging.getLogger("gptme_grimdall")

HOOK_NAME = "gptme_grimdall_tool_confirm"
# Must exceed server_confirm (100) and cli/auto_confirm (0) so our deny
# decision is consulted before any hook that would confirm execution.
PRIORITY = 200

_SHELL_TOOLS = frozenset({"shell"})
_CODE_TOOLS = frozenset({"python", "ipython"})
_FILE_TOOLS = frozenset({"read", "save", "append", "patch"})


def _tool_name(tool_use: Any) -> str:
    return getattr(tool_use, "tool", None) or "unknown"


def _args_list(tool_use: Any) -> list[str]:
    a = getattr(tool_use, "args", None)
    return list(a) if isinstance(a, (list, tuple)) else []


def _kwargs(tool_use: Any) -> dict[str, Any]:
    k = getattr(tool_use, "kwargs", None)
    return dict(k) if isinstance(k, dict) else {}


def _content(tool_use: Any) -> str | None:
    return getattr(tool_use, "content", None)


def _extract_command(tool_use: Any) -> str | None:
    # gptme passes the shell command (and code blocks) via ``tool_use.content``,
    # not ``tool_use.args``/``kwargs`` — see ``gptme.tools.base.ToolUse`` and
    # ``gptme.tools.shell.get_shell_command``.
    return _content(tool_use)


def _extract_file_path(tool_use: Any) -> str | None:
    kws = _kwargs(tool_use)
    for key in ("file_path", "path", "filename"):
        val = kws.get(key)
        if val:
            return val
    args = _args_list(tool_use)
    return args[0] if args else None


def _args_hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def _receipt(
    tool: str,
    payload: dict[str, Any],
    decision: str,
    reason: str | None,
    started: float,
) -> dict[str, Any]:
    """Structured audit receipt (``{tool, args_hash, decision, reason, timestamp, latency_ms}``)."""
    return {
        "tool": tool,
        "args_hash": _args_hash(payload),
        "decision": decision,
        "reason": reason,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "latency_ms": round((time.perf_counter() - started) * 1000.0, 3),
    }


def _evaluate(tool: str, command: str | None, file_path: str | None) -> tuple[str, str | None]:
    """Run all three checks; return ``(decision, reason)``."""
    executable = tool in _SHELL_TOOLS or tool in _CODE_TOOLS

    if executable and command:
        # 1. Shell policy
        reason = evaluate_shell(
            command, grimdall_config.extra_destructive_patterns
        )
        if reason:
            return "deny", reason

        # 3. Egress allowlist
        reason = check_egress(command, grimdall_config.egress_allowlist)
        if reason:
            return "deny", reason

    # 2. Secret-read denial
    if file_path:
        reason = check_secret_path(
            file_path, grimdall_config.extra_secret_patterns
        )
        if reason:
            return "deny", reason

    if tool in _SHELL_TOOLS and command:
        reason = scan_command(command, grimdall_config.extra_secret_patterns)
        if reason:
            return "deny", reason

    return "allow", None


def tool_confirm_hook(
    tool_use: Any,
    preview: str | None = None,
    workspace: Any = None,
) -> ConfirmationResult | None:
    """The ``TOOL_CONFIRM`` guardrail hook."""
    started = time.perf_counter()
    tool = _tool_name(tool_use)
    command = _extract_command(tool_use)
    file_path = _extract_file_path(tool_use)
    payload = {"command": command, "file_path": file_path}

    try:
        decision, reason = _evaluate(tool, command, file_path)
    except Exception as exc:  # fail closed
        decision, reason = "deny", f"evaluation error (fail closed): {exc}"
        logger.exception("grimdall evaluation error for tool %r", tool)

    if decision == "deny":
        receipt = _receipt(
            tool,
            payload,
            "would_block" if grimdall_config.shadow_mode else "deny",
            reason,
            started,
        )
        if grimdall_config.shadow_mode:
            logger.info(
                "grimdall [shadow] would block: %s", json.dumps(receipt, default=str)
            )
            return None  # fall through — zero behavior change
        logger.warning("grimdall denied: %s", json.dumps(receipt, default=str))
        return ConfirmationResult.skip(reason)

    return None  # allow — fall through to normal confirmation


def register_hooks() -> None:
    """Register the guardrail hook with gptme's hook registry."""
    register_hook(
        HOOK_NAME,
        HookType.TOOL_CONFIRM,
        tool_confirm_hook,
        priority=PRIORITY,
        enabled=True,
    )


# The gptme plugin manifest, exported via the ``gptme.plugins`` entry point.
plugin = GptmePlugin(
    name="gptme-grimdall",
    register_hooks=register_hooks,
)
