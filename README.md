# gptme-grimdall

Deterministic security plugin for [gptme](https://github.com/gptme/gptme) that enforces policy below the model.

## What it catches

- **Destructive shell commands** (`rm -rf`, `DROP TABLE`, fork bombs, `chmod -R 000`)
- **Secret file reads** (`~/.ssh/id_rsa`, `~/.aws/credentials`, `.env`, `*.pem`)
- **Egress to undeclared hosts** (blocks secret exfiltration via `curl`/`wget`)

## How it works

Registers a `TOOL_CONFIRM` hook that AST-parses commands before execution. Runs in **shadow-mode by default** (logs what it would block, zero behavior change unless enabled).

- <2ms overhead
- No LLM in the hot path
- Deterministic policy enforcement
- Fails closed on any evaluation error

## Architecture

The plugin wraps gptme's tool confirmation hook to intercept shell execution:

1. **Shell policy** — AST-parse commands, block destructive patterns regardless of prompt justification
2. **Secret-read denial** — refuse reads of `~/.ssh`, `~/.aws`, `.env`, `*.pem`, keychain material
3. **Egress allowlist** — deny network egress not on explicit allowlist

Shadow mode emits a system message showing what would have been blocked, so users can preview before enabling enforcement.

## Status

Early development. Maintainer-endorsed plugin (see [gptme#3598](https://github.com/gptme/gptme/issues/3598)).

## Installation

*(Coming soon — wiring the hook registry now)*

## License

MIT
