# bwssh

Bitwarden-backed SSH agent for Linux. bwssh runs a local SSH agent that signs
using keys stored in Bitwarden, gates signing through polkit approvals, and
integrates with systemd user services.

## Features

-   Bitwarden CLI integration for SSH key material
-   OpenSSH-compatible agent socket at `${XDG_RUNTIME_DIR}/bwssh/agent.sock`
-   polkit authorization with process metadata
-   Approval caching modes: `always`, `per_connection`, `ttl`
-   Forwarded agent guardrails via `deny_forwarded_by_default`

## Requirements

-   Linux with systemd user services
-   Python 3.12+
-   Bitwarden CLI (`bw`) installed and logged in

## Installation

```bash
uv sync
```

## Bitwarden CLI

Install the Bitwarden CLI (`bw`) and log in before using bwssh. See
https://bitwarden.com/help/cli/ for installation instructions.

```bash
bw --version
bw login
```

## Quick start

```bash
uv run bwssh install --user-systemd
uv run bwssh start
uv run bwssh unlock
```

```bash
export SSH_AUTH_SOCK=${XDG_RUNTIME_DIR}/bwssh/agent.sock
ssh -T git@github.com
```

## Configuration

Config file location:

```
${XDG_CONFIG_HOME:-~/.config}/bwssh/config.toml
```

Minimal example:

```toml
[daemon]
agent_socket = "agent.sock"
control_socket = "control.sock"
log_level = "INFO"

[bitwarden]
bw_path = "bw"
mode = "explicit"
item_ids = []

[auth]
approval_mode = "per_connection"
approval_ttl_seconds = 300
deny_forwarded_by_default = true

[ssh]
allow_ed25519 = true
allow_ecdsa = true
allow_rsa = true
prefer_rsa_sha2 = true
```

Environment overrides:

-   `BWSSH_RUNTIME_DIR`
-   `BWSSH_LOG_LEVEL`

## CLI commands

```bash
bwssh status
bwssh start
bwssh stop
bwssh install --user-systemd
bwssh install --polkit
bwssh unlock
bwssh lock
bwssh sync
bwssh keys
```

## Documentation

Full documentation lives in `docs/` and can be served locally:

```bash
cd docs
bun install
bun run dev
```

## Development

```bash
uv run ruff check .
uv run ruff format .
uv run mypy src tests
uv run pytest
```
