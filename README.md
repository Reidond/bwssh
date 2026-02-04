# bwssh

Bitwarden-backed SSH agent for Linux. Store your SSH keys in Bitwarden and use
them seamlessly with any SSH client.

## Features

-   **Bitwarden integration**: SSH keys stored securely in your Bitwarden vault
-   **Standard SSH agent**: Works with `ssh`, `git`, and any SSH client
-   **Systemd integration**: Runs as a user service, starts on login
-   **Forwarding protection**: Blocks remote servers from using your keys
-   **Optional polkit prompts**: Desktop authorization popups (disabled by default)

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

Config file: `~/.config/bwssh/config.toml`

### Required: Add Your SSH Keys

First, find your Bitwarden SSH key item IDs:

```bash
bw unlock
export BW_SESSION="..."  # from unlock output
bw list items | jq -r '.[] | select(.sshKey != null) | "\(.id) \(.name)"'
```

Then add them to your config:

```toml
[bitwarden]
bw_path = "/full/path/to/bw"  # Use 'which bw' to find this
item_ids = [
    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",  # your-key-name
]
```

### Full Config Example

```toml
[daemon]
log_level = "INFO"

[bitwarden]
bw_path = "/usr/bin/bw"
item_ids = [
    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
]

[auth]
# Polkit authorization prompts (default: disabled)
require_polkit = false

# Block forwarded agent requests (recommended)
deny_forwarded_by_default = true

[ssh]
allow_ed25519 = true
allow_ecdsa = true
allow_rsa = true
```

### Environment Variables

-   `BWSSH_RUNTIME_DIR`: Override socket directory
-   `BWSSH_LOG_LEVEL`: Override log level
-   `BW_SESSION`: Bitwarden session key (auto-detected by `bwssh unlock`)

## Security

### Default Mode

By default, bwssh allows all local signing requests without prompts. Security comes from:

-   Your Bitwarden vault being locked when away (`bwssh lock`)
-   Forwarded agent requests being blocked by default

### Polkit Prompts (Optional)

For extra security, enable polkit to show desktop prompts for each signing request:

```toml
[auth]
require_polkit = true
```

This requires installing the polkit policy:

```bash
bwssh install --polkit | sudo tee /etc/polkit-1/actions/io.github.reidond.bwssh.policy > /dev/null
```

See `docs/` for detailed polkit setup instructions.

## CLI Commands

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
