# bwssh — Bitwarden-backed SSH Agent (Python)

**Status:** Draft (v0.1)
**Date:** 2026-02-02
**Target OS:** Linux (systemd user services + polkit)
**Repository:** https://github.com/Reidond/bwssh
**Tooling constraints:** Use **uv** for project/deps/build/run and **ruff** for lint/format only.

---

## Naming and identifiers (canonical)

-   **Project / repo:** `bwssh`
-   **CLI binary:** `bwssh`
-   **Daemon binary:** `bwssh-agentd`
-   **Python package:** `bwssh`

### Runtime paths

-   **Runtime dir:** `$XDG_RUNTIME_DIR/bwssh/`
-   **Agent socket:** `$XDG_RUNTIME_DIR/bwssh/agent.sock`
-   **Control socket:** `$XDG_RUNTIME_DIR/bwssh/control.sock`

### systemd user units

-   `bwssh-agent.service`
-   `bwssh-agent.socket`

### polkit action IDs (reverse-DNS)

-   `io.github.reidond.bwssh.sign`
-   `io.github.reidond.bwssh.unlock`
-   `io.github.reidond.bwssh.list`

### polkit policy file

-   `io.github.reidond.bwssh.policy`

---

## 0. Executive summary

Yes — it’s entirely feasible to build a Python CLI + daemon that behaves like an SSH agent and mediates private-key use via interactive approval (similar to Bitwarden Desktop’s SSH Agent behavior). The core requirements are:

-   Implement the SSH agent protocol over a Unix domain socket referenced by `SSH_AUTH_SOCK`.
-   Support at least **list identities** and **sign request** operations (the common subset used by OpenSSH).
-   Identify the requesting client process (Linux: `SO_PEERCRED`) and gate signing behind **polkit** authorization.
-   Integrate with Bitwarden to obtain SSH key material (ideally without ever writing private keys to disk).

Bitwarden’s own documentation describes their agent as a Unix-domain-socket based service which implements a subset of the agent protocol (list + sign), requiring user verification for signing. Their deep-dive also calls out using `SO_PEERCRED` to identify the requesting process on Unix. (See references.)

This spec defines an OSS-friendly, Linux-first design that can be implemented in Python 3.12+ with an `asyncio` daemon, polkit authorization checks, and a Bitwarden “provider” abstraction.

---

## 1. Goals and non-goals

### 1.1 Goals (must have)

1. **Act as an SSH agent (protocol v2 focus).**

    - Provide a Unix domain socket that OpenSSH (`ssh`, `ssh-add`, `git`, etc.) can use via `SSH_AUTH_SOCK`.
    - Implement request/response framing as per the de-facto agent protocol standard (IETF draft + OpenSSH docs).

2. **Supported operations (MVP)**

    - `REQUEST_IDENTITIES` → return public keys + comments.
    - `SIGN_REQUEST` → return a valid signature for a matching key.
    - All other operations: reply with failure (explicitly “unsupported”).

3. **Daemon mode**

    - Run persistently as a **per-user** background service.
    - Provide a CLI to start/stop/status, and to unlock/sync keys.

4. **Interactive authorization via polkit**

    - For every **sign** operation (or per configured policy), request authorization via polkit.
    - Include caller identity (pid/uid/exe/cmdline) and key metadata (fingerprint, label) in the authorization prompt where possible.

5. **Bitwarden-backed key source**

    - Keys are stored in the user’s Bitwarden vault (as “SSH key” items or other supported storage patterns).
    - Private keys are handled in-memory only (no disk writes by default).

6. **Modern Python project layout and tooling**
    - `pyproject.toml` (PEP 621) + `uv.lock`.
    - `uv` as the only environment/dependency/build frontend.
    - `ruff` as the only linter/formatter (no black/isort/flake8).

### 1.2 Non-goals (explicitly out of scope)

-   Providing root privileges or privilege escalation (polkit is used strictly for authorization prompts, not “sudo”).
-   Windows/macOS agent transports (named pipes on Windows, launchd integration, etc.).
-   Full SSH agent feature parity (smartcard/PKCS#11, key generation, constraint editing, etc.).
-   “Keys never leave the vault” in the strict Bitwarden sense: in this design, the daemon must eventually hold decrypted private key material (at least transiently) to sign.

---

## 2. Target users and use-cases

### 2.1 Users

-   Developers who store SSH keys in Bitwarden and want agent-style signing without exporting the key to `~/.ssh`.
-   Users who want an approval prompt each time a key is used (or per process/TTL).

### 2.2 Core use-cases

-   `ssh git@github.com` uses the agent to authenticate.
-   `git fetch/push` uses SSH auth repeatedly; user can configure approval caching.
-   `ssh-add -L` lists keys (public only).
-   Agent forwarding (`ssh -A`) is either blocked or handled with stronger prompts by default.

---

## 3. High-level architecture

```
+---------------------------+          +-----------------------------------+
| OpenSSH / git / rsync ... |          | bwssh CLI                          |
| (client processes)        |          | - status/start/stop                 |
|                           |          | - unlock (Bitwarden)                |
|   SSH_AUTH_SOCK           |          | - sync keys                         |
|      |                    |          | - install systemd/polkit assets     |
+------|--------------------+          +------------------|----------------+
       |                                                Control socket (UDS)
       v
+---------------------------+
| bw-ssh-agentd (daemon)    |
| - UDS listener (agent)    |
| - SSH agent protocol      |
| - Key registry (pub/priv) |
| - polkit auth checks      |
| - Bitwarden provider      |
+---------------------------+
```

### 3.1 Processes and sockets

-   **Agent socket (data plane):** Unix domain socket that implements SSH agent protocol.
-   **Control socket (control plane):** Unix domain socket with a small JSON-RPC-ish API for management:
    -   `status`, `sync`, `lock`, `unlock`, `reload-config`, `list-keys`.
-   Both sockets are created under `XDG_RUNTIME_DIR` with strict permissions (0700 dir, 0600 socket).

---

## 4. Functional requirements

### 4.1 SSH agent protocol (MVP)

#### 4.1.1 Framing

-   Messages are: `uint32 length` (big endian) + `byte type` + payload.
-   The server only sends replies in response to requests (no unsolicited messages).

#### 4.1.2 Requests to implement

1. **REQUEST_IDENTITIES**

    - Return `IDENTITIES_ANSWER` with all available public keys and comments.
    - Works even when locked (public keys only), if configured.

2. **SIGN_REQUEST**
    - Find the referenced public key blob.
    - Authorize via polkit according to policy.
    - If locked or authorization denied → return failure.
    - Otherwise sign and return `SIGN_RESPONSE` with signature blob.

#### 4.1.3 Requests to reject (MVP)

-   ADD/REMOVE keys, smartcard operations, lock/unlock via agent protocol, etc.
-   For unsupported types: reply with `FAILURE`.

#### 4.1.4 Extensions (recommended but optional for MVP)

-   Support `SSH_AGENTC_EXTENSION` `query` (return supported extension list).
-   Detect `session-bind@openssh.com` (OpenSSH agent restriction / forwarding info) and mark the connection as forwarded or host-bound where applicable.

**Rationale:** Agent forwarding is a common attack surface. OpenSSH provides extensions to distinguish forwarded connections and to restrict key usage; we should at minimum detect forwarding and tighten authorization policies when forwarding is involved.

### 4.2 Process identification and attribution

For each incoming agent connection:

-   Use `SO_PEERCRED` (Linux) to obtain peer `pid`, `uid`, `gid`.
-   Read best-effort metadata (when permitted):
    -   `/proc/<pid>/exe` target path
    -   `/proc/<pid>/cmdline`
    -   `/proc/<pid>/cgroup` (container context)
    -   parent pid / process tree (optional)

Store this as `ConnectionContext` and attach to all requests on that connection.

### 4.3 polkit authorization

#### 4.3.1 polkit integration strategy

-   Use D-Bus system bus to call `org.freedesktop.PolicyKit1.Authority.CheckAuthorization`.
-   Use a **`unix-process` Subject** with:
    -   `pid` (uint32)
    -   `start-time` (uint64) from `/proc/<pid>/stat` to avoid PID reuse issues.
-   Pass `AllowUserInteraction` when the sign request plausibly originates from a user action (typical for ssh/git).

#### 4.3.2 Actions

Define at least these action IDs (names are placeholders):

-   `com.example.bwssh.sign` — authorize using a specific SSH private key for a sign operation.
-   `com.example.bwssh.unlock` — authorize updating the daemon’s Bitwarden session/unlocked state (optional hardening).
-   `com.example.bwssh.list` — list public identities (default allow; may be used in high-security mode).

#### 4.3.3 Prompt content (details dict)

Populate `details` with:

-   `bwssh.key_fingerprint`
-   `bwssh.key_label`
-   `bwssh.request.pid`, `bwssh.request.exe`, `bwssh.request.cmdline`
-   `bwssh.forwarded` (true/false/unknown)
-   `polkit.message` override describing the request in user-friendly terms.

#### 4.3.4 Authorization caching policy

Support three modes (configurable):

1. `always` — prompt every sign request.
2. `per-connection` — authorize once per agent connection (typical for one `ssh` auth attempt).
3. `ttl` — authorize once per (key fingerprint + executable path) for N seconds.

Note: polkit itself can retain authorizations depending on policy (`auth_self_keep` behavior), but the daemon should not rely solely on that for correctness.

### 4.4 Bitwarden integration (“provider”)

#### 4.4.1 Provider interface

Define an internal interface:

-   `list_identities() -> list[Identity]`
-   `get_private_key(identity_id) -> PrivateKeyMaterial`
-   `lock()`
-   `unlock(session_or_token)`
-   `healthcheck()`

#### 4.4.2 Bitwarden provider MVP approach

Use the **Bitwarden CLI (`bw`)** as the integration boundary.

-   The CLI is responsible for:
    -   login, 2FA handling, vault encryption/decryption.
-   Our daemon is responsible for:
    -   requesting items (SSH key objects or attachments),
    -   parsing keys in OpenSSH or PKCS#8 format,
    -   holding them in memory while unlocked.

**Why:** Implementing Bitwarden cryptography and sync directly is out of scope; leveraging the official CLI reduces risk and maintenance burden.

#### 4.4.3 Key discovery

Support two discovery mechanisms (configurable):

1. **Explicit item IDs (recommended)**

    - User lists Bitwarden item/cipher IDs in config.
    - Daemon loads only those keys.

2. **Query-based discovery**
    - User specifies a search query / folder / collection filter.
    - Daemon enumerates matching “SSH key” items and/or items with an attachment named like `id_ed25519`.

#### 4.4.4 Key formats

-   Accept keys in **OpenSSH** or **PKCS#8**, matching Bitwarden’s documented import formats for SSH keys.
-   Encrypted private keys:
    -   If Bitwarden returns encrypted PEM/OpenSSH, the daemon must prompt for passphrase (out of scope for MVP) or require pre-decrypted export from Bitwarden.
    -   MVP: require keys to be stored unencrypted _inside the already-encrypted Bitwarden vault_ (i.e., Bitwarden provides decrypted key to the daemon when unlocked).

#### 4.4.5 Public key caching when locked

When locked:

-   Keep **public key blobs** and comments in memory or on disk (optional, public-only cache).
-   Do not keep private key material.
    This mirrors Bitwarden’s described behavior: listing may remain available while locked, but signing requires user verification/unlock.

### 4.5 Daemon lifecycle

#### 4.5.1 Foreground mode

`bwssh-agentd --foreground` runs until SIGINT/SIGTERM.

#### 4.5.2 systemd user service

Provide unit files for:

-   `bwssh-agent.service` (exec daemon)
-   `bwssh-agent.socket` (socket activation, optional)

Socket activation is strongly preferred: it reduces idle daemon footprint and ensures the socket path exists consistently.

### 4.6 CLI surface (proposed)

Binary name: `bwssh`

Commands:

-   `bwssh status`

    -   Shows socket paths, daemon PID, lock/unlock state, loaded keys count.

-   `bwssh start` / `bwssh stop`

    -   Start/stop the user service (systemd user service if available; fallback to manual).

-   `bwssh install --user-systemd`

    -   Installs systemd unit files to `~/.config/systemd/user/`.

-   `bwssh install --polkit`

    -   Installs polkit action policy file (requires root; the CLI prints the file path and required copy destination).

-   `bwssh unlock`

    -   Obtains Bitwarden session via `bw unlock --raw` (interactive) and sends it to daemon over control socket.
    -   Optional: require polkit `com.example.bwssh.unlock` authorization before daemon accepts the token.

-   `bwssh lock`

    -   Clears session/private keys in daemon memory.

-   `bwssh sync`

    -   Refreshes key list from Bitwarden.

-   `bwssh keys`
    -   Lists loaded identities and fingerprints (public info only).

---

## 5. Configuration

### 5.1 Location and format

-   Config file: `${XDG_CONFIG_HOME:-~/.config}/bwssh/config.toml`
-   Optional drop-ins: `config.d/*.toml`
-   Environment overrides for paths and log level.

### 5.2 Example `config.toml`

```toml
[daemon]
# Where to create sockets. Must be user-private (0700).
runtime_dir = "${XDG_RUNTIME_DIR}/bwssh"
agent_socket = "${daemon.runtime_dir}/agent.sock"
control_socket = "${daemon.runtime_dir}/control.sock"
log_level = "info" # debug|info|warning|error

[bitwarden]
# External CLI binary to use.
bw_path = "bw"
# How to discover keys.
mode = "explicit" # explicit|query
item_ids = ["<uuid-1>", "<uuid-2>"]
# mode = "query"
# query = "tag:ssh OR type:sshkey"
# collection_ids = ["..."]

[auth]
# always|per_connection|ttl
approval_mode = "ttl"
approval_ttl_seconds = 300
# Disallow signing when the daemon believes the request is via forwarded agent.
deny_forwarded_by_default = true

[ssh]
# Which algorithms to allow
allow_ed25519 = true
allow_ecdsa = true
allow_rsa = true
# Prefer SHA-2 RSA signatures when the request flags allow it.
prefer_rsa_sha2 = true
```

---

## 6. Data model

### 6.1 Identity

Fields (in-memory, and public-cache if enabled):

-   `identity_id` (stable internal id; e.g., Bitwarden cipher id + key slot)
-   `comment` (string)
-   `public_key_blob` (bytes)
-   `fingerprint` (string; computed)
-   `algorithm` (enum: ed25519 / ecdsa / rsa)
-   `source` (provider metadata)

### 6.2 PrivateKeyMaterial (in-memory only)

-   `identity_id`
-   `private_key` (cryptography key object or raw bytes)
-   `loaded_at`
-   `expires_at` (optional)

### 6.3 ConnectionContext

-   `peer_pid`, `peer_uid`, `peer_gid`
-   `peer_start_time`
-   `exe_path`, `cmdline`
-   `is_forwarded` (bool/unknown)
-   `first_seen_at`

---

## 7. Security model

### 7.1 Threats

-   Any local process under the same user can attempt to talk to the agent socket.
-   Agent forwarding can expose agent operations to remote systems (via the local ssh client).
-   Python processes cannot reliably “zeroize” all key material in RAM; memory forensics remains a risk.
-   A compromised user account (malware) can spam sign requests to coerce approvals.

### 7.2 Mitigations

-   **Socket permissions**: 0700 directory, 0600 socket; verify peer UID == daemon UID.
-   **Mandatory polkit authorization** for sign operations, with clear prompts and deny-by-default behavior for forwarded sessions.
-   **Rate limiting** sign requests per connection and per (pid, key).
-   **Short-lived in-memory keys**: TTL-based eviction; `lock` clears keys.
-   **Minimal protocol surface**: implement only list+sign initially.
-   **Audit logs**: log sign attempts (time, pid, exe, key fingerprint, allow/deny). Avoid logging sensitive payload bytes.

### 7.3 Forwarding policy (default)

-   If forwarding detected (e.g., via `session-bind@openssh.com`), default to:
    -   deny signing unless config explicitly allows forwarded signing, and
    -   always prompt (no caching).

---

## 8. Implementation plan (MVP milestones)

### Milestone A — Protocol skeleton

-   `asyncio` Unix server
-   message framing + minimal dispatch
-   `REQUEST_IDENTITIES` stub (empty list)
-   `SIGN_REQUEST` stub (failure)

### Milestone B — Key handling

-   parse OpenSSH / PKCS#8 private keys (in-memory)
-   compute public key blobs + fingerprints
-   implement `IDENTITIES_ANSWER`
-   implement `SIGN_RESPONSE` for ed25519 + rsa (then ecdsa)

### Milestone C — Process attribution

-   `SO_PEERCRED` support + `/proc` metadata collection
-   structured audit logging

### Milestone D — polkit gate

-   DBus integration
-   `CheckAuthorization` before signing
-   caching policies

### Milestone E — Bitwarden provider

-   `bwssh unlock` obtains session token and sends to daemon
-   daemon uses `bw` to fetch configured items
-   implement `bwssh sync` and `bwssh keys`

### Milestone F — Packaging and integration

-   systemd user unit + optional socket activation
-   polkit policy template
-   documentation and examples

---

## 9. Repository & tooling requirements (uv + ruff)

### 9.1 Python version

-   Minimum: Python **3.12**
-   Recommended: newest stable Python available on target distro (3.12/3.13+).

### 9.2 Project layout (src layout)

```
bw-ssh-agent/
  pyproject.toml
  uv.lock
  src/
    bwssh/
      __init__.py
      cli.py
      daemon.py
      agent_proto.py
      polkit.py
      bitwarden.py
      config.py
      logging.py
  tests/
  packaging/
    systemd/
      bwssh-agent.service
      bwssh-agent.socket
    polkit/
      com.example.bwssh.policy
```

### 9.3 Build backend

Use the uv build backend (`uv_build`) in `pyproject.toml`:

```toml
[build-system]
requires = ["uv_build>=0.9.28,<0.10.0"]
build-backend = "uv_build"
```

### 9.4 Common workflows (canonical commands)

-   Create env + install deps: `uv sync`
-   Run CLI in env: `uv run -- bwssh status`
-   Add dependency: `uv add <pkg>`
-   Lint: `uv run -- ruff check .`
-   Auto-fix: `uv run -- ruff check . --fix`
-   Format: `uv run -- ruff format .`
-   Build dist: `uv build`

### 9.5 Ruff configuration (single source of truth)

All Ruff config lives in `pyproject.toml` under `[tool.ruff]` / `[tool.ruff.lint]` / `[tool.ruff.format]`.

Policy:

-   Enforce formatting with `ruff format`.
-   Enable import sorting (`I` rules) and common correctness rules.
-   Avoid stylistic bikeshedding beyond what Ruff already enforces.

---

## 10. Packaging assets

### 10.1 systemd user service (example)

`packaging/systemd/bwssh-agent.service` (template):

```ini
[Unit]
Description=Bitwarden-backed SSH agent (bwssh)
After=default.target

[Service]
Type=simple
ExecStart=%h/.local/bin/bwssh-agentd --foreground
Restart=on-failure
Environment=RUST_LOG=
# Ensure user-private umask.
UMask=0077

[Install]
WantedBy=default.target
```

### 10.2 polkit action policy (example)

`packaging/polkit/com.example.bwssh.policy` (template):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <action id="com.example.bwssh.sign">
    <description>Use an SSH key from Bitwarden</description>
    <message>Authentication is required to use an SSH key from Bitwarden.</message>
    <defaults>
      <allow_any>no</allow_any>
      <allow_inactive>no</allow_inactive>
      <allow_active>auth_self_keep</allow_active>
    </defaults>
  </action>
</policyconfig>
```

Notes:

-   Installation location typically `/usr/share/polkit-1/actions/` (system-managed).
-   Distros differ; spec does not mandate an installer beyond providing the file.

---

## 11. Testing strategy

-   Unit tests for message encoding/decoding and signature correctness.
-   Golden tests: compare our agent responses to OpenSSH expectations (via `ssh-add -L` and a small protocol client).
-   Integration test (optional): spawn daemon in temp runtime dir, run `ssh -o IdentityAgent=...` against a local test sshd container.

Keep the test toolchain minimal; prefer stdlib `unittest` unless pytest is explicitly chosen.

---

## 12. References

These are key upstream references used to define protocol and system integration behavior:

-   IETF SSH Agent Protocol draft (packet format, message types, extensions):
    https://datatracker.ietf.org/doc/draft-ietf-sshm-ssh-agent/

-   OpenSSH agent protocol notes (legacy but still widely referenced):
    https://web.mit.edu/freebsd/head/crypto/openssh/PROTOCOL.agent

-   OpenSSH agent restriction / `session-bind@openssh.com` (forwarding detection and constraints):
    https://www.openssh.org/agent-restrict.html

-   polkit D-Bus `Authority.CheckAuthorization` interface (subjects, flags):
    https://www.freedesktop.org/software/polkit/docs/0.105/eggdbus-interface-org.freedesktop.PolicyKit1.Authority.html

-   Bitwarden Help: SSH Agent + SSH key import formats:
    https://bitwarden.com/help/ssh-agent/

-   Bitwarden Contributing Docs: SSH Agent deep dive (socket transport, subset operations, `SO_PEERCRED`):
    https://contributing.bitwarden.com/architecture/deep-dives/ssh/agent/

-   uv project guide and build backend docs:
    https://docs.astral.sh/uv/guides/projects/
    https://docs.astral.sh/uv/concepts/build-backend/

-   Ruff configuration docs:
    https://docs.astral.sh/ruff/configuration/
