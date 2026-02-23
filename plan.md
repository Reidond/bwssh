# macOS Terminal Support — Implementation Plan

## Goal
Full macOS support for the terminal UI (all 5 platform areas), with zero breaking changes to existing Linux behavior.

## Strategy
Introduce a **platform abstraction layer** (`src/bwssh/platform/`) that encapsulates all OS-specific behavior behind common interfaces. Linux code moves into `platform/_linux.py`, macOS code goes into `platform/_darwin.py`, and a `platform/__init__.py` auto-selects the right backend at import time. All existing call sites switch to using these abstractions.

---

## Files to Create

### 1. `src/bwssh/platform/__init__.py`
Auto-detect `sys.platform` and re-export the correct backend:
- `get_peer_credentials(sock) -> PeerCredentials`
- `get_process_metadata(pid) -> ProcessMetadata`
- `create_authorizer(config) -> tuple[Authorizer, bool, str | None]`
- `create_sleep_watcher(control_server, shutdown_event) -> coroutine`
- `get_runtime_dir() -> Path`
- `get_config_dir() -> Path`
- `try_service_start() -> bool`
- `try_service_stop() -> bool`
- `install_service(...)` — writes service files (systemd units or launchd plists)

### 2. `src/bwssh/platform/_linux.py`
Move existing Linux-specific implementations here (verbatim from current code):
- `SO_PEERCRED` + `/proc` metadata (from `peercred.py`)
- D-Bus polkit authorizer factory (from `daemon.py:_connect_polkit`)
- Sleep watcher via logind (from `daemon.py:_sleep_watcher`)
- `_default_runtime_dir()` using `XDG_RUNTIME_DIR`
- systemd start/stop/install helpers (from `cli.py`)

### 3. `src/bwssh/platform/_darwin.py`
New macOS implementations:
- **Peer credentials**: `LOCAL_PEERCRED` (SO level 0, option 0x001) for UID/GID, `LOCAL_PEERPID` (option 0x002) for PID
- **Process metadata**: `ctypes` calls to `libproc.dylib` (`proc_pidpath`, `proc_pidinfo`) for exe path, and `sysctl` (`CTL_KERN`/`KERN_PROCARGS2`) for cmdline, `proc_pidinfo` with `PROC_PIDTASKINFO` for start time
- **Authorization**: Return `MockPolkitAuthorizer(always_allow=True)` — on macOS, socket permissions (0600) + the unlock prompt are the authorization gate. Log that polkit is not applicable.
- **Sleep watcher**: Use `pyobjc-framework-Cocoa` `NSWorkspace` notifications (`NSWorkspaceWillSleepNotification`) if available, otherwise no-op with a log message
- **Runtime dir**: `~/Library/Caches/bwssh/` (or `$TMPDIR/bwssh-{uid}` fallback)
- **Config dir**: `~/.config/bwssh/` (keep XDG compatible, same as Linux)
- **Service management**: `launchctl` + `~/Library/LaunchAgents/` plist generation

### 4. `src/bwssh/data/launchd/io.github.reidond.bwssh-agent.plist`
launchd user agent plist template for the daemon.

### 5. `tests/test_platform.py`
Tests for the platform abstraction layer covering both backends.

---

## Files to Modify

### 6. `src/bwssh/peercred.py`
- Keep `PeerCredentials`, `ProcessMetadata`, `ConnectionContext` dataclasses and `build_connection_context()` here (they are platform-agnostic data structures)
- Replace the `get_peer_credentials()` and `get_process_metadata()` function bodies to delegate to `bwssh.platform`
- Remove the Linux-specific `_read_exe`, `_read_cmdline`, `_read_start_time` helpers (moved to `platform/_linux.py`)

### 7. `src/bwssh/daemon.py`
- Replace `from dbus_fast import ...` / `from dbus_fast.aio import ...` with conditional import guarded by `sys.platform`
- Replace `_default_runtime_dir()` to delegate to `bwssh.platform.get_runtime_dir()`
- Replace `_connect_polkit()` to delegate to `bwssh.platform.create_authorizer(config)`
- Replace `_sleep_watcher()` to delegate to `bwssh.platform.create_sleep_watcher()`
- Existing `AgentServer` class — no interface changes

### 8. `src/bwssh/cli.py`
- Replace `_try_systemd_start()` / `_try_systemd_stop()` to delegate to `bwssh.platform`
- Replace `_get_control_socket()` and `_tray_lock_path()` to use `bwssh.platform.get_runtime_dir()`
- Replace `install` command to delegate service installation to `bwssh.platform`
- Add `--launchd` flag to `install` command for macOS (alongside existing `--user-systemd`)
- Update CLI description from "for Linux" to remove platform restriction

### 9. `src/bwssh/config.py`
- Update `_default_config_path()` to use platform-aware config dir (still `~/.config/bwssh/` on both platforms for XDG compat)

### 10. `pyproject.toml`
- Make `dbus-fast` conditional: `dbus-fast>=4.0.0; sys_platform == 'linux'`
- Add optional `macos` extra: `pyobjc-framework-Cocoa` for sleep watcher
- Update project description to remove "for Linux"

### 11. `tests/test_peercred.py`
- Tests should continue to pass unchanged (they test via the public API which now delegates to the platform layer)

---

## Design Principles

1. **Zero breaking changes**: Every existing import path, function signature, and behavior remains identical on Linux
2. **Platform detection at import time**: `sys.platform == "darwin"` vs `"linux"` in `platform/__init__.py`
3. **Graceful degradation**: If a macOS feature (e.g. sleep watcher) can't be loaded, log a warning and continue
4. **Existing tests pass**: All current tests run on Linux exactly as before
5. **No new required dependencies on Linux**: `dbus-fast` stays for Linux; macOS uses stdlib `ctypes` for core features
