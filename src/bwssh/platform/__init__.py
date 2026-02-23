"""Platform abstraction layer for bwssh.

Auto-detects the current OS and re-exports the appropriate backend
functions. On Linux, uses SO_PEERCRED, /proc, D-Bus polkit, and systemd.
On macOS, uses LOCAL_PEERCRED, libproc, socket-permission auth, and launchd.
"""

from __future__ import annotations

import sys

if sys.platform == "darwin":
    from bwssh.platform._darwin import (  # noqa: I001
        create_authorizer as create_authorizer,
        create_sleep_watcher as create_sleep_watcher,
        get_config_dir as get_config_dir,
        get_peer_credentials as get_peer_credentials,
        get_process_metadata as get_process_metadata,
        get_runtime_dir as get_runtime_dir,
        try_service_start as try_service_start,
        try_service_stop as try_service_stop,
    )
else:
    from bwssh.platform._linux import (  # noqa: I001
        create_authorizer as create_authorizer,
        create_sleep_watcher as create_sleep_watcher,
        get_config_dir as get_config_dir,
        get_peer_credentials as get_peer_credentials,
        get_process_metadata as get_process_metadata,
        get_runtime_dir as get_runtime_dir,
        try_service_start as try_service_start,
        try_service_stop as try_service_stop,
    )

__all__ = [
    "create_authorizer",
    "create_sleep_watcher",
    "get_config_dir",
    "get_peer_credentials",
    "get_process_metadata",
    "get_runtime_dir",
    "try_service_start",
    "try_service_stop",
]
