"""polkit D-Bus authorization gate for sign operations.

Uses dbus-fast to call CheckAuthorization on the system D-Bus via
org.freedesktop.PolicyKit1.Authority. Fails closed: if polkit is
unavailable or any error occurs, authorization is denied.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Protocol

import dbus_fast

if TYPE_CHECKING:
    from dbus_fast.aio import MessageBus

    from bwssh.peercred import ConnectionContext

logger = logging.getLogger(__name__)

ACTION_SIGN = "io.github.reidond.bwssh.sign"
ACTION_UNLOCK = "io.github.reidond.bwssh.unlock"
ACTION_LIST = "io.github.reidond.bwssh.list"

_ALLOW_USER_INTERACTION = 0x1

_POLKIT_BUS_NAME = "org.freedesktop.PolicyKit1"
_POLKIT_OBJECT_PATH = "/org/freedesktop/PolicyKit1/Authority"
_POLKIT_INTERFACE = "org.freedesktop.PolicyKit1.Authority"


class Authorizer(Protocol):
    """Protocol for polkit-style authorization checks."""

    async def check_authorization(
        self,
        action_id: str,
        connection_ctx: ConnectionContext,
        details: dict[str, str],
    ) -> bool: ...


def build_details(
    fingerprint: str,
    comment: str,
    conn_ctx: ConnectionContext,
) -> dict[str, str]:
    """Build the polkit details dict for a sign request.

    Populates all fields specified in SPEC.md §4.3.3.
    """
    return {
        "bwssh.key_fingerprint": fingerprint,
        "bwssh.key_label": comment,
        "bwssh.request.pid": str(conn_ctx.peer_pid),
        "bwssh.request.exe": conn_ctx.exe_path or "unknown",
        "bwssh.request.cmdline": " ".join(conn_ctx.cmdline or []),
        "bwssh.forwarded": str(conn_ctx.is_forwarded).lower(),
        "polkit.message": f"Sign data with SSH key {fingerprint}",
    }


class PolkitAuthorizer:
    """Gate operations behind polkit CheckAuthorization on system D-Bus.

    Constructs a unix-process Subject using the peer's PID and start-time
    from ConnectionContext. Passes AllowUserInteraction so the desktop
    polkit agent can prompt the user.

    Fails closed: any D-Bus or polkit error results in denial.
    """

    def __init__(self, bus: MessageBus) -> None:
        self._bus = bus

    async def check_authorization(
        self,
        action_id: str,
        connection_ctx: ConnectionContext,
        details: dict[str, str],
    ) -> bool:
        try:
            introspection = await self._bus.introspect(
                _POLKIT_BUS_NAME, _POLKIT_OBJECT_PATH
            )
            proxy = self._bus.get_proxy_object(
                _POLKIT_BUS_NAME, _POLKIT_OBJECT_PATH, introspection
            )
            authority = proxy.get_interface(_POLKIT_INTERFACE)

            subject = (
                "unix-process",
                {
                    "pid": dbus_fast.Variant("u", connection_ctx.peer_pid),
                    "start-time": dbus_fast.Variant(
                        "t", connection_ctx.peer_start_time or 0
                    ),
                },
            )

            result = await authority.call_check_authorization(  # type: ignore[attr-defined]
                subject,
                action_id,
                details,
                _ALLOW_USER_INTERACTION,
                "",
            )

            is_authorized = result[0]
            logger.info(
                "polkit authorization: action=%s, pid=%d, authorized=%s",
                action_id,
                connection_ctx.peer_pid,
                is_authorized,
            )
            return bool(is_authorized)

        except Exception:
            logger.warning(
                "polkit authorization failed (denying): action=%s, pid=%d",
                action_id,
                connection_ctx.peer_pid,
                exc_info=True,
            )
            return False


class MockPolkitAuthorizer:
    """Test double that records calls and returns a fixed allow/deny decision."""

    def __init__(self, always_allow: bool = True) -> None:
        self._always_allow = always_allow
        self.calls: list[tuple[str, object, dict[str, str]]] = []

    async def check_authorization(
        self,
        action_id: str,
        connection_ctx: ConnectionContext,
        details: dict[str, str],
    ) -> bool:
        self.calls.append((action_id, connection_ctx, details))
        return self._always_allow
