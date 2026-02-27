"""polkit D-Bus authorization gate for sign operations.

Uses dbus-fast to call CheckAuthorization on the system D-Bus via
org.freedesktop.PolicyKit1.Authority. Fails closed: if polkit is
unavailable or any error occurs, authorization is denied.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    import dbus_fast
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
        details: dict[str, str],  # noqa: ARG002
    ) -> bool:
        try:
            import dbus_fast as _dbus_fast  # noqa: PLC0415

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
                    "pid": _dbus_fast.Variant("u", connection_ctx.peer_pid),
                    "start-time": _dbus_fast.Variant(
                        "t", connection_ctx.peer_start_time or 0
                    ),
                },
            )

            # Note: We pass empty details ({}) because only trusted callers (root)
            # can pass details to polkit. The key info is logged separately.
            result = await authority.call_check_authorization(  # type: ignore[attr-defined]
                subject,
                action_id,
                {},  # Empty details - see note above
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


class CachingAuthorizer:
    """Wraps an Authorizer with configurable caching policy.

    Three modes:
    - always: No caching, every request goes through
    - per_connection: Cache by connection ID (first auth per connection)
    - ttl: Cache by (fingerprint, exe_path) with time-based expiry

    Forwarded connections always bypass cache regardless of mode.
    """

    def __init__(self, underlying: Authorizer, mode: str, ttl_seconds: int) -> None:
        self._underlying = underlying
        self._mode = mode
        self._ttl_seconds = ttl_seconds
        self._per_connection_cache: set[int] = set()
        self._ttl_cache: dict[tuple[str, str | None], float] = {}

    async def check_authorization(
        self,
        action_id: str,
        connection_ctx: ConnectionContext,
        details: dict[str, str],
    ) -> bool:
        if connection_ctx.is_forwarded or self._mode == "always":
            return await self._underlying.check_authorization(
                action_id, connection_ctx, details
            )

        if self._mode == "per_connection":
            return await self._check_per_connection(action_id, connection_ctx, details)

        if self._mode == "ttl":
            return await self._check_ttl(action_id, connection_ctx, details)

        return await self._underlying.check_authorization(
            action_id, connection_ctx, details
        )

    async def _check_per_connection(
        self,
        action_id: str,
        connection_ctx: ConnectionContext,
        details: dict[str, str],
    ) -> bool:
        conn_id = id(connection_ctx)
        if conn_id in self._per_connection_cache:
            logger.debug(
                "Authorization cached for connection pid=%d",
                connection_ctx.peer_pid,
            )
            return True

        result = await self._underlying.check_authorization(
            action_id, connection_ctx, details
        )
        if result:
            self._per_connection_cache.add(conn_id)
        return result

    async def _check_ttl(
        self,
        action_id: str,
        connection_ctx: ConnectionContext,
        details: dict[str, str],
    ) -> bool:
        fingerprint = details.get("bwssh.key_fingerprint", "")
        exe_path = connection_ctx.exe_path
        cache_key = (fingerprint, exe_path)

        if cache_key in self._ttl_cache:
            cached_time = self._ttl_cache[cache_key]
            if time.time() - cached_time < self._ttl_seconds:
                logger.debug(
                    "Authorization cached for key=%s exe=%s",
                    fingerprint,
                    exe_path,
                )
                return True
            del self._ttl_cache[cache_key]

        result = await self._underlying.check_authorization(
            action_id, connection_ctx, details
        )
        if result:
            self._ttl_cache[cache_key] = time.time()
        return result

    def clear_cache(self) -> None:
        """Clear all cached authorizations."""
        self._per_connection_cache.clear()
        self._ttl_cache.clear()
        logger.info("Authorization cache cleared")
