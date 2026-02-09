"""Graphical unlock UI using GTK 4 + libadwaita.

Provides an Adwaita-styled dialog window for entering the Bitwarden
master password, running ``bw unlock --raw``, and optionally sending
the session to the daemon to load SSH keys.

All ``gi`` imports are guarded so the module can be imported safely
even when PyGObject / GTK 4 / libadwaita are not installed.
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
import threading
from typing import TYPE_CHECKING, Any

from bwssh.ui._base import UnlockResult

if TYPE_CHECKING:
    from bwssh.ui._base import PostUnlockHook

logger = logging.getLogger(__name__)

# --- Graceful GTK 4 / libadwaita availability detection --------------------

GTK_AVAILABLE = False

try:
    import gi  # pyright: ignore[reportMissingImports]

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, GLib, Gtk  # pyright: ignore[reportMissingImports]

    GTK_AVAILABLE = True
except (ImportError, ValueError) as _exc:
    logger.debug("GTK 4 / libadwaita not available: %s", _exc)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_BW_UNLOCK_TIMEOUT = 30.0
_WINDOW_WIDTH = 420

# Stack page names
_PAGE_INPUT = "input"
_PAGE_LOADING = "loading"
_PAGE_SUCCESS = "success"


# ---------------------------------------------------------------------------
# GraphicalUnlockUI — public API
# ---------------------------------------------------------------------------


class GraphicalUnlockUI:
    """GTK 4 + libadwaita unlock UI.

    Call :meth:`run` to display an Adwaita dialog that collects the
    master password, runs ``bw unlock --raw``, and (optionally) sends
    the session key to the daemon.

    Parameters:
        bw_path: Path to the ``bw`` CLI binary.
        on_session_ready: Async callback invoked after a successful
            ``bw unlock``.  Receives the session key and should return
            a dict containing at least ``"key_count"`` and optionally
            ``"keys"`` with per-key details.
    """

    def __init__(
        self,
        bw_path: str = "bw",
        on_session_ready: PostUnlockHook | None = None,
    ) -> None:
        self._bw_path = bw_path
        self._on_session_ready = on_session_ready

    def run(self) -> UnlockResult:
        """Show the GTK unlock window and block until it closes."""
        if not GTK_AVAILABLE:
            raise RuntimeError(
                "GTK 4 / libadwaita is not available. "
                "Install PyGObject + GTK 4 + libadwaita or set "
                "BWSSH_UNLOCK_MODE=tui."
            )

        app = _UnlockApplication(
            bw_path=self._bw_path,
            on_session_ready=self._on_session_ready,
        )
        app.run(None)
        return app.result


# ---------------------------------------------------------------------------
# Internal GTK application + window
# ---------------------------------------------------------------------------

if GTK_AVAILABLE:

    class _UnlockApplication(Adw.Application):  # type: ignore[misc]
        """Single-window Adw.Application that drives the unlock flow."""

        def __init__(
            self,
            bw_path: str,
            on_session_ready: PostUnlockHook | None,
        ) -> None:
            super().__init__(application_id="io.github.reidond.bwssh.unlock")
            self._bw_path = bw_path
            self._on_session_ready = on_session_ready
            self.result = UnlockResult()

        def do_activate(self) -> None:
            # HIG: Escape closes modal windows; Ctrl+W closes any window.
            self.set_accels_for_action("window.close", ["Escape", "<Control>w"])

            win = _UnlockWindow(
                application=self,
                bw_path=self._bw_path,
                on_session_ready=self._on_session_ready,
            )
            win.present()

    class _UnlockWindow(Adw.ApplicationWindow):  # type: ignore[misc]
        """Adwaita window containing the unlock form.

        Uses a ``Gtk.Stack`` with three pages (input / loading / success)
        and crossfade transitions between them.
        """

        def __init__(
            self,
            *,
            application: _UnlockApplication,
            bw_path: str,
            on_session_ready: PostUnlockHook | None,
        ) -> None:
            super().__init__(
                application=application,
                title="Unlock Bitwarden Vault",
                default_width=_WINDOW_WIDTH,
                resizable=False,
            )
            self._app = application
            self._bw_path = bw_path
            self._on_session_ready = on_session_ready

            self._build_ui()
            self._enter_input()

        # -- UI construction ------------------------------------------------

        def _build_ui(self) -> None:
            toolbar_view = Adw.ToolbarView()
            toolbar_view.add_top_bar(Adw.HeaderBar())

            # State stack with crossfade transitions.
            # vhomogeneous=False so each page sizes to its own content
            # rather than reserving the height of the tallest child.
            self._stack = Gtk.Stack(
                transition_type=Gtk.StackTransitionType.CROSSFADE,
                transition_duration=200,
                vhomogeneous=False,
                vexpand=True,
            )

            self._build_input_page()
            self._build_loading_page()
            self._build_success_page()

            toolbar_view.set_content(self._stack)
            self.set_content(toolbar_view)

            # window.close handles Escape, Ctrl+W, and the [x] button
            self.connect("close-request", self._on_close_request)

        def _build_input_page(self) -> None:
            box = Gtk.Box(
                orientation=Gtk.Orientation.VERTICAL,
                spacing=18,
                margin_top=24,
                margin_bottom=24,
                margin_start=24,
                margin_end=24,
            )

            # HIG: sentence capitalization for body/description text
            subtitle = Gtk.Label(label="Enter your master password")
            subtitle.add_css_class("dim-label")
            box.append(subtitle)

            # HIG: Adw.PasswordEntryRow in a boxed list is the canonical
            # Adwaita pattern for password input.
            password_list = Gtk.ListBox(
                selection_mode=Gtk.SelectionMode.NONE,
            )
            password_list.add_css_class("boxed-list")

            # HIG: header capitalization for short control labels
            self._password_row = Adw.PasswordEntryRow(title="Password")
            self._password_row.connect("entry-activated", self._on_activate)
            password_list.append(self._password_row)
            box.append(password_list)

            # Error label — uses built-in Adwaita .error CSS class
            self._error_label = Gtk.Label(label="", wrap=True, visible=False, xalign=0)
            self._error_label.add_css_class("error")
            box.append(self._error_label)

            # HIG: label the affirmative button with a specific imperative
            # verb; suggested-action styling for the primary action.
            self._unlock_button = Gtk.Button(label="Unlock")
            self._unlock_button.add_css_class("suggested-action")
            self._unlock_button.add_css_class("pill")
            self._unlock_button.set_halign(Gtk.Align.CENTER)
            self._unlock_button.connect("clicked", self._on_activate)
            box.append(self._unlock_button)

            clamp = Adw.Clamp(maximum_size=360)
            clamp.set_child(box)
            self._stack.add_named(clamp, _PAGE_INPUT)

        def _build_loading_page(self) -> None:
            box = Gtk.Box(
                orientation=Gtk.Orientation.VERTICAL,
                spacing=12,
                halign=Gtk.Align.CENTER,
                valign=Gtk.Align.CENTER,
                vexpand=True,
            )

            self._loading_spinner = Gtk.Spinner(width_request=32, height_request=32)
            self._loading_spinner.set_halign(Gtk.Align.CENTER)
            box.append(self._loading_spinner)

            self._loading_label = Gtk.Label(label="")
            self._loading_label.add_css_class("dim-label")
            box.append(self._loading_label)

            self._stack.add_named(box, _PAGE_LOADING)

        def _build_success_page(self) -> None:
            # HIG: Adw.StatusPage is the standard pattern for status
            # feedback with icon + title + description.
            self._success_page = Adw.StatusPage(
                icon_name="object-select-symbolic",
                title="Vault Unlocked",
            )
            self._success_page.add_css_class("compact")

            # Child: key list + Close button
            child_box = Gtk.Box(
                orientation=Gtk.Orientation.VERTICAL,
                spacing=18,
            )

            # HIG: boxed list with Adw.ActionRow for each loaded key.
            # Wrapped in a scrolled window in case there are many keys.
            self._keys_list = Gtk.ListBox(
                selection_mode=Gtk.SelectionMode.NONE,
            )
            self._keys_list.add_css_class("boxed-list")

            scroll = Gtk.ScrolledWindow(
                hscrollbar_policy=Gtk.PolicyType.NEVER,
                vscrollbar_policy=Gtk.PolicyType.AUTOMATIC,
                max_content_height=200,
                propagate_natural_height=True,
            )
            scroll.set_child(self._keys_list)
            child_box.append(scroll)

            # Close button — user dismisses manually (no auto-close)
            close_button = Gtk.Button(label="Close")
            close_button.add_css_class("pill")
            close_button.set_halign(Gtk.Align.CENTER)
            close_button.connect("clicked", lambda _: self.close())
            child_box.append(close_button)

            clamp = Adw.Clamp(maximum_size=360)
            clamp.set_child(child_box)
            self._success_page.set_child(clamp)

            self._stack.add_named(self._success_page, _PAGE_SUCCESS)

        # -- Event handlers -------------------------------------------------

        def _on_activate(self, _widget: Any) -> None:
            """Triggered by Enter in the entry row or clicking Unlock."""
            password = self._password_row.get_text()
            if not password:
                # HIG: no trailing period on UI text
                self._show_error("Password cannot be empty")
                return
            self._enter_loading("Unlocking vault\u2026")
            self._do_unlock(password)

        def _on_close_request(self, _window: Any) -> bool:
            """Handle window close — cancel if not yet succeeded."""
            if self._app.result.session_key is None:
                self._app.result = UnlockResult(error="cancelled")
            return False  # allow default close behaviour

        # -- State transitions ----------------------------------------------

        def _enter_input(self) -> None:
            """Switch to the input page and reset the form."""
            self._password_row.set_text("")
            self._error_label.set_visible(False)
            self._unlock_button.set_sensitive(True)
            self._stack.set_visible_child_name(_PAGE_INPUT)
            self._password_row.grab_focus()

        def _enter_loading(self, status: str) -> None:
            """Switch to the loading page with a spinner and status text."""
            self._loading_label.set_text(status)
            self._loading_spinner.start()
            self._stack.set_visible_child_name(_PAGE_LOADING)

        def _enter_success(
            self,
            title: str,
            description: str,
            keys: list[dict[str, str]],
        ) -> None:
            """Switch to the success status page with key list."""
            self._loading_spinner.stop()

            # HIG: header capitalization for StatusPage title,
            # sentence capitalization for description.
            self._success_page.set_title(title)
            self._success_page.set_description(description)

            # Clear any previous rows
            while (row := self._keys_list.get_row_at_index(0)) is not None:
                self._keys_list.remove(row)

            # HIG: Adw.ActionRow in boxed list — title/subtitle per key,
            # algorithm as a dim suffix label.
            for key in keys:
                comment = key.get("comment", "") or "Unnamed key"
                fingerprint = key.get("fingerprint", "")
                algorithm = key.get("algorithm", "")

                row = Adw.ActionRow(title=comment, subtitle=fingerprint)
                if algorithm:
                    algo_label = Gtk.Label(label=algorithm)
                    algo_label.add_css_class("dim-label")
                    algo_label.set_valign(Gtk.Align.CENTER)
                    row.add_suffix(algo_label)
                self._keys_list.append(row)

            self._keys_list.set_visible(len(keys) > 0)
            self._stack.set_visible_child_name(_PAGE_SUCCESS)

        def _show_error(self, message: str) -> None:
            """Display an inline error below the password entry."""
            self._error_label.set_text(message)
            self._error_label.set_visible(True)

        # -- Unlock pipeline (threaded) ------------------------------------

        def _do_unlock(self, password: str) -> None:
            """Spawn the unlock pipeline in a background thread."""
            thread = threading.Thread(
                target=self._unlock_thread,
                args=(password,),
                daemon=True,
            )
            thread.start()

        def _unlock_thread(self, password: str) -> None:
            """Background thread: bw unlock -> on_session_ready -> result."""
            try:
                session_key = self._run_bw_unlock(password)
            except FileNotFoundError:
                GLib.idle_add(self._enter_input)
                GLib.idle_add(
                    self._show_error,
                    f"Bitwarden CLI not found: {self._bw_path}",
                )
                return
            except TimeoutError:
                GLib.idle_add(self._enter_input)
                GLib.idle_add(self._show_error, "Unlock timed out")
                return
            except RuntimeError as exc:
                GLib.idle_add(self._enter_input)
                GLib.idle_add(self._show_error, str(exc))
                return
            except OSError as exc:
                GLib.idle_add(self._enter_input)
                GLib.idle_add(self._show_error, str(exc))
                return

            if session_key is None:
                GLib.idle_add(self._enter_input)
                GLib.idle_add(self._show_error, "No session key returned")
                return

            # Phase 2: send session to daemon and load keys
            key_count = 0
            keys: list[dict[str, str]] = []
            if self._on_session_ready is not None:
                GLib.idle_add(self._enter_loading, "Loading keys\u2026")
                try:
                    daemon_result: dict[str, Any] = asyncio.run(
                        self._on_session_ready(session_key)  # type: ignore[arg-type]
                    )
                    key_count = daemon_result.get("key_count", 0)
                    keys = daemon_result.get("keys", [])
                except Exception as exc:
                    GLib.idle_add(self._enter_input)
                    GLib.idle_add(
                        self._show_error,
                        f"Failed to load keys: {exc}",
                    )
                    return

            # Phase 3: set result and show success — user closes manually
            self._app.result = UnlockResult(
                session_key=session_key, key_count=key_count, keys=keys
            )
            GLib.idle_add(
                self._show_success_page,
                key_count,
                keys,
            )

        def _show_success_page(
            self, key_count: int, keys: list[dict[str, str]]
        ) -> bool:
            """Show the success status page with key details."""
            self._enter_success(
                "Vault Unlocked",
                f"{key_count} key(s) loaded",
                keys,
            )
            return bool(GLib.SOURCE_REMOVE)

        # -- bw unlock subprocess ------------------------------------------

        def _run_bw_unlock(self, password: str) -> str | None:
            """Execute ``bw unlock --raw`` synchronously (from thread).

            The password is piped via stdin to avoid exposure in
            ``/proc/<pid>/cmdline``.

            Raises:
                FileNotFoundError: ``bw`` binary not found.
                TimeoutError: Command did not finish in time.
                RuntimeError: ``bw`` exited with non-zero status.
                OSError: Other I/O errors.
            """
            proc = subprocess.run(
                [self._bw_path, "unlock", "--raw"],
                input=(password + "\n").encode("utf-8"),
                capture_output=True,
                timeout=_BW_UNLOCK_TIMEOUT,
                check=False,
            )

            if proc.returncode != 0:
                error_msg = proc.stderr.decode("utf-8", errors="replace").strip()
                raise RuntimeError(error_msg or "Unlock failed")

            session_key = proc.stdout.decode("utf-8").strip()
            return session_key or None

else:
    # GTK not available — provide a stub so the class can still be imported.
    class _UnlockApplication:  # type: ignore[no-redef]
        """Stub when GTK is not available."""

        def __init__(self, **_kwargs: Any) -> None:
            raise RuntimeError("GTK 4 is not available")

        def run(self, *_args: Any) -> None:
            raise RuntimeError("GTK 4 is not available")
