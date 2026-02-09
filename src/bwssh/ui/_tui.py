"""TUI unlock screen powered by *textual*."""

from __future__ import annotations

import asyncio
from typing import ClassVar

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import Input, Label, LoadingIndicator, Static

from bwssh.ui._base import PostUnlockHook, UnlockResult

_BW_UNLOCK_TIMEOUT = 30.0


class TuiUnlockUI:
    """TUI-based unlock UI using *textual*.

    Call :meth:`run` to take over the terminal, prompt for the master
    password, run ``bw unlock --raw``, optionally send the session to
    the daemon, and return the result.

    Parameters:
        bw_path: Path to the ``bw`` CLI binary.
        on_session_ready: Async callback invoked after a successful
            ``bw unlock``.  Receives the session key and should return
            a dict containing at least ``"key_count"`` and optionally
            ``"keys"`` with details of each loaded key.  When provided
            the TUI keeps the loading indicator visible until the
            callback completes.
    """

    def __init__(
        self,
        bw_path: str = "bw",
        on_session_ready: PostUnlockHook | None = None,
    ) -> None:
        self._bw_path = bw_path
        self._on_session_ready = on_session_ready

    def run(self) -> UnlockResult:
        """Show TUI unlock screen and return the result."""
        app = _UnlockApp(
            bw_path=self._bw_path,
            on_session_ready=self._on_session_ready,
        )
        app.run()
        return app.result


# ---------------------------------------------------------------------------
# Internal textual application
# ---------------------------------------------------------------------------


class _UnlockApp(App[None]):
    """Full-screen textual application for vault unlock."""

    CSS = """
    Screen {
        align: center middle;
    }

    #dialog {
        width: 60;
        height: auto;
        padding: 1 2;
        border: thick $accent;
        background: $surface;
    }

    #title {
        width: 100%;
        text-align: center;
        text-style: bold;
        color: $accent;
    }

    #subtitle {
        width: 100%;
        text-align: center;
        color: $text-muted;
        margin-bottom: 1;
    }

    #error-label {
        color: $error;
        display: none;
        margin-top: 1;
    }

    #status-label {
        width: 100%;
        text-align: center;
        display: none;
        margin-top: 1;
    }

    #spinner {
        display: none;
        margin-top: 1;
    }

    #key-list {
        display: none;
        margin-top: 1;
    }

    #dismiss-hint {
        display: none;
        width: 100%;
        text-align: center;
        color: $text-muted;
        margin-top: 1;
    }
    """

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "close_screen", "Close", show=True),
    ]

    def __init__(
        self,
        bw_path: str,
        on_session_ready: PostUnlockHook | None = None,
    ) -> None:
        super().__init__()
        self._bw_path = bw_path
        self._on_session_ready = on_session_ready
        self._is_success = False
        self.result = UnlockResult()

    # -- layout -------------------------------------------------------------

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Static("Unlock Bitwarden Vault", id="title")
            yield Static("Enter your master password", id="subtitle")
            yield Input(
                placeholder="Master password",
                password=True,
                id="password-input",
            )
            yield Label("", id="error-label")
            yield Label("", id="status-label")
            yield LoadingIndicator(id="spinner")
            yield Static("", id="key-list")
            yield Static("Press Escape to close", id="dismiss-hint")

    def on_mount(self) -> None:
        self.query_one("#password-input", Input).focus()

    # -- event handlers -----------------------------------------------------

    def on_input_submitted(self, event: Input.Submitted) -> None:  # noqa: ARG002
        password = self.query_one("#password-input", Input).value
        if not password:
            self._show_error("Password cannot be empty")
            return
        self._enter_loading("Unlocking vault\u2026")
        self._do_unlock(password)

    def action_close_screen(self) -> None:
        """Handle Escape — cancel during input, dismiss during success."""
        if not self._is_success:
            self.result = UnlockResult(error="cancelled")
        self.exit()

    # -- UI state helpers ---------------------------------------------------

    def _enter_loading(self, status: str) -> None:
        """Switch to the loading state: hide input, show spinner + status."""
        self.query_one("#subtitle", Static).display = False
        self.query_one("#password-input", Input).display = False
        self.query_one("#error-label", Label).display = False
        self.query_one("#key-list", Static).display = False
        self.query_one("#dismiss-hint", Static).display = False
        status_label = self.query_one("#status-label", Label)
        status_label.update(status)
        status_label.display = True
        self.query_one("#spinner", LoadingIndicator).display = True

    def _enter_input(self) -> None:
        """Switch back to the input state: show input, hide spinner."""
        self.query_one("#subtitle", Static).display = True
        pw = self.query_one("#password-input", Input)
        pw.display = True
        pw.disabled = False
        pw.clear()
        pw.focus()
        self.query_one("#status-label", Label).display = False
        self.query_one("#spinner", LoadingIndicator).display = False
        self.query_one("#key-list", Static).display = False
        self.query_one("#dismiss-hint", Static).display = False

    def _enter_success(self, key_count: int, keys: list[dict[str, str]]) -> None:
        """Switch to success state: show key list, wait for dismiss."""
        status_label = self.query_one("#status-label", Label)
        status_label.update(
            f"[bold green]\u2713[/bold green] Vault unlocked \u2014"
            f" {key_count} key(s) loaded"
        )
        status_label.display = True
        self.query_one("#spinner", LoadingIndicator).display = False

        # Build key list markup
        if keys:
            lines: list[str] = []
            for key in keys:
                comment = key.get("comment", "") or "Unnamed key"
                algorithm = key.get("algorithm", "")
                fingerprint = key.get("fingerprint", "")
                lines.append(f"  [bold]{comment}[/bold]")
                details = " \u00b7 ".join(p for p in (algorithm, fingerprint) if p)
                if details:
                    lines.append(f"  [dim]{details}[/dim]")
            key_list = self.query_one("#key-list", Static)
            key_list.update("\n".join(lines))
            key_list.display = True

        self.query_one("#dismiss-hint", Static).display = True

    def _show_error(self, message: str) -> None:
        label = self.query_one("#error-label", Label)
        label.update(message)
        label.display = True

    # -- worker -------------------------------------------------------------

    @work(exclusive=True)
    async def _do_unlock(self, password: str) -> None:
        """Full unlock pipeline: bw unlock -> daemon key-load -> success."""
        # Phase 1: unlock the vault
        try:
            session_key = await self._run_bw_unlock(password)
        except FileNotFoundError:
            self._enter_input()
            self._show_error(f"Bitwarden CLI not found: {self._bw_path}")
            return
        except TimeoutError:
            self._enter_input()
            self._show_error("Unlock timed out")
            return
        except RuntimeError as exc:
            # Wrong password or other bw failure
            self._enter_input()
            self._show_error(str(exc))
            return
        except OSError as exc:
            self._enter_input()
            self._show_error(str(exc))
            return

        if session_key is None:
            self._enter_input()
            self._show_error("No session key returned")
            return

        # Phase 2: send session to daemon and load keys
        key_count = 0
        keys: list[dict[str, str]] = []
        if self._on_session_ready is not None:
            self._enter_loading("Loading keys\u2026")
            try:
                daemon_result = await self._on_session_ready(session_key)
                key_count = daemon_result.get("key_count", 0)
                keys = daemon_result.get("keys", [])
            except Exception as exc:
                self._enter_input()
                self._show_error(f"Failed to load keys: {exc}")
                return

        # Phase 3: show success with key details — user dismisses manually
        self.result = UnlockResult(
            session_key=session_key, key_count=key_count, keys=keys
        )
        self._is_success = True
        self._enter_success(key_count, keys)

    async def _run_bw_unlock(self, password: str) -> str | None:
        """Execute ``bw unlock --raw`` and return the session key.

        The *password* is piped to stdin (not passed as an argument)
        to avoid exposure via ``/proc/<pid>/cmdline``.

        Raises:
            FileNotFoundError: If the ``bw`` binary cannot be found.
            TimeoutError: If the command does not finish in time.
            OSError: On other I/O errors.
            RuntimeError: If ``bw`` exits with a non-zero code.
        """
        proc = await asyncio.create_subprocess_exec(
            self._bw_path,
            "unlock",
            "--raw",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=(password + "\n").encode("utf-8")),
            timeout=_BW_UNLOCK_TIMEOUT,
        )

        if proc.returncode != 0:
            error_msg = stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(error_msg or "Unlock failed")

        session_key = stdout.decode("utf-8").strip()
        return session_key or None
