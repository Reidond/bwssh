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
            a dict containing at least ``"key_count"``.  When provided
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

_SUCCESS_PAUSE = 1.0  # seconds to show the success message


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
    """

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Cancel", show=True),
    ]

    def __init__(
        self,
        bw_path: str,
        on_session_ready: PostUnlockHook | None = None,
    ) -> None:
        super().__init__()
        self._bw_path = bw_path
        self._on_session_ready = on_session_ready
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

    def on_mount(self) -> None:
        self.query_one("#password-input", Input).focus()

    # -- event handlers -----------------------------------------------------

    def on_input_submitted(self, event: Input.Submitted) -> None:  # noqa: ARG002
        password = self.query_one("#password-input", Input).value
        if not password:
            self._show_error("Password cannot be empty.")
            return
        self._enter_loading("Unlocking vault...")
        self._do_unlock(password)

    def action_cancel(self) -> None:
        self.result = UnlockResult(error="cancelled")
        self.exit()

    # -- UI state helpers ---------------------------------------------------

    def _enter_loading(self, status: str) -> None:
        """Switch to the loading state: hide input, show spinner + status."""
        self.query_one("#subtitle", Static).display = False
        self.query_one("#password-input", Input).display = False
        self.query_one("#error-label", Label).display = False
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

    def _enter_success(self, message: str) -> None:
        """Switch to success state: show status, hide spinner."""
        status_label = self.query_one("#status-label", Label)
        status_label.update(f"[bold green]✓[/bold green] {message}")
        status_label.display = True
        self.query_one("#spinner", LoadingIndicator).display = False

    def _show_error(self, message: str) -> None:
        label = self.query_one("#error-label", Label)
        label.update(message)
        label.display = True

    # -- worker -------------------------------------------------------------

    @work(exclusive=True)
    async def _do_unlock(self, password: str) -> None:
        """Full unlock pipeline: bw unlock → daemon key-load → success."""
        # Phase 1: unlock the vault
        try:
            session_key = await self._run_bw_unlock(password)
        except FileNotFoundError:
            self._enter_input()
            self._show_error(f"Bitwarden CLI not found: {self._bw_path}")
            return
        except TimeoutError:
            self._enter_input()
            self._show_error("Unlock timed out.")
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
            self._show_error("No session key returned.")
            return

        # Phase 2: send session to daemon and load keys
        key_count = 0
        if self._on_session_ready is not None:
            self._enter_loading("Loading keys...")
            try:
                daemon_result = await self._on_session_ready(session_key)
                key_count = daemon_result.get("key_count", 0)
            except Exception as exc:
                self._enter_input()
                self._show_error(f"Failed to load keys: {exc}")
                return

        # Phase 3: show success briefly, then exit
        self._enter_success(f"Unlocked! {key_count} key(s) loaded.")
        await asyncio.sleep(_SUCCESS_PAUSE)

        self.result = UnlockResult(session_key=session_key, key_count=key_count)
        self.exit()

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
