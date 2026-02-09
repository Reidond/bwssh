"""TUI unlock screen powered by *textual*."""

from __future__ import annotations

import asyncio
from typing import ClassVar

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import Input, Label, LoadingIndicator, Static

from bwssh.ui._base import UnlockResult

_BW_UNLOCK_TIMEOUT = 30.0


class TuiUnlockUI:
    """TUI-based unlock UI using *textual*.

    Call :meth:`run` to take over the terminal, prompt for the master
    password, run ``bw unlock --raw``, and return the result.
    """

    def __init__(self, bw_path: str = "bw") -> None:
        self._bw_path = bw_path

    def run(self) -> UnlockResult:
        """Show TUI unlock screen and return the result."""
        app = _UnlockApp(bw_path=self._bw_path)
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

    #spinner {
        display: none;
        margin-top: 1;
    }
    """

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Cancel", show=True),
    ]

    def __init__(self, bw_path: str) -> None:
        super().__init__()
        self._bw_path = bw_path
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
            yield LoadingIndicator(id="spinner")

    def on_mount(self) -> None:
        self.query_one("#password-input", Input).focus()

    # -- event handlers -----------------------------------------------------

    def on_input_submitted(self, event: Input.Submitted) -> None:  # noqa: ARG002
        password = self.query_one("#password-input", Input).value
        if not password:
            self._show_error("Password cannot be empty.")
            return
        self._set_loading(loading=True)
        self._do_unlock(password)

    def action_cancel(self) -> None:
        self.result = UnlockResult(error="cancelled")
        self.exit()

    # -- helpers ------------------------------------------------------------

    def _show_error(self, message: str) -> None:
        label = self.query_one("#error-label", Label)
        label.update(message)
        label.display = True

    def _hide_error(self) -> None:
        self.query_one("#error-label", Label).display = False

    def _set_loading(self, *, loading: bool) -> None:
        self.query_one("#spinner", LoadingIndicator).display = loading
        self.query_one("#password-input", Input).disabled = loading
        if loading:
            self._hide_error()

    def _reset_input(self) -> None:
        pw = self.query_one("#password-input", Input)
        pw.clear()
        pw.focus()

    # -- worker -------------------------------------------------------------

    @work(exclusive=True)
    async def _do_unlock(self, password: str) -> None:
        """Run ``bw unlock --raw`` in the background."""
        try:
            session_key = await self._run_bw_unlock(password)
        except FileNotFoundError:
            self._set_loading(loading=False)
            self._show_error(f"Bitwarden CLI not found: {self._bw_path}")
            return
        except TimeoutError:
            self._set_loading(loading=False)
            self._show_error("Unlock timed out.")
            self._reset_input()
            return
        except OSError as exc:
            self._set_loading(loading=False)
            self._show_error(str(exc))
            self._reset_input()
            return

        if session_key is None:
            # Should not happen, but guard anyway
            self._set_loading(loading=False)
            self._show_error("No session key returned.")
            self._reset_input()
            return

        self.result = UnlockResult(session_key=session_key)
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
