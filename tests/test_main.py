"""Tests for bwssh.main module — verify redirect to cli."""

from bwssh.cli import main as cli_main
from bwssh.main import main as main_func


def test_main_is_cli_main() -> None:
    assert main_func is cli_main
