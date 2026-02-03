"""Tests for bwssh.main module."""

import pytest

from bwssh.main import main


def test_main(capsys: pytest.CaptureFixture[str]) -> None:
    """Test main function prints expected output."""
    main()
    captured = capsys.readouterr()
    assert "Hello from bwssh!" in captured.out
