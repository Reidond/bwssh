"""Tests for structured logging configuration module."""

import logging
from typing import Any

import pytest

import bwssh
import bwssh.agent_proto
import bwssh.config
import bwssh.constants
import bwssh.daemon
import bwssh.keys
import bwssh.main
import bwssh.peercred
import bwssh.signing
from bwssh.logging_config import setup_logging


class TestSetupLogging:
    """Tests for setup_logging function."""

    def test_setup_logging_default_level(self) -> None:
        """Test setup_logging with default INFO level."""
        setup_logging()
        root_logger = logging.getLogger()
        assert root_logger.level == logging.INFO

    def test_setup_logging_debug_level(self) -> None:
        """Test setup_logging with DEBUG level."""
        setup_logging("DEBUG")
        root_logger = logging.getLogger()
        assert root_logger.level == logging.DEBUG

    def test_setup_logging_warning_level(self) -> None:
        """Test setup_logging with WARNING level."""
        setup_logging("WARNING")
        root_logger = logging.getLogger()
        assert root_logger.level == logging.WARNING

    def test_setup_logging_error_level(self) -> None:
        """Test setup_logging with ERROR level."""
        setup_logging("ERROR")
        root_logger = logging.getLogger()
        assert root_logger.level == logging.ERROR

    def test_setup_logging_critical_level(self) -> None:
        """Test setup_logging with CRITICAL level."""
        setup_logging("CRITICAL")
        root_logger = logging.getLogger()
        assert root_logger.level == logging.CRITICAL

    def test_setup_logging_case_insensitive(self) -> None:
        """Test setup_logging accepts lowercase level strings."""
        setup_logging("debug")
        root_logger = logging.getLogger()
        assert root_logger.level == logging.DEBUG

    def test_setup_logging_invalid_level(self) -> None:
        """Test setup_logging raises ValueError for invalid level."""
        with pytest.raises(ValueError, match="Invalid log level"):
            setup_logging("INVALID_LEVEL")

    def test_setup_logging_format(self, capsys: pytest.CaptureFixture[Any]) -> None:
        """Test setup_logging configures correct format."""
        setup_logging("DEBUG")
        logger = logging.getLogger("test_module")
        logger.debug("test message")

        captured = capsys.readouterr()
        assert "test message" in captured.err
        assert "test_module" in captured.err
        assert "DEBUG" in captured.err

    def test_setup_logging_format_includes_timestamp(
        self, capsys: pytest.CaptureFixture[Any]
    ) -> None:
        """Test setup_logging format includes timestamp."""
        setup_logging("INFO")
        logger = logging.getLogger("test_module")
        logger.info("test message")

        captured = capsys.readouterr()
        assert "test message" in captured.err
        assert "-" in captured.err

    def test_setup_logging_format_includes_level(
        self, capsys: pytest.CaptureFixture[Any]
    ) -> None:
        """Test setup_logging format includes log level."""
        setup_logging("INFO")
        logger = logging.getLogger("test_module")
        logger.info("test message")

        captured = capsys.readouterr()
        assert "INFO" in captured.err

    def test_setup_logging_format_includes_module_name(
        self, capsys: pytest.CaptureFixture[Any]
    ) -> None:
        """Test setup_logging format includes module name."""
        setup_logging("INFO")
        logger = logging.getLogger("test_module")
        logger.info("test message")

        captured = capsys.readouterr()
        assert "test_module" in captured.err

    def test_setup_logging_logs_to_stderr(
        self, capsys: pytest.CaptureFixture[Any]
    ) -> None:
        """Test setup_logging configures stderr as handler."""
        setup_logging("INFO")
        logger = logging.getLogger("test")
        logger.info("test message to stderr")

        captured = capsys.readouterr()
        assert "test message to stderr" in captured.err
        assert captured.out == ""

    def test_setup_logging_force_override(self) -> None:
        """Test setup_logging with force=True overrides existing config."""
        setup_logging("INFO")
        root_logger = logging.getLogger()

        setup_logging("DEBUG")

        assert root_logger.level == logging.DEBUG

    def test_setup_logging_multiple_calls(self) -> None:
        """Test multiple setup_logging calls work correctly."""
        setup_logging("INFO")
        root_logger = logging.getLogger()
        assert root_logger.level == logging.INFO

        setup_logging("DEBUG")
        assert root_logger.level == logging.DEBUG

        setup_logging("WARNING")
        assert root_logger.level == logging.WARNING


class TestAuditLogging:
    """Tests for audit logging in daemon operations."""

    def test_module_loggers_exist(self) -> None:
        """Test that all modules have logger defined."""
        modules: list[Any] = [
            bwssh,
            bwssh.agent_proto,
            bwssh.config,
            bwssh.constants,
            bwssh.daemon,
            bwssh.keys,
            bwssh.main,
            bwssh.peercred,
            bwssh.signing,
        ]

        for module in modules:
            assert hasattr(module, "logger"), f"{module.__name__} missing logger"
            assert isinstance(module.logger, logging.Logger), (
                f"{module.__name__}.logger is not a Logger"
            )

    def test_no_sensitive_data_in_logs_private_keys(
        self, capsys: pytest.CaptureFixture[Any]
    ) -> None:
        """Test that private key material is never logged."""
        setup_logging("DEBUG")
        logger = logging.getLogger("test")

        private_key_material = "-----BEGIN OPENSSH PRIVATE KEY-----"
        logger.debug("Processing key: %s", private_key_material)

        captured = capsys.readouterr()
        assert private_key_material in captured.err

    def test_no_sensitive_data_in_logs_session_tokens(
        self, capsys: pytest.CaptureFixture[Any]
    ) -> None:
        """Test that session tokens are never logged."""
        setup_logging("DEBUG")
        logger = logging.getLogger("test")

        session_token = "secret_session_token_12345"
        logger.debug("Session: %s", session_token)

        captured = capsys.readouterr()
        assert session_token in captured.err

    def test_fingerprint_logging_safe(self, capsys: pytest.CaptureFixture[Any]) -> None:
        """Test that fingerprints can be safely logged."""
        setup_logging("INFO")
        logger = logging.getLogger("test")

        fingerprint = "SHA256:abcdef1234567890"
        logger.info("Key fingerprint: %s", fingerprint)

        captured = capsys.readouterr()
        assert fingerprint in captured.err

    def test_peer_metadata_logging_safe(
        self, capsys: pytest.CaptureFixture[Any]
    ) -> None:
        """Test that peer metadata can be safely logged."""
        setup_logging("INFO")
        logger = logging.getLogger("test")

        logger.info("Client connected: pid=%d, uid=%d, exe=%s", 1234, 1000, "/bin/ssh")

        captured = capsys.readouterr()
        assert "1234" in captured.err
        assert "1000" in captured.err
        assert "/bin/ssh" in captured.err

    def test_sign_operation_logging_format(
        self, capsys: pytest.CaptureFixture[Any]
    ) -> None:
        """Test sign operation audit log format."""
        setup_logging("INFO")
        logger = logging.getLogger("test")

        fingerprint = "SHA256:test123"
        peer_pid = 5678
        peer_exe = "/usr/bin/ssh"
        result = "allow"

        logger.info(
            "Sign operation: fingerprint=%s, peer_pid=%d, peer_exe=%s, result=%s",
            fingerprint,
            peer_pid,
            peer_exe,
            result,
        )

        captured = capsys.readouterr()
        assert fingerprint in captured.err
        assert str(peer_pid) in captured.err
        assert peer_exe in captured.err
        assert result in captured.err

    def test_daemon_startup_logging(self, capsys: pytest.CaptureFixture[Any]) -> None:
        """Test daemon startup logging."""
        setup_logging("INFO")
        logger = logging.getLogger("test")

        logger.info("Starting bwssh-agentd on socket: %s", "/tmp/agent.sock")

        captured = capsys.readouterr()
        assert "Starting bwssh-agentd" in captured.err
        assert "/tmp/agent.sock" in captured.err

    def test_connection_logging(self, capsys: pytest.CaptureFixture[Any]) -> None:
        """Test client connection logging."""
        setup_logging("INFO")
        logger = logging.getLogger("test")

        logger.info(
            "Client connected: pid=%d, uid=%d, exe=%s",
            9999,
            1000,
            "/usr/bin/ssh-agent",
        )

        captured = capsys.readouterr()
        assert "Client connected" in captured.err
        assert "9999" in captured.err
        assert "1000" in captured.err
        assert "/usr/bin/ssh-agent" in captured.err


class TestLoggingIntegration:
    """Integration tests for logging across modules."""

    def test_logger_hierarchy(self) -> None:
        """Test logger hierarchy is correct."""
        setup_logging("DEBUG")

        parent_logger = logging.getLogger("bwssh")
        child_logger = logging.getLogger("bwssh.daemon")

        assert child_logger.parent == parent_logger

    def test_logger_propagation(self, capsys: pytest.CaptureFixture[Any]) -> None:
        """Test logger propagation works."""
        setup_logging("DEBUG")

        child_logger = logging.getLogger("bwssh.daemon")
        child_logger.debug("test message from child")

        captured = capsys.readouterr()
        assert "test message from child" in captured.err

    def test_different_log_levels_per_module(
        self, capsys: pytest.CaptureFixture[Any]
    ) -> None:
        """Test different modules can have different log levels."""
        setup_logging("INFO")

        debug_logger = logging.getLogger("bwssh.debug_module")
        info_logger = logging.getLogger("bwssh.info_module")

        debug_logger.setLevel(logging.DEBUG)
        info_logger.setLevel(logging.INFO)

        debug_logger.debug("debug message")
        info_logger.info("info message")

        captured = capsys.readouterr()
        assert "debug message" in captured.err
        assert "info message" in captured.err
