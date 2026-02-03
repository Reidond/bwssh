"""Tests for systemd unit files and packaging assets."""

from __future__ import annotations

import configparser
import xml.etree.ElementTree as ET
from pathlib import Path


class TestServiceFile:
    """Tests for bwssh-agent.service unit file."""

    @staticmethod
    def _get_service_path() -> Path:
        """Get path to service file."""
        return (
            Path(__file__).parent.parent
            / "packaging"
            / "systemd"
            / "bwssh-agent.service"
        )

    def test_service_file_exists(self) -> None:
        """Service file should exist."""
        assert self._get_service_path().exists()

    def test_service_file_is_valid_ini(self) -> None:
        """Service file should be valid INI format."""
        path = self._get_service_path()
        parser = configparser.ConfigParser()
        # Should not raise
        parser.read(path)

    def test_service_file_has_unit_section(self) -> None:
        """Service file should have [Unit] section."""
        path = self._get_service_path()
        parser = configparser.ConfigParser()
        parser.read(path)
        assert "Unit" in parser.sections()

    def test_service_file_has_service_section(self) -> None:
        """Service file should have [Service] section."""
        path = self._get_service_path()
        parser = configparser.ConfigParser()
        parser.read(path)
        assert "Service" in parser.sections()

    def test_service_file_has_install_section(self) -> None:
        """Service file should have [Install] section."""
        path = self._get_service_path()
        parser = configparser.ConfigParser()
        parser.read(path)
        assert "Install" in parser.sections()

    def test_service_has_description(self) -> None:
        """Service should have Description field."""
        path = self._get_service_path()
        parser = configparser.ConfigParser()
        parser.read(path)
        assert parser.has_option("Unit", "Description")
        assert "Bitwarden" in parser.get("Unit", "Description")

    def test_service_has_documentation(self) -> None:
        """Service should have Documentation field."""
        path = self._get_service_path()
        parser = configparser.ConfigParser()
        parser.read(path)
        assert parser.has_option("Unit", "Documentation")

    def test_service_requires_socket(self) -> None:
        """Service should require socket."""
        path = self._get_service_path()
        parser = configparser.ConfigParser()
        parser.read(path)
        assert parser.has_option("Unit", "Requires")
        assert "bwssh-agent.socket" in parser.get("Unit", "Requires")

    def test_service_type_is_simple(self) -> None:
        """Service type should be simple."""
        path = self._get_service_path()
        parser = configparser.ConfigParser()
        parser.read(path)
        assert parser.get("Service", "Type") == "simple"

    def test_service_exec_start_points_to_agentd(self) -> None:
        """ExecStart should point to bwssh-agentd."""
        path = self._get_service_path()
        parser = configparser.ConfigParser()
        parser.read(path)
        exec_start = parser.get("Service", "ExecStart", raw=True)
        assert "bwssh-agentd" in exec_start
        assert "--foreground" in exec_start

    def test_service_has_restart_policy(self) -> None:
        """Service should have Restart policy."""
        path = self._get_service_path()
        parser = configparser.ConfigParser()
        parser.read(path)
        assert parser.has_option("Service", "Restart")
        assert parser.get("Service", "Restart") == "on-failure"

    def test_service_has_umask(self) -> None:
        """Service should have UMask for security."""
        path = self._get_service_path()
        parser = configparser.ConfigParser()
        parser.read(path)
        assert parser.has_option("Service", "UMask")
        assert parser.get("Service", "UMask") == "0077"

    def test_service_install_also_socket(self) -> None:
        """Install section should also enable socket."""
        path = self._get_service_path()
        parser = configparser.ConfigParser()
        parser.read(path)
        assert parser.has_option("Install", "Also")
        assert "bwssh-agent.socket" in parser.get("Install", "Also")

    def test_service_wanted_by_default_target(self) -> None:
        """Service should be wanted by default.target."""
        path = self._get_service_path()
        parser = configparser.ConfigParser()
        parser.read(path)
        assert parser.has_option("Install", "WantedBy")
        assert "default.target" in parser.get("Install", "WantedBy")


class TestSocketFile:
    """Tests for bwssh-agent.socket unit file."""

    @staticmethod
    def _get_socket_path() -> Path:
        """Get path to socket file."""
        return (
            Path(__file__).parent.parent
            / "packaging"
            / "systemd"
            / "bwssh-agent.socket"
        )

    def test_socket_file_exists(self) -> None:
        """Socket file should exist."""
        assert self._get_socket_path().exists()

    def test_socket_file_is_valid_ini(self) -> None:
        """Socket file should be valid INI format."""
        path = self._get_socket_path()
        parser = configparser.ConfigParser()
        # Should not raise
        parser.read(path)

    def test_socket_file_has_unit_section(self) -> None:
        """Socket file should have [Unit] section."""
        path = self._get_socket_path()
        parser = configparser.ConfigParser()
        parser.read(path)
        assert "Unit" in parser.sections()

    def test_socket_file_has_socket_section(self) -> None:
        """Socket file should have [Socket] section."""
        path = self._get_socket_path()
        parser = configparser.ConfigParser()
        parser.read(path)
        assert "Socket" in parser.sections()

    def test_socket_file_has_install_section(self) -> None:
        """Socket file should have [Install] section."""
        path = self._get_socket_path()
        parser = configparser.ConfigParser()
        parser.read(path)
        assert "Install" in parser.sections()

    def test_socket_has_description(self) -> None:
        """Socket should have Description field."""
        path = self._get_socket_path()
        parser = configparser.ConfigParser()
        parser.read(path)
        assert parser.has_option("Unit", "Description")
        assert "Bitwarden" in parser.get("Unit", "Description")

    def test_socket_has_documentation(self) -> None:
        """Socket should have Documentation field."""
        path = self._get_socket_path()
        parser = configparser.ConfigParser()
        parser.read(path)
        assert parser.has_option("Unit", "Documentation")

    def test_socket_listen_stream_uses_runtime_dir(self) -> None:
        """ListenStream should use %t (runtime dir) specifier."""
        path = self._get_socket_path()
        parser = configparser.ConfigParser()
        parser.read(path)
        assert parser.has_option("Socket", "ListenStream")
        listen_stream = parser.get("Socket", "ListenStream", raw=True)
        assert "%t" in listen_stream
        assert "bwssh" in listen_stream
        assert "agent.sock" in listen_stream

    def test_socket_mode_is_secure(self) -> None:
        """SocketMode should be 0600 (owner only)."""
        path = self._get_socket_path()
        parser = configparser.ConfigParser()
        parser.read(path)
        assert parser.has_option("Socket", "SocketMode")
        assert parser.get("Socket", "SocketMode") == "0600"

    def test_directory_mode_is_secure(self) -> None:
        """DirectoryMode should be 0700 (owner only)."""
        path = self._get_socket_path()
        parser = configparser.ConfigParser()
        parser.read(path)
        assert parser.has_option("Socket", "DirectoryMode")
        assert parser.get("Socket", "DirectoryMode") == "0700"

    def test_socket_wanted_by_sockets_target(self) -> None:
        """Socket should be wanted by sockets.target."""
        path = self._get_socket_path()
        parser = configparser.ConfigParser()
        parser.read(path)
        assert parser.has_option("Install", "WantedBy")
        assert "sockets.target" in parser.get("Install", "WantedBy")


class TestPolkitPolicy:
    """Tests for polkit policy XML file."""

    @staticmethod
    def _get_policy_path() -> Path:
        """Get path to polkit policy file."""
        return (
            Path(__file__).parent.parent
            / "packaging"
            / "polkit"
            / "io.github.reidond.bwssh.policy"
        )

    def test_policy_file_exists(self) -> None:
        """Polkit policy file should exist."""
        assert self._get_policy_path().exists()

    def test_policy_xml_is_valid(self) -> None:
        """Polkit policy XML should be well-formed."""
        path = self._get_policy_path()
        tree = ET.parse(path)
        root = tree.getroot()
        assert root is not None

    def test_policy_root_element_is_policyconfig(self) -> None:
        """Root element should be policyconfig."""
        path = self._get_policy_path()
        tree = ET.parse(path)
        root = tree.getroot()
        assert root.tag == "policyconfig"

    def test_policy_has_vendor_info(self) -> None:
        """Policy should have vendor and vendor_url elements."""
        path = self._get_policy_path()
        tree = ET.parse(path)
        root = tree.getroot()
        vendor = root.find("vendor")
        vendor_url = root.find("vendor_url")
        assert vendor is not None
        assert vendor.text == "bwssh"
        assert vendor_url is not None
        assert vendor_url.text == "https://github.com/reidond/bwssh"

    def test_policy_has_three_actions(self) -> None:
        """Policy should have exactly 3 action elements."""
        path = self._get_policy_path()
        tree = ET.parse(path)
        root = tree.getroot()
        actions = root.findall("action")
        assert len(actions) == 3

    def test_policy_action_ids_are_canonical(self) -> None:
        """Action IDs should follow canonical naming."""
        path = self._get_policy_path()
        tree = ET.parse(path)
        root = tree.getroot()
        actions = root.findall("action")
        action_ids = {action.get("id") for action in actions}
        expected_ids = {
            "io.github.reidond.bwssh.sign",
            "io.github.reidond.bwssh.unlock",
            "io.github.reidond.bwssh.list",
        }
        assert action_ids == expected_ids

    def test_policy_sign_action_has_description(self) -> None:
        """Sign action should have description."""
        path = self._get_policy_path()
        tree = ET.parse(path)
        root = tree.getroot()
        sign_action = root.find(".//action[@id='io.github.reidond.bwssh.sign']")
        assert sign_action is not None
        description = sign_action.find("description")
        assert description is not None
        assert description.text == "Use an SSH key from Bitwarden"

    def test_policy_unlock_action_has_description(self) -> None:
        """Unlock action should have description."""
        path = self._get_policy_path()
        tree = ET.parse(path)
        root = tree.getroot()
        unlock_action = root.find(".//action[@id='io.github.reidond.bwssh.unlock']")
        assert unlock_action is not None
        description = unlock_action.find("description")
        assert description is not None
        assert description.text == "Unlock Bitwarden SSH agent"

    def test_policy_list_action_has_description(self) -> None:
        """List action should have description."""
        path = self._get_policy_path()
        tree = ET.parse(path)
        root = tree.getroot()
        list_action = root.find(".//action[@id='io.github.reidond.bwssh.list']")
        assert list_action is not None
        description = list_action.find("description")
        assert description is not None
        assert description.text == "List SSH identities"

    def test_policy_all_actions_have_message(self) -> None:
        """All actions should have message element."""
        path = self._get_policy_path()
        tree = ET.parse(path)
        root = tree.getroot()
        actions = root.findall("action")
        for action in actions:
            message = action.find("message")
            assert message is not None
            assert message.text is not None
            assert len(message.text) > 0

    def test_policy_all_actions_have_defaults(self) -> None:
        """All actions should have defaults element."""
        path = self._get_policy_path()
        tree = ET.parse(path)
        root = tree.getroot()
        actions = root.findall("action")
        for action in actions:
            defaults = action.find("defaults")
            assert defaults is not None

    def test_policy_all_defaults_have_allow_any(self) -> None:
        """All defaults should have allow_any=no."""
        path = self._get_policy_path()
        tree = ET.parse(path)
        root = tree.getroot()
        defaults_list = root.findall(".//defaults")
        for defaults in defaults_list:
            allow_any = defaults.find("allow_any")
            assert allow_any is not None
            assert allow_any.text == "no"

    def test_policy_all_defaults_have_allow_inactive(self) -> None:
        """All defaults should have allow_inactive=no."""
        path = self._get_policy_path()
        tree = ET.parse(path)
        root = tree.getroot()
        defaults_list = root.findall(".//defaults")
        for defaults in defaults_list:
            allow_inactive = defaults.find("allow_inactive")
            assert allow_inactive is not None
            assert allow_inactive.text == "no"

    def test_policy_all_defaults_have_allow_active(self) -> None:
        """All defaults should have allow_active element."""
        path = self._get_policy_path()
        tree = ET.parse(path)
        root = tree.getroot()
        defaults_list = root.findall(".//defaults")
        for defaults in defaults_list:
            allow_active = defaults.find("allow_active")
            assert allow_active is not None
            assert allow_active.text is not None

    def test_policy_sign_action_requires_auth_self_keep(self) -> None:
        """Sign action should have auth_self_keep for allow_active."""
        path = self._get_policy_path()
        tree = ET.parse(path)
        root = tree.getroot()
        sign_action = root.find(".//action[@id='io.github.reidond.bwssh.sign']")
        assert sign_action is not None
        defaults = sign_action.find("defaults")
        assert defaults is not None
        allow_active = defaults.find("allow_active")
        assert allow_active is not None
        assert allow_active.text == "auth_self_keep"

    def test_policy_unlock_action_requires_auth_self_keep(self) -> None:
        """Unlock action should have auth_self_keep for allow_active."""
        path = self._get_policy_path()
        tree = ET.parse(path)
        root = tree.getroot()
        unlock_action = root.find(".//action[@id='io.github.reidond.bwssh.unlock']")
        assert unlock_action is not None
        defaults = unlock_action.find("defaults")
        assert defaults is not None
        allow_active = defaults.find("allow_active")
        assert allow_active is not None
        assert allow_active.text == "auth_self_keep"

    def test_policy_list_action_allows_active_without_prompt(self) -> None:
        """List action should have yes for allow_active (no prompt)."""
        path = self._get_policy_path()
        tree = ET.parse(path)
        root = tree.getroot()
        list_action = root.find(".//action[@id='io.github.reidond.bwssh.list']")
        assert list_action is not None
        defaults = list_action.find("defaults")
        assert defaults is not None
        allow_active = defaults.find("allow_active")
        assert allow_active is not None
        assert allow_active.text == "yes"
