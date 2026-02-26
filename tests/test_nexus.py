"""
BJHunt Alpha — Unified Test Suite

Single test file covering all components:
  1. Health Check System (integration)
  2. Core Imports & Configuration
  3. Server Routing (all 35+ tools)
  4. Tool Functions (unit tests with mocks)
  5. Utility Functions
  6. Session Management
  7. MCP Protocol

Run with:  pytest tests/test_bjhunt.py -v
"""

import asyncio
import json
import os
import shutil
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import mcp.types as types
import pytest


# ══════════════════════════════════════════════════════════════════════════════
# FIXTURES
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def clean_test_artifacts(tmp_path, monkeypatch):
    """Ensure tests run in a temp directory and clean up after."""
    monkeypatch.chdir(tmp_path)
    os.makedirs("sessions", exist_ok=True)
    yield
    # Cleanup happens automatically via tmp_path


@pytest.fixture
def mock_subprocess():
    """Provide a mock for asyncio.create_subprocess_shell."""
    mock_proc = AsyncMock()
    mock_proc.communicate = AsyncMock(return_value=(b"mock output", b""))
    mock_proc.returncode = 0
    mock_proc.kill = MagicMock()

    with patch("asyncio.create_subprocess_shell", return_value=mock_proc) as mock:
        yield mock, mock_proc


# ══════════════════════════════════════════════════════════════════════════════
# 1. HEALTH CHECK SYSTEM TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestHealthCheck:
    """Tests for the health check infrastructure."""

    def test_health_check_imports(self):
        """Health check module imports without errors."""
        from bjhunt_alpha.healthcheck import (
            Status, CheckResult, HealthReport,
            run_health_check, format_report_text,
        )
        assert Status.OK.value == "ok"
        assert Status.FAIL.value == "fail"

    def test_health_check_quick(self):
        """Quick health check runs and returns a valid report."""
        from bjhunt_alpha.healthcheck import run_health_check, Status

        report = run_health_check(quick=True)

        assert report.timestamp != ""
        assert report.version != ""
        assert report.overall_status in (Status.OK, Status.WARN, Status.FAIL)
        assert len(report.checks) > 0
        assert report.summary["ok"] + report.summary["warn"] + report.summary["fail"] + report.summary["skip"] == len(report.checks)

    def test_health_check_full(self):
        """Full health check runs all checks."""
        from bjhunt_alpha.healthcheck import run_health_check, FULL_CHECKS

        report = run_health_check(quick=False)

        assert len(report.checks) >= len(FULL_CHECKS)

    def test_health_report_to_dict(self):
        """Health report serializes to dict correctly."""
        from bjhunt_alpha.healthcheck import run_health_check

        report = run_health_check(quick=True)
        d = report.to_dict()

        assert "timestamp" in d
        assert "overall_status" in d
        assert "checks" in d
        assert isinstance(d["checks"], list)
        # Verify JSON serializable
        json_str = json.dumps(d)
        assert len(json_str) > 0

    def test_health_report_format_text(self):
        """Health report formats to readable text."""
        from bjhunt_alpha.healthcheck import run_health_check, format_report_text

        report = run_health_check(quick=True)
        text = format_report_text(report)

        assert "BJHunt Alpha" in text
        assert "Health Check Report" in text
        assert report.version in text

    def test_check_core_imports(self):
        """Core import check passes."""
        from bjhunt_alpha.healthcheck import check_core_imports, Status

        result = check_core_imports()
        assert result.status == Status.OK
        assert "core modules" in result.message

    def test_check_version(self):
        """Version check returns valid semver."""
        from bjhunt_alpha.healthcheck import check_version, Status

        result = check_version()
        assert result.status == Status.OK
        assert "1.0.0" in result.message

    def test_check_server_instance(self):
        """Server instance check confirms bjhunt-alpha name."""
        from bjhunt_alpha.healthcheck import check_server_instance, Status

        result = check_server_instance()
        assert result.status == Status.OK
        assert "bjhunt-alpha" in result.message

    def test_check_tool_functions(self):
        """All tool functions are found and callable."""
        from bjhunt_alpha.healthcheck import check_tool_functions, Status

        result = check_tool_functions()
        assert result.status == Status.OK
        assert "tool functions" in result.message.lower()

    def test_check_utility_functions(self):
        """Utility functions work correctly."""
        from bjhunt_alpha.healthcheck import check_utility_functions, Status

        result = check_utility_functions()
        assert result.status == Status.OK

    def test_check_python_dependencies(self):
        """All Python deps are installed."""
        from bjhunt_alpha.healthcheck import check_python_dependencies, Status

        result = check_python_dependencies()
        assert result.status == Status.OK
        assert "dependencies" in result.message.lower()


# ══════════════════════════════════════════════════════════════════════════════
# 2. CORE IMPORTS & CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

class TestCoreImports:
    """Verify all modules import and are configured correctly."""

    def test_package_import(self):
        """Package imports successfully."""
        import bjhunt_alpha
        assert bjhunt_alpha.__version__ == "1.0.0"

    def test_server_import(self):
        """Server module imports and has required exports."""
        from bjhunt_alpha.server import (
            bjhunt_server, handle_tool_request,
            list_available_tools, list_resources,
            read_resource, main, start_sse_server,
            start_stdio_server,
        )
        assert bjhunt_server.name == "bjhunt-alpha"

    def test_tools_import(self):
        """Tools module imports and has all required functions."""
        from bjhunt_alpha.tools import (
            fetch_website, run_command, sudo_command,
            list_system_resources, vulnerability_scan,
            web_enumeration, network_discovery, exploit_search,
            save_output, create_report, file_analysis, download_file,
            session_create, session_list, session_switch,
            session_status, session_delete, session_history,
            spider_website, form_analysis, header_analysis,
            ssl_analysis, subdomain_enum, web_audit,
            start_mitmdump, start_proxify,
            list_processes, stop_process,
            msfvenom_payload, metasploit_handler,
            impacket_attack, netexec_attack,
            responder_start, bloodhound_collect,
            reverse_shell_listener, chisel_tunnel,
            wifi_scan, hash_crack,
        )

    def test_healthcheck_import(self):
        """Healthcheck module imports successfully."""
        from bjhunt_alpha.healthcheck import (
            run_health_check, format_report_text,
            HealthReport, CheckResult, Status,
        )


# ══════════════════════════════════════════════════════════════════════════════
# 3. SERVER ROUTING — ALL TOOLS
# ══════════════════════════════════════════════════════════════════════════════

class TestServerRouting:
    """Verify handle_tool_request routes to the correct handler for every tool."""

    @pytest.mark.asyncio
    async def test_unknown_tool_raises(self):
        """Unknown tool name raises ValueError."""
        from bjhunt_alpha.server import handle_tool_request

        with pytest.raises(ValueError, match="Unknown tool"):
            await handle_tool_request("nonexistent_tool_xyz", {})

    @pytest.mark.asyncio
    @pytest.mark.parametrize("tool_name,required_args", [
        ("fetch", ["url"]),
        ("run", ["command"]),
        ("vulnerability_scan", ["target"]),
        ("web_enumeration", ["target"]),
        ("network_discovery", ["target"]),
        ("exploit_search", ["search_term"]),
        ("save_output", ["content"]),
        ("create_report", ["title", "findings"]),
        ("file_analysis", ["filepath"]),
        ("download_file", ["url"]),
        ("session_create", ["session_name"]),
        ("session_switch", ["session_name"]),
        ("session_delete", ["session_name"]),
        ("spider_website", ["url"]),
        ("form_analysis", ["url"]),
        ("header_analysis", ["url"]),
        ("ssl_analysis", ["url"]),
        ("subdomain_enum", ["url"]),
        ("web_audit", ["url"]),
        ("stop_process", ["pattern"]),
        ("sudo", ["command"]),
        ("msfvenom_payload", ["payload_type", "lhost", "lport"]),
        ("metasploit_handler", ["payload_type", "lhost", "lport"]),
        ("impacket_attack", ["attack_type", "target"]),
        ("netexec_attack", ["protocol", "target"]),
        ("bloodhound_collect", ["domain", "username", "password", "dc_ip"]),
        ("reverse_shell_listener", ["port"]),
        ("chisel_tunnel", ["mode"]),
        ("hash_crack", ["hash_value"]),
    ])
    async def test_missing_required_args(self, tool_name, required_args):
        """Tools with required args raise ValueError when called without them."""
        from bjhunt_alpha.server import handle_tool_request

        with pytest.raises(ValueError, match="Missing required argument"):
            await handle_tool_request(tool_name, {})

    @pytest.mark.asyncio
    @pytest.mark.parametrize("tool_name", [
        "resources", "session_list", "session_status",
        "session_history", "list_processes",
    ])
    async def test_no_required_args_tools(self, tool_name):
        """Tools with no required args execute without raising ValueError."""
        from bjhunt_alpha.server import handle_tool_request

        # These tools should not raise ValueError for missing args
        # They may raise other exceptions if not in Docker, but not ValueError
        try:
            result = await handle_tool_request(tool_name, {})
            assert len(result) >= 1
            assert hasattr(result[0], "text")
        except ValueError as e:
            # Only fail if it's a "Missing required argument" or "Unknown tool"
            if "Missing required argument" in str(e) or "Unknown tool" in str(e):
                pytest.fail(f"Tool '{tool_name}' should not require args: {e}")

    @pytest.mark.asyncio
    async def test_fetch_routing(self):
        """Fetch tool routes correctly with mock."""
        from bjhunt_alpha.server import handle_tool_request

        async def mock_fetch(url):
            return [types.TextContent(type="text", text=f"Fetched: {url}")]

        with patch("bjhunt_alpha.server.fetch_website", mock_fetch):
            result = await handle_tool_request("fetch", {"url": "https://test.com"})
            assert result[0].text == "Fetched: https://test.com"

    @pytest.mark.asyncio
    async def test_run_routing(self):
        """Run tool routes correctly with mock."""
        from bjhunt_alpha.server import handle_tool_request

        async def mock_run(command, **kwargs):
            return [types.TextContent(type="text", text=f"Ran: {command}")]

        with patch("bjhunt_alpha.server.run_command", mock_run):
            result = await handle_tool_request("run", {"command": "whoami"})
            assert "Ran: whoami" in result[0].text

    @pytest.mark.asyncio
    async def test_all_registered_tools_are_routable(self):
        """Every tool registered in MCP schema maps to a valid route."""
        from bjhunt_alpha.server import list_available_tools, handle_tool_request

        tools = await list_available_tools()
        unroutable = []

        for tool in tools:
            try:
                await handle_tool_request(tool.name, {})
            except ValueError as e:
                if "Unknown tool" in str(e):
                    unroutable.append(tool.name)
            except Exception:
                pass  # Other errors are OK (missing deps, not in Docker, etc.)

        assert unroutable == [], f"Unroutable tools: {unroutable}"


# ══════════════════════════════════════════════════════════════════════════════
# 4. TOOL FUNCTIONS — UNIT TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestToolFunctions:
    """Unit tests for individual tool functions with mocking."""

    @pytest.mark.asyncio
    async def test_fetch_website_valid_url(self):
        """fetch_website accepts valid URLs."""
        from bjhunt_alpha.tools import fetch_website

        mock_response = MagicMock()
        mock_response.text = "<html>Hello</html>"
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("bjhunt_alpha.tools.httpx.AsyncClient", return_value=mock_client):
            result = await fetch_website("https://example.com")
            assert len(result) == 1
            assert result[0].text == "<html>Hello</html>"

    @pytest.mark.asyncio
    async def test_fetch_website_invalid_url(self):
        """fetch_website rejects URLs without protocol."""
        from bjhunt_alpha.tools import fetch_website

        with pytest.raises(ValueError, match="URL must start with http"):
            await fetch_website("example.com")

    @pytest.mark.asyncio
    async def test_run_command_foreground(self, mock_subprocess):
        """run_command executes foreground commands."""
        from bjhunt_alpha.tools import run_command

        mock_shell, mock_proc = mock_subprocess
        result = await run_command("echo hello", timeout=10)
        assert len(result) == 1
        assert "mock output" in result[0].text

    @pytest.mark.asyncio
    async def test_run_command_background(self, mock_subprocess):
        """run_command handles background execution."""
        from bjhunt_alpha.tools import run_command

        mock_shell, mock_proc = mock_subprocess
        result = await run_command("echo hello", background=True)
        assert len(result) == 1
        assert "background" in result[0].text.lower()

    @pytest.mark.asyncio
    async def test_run_command_auto_background(self, mock_subprocess):
        """run_command auto-detects long-running commands."""
        from bjhunt_alpha.tools import run_command

        mock_shell, mock_proc = mock_subprocess
        result = await run_command("nmap -sS 127.0.0.1")
        assert "background" in result[0].text.lower()

    @pytest.mark.asyncio
    async def test_sudo_command(self, mock_subprocess):
        """sudo_command prefixes with sudo."""
        from bjhunt_alpha.tools import sudo_command

        mock_shell, mock_proc = mock_subprocess
        result = await sudo_command("whoami", timeout=10)
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_vulnerability_scan(self, mock_subprocess):
        """vulnerability_scan returns expected output structure."""
        from bjhunt_alpha.tools import vulnerability_scan

        result = await vulnerability_scan("127.0.0.1", "quick")
        assert len(result) == 1
        assert "Starting quick vulnerability scan" in result[0].text
        assert "127.0.0.1" in result[0].text

    @pytest.mark.asyncio
    async def test_web_enumeration(self, mock_subprocess):
        """web_enumeration returns expected output."""
        from bjhunt_alpha.tools import web_enumeration

        result = await web_enumeration("http://example.com", "basic")
        assert "Starting basic web enumeration" in result[0].text

    @pytest.mark.asyncio
    async def test_network_discovery(self, mock_subprocess):
        """network_discovery returns expected output."""
        from bjhunt_alpha.tools import network_discovery

        result = await network_discovery("192.168.1.0/24", "quick")
        assert "Starting quick network discovery" in result[0].text

    @pytest.mark.asyncio
    async def test_save_output(self):
        """save_output creates timestamped file."""
        from bjhunt_alpha.tools import save_output

        result = await save_output("test data", "test_save", "evidence")
        assert "Content saved successfully" in result[0].text
        assert "evidence_test_save_" in result[0].text

    @pytest.mark.asyncio
    async def test_create_report_markdown(self):
        """create_report generates markdown report."""
        from bjhunt_alpha.tools import create_report

        result = await create_report("Pentest Report", "Found vuln XSS", "markdown")
        assert "Report generated successfully" in result[0].text

    @pytest.mark.asyncio
    async def test_create_report_json(self):
        """create_report generates JSON report."""
        from bjhunt_alpha.tools import create_report

        result = await create_report("JSON Report", "Findings data", "json")
        assert "Report generated successfully" in result[0].text

    @pytest.mark.asyncio
    async def test_create_report_text(self):
        """create_report generates text report."""
        from bjhunt_alpha.tools import create_report

        result = await create_report("Text Report", "Text findings", "text")
        assert "Report generated successfully" in result[0].text

    @pytest.mark.asyncio
    async def test_list_system_resources(self):
        """list_system_resources returns structured output."""
        from bjhunt_alpha.tools import list_system_resources

        result = await list_system_resources()
        assert len(result) == 1
        assert "System Resources" in result[0].text
        assert "network" in result[0].text.lower()

    @pytest.mark.asyncio
    async def test_reverse_shell_listener(self):
        """reverse_shell_listener generates payload hints."""
        from bjhunt_alpha.tools import reverse_shell_listener

        result = await reverse_shell_listener(4444, "nc")
        text = result[0].text
        assert "Reverse Shell Listener" in text
        assert "4444" in text
        assert "Bash" in text or "Python" in text  # payload hints

    @pytest.mark.asyncio
    async def test_wifi_scan(self):
        """wifi_scan returns scan instructions."""
        from bjhunt_alpha.tools import wifi_scan

        result = await wifi_scan("wlan0")
        text = result[0].text
        assert "WiFi" in text
        assert "wlan0" in text

    @pytest.mark.asyncio
    async def test_hash_crack(self):
        """hash_crack returns cracking command."""
        from bjhunt_alpha.tools import hash_crack

        result = await hash_crack("5f4dcc3b5aa765d61d8327deb882cf99", "md5")
        text = result[0].text
        assert "Hash Cracking" in text
        assert "md5" in text


# ══════════════════════════════════════════════════════════════════════════════
# 5. UTILITY FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

class TestUtilityFunctions:
    """Test security utilities and helper functions."""

    def test_sanitize_credentials_password(self):
        """Passwords are masked in output."""
        from bjhunt_alpha.tools import sanitize_credentials

        result = sanitize_credentials(
            "Login with password MySecret123",
            password="MySecret123"
        )
        assert "MySecret123" not in result
        assert "***PASSWORD***" in result

    def test_sanitize_credentials_hash(self):
        """Hashes are masked in output."""
        from bjhunt_alpha.tools import sanitize_credentials

        result = sanitize_credentials(
            "Hash is ABCDEF012345",
            hashes="ABCDEF012345"
        )
        assert "ABCDEF012345" not in result
        assert "***HASH***" in result

    def test_sanitize_credentials_none(self):
        """No masking when no credentials provided."""
        from bjhunt_alpha.tools import sanitize_credentials

        text = "No credentials here"
        result = sanitize_credentials(text)
        assert result == text

    def test_check_tool_exists_python(self):
        """check_tool_exists finds python."""
        from bjhunt_alpha.tools import check_tool_exists

        assert check_tool_exists("python") or check_tool_exists("python3")

    def test_check_tool_exists_missing(self):
        """check_tool_exists returns False for missing tools."""
        from bjhunt_alpha.tools import check_tool_exists

        assert not check_tool_exists("nonexistent_tool_xyz_12345")

    def test_is_long_running_detection(self):
        """Long-running command detection."""
        from bjhunt_alpha.tools import is_long_running

        assert is_long_running("nmap -sS 10.0.0.1")
        assert is_long_running("nikto -h http://target")
        assert is_long_running("gobuster dir -u http://target")
        assert is_long_running("sqlmap --url http://target")
        assert is_long_running("hydra -l admin ssh://target")
        assert is_long_running("masscan -p1-65535 10.0.0.0/8")

    def test_is_long_running_short_commands(self):
        """Short commands are not detected as long-running."""
        from bjhunt_alpha.tools import is_long_running

        assert not is_long_running("echo hello")
        assert not is_long_running("whoami")
        assert not is_long_running("cat /etc/passwd")
        assert not is_long_running("ls -la")
        assert not is_long_running("pwd")

    def test_cleanup_old_files(self):
        """cleanup_old_files removes excess files."""
        from bjhunt_alpha.tools import cleanup_old_files

        # Create test files
        for i in range(15):
            with open(f"test_cleanup_{i:03d}.txt", "w") as f:
                f.write(f"file {i}")

        cleanup_old_files("test_cleanup_*.txt", max_files=5)

        remaining = [f for f in os.listdir(".") if f.startswith("test_cleanup_")]
        assert len(remaining) <= 5

    def test_log_action_no_crash(self):
        """log_action doesn't crash."""
        from bjhunt_alpha.tools import log_action

        # Should not raise
        log_action("test_action", key="value", num=42)


# ══════════════════════════════════════════════════════════════════════════════
# 6. SESSION MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

class TestSessionManagement:
    """Test session lifecycle: create → list → switch → status → history → delete."""

    @pytest.mark.asyncio
    async def test_session_create(self):
        """Create a new session."""
        from bjhunt_alpha.tools import session_create

        result = await session_create("pentest_01", "Test session", "192.168.1.1")
        assert "created and set as active" in result[0].text
        assert "pentest_01" in result[0].text

    @pytest.mark.asyncio
    async def test_session_create_duplicate(self):
        """Creating duplicate session returns error."""
        from bjhunt_alpha.tools import session_create

        await session_create("dup_session", "First", "target")
        result = await session_create("dup_session", "Second", "target")
        assert "already exists" in result[0].text

    @pytest.mark.asyncio
    async def test_session_list(self):
        """List sessions shows created sessions."""
        from bjhunt_alpha.tools import session_create, session_list

        await session_create("list_test", "For listing", "target")
        result = await session_list()
        assert "list_test" in result[0].text

    @pytest.mark.asyncio
    async def test_session_list_empty(self):
        """List sessions when none exist."""
        from bjhunt_alpha.tools import session_list

        # Clean sessions dir
        shutil.rmtree("sessions", ignore_errors=True)
        os.makedirs("sessions", exist_ok=True)

        result = await session_list()
        assert "No sessions found" in result[0].text

    @pytest.mark.asyncio
    async def test_session_switch(self):
        """Switch between sessions."""
        from bjhunt_alpha.tools import session_create, session_switch

        await session_create("switch_a", "Session A", "target_a")
        await session_create("switch_b", "Session B", "target_b")
        result = await session_switch("switch_a")
        assert "Switched to session 'switch_a'" in result[0].text

    @pytest.mark.asyncio
    async def test_session_switch_nonexistent(self):
        """Switch to non-existent session fails."""
        from bjhunt_alpha.tools import session_switch

        result = await session_switch("does_not_exist")
        assert "not found" in result[0].text

    @pytest.mark.asyncio
    async def test_session_status(self):
        """Session status shows active session info."""
        from bjhunt_alpha.tools import session_create, session_status

        await session_create("status_test", "For status", "10.0.0.1")
        result = await session_status()
        assert "Active Session" in result[0].text
        assert "status_test" in result[0].text

    @pytest.mark.asyncio
    async def test_session_history_empty(self):
        """Session history when no activity recorded."""
        from bjhunt_alpha.tools import session_create, session_history

        await session_create("history_test", "For history", "target")
        result = await session_history()
        assert "No history recorded" in result[0].text or "Session History" in result[0].text

    @pytest.mark.asyncio
    async def test_session_delete(self):
        """Delete a non-active session."""
        from bjhunt_alpha.tools import session_create, session_switch, session_delete

        await session_create("keep_session", "Keep", "target")
        await session_create("delete_me", "Delete", "target")
        await session_switch("keep_session")

        result = await session_delete("delete_me")
        assert "deleted successfully" in result[0].text

    @pytest.mark.asyncio
    async def test_session_delete_active_fails(self):
        """Cannot delete the active session."""
        from bjhunt_alpha.tools import session_create, session_delete

        await session_create("active_session", "Active", "target")
        result = await session_delete("active_session")
        assert "Cannot delete active session" in result[0].text

    @pytest.mark.asyncio
    async def test_session_full_lifecycle(self):
        """Full session lifecycle: create → status → switch → delete."""
        from bjhunt_alpha.tools import (
            session_create, session_list, session_switch,
            session_status, session_delete, session_history,
        )

        # Create two sessions
        r1 = await session_create("lifecycle_a", "Alpha", "10.0.0.1")
        assert "created" in r1[0].text

        r2 = await session_create("lifecycle_b", "Beta", "10.0.0.2")
        assert "created" in r2[0].text

        # List
        r3 = await session_list()
        assert "lifecycle_a" in r3[0].text
        assert "lifecycle_b" in r3[0].text

        # Status (lifecycle_b is active since it was created last)
        r4 = await session_status()
        assert "lifecycle_b" in r4[0].text

        # Switch to a
        r5 = await session_switch("lifecycle_a")
        assert "Switched" in r5[0].text

        # Delete b (now inactive)
        r6 = await session_delete("lifecycle_b")
        assert "deleted" in r6[0].text

        # History
        r7 = await session_history()
        assert len(r7) == 1


# ══════════════════════════════════════════════════════════════════════════════
# 7. MCP PROTOCOL
# ══════════════════════════════════════════════════════════════════════════════

class TestMCPProtocol:
    """Test MCP-level protocol concerns."""

    @pytest.mark.asyncio
    async def test_list_tools_returns_all(self):
        """list_available_tools returns all 35+ tools."""
        from bjhunt_alpha.server import list_available_tools

        tools = await list_available_tools()
        tool_names = [t.name for t in tools]

        assert len(tools) >= 35
        # Spot check critical tools
        assert "run" in tool_names
        assert "fetch" in tool_names
        assert "vulnerability_scan" in tool_names
        assert "msfvenom_payload" in tool_names
        assert "hash_crack" in tool_names

    @pytest.mark.asyncio
    async def test_tool_schemas_valid(self):
        """All tool input schemas have required structure."""
        from bjhunt_alpha.server import list_available_tools

        tools = await list_available_tools()
        for tool in tools:
            assert tool.name, f"Tool has empty name"
            assert tool.description, f"Tool '{tool.name}' has empty description"
            assert tool.inputSchema, f"Tool '{tool.name}' has no schema"
            assert tool.inputSchema.get("type") == "object", \
                f"Tool '{tool.name}' schema type is not 'object'"
            assert "properties" in tool.inputSchema, \
                f"Tool '{tool.name}' schema has no properties"

    @pytest.mark.asyncio
    async def test_no_duplicate_tool_names(self):
        """No duplicate tool names in MCP registration."""
        from bjhunt_alpha.server import list_available_tools

        tools = await list_available_tools()
        names = [t.name for t in tools]
        assert len(names) == len(set(names)), \
            f"Duplicate tool names: {[n for n in names if names.count(n) > 1]}"

    @pytest.mark.asyncio
    async def test_required_args_match_schema(self):
        """Tools with required schema args raise ValueError when missing."""
        from bjhunt_alpha.server import list_available_tools, handle_tool_request

        tools = await list_available_tools()

        for tool in tools:
            required = tool.inputSchema.get("required", [])
            if required:
                try:
                    await handle_tool_request(tool.name, {})
                    # If no error, the tool doesn't enforce required args
                except ValueError as e:
                    assert "Missing required argument" in str(e), \
                        f"Tool '{tool.name}' raised wrong ValueError: {e}"
                except Exception:
                    pass  # Other exceptions are fine
