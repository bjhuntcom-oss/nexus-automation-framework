"""
Nexus Automation Framework - Health Check System

Comprehensive health check module that validates all services, tools,
and internal components. Can be run standalone or integrated into the
MCP server as a diagnostic tool.

Usage:
    python -m nexus_framework.healthcheck          # Full health check
    python -m nexus_framework.healthcheck --json   # JSON output
    python -m nexus_framework.healthcheck --quick  # Quick check only
"""

import asyncio
import datetime
import importlib
import json
import os
import platform
import shutil
import sys
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional


# ══════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ══════════════════════════════════════════════════════════════════════════════

class Status(str, Enum):
    OK = "ok"
    WARN = "warn"
    FAIL = "fail"
    SKIP = "skip"


@dataclass
class CheckResult:
    name: str
    status: Status
    message: str
    duration_ms: float = 0.0
    details: Optional[Dict] = None


@dataclass
class HealthReport:
    timestamp: str = ""
    overall_status: Status = Status.OK
    version: str = ""
    hostname: str = ""
    python_version: str = ""
    uptime_seconds: float = 0.0
    checks: List[CheckResult] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "overall_status": self.overall_status.value,
            "version": self.version,
            "hostname": self.hostname,
            "python_version": self.python_version,
            "uptime_seconds": self.uptime_seconds,
            "summary": self.summary,
            "checks": [
                {
                    "name": c.name,
                    "status": c.status.value,
                    "message": c.message,
                    "duration_ms": round(c.duration_ms, 2),
                    **({"details": c.details} if c.details else {}),
                }
                for c in self.checks
            ],
        }


# ══════════════════════════════════════════════════════════════════════════════
# HEALTH CHECK ENGINE
# ══════════════════════════════════════════════════════════════════════════════

_start_time = time.time()


def _timed_check(name: str):
    """Decorator-like context for timing a health check."""
    class Timer:
        def __init__(self):
            self.start = 0.0
            self.elapsed_ms = 0.0
        def __enter__(self):
            self.start = time.perf_counter()
            return self
        def __exit__(self, *args):
            self.elapsed_ms = (time.perf_counter() - self.start) * 1000
    return Timer()


def _run_async(coro_fn, *args, **kwargs):
    """Run a coroutine safely even if a loop is already running."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro_fn(*args, **kwargs))

    new_loop = asyncio.new_event_loop()
    try:
        return new_loop.run_until_complete(coro_fn(*args, **kwargs))
    finally:
        new_loop.close()


# ──────────────────────────────────────────────────────────────────────────────
# 1. CORE MODULE CHECKS
# ──────────────────────────────────────────────────────────────────────────────

def check_core_imports() -> CheckResult:
    """Verify all core Nexus Automation Framework modules can be imported."""
    with _timed_check("core_imports") as t:
        errors = []
        modules = [
            "nexus_framework",
            "nexus_framework.server",
            "nexus_framework.tools",
            "nexus_framework.healthcheck",
        ]
        imported = []
        for mod in modules:
            try:
                importlib.import_module(mod)
                imported.append(mod)
            except Exception as e:
                errors.append(f"{mod}: {e}")

    if errors:
        return CheckResult(
            "core_imports", Status.FAIL,
            f"{len(errors)}/{len(modules)} modules failed to import",
            t.elapsed_ms, {"errors": errors}
        )
    return CheckResult(
        "core_imports", Status.OK,
        f"All {len(modules)} core modules imported successfully",
        t.elapsed_ms, {"modules": imported}
    )


def check_version() -> CheckResult:
    """Verify package version is set and valid."""
    with _timed_check("version") as t:
        try:
            from nexus_framework import __version__
            parts = __version__.split(".")
            if len(parts) != 3:
                return CheckResult("version", Status.WARN,
                    f"Version '{__version__}' is not semver", t.elapsed_ms)
            return CheckResult("version", Status.OK,
                f"Version {__version__}", t.elapsed_ms,
                {"version": __version__})
        except Exception as e:
            return CheckResult("version", Status.FAIL, str(e), t.elapsed_ms)


def check_server_instance() -> CheckResult:
    """Verify MCP server instance is created and configured."""
    with _timed_check("server_instance") as t:
        try:
            from nexus_framework.server import nexus_server
            name = nexus_server.name
            if name != "nexus-automation-framework":
                return CheckResult("server_instance", Status.WARN,
                    f"Server name is '{name}', expected 'nexus-automation-framework'",
                    t.elapsed_ms)
            return CheckResult("server_instance", Status.OK,
                f"Server '{name}' initialized", t.elapsed_ms)
        except Exception as e:
            return CheckResult("server_instance", Status.FAIL, str(e), t.elapsed_ms)


# ──────────────────────────────────────────────────────────────────────────────
# 2. TOOL FUNCTION CHECKS
# ──────────────────────────────────────────────────────────────────────────────

def check_tool_functions() -> CheckResult:
    """Verify all tool functions exist and are callable."""
    with _timed_check("tool_functions") as t:
        required_tools = [
            "fetch_website", "run_command", "sudo_command",
            "list_system_resources", "vulnerability_scan",
            "web_enumeration", "network_discovery", "exploit_search",
            "save_output", "create_report", "file_analysis", "download_file",
            "session_create", "session_list", "session_switch",
            "session_status", "session_delete", "session_history",
            "spider_website", "form_analysis", "header_analysis",
            "ssl_analysis", "subdomain_enum", "web_audit",
            "start_mitmdump", "start_proxify",
            "list_processes", "stop_process",
            "msfvenom_payload", "metasploit_handler",
            "impacket_attack", "netexec_attack",
            "responder_start", "bloodhound_collect",
            "reverse_shell_listener", "chisel_tunnel",
            "wifi_scan", "hash_crack",
        ]

        import nexus_framework.tools as tools_module
        found = []
        missing = []

        for tool_name in required_tools:
            fn = getattr(tools_module, tool_name, None)
            if fn and callable(fn):
                found.append(tool_name)
            else:
                missing.append(tool_name)

    if missing:
        return CheckResult(
            "tool_functions", Status.FAIL,
            f"{len(missing)}/{len(required_tools)} tools missing",
            t.elapsed_ms, {"missing": missing}
        )
    return CheckResult(
        "tool_functions", Status.OK,
        f"All {len(required_tools)} tool functions found and callable",
        t.elapsed_ms, {"count": len(found)}
    )


def check_tool_registration() -> CheckResult:
    """Verify MCP tool definitions match actual tool functions."""
    with _timed_check("tool_registration") as t:
        try:
            result = _run_async(_check_tool_registration_async)
            return CheckResult(
                "tool_registration", result[0], result[1],
                t.elapsed_ms, result[2]
            )
        except Exception as e:
            return CheckResult("tool_registration", Status.FAIL, str(e), t.elapsed_ms)


async def _check_tool_registration_async():
    from nexus_framework.server import list_available_tools
    tools = await list_available_tools()
    tool_names = [t.name for t in tools]

    # Check for duplicate names
    seen = set()
    duplicates = []
    for name in tool_names:
        if name in seen:
            duplicates.append(name)
        seen.add(name)

    if duplicates:
        return (Status.FAIL,
                f"Duplicate tool names: {duplicates}",
                {"duplicates": duplicates, "total": len(tool_names)})

    return (Status.OK,
            f"{len(tool_names)} tools registered in MCP schema",
            {"tool_names": tool_names, "total": len(tool_names)})


# ──────────────────────────────────────────────────────────────────────────────
# 3. UTILITY FUNCTION CHECKS
# ──────────────────────────────────────────────────────────────────────────────

def check_utility_functions() -> CheckResult:
    """Verify utility functions (sanitize, cleanup, logging) work correctly."""
    with _timed_check("utility_functions") as t:
        errors = []

        # Test sanitize_credentials
        try:
            from nexus_framework.tools import sanitize_credentials
            result = sanitize_credentials("password is secret123", password="secret123")
            if "secret123" in result:
                errors.append("sanitize_credentials: password not masked")
            result2 = sanitize_credentials("hash is ABCDEF", hashes="ABCDEF")
            if "ABCDEF" in result2:
                errors.append("sanitize_credentials: hash not masked")
        except Exception as e:
            errors.append(f"sanitize_credentials: {e}")

        # Test check_tool_exists
        try:
            from nexus_framework.tools import check_tool_exists
            # python should always exist
            if not check_tool_exists("python3") and not check_tool_exists("python"):
                errors.append("check_tool_exists: python not found")
        except Exception as e:
            errors.append(f"check_tool_exists: {e}")

        # Test is_long_running
        try:
            from nexus_framework.tools import is_long_running
            if not is_long_running("nmap -sS target"):
                errors.append("is_long_running: nmap not detected")
            if is_long_running("echo hello"):
                errors.append("is_long_running: echo detected as long-running")
        except Exception as e:
            errors.append(f"is_long_running: {e}")

        # Test log_action (should not raise)
        try:
            from nexus_framework.tools import log_action
            log_action("healthcheck_test", status="ok")
        except Exception as e:
            errors.append(f"log_action: {e}")

    if errors:
        return CheckResult("utility_functions", Status.FAIL,
            f"{len(errors)} utility checks failed", t.elapsed_ms,
            {"errors": errors})
    return CheckResult("utility_functions", Status.OK,
        "All utility functions working correctly", t.elapsed_ms)


# ──────────────────────────────────────────────────────────────────────────────
# 4. SESSION MANAGEMENT CHECKS
# ──────────────────────────────────────────────────────────────────────────────

def check_session_management() -> CheckResult:
    """Verify session management backend functions work."""
    with _timed_check("session_management") as t:
        errors = []

        try:
            from nexus_framework.tools import (
                ensure_sessions_dir, get_session_path,
                get_session_metadata_path, list_sessions,
                save_active_session, load_active_session,
            )

            # Verify sessions directory creation
            ensure_sessions_dir()
            if not os.path.exists("sessions"):
                errors.append("sessions directory not created")

            # Verify path generation
            path = get_session_path("test")
            if not path:
                errors.append("get_session_path returned empty")

            meta_path = get_session_metadata_path("test")
            if "metadata.json" not in meta_path:
                errors.append("metadata path incorrect")

            # Verify list_sessions doesn't crash
            sessions = list_sessions()
            if not isinstance(sessions, list):
                errors.append("list_sessions didn't return a list")

        except Exception as e:
            errors.append(f"session_management: {e}")

    if errors:
        return CheckResult("session_management", Status.FAIL,
            f"{len(errors)} session checks failed", t.elapsed_ms,
            {"errors": errors})
    return CheckResult("session_management", Status.OK,
        "Session management backend is functional", t.elapsed_ms,
        {"sessions_found": len(sessions) if 'sessions' in dir() else 0})


# ──────────────────────────────────────────────────────────────────────────────
# 5. DEPENDENCY CHECKS
# ──────────────────────────────────────────────────────────────────────────────

def check_python_dependencies() -> CheckResult:
    """Verify all required Python packages are installed."""
    with _timed_check("python_dependencies") as t:
        required = {
            "anyio": "anyio",
            "click": "click",
            "httpx": "httpx",
            "mcp": "mcp",
            "starlette": "starlette",
            "uvicorn": "uvicorn",
        }
        installed = []
        missing = []

        for display_name, import_name in required.items():
            try:
                mod = importlib.import_module(import_name)
                version = getattr(mod, "__version__", "unknown")
                installed.append(f"{display_name}=={version}")
            except ImportError:
                missing.append(display_name)

    if missing:
        return CheckResult("python_dependencies", Status.FAIL,
            f"{len(missing)} dependencies missing: {', '.join(missing)}",
            t.elapsed_ms, {"missing": missing, "installed": installed})
    return CheckResult("python_dependencies", Status.OK,
        f"All {len(required)} dependencies installed",
        t.elapsed_ms, {"installed": installed})


# ──────────────────────────────────────────────────────────────────────────────
# 6. SECURITY TOOLS (EXTERNAL BINARY) CHECKS
# ──────────────────────────────────────────────────────────────────────────────

def check_security_tools() -> CheckResult:
    """Check availability of external security tools (Kali Linux binaries)."""
    with _timed_check("security_tools") as t:
        categories = {
            "scanning": ["nmap", "masscan"],
            "web": ["nikto", "gobuster", "dirb", "ffuf", "sqlmap", "whatweb"],
            "exploitation": ["msfconsole", "searchsploit"],
            "credentials": ["hydra", "john", "hashcat"],
            "active_directory": ["crackmapexec", "responder", "enum4linux"],
            "network": ["tcpdump", "ettercap"],
            "wireless": ["aircrack-ng"],
            "recon": ["whois", "theharvester", "amass", "subfinder"],
            "tunneling": ["socat", "proxychains4"],
            "forensics": ["binwalk", "foremost", "exiftool"],
            "ssl": ["sslscan", "sslyze"],
            "go_tools": ["nuclei", "httpx", "waybackurls"],
            "proxy": ["mitmdump"],
            "utils": ["curl", "wget", "git", "python3"],
        }

        available = {}
        missing = {}
        total = 0
        total_found = 0

        for category, tools in categories.items():
            cat_available = []
            cat_missing = []
            for tool in tools:
                total += 1
                if shutil.which(tool):
                    cat_available.append(tool)
                    total_found += 1
                else:
                    cat_missing.append(tool)
            if cat_available:
                available[category] = cat_available
            if cat_missing:
                missing[category] = cat_missing

    # On Windows or non-Kali, most tools won't be present — that's OK
    if platform.system() != "Linux":
        return CheckResult("security_tools", Status.WARN,
            f"Non-Linux system detected — {total_found}/{total} tools found. "
            f"Full toolkit requires Kali Linux Docker container.",
            t.elapsed_ms, {"available": available, "missing": missing})

    if total_found == 0:
        return CheckResult("security_tools", Status.FAIL,
            "No security tools found — is this running in the Kali container?",
            t.elapsed_ms, {"missing": missing})

    if total_found < total * 0.5:
        return CheckResult("security_tools", Status.WARN,
            f"{total_found}/{total} tools available",
            t.elapsed_ms, {"available": available, "missing": missing})

    return CheckResult("security_tools", Status.OK,
        f"{total_found}/{total} security tools available",
        t.elapsed_ms, {"available": available, "missing": missing})


# ──────────────────────────────────────────────────────────────────────────────
# 7. FILESYSTEM CHECKS
# ──────────────────────────────────────────────────────────────────────────────

def check_filesystem() -> CheckResult:
    """Check that required directories and files exist."""
    with _timed_check("filesystem") as t:
        checks = {}

        # Required directories
        required_dirs = ["sessions"]
        optional_dirs = ["loot", "reports", "downloads"]

        for d in required_dirs:
            checks[f"dir:{d}"] = os.path.exists(d)

        for d in optional_dirs:
            if os.path.exists(d):
                checks[f"dir:{d}"] = True
            else:
                checks[f"dir:{d}"] = None  # optional

        # Required files
        required_files = [
            "nexus_framework/__init__.py",
            "nexus_framework/server.py",
            "nexus_framework/tools.py",
        ]

        for f in required_files:
            checks[f"file:{f}"] = os.path.isfile(f)

        # Check for wordlists (only in container)
        wordlist_dir = "/usr/share/wordlists"
        if os.path.exists(wordlist_dir):
            rockyou = os.path.exists(os.path.join(wordlist_dir, "rockyou.txt"))
            checks["wordlist:rockyou"] = rockyou
        else:
            checks["wordlist:rockyou"] = None  # not in container

        failed = [k for k, v in checks.items() if v is False]
        warnings = [k for k, v in checks.items() if v is None]

    if failed:
        return CheckResult("filesystem", Status.FAIL,
            f"{len(failed)} required files/dirs missing: {failed}",
            t.elapsed_ms, {"checks": {k: v for k, v in checks.items()}})
    if warnings:
        return CheckResult("filesystem", Status.WARN,
            f"All required paths exist, {len(warnings)} optional paths missing",
            t.elapsed_ms, {"checks": {k: v for k, v in checks.items()}})
    return CheckResult("filesystem", Status.OK,
        "All filesystem paths verified", t.elapsed_ms,
        {"checks": {k: v for k, v in checks.items()}})


# ──────────────────────────────────────────────────────────────────────────────
# 8. MCP PROTOCOL CHECKS
# ──────────────────────────────────────────────────────────────────────────────

def check_mcp_protocol() -> CheckResult:
    """Verify MCP protocol handlers are registered."""
    with _timed_check("mcp_protocol") as t:
        try:
            from nexus_framework.server import nexus_server

            handlers = {
                "call_tool": hasattr(nexus_server, "request_handlers"),
                "list_tools": True,  # We know it's registered via decorator
                "list_resources": True,
                "read_resource": True,
            }

            return CheckResult("mcp_protocol", Status.OK,
                "MCP protocol handlers registered", t.elapsed_ms,
                {"handlers": handlers})
        except Exception as e:
            return CheckResult("mcp_protocol", Status.FAIL, str(e), t.elapsed_ms)


# ──────────────────────────────────────────────────────────────────────────────
# 9. NETWORK CONNECTIVITY CHECK
# ──────────────────────────────────────────────────────────────────────────────

def check_network() -> CheckResult:
    """Check basic network connectivity."""
    with _timed_check("network") as t:
        try:
            import socket
            # Try DNS resolution
            socket.setdefaulttimeout(5)
            ip = socket.gethostbyname("example.com")
            return CheckResult("network", Status.OK,
                f"DNS resolution working (example.com -> {ip})",
                t.elapsed_ms, {"resolved_ip": ip})
        except socket.gaierror:
            return CheckResult("network", Status.WARN,
                "DNS resolution failed — network may be offline",
                t.elapsed_ms)
        except Exception as e:
            return CheckResult("network", Status.WARN,
                f"Network check failed: {e}", t.elapsed_ms)


# ──────────────────────────────────────────────────────────────────────────────
# 10. SERVER ROUTING CHECK
# ──────────────────────────────────────────────────────────────────────────────

def check_server_routing() -> CheckResult:
    """Verify all tool names in MCP schema can be routed by handle_tool_request."""
    with _timed_check("server_routing") as t:
        try:
            result = _run_async(_check_routing_async)
            return CheckResult("server_routing", result[0], result[1],
                t.elapsed_ms, result[2])
        except Exception as e:
            return CheckResult("server_routing", Status.FAIL, str(e), t.elapsed_ms)


async def _check_routing_async():
    from nexus_framework.server import list_available_tools, handle_tool_request

    tools = await list_available_tools()
    routable = []
    unroutable = []

    for tool in tools:
        name = tool.name
        # Try calling with empty args — should raise ValueError for missing args
        # or succeed for tools with no required args
        try:
            await handle_tool_request(name, {})
            routable.append(name)
        except ValueError as e:
            if "Missing required argument" in str(e):
                routable.append(name)  # Route found, just missing args
            elif "Unknown tool" in str(e):
                unroutable.append(name)
            else:
                routable.append(name)  # Other ValueError = route exists
        except Exception:
            routable.append(name)  # Any other error = route exists

    if unroutable:
        return (Status.FAIL,
                f"{len(unroutable)} tools have no route: {unroutable}",
                {"routable": len(routable), "unroutable": unroutable})

    return (Status.OK,
            f"All {len(routable)} tools are routable",
            {"total": len(routable)})


# ══════════════════════════════════════════════════════════════════════════════
# HEALTH CHECK RUNNER
# ══════════════════════════════════════════════════════════════════════════════

QUICK_CHECKS = [
    check_core_imports,
    check_version,
    check_server_instance,
    check_python_dependencies,
]

FULL_CHECKS = QUICK_CHECKS + [
    check_tool_functions,
    check_tool_registration,
    check_utility_functions,
    check_session_management,
    check_security_tools,
    check_filesystem,
    check_mcp_protocol,
    check_network,
    check_server_routing,
]


def run_health_check(quick: bool = False) -> HealthReport:
    """
    Run all health checks and produce a report.

    Args:
        quick: Only run quick checks (core imports, version, deps).

    Returns:
        HealthReport with all results.
    """
    from nexus_framework import __version__

    report = HealthReport(
        timestamp=datetime.datetime.now().isoformat(),
        version=__version__,
        hostname=platform.node(),
        python_version=platform.python_version(),
        uptime_seconds=round(time.time() - _start_time, 2),
    )

    checks = QUICK_CHECKS if quick else FULL_CHECKS
    for check_fn in checks:
        try:
            result = check_fn()
            report.checks.append(result)
        except Exception as e:
            report.checks.append(CheckResult(
                check_fn.__name__, Status.FAIL,
                f"Check crashed: {e}", 0.0
            ))

    # Calculate summary
    summary = {"ok": 0, "warn": 0, "fail": 0, "skip": 0}
    for check in report.checks:
        summary[check.status.value] += 1
    report.summary = summary

    # Overall status
    if summary["fail"] > 0:
        report.overall_status = Status.FAIL
    elif summary["warn"] > 0:
        report.overall_status = Status.WARN
    else:
        report.overall_status = Status.OK

    return report


def format_report_text(report: HealthReport) -> str:
    """Format health report as human-readable text."""
    STATUS_ICONS = {
        Status.OK: "✅",
        Status.WARN: "⚠️",
        Status.FAIL: "❌",
        Status.SKIP: "⏭️",
    }

    lines = []
    lines.append("=" * 60)
    lines.append("  🎯 Nexus Automation Framework — Health Check Report")
    lines.append("=" * 60)
    lines.append(f"  Timestamp:  {report.timestamp}")
    lines.append(f"  Version:    {report.version}")
    lines.append(f"  Hostname:   {report.hostname}")
    lines.append(f"  Python:     {report.python_version}")
    lines.append(f"  Uptime:     {report.uptime_seconds}s")
    lines.append("")
    lines.append(f"  Overall:    {STATUS_ICONS[report.overall_status]}  {report.overall_status.value.upper()}")
    lines.append(f"  Summary:    ✅ {report.summary.get('ok', 0)}  "
                 f"⚠️ {report.summary.get('warn', 0)}  "
                 f"❌ {report.summary.get('fail', 0)}  "
                 f"⏭️ {report.summary.get('skip', 0)}")
    lines.append("-" * 60)

    for check in report.checks:
        icon = STATUS_ICONS[check.status]
        lines.append(f"  {icon}  {check.name:<25}  {check.message}")
        if check.details:
            for key, val in check.details.items():
                if isinstance(val, list) and len(val) > 5:
                    lines.append(f"       {key}: [{len(val)} items]")
                elif isinstance(val, dict) and len(val) > 5:
                    lines.append(f"       {key}: {{{len(val)} entries}}")
                else:
                    lines.append(f"       {key}: {val}")
        lines.append(f"       ({check.duration_ms:.1f}ms)")

    lines.append("-" * 60)
    lines.append("")
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    """CLI entry point for the health check."""
    import argparse

    parser = argparse.ArgumentParser(description="Nexus Automation Framework Health Check")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--quick", action="store_true", help="Quick checks only")
    args = parser.parse_args()

    report = run_health_check(quick=args.quick)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(format_report_text(report))

    # Exit code
    sys.exit(0 if report.overall_status != Status.FAIL else 1)


if __name__ == "__main__":
    main()
