"""
Nexus Automation Framework - Output Normalization Engine

Provides standardized, structured output format for all MCP tool responses.
Ensures consistent error handling, metadata enrichment, and professional
formatting across every tool in the framework.

Features:
- Structured response envelope (status, data, metadata, errors)
- Automatic tool output parsing (nmap XML, JSON, plain text)
- Error classification and recovery suggestions
- Execution timing and resource tracking
- Session-aware output with evidence tagging
"""

import json
import logging
import re
import time
import traceback
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Union

import mcp.types as types

logger = logging.getLogger("nexus.output")


# ══════════════════════════════════════════════════════════════════════════════
# ENUMS & MODELS
# ══════════════════════════════════════════════════════════════════════════════

class OutputStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    ERROR = "error"
    TIMEOUT = "timeout"
    BLOCKED = "blocked"
    TOOL_MISSING = "tool_missing"

class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ErrorCategory(str, Enum):
    NETWORK = "network"
    AUTH = "authentication"
    PERMISSION = "permission"
    TIMEOUT = "timeout"
    TOOL_NOT_FOUND = "tool_not_found"
    PARSE_ERROR = "parse_error"
    INVALID_INPUT = "invalid_input"
    RATE_LIMITED = "rate_limited"
    TARGET_DOWN = "target_down"
    INTERNAL = "internal"
    UNKNOWN = "unknown"


@dataclass
class Finding:
    """A single security finding from a tool."""
    title: str
    severity: Severity
    description: str
    evidence: str = ""
    remediation: str = ""
    cve_ids: List[str] = field(default_factory=list)
    confidence: float = 1.0
    source_tool: str = ""
    target: str = ""


@dataclass
class NexusError:
    """Structured error with classification and recovery hints."""
    category: ErrorCategory
    message: str
    recovery_hint: str = ""
    raw_error: str = ""
    retryable: bool = False


@dataclass
class ToolMetadata:
    """Execution metadata for a tool invocation."""
    tool_name: str
    started_at: str = ""
    completed_at: str = ""
    duration_ms: float = 0.0
    target: str = ""
    session_id: str = ""
    exit_code: Optional[int] = None
    raw_command: str = ""
    output_files: List[str] = field(default_factory=list)


# ══════════════════════════════════════════════════════════════════════════════
# RESPONSE BUILDER
# ══════════════════════════════════════════════════════════════════════════════

class NexusResponse:
    """
    Standardized response builder for all MCP tool outputs.
    Provides consistent formatting with status, data, metadata, and errors.
    """

    def __init__(self, tool_name: str, target: str = ""):
        self.status: OutputStatus = OutputStatus.SUCCESS
        self.tool_name = tool_name
        self.target = target
        self.title: str = ""
        self.summary: str = ""
        self.findings: List[Finding] = []
        self.raw_output: str = ""
        self.errors: List[NexusError] = []
        self.metadata = ToolMetadata(tool_name=tool_name, target=target)
        self.sections: List[Dict[str, str]] = []
        self._start_time = time.time()
        self.metadata.started_at = datetime.now(timezone.utc).isoformat()

    def set_title(self, title: str) -> "NexusResponse":
        self.title = title
        return self

    def set_summary(self, summary: str) -> "NexusResponse":
        self.summary = summary
        return self

    def add_section(self, heading: str, content: str) -> "NexusResponse":
        self.sections.append({"heading": heading, "content": content})
        return self

    def add_finding(self, finding: Finding) -> "NexusResponse":
        finding.source_tool = finding.source_tool or self.tool_name
        finding.target = finding.target or self.target
        self.findings.append(finding)
        return self

    def set_raw_output(self, output: str, truncate_at: int = 50000) -> "NexusResponse":
        if len(output) > truncate_at:
            self.raw_output = output[:truncate_at] + f"\n\n[TRUNCATED — {len(output)} total chars]"
        else:
            self.raw_output = output
        return self

    def add_error(self, error: NexusError) -> "NexusResponse":
        self.errors.append(error)
        if self.status == OutputStatus.SUCCESS:
            self.status = OutputStatus.ERROR
        return self

    def set_status(self, status: OutputStatus) -> "NexusResponse":
        self.status = status
        return self

    def set_exit_code(self, code: int) -> "NexusResponse":
        self.metadata.exit_code = code
        return self

    def set_command(self, cmd: str) -> "NexusResponse":
        self.metadata.raw_command = cmd
        return self

    def add_output_file(self, path: str) -> "NexusResponse":
        self.metadata.output_files.append(path)
        return self

    def finalize(self) -> "NexusResponse":
        """Finalize timing and metadata."""
        self.metadata.completed_at = datetime.now(timezone.utc).isoformat()
        self.metadata.duration_ms = round((time.time() - self._start_time) * 1000, 2)
        return self

    # ──────────────────────────────────────────────────────────────────────
    # RENDERING
    # ──────────────────────────────────────────────────────────────────────

    def to_markdown(self) -> str:
        """Render response as professional Markdown."""
        self.finalize()
        parts = []

        # Status icon
        icon = {
            OutputStatus.SUCCESS: "✅",
            OutputStatus.PARTIAL: "⚠️",
            OutputStatus.ERROR: "❌",
            OutputStatus.TIMEOUT: "⏱️",
            OutputStatus.BLOCKED: "🚫",
            OutputStatus.TOOL_MISSING: "🔧",
        }.get(self.status, "ℹ️")

        # Header
        title = self.title or f"{self.tool_name}"
        parts.append(f"{icon} **{title}**")

        if self.target:
            parts.append(f"**Target:** `{self.target}`")

        if self.summary:
            parts.append(f"\n{self.summary}")

        # Errors
        if self.errors:
            parts.append("\n**Errors:**")
            for err in self.errors:
                parts.append(f"- `[{err.category.value}]` {err.message}")
                if err.recovery_hint:
                    parts.append(f"  💡 *{err.recovery_hint}*")

        # Sections
        for section in self.sections:
            parts.append(f"\n### {section['heading']}")
            parts.append(section["content"])

        # Findings
        if self.findings:
            parts.append(f"\n### Findings ({len(self.findings)})")
            for i, f in enumerate(self.findings, 1):
                sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(f.severity.value, "⚪")
                parts.append(f"{i}. {sev_icon} **[{f.severity.value.upper()}]** {f.title}")
                if f.description:
                    parts.append(f"   {f.description}")
                if f.evidence:
                    parts.append(f"   📋 Evidence: `{f.evidence[:200]}`")
                if f.cve_ids:
                    parts.append(f"   🔗 CVEs: {', '.join(f.cve_ids)}")
                if f.remediation:
                    parts.append(f"   🛡️ Fix: {f.remediation}")

        # Raw output
        if self.raw_output:
            preview = self.raw_output[:2000]
            if len(self.raw_output) > 2000:
                preview += f"\n\n... [{len(self.raw_output)} total chars]"
            parts.append(f"\n### Output\n```\n{preview}\n```")

        # Metadata footer
        meta_items = []
        if self.metadata.duration_ms:
            meta_items.append(f"⏱ {self.metadata.duration_ms:.0f}ms")
        if self.metadata.exit_code is not None:
            meta_items.append(f"Exit: {self.metadata.exit_code}")
        if self.metadata.output_files:
            meta_items.append(f"Files: {', '.join(self.metadata.output_files)}")
        if meta_items:
            parts.append(f"\n---\n*{' | '.join(meta_items)}*")

        return "\n".join(parts)

    def to_mcp(self) -> List[types.TextContent]:
        """Convert to MCP TextContent response."""
        return [types.TextContent(type="text", text=self.to_markdown())]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (for JSON serialization)."""
        self.finalize()
        return {
            "status": self.status.value,
            "tool": self.tool_name,
            "target": self.target,
            "title": self.title,
            "summary": self.summary,
            "findings": [asdict(f) for f in self.findings],
            "errors": [asdict(e) for e in self.errors],
            "sections": self.sections,
            "metadata": asdict(self.metadata),
        }


# ══════════════════════════════════════════════════════════════════════════════
# ERROR CLASSIFIER
# ══════════════════════════════════════════════════════════════════════════════

def classify_error(error: Exception, command: str = "", output: str = "") -> NexusError:
    """
    Classify an exception or tool error into a structured NexusError
    with recovery hints.
    """
    msg = str(error)
    combined = f"{msg} {output}".lower()

    # Network errors
    if any(k in combined for k in ["connection refused", "no route to host", "network unreachable", "name resolution"]):
        return NexusError(
            category=ErrorCategory.NETWORK,
            message=f"Network error: {msg}",
            recovery_hint="Check target is reachable. Verify DNS resolution and firewall rules.",
            raw_error=msg,
            retryable=True
        )

    # Target down
    if any(k in combined for k in ["host seems down", "no response", "timed out", "connection timed out"]):
        return NexusError(
            category=ErrorCategory.TARGET_DOWN,
            message=f"Target unreachable: {msg}",
            recovery_hint="Target may be offline or filtering probes. Try -Pn flag for nmap.",
            raw_error=msg,
            retryable=True
        )

    # Timeout
    if any(k in combined for k in ["timeout", "timed out", "deadline exceeded"]):
        return NexusError(
            category=ErrorCategory.TIMEOUT,
            message=f"Operation timed out: {msg}",
            recovery_hint="Increase timeout, reduce scan scope, or run in background mode.",
            raw_error=msg,
            retryable=True
        )

    # Authentication
    if any(k in combined for k in ["authentication failed", "access denied", "login failed", "invalid credentials"]):
        return NexusError(
            category=ErrorCategory.AUTH,
            message=f"Authentication failed: {msg}",
            recovery_hint="Verify credentials. Try alternate auth methods (hash, kerberos, key).",
            raw_error=msg,
            retryable=False
        )

    # Permission
    if any(k in combined for k in ["permission denied", "operation not permitted", "requires root"]):
        return NexusError(
            category=ErrorCategory.PERMISSION,
            message=f"Permission denied: {msg}",
            recovery_hint="Use sudo or run the tool with elevated privileges.",
            raw_error=msg,
            retryable=False
        )

    # Rate limited
    if any(k in combined for k in ["rate limit", "too many requests", "429", "throttl"]):
        return NexusError(
            category=ErrorCategory.RATE_LIMITED,
            message=f"Rate limited: {msg}",
            recovery_hint="Reduce scan speed, add delays, or use proxy rotation.",
            raw_error=msg,
            retryable=True
        )

    # Tool not found
    if any(k in combined for k in ["command not found", "no such file", "not installed"]):
        tool_match = re.search(r"(\w+):\s*(command not found|not found)", combined)
        tool_name = tool_match.group(1) if tool_match else "unknown"
        return NexusError(
            category=ErrorCategory.TOOL_NOT_FOUND,
            message=f"Tool not found: {tool_name}",
            recovery_hint=f"Install with: apt-get install {tool_name} or check PATH.",
            raw_error=msg,
            retryable=False
        )

    # Invalid input
    if any(k in combined for k in ["invalid", "malformed", "bad argument", "usage:"]):
        return NexusError(
            category=ErrorCategory.INVALID_INPUT,
            message=f"Invalid input: {msg}",
            recovery_hint="Check command syntax and arguments.",
            raw_error=msg,
            retryable=False
        )

    # Default
    return NexusError(
        category=ErrorCategory.UNKNOWN,
        message=msg,
        recovery_hint="Check logs for details. Retry or try alternate approach.",
        raw_error=traceback.format_exc() if isinstance(error, Exception) else msg,
        retryable=True
    )


# ══════════════════════════════════════════════════════════════════════════════
# OUTPUT PARSERS
# ══════════════════════════════════════════════════════════════════════════════

def parse_nmap_output(raw: str) -> List[Finding]:
    """Parse nmap text output into structured findings."""
    findings = []

    # Parse open ports
    port_pattern = re.compile(r"(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)\s*(.*)")
    for match in port_pattern.finditer(raw):
        port, proto, state, service, version = match.groups()
        findings.append(Finding(
            title=f"Port {port}/{proto} {state} — {service}",
            severity=Severity.INFO if state == "open" else Severity.LOW,
            description=f"Service: {service} {version.strip()}",
            evidence=match.group(0),
            source_tool="nmap"
        ))

    # Parse vulnerabilities from NSE scripts
    vuln_pattern = re.compile(r"\|\s+(CVE-\d{4}-\d+).*", re.IGNORECASE)
    for match in vuln_pattern.finditer(raw):
        cve = match.group(1).upper()
        findings.append(Finding(
            title=f"Vulnerability: {cve}",
            severity=Severity.HIGH,
            description=f"NSE script detected {cve}",
            evidence=match.group(0),
            cve_ids=[cve],
            source_tool="nmap"
        ))

    # Parse OS detection
    os_pattern = re.compile(r"OS details:\s*(.*)")
    for match in os_pattern.finditer(raw):
        findings.append(Finding(
            title=f"OS Detection: {match.group(1)}",
            severity=Severity.INFO,
            description=match.group(1),
            source_tool="nmap"
        ))

    return findings


def parse_nikto_output(raw: str) -> List[Finding]:
    """Parse nikto output into structured findings."""
    findings = []
    line_pattern = re.compile(r"\+\s+(OSVDB-\d+|OSV-\d+)?:?\s*(.*)")

    for match in line_pattern.finditer(raw):
        osvdb, desc = match.groups()
        if not desc or len(desc) < 10:
            continue
        severity = Severity.MEDIUM
        if any(k in desc.lower() for k in ["xss", "injection", "rce", "remote code"]):
            severity = Severity.HIGH
        elif any(k in desc.lower() for k in ["disclosure", "information", "version"]):
            severity = Severity.LOW

        findings.append(Finding(
            title=desc[:100],
            severity=severity,
            description=desc,
            evidence=match.group(0),
            source_tool="nikto"
        ))

    return findings


def parse_sqlmap_output(raw: str) -> List[Finding]:
    """Parse sqlmap output into structured findings."""
    findings = []

    if "is vulnerable" in raw.lower() or "injection" in raw.lower():
        # Extract injection type
        inj_pattern = re.compile(r"Type:\s*(.*?)(?:\n|$)")
        for match in inj_pattern.finditer(raw):
            findings.append(Finding(
                title=f"SQL Injection: {match.group(1)}",
                severity=Severity.CRITICAL,
                description=f"SQL injection vulnerability detected: {match.group(1)}",
                evidence=match.group(0),
                remediation="Use parameterized queries and input validation",
                source_tool="sqlmap"
            ))

    # Database detected
    db_pattern = re.compile(r"back-end DBMS:\s*(.*)")
    for match in db_pattern.finditer(raw):
        findings.append(Finding(
            title=f"Database: {match.group(1)}",
            severity=Severity.INFO,
            description=f"Backend database identified: {match.group(1)}",
            source_tool="sqlmap"
        ))

    return findings


def parse_nuclei_output(raw: str) -> List[Finding]:
    """Parse nuclei JSON/text output into structured findings."""
    findings = []

    for line in raw.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        # Try JSON line format
        try:
            data = json.loads(line)
            sev_map = {"info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH, "critical": Severity.CRITICAL}
            findings.append(Finding(
                title=data.get("info", {}).get("name", data.get("template-id", "Unknown")),
                severity=sev_map.get(data.get("info", {}).get("severity", "info"), Severity.INFO),
                description=data.get("info", {}).get("description", ""),
                evidence=data.get("matched-at", ""),
                cve_ids=[r for r in data.get("info", {}).get("reference", []) if "CVE-" in r],
                source_tool="nuclei",
                target=data.get("host", "")
            ))
            continue
        except (json.JSONDecodeError, AttributeError):
            pass

        # Text format: [severity] [template-id] [protocol] url
        text_pattern = re.compile(r"\[(\w+)\]\s+\[([^\]]+)\]\s+\[(\w+)\]\s+(.*)")
        match = text_pattern.match(line)
        if match:
            sev, template, proto, url = match.groups()
            sev_map = {"info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH, "critical": Severity.CRITICAL}
            findings.append(Finding(
                title=template,
                severity=sev_map.get(sev.lower(), Severity.INFO),
                description=f"{template} detected via {proto}",
                evidence=url,
                source_tool="nuclei"
            ))

    return findings


def parse_generic_output(raw: str, tool_name: str = "unknown") -> List[Finding]:
    """
    Generic output parser — extracts CVEs, IPs, common patterns
    from arbitrary tool output.
    """
    findings = []

    # CVE extraction
    cves = set(re.findall(r"CVE-\d{4}-\d{4,}", raw, re.IGNORECASE))
    for cve in cves:
        findings.append(Finding(
            title=f"CVE Reference: {cve.upper()}",
            severity=Severity.MEDIUM,
            description=f"CVE {cve.upper()} referenced in output",
            cve_ids=[cve.upper()],
            source_tool=tool_name
        ))

    # Credential patterns
    cred_patterns = [
        (r"password\s*[:=]\s*(\S+)", "Exposed password"),
        (r"token\s*[:=]\s*(\S+)", "Exposed token"),
        (r"api[_-]?key\s*[:=]\s*(\S+)", "Exposed API key"),
    ]
    for pattern, desc in cred_patterns:
        for match in re.finditer(pattern, raw, re.IGNORECASE):
            findings.append(Finding(
                title=f"Credential Exposure: {desc}",
                severity=Severity.HIGH,
                description=desc,
                evidence=match.group(0)[:100],
                remediation="Rotate exposed credentials immediately",
                source_tool=tool_name
            ))

    return findings


# Map tool names to their parsers
TOOL_PARSERS = {
    "nmap": parse_nmap_output,
    "nikto": parse_nikto_output,
    "sqlmap": parse_sqlmap_output,
    "nuclei": parse_nuclei_output,
}

def auto_parse(raw: str, tool_name: str) -> List[Finding]:
    """Auto-detect and parse tool output."""
    parser = TOOL_PARSERS.get(tool_name)
    findings = []
    if parser:
        findings = parser(raw)
    # Always run generic parser for CVEs/creds
    findings.extend(parse_generic_output(raw, tool_name))
    return findings
