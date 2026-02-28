"""
Nexus Automation Framework - Input Validators

Military-grade input validation and sanitization for MCP tool arguments.
Prevents injection attacks, validates formats, and sanitizes dangerous inputs.
"""

import re
import ipaddress
import shlex
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse
from dataclasses import dataclass

from nexus_framework.exceptions import (
    InvalidArgumentError, InputSanitizationError, CommandBlockedError
)
from nexus_framework.config import CONTAINER_ESCAPE_SIGNATURES, EXFILTRATION_SIGNATURES


# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

MAX_COMMAND_LENGTH = 10000
MAX_ARGUMENT_LENGTH = 5000
MAX_URL_LENGTH = 4096
MAX_PATH_LENGTH = 1024
MAX_FILENAME_LENGTH = 255

# Dangerous shell metacharacters for injection
SHELL_INJECTION_PATTERNS = [
    r";\s*rm\s+-rf",
    r"\$\(.*\)",
    r"`.*`",
    r"\|\s*bash",
    r"\|\s*sh\s",
    r">\s*/dev/sd",
    r">\s*/etc/",
    r">\s*/proc/",
    r">\s*/sys/",
    r"mkfs\.\w+",
    r"dd\s+if=.*of=/dev/",
    r":(){ :|:& };:",  # fork bomb
    r"\beval\b.*\$",
    r"python.*-c\s*['\"].*__import__",
]

# Path traversal patterns
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\%2[fF]",
    r"\.\.\%252[fF]",
    r"\.\.\\",
    r"%2e%2e",
    r"%252e%252e",
]


# ══════════════════════════════════════════════════════════════════════════════
# VALIDATORS
# ══════════════════════════════════════════════════════════════════════════════

def validate_required(arguments: Dict[str, Any], tool_name: str, *required_args: str):
    """Validate that all required arguments are present."""
    for arg in required_args:
        if arg not in arguments or arguments[arg] is None:
            raise InvalidArgumentError(
                tool_name=tool_name,
                argument=arg,
                reason="missing required argument"
            )
        if isinstance(arguments[arg], str) and not arguments[arg].strip():
            raise InvalidArgumentError(
                tool_name=tool_name,
                argument=arg,
                reason="argument cannot be empty"
            )


def validate_type(value: Any, expected_type: type, field_name: str, tool_name: str = ""):
    """Validate argument type."""
    if not isinstance(value, expected_type):
        raise InvalidArgumentError(
            tool_name=tool_name,
            argument=field_name,
            reason=f"expected {expected_type.__name__}, got {type(value).__name__}"
        )


def validate_enum(value: str, allowed_values: List[str], field_name: str, tool_name: str = ""):
    """Validate value is in allowed set."""
    if value not in allowed_values:
        raise InvalidArgumentError(
            tool_name=tool_name,
            argument=field_name,
            reason=f"must be one of: {', '.join(allowed_values)}"
        )


def validate_range(value: Union[int, float], min_val: Union[int, float],
                   max_val: Union[int, float], field_name: str, tool_name: str = ""):
    """Validate numeric value is within range."""
    if value < min_val or value > max_val:
        raise InvalidArgumentError(
            tool_name=tool_name,
            argument=field_name,
            reason=f"must be between {min_val} and {max_val}, got {value}"
        )


def validate_ip(ip_str: str, tool_name: str = "") -> str:
    """Validate and normalize an IP address or CIDR."""
    try:
        # CIDR range
        if "/" in ip_str:
            net = ipaddress.ip_network(ip_str, strict=False)
            return str(net)
        # Single IP
        addr = ipaddress.ip_address(ip_str)
        return str(addr)
    except ValueError:
        raise InvalidArgumentError(
            tool_name=tool_name,
            argument="ip/target",
            reason=f"invalid IP address or CIDR: {ip_str}"
        )


def validate_url(url: str, tool_name: str = "", require_scheme: bool = True) -> str:
    """Validate and normalize a URL."""
    if len(url) > MAX_URL_LENGTH:
        raise InvalidArgumentError(
            tool_name=tool_name,
            argument="url",
            reason=f"URL too long (max {MAX_URL_LENGTH} chars)"
        )

    parsed = urlparse(url)

    if require_scheme and parsed.scheme not in ("http", "https", "ftp", "ftps"):
        # Try adding http://
        if not parsed.scheme:
            url = f"http://{url}"
            parsed = urlparse(url)
        else:
            raise InvalidArgumentError(
                tool_name=tool_name,
                argument="url",
                reason=f"invalid URL scheme: {parsed.scheme}"
            )

    if not parsed.hostname:
        raise InvalidArgumentError(
            tool_name=tool_name,
            argument="url",
            reason="URL must have a hostname"
        )

    # Check for SSRF against internal networks (warning only)
    try:
        host_ip = ipaddress.ip_address(parsed.hostname)
        if host_ip.is_private or host_ip.is_loopback:
            pass  # Allow in pentest context
    except ValueError:
        pass  # Hostname is a domain

    return url


def validate_port(port: int, tool_name: str = "") -> int:
    """Validate a port number."""
    if not isinstance(port, int) or port < 1 or port > 65535:
        raise InvalidArgumentError(
            tool_name=tool_name,
            argument="port",
            reason=f"port must be between 1 and 65535, got {port}"
        )
    return port


def validate_filepath(path: str, tool_name: str = "") -> str:
    """Validate a file path (basic safety checks)."""
    if len(path) > MAX_PATH_LENGTH:
        raise InvalidArgumentError(
            tool_name=tool_name,
            argument="filepath",
            reason=f"path too long (max {MAX_PATH_LENGTH} chars)"
        )

    # Check for null bytes
    if "\x00" in path:
        raise InputSanitizationError(
            field="filepath",
            reason="null byte detected in path"
        )

    return path


def validate_target(target: str, tool_name: str = "") -> str:
    """Validate a target (IP, CIDR, hostname, or URL)."""
    if not target or not target.strip():
        raise InvalidArgumentError(
            tool_name=tool_name,
            argument="target",
            reason="target cannot be empty"
        )

    target = target.strip()

    if len(target) > MAX_ARGUMENT_LENGTH:
        raise InvalidArgumentError(
            tool_name=tool_name,
            argument="target",
            reason="target too long"
        )

    # Check for shell injection in target
    for pattern in SHELL_INJECTION_PATTERNS:
        if re.search(pattern, target, re.IGNORECASE):
            raise InputSanitizationError(
                field="target",
                reason="potentially dangerous characters detected"
            )

    return target


# ══════════════════════════════════════════════════════════════════════════════
# COMMAND SECURITY
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class CommandValidationResult:
    """Result of command validation."""
    safe: bool
    risk_level: str  # low, medium, high, critical
    warnings: List[str]
    blocked_reason: Optional[str] = None
    escape_vector: Optional[str] = None
    exfil_technique: Optional[str] = None


def validate_command(command: str, strict_mode: bool = False) -> CommandValidationResult:
    """
    Validate a command for container security.
    In pentest mode, most commands are allowed but escape attempts are blocked.
    """
    warnings = []
    risk = "low"

    if not command or not command.strip():
        return CommandValidationResult(
            safe=False, risk_level="low", warnings=[],
            blocked_reason="empty command"
        )

    if len(command) > MAX_COMMAND_LENGTH:
        return CommandValidationResult(
            safe=False, risk_level="medium", warnings=[],
            blocked_reason=f"command too long ({len(command)} > {MAX_COMMAND_LENGTH})"
        )

    # Check for container escape attempts (ALWAYS blocked)
    for sig in CONTAINER_ESCAPE_SIGNATURES:
        if re.search(sig["pattern"], command, re.IGNORECASE):
            return CommandValidationResult(
                safe=False,
                risk_level="critical",
                warnings=[f"Container escape attempt: {sig['vector']}"],
                blocked_reason=f"Container escape vector detected: {sig['vector']}",
                escape_vector=sig["vector"]
            )

    # Check for data exfiltration patterns (warn but allow in pentest mode)
    for sig in EXFILTRATION_SIGNATURES:
        if re.search(sig["pattern"], command, re.IGNORECASE):
            warnings.append(f"Potential exfiltration: {sig['technique']}")
            risk = max(risk, sig["severity"], key=lambda x: {
                "low": 0, "medium": 1, "high": 2, "critical": 3
            }.get(x, 0))

    # Check for self-destructive commands
    dangerous_self_patterns = [
        (r"rm\s+-rf\s+/\s*$", "Destructive: rm -rf /"),
        (r"rm\s+-rf\s+/\*", "Destructive: rm -rf /*"),
        (r":\(\)\s*\{", "Fork bomb detected"),
        (r"dd\s+if=/dev/zero\s+of=/dev/sd", "Disk wipe attempt"),
        (r"mkfs\.\w+\s+/dev/sd", "Filesystem format attempt"),
    ]

    for pattern, desc in dangerous_self_patterns:
        if re.search(pattern, command, re.IGNORECASE):
            return CommandValidationResult(
                safe=False, risk_level="critical", warnings=[desc],
                blocked_reason=f"Self-destructive command blocked: {desc}"
            )

    if strict_mode:
        # Additional checks in strict mode
        if ";" in command or "&&" in command or "||" in command:
            warnings.append("Command chaining detected")
            risk = "medium"

    return CommandValidationResult(
        safe=True, risk_level=risk, warnings=warnings
    )


# ══════════════════════════════════════════════════════════════════════════════
# SANITIZERS
# ══════════════════════════════════════════════════════════════════════════════

def sanitize_output(output: str, max_length: int = 500000) -> str:
    """Sanitize tool output, removing sensitive data and limiting length."""
    if not output:
        return ""

    # Truncate
    if len(output) > max_length:
        output = output[:max_length] + f"\n\n[TRUNCATED - {len(output)} total bytes]"

    # Remove ANSI escape codes
    output = re.sub(r'\x1b\[[0-9;]*m', '', output)
    output = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', output)

    # Remove null bytes
    output = output.replace('\x00', '')

    return output


def sanitize_credentials(text: str, password: Optional[str] = None,
                         hashes: Optional[str] = None) -> str:
    """Mask credentials in output text."""
    if password and len(password) > 2:
        text = text.replace(password, "****")
    if hashes and len(hashes) > 2:
        text = text.replace(hashes, "****:****")

    # Generic credential patterns
    patterns = [
        (r'(password["\s:=]+)\S+', r'\1****'),
        (r'(passwd["\s:=]+)\S+', r'\1****'),
        (r'(secret["\s:=]+)\S+', r'\1****'),
        (r'(token["\s:=]+)\S+', r'\1****'),
        (r'(api[_-]?key["\s:=]+)\S+', r'\1****'),
    ]
    for pattern, replacement in patterns:
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)

    return text


def sanitize_filename(filename: str) -> str:
    """Sanitize a filename for safe filesystem use."""
    # Remove path separators
    filename = filename.replace("/", "_").replace("\\", "_")
    # Remove special chars
    filename = re.sub(r'[<>:"|?*\x00-\x1f]', '_', filename)
    # Limit length
    if len(filename) > MAX_FILENAME_LENGTH:
        ext = filename.rsplit(".", 1)[-1] if "." in filename else ""
        filename = filename[:MAX_FILENAME_LENGTH - len(ext) - 1] + "." + ext
    return filename


# ══════════════════════════════════════════════════════════════════════════════
# ARGUMENT EXTRACTORS
# ══════════════════════════════════════════════════════════════════════════════

def extract_str(arguments: Dict[str, Any], key: str, default: str = "") -> str:
    """Extract and validate a string argument."""
    value = arguments.get(key, default)
    if value is None:
        return default
    if not isinstance(value, str):
        value = str(value)
    return value.strip()


def extract_int(arguments: Dict[str, Any], key: str, default: int = 0,
                min_val: int = None, max_val: int = None) -> int:
    """Extract and validate an integer argument."""
    value = arguments.get(key, default)
    try:
        value = int(value)
    except (TypeError, ValueError):
        return default
    if min_val is not None:
        value = max(value, min_val)
    if max_val is not None:
        value = min(value, max_val)
    return value


def extract_float(arguments: Dict[str, Any], key: str, default: float = 0.0,
                  min_val: float = None, max_val: float = None) -> float:
    """Extract and validate a float argument."""
    value = arguments.get(key, default)
    try:
        value = float(value)
    except (TypeError, ValueError):
        return default
    if min_val is not None:
        value = max(value, min_val)
    if max_val is not None:
        value = min(value, max_val)
    return value


def extract_bool(arguments: Dict[str, Any], key: str, default: bool = False) -> bool:
    """Extract and validate a boolean argument."""
    value = arguments.get(key, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ("true", "1", "yes", "on")
    return bool(value)


def extract_list(arguments: Dict[str, Any], key: str, default: List = None) -> List:
    """Extract and validate a list argument."""
    value = arguments.get(key, default or [])
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return default or []
