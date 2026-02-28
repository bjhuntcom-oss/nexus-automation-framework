"""
Nexus Automation Framework - Exception Hierarchy

Military-grade exception taxonomy for structured error handling.
Every failure mode has a dedicated exception class with context,
recovery hints, and severity classification.
"""

from enum import Enum
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime


# ══════════════════════════════════════════════════════════════════════════════
# SEVERITY CLASSIFICATION
# ══════════════════════════════════════════════════════════════════════════════

class ExceptionSeverity(Enum):
    """Severity levels for exceptions."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    FATAL = "fatal"


class RecoveryAction(Enum):
    """Recommended recovery actions."""
    RETRY = "retry"
    RETRY_WITH_BACKOFF = "retry_with_backoff"
    FALLBACK = "fallback"
    SKIP = "skip"
    ABORT = "abort"
    ESCALATE = "escalate"
    RECONFIGURE = "reconfigure"
    MANUAL_INTERVENTION = "manual_intervention"


# ══════════════════════════════════════════════════════════════════════════════
# BASE EXCEPTION
# ══════════════════════════════════════════════════════════════════════════════

class NexusError(Exception):
    """
    Base exception for all Nexus Automation Framework errors.
    Provides structured context, severity, and recovery guidance.
    """

    def __init__(
        self,
        message: str,
        severity: ExceptionSeverity = ExceptionSeverity.ERROR,
        recovery: RecoveryAction = RecoveryAction.ABORT,
        recovery_hint: str = "",
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
        retryable: bool = False,
        error_code: str = "NEXUS-0000",
    ):
        super().__init__(message)
        self.severity = severity
        self.recovery = recovery
        self.recovery_hint = recovery_hint
        self.context = context or {}
        self.cause = cause
        self.retryable = retryable
        self.error_code = error_code
        self.timestamp = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize exception for logging and MCP responses."""
        return {
            "error_code": self.error_code,
            "severity": self.severity.value,
            "message": str(self),
            "recovery_action": self.recovery.value,
            "recovery_hint": self.recovery_hint,
            "retryable": self.retryable,
            "context": self.context,
            "cause": str(self.cause) if self.cause else None,
            "timestamp": self.timestamp,
            "exception_type": self.__class__.__name__,
        }

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} [{self.error_code}] "
            f"severity={self.severity.value} "
            f"message='{str(self)[:80]}'>"
        )


# ══════════════════════════════════════════════════════════════════════════════
# SECURITY EXCEPTIONS
# ══════════════════════════════════════════════════════════════════════════════

class SecurityError(NexusError):
    """Base class for security-related errors."""

    def __init__(self, message: str, **kwargs):
        kwargs.setdefault("severity", ExceptionSeverity.CRITICAL)
        kwargs.setdefault("error_code", "NEXUS-SEC-0000")
        super().__init__(message, **kwargs)


class KillSwitchActivated(SecurityError):
    """Kill switch has been activated — all operations blocked."""

    def __init__(self, reason: str = "Kill switch activated", **kwargs):
        kwargs.setdefault("error_code", "NEXUS-SEC-0001")
        kwargs.setdefault("severity", ExceptionSeverity.FATAL)
        kwargs.setdefault("recovery", RecoveryAction.MANUAL_INTERVENTION)
        kwargs.setdefault("recovery_hint", "Container is locked down. Manual reset required.")
        super().__init__(f"KILL SWITCH: {reason}", **kwargs)


class ContainerEscapeAttempt(SecurityError):
    """Detected attempt to escape the container."""

    def __init__(self, vector: str, command: str = "", **kwargs):
        kwargs.setdefault("error_code", "NEXUS-SEC-0002")
        kwargs.setdefault("severity", ExceptionSeverity.FATAL)
        kwargs.setdefault("recovery", RecoveryAction.ABORT)
        kwargs.setdefault("recovery_hint", "Container escape attempt blocked. Kill switch may activate.")
        kwargs.setdefault("context", {"vector": vector, "command": command})
        super().__init__(f"Container escape attempt detected via {vector}", **kwargs)


class UnauthorizedConnectionError(SecurityError):
    """Unauthorized network connection detected."""

    def __init__(self, remote_ip: str, remote_port: int, **kwargs):
        kwargs.setdefault("error_code", "NEXUS-SEC-0003")
        kwargs.setdefault("recovery", RecoveryAction.ABORT)
        kwargs.setdefault("context", {"remote_ip": remote_ip, "remote_port": remote_port})
        super().__init__(
            f"Unauthorized connection from {remote_ip}:{remote_port}", **kwargs
        )


class IntrusionDetected(SecurityError):
    """Intrusion attempt detected on the container."""

    def __init__(self, description: str, indicators: Optional[List[str]] = None, **kwargs):
        kwargs.setdefault("error_code", "NEXUS-SEC-0004")
        kwargs.setdefault("severity", ExceptionSeverity.FATAL)
        kwargs.setdefault("context", {"indicators": indicators or []})
        super().__init__(f"Intrusion detected: {description}", **kwargs)


class CommandBlockedError(SecurityError):
    """Command blocked by security policy."""

    def __init__(self, command: str, reason: str = "", **kwargs):
        kwargs.setdefault("error_code", "NEXUS-SEC-0005")
        kwargs.setdefault("severity", ExceptionSeverity.WARNING)
        kwargs.setdefault("recovery", RecoveryAction.SKIP)
        kwargs.setdefault("context", {"command": command[:200], "reason": reason})
        super().__init__(f"Command blocked: {reason}", **kwargs)


class AuditChainCorrupted(SecurityError):
    """Audit log chain integrity verification failed."""

    def __init__(self, details: str = "", **kwargs):
        kwargs.setdefault("error_code", "NEXUS-SEC-0006")
        kwargs.setdefault("severity", ExceptionSeverity.CRITICAL)
        kwargs.setdefault("recovery_hint", "Audit log may have been tampered with.")
        super().__init__(f"Audit chain corrupted: {details}", **kwargs)


class VPNDisconnected(SecurityError):
    """VPN connection lost while in VPN-only mode."""

    def __init__(self, **kwargs):
        kwargs.setdefault("error_code", "NEXUS-SEC-0007")
        kwargs.setdefault("recovery", RecoveryAction.ABORT)
        kwargs.setdefault("recovery_hint", "Reconnect VPN before continuing operations.")
        super().__init__("VPN connection lost — operations suspended", **kwargs)


# ══════════════════════════════════════════════════════════════════════════════
# MCP / PROTOCOL EXCEPTIONS
# ══════════════════════════════════════════════════════════════════════════════

class MCPError(NexusError):
    """Base class for MCP protocol errors."""

    def __init__(self, message: str, **kwargs):
        kwargs.setdefault("error_code", "NEXUS-MCP-0000")
        super().__init__(message, **kwargs)


class ToolNotFoundError(MCPError):
    """Requested MCP tool does not exist."""

    def __init__(self, tool_name: str, **kwargs):
        kwargs.setdefault("error_code", "NEXUS-MCP-0001")
        kwargs.setdefault("recovery", RecoveryAction.SKIP)
        kwargs.setdefault("context", {"tool_name": tool_name})
        super().__init__(f"Unknown tool: {tool_name}", **kwargs)


class InvalidArgumentError(MCPError):
    """Invalid or missing argument in MCP tool call."""

    def __init__(self, tool_name: str, argument: str, reason: str = "missing", **kwargs):
        kwargs.setdefault("error_code", "NEXUS-MCP-0002")
        kwargs.setdefault("recovery", RecoveryAction.SKIP)
        kwargs.setdefault("context", {"tool_name": tool_name, "argument": argument, "reason": reason})
        super().__init__(
            f"Invalid argument '{argument}' for tool '{tool_name}': {reason}", **kwargs
        )


class RateLimitExceeded(MCPError):
    """MCP rate limit exceeded."""

    def __init__(self, tool_name: str = "", window_seconds: int = 60, **kwargs):
        kwargs.setdefault("error_code", "NEXUS-MCP-0003")
        kwargs.setdefault("recovery", RecoveryAction.RETRY_WITH_BACKOFF)
        kwargs.setdefault("retryable", True)
        kwargs.setdefault("recovery_hint", f"Wait {window_seconds}s before retrying.")
        super().__init__(f"Rate limit exceeded for {tool_name or 'global'}", **kwargs)


class ToolTimeoutError(MCPError):
    """Tool execution timed out."""

    def __init__(self, tool_name: str, timeout_seconds: int, **kwargs):
        kwargs.setdefault("error_code", "NEXUS-MCP-0004")
        kwargs.setdefault("recovery", RecoveryAction.RETRY)
        kwargs.setdefault("retryable", True)
        kwargs.setdefault("context", {"tool_name": tool_name, "timeout": timeout_seconds})
        super().__init__(f"Tool '{tool_name}' timed out after {timeout_seconds}s", **kwargs)


# ══════════════════════════════════════════════════════════════════════════════
# EXECUTION EXCEPTIONS
# ══════════════════════════════════════════════════════════════════════════════

class ExecutionError(NexusError):
    """Base class for command/tool execution errors."""

    def __init__(self, message: str, **kwargs):
        kwargs.setdefault("error_code", "NEXUS-EXEC-0000")
        super().__init__(message, **kwargs)


class CommandExecutionError(ExecutionError):
    """Shell command execution failed."""

    def __init__(self, command: str, exit_code: int = -1, stderr: str = "", **kwargs):
        kwargs.setdefault("error_code", "NEXUS-EXEC-0001")
        kwargs.setdefault("context", {
            "command": command[:300],
            "exit_code": exit_code,
            "stderr": stderr[:500]
        })
        super().__init__(f"Command failed (exit {exit_code}): {command[:100]}", **kwargs)


class ToolMissingError(ExecutionError):
    """Required external tool not installed."""

    def __init__(self, tool_name: str, install_hint: str = "", **kwargs):
        kwargs.setdefault("error_code", "NEXUS-EXEC-0002")
        kwargs.setdefault("recovery", RecoveryAction.FALLBACK)
        kwargs.setdefault("recovery_hint", install_hint or f"Install {tool_name}: apt-get install {tool_name}")
        super().__init__(f"Tool not found: {tool_name}", **kwargs)


class ResourceExhaustedError(ExecutionError):
    """System resources exhausted (CPU, memory, disk)."""

    def __init__(self, resource: str, current_usage: str = "", **kwargs):
        kwargs.setdefault("error_code", "NEXUS-EXEC-0003")
        kwargs.setdefault("severity", ExceptionSeverity.CRITICAL)
        kwargs.setdefault("recovery", RecoveryAction.RETRY_WITH_BACKOFF)
        kwargs.setdefault("retryable", True)
        super().__init__(f"Resource exhausted: {resource} ({current_usage})", **kwargs)


# ══════════════════════════════════════════════════════════════════════════════
# DATABASE EXCEPTIONS
# ══════════════════════════════════════════════════════════════════════════════

class DatabaseError(NexusError):
    """Base class for database errors."""

    def __init__(self, message: str, **kwargs):
        kwargs.setdefault("error_code", "NEXUS-DB-0000")
        super().__init__(message, **kwargs)


class DatabaseConnectionError(DatabaseError):
    """Failed to connect to the database."""

    def __init__(self, db_path: str = "", **kwargs):
        kwargs.setdefault("error_code", "NEXUS-DB-0001")
        kwargs.setdefault("recovery", RecoveryAction.RETRY)
        kwargs.setdefault("retryable", True)
        super().__init__(f"Database connection failed: {db_path}", **kwargs)


class DatabaseCorruptedError(DatabaseError):
    """Database file is corrupted."""

    def __init__(self, db_path: str = "", **kwargs):
        kwargs.setdefault("error_code", "NEXUS-DB-0002")
        kwargs.setdefault("severity", ExceptionSeverity.CRITICAL)
        kwargs.setdefault("recovery", RecoveryAction.MANUAL_INTERVENTION)
        super().__init__(f"Database corrupted: {db_path}", **kwargs)


class QueryError(DatabaseError):
    """Database query execution failed."""

    def __init__(self, query: str = "", error: str = "", **kwargs):
        kwargs.setdefault("error_code", "NEXUS-DB-0003")
        kwargs.setdefault("context", {"query": query[:200], "error": error})
        super().__init__(f"Query failed: {error}", **kwargs)


# ══════════════════════════════════════════════════════════════════════════════
# NETWORK EXCEPTIONS
# ══════════════════════════════════════════════════════════════════════════════

class NetworkError(NexusError):
    """Base class for network errors."""

    def __init__(self, message: str, **kwargs):
        kwargs.setdefault("error_code", "NEXUS-NET-0000")
        kwargs.setdefault("retryable", True)
        super().__init__(message, **kwargs)


class TargetUnreachableError(NetworkError):
    """Target host is unreachable."""

    def __init__(self, target: str, **kwargs):
        kwargs.setdefault("error_code", "NEXUS-NET-0001")
        kwargs.setdefault("recovery", RecoveryAction.RETRY)
        super().__init__(f"Target unreachable: {target}", **kwargs)


class AuthenticationError(NetworkError):
    """Authentication failed against target."""

    def __init__(self, target: str = "", service: str = "", **kwargs):
        kwargs.setdefault("error_code", "NEXUS-NET-0002")
        kwargs.setdefault("retryable", False)
        kwargs.setdefault("recovery", RecoveryAction.RECONFIGURE)
        super().__init__(
            f"Authentication failed: {service}@{target}" if service else f"Auth failed: {target}",
            **kwargs
        )


class ConnectionTimeoutError(NetworkError):
    """Network connection timed out."""

    def __init__(self, target: str, timeout: int = 0, **kwargs):
        kwargs.setdefault("error_code", "NEXUS-NET-0003")
        kwargs.setdefault("recovery", RecoveryAction.RETRY_WITH_BACKOFF)
        super().__init__(f"Connection timeout: {target} ({timeout}s)", **kwargs)


# ══════════════════════════════════════════════════════════════════════════════
# STRATEGIC ENGINE EXCEPTIONS
# ══════════════════════════════════════════════════════════════════════════════

class StrategicError(NexusError):
    """Base class for strategic engine errors."""

    def __init__(self, message: str, **kwargs):
        kwargs.setdefault("error_code", "NEXUS-STR-0000")
        super().__init__(message, **kwargs)


class OperationNotFoundError(StrategicError):
    """Strategic operation not found."""

    def __init__(self, operation_id: str, **kwargs):
        kwargs.setdefault("error_code", "NEXUS-STR-0001")
        kwargs.setdefault("recovery", RecoveryAction.SKIP)
        super().__init__(f"Operation not found: {operation_id}", **kwargs)


class ScopeViolationError(StrategicError):
    """Operation violated defined scope boundaries."""

    def __init__(self, target: str, scope_id: str = "", **kwargs):
        kwargs.setdefault("error_code", "NEXUS-STR-0002")
        kwargs.setdefault("severity", ExceptionSeverity.CRITICAL)
        kwargs.setdefault("recovery", RecoveryAction.ABORT)
        super().__init__(f"Scope violation: {target} (scope: {scope_id})", **kwargs)


class OPSECViolationError(StrategicError):
    """OPSEC violation detected during operation."""

    def __init__(self, violation_type: str, details: str = "", **kwargs):
        kwargs.setdefault("error_code", "NEXUS-STR-0003")
        kwargs.setdefault("severity", ExceptionSeverity.WARNING)
        kwargs.setdefault("recovery", RecoveryAction.RETRY_WITH_BACKOFF)
        super().__init__(f"OPSEC violation ({violation_type}): {details}", **kwargs)


# ══════════════════════════════════════════════════════════════════════════════
# VALIDATION EXCEPTIONS
# ══════════════════════════════════════════════════════════════════════════════

class ValidationError(NexusError):
    """Base class for input validation errors."""

    def __init__(self, message: str, **kwargs):
        kwargs.setdefault("error_code", "NEXUS-VAL-0000")
        kwargs.setdefault("severity", ExceptionSeverity.WARNING)
        kwargs.setdefault("recovery", RecoveryAction.SKIP)
        super().__init__(message, **kwargs)


class InputSanitizationError(ValidationError):
    """Potentially malicious input detected."""

    def __init__(self, field: str, reason: str = "", **kwargs):
        kwargs.setdefault("error_code", "NEXUS-VAL-0001")
        kwargs.setdefault("severity", ExceptionSeverity.WARNING)
        super().__init__(f"Input sanitization failed for '{field}': {reason}", **kwargs)


class SchemaValidationError(ValidationError):
    """Input does not match expected schema."""

    def __init__(self, field: str, expected_type: str = "", got_type: str = "", **kwargs):
        kwargs.setdefault("error_code", "NEXUS-VAL-0002")
        super().__init__(
            f"Schema validation failed: '{field}' expected {expected_type}, got {got_type}",
            **kwargs
        )
