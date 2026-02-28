"""
Nexus Automation Framework - Prometheus Metrics

Advanced metrics collection and export for:
- MCP tool call metrics (latency, error rates, throughput)
- Container resource metrics (CPU, memory, disk)
- Security metrics (kill switch, IDS alerts)
- Strategic engine metrics (operations, findings)
- Database metrics (queries, pool, size)
"""

import time
import logging
import os
from typing import Dict, Any
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger("nexus_metrics")

try:
    from prometheus_client import (
        Counter, Histogram, Gauge, Summary, Info,
        CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST,
        start_http_server,
    )
    HAS_PROMETHEUS = True
except ImportError:
    HAS_PROMETHEUS = False


# ══════════════════════════════════════════════════════════════════════════════
# METRICS DEFINITIONS
# ══════════════════════════════════════════════════════════════════════════════

if HAS_PROMETHEUS:
    REGISTRY = CollectorRegistry()

    # ── MCP Tool Metrics ──
    TOOL_CALLS_TOTAL = Counter(
        "nexus_tool_calls_total",
        "Total number of MCP tool calls",
        ["tool_name", "status"],
        registry=REGISTRY,
    )
    TOOL_DURATION = Histogram(
        "nexus_tool_duration_seconds",
        "Duration of MCP tool calls in seconds",
        ["tool_name"],
        buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300],
        registry=REGISTRY,
    )
    TOOL_ERRORS = Counter(
        "nexus_tool_errors_total",
        "Total number of tool errors",
        ["tool_name", "error_type"],
        registry=REGISTRY,
    )
    ACTIVE_TOOLS = Gauge(
        "nexus_active_tool_executions",
        "Number of currently executing tools",
        registry=REGISTRY,
    )

    # ── Security Metrics ──
    SECURITY_EVENTS = Counter(
        "nexus_security_events_total",
        "Total security events",
        ["event_type", "severity"],
        registry=REGISTRY,
    )
    KILL_SWITCH_STATUS = Gauge(
        "nexus_kill_switch_active",
        "Kill switch status (1=active, 0=inactive)",
        registry=REGISTRY,
    )
    IDS_ALERTS = Counter(
        "nexus_ids_alerts_total",
        "Total IDS alerts",
        ["alert_type"],
        registry=REGISTRY,
    )
    RATE_LIMIT_BLOCKS = Counter(
        "nexus_rate_limit_blocks_total",
        "Rate limit blocks",
        ["tool_name"],
        registry=REGISTRY,
    )
    BLOCKED_COMMANDS = Counter(
        "nexus_blocked_commands_total",
        "Commands blocked by security policy",
        ["reason"],
        registry=REGISTRY,
    )

    # ── Container Metrics ──
    CONTAINER_CPU = Gauge(
        "nexus_container_cpu_percent",
        "Container CPU usage percentage",
        registry=REGISTRY,
    )
    CONTAINER_MEMORY = Gauge(
        "nexus_container_memory_bytes",
        "Container memory usage in bytes",
        registry=REGISTRY,
    )
    CONTAINER_DISK = Gauge(
        "nexus_container_disk_bytes",
        "Container disk usage in bytes",
        registry=REGISTRY,
    )
    CONTAINER_CONNECTIONS = Gauge(
        "nexus_container_connections",
        "Container network connections",
        ["state"],
        registry=REGISTRY,
    )

    # ── Database Metrics ──
    DB_QUERIES = Counter(
        "nexus_db_queries_total",
        "Total database queries",
        ["operation"],
        registry=REGISTRY,
    )
    DB_QUERY_DURATION = Histogram(
        "nexus_db_query_duration_seconds",
        "Database query duration",
        ["operation"],
        buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5],
        registry=REGISTRY,
    )
    DB_POOL_SIZE = Gauge(
        "nexus_db_pool_size",
        "Database connection pool size",
        registry=REGISTRY,
    )
    DB_POOL_AVAILABLE = Gauge(
        "nexus_db_pool_available",
        "Available database connections",
        registry=REGISTRY,
    )

    # ── Strategic Engine Metrics ──
    ACTIVE_OPERATIONS = Gauge(
        "nexus_active_operations",
        "Active strategic operations",
        registry=REGISTRY,
    )
    TOTAL_FINDINGS = Counter(
        "nexus_findings_total",
        "Total findings discovered",
        ["severity"],
        registry=REGISTRY,
    )
    EXPLOITS_ATTEMPTED = Counter(
        "nexus_exploits_attempted_total",
        "Total exploitation attempts",
        ["status"],
        registry=REGISTRY,
    )

    # ── Framework Info ──
    FRAMEWORK_INFO = Info(
        "nexus_framework",
        "Framework information",
        registry=REGISTRY,
    )
    FRAMEWORK_INFO.info({
        "version": "1.0.0",
        "name": "Nexus Automation Framework",
        "environment": os.environ.get("NEXUS_ENVIRONMENT", "production"),
    })


# ══════════════════════════════════════════════════════════════════════════════
# METRICS MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class MetricsManager:
    """Central metrics management."""

    def __init__(self):
        self._enabled = HAS_PROMETHEUS
        self._server_started = False

    def start_server(self, port: int = 9090):
        """Start Prometheus metrics HTTP server."""
        if not self._enabled:
            logger.warning("Prometheus client not available, metrics disabled")
            return

        if self._server_started:
            return

        try:
            start_http_server(port, registry=REGISTRY)
            self._server_started = True
            logger.info(f"Prometheus metrics server started on port {port}")
        except Exception as e:
            logger.error(f"Failed to start metrics server: {e}")

    def record_tool_call(self, tool_name: str, duration: float, success: bool, error_type: str = ""):
        """Record a tool call."""
        if not self._enabled:
            return
        status = "success" if success else "error"
        TOOL_CALLS_TOTAL.labels(tool_name=tool_name, status=status).inc()
        TOOL_DURATION.labels(tool_name=tool_name).observe(duration)
        if not success and error_type:
            TOOL_ERRORS.labels(tool_name=tool_name, error_type=error_type).inc()

    def record_security_event(self, event_type: str, severity: str):
        """Record a security event."""
        if not self._enabled:
            return
        SECURITY_EVENTS.labels(event_type=event_type, severity=severity).inc()

    def set_kill_switch(self, active: bool):
        """Update kill switch status."""
        if not self._enabled:
            return
        KILL_SWITCH_STATUS.set(1 if active else 0)

    def record_ids_alert(self, alert_type: str):
        """Record an IDS alert."""
        if not self._enabled:
            return
        IDS_ALERTS.labels(alert_type=alert_type).inc()

    def record_rate_limit(self, tool_name: str):
        """Record a rate limit block."""
        if not self._enabled:
            return
        RATE_LIMIT_BLOCKS.labels(tool_name=tool_name).inc()

    def record_blocked_command(self, reason: str):
        """Record a blocked command."""
        if not self._enabled:
            return
        BLOCKED_COMMANDS.labels(reason=reason).inc()

    def update_container_metrics(self):
        """Update container resource metrics."""
        if not self._enabled:
            return
        try:
            import psutil
            CONTAINER_CPU.set(psutil.cpu_percent())
            mem = psutil.virtual_memory()
            CONTAINER_MEMORY.set(mem.used)
            disk = psutil.disk_usage("/")
            CONTAINER_DISK.set(disk.used)
        except Exception:
            pass

    def record_db_query(self, operation: str, duration: float):
        """Record a database query."""
        if not self._enabled:
            return
        DB_QUERIES.labels(operation=operation).inc()
        DB_QUERY_DURATION.labels(operation=operation).observe(duration)

    def record_finding(self, severity: str):
        """Record a finding."""
        if not self._enabled:
            return
        TOTAL_FINDINGS.labels(severity=severity).inc()

    def record_exploit(self, status: str):
        """Record an exploitation attempt."""
        if not self._enabled:
            return
        EXPLOITS_ATTEMPTED.labels(status=status).inc()

    def get_metrics_text(self) -> str:
        """Get metrics in Prometheus exposition format."""
        if not self._enabled:
            return "# Prometheus metrics disabled\n"
        return generate_latest(REGISTRY).decode("utf-8")

    def get_summary(self) -> Dict[str, Any]:
        """Get a human-readable metrics summary."""
        return {
            "enabled": self._enabled,
            "server_started": self._server_started,
            "has_prometheus": HAS_PROMETHEUS,
        }


# ══════════════════════════════════════════════════════════════════════════════
# GLOBAL INSTANCE
# ══════════════════════════════════════════════════════════════════════════════

metrics_manager = MetricsManager()
