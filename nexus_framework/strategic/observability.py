"""
Observability Stack - Complete Monitoring System

Enterprise-grade observability with:
- Structured logging with correlation IDs
- Distributed tracing across components
- Prometheus-compatible metrics
- Alerting and health checks
- Performance monitoring
- Error tracking and analysis
- Dashboard architecture
- SLA monitoring and reporting
"""

import asyncio
import json
import logging
import time
import uuid
import threading
from typing import Dict, List, Optional, Set, Tuple, Any, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from collections import defaultdict, deque
import statistics
import traceback
import psutil
import sys


class LogLevel(Enum):
    """Log levels for structured logging."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class MetricType(Enum):
    """Types of metrics."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class HealthStatus(Enum):
    """Health check status."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class LogEntry:
    """Structured log entry."""
    timestamp: datetime
    level: LogLevel
    message: str
    component: str
    correlation_id: Optional[str]
    user_id: Optional[str]
    tenant_id: Optional[str]
    operation_id: Optional[str]
    metadata: Dict[str, Any] = field(default_factory=dict)
    stack_trace: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'level': self.level.value,
            'message': self.message,
            'component': self.component,
            'correlation_id': self.correlation_id,
            'user_id': self.user_id,
            'tenant_id': self.tenant_id,
            'operation_id': self.operation_id,
            'metadata': self.metadata,
            'stack_trace': self.stack_trace
        }


@dataclass
class TraceSpan:
    """Distributed trace span."""
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    operation_name: str
    start_time: datetime
    end_time: Optional[datetime]
    duration_ms: Optional[float]
    status: str
    tags: Dict[str, Any] = field(default_factory=dict)
    logs: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'trace_id': self.trace_id,
            'span_id': self.span_id,
            'parent_span_id': self.parent_span_id,
            'operation_name': self.operation_name,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration_ms': self.duration_ms,
            'status': self.status,
            'tags': self.tags,
            'logs': self.logs
        }


@dataclass
class Metric:
    """Metric data point."""
    name: str
    metric_type: MetricType
    value: float
    labels: Dict[str, str]
    timestamp: datetime
    help_text: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'name': self.name,
            'type': self.metric_type.value,
            'value': self.value,
            'labels': self.labels,
            'timestamp': self.timestamp.isoformat(),
            'help': self.help_text
        }


@dataclass
class Alert:
    """Alert definition."""
    alert_id: str
    name: str
    description: str
    severity: AlertSeverity
    condition: str
    threshold: float
    current_value: float
    triggered_at: datetime
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'alert_id': self.alert_id,
            'name': self.name,
            'description': self.description,
            'severity': self.severity.value,
            'condition': self.condition,
            'threshold': self.threshold,
            'current_value': self.current_value,
            'triggered_at': self.triggered_at.isoformat(),
            'acknowledged': self.acknowledged,
            'acknowledged_by': self.acknowledged_by,
            'acknowledged_at': self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            'resolved': self.resolved,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'metadata': self.metadata
        }


@dataclass
class HealthCheck:
    """Health check definition."""
    check_id: str
    name: str
    component: str
    status: HealthStatus
    message: str
    last_check: datetime
    response_time_ms: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'check_id': self.check_id,
            'name': self.name,
            'component': self.component,
            'status': self.status.value,
            'message': self.message,
            'last_check': self.last_check.isoformat(),
            'response_time_ms': self.response_time_ms,
            'metadata': self.metadata
        }


class StructuredLogger:
    """Structured logging with correlation."""
    
    def __init__(self, component_name: str):
        self.component_name = component_name
        self.logger = logging.getLogger(component_name)
        self.log_buffer: deque = deque(maxlen=10000)
        self.correlation_context = threading.local()
    
    def _create_log_entry(self, level: LogLevel, message: str, 
                         correlation_id: Optional[str] = None,
                         user_id: Optional[str] = None,
                         tenant_id: Optional[str] = None,
                         operation_id: Optional[str] = None,
                         metadata: Optional[Dict[str, Any]] = None,
                         stack_trace: Optional[str] = None) -> LogEntry:
        """Create structured log entry."""
        # Use context values if not provided
        if not correlation_id:
            correlation_id = getattr(self.correlation_context, 'correlation_id', None)
        if not user_id:
            user_id = getattr(self.correlation_context, 'user_id', None)
        if not tenant_id:
            tenant_id = getattr(self.correlation_context, 'tenant_id', None)
        if not operation_id:
            operation_id = getattr(self.correlation_context, 'operation_id', None)
        
        return LogEntry(
            timestamp=datetime.now(),
            level=level,
            message=message,
            component=self.component_name,
            correlation_id=correlation_id,
            user_id=user_id,
            tenant_id=tenant_id,
            operation_id=operation_id,
            metadata=metadata or {},
            stack_trace=stack_trace
        )
    
    def debug(self, message: str, **kwargs):
        """Log debug message."""
        entry = self._create_log_entry(LogLevel.DEBUG, message, **kwargs)
        self._log_entry(entry)
    
    def info(self, message: str, **kwargs):
        """Log info message."""
        entry = self._create_log_entry(LogLevel.INFO, message, **kwargs)
        self._log_entry(entry)
    
    def warning(self, message: str, **kwargs):
        """Log warning message."""
        entry = self._create_log_entry(LogLevel.WARNING, message, **kwargs)
        self._log_entry(entry)
    
    def error(self, message: str, **kwargs):
        """Log error message."""
        entry = self._create_log_entry(LogLevel.ERROR, message, **kwargs)
        self._log_entry(entry)
    
    def critical(self, message: str, **kwargs):
        """Log critical message."""
        entry = self._create_log_entry(LogLevel.CRITICAL, message, **kwargs)
        self._log_entry(entry)
    
    def exception(self, message: str, **kwargs):
        """Log exception with stack trace."""
        stack_trace = traceback.format_exc()
        entry = self._create_log_entry(LogLevel.ERROR, message, stack_trace=stack_trace, **kwargs)
        self._log_entry(entry)
    
    def _log_entry(self, entry: LogEntry):
        """Log entry to buffer and standard logger."""
        # Add to buffer
        self.log_buffer.append(entry)
        
        # Log to standard logger
        log_method = getattr(self.logger, entry.level.value)
        log_method(entry.message, extra={
            'correlation_id': entry.correlation_id,
            'user_id': entry.user_id,
            'tenant_id': entry.tenant_id,
            'operation_id': entry.operation_id,
            'metadata': entry.metadata
        })
    
    def set_correlation_context(self, correlation_id: str, user_id: Optional[str] = None,
                               tenant_id: Optional[str] = None, operation_id: Optional[str] = None):
        """Set correlation context for current thread."""
        self.correlation_context.correlation_id = correlation_id
        self.correlation_context.user_id = user_id
        self.correlation_context.tenant_id = tenant_id
        self.correlation_context.operation_id = operation_id
    
    def clear_correlation_context(self):
        """Clear correlation context."""
        self.correlation_context.__dict__.clear()
    
    def get_logs(self, level: Optional[LogLevel] = None,
                component: Optional[str] = None,
                correlation_id: Optional[str] = None,
                start_time: Optional[datetime] = None,
                end_time: Optional[datetime] = None,
                limit: int = 1000) -> List[LogEntry]:
        """Get filtered logs."""
        logs = list(self.log_buffer)
        
        # Apply filters
        if level:
            logs = [log for log in logs if log.level == level]
        
        if component:
            logs = [log for log in logs if log.component == component]
        
        if correlation_id:
            logs = [log for log in logs if log.correlation_id == correlation_id]
        
        if start_time:
            logs = [log for log in logs if log.timestamp >= start_time]
        
        if end_time:
            logs = [log for log in logs if log.timestamp <= end_time]
        
        # Sort by timestamp (newest first) and limit
        logs.sort(key=lambda x: x.timestamp, reverse=True)
        return logs[:limit]


class DistributedTracer:
    """Distributed tracing implementation."""
    
    def __init__(self):
        self.active_spans: Dict[str, TraceSpan] = {}
        self.trace_history: deque = deque(maxlen=5000)
        self.span_context = threading.local()
    
    def start_trace(self, operation_name: str, trace_id: Optional[str] = None,
                   parent_span_id: Optional[str] = None,
                   tags: Optional[Dict[str, Any]] = None) -> str:
        """Start a new trace span."""
        if trace_id is None:
            trace_id = str(uuid.uuid4())
        
        span_id = str(uuid.uuid4())
        
        span = TraceSpan(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            operation_name=operation_name,
            start_time=datetime.now(),
            end_time=None,
            duration_ms=None,
            status="ok",
            tags=tags or {}
        )
        
        self.active_spans[span_id] = span
        self.span_context.current_span_id = span_id
        
        return span_id
    
    def finish_span(self, span_id: Optional[str] = None, status: str = "ok",
                   tags: Optional[Dict[str, Any]] = None):
        """Finish a trace span."""
        if span_id is None:
            span_id = getattr(self.span_context, 'current_span_id', None)
        
        if not span_id or span_id not in self.active_spans:
            return
        
        span = self.active_spans[span_id]
        span.end_time = datetime.now()
        span.duration_ms = (span.end_time - span.start_time).total_seconds() * 1000
        span.status = status
        
        if tags:
            span.tags.update(tags)
        
        # Move to history
        self.trace_history.append(span)
        del self.active_spans[span_id]
        
        # Clear context if this was the current span
        if getattr(self.span_context, 'current_span_id', None) == span_id:
            self.span_context.current_span_id = None
    
    def add_span_tag(self, key: str, value: Any, span_id: Optional[str] = None):
        """Add tag to span."""
        if span_id is None:
            span_id = getattr(self.span_context, 'current_span_id', None)
        
        if span_id and span_id in self.active_spans:
            self.active_spans[span_id].tags[key] = value
    
    def add_span_log(self, level: str, message: str, 
                    fields: Optional[Dict[str, Any]] = None,
                    span_id: Optional[str] = None):
        """Add log entry to span."""
        if span_id is None:
            span_id = getattr(self.span_context, 'current_span_id', None)
        
        if span_id and span_id in self.active_spans:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'level': level,
                'message': message,
                'fields': fields or {}
            }
            self.active_spans[span_id].logs.append(log_entry)
    
    def get_trace(self, trace_id: str) -> List[TraceSpan]:
        """Get all spans for a trace."""
        spans = [span for span in self.trace_history if span.trace_id == trace_id]
        spans.extend([span for span in self.active_spans.values() if span.trace_id == trace_id])
        
        # Sort by start time
        spans.sort(key=lambda x: x.start_time)
        return spans
    
    def get_active_spans(self) -> List[TraceSpan]:
        """Get all active spans."""
        return list(self.active_spans.values())


class MetricsCollector:
    """Prometheus-compatible metrics collector."""
    
    def __init__(self):
        self.metrics: Dict[str, List[Metric]] = defaultdict(list)
        self.metric_definitions: Dict[str, Dict[str, Any]] = {}
        self.counters: Dict[str, float] = defaultdict(float)
        self.gauges: Dict[str, float] = defaultdict(float)
        self.histograms: Dict[str, List[float]] = defaultdict(list)
        self.lock = threading.Lock()
    
    def define_metric(self, name: str, metric_type: MetricType, help_text: str = ""):
        """Define a metric."""
        self.metric_definitions[name] = {
            'type': metric_type,
            'help': help_text
        }
    
    def increment_counter(self, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None):
        """Increment counter metric."""
        with self.lock:
            self.counters[name] += value
            
            metric = Metric(
                name=name,
                metric_type=MetricType.COUNTER,
                value=self.counters[name],
                labels=labels or {},
                timestamp=datetime.now(),
                help_text=self.metric_definitions.get(name, {}).get('help', '')
            )
            self.metrics[name].append(metric)
    
    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Set gauge metric."""
        with self.lock:
            self.gauges[name] = value
            
            metric = Metric(
                name=name,
                metric_type=MetricType.GAUGE,
                value=value,
                labels=labels or {},
                timestamp=datetime.now(),
                help_text=self.metric_definitions.get(name, {}).get('help', '')
            )
            self.metrics[name].append(metric)
    
    def record_histogram(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Record histogram metric."""
        with self.lock:
            self.histograms[name].append(value)
            
            metric = Metric(
                name=name,
                metric_type=MetricType.HISTOGRAM,
                value=value,
                labels=labels or {},
                timestamp=datetime.now(),
                help_text=self.metric_definitions.get(name, {}).get('help', '')
            )
            self.metrics[name].append(metric)
    
    def get_metrics(self, name: Optional[str] = None, 
                   start_time: Optional[datetime] = None,
                   end_time: Optional[datetime] = None) -> List[Metric]:
        """Get metrics with optional filtering."""
        with self.lock:
            if name:
                all_metrics = self.metrics.get(name, [])
            else:
                all_metrics = []
                for metric_list in self.metrics.values():
                    all_metrics.extend(metric_list)
            
            # Filter by time
            if start_time:
                all_metrics = [m for m in all_metrics if m.timestamp >= start_time]
            
            if end_time:
                all_metrics = [m for m in all_metrics if m.timestamp <= end_time]
            
            return all_metrics
    
    def export_prometheus_format(self) -> str:
        """Export metrics in Prometheus format."""
        output = []
        
        # Export metric definitions
        for name, definition in self.metric_definitions.items():
            output.append(f"# HELP {name} {definition.get('help', '')}")
            output.append(f"# TYPE {name} {definition['type'].value}")
        
        # Export current values
        for name, value in self.counters.items():
            output.append(f"{name} {value}")
        
        for name, value in self.gauges.items():
            output.append(f"{name} {value}")
        
        # Export histogram statistics
        for name, values in self.histograms.items():
            if values:
                output.append(f"{name}_count {len(values)}")
                output.append(f"{name}_sum {sum(values)}")
                output.append(f"{name}_bucket{{le=\"+Inf\"}} {len(values)}")
        
        return '\n'.join(output)


class AlertManager:
    """Alert management system."""
    
    def __init__(self):
        self.alerts: Dict[str, Alert] = {}
        self.alert_rules: List[Dict[str, Any]] = []
        self.alert_history: deque = deque(maxlen=1000)
        self.notification_callbacks: List[Callable] = []
    
    def add_alert_rule(self, name: str, condition: str, threshold: float,
                      severity: AlertSeverity, description: str = ""):
        """Add alert rule."""
        rule = {
            'name': name,
            'condition': condition,
            'threshold': threshold,
            'severity': severity,
            'description': description
        }
        self.alert_rules.append(rule)
    
    def evaluate_alerts(self, metrics_collector: MetricsCollector):
        """Evaluate alert rules against metrics."""
        for rule in self.alert_rules:
            try:
                # Parse condition (simplified)
                metric_name = rule['condition']
                current_metrics = metrics_collector.get_metrics(metric_name)
                
                if current_metrics:
                    latest_metric = current_metrics[-1]
                    current_value = latest_metric.value
                    
                    # Check threshold
                    if current_value >= rule['threshold']:
                        self._trigger_alert(rule, current_value)
                    else:
                        self._resolve_alert(rule['name'])
            
            except Exception as e:
                logging.error(f"Error evaluating alert rule {rule['name']}: {e}")
    
    def _trigger_alert(self, rule: Dict[str, Any], current_value: float):
        """Trigger an alert."""
        alert_id = rule['name']
        
        if alert_id not in self.alerts or self.alerts[alert_id].resolved:
            # Create new alert
            alert = Alert(
                alert_id=alert_id,
                name=rule['name'],
                description=rule['description'],
                severity=rule['severity'],
                condition=rule['condition'],
                threshold=rule['threshold'],
                current_value=current_value,
                triggered_at=datetime.now()
            )
            
            self.alerts[alert_id] = alert
            self.alert_history.append(alert)
            
            # Send notifications
            for callback in self.notification_callbacks:
                try:
                    callback(alert)
                except Exception as e:
                    logging.error(f"Error sending alert notification: {e}")
    
    def _resolve_alert(self, alert_id: str):
        """Resolve an alert."""
        if alert_id in self.alerts and not self.alerts[alert_id].resolved:
            alert = self.alerts[alert_id]
            alert.resolved = True
            alert.resolved_at = datetime.now()
    
    def acknowledge_alert(self, alert_id: str, acknowledged_by: str):
        """Acknowledge an alert."""
        if alert_id in self.alerts:
            alert = self.alerts[alert_id]
            alert.acknowledged = True
            alert.acknowledged_by = acknowledged_by
            alert.acknowledged_at = datetime.now()
    
    def get_active_alerts(self) -> List[Alert]:
        """Get all active (unresolved) alerts."""
        return [alert for alert in self.alerts.values() if not alert.resolved]


class HealthChecker:
    """Health check system."""
    
    def __init__(self):
        self.health_checks: Dict[str, HealthCheck] = {}
        self.check_functions: Dict[str, Callable] = {}
    
    def register_health_check(self, check_id: str, name: str, component: str,
                            check_function: Callable[[], Tuple[bool, str, float]]):
        """Register a health check."""
        self.check_functions[check_id] = check_function
        
        # Create initial health check entry
        health_check = HealthCheck(
            check_id=check_id,
            name=name,
            component=component,
            status=HealthStatus.UNKNOWN,
            message="Not yet checked",
            last_check=datetime.now(),
            response_time_ms=0.0
        )
        
        self.health_checks[check_id] = health_check
    
    def run_health_check(self, check_id: str) -> HealthCheck:
        """Run a specific health check."""
        if check_id not in self.check_functions:
            raise ValueError(f"Health check {check_id} not registered")
        
        start_time = time.time()
        
        try:
            healthy, message, response_time = self.check_functions[check_id]()
            status = HealthStatus.HEALTHY if healthy else HealthStatus.UNHEALTHY
            
            health_check = self.health_checks[check_id]
            health_check.status = status
            health_check.message = message
            health_check.last_check = datetime.now()
            health_check.response_time_ms = response_time * 1000
            
        except Exception as e:
            health_check = self.health_checks[check_id]
            health_check.status = HealthStatus.UNHEALTHY
            health_check.message = f"Check failed: {str(e)}"
            health_check.last_check = datetime.now()
            health_check.response_time_ms = (time.time() - start_time) * 1000
        
        return health_check
    
    def run_all_health_checks(self) -> Dict[str, HealthCheck]:
        """Run all registered health checks."""
        results = {}
        
        for check_id in self.check_functions:
            try:
                results[check_id] = self.run_health_check(check_id)
            except Exception as e:
                logging.error(f"Error running health check {check_id}: {e}")
        
        return results
    
    def get_overall_health(self) -> Tuple[HealthStatus, str]:
        """Get overall system health."""
        if not self.health_checks:
            return HealthStatus.UNKNOWN, "No health checks registered"
        
        statuses = [check.status for check in self.health_checks.values()]
        
        if all(status == HealthStatus.HEALTHY for status in statuses):
            return HealthStatus.HEALTHY, "All components healthy"
        elif any(status == HealthStatus.UNHEALTHY for status in statuses):
            return HealthStatus.UNHEALTHY, "Some components unhealthy"
        else:
            return HealthStatus.DEGRADED, "Some components degraded"


class ObservabilityManager:
    """Main observability management system."""
    
    def __init__(self):
        self.logger = logging.getLogger("observability_manager")
        
        # Core components
        self.loggers: Dict[str, StructuredLogger] = {}
        self.tracer = DistributedTracer()
        self.metrics_collector = MetricsCollector()
        self.alert_manager = AlertManager()
        self.health_checker = HealthChecker()
        
        # System metrics
        self._define_system_metrics()
        self._register_system_health_checks()
        
        # Background monitoring
        self.monitoring_active = False
        self.monitoring_thread: Optional[threading.Thread] = None
    
    def _define_system_metrics(self):
        """Define system metrics."""
        self.metrics_collector.define_metric("system_cpu_usage", MetricType.GAUGE, "System CPU usage percentage")
        self.metrics_collector.define_metric("system_memory_usage", MetricType.GAUGE, "System memory usage percentage")
        self.metrics_collector.define_metric("system_disk_usage", MetricType.GAUGE, "System disk usage percentage")
        self.metrics_collector.define_metric("active_operations", MetricType.GAUGE, "Number of active operations")
        self.metrics_collector.define_metric("operation_duration", MetricType.HISTOGRAM, "Operation duration in milliseconds")
        self.metrics_collector.define_metric("error_count", MetricType.COUNTER, "Total error count")
        self.metrics_collector.define_metric("request_count", MetricType.COUNTER, "Total request count")
    
    def _register_system_health_checks(self):
        """Register system health checks."""
        def cpu_check() -> Tuple[bool, str, float]:
            cpu_percent = psutil.cpu_percent(interval=1)
            healthy = cpu_percent < 90
            return healthy, f"CPU usage: {cpu_percent:.1f}%", 1.0
        
        def memory_check() -> Tuple[bool, str, float]:
            memory = psutil.virtual_memory()
            healthy = memory.percent < 90
            return healthy, f"Memory usage: {memory.percent:.1f}%", 1.0
        
        def disk_check() -> Tuple[bool, str, float]:
            disk = psutil.disk_usage('/')
            percent = (disk.used / disk.total) * 100
            healthy = percent < 90
            return healthy, f"Disk usage: {percent:.1f}%", 1.0
        
        self.health_checker.register_health_check("cpu", "CPU Usage", "system", cpu_check)
        self.health_checker.register_health_check("memory", "Memory Usage", "system", memory_check)
        self.health_checker.register_health_check("disk", "Disk Usage", "system", disk_check)
    
    def get_logger(self, component_name: str) -> StructuredLogger:
        """Get structured logger for component."""
        if component_name not in self.loggers:
            self.loggers[component_name] = StructuredLogger(component_name)
        return self.loggers[component_name]
    
    def start_monitoring(self, interval_seconds: int = 30):
        """Start background monitoring."""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            args=(interval_seconds,),
            daemon=True
        )
        self.monitoring_thread.start()
        
        self.logger.info("Started background monitoring")
    
    def stop_monitoring(self):
        """Stop background monitoring."""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        
        self.logger.info("Stopped background monitoring")
    
    def _monitoring_loop(self, interval_seconds: int):
        """Background monitoring loop."""
        while self.monitoring_active:
            try:
                # Collect system metrics
                cpu_percent = psutil.cpu_percent()
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                self.metrics_collector.set_gauge("system_cpu_usage", cpu_percent)
                self.metrics_collector.set_gauge("system_memory_usage", memory.percent)
                self.metrics_collector.set_gauge("system_disk_usage", (disk.used / disk.total) * 100)
                
                # Run health checks
                self.health_checker.run_all_health_checks()
                
                # Evaluate alerts
                self.alert_manager.evaluate_alerts(self.metrics_collector)
                
                time.sleep(interval_seconds)
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(interval_seconds)
    
    def create_dashboard_data(self) -> Dict[str, Any]:
        """Create dashboard data."""
        # Get system health
        overall_health, health_message = self.health_checker.get_overall_health()
        health_checks = self.health_checker.run_all_health_checks()
        
        # Get recent metrics
        now = datetime.now()
        hour_ago = now - timedelta(hours=1)
        
        cpu_metrics = self.metrics_collector.get_metrics("system_cpu_usage", hour_ago, now)
        memory_metrics = self.metrics_collector.get_metrics("system_memory_usage", hour_ago, now)
        
        # Get active alerts
        active_alerts = self.alert_manager.get_active_alerts()
        
        # Get recent logs
        recent_logs = []
        for logger in self.loggers.values():
            recent_logs.extend(logger.get_logs(limit=50))
        
        recent_logs.sort(key=lambda x: x.timestamp, reverse=True)
        recent_logs = recent_logs[:100]
        
        return {
            'timestamp': now.isoformat(),
            'health': {
                'overall_status': overall_health.value,
                'message': health_message,
                'checks': {check_id: check.to_dict() for check_id, check in health_checks.items()}
            },
            'metrics': {
                'cpu': [m.to_dict() for m in cpu_metrics[-10:]],  # Last 10 data points
                'memory': [m.to_dict() for m in memory_metrics[-10:]],
                'prometheus_export': self.metrics_collector.export_prometheus_format()
            },
            'alerts': {
                'active_count': len(active_alerts),
                'active_alerts': [alert.to_dict() for alert in active_alerts]
            },
            'logs': {
                'recent_count': len(recent_logs),
                'recent_logs': [log.to_dict() for log in recent_logs[:20]]  # Last 20 logs
            },
            'tracing': {
                'active_spans': len(self.tracer.get_active_spans()),
                'total_traces': len(self.tracer.trace_history)
            }
        }
    
    def get_observability_summary(self) -> Dict[str, Any]:
        """Get observability system summary."""
        return {
            'components': {
                'loggers': len(self.loggers),
                'active_traces': len(self.tracer.get_active_spans()),
                'total_metrics': sum(len(metrics) for metrics in self.metrics_collector.metrics.values()),
                'active_alerts': len(self.alert_manager.get_active_alerts()),
                'health_checks': len(self.health_checker.health_checks)
            },
            'monitoring': {
                'active': self.monitoring_active,
                'system_health': self.health_checker.get_overall_health()[0].value
            },
            'performance': {
                'cpu_usage': psutil.cpu_percent(),
                'memory_usage': psutil.virtual_memory().percent,
                'disk_usage': (psutil.disk_usage('/').used / psutil.disk_usage('/').total) * 100
            }
        }


# Global observability manager instance
observability_manager = ObservabilityManager()
