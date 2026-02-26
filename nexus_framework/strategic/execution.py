"""
Adaptive Execution Layer - Intelligent Tool Execution

Smart execution layer with retry logic, backoff strategies, 
fallback mechanisms, and performance-based tool selection.

Features:
- Intelligent retry with exponential backoff
- Adaptive timeout management
- Multi-tool fallback strategies
- Tool performance scoring and learning
- Resource limiting and isolation
- Execution context management
- Failure pattern analysis
"""

import asyncio
import json
import logging
import time
import random
from typing import Dict, List, Optional, Set, Tuple, Any, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from collections import defaultdict, deque
import statistics
import hashlib
import uuid


class ExecutionStatus(Enum):
    """Execution status values."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    RETRYING = "retrying"


class RetryStrategy(Enum):
    """Retry strategies."""
    EXPONENTIAL_BACKOFF = "exponential_backoff"
    LINEAR_BACKOFF = "linear_backoff"
    FIXED_INTERVAL = "fixed_interval"
    FIBONACCI_BACKOFF = "fibonacci_backoff"
    ADAPTIVE = "adaptive"


class FailureType(Enum):
    """Types of execution failures."""
    TIMEOUT = "timeout"
    NETWORK_ERROR = "network_error"
    AUTHENTICATION_ERROR = "authentication_error"
    PERMISSION_ERROR = "permission_error"
    RESOURCE_ERROR = "resource_error"
    TOOL_NOT_FOUND = "tool_not_found"
    INVALID_INPUT = "invalid_input"
    UNKNOWN_ERROR = "unknown_error"


@dataclass
class ExecutionMetrics:
    """Execution performance metrics."""
    tool_name: str
    total_executions: int = 0
    successful_executions: int = 0
    failed_executions: int = 0
    average_execution_time: float = 0.0
    average_success_rate: float = 0.0
    last_execution: Optional[datetime] = None
    failure_patterns: Dict[str, int] = field(default_factory=dict)
    performance_score: float = 0.5  # 0-1 score
    reliability_score: float = 0.5  # 0-1 score
    
    def update_metrics(self, execution_time: float, success: bool, failure_type: Optional[str] = None):
        """Update metrics with new execution data."""
        self.total_executions += 1
        self.last_execution = datetime.now()
        
        if success:
            self.successful_executions += 1
        else:
            self.failed_executions += 1
            if failure_type:
                self.failure_patterns[failure_type] = self.failure_patterns.get(failure_type, 0) + 1
        
        # Update average execution time
        if self.total_executions == 1:
            self.average_execution_time = execution_time
        else:
            self.average_execution_time = (
                (self.average_execution_time * (self.total_executions - 1) + execution_time) / 
                self.total_executions
            )
        
        # Update success rate
        self.average_success_rate = self.successful_executions / self.total_executions
        
        # Update performance score (combination of speed and success)
        speed_score = 1.0 / (1.0 + self.average_execution_time / 60)  # Normalize by minute
        self.performance_score = (speed_score + self.average_success_rate) / 2
        
        # Update reliability score (success rate weighted by recent performance)
        recent_weight = 0.7
        historical_weight = 0.3
        self.reliability_score = (
            self.average_success_rate * historical_weight + 
            (1.0 if success else 0.0) * recent_weight
        )


@dataclass
class ExecutionContext:
    """Execution context for tool execution."""
    execution_id: str
    tool_name: str
    command: str
    parameters: Dict[str, Any]
    timeout: int
    max_retries: int
    retry_strategy: RetryStrategy
    fallback_tools: List[str]
    resource_limits: Dict[str, Any]
    priority: int  # 1-10, higher = more important
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'execution_id': self.execution_id,
            'tool_name': self.tool_name,
            'command': self.command,
            'parameters': self.parameters,
            'timeout': self.timeout,
            'max_retries': self.max_retries,
            'retry_strategy': self.retry_strategy.value,
            'fallback_tools': self.fallback_tools,
            'resource_limits': self.resource_limits,
            'priority': self.priority,
            'metadata': self.metadata,
            'created_at': self.created_at.isoformat()
        }


@dataclass
class ExecutionResult:
    """Result of tool execution."""
    execution_id: str
    tool_name: str
    status: ExecutionStatus
    start_time: datetime
    end_time: Optional[datetime]
    execution_time: float
    exit_code: Optional[int]
    stdout: str
    stderr: str
    error_message: Optional[str]
    retry_count: int
    used_fallback: bool
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'execution_id': self.execution_id,
            'tool_name': self.tool_name,
            'status': self.status.value,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'execution_time': self.execution_time,
            'exit_code': self.exit_code,
            'stdout': self.stdout,
            'stderr': self.stderr,
            'error_message': self.error_message,
            'retry_count': self.retry_count,
            'used_fallback': self.used_fallback,
            'metadata': self.metadata
        }


class RetryManager:
    """Manages retry strategies and backoff calculations."""
    
    def __init__(self):
        self.retry_strategies = {
            RetryStrategy.EXPONENTIAL_BACKOFF: self._exponential_backoff,
            RetryStrategy.LINEAR_BACKOFF: self._linear_backoff,
            RetryStrategy.FIXED_INTERVAL: self._fixed_interval,
            RetryStrategy.FIBONACCI_BACKOFF: self._fibonacci_backoff,
            RetryStrategy.ADAPTIVE: self._adaptive_backoff
        }
    
    def calculate_retry_delay(self, strategy: RetryStrategy, attempt: int, 
                            base_delay: float = 1.0, max_delay: float = 60.0,
                            context: Optional[ExecutionContext] = None) -> float:
        """Calculate retry delay based on strategy."""
        if strategy not in self.retry_strategies:
            strategy = RetryStrategy.EXPONENTIAL_BACKOFF
        
        delay = self.retry_strategies[strategy](attempt, base_delay, context)
        return min(delay, max_delay)
    
    def _exponential_backoff(self, attempt: int, base_delay: float, 
                            context: Optional[ExecutionContext] = None) -> float:
        """Exponential backoff: delay = base_delay * (2 ^ attempt)"""
        return base_delay * (2 ** attempt)
    
    def _linear_backoff(self, attempt: int, base_delay: float, 
                       context: Optional[ExecutionContext] = None) -> float:
        """Linear backoff: delay = base_delay * (1 + attempt)"""
        return base_delay * (1 + attempt)
    
    def _fixed_interval(self, attempt: int, base_delay: float, 
                       context: Optional[ExecutionContext] = None) -> float:
        """Fixed interval: delay = base_delay"""
        return base_delay
    
    def _fibonacci_backoff(self, attempt: int, base_delay: float, 
                          context: Optional[ExecutionContext] = None) -> float:
        """Fibonacci backoff: delay = base_delay * fibonacci(attempt)"""
        def fibonacci(n):
            if n <= 1:
                return n
            a, b = 0, 1
            for _ in range(2, n + 1):
                a, b = b, a + b
            return b
        
        return base_delay * fibonacci(attempt)
    
    def _adaptive_backoff(self, attempt: int, base_delay: float, 
                         context: Optional[ExecutionContext] = None) -> float:
        """Adaptive backoff based on failure patterns and tool performance."""
        if not context:
            return self._exponential_backoff(attempt, base_delay)
        
        # Base exponential backoff
        delay = base_delay * (2 ** attempt)
        
        # Adjust based on tool reliability (less reliable tools get more delay)
        tool_metrics = execution_engine.get_tool_metrics(context.tool_name) if execution_engine else None
        if tool_metrics:
            reliability_factor = 1.0 / (tool_metrics.reliability_score + 0.1)  # Avoid division by zero
            delay *= reliability_factor
        
        # Add jitter to prevent thundering herd
        jitter = random.uniform(0.8, 1.2)
        delay *= jitter
        
        return delay


class TimeoutManager:
    """Manages adaptive timeout calculations."""
    
    def __init__(self):
        self.default_timeouts = {
            'quick_scan': 30,
            'comprehensive_scan': 300,
            'exploitation': 600,
            'credential_attack': 1800,
            'file_transfer': 120,
            'reconnaissance': 120
        }
        
        self.tool_timeouts = {
            'nmap': 300,
            'masscan': 180,
            'nikto': 120,
            'sqlmap': 600,
            'hydra': 1800,
            'john': 3600,
            'hashcat': 3600,
            'metasploit': 600,
            'impacket': 300
        }
    
    def calculate_timeout(self, tool_name: str, operation_type: str, 
                         target_complexity: float = 1.0, 
                         historical_data: Optional[Dict] = None) -> int:
        """Calculate adaptive timeout."""
        # Base timeout
        base_timeout = self.tool_timeouts.get(tool_name, self.default_timeouts.get(operation_type, 300))
        
        # Adjust for target complexity
        complexity_factor = max(0.5, min(3.0, target_complexity))
        adjusted_timeout = base_timeout * complexity_factor
        
        # Adjust based on historical data
        if historical_data:
            avg_time = historical_data.get('average_execution_time')
            if avg_time:
                # Use 125% of historical average as timeout
                adjusted_timeout = max(adjusted_timeout, avg_time * 1.25)
        
        # Ensure reasonable bounds
        min_timeout = 30
        max_timeout = 7200  # 2 hours
        
        return max(min_timeout, min(int(adjusted_timeout), max_timeout))


class FallbackManager:
    """Manages fallback tool selection and execution."""
    
    def __init__(self):
        self.tool_alternatives = {
            'nmap': ['masscan', 'netdiscover', 'arp-scan'],
            'nikto': ['dirb', 'gobuster', 'ffuf'],
            'sqlmap': ['burp_suite', 'sqlninja', 'commix'],
            'hydra': ['medusa', 'ncrack', 'patator'],
            'john': ['hashcat', 'ophcrack'],
            'metasploit': ['empire', 'cobalt_strike', 'custom_exploits'],
            'impacket': ['crackmapexec', 'netexec', 'smbclient'],
            'sslscan': ['sslyze', 'testssl', 'openssl']
        }
        
        self.tool_capabilities = {
            'nmap': ['port_scanning', 'service_detection', 'os_detection', 'script_scanning'],
            'masscan': ['port_scanning', 'fast_scanning'],
            'nikto': ['web_vulnerability_scanning', 'version_detection'],
            'sqlmap': ['sql_injection', 'database_fingerprinting', 'data_extraction'],
            'hydra': ['brute_force', 'credential_testing'],
            'metasploit': ['exploitation', 'post_exploitation', 'payload_delivery']
        }
    
    def get_fallback_tools(self, primary_tool: str, required_capabilities: List[str]) -> List[str]:
        """Get fallback tools with required capabilities."""
        fallback_tools = self.tool_alternatives.get(primary_tool, [])
        
        # Filter by capabilities
        capable_tools = []
        for tool in fallback_tools:
            tool_caps = self.tool_capabilities.get(tool, [])
            if all(cap in tool_caps for cap in required_capabilities):
                capable_tools.append(tool)
        
        return capable_tools
    
    def select_best_fallback(self, fallback_tools: List[str], 
                           failure_type: FailureType) -> Optional[str]:
        """Select best fallback tool based on failure type."""
        if not fallback_tools:
            return None
        
        # Different strategies for different failure types
        if failure_type == FailureType.TIMEOUT:
            # Prefer faster tools for timeouts
            speed_ranking = {'masscan': 1, 'netdiscover': 2, 'arp-scan': 3, 'nmap': 4}
            return min(fallback_tools, key=lambda x: speed_ranking.get(x, 999))
        
        elif failure_type == FailureType.NETWORK_ERROR:
            # Prefer tools with better network handling
            network_ranking = {'netexec': 1, 'crackmapexec': 2, 'impacket': 3}
            return min(fallback_tools, key=lambda x: network_ranking.get(x, 999))
        
        elif failure_type == FailureType.PERMISSION_ERROR:
            # Prefer tools with better privilege handling
            priv_ranking = {'sudo': 1, 'runas': 2, 'su': 3}
            return min(fallback_tools, key=lambda x: priv_ranking.get(x, 999))
        
        else:
            # Default: return first available
            return fallback_tools[0]


class AdaptiveExecutionEngine:
    """Main adaptive execution engine."""
    
    def __init__(self):
        self.logger = logging.getLogger("adaptive_execution")
        self.retry_manager = RetryManager()
        self.timeout_manager = TimeoutManager()
        self.fallback_manager = FallbackManager()
        
        # Execution tracking
        self.active_executions: Dict[str, ExecutionContext] = {}
        self.execution_history: deque = deque(maxlen=1000)
        self.tool_metrics: Dict[str, ExecutionMetrics] = {}
        
        # Resource management
        self.max_concurrent_executions = 10
        self.current_executions = 0
        self.execution_queue = asyncio.Queue()
        
        # Performance tracking
        self.global_stats = {
            'total_executions': 0,
            'successful_executions': 0,
            'failed_executions': 0,
            'average_execution_time': 0.0,
            'fallback_usage_rate': 0.0
        }
    
    async def execute_tool(self, tool_name: str, command: str, 
                          parameters: Dict[str, Any],
                          timeout: Optional[int] = None,
                          max_retries: int = 3,
                          retry_strategy: RetryStrategy = RetryStrategy.EXPONENTIAL_BACKOFF,
                          fallback_tools: Optional[List[str]] = None,
                          resource_limits: Optional[Dict[str, Any]] = None,
                          priority: int = 5) -> ExecutionResult:
        """Execute tool with adaptive retry and fallback logic."""
        
        # Generate execution ID
        execution_id = str(uuid.uuid4())
        
        # Calculate adaptive timeout
        if timeout is None:
            timeout = self.timeout_manager.calculate_timeout(tool_name, parameters.get('operation_type', 'default'))
        
        # Create execution context
        context = ExecutionContext(
            execution_id=execution_id,
            tool_name=tool_name,
            command=command,
            parameters=parameters,
            timeout=timeout,
            max_retries=max_retries,
            retry_strategy=retry_strategy,
            fallback_tools=fallback_tools or self.fallback_manager.tool_alternatives.get(tool_name, []),
            resource_limits=resource_limits or {},
            priority=priority
        )
        
        # Start execution
        return await self._execute_with_retry(context)
    
    async def _execute_with_retry(self, context: ExecutionContext) -> ExecutionResult:
        """Execute tool with retry logic."""
        start_time = datetime.now()
        retry_count = 0
        used_fallback = False
        current_tool = context.tool_name
        
        while retry_count <= context.max_retries:
            try:
                # Check resource limits
                if not await self._check_resource_limits(context):
                    raise ResourceError("Resource limits exceeded")
                
                # Execute tool
                result = await self._execute_single_tool(current_tool, context.command, context.timeout)
                
                # Check if execution was successful
                if self._is_successful_execution(result):
                    # Update metrics
                    self._update_tool_metrics(current_tool, result.execution_time, True)
                    self._update_global_stats(True, result.execution_time, used_fallback)
                    
                    return ExecutionResult(
                        execution_id=context.execution_id,
                        tool_name=current_tool,
                        status=ExecutionStatus.COMPLETED,
                        start_time=start_time,
                        end_time=datetime.now(),
                        execution_time=result.execution_time,
                        exit_code=result.exit_code,
                        stdout=result.stdout,
                        stderr=result.stderr,
                        error_message=None,
                        retry_count=retry_count,
                        used_fallback=used_fallback,
                        metadata={'original_tool': context.tool_name}
                    )
                
                else:
                    # Execution failed, determine failure type
                    failure_type = self._classify_failure(result)
                    
                    # Update metrics
                    self._update_tool_metrics(current_tool, result.execution_time, False, failure_type)
                    
                    # Try fallback if available and this is the first failure
                    if retry_count == 0 and not used_fallback:
                        fallback_tool = self.fallback_manager.select_best_fallback(
                            context.fallback_tools, failure_type
                        )
                        
                        if fallback_tool:
                            self.logger.info(f"Using fallback tool {fallback_tool} for {context.tool_name}")
                            current_tool = fallback_tool
                            used_fallback = True
                            continue
                    
                    # Retry if we haven't exhausted retries
                    if retry_count < context.max_retries:
                        retry_count += 1
                        delay = self.retry_manager.calculate_retry_delay(
                            context.retry_strategy, retry_count, context=context
                        )
                        
                        self.logger.warning(f"Execution failed, retrying in {delay}s (attempt {retry_count})")
                        await asyncio.sleep(delay)
                        continue
                    
                    else:
                        # Max retries exceeded
                        self._update_global_stats(False, result.execution_time, used_fallback)
                        
                        return ExecutionResult(
                            execution_id=context.execution_id,
                            tool_name=current_tool,
                            status=ExecutionStatus.FAILED,
                            start_time=start_time,
                            end_time=datetime.now(),
                            execution_time=result.execution_time,
                            exit_code=result.exit_code,
                            stdout=result.stdout,
                            stderr=result.stderr,
                            error_message=f"Max retries exceeded. Last error: {result.stderr}",
                            retry_count=retry_count,
                            used_fallback=used_fallback,
                            metadata={'original_tool': context.tool_name, 'failure_type': failure_type.value}
                        )
            
            except asyncio.TimeoutError:
                failure_type = FailureType.TIMEOUT
                self._update_tool_metrics(current_tool, context.timeout, False, failure_type.value)
                
                if retry_count < context.max_retries:
                    retry_count += 1
                    # Increase timeout for retry
                    context.timeout = int(context.timeout * 1.5)
                    continue
                
                return self._create_timeout_result(context, start_time, retry_count, used_fallback)
            
            except Exception as e:
                failure_type = FailureType.UNKNOWN_ERROR
                self._update_tool_metrics(current_tool, 0, False, failure_type.value)
                
                if retry_count < context.max_retries:
                    retry_count += 1
                    delay = self.retry_manager.calculate_retry_delay(
                        context.retry_strategy, retry_count, context=context
                    )
                    await asyncio.sleep(delay)
                    continue
                
                return self._create_error_result(context, start_time, str(e), retry_count, used_fallback)
        
        # Should never reach here
        return self._create_error_result(context, start_time, "Unknown execution error", retry_count, used_fallback)
    
    async def _execute_single_tool(self, tool_name: str, command: str, timeout: int) -> Dict[str, Any]:
        """Execute a single tool command."""
        start_time = time.time()
        
        try:
            # Create subprocess
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Wait for completion with timeout
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            
            execution_time = time.time() - start_time
            
            return {
                'exit_code': process.returncode,
                'stdout': stdout.decode('utf-8', errors='replace'),
                'stderr': stderr.decode('utf-8', errors='replace'),
                'execution_time': execution_time
            }
        
        except asyncio.TimeoutError:
            # Kill the process
            try:
                process.kill()
                await process.wait()
            except:
                pass
            
            execution_time = time.time() - start_time
            raise asyncio.TimeoutError(f"Tool execution timed out after {timeout}s")
        
        except Exception as e:
            execution_time = time.time() - start_time
            return {
                'exit_code': -1,
                'stdout': '',
                'stderr': str(e),
                'execution_time': execution_time
            }
    
    def _is_successful_execution(self, result: Dict[str, Any]) -> bool:
        """Determine if execution was successful."""
        # Check exit code
        if result.get('exit_code', -1) != 0:
            return False
        
        # Check for common error patterns in stderr
        stderr = result.get('stderr', '').lower()
        error_patterns = [
            'command not found',
            'permission denied',
            'no such file or directory',
            'connection refused',
            'timeout',
            'error'
        ]
        
        for pattern in error_patterns:
            if pattern in stderr:
                return False
        
        return True
    
    def _classify_failure(self, result: Dict[str, Any]) -> FailureType:
        """Classify the type of failure."""
        stderr = result.get('stderr', '').lower()
        exit_code = result.get('exit_code', -1)
        
        if 'timeout' in stderr or exit_code == 124:  # timeout command exit code
            return FailureType.TIMEOUT
        
        elif 'connection refused' in stderr or 'network unreachable' in stderr:
            return FailureType.NETWORK_ERROR
        
        elif 'permission denied' in stderr or 'access denied' in stderr:
            return FailureType.PERMISSION_ERROR
        
        elif 'command not found' in stderr or 'not found' in stderr:
            return FailureType.TOOL_NOT_FOUND
        
        elif 'authentication failed' in stderr or 'login failed' in stderr:
            return FailureType.AUTHENTICATION_ERROR
        
        elif 'no space left' in stderr or 'resource temporarily unavailable' in stderr:
            return FailureType.RESOURCE_ERROR
        
        else:
            return FailureType.UNKNOWN_ERROR
    
    async def _check_resource_limits(self, context: ExecutionContext) -> bool:
        """Check if execution respects resource limits."""
        # Check concurrent execution limit
        if self.current_executions >= self.max_concurrent_executions:
            return False
        
        # Check tool-specific resource limits
        limits = context.resource_limits
        if limits:
            # Memory limit check would go here
            # CPU limit check would go here
            # Network limit check would go here
            pass
        
        return True
    
    def _update_tool_metrics(self, tool_name: str, execution_time: float, 
                           success: bool, failure_type: Optional[str] = None):
        """Update tool performance metrics."""
        if tool_name not in self.tool_metrics:
            self.tool_metrics[tool_name] = ExecutionMetrics(tool_name=tool_name)
        
        self.tool_metrics[tool_name].update_metrics(execution_time, success, failure_type)
    
    def _update_global_stats(self, success: bool, execution_time: float, used_fallback: bool):
        """Update global execution statistics."""
        self.global_stats['total_executions'] += 1
        
        if success:
            self.global_stats['successful_executions'] += 1
        else:
            self.global_stats['failed_executions'] += 1
        
        # Update average execution time
        total = self.global_stats['total_executions']
        current_avg = self.global_stats['average_execution_time']
        self.global_stats['average_execution_time'] = (
            (current_avg * (total - 1) + execution_time) / total
        )
        
        # Update fallback usage rate
        if used_fallback:
            fallback_count = self.global_stats.get('fallback_usage_count', 0) + 1
            self.global_stats['fallback_usage_count'] = fallback_count
            self.global_stats['fallback_usage_rate'] = fallback_count / total
    
    def _create_timeout_result(self, context: ExecutionContext, start_time: datetime, 
                             retry_count: int, used_fallback: bool) -> ExecutionResult:
        """Create timeout execution result."""
        return ExecutionResult(
            execution_id=context.execution_id,
            tool_name=context.tool_name,
            status=ExecutionStatus.TIMEOUT,
            start_time=start_time,
            end_time=datetime.now(),
            execution_time=context.timeout,
            exit_code=None,
            stdout='',
            stderr='Execution timed out',
            error_message=f'Execution timed out after {context.timeout}s',
            retry_count=retry_count,
            used_fallback=used_fallback,
            metadata={'original_tool': context.tool_name}
        )
    
    def _create_error_result(self, context: ExecutionContext, start_time: datetime,
                           error_message: str, retry_count: int, used_fallback: bool) -> ExecutionResult:
        """Create error execution result."""
        return ExecutionResult(
            execution_id=context.execution_id,
            tool_name=context.tool_name,
            status=ExecutionStatus.FAILED,
            start_time=start_time,
            end_time=datetime.now(),
            execution_time=0.0,
            exit_code=-1,
            stdout='',
            stderr=error_message,
            error_message=error_message,
            retry_count=retry_count,
            used_fallback=used_fallback,
            metadata={'original_tool': context.tool_name}
        )
    
    def get_tool_metrics(self, tool_name: str) -> Optional[ExecutionMetrics]:
        """Get performance metrics for a tool."""
        return self.tool_metrics.get(tool_name)
    
    def get_global_statistics(self) -> Dict[str, Any]:
        """Get global execution statistics."""
        stats = self.global_stats.copy()
        
        # Add tool-specific stats
        stats['tool_count'] = len(self.tool_metrics)
        stats['top_performing_tools'] = []
        
        if self.tool_metrics:
            # Sort tools by performance score
            sorted_tools = sorted(
                self.tool_metrics.items(),
                key=lambda x: x[1].performance_score,
                reverse=True
            )
            
            stats['top_performing_tools'] = [
                {
                    'tool_name': tool,
                    'performance_score': metrics.performance_score,
                    'reliability_score': metrics.reliability_score,
                    'success_rate': metrics.average_success_rate,
                    'avg_execution_time': metrics.average_execution_time
                }
                for tool, metrics in sorted_tools[:5]
            ]
        
        return stats
    
    def get_execution_recommendations(self, operation_type: str) -> List[str]:
        """Get tool recommendations based on performance."""
        recommendations = []
        
        # Filter tools by capability
        capable_tools = []
        for tool_name, metrics in self.tool_metrics.items():
            if metrics.performance_score > 0.6 and metrics.reliability_score > 0.7:
                capable_tools.append((tool_name, metrics.performance_score))
        
        # Sort by performance
        capable_tools.sort(key=lambda x: x[1], reverse=True)
        
        # Return top recommendations
        return [tool for tool, _ in capable_tools[:3]]


class ResourceError(Exception):
    """Resource limit exceeded error."""
    pass


# Global instance for easy access
execution_engine = AdaptiveExecutionEngine()
