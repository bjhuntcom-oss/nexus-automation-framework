"""
Distributed Orchestration Layer - Task Queue & Worker Management

Distributed task orchestration with Redis/Kafka-style queue concepts,
horizontal worker nodes, tenant isolation, resource limiting,
concurrency control, and idempotency guarantees.

Features:
- Distributed task queue management
- Horizontal worker scaling
- Tenant isolation and multi-tenancy
- Resource limiting and quotas
- Concurrency control
- Task deduplication and idempotency
- Fault tolerance and recovery
- Load balancing
"""

import asyncio
import json
import logging
import time
import uuid
from typing import Dict, List, Optional, Set, Tuple, Any, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from collections import defaultdict, deque
import hashlib
import pickle
import threading
import random
from concurrent.futures import ThreadPoolExecutor
import queue as thread_queue

# Internal imports
from .execution import execution_engine


class TaskStatus(Enum):
    """Task execution status."""
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"
    RETRYING = "retrying"


class TaskPriority(Enum):
    """Task priority levels."""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4
    URGENT = 5


class TaskType(Enum):
    """Types of tasks."""
    SCAN = "scan"
    EXPLOIT = "exploit"
    ENUMERATION = "enumeration"
    ANALYSIS = "analysis"
    CORRELATION = "correlation"
    REPORTING = "reporting"
    CLEANUP = "cleanup"


@dataclass
class TaskDefinition:
    """Task definition with metadata."""
    task_id: str
    task_type: TaskType
    task_name: str
    payload: Dict[str, Any]
    priority: TaskPriority
    tenant_id: str
    user_id: str
    created_at: datetime = field(default_factory=datetime.now)
    scheduled_at: Optional[datetime] = None
    timeout: int = 300
    max_retries: int = 3
    retry_delay: int = 60
    dependencies: List[str] = field(default_factory=list)
    tags: Set[str] = field(default_factory=set)
    resource_requirements: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'task_id': self.task_id,
            'task_type': self.task_type.value,
            'task_name': self.task_name,
            'payload': self.payload,
            'priority': self.priority.value,
            'tenant_id': self.tenant_id,
            'user_id': self.user_id,
            'created_at': self.created_at.isoformat(),
            'scheduled_at': self.scheduled_at.isoformat() if self.scheduled_at else None,
            'timeout': self.timeout,
            'max_retries': self.max_retries,
            'retry_delay': self.retry_delay,
            'dependencies': self.dependencies,
            'tags': list(self.tags),
            'resource_requirements': self.resource_requirements,
            'metadata': self.metadata
        }


@dataclass
class TaskResult:
    """Result of task execution."""
    task_id: str
    status: TaskStatus
    started_at: datetime
    completed_at: Optional[datetime]
    execution_time: float
    worker_id: str
    result_data: Optional[Dict[str, Any]]
    error_message: Optional[str]
    retry_count: int
    logs: List[str] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'task_id': self.task_id,
            'status': self.status.value,
            'started_at': self.started_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'execution_time': self.execution_time,
            'worker_id': self.worker_id,
            'result_data': self.result_data,
            'error_message': self.error_message,
            'retry_count': self.retry_count,
            'logs': self.logs,
            'metrics': self.metrics
        }


@dataclass
class WorkerNode:
    """Worker node definition."""
    worker_id: str
    hostname: str
    capabilities: Set[str]
    max_concurrent_tasks: int
    current_tasks: int = 0
    status: str = "active"
    last_heartbeat: datetime = field(default_factory=datetime.now)
    resource_usage: Dict[str, float] = field(default_factory=dict)
    tenant_restrictions: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def can_execute_task(self, task: TaskDefinition) -> bool:
        """Check if worker can execute task."""
        # Check capacity
        if self.current_tasks >= self.max_concurrent_tasks:
            return False
        
        # Check capabilities
        required_caps = task.resource_requirements.get('capabilities', [])
        if not all(cap in self.capabilities for cap in required_caps):
            return False
        
        # Check tenant restrictions
        if self.tenant_restrictions and task.tenant_id not in self.tenant_restrictions:
            return False
        
        # Check resource availability
        for resource, required in task.resource_requirements.get('resources', {}).items():
            available = self.resource_usage.get(resource, 0.0)
            if available + required > 1.0:  # Assume resources are normalized 0-1
                return False
        
        return True


class TaskQueue:
    """In-memory task queue with priority ordering."""
    
    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self._queues = {
            priority: deque() for priority in TaskPriority
        }
        self._task_lookup: Dict[str, TaskDefinition] = {}
        self._lock = threading.RLock()
    
    def enqueue(self, task: TaskDefinition) -> bool:
        """Add task to queue."""
        with self._lock:
            if len(self._task_lookup) >= self.max_size:
                return False
            
            # Check for duplicates
            if task.task_id in self._task_lookup:
                return False
            
            # Add to appropriate priority queue
            self._queues[task.priority].append(task)
            self._task_lookup[task.task_id] = task
            
            return True
    
    def dequeue(self, worker_capabilities: Set[str], tenant_id: Optional[str] = None) -> Optional[TaskDefinition]:
        """Get next task for worker."""
        with self._lock:
            # Check queues in priority order
            for priority in sorted(TaskPriority, key=lambda x: x.value, reverse=True):
                queue = self._queues[priority]
                
                # Find suitable task
                for i, task in enumerate(queue):
                    # Check tenant compatibility
                    if tenant_id and task.tenant_id != tenant_id:
                        continue
                    
                    # Check worker capabilities
                    required_caps = task.resource_requirements.get('capabilities', [])
                    if all(cap in worker_capabilities for cap in required_caps):
                        # Remove from queue and lookup
                        queue.remove(task)
                        del self._task_lookup[task.task_id]
                        return task
            
            return None
    
    def peek(self, count: int = 10) -> List[TaskDefinition]:
        """Peek at next tasks without removing them."""
        with self._lock:
            tasks = []
            for priority in sorted(TaskPriority, key=lambda x: x.value, reverse=True):
                queue = self._queues[priority]
                tasks.extend(list(queue)[:count - len(tasks)])
                if len(tasks) >= count:
                    break
            return tasks
    
    def get_task(self, task_id: str) -> Optional[TaskDefinition]:
        """Get task by ID."""
        with self._lock:
            return self._task_lookup.get(task_id)
    
    def remove_task(self, task_id: str) -> bool:
        """Remove task from queue."""
        with self._lock:
            if task_id not in self._task_lookup:
                return False
            
            task = self._task_lookup[task_id]
            queue = self._queues[task.priority]
            
            if task in queue:
                queue.remove(task)
            del self._task_lookup[task_id]
            
            return True
    
    def size(self) -> int:
        """Get total queue size."""
        with self._lock:
            return len(self._task_lookup)
    
    def size_by_priority(self) -> Dict[str, int]:
        """Get queue size by priority."""
        with self._lock:
            return {priority.name: len(queue) for priority, queue in self._queues.items()}


class ResourceManager:
    """Manages resource allocation and limits."""
    
    def __init__(self):
        self.global_limits = {
            'cpu': 100.0,  # Percentage
            'memory': 100.0,  # Percentage
            'network': 100.0,  # Percentage
            'disk': 100.0  # Percentage
        }
        
        self.tenant_limits: Dict[str, Dict[str, float]] = {}
        self.tenant_usage: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self.worker_resources: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
    
    def set_tenant_limits(self, tenant_id: str, limits: Dict[str, float]):
        """Set resource limits for tenant."""
        self.tenant_limits[tenant_id] = limits
    
    def can_allocate_resources(self, tenant_id: str, worker_id: str, 
                             requirements: Dict[str, float]) -> bool:
        """Check if resources can be allocated."""
        # Check global limits
        for resource, required in requirements.items():
            if resource not in self.global_limits:
                continue
            
            global_usage = sum(
                self.worker_resources[w].get(resource, 0.0) 
                for w in self.worker_resources
            )
            
            if global_usage + required > self.global_limits[resource]:
                return False
        
        # Check tenant limits
        if tenant_id in self.tenant_limits:
            for resource, required in requirements.items():
                if resource not in self.tenant_limits[tenant_id]:
                    continue
                
                if (self.tenant_usage[tenant_id][resource] + required > 
                    self.tenant_limits[tenant_id][resource]):
                    return False
        
        return True
    
    def allocate_resources(self, tenant_id: str, worker_id: str, 
                          resources: Dict[str, float]):
        """Allocate resources to task."""
        for resource, amount in resources.items():
            self.tenant_usage[tenant_id][resource] += amount
            self.worker_resources[worker_id][resource] += amount
    
    def release_resources(self, tenant_id: str, worker_id: str, 
                         resources: Dict[str, float]):
        """Release allocated resources."""
        for resource, amount in resources.items():
            self.tenant_usage[tenant_id][resource] -= amount
            self.worker_resources[worker_id][resource] -= amount
            
            # Ensure non-negative
            self.tenant_usage[tenant_id][resource] = max(0, self.tenant_usage[tenant_id][resource])
            self.worker_resources[worker_id][resource] = max(0, self.worker_resources[worker_id][resource])
    
    def get_usage_statistics(self) -> Dict[str, Any]:
        """Get resource usage statistics."""
        return {
            'global_usage': {
                resource: sum(
                    self.worker_resources[w].get(resource, 0.0) 
                    for w in self.worker_resources
                )
                for resource in self.global_limits
            },
            'tenant_usage': dict(self.tenant_usage),
            'worker_usage': dict(self.worker_resources)
        }


class DistributedOrchestrator:
    """Main distributed orchestration engine."""
    
    def __init__(self):
        self.logger = logging.getLogger("distributed_orchestrator")
        
        # Core components
        self.task_queue = TaskQueue()
        self.resource_manager = ResourceManager()
        
        # Worker management
        self.workers: Dict[str, WorkerNode] = {}
        self.worker_tasks: Dict[str, Set[str]] = defaultdict(set)  # worker_id -> task_ids
        
        # Task tracking
        self.active_tasks: Dict[str, TaskDefinition] = {}
        self.task_results: Dict[str, TaskResult] = {}
        self.task_dependencies: Dict[str, Set[str]] = defaultdict(set)
        
        # Concurrency control
        self.max_concurrent_tasks = 100
        self.current_task_count = 0
        
        # Background processing
        self._scheduler_running = False
        self._scheduler_thread: Optional[threading.Thread] = None
        self._executor = ThreadPoolExecutor(max_workers=10)
        
        # Statistics
        self.stats = {
            'total_tasks': 0,
            'completed_tasks': 0,
            'failed_tasks': 0,
            'average_execution_time': 0.0,
            'queue_size': 0,
            'active_workers': 0
        }
        
        # Task callbacks
        self.on_task_complete_callbacks: List[Callable[[TaskResult], Any]] = []
    
    def start(self):
        """Start the orchestrator."""
        if not self._scheduler_running:
            self._scheduler_running = True
            self._scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
            self._scheduler_thread.start()
            self.logger.info("Distributed orchestrator started")
    
    def stop(self):
        """Stop the orchestrator."""
        self._scheduler_running = False
        if self._scheduler_thread:
            self._scheduler_thread.join(timeout=5)
        self._executor.shutdown(wait=True)
        self.logger.info("Distributed orchestrator stopped")
    
    def register_worker(self, worker: WorkerNode) -> bool:
        """Register a new worker node."""
        if worker.worker_id in self.workers:
            return False
        
        self.workers[worker.worker_id] = worker
        self.logger.info(f"Registered worker {worker.worker_id} with capabilities {worker.capabilities}")
        return True
    
    def unregister_worker(self, worker_id: str) -> bool:
        """Unregister a worker node."""
        if worker_id not in self.workers:
            return False
        
        # Cancel active tasks
        active_task_ids = self.worker_tasks[worker_id].copy()
        for task_id in active_task_ids:
            self.cancel_task(task_id)
        
        del self.workers[worker_id]
        del self.worker_tasks[worker_id]
        
        self.logger.info(f"Unregistered worker {worker_id}")
        return True
    
    def submit_task(self, task: TaskDefinition) -> bool:
        """Submit a new task for execution."""
        # Validate task
        if not self._validate_task(task):
            return False
        
        # Check dependencies
        if not self._check_dependencies(task):
            return False
        
        # Add to queue
        if self.task_queue.enqueue(task):
            self.stats['total_tasks'] += 1
            self.logger.info(f"Submitted task {task.task_id} of type {task.task_type.value}")
            return True
        
        return False
    
    def cancel_task(self, task_id: str) -> bool:
        """Cancel a task."""
        # Remove from queue if pending
        if self.task_queue.remove_task(task_id):
            return True
        
        # Cancel if running
        if task_id in self.active_tasks:
            task = self.active_tasks[task_id]
            
            # Find worker and cancel
            for worker_id, task_ids in self.worker_tasks.items():
                if task_id in task_ids:
                    self._cancel_worker_task(worker_id, task_id)
                    break
            
            # Mark as cancelled
            result = TaskResult(
                task_id=task_id,
                status=TaskStatus.CANCELLED,
                started_at=datetime.now(),
                completed_at=datetime.now(),
                execution_time=0.0,
                worker_id="",
                result_data=None,
                error_message="Task cancelled",
                retry_count=0
            )
            
            self.task_results[task_id] = result
            del self.active_tasks[task_id]
            
            return True
        
        return False
    
    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get task status."""
        # Check if in queue
        task = self.task_queue.get_task(task_id)
        if task:
            return {
                'task_id': task_id,
                'status': TaskStatus.QUEUED.value,
                'task': task.to_dict()
            }
        
        # Check if active
        if task_id in self.active_tasks:
            task = self.active_tasks[task_id]
            return {
                'task_id': task_id,
                'status': TaskStatus.RUNNING.value,
                'task': task.to_dict()
            }
        
        # Check if completed
        if task_id in self.task_results:
            result = self.task_results[task_id]
            return {
                'task_id': task_id,
                'status': result.status.value,
                'result': result.to_dict()
            }
        
        return None
    
    def get_queue_statistics(self) -> Dict[str, Any]:
        """Get queue statistics."""
        return {
            'queue_size': self.task_queue.size(),
            'queue_by_priority': self.task_queue.size_by_priority(),
            'active_tasks': len(self.active_tasks),
            'completed_tasks': len(self.task_results),
            'active_workers': len(self.workers),
            'worker_status': {
                worker_id: {
                    'status': worker.status,
                    'current_tasks': worker.current_tasks,
                    'max_concurrent_tasks': worker.max_concurrent_tasks
                }
                for worker_id, worker in self.workers.items()
            }
        }
    
    def _validate_task(self, task: TaskDefinition) -> bool:
        """Validate task definition."""
        # Check required fields
        if not task.task_id or not task.task_name or not task.tenant_id:
            return False
        
        # Check timeout
        if task.timeout <= 0 or task.timeout > 7200:  # Max 2 hours
            return False
        
        # Check resource requirements
        for resource, amount in task.resource_requirements.get('resources', {}).items():
            if amount < 0 or amount > 1.0:
                return False
        
        return True
    
    def _check_dependencies(self, task: TaskDefinition) -> bool:
        """Check if task dependencies are satisfied."""
        for dep_id in task.dependencies:
            if dep_id not in self.task_results:
                return False
            
            result = self.task_results[dep_id]
            if result.status != TaskStatus.COMPLETED:
                return False
        
        return True
    
    def _scheduler_loop(self):
        """Main scheduler loop."""
        while self._scheduler_running:
            try:
                self._schedule_tasks()
                self._cleanup_completed_tasks()
                self._check_worker_heartbeats()
                time.sleep(1)  # Schedule every second
            except Exception as e:
                self.logger.error(f"Scheduler loop error: {e}")
    
    def _schedule_tasks(self):
        """Schedule pending tasks to available workers."""
        # Get available workers
        available_workers = [
            worker for worker in self.workers.values()
            if worker.status == "active" and worker.current_tasks < worker.max_concurrent_tasks
        ]
        
        if not available_workers:
            return
        
        # Sort workers by current load (least loaded first)
        available_workers.sort(key=lambda w: w.current_tasks / w.max_concurrent_tasks)
        
        # Try to schedule tasks
        for worker in available_workers:
            if self.current_task_count >= self.max_concurrent_tasks:
                break
            
            # Get next suitable task
            task = self.task_queue.dequeue(worker.capabilities)
            if not task:
                continue
            
            # Check resource availability
            if not self.resource_manager.can_allocate_resources(
                task.tenant_id, worker.worker_id, 
                task.resource_requirements.get('resources', {})
            ):
                # Put task back and continue
                self.task_queue.enqueue(task)
                continue
            
            # Execute task
            self._execute_task_on_worker(worker, task)
    
    def _execute_task_on_worker(self, worker: WorkerNode, task: TaskDefinition):
        """Execute task on worker."""
        # Update worker state
        worker.current_tasks += 1
        self.worker_tasks[worker.worker_id].add(task.task_id)
        
        # Update active tasks
        self.active_tasks[task.task_id] = task
        self.current_task_count += 1
        
        # Allocate resources
        self.resource_manager.allocate_resources(
            task.tenant_id, worker.worker_id,
            task.resource_requirements.get('resources', {})
        )
        
        # Submit to worker (simulated)
        self._executor.submit(self._run_task, worker, task)
        
        self.logger.info(f"Executing task {task.task_id} on worker {worker.worker_id}")
    
    def _run_task(self, worker: WorkerNode, task: TaskDefinition):
        """Run task execution using the adaptive execution engine."""
        start_time = datetime.now()
        
        try:
            # Get tool and command from payload
            tool_name = task.payload.get('tool_name', 'generic_shell')
            command = task.payload.get('command')
            
            if not command:
                error_message = f"No command provided in task payload for task {task.task_id}"
                self.logger.error(error_message)
                status = TaskStatus.FAILED
                result_data = None
                execution_time = 0.0
            else:
                # Use execution engine (must run async)
                # Since we are in a ThreadPoolExecutor thread, we use a temporary event loop
                self.logger.info(f"Worker {worker.worker_id} executing: {command}")
                
                try:
                    # Initialize a new event loop for this thread if needed
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    
                    try:
                        # Execute the tool via the adaptive execution engine
                        execution_result = loop.run_until_complete(
                            execution_engine.execute_tool(
                                tool_name=tool_name,
                                command=command,
                                timeout=task.timeout
                            )
                        )
                        
                        # Map execution result to task outcome
                        execution_time = execution_result.execution_time
                        
                        if execution_result.status.value == "completed":
                            status = TaskStatus.COMPLETED
                            result_data = {
                                'stdout': execution_result.stdout,
                                'stderr': execution_result.stderr,
                                'exit_code': execution_result.exit_code,
                                'metrics': execution_result.metrics
                            }
                            error_message = None
                        elif execution_result.status.value == "timeout":
                            status = TaskStatus.TIMEOUT
                            result_data = {
                                'stdout': execution_result.stdout,
                                'stderr': execution_result.stderr,
                                'exit_code': execution_result.exit_code
                            }
                            error_message = "Task execution timed out"
                        else:
                            status = TaskStatus.FAILED
                            result_data = {
                                'stdout': execution_result.stdout,
                                'stderr': execution_result.stderr,
                                'exit_code': execution_result.exit_code
                            }
                            error_message = execution_result.error_message or "Execution failed"
                            
                    finally:
                        loop.close()
                        
                except Exception as e:
                    self.logger.exception(f"Exception during task execution: {e}")
                    status = TaskStatus.FAILED
                    result_data = None
                    error_message = str(e)
                    execution_time = (datetime.now() - start_time).total_seconds()
            
            # Create result
            result = TaskResult(
                task_id=task.task_id,
                status=status,
                started_at=start_time,
                completed_at=datetime.now(),
                execution_time=execution_time,
                worker_id=worker.worker_id,
                result_data=result_data,
                error_message=error_message,
                retry_count=0  # Execution engine handles retries internally
            )
            
            # Store result
            self.task_results[task.task_id] = result
            
        except Exception as e:
            # Handle unexpected errors in the runner itself
            self.logger.exception(f"Critical error in _run_task: {e}")
            result = TaskResult(
                task_id=task.task_id,
                status=TaskStatus.FAILED,
                started_at=start_time,
                completed_at=datetime.now(),
                execution_time=0.0,
                worker_id=worker.worker_id,
                result_data=None,
                error_message=str(e),
                retry_count=0
            )
            
            self.task_results[task.task_id] = result
        
        finally:
            # Trigger callbacks
            for callback in self.on_task_complete_callbacks:
                try:
                    callback(result)
                except Exception as e:
                    self.logger.error(f"Error in task completion callback: {e}")
                    
            # Cleanup
            self._cleanup_task_execution(worker, task)
    
    def _cleanup_task_execution(self, worker: WorkerNode, task: TaskDefinition):
        """Cleanup after task execution."""
        # Update worker state
        worker.current_tasks -= 1
        self.worker_tasks[worker.worker_id].discard(task.task_id)
        
        # Remove from active tasks
        self.active_tasks.pop(task.task_id, None)
        self.current_task_count -= 1
        
        # Release resources
        self.resource_manager.release_resources(
            task.tenant_id, worker.worker_id,
            task.resource_requirements.get('resources', {})
        )
        
        # Update statistics
        result = self.task_results.get(task.task_id)
        if result:
            if result.status == TaskStatus.COMPLETED:
                self.stats['completed_tasks'] += 1
            else:
                self.stats['failed_tasks'] += 1
            
            # Update average execution time
            total_completed = self.stats['completed_tasks']
            if total_completed > 0:
                current_avg = self.stats['average_execution_time']
                self.stats['average_execution_time'] = (
                    (current_avg * (total_completed - 1) + result.execution_time) / total_completed
                )
    
    def _cleanup_completed_tasks(self):
        """Cleanup old completed tasks."""
        cutoff_time = datetime.now() - timedelta(hours=24)
        
        # Remove old results
        old_tasks = [
            task_id for task_id, result in self.task_results.items()
            if result.completed_at and result.completed_at < cutoff_time
        ]
        
        for task_id in old_tasks:
            del self.task_results[task_id]
    
    def _check_worker_heartbeats(self):
        """Check worker heartbeats and mark inactive workers."""
        cutoff_time = datetime.now() - timedelta(minutes=5)
        
        for worker_id, worker in self.workers.items():
            if worker.last_heartbeat < cutoff_time:
                worker.status = "inactive"
                self.logger.warning(f"Worker {worker_id} marked as inactive (no heartbeat)")
    
    def _cancel_worker_task(self, worker_id: str, task_id: str):
        """Cancel task on worker (simulated)."""
        # In a real implementation, this would send a cancellation signal to the worker
        self.logger.info(f"Cancelling task {task_id} on worker {worker_id}")


# Global orchestrator instance
orchestrator = DistributedOrchestrator()
