"""
Multi-Agent Infrastructure - Base Classes, Registry, Message Bus

Foundation for the 37-agent pentest architecture.
Implements the Supervisor Pattern with MCP tool integration.

Architecture:
    Claude (MCP Client)
        -> AgentOrchestrator (supervisor)
            -> MessageBus (async inter-agent communication)
            -> AgentRegistry (discovery + lifecycle)
            -> BaseAgent subclasses (specialized agents)

Features:
    - Abstract BaseAgent with lifecycle management
    - AgentRegistry with hot-reload and health monitoring
    - Async MessageBus with pub/sub + direct messaging
    - AgentOrchestrator with task decomposition
    - Full audit trail for every agent action
"""

import asyncio
import json
import logging
import uuid
import time
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Set, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from collections import defaultdict, deque
import traceback


# ══════════════════════════════════════════════════════════════════════════════
# ENUMS & DATA STRUCTURES
# ══════════════════════════════════════════════════════════════════════════════

class AgentStatus(Enum):
    """Agent lifecycle status."""
    INITIALIZING = "initializing"
    READY = "ready"
    BUSY = "busy"
    PAUSED = "paused"
    ERROR = "error"
    TERMINATED = "terminated"


class AgentCategory(Enum):
    """Agent categories from the architecture doc."""
    INFRASTRUCTURE = "infrastructure"
    RECONNAISSANCE = "reconnaissance"
    ACQUISITION = "acquisition"
    ANALYSIS = "analysis"
    VULNERABILITY = "vulnerability"
    SPECIALIST = "specialist"
    EXPLOITATION = "exploitation"
    INTELLIGENCE = "intelligence"


class MessagePriority(Enum):
    """Message priority levels."""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4
    URGENT = 5


class MessageType(Enum):
    """Types of inter-agent messages."""
    TASK = "task"             # Task assignment
    RESULT = "result"         # Task result
    EVENT = "event"           # Event notification
    QUERY = "query"           # Information request
    RESPONSE = "response"     # Query response
    COMMAND = "command"       # Control command (pause, resume, etc.)
    HEARTBEAT = "heartbeat"   # Health check
    ALERT = "alert"           # Security/anomaly alert


@dataclass
class AgentMessage:
    """Inter-agent message."""
    message_id: str
    message_type: MessageType
    sender: str
    recipient: str  # Agent ID or "broadcast" or topic name
    priority: MessagePriority
    payload: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)
    correlation_id: Optional[str] = None  # For request-response pairing
    ttl: int = 300  # Time-to-live in seconds
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'message_id': self.message_id,
            'message_type': self.message_type.value,
            'sender': self.sender,
            'recipient': self.recipient,
            'priority': self.priority.value,
            'payload': self.payload,
            'timestamp': self.timestamp.isoformat(),
            'correlation_id': self.correlation_id,
            'ttl': self.ttl,
            'metadata': self.metadata,
        }


@dataclass
class AgentCapability:
    """Describes what an agent can do."""
    name: str
    description: str
    input_schema: Dict[str, Any] = field(default_factory=dict)
    output_schema: Dict[str, Any] = field(default_factory=dict)
    estimated_duration: float = 30.0  # seconds
    risk_level: int = 1  # 1-5
    requires_tools: List[str] = field(default_factory=list)


@dataclass
class AgentMetrics:
    """Runtime metrics for an agent."""
    tasks_completed: int = 0
    tasks_failed: int = 0
    total_execution_time: float = 0.0
    avg_execution_time: float = 0.0
    last_active: Optional[datetime] = None
    error_count: int = 0
    messages_sent: int = 0
    messages_received: int = 0


# ══════════════════════════════════════════════════════════════════════════════
# BASE AGENT
# ══════════════════════════════════════════════════════════════════════════════

class BaseAgent(ABC):
    """Abstract base class for all pentest agents.
    
    Every agent in the system inherits from this.
    Provides:
        - Lifecycle management (init, start, stop, pause, resume)
        - Message bus integration (send/receive messages)
        - Capability declaration
        - Metrics tracking
        - Structured logging
        - Error handling with recovery
    
    Subclasses must implement:
        - _initialize(): Setup agent-specific resources
        - _execute_task(): Core logic for handling tasks
        - capabilities: Property returning agent capabilities
    """

    def __init__(self, agent_id: str, name: str, category: AgentCategory,
                 description: str = ""):
        self.agent_id = agent_id
        self.name = name
        self.category = category
        self.description = description
        self.status = AgentStatus.INITIALIZING
        self.logger = logging.getLogger(f"agent.{agent_id}")
        self.metrics = AgentMetrics()
        self.created_at = datetime.now()
        
        # Message handling
        self._message_queue: asyncio.Queue = asyncio.Queue()
        self._message_handlers: Dict[MessageType, Callable] = {}
        self._subscribed_topics: Set[str] = set()
        
        # References (set by registry/orchestrator)
        self._message_bus: Optional['MessageBus'] = None
        self._registry: Optional['AgentRegistry'] = None
        
        # Task tracking
        self._current_task: Optional[Dict] = None
        self._task_history: deque = deque(maxlen=100)
        
        # Register default message handlers
        self._register_default_handlers()

    def _register_default_handlers(self):
        """Register default message handlers."""
        self._message_handlers[MessageType.TASK] = self._handle_task_message
        self._message_handlers[MessageType.QUERY] = self._handle_query_message
        self._message_handlers[MessageType.COMMAND] = self._handle_command_message
        self._message_handlers[MessageType.HEARTBEAT] = self._handle_heartbeat

    @property
    @abstractmethod
    def capabilities(self) -> List[AgentCapability]:
        """Declare agent capabilities."""
        ...

    @abstractmethod
    async def _initialize(self):
        """Agent-specific initialization. Called once at startup."""
        ...

    @abstractmethod
    async def _execute_task(self, task_type: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a task. Core agent logic goes here.
        
        Args:
            task_type: The capability name to execute
            params: Task parameters
            
        Returns:
            Result dictionary
        """
        ...

    async def start(self):
        """Start the agent."""
        try:
            await self._initialize()
            self.status = AgentStatus.READY
            self.logger.info(f"Agent {self.name} [{self.agent_id}] started")
        except Exception as e:
            self.status = AgentStatus.ERROR
            self.logger.error(f"Agent {self.name} failed to start: {e}")
            raise

    async def stop(self):
        """Stop the agent gracefully."""
        self.status = AgentStatus.TERMINATED
        self.logger.info(f"Agent {self.name} [{self.agent_id}] stopped")

    async def execute(self, task_type: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a task with metrics tracking and error handling."""
        if self.status not in (AgentStatus.READY, AgentStatus.BUSY):
            raise RuntimeError(f"Agent {self.name} is not ready (status: {self.status.value})")

        self.status = AgentStatus.BUSY
        self._current_task = {"type": task_type, "params": params, "started": datetime.now().isoformat()}
        start_time = time.time()

        try:
            result = await self._execute_task(task_type, params)
            
            # Update metrics
            exec_time = time.time() - start_time
            self.metrics.tasks_completed += 1
            self.metrics.total_execution_time += exec_time
            self.metrics.avg_execution_time = (
                self.metrics.total_execution_time / self.metrics.tasks_completed
            )
            self.metrics.last_active = datetime.now()
            
            # Record in history
            self._task_history.append({
                "task_type": task_type,
                "status": "completed",
                "execution_time": exec_time,
                "timestamp": datetime.now().isoformat(),
            })
            
            self.status = AgentStatus.READY
            return result

        except Exception as e:
            exec_time = time.time() - start_time
            self.metrics.tasks_failed += 1
            self.metrics.error_count += 1
            self.metrics.last_active = datetime.now()
            
            self._task_history.append({
                "task_type": task_type,
                "status": "failed",
                "error": str(e),
                "execution_time": exec_time,
                "timestamp": datetime.now().isoformat(),
            })
            
            self.status = AgentStatus.READY
            self.logger.error(f"Task {task_type} failed: {e}")
            raise

        finally:
            self._current_task = None

    # ── Message handling ─────────────────────────────────────────────────

    async def send_message(self, recipient: str, msg_type: MessageType,
                           payload: Dict[str, Any], 
                           priority: MessagePriority = MessagePriority.NORMAL,
                           correlation_id: str = None):
        """Send a message to another agent or topic."""
        if not self._message_bus:
            self.logger.warning("No message bus connected")
            return
        
        msg = AgentMessage(
            message_id=str(uuid.uuid4()),
            message_type=msg_type,
            sender=self.agent_id,
            recipient=recipient,
            priority=priority,
            payload=payload,
            correlation_id=correlation_id,
        )
        await self._message_bus.publish(msg)
        self.metrics.messages_sent += 1

    async def receive_message(self, message: AgentMessage):
        """Receive and route a message to the appropriate handler."""
        self.metrics.messages_received += 1
        handler = self._message_handlers.get(message.message_type)
        if handler:
            try:
                await handler(message)
            except Exception as e:
                self.logger.error(f"Message handler error: {e}")
        else:
            self.logger.debug(f"No handler for message type {message.message_type}")

    async def _handle_task_message(self, message: AgentMessage):
        """Handle incoming task messages."""
        task_type = message.payload.get("task_type", "")
        params = message.payload.get("params", {})
        try:
            result = await self.execute(task_type, params)
            # Send result back
            await self.send_message(
                message.sender, MessageType.RESULT,
                {"task_type": task_type, "result": result},
                correlation_id=message.message_id,
            )
        except Exception as e:
            await self.send_message(
                message.sender, MessageType.RESULT,
                {"task_type": task_type, "error": str(e)},
                correlation_id=message.message_id,
            )

    async def _handle_query_message(self, message: AgentMessage):
        """Handle query messages. Override in subclasses for custom queries."""
        query = message.payload.get("query", "")
        if query == "status":
            await self.send_message(
                message.sender, MessageType.RESPONSE,
                self.get_status(),
                correlation_id=message.message_id,
            )
        elif query == "capabilities":
            await self.send_message(
                message.sender, MessageType.RESPONSE,
                {"capabilities": [c.__dict__ for c in self.capabilities]},
                correlation_id=message.message_id,
            )

    async def _handle_command_message(self, message: AgentMessage):
        """Handle control commands."""
        command = message.payload.get("command", "")
        if command == "pause":
            self.status = AgentStatus.PAUSED
        elif command == "resume":
            self.status = AgentStatus.READY
        elif command == "stop":
            await self.stop()

    async def _handle_heartbeat(self, message: AgentMessage):
        """Respond to heartbeat."""
        await self.send_message(
            message.sender, MessageType.HEARTBEAT,
            {"status": self.status.value, "timestamp": datetime.now().isoformat()},
            correlation_id=message.message_id,
        )

    # ── Status & info ────────────────────────────────────────────────────

    def get_status(self) -> Dict[str, Any]:
        """Get agent status."""
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "category": self.category.value,
            "status": self.status.value,
            "metrics": {
                "tasks_completed": self.metrics.tasks_completed,
                "tasks_failed": self.metrics.tasks_failed,
                "avg_execution_time": round(self.metrics.avg_execution_time, 2),
                "error_count": self.metrics.error_count,
                "messages_sent": self.metrics.messages_sent,
                "messages_received": self.metrics.messages_received,
            },
            "current_task": self._current_task,
            "uptime": str(datetime.now() - self.created_at),
        }


# ══════════════════════════════════════════════════════════════════════════════
# MESSAGE BUS
# ══════════════════════════════════════════════════════════════════════════════

class MessageBus:
    """Async inter-agent message bus.
    
    Supports:
        - Direct messaging (agent-to-agent)
        - Pub/Sub (topic-based broadcasting)
        - Priority queuing
        - Message TTL and expiry
        - Audit trail
    """

    def __init__(self):
        self.logger = logging.getLogger("message_bus")
        self._subscribers: Dict[str, Set[str]] = defaultdict(set)  # topic -> agent_ids
        self._agents: Dict[str, BaseAgent] = {}  # agent_id -> agent instance
        self._message_log: deque = deque(maxlen=10000)
        self._pending_responses: Dict[str, asyncio.Future] = {}
        self.stats = {
            "total_messages": 0,
            "direct_messages": 0,
            "broadcast_messages": 0,
            "dropped_messages": 0,
        }

    def register_agent(self, agent: BaseAgent):
        """Register an agent with the message bus."""
        self._agents[agent.agent_id] = agent
        agent._message_bus = self
        self.logger.debug(f"Agent {agent.agent_id} registered with message bus")

    def unregister_agent(self, agent_id: str):
        """Unregister an agent."""
        if agent_id in self._agents:
            self._agents[agent_id]._message_bus = None
            del self._agents[agent_id]
            # Remove from all subscriptions
            for topic_subs in self._subscribers.values():
                topic_subs.discard(agent_id)

    def subscribe(self, agent_id: str, topic: str):
        """Subscribe agent to a topic."""
        self._subscribers[topic].add(agent_id)

    def unsubscribe(self, agent_id: str, topic: str):
        """Unsubscribe agent from a topic."""
        self._subscribers[topic].discard(agent_id)

    async def publish(self, message: AgentMessage):
        """Publish a message."""
        self.stats["total_messages"] += 1
        self._message_log.append(message.to_dict())

        if message.recipient == "broadcast":
            # Broadcast to all agents except sender
            self.stats["broadcast_messages"] += 1
            for agent_id, agent in self._agents.items():
                if agent_id != message.sender:
                    await self._deliver(agent, message)

        elif message.recipient.startswith("topic:"):
            # Topic-based pub/sub
            topic = message.recipient[6:]  # Remove "topic:" prefix
            subscribers = self._subscribers.get(topic, set())
            self.stats["broadcast_messages"] += 1
            for sub_id in subscribers:
                if sub_id in self._agents and sub_id != message.sender:
                    await self._deliver(self._agents[sub_id], message)

        else:
            # Direct message
            self.stats["direct_messages"] += 1
            target = self._agents.get(message.recipient)
            if target:
                await self._deliver(target, message)
            else:
                self.stats["dropped_messages"] += 1
                self.logger.warning(f"Agent {message.recipient} not found, message dropped")

    async def _deliver(self, agent: BaseAgent, message: AgentMessage):
        """Deliver message to an agent."""
        try:
            await agent.receive_message(message)
        except Exception as e:
            self.logger.error(f"Failed to deliver to {agent.agent_id}: {e}")

    async def request_response(self, sender_id: str, recipient_id: str,
                               msg_type: MessageType, payload: Dict,
                               timeout: float = 30.0) -> Optional[Dict]:
        """Send a message and wait for response (request-response pattern)."""
        correlation_id = str(uuid.uuid4())
        future = asyncio.get_running_loop().create_future()
        self._pending_responses[correlation_id] = future

        msg = AgentMessage(
            message_id=str(uuid.uuid4()),
            message_type=msg_type,
            sender=sender_id,
            recipient=recipient_id,
            priority=MessagePriority.NORMAL,
            payload=payload,
            correlation_id=correlation_id,
        )
        await self.publish(msg)

        try:
            result = await asyncio.wait_for(future, timeout=timeout)
            return result
        except asyncio.TimeoutError:
            self.logger.warning(f"Response timeout for {correlation_id}")
            return None
        finally:
            self._pending_responses.pop(correlation_id, None)

    def get_statistics(self) -> Dict[str, Any]:
        """Get message bus stats."""
        return {
            **self.stats,
            "registered_agents": len(self._agents),
            "active_topics": len(self._subscribers),
            "pending_responses": len(self._pending_responses),
            "log_size": len(self._message_log),
        }


# ══════════════════════════════════════════════════════════════════════════════
# AGENT REGISTRY
# ══════════════════════════════════════════════════════════════════════════════

class AgentRegistry:
    """Agent registry with discovery, lifecycle, and health monitoring.
    
    Features:
        - Agent registration and discovery by capability/category
        - Lifecycle management (start, stop, restart)
        - Health monitoring via heartbeats
        - Dependency resolution
        - Hot-reload support
    """

    def __init__(self, message_bus: MessageBus):
        self.message_bus = message_bus
        self.logger = logging.getLogger("agent_registry")
        self._agents: Dict[str, BaseAgent] = {}
        self._capability_index: Dict[str, List[str]] = defaultdict(list)  # capability -> agent_ids
        self._category_index: Dict[AgentCategory, List[str]] = defaultdict(list)
        self._health_status: Dict[str, Dict] = {}

    async def register(self, agent: BaseAgent) -> str:
        """Register and start an agent."""
        self._agents[agent.agent_id] = agent
        agent._registry = self
        
        # Register with message bus
        self.message_bus.register_agent(agent)
        
        # Index capabilities
        for cap in agent.capabilities:
            self._capability_index[cap.name].append(agent.agent_id)
        
        # Index category
        self._category_index[agent.category].append(agent.agent_id)
        
        # Start agent
        await agent.start()
        
        self._health_status[agent.agent_id] = {
            "status": "healthy",
            "last_check": datetime.now().isoformat(),
            "consecutive_failures": 0,
        }
        
        self.logger.info(f"Registered agent: {agent.name} [{agent.agent_id}] "
                        f"category={agent.category.value} "
                        f"capabilities={[c.name for c in agent.capabilities]}")
        return agent.agent_id

    async def unregister(self, agent_id: str):
        """Stop and unregister an agent."""
        agent = self._agents.get(agent_id)
        if agent:
            await agent.stop()
            self.message_bus.unregister_agent(agent_id)
            
            # Remove from indices
            for cap in agent.capabilities:
                if agent_id in self._capability_index.get(cap.name, []):
                    self._capability_index[cap.name].remove(agent_id)
            
            cat_list = self._category_index.get(agent.category, [])
            if agent_id in cat_list:
                cat_list.remove(agent_id)
            
            del self._agents[agent_id]
            self._health_status.pop(agent_id, None)
            self.logger.info(f"Unregistered agent: {agent.name} [{agent_id}]")

    def find_by_capability(self, capability_name: str) -> List[BaseAgent]:
        """Find agents that have a specific capability."""
        agent_ids = self._capability_index.get(capability_name, [])
        return [self._agents[aid] for aid in agent_ids if aid in self._agents]

    def find_by_category(self, category: AgentCategory) -> List[BaseAgent]:
        """Find agents in a category."""
        agent_ids = self._category_index.get(category, [])
        return [self._agents[aid] for aid in agent_ids if aid in self._agents]

    def get_agent(self, agent_id: str) -> Optional[BaseAgent]:
        """Get an agent by ID."""
        return self._agents.get(agent_id)

    def get_all_agents(self) -> List[BaseAgent]:
        """Get all registered agents."""
        return list(self._agents.values())

    def get_ready_agents(self) -> List[BaseAgent]:
        """Get agents that are ready to accept tasks."""
        return [a for a in self._agents.values() if a.status == AgentStatus.READY]

    async def health_check(self) -> Dict[str, Any]:
        """Run health check on all agents."""
        results = {}
        for agent_id, agent in self._agents.items():
            health = {
                "status": agent.status.value,
                "metrics": agent.metrics.__dict__,
                "current_task": agent._current_task,
            }
            
            if agent.status == AgentStatus.ERROR:
                self._health_status[agent_id]["consecutive_failures"] += 1
                health["healthy"] = False
            else:
                self._health_status[agent_id]["consecutive_failures"] = 0
                health["healthy"] = True
            
            self._health_status[agent_id]["last_check"] = datetime.now().isoformat()
            results[agent_id] = health
        
        return results

    def get_registry_info(self) -> Dict[str, Any]:
        """Get full registry information."""
        agents_info = []
        for agent in self._agents.values():
            agents_info.append({
                "agent_id": agent.agent_id,
                "name": agent.name,
                "category": agent.category.value,
                "status": agent.status.value,
                "capabilities": [c.name for c in agent.capabilities],
                "tasks_completed": agent.metrics.tasks_completed,
                "tasks_failed": agent.metrics.tasks_failed,
            })
        
        return {
            "total_agents": len(self._agents),
            "agents": agents_info,
            "capabilities": {k: len(v) for k, v in self._capability_index.items()},
            "categories": {k.value: len(v) for k, v in self._category_index.items()},
            "message_bus": self.message_bus.get_statistics(),
        }


# ══════════════════════════════════════════════════════════════════════════════
# AGENT ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════

class AgentOrchestrator:
    """Supervisor-pattern orchestrator for multi-agent coordination.
    
    Responsibilities:
        - Task decomposition and assignment
        - Agent selection based on capabilities and load
        - Workflow coordination (sequential, parallel, conditional)
        - Result aggregation
        - Error recovery and failover
    """

    def __init__(self, registry: AgentRegistry, message_bus: MessageBus):
        self.registry = registry
        self.message_bus = message_bus
        self.logger = logging.getLogger("orchestrator")
        self._active_workflows: Dict[str, Dict] = {}
        self._workflow_history: deque = deque(maxlen=500)

    async def execute_task(self, capability: str, params: Dict[str, Any],
                           preferred_agent: str = None) -> Dict[str, Any]:
        """Execute a task by routing to the best available agent.
        
        Args:
            capability: The capability name to execute
            params: Task parameters
            preferred_agent: Optional preferred agent ID
            
        Returns:
            Task result
        """
        # Find suitable agents
        if preferred_agent:
            agent = self.registry.get_agent(preferred_agent)
            if agent and agent.status == AgentStatus.READY:
                agents = [agent]
            else:
                agents = self.registry.find_by_capability(capability)
        else:
            agents = self.registry.find_by_capability(capability)

        if not agents:
            raise ValueError(f"No agent available for capability: {capability}")

        # Select best agent (prefer ready + lowest load)
        ready_agents = [a for a in agents if a.status == AgentStatus.READY]
        if not ready_agents:
            raise RuntimeError(f"All agents for '{capability}' are busy")

        # Round-robin: pick agent with fewest tasks served (even load distribution)
        agent = min(ready_agents, key=lambda a: (a.metrics.tasks_failed, a.metrics.tasks_completed))
        
        self.logger.info(f"Routing '{capability}' to agent {agent.name} [{agent.agent_id}]")
        return await agent.execute(capability, params)

    async def execute_workflow(self, workflow_name: str,
                               steps: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Execute a multi-step workflow.
        
        Each step: {"capability": str, "params": dict, "depends_on": [step_indices]}
        """
        workflow_id = str(uuid.uuid4())[:8]
        self.logger.info(f"Starting workflow '{workflow_name}' [{workflow_id}] with {len(steps)} steps")
        
        results = {}
        self._active_workflows[workflow_id] = {
            "name": workflow_name,
            "steps": len(steps),
            "completed": 0,
            "status": "running",
            "started_at": datetime.now().isoformat(),
        }

        try:
            for i, step in enumerate(steps):
                capability = step["capability"]
                params = step.get("params", {})
                depends_on = step.get("depends_on", [])

                # Inject results from dependencies
                for dep_idx in depends_on:
                    if dep_idx in results:
                        params[f"dep_{dep_idx}_result"] = results[dep_idx]

                self.logger.info(f"  Step {i}: {capability}")
                result = await self.execute_task(capability, params)
                results[i] = result
                self._active_workflows[workflow_id]["completed"] = i + 1

            self._active_workflows[workflow_id]["status"] = "completed"
            
        except Exception as e:
            self._active_workflows[workflow_id]["status"] = f"failed: {e}"
            self.logger.error(f"Workflow '{workflow_name}' failed at step {i}: {e}")
            raise
        finally:
            self._workflow_history.append(self._active_workflows.pop(workflow_id))

        return {"workflow_id": workflow_id, "steps_completed": len(results), "results": results}

    async def execute_parallel(self, tasks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Execute multiple tasks in parallel.
        
        Each task: {"capability": str, "params": dict}
        """
        coros = [
            self.execute_task(t["capability"], t.get("params", {}))
            for t in tasks
        ]
        return await asyncio.gather(*coros, return_exceptions=True)

    def get_orchestrator_status(self) -> Dict[str, Any]:
        """Get orchestrator status."""
        return {
            "active_workflows": len(self._active_workflows),
            "workflows_in_history": len(self._workflow_history),
            "active_details": dict(self._active_workflows),
            "registry": self.registry.get_registry_info(),
        }


# ══════════════════════════════════════════════════════════════════════════════
# GLOBAL INSTANCES
# ══════════════════════════════════════════════════════════════════════════════

# Singleton instances for the framework
message_bus = MessageBus()
agent_registry = AgentRegistry(message_bus)
agent_orchestrator = AgentOrchestrator(agent_registry, message_bus)
