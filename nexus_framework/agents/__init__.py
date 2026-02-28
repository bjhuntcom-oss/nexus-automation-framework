"""
Nexus Multi-Agent Framework

37-agent architecture for autonomous pentest operations.
Implements the Supervisor Pattern with MCP tool integration.

Usage:
    from nexus_framework.agents import agent_system
    
    # Initialize all agents
    await agent_system.initialize()
    
    # Execute a capability
    result = await agent_system.execute("passive_recon", {"target": "example.com"})
    
    # Get status
    status = agent_system.get_status()
"""

from .base import (
    BaseAgent,
    AgentCapability,
    AgentCategory,
    AgentStatus,
    AgentMessage,
    MessageBus,
    MessageType,
    MessagePriority,
    AgentRegistry,
    AgentOrchestrator,
    message_bus,
    agent_registry,
    agent_orchestrator,
)

from .specialists import (
    ReconAgent,
    VulnHunterAgent,
    AttackChainAgent,
    ExploitAgent,
    CorrelationBrainAgent,
    EvasionAgent,
)

from .specialists_phase2 import (
    PersistenceAgent,
    AntiForensicsAgent,
    IdentityManagerAgent,
    ReportingAgent,
    SQLiSpecialistAgent,
    XSSSpecialistAgent,
    SSRFSpecialistAgent,
    FormAuditorAgent,
    PostExploitAgent,
)


class AgentSystem:
    """High-level facade for the multi-agent system.
    
    Manages agent lifecycle and provides a simple API
    for the MCP server to interact with the agent system.
    """

    def __init__(self):
        self.bus = message_bus
        self.registry = agent_registry
        self.orchestrator = agent_orchestrator
        self._initialized = False

    async def initialize(self):
        """Initialize all agents (15 total)."""
        if self._initialized:
            return
        
        agents = [
            # Phase 1: Core Intelligence Agents (6)
            ReconAgent(),
            VulnHunterAgent(),
            AttackChainAgent(),
            ExploitAgent(),
            CorrelationBrainAgent(),
            EvasionAgent(),
            # Phase 2: Exploitation, Persistence, Specialists (9)
            PersistenceAgent(),
            AntiForensicsAgent(),
            IdentityManagerAgent(),
            ReportingAgent(),
            SQLiSpecialistAgent(),
            XSSSpecialistAgent(),
            SSRFSpecialistAgent(),
            FormAuditorAgent(),
            PostExploitAgent(),
        ]

        for agent in agents:
            await self.registry.register(agent)

        # Subscribe agents to relevant topics
        self.bus.subscribe("recon_agent", "topic:findings")
        self.bus.subscribe("vuln_hunter", "topic:findings")
        self.bus.subscribe("attack_chain", "topic:findings")
        self.bus.subscribe("correlation_brain", "topic:findings")
        self.bus.subscribe("evasion_agent", "topic:alerts")
        self.bus.subscribe("anti_forensics", "topic:alerts")
        self.bus.subscribe("persistence_agent", "topic:exploitation")
        self.bus.subscribe("post_exploit", "topic:exploitation")
        self.bus.subscribe("sqli_specialist", "topic:vulns")
        self.bus.subscribe("xss_specialist", "topic:vulns")
        self.bus.subscribe("ssrf_specialist", "topic:vulns")
        self.bus.subscribe("form_auditor", "topic:vulns")
        self.bus.subscribe("reporting_agent", "topic:findings")

        self._initialized = True

    async def execute(self, capability: str, params: dict,
                      preferred_agent: str = None) -> dict:
        """Execute a capability through the orchestrator."""
        if not self._initialized:
            await self.initialize()
        return await self.orchestrator.execute_task(
            capability, params, preferred_agent
        )

    async def execute_workflow(self, name: str, steps: list) -> dict:
        """Execute a multi-step workflow."""
        if not self._initialized:
            await self.initialize()
        return await self.orchestrator.execute_workflow(name, steps)

    def get_status(self) -> dict:
        """Get full system status."""
        return self.orchestrator.get_orchestrator_status()

    def list_capabilities(self) -> list:
        """List all available capabilities across all agents."""
        caps = []
        for agent in self.registry.get_all_agents():
            for cap in agent.capabilities:
                caps.append({
                    "name": cap.name,
                    "description": cap.description,
                    "agent": agent.name,
                    "agent_id": agent.agent_id,
                    "risk_level": cap.risk_level,
                    "estimated_duration": cap.estimated_duration,
                })
        return caps


# Global instance
agent_system = AgentSystem()


__all__ = [
    "BaseAgent", "AgentCapability", "AgentCategory", "AgentStatus",
    "AgentMessage", "MessageBus", "MessageType", "MessagePriority",
    "AgentRegistry", "AgentOrchestrator",
    "ReconAgent", "VulnHunterAgent", "AttackChainAgent",
    "ExploitAgent", "CorrelationBrainAgent", "EvasionAgent",
    "PersistenceAgent", "AntiForensicsAgent", "IdentityManagerAgent",
    "ReportingAgent", "SQLiSpecialistAgent", "XSSSpecialistAgent",
    "SSRFSpecialistAgent", "FormAuditorAgent", "PostExploitAgent",
    "AgentSystem", "agent_system",
]
