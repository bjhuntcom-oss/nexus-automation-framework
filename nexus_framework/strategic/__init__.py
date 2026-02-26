"""
BJHunt Alpha Strategic Engine Package

Enterprise-grade autonomous offensive security evaluation platform
with advanced decision-making capabilities and distributed orchestration.

Modules:
- brain: Strategic Brain Engine with rule-based decision making
- attack_graph: Attack Graph Engine with weighted pathfinding
- correlation: Multi-tool output correlation and normalization
- knowledge: CVE and MITRE ATT&CK knowledge database
- execution: Adaptive execution layer with intelligent retry
- orchestration: Distributed task orchestration and worker management
- opsec: OPSEC and safety controls with scope enforcement
- governance: Enterprise governance with RBAC and audit trails
- observability: Complete monitoring and observability stack
"""

from .brain import StrategicBrainEngine, OperationContext, OperationState
from .attack_graph import AttackGraphEngine, GraphNode, GraphEdge
from .correlation import CorrelationEngine, NormalizedResult
from .knowledge import KnowledgeDatabase, CVEEntry, AttackTechnique
from .execution import AdaptiveExecutionEngine, ExecutionResult
from .orchestration import DistributedOrchestrator, TaskDefinition
from .opsec import OPSECManager, ScopeDefinition
from .governance import GovernanceManager, User, UserRole
from .observability import ObservabilityManager

__version__ = "2.0.0"
__author__ = "BJHunt Team"
__description__ = "Enterprise-grade autonomous offensive security platform"

# Global instances for easy access
brain_engine = StrategicBrainEngine()
attack_graph_engine = AttackGraphEngine()
correlation_engine = CorrelationEngine()
knowledge_database = KnowledgeDatabase()
execution_engine = AdaptiveExecutionEngine()
orchestrator = DistributedOrchestrator()
opsec_manager = OPSECManager()
governance_manager = GovernanceManager("bjhunt-alpha-production-key")
observability_manager = ObservabilityManager()

# Initialize strategic components
def initialize_strategic_components():
    """Initialize all strategic components and wire them together."""
    global brain_engine, attack_graph_engine, correlation_engine
    global knowledge_database, execution_engine, orchestrator
    global opsec_manager, governance_manager, observability_manager
    
    # Start background services
    orchestrator.start()
    observability_manager.start_monitoring()
    
    # Load initial knowledge
    knowledge_database._load_initial_knowledge()
    
    # Setup default governance policies
    governance_manager._create_default_policies()
    
    # Wire Orchestrator to Correlation Engine and Brain Engine
    def task_completion_callback(result):
        """Callback triggered when any task completes."""
        if result.status.value == "completed" and result.result_data:
            # We are likely in a worker thread, so we need a loop for async calls
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                try:
                    # 1. Correlate and normalize findings
                    output = result.result_data.get('stdout', '')
                    tool_name = result.result_data.get('tool_name', 'unknown')
                    
                    # Determine output format (simplistic for now)
                    from .correlation import OutputFormat
                    fmt = OutputFormat.PLAIN_TEXT
                    if '<?xml' in output: fmt = OutputFormat.XML
                    elif output.startswith('{') or output.startswith('['): fmt = OutputFormat.JSON
                    
                    normalized_findings = loop.run_until_complete(
                        correlation_engine.process_tool_output(
                            output=output,
                            format=fmt,
                            tool_name=tool_name
                        )
                    )
                    
                    # 2. Update Brain Engine with new findings
                    op_id = result.task_id.split('_')[1] if 'op_' in result.task_id else None
                    if op_id:
                        loop.run_until_complete(
                            brain_engine.update_operation_state(
                                operation_id=op_id,
                                new_state=brain_engine.active_operations[op_id].current_state.value,
                                execution_result={
                                    "task_id": result.task_id,
                                    "findings_count": len(normalized_findings),
                                    "status": "success"
                                }
                            )
                        )
                finally:
                    loop.close()
            except Exception as e:
                import logging
                logging.getLogger("strategic_init").error(f"Error in strategic loop callback: {e}")

    orchestrator.on_task_complete_callbacks.append(task_completion_callback)
    
    return True

import asyncio

def shutdown_strategic_components():
    """Shutdown all strategic components."""
    global orchestrator, observability_manager
    
    # Stop background services
    orchestrator.stop()
    observability_manager.stop_monitoring()
    
    return True

# Export main classes and instances
__all__ = [
    # Classes
    'StrategicBrainEngine', 'OperationContext', 'OperationState',
    'AttackGraphEngine', 'GraphNode', 'GraphEdge',
    'CorrelationEngine', 'NormalizedResult',
    'KnowledgeDatabase', 'CVEEntry', 'AttackTechnique',
    'AdaptiveExecutionEngine', 'ExecutionResult',
    'DistributedOrchestrator', 'TaskDefinition',
    'OPSECManager', 'ScopeDefinition',
    'GovernanceManager', 'User', 'UserRole',
    'ObservabilityManager',
    
    # Global instances
    'brain_engine', 'attack_graph_engine', 'correlation_engine',
    'knowledge_database', 'execution_engine', 'orchestrator',
    'opsec_manager', 'governance_manager', 'observability_manager',
    
    # Functions
    'initialize_strategic_components', 'shutdown_strategic_components'
]
