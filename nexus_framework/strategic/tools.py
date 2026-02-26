"""
Strategic Engine Tools - Enhanced MCP Tool Integration

Integration layer between the Strategic Engine and existing MCP tools.
Provides strategic decision-making, orchestration, and enhanced capabilities
for the existing toolset while maintaining full backward compatibility.
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from dataclasses import dataclass

from bjhunt_alpha.strategic import (
    brain_engine, attack_graph_engine, correlation_engine,
    knowledge_database, execution_engine, orchestrator,
    opsec_manager, governance_manager, observability_manager
)
from bjhunt_alpha.tools import run_command, log_action


@dataclass
class StrategicOperation:
    """Strategic operation context for tool execution."""
    operation_id: str
    objectives: List[str]
    target_scope: List[str]
    constraints: List[str]
    risk_tolerance: float
    stealth_requirement: float
    current_phase: str = "reconnaissance"
    discovered_assets: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.discovered_assets is None:
            self.discovered_assets = {}


class StrategicToolOrchestrator:
    """Enhanced tool orchestration with strategic decision-making."""
    
    def __init__(self):
        self.logger = logging.getLogger("strategic_tools")
        self.active_operations: Dict[str, StrategicOperation] = {}
        self.operation_history: List[Dict] = []
        
        # Initialize strategic components
        self._initialize_strategic_components()
    
    def _initialize_strategic_components(self):
        """Initialize strategic engine components."""
        try:
            # Start background services
            orchestrator.start()
            observability_manager.start_monitoring()
            
            # Setup default OPSEC scope
            self._setup_default_opsec_scope()
            
            # Create default governance user
            self._setup_default_governance()
            
            self.logger.info("Strategic Tool Orchestrator initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize strategic components: {e}")
    
    def _setup_default_opsec_scope(self):
        """Setup default OPSEC scope for operations."""
        from bjhunt_alpha.strategic.opsec import ScopeDefinition
        
        default_scope = ScopeDefinition(
            scope_id="default_scope",
            name="Default Operational Scope",
            authorized_targets=["0.0.0.0/0"],  # All targets (adjust as needed)
            forbidden_targets=["127.0.0.1"],  # Exclude localhost
            allowed_ports=set(range(1, 65536)),  # All ports
            forbidden_ports=set(),
            allowed_protocols={"tcp", "udp"},
            stealth_requirement=0.5,
            max_requests_per_minute=1000
        )
        
        opsec_manager.add_scope(default_scope)
    
    def _setup_default_governance(self):
        """Setup default governance configuration."""
        # Create default tenant
        tenant = governance_manager.create_tenant(
            name="Default Organization",
            description="Default tenant for operations",
            compliance_frameworks=set(),
            data_residency="US",
            retention_policy=365,
            max_users=100,
            resource_limits={}
        )
        
        # Create default admin user
        user = governance_manager.rbac.create_user(
            username="strategic_engine",
            email="strategic@bjhunt.local",
            roles={governance_manager.rbac.UserRole.ADMIN},
            tenant_id=tenant.tenant_id
        )
        
        # Authenticate and get session
        session_token = governance_manager.rbac.authenticate_user("strategic_engine", "password")
        self.default_session_token = session_token
    
    async def create_strategic_operation(self, objectives: List[str], 
                                       target_scope: List[str],
                                       constraints: List[str] = None,
                                       risk_tolerance: float = 0.5,
                                       stealth_requirement: float = 0.5) -> str:
        """Create a new strategic operation."""
        operation_id = f"strategic_op_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        operation = StrategicOperation(
            operation_id=operation_id,
            objectives=objectives,
            target_scope=target_scope,
            constraints=constraints or [],
            risk_tolerance=risk_tolerance,
            stealth_requirement=stealth_requirement
        )
        
        # Initialize in brain engine
        brain_config = {
            "target_scope": target_scope,
            "objectives": objectives,
            "risk_tolerance": risk_tolerance,
            "stealth_requirement": stealth_requirement,
            "constraints": constraints or []
        }
        
        brain_operation_id = await brain_engine.initialize_operation(brain_config)
        operation.operation_id = brain_operation_id
        
        self.active_operations[operation_id] = operation
        
        # Log operation creation
        self.logger.info(f"Created strategic operation {operation_id}")
        observability_manager.get_logger("strategic_tools").info(
            f"Strategic operation created",
            operation_id=operation_id,
            objectives=objectives,
            target_count=len(target_scope)
        )
        
        return operation_id
    
    async def get_strategic_recommendation(self, operation_id: str) -> Dict[str, Any]:
        """Get strategic recommendation for next actions."""
        if operation_id not in self.active_operations:
            return {"error": "Operation not found"}
        
        operation = self.active_operations[operation_id]
        
        # Get decision from brain engine
        decision = await brain_engine.decide_next_action(operation.operation_id)
        
        # Enhance with attack graph analysis
        if operation.discovered_assets:
            graph_analysis = await self._analyze_attack_surface(operation)
            decision["attack_graph_analysis"] = graph_analysis
        
        # Add OPSEC recommendations
        opsec_recommendations = self._get_opsec_recommendations(operation)
        decision["opsec_recommendations"] = opsec_recommendations
        
        return decision
    
    async def _analyze_attack_surface(self, operation: StrategicOperation) -> Dict[str, Any]:
        """Analyze attack surface using attack graph engine."""
        # Add discovered assets to attack graph
        for asset_id, asset_info in operation.discovered_assets.items():
            if asset_info.get("type") == "host":
                from bjhunt_alpha.strategic.attack_graph import GraphNode, NodeType
                
                node = GraphNode(
                    node_id=asset_id,
                    node_type=NodeType.HOST,
                    value=asset_info.get("value", 0.5),
                    defenses=asset_info.get("defenses", []),
                    vulnerabilities=asset_info.get("vulnerabilities", [])
                )
                attack_graph_engine.add_node(node)
        
        # Calculate attack surface metrics
        metrics = attack_graph_engine.calculate_centrality_metrics()
        
        return {
            "total_assets": len(operation.discovered_assets),
            "attack_surface_metrics": metrics,
            "critical_assets": [aid for aid, m in metrics.items() if m.get("betweenness", 0) > 0.5]
        }
    
    def _get_opsec_recommendations(self, operation: StrategicOperation) -> Dict[str, Any]:
        """Get OPSEC recommendations for the operation."""
        recommendations = {
            "noise_level": "moderate",
            "stealth_tips": [],
            "scope_compliance": True
        }
        
        # Adjust based on stealth requirement
        if operation.stealth_requirement > 0.7:
            recommendations["noise_level"] = "low"
            recommendations["stealth_tips"].extend([
                "Use timing delays between requests",
                "Limit concurrent connections",
                "Prefer passive reconnaissance"
            ])
        
        return recommendations
    
    async def execute_strategic_tool(self, operation_id: str, tool_name: str,
                                   command: str, parameters: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute tool with strategic orchestration."""
        if operation_id not in self.active_operations:
            return {"error": "Operation not found"}
        
        operation = self.active_operations[operation_id]
        parameters = parameters or {}
        
        # Validate against OPSEC rules
        target = parameters.get("target", "unknown")
        valid, violations = opsec_manager.validate_operation(
            scope_id="default_scope",
            tool_name=tool_name,
            target=target
        )
        
        if not valid:
            return {
                "error": "OPSEC validation failed",
                "violations": [v.to_dict() for v in violations]
            }
        
        # Execute with adaptive execution layer
        try:
            result = await execution_engine.execute_tool(
                tool_name=tool_name,
                command=command,
                parameters=parameters,
                timeout=parameters.get("timeout", 300),
                max_retries=3
            )
            
            # Process results through correlation engine
            if result.status.value == "completed" and result.stdout:
                from bjhunt_alpha.strategic.correlation import OutputFormat
                
                normalized_results = await correlation_engine.process_tool_output(
                    output=result.stdout,
                    format=OutputFormat.PLAIN_TEXT,
                    tool_name=tool_name,
                    target=target
                )
                
                # Update operation with discovered assets
                await self._update_operation_assets(operation_id, normalized_results)
                
                result["correlated_findings"] = [r.to_dict() for r in normalized_results]
            
            # Log execution
            self.logger.info(f"Strategic tool execution completed: {tool_name}")
            observability_manager.get_logger("strategic_tools").info(
                f"Tool executed",
                operation_id=operation_id,
                tool_name=tool_name,
                status=result.status.value,
                execution_time=result.execution_time
            )
            
            return result.to_dict()
            
        except Exception as e:
            self.logger.error(f"Strategic tool execution failed: {e}")
            return {"error": str(e)}
    
    async def _update_operation_assets(self, operation_id: str, findings: List) -> None:
        """Update operation with newly discovered assets."""
        if operation_id not in self.active_operations:
            return
        
        operation = self.active_operations[operation_id]
        
        for finding in findings:
            if finding.finding_type == "host":
                asset_id = f"host_{finding.target.replace('.', '_')}"
                operation.discovered_assets[asset_id] = {
                    "type": "host",
                    "ip": finding.target,
                    "services": finding.metadata.get("services", []),
                    "value": finding.severity
                }
        
        # Update brain engine with new assets
        await brain_engine.update_operation_state(
            operation.operation_id,
            "enumeration",
            discovered_assets=operation.discovered_assets
        )
    
    async def correlate_findings(self, operation_id: str, tool_outputs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Correlate findings from multiple tools."""
        if operation_id not in self.active_operations:
            return {"error": "Operation not found"}
        
        # Process all outputs through correlation engine
        all_findings = []
        for output in tool_outputs:
            from bjhunt_alpha.strategic.correlation import OutputFormat
            
            normalized = await correlation_engine.process_tool_output(
                output=output.get("output", ""),
                format=OutputFormat.PLAIN_TEXT,
                tool_name=output.get("tool", "unknown"),
                target=output.get("target", "unknown")
            )
            all_findings.extend(normalized)
        
        # Correlate findings
        correlations = await correlation_engine.correlate_findings(all_findings)
        
        return {
            "total_findings": len(all_findings),
            "correlations": [c.to_dict() for c in correlations],
            "high_confidence_findings": [f.to_dict() for f in all_findings if f.confidence > 0.8]
        }
    
    def get_operation_status(self, operation_id: str) -> Dict[str, Any]:
        """Get comprehensive operation status."""
        if operation_id not in self.active_operations:
            return {"error": "Operation not found"}
        
        operation = self.active_operations[operation_id]
        
        # Get brain engine status
        brain_status = brain_engine.active_operations.get(operation.operation_id)
        
        # Get observability data
        dashboard_data = observability_manager.create_dashboard_data()
        
        return {
            "operation_id": operation_id,
            "objectives": operation.objectives,
            "current_phase": operation.current_phase,
            "discovered_assets": operation.discovered_assets,
            "brain_status": brain_status.to_dict() if brain_status else None,
            "observability": {
                "active_alerts": dashboard_data["alerts"]["active_count"],
                "system_health": dashboard_data["health"]["overall_status"]
            }
        }
    
    def list_operations(self) -> List[Dict[str, Any]]:
        """List all active operations."""
        return [
            {
                "operation_id": op_id,
                "objectives": op.objectives,
                "target_count": len(op.target_scope),
                "current_phase": op.current_phase,
                "asset_count": len(op.discovered_assets)
            }
            for op_id, op in self.active_operations.items()
        ]
    
    def shutdown(self):
        """Shutdown strategic orchestrator."""
        try:
            shutdown_strategic_components()
            self.logger.info("Strategic Tool Orchestrator shutdown successfully")
        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")


# Global strategic tool orchestrator instance
strategic_orchestrator = StrategicToolOrchestrator()
