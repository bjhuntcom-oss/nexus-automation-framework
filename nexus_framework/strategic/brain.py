"""
Strategic Brain Engine - Autonomous Decision Making

Core autonomous reasoning engine for offensive security operations.
Rule-based + heuristic + Bayesian risk modeling.
Non-LLM deterministic decision making.

Architecture:
- State machine for offensive operations
- Rule engine with priority scoring
- Bayesian risk assessment
- Multi-path attack planning
- Dynamic strategy adaptation
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import networkx as nx
import numpy as np
from datetime import datetime, timedelta
import uuid

# Internal imports
from .orchestration import TaskDefinition, TaskType, TaskPriority


class OperationState(Enum):
    """Offensive operation states."""
    RECONNAISSANCE = "reconnaissance"
    ENUMERATION = "enumeration"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    PERSISTENCE = "persistence"
    COVERING_TRACKS = "covering_tracks"
    COMPLETED = "completed"
    FAILED = "failed"


class AttackPhase(Enum):
    """Attack phases with weights."""
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class TargetAsset:
    """Target asset representation."""
    asset_id: str
    asset_type: str  # host, service, user, application
    value: float  # Business value 0-1
    criticality: float  # Criticality 0-1
    defenses: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    network_position: str = ""
    trust_level: float = 0.0


@dataclass
class AttackTechnique:
    """Attack technique with metadata."""
    technique_id: str
    name: str
    phase: AttackPhase
    success_probability: float
    impact_score: float
    stealth_score: float
    required_tools: List[str]
    prerequisites: List[str]
    side_effects: List[str]
    detection_risk: float
    time_cost: int  # minutes


@dataclass
class OperationContext:
    """Current operation context."""
    operation_id: str
    target_scope: List[str]
    objectives: List[str]
    constraints: List[str]
    risk_tolerance: float
    time_limit: Optional[datetime]
    stealth_requirement: float
    allowed_tools: Set[str]
    forbidden_techniques: Set[str]
    current_state: OperationState
    discovered_assets: Dict[str, TargetAsset] = field(default_factory=dict)
    attack_graph: Optional[nx.DiGraph] = None
    execution_history: List[Dict] = field(default_factory=list)


class RuleEngine:
    """Rule-based decision engine."""
    
    def __init__(self):
        self.rules = []
        self._load_default_rules()
    
    def _load_default_rules(self):
        """Load default offensive security rules."""
        self.rules = [
            {
                "name": "reconnaissance_first",
                "condition": lambda ctx: ctx.current_state == OperationState.RECONNAISSANCE,
                "action": "perform_network_discovery",
                "priority": 100,
                "description": "Always start with reconnaissance"
            },
            {
                "name": "validate_scope",
                "condition": lambda ctx: any(asset not in ctx.target_scope for asset in ctx.discovered_assets),
                "action": "scope_enforcement",
                "priority": 200,
                "description": "Enforce scope boundaries"
            },
            {
                "name": "stealth_priority",
                "condition": lambda ctx: ctx.stealth_requirement > 0.7,
                "action": "select_stealthy_techniques",
                "priority": 150,
                "description": "Prioritize stealth in high-stealth operations"
            },
            {
                "name": "risk_assessment",
                "condition": lambda ctx: True,
                "action": "calculate_attack_risk",
                "priority": 120,
                "description": "Continuous risk assessment"
            }
        ]
    
    def evaluate_rules(self, context: OperationContext) -> List[Tuple[str, int]]:
        """Evaluate all rules against context."""
        applicable_rules = []
        for rule in self.rules:
            try:
                if rule["condition"](context):
                    applicable_rules.append((rule["action"], rule["priority"]))
            except Exception as e:
                logging.warning(f"Rule evaluation failed for {rule['name']}: {e}")
        
        # Sort by priority (higher = more important)
        return sorted(applicable_rules, key=lambda x: x[1], reverse=True)


class BayesianRiskModel:
    """Bayesian risk assessment model."""
    
    def __init__(self):
        self.prior_probabilities = {
            "detection": 0.1,
            "failure": 0.2,
            "collateral_damage": 0.05
        }
        self.likelihood_factors = {}
    
    def calculate_risk(self, technique: AttackTechnique, context: OperationContext) -> Dict[str, float]:
        """Calculate Bayesian risk probabilities."""
        risks = {}
        
        # Detection risk based on stealth and target defenses
        detection_likelihood = technique.detection_risk * (1 - technique.stealth_score)
        for asset_id in context.discovered_assets:
            asset = context.discovered_assets[asset_id]
            if "IDS" in asset.defenses:
                detection_likelihood *= 1.5
            if "SIEM" in asset.defenses:
                detection_likelihood *= 1.3
        
        risks["detection"] = self._bayesian_update(
            self.prior_probabilities["detection"],
            detection_likelihood
        )
        
        # Failure risk based on success probability
        risks["failure"] = self._bayesian_update(
            self.prior_probabilities["failure"],
            1 - technique.success_probability
        )
        
        # Collateral damage based on impact and asset value
        collateral_likelihood = technique.impact_score * 0.1
        risks["collateral_damage"] = self._bayesian_update(
            self.prior_probabilities["collateral_damage"],
            collateral_likelihood
        )
        
        return risks
    
    def _bayesian_update(self, prior: float, likelihood: float) -> float:
        """Simple Bayesian update."""
        # P(H|E) = P(E|H) * P(H) / P(E)
        evidence = likelihood * prior + (1 - likelihood) * (1 - prior)
        if evidence == 0:
            return prior
        return (likelihood * prior) / evidence


class HeuristicPlanner:
    """Heuristic attack path planner."""
    
    def __init__(self):
        self.heuristics = {
            "path_efficiency": 0.3,
            "risk_minimization": 0.25,
            "stealth_optimization": 0.2,
            "time_optimization": 0.15,
            "impact_maximization": 0.1
        }
    
    def plan_attack_paths(self, context: OperationContext, techniques: List[AttackTechnique]) -> List[List[str]]:
        """Generate optimal attack paths using heuristics."""
        if not context.attack_graph:
            return []
        
        paths = []
        target_objectives = context.objectives
        
        for objective in target_objectives:
            try:
                # Find paths to objective
                all_paths = list(nx.all_simple_paths(
                    context.attack_graph,
                    source="initial",
                    target=objective,
                    cutoff=10  # Limit path length
                ))
                
                # Score paths using heuristics
                scored_paths = []
                for path in all_paths:
                    score = self._score_path(path, techniques, context)
                    scored_paths.append((score, path))
                
                # Sort by score (higher = better)
                scored_paths.sort(reverse=True, key=lambda x: x[0])
                
                # Add top paths
                for score, path in scored_paths[:3]:  # Top 3 paths
                    paths.append(path)
                    
            except nx.NetworkXNoPath:
                continue
        
        return paths
    
    def _score_path(self, path: List[str], techniques: List[AttackTechnique], context: OperationContext) -> float:
        """Score attack path using multiple heuristics."""
        technique_map = {t.technique_id: t for t in techniques}
        score = 0.0
        
        # Path efficiency (shorter paths better)
        path_length = len(path)
        efficiency_score = 1.0 / path_length
        score += efficiency_score * self.heuristics["path_efficiency"]
        
        # Risk minimization
        total_risk = 0.0
        for technique_id in path:
            if technique_id in technique_map:
                technique = technique_map[technique_id]
                risks = BayesianRiskModel().calculate_risk(technique, context)
                total_risk += sum(risks.values())
        
        risk_score = 1.0 / (1.0 + total_risk / len(path))
        score += risk_score * self.heuristics["risk_minimization"]
        
        # Stealth optimization
        stealth_score = 0.0
        for technique_id in path:
            if technique_id in technique_map:
                stealth_score += technique_map[technique_id].stealth_score
        stealth_score /= len(path)
        score += stealth_score * self.heuristics["stealth_optimization"]
        
        # Time optimization
        total_time = sum(
            technique_map[t].time_cost for t in path if t in technique_map
        )
        time_score = 1.0 / (1.0 + total_time / 60)  # Normalize by hour
        score += time_score * self.heuristics["time_optimization"]
        
        # Impact maximization
        impact_score = sum(
            technique_map[t].impact_score for t in path if t in technique_map
        ) / len(path)
        score += impact_score * self.heuristics["impact_maximization"]
        
        return score


class StrategicBrainEngine:
    """Main strategic brain engine."""
    
    def __init__(self):
        self.rule_engine = RuleEngine()
        self.risk_model = BayesianRiskModel()
        self.planner = HeuristicPlanner()
        self.logger = logging.getLogger("strategic_brain")
        
        # Operation state tracking
        self.active_operations: Dict[str, OperationContext] = {}
        self.operation_history: List[Dict] = []
        
        # Knowledge base integration
        self.techniques_database: Dict[str, AttackTechnique] = {}
        self._load_techniques()
        
        # Action to Command mapping
        self.action_mapping = {
            "perform_network_discovery": {
                "tool_name": "nmap",
                "command_template": "nmap -sS -F --open {target}",
                "task_type": TaskType.SCAN
            },
            "perform_service_enumeration": {
                "tool_name": "nmap",
                "command_template": "nmap -sV -p- {target}",
                "task_type": TaskType.ENUMERATION
            },
            "perform_vulnerability_scan": {
                "tool_name": "nuclei",
                "command_template": "nuclei -u {target} -severity low,medium,high,critical",
                "task_type": TaskType.SCAN
            },
            "exploit_web_vulnerability": {
                "tool_name": "sqlmap",
                "command_template": "sqlmap -u {target} --batch --random-agent",
                "task_type": TaskType.EXPLOIT
            },
            "brute_force_credentials": {
                "tool_name": "hydra",
                "command_template": "hydra -L /usr/share/wordlists/metasploit/common_users.txt -P /usr/share/wordlists/metasploit/common_passwords.txt {target} ssh",
                "task_type": TaskType.EXPLOIT
            }
        }
    
    def _load_techniques(self):
        """Load attack techniques database."""
        # Sample techniques - should be loaded from knowledge engine
        self.techniques_database = {
            "T1018": AttackTechnique(
                technique_id="T1018",
                name="Remote System Discovery",
                phase=AttackPhase.DISCOVERY,
                success_probability=0.9,
                impact_score=0.2,
                stealth_score=0.7,
                required_tools=["nmap", "netexec"],
                prerequisites=[],
                side_effects=["network_noise"],
                detection_risk=0.3,
                time_cost=15
            ),
            "T1075": AttackTechnique(
                technique_id="T1075",
                name="Pass the Hash",
                phase=AttackPhase.CREDENTIAL_ACCESS,
                success_probability=0.7,
                impact_score=0.8,
                stealth_score=0.6,
                required_tools=["impacket", "crackmapexec"],
                prerequisites=["hashes"],
                side_effects=["log_entries"],
                detection_risk=0.5,
                time_cost=10
            ),
            "T1059": AttackTechnique(
                technique_id="T1059",
                name="Command and Scripting Interpreter",
                phase=AttackPhase.EXECUTION,
                success_probability=0.8,
                impact_score=0.6,
                stealth_score=0.4,
                required_tools=["shell"],
                prerequisites=["initial_access"],
                side_effects=["process_creation"],
                detection_risk=0.6,
                time_cost=5
            )
        }
    
    async def initialize_operation(self, operation_config: Dict[str, Any]) -> str:
        """Initialize new offensive operation."""
        operation_id = f"op_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        context = OperationContext(
            operation_id=operation_id,
            target_scope=operation_config.get("target_scope", []),
            objectives=operation_config.get("objectives", []),
            constraints=operation_config.get("constraints", []),
            risk_tolerance=operation_config.get("risk_tolerance", 0.5),
            time_limit=operation_config.get("time_limit"),
            stealth_requirement=operation_config.get("stealth_requirement", 0.5),
            allowed_tools=set(operation_config.get("allowed_tools", [])),
            forbidden_techniques=set(operation_config.get("forbidden_techniques", [])),
            current_state=OperationState.RECONNAISSANCE
        )
        
        self.active_operations[operation_id] = context
        
        self.logger.info(f"Initialized operation {operation_id}")
        return operation_id
    
    async def decide_next_action(self, operation_id: str) -> Dict[str, Any]:
        """Decide next strategic action."""
        if operation_id not in self.active_operations:
            raise ValueError(f"Operation {operation_id} not found")
        
        context = self.active_operations[operation_id]
        
        # Evaluate rules
        applicable_rules = self.rule_engine.evaluate_rules(context)
        
        # Generate attack paths if in appropriate state
        attack_paths = []
        if context.current_state in [OperationState.ENUMERATION, OperationState.EXPLOITATION]:
            techniques = list(self.techniques_database.values())
            attack_paths = self.planner.plan_attack_paths(context, techniques)
        
        # Make strategic decision
        decision = {
            "operation_id": operation_id,
            "current_state": context.current_state.value,
            "applicable_rules": applicable_rules,
            "attack_paths": attack_paths,
            "recommended_actions": []
        }
        
        # Add recommended actions based on rules
        for action, priority in applicable_rules[:3]:  # Top 3 actions
            decision["recommended_actions"].append({
                "action": action,
                "priority": priority,
                "rationale": f"Rule-based decision with priority {priority}"
            })
        
        # State transition logic
        decision["state_transition"] = self._determine_state_transition(context)
        
        return decision
    
    def _determine_state_transition(self, context: OperationContext) -> Optional[str]:
        """Determine if state transition is needed."""
        state_transitions = {
            OperationState.RECONNAISSANCE: OperationState.ENUMERATION,
            OperationState.ENUMERATION: OperationState.VULNERABILITY_ASSESSMENT,
            OperationState.VULNERABILITY_ASSESSMENT: OperationState.EXPLOITATION,
            OperationState.EXPLOITATION: OperationState.POST_EXPLOITATION,
            OperationState.POST_EXPLOITATION: OperationState.PERSISTENCE,
            OperationState.PERSISTENCE: OperationState.COVERING_TRACKS,
            OperationState.COVERING_TRACKS: OperationState.COMPLETED
        }
        
        # Simple transition logic - can be enhanced with conditions
        if context.current_state in state_transitions:
            return state_transitions[context.current_state].value
        
        return None
    
    async def update_operation_state(self, operation_id: str, new_state: str, 
                                   discovered_assets: Optional[Dict] = None,
                                   execution_result: Optional[Dict] = None) -> bool:
        """Update operation state with new information."""
        if operation_id not in self.active_operations:
            return False
        
        context = self.active_operations[operation_id]
        
        # Update state
        try:
            context.current_state = OperationState(new_state)
        except ValueError:
            self.logger.error(f"Invalid state: {new_state}")
            return False
        
        # Update discovered assets
        if discovered_assets:
            for asset_id, asset_data in discovered_assets.items():
                if isinstance(asset_data, dict):
                    asset = TargetAsset(**asset_data)
                else:
                    asset = asset_data
                context.discovered_assets[asset_id] = asset
        
        # Record execution result
        if execution_result:
            context.execution_history.append({
                "timestamp": datetime.now().isoformat(),
                "result": execution_result
            })
        
        self.logger.info(f"Updated operation {operation_id} to state {new_state}")
        return True
    
    async def get_operation_status(self, operation_id: str) -> Optional[Dict]:
        """Get current operation status."""
        if operation_id not in self.active_operations:
            return None
        
        context = self.active_operations[operation_id]
        
        return {
            "operation_id": operation_id,
            "current_state": context.current_state.value,
            "objectives": context.objectives,
            "discovered_assets_count": len(context.discovered_assets),
            "execution_history_count": len(context.execution_history),
            "time_remaining": (
                None if not context.time_limit 
                else context.time_limit - datetime.now()
            )
        }
    
    async def terminate_operation(self, operation_id: str) -> bool:
        """Terminate operation and archive."""
        if operation_id not in self.active_operations:
            return False
        
        context = self.active_operations.pop(operation_id)
        
        # Archive to history
        archive_entry = {
            "operation_id": operation_id,
            "terminated_at": datetime.now().isoformat(),
            "final_state": context.current_state.value,
            "objectives": context.objectives,
            "assets_discovered": len(context.discovered_assets),
            "execution_steps": len(context.execution_history)
        }
        
        self.operation_history.append(archive_entry)
        
        self.logger.info(f"Terminated operation {operation_id}")
        return True
    async def execute_strategic_loop(self, operation_id: str, orchestrator_instance: Any) -> List[str]:
        """
        Run one iteration of the strategic loop:
        1. Decide next action
        2. Map to orchestrator tasks
        3. Submit tasks
        """
        if operation_id not in self.active_operations:
            return []
            
        decision = await self.decide_next_action(operation_id)
        submitted_tasks = []
        
        context = self.active_operations[operation_id]
        
        for rec in decision.get("recommended_actions", []):
            action_name = rec["action"]
            if action_name in self.action_mapping:
                mapping = self.action_mapping[action_name]
                
                # Create tasks for each target in scope
                for target in context.target_scope:
                    task_id = f"task_{operation_id}_{uuid.uuid4().hex[:8]}"
                    command = mapping["command_template"].format(target=target)
                    
                    task = TaskDefinition(
                        task_id=task_id,
                        task_type=mapping["task_type"],
                        task_name=f"{action_name} on {target}",
                        payload={
                            "tool_name": mapping["tool_name"],
                            "command": command
                        },
                        priority=TaskPriority.NORMAL,
                        tenant_id="default_tenant",
                        user_id="default_user",
                        timeout=600,
                        metadata={
                            "operation_id": operation_id,
                            "strategic_action": action_name
                        }
                    )
                    
                    orchestrator_instance.submit_task(task)
                    submitted_tasks.append(task_id)
                    
                    self.logger.info(f"Submitted task {task_id} for action {action_name} on {target}")
            
            # If state transition is recommended, update it
            if decision.get("state_transition"):
                await self.update_operation_state(operation_id, decision["state_transition"])
                
        return submitted_tasks

# Import at the end to avoid circular imports
import uuid
