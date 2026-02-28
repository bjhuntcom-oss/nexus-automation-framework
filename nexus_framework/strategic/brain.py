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
import os
import uuid
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import networkx as nx
import numpy as np
from datetime import datetime, timedelta

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
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
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
        # Clamp to valid probability range to prevent BayesianRiskModel overflow
        detection_likelihood = min(1.0, detection_likelihood)

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
        # Shared risk model — avoid re-instantiating on every path/technique iteration
        self._risk_model = BayesianRiskModel()
    
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
                risks = self._risk_model.calculate_risk(technique, context)
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
        """Load attack techniques from the actual enriched knowledge database.
        
        Actual DB schema for attack_techniques:
            technique_id, name, description, tactic, platforms,
            data_sources, detection, mitigation, ref_links,
            knowledge_version, created_at, updated_at
        """
        import sqlite3
        import json as _json
        
        db_path = os.environ.get("NEXUS_DB_PATH", "/app/knowledge.db")
        # Map tactic names (actual DB column) to AttackPhase enum
        phase_mapping = {
            "reconnaissance": AttackPhase.RECONNAISSANCE,
            "discovery": AttackPhase.DISCOVERY,
            "resource-development": AttackPhase.RESOURCE_DEVELOPMENT,
            "resource_development": AttackPhase.RESOURCE_DEVELOPMENT,
            "initial-access": AttackPhase.INITIAL_ACCESS,
            "initial_access": AttackPhase.INITIAL_ACCESS,
            "execution": AttackPhase.EXECUTION,
            "persistence": AttackPhase.PERSISTENCE,
            "privilege-escalation": AttackPhase.PRIVILEGE_ESCALATION,
            "privilege_escalation": AttackPhase.PRIVILEGE_ESCALATION,
            "defense-evasion": AttackPhase.DEFENSE_EVASION,
            "defense_evasion": AttackPhase.DEFENSE_EVASION,
            "credential-access": AttackPhase.CREDENTIAL_ACCESS,
            "credential_access": AttackPhase.CREDENTIAL_ACCESS,
            "lateral-movement": AttackPhase.LATERAL_MOVEMENT,
            "lateral_movement": AttackPhase.LATERAL_MOVEMENT,
            "collection": AttackPhase.COLLECTION,
            "command-and-control": AttackPhase.COMMAND_AND_CONTROL,
            "command_and_control": AttackPhase.COMMAND_AND_CONTROL,
            "exfiltration": AttackPhase.EXFILTRATION,
            "impact": AttackPhase.IMPACT,
        }
        
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            # Use ACTUAL column names from the enriched DB
            cursor.execute("""
                SELECT technique_id, name, tactic, detection, description
                FROM attack_techniques LIMIT 700
            """)
            rows = cursor.fetchall()
            conn.close()
            
            for row in rows:
                tid, name, tactic_str, detection_text, description = row
                phase = phase_mapping.get(
                    (tactic_str or "").lower().strip(),
                    AttackPhase.DISCOVERY
                )
                
                # Derive detection risk & stealth from detection text length/detail
                det_risk = 0.5
                stealth = 0.5
                if detection_text:
                    det_len = len(detection_text)
                    if det_len > 500:  # Well-documented detection = easier to detect
                        det_risk = 0.7; stealth = 0.3
                    elif det_len < 100:  # Sparse detection info = harder to detect
                        det_risk = 0.2; stealth = 0.8
                
                # Derive success probability from tactic type
                success_map = {
                    AttackPhase.RECONNAISSANCE: 0.9,
                    AttackPhase.DISCOVERY: 0.85,
                    AttackPhase.EXECUTION: 0.7,
                    AttackPhase.INITIAL_ACCESS: 0.5,
                    AttackPhase.PRIVILEGE_ESCALATION: 0.4,
                    AttackPhase.LATERAL_MOVEMENT: 0.5,
                    AttackPhase.CREDENTIAL_ACCESS: 0.6,
                    AttackPhase.PERSISTENCE: 0.65,
                    AttackPhase.DEFENSE_EVASION: 0.6,
                    AttackPhase.EXFILTRATION: 0.55,
                }
                success_prob = success_map.get(phase, 0.5)
                
                self.techniques_database[tid] = AttackTechnique(
                    technique_id=tid,
                    name=name,
                    phase=phase,
                    success_probability=success_prob,
                    impact_score=0.6 if phase in [AttackPhase.INITIAL_ACCESS, AttackPhase.PRIVILEGE_ESCALATION, AttackPhase.IMPACT] else 0.4,
                    stealth_score=stealth,
                    required_tools=[],
                    prerequisites=[],
                    side_effects=[],
                    detection_risk=det_risk,
                    time_cost=15
                )
            
            self.logger.info(f"Loaded {len(self.techniques_database)} techniques from knowledge DB")
        except Exception as e:
            self.logger.warning(f"Failed to load techniques from DB, using defaults: {e}")
            self.techniques_database = {
                "T1018": AttackTechnique("T1018", "Remote System Discovery", AttackPhase.DISCOVERY, 0.9, 0.2, 0.7, ["nmap"], [], ["network_noise"], 0.3, 15),
                "T1059": AttackTechnique("T1059", "Command and Scripting Interpreter", AttackPhase.EXECUTION, 0.8, 0.6, 0.4, ["shell"], ["initial_access"], ["process_creation"], 0.6, 5),
            }
    
    def _load_workflow_rules(self) -> List[Dict]:
        """Load workflow rules from the actual enriched knowledge database.
        
        Actual DB schema for workflow_rules:
            rule_id, name, phase, category, description,
            conditions, actions, priority, enabled, created_at, updated_at
        """
        import sqlite3
        import json as _json
        
        def _safe_json(val):
            """Safely parse JSON — return raw string if not valid JSON."""
            if not val:
                return []
            try:
                return _json.loads(val)
            except (ValueError, TypeError):
                return val  # Return raw text if not JSON
        
        rules = []
        try:
            conn = sqlite3.connect(os.environ.get("NEXUS_DB_PATH", "/app/knowledge.db"))
            cursor = conn.cursor()
            cursor.execute("""
                SELECT rule_id, name, category, phase, conditions, actions,
                       priority, description
                FROM workflow_rules WHERE enabled = 1 
                ORDER BY priority DESC
            """)
            for row in cursor.fetchall():
                rules.append({
                    "rule_id": row[0], "name": row[1], "category": row[2],
                    "phase": row[3],
                    "trigger": _safe_json(row[4]),
                    "actions": _safe_json(row[5]),
                    "priority": row[6], "description": row[7],
                })
            conn.close()
            self.logger.info(f"Loaded {len(rules)} workflow rules from knowledge DB")
        except Exception as e:
            self.logger.warning(f"Failed to load workflow rules: {e}")
        return rules
    
    def query_knowledge(self, query_type: str, query: str, limit: int = 20) -> List[Dict]:
        """Query the knowledge database using ACTUAL enriched DB schema.
        
        Supports: cve, technique, service, exploit_pattern, evasion, 
                  workflow, stats, auto_analyze
        
        Returns structured results formatted for Claude's reasoning.
        """
        import sqlite3
        import json as _json
        
        results = []
        try:
            conn = sqlite3.connect(os.environ.get("NEXUS_DB_PATH", "/app/knowledge.db"))
            cursor = conn.cursor()
            
            if query_type == "cve":
                cursor.execute("""
                    SELECT cve_id, description, cvss_score, severity, cvss_vector,
                           affected_products, exploit_available, published_date,
                           exploit_complexity, required_privileges, 
                           confidentiality_impact, integrity_impact, availability_impact
                    FROM cve_entries
                    WHERE cve_id LIKE ? OR description LIKE ? OR affected_products LIKE ?
                    ORDER BY cvss_score DESC LIMIT ?
                """, (f"%{query}%", f"%{query}%", f"%{query}%", limit))
                for row in cursor.fetchall():
                    results.append({
                        "cve_id": row[0], "description": row[1],
                        "cvss_score": row[2], "severity": row[3],
                        "cvss_vector": row[4],
                        "affected_products": _json.loads(row[5]) if row[5] else [],
                        "exploit_available": bool(row[6]),
                        "published_date": row[7],
                        "exploit_complexity": row[8] or "Unknown",
                        "required_privileges": row[9] or "Unknown",
                        "cia_impact": {
                            "confidentiality": row[10] or "Unknown",
                            "integrity": row[11] or "Unknown",
                            "availability": row[12] or "Unknown",
                        },
                    })
            
            elif query_type == "technique":
                # Actual columns: technique_id, name, description, tactic, platforms,
                #                  data_sources, detection, mitigation, ref_links
                cursor.execute("""
                    SELECT technique_id, name, description, tactic, platforms,
                           detection, mitigation
                    FROM attack_techniques
                    WHERE technique_id LIKE ? OR name LIKE ? OR description LIKE ?
                          OR tactic LIKE ?
                    ORDER BY technique_id LIMIT ?
                """, (f"%{query}%", f"%{query}%", f"%{query}%", f"%{query}%", limit))
                for row in cursor.fetchall():
                    results.append({
                        "technique_id": row[0], "name": row[1],
                        "description": (row[2] or "")[:600], "tactic": row[3],
                        "platforms": _json.loads(row[4]) if row[4] else [],
                        "detection": (row[5] or "")[:300],
                        "mitigation": (row[6] or "")[:300],
                    })
            
            elif query_type == "service":
                # Actual columns: vuln_id, service_name, version_pattern,
                #   vulnerability_type, description, severity, cve_refs,
                #   exploit_refs, detection_methods, mitigation
                cursor.execute("""
                    SELECT vuln_id, service_name, version_pattern, vulnerability_type,
                           description, severity, cve_refs, exploit_refs,
                           detection_methods, mitigation
                    FROM service_vulnerabilities
                    WHERE service_name LIKE ? OR version_pattern LIKE ?
                          OR vulnerability_type LIKE ? OR description LIKE ?
                    LIMIT ?
                """, (f"%{query}%", f"%{query}%", f"%{query}%", f"%{query}%", limit))
                for row in cursor.fetchall():
                    results.append({
                        "vuln_id": row[0], "service": row[1],
                        "version_pattern": row[2], "vuln_type": row[3],
                        "description": row[4], "severity": row[5],
                        "cve_refs": _json.loads(row[6]) if row[6] else [],
                        "exploit_refs": _json.loads(row[7]) if row[7] else [],
                        "detection": _json.loads(row[8]) if row[8] else [],
                        "mitigation": row[9],
                    })
            
            elif query_type == "exploit_pattern":
                # Actual columns: pattern_id, name, description, category,
                #   technique_refs, service_refs, payload_examples,
                #   detection_indicators, success_indicators, complexity,
                #   reliability, side_effects
                cursor.execute("""
                    SELECT pattern_id, name, description, category,
                           technique_refs, service_refs, payload_examples,
                           success_indicators, complexity, reliability
                    FROM exploit_patterns
                    WHERE name LIKE ? OR category LIKE ? OR description LIKE ?
                    LIMIT ?
                """, (f"%{query}%", f"%{query}%", f"%{query}%", limit))
                for row in cursor.fetchall():
                    results.append({
                        "pattern_id": row[0], "name": row[1],
                        "description": (row[2] or "")[:400], "category": row[3],
                        "technique_refs": _json.loads(row[4]) if row[4] else [],
                        "service_refs": _json.loads(row[5]) if row[5] else [],
                        "payload_examples": _json.loads(row[6]) if row[6] else [],
                        "success_indicators": _json.loads(row[7]) if row[7] else [],
                        "complexity": row[8], "reliability": row[9],
                    })
            
            elif query_type == "evasion":
                # Actual columns: pattern_id, name, description, category,
                #   target_systems, technique_refs, implementation,
                #   detection_bypass, effectiveness
                cursor.execute("""
                    SELECT pattern_id, name, description, category,
                           target_systems, technique_refs, implementation,
                           detection_bypass, effectiveness
                    FROM evasion_patterns
                    WHERE name LIKE ? OR category LIKE ? OR description LIKE ?
                    LIMIT ?
                """, (f"%{query}%", f"%{query}%", f"%{query}%", limit))
                for row in cursor.fetchall():
                    results.append({
                        "pattern_id": row[0], "name": row[1],
                        "description": (row[2] or "")[:400], "category": row[3],
                        "target_systems": _json.loads(row[4]) if row[4] else [],
                        "technique_refs": _json.loads(row[5]) if row[5] else [],
                        "implementation": _json.loads(row[6]) if row[6] else [],
                        "detection_bypass": _json.loads(row[7]) if row[7] else [],
                        "effectiveness": row[8],
                    })
            
            elif query_type == "workflow":
                # Actual columns: rule_id, name, phase, category, description,
                #   conditions, actions, priority, enabled
                cursor.execute("""
                    SELECT rule_id, name, phase, category, description,
                           conditions, actions, priority
                    FROM workflow_rules
                    WHERE name LIKE ? OR category LIKE ? OR description LIKE ?
                          OR phase LIKE ?
                    ORDER BY priority DESC LIMIT ?
                """, (f"%{query}%", f"%{query}%", f"%{query}%", f"%{query}%", limit))
                def _safe_json(val):
                    if not val:
                        return []
                    try:
                        return _json.loads(val)
                    except (ValueError, TypeError):
                        return val
                
                for row in cursor.fetchall():
                    results.append({
                        "rule_id": row[0], "name": row[1],
                        "phase": row[2], "category": row[3],
                        "description": row[4],
                        "conditions": _safe_json(row[5]),
                        "actions": _safe_json(row[6]),
                        "priority": row[7],
                    })
            
            elif query_type == "auto_analyze":
                # Cross-reference: find CVEs + techniques + exploits for a service/product
                # This is the POWER query that Claude uses to build attack plans
                search = f"%{query}%"
                
                # 1) Find matching service vulns
                cursor.execute("""
                    SELECT service_name, version_pattern, vulnerability_type,
                           severity, cve_refs, exploit_refs, detection_methods
                    FROM service_vulnerabilities
                    WHERE service_name LIKE ? OR version_pattern LIKE ?
                    LIMIT 10
                """, (search, search))
                svc_results = []
                all_cve_refs = set()
                for row in cursor.fetchall():
                    cves = _json.loads(row[4]) if row[4] else []
                    all_cve_refs.update(cves)
                    svc_results.append({
                        "service": row[0], "version": row[1],
                        "vuln_type": row[2], "severity": row[3],
                        "cves": cves,
                        "exploits": _json.loads(row[5]) if row[5] else [],
                        "detection": _json.loads(row[6]) if row[6] else [],
                    })
                
                # 2) Find CVEs matching the service
                cursor.execute("""
                    SELECT cve_id, description, cvss_score, exploit_available,
                           exploit_complexity
                    FROM cve_entries
                    WHERE (affected_products LIKE ? OR description LIKE ?)
                          AND cvss_score >= 4.0
                    ORDER BY cvss_score DESC LIMIT 15
                """, (search, search))
                cve_results = []
                for row in cursor.fetchall():
                    cve_results.append({
                        "cve_id": row[0], "description": row[1][:200],
                        "cvss": row[2], "exploit_available": bool(row[3]),
                        "complexity": row[4],
                    })
                
                # 3) Find relevant techniques
                cursor.execute("""
                    SELECT technique_id, name, tactic, detection, mitigation
                    FROM attack_techniques
                    WHERE name LIKE ? OR description LIKE ?
                    LIMIT 10
                """, (search, search))
                tech_results = []
                for row in cursor.fetchall():
                    tech_results.append({
                        "id": row[0], "name": row[1], "tactic": row[2],
                        "detection": (row[3] or "")[:150],
                        "mitigation": (row[4] or "")[:150],
                    })
                
                # 4) Find matching exploit patterns
                cursor.execute("""
                    SELECT name, category, complexity, reliability,
                           payload_examples, success_indicators
                    FROM exploit_patterns
                    WHERE name LIKE ? OR category LIKE ? OR description LIKE ?
                    LIMIT 5
                """, (search, search, search))
                exploit_results = []
                for row in cursor.fetchall():
                    exploit_results.append({
                        "name": row[0], "category": row[1],
                        "complexity": row[2], "reliability": row[3],
                        "payloads": _json.loads(row[4]) if row[4] else [],
                        "success_indicators": _json.loads(row[5]) if row[5] else [],
                    })
                
                results.append({
                    "analysis_target": query,
                    "service_vulnerabilities": svc_results,
                    "related_cves": cve_results,
                    "attack_techniques": tech_results,
                    "exploit_patterns": exploit_results,
                    "summary": {
                        "total_service_vulns": len(svc_results),
                        "total_cves": len(cve_results),
                        "critical_cves": sum(1 for c in cve_results if c.get("cvss", 0) >= 9.0),
                        "exploitable_cves": sum(1 for c in cve_results if c.get("exploit_available")),
                        "techniques": len(tech_results),
                        "exploit_patterns": len(exploit_results),
                    }
                })
            
            elif query_type == "stats":
                tables = {
                    "cve_entries": "CVE vulnerabilities",
                    "attack_techniques": "MITRE ATT&CK techniques",
                    "service_vulnerabilities": "Service vulnerability profiles",
                    "exploit_patterns": "Exploit patterns",
                    "evasion_patterns": "Evasion techniques",
                    "workflow_rules": "Automation workflow rules",
                    "payloads": "Attack payloads",
                    "cve_technique_mapping": "CVE-to-technique mappings",
                    "technique_payload_mapping": "Technique-to-payload mappings",
                }
                stats = {}
                for table, desc in tables.items():
                    try:
                        count = cursor.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                        stats[table] = {"count": count, "description": desc}
                    except Exception:
                        stats[table] = {"count": 0, "description": desc, "error": "table not found"}
                
                # CVE depth stats
                exploitable = cursor.execute("SELECT COUNT(*) FROM cve_entries WHERE exploit_available = 1").fetchone()[0]
                critical = cursor.execute("SELECT COUNT(*) FROM cve_entries WHERE cvss_score >= 9.0").fetchone()[0]
                high = cursor.execute("SELECT COUNT(*) FROM cve_entries WHERE cvss_score >= 7.0 AND cvss_score < 9.0").fetchone()[0]
                
                results.append({
                    "tables": stats,
                    "cve_depth": {
                        "total": stats.get("cve_entries", {}).get("count", 0),
                        "critical": critical,
                        "high": high,
                        "exploitable": exploitable,
                    },
                    "cross_references": {
                        "cve_technique_mappings": stats.get("cve_technique_mapping", {}).get("count", 0),
                        "technique_payload_mappings": stats.get("technique_payload_mapping", {}).get("count", 0),
                    }
                })
            
            conn.close()
        except Exception as e:
            self.logger.error(f"Knowledge query failed: {e}")
            results.append({"error": str(e)})
        
        return results
    
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
        
        time_remaining = None
        if context.time_limit:
            delta = context.time_limit - datetime.now()
            time_remaining = max(0, int(delta.total_seconds()))

        return {
            "operation_id": operation_id,
            "current_state": context.current_state.value,
            "objectives": context.objectives,
            "discovered_assets_count": len(context.discovered_assets),
            "execution_history_count": len(context.execution_history),
            "risk_tolerance": context.risk_tolerance,
            "stealth_requirement": context.stealth_requirement,
            "time_remaining": time_remaining,
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

        # Apply state transition once, after all tasks have been submitted
        if decision.get("state_transition"):
            await self.update_operation_state(operation_id, decision["state_transition"])

        return submitted_tasks
