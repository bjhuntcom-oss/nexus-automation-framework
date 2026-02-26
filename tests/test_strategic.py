"""
BJHunt Alpha - Strategic Engine Test Suite

Comprehensive test coverage for all strategic components:
- Strategic Brain Engine
- Attack Graph Engine  
- Correlation Engine
- Knowledge Engine
- Adaptive Execution Layer
- Distributed Orchestration
- OPSEC & Safety Layer
- Enterprise Governance Layer
- Observability Stack

Run with: pytest tests/test_strategic.py -v
"""

import asyncio
import json
import pytest
import tempfile
import os
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

# Import strategic components
from bjhunt_alpha.strategic.brain import (
    StrategicBrainEngine, OperationContext, OperationState, AttackPhase,
    RuleEngine, BayesianRiskModel, HeuristicPlanner
)
from bjhunt_alpha.strategic.attack_graph import (
    AttackGraphEngine, GraphNode, NodeType, GraphEdge, EdgeType
)
from bjhunt_alpha.strategic.correlation import (
    CorrelationEngine, NormalizedResult, OutputFormat, ConfidenceLevel
)
from bjhunt_alpha.strategic.knowledge import (
    KnowledgeDatabase, CVEEntry, AttackTechnique, VulnerabilitySeverity
)
from bjhunt_alpha.strategic.execution import (
    AdaptiveExecutionEngine, ExecutionStatus, RetryStrategy
)
from bjhunt_alpha.strategic.orchestration import (
    DistributedOrchestrator, TaskDefinition, TaskStatus, TaskType
)
from bjhunt_alpha.strategic.opsec import (
    OPSECManager, ScopeDefinition, RiskLevel, NoiseLevel
)
from bjhunt_alpha.strategic.governance import (
    GovernanceManager, UserRole, Permission, ApprovalStatus
)
from bjhunt_alpha.strategic.observability import (
    ObservabilityManager, LogLevel, MetricType
)


# ══════════════════════════════════════════════════════════════════════════════
# FIXTURES
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def temp_db_path():
    """Temporary database path for testing."""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name
    yield db_path
    os.unlink(db_path)


@pytest.fixture
def sample_operation_context():
    """Sample operation context for testing."""
    return OperationContext(
        operation_id="test_op_001",
        target_scope=["192.168.1.0/24"],
        objectives=["initial_access", "privilege_escalation"],
        constraints=["no_destruction", "stealth_required"],
        risk_tolerance=0.3,
        stealth_requirement=0.8,
        allowed_tools={"nmap", "nikto"},
        forbidden_techniques={"destruction"},
        current_state=OperationState.RECONNAISSANCE
    )


@pytest.fixture
def sample_graph_node():
    """Sample graph node for testing."""
    return GraphNode(
        node_id="host_001",
        node_type=NodeType.HOST,
        value=0.8,
        defenses=["firewall", "ids"],
        vulnerabilities=["CVE-2021-44228"],
        network_position="dmz",
        trust_level=0.3,
        detection_level=0.6
    )


@pytest.fixture
def sample_graph_edge():
    """Sample graph edge for testing."""
    return GraphEdge(
        source_id="host_001",
        target_id="host_002",
        edge_type=EdgeType.EXPLOIT,
        technique_id="T1190",
        success_probability=0.7,
        impact_score=0.8,
        stealth_score=0.4,
        detection_risk=0.6,
        time_cost=15
    )


@pytest.fixture
def sample_cve_entry():
    """Sample CVE entry for testing."""
    return CVEEntry(
        cve_id="CVE-2021-44228",
        description="Apache Log4j remote code execution",
        severity=VulnerabilitySeverity.CRITICAL,
        cvss_score=10.0,
        cvss_vector="AV:N/AC:L/Au:N/C:C/I:C/A:C",
        published_date=datetime(2021, 12, 10),
        modified_date=datetime(2021, 12, 15),
        affected_products=["Apache Log4j2"],
        exploit_available=True
    )


@pytest.fixture
def sample_normalized_result():
    """Sample normalized result for testing."""
    return NormalizedResult(
        finding_id="nmap_001",
        tool_name="nmap",
        timestamp=datetime.now(),
        target="192.168.1.100",
        finding_type="service",
        severity=0.7,
        confidence=0.9,
        description="HTTP service on port 80",
        raw_output="80/tcp open http",
        metadata={"port": 80, "service": "http"}
    )


# ══════════════════════════════════════════════════════════════════════════════
# STRATEGIC BRAIN ENGINE TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestStrategicBrainEngine:
    """Test Strategic Brain Engine functionality."""
    
    @pytest.fixture
    def brain_engine(self):
        """Create brain engine instance."""
        return StrategicBrainEngine()
    
    def test_initialize_operation(self, brain_engine, sample_operation_context):
        """Test operation initialization."""
        operation_config = {
            "target_scope": ["192.168.1.0/24"],
            "objectives": ["reconnaissance"],
            "risk_tolerance": 0.5,
            "stealth_requirement": 0.7
        }
        
        operation_id = asyncio.run(brain_engine.initialize_operation(operation_config))
        
        assert operation_id is not None
        assert operation_id.startswith("op_")
        assert operation_id in brain_engine.active_operations
    
    def test_decide_next_action(self, brain_engine, sample_operation_context):
        """Test strategic decision making."""
        # Add operation to active operations
        brain_engine.active_operations[sample_operation_context.operation_id] = sample_operation_context
        
        decision = asyncio.run(brain_engine.decide_next_action(sample_operation_context.operation_id))
        
        assert "operation_id" in decision
        assert "current_state" in decision
        assert "applicable_rules" in decision
        assert "recommended_actions" in decision
        assert decision["operation_id"] == sample_operation_context.operation_id
    
    def test_update_operation_state(self, brain_engine, sample_operation_context):
        """Test operation state updates."""
        # Add operation
        brain_engine.active_operations[sample_operation_context.operation_id] = sample_operation_context
        
        # Update state
        success = asyncio.run(brain_engine.update_operation_state(
            sample_operation_context.operation_id,
            "enumeration",
            discovered_assets={"host_001": {"type": "server", "os": "linux"}}
        ))
        
        assert success
        updated_context = brain_engine.active_operations[sample_operation_context.operation_id]
        assert updated_context.current_state == OperationState.ENUMERATION
        assert "host_001" in updated_context.discovered_assets
    
    def test_terminate_operation(self, brain_engine, sample_operation_context):
        """Test operation termination."""
        # Add operation
        brain_engine.active_operations[sample_operation_context.operation_id] = sample_operation_context
        
        # Terminate
        success = asyncio.run(brain_engine.terminate_operation(sample_operation_context.operation_id))
        
        assert success
        assert sample_operation_context.operation_id not in brain_engine.active_operations
        assert len(brain_engine.operation_history) == 1


class TestRuleEngine:
    """Test Rule Engine functionality."""
    
    @pytest.fixture
    def rule_engine(self):
        """Create rule engine instance."""
        return RuleEngine()
    
    def test_evaluate_rules(self, rule_engine, sample_operation_context):
        """Test rule evaluation."""
        applicable_rules = rule_engine.evaluate_rules(sample_operation_context)
        
        assert isinstance(applicable_rules, list)
        assert len(applicable_rules) > 0
        
        # Check that rules are sorted by priority
        priorities = [priority for action, priority in applicable_rules]
        assert priorities == sorted(priorities, reverse=True)


class TestBayesianRiskModel:
    """Test Bayesian Risk Model functionality."""
    
    @pytest.fixture
    def risk_model(self):
        """Create risk model instance."""
        return BayesianRiskModel()
    
    def test_calculate_risk(self, risk_model, sample_operation_context):
        """Test risk calculation."""
        from bjhunt_alpha.strategic.brain import AttackTechnique
        
        technique = AttackTechnique(
            technique_id="T1190",
            name="Exploit Public-Facing Application",
            phase=AttackPhase.INITIAL_ACCESS,
            success_probability=0.7,
            impact_score=0.8,
            stealth_score=0.4,
            detection_risk=0.6,
            time_cost=15
        )
        
        risks = risk_model.calculate_risk(technique, sample_operation_context)
        
        assert "detection" in risks
        assert "failure" in risks
        assert "collateral_damage" in risks
        
        # Check that risk values are between 0 and 1
        for risk_type, risk_value in risks.items():
            assert 0 <= risk_value <= 1


# ══════════════════════════════════════════════════════════════════════════════
# ATTACK GRAPH ENGINE TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestAttackGraphEngine:
    """Test Attack Graph Engine functionality."""
    
    @pytest.fixture
    def attack_graph(self):
        """Create attack graph engine instance."""
        return AttackGraphEngine()
    
    def test_add_node(self, attack_graph, sample_graph_node):
        """Test node addition."""
        success = attack_graph.add_node(sample_graph_node)
        
        assert success
        assert sample_graph_node.node_id in attack_graph.nodes
        assert sample_graph_node.node_id in attack_graph.graph.nodes
    
    def test_add_edge(self, attack_graph, sample_graph_node, sample_graph_edge):
        """Test edge addition."""
        # Add nodes first
        target_node = GraphNode(
            node_id="host_002",
            node_type=NodeType.HOST,
            value=0.6,
            defenses=["antivirus"]
        )
        attack_graph.add_node(sample_graph_node)
        attack_graph.add_node(target_node)
        
        # Add edge
        success = attack_graph.add_edge(sample_graph_edge)
        
        assert success
        assert (sample_graph_edge.source_id, sample_graph_edge.target_id) in attack_graph.edges
        assert attack_graph.graph.has_edge(sample_graph_edge.source_id, sample_graph_edge.target_id)
    
    def test_find_optimal_paths(self, attack_graph, sample_graph_node, sample_graph_edge):
        """Test optimal path finding."""
        # Create a simple graph
        target_node = GraphNode(
            node_id="host_002",
            node_type=NodeType.HOST,
            value=0.6
        )
        attack_graph.add_node(sample_graph_node)
        attack_graph.add_node(target_node)
        attack_graph.add_edge(sample_graph_edge)
        
        # Find paths
        paths = attack_graph.find_optimal_paths("host_001", "host_002")
        
        assert len(paths) > 0
        assert paths[0] == ["host_001", "host_002"]
    
    def test_calculate_centrality_metrics(self, attack_graph, sample_graph_node):
        """Test centrality metrics calculation."""
        # Add multiple nodes and edges to create a connected graph
        node2 = GraphNode(node_id="host_002", node_type=NodeType.HOST, value=0.6)
        node3 = GraphNode(node_id="host_003", node_type=NodeType.HOST, value=0.4)
        
        attack_graph.add_node(sample_graph_node)
        attack_graph.add_node(node2)
        attack_graph.add_node(node3)
        
        # Add edges
        edge1 = GraphEdge("host_001", "host_002", EdgeType.EXPLOIT, "T1190", 0.7, 0.8, 0.4, 0.6, 15)
        edge2 = GraphEdge("host_002", "host_003", EdgeType.LATERAL_MOVEMENT, "T1021", 0.8, 0.5, 0.7, 0.3, 10)
        
        attack_graph.add_edge(edge1)
        attack_graph.add_edge(edge2)
        
        # Calculate metrics
        metrics = attack_graph.calculate_centrality_metrics()
        
        assert isinstance(metrics, dict)
        assert len(metrics) == 3  # Three nodes
        assert all("betweenness" in node_metrics for node_metrics in metrics.values())


# ══════════════════════════════════════════════════════════════════════════════
# CORRELATION ENGINE TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestCorrelationEngine:
    """Test Correlation Engine functionality."""
    
    @pytest.fixture
    def correlation_engine(self):
        """Create correlation engine instance."""
        return CorrelationEngine()
    
    def test_process_tool_output_json(self, correlation_engine):
        """Test processing JSON tool output."""
        json_output = json.dumps([
            {"ip": "192.168.1.100", "port": 80, "service": "http", "state": "open"},
            {"ip": "192.168.1.100", "port": 22, "service": "ssh", "state": "open"}
        ])
        
        results = asyncio.run(correlation_engine.process_tool_output(
            json_output, OutputFormat.JSON, "nmap", "192.168.1.100"
        ))
        
        assert len(results) == 2
        assert all(isinstance(result, NormalizedResult) for result in results)
        assert all(result.tool_name == "nmap" for result in results)
    
    def test_correlate_findings(self, correlation_engine, sample_normalized_result):
        """Test finding correlation."""
        # Create duplicate findings
        duplicate_result = NormalizedResult(
            finding_id="nikto_001",
            tool_name="nikto",
            timestamp=datetime.now(),
            target="192.168.1.100",
            finding_type="service",
            severity=0.7,
            confidence=0.9,
            description="Web server detected",
            raw_output="Web server found",
            metadata={"port": 80}
        )
        
        findings = [sample_normalized_result, duplicate_result]
        correlations = asyncio.run(correlation_engine.correlate_findings(findings))
        
        assert len(correlations) >= 1
        assert any(correlation.correlation_type == "confirmation" for correlation in correlations)
    
    def test_detect_anomalies(self, correlation_engine):
        """Test anomaly detection."""
        # Create findings with anomaly
        normal_findings = [
            NormalizedResult("f1", "nmap", datetime.now(), "target1", "service", 0.5, 0.8, "normal", "")
            for _ in range(10)
        ]
        
        # Add outlier
        outlier = NormalizedResult("f_outlier", "nmap", datetime.now(), "target1", "service", 0.9, 0.8, "critical", "")
        normal_findings.append(outlier)
        
        anomalies = correlation_engine.detect_anomalies(normal_findings)
        
        assert len(anomalies) > 0
        assert any("severity_outlier" in anomaly for anomaly in anomalies)


# ══════════════════════════════════════════════════════════════════════════════
# KNOWLEDGE ENGINE TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestKnowledgeDatabase:
    """Test Knowledge Database functionality."""
    
    @pytest.fixture
    def knowledge_db(self, temp_db_path):
        """Create knowledge database instance."""
        return KnowledgeDatabase(temp_db_path)
    
    def test_add_cve_entry(self, knowledge_db, sample_cve_entry):
        """Test CVE entry addition."""
        success = knowledge_db.add_cve_entry(sample_cve_entry)
        
        assert success
        
        # Verify retrieval
        results = knowledge_db.search_cve("CVE-2021-44228")
        assert len(results) == 1
        assert results[0].cve_id == "CVE-2021-44228"
    
    def test_search_cve(self, knowledge_db, sample_cve_entry):
        """Test CVE search."""
        # Add CVE
        knowledge_db.add_cve_entry(sample_cve_entry)
        
        # Search by CVE ID
        results = knowledge_db.search_cve("CVE-2021-44228")
        assert len(results) == 1
        
        # Search by description
        results = knowledge_db.search_cve("Log4j")
        assert len(results) == 1
        
        # Search with no results
        results = knowledge_db.search_cve("CVE-2024-0000")
        assert len(results) == 0
    
    def test_get_attack_techniques_by_phase(self, knowledge_db):
        """Test getting techniques by attack phase."""
        techniques = knowledge_db.get_attack_techniques_by_phase(AttackPhase.DISCOVERY)
        
        assert len(techniques) > 0
        assert all(technique.phase == AttackPhase.DISCOVERY for technique in techniques)
    
    def test_get_knowledge_statistics(self, knowledge_db, sample_cve_entry):
        """Test knowledge statistics."""
        # Add some data
        knowledge_db.add_cve_entry(sample_cve_entry)
        
        stats = knowledge_db.get_knowledge_statistics()
        
        assert "cve_count" in stats
        assert "technique_count" in stats
        assert "knowledge_version" in stats
        assert stats["cve_count"] >= 1


# ══════════════════════════════════════════════════════════════════════════════
# ADAPTIVE EXECUTION LAYER TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestAdaptiveExecutionEngine:
    """Test Adaptive Execution Engine functionality."""
    
    @pytest.fixture
    def execution_engine(self):
        """Create execution engine instance."""
        return AdaptiveExecutionEngine()
    
    @patch('asyncio.create_subprocess_shell')
    async def test_execute_tool_success(self, mock_subprocess, execution_engine):
        """Test successful tool execution."""
        # Mock subprocess
        mock_process = AsyncMock()
        mock_process.communicate.return_value = (b"success output", b"")
        mock_process.returncode = 0
        mock_subprocess.return_value = mock_process
        
        result = await execution_engine.execute_tool(
            tool_name="nmap",
            command="echo test",
            parameters={"target": "127.0.0.1"},
            timeout=30
        )
        
        assert result.status == ExecutionStatus.COMPLETED
        assert result.exit_code == 0
        assert result.retry_count == 0
        assert not result.used_fallback
    
    @patch('asyncio.create_subprocess_shell')
    async def test_execute_tool_with_retry(self, mock_subprocess, execution_engine):
        """Test tool execution with retry."""
        # Mock subprocess failure then success
        mock_process_fail = AsyncMock()
        mock_process_fail.communicate.return_value = (b"", b"error")
        mock_process_fail.returncode = 1
        
        mock_process_success = AsyncMock()
        mock_process_success.communicate.return_value = (b"success", b"")
        mock_process_success.returncode = 0
        
        mock_subprocess.side_effect = [mock_process_fail, mock_process_success]
        
        result = await execution_engine.execute_tool(
            tool_name="nmap",
            command="echo test",
            parameters={},
            timeout=30,
            max_retries=2
        )
        
        assert result.status == ExecutionStatus.COMPLETED
        assert result.retry_count == 1
    
    def test_get_tool_metrics(self, execution_engine):
        """Test tool metrics retrieval."""
        # Initially should be None
        metrics = execution_engine.get_tool_metrics("nmap")
        assert metrics is None
    
    def test_get_global_statistics(self, execution_engine):
        """Test global statistics."""
        stats = execution_engine.get_global_statistics()
        
        assert "total_executions" in stats
        assert "successful_executions" in stats
        assert "failed_executions" in stats
        assert "tool_count" in stats


# ══════════════════════════════════════════════════════════════════════════════
# DISTRIBUTED ORCHESTRATION TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestDistributedOrchestrator:
    """Test Distributed Orchestrator functionality."""
    
    @pytest.fixture
    def orchestrator(self):
        """Create orchestrator instance."""
        return DistributedOrchestrator()
    
    def test_register_worker(self, orchestrator):
        """Test worker registration."""
        from bjhunt_alpha.strategic.orchestration import WorkerNode
        
        worker = WorkerNode(
            worker_id="worker_001",
            hostname="test-host",
            capabilities={"nmap", "nikto"},
            max_concurrent_tasks=5
        )
        
        success = orchestrator.register_worker(worker)
        
        assert success
        assert worker.worker_id in orchestrator.workers
    
    def test_submit_task(self, orchestrator):
        """Test task submission."""
        task = TaskDefinition(
            task_id="task_001",
            task_type=TaskType.SCAN,
            task_name="Network Scan",
            payload={"target": "192.168.1.0/24"},
            priority=2,
            tenant_id="tenant_001",
            user_id="user_001"
        )
        
        success = orchestrator.submit_task(task)
        
        assert success
        assert orchestrator.stats['total_tasks'] == 1
    
    def test_get_queue_statistics(self, orchestrator):
        """Test queue statistics."""
        stats = orchestrator.get_queue_statistics()
        
        assert "queue_size" in stats
        assert "active_tasks" in stats
        assert "active_workers" in stats
        assert "worker_status" in stats


# ══════════════════════════════════════════════════════════════════════════════
# OPSEC LAYER TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestOPSECManager:
    """Test OPSEC Manager functionality."""
    
    @pytest.fixture
    def opsec_manager(self):
        """Create OPSEC manager instance."""
        return OPSECManager()
    
    def test_add_scope(self, opsec_manager):
        """Test scope addition."""
        scope = ScopeDefinition(
            scope_id="scope_001",
            name="Test Scope",
            authorized_targets=["192.168.1.0/24"],
            forbidden_targets=["192.168.1.1"],
            allowed_ports={80, 443, 22},
            forbidden_ports={3389},
            allowed_protocols={"tcp", "udp"},
            stealth_requirement=0.7,
            max_requests_per_minute=100
        )
        
        success = opsec_manager.add_scope(scope)
        
        assert success
        assert scope.scope_id in opsec_manager.scope_enforcer.scopes
    
    def test_validate_operation_success(self, opsec_manager):
        """Test successful operation validation."""
        # Add scope
        scope = ScopeDefinition(
            scope_id="scope_001",
            name="Test Scope",
            authorized_targets=["192.168.1.0/24"],
            allowed_ports={80},
            allowed_protocols={"tcp"},
            stealth_requirement=0.5
        )
        opsec_manager.add_scope(scope)
        
        # Validate operation
        valid, violations = opsec_manager.validate_operation(
            scope_id="scope_001",
            tool_name="nmap",
            target="192.168.1.100",
            port=80,
            protocol="tcp"
        )
        
        assert valid
        assert len(violations) == 0
    
    def test_validate_operation_violation(self, opsec_manager):
        """Test operation validation with violations."""
        # Add restrictive scope
        scope = ScopeDefinition(
            scope_id="scope_001",
            name="Test Scope",
            authorized_targets=["192.168.1.0/24"],
            forbidden_ports={3389},
            stealth_requirement=0.5
        )
        opsec_manager.add_scope(scope)
        
        # Validate operation with forbidden port
        valid, violations = opsec_manager.validate_operation(
            scope_id="scope_001",
            tool_name="nmap",
            target="192.168.1.100",
            port=3389
        )
        
        assert not valid
        assert len(violations) > 0
        assert any(v.violation_type.value == "port_restriction" for v in violations)


# ══════════════════════════════════════════════════════════════════════════════
# GOVERNANCE LAYER TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestGovernanceManager:
    """Test Governance Manager functionality."""
    
    @pytest.fixture
    def governance_manager(self):
        """Create governance manager instance."""
        return GovernanceManager("test-secret-key")
    
    def test_create_user(self, governance_manager):
        """Test user creation."""
        user = governance_manager.rbac.create_user(
            username="testuser",
            email="test@example.com",
            roles={UserRole.ANALYST},
            tenant_id="tenant_001"
        )
        
        assert user is not None
        assert user.username == "testuser"
        assert UserRole.ANALYST in user.roles
        assert Permission.READ in user.permissions
    
    def test_authenticate_user(self, governance_manager):
        """Test user authentication."""
        # Create user first
        user = governance_manager.rbac.create_user(
            username="testuser",
            email="test@example.com",
            roles={UserRole.ANALYST},
            tenant_id="tenant_001"
        )
        
        # Authenticate
        session_token = governance_manager.rbac.authenticate_user("testuser", "password")
        
        assert session_token is not None
        assert session_token in governance_manager.rbac.user_sessions
    
    def test_authorize_operation_success(self, governance_manager):
        """Test successful operation authorization."""
        # Create user and authenticate
        user = governance_manager.rbac.create_user(
            username="testuser",
            email="test@example.com",
            roles={UserRole.OPERATOR},
            tenant_id="tenant_001"
        )
        session_token = governance_manager.rbac.authenticate_user("testuser", "password")
        
        # Authorize operation
        result = governance_manager.authorize_operation(
            session_token=session_token,
            operation="read",
            resource="scan_results",
            context={"tenant_id": "tenant_001"}
        )
        
        assert result['authorized'] is True
    
    def test_enable_kill_switch(self, governance_manager):
        """Test kill switch functionality."""
        governance_manager.enable_kill_switch("Emergency maintenance")
        
        assert governance_manager.kill_switch_enabled is True
        assert governance_manager.kill_switch_reason == "Emergency maintenance"
        
        # Operation should be denied
        result = governance_manager.authorize_operation(
            session_token="fake_token",
            operation="read",
            resource="test"
        )
        
        assert result['authorized'] is False
        assert "kill switch" in result['reason'].lower()


# ══════════════════════════════════════════════════════════════════════════════
# OBSERVABILITY STACK TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestObservabilityManager:
    """Test Observability Manager functionality."""
    
    @pytest.fixture
    def observability_manager(self):
        """Create observability manager instance."""
        return ObservabilityManager()
    
    def test_get_logger(self, observability_manager):
        """Test logger retrieval."""
        logger = observability_manager.get_logger("test_component")
        
        assert logger is not None
        assert logger.component_name == "test_component"
    
    def test_structured_logging(self, observability_manager):
        """Test structured logging."""
        logger = observability_manager.get_logger("test_component")
        
        # Set correlation context
        logger.set_correlation_context(
            correlation_id="corr_001",
            user_id="user_001",
            tenant_id="tenant_001"
        )
        
        # Log message
        logger.info("Test message", operation_type="scan", target="192.168.1.100")
        
        # Get logs
        logs = logger.get_logs(correlation_id="corr_001")
        
        assert len(logs) > 0
        assert logs[0].correlation_id == "corr_001"
        assert logs[0].user_id == "user_001"
        assert logs[0].tenant_id == "tenant_001"
        assert "operation_type" in logs[0].metadata
    
    def test_distributed_tracing(self, observability_manager):
        """Test distributed tracing."""
        tracer = observability_manager.tracer
        
        # Start trace
        span_id = tracer.start_trace("test_operation", tags={"component": "test"})
        
        assert span_id is not None
        assert span_id in tracer.active_spans
        
        # Add tag
        tracer.add_span_tag("user_id", "user_001", span_id)
        
        # Add log
        tracer.add_span_log("info", "Operation started", {"step": 1}, span_id)
        
        # Finish span
        tracer.finish_span(span_id, "ok")
        
        # Verify span is finished
        assert span_id not in tracer.active_spans
        
        # Get trace
        trace = tracer.get_trace(tracer.active_spans[span_id].trace_id if tracer.active_spans else "test")
        assert len(trace) >= 1
    
    def test_metrics_collection(self, observability_manager):
        """Test metrics collection."""
        metrics = observability_manager.metrics_collector
        
        # Define metric
        metrics.define_metric("test_counter", MetricType.COUNTER, "Test counter metric")
        
        # Record metric
        metrics.increment_counter("test_counter", 1.0, {"label": "test"})
        
        # Get metrics
        metric_data = metrics.get_metrics("test_counter")
        
        assert len(metric_data) > 0
        assert metric_data[0].name == "test_counter"
        assert metric_data[0].value == 1.0
        assert metric_data[0].metric_type == MetricType.COUNTER
    
    def test_health_checks(self, observability_manager):
        """Test health checks."""
        health_checker = observability_manager.health_checker
        
        # Run all health checks
        results = health_checker.run_all_health_checks()
        
        assert isinstance(results, dict)
        assert len(results) >= 3  # At least cpu, memory, disk checks
        
        # Get overall health
        overall_status, message = health_checker.get_overall_health()
        
        assert overall_status in [status.value for status in HealthStatus]
        assert message is not None
    
    def test_dashboard_data(self, observability_manager):
        """Test dashboard data creation."""
        dashboard_data = observability_manager.create_dashboard_data()
        
        assert "timestamp" in dashboard_data
        assert "health" in dashboard_data
        assert "metrics" in dashboard_data
        assert "alerts" in dashboard_data
        assert "logs" in dashboard_data
        assert "tracing" in dashboard_data
        
        # Verify health section
        health = dashboard_data["health"]
        assert "overall_status" in health
        assert "checks" in health
        
        # Verify metrics section
        metrics = dashboard_data["metrics"]
        assert "cpu" in metrics
        assert "memory" in metrics
        assert "prometheus_export" in metrics


# ══════════════════════════════════════════════════════════════════════════════
# INTEGRATION TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestStrategicIntegration:
    """Integration tests for strategic components."""
    
    @pytest.fixture
    def integrated_system(self):
        """Create integrated system with all components."""
        return {
            'brain': StrategicBrainEngine(),
            'attack_graph': AttackGraphEngine(),
            'correlation': CorrelationEngine(),
            'knowledge': KnowledgeDatabase(":memory:"),
            'execution': AdaptiveExecutionEngine(),
            'orchestration': DistributedOrchestrator(),
            'opsec': OPSECManager(),
            'governance': GovernanceManager("integration-test-key"),
            'observability': ObservabilityManager()
        }
    
    def test_end_to_end_operation_flow(self, integrated_system):
        """Test end-to-end operation flow."""
        # 1. Initialize operation in brain engine
        brain = integrated_system['brain']
        operation_id = asyncio.run(brain.initialize_operation({
            "target_scope": ["192.168.1.0/24"],
            "objectives": ["reconnaissance"],
            "risk_tolerance": 0.5
        }))
        
        # 2. Add nodes to attack graph
        attack_graph = integrated_system['attack_graph']
        node = GraphNode("target_001", NodeType.HOST, 0.8)
        attack_graph.add_node(node)
        
        # 3. Process tool output through correlation
        correlation = integrated_system['correlation']
        results = asyncio.run(correlation.process_tool_output(
            json.dumps([{"ip": "192.168.1.100", "port": 80}]),
            OutputFormat.JSON,
            "nmap",
            "192.168.1.100"
        ))
        
        # 4. Update operation with discovered assets
        asyncio.run(brain.update_operation_state(
            operation_id,
            "enumeration",
            discovered_assets={"target_001": {"ip": "192.168.1.100", "services": ["http"]}}
        ))
        
        # 5. Get strategic decision
        decision = asyncio.run(brain.decide_next_action(operation_id))
        
        # Verify integration
        assert operation_id in brain.active_operations
        assert len(results) > 0
        assert "target_001" in attack_graph.nodes
        assert decision["operation_id"] == operation_id
    
    def test_observability_across_components(self, integrated_system):
        """Test observability across all components."""
        observability = integrated_system['observability']
        
        # Get loggers for different components
        brain_logger = observability.get_logger("strategic_brain")
        graph_logger = observability.get_logger("attack_graph")
        
        # Set correlation context
        correlation_id = "integration_test_001"
        brain_logger.set_correlation_context(correlation_id, "user_001", "tenant_001")
        graph_logger.set_correlation_context(correlation_id, "user_001", "tenant_001")
        
        # Log from different components
        brain_logger.info("Brain operation started", operation_id="op_001")
        graph_logger.info("Graph node added", node_id="node_001")
        
        # Start distributed trace
        tracer = observability.tracer
        span_id = tracer.start_trace("integration_test", tags={"test": True})
        
        # Record metrics
        metrics = observability.metrics_collector
        metrics.increment_counter("operations_total", 1.0, {"component": "brain"})
        metrics.set_gauge("active_nodes", 5.0, {"component": "graph"})
        
        # Finish trace
        tracer.finish_span(span_id)
        
        # Verify observability data
        all_logs = brain_logger.get_logs(correlation_id=correlation_id)
        assert len(all_logs) >= 2
        
        trace_data = tracer.get_trace(tracer.active_spans.get(span_id, tracer.trace_history[0]).trace_id if tracer.trace_history else "test")
        assert len(trace_data) >= 1
        
        dashboard_data = observability.create_dashboard_data()
        assert dashboard_data["logs"]["recent_count"] >= 2


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])
