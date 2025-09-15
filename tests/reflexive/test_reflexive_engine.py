"""Tests for the reflexive engine."""

import pytest
from datetime import datetime
from unittest.mock import Mock, AsyncMock

from fastmcp.reflexive import ReflexiveEngine, ActionContext, DecisionType, RiskLevel
from fastmcp.reflexive.engine import ReflexiveDecision


class TestReflexiveEngine:
    """Test the reflexive engine functionality."""
    
    @pytest.fixture
    def reflexive_engine(self):
        """Create a reflexive engine for testing."""
        return ReflexiveEngine()
    
    @pytest.fixture
    def action_context(self):
        """Create an action context for testing."""
        return ActionContext(
            action_id="test_action_123",
            actor_id="test_user",
            action_type="tool_call",
            resource_id="test_resource",
            metadata={"test": "data"}
        )
    
    def test_engine_initialization(self, reflexive_engine):
        """Test reflexive engine initialization."""
        assert reflexive_engine.policy_engine is None
        assert reflexive_engine.ledger is None
        assert len(reflexive_engine.monitors) == 0
        assert len(reflexive_engine.decision_handlers) == 4
        assert not reflexive_engine.is_running
    
    def test_engine_status(self, reflexive_engine):
        """Test getting engine status."""
        status = reflexive_engine.get_engine_status()
        
        assert "is_running" in status
        assert "monitor_count" in status
        assert "queue_size" in status
        assert "decision_handlers" in status
        
        assert status["is_running"] is False
        assert status["monitor_count"] == 0
        assert len(status["decision_handlers"]) == 4
    
    def test_add_remove_monitor(self, reflexive_engine):
        """Test adding and removing monitors."""
        def test_monitor(context):
            return None
        
        # Add monitor
        reflexive_engine.add_monitor(test_monitor)
        assert len(reflexive_engine.monitors) == 1
        assert test_monitor in reflexive_engine.monitors
        
        # Remove monitor
        reflexive_engine.remove_monitor(test_monitor)
        assert len(reflexive_engine.monitors) == 0
        assert test_monitor not in reflexive_engine.monitors
    
    async def test_submit_action(self, reflexive_engine, action_context):
        """Test submitting an action for evaluation."""
        await reflexive_engine.submit_action(action_context)
        
        # Check that action was added to queue
        assert reflexive_engine.event_queue.qsize() == 1
    
    async def test_evaluate_action_no_violations(self, reflexive_engine, action_context):
        """Test evaluating an action with no violations."""
        decision = await reflexive_engine._evaluate_action(action_context)
        
        assert decision.decision_type == DecisionType.ALLOW
        assert decision.risk_level == RiskLevel.LOW
        assert decision.reason == "No violations or anomalies detected"
        assert decision.action_context == action_context
        assert decision.proof_hash is not None
    
    async def test_evaluate_action_with_violations(self, reflexive_engine, action_context):
        """Test evaluating an action with violations."""
        # Add a monitor that returns violations
        def violation_monitor(context):
            return {
                "type": "violation",
                "severity": "high",
                "violations": [{"rule": "test_rule", "message": "Test violation", "severity": "high"}]
            }
        
        reflexive_engine.add_monitor(violation_monitor)
        
        decision = await reflexive_engine._evaluate_action(action_context)
        
        assert decision.decision_type == DecisionType.HALT
        assert decision.risk_level == RiskLevel.HIGH
        assert "violations" in decision.evidence
        assert len(decision.evidence["violations"]) == 1
    
    async def test_evaluate_action_with_anomalies(self, reflexive_engine, action_context):
        """Test evaluating an action with anomalies."""
        # Add a monitor that returns anomalies
        def anomaly_monitor(context):
            return {
                "type": "anomaly",
                "severity": "medium",
                "anomalies": [{"type": "test_anomaly", "message": "Test anomaly", "severity": "medium"}]
            }
        
        reflexive_engine.add_monitor(anomaly_monitor)
        
        decision = await reflexive_engine._evaluate_action(action_context)
        
        assert decision.decision_type == DecisionType.ESCALATE
        assert decision.risk_level == RiskLevel.MEDIUM
        assert "anomalies" in decision.evidence
        assert len(decision.evidence["anomalies"]) == 1
    
    async def test_evaluate_action_critical_violation(self, reflexive_engine, action_context):
        """Test evaluating an action with critical violations."""
        # Add a monitor that returns critical violations
        def critical_monitor(context):
            return {
                "type": "violation",
                "severity": "critical",
                "violations": [{"rule": "critical_rule", "message": "Critical violation", "severity": "critical"}]
            }
        
        reflexive_engine.add_monitor(critical_monitor)
        
        decision = await reflexive_engine._evaluate_action(action_context)
        
        assert decision.decision_type == DecisionType.HALT
        assert decision.risk_level == RiskLevel.CRITICAL
    
    async def test_simulate_risk(self, reflexive_engine):
        """Test risk simulation."""
        risk_scenario = {
            "action_context": {
                "action_id": "simulation_action",
                "actor_id": "test_actor",
                "action_type": "admin_access",
                "resource_id": "sensitive_data"
            },
            "monitors": [
                lambda ctx: {
                    "type": "violation",
                    "severity": "high",
                    "violations": [{"rule": "admin_restriction", "message": "Unauthorized admin access", "severity": "high"}]
                }
            ]
        }
        
        decision = await reflexive_engine.simulate_risk(risk_scenario)
        
        assert decision.decision_type == DecisionType.HALT
        assert decision.risk_level == RiskLevel.HIGH
        assert decision.action_context.action_id == "simulation_action"
    
    def test_assess_risk_level(self, reflexive_engine):
        """Test risk level assessment."""
        # Test critical risk
        critical_violations = [{"severity": "critical"}]
        assert reflexive_engine._assess_risk_level(critical_violations, []) == RiskLevel.CRITICAL
        
        # Test high risk
        high_violations = [{"severity": "high"}]
        assert reflexive_engine._assess_risk_level(high_violations, []) == RiskLevel.HIGH
        
        # Test medium risk
        medium_violations = [{"severity": "medium"}]
        assert reflexive_engine._assess_risk_level(medium_violations, []) == RiskLevel.MEDIUM
        
        # Test low risk
        low_violations = [{"severity": "low"}]
        assert reflexive_engine._assess_risk_level(low_violations, []) == RiskLevel.LOW
        
        # Test multiple issues
        multiple_issues = [{"severity": "low"}, {"severity": "low"}, {"severity": "low"}]
        assert reflexive_engine._assess_risk_level(multiple_issues, []) == RiskLevel.MEDIUM
    
    def test_determine_escalation_target(self, reflexive_engine):
        """Test escalation target determination."""
        decision = ReflexiveDecision(
            decision_type=DecisionType.ESCALATE,
            risk_level=RiskLevel.CRITICAL,
            action_context=ActionContext(action_id="test", actor_id="test", action_type="test"),
            reason="Test"
        )
        
        target = reflexive_engine._determine_escalation_target(decision)
        assert target == "security_admin"
        
        decision.risk_level = RiskLevel.HIGH
        target = reflexive_engine._determine_escalation_target(decision)
        assert target == "system_admin"
        
        decision.risk_level = RiskLevel.MEDIUM
        target = reflexive_engine._determine_escalation_target(decision)
        assert target == "monitoring_team"


class TestActionContext:
    """Test the ActionContext class."""
    
    def test_action_context_creation(self):
        """Test creating an action context."""
        context = ActionContext(
            action_id="test_action",
            actor_id="test_actor",
            action_type="test_type"
        )
        
        assert context.action_id == "test_action"
        assert context.actor_id == "test_actor"
        assert context.action_type == "test_type"
        assert context.resource_id is None
        assert context.metadata == {}
        assert isinstance(context.timestamp, datetime)
    
    def test_action_context_hash(self):
        """Test action context hash generation."""
        context1 = ActionContext(
            action_id="test_action",
            actor_id="test_actor",
            action_type="test_type",
            metadata={"key": "value"}
        )
        
        context2 = ActionContext(
            action_id="test_action",
            actor_id="test_actor",
            action_type="test_type",
            metadata={"key": "value"}
        )
        
        # Same content should produce same hash
        assert context1.get_context_hash() == context2.get_context_hash()
        
        # Different content should produce different hash
        context3 = ActionContext(
            action_id="different_action",
            actor_id="test_actor",
            action_type="test_type",
            metadata={"key": "value"}
        )
        
        assert context1.get_context_hash() != context3.get_context_hash()


class TestReflexiveDecision:
    """Test the ReflexiveDecision class."""
    
    def test_decision_creation(self):
        """Test creating a reflexive decision."""
        action_context = ActionContext(
            action_id="test_action",
            actor_id="test_actor",
            action_type="test_type"
        )
        
        decision = ReflexiveDecision(
            decision_type=DecisionType.HALT,
            risk_level=RiskLevel.HIGH,
            action_context=action_context,
            reason="Test reason"
        )
        
        assert decision.decision_type == DecisionType.HALT
        assert decision.risk_level == RiskLevel.HIGH
        assert decision.action_context == action_context
        assert decision.reason == "Test reason"
        assert decision.evidence == {}
        assert decision.escalated_to is None
        assert decision.proof_hash is None
        assert isinstance(decision.timestamp, datetime)
    
    def test_decision_hash(self):
        """Test decision hash generation."""
        from uuid import uuid4
        
        action_context = ActionContext(
            action_id="test_action",
            actor_id="test_actor",
            action_type="test_type"
        )
        
        # Use the same decision_id for both decisions
        decision_id = uuid4()
        
        decision1 = ReflexiveDecision(
            decision_id=decision_id,
            decision_type=DecisionType.HALT,
            risk_level=RiskLevel.HIGH,
            action_context=action_context,
            reason="Test reason"
        )
        
        decision2 = ReflexiveDecision(
            decision_id=decision_id,
            decision_type=DecisionType.HALT,
            risk_level=RiskLevel.HIGH,
            action_context=action_context,
            reason="Test reason"
        )
        
        # Same content should produce same hash
        assert decision1.get_decision_hash() == decision2.get_decision_hash()
        
        # Different content should produce different hash
        decision3 = ReflexiveDecision(
            decision_type=DecisionType.ESCALATE,
            risk_level=RiskLevel.HIGH,
            action_context=action_context,
            reason="Test reason"
        )
        
        assert decision1.get_decision_hash() != decision3.get_decision_hash()
