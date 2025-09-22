"""Tests for the reflexive actions."""

import pytest
from datetime import datetime
from unittest.mock import Mock

from fastmcp.reflexive.actions import (
    HaltAction, EscalateAction, MonitorAction, AllowAction,
    ActionFactory, ActionExecutor
)
from fastmcp.reflexive.engine import ReflexiveDecision, ActionContext, DecisionType, RiskLevel


class TestHaltAction:
    """Test the HaltAction class."""
    
    @pytest.fixture
    def halt_decision(self):
        """Create a halt decision for testing."""
        action_context = ActionContext(
            action_id="test_action",
            actor_id="test_user",
            action_type="admin_access"
        )
        
        return ReflexiveDecision(
            decision_type=DecisionType.HALT,
            risk_level=RiskLevel.HIGH,
            action_context=action_context,
            reason="Unauthorized admin access attempt"
        )
    
    @pytest.fixture
    def halt_action(self, halt_decision):
        """Create a halt action for testing."""
        return HaltAction(
            decision=halt_decision,
            halt_reason="Security violation detected",
            halt_level="immediate",
            affected_operations=["admin_access", "user_management"]
        )
    
    def test_halt_action_creation(self, halt_action, halt_decision):
        """Test halt action creation."""
        assert halt_action.decision == halt_decision
        assert halt_action.halt_reason == "Security violation detected"
        assert halt_action.halt_level == "immediate"
        assert halt_action.affected_operations == ["admin_access", "user_management"]
        assert halt_action.status == "pending"
        assert halt_action.result is None
    
    async def test_halt_action_execution(self, halt_action):
        """Test halt action execution."""
        result = await halt_action.execute()
        
        assert halt_action.status == "completed"
        assert halt_action.result is not None
        assert result["halted_operations"] == ["admin_access", "user_management"]
        assert result["halt_reason"] == "Security violation detected"
        assert result["halt_level"] == "immediate"
        assert "halt_timestamp" in result
        assert "decision_id" in result
    
    def test_halt_action_type(self, halt_action):
        """Test halt action type."""
        assert halt_action.get_action_type() == "halt"


class TestEscalateAction:
    """Test the EscalateAction class."""
    
    @pytest.fixture
    def escalate_decision(self):
        """Create an escalate decision for testing."""
        action_context = ActionContext(
            action_id="test_action",
            actor_id="test_user",
            action_type="data_access"
        )
        
        return ReflexiveDecision(
            decision_type=DecisionType.ESCALATE,
            risk_level=RiskLevel.MEDIUM,
            action_context=action_context,
            reason="Suspicious data access pattern"
        )
    
    @pytest.fixture
    def escalate_action(self, escalate_decision):
        """Create an escalate action for testing."""
        return EscalateAction(
            decision=escalate_decision,
            escalation_target="security_team",
            escalation_priority="high",
            escalation_context={"alert_level": "medium"},
            notification_channels=["email", "slack"]
        )
    
    def test_escalate_action_creation(self, escalate_action, escalate_decision):
        """Test escalate action creation."""
        assert escalate_action.decision == escalate_decision
        assert escalate_action.escalation_target == "security_team"
        assert escalate_action.escalation_priority == "high"
        assert escalate_action.escalation_context == {"alert_level": "medium"}
        assert escalate_action.notification_channels == ["email", "slack"]
        assert escalate_action.status == "pending"
        assert escalate_action.result is None
    
    async def test_escalate_action_execution(self, escalate_action):
        """Test escalate action execution."""
        result = await escalate_action.execute()
        
        assert escalate_action.status == "completed"
        assert escalate_action.result is not None
        assert result["escalation_target"] == "security_team"
        assert result["escalation_priority"] == "high"
        assert result["escalation_context"] == {"alert_level": "medium"}
        assert result["notification_channels"] == ["email", "slack"]
        assert "escalation_timestamp" in result
        assert "decision_id" in result
        assert "action_context" in result
    
    def test_escalate_action_type(self, escalate_action):
        """Test escalate action type."""
        assert escalate_action.get_action_type() == "escalate"


class TestMonitorAction:
    """Test the MonitorAction class."""
    
    @pytest.fixture
    def monitor_decision(self):
        """Create a monitor decision for testing."""
        action_context = ActionContext(
            action_id="test_action",
            actor_id="test_user",
            action_type="api_call"
        )
        
        return ReflexiveDecision(
            decision_type=DecisionType.MONITOR,
            risk_level=RiskLevel.LOW,
            action_context=action_context,
            reason="Unusual but not suspicious activity"
        )
    
    @pytest.fixture
    def monitor_action(self, monitor_decision):
        """Create a monitor action for testing."""
        return MonitorAction(
            decision=monitor_decision,
            monitoring_level="enhanced",
            monitoring_duration=1800,
            monitoring_scope=["test_user", "api_calls"]
        )
    
    def test_monitor_action_creation(self, monitor_action, monitor_decision):
        """Test monitor action creation."""
        assert monitor_action.decision == monitor_decision
        assert monitor_action.monitoring_level == "enhanced"
        assert monitor_action.monitoring_duration == 1800
        assert monitor_action.monitoring_scope == ["test_user", "api_calls"]
        assert monitor_action.status == "pending"
        assert monitor_action.result is None
    
    async def test_monitor_action_execution(self, monitor_action):
        """Test monitor action execution."""
        result = await monitor_action.execute()
        
        assert monitor_action.status == "completed"
        assert monitor_action.result is not None
        assert result["monitoring_level"] == "enhanced"
        assert result["monitoring_duration"] == 1800
        assert result["monitoring_scope"] == ["test_user", "api_calls"]
        assert "monitoring_timestamp" in result
        assert "decision_id" in result
        assert "action_context" in result
    
    def test_monitor_action_type(self, monitor_action):
        """Test monitor action type."""
        assert monitor_action.get_action_type() == "monitor"


class TestAllowAction:
    """Test the AllowAction class."""
    
    @pytest.fixture
    def allow_decision(self):
        """Create an allow decision for testing."""
        action_context = ActionContext(
            action_id="test_action",
            actor_id="test_user",
            action_type="normal_operation"
        )
        
        return ReflexiveDecision(
            decision_type=DecisionType.ALLOW,
            risk_level=RiskLevel.LOW,
            action_context=action_context,
            reason="No violations or anomalies detected"
        )
    
    @pytest.fixture
    def allow_action(self, allow_decision):
        """Create an allow action for testing."""
        return AllowAction(
            decision=allow_decision,
            allow_conditions=["authenticated", "authorized"],
            allow_restrictions=["rate_limited"]
        )
    
    def test_allow_action_creation(self, allow_action, allow_decision):
        """Test allow action creation."""
        assert allow_action.decision == allow_decision
        assert allow_action.allow_conditions == ["authenticated", "authorized"]
        assert allow_action.allow_restrictions == ["rate_limited"]
        assert allow_action.status == "pending"
        assert allow_action.result is None
    
    async def test_allow_action_execution(self, allow_action):
        """Test allow action execution."""
        result = await allow_action.execute()
        
        assert allow_action.status == "completed"
        assert allow_action.result is not None
        assert result["allowed"] is True
        assert result["allow_conditions"] == ["authenticated", "authorized"]
        assert result["allow_restrictions"] == ["rate_limited"]
        assert "allow_timestamp" in result
        assert "decision_id" in result
        assert "action_context" in result
    
    def test_allow_action_type(self, allow_action):
        """Test allow action type."""
        assert allow_action.get_action_type() == "allow"


class TestActionFactory:
    """Test the ActionFactory class."""
    
    @pytest.fixture
    def halt_decision(self):
        """Create a halt decision for testing."""
        action_context = ActionContext(
            action_id="test_action",
            actor_id="test_user",
            action_type="admin_access"
        )
        
        return ReflexiveDecision(
            decision_type=DecisionType.HALT,
            risk_level=RiskLevel.HIGH,
            action_context=action_context,
            reason="Security violation"
        )
    
    @pytest.fixture
    def escalate_decision(self):
        """Create an escalate decision for testing."""
        action_context = ActionContext(
            action_id="test_action",
            actor_id="test_user",
            action_type="data_access"
        )
        
        return ReflexiveDecision(
            decision_type=DecisionType.ESCALATE,
            risk_level=RiskLevel.MEDIUM,
            action_context=action_context,
            reason="Suspicious activity"
        )
    
    @pytest.fixture
    def monitor_decision(self):
        """Create a monitor decision for testing."""
        action_context = ActionContext(
            action_id="test_action",
            actor_id="test_user",
            action_type="api_call"
        )
        
        return ReflexiveDecision(
            decision_type=DecisionType.MONITOR,
            risk_level=RiskLevel.LOW,
            action_context=action_context,
            reason="Unusual activity"
        )
    
    @pytest.fixture
    def allow_decision(self):
        """Create an allow decision for testing."""
        action_context = ActionContext(
            action_id="test_action",
            actor_id="test_user",
            action_type="normal_operation"
        )
        
        return ReflexiveDecision(
            decision_type=DecisionType.ALLOW,
            risk_level=RiskLevel.LOW,
            action_context=action_context,
            reason="No issues detected"
        )
    
    def test_create_halt_action(self, halt_decision):
        """Test creating a halt action."""
        action = ActionFactory.create_action(halt_decision)
        
        assert isinstance(action, HaltAction)
        assert action.decision == halt_decision
        assert action.halt_reason == halt_decision.reason
        assert action.halt_level == "immediate"
        assert halt_decision.action_context.action_id in action.affected_operations
    
    def test_create_escalate_action(self, escalate_decision):
        """Test creating an escalate action."""
        action = ActionFactory.create_action(escalate_decision)
        
        assert isinstance(action, EscalateAction)
        assert action.decision == escalate_decision
        assert action.escalation_target == "default_admin"
        assert action.escalation_priority == "normal"
    
    def test_create_monitor_action(self, monitor_decision):
        """Test creating a monitor action."""
        action = ActionFactory.create_action(monitor_decision)
        
        assert isinstance(action, MonitorAction)
        assert action.decision == monitor_decision
        assert action.monitoring_level == "enhanced"
        assert action.monitoring_duration == 3600
    
    def test_create_allow_action(self, allow_decision):
        """Test creating an allow action."""
        action = ActionFactory.create_action(allow_decision)
        
        assert isinstance(action, AllowAction)
        assert action.decision == allow_decision
        assert action.allow_conditions == []
        assert action.allow_restrictions == []
    
    def test_create_action_with_kwargs(self, halt_decision):
        """Test creating an action with additional kwargs."""
        action = ActionFactory.create_action(
            halt_decision,
            halt_level="graceful",
            affected_operations=["operation1", "operation2"]
        )
        
        assert isinstance(action, HaltAction)
        assert action.halt_level == "graceful"
        assert action.affected_operations == ["operation1", "operation2"]
    
    def test_create_action_unknown_type(self, halt_decision):
        """Test creating an action with unknown decision type."""
        halt_decision.decision_type = "unknown_type"  # type: ignore
        
        with pytest.raises(ValueError, match="Unknown decision type"):
            ActionFactory.create_action(halt_decision)


class TestActionExecutor:
    """Test the ActionExecutor class."""
    
    @pytest.fixture
    def action_executor(self):
        """Create an action executor for testing."""
        return ActionExecutor()
    
    @pytest.fixture
    def halt_action(self):
        """Create a halt action for testing."""
        action_context = ActionContext(
            action_id="test_action",
            actor_id="test_user",
            action_type="admin_access"
        )
        
        decision = ReflexiveDecision(
            decision_type=DecisionType.HALT,
            risk_level=RiskLevel.HIGH,
            action_context=action_context,
            reason="Security violation"
        )
        
        return HaltAction(
            decision=decision,
            halt_reason="Unauthorized access",
            halt_level="immediate",
            affected_operations=[action_context.action_id]
        )
    
    async def test_execute_action_success(self, action_executor, halt_action):
        """Test successful action execution."""
        result = await action_executor.execute_action(halt_action)
        
        assert result["halted_operations"] == [halt_action.decision.action_context.action_id]
        assert result["halt_reason"] == "Unauthorized access"
        assert result["halt_level"] == "immediate"
        
        # Check execution history
        assert len(action_executor.execution_history) == 1
        history_record = action_executor.execution_history[0]
        assert history_record["action_id"] == str(halt_action.action_id)
        assert history_record["action_type"] == "halt"
        assert history_record["status"] == "completed"
        assert "end_time" in history_record
        assert "result" in history_record
    
    async def test_execute_action_failure(self, action_executor):
        """Test action execution failure."""
        # Create a mock action that raises an exception
        mock_action = Mock()
        mock_action.action_id = "test_action_id"
        mock_action.decision = Mock()
        mock_action.decision.decision_id = "test_decision_id"
        mock_action.execute.side_effect = Exception("Execution failed")
        mock_action.get_action_type.return_value = "test_type"
        mock_action.timestamp = datetime.utcnow()
        mock_action.status = "pending"
        
        with pytest.raises(Exception, match="Execution failed"):
            await action_executor.execute_action(mock_action)
        
        # Check execution history
        assert len(action_executor.execution_history) == 1
        history_record = action_executor.execution_history[0]
        assert history_record["action_id"] == "test_action_id"
        assert history_record["status"] == "failed"
        assert "error" in history_record
        assert history_record["error"] == "Execution failed"
    
    def test_get_execution_stats(self, action_executor):
        """Test getting execution statistics."""
        # Add some execution history
        action_executor.execution_history = [
            {"action_id": "1", "status": "completed"},
            {"action_id": "2", "status": "completed"},
            {"action_id": "3", "status": "failed"},
        ]
        
        stats = action_executor.get_execution_stats()
        
        assert stats["total_actions"] == 3
        assert stats["completed_actions"] == 2
        assert stats["failed_actions"] == 1
        assert stats["active_actions"] == 0
        assert stats["success_rate"] == 2/3
    
    def test_active_actions_tracking(self, action_executor, halt_action):
        """Test active actions tracking."""
        # Start execution (this would normally be async)
        action_executor.active_actions[str(halt_action.action_id)] = halt_action
        
        assert len(action_executor.active_actions) == 1
        assert str(halt_action.action_id) in action_executor.active_actions
        
        # Simulate completion
        del action_executor.active_actions[str(halt_action.action_id)]
        
        assert len(action_executor.active_actions) == 0
