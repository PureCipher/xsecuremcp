"""Tests for the reflexive monitors."""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock

from fastmcp.reflexive.monitor import PolicyMonitor, LedgerMonitor, AnomalyDetector
from fastmcp.reflexive.engine import ActionContext


class TestPolicyMonitor:
    """Test the PolicyMonitor class."""
    
    @pytest.fixture
    def policy_monitor(self):
        """Create a policy monitor for testing."""
        return PolicyMonitor()
    
    @pytest.fixture
    def action_context(self):
        """Create an action context for testing."""
        return ActionContext(
            action_id="test_action",
            actor_id="test_user",
            action_type="tool_call",
            resource_id="test_resource"
        )
    
    async def test_monitor_no_violations(self, policy_monitor, action_context):
        """Test monitoring with no violations."""
        result = await policy_monitor(action_context)
        assert result is None
    
    async def test_monitor_admin_access_violation(self, policy_monitor, action_context):
        """Test monitoring admin access violation."""
        # Create action context with admin access by guest user
        admin_context = ActionContext(
            action_id="admin_action",
            actor_id="guest_user",
            action_type="admin_access",
            resource_id="admin_panel"
        )
        
        result = await policy_monitor(admin_context)
        
        assert result is not None
        assert result["type"] == "violation"
        assert result["severity"] == "high"
        assert len(result["violations"]) == 1
        assert result["violations"][0]["rule"] == "admin_access_restriction"
    
    async def test_monitor_rate_limit_violation(self, policy_monitor, action_context):
        """Test monitoring rate limit violation."""
        # Add multiple violations for the same actor
        for i in range(5):
            violation_context = ActionContext(
                action_id=f"action_{i}",
                actor_id="rate_limit_user",
                action_type="api_call"
            )
            
            # Manually add violations to history
            policy_monitor.violation_history.append({
                "type": "violation",
                "severity": "low",
                "actor_id": "rate_limit_user",
                "action_id": f"action_{i}",
                "timestamp": datetime.utcnow().isoformat()
            })
        
        # Test rate limit violation
        result = await policy_monitor(action_context)
        
        # Should not trigger rate limit for different actor
        assert result is None
        
        # Test with same actor
        rate_limit_context = ActionContext(
            action_id="rate_limit_action",
            actor_id="rate_limit_user",
            action_type="api_call"
        )
        
        result = await policy_monitor(rate_limit_context)
        
        assert result is not None
        assert result["type"] == "violation"
        assert result["severity"] == "medium"
        assert len(result["violations"]) == 1
        assert result["violations"][0]["rule"] == "rate_limit_exceeded"
    
    async def test_monitor_sensitive_resource_violation(self, policy_monitor, action_context):
        """Test monitoring sensitive resource access violation."""
        sensitive_context = ActionContext(
            action_id="sensitive_action",
            actor_id="unauthorized_user",
            action_type="data_access",
            resource_id="sensitive_data",
            metadata={"authorized": False}
        )
        
        result = await policy_monitor(sensitive_context)
        
        assert result is not None
        assert result["type"] == "violation"
        assert result["severity"] == "critical"
        assert len(result["violations"]) == 1
        assert result["violations"][0]["rule"] == "unauthorized_sensitive_access"
    
    def test_assess_violation_severity(self, policy_monitor):
        """Test violation severity assessment."""
        # Test critical severity
        critical_violations = [{"severity": "critical"}]
        assert policy_monitor._assess_violation_severity(critical_violations) == "critical"
        
        # Test high severity
        high_violations = [{"severity": "high"}]
        assert policy_monitor._assess_violation_severity(high_violations) == "high"
        
        # Test medium severity
        medium_violations = [{"severity": "medium"}]
        assert policy_monitor._assess_violation_severity(medium_violations) == "medium"
        
        # Test low severity
        low_violations = [{"severity": "low"}]
        assert policy_monitor._assess_violation_severity(low_violations) == "low"
        
        # Test mixed severities
        mixed_violations = [{"severity": "low"}, {"severity": "high"}]
        assert policy_monitor._assess_violation_severity(mixed_violations) == "high"
    
    def test_get_violation_stats(self, policy_monitor):
        """Test getting violation statistics."""
        # Add some violations
        policy_monitor.violation_history.append({
            "type": "violation",
            "severity": "high",
            "actor_id": "user1",
            "action_id": "action1",
            "timestamp": datetime.utcnow().isoformat()
        })
        
        policy_monitor.actor_violations["user1"] = 1
        policy_monitor.actor_violations["user2"] = 2
        
        stats = policy_monitor.get_violation_stats()
        
        assert stats["total_violations"] == 1
        assert stats["actor_violations"]["user1"] == 1
        assert stats["actor_violations"]["user2"] == 2
        assert "recent_violations" in stats


class TestLedgerMonitor:
    """Test the LedgerMonitor class."""
    
    @pytest.fixture
    def ledger_monitor(self):
        """Create a ledger monitor for testing."""
        return LedgerMonitor()
    
    @pytest.fixture
    def mock_ledger(self):
        """Create a mock ledger for testing."""
        mock_ledger = Mock()
        mock_ledger.verify_chain_integrity.return_value = True
        mock_ledger.get_ledger_statistics.return_value = {
            "total_entries": 10,
            "total_blocks": 2
        }
        return mock_ledger
    
    @pytest.fixture
    def action_context(self):
        """Create an action context for testing."""
        return ActionContext(
            action_id="test_action",
            actor_id="test_user",
            action_type="tool_call"
        )
    
    async def test_monitor_no_issues(self, ledger_monitor, mock_ledger, action_context):
        """Test monitoring with no ledger issues."""
        ledger_monitor.ledger = mock_ledger
        
        result = await ledger_monitor(action_context)
        assert result is None
    
    async def test_monitor_chain_integrity_issue(self, ledger_monitor, mock_ledger, action_context):
        """Test monitoring chain integrity issue."""
        # Mock chain integrity failure
        mock_ledger.verify_chain_integrity.return_value = False
        ledger_monitor.ledger = mock_ledger
        
        result = await ledger_monitor(action_context)
        
        assert result is not None
        assert result["type"] == "anomaly"
        assert result["severity"] == "critical"
        assert len(result["issues"]) == 1
        assert result["issues"][0]["type"] == "chain_integrity"
    
    async def test_monitor_missing_blocks_issue(self, ledger_monitor, mock_ledger, action_context):
        """Test monitoring missing blocks issue."""
        # Mock missing blocks scenario
        mock_ledger.get_ledger_statistics.return_value = {
            "total_entries": 10,
            "total_blocks": 0
        }
        ledger_monitor.ledger = mock_ledger
        
        result = await ledger_monitor(action_context)
        
        assert result is not None
        assert result["type"] == "anomaly"
        assert result["severity"] == "high"
        assert len(result["issues"]) == 1
        assert result["issues"][0]["type"] == "missing_blocks"
    
    async def test_monitor_integrity_check_error(self, ledger_monitor, action_context):
        """Test monitoring with integrity check error."""
        # Mock ledger that raises exception
        mock_ledger = Mock()
        mock_ledger.verify_chain_integrity.side_effect = Exception("Database error")
        ledger_monitor.ledger = mock_ledger
        
        result = await ledger_monitor(action_context)
        
        assert result is not None
        assert result["type"] == "anomaly"
        assert result["severity"] == "medium"
        assert len(result["issues"]) == 1
        assert result["issues"][0]["type"] == "integrity_check_error"
    
    def test_assess_integrity_severity(self, ledger_monitor):
        """Test integrity severity assessment."""
        # Test critical severity
        critical_issues = [{"severity": "critical"}]
        assert ledger_monitor._assess_integrity_severity(critical_issues) == "critical"
        
        # Test high severity
        high_issues = [{"severity": "high"}]
        assert ledger_monitor._assess_integrity_severity(high_issues) == "high"
        
        # Test medium severity
        medium_issues = [{"severity": "medium"}]
        assert ledger_monitor._assess_integrity_severity(medium_issues) == "medium"
        
        # Test low severity
        low_issues = [{"severity": "low"}]
        assert ledger_monitor._assess_integrity_severity(low_issues) == "low"
    
    def test_get_integrity_stats(self, ledger_monitor):
        """Test getting integrity statistics."""
        # Add some integrity checks
        ledger_monitor.integrity_checks.append({
            "type": "anomaly",
            "severity": "high",
            "timestamp": datetime.utcnow().isoformat()
        })
        
        stats = ledger_monitor.get_integrity_stats()
        
        assert stats["total_checks"] == 1
        assert "recent_issues" in stats


class TestAnomalyDetector:
    """Test the AnomalyDetector class."""
    
    @pytest.fixture
    def anomaly_detector(self):
        """Create an anomaly detector for testing."""
        return AnomalyDetector()
    
    @pytest.fixture
    def action_context(self):
        """Create an action context for testing."""
        return ActionContext(
            action_id="test_action",
            actor_id="test_user",
            action_type="tool_call",
            resource_id="test_resource"
        )
    
    async def test_detector_no_anomalies(self, anomaly_detector, action_context):
        """Test detection with no anomalies."""
        # First access to a resource will be flagged as new resource access
        # So we need to access the resource twice to avoid the "new resource" anomaly
        await anomaly_detector(action_context)
        result = await anomaly_detector(action_context)
        assert result is None
    
    async def test_detector_high_frequency_anomaly(self, anomaly_detector, action_context):
        """Test detection of high frequency anomaly."""
        # Add many recent actions for the same actor
        for i in range(25):
            recent_context = ActionContext(
                action_id=f"action_{i}",
                actor_id="high_frequency_user",
                action_type="api_call"
            )
            anomaly_detector._update_patterns(recent_context)
        
        # Test high frequency detection
        high_freq_context = ActionContext(
            action_id="high_freq_action",
            actor_id="high_frequency_user",
            action_type="api_call"
        )
        
        result = await anomaly_detector(high_freq_context)
        
        assert result is not None
        assert result["type"] == "anomaly"
        assert result["severity"] == "medium"
        assert len(result["anomalies"]) == 1
        assert result["anomalies"][0]["type"] == "high_frequency"
    
    async def test_detector_unusual_timing_anomaly(self, anomaly_detector, action_context):
        """Test detection of unusual timing anomaly."""
        # Create action at unusual hour with new action type
        unusual_context = ActionContext(
            action_id="unusual_action",
            actor_id="test_user",
            action_type="new_action_type"  # New action type
        )
        unusual_context.timestamp = datetime.utcnow().replace(hour=3)  # 3 AM
        
        result = await anomaly_detector(unusual_context)
        
        assert result is not None
        assert result["type"] == "anomaly"
        assert result["severity"] == "low"
        assert len(result["anomalies"]) == 1
        assert result["anomalies"][0]["type"] == "unusual_timing"
    
    async def test_detector_new_resource_access_anomaly(self, anomaly_detector, action_context):
        """Test detection of new resource access anomaly."""
        # First access to a resource
        new_resource_context = ActionContext(
            action_id="new_resource_action",
            actor_id="test_user",
            action_type="data_access",
            resource_id="new_resource"
        )
        
        result = await anomaly_detector(new_resource_context)
        
        assert result is not None
        assert result["type"] == "anomaly"
        assert result["severity"] == "low"
        assert len(result["anomalies"]) == 1
        assert result["anomalies"][0]["type"] == "new_resource_access"
    
    async def test_detector_privilege_escalation_anomaly(self, anomaly_detector, action_context):
        """Test detection of privilege escalation anomaly."""
        # First time performing privileged action
        privilege_context = ActionContext(
            action_id="privilege_action",
            actor_id="test_user",
            action_type="admin_access",
            resource_id="admin_panel"
        )
        
        result = await anomaly_detector(privilege_context)
        
        assert result is not None
        assert result["type"] == "anomaly"
        assert result["severity"] == "high"
        # Should detect both new resource access and privilege escalation
        assert len(result["anomalies"]) >= 1
        # Check that privilege escalation is detected
        privilege_anomalies = [a for a in result["anomalies"] if a["type"] == "privilege_escalation"]
        assert len(privilege_anomalies) == 1
        assert privilege_anomalies[0]["type"] == "privilege_escalation"
    
    def test_update_patterns(self, anomaly_detector, action_context):
        """Test pattern updating."""
        # Update patterns
        anomaly_detector._update_patterns(action_context)
        
        # Check that patterns were updated
        actor_data = anomaly_detector.actor_patterns[action_context.actor_id]
        assert actor_data["action_counts"][action_context.action_type] == 1
        assert actor_data["resource_access"][action_context.resource_id] == 1
        assert len(actor_data["session_times"]) == 1
        assert actor_data["last_seen"] == action_context.timestamp
        
        # Check global patterns
        assert anomaly_detector.global_patterns["action_frequency"][action_context.action_type] == 1
        assert anomaly_detector.global_patterns["resource_access"][action_context.resource_id] == 1
    
    def test_assess_anomaly_severity(self, anomaly_detector):
        """Test anomaly severity assessment."""
        # Test high severity
        high_anomalies = [{"severity": "high"}]
        assert anomaly_detector._assess_anomaly_severity(high_anomalies) == "high"
        
        # Test medium severity
        medium_anomalies = [{"severity": "medium"}]
        assert anomaly_detector._assess_anomaly_severity(medium_anomalies) == "medium"
        
        # Test low severity
        low_anomalies = [{"severity": "low"}]
        assert anomaly_detector._assess_anomaly_severity(low_anomalies) == "low"
        
        # Test mixed severities
        mixed_anomalies = [{"severity": "low"}, {"severity": "high"}]
        assert anomaly_detector._assess_anomaly_severity(mixed_anomalies) == "high"
    
    def test_get_anomaly_stats(self, anomaly_detector, action_context):
        """Test getting anomaly statistics."""
        # Update patterns for some actors
        anomaly_detector._update_patterns(action_context)
        
        another_context = ActionContext(
            action_id="another_action",
            actor_id="another_user",
            action_type="another_type"
        )
        anomaly_detector._update_patterns(another_context)
        
        stats = anomaly_detector.get_anomaly_stats()
        
        assert stats["tracked_actors"] == 2
        assert stats["global_action_types"] == 2
        assert stats["global_resources"] == 1
