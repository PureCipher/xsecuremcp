"""Tests for the reflexive HTTP endpoints."""

import pytest
import httpx
from unittest.mock import Mock, AsyncMock

from fastmcp.server.server import FastMCP
from fastmcp.reflexive import ReflexiveEngine, ActionContext, DecisionType, RiskLevel
from fastmcp.server.http import create_streamable_http_app


@pytest.fixture(name="server_with_reflexive")
async def server_with_reflexive_fixture():
    """Fixture for a FastMCP server with an enabled reflexive core."""
    server = FastMCP("TestReflexiveServer")
    reflexive_engine = server.enable_reflexive_core()
    return server, reflexive_engine


@pytest.fixture
async def client(server_with_reflexive):
    """Create an HTTP client for testing."""
    server, reflexive_engine = server_with_reflexive
    app = create_streamable_http_app(server, streamable_http_path="/")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # Store server and reflexive engine in client for test access
        client.server = server
        client.reflexive_engine = reflexive_engine
        yield client


class TestReflexiveHTTPEndpoints:
    """Test the reflexive HTTP endpoints."""
    
    async def test_simulate_risk_endpoint(self, client):
        """Test the simulate risk endpoint."""
        risk_scenario = {
            "action_context": {
                "action_id": "test_action",
                "actor_id": "test_user",
                "action_type": "admin_access",
                "resource_id": "admin_panel"
            },
            "scenario_type": "policy_violation"
        }
        
        response = await client.post("/core/simulate-risk", json=risk_scenario)
        
        assert response.status_code == 200
        data = response.json()
        assert "simulation_id" in data
        assert "decision" in data
        assert "action" in data
        assert "action_context" in data
        
        # Check decision structure
        decision = data["decision"]
        assert "decision_id" in decision
        assert "decision_type" in decision
        assert "risk_level" in decision
        assert "reason" in decision
        assert "proof_hash" in decision
        
        # Check action structure
        action = data["action"]
        assert "action_id" in action
        assert "action_type" in action
        assert "status" in action
        assert "result" in action
    
    async def test_simulate_risk_invalid_data(self, client):
        """Test simulate risk endpoint with invalid data."""
        invalid_scenario = {
            "invalid_field": "invalid_value"
        }
        
        response = await client.post("/core/simulate-risk", json=invalid_scenario)
        
        assert response.status_code == 400
        data = response.json()
        assert "error" in data
        assert "Missing required field: action_context" in data["error"]
    
    async def test_get_engine_status_endpoint(self, client):
        """Test the get engine status endpoint."""
        response = await client.get("/core/status")
        
        assert response.status_code == 200
        data = response.json()
        assert "is_running" in data
        assert "monitor_count" in data
        assert "queue_size" in data
        assert "decision_handlers" in data
    
    async def test_submit_action_endpoint(self, client):
        """Test the submit action endpoint."""
        action_data = {
            "action_id": "test_action",
            "actor_id": "test_user",
            "action_type": "tool_call",
            "resource_id": "test_resource",
            "metadata": {"test": "data"}
        }
        
        response = await client.post("/core/submit-action", json=action_data)
        
        assert response.status_code == 202
        data = response.json()
        assert "message" in data
        assert "action_id" in data
        assert "submitted_at" in data
        assert data["action_id"] == "test_action"
    
    async def test_submit_action_invalid_data(self, client):
        """Test submit action endpoint with invalid data."""
        invalid_action = {
            "invalid_field": "invalid_value"
        }
        
        response = await client.post("/core/submit-action", json=invalid_action)
        
        assert response.status_code == 400
        data = response.json()
        assert "error" in data
        assert "Invalid action data" in data["error"]
    
    async def test_get_monitor_stats_endpoint(self, client):
        """Test the get monitor stats endpoint."""
        response = await client.get("/core/monitor-stats")
        
        assert response.status_code == 200
        data = response.json()
        # Should return empty dict if no monitors are configured
        assert isinstance(data, dict)
    
    async def test_create_risk_scenario_endpoint(self, client):
        """Test the create risk scenario endpoint."""
        scenario_data = {
            "scenario_name": "admin_privilege_escalation",
            "scenario_type": "policy_violation",
            "parameters": {
                "actor_type": "guest_user",
                "target_resource": "admin_panel",
                "severity": "high"
            }
        }
        
        response = await client.post("/core/risk-scenario", json=scenario_data)
        
        assert response.status_code == 200
        data = response.json()
        assert "scenario" in data
        assert "message" in data
        assert data["message"] == "Risk scenario 'admin_privilege_escalation' created successfully"
        
        # Check scenario structure
        scenario = data["scenario"]
        assert "action_context" in scenario
        assert "expected_decision" in scenario
        assert "expected_risk_level" in scenario
        
        # Check action context
        action_context = scenario["action_context"]
        assert action_context["action_type"] == "admin_access"
        assert action_context["resource_id"] == "admin_panel"
    
    async def test_create_risk_scenario_missing_fields(self, client):
        """Test create risk scenario endpoint with missing fields."""
        invalid_scenario = {
            "scenario_name": "test_scenario"
            # Missing scenario_type
        }
        
        response = await client.post("/core/risk-scenario", json=invalid_scenario)
        
        assert response.status_code == 400
        data = response.json()
        assert "error" in data
        assert "Missing required fields" in data["error"]
    
    async def test_create_risk_scenario_unknown_type(self, client):
        """Test create risk scenario endpoint with unknown scenario type."""
        scenario_data = {
            "scenario_name": "unknown_scenario",
            "scenario_type": "unknown_type",
            "parameters": {}
        }
        
        response = await client.post("/core/risk-scenario", json=scenario_data)
        
        assert response.status_code == 200
        data = response.json()
        assert "scenario" in data
        
        # Should create a custom scenario
        scenario = data["scenario"]
        assert scenario["action_context"]["action_id"] == "custom_unknown_scenario"
        assert scenario["expected_decision"] == "monitor"
        assert scenario["expected_risk_level"] == "low"
    
    async def test_simulate_risk_with_violations(self, client):
        """Test simulate risk with policy violations."""
        # Add a monitor that returns violations
        def violation_monitor(context):
            return {
                "type": "violation",
                "severity": "high",
                "violations": [{"rule": "admin_restriction", "message": "Unauthorized admin access", "severity": "high"}]
            }
        
        client.reflexive_engine.add_monitor(violation_monitor)
        
        risk_scenario = {
            "action_context": {
                "action_id": "admin_action",
                "actor_id": "guest_user",
                "action_type": "admin_access",
                "resource_id": "admin_panel"
            }
        }
        
        response = await client.post("/core/simulate-risk", json=risk_scenario)
        
        assert response.status_code == 200
        data = response.json()
        
        # Should result in a halt decision
        decision = data["decision"]
        assert decision["decision_type"] == "halt"
        assert decision["risk_level"] == "high"
        assert "violations" in decision["evidence"]
    
    async def test_simulate_risk_with_anomalies(self, client):
        """Test simulate risk with anomalies."""
        # Add a monitor that returns anomalies
        def anomaly_monitor(context):
            return {
                "type": "anomaly",
                "severity": "medium",
                "anomalies": [{"type": "unusual_timing", "message": "Action at unusual hour", "severity": "medium"}]
            }
        
        client.reflexive_engine.add_monitor(anomaly_monitor)
        
        risk_scenario = {
            "action_context": {
                "action_id": "unusual_action",
                "actor_id": "test_user",
                "action_type": "data_access",
                "resource_id": "sensitive_data"
            }
        }
        
        response = await client.post("/core/simulate-risk", json=risk_scenario)
        
        assert response.status_code == 200
        data = response.json()
        
        # Should result in an escalate decision
        decision = data["decision"]
        assert decision["decision_type"] == "escalate"
        assert decision["risk_level"] == "medium"
        assert "anomalies" in decision["evidence"]
    
    async def test_simulate_risk_no_issues(self, client):
        """Test simulate risk with no violations or anomalies."""
        risk_scenario = {
            "action_context": {
                "action_id": "normal_action",
                "actor_id": "authorized_user",
                "action_type": "normal_operation",
                "resource_id": "public_resource"
            }
        }
        
        response = await client.post("/core/simulate-risk", json=risk_scenario)
        
        assert response.status_code == 200
        data = response.json()
        
        # Should result in an allow decision
        decision = data["decision"]
        assert decision["decision_type"] == "allow"
        assert decision["risk_level"] == "low"
        assert decision["reason"] == "No violations or anomalies detected"
    
    async def test_multiple_risk_scenarios(self, client):
        """Test multiple predefined risk scenarios."""
        scenarios = [
            {
                "name": "admin_privilege_escalation",
                "expected_decision": "halt",
                "expected_risk": "high"
            },
            {
                "name": "suspicious_activity",
                "expected_decision": "escalate",
                "expected_risk": "medium"
            },
            {
                "name": "integrity_violation",
                "expected_decision": "halt",
                "expected_risk": "critical"
            },
            {
                "name": "rate_limit_exceeded",
                "expected_decision": "escalate",
                "expected_risk": "medium"
            }
        ]
        
        for scenario in scenarios:
            scenario_data = {
                "scenario_name": scenario["name"],
                "scenario_type": "test",
                "parameters": {}
            }
            
            response = await client.post("/core/risk-scenario", json=scenario_data)
            assert response.status_code == 200
            
            data = response.json()
            created_scenario = data["scenario"]
            assert created_scenario["expected_decision"] == scenario["expected_decision"]
            assert created_scenario["expected_risk_level"] == scenario["expected_risk"]
