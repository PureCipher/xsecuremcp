"""Tests for policy HTTP endpoints."""

import pytest
from fastmcp import FastMCP
from fastmcp.policy import PolicyEngine
from fastmcp.policy.policies import MinimumNecessaryAccessPolicy, RBACPolicy
from starlette.routing import Route


class TestPolicyHTTPEndpoint:
    """Test the policy evaluation HTTP endpoint."""
    
    @pytest.fixture
    def server_with_policy(self):
        """Create a server with policy engine enabled."""
        server = FastMCP("Test Policy Server")
        policy_engine = server.enable_policy_engine()
        
        # Register policies
        policy_engine.register_policy(MinimumNecessaryAccessPolicy())
        policy_engine.register_policy(RBACPolicy())
        
        return server
    
    @pytest.fixture
    def app(self, server_with_policy):
        """Create the HTTP app with policy endpoint."""
        return server_with_policy.http_app(transport="sse")
    
    def test_policy_evaluate_endpoint_exists(self, app):
        """Test that the policy evaluation endpoint exists in the app."""
        # Check that the policy route exists
        policy_route_found = False
        for route in app.routes:
            if isinstance(route, Route) and route.path == "/policy/evaluate":
                policy_route_found = True
                break
        
        assert policy_route_found, "Policy evaluation endpoint not found in app routes"
    
    def test_policy_engine_integration(self, server_with_policy):
        """Test that policy engine is properly integrated with the server."""
        # Check that policy engine is enabled
        assert server_with_policy.get_policy_engine() is not None
        
        # Check that policies are registered
        policy_engine = server_with_policy.get_policy_engine()
        policies = policy_engine.get_policy_metadata()
        assert len(policies) == 2
        
        # Check that both policies are present
        policy_names = [p["name"] for p in policies]
        assert "minimum_necessary_access" in policy_names
        assert "rbac" in policy_names
