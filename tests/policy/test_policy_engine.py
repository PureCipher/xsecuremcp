"""Tests for the policy engine."""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch

from fastmcp.policy import PolicyEngine, PolicyRegistry, Decision
from fastmcp.policy.policies import MinimumNecessaryAccessPolicy, RBACPolicy


class TestPolicyEngine:
    """Test the policy engine functionality."""
    
    @pytest.fixture
    def policy_engine(self):
        """Create a policy engine for testing."""
        return PolicyEngine()
    
    @pytest.fixture
    def sample_context(self):
        """Create a sample context for testing."""
        return {
            "user": {
                "id": "user123",
                "roles": ["user"],
                "permissions": ["read", "write"]
            },
            "action": "read",
            "resource": {
                "type": "document",
                "id": "doc123",
                "owner": "user123",
                "visibility": "private"
            }
        }
    
    def test_policy_engine_initialization(self, policy_engine):
        """Test policy engine initialization."""
        assert policy_engine.registry is not None
        assert isinstance(policy_engine.registry, PolicyRegistry)
        assert policy_engine._evaluation_order == []
    
    def test_set_evaluation_order(self, policy_engine):
        """Test setting evaluation order."""
        order = ["policy1", "policy2", "policy3"]
        policy_engine.set_evaluation_order(order)
        assert policy_engine._evaluation_order == order
    
    @pytest.mark.asyncio
    async def test_evaluate_no_policies(self, policy_engine, sample_context):
        """Test evaluation when no policies are registered."""
        decision = await policy_engine.evaluate(sample_context)
        assert decision.allow is True
        assert "All policies evaluated successfully" in decision.reason
    
    @pytest.mark.asyncio
    async def test_evaluate_single_policy(self, policy_engine, sample_context):
        """Test evaluation of a single policy."""
        # Register a policy
        policy = MinimumNecessaryAccessPolicy()
        policy_engine.register_policy(policy)
        
        # Evaluate
        decision = await policy_engine.evaluate(sample_context)
        assert decision.allow is True
        # The policy engine returns its own response, not the individual policy response
        assert "All policies evaluated successfully" in decision.reason
    
    @pytest.mark.asyncio
    async def test_evaluate_specific_policies(self, policy_engine, sample_context):
        """Test evaluation of specific policies."""
        # Register multiple policies
        policy1 = MinimumNecessaryAccessPolicy(name="policy1")
        policy2 = RBACPolicy(name="policy2")
        policy_engine.register_policy(policy1)
        policy_engine.register_policy(policy2)
        
        # Evaluate only policy1
        decision = await policy_engine.evaluate(sample_context, ["policy1"])
        assert decision.allow is True
    
    @pytest.mark.asyncio
    async def test_evaluate_policy_denial(self, policy_engine):
        """Test evaluation when a policy denies access."""
        # Create context with sensitive action
        context = {
            "user": {"roles": ["user"]},
            "action": "delete",
            "resource": {"type": "user_data"}
        }
        
        # Register minimum necessary policy
        policy = MinimumNecessaryAccessPolicy()
        policy_engine.register_policy(policy)
        
        # Evaluate
        decision = await policy_engine.evaluate(context)
        assert decision.allow is False
        assert "requires justification" in decision.reason
    
    @pytest.mark.asyncio
    async def test_evaluate_single_policy_method(self, policy_engine, sample_context):
        """Test evaluate_single_policy method."""
        # Register a policy
        policy = MinimumNecessaryAccessPolicy(name="test_policy")
        policy_engine.register_policy(policy)
        
        # Evaluate single policy
        decision = await policy_engine.evaluate_single_policy("test_policy", sample_context)
        assert decision is not None
        assert decision.allow is True
    
    @pytest.mark.asyncio
    async def test_evaluate_single_policy_not_found(self, policy_engine, sample_context):
        """Test evaluate_single_policy with non-existent policy."""
        decision = await policy_engine.evaluate_single_policy("non_existent", sample_context)
        assert decision is None
    
    def test_get_policy_metadata(self, policy_engine):
        """Test getting policy metadata."""
        # Register policies
        policy1 = MinimumNecessaryAccessPolicy(name="policy1")
        policy2 = RBACPolicy(name="policy2")
        policy_engine.register_policy(policy1)
        policy_engine.register_policy(policy2)
        
        metadata = policy_engine.get_policy_metadata()
        assert len(metadata) == 2
        assert any(p["name"] == "policy1" for p in metadata)
        assert any(p["name"] == "policy2" for p in metadata)
    
    def test_register_unregister_policy(self, policy_engine):
        """Test policy registration and unregistration."""
        policy = MinimumNecessaryAccessPolicy(name="test_policy")
        
        # Register
        policy_engine.register_policy(policy)
        assert policy_engine.registry.get_policy("test_policy") is not None
        
        # Unregister
        unregistered = policy_engine.unregister_policy("test_policy")
        assert unregistered is not None
        assert unregistered.name == "test_policy"
        assert policy_engine.registry.get_policy("test_policy") is None


class TestPolicyRegistry:
    """Test the policy registry functionality."""
    
    @pytest.fixture
    def registry(self):
        """Create a policy registry for testing."""
        return PolicyRegistry()
    
    def test_registry_initialization(self, registry):
        """Test registry initialization."""
        assert registry._policies == {}
        assert registry._policy_classes == {}
    
    def test_register_policy(self, registry):
        """Test policy registration."""
        policy = MinimumNecessaryAccessPolicy()
        registry.register_policy(policy)
        assert "minimum_necessary_access" in registry._policies
    
    def test_unregister_policy(self, registry):
        """Test policy unregistration."""
        policy = MinimumNecessaryAccessPolicy()
        registry.register_policy(policy)
        
        unregistered = registry.unregister_policy("minimum_necessary_access")
        assert unregistered is not None
        assert "minimum_necessary_access" not in registry._policies
    
    def test_get_policy(self, registry):
        """Test getting a policy."""
        policy = MinimumNecessaryAccessPolicy()
        registry.register_policy(policy)
        
        retrieved = registry.get_policy("minimum_necessary_access")
        assert retrieved is not None
        assert retrieved.name == "minimum_necessary_access"
    
    def test_list_policies(self, registry):
        """Test listing policies."""
        policy1 = MinimumNecessaryAccessPolicy(name="policy1")
        policy2 = RBACPolicy(name="policy2")
        registry.register_policy(policy1)
        registry.register_policy(policy2)
        
        policies = registry.list_policies()
        assert len(policies) == 2
        assert any(p["name"] == "policy1" for p in policies)
        assert any(p["name"] == "policy2" for p in policies)
    
    def test_register_policy_class(self, registry):
        """Test registering a policy class."""
        registry.register_policy_class("test_policy", MinimumNecessaryAccessPolicy)
        assert "test_policy" in registry._policy_classes
        assert registry._policy_classes["test_policy"] == MinimumNecessaryAccessPolicy
    
    def test_register_invalid_policy_class(self, registry):
        """Test registering an invalid policy class."""
        with pytest.raises(ValueError):
            registry.register_policy_class("invalid", str)
    
    def test_create_policy_from_config(self, registry):
        """Test creating policy from configuration."""
        registry.register_policy_class("test_policy", MinimumNecessaryAccessPolicy)
        
        config = {
            "type": "test_policy",
            "parameters": {
                "name": "config_policy",
                "required_justification": False
            }
        }
        
        policy = registry.create_policy_from_config(config)
        assert policy is not None
        assert policy.name == "config_policy"
        assert isinstance(policy, MinimumNecessaryAccessPolicy)
    
    def test_create_policy_from_invalid_config(self, registry):
        """Test creating policy from invalid configuration."""
        config = {"type": "non_existent"}
        policy = registry.create_policy_from_config(config)
        assert policy is None


class TestPolicyLoadAndReload:
    """Test policy loading and hot-reload functionality."""
    
    @pytest.fixture
    def registry(self):
        """Create a policy registry for testing."""
        return PolicyRegistry()
    
    @pytest.fixture
    def yaml_config_file(self, tmp_path):
        """Create a temporary YAML config file."""
        config_content = """
policies:
  - name: yaml_policy1
    type: minimum_necessary
    parameters:
      required_justification: false
  - name: yaml_policy2
    type: rbac
    parameters:
      version: "1.0.0"
"""
        config_file = tmp_path / "policies.yaml"
        config_file.write_text(config_content)
        return config_file
    
    def test_load_policies_from_yaml(self, registry, yaml_config_file):
        """Test loading policies from YAML file."""
        # Register policy classes
        registry.register_policy_class("minimum_necessary", MinimumNecessaryAccessPolicy)
        registry.register_policy_class("rbac", RBACPolicy)
        
        # Load from YAML
        registry.load_policies_from_yaml(yaml_config_file)
        
        # Check that policies were loaded
        assert registry.get_policy("yaml_policy1") is not None
        assert registry.get_policy("yaml_policy2") is not None
    
    def test_hot_reload_policies(self, registry, yaml_config_file):
        """Test hot reloading policies."""
        # Register policy classes
        registry.register_policy_class("minimum_necessary", MinimumNecessaryAccessPolicy)
        registry.register_policy_class("rbac", RBACPolicy)
        
        # Initial load
        registry.load_policies_from_yaml(yaml_config_file)
        initial_count = len(registry._policies)
        
        # Hot reload
        registry.hot_reload_policies(yaml_config_file)
        
        # Check that policies were reloaded
        assert len(registry._policies) == initial_count
        assert registry.get_policy("yaml_policy1") is not None
        assert registry.get_policy("yaml_policy2") is not None
    
    @patch('importlib.metadata.entry_points')
    def test_load_policy_from_entry_point(self, mock_entry_points, registry):
        """Test loading policies from entry points."""
        # Mock entry points
        mock_entry_point = Mock()
        mock_entry_point.name = "test_policy"
        mock_entry_point.load.return_value = MinimumNecessaryAccessPolicy
        
        mock_entry_points.return_value.select.return_value = [mock_entry_point]
        
        # Load from entry points
        registry.load_policy_from_entry_point("fastmcp.policies")
        
        # Check that policy was loaded
        assert registry.get_policy("test_policy") is not None


class TestPolicyIntegration:
    """Test policy integration with FastMCP server."""
    
    @pytest.mark.asyncio
    async def test_policy_engine_with_server(self):
        """Test policy engine integration with FastMCP server."""
        from fastmcp import FastMCP
        
        # Create server with policy engine
        server = FastMCP("Test Server")
        policy_engine = server.enable_policy_engine()
        
        # Register policies
        policy_engine.register_policy(MinimumNecessaryAccessPolicy())
        policy_engine.register_policy(RBACPolicy())
        
        # Test that policy engine is accessible
        assert server.get_policy_engine() is not None
        assert server.get_policy_engine() == policy_engine
        
        # Test policy evaluation
        context = {
            "user": {"roles": ["user"]},
            "action": "read",
            "resource": {"type": "document"}
        }
        
        decision = await policy_engine.evaluate(context)
        assert decision.allow is True
