"""
FastMCP Policy Engine Example

This example demonstrates the pluggable policy engine with:
- Minimum Necessary Access Policy
- RBAC Policy
- Policy evaluation via HTTP endpoint
- Hot reloading of policies
"""

import asyncio
import json
from pathlib import Path

from fastmcp import FastMCP
from fastmcp.policy import PolicyEngine
from fastmcp.policy.policies import MinimumNecessaryAccessPolicy, RBACPolicy


def create_policy_example():
    """Create a FastMCP server with policy engine enabled."""
    
    # Create server
    server = FastMCP("Policy Example Server")
    
    # Enable policy engine
    policy_engine = server.enable_policy_engine()
    
    # Register built-in policies
    policy_engine.register_policy(MinimumNecessaryAccessPolicy())
    policy_engine.register_policy(RBACPolicy())
    
    # Add a simple tool that demonstrates policy evaluation
    @server.tool
    async def access_resource(user_id: str, action: str, resource_type: str) -> dict:
        """Access a resource with policy evaluation."""
        
        # Create context for policy evaluation
        context = {
            "user": {
                "id": user_id,
                "roles": ["user"] if user_id != "admin" else ["admin"],
                "permissions": ["read", "write"] if user_id != "admin" else ["*"]
            },
            "action": action,
            "resource": {
                "type": resource_type,
                "id": f"{resource_type}_123",
                "owner": user_id,
                "visibility": "private"
            }
        }
        
        # Evaluate policies
        decision = await policy_engine.evaluate(context)
        
        return {
            "access_granted": decision.allow,
            "reason": decision.reason,
            "obligations": decision.obligations,
            "proof": decision.proof
        }
    
    return server


async def demonstrate_policy_evaluation():
    """Demonstrate policy evaluation with different scenarios."""
    
    server = create_policy_example()
    policy_engine = server.get_policy_engine()
    assert policy_engine is not None  # Ensure policy engine is enabled
    
    print("🔐 FastMCP Policy Engine Example")
    print("=" * 50)
    
    # Test scenarios
    scenarios = [
        {
            "name": "Regular user reading document",
            "user_id": "user123",
            "action": "read",
            "resource_type": "document"
        },
        {
            "name": "Regular user deleting sensitive data",
            "user_id": "user123",
            "action": "delete",
            "resource_type": "user_data"
        },
        {
            "name": "Admin accessing sensitive data",
            "user_id": "admin",
            "action": "delete",
            "resource_type": "user_data"
        },
        {
            "name": "User without roles",
            "user_id": "guest",
            "action": "read",
            "resource_type": "document"
        }
    ]
    
    for scenario in scenarios:
        print(f"\n📋 Scenario: {scenario['name']}")
        print("-" * 40)
        
        # Create context
        context = {
            "user": {
                "id": scenario["user_id"],
                "roles": ["user"] if scenario["user_id"] != "admin" else ["admin"],
                "permissions": ["read", "write"] if scenario["user_id"] != "admin" else ["*"]
            },
            "action": scenario["action"],
            "resource": {
                "type": scenario["resource_type"],
                "id": f"{scenario['resource_type']}_123",
                "owner": scenario["user_id"],
                "visibility": "private"
            }
        }
        
        # Evaluate policies
        decision = await policy_engine.evaluate(context)
        
        print(f"User: {scenario['user_id']}")
        print(f"Action: {scenario['action']}")
        print(f"Resource: {scenario['resource_type']}")
        print(f"Decision: {'✅ ALLOW' if decision.allow else '❌ DENY'}")
        print(f"Reason: {decision.reason}")
        
        if decision.obligations:
            print("Obligations:")
            for obligation in decision.obligations:
                print(f"  - {obligation.get('type', 'unknown')}: {obligation.get('description', 'No description')}")
        
        if decision.proof:
            print(f"Proof: {json.dumps(decision.proof, indent=2)}")


def create_yaml_config():
    """Create a YAML configuration file for policies."""
    
    config_content = """
policies:
  - name: custom_minimum_necessary
    type: minimum_necessary
    parameters:
      required_justification: true
      sensitive_actions:
        - "delete"
        - "admin"
        - "privileged"
      sensitive_resources:
        - "user_data"
        - "financial"
        - "medical"
  
  - name: custom_rbac
    type: rbac
    parameters:
      version: "1.0.0"
      roles:
        admin:
          description: "Administrator with full access"
          permissions: ["*"]
        user:
          description: "Regular user with basic access"
          permissions: ["read", "write"]
        guest:
          description: "Guest user with read-only access"
          permissions: ["read"]
"""
    
    config_path = Path("policies.yaml")
    config_path.write_text(config_content)
    print(f"📄 Created YAML config: {config_path}")
    return config_path


async def demonstrate_hot_reload():
    """Demonstrate hot reloading of policies."""
    
    print("\n🔄 Hot Reload Demonstration")
    print("=" * 50)
    
    # Create server with policy engine
    server = create_policy_example()
    policy_engine = server.get_policy_engine()
    assert policy_engine is not None  # Ensure policy engine is enabled
    
    # Register policy classes for YAML loading
    policy_engine.registry.register_policy_class("minimum_necessary", MinimumNecessaryAccessPolicy)
    policy_engine.registry.register_policy_class("rbac", RBACPolicy)
    
    # Create YAML config
    config_path = create_yaml_config()
    
    # Load policies from YAML
    print("Loading policies from YAML...")
    policy_engine.registry.load_policies_from_yaml(config_path)
    
    # List loaded policies
    policies = policy_engine.get_policy_metadata()
    print(f"Loaded {len(policies)} policies:")
    for policy in policies:
        print(f"  - {policy['name']} ({policy['type']}) v{policy['version']}")
    
    # Demonstrate hot reload
    print("\nHot reloading policies...")
    policy_engine.registry.hot_reload_policies(config_path)
    
    # Clean up
    config_path.unlink()
    print("✅ Hot reload demonstration complete")


def main():
    """Run the policy engine example."""
    
    async def run_example():
        # Demonstrate policy evaluation
        await demonstrate_policy_evaluation()
        
        # Demonstrate hot reload
        await demonstrate_hot_reload()
        
        print("\n🚀 Policy Engine Example Complete!")
        print("\nTo test the HTTP endpoint:")
        print("1. Run: fastmcp run examples/policy_example.py --transport http")
        print("2. POST to /policy/evaluate with JSON body:")
        print("""
{
  "context": {
    "user": {"id": "user123", "roles": ["user"]},
    "action": "read",
    "resource": {"type": "document", "id": "doc123"}
  }
}
        """)
    
    asyncio.run(run_example())


if __name__ == "__main__":
    main()
