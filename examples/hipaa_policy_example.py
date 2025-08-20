"""
Example demonstrating the actor-aware HIPAAAccessPolicy.
"""
import asyncio
import json
from fastmcp import FastMCP
from fastmcp.policy.policies import HIPAAAccessPolicy


def create_hipaa_server():
    """Create a FastMCP server with HIPAA policy engine enabled."""
    
    # Create server
    server = FastMCP("HIPAA Compliance Server")
    
    # Enable policy engine
    policy_engine = server.enable_policy_engine()
    policy_engine.register_policy(HIPAAAccessPolicy())
    
    @server.tool
    async def access_phi(
        user_id: str,
        user_roles: list[str],
        action: str,
        purpose: str,
        patient_id: str,
        data_elements: list[str],
        is_clinical: bool = True,
        recipient_id: str | None = None,
        recipient_type: str | None = None
    ) -> dict:
        """Access PHI with HIPAA policy evaluation."""
        
        # Create context for policy evaluation
        context = {
            "user": {"id": user_id, "roles": user_roles},
            "action": action,
            "purpose": purpose,
            "resource": {
                "is_phi": True,
                "type": "phi",
                "is_clinical": is_clinical,
                "data_elements": data_elements
            },
            "patient": {"id": patient_id}
        }
        
        # Add recipient if provided (for disclosure scenarios)
        if recipient_id and recipient_type:
            context["recipient"] = {"id": recipient_id, "type": recipient_type}
        
        # Evaluate HIPAA policy
        decision = await policy_engine.evaluate(context)
        
        return {
            "access_granted": decision.allow,
            "reason": decision.reason,
            "obligations": decision.obligations,
            "proof": decision.proof
        }
    
    @server.tool
    async def access_billing_data(
        user_id: str,
        user_roles: list[str], 
        action: str,
        purpose: str,
        patient_id: str,
        billing_elements: list[str]
    ) -> dict:
        """Access billing data with HIPAA policy evaluation."""
        
        context = {
            "user": {"id": user_id, "roles": user_roles},
            "action": action,
            "purpose": purpose,
            "resource": {
                "is_phi": True,
                "is_clinical": False,
                "data_elements": billing_elements
            },
            "patient": {"id": patient_id}
        }
        
        decision = await policy_engine.evaluate(context)
        
        return {
            "access_granted": decision.allow,
            "reason": decision.reason,
            "obligations": decision.obligations,
            "proof": decision.proof
        }
    
    return server


async def demonstrate_actor_aware_hipaa_policy():
    """Demonstrate HIPAAPolicy with scenarios for each actor type."""
    server = create_hipaa_server()
    policy_engine = server.get_policy_engine()
    assert policy_engine is not None

    print("🔐 Actor-Aware HIPAA Policy Evaluation Example")
    print("=" * 60)

    # Test scenarios using the tools
    scenarios = [
        # --- Provider Scenarios ---
        {
            "name": "[Provider] Access clinical data for treatment (Allowed)",
            "tool": "access_phi",
            "params": {
                "user_id": "dr_smith",
                "user_roles": ["provider"],
                "action": "read",
                "purpose": "Treatment",
                "patient_id": "patient_123",
                "data_elements": ["full_record"],
                "is_clinical": True
            }
        },
        {
            "name": "[Provider] Disclose PHI to another provider (Allowed with obligations)",
            "tool": "access_phi", 
            "params": {
                "user_id": "dr_jones",
                "user_roles": ["provider"],
                "action": "disclose",
                "purpose": "Treatment",
                "patient_id": "patient_123",
                "data_elements": ["lab_results"],
                "is_clinical": True,
                "recipient_id": "specialist_clinic",
                "recipient_type": "health_care_provider"
            }
        },
        # --- Payee Scenarios ---
        {
            "name": "[Payee] Access billing information for payment (Allowed)",
            "tool": "access_billing_data",
            "params": {
                "user_id": "bill_staff_01",
                "user_roles": ["payee"],
                "action": "read",
                "purpose": "Payment",
                "patient_id": "patient_456",
                "billing_elements": ["billing_codes", "dates_of_service"]
            }
        },
        {
            "name": "[Payee] Attempt to access clinical notes (Denied by Minimum Necessary)",
            "tool": "access_phi",
            "params": {
                "user_id": "bill_staff_01",
                "user_roles": ["payee"],
                "action": "read",
                "purpose": "Payment",
                "patient_id": "patient_456",
                "data_elements": ["physician_notes"],
                "is_clinical": True
            }
        },
        {
            "name": "[Payee] Attempt to modify clinical record (Denied by Integrity Rule)",
            "tool": "access_phi",
            "params": {
                "user_id": "bill_staff_01",
                "user_roles": ["payee"],
                "action": "write",
                "purpose": "Payment",
                "patient_id": "patient_456",
                "data_elements": ["diagnosis_code"],
                "is_clinical": True
            }
        },
        # --- Patient Scenarios ---
        {
            "name": "[Patient] Request own full medical record (Allowed, bypasses Min. Necessary)",
            "tool": "access_phi",
            "params": {
                "user_id": "patient_789",
                "user_roles": ["patient"],
                "action": "read",
                "purpose": "Self_Access",
                "patient_id": "patient_789",
                "data_elements": ["full_record"],
                "is_clinical": True
            }
        },
        {
            "name": "[Patient] Request export of own data (Allowed with encryption obligation)",
            "tool": "access_phi",
            "params": {
                "user_id": "patient_789",
                "user_roles": ["patient"],
                "action": "export",
                "purpose": "Self_Access",
                "patient_id": "patient_789",
                "data_elements": ["full_record"],
                "is_clinical": True
            }
        }
    ]

    for scenario in scenarios:
        print(f"\n📋 Scenario: {scenario['name']}")
        print("-" * 40)
        
        # Create context directly for policy evaluation
        if scenario["tool"] == "access_phi":
            context = {
                "user": {
                    "id": scenario["params"]["user_id"],
                    "roles": scenario["params"]["user_roles"]
                },
                "action": scenario["params"]["action"],
                "purpose": scenario["params"]["purpose"],
                "resource": {
                    "is_phi": True,
                    "type": "phi",
                    "is_clinical": scenario["params"]["is_clinical"],
                    "data_elements": scenario["params"]["data_elements"]
                },
                "patient": {"id": scenario["params"]["patient_id"]}
            }
            
            # Add recipient if provided
            if "recipient_id" in scenario["params"]:
                context["recipient"] = {
                    "id": scenario["params"]["recipient_id"],
                    "type": scenario["params"]["recipient_type"]
                }
                
        elif scenario["tool"] == "access_billing_data":
            context = {
                "user": {
                    "id": scenario["params"]["user_id"],
                    "roles": scenario["params"]["user_roles"]
                },
                "action": scenario["params"]["action"],
                "purpose": scenario["params"]["purpose"],
                "resource": {
                    "is_phi": True,
                    "is_clinical": False,
                    "data_elements": scenario["params"]["billing_elements"]
                },
                "patient": {"id": scenario["params"]["patient_id"]}
            }
        
        decision = await policy_engine.evaluate(context)
        print(f"Decision: {'✅ ALLOW' if decision.allow else '❌ DENY'}")
        print(f"Reason: {decision.reason}")
        if decision.obligations:
            print("Obligations:")
            for ob in decision.obligations:
                print(f"  - {ob['type']}: {ob['description']}")
        if decision.proof:
            print(f"Proof: {json.dumps(decision.proof, indent=2)}")


def main():
    """Run the HIPAA policy example."""
    asyncio.run(demonstrate_actor_aware_hipaa_policy())


if __name__ == "__main__":
    main()


