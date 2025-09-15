"""
FastMCP Contract Management Example

This example demonstrates the inter-agent contract management system with:
- Contract lifecycle management (draft, propose, sign, revoke)
- Ed25519 cryptographic signatures for non-repudiation
- HIPAA compliance support
- SQLite persistence
- HTTP API endpoints
"""

import asyncio
import json
from datetime import datetime, timedelta

from fastmcp import FastMCP
from fastmcp.contracts import ContractEngine, ContractState
from fastmcp.contracts.contract import (
    Clause, ContractCreateRequest, ContractProposeRequest,
    ContractSignRequest, ContractRevokeRequest
)
from fastmcp.contracts.crypto import generate_key_pair, Ed25519Signer


def create_contract_example():
    """Create a FastMCP server with contract engine enabled."""

    # Create server
    server = FastMCP("Contract Management Server")

    # Enable contract engine
    contract_engine = server.enable_contract_engine()

    # Add a simple tool that demonstrates contract operations
    @server.tool
    async def create_sample_contract(title: str, description: str) -> dict:
        """Create a sample contract for demonstration."""

        # Create sample clauses
        clauses = [
            Clause(
                title="Data Protection",
                content="All personal data must be protected according to HIPAA regulations.",
                type="hipaa"
            ),
            Clause(
                title="Access Control",
                content="Only authorized personnel may access patient data.",
                type="security"
            ),
            Clause(
                title="Audit Trail",
                content="All data access must be logged for audit purposes.",
                type="compliance"
            )
        ]

        # Create sample parties
        parties = [
            {
                "id": "provider1",
                "name": "Healthcare Provider Inc.",
                "type": "provider",
                "email": "provider@example.com",
                "role": "data_controller"
            },
            {
                "id": "patient1",
                "name": "John Doe",
                "type": "patient",
                "email": "patient@example.com",
                "role": "data_subject"
            }
        ]

        # Create contract request
        contract_request = ContractCreateRequest(
            title=title,
            description=description,
            clauses=clauses,
            parties=parties,
            is_hipaa_compliant=True,
            expires_at=datetime.utcnow() + timedelta(days=365),
            metadata={
                "created_by": "system",
                "purpose": "data_sharing_agreement"
            }
        )

        # Create contract
        contract = await contract_engine.create_contract(contract_request, "system")

        return {
            "contract_id": str(contract.id),
            "title": contract.title,
            "state": contract.state.value,
            "parties": [party["name"] for party in contract.get_parties()],
            "clauses": [clause.title for clause in contract.get_clauses()],
            "is_hipaa_compliant": contract.is_hipaa_compliant
        }

    return server


async def demonstrate_contract_lifecycle():
    """Demonstrate complete contract lifecycle."""

    server = create_contract_example()
    contract_engine = server.get_contract_engine()
    assert contract_engine is not None  # Ensure contract engine is enabled

    print("📋 FastMCP Contract Management Example")
    print("=" * 50)

    # 1. Create a contract
    print("\n1️⃣ Creating Contract")
    print("-" * 30)

    clauses = [
        Clause(
            title="Data Sharing Agreement",
            content="Healthcare provider may share patient data with authorized third parties.",
            type="hipaa"
        ),
        Clause(
            title="Consent Requirement",
            content="Patient consent must be obtained before data sharing.",
            type="consent"
        )
    ]

    parties = [
        {
            "id": "provider1",
            "name": "Metro Health System",
            "type": "provider",
            "email": "admin@metrohealth.com"
        },
        {
            "id": "patient1",
            "name": "Jane Smith",
            "type": "patient",
            "email": "jane.smith@email.com"
        }
    ]

    contract_request = ContractCreateRequest(
        title="HIPAA Data Sharing Agreement",
        description="Agreement for sharing patient data between healthcare providers",
        clauses=clauses,
        parties=parties,
        is_hipaa_compliant=True,
        expires_at=datetime.utcnow() + timedelta(days=365)
    )

    contract = await contract_engine.create_contract(contract_request, "admin")
    print(f"✅ Contract created: {contract.title}")
    print(f"   ID: {contract.id}")
    print(f"   State: {contract.state.value}")
    print(f"   Parties: {len(contract.get_parties())}")
    print(f"   HIPAA Compliant: {contract.is_hipaa_compliant}")

    # 2. Propose the contract
    print("\n2️⃣ Proposing Contract")
    print("-" * 30)

    proposal_request = ContractProposeRequest(
        proposed_to=["provider1", "patient1"],
        message="Please review and sign this data sharing agreement."
    )

    contract = await contract_engine.propose_contract(contract.id, proposal_request, "admin")
    print(f"✅ Contract proposed to: {proposal_request.proposed_to}")
    print(f"   State: {contract.state.value}")
    print(f"   Proposed at: {contract.proposed_at}")

    # 3. Sign the contract (Provider)
    print("\n3️⃣ Signing Contract (Provider)")
    print("-" * 30)

    # Generate key pair for provider
    provider_public_key, provider_private_key = generate_key_pair()
    provider_signer = Ed25519Signer.from_private_key_b64(provider_private_key)

    # Create signing message
    signing_message = f"{contract.id}:{contract.get_content_hash()}:provider1:provider"
    provider_signature = provider_signer.sign(signing_message)

    sign_request = ContractSignRequest(
        signer_id="provider1",
        signer_type="provider",
        public_key=provider_public_key,
        signature=provider_signature
    )

    contract = await contract_engine.sign_contract(contract.id, sign_request)
    print(f"✅ Provider signed the contract")
    print(f"   Signatures: {len(contract.get_signatures())}")
    print(f"   State: {contract.state.value}")

    # 4. Sign the contract (Patient)
    print("\n4️⃣ Signing Contract (Patient)")
    print("-" * 30)

    # Generate key pair for patient
    patient_public_key, patient_private_key = generate_key_pair()
    patient_signer = Ed25519Signer.from_private_key_b64(patient_private_key)

    # Create signing message
    signing_message = f"{contract.id}:{contract.get_content_hash()}:patient1:patient"
    patient_signature = patient_signer.sign(signing_message)

    sign_request = ContractSignRequest(
        signer_id="patient1",
        signer_type="patient",
        public_key=patient_public_key,
        signature=patient_signature
    )

    contract = await contract_engine.sign_contract(contract.id, sign_request)
    print(f"✅ Patient signed the contract")
    print(f"   Signatures: {len(contract.get_signatures())}")
    print(f"   State: {contract.state.value}")
    print(f"   Fully signed: {contract.is_fully_signed()}")

    # 5. Demonstrate contract verification
    print("\n5️⃣ Contract Verification")
    print("-" * 30)

    signatures = contract.get_signatures()
    for signature in signatures:
        # Verify signature
        signing_message = f"{contract.id}:{contract.get_content_hash()}:{signature.signer_id}:{signature.signer_type}"
        is_valid = provider_signer.verify(signing_message, signature.signature)
        print(f"   {signature.signer_id} signature: {'✅ Valid' if is_valid else '❌ Invalid'}")

    # 6. Get contract statistics
    print("\n6️⃣ Contract Statistics")
    print("-" * 30)

    stats = await contract_engine.get_contract_statistics()
    print(f"   Total contracts: {stats['total_contracts']}")
    print(f"   By state: {stats['by_state']}")
    print(f"   HIPAA compliant: {stats['hipaa_compliant']}")
    print(f"   Signed contracts: {stats['signed_contracts']}")

    # 7. Demonstrate revocation (optional)
    print("\n7️⃣ Contract Revocation (Optional)")
    print("-" * 30)

    revoke_request = ContractRevokeRequest(
        reason="Patient requested data deletion",
        revoked_by="admin"
    )

    contract = await contract_engine.revoke_contract(contract.id, revoke_request)
    print(f"✅ Contract revoked")
    print(f"   State: {contract.state.value}")
    print(f"   Revoked at: {contract.revoked_at}")
    print(f"   Reason: {revoke_request.reason}")


async def demonstrate_hipaa_compliance():
    """Demonstrate HIPAA compliance features."""

    print("\n🏥 HIPAA Compliance Demonstration")
    print("=" * 50)

    server = create_contract_example()
    contract_engine = server.get_contract_engine()
    assert contract_engine is not None

    # Create HIPAA-compliant contract
    hipaa_clauses = [
        Clause(
            title="HIPAA Privacy Rule",
            content="All patient data must be handled according to HIPAA Privacy Rule requirements.",
            type="hipaa",
            metadata={"regulation": "45 CFR 164.502"}
        ),
        Clause(
            title="Minimum Necessary Standard",
            content="Only the minimum necessary information may be disclosed.",
            type="hipaa",
            metadata={"regulation": "45 CFR 164.502(b)"}
        ),
        Clause(
            title="Business Associate Agreement",
            content="Third parties must sign a Business Associate Agreement.",
            type="hipaa",
            metadata={"regulation": "45 CFR 164.502(e)"}
        )
    ]

    hipaa_parties = [
        {
            "id": "covered_entity",
            "name": "Regional Medical Center",
            "type": "covered_entity",
            "email": "privacy@regionalmedical.com",
            "hipaa_role": "covered_entity"
        },
        {
            "id": "business_associate",
            "name": "HealthTech Solutions",
            "type": "business_associate",
            "email": "compliance@healthtech.com",
            "hipaa_role": "business_associate"
        }
    ]

    contract_request = ContractCreateRequest(
        title="HIPAA Business Associate Agreement",
        description="Agreement for HIPAA-compliant data processing services",
        clauses=hipaa_clauses,
        parties=hipaa_parties,
        is_hipaa_compliant=True,
        hipaa_entities=[
            {
                "type": "covered_entity",
                "name": "Regional Medical Center",
                "hipaa_id": "CE-001"
            },
            {
                "type": "business_associate",
                "name": "HealthTech Solutions",
                "hipaa_id": "BA-001"
            }
        ],
        metadata={
            "hipaa_version": "2023",
            "compliance_level": "full",
            "audit_required": True
        }
    )

    contract = await contract_engine.create_contract(contract_request, "hipaa_admin")
    
    print(f"✅ HIPAA-compliant contract created")
    print(f"   Title: {contract.title}")
    print(f"   HIPAA Compliant: {contract.is_hipaa_compliant}")
    print(f"   HIPAA Entities: {len(contract.get_hipaa_entities())}")
    print(f"   Clauses: {len(contract.get_clauses())}")

    # Show HIPAA-specific metadata
    metadata = contract.get_metadata()
    print(f"   Compliance Level: {metadata.get('compliance_level')}")
    print(f"   Audit Required: {metadata.get('audit_required')}")


def main():
    """Run the contract management example."""

    async def run_example():
        # Demonstrate contract lifecycle
        await demonstrate_contract_lifecycle()

        # Demonstrate HIPAA compliance
        await demonstrate_hipaa_compliance()

        print("\n🚀 Contract Management Example Complete!")
        print("\nTo test the HTTP endpoints:")
        print("1. Run: fastmcp run examples/contract_example.py --transport http")
        print("2. Available endpoints:")
        print("   - POST /contracts - Create contract")
        print("   - GET /contracts - List contracts")
        print("   - GET /contracts/{id} - Get contract")
        print("   - POST /contracts/{id}/propose - Propose contract")
        print("   - POST /contracts/{id}/sign - Sign contract")
        print("   - POST /contracts/{id}/revoke - Revoke contract")
        print("   - GET /contracts/statistics - Get statistics")
        print("\n3. Example contract creation:")
        print("""
curl -X POST http://localhost:8000/contracts \\
  -H "Content-Type: application/json" \\
  -d '{
    "title": "Test Contract",
    "description": "A test contract",
    "clauses": [
      {
        "title": "Test Clause",
        "content": "This is a test clause",
        "type": "test"
      }
    ],
    "parties": [
      {
        "id": "party1",
        "name": "Test Party",
        "type": "provider"
      }
    ],
    "is_hipaa_compliant": false
  }'
        """)

    asyncio.run(run_example())


if __name__ == "__main__":
    main()
