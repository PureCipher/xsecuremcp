"""Tests for the contract engine."""

import pytest
from datetime import datetime, timedelta
from uuid import UUID

from fastmcp.contracts import ContractEngine, ContractState
from fastmcp.contracts.contract import (
    Contract, Clause, Signature, ContractCreateRequest, ContractProposeRequest,
    ContractSignRequest, ContractRevokeRequest
)
from fastmcp.contracts.crypto import Ed25519Signer, generate_key_pair


class TestContractEngine:
    """Test the contract engine functionality."""

    @pytest.fixture
    def contract_engine(self):
        """Create a contract engine for testing."""
        return ContractEngine("sqlite:///:memory:")

    @pytest.fixture
    def sample_clauses(self):
        """Create sample clauses for testing."""
        return [
            Clause(
                title="Data Handling",
                content="All data must be handled in accordance with HIPAA regulations.",
                type="hipaa"
            ),
            Clause(
                title="Access Control",
                content="Only authorized personnel may access patient data.",
                type="security"
            )
        ]

    @pytest.fixture
    def sample_parties(self):
        """Create sample parties for testing."""
        return [
            {
                "id": "provider1",
                "name": "Healthcare Provider",
                "type": "provider",
                "email": "provider@example.com"
            },
            {
                "id": "patient1",
                "name": "John Doe",
                "type": "patient",
                "email": "patient@example.com"
            }
        ]

    @pytest.fixture
    def sample_contract_request(self, sample_clauses, sample_parties):
        """Create a sample contract creation request."""
        return ContractCreateRequest(
            title="HIPAA Data Sharing Agreement",
            description="Agreement for sharing patient data between healthcare providers",
            clauses=sample_clauses,
            parties=sample_parties,
            is_hipaa_compliant=True,
            expires_at=datetime.utcnow() + timedelta(days=365)
        )

    def test_contract_engine_initialization(self, contract_engine):
        """Test contract engine initialization."""
        assert contract_engine.engine is not None
        assert contract_engine.get_registry() is not None

    @pytest.mark.asyncio
    async def test_create_contract(self, contract_engine, sample_contract_request):
        """Test contract creation."""
        created_by = "admin"
        
        contract = await contract_engine.create_contract(sample_contract_request, created_by)
        
        assert contract is not None
        assert contract.title == sample_contract_request.title
        assert contract.description == sample_contract_request.description
        assert contract.state == ContractState.DRAFT
        assert contract.created_by == created_by
        assert contract.is_hipaa_compliant is True
        assert len(contract.get_clauses()) == 2
        assert len(contract.get_parties()) == 2

    @pytest.mark.asyncio
    async def test_get_contract(self, contract_engine, sample_contract_request):
        """Test getting a contract by ID."""
        created_by = "admin"
        contract = await contract_engine.create_contract(sample_contract_request, created_by)
        
        retrieved_contract = await contract_engine.get_contract(contract.id)
        
        assert retrieved_contract is not None
        assert retrieved_contract.id == contract.id
        assert retrieved_contract.title == contract.title

    @pytest.mark.asyncio
    async def test_get_contract_not_found(self, contract_engine):
        """Test getting a non-existent contract."""
        fake_id = UUID("12345678-1234-1234-1234-123456789012")
        contract = await contract_engine.get_contract(fake_id)
        
        assert contract is None

    @pytest.mark.asyncio
    async def test_list_contracts(self, contract_engine, sample_contract_request):
        """Test listing contracts."""
        created_by = "admin"
        
        # Create multiple contracts
        contract1 = await contract_engine.create_contract(sample_contract_request, created_by)
        contract2 = await contract_engine.create_contract(sample_contract_request, created_by)
        
        # List all contracts
        all_contracts = await contract_engine.list_contracts()
        assert len(all_contracts) == 2
        
        # List contracts by state
        draft_contracts = await contract_engine.list_contracts(state=ContractState.DRAFT)
        assert len(draft_contracts) == 2
        
        # List contracts by creator
        admin_contracts = await contract_engine.list_contracts(created_by=created_by)
        assert len(admin_contracts) == 2

    @pytest.mark.asyncio
    async def test_propose_contract(self, contract_engine, sample_contract_request):
        """Test proposing a contract."""
        created_by = "admin"
        contract = await contract_engine.create_contract(sample_contract_request, created_by)
        
        proposal_request = ContractProposeRequest(
            proposed_to=["provider1", "patient1"],
            message="Please review and sign this contract"
        )
        
        proposed_contract = await contract_engine.propose_contract(
            contract.id, proposal_request, created_by
        )
        
        assert proposed_contract is not None
        assert proposed_contract.state == ContractState.PROPOSED
        assert proposed_contract.proposed_at is not None

    @pytest.mark.asyncio
    async def test_propose_contract_invalid_state(self, contract_engine, sample_contract_request):
        """Test proposing a contract in invalid state."""
        created_by = "admin"
        contract = await contract_engine.create_contract(sample_contract_request, created_by)
        
        # First propose the contract
        proposal_request = ContractProposeRequest(proposed_to=["provider1"])
        await contract_engine.propose_contract(contract.id, proposal_request, created_by)
        
        # Try to propose again (should fail)
        with pytest.raises(ValueError, match="Cannot propose contract in state ContractState.PROPOSED"):
            await contract_engine.propose_contract(contract.id, proposal_request, created_by)

    @pytest.mark.asyncio
    async def test_sign_contract(self, contract_engine, sample_contract_request):
        """Test signing a contract."""
        created_by = "admin"
        contract = await contract_engine.create_contract(sample_contract_request, created_by)
        
        # Propose the contract
        proposal_request = ContractProposeRequest(proposed_to=["provider1"])
        await contract_engine.propose_contract(contract.id, proposal_request, created_by)
        
        # Generate key pair for signing
        public_key, private_key = generate_key_pair()
        signer = Ed25519Signer.from_private_key_b64(private_key)
        
        # Create signing message
        signing_message = f"{contract.id}:{contract.get_content_hash()}:provider1:provider"
        signature = signer.sign(signing_message)
        
        # Sign the contract
        sign_request = ContractSignRequest(
            signer_id="provider1",
            signer_type="provider",
            public_key=public_key,
            signature=signature
        )
        
        signed_contract = await contract_engine.sign_contract(contract.id, sign_request)
        
        assert signed_contract is not None
        assert len(signed_contract.get_signatures()) == 1
        assert signed_contract.get_signatures()[0].signer_id == "provider1"

    @pytest.mark.asyncio
    async def test_sign_contract_invalid_signature(self, contract_engine, sample_contract_request):
        """Test signing a contract with invalid signature."""
        created_by = "admin"
        contract = await contract_engine.create_contract(sample_contract_request, created_by)
        
        # Propose the contract
        proposal_request = ContractProposeRequest(proposed_to=["provider1"])
        await contract_engine.propose_contract(contract.id, proposal_request, created_by)
        
        # Generate key pair for signing
        public_key, private_key = generate_key_pair()
        signer = Ed25519Signer.from_private_key_b64(private_key)
        
        # Create invalid signing message (wrong content hash)
        invalid_signing_message = f"{contract.id}:invalid_hash:provider1:provider"
        signature = signer.sign(invalid_signing_message)
        
        # Try to sign with invalid signature
        sign_request = ContractSignRequest(
            signer_id="provider1",
            signer_type="provider",
            public_key=public_key,
            signature=signature
        )
        
        with pytest.raises(ValueError, match="Invalid signature"):
            await contract_engine.sign_contract(contract.id, sign_request)

    @pytest.mark.asyncio
    async def test_revoke_contract(self, contract_engine, sample_contract_request):
        """Test revoking a contract."""
        created_by = "admin"
        contract = await contract_engine.create_contract(sample_contract_request, created_by)
        
        revoke_request = ContractRevokeRequest(
            reason="Contract terms violated",
            revoked_by="admin"
        )
        
        revoked_contract = await contract_engine.revoke_contract(contract.id, revoke_request)
        
        assert revoked_contract is not None
        assert revoked_contract.state == ContractState.REVOKED
        assert revoked_contract.revoked_at is not None

    @pytest.mark.asyncio
    async def test_revoke_contract_already_revoked(self, contract_engine, sample_contract_request):
        """Test revoking an already revoked contract."""
        created_by = "admin"
        contract = await contract_engine.create_contract(sample_contract_request, created_by)
        
        # First revoke the contract
        revoke_request = ContractRevokeRequest(
            reason="Contract terms violated",
            revoked_by="admin"
        )
        await contract_engine.revoke_contract(contract.id, revoke_request)
        
        # Try to revoke again (should fail)
        with pytest.raises(ValueError, match="Contract is already revoked"):
            await contract_engine.revoke_contract(contract.id, revoke_request)

    @pytest.mark.asyncio
    async def test_get_contracts_by_party(self, contract_engine, sample_contract_request):
        """Test getting contracts by party."""
        created_by = "admin"
        contract = await contract_engine.create_contract(sample_contract_request, created_by)
        
        # Get contracts for provider1
        provider_contracts = await contract_engine.get_contracts_by_party("provider1")
        assert len(provider_contracts) == 1
        assert provider_contracts[0].id == contract.id
        
        # Get contracts for non-existent party
        empty_contracts = await contract_engine.get_contracts_by_party("nonexistent")
        assert len(empty_contracts) == 0

    @pytest.mark.asyncio
    async def test_cleanup_expired_contracts(self, contract_engine, sample_contract_request):
        """Test cleanup of expired contracts."""
        created_by = "admin"
        
        # Create contract with past expiration
        past_expiration = datetime.utcnow() - timedelta(days=1)
        sample_contract_request.expires_at = past_expiration
        
        contract = await contract_engine.create_contract(sample_contract_request, created_by)
        
        # Cleanup expired contracts
        count = await contract_engine.cleanup_expired_contracts()
        
        assert count == 1
        
        # Verify contract is marked as expired
        expired_contract = await contract_engine.get_contract(contract.id)
        assert expired_contract.state == ContractState.EXPIRED

    @pytest.mark.asyncio
    async def test_get_contract_statistics(self, contract_engine, sample_contract_request):
        """Test getting contract statistics."""
        created_by = "admin"
        
        # Create multiple contracts
        contract1 = await contract_engine.create_contract(sample_contract_request, created_by)
        contract2 = await contract_engine.create_contract(sample_contract_request, created_by)
        
        # Propose one contract
        proposal_request = ContractProposeRequest(proposed_to=["provider1"])
        await contract_engine.propose_contract(contract1.id, proposal_request, created_by)
        
        # Get statistics
        stats = await contract_engine.get_contract_statistics()
        
        assert stats["total_contracts"] == 2
        assert stats["by_state"]["draft"] == 1
        assert stats["by_state"]["proposed"] == 1
        assert stats["hipaa_compliant"] == 2
        assert stats["signed_contracts"] == 0


class TestContractLifecycle:
    """Test complete contract lifecycle."""

    @pytest.fixture
    def contract_engine(self):
        """Create a contract engine for testing."""
        return ContractEngine("sqlite:///:memory:")

    @pytest.fixture
    def sample_contract_request(self):
        """Create a sample contract creation request."""
        return ContractCreateRequest(
            title="Test Contract",
            description="A test contract for lifecycle testing",
            clauses=[
                Clause(
                    title="Test Clause",
                    content="This is a test clause",
                    type="test"
                )
            ],
            parties=[
                {
                    "id": "party1",
                    "name": "Test Party 1",
                    "type": "provider"
                },
                {
                    "id": "party2",
                    "name": "Test Party 2",
                    "type": "patient"
                }
            ]
        )

    @pytest.mark.asyncio
    async def test_complete_contract_lifecycle(self, contract_engine, sample_contract_request):
        """Test complete contract lifecycle: create → propose → sign → revoke."""
        created_by = "admin"
        
        # 1. Create contract
        contract = await contract_engine.create_contract(sample_contract_request, created_by)
        assert contract.state == ContractState.DRAFT
        
        # 2. Propose contract
        proposal_request = ContractProposeRequest(
            proposed_to=["party1", "party2"],
            message="Please review and sign"
        )
        contract = await contract_engine.propose_contract(contract.id, proposal_request, created_by)
        assert contract.state == ContractState.PROPOSED
        
        # 3. Sign contract (party1)
        public_key1, private_key1 = generate_key_pair()
        signer1 = Ed25519Signer.from_private_key_b64(private_key1)
        signing_message1 = f"{contract.id}:{contract.get_content_hash()}:party1:provider"
        signature1 = signer1.sign(signing_message1)
        
        sign_request1 = ContractSignRequest(
            signer_id="party1",
            signer_type="provider",
            public_key=public_key1,
            signature=signature1
        )
        contract = await contract_engine.sign_contract(contract.id, sign_request1)
        assert len(contract.get_signatures()) == 1
        assert contract.state == ContractState.PROPOSED  # Still proposed until all parties sign
        
        # 4. Sign contract (party2)
        public_key2, private_key2 = generate_key_pair()
        signer2 = Ed25519Signer.from_private_key_b64(private_key2)
        signing_message2 = f"{contract.id}:{contract.get_content_hash()}:party2:patient"
        signature2 = signer2.sign(signing_message2)
        
        sign_request2 = ContractSignRequest(
            signer_id="party2",
            signer_type="patient",
            public_key=public_key2,
            signature=signature2
        )
        contract = await contract_engine.sign_contract(contract.id, sign_request2)
        assert len(contract.get_signatures()) == 2
        assert contract.state == ContractState.SIGNED  # Now fully signed
        
        # 5. Revoke contract
        revoke_request = ContractRevokeRequest(
            reason="Contract terms violated",
            revoked_by="admin"
        )
        contract = await contract_engine.revoke_contract(contract.id, revoke_request)
        assert contract.state == ContractState.REVOKED
        assert contract.revoked_at is not None
