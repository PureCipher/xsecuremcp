"""Tests for contract HTTP endpoints."""

import pytest
from datetime import datetime, timedelta
from uuid import UUID

from fastmcp import FastMCP
from fastmcp.contracts import ContractEngine, ContractState
from fastmcp.contracts.contract import (
    Clause, ContractCreateRequest, ContractProposeRequest,
    ContractSignRequest, ContractRevokeRequest
)
from fastmcp.contracts.crypto import generate_key_pair, Ed25519Signer
from starlette.routing import Route


class TestContractHTTPEndpoint:
    """Test the contract management HTTP endpoints."""

    @pytest.fixture
    def server_with_contracts(self):
        """Create a server with contract engine enabled."""
        server = FastMCP("Test Contract Server")
        # Use in-memory database for testing
        contract_engine = server.enable_contract_engine(database_url="sqlite:///:memory:")
        return server

    @pytest.fixture
    def app(self, server_with_contracts):
        """Create the HTTP app with contract endpoints."""
        return server_with_contracts.http_app(transport="sse")

    def test_contract_endpoints_exist(self, app):
        """Test that all contract endpoints exist in the app."""
        expected_paths = [
            "/contracts",
            "/contracts/{id}",
            "/contracts/{id}/propose",
            "/contracts/{id}/sign",
            "/contracts/{id}/revoke",
            "/contracts/statistics"
        ]
        
        # Check that all contract routes exist
        contract_routes_found = set()
        for route in app.routes:
            if isinstance(route, Route):
                if route.path in expected_paths:
                    contract_routes_found.add(route.path)
        
        assert len(contract_routes_found) == len(expected_paths), f"Expected {len(expected_paths)} unique contract routes, found {len(contract_routes_found)}: {sorted(contract_routes_found)}"

    def test_contract_engine_integration(self, server_with_contracts):
        """Test that contract engine is properly integrated with the server."""
        # Check that contract engine is enabled
        assert server_with_contracts.get_contract_engine() is not None
        
        # Check that contract engine is the right type
        contract_engine = server_with_contracts.get_contract_engine()
        assert isinstance(contract_engine, ContractEngine)

    @pytest.mark.asyncio
    async def test_create_contract_endpoint(self, app):
        """Test the create contract endpoint."""
        import httpx
        
        contract_data = {
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
            "is_hipaa_compliant": False
        }
        
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/contracts", json=contract_data)
            
            assert response.status_code == 201
            data = response.json()
            assert data["title"] == contract_data["title"]
            assert data["description"] == contract_data["description"]
            assert data["state"] == "draft"
            assert data["is_hipaa_compliant"] is False

    @pytest.mark.asyncio
    async def test_get_contract_endpoint(self, app):
        """Test the get contract endpoint."""
        import httpx
        
        # First create a contract
        contract_data = {
            "title": "Test Contract",
            "description": "A test contract",
            "clauses": [],
            "parties": []
        }
        
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            # Create contract
            create_response = await client.post("/contracts", json=contract_data)
            assert create_response.status_code == 201
            contract_id = create_response.json()["id"]
            
            # Get contract
            get_response = await client.get(f"/contracts/{contract_id}")
            assert get_response.status_code == 200
            data = get_response.json()
            assert data["id"] == contract_id
            assert data["title"] == contract_data["title"]

    @pytest.mark.asyncio
    async def test_get_contract_not_found(self, app):
        """Test getting a non-existent contract."""
        import httpx
        
        fake_id = "12345678-1234-1234-1234-123456789012"
        
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get(f"/contracts/{fake_id}")
            assert response.status_code == 404
            data = response.json()
            assert "not found" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_list_contracts_endpoint(self, app):
        """Test the list contracts endpoint."""
        import httpx
        
        # Create multiple contracts
        contract_data = {
            "title": "Test Contract",
            "description": "A test contract",
            "clauses": [],
            "parties": []
        }
        
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            # Create contracts
            await client.post("/contracts", json=contract_data)
            await client.post("/contracts", json=contract_data)
            
            # List contracts
            response = await client.get("/contracts")
            assert response.status_code == 200
            data = response.json()
            assert "contracts" in data
            assert "count" in data
            assert data["count"] == 2
            assert len(data["contracts"]) == 2

    @pytest.mark.asyncio
    async def test_propose_contract_endpoint(self, app):
        """Test the propose contract endpoint."""
        import httpx
        
        # First create a contract
        contract_data = {
            "title": "Test Contract",
            "description": "A test contract",
            "clauses": [],
            "parties": []
        }
        
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            # Create contract
            create_response = await client.post("/contracts", json=contract_data)
            contract_id = create_response.json()["id"]
            
            # Propose contract
            proposal_data = {
                "proposed_to": ["party1", "party2"],
                "message": "Please review and sign"
            }
            
            response = await client.post(f"/contracts/{contract_id}/propose", json=proposal_data)
            assert response.status_code == 200
            data = response.json()
            assert data["state"] == "proposed"
            assert data["proposed_at"] is not None

    @pytest.mark.asyncio
    async def test_sign_contract_endpoint(self, app):
        """Test the sign contract endpoint."""
        import httpx
        
        # First create and propose a contract
        contract_data = {
            "title": "Test Contract",
            "description": "A test contract",
            "clauses": [],
            "parties": [{"id": "party1", "name": "Test Party", "type": "provider"}]
        }
        
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            # Create contract
            create_response = await client.post("/contracts", json=contract_data)
            contract_id = create_response.json()["id"]
            
            # Propose contract
            proposal_data = {"proposed_to": ["party1"]}
            await client.post(f"/contracts/{contract_id}/propose", json=proposal_data)
            
            # Generate key pair for signing
            public_key, private_key = generate_key_pair()
            signer = Ed25519Signer.from_private_key_b64(private_key)
            
            # Get contract to get content hash
            contract_response = await client.get(f"/contracts/{contract_id}")
            contract_data_response = contract_response.json()
            content_hash = contract_data_response["content_hash"]
            
            # Create signature
            signing_message = f"{contract_id}:{content_hash}:party1:provider"
            signature = signer.sign(signing_message)
            
            # Sign contract
            sign_data = {
                "signer_id": "party1",
                "signer_type": "provider",
                "public_key": public_key,
                "signature": signature
            }
            
            response = await client.post(f"/contracts/{contract_id}/sign", json=sign_data)
            assert response.status_code == 200
            data = response.json()
            assert len(data["signatures"]) == 1
            assert data["signatures"][0]["signer_id"] == "party1"

    @pytest.mark.asyncio
    async def test_revoke_contract_endpoint(self, app):
        """Test the revoke contract endpoint."""
        import httpx
        
        # First create a contract
        contract_data = {
            "title": "Test Contract",
            "description": "A test contract",
            "clauses": [],
            "parties": []
        }
        
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            # Create contract
            create_response = await client.post("/contracts", json=contract_data)
            contract_id = create_response.json()["id"]
            
            # Revoke contract
            revoke_data = {
                "reason": "Contract terms violated",
                "revoked_by": "admin"
            }
            
            response = await client.post(f"/contracts/{contract_id}/revoke", json=revoke_data)
            assert response.status_code == 200
            data = response.json()
            assert data["state"] == "revoked"
            assert data["revoked_at"] is not None

    @pytest.mark.asyncio
    async def test_contract_statistics_endpoint(self, app):
        """Test the contract statistics endpoint."""
        import httpx
        
        # Create some contracts
        contract_data = {
            "title": "Test Contract",
            "description": "A test contract",
            "clauses": [],
            "parties": []
        }
        
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            # Create contracts
            await client.post("/contracts", json=contract_data)
            await client.post("/contracts", json=contract_data)
            
            # Get statistics
            response = await client.get("/contracts/statistics")
            assert response.status_code == 200
            data = response.json()
            assert "total_contracts" in data
            assert "by_state" in data
            assert "hipaa_compliant" in data
            assert "signed_contracts" in data
            assert data["total_contracts"] == 2
