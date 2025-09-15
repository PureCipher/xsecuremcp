"""Tests for the ledger HTTP endpoints."""

import pytest
import httpx
from fastmcp import FastMCP
from fastmcp.ledger import ProvenanceLedger, LedgerEvent, EventType


@pytest.fixture
def server_with_ledger():
    """Create a FastMCP server with ledger enabled."""
    server = FastMCP("TestLedgerServer")
    ledger = server.enable_ledger(database_url="sqlite:///:memory:")
    return server, ledger


@pytest.fixture
async def client(server_with_ledger):
    """Create an HTTP client for testing."""
    server, ledger = server_with_ledger
    from fastmcp.server.http import create_streamable_http_app
    app = create_streamable_http_app(server, streamable_http_path="/")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # Store server and ledger in client for test access
        client.server = server
        client.ledger = ledger
        yield client


class TestLedgerHTTPEndpoints:
    """Test the ledger HTTP endpoints."""
    
    async def test_append_event_endpoint(self, client):
        """Test the append event endpoint."""
        event_data = {
            "event_type": "tool_call",
            "actor_id": "user123",
            "resource_id": "resource456",
            "action": "execute_tool",
            "metadata": {"tool_name": "test_tool"},
            "data_hash": "sha256_hash"
        }
        
        response = await client.post("/ledger/events", json=event_data)
        
        assert response.status_code == 201
        data = response.json()
        assert "entry_id" in data
        assert "sequence_number" in data
        assert "entry_hash" in data
        assert "block_id" in data
        assert "created_at" in data
        assert data["sequence_number"] == 1
    
    async def test_append_event_invalid_data(self, client):
        """Test append event with invalid data."""
        invalid_data = {
            "event_type": "invalid_type",
            "actor_id": "user123",
            "action": "test_action"
        }
        
        response = await client.post("/ledger/events", json=invalid_data)
        
        assert response.status_code == 400
        data = response.json()
        assert "error" in data
        assert "Invalid event data" in data["error"]
    
    async def test_verify_block_endpoint(self, client):
        """Test the verify block endpoint."""
        # First, add some events to create a block
        for i in range(3):
            event_data = {
                "event_type": "tool_call",
                "actor_id": f"user{i}",
                "action": f"action_{i}"
            }
            await client.post("/ledger/events", json=event_data)
        
        # Manually seal the block for testing
        client.ledger.seal_current_block()
    
        # Verify the block
        response = await client.get("/ledger/verify/1")
        
        assert response.status_code == 200
        data = response.json()
        assert data["block_number"] == 1
        assert data["verified"] is True
        assert "block_id" in data
        assert "entry_count" in data
        assert "merkle_root" in data
    
    async def test_verify_nonexistent_block(self, client):
        """Test verifying a non-existent block."""
        response = await client.get("/ledger/verify/999")
        
        assert response.status_code == 400
        data = response.json()
        assert "error" in data
        assert "Block integrity verification failed" in data["error"]
    
    async def test_get_entry_endpoint(self, client):
        """Test the get entry endpoint."""
        # First, add an event
        event_data = {
            "event_type": "tool_call",
            "actor_id": "user123",
            "action": "test_action"
        }
        await client.post("/ledger/events", json=event_data)
        
        # Get the entry
        response = await client.get("/ledger/entries/1")
        
        assert response.status_code == 200
        data = response.json()
        assert data["sequence_number"] == 1
        assert "entry_hash" in data
        assert "previous_hash" in data
        assert "event" in data
        assert data["event"]["actor_id"] == "user123"
        assert data["event"]["action"] == "test_action"
    
    async def test_get_nonexistent_entry(self, client):
        """Test getting a non-existent entry."""
        response = await client.get("/ledger/entries/999")
        
        assert response.status_code == 404
        data = response.json()
        assert "error" in data
        assert "Entry not found" in data["error"]
    
    async def test_get_block_endpoint(self, client):
        """Test the get block endpoint."""
        # First, add some events to create a block
        for i in range(3):
            event_data = {
                "event_type": "tool_call",
                "actor_id": f"user{i}",
                "action": f"action_{i}"
            }
            await client.post("/ledger/events", json=event_data)
        
        # Get the block
        response = await client.get("/ledger/blocks/1")
        
        assert response.status_code == 200
        data = response.json()
        assert data["block_number"] == 1
        assert "entry_count" in data
        assert "merkle_root" in data
        assert "entries" in data
        assert len(data["entries"]) == 3
    
    async def test_get_nonexistent_block(self, client):
        """Test getting a non-existent block."""
        response = await client.get("/ledger/blocks/999")
        
        assert response.status_code == 404
        data = response.json()
        assert "error" in data
        assert "Block not found" in data["error"]
    
    async def test_verify_chain_endpoint(self, client):
        """Test the verify chain endpoint."""
        # Add some events
        for i in range(3):
            event_data = {
                "event_type": "tool_call",
                "actor_id": f"user{i}",
                "action": f"action_{i}"
            }
            await client.post("/ledger/events", json=event_data)
        
        # Verify the chain
        response = await client.get("/ledger/verify-chain")
        
        assert response.status_code == 200
        data = response.json()
        assert data["verified"] is True
        assert "start_sequence" in data
        assert "end_sequence" in data
    
    async def test_verify_chain_with_range(self, client):
        """Test verify chain with specific range."""
        # Add some events
        for i in range(5):
            event_data = {
                "event_type": "tool_call",
                "actor_id": f"user{i}",
                "action": f"action_{i}"
            }
            await client.post("/ledger/events", json=event_data)
        
        # Verify partial chain
        response = await client.get("/ledger/verify-chain?start_sequence=2&end_sequence=4")
        
        assert response.status_code == 200
        data = response.json()
        assert data["verified"] is True
        assert data["start_sequence"] == 2
        assert data["end_sequence"] == 4
    
    async def test_get_merkle_proof_endpoint(self, client):
        """Test the get Merkle proof endpoint."""
        # Add some events to create a block
        for i in range(3):
            event_data = {
                "event_type": "tool_call",
                "actor_id": f"user{i}",
                "action": f"action_{i}"
            }
            await client.post("/ledger/events", json=event_data)
        
        # Manually seal the block for testing
        client.ledger.seal_current_block()
    
        # Get Merkle proof for first entry
        response = await client.get("/ledger/proof/1")
        
        assert response.status_code == 200
        data = response.json()
        assert data["sequence_number"] == 1
        assert "entry_hash" in data
        assert "block_number" in data
        assert "merkle_root" in data
        assert "proof" in data
        assert "leaf_hash" in data["proof"]
        assert "path" in data["proof"]
        assert "root_hash" in data["proof"]
        assert data["verified"] is True
    
    async def test_get_merkle_proof_nonexistent_entry(self, client):
        """Test getting Merkle proof for non-existent entry."""
        response = await client.get("/ledger/proof/999")
        
        assert response.status_code == 404
        data = response.json()
        assert "error" in data
        assert "Entry not found" in data["error"]
    
    async def test_get_ledger_statistics_endpoint(self, client):
        """Test the get ledger statistics endpoint."""
        # Initially empty
        response = await client.get("/ledger/statistics")
        
        assert response.status_code == 200
        data = response.json()
        assert data["total_entries"] == 0
        assert data["total_blocks"] == 0
        assert data["current_sequence"] == 0
        
        # Add some events
        for i in range(3):
            event_data = {
                "event_type": "tool_call",
                "actor_id": f"user{i}",
                "action": f"action_{i}"
            }
            await client.post("/ledger/events", json=event_data)
        
        # Check updated statistics
        response = await client.get("/ledger/statistics")
        
        assert response.status_code == 200
        data = response.json()
        assert data["total_entries"] == 3
        assert data["total_blocks"] == 1
        assert data["current_sequence"] == 3
    
    async def test_multiple_event_types(self, client):
        """Test appending different event types."""
        event_types = [
            "tool_call",
            "policy_decision", 
            "data_flow",
            "contract_action",
            "authentication",
            "authorization",
            "system_event"
        ]
        
        for event_type in event_types:
            event_data = {
                "event_type": event_type,
                "actor_id": "test_actor",
                "action": "test_action"
            }
            
            response = await client.post("/ledger/events", json=event_data)
            assert response.status_code == 201
    
    async def test_event_with_complex_metadata(self, client):
        """Test event with complex metadata."""
        event_data = {
            "event_type": "tool_call",
            "actor_id": "test_actor",
            "action": "test_action",
            "metadata": {
                "nested": {"key": "value"},
                "list": [1, 2, 3],
                "boolean": True,
                "null": None
            }
        }
        
        response = await client.post("/ledger/events", json=event_data)
        
        assert response.status_code == 201
        data = response.json()
        assert data["sequence_number"] == 1
        
        # Verify the event was stored correctly
        entry_response = await client.get("/ledger/entries/1")
        assert entry_response.status_code == 200
        entry_data = entry_response.json()
        assert entry_data["event"]["metadata"] == event_data["metadata"]
