"""Tests for the ledger adapters."""

import pytest
from fastmcp.ledger.adapter import HyperledgerAdapter, OmniSealAdapter, StubAdapter


class TestHyperledgerAdapter:
    """Test the HyperledgerAdapter class."""
    
    @pytest.fixture
    def adapter(self):
        """Create a Hyperledger adapter for testing."""
        return HyperledgerAdapter(
            network_config="test_config.json",
            channel_name="test-channel",
            chaincode_name="test-chaincode"
        )
    
    async def test_adapter_initialization(self, adapter):
        """Test adapter initialization."""
        assert adapter.network_config == "test_config.json"
        assert adapter.channel_name == "test-channel"
        assert adapter.chaincode_name == "test-chaincode"
        assert adapter.peer_endpoint == "localhost:7051"
        assert adapter.orderer_endpoint == "localhost:7050"
    
    async def test_submit_block(self, adapter):
        """Test block submission."""
        block_data = {
            "block_number": 1,
            "merkle_root": "test_merkle_root",
            "entry_count": 5,
            "entries": ["entry1", "entry2", "entry3", "entry4", "entry5"]
        }
        
        tx_id = await adapter.submit_block(block_data)
        
        assert tx_id is not None
        assert len(tx_id) == 64  # SHA-256 hex length
    
    async def test_verify_block(self, adapter):
        """Test block verification."""
        block_id = "test_block_1"
        
        result = await adapter.verify_block(block_id)
        
        # Stub implementation always returns True
        assert result is True
    
    async def test_get_block_proof(self, adapter):
        """Test getting block proof."""
        block_id = "test_block_1"
        
        proof = await adapter.get_block_proof(block_id)
        
        assert proof is not None
        assert proof["block_id"] == block_id
        assert "block_hash" in proof
        assert "block_number" in proof
        assert "timestamp" in proof
        assert "proof_type" in proof
        assert proof["proof_type"] == "hyperledger_fabric"
        assert "signatures" in proof
        assert "merkle_root" in proof


class TestOmniSealAdapter:
    """Test the OmniSealAdapter class."""
    
    @pytest.fixture
    def adapter(self):
        """Create an OmniSeal adapter for testing."""
        return OmniSealAdapter(
            api_endpoint="https://api.test.omniseal.com",
            api_key="test_api_key",
            network_id="testnet"
        )
    
    async def test_adapter_initialization(self, adapter):
        """Test adapter initialization."""
        assert adapter.api_endpoint == "https://api.test.omniseal.com"
        assert adapter.api_key == "test_api_key"
        assert adapter.network_id == "testnet"
    
    async def test_submit_block(self, adapter):
        """Test block submission."""
        block_data = {
            "block_number": 1,
            "merkle_root": "test_merkle_root",
            "entry_count": 3,
            "entries": ["entry1", "entry2", "entry3"]
        }
        
        tx_id = await adapter.submit_block(block_data)
        
        assert tx_id is not None
        assert len(tx_id) == 64  # SHA-256 hex length
    
    async def test_verify_block(self, adapter):
        """Test block verification."""
        block_id = "test_block_1"
        
        result = await adapter.verify_block(block_id)
        
        # Stub implementation always returns True
        assert result is True
    
    async def test_get_block_proof(self, adapter):
        """Test getting block proof."""
        block_id = "test_block_1"
        
        proof = await adapter.get_block_proof(block_id)
        
        assert proof is not None
        assert proof["block_id"] == block_id
        assert "block_hash" in proof
        assert "block_number" in proof
        assert "timestamp" in proof
        assert "proof_type" in proof
        assert proof["proof_type"] == "omniseal"
        assert "network_id" in proof
        assert proof["network_id"] == "testnet"
        assert "merkle_root" in proof


class TestStubAdapter:
    """Test the StubAdapter class."""
    
    @pytest.fixture
    def adapter(self):
        """Create a stub adapter for testing."""
        return StubAdapter()
    
    async def test_adapter_initialization(self, adapter):
        """Test adapter initialization."""
        assert adapter.submitted_blocks == {}
        assert adapter.block_proofs == {}
    
    async def test_submit_block(self, adapter):
        """Test block submission."""
        block_data = {
            "block_number": 1,
            "merkle_root": "test_merkle_root",
            "entry_count": 2,
            "entries": ["entry1", "entry2"]
        }
        
        block_id = await adapter.submit_block(block_data)
        
        assert block_id == "stub_block_1"
        assert block_id in adapter.submitted_blocks
        assert adapter.submitted_blocks[block_id] == block_data
    
    async def test_submit_multiple_blocks(self, adapter):
        """Test submitting multiple blocks."""
        for i in range(3):
            block_data = {
                "block_number": i + 1,
                "merkle_root": f"merkle_root_{i}",
                "entry_count": 1,
                "entries": [f"entry_{i}"]
            }
            
            block_id = await adapter.submit_block(block_data)
            assert block_id == f"stub_block_{i + 1}"
        
        assert len(adapter.submitted_blocks) == 3
    
    async def test_verify_block(self, adapter):
        """Test block verification."""
        # Submit a block first
        block_data = {"block_number": 1, "merkle_root": "test"}
        block_id = await adapter.submit_block(block_data)
        
        # Verify existing block
        result = await adapter.verify_block(block_id)
        assert result is True
        
        # Verify non-existent block
        result = await adapter.verify_block("nonexistent_block")
        assert result is False
    
    async def test_get_block_proof(self, adapter):
        """Test getting block proof."""
        # Submit a block first
        block_data = {
            "block_number": 1,
            "merkle_root": "test_merkle_root",
            "entry_count": 2
        }
        block_id = await adapter.submit_block(block_data)
        
        # Get proof for existing block
        proof = await adapter.get_block_proof(block_id)
        
        assert proof is not None
        assert proof["block_id"] == block_id
        assert proof["block_hash"] == f"stub_hash_{block_id}"
        assert proof["block_number"] == 1
        assert "timestamp" in proof
        assert proof["proof_type"] == "stub"
        assert proof["merkle_root"] == "test_merkle_root"
        
        # Get proof for non-existent block
        proof = await adapter.get_block_proof("nonexistent_block")
        assert proof is None
    
    async def test_adapter_state_persistence(self, adapter):
        """Test that adapter maintains state across operations."""
        # Submit a block
        block_data = {"block_number": 1, "merkle_root": "test"}
        block_id = await adapter.submit_block(block_data)
        
        # Verify it exists
        assert await adapter.verify_block(block_id) is True
        
        # Get proof
        proof = await adapter.get_block_proof(block_id)
        assert proof is not None
        
        # Submit another block
        block_data2 = {"block_number": 2, "merkle_root": "test2"}
        block_id2 = await adapter.submit_block(block_data2)
        
        # Both blocks should exist
        assert await adapter.verify_block(block_id) is True
        assert await adapter.verify_block(block_id2) is True
        
        # Both proofs should be available
        proof1 = await adapter.get_block_proof(block_id)
        proof2 = await adapter.get_block_proof(block_id2)
        assert proof1 is not None
        assert proof2 is not None
        assert proof1["block_id"] != proof2["block_id"]
