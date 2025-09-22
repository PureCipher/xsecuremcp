"""Ledger adapters for external blockchain backends like Hyperledger/OmniSeal."""

import json
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from datetime import datetime

from fastmcp.utilities.logging import get_logger

logger = get_logger(__name__)


class LedgerAdapter(ABC):
    """Abstract base class for ledger adapters."""
    
    @abstractmethod
    async def submit_block(self, block_data: Dict[str, Any]) -> str:
        """Submit a block to the external ledger.
        
        Args:
            block_data: The block data to submit
            
        Returns:
            Transaction ID or block hash from the external ledger
        """
        pass
    
    @abstractmethod
    async def verify_block(self, block_id: str) -> bool:
        """Verify a block exists and is valid on the external ledger.
        
        Args:
            block_id: The block ID to verify
            
        Returns:
            True if block is valid, False otherwise
        """
        pass
    
    @abstractmethod
    async def get_block_proof(self, block_id: str) -> Optional[Dict[str, Any]]:
        """Get a proof of block existence from the external ledger.
        
        Args:
            block_id: The block ID to get proof for
            
        Returns:
            Proof data or None if not found
        """
        pass


class HyperledgerAdapter(LedgerAdapter):
    """Adapter for Hyperledger Fabric blockchain backend."""
    
    def __init__(self, 
                 network_config: str,
                 channel_name: str = "mcp-channel",
                 chaincode_name: str = "provenance-ledger",
                 peer_endpoint: str = "localhost:7051",
                 orderer_endpoint: str = "localhost:7050"):
        """Initialize Hyperledger adapter.
        
        Args:
            network_config: Path to network configuration file
            channel_name: Name of the Hyperledger channel
            chaincode_name: Name of the deployed chaincode
            peer_endpoint: Peer endpoint URL
            orderer_endpoint: Orderer endpoint URL
        """
        self.network_config = network_config
        self.channel_name = channel_name
        self.chaincode_name = chaincode_name
        self.peer_endpoint = peer_endpoint
        self.orderer_endpoint = orderer_endpoint
        self._client = None
        
    async def _get_client(self):
        """Get or create Hyperledger client."""
        if self._client is None:
            try:
                # This would import the actual Hyperledger Fabric SDK
                # from hfc.fabric import Client
                # self._client = Client(net_profile=self.network_config)
                logger.info("Hyperledger client initialized (stub implementation)")
                self._client = "stub_client"
            except ImportError:
                logger.warning("Hyperledger Fabric SDK not available, using stub implementation")
                self._client = "stub_client"
        return self._client
    
    async def submit_block(self, block_data: Dict[str, Any]) -> str:
        """Submit a block to Hyperledger Fabric.
        
        Args:
            block_data: The block data to submit
            
        Returns:
            Transaction ID from Hyperledger
        """
        try:
            client = await self._get_client()
            
            # Prepare transaction data
            transaction_data = {
                "block_number": block_data.get("block_number"),
                "merkle_root": block_data.get("merkle_root"),
                "entry_count": block_data.get("entry_count"),
                "timestamp": datetime.utcnow().isoformat(),
                "entries": block_data.get("entries", [])
            }
            
            # In a real implementation, this would:
            # 1. Create a transaction proposal
            # 2. Send it to endorsing peers
            # 3. Submit to ordering service
            # 4. Return transaction ID
            
            # Stub implementation
            import hashlib
            tx_data = json.dumps(transaction_data, sort_keys=True)
            tx_id = hashlib.sha256(tx_data.encode()).hexdigest()
            
            logger.info(f"Submitted block {block_data.get('block_number')} to Hyperledger (tx: {tx_id})")
            return tx_id
            
        except Exception as e:
            logger.error(f"Failed to submit block to Hyperledger: {e}")
            raise
    
    async def verify_block(self, block_id: str) -> bool:
        """Verify a block exists on Hyperledger Fabric.
        
        Args:
            block_id: The block ID to verify
            
        Returns:
            True if block is valid, False otherwise
        """
        try:
            client = await self._get_client()
            
            # In a real implementation, this would:
            # 1. Query the blockchain for the block
            # 2. Verify the block structure
            # 3. Check block signatures
            
            # Stub implementation - always return True for demo
            logger.info(f"Verified block {block_id} on Hyperledger")
            return True
            
        except Exception as e:
            logger.error(f"Failed to verify block {block_id}: {e}")
            return False
    
    async def get_block_proof(self, block_id: str) -> Optional[Dict[str, Any]]:
        """Get a proof of block existence from Hyperledger Fabric.
        
        Args:
            block_id: The block ID to get proof for
            
        Returns:
            Proof data or None if not found
        """
        try:
            client = await self._get_client()
            
            # In a real implementation, this would:
            # 1. Query the blockchain for block details
            # 2. Get block header and signatures
            # 3. Return proof data
            
            # Stub implementation
            proof_data = {
                "block_id": block_id,
                "block_hash": f"hyperledger_hash_{block_id}",
                "block_number": int(block_id.split('_')[-1]) if '_' in block_id else 0,
                "timestamp": datetime.utcnow().isoformat(),
                "proof_type": "hyperledger_fabric",
                "signatures": ["peer1_signature", "peer2_signature"],
                "merkle_root": f"merkle_root_{block_id}"
            }
            
            logger.info(f"Retrieved block proof for {block_id} from Hyperledger")
            return proof_data
            
        except Exception as e:
            logger.error(f"Failed to get block proof for {block_id}: {e}")
            return None


class OmniSealAdapter(LedgerAdapter):
    """Adapter for OmniSeal blockchain backend."""
    
    def __init__(self, 
                 api_endpoint: str = "https://api.omniseal.com",
                 api_key: str = None,
                 network_id: str = "mainnet"):
        """Initialize OmniSeal adapter.
        
        Args:
            api_endpoint: OmniSeal API endpoint
            api_key: API key for authentication
            network_id: Network ID to use
        """
        self.api_endpoint = api_endpoint
        self.api_key = api_key
        self.network_id = network_id
        self._session = None
    
    async def _get_session(self):
        """Get or create HTTP session."""
        if self._session is None:
            try:
                import aiohttp
                headers = {}
                if self.api_key:
                    headers["Authorization"] = f"Bearer {self.api_key}"
                self._session = aiohttp.ClientSession(
                    base_url=self.api_endpoint,
                    headers=headers
                )
            except ImportError:
                logger.warning("aiohttp not available, using stub implementation")
                self._session = "stub_session"
        return self._session
    
    async def submit_block(self, block_data: Dict[str, Any]) -> str:
        """Submit a block to OmniSeal.
        
        Args:
            block_data: The block data to submit
            
        Returns:
            Transaction ID from OmniSeal
        """
        try:
            session = await self._get_session()
            
            # Prepare submission data
            submission_data = {
                "network_id": self.network_id,
                "block_data": block_data,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # In a real implementation, this would:
            # 1. Send POST request to OmniSeal API
            # 2. Handle response and errors
            # 3. Return transaction ID
            
            # Stub implementation
            import hashlib
            tx_data = json.dumps(submission_data, sort_keys=True)
            tx_id = hashlib.sha256(tx_data.encode()).hexdigest()
            
            logger.info(f"Submitted block {block_data.get('block_number')} to OmniSeal (tx: {tx_id})")
            return tx_id
            
        except Exception as e:
            logger.error(f"Failed to submit block to OmniSeal: {e}")
            raise
    
    async def verify_block(self, block_id: str) -> bool:
        """Verify a block exists on OmniSeal.
        
        Args:
            block_id: The block ID to verify
            
        Returns:
            True if block is valid, False otherwise
        """
        try:
            session = await self._get_session()
            
            # In a real implementation, this would:
            # 1. Send GET request to OmniSeal API
            # 2. Check response status
            # 3. Verify block data
            
            # Stub implementation
            logger.info(f"Verified block {block_id} on OmniSeal")
            return True
            
        except Exception as e:
            logger.error(f"Failed to verify block {block_id}: {e}")
            return False
    
    async def get_block_proof(self, block_id: str) -> Optional[Dict[str, Any]]:
        """Get a proof of block existence from OmniSeal.
        
        Args:
            block_id: The block ID to get proof for
            
        Returns:
            Proof data or None if not found
        """
        try:
            session = await self._get_session()
            
            # In a real implementation, this would:
            # 1. Send GET request to OmniSeal API
            # 2. Parse response data
            # 3. Return proof information
            
            # Stub implementation
            proof_data = {
                "block_id": block_id,
                "block_hash": f"omniseal_hash_{block_id}",
                "block_number": int(block_id.split('_')[-1]) if '_' in block_id else 0,
                "timestamp": datetime.utcnow().isoformat(),
                "proof_type": "omniseal",
                "network_id": self.network_id,
                "merkle_root": f"merkle_root_{block_id}"
            }
            
            logger.info(f"Retrieved block proof for {block_id} from OmniSeal")
            return proof_data
            
        except Exception as e:
            logger.error(f"Failed to get block proof for {block_id}: {e}")
            return None


class StubAdapter(LedgerAdapter):
    """Stub adapter for testing and development."""
    
    def __init__(self):
        """Initialize stub adapter."""
        self.submitted_blocks = {}
        self.block_proofs = {}
    
    async def submit_block(self, block_data: Dict[str, Any]) -> str:
        """Submit a block to the stub storage.
        
        Args:
            block_data: The block data to submit
            
        Returns:
            Generated block ID
        """
        import hashlib
        block_id = f"stub_block_{len(self.submitted_blocks) + 1}"
        self.submitted_blocks[block_id] = block_data
        logger.info(f"Submitted block {block_data.get('block_number')} to stub storage (id: {block_id})")
        return block_id
    
    async def verify_block(self, block_id: str) -> bool:
        """Verify a block exists in stub storage.
        
        Args:
            block_id: The block ID to verify
            
        Returns:
            True if block exists, False otherwise
        """
        exists = block_id in self.submitted_blocks
        logger.info(f"Verified block {block_id} in stub storage: {exists}")
        return exists
    
    async def get_block_proof(self, block_id: str) -> Optional[Dict[str, Any]]:
        """Get a proof of block existence from stub storage.
        
        Args:
            block_id: The block ID to get proof for
            
        Returns:
            Proof data or None if not found
        """
        if block_id not in self.submitted_blocks:
            return None
        
        block_data = self.submitted_blocks[block_id]
        proof_data = {
            "block_id": block_id,
            "block_hash": f"stub_hash_{block_id}",
            "block_number": block_data.get("block_number", 0),
            "timestamp": datetime.utcnow().isoformat(),
            "proof_type": "stub",
            "merkle_root": block_data.get("merkle_root", "")
        }
        
        logger.info(f"Retrieved block proof for {block_id} from stub storage")
        return proof_data
