"""Contract engine for managing contract lifecycle and operations."""

from datetime import datetime
from typing import List, Optional
from uuid import UUID

from sqlmodel import Session, create_engine

from fastmcp.utilities.logging import get_logger

from .contract import Contract, ContractState, ContractCreateRequest, ContractProposeRequest, ContractSignRequest, ContractRevokeRequest
from .crypto import ContractSigner, CryptoError
from .registry import ContractRegistry

logger = get_logger(__name__)


class ContractEngine:
    """Engine for managing contract lifecycle and operations."""
    
    def __init__(self, database_url: str = "sqlite:///contracts.db"):
        """Initialize contract engine with database connection.
        
        Args:
            database_url: Database connection URL
        """
        self.engine = create_engine(database_url, echo=False)
        self._create_tables()
    
    def _create_tables(self):
        """Create database tables."""
        try:
            Contract.metadata.create_all(self.engine)
            logger.info("Contract database tables created/verified")
        except Exception as e:
            logger.error(f"Failed to create contract tables: {e}")
            raise
    
    def get_session(self) -> Session:
        """Get database session.
        
        Returns:
            SQLModel database session
        """
        return Session(self.engine)
    
    def get_registry(self) -> ContractRegistry:
        """Get contract registry.
        
        Returns:
            Contract registry instance
        """
        return ContractRegistry(self.get_session())
    
    async def create_contract(self, request: ContractCreateRequest, created_by: str) -> Contract:
        """Create a new contract.
        
        Args:
            request: Contract creation request
            created_by: ID of the creating party
            
        Returns:
            Created contract instance
            
        Raises:
            ValueError: If contract creation fails
        """
        try:
            registry = self.get_registry()
            
            # Convert request to contract data
            contract_data = {
                "title": request.title,
                "description": request.description,
                "clauses": [clause.model_dump() for clause in request.clauses],
                "parties": request.parties,
                "is_hipaa_compliant": request.is_hipaa_compliant,
                "hipaa_entities": request.hipaa_entities or [],
                "expires_at": request.expires_at,
                "metadata": request.metadata,
                "version": request.version
            }
            
            contract = registry.create_contract(contract_data, created_by)
            logger.info(f"Created contract {contract.id} by {created_by}")
            return contract
            
        except Exception as e:
            logger.error(f"Failed to create contract: {e}")
            raise
    
    async def get_contract(self, contract_id: UUID) -> Optional[Contract]:
        """Get a contract by ID.
        
        Args:
            contract_id: Contract UUID
            
        Returns:
            Contract instance or None if not found
        """
        try:
            registry = self.get_registry()
            return registry.get_contract(contract_id)
        except Exception as e:
            logger.error(f"Failed to get contract {contract_id}: {e}")
            return None
    
    async def list_contracts(self, state: Optional[ContractState] = None, 
                           created_by: Optional[str] = None) -> List[Contract]:
        """List contracts with optional filtering.
        
        Args:
            state: Optional state filter
            created_by: Optional creator filter
            
        Returns:
            List of contract instances
        """
        try:
            registry = self.get_registry()
            return registry.list_contracts(state, created_by)
        except Exception as e:
            logger.error(f"Failed to list contracts: {e}")
            return []
    
    async def propose_contract(self, contract_id: UUID, request: ContractProposeRequest, 
                              proposed_by: str) -> Optional[Contract]:
        """Propose a contract to parties.
        
        Args:
            contract_id: Contract UUID
            request: Proposal request
            proposed_by: ID of the proposing party
            
        Returns:
            Updated contract instance or None if not found
            
        Raises:
            ValueError: If proposal fails
        """
        try:
            registry = self.get_registry()
            
            # Validate contract exists and can be proposed
            contract = registry.get_contract(contract_id)
            if not contract:
                raise ValueError("Contract not found")
            
            if contract.state != ContractState.DRAFT:
                raise ValueError(f"Cannot propose contract in state {contract.state}")
            
            # Update metadata with proposal info
            metadata = {
                "proposal": {
                    "proposed_to": request.proposed_to,
                    "message": request.message,
                    "proposed_by": proposed_by,
                    "timestamp": datetime.utcnow().isoformat()
                }
            }
            
            # Update state to proposed
            updated_contract = registry.update_contract_state(
                contract_id, ContractState.PROPOSED, proposed_by, metadata
            )
            
            logger.info(f"Proposed contract {contract_id} to {request.proposed_to} by {proposed_by}")
            return updated_contract
            
        except Exception as e:
            logger.error(f"Failed to propose contract {contract_id}: {e}")
            raise
    
    async def sign_contract(self, contract_id: UUID, request: ContractSignRequest) -> Optional[Contract]:
        """Sign a contract.
        
        Args:
            contract_id: Contract UUID
            request: Signing request
            
        Returns:
            Updated contract instance or None if not found
            
        Raises:
            ValueError: If signing fails
        """
        try:
            registry = self.get_registry()
            
            # Validate contract exists and can be signed
            contract = registry.get_contract(contract_id)
            if not contract:
                raise ValueError("Contract not found")
            
            if contract.state not in [ContractState.PROPOSED, ContractState.SIGNED]:
                raise ValueError(f"Cannot sign contract in state {contract.state}")
            
            # Check if party is already signed
            existing_signatures = contract.get_signatures()
            if any(sig.signer_id == request.signer_id for sig in existing_signatures):
                raise ValueError("Party has already signed this contract")
            
            # Verify signature
            if not self._verify_contract_signature(contract, request):
                raise ValueError("Invalid signature")
            
            # Create signature object
            from .contract import Signature
            signature = Signature(
                signer_id=request.signer_id,
                signer_type=request.signer_type,
                signature=request.signature,
                public_key=request.public_key,
                metadata=request.metadata
            )
            
            # Add signature
            updated_contract = registry.add_signature(contract_id, signature.model_dump())
            
            logger.info(f"Signed contract {contract_id} by {request.signer_id}")
            return updated_contract
            
        except Exception as e:
            logger.error(f"Failed to sign contract {contract_id}: {e}")
            raise
    
    async def revoke_contract(self, contract_id: UUID, request: ContractRevokeRequest) -> Optional[Contract]:
        """Revoke a contract.
        
        Args:
            contract_id: Contract UUID
            request: Revocation request
            
        Returns:
            Updated contract instance or None if not found
            
        Raises:
            ValueError: If revocation fails
        """
        try:
            registry = self.get_registry()
            
            # Validate contract exists and can be revoked
            contract = registry.get_contract(contract_id)
            if not contract:
                raise ValueError("Contract not found")
            
            if contract.state == ContractState.REVOKED:
                raise ValueError("Contract is already revoked")
            
            if contract.state == ContractState.EXPIRED:
                raise ValueError("Cannot revoke expired contract")
            
            # Revoke contract
            updated_contract = registry.revoke_contract(
                contract_id, request.reason, request.revoked_by, request.metadata
            )
            
            logger.info(f"Revoked contract {contract_id} by {request.revoked_by}: {request.reason}")
            return updated_contract
            
        except Exception as e:
            logger.error(f"Failed to revoke contract {contract_id}: {e}")
            raise
    
    def _verify_contract_signature(self, contract: Contract, request: ContractSignRequest) -> bool:
        """Verify a contract signature.
        
        Args:
            contract: Contract instance
            request: Signing request
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            from .crypto import verify_signature
            
            # Create signing message
            signing_message = f"{contract.id}:{contract.get_content_hash()}:{request.signer_id}:{request.signer_type}"
            
            # Verify signature
            return verify_signature(
                request.public_key,
                signing_message,
                request.signature
            )
            
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False
    
    async def get_contracts_by_party(self, party_id: str) -> List[Contract]:
        """Get contracts involving a specific party.
        
        Args:
            party_id: Party ID to search for
            
        Returns:
            List of contracts involving the party
        """
        try:
            registry = self.get_registry()
            return registry.get_contracts_by_party(party_id)
        except Exception as e:
            logger.error(f"Failed to get contracts for party {party_id}: {e}")
            return []
    
    async def cleanup_expired_contracts(self) -> int:
        """Mark expired contracts as expired.
        
        Returns:
            Number of contracts marked as expired
        """
        try:
            registry = self.get_registry()
            count = registry.mark_contracts_expired()
            logger.info(f"Marked {count} contracts as expired")
            return count
        except Exception as e:
            logger.error(f"Failed to cleanup expired contracts: {e}")
            return 0
    
    async def get_contract_statistics(self) -> dict:
        """Get contract statistics.
        
        Returns:
            Dictionary with contract statistics
        """
        try:
            registry = self.get_registry()
            
            # Get all contracts
            all_contracts = registry.list_contracts()
            
            # Count by state
            state_counts = {}
            for state in ContractState:
                state_counts[state.value] = len([c for c in all_contracts if c.state == state])
            
            # Count HIPAA contracts
            hipaa_count = len([c for c in all_contracts if c.is_hipaa_compliant])
            
            # Count signed contracts
            signed_count = len([c for c in all_contracts if c.state == ContractState.SIGNED])
            
            return {
                "total_contracts": len(all_contracts),
                "by_state": state_counts,
                "hipaa_compliant": hipaa_count,
                "signed_contracts": signed_count,
                "expired_contracts": len(registry.get_expired_contracts())
            }
            
        except Exception as e:
            logger.error(f"Failed to get contract statistics: {e}")
            return {}
