"""Contract registry for managing contract persistence and lifecycle."""

import json
from datetime import datetime
from typing import List, Optional
from uuid import UUID

from sqlmodel import Session, select

from fastmcp.utilities.logging import get_logger

from .contract import Contract, ContractState, Signature
from .crypto import ContractSigner, CryptoError

logger = get_logger(__name__)


class ContractRegistry:
    """Registry for managing contract persistence and lifecycle operations."""
    
    def __init__(self, session: Session):
        """Initialize registry with database session.
        
        Args:
            session: SQLModel database session
        """
        self.session = session
    
    def create_contract(self, contract_data: dict, created_by: str) -> Contract:
        """Create a new contract.
        
        Args:
            contract_data: Contract data dictionary
            created_by: ID of the creating party
            
        Returns:
            Created contract instance
            
        Raises:
            ValueError: If contract data is invalid
        """
        try:
            # Create contract instance
            contract = Contract(
                title=contract_data["title"],
                description=contract_data["description"],
                created_by=created_by,
                is_hipaa_compliant=contract_data.get("is_hipaa_compliant", False),
                version=contract_data.get("version", "1.0.0")
            )
            
            # Set clauses
            if "clauses" in contract_data:
                from .contract import Clause
                clauses = [Clause(**clause) for clause in contract_data["clauses"]]
                contract.set_clauses(clauses)
            
            # Set parties
            if "parties" in contract_data:
                contract.set_parties(contract_data["parties"])
            
            # Set HIPAA entities
            if "hipaa_entities" in contract_data and contract_data["hipaa_entities"]:
                contract.set_hipaa_entities(contract_data["hipaa_entities"])
            
            # Set metadata
            if "metadata" in contract_data:
                contract.set_metadata(contract_data["metadata"])
            
            # Set expiration
            if "expires_at" in contract_data and contract_data["expires_at"]:
                contract.expires_at = contract_data["expires_at"]
            
            # Save to database
            self.session.add(contract)
            self.session.commit()
            self.session.refresh(contract)
            
            logger.info(f"Created contract {contract.id} by {created_by}")
            return contract
            
        except Exception as e:
            self.session.rollback()
            logger.error(f"Failed to create contract: {e}")
            raise ValueError(f"Contract creation failed: {e}")
    
    def get_contract(self, contract_id: UUID) -> Optional[Contract]:
        """Get a contract by ID.
        
        Args:
            contract_id: Contract UUID
            
        Returns:
            Contract instance or None if not found
        """
        try:
            statement = select(Contract).where(Contract.id == contract_id)
            return self.session.exec(statement).first()
        except Exception as e:
            logger.error(f"Failed to get contract {contract_id}: {e}")
            return None
    
    def list_contracts(self, state: Optional[ContractState] = None, 
                      created_by: Optional[str] = None) -> List[Contract]:
        """List contracts with optional filtering.
        
        Args:
            state: Optional state filter
            created_by: Optional creator filter
            
        Returns:
            List of contract instances
        """
        try:
            statement = select(Contract)
            
            if state is not None:
                statement = statement.where(Contract.state == state)
            
            if created_by is not None:
                statement = statement.where(Contract.created_by == created_by)
            
            statement = statement.order_by(Contract.created_at.desc())
            return list(self.session.exec(statement))
            
        except Exception as e:
            logger.error(f"Failed to list contracts: {e}")
            return []
    
    def update_contract_state(self, contract_id: UUID, new_state: ContractState, 
                            updated_by: str, metadata: Optional[dict] = None) -> Optional[Contract]:
        """Update contract state with lifecycle validation.
        
        Args:
            contract_id: Contract UUID
            new_state: New state to transition to
            updated_by: ID of the updating party
            metadata: Optional metadata for the state change
            
        Returns:
            Updated contract instance or None if not found
            
        Raises:
            ValueError: If state transition is invalid
        """
        try:
            contract = self.get_contract(contract_id)
            if not contract:
                return None
            
            # Validate state transition
            if not contract.can_transition_to(new_state):
                raise ValueError(f"Invalid state transition from {contract.state} to {new_state}")
            
            # Update state and timestamps
            old_state = contract.state
            contract.state = new_state
            contract.last_modified = datetime.utcnow()
            
            # Set state-specific timestamps
            if new_state == ContractState.PROPOSED and contract.proposed_at is None:
                contract.proposed_at = datetime.utcnow()
            elif new_state == ContractState.SIGNED and contract.signed_at is None:
                contract.signed_at = datetime.utcnow()
            elif new_state == ContractState.REVOKED and contract.revoked_at is None:
                contract.revoked_at = datetime.utcnow()
            
            # Update metadata if provided
            if metadata:
                current_metadata = contract.get_metadata()
                current_metadata.update(metadata)
                current_metadata[f"state_change_{new_state}"] = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "updated_by": updated_by,
                    "previous_state": old_state
                }
                contract.set_metadata(current_metadata)
            
            # Save changes
            self.session.add(contract)
            self.session.commit()
            self.session.refresh(contract)
            
            logger.info(f"Updated contract {contract_id} state from {old_state} to {new_state} by {updated_by}")
            return contract
            
        except Exception as e:
            self.session.rollback()
            logger.error(f"Failed to update contract {contract_id} state: {e}")
            raise
    
    def add_signature(self, contract_id: UUID, signature_data: dict) -> Optional[Contract]:
        """Add a signature to a contract.
        
        Args:
            contract_id: Contract UUID
            signature_data: Signature data dictionary
            
        Returns:
            Updated contract instance or None if not found
            
        Raises:
            ValueError: If signature is invalid or contract not in signable state
        """
        try:
            contract = self.get_contract(contract_id)
            if not contract:
                return None
            
            # Validate contract state
            if contract.state not in [ContractState.PROPOSED, ContractState.SIGNED]:
                raise ValueError(f"Cannot sign contract in state {contract.state}")
            
            # Create signature
            from .contract import Signature
            signature = Signature(**signature_data)
            
            # Verify signature
            if not self._verify_signature(contract, signature):
                raise ValueError("Invalid signature")
            
            # Add signature
            signatures = contract.get_signatures()
            signatures.append(signature)
            contract.set_signatures(signatures)
            
            # Update state if fully signed
            if contract.is_fully_signed() and contract.state == ContractState.PROPOSED:
                # Use the proper state transition method
                contract = self.update_contract_state(contract_id, ContractState.SIGNED, signature.signer_id)
            
            contract.last_modified = datetime.utcnow()
            
            # Save changes
            self.session.add(contract)
            self.session.commit()
            self.session.refresh(contract)
            
            logger.info(f"Added signature to contract {contract_id} by {signature.signer_id}")
            return contract
            
        except Exception as e:
            self.session.rollback()
            logger.error(f"Failed to add signature to contract {contract_id}: {e}")
            raise
    
    def _verify_signature(self, contract: Contract, signature: Signature) -> bool:
        """Verify a contract signature.
        
        Args:
            contract: Contract instance
            signature: Signature to verify
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            from .crypto import verify_signature
            
            # Create signing message
            signing_message = f"{contract.id}:{contract.get_content_hash()}:{signature.signer_id}:{signature.signer_type}"
            
            # Verify signature
            return verify_signature(
                signature.public_key,
                signing_message,
                signature.signature
            )
            
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False
    
    def revoke_contract(self, contract_id: UUID, reason: str, revoked_by: str, 
                       metadata: Optional[dict] = None) -> Optional[Contract]:
        """Revoke a contract.
        
        Args:
            contract_id: Contract UUID
            reason: Reason for revocation
            revoked_by: ID of the revoking party
            metadata: Optional revocation metadata
            
        Returns:
            Updated contract instance or None if not found
            
        Raises:
            ValueError: If contract cannot be revoked
        """
        try:
            contract = self.get_contract(contract_id)
            if not contract:
                return None
            
            # Validate revocation
            if contract.state == ContractState.REVOKED:
                raise ValueError("Contract is already revoked")
            
            if contract.state == ContractState.EXPIRED:
                raise ValueError("Cannot revoke expired contract")
            
            # Update metadata with revocation info
            current_metadata = contract.get_metadata()
            current_metadata["revocation"] = {
                "reason": reason,
                "revoked_by": revoked_by,
                "timestamp": datetime.utcnow().isoformat()
            }
            if metadata:
                current_metadata["revocation"].update(metadata)
            
            contract.set_metadata(current_metadata)
            
            # Update state
            return self.update_contract_state(contract_id, ContractState.REVOKED, revoked_by)
            
        except Exception as e:
            logger.error(f"Failed to revoke contract {contract_id}: {e}")
            raise
    
    def get_contracts_by_party(self, party_id: str) -> List[Contract]:
        """Get contracts involving a specific party.
        
        Args:
            party_id: Party ID to search for
            
        Returns:
            List of contracts involving the party
        """
        try:
            statement = select(Contract)
            contracts = list(self.session.exec(statement))
            
            # Filter contracts that involve the party
            party_contracts = []
            for contract in contracts:
                parties = contract.get_parties()
                if any(party.get("id") == party_id for party in parties):
                    party_contracts.append(contract)
            
            return party_contracts
            
        except Exception as e:
            logger.error(f"Failed to get contracts for party {party_id}: {e}")
            return []
    
    def get_expired_contracts(self) -> List[Contract]:
        """Get contracts that have expired.
        
        Returns:
            List of expired contracts
        """
        try:
            now = datetime.utcnow()
            statement = select(Contract).where(
                Contract.expires_at.isnot(None),
                Contract.expires_at < now,
                Contract.state.notin_([ContractState.EXPIRED, ContractState.REVOKED])
            )
            return list(self.session.exec(statement))
            
        except Exception as e:
            logger.error(f"Failed to get expired contracts: {e}")
            return []
    
    def mark_contracts_expired(self) -> int:
        """Mark expired contracts as expired.
        
        Returns:
            Number of contracts marked as expired
        """
        try:
            expired_contracts = self.get_expired_contracts()
            count = 0
            
            for contract in expired_contracts:
                contract.state = ContractState.EXPIRED
                contract.last_modified = datetime.utcnow()
                self.session.add(contract)
                count += 1
            
            if count > 0:
                self.session.commit()
                logger.info(f"Marked {count} contracts as expired")
            
            return count
            
        except Exception as e:
            self.session.rollback()
            logger.error(f"Failed to mark contracts as expired: {e}")
            return 0
