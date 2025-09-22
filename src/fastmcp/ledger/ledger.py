"""Core ledger implementation with hash-linked entries and tamper-evident properties."""

import hashlib
import json
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field
from sqlmodel import SQLModel, Field as SQLField, Relationship

from fastmcp.utilities.logging import get_logger

logger = get_logger(__name__)


class EventType(str, Enum):
    """Types of events that can be recorded in the ledger."""
    TOOL_CALL = "tool_call"
    POLICY_DECISION = "policy_decision"
    DATA_FLOW = "data_flow"
    CONTRACT_ACTION = "contract_action"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    SYSTEM_EVENT = "system_event"


class LedgerEvent(BaseModel):
    """A ledger event with structured data."""
    
    event_type: EventType = Field(..., description="Type of event")
    actor_id: str = Field(..., description="ID of the actor performing the action")
    resource_id: Optional[str] = Field(default=None, description="ID of the resource being acted upon")
    action: str = Field(..., description="Action being performed")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional event metadata")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Event timestamp")
    data_hash: Optional[str] = Field(default=None, description="Hash of associated data")
    
    def get_content_hash(self) -> str:
        """Get SHA-256 hash of event content for integrity verification."""
        content = {
            "event_type": self.event_type,
            "actor_id": self.actor_id,
            "resource_id": self.resource_id,
            "action": self.action,
            "metadata": self.metadata,
            "data_hash": self.data_hash
        }
        content_str = json.dumps(content, sort_keys=True, default=str)
        return hashlib.sha256(content_str.encode()).hexdigest()


class LedgerEntry(SQLModel, table=True):
    """A single entry in the provenance ledger with hash chaining."""
    
    __tablename__ = "ledger_entries"
    
    # Primary fields
    id: UUID = SQLField(default_factory=uuid4, primary_key=True)
    sequence_number: int = SQLField(..., index=True, description="Sequential entry number")
    
    # Event data
    event_data: str = SQLField(..., description="JSON-encoded event data")
    
    # Hash chaining
    previous_hash: Optional[str] = SQLField(default=None, description="Hash of previous entry")
    entry_hash: str = SQLField(..., index=True, description="Hash of this entry")
    
    # Block information
    block_id: Optional[UUID] = SQLField(default=None, foreign_key="ledger_blocks.id", index=True)
    
    # Timestamps
    created_at: datetime = SQLField(default_factory=datetime.utcnow, index=True)
    
    # Verification
    is_verified: bool = SQLField(default=True, description="Whether entry has been verified")
    verification_timestamp: Optional[datetime] = SQLField(default=None)
    
    def get_event(self) -> LedgerEvent:
        """Get parsed event from JSON."""
        try:
            event_data = json.loads(self.event_data)
            return LedgerEvent(**event_data)
        except (json.JSONDecodeError, ValueError) as e:
            logger.error(f"Failed to parse event data: {e}")
            raise ValueError(f"Invalid event data: {e}")
    
    def set_event(self, event: LedgerEvent) -> None:
        """Set event as JSON."""
        self.event_data = json.dumps(event.model_dump(), default=str)
    
    def calculate_hash(self) -> str:
        """Calculate hash of this entry including previous hash."""
        content = {
            "sequence_number": self.sequence_number,
            "event_data": self.event_data,
            "previous_hash": self.previous_hash,
            "created_at": self.created_at.isoformat()
        }
        content_str = json.dumps(content, sort_keys=True, default=str)
        return hashlib.sha256(content_str.encode()).hexdigest()
    
    def verify_integrity(self) -> bool:
        """Verify that the entry hash matches the calculated hash."""
        calculated_hash = self.calculate_hash()
        return calculated_hash == self.entry_hash


class LedgerBlock(SQLModel, table=True):
    """A block of ledger entries with Merkle tree root."""
    
    __tablename__ = "ledger_blocks"
    
    # Primary fields
    id: UUID = SQLField(default_factory=uuid4, primary_key=True)
    block_number: int = SQLField(..., index=True, description="Sequential block number")
    
    # Block metadata
    entry_count: int = SQLField(..., description="Number of entries in this block")
    first_entry_sequence: int = SQLField(..., description="Sequence number of first entry")
    last_entry_sequence: int = SQLField(..., description="Sequence number of last entry")
    
    # Merkle tree
    merkle_root: str = SQLField(..., description="Merkle tree root hash")
    merkle_tree_data: str = SQLField(default="[]", description="JSON-encoded Merkle tree data")
    
    # Timestamps
    created_at: datetime = SQLField(default_factory=datetime.utcnow, index=True)
    sealed_at: Optional[datetime] = SQLField(default=None, description="When block was sealed")
    
    # Verification
    is_verified: bool = SQLField(default=True, description="Whether block has been verified")
    verification_timestamp: Optional[datetime] = SQLField(default=None)
    
    def get_merkle_tree_data(self) -> List[Dict[str, Any]]:
        """Get parsed Merkle tree data from JSON."""
        try:
            return json.loads(self.merkle_tree_data)
        except json.JSONDecodeError:
            return []
    
    def set_merkle_tree_data(self, tree_data: List[Dict[str, Any]]) -> None:
        """Set Merkle tree data as JSON."""
        self.merkle_tree_data = json.dumps(tree_data)
    
    def verify_integrity(self, entries: List[LedgerEntry]) -> bool:
        """Verify that the Merkle root matches the entries."""
        if len(entries) != self.entry_count:
            return False
        
        # Calculate Merkle root from entries
        from .merkle import MerkleTree
        entry_hashes = [entry.entry_hash for entry in entries]
        merkle_tree = MerkleTree(entry_hashes)
        calculated_root = merkle_tree.get_root()
        
        return calculated_root == self.merkle_root


class ProvenanceLedger:
    """Main ledger class for managing provenance entries with tamper-evident properties."""
    
    def __init__(self, database_url: str = "sqlite:///ledger.db"):
        """Initialize the provenance ledger.
        
        Args:
            database_url: Database connection URL
        """
        from sqlmodel import create_engine, Session
        self.engine = create_engine(database_url, echo=False)
        self._create_tables()
        self._current_sequence = self._get_next_sequence_number()
        self._current_block = None
        self._block_size = 100  # Entries per block
        
    def _create_tables(self):
        """Create database tables."""
        try:
            LedgerEntry.metadata.create_all(self.engine)
            LedgerBlock.metadata.create_all(self.engine)
            logger.info("Ledger database tables created/verified")
        except Exception as e:
            logger.error(f"Failed to create ledger tables: {e}")
            raise
    
    def _get_next_sequence_number(self) -> int:
        """Get the next sequence number for entries."""
        from sqlmodel import Session, select, func
        with Session(self.engine) as session:
            result = session.exec(select(func.max(LedgerEntry.sequence_number))).first()
            return (result or 0) + 1
    
    def _get_next_block_number(self) -> int:
        """Get the next block number."""
        from sqlmodel import Session, select, func
        with Session(self.engine) as session:
            result = session.exec(select(func.max(LedgerBlock.block_number))).first()
            return (result or 0) + 1
    
    def append_event(self, event: LedgerEvent) -> LedgerEntry:
        """Append a new event to the ledger.
        
        Args:
            event: The event to append
            
        Returns:
            The created ledger entry
            
        Raises:
            ValueError: If event is invalid
        """
        try:
            from sqlmodel import Session, select
            
            with Session(self.engine) as session:
                # Get previous entry hash
                previous_hash = None
                if self._current_sequence > 1:
                    prev_entry = session.exec(
                        select(LedgerEntry).where(
                            LedgerEntry.sequence_number == self._current_sequence - 1
                        )
                    ).first()
                    if prev_entry:
                        previous_hash = prev_entry.entry_hash
                
                # Create new entry
                entry = LedgerEntry(
                    sequence_number=self._current_sequence,
                    previous_hash=previous_hash
                )
                entry.set_event(event)
                entry.entry_hash = entry.calculate_hash()
                
                # Add to current block or create new block
                if self._current_block is None or self._should_seal_block():
                    self._current_block = self._create_new_block(session)
                
                entry.block_id = self._current_block.id
                
                # Save entry
                session.add(entry)
                session.commit()
                session.refresh(entry)
                
                # Update block entry count
                self._current_block.entry_count += 1
                self._current_block.last_entry_sequence = entry.sequence_number
                session.add(self._current_block)
                
                # Check if block should be sealed
                if self._should_seal_block():
                    self._seal_block(session)
                
                self._current_sequence += 1
                
                logger.info(f"Appended event {entry.id} to ledger (sequence: {entry.sequence_number})")
                return entry
                
        except Exception as e:
            logger.error(f"Failed to append event: {e}")
            raise ValueError(f"Failed to append event: {e}")
    
    def _should_seal_block(self) -> bool:
        """Check if current block should be sealed."""
        return (self._current_block and 
                self._current_block.entry_count >= self._block_size)
    
    def _create_new_block(self, session) -> LedgerBlock:
        """Create a new block."""
        block_number = self._get_next_block_number()
        block = LedgerBlock(
            block_number=block_number,
            entry_count=0,
            first_entry_sequence=self._current_sequence,
            last_entry_sequence=self._current_sequence - 1,
            merkle_root="",  # Will be set when sealed
            merkle_tree_data="[]"
        )
        session.add(block)
        session.commit()
        session.refresh(block)
        return block
    
    def _seal_block(self, session):
        """Seal the current block with Merkle tree."""
        if not self._current_block:
            return
        
        from sqlmodel import select
        
        # Get all entries in this block
        entries = session.exec(
            select(LedgerEntry).where(
                LedgerEntry.block_id == self._current_block.id
            ).order_by(LedgerEntry.sequence_number)
        ).all()
        
        if not entries:
            return
        
        # Create Merkle tree
        from .merkle import MerkleTree
        entry_hashes = [entry.entry_hash for entry in entries]
        merkle_tree = MerkleTree(entry_hashes)
        
        # Update block with Merkle root
        self._current_block.merkle_root = merkle_tree.get_root()
        self._current_block.merkle_tree_data = json.dumps(merkle_tree.get_tree_data())
        self._current_block.sealed_at = datetime.utcnow()
        self._current_block.is_verified = True
        self._current_block.verification_timestamp = datetime.utcnow()
        
        session.add(self._current_block)
        session.commit()
        
        logger.info(f"Sealed block {self._current_block.block_number} with {len(entries)} entries")
        self._current_block = None

    def seal_current_block(self) -> bool:
        """Manually seal the current block if it exists.
        
        Returns:
            True if block was sealed, False if no current block
        """
        if not self._current_block:
            return False
        
        try:
            from sqlmodel import Session
            
            with Session(self.engine) as session:
                self._seal_block(session)
            return True
        except Exception as e:
            logger.error(f"Failed to seal current block: {e}")
            return False
    
    def get_entry(self, sequence_number: int) -> Optional[LedgerEntry]:
        """Get a ledger entry by sequence number.
        
        Args:
            sequence_number: The sequence number of the entry
            
        Returns:
            The ledger entry or None if not found
        """
        from sqlmodel import Session, select
        
        with Session(self.engine) as session:
            return session.exec(
                select(LedgerEntry).where(
                    LedgerEntry.sequence_number == sequence_number
                )
            ).first()
    
    def get_block(self, block_number: int) -> Optional[LedgerBlock]:
        """Get a ledger block by block number.
        
        Args:
            block_number: The block number
            
        Returns:
            The ledger block or None if not found
        """
        from sqlmodel import Session, select
        
        with Session(self.engine) as session:
            return session.exec(
                select(LedgerBlock).where(
                    LedgerBlock.block_number == block_number
                )
            ).first()
    
    def get_block_entries(self, block_number: int) -> List[LedgerEntry]:
        """Get all entries in a block.
        
        Args:
            block_number: The block number
            
        Returns:
            List of ledger entries in the block
        """
        from sqlmodel import Session, select
        
        with Session(self.engine) as session:
            block = self.get_block(block_number)
            if not block:
                return []
            
            return session.exec(
                select(LedgerEntry).where(
                    LedgerEntry.block_id == block.id
                ).order_by(LedgerEntry.sequence_number)
            ).all()
    
    def verify_block_integrity(self, block_number: int) -> bool:
        """Verify the integrity of a block and its entries.
        
        Args:
            block_number: The block number to verify
            
        Returns:
            True if block is valid, False otherwise
        """
        try:
            block = self.get_block(block_number)
            if not block:
                return False
            
            entries = self.get_block_entries(block_number)
            if not entries:
                return False
            
            # Verify each entry
            for entry in entries:
                if not entry.verify_integrity():
                    logger.warning(f"Entry {entry.sequence_number} failed integrity check")
                    return False
            
            # Verify block Merkle root
            if not block.verify_integrity(entries):
                logger.warning(f"Block {block_number} failed Merkle root verification")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to verify block {block_number}: {e}")
            return False
    
    def verify_chain_integrity(self, start_sequence: int = 1, end_sequence: Optional[int] = None) -> bool:
        """Verify the integrity of the entire chain or a range of entries.
        
        Args:
            start_sequence: Starting sequence number (default: 1)
            end_sequence: Ending sequence number (default: None for all)
            
        Returns:
            True if chain is valid, False otherwise
        """
        try:
            from sqlmodel import Session, select
            
            with Session(self.engine) as session:
                query = select(LedgerEntry).where(
                    LedgerEntry.sequence_number >= start_sequence
                ).order_by(LedgerEntry.sequence_number)
                
                if end_sequence:
                    query = query.where(LedgerEntry.sequence_number <= end_sequence)
                
                entries = session.exec(query).all()
                
                if not entries:
                    return True
                
                # Verify each entry and hash chain
                previous_hash = None
                for entry in entries:
                    # Verify entry integrity
                    if not entry.verify_integrity():
                        logger.warning(f"Entry {entry.sequence_number} failed integrity check")
                        return False
                    
                    # Verify hash chain
                    if previous_hash and entry.previous_hash != previous_hash:
                        logger.warning(f"Hash chain broken at entry {entry.sequence_number}")
                        return False
                    
                    previous_hash = entry.entry_hash
                
                return True
                
        except Exception as e:
            logger.error(f"Failed to verify chain integrity: {e}")
            return False
    
    def get_ledger_statistics(self) -> Dict[str, Any]:
        """Get statistics about the ledger.
        
        Returns:
            Dictionary with ledger statistics
        """
        from sqlmodel import Session, select, func
        
        with Session(self.engine) as session:
            total_entries = session.exec(select(func.count(LedgerEntry.id))).first() or 0
            total_blocks = session.exec(select(func.count(LedgerBlock.id))).first() or 0
            sealed_blocks = session.exec(
                select(func.count(LedgerBlock.id)).where(
                    LedgerBlock.sealed_at.isnot(None)
                )
            ).first() or 0
            
            return {
                "total_entries": total_entries,
                "total_blocks": total_blocks,
                "sealed_blocks": sealed_blocks,
                "unsealed_blocks": total_blocks - sealed_blocks,
                "current_sequence": self._current_sequence - 1,
                "block_size": self._block_size
            }
