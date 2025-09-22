"""Tests for the core ledger functionality."""

import pytest
from datetime import datetime
from uuid import uuid4

from fastmcp.ledger import ProvenanceLedger, LedgerEvent, EventType, LedgerEntry, LedgerBlock


class TestProvenanceLedger:
    """Test the ProvenanceLedger class."""
    
    @pytest.fixture
    def ledger(self):
        """Create a ledger instance for testing."""
        return ProvenanceLedger("sqlite:///:memory:")
    
    @pytest.fixture
    def sample_event(self):
        """Create a sample event for testing."""
        return LedgerEvent(
            event_type=EventType.TOOL_CALL,
            actor_id="user123",
            resource_id="resource456",
            action="execute_tool",
            metadata={"tool_name": "test_tool", "parameters": {"x": 1, "y": 2}},
            data_hash="sha256_hash_of_data"
        )
    
    def test_ledger_initialization(self, ledger):
        """Test ledger initialization."""
        assert ledger is not None
        assert ledger._current_sequence == 1
        assert ledger._current_block is None
        assert ledger._block_size == 100
    
    def test_append_event(self, ledger, sample_event):
        """Test appending an event to the ledger."""
        entry = ledger.append_event(sample_event)
        
        assert entry is not None
        assert entry.sequence_number == 1
        assert entry.previous_hash is None
        assert entry.entry_hash is not None
        assert entry.block_id is not None
        assert entry.is_verified is True
        
        # Verify the event data
        event = entry.get_event()
        assert event.event_type == sample_event.event_type
        assert event.actor_id == sample_event.actor_id
        assert event.action == sample_event.action
    
    def test_hash_chaining(self, ledger, sample_event):
        """Test that entries are properly hash-chained."""
        # Append first event
        entry1 = ledger.append_event(sample_event)
        
        # Append second event
        entry2 = ledger.append_event(sample_event)
        
        # Verify hash chaining
        assert entry2.previous_hash == entry1.entry_hash
        assert entry2.sequence_number == entry1.sequence_number + 1
    
    def test_entry_integrity_verification(self, ledger, sample_event):
        """Test entry integrity verification."""
        entry = ledger.append_event(sample_event)
        
        # Verify entry integrity
        assert entry.verify_integrity() is True
        
        # Tamper with the entry
        original_hash = entry.entry_hash
        entry.entry_hash = "tampered_hash"
        
        # Verify integrity fails
        assert entry.verify_integrity() is False
        
        # Restore original hash
        entry.entry_hash = original_hash
        assert entry.verify_integrity() is True
    
    def test_get_entry(self, ledger, sample_event):
        """Test retrieving an entry by sequence number."""
        entry = ledger.append_event(sample_event)
        
        retrieved_entry = ledger.get_entry(entry.sequence_number)
        assert retrieved_entry is not None
        assert retrieved_entry.id == entry.id
        assert retrieved_entry.sequence_number == entry.sequence_number
    
    def test_get_nonexistent_entry(self, ledger):
        """Test retrieving a non-existent entry."""
        entry = ledger.get_entry(999)
        assert entry is None
    
    def test_block_creation_and_sealing(self, ledger, sample_event):
        """Test block creation and sealing."""
        # Append events to fill a block
        entries = []
        for i in range(5):  # Use a smaller number for testing
            event = LedgerEvent(
                event_type=EventType.TOOL_CALL,
                actor_id=f"user{i}",
                action=f"action_{i}",
                metadata={"index": i}
            )
            entry = ledger.append_event(event)
            entries.append(entry)
        
        # Manually seal the block (normally done when block_size is reached)
        from sqlmodel import Session
        with Session(ledger.engine) as session:
            ledger._seal_block(session)
        
        # Get the block
        block = ledger.get_block(1)
        assert block is not None
        assert block.block_number == 1
        assert block.entry_count == 5
        assert block.merkle_root is not None
        assert block.sealed_at is not None
        assert block.is_verified is True
    
    def test_block_integrity_verification(self, ledger, sample_event):
        """Test block integrity verification."""
        # Create a block with multiple entries
        entries = []
        for i in range(3):
            event = LedgerEvent(
                event_type=EventType.TOOL_CALL,
                actor_id=f"user{i}",
                action=f"action_{i}"
            )
            entry = ledger.append_event(event)
            entries.append(entry)
        
        # Seal the block
        from sqlmodel import Session
        with Session(ledger.engine) as session:
            ledger._seal_block(session)
        
        # Verify block integrity
        assert ledger.verify_block_integrity(1) is True
        
        # Tamper with an entry
        entry = ledger.get_entry(1)
        original_hash = entry.entry_hash
        entry.entry_hash = "tampered_hash"
        
        # Update the entry in the database
        with Session(ledger.engine) as session:
            session.add(entry)
            session.commit()
        
        # Verify block integrity fails
        assert ledger.verify_block_integrity(1) is False
    
    def test_chain_integrity_verification(self, ledger, sample_event):
        """Test chain integrity verification."""
        # Append multiple events
        for i in range(5):
            event = LedgerEvent(
                event_type=EventType.TOOL_CALL,
                actor_id=f"user{i}",
                action=f"action_{i}"
            )
            ledger.append_event(event)
        
        # Verify entire chain
        assert ledger.verify_chain_integrity() is True
        
        # Verify partial chain
        assert ledger.verify_chain_integrity(start_sequence=2, end_sequence=4) is True
    
    def test_chain_integrity_with_tampering(self, ledger, sample_event):
        """Test chain integrity verification with tampered entries."""
        # Append multiple events
        entries = []
        for i in range(3):
            event = LedgerEvent(
                event_type=EventType.TOOL_CALL,
                actor_id=f"user{i}",
                action=f"action_{i}"
            )
            entry = ledger.append_event(event)
            entries.append(entry)
        
        # Verify chain is intact
        assert ledger.verify_chain_integrity() is True
        
        # Tamper with middle entry
        middle_entry = entries[1]
        original_hash = middle_entry.entry_hash
        middle_entry.entry_hash = "tampered_hash"
        
        # Update in database
        from sqlmodel import Session
        with Session(ledger.engine) as session:
            session.add(middle_entry)
            session.commit()
        
        # Verify chain integrity fails
        assert ledger.verify_chain_integrity() is False
    
    def test_ledger_statistics(self, ledger, sample_event):
        """Test ledger statistics."""
        # Initially empty
        stats = ledger.get_ledger_statistics()
        assert stats["total_entries"] == 0
        assert stats["total_blocks"] == 0
        assert stats["current_sequence"] == 0
        
        # Add some entries
        for i in range(3):
            event = LedgerEvent(
                event_type=EventType.TOOL_CALL,
                actor_id=f"user{i}",
                action=f"action_{i}"
            )
            ledger.append_event(event)
        
        # Check updated statistics
        stats = ledger.get_ledger_statistics()
        assert stats["total_entries"] == 3
        assert stats["total_blocks"] == 1
        assert stats["current_sequence"] == 3
    
    def test_different_event_types(self, ledger):
        """Test appending different types of events."""
        event_types = [
            EventType.TOOL_CALL,
            EventType.POLICY_DECISION,
            EventType.DATA_FLOW,
            EventType.CONTRACT_ACTION,
            EventType.AUTHENTICATION,
            EventType.AUTHORIZATION,
            EventType.SYSTEM_EVENT
        ]
        
        for event_type in event_types:
            event = LedgerEvent(
                event_type=event_type,
                actor_id="test_actor",
                action="test_action"
            )
            entry = ledger.append_event(event)
            
            retrieved_event = entry.get_event()
            assert retrieved_event.event_type == event_type
    
    def test_event_with_metadata(self, ledger):
        """Test events with complex metadata."""
        metadata = {
            "nested": {"key": "value"},
            "list": [1, 2, 3],
            "boolean": True,
            "null": None
        }
        
        event = LedgerEvent(
            event_type=EventType.TOOL_CALL,
            actor_id="test_actor",
            action="test_action",
            metadata=metadata
        )
        
        entry = ledger.append_event(event)
        retrieved_event = entry.get_event()
        
        assert retrieved_event.metadata == metadata
    
    def test_event_content_hash(self, ledger):
        """Test event content hash generation."""
        event = LedgerEvent(
            event_type=EventType.TOOL_CALL,
            actor_id="test_actor",
            action="test_action",
            metadata={"key": "value"}
        )
        
        content_hash = event.get_content_hash()
        assert content_hash is not None
        assert len(content_hash) == 64  # SHA-256 hex length
        
        # Same event should produce same hash
        event2 = LedgerEvent(
            event_type=EventType.TOOL_CALL,
            actor_id="test_actor",
            action="test_action",
            metadata={"key": "value"}
        )
        
        assert event2.get_content_hash() == content_hash
        
        # Different event should produce different hash
        event3 = LedgerEvent(
            event_type=EventType.TOOL_CALL,
            actor_id="test_actor",
            action="different_action",
            metadata={"key": "value"}
        )
        
        assert event3.get_content_hash() != content_hash
