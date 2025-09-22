"""Example demonstrating the FastMCP Provenance Ledger functionality."""

import asyncio
from datetime import datetime
from fastmcp import FastMCP
from fastmcp.ledger import ProvenanceLedger, LedgerEvent, EventType


def create_ledger_server():
    """Create a FastMCP server with ledger functionality."""
    server = FastMCP("LedgerExampleServer")
    
    # Enable the provenance ledger
    ledger = server.enable_ledger(database_url="sqlite:///example_ledger.db")
    
    @server.tool
    def log_tool_call(tool_name: str, parameters: dict, result: str) -> str:
        """Log a tool call to the provenance ledger."""
        # Create a ledger event
        event = LedgerEvent(
            event_type=EventType.TOOL_CALL,
            actor_id="system",
            resource_id=f"tool://{tool_name}",
            action="execute",
            metadata={
                "tool_name": tool_name,
                "parameters": parameters,
                "result": result,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
        
        # Append to ledger
        entry = ledger.append_event(event)
        
        return f"Logged tool call {tool_name} as entry {entry.sequence_number}"
    
    @server.tool
    def log_policy_decision(policy_name: str, decision: str, context: dict) -> str:
        """Log a policy decision to the provenance ledger."""
        event = LedgerEvent(
            event_type=EventType.POLICY_DECISION,
            actor_id="policy_engine",
            resource_id=f"policy://{policy_name}",
            action="evaluate",
            metadata={
                "policy_name": policy_name,
                "decision": decision,
                "context": context,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
        
        entry = ledger.append_event(event)
        return f"Logged policy decision {policy_name} as entry {entry.sequence_number}"
    
    @server.tool
    def log_data_flow(source: str, destination: str, data_type: str, size: int) -> str:
        """Log a data flow event to the provenance ledger."""
        event = LedgerEvent(
            event_type=EventType.DATA_FLOW,
            actor_id="data_processor",
            resource_id=f"data://{source}",
            action="transfer",
            metadata={
                "source": source,
                "destination": destination,
                "data_type": data_type,
                "size_bytes": size,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
        
        entry = ledger.append_event(event)
        return f"Logged data flow from {source} to {destination} as entry {entry.sequence_number}"
    
    @server.tool
    def verify_ledger_integrity() -> dict:
        """Verify the integrity of the entire ledger."""
        # Verify chain integrity
        chain_valid = ledger.verify_chain_integrity()
        
        # Get statistics
        stats = ledger.get_ledger_statistics()
        
        return {
            "chain_integrity": chain_valid,
            "statistics": stats,
            "verification_timestamp": datetime.utcnow().isoformat()
        }
    
    @server.tool
    def get_ledger_entry(sequence_number: int) -> dict:
        """Get a specific ledger entry."""
        entry = ledger.get_entry(sequence_number)
        
        if not entry:
            return {"error": f"Entry {sequence_number} not found"}
        
        event = entry.get_event()
        
        return {
            "sequence_number": entry.sequence_number,
            "entry_hash": entry.entry_hash,
            "previous_hash": entry.previous_hash,
            "created_at": entry.created_at.isoformat(),
            "event": {
                "type": event.event_type,
                "actor_id": event.actor_id,
                "action": event.action,
                "metadata": event.metadata
            }
        }
    
    return server, ledger


async def demonstrate_ledger_functionality():
    """Demonstrate the ledger functionality."""
    print("🚀 Creating FastMCP server with Provenance Ledger...")
    server, ledger = create_ledger_server()
    
    print("\n📝 Logging various events to the ledger...")
    
    # Log some tool calls
    print(server._tool_manager.call_tool("log_tool_call", {
        "tool_name": "file_reader",
        "parameters": {"path": "/data/file.txt"},
        "result": "success"
    }))
    
    print(server._tool_manager.call_tool("log_tool_call", {
        "tool_name": "data_processor",
        "parameters": {"input": "raw_data", "format": "json"},
        "result": "processed_data"
    }))
    
    # Log policy decisions
    print(server._tool_manager.call_tool("log_policy_decision", {
        "policy_name": "access_control",
        "decision": "allow",
        "context": {"user": "alice", "resource": "sensitive_data"}
    }))
    
    print(server._tool_manager.call_tool("log_policy_decision", {
        "policy_name": "data_retention",
        "decision": "delete",
        "context": {"age_days": 365, "type": "logs"}
    }))
    
    # Log data flows
    print(server._tool_manager.call_tool("log_data_flow", {
        "source": "database",
        "destination": "cache",
        "data_type": "user_profiles",
        "size": 1024
    }))
    
    print(server._tool_manager.call_tool("log_data_flow", {
        "source": "api",
        "destination": "analytics",
        "data_type": "usage_metrics",
        "size": 512
    }))
    
    print("\n🔍 Verifying ledger integrity...")
    integrity_result = server._tool_manager.call_tool("verify_ledger_integrity", {})
    print(f"Chain integrity: {integrity_result['chain_integrity']}")
    print(f"Total entries: {integrity_result['statistics']['total_entries']}")
    print(f"Total blocks: {integrity_result['statistics']['total_blocks']}")
    
    print("\n📋 Retrieving specific entries...")
    for i in range(1, 4):
        entry = server._tool_manager.call_tool("get_ledger_entry", {"sequence_number": i})
        if "error" not in entry:
            print(f"Entry {i}: {entry['event']['type']} - {entry['event']['action']}")
    
    print("\n🔗 Demonstrating hash chaining...")
    entry1 = ledger.get_entry(1)
    entry2 = ledger.get_entry(2)
    
    if entry1 and entry2:
        print(f"Entry 1 hash: {entry1.entry_hash[:16]}...")
        print(f"Entry 2 previous hash: {entry2.previous_hash[:16]}...")
        print(f"Hash chain intact: {entry2.previous_hash == entry1.entry_hash}")
    
    print("\n🌳 Demonstrating Merkle tree verification...")
    # Get the first block
    block = ledger.get_block(1)
    if block:
        print(f"Block 1 Merkle root: {block.merkle_root[:16]}...")
        print(f"Block 1 entry count: {block.entry_count}")
        
        # Verify block integrity
        block_valid = ledger.verify_block_integrity(1)
        print(f"Block 1 integrity: {block_valid}")
    
    print("\n✅ Ledger demonstration complete!")
    print("\nThe ledger provides:")
    print("- Tamper-evident hash chaining between entries")
    print("- Merkle tree verification for blocks")
    print("- Cryptographic integrity guarantees")
    print("- Audit trail for all system events")
    print("- HTTP API endpoints for external access")


if __name__ == "__main__":
    asyncio.run(demonstrate_ledger_functionality())
