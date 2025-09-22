"""Ledger management HTTP routes."""

from typing import Any, Dict, List, Optional
from uuid import UUID

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from fastmcp.ledger import ProvenanceLedger, LedgerEvent, EventType, MerkleProof, LedgerBlock
from fastmcp.utilities.logging import get_logger

logger = get_logger(__name__)


async def append_event_endpoint(request: Request) -> JSONResponse:
    """HTTP endpoint for appending events to the ledger.
    
    Expected JSON body:
    {
        "event_type": "tool_call",
        "actor_id": "user123",
        "resource_id": "resource456",
        "action": "execute_tool",
        "metadata": {...},
        "data_hash": "sha256_hash_of_data"
    }
    """
    try:
        # Parse request body
        body = await request.json()
        
        # Get ledger from request state
        ledger: ProvenanceLedger = request.app.state.ledger
        
        # Create ledger event
        event = LedgerEvent(**body)
        
        # Append to ledger
        entry = ledger.append_event(event)
        
        return JSONResponse(
            status_code=201,
            content={
                "entry_id": str(entry.id),
                "sequence_number": entry.sequence_number,
                "entry_hash": entry.entry_hash,
                "block_id": str(entry.block_id) if entry.block_id else None,
                "created_at": entry.created_at.isoformat()
            }
        )
        
    except ValueError as e:
        logger.error(f"Invalid event data: {e}")
        return JSONResponse(
            status_code=400,
            content={
                "error": "Invalid event data",
                "reason": str(e)
            }
        )
    except Exception as e:
        logger.error(f"Failed to append event: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "Failed to append event",
                "reason": str(e)
            }
        )


async def verify_block_endpoint(request: Request) -> JSONResponse:
    """HTTP endpoint for verifying block integrity.
    
    Path parameter: block_number (int)
    """
    try:
        # Get block number from path
        block_number = int(request.path_params["block"])
        
        # Get ledger from request state
        ledger: ProvenanceLedger = request.app.state.ledger
        
        # Verify block integrity
        is_valid = ledger.verify_block_integrity(block_number)
        
        if not is_valid:
            return JSONResponse(
                status_code=400,
                content={
                    "block_number": block_number,
                    "verified": False,
                    "error": "Block integrity verification failed"
                }
            )
        
        # Get block details
        block = ledger.get_block(block_number)
        entries = ledger.get_block_entries(block_number)
        
        return JSONResponse(
            status_code=200,
            content={
                "block_number": block_number,
                "verified": True,
                "block_id": str(block.id) if block else None,
                "entry_count": len(entries),
                "merkle_root": block.merkle_root if block else None,
                "sealed_at": block.sealed_at.isoformat() if block and block.sealed_at else None,
                "verification_timestamp": block.verification_timestamp.isoformat() if block and block.verification_timestamp else None
            }
        )
        
    except ValueError as e:
        return JSONResponse(
            status_code=400,
            content={
                "error": "Invalid block number",
                "reason": str(e)
            }
        )
    except Exception as e:
        logger.error(f"Failed to verify block: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "Failed to verify block",
                "reason": str(e)
            }
        )


async def get_entry_endpoint(request: Request) -> JSONResponse:
    """HTTP endpoint for getting a ledger entry by sequence number.
    
    Path parameter: sequence_number (int)
    """
    try:
        # Get sequence number from path
        sequence_number = int(request.path_params["sequence"])
        
        # Get ledger from request state
        ledger: ProvenanceLedger = request.app.state.ledger
        
        # Get entry
        entry = ledger.get_entry(sequence_number)
        
        if not entry:
            return JSONResponse(
                status_code=404,
                content={
                    "error": "Entry not found",
                    "sequence_number": sequence_number
                }
            )
        
        # Get event data
        event = entry.get_event()
        
        return JSONResponse(
            status_code=200,
            content={
                "entry_id": str(entry.id),
                "sequence_number": entry.sequence_number,
                "entry_hash": entry.entry_hash,
                "previous_hash": entry.previous_hash,
                "block_id": str(entry.block_id) if entry.block_id else None,
                "created_at": entry.created_at.isoformat(),
                "is_verified": entry.is_verified,
                "event": {
                    "event_type": event.event_type,
                    "actor_id": event.actor_id,
                    "resource_id": event.resource_id,
                    "action": event.action,
                    "metadata": event.metadata,
                    "timestamp": event.timestamp.isoformat(),
                    "data_hash": event.data_hash
                }
            }
        )
        
    except ValueError as e:
        return JSONResponse(
            status_code=400,
            content={
                "error": "Invalid sequence number",
                "reason": str(e)
            }
        )
    except Exception as e:
        logger.error(f"Failed to get entry: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "Failed to get entry",
                "reason": str(e)
            }
        )


async def get_block_endpoint(request: Request) -> JSONResponse:
    """HTTP endpoint for getting a ledger block by block number.
    
    Path parameter: block_number (int)
    """
    try:
        # Get block number from path
        block_number = int(request.path_params["block"])
        
        # Get ledger from request state
        ledger: ProvenanceLedger = request.app.state.ledger
        
        # Get block
        block = ledger.get_block(block_number)
        
        if not block:
            return JSONResponse(
                status_code=404,
                content={
                    "error": "Block not found",
                    "block_number": block_number
                }
            )
        
        # Get entries in block
        entries = ledger.get_block_entries(block_number)
        
        return JSONResponse(
            status_code=200,
            content={
                "block_id": str(block.id),
                "block_number": block.block_number,
                "entry_count": block.entry_count,
                "first_entry_sequence": block.first_entry_sequence,
                "last_entry_sequence": block.last_entry_sequence,
                "merkle_root": block.merkle_root,
                "created_at": block.created_at.isoformat(),
                "sealed_at": block.sealed_at.isoformat() if block.sealed_at else None,
                "is_verified": block.is_verified,
                "verification_timestamp": block.verification_timestamp.isoformat() if block.verification_timestamp else None,
                "entries": [
                    {
                        "entry_id": str(entry.id),
                        "sequence_number": entry.sequence_number,
                        "entry_hash": entry.entry_hash,
                        "created_at": entry.created_at.isoformat()
                    }
                    for entry in entries
                ]
            }
        )
        
    except ValueError as e:
        return JSONResponse(
            status_code=400,
            content={
                "error": "Invalid block number",
                "reason": str(e)
            }
        )
    except Exception as e:
        logger.error(f"Failed to get block: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "Failed to get block",
                "reason": str(e)
            }
        )


async def verify_chain_endpoint(request: Request) -> JSONResponse:
    """HTTP endpoint for verifying chain integrity.
    
    Query parameters:
    - start_sequence (int, optional): Starting sequence number (default: 1)
    - end_sequence (int, optional): Ending sequence number (default: None)
    """
    try:
        # Get query parameters
        start_sequence = int(request.query_params.get("start_sequence", 1))
        end_sequence = request.query_params.get("end_sequence")
        if end_sequence:
            end_sequence = int(end_sequence)
        
        # Get ledger from request state
        ledger: ProvenanceLedger = request.app.state.ledger
        
        # Verify chain integrity
        is_valid = ledger.verify_chain_integrity(start_sequence, end_sequence)
        
        return JSONResponse(
            status_code=200,
            content={
                "verified": is_valid,
                "start_sequence": start_sequence,
                "end_sequence": end_sequence,
                "verification_timestamp": ledger._get_next_sequence_number() - 1
            }
        )
        
    except ValueError as e:
        return JSONResponse(
            status_code=400,
            content={
                "error": "Invalid sequence parameters",
                "reason": str(e)
            }
        )
    except Exception as e:
        logger.error(f"Failed to verify chain: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "Failed to verify chain",
                "reason": str(e)
            }
        )


async def get_merkle_proof_endpoint(request: Request) -> JSONResponse:
    """HTTP endpoint for getting a Merkle proof for an entry.
    
    Path parameter: sequence_number (int)
    """
    try:
        # Get sequence number from path
        sequence_number = int(request.path_params["sequence"])
        
        # Get ledger from request state
        ledger: ProvenanceLedger = request.app.state.ledger
        
        # Get entry
        entry = ledger.get_entry(sequence_number)
        
        if not entry:
            return JSONResponse(
                status_code=404,
                content={
                    "error": "Entry not found",
                    "sequence_number": sequence_number
                }
            )
        
        # Get block - we need to find the block number from the entry
        block = None
        if entry.block_id:
            # Find the block by querying for the block that contains this entry
            from sqlmodel import Session, select
            with Session(ledger.engine) as session:
                block_query = session.exec(
                    select(LedgerBlock).where(LedgerBlock.id == entry.block_id)
                ).first()
                if block_query:
                    block = ledger.get_block(block_query.block_number)
        
        if not block:
            return JSONResponse(
                status_code=404,
                content={
                    "error": "Block not found for entry",
                    "sequence_number": sequence_number
                }
            )
        
        # Get all entries in block
        entries = ledger.get_block_entries(block.block_number)
        
        # Create Merkle tree and generate proof
        from fastmcp.ledger.merkle import MerkleTree
        entry_hashes = [e.entry_hash for e in entries]
        merkle_tree = MerkleTree(entry_hashes)
        
        proof = merkle_tree.generate_proof(entry.entry_hash)
        
        if not proof:
            return JSONResponse(
                status_code=500,
                content={
                    "error": "Failed to generate Merkle proof",
                    "sequence_number": sequence_number
                }
            )
        
        return JSONResponse(
            status_code=200,
            content={
                "sequence_number": sequence_number,
                "entry_hash": entry.entry_hash,
                "block_number": block.block_number,
                "merkle_root": block.merkle_root,
                "proof": {
                    "leaf_hash": proof.leaf_hash,
                    "path": proof.path,
                    "root_hash": proof.root_hash
                },
                "verified": proof.verify()
            }
        )
        
    except ValueError as e:
        return JSONResponse(
            status_code=400,
            content={
                "error": "Invalid sequence number",
                "reason": str(e)
            }
        )
    except Exception as e:
        logger.error(f"Failed to get Merkle proof: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "Failed to get Merkle proof",
                "reason": str(e)
            }
        )


async def get_ledger_statistics_endpoint(request: Request) -> JSONResponse:
    """HTTP endpoint for getting ledger statistics."""
    try:
        # Get ledger from request state
        ledger: ProvenanceLedger = request.app.state.ledger
        
        # Get statistics
        stats = ledger.get_ledger_statistics()
        
        return JSONResponse(
            status_code=200,
            content=stats
        )
        
    except Exception as e:
        logger.error(f"Failed to get ledger statistics: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "Failed to get ledger statistics",
                "reason": str(e)
            }
        )


def create_ledger_routes(ledger: ProvenanceLedger) -> List[Route]:
    """Create ledger management routes.
    
    Args:
        ledger: The provenance ledger instance
        
    Returns:
        List of Starlette Route objects for ledger management
    """
    def endpoint_with_ledger(endpoint_func):
        async def wrapper(request: Request) -> JSONResponse:
            # Store ledger in app state for access in endpoint
            request.app.state.ledger = ledger
            return await endpoint_func(request)
        return wrapper
    
    return [
        Route(
            path="/ledger/events",
            endpoint=endpoint_with_ledger(append_event_endpoint),
            methods=["POST"]
        ),
        Route(
            path="/ledger/verify/{block}",
            endpoint=endpoint_with_ledger(verify_block_endpoint),
            methods=["GET"]
        ),
        Route(
            path="/ledger/entries/{sequence}",
            endpoint=endpoint_with_ledger(get_entry_endpoint),
            methods=["GET"]
        ),
        Route(
            path="/ledger/blocks/{block}",
            endpoint=endpoint_with_ledger(get_block_endpoint),
            methods=["GET"]
        ),
        Route(
            path="/ledger/verify-chain",
            endpoint=endpoint_with_ledger(verify_chain_endpoint),
            methods=["GET"]
        ),
        Route(
            path="/ledger/proof/{sequence}",
            endpoint=endpoint_with_ledger(get_merkle_proof_endpoint),
            methods=["GET"]
        ),
        Route(
            path="/ledger/statistics",
            endpoint=endpoint_with_ledger(get_ledger_statistics_endpoint),
            methods=["GET"]
        )
    ]
