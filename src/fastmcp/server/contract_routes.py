"""Contract management HTTP routes."""

from typing import Any, Dict, List, Optional
from uuid import UUID

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from fastmcp.contracts import ContractEngine, ContractState
from fastmcp.contracts.contract import (
    ContractCreateRequest, ContractProposeRequest, ContractSignRequest, 
    ContractRevokeRequest, ContractResponse
)
from fastmcp.utilities.logging import get_logger

logger = get_logger(__name__)


async def create_contract_endpoint(request: Request) -> JSONResponse:
    """HTTP endpoint for creating contracts.
    
    Expected JSON body:
    {
        "title": "Contract Title",
        "description": "Contract Description",
        "clauses": [...],
        "parties": [...],
        "is_hipaa_compliant": false,
        "expires_at": "2024-12-31T23:59:59Z"
    }
    """
    try:
        # Parse request body
        body = await request.json()
        
        # Get contract engine from request state
        contract_engine: ContractEngine = request.app.state.contract_engine
        
        # Get creator from headers or body
        created_by = request.headers.get("X-User-ID") or body.get("created_by", "anonymous")
        
        # Create contract request
        contract_request = ContractCreateRequest(**body)
        
        # Create contract
        contract = await contract_engine.create_contract(contract_request, created_by)
        
        # Return contract response
        response = ContractResponse.from_contract(contract)
        return JSONResponse(
            status_code=201,
            content=response.model_dump()
        )
        
    except Exception as e:
        logger.error(f"Contract creation error: {e}")
        return JSONResponse(
            status_code=400,
            content={
                "error": "Contract creation failed",
                "reason": str(e)
            }
        )


async def get_contract_endpoint(request: Request) -> JSONResponse:
    """HTTP endpoint for getting a contract by ID."""
    try:
        # Get contract ID from path
        contract_id = UUID(request.path_params["id"])
        
        # Get contract engine from request state
        contract_engine: ContractEngine = request.app.state.contract_engine
        
        # Get contract
        contract = await contract_engine.get_contract(contract_id)
        
        if not contract:
            return JSONResponse(
                status_code=404,
                content={
                    "error": "Contract not found",
                    "contract_id": str(contract_id)
                }
            )
        
        # Return contract response
        response = ContractResponse.from_contract(contract)
        return JSONResponse(
            status_code=200,
            content=response.model_dump()
        )
        
    except ValueError as e:
        return JSONResponse(
            status_code=400,
            content={
                "error": "Invalid contract ID",
                "reason": str(e)
            }
        )
    except Exception as e:
        logger.error(f"Contract retrieval error: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "Contract retrieval failed",
                "reason": str(e)
            }
        )


async def list_contracts_endpoint(request: Request) -> JSONResponse:
    """HTTP endpoint for listing contracts."""
    try:
        # Get query parameters
        state = request.query_params.get("state")
        created_by = request.query_params.get("created_by")
        
        # Get contract engine from request state
        contract_engine: ContractEngine = request.app.state.contract_engine
        
        # Parse state if provided
        contract_state = None
        if state:
            try:
                contract_state = ContractState(state)
            except ValueError:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "Invalid state",
                        "valid_states": [s.value for s in ContractState]
                    }
                )
        
        # List contracts
        contracts = await contract_engine.list_contracts(contract_state, created_by)
        
        # Convert to response format
        responses = [ContractResponse.from_contract(contract).model_dump() for contract in contracts]
        
        return JSONResponse(
            status_code=200,
            content={
                "contracts": responses,
                "count": len(responses)
            }
        )
        
    except Exception as e:
        logger.error(f"Contract listing error: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "Contract listing failed",
                "reason": str(e)
            }
        )


async def propose_contract_endpoint(request: Request) -> JSONResponse:
    """HTTP endpoint for proposing contracts.
    
    Expected JSON body:
    {
        "proposed_to": ["party1", "party2"],
        "message": "Please review and sign this contract"
    }
    """
    try:
        # Get contract ID from path
        contract_id = UUID(request.path_params["id"])
        
        # Parse request body
        body = await request.json()
        
        # Get contract engine from request state
        contract_engine: ContractEngine = request.app.state.contract_engine
        
        # Get proposer from headers or body
        proposed_by = request.headers.get("X-User-ID") or body.get("proposed_by", "anonymous")
        
        # Create proposal request
        proposal_request = ContractProposeRequest(**body)
        
        # Propose contract
        contract = await contract_engine.propose_contract(contract_id, proposal_request, proposed_by)
        
        if not contract:
            return JSONResponse(
                status_code=404,
                content={
                    "error": "Contract not found",
                    "contract_id": str(contract_id)
                }
            )
        
        # Return contract response
        response = ContractResponse.from_contract(contract)
        return JSONResponse(
            status_code=200,
            content=response.model_dump()
        )
        
    except ValueError as e:
        return JSONResponse(
            status_code=400,
            content={
                "error": "Invalid request",
                "reason": str(e)
            }
        )
    except Exception as e:
        logger.error(f"Contract proposal error: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "Contract proposal failed",
                "reason": str(e)
            }
        )


async def sign_contract_endpoint(request: Request) -> JSONResponse:
    """HTTP endpoint for signing contracts.
    
    Expected JSON body:
    {
        "signer_id": "party1",
        "signer_type": "provider",
        "public_key": "base64_public_key",
        "signature": "base64_signature"
    }
    """
    try:
        # Get contract ID from path
        contract_id = UUID(request.path_params["id"])
        
        # Parse request body
        body = await request.json()
        
        # Get contract engine from request state
        contract_engine: ContractEngine = request.app.state.contract_engine
        
        # Create signing request
        sign_request = ContractSignRequest(**body)
        
        # Sign contract
        contract = await contract_engine.sign_contract(contract_id, sign_request)
        
        if not contract:
            return JSONResponse(
                status_code=404,
                content={
                    "error": "Contract not found",
                    "contract_id": str(contract_id)
                }
            )
        
        # Return contract response
        response = ContractResponse.from_contract(contract)
        return JSONResponse(
            status_code=200,
            content=response.model_dump()
        )
        
    except ValueError as e:
        return JSONResponse(
            status_code=400,
            content={
                "error": "Invalid request",
                "reason": str(e)
            }
        )
    except Exception as e:
        logger.error(f"Contract signing error: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "Contract signing failed",
                "reason": str(e)
            }
        )


async def revoke_contract_endpoint(request: Request) -> JSONResponse:
    """HTTP endpoint for revoking contracts.
    
    Expected JSON body:
    {
        "reason": "Contract terms violated",
        "revoked_by": "party1"
    }
    """
    try:
        # Get contract ID from path
        contract_id = UUID(request.path_params["id"])
        
        # Parse request body
        body = await request.json()
        
        # Get contract engine from request state
        contract_engine: ContractEngine = request.app.state.contract_engine
        
        # Create revocation request
        revoke_request = ContractRevokeRequest(**body)
        
        # Revoke contract
        contract = await contract_engine.revoke_contract(contract_id, revoke_request)
        
        if not contract:
            return JSONResponse(
                status_code=404,
                content={
                    "error": "Contract not found",
                    "contract_id": str(contract_id)
                }
            )
        
        # Return contract response
        response = ContractResponse.from_contract(contract)
        return JSONResponse(
            status_code=200,
            content=response.model_dump()
        )
        
    except ValueError as e:
        return JSONResponse(
            status_code=400,
            content={
                "error": "Invalid request",
                "reason": str(e)
            }
        )
    except Exception as e:
        logger.error(f"Contract revocation error: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "Contract revocation failed",
                "reason": str(e)
            }
        )


async def get_contract_statistics_endpoint(request: Request) -> JSONResponse:
    """HTTP endpoint for getting contract statistics."""
    try:
        # Get contract engine from request state
        contract_engine: ContractEngine = request.app.state.contract_engine
        
        # Get statistics
        stats = await contract_engine.get_contract_statistics()
        
        return JSONResponse(
            status_code=200,
            content=stats
        )
        
    except Exception as e:
        logger.error(f"Contract statistics error: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "Contract statistics failed",
                "reason": str(e)
            }
        )


def create_contract_routes(contract_engine: ContractEngine) -> List[Route]:
    """Create contract management routes.
    
    Args:
        contract_engine: The contract engine instance
        
    Returns:
        List of Starlette Route objects for contract management
    """
    def endpoint_with_engine(endpoint_func):
        async def wrapper(request: Request) -> JSONResponse:
            # Store contract engine in app state for access in endpoint
            request.app.state.contract_engine = contract_engine
            return await endpoint_func(request)
        return wrapper
    
    return [
        Route(
            path="/contracts",
            endpoint=endpoint_with_engine(create_contract_endpoint),
            methods=["POST"]
        ),
        Route(
            path="/contracts",
            endpoint=endpoint_with_engine(list_contracts_endpoint),
            methods=["GET"]
        ),
        Route(
            path="/contracts/statistics",
            endpoint=endpoint_with_engine(get_contract_statistics_endpoint),
            methods=["GET"]
        ),
        Route(
            path="/contracts/{id}",
            endpoint=endpoint_with_engine(get_contract_endpoint),
            methods=["GET"]
        ),
        Route(
            path="/contracts/{id}/propose",
            endpoint=endpoint_with_engine(propose_contract_endpoint),
            methods=["POST"]
        ),
        Route(
            path="/contracts/{id}/sign",
            endpoint=endpoint_with_engine(sign_contract_endpoint),
            methods=["POST"]
        ),
        Route(
            path="/contracts/{id}/revoke",
            endpoint=endpoint_with_engine(revoke_contract_endpoint),
            methods=["POST"]
        )
    ]
