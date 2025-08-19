"""Policy evaluation HTTP routes."""

from typing import Any, Dict

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from fastmcp.policy import PolicyEngine
from fastmcp.utilities.logging import get_logger

logger = get_logger(__name__)


async def policy_evaluate_endpoint(request: Request) -> JSONResponse:
    """HTTP endpoint for policy evaluation.
    
    Expected JSON body:
    {
        "context": {
            "user": {...},
            "action": "read",
            "resource": {...},
            ...
        },
        "policy_names": ["policy1", "policy2"]  // optional
    }
    """
    try:
        # Parse request body
        body = await request.json()
        
        # Get policy engine from request state
        policy_engine: PolicyEngine = request.app.state.policy_engine
        
        # Extract context and optional policy names
        context = body.get("context", {})
        policy_names = body.get("policy_names")
        
        if not context:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "Missing required 'context' field",
                    "reason": "Policy evaluation requires a context object"
                }
            )
        
        # Evaluate policies
        decision = await policy_engine.evaluate(context, policy_names)
        
        # Return structured decision
        return JSONResponse(
            status_code=200,
            content=decision.to_dict()
        )
        
    except Exception as e:
        logger.error(f"Policy evaluation error: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "Policy evaluation failed",
                "reason": str(e)
            }
        )


def create_policy_evaluate_route(policy_engine: PolicyEngine) -> Route:
    """Create the policy evaluation route.
    
    Args:
        policy_engine: The policy engine instance
        
    Returns:
        Starlette Route for policy evaluation
    """
    async def endpoint_with_engine(request: Request) -> JSONResponse:
        # Store policy engine in app state for access in endpoint
        request.app.state.policy_engine = policy_engine
        return await policy_evaluate_endpoint(request)
    
    return Route(
        path="/policy/evaluate",
        endpoint=endpoint_with_engine,
        methods=["POST"]
    )
