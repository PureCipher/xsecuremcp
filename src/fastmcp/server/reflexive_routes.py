"""Reflexive Core HTTP routes."""

from typing import Any, Dict, List, Optional
from uuid import UUID

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from fastmcp.reflexive import ReflexiveEngine, ActionContext, DecisionType, RiskLevel
from fastmcp.reflexive.actions import ActionFactory, ActionExecutor
from fastmcp.utilities.logging import get_logger

logger = get_logger(__name__)


async def simulate_risk_endpoint(request: Request) -> JSONResponse:
    """HTTP endpoint for simulating risk scenarios.
    
    Expected JSON body:
    {
        "action_context": {
            "action_id": "test_action_123",
            "actor_id": "test_user",
            "action_type": "admin_access",
            "resource_id": "sensitive_data",
            "metadata": {...}
        },
        "monitors": [
            // List of monitor functions (for simulation)
        ],
        "scenario_type": "policy_violation" | "anomaly" | "integrity_issue"
    }
    """
    try:
        # Parse request body
        body = await request.json()
        
        # Get reflexive engine from request state
        reflexive_engine: ReflexiveEngine = request.app.state.reflexive_engine
        
        # Validate required fields
        if "action_context" not in body:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "Missing required field: action_context"
                }
            )
        
        # Simulate the risk scenario
        decision = await reflexive_engine.simulate_risk(body)
        
        # Create and execute the corresponding action
        action = ActionFactory.create_action(decision)
        executor = ActionExecutor()
        action_result = await executor.execute_action(action)
        
        return JSONResponse(
            status_code=200,
            content={
                "simulation_id": str(decision.decision_id),
                "decision": {
                    "decision_id": str(decision.decision_id),
                    "decision_type": decision.decision_type,
                    "risk_level": decision.risk_level,
                    "reason": decision.reason,
                    "evidence": decision.evidence,
                    "proof_hash": decision.proof_hash,
                    "escalated_to": decision.escalated_to,
                    "timestamp": decision.timestamp.isoformat()
                },
                "action": {
                    "action_id": str(action.action_id),
                    "action_type": action.get_action_type(),
                    "status": action.status,
                    "result": action_result
                },
                "action_context": decision.action_context.model_dump(mode='json')
            }
        )
        
    except ValueError as e:
        logger.error(f"Invalid simulation data: {e}")
        return JSONResponse(
            status_code=400,
            content={
                "error": "Invalid simulation data",
                "reason": str(e)
            }
        )
    except Exception as e:
        logger.error(f"Failed to simulate risk: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "Failed to simulate risk",
                "reason": str(e)
            }
        )


async def get_engine_status_endpoint(request: Request) -> JSONResponse:
    """HTTP endpoint for getting reflexive engine status."""
    try:
        # Get reflexive engine from request state
        reflexive_engine: ReflexiveEngine = request.app.state.reflexive_engine
        
        # Get engine status
        status = reflexive_engine.get_engine_status()
        
        return JSONResponse(
            status_code=200,
            content=status
        )
        
    except Exception as e:
        logger.error(f"Failed to get engine status: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "Failed to get engine status",
                "reason": str(e)
            }
        )


async def submit_action_endpoint(request: Request) -> JSONResponse:
    """HTTP endpoint for submitting an action for reflexive evaluation.
    
    Expected JSON body:
    {
        "action_id": "action_123",
        "actor_id": "user_456",
        "action_type": "tool_call",
        "resource_id": "resource_789",
        "metadata": {...},
        "session_id": "session_abc",
        "request_id": "request_def"
    }
    """
    try:
        # Parse request body
        body = await request.json()
        
        # Get reflexive engine from request state
        reflexive_engine: ReflexiveEngine = request.app.state.reflexive_engine
        
        # Create action context
        action_context = ActionContext(**body)
        
        # Submit action for evaluation
        await reflexive_engine.submit_action(action_context)
        
        return JSONResponse(
            status_code=202,
            content={
                "message": "Action submitted for reflexive evaluation",
                "action_id": action_context.action_id,
                "submitted_at": action_context.timestamp.isoformat()
            }
        )
        
    except ValueError as e:
        logger.error(f"Invalid action data: {e}")
        return JSONResponse(
            status_code=400,
            content={
                "error": "Invalid action data",
                "reason": str(e)
            }
        )
    except Exception as e:
        logger.error(f"Failed to submit action: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "Failed to submit action",
                "reason": str(e)
            }
        )


async def get_monitor_stats_endpoint(request: Request) -> JSONResponse:
    """HTTP endpoint for getting monitor statistics."""
    try:
        # Get reflexive engine from request state
        reflexive_engine: ReflexiveEngine = request.app.state.reflexive_engine
        
        # Collect stats from all monitors
        stats = {}
        
        for monitor in reflexive_engine.monitors:
            if hasattr(monitor, 'get_violation_stats'):
                stats['policy_monitor'] = monitor.get_violation_stats()
            elif hasattr(monitor, 'get_integrity_stats'):
                stats['ledger_monitor'] = monitor.get_integrity_stats()
            elif hasattr(monitor, 'get_anomaly_stats'):
                stats['anomaly_detector'] = monitor.get_anomaly_stats()
        
        return JSONResponse(
            status_code=200,
            content=stats
        )
        
    except Exception as e:
        logger.error(f"Failed to get monitor stats: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "Failed to get monitor stats",
                "reason": str(e)
            }
        )


async def create_risk_scenario_endpoint(request: Request) -> JSONResponse:
    """HTTP endpoint for creating predefined risk scenarios.
    
    Expected JSON body:
    {
        "scenario_name": "admin_privilege_escalation",
        "scenario_type": "policy_violation",
        "parameters": {
            "actor_type": "guest_user",
            "target_resource": "admin_panel",
            "severity": "high"
        }
    }
    """
    try:
        # Parse request body
        body = await request.json()
        
        scenario_name = body.get("scenario_name")
        scenario_type = body.get("scenario_type")
        parameters = body.get("parameters", {})
        
        if not scenario_name or not scenario_type:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "Missing required fields: scenario_name, scenario_type"
                }
            )
        
        # Create scenario based on type
        scenario = _create_risk_scenario(scenario_name, scenario_type, parameters)
        
        return JSONResponse(
            status_code=200,
            content={
                "scenario": scenario,
                "message": f"Risk scenario '{scenario_name}' created successfully"
            }
        )
        
    except Exception as e:
        logger.error(f"Failed to create risk scenario: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "Failed to create risk scenario",
                "reason": str(e)
            }
        )


def _create_risk_scenario(scenario_name: str, scenario_type: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """Create a predefined risk scenario."""
    scenarios = {
        "admin_privilege_escalation": {
            "action_context": {
                "action_id": f"admin_escalation_{scenario_name}",
                "actor_id": parameters.get("actor_type", "guest_user"),
                "action_type": "admin_access",
                "resource_id": parameters.get("target_resource", "admin_panel"),
                "metadata": {
                    "privilege_level": "admin",
                    "escalation_attempt": True
                }
            },
            "expected_decision": "halt",
            "expected_risk_level": "high"
        },
        "suspicious_activity": {
            "action_context": {
                "action_id": f"suspicious_{scenario_name}",
                "actor_id": "suspicious_user",
                "action_type": "data_access",
                "resource_id": "sensitive_data",
                "metadata": {
                    "access_pattern": "unusual",
                    "time_of_day": "off_hours"
                }
            },
            "expected_decision": "escalate",
            "expected_risk_level": "medium"
        },
        "integrity_violation": {
            "action_context": {
                "action_id": f"integrity_{scenario_name}",
                "actor_id": "system",
                "action_type": "ledger_modification",
                "resource_id": "provenance_ledger",
                "metadata": {
                    "modification_type": "unauthorized",
                    "integrity_check": "failed"
                }
            },
            "expected_decision": "halt",
            "expected_risk_level": "critical"
        },
        "rate_limit_exceeded": {
            "action_context": {
                "action_id": f"rate_limit_{scenario_name}",
                "actor_id": "high_frequency_user",
                "action_type": "api_call",
                "resource_id": "api_endpoint",
                "metadata": {
                    "request_count": 1000,
                    "time_window": "1_minute"
                }
            },
            "expected_decision": "escalate",
            "expected_risk_level": "medium"
        }
    }
    
    return scenarios.get(scenario_name, {
        "action_context": {
            "action_id": f"custom_{scenario_name}",
            "actor_id": "test_user",
            "action_type": "custom_action",
            "resource_id": "test_resource",
            "metadata": parameters
        },
        "expected_decision": "monitor",
        "expected_risk_level": "low"
    })


def create_reflexive_routes(reflexive_engine: ReflexiveEngine) -> List[Route]:
    """Create reflexive core routes.
    
    Args:
        reflexive_engine: The reflexive engine instance
        
    Returns:
        List of Starlette Route objects for reflexive core management
    """
    def endpoint_with_engine(endpoint_func):
        async def wrapper(request: Request) -> JSONResponse:
            # Store reflexive engine in app state for access in endpoint
            request.app.state.reflexive_engine = reflexive_engine
            return await endpoint_func(request)
        return wrapper
    
    return [
        Route(
            path="/core/simulate-risk",
            endpoint=endpoint_with_engine(simulate_risk_endpoint),
            methods=["POST"]
        ),
        Route(
            path="/core/status",
            endpoint=endpoint_with_engine(get_engine_status_endpoint),
            methods=["GET"]
        ),
        Route(
            path="/core/submit-action",
            endpoint=endpoint_with_engine(submit_action_endpoint),
            methods=["POST"]
        ),
        Route(
            path="/core/monitor-stats",
            endpoint=endpoint_with_engine(get_monitor_stats_endpoint),
            methods=["GET"]
        ),
        Route(
            path="/core/risk-scenario",
            endpoint=endpoint_with_engine(create_risk_scenario_endpoint),
            methods=["POST"]
        )
    ]
