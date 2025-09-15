"""Action components for the reflexive core."""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from .engine import ReflexiveDecision, ActionContext
from fastmcp.utilities.logging import get_logger

logger = get_logger(__name__)


class ReflexiveAction(BaseModel, ABC):
    """Base class for reflexive actions."""
    
    action_id: UUID = Field(default_factory=uuid4, description="Unique action identifier")
    decision: ReflexiveDecision = Field(..., description="The decision that triggered this action")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="When the action was created")
    status: str = Field(default="pending", description="Action status")
    result: Optional[Dict[str, Any]] = Field(default=None, description="Action result")
    
    @abstractmethod
    async def execute(self) -> Dict[str, Any]:
        """Execute the reflexive action."""
        pass
    
    @abstractmethod
    def get_action_type(self) -> str:
        """Get the type of this action."""
        pass


class HaltAction(ReflexiveAction):
    """Action to halt unsafe execution."""
    
    halt_reason: str = Field(..., description="Reason for halting")
    halt_level: str = Field(default="immediate", description="Level of halt (immediate, graceful, etc.)")
    affected_operations: List[str] = Field(default_factory=list, description="Operations affected by the halt")
    
    async def execute(self) -> Dict[str, Any]:
        """Execute the halt action."""
        try:
            self.status = "executing"
            
            # Log the halt
            logger.critical(f"HALTING OPERATIONS: {self.halt_reason}")
            logger.critical(f"Affected operations: {self.affected_operations}")
            logger.critical(f"Decision ID: {self.decision.decision_id}")
            
            # In a real implementation, this would:
            # 1. Stop the current operation
            # 2. Cancel pending operations
            # 3. Notify relevant systems
            # 4. Update system state
            
            # Simulate halt execution
            halt_result = {
                "halted_operations": self.affected_operations,
                "halt_timestamp": self.timestamp.isoformat(),
                "halt_reason": self.halt_reason,
                "halt_level": self.halt_level,
                "decision_id": str(self.decision.decision_id)
            }
            
            self.result = halt_result
            self.status = "completed"
            
            logger.info(f"Halt action completed: {self.action_id}")
            return halt_result
            
        except Exception as e:
            self.status = "failed"
            self.result = {"error": str(e)}
            logger.error(f"Halt action failed: {e}")
            raise
    
    def get_action_type(self) -> str:
        """Get the type of this action."""
        return "halt"


class EscalateAction(ReflexiveAction):
    """Action to escalate an issue to higher authority."""
    
    escalation_target: str = Field(..., description="Target role/entity for escalation")
    escalation_priority: str = Field(default="normal", description="Priority of the escalation")
    escalation_context: Dict[str, Any] = Field(default_factory=dict, description="Additional context for escalation")
    notification_channels: List[str] = Field(default_factory=list, description="Channels to use for notification")
    
    async def execute(self) -> Dict[str, Any]:
        """Execute the escalation action."""
        try:
            self.status = "executing"
            
            # Log the escalation
            logger.warning(f"ESCALATING TO {self.escalation_target}: {self.decision.reason}")
            logger.warning(f"Priority: {self.escalation_priority}")
            logger.warning(f"Decision ID: {self.decision.decision_id}")
            
            # In a real implementation, this would:
            # 1. Create escalation ticket/alert
            # 2. Send notifications via configured channels
            # 3. Update escalation tracking
            # 4. Set up monitoring for response
            
            # Simulate escalation execution
            escalation_result = {
                "escalation_target": self.escalation_target,
                "escalation_priority": self.escalation_priority,
                "escalation_timestamp": self.timestamp.isoformat(),
                "escalation_context": self.escalation_context,
                "notification_channels": self.notification_channels,
                "decision_id": str(self.decision.decision_id),
                "action_context": self.decision.action_context.model_dump(mode='json')
            }
            
            self.result = escalation_result
            self.status = "completed"
            
            logger.info(f"Escalation action completed: {self.action_id}")
            return escalation_result
            
        except Exception as e:
            self.status = "failed"
            self.result = {"error": str(e)}
            logger.error(f"Escalation action failed: {e}")
            raise
    
    def get_action_type(self) -> str:
        """Get the type of this action."""
        return "escalate"


class MonitorAction(ReflexiveAction):
    """Action to increase monitoring for an operation."""
    
    monitoring_level: str = Field(default="enhanced", description="Level of monitoring to apply")
    monitoring_duration: int = Field(default=3600, description="Duration of enhanced monitoring in seconds")
    monitoring_scope: List[str] = Field(default_factory=list, description="Scope of monitoring")
    
    async def execute(self) -> Dict[str, Any]:
        """Execute the monitoring action."""
        try:
            self.status = "executing"
            
            # Log the monitoring increase
            logger.info(f"ENHANCING MONITORING: {self.decision.reason}")
            logger.info(f"Monitoring level: {self.monitoring_level}")
            logger.info(f"Duration: {self.monitoring_duration} seconds")
            
            # In a real implementation, this would:
            # 1. Increase logging verbosity
            # 2. Add additional monitoring points
            # 3. Set up alerts for specific conditions
            # 4. Schedule monitoring reduction after duration
            
            # Simulate monitoring execution
            monitoring_result = {
                "monitoring_level": self.monitoring_level,
                "monitoring_duration": self.monitoring_duration,
                "monitoring_scope": self.monitoring_scope,
                "monitoring_timestamp": self.timestamp.isoformat(),
                "decision_id": str(self.decision.decision_id),
                "action_context": self.decision.action_context.model_dump(mode='json')
            }
            
            self.result = monitoring_result
            self.status = "completed"
            
            logger.info(f"Monitoring action completed: {self.action_id}")
            return monitoring_result
            
        except Exception as e:
            self.status = "failed"
            self.result = {"error": str(e)}
            logger.error(f"Monitoring action failed: {e}")
            raise
    
    def get_action_type(self) -> str:
        """Get the type of this action."""
        return "monitor"


class AllowAction(ReflexiveAction):
    """Action to allow an operation to proceed."""
    
    allow_conditions: List[str] = Field(default_factory=list, description="Conditions under which the action is allowed")
    allow_restrictions: List[str] = Field(default_factory=list, description="Restrictions that still apply")
    
    async def execute(self) -> Dict[str, Any]:
        """Execute the allow action."""
        try:
            self.status = "executing"
            
            # Log the allowance
            logger.debug(f"ALLOWING OPERATION: {self.decision.action_context.action_id}")
            logger.debug(f"Reason: {self.decision.reason}")
            
            # In a real implementation, this would:
            # 1. Remove any temporary restrictions
            # 2. Log the decision for audit
            # 3. Continue normal operation flow
            
            # Simulate allow execution
            allow_result = {
                "allowed": True,
                "allow_timestamp": self.timestamp.isoformat(),
                "allow_conditions": self.allow_conditions,
                "allow_restrictions": self.allow_restrictions,
                "decision_id": str(self.decision.decision_id),
                "action_context": self.decision.action_context.model_dump(mode='json')
            }
            
            self.result = allow_result
            self.status = "completed"
            
            logger.debug(f"Allow action completed: {self.action_id}")
            return allow_result
            
        except Exception as e:
            self.status = "failed"
            self.result = {"error": str(e)}
            logger.error(f"Allow action failed: {e}")
            raise
    
    def get_action_type(self) -> str:
        """Get the type of this action."""
        return "allow"


class ActionFactory:
    """Factory for creating reflexive actions."""
    
    @staticmethod
    def create_action(decision: ReflexiveDecision, **kwargs) -> ReflexiveAction:
        """Create a reflexive action based on a decision."""
        decision_type = decision.decision_type.value if hasattr(decision.decision_type, 'value') else str(decision.decision_type)
        
        if decision_type == "halt":
            return HaltAction(
                decision=decision,
                halt_reason=decision.reason,
                halt_level=kwargs.get("halt_level", "immediate"),
                affected_operations=kwargs.get("affected_operations", [decision.action_context.action_id])
            )
        elif decision_type == "escalate":
            return EscalateAction(
                decision=decision,
                escalation_target=decision.escalated_to or "default_admin",
                escalation_priority=kwargs.get("escalation_priority", "normal"),
                escalation_context=kwargs.get("escalation_context", {}),
                notification_channels=kwargs.get("notification_channels", ["email", "slack"])
            )
        elif decision_type == "monitor":
            return MonitorAction(
                decision=decision,
                monitoring_level=kwargs.get("monitoring_level", "enhanced"),
                monitoring_duration=kwargs.get("monitoring_duration", 3600),
                monitoring_scope=kwargs.get("monitoring_scope", [decision.action_context.actor_id])
            )
        elif decision_type == "allow":
            return AllowAction(
                decision=decision,
                allow_conditions=kwargs.get("allow_conditions", []),
                allow_restrictions=kwargs.get("allow_restrictions", [])
            )
        else:
            raise ValueError(f"Unknown decision type: {decision.decision_type}")


class ActionExecutor:
    """Executor for reflexive actions."""
    
    def __init__(self):
        """Initialize the action executor."""
        self.execution_history = []
        self.active_actions = {}
    
    async def execute_action(self, action: ReflexiveAction) -> Dict[str, Any]:
        """Execute a reflexive action."""
        try:
            # Record the action
            self.active_actions[str(action.action_id)] = action
            self.execution_history.append({
                "action_id": str(action.action_id),
                "action_type": action.get_action_type(),
                "decision_id": str(action.decision.decision_id),
                "start_time": action.timestamp.isoformat(),
                "status": action.status
            })
            
            # Execute the action
            result = await action.execute()
            
            # Update history
            for record in self.execution_history:
                if record["action_id"] == str(action.action_id):
                    record["end_time"] = datetime.utcnow().isoformat()
                    record["status"] = action.status
                    record["result"] = result
                    break
            
            # Remove from active actions
            if str(action.action_id) in self.active_actions:
                del self.active_actions[str(action.action_id)]
            
            return result
            
        except Exception as e:
            # Update history with error
            for record in self.execution_history:
                if record["action_id"] == str(action.action_id):
                    record["end_time"] = datetime.utcnow().isoformat()
                    record["status"] = "failed"
                    record["error"] = str(e)
                    break
            
            # Remove from active actions
            if str(action.action_id) in self.active_actions:
                del self.active_actions[str(action.action_id)]
            
            raise
    
    def get_execution_stats(self) -> Dict[str, Any]:
        """Get execution statistics."""
        total_actions = len(self.execution_history)
        completed_actions = len([a for a in self.execution_history if a.get("status") == "completed"])
        failed_actions = len([a for a in self.execution_history if a.get("status") == "failed"])
        active_actions = len(self.active_actions)
        
        return {
            "total_actions": total_actions,
            "completed_actions": completed_actions,
            "failed_actions": failed_actions,
            "active_actions": active_actions,
            "success_rate": completed_actions / total_actions if total_actions > 0 else 0
        }
