"""Reflexive Core Engine - Main runtime for self-monitoring and corrective actions."""

import asyncio
import json
import hashlib
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Callable, Union
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from fastmcp.utilities.logging import get_logger

logger = get_logger(__name__)


class DecisionType(str, Enum):
    """Types of reflexive decisions."""
    HALT = "halt"
    ESCALATE = "escalate"
    MONITOR = "monitor"
    ALLOW = "allow"


class RiskLevel(str, Enum):
    """Risk levels for reflexive decisions."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionContext(BaseModel):
    """Context for an action being evaluated by the reflexive core."""
    
    action_id: str = Field(..., description="Unique identifier for the action")
    actor_id: str = Field(..., description="ID of the entity performing the action")
    action_type: str = Field(..., description="Type of action being performed")
    resource_id: Optional[str] = Field(default=None, description="ID of the resource being accessed")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional action metadata")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="When the action occurred")
    session_id: Optional[str] = Field(default=None, description="Session identifier")
    request_id: Optional[str] = Field(default=None, description="Request identifier")
    
    def get_context_hash(self) -> str:
        """Get SHA-256 hash of action context for integrity verification."""
        content = {
            "action_id": self.action_id,
            "actor_id": self.actor_id,
            "action_type": self.action_type,
            "resource_id": self.resource_id,
            "metadata": self.metadata,
            "session_id": self.session_id,
            "request_id": self.request_id
        }
        content_str = json.dumps(content, sort_keys=True, default=str)
        return hashlib.sha256(content_str.encode()).hexdigest()


class ReflexiveDecision(BaseModel):
    """A decision made by the reflexive core."""
    
    decision_id: UUID = Field(default_factory=uuid4, description="Unique decision identifier")
    decision_type: DecisionType = Field(..., description="Type of decision made")
    risk_level: RiskLevel = Field(..., description="Risk level of the situation")
    action_context: ActionContext = Field(..., description="Context of the action being evaluated")
    reason: str = Field(..., description="Reason for the decision")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Evidence supporting the decision")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="When the decision was made")
    escalated_to: Optional[str] = Field(default=None, description="Role/entity escalated to")
    proof_hash: Optional[str] = Field(default=None, description="Hash of decision proof")
    
    model_config = {"use_enum_values": True}
    
    def get_decision_hash(self) -> str:
        """Get SHA-256 hash of decision for integrity verification."""
        content = {
            "decision_id": str(self.decision_id),
            "decision_type": self.decision_type,
            "risk_level": self.risk_level,
            "action_context": self.action_context.model_dump(),
            "reason": self.reason,
            "evidence": self.evidence,
            "escalated_to": self.escalated_to
        }
        content_str = json.dumps(content, sort_keys=True, default=str)
        return hashlib.sha256(content_str.encode()).hexdigest()


class ReflexiveEngine:
    """Main reflexive core engine for self-monitoring and corrective actions."""
    
    def __init__(self, policy_engine=None, ledger=None):
        """Initialize the reflexive engine.
        
        Args:
            policy_engine: Policy engine instance for policy monitoring
            ledger: Provenance ledger instance for audit logging
        """
        self.policy_engine = policy_engine
        self.ledger = ledger
        self.monitors: List[Callable] = []
        self.decision_handlers: Dict[DecisionType, Callable] = {}
        self.is_running = False
        self.event_queue = asyncio.Queue()
        
        # Register default decision handlers
        self._register_default_handlers()
        
        logger.info("Reflexive engine initialized")
    
    def _register_default_handlers(self):
        """Register default decision handlers."""
        self.decision_handlers[DecisionType.HALT] = self._handle_halt
        self.decision_handlers[DecisionType.ESCALATE] = self._handle_escalate
        self.decision_handlers[DecisionType.MONITOR] = self._handle_monitor
        self.decision_handlers[DecisionType.ALLOW] = self._handle_allow
    
    async def start(self):
        """Start the reflexive engine."""
        if self.is_running:
            logger.warning("Reflexive engine is already running")
            return
        
        self.is_running = True
        logger.info("Reflexive engine started")
        
        # Start the main event processing loop
        asyncio.create_task(self._process_events())
    
    async def stop(self):
        """Stop the reflexive engine."""
        self.is_running = False
        logger.info("Reflexive engine stopped")
    
    async def _process_events(self):
        """Main event processing loop."""
        while self.is_running:
            try:
                # Wait for events with timeout
                event = await asyncio.wait_for(self.event_queue.get(), timeout=1.0)
                await self._handle_event(event)
            except asyncio.TimeoutError:
                # No events, continue
                continue
            except Exception as e:
                logger.error(f"Error processing reflexive event: {e}")
    
    async def _handle_event(self, event: Dict[str, Any]):
        """Handle a reflexive event."""
        try:
            # Create action context from event
            action_context = ActionContext(**event.get("action_context", {}))
            
            # Evaluate the action
            decision = await self._evaluate_action(action_context)
            
            # Execute the decision
            await self._execute_decision(decision)
            
            # Log the decision to audit trail
            await self._log_decision(decision)
            
        except Exception as e:
            logger.error(f"Error handling reflexive event: {e}")
    
    async def _evaluate_action(self, action_context: ActionContext) -> ReflexiveDecision:
        """Evaluate an action and make a reflexive decision."""
        # Run all monitors
        violations = []
        anomalies = []
        
        for monitor in self.monitors:
            try:
                # Check if monitor is async
                if asyncio.iscoroutinefunction(monitor):
                    result = await monitor(action_context)
                else:
                    result = monitor(action_context)
                if result:
                    if result.get("type") == "violation":
                        violations.append(result)
                    elif result.get("type") == "anomaly":
                        anomalies.append(result)
            except Exception as e:
                logger.error(f"Monitor error: {e}")
        
        # Make decision based on findings
        if violations or anomalies:
            # Determine risk level
            risk_level = self._assess_risk_level(violations, anomalies)
            
            # Make decision based on risk level
            if risk_level == RiskLevel.CRITICAL:
                decision_type = DecisionType.HALT
                reason = f"Critical risk detected: {len(violations)} violations, {len(anomalies)} anomalies"
            elif risk_level == RiskLevel.HIGH:
                decision_type = DecisionType.HALT
                reason = f"High risk detected: {len(violations)} violations, {len(anomalies)} anomalies"
            elif risk_level == RiskLevel.MEDIUM:
                decision_type = DecisionType.ESCALATE
                reason = f"Medium risk detected: {len(violations)} violations, {len(anomalies)} anomalies"
            else:
                decision_type = DecisionType.MONITOR
                reason = f"Low risk detected: {len(violations)} violations, {len(anomalies)} anomalies"
        else:
            decision_type = DecisionType.ALLOW
            reason = "No violations or anomalies detected"
            risk_level = RiskLevel.LOW
        
        # Create decision
        decision = ReflexiveDecision(
            decision_type=decision_type,
            risk_level=risk_level,
            action_context=action_context,
            reason=reason,
            evidence={
                "violations": violations,
                "anomalies": anomalies
            }
        )
        
        # Set proof hash
        decision.proof_hash = decision.get_decision_hash()
        
        return decision
    
    def _assess_risk_level(self, violations: List[Dict], anomalies: List[Dict]) -> RiskLevel:
        """Assess the overall risk level based on violations and anomalies."""
        total_issues = len(violations) + len(anomalies)
        
        # Check for critical violations or anomalies
        critical_violations = [v for v in violations if v.get("severity") == "critical"]
        critical_anomalies = [a for a in anomalies if a.get("severity") == "critical"]
        if critical_violations or critical_anomalies:
            return RiskLevel.CRITICAL
        
        # Check for high severity issues
        high_violations = [v for v in violations if v.get("severity") == "high"]
        high_anomalies = [a for a in anomalies if a.get("severity") == "high"]
        if high_violations or high_anomalies or total_issues >= 5:
            return RiskLevel.HIGH
        
        # Check for medium severity issues
        medium_violations = [v for v in violations if v.get("severity") == "medium"]
        medium_anomalies = [a for a in anomalies if a.get("severity") == "medium"]
        if medium_violations or medium_anomalies or total_issues >= 2:
            return RiskLevel.MEDIUM
        
        return RiskLevel.LOW
    
    async def _execute_decision(self, decision: ReflexiveDecision):
        """Execute a reflexive decision."""
        handler = self.decision_handlers.get(decision.decision_type)
        if handler:
            try:
                await handler(decision)
            except Exception as e:
                logger.error(f"Error executing decision {decision.decision_type}: {e}")
        else:
            logger.warning(f"No handler for decision type: {decision.decision_type}")
    
    async def _handle_halt(self, decision: ReflexiveDecision):
        """Handle a halt decision."""
        logger.critical(f"HALTING ACTION: {decision.action_context.action_id} - {decision.reason}")
        # In a real implementation, this would stop the action execution
        # For now, we just log the halt decision
    
    async def _handle_escalate(self, decision: ReflexiveDecision):
        """Handle an escalate decision."""
        # Determine escalation target
        escalation_target = self._determine_escalation_target(decision)
        decision.escalated_to = escalation_target
        
        logger.warning(f"ESCALATING TO {escalation_target}: {decision.action_context.action_id} - {decision.reason}")
        # In a real implementation, this would notify the escalation target
    
    async def _handle_monitor(self, decision: ReflexiveDecision):
        """Handle a monitor decision."""
        logger.info(f"MONITORING ACTION: {decision.action_context.action_id} - {decision.reason}")
        # In a real implementation, this would increase monitoring for this action
    
    async def _handle_allow(self, decision: ReflexiveDecision):
        """Handle an allow decision."""
        logger.debug(f"ALLOWING ACTION: {decision.action_context.action_id} - {decision.reason}")
        # Action is allowed to proceed
    
    def _determine_escalation_target(self, decision: ReflexiveDecision) -> str:
        """Determine the appropriate escalation target based on the decision."""
        if decision.risk_level == RiskLevel.CRITICAL:
            return "security_admin"
        elif decision.risk_level == RiskLevel.HIGH:
            return "system_admin"
        else:
            return "monitoring_team"
    
    async def _log_decision(self, decision: ReflexiveDecision):
        """Log the reflexive decision to the audit trail."""
        if self.ledger:
            try:
                from fastmcp.ledger import LedgerEvent, EventType
                
                event = LedgerEvent(
                    event_type=EventType.REFLEXIVE_DECISION,
                    actor_id="reflexive_core",
                    resource_id=decision.action_context.action_id,
                    action=f"reflexive_{decision.decision_type}",
                    metadata={
                        "decision_id": str(decision.decision_id),
                        "risk_level": decision.risk_level,
                        "reason": decision.reason,
                        "proof_hash": decision.proof_hash,
                        "escalated_to": decision.escalated_to
                    }
                )
                
                self.ledger.append_event(event)
                logger.debug(f"Logged reflexive decision {decision.decision_id} to audit trail")
                
            except Exception as e:
                logger.error(f"Failed to log reflexive decision: {e}")
        else:
            # Log to standard logger if no ledger is available
            logger.info(f"Reflexive decision: {decision.decision_type} - {decision.reason} (Decision ID: {decision.decision_id})")
    
    def add_monitor(self, monitor: Callable):
        """Add a monitor function to the reflexive engine."""
        self.monitors.append(monitor)
        logger.info(f"Added monitor: {monitor.__name__}")
    
    def remove_monitor(self, monitor: Callable):
        """Remove a monitor function from the reflexive engine."""
        if monitor in self.monitors:
            self.monitors.remove(monitor)
            logger.info(f"Removed monitor: {monitor.__name__}")
    
    async def submit_action(self, action_context: ActionContext):
        """Submit an action for reflexive evaluation."""
        event = {
            "action_context": action_context.model_dump(),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await self.event_queue.put(event)
        logger.debug(f"Submitted action {action_context.action_id} for reflexive evaluation")
    
    async def simulate_risk(self, risk_scenario: Dict[str, Any]) -> ReflexiveDecision:
        """Simulate a risk scenario and return the reflexive decision."""
        # Create action context from scenario
        action_context = ActionContext(**risk_scenario.get("action_context", {}))
        
        # Override monitors temporarily for simulation
        original_monitors = self.monitors.copy()
        
        # Add simulation monitors
        simulation_monitors = risk_scenario.get("monitors", [])
        for monitor_func in simulation_monitors:
            self.monitors.append(monitor_func)
        
        try:
            # Evaluate the action
            decision = await self._evaluate_action(action_context)
            return decision
        finally:
            # Restore original monitors
            self.monitors = original_monitors
    
    def get_engine_status(self) -> Dict[str, Any]:
        """Get the current status of the reflexive engine."""
        return {
            "is_running": self.is_running,
            "monitor_count": len(self.monitors),
            "queue_size": self.event_queue.qsize(),
            "decision_handlers": list(self.decision_handlers.keys())
        }
