"""Policy engine for coordinating policy evaluation."""

from typing import Any, Dict, List, Optional

from fastmcp.utilities.logging import get_logger

from .decision import Decision
from .policy import Policy, PolicyContext
from .registry import PolicyRegistry

logger = get_logger(__name__)


class PolicyEngine:
    """Engine for evaluating policies."""
    
    def __init__(self, registry: Optional[PolicyRegistry] = None):
        self.registry = registry or PolicyRegistry()
        self._evaluation_order: List[str] = []
    
    def set_evaluation_order(self, policy_names: List[str]) -> None:
        """Set the order in which policies should be evaluated.
        
        Args:
            policy_names: List of policy names in evaluation order
        """
        self._evaluation_order = policy_names.copy()
        logger.info(f"Set policy evaluation order: {policy_names}")
    
    async def evaluate(
        self, 
        context: Dict[str, Any], 
        policy_names: Optional[List[str]] = None
    ) -> Decision:
        """Evaluate policies against the given context.
        
        Args:
            context: The context for evaluation
            policy_names: Optional list of policy names to evaluate.
                         If None, evaluates all registered policies.
        
        Returns:
            The final decision after evaluating all policies
        """
        if policy_names is None:
            # Use evaluation order if set, otherwise use all policies
            if self._evaluation_order:
                policy_names = self._evaluation_order
            else:
                policy_names = list(self.registry._policies.keys())
        
        logger.debug(f"Evaluating policies: {policy_names}")
        
        # Evaluate each policy in order
        for policy_name in policy_names:
            policy = self.registry.get_policy(policy_name)
            if not policy:
                logger.warning(f"Policy not found: {policy_name}")
                continue
            
            try:
                decision = await policy.evaluate(context)
                logger.debug(f"Policy {policy_name} decision: {decision.allow} - {decision.reason}")
                
                # If any policy denies, return deny decision
                if not decision.allow:
                    return decision
                    
            except Exception as e:
                logger.error(f"Error evaluating policy {policy_name}: {e}")
                return Decision.deny_decision(
                    reason=f"Policy evaluation error: {e}",
                    proof={"policy": policy_name, "error": str(e)}
                )
        
        # All policies allowed
        return Decision.allow_decision(
            reason="All policies evaluated successfully",
            proof={"evaluated_policies": policy_names}
        )
    
    async def evaluate_single_policy(
        self, 
        policy_name: str, 
        context: Dict[str, Any]
    ) -> Optional[Decision]:
        """Evaluate a single policy.
        
        Args:
            policy_name: The name of the policy to evaluate
            context: The context for evaluation
            
        Returns:
            The decision, or None if policy not found
        """
        policy = self.registry.get_policy(policy_name)
        if not policy:
            logger.warning(f"Policy not found: {policy_name}")
            return None
        
        try:
            decision = await policy.evaluate(context)
            logger.debug(f"Single policy {policy_name} decision: {decision.allow} - {decision.reason}")
            return decision
        except Exception as e:
            logger.error(f"Error evaluating policy {policy_name}: {e}")
            return Decision.deny_decision(
                reason=f"Policy evaluation error: {e}",
                proof={"policy": policy_name, "error": str(e)}
            )
    
    def get_policy_metadata(self) -> List[Dict[str, Any]]:
        """Get metadata for all registered policies.
        
        Returns:
            List of policy metadata dictionaries
        """
        return self.registry.list_policies()
    
    def register_policy(self, policy: Policy) -> None:
        """Register a policy with the engine.
        
        Args:
            policy: The policy to register
        """
        self.registry.register_policy(policy)
    
    def unregister_policy(self, name: str) -> Optional[Policy]:
        """Unregister a policy from the engine.
        
        Args:
            name: The name of the policy to unregister
            
        Returns:
            The unregistered policy, or None if not found
        """
        return self.registry.unregister_policy(name)
