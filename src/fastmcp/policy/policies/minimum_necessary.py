"""Minimum Necessary Access Policy implementation."""

from typing import Any, Dict, List, Set, Optional

from ..policy import Policy
from ..decision import Decision


class MinimumNecessaryAccessPolicy(Policy):
    """Policy that enforces minimum necessary access principles."""
    
    def __init__(
        self, 
        name: str = "minimum_necessary_access",
        version: str = "1.0.0",
        sensitive_actions: Optional[List[str]] = None,
        sensitive_resources: Optional[List[str]] = None,
        required_justification: bool = True
    ):
        super().__init__(name, version)
        self.sensitive_actions = set(sensitive_actions or [
            "delete", "modify", "admin", "root", "sudo", "privileged"
        ])
        self.sensitive_resources = set(sensitive_resources or [
            "user_data", "financial", "medical", "personal", "confidential"
        ])
        self.required_justification = required_justification
    
    async def evaluate(self, context: Dict[str, Any]) -> Decision:
        """Evaluate minimum necessary access policy.
        
        Args:
            context: The context containing user, action, resource information
            
        Returns:
            Decision indicating whether access is allowed
        """
        user = context.get("user", {})
        action = context.get("action", "")
        resource = context.get("resource", {})
        
        # Check if action is sensitive
        action_lower = action.lower()
        is_sensitive_action = any(
            sensitive in action_lower for sensitive in self.sensitive_actions
        )
        
        # Check if resource is sensitive
        resource_type = resource.get("type", "")
        resource_tags = resource.get("tags", [])
        is_sensitive_resource = (
            resource_type in self.sensitive_resources or
            any(tag in self.sensitive_resources for tag in resource_tags)
        )
        
        # If neither action nor resource is sensitive, allow
        if not is_sensitive_action and not is_sensitive_resource:
            return Decision.allow_decision(
                reason="Action and resource are not sensitive",
                proof={
                    "action_sensitive": False,
                    "resource_sensitive": False
                }
            )
        
        # Check for justification if required
        if self.required_justification:
            justification = context.get("justification", "")
            if not justification or len(justification.strip()) < 10:
                return Decision.deny_decision(
                    reason="Sensitive operation requires justification",
                    obligations=[
                        {
                            "type": "provide_justification",
                            "description": "Provide a detailed justification for this sensitive operation"
                        }
                    ],
                    proof={
                        "action_sensitive": is_sensitive_action,
                        "resource_sensitive": is_sensitive_resource,
                        "justification_provided": bool(justification),
                        "justification_length": len(justification) if justification else 0
                    }
                )
        
        # Check user permissions
        user_roles = user.get("roles", [])
        user_permissions = user.get("permissions", [])
        
        # Allow if user has explicit permission
        if "admin" in user_roles or "privileged" in user_permissions:
            return Decision.allow_decision(
                reason="User has privileged access",
                obligations=[
                    {
                        "type": "audit_log",
                        "description": "Log this sensitive operation for audit purposes"
                    }
                ],
                proof={
                    "user_roles": user_roles,
                    "user_permissions": user_permissions,
                    "action_sensitive": is_sensitive_action,
                    "resource_sensitive": is_sensitive_resource
                }
            )
        
        # Check for time-based restrictions
        time_context = context.get("time", {})
        current_hour = time_context.get("hour", 0)
        
        # Restrict sensitive operations during off-hours (example: 10 PM to 6 AM)
        if is_sensitive_action and (current_hour >= 22 or current_hour < 6):
            return Decision.deny_decision(
                reason="Sensitive operations restricted during off-hours",
                obligations=[
                    {
                        "type": "schedule_operation",
                        "description": "Schedule this operation during business hours"
                    }
                ],
                proof={
                    "current_hour": current_hour,
                    "off_hours": True,
                    "action_sensitive": True
                }
            )
        
        # Default deny for sensitive operations without proper authorization
        return Decision.deny_decision(
            reason="Insufficient permissions for sensitive operation",
            obligations=[
                {
                    "type": "request_approval",
                    "description": "Request approval from administrator"
                }
            ],
            proof={
                "action_sensitive": is_sensitive_action,
                "resource_sensitive": is_sensitive_resource,
                "user_roles": user_roles,
                "user_permissions": user_permissions
            }
        )
