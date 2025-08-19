"""Role-Based Access Control (RBAC) Policy implementation."""

from typing import Any, Dict, List, Optional, Set

from ..policy import Policy
from ..decision import Decision


class RBACPolicy(Policy):
    """Policy that implements Role-Based Access Control."""
    
    def __init__(
        self,
        name: str = "rbac",
        version: str = "1.0.0",
        roles: Optional[Dict[str, Dict[str, Any]]] = None,
        permissions: Optional[Dict[str, List[str]]] = None,
        role_hierarchy: Optional[Dict[str, List[str]]] = None
    ):
        super().__init__(name, version)
        
        # Default roles and permissions
        self.roles = roles or {
            "admin": {
                "description": "Administrator with full access",
                "permissions": ["*"]
            },
            "user": {
                "description": "Regular user with basic access",
                "permissions": ["read", "write"]
            },
            "guest": {
                "description": "Guest user with read-only access",
                "permissions": ["read"]
            }
        }
        
        # Custom permissions mapping
        self.permissions = permissions or {
            "read": ["get", "list", "view", "read"],
            "write": ["create", "update", "modify", "write"],
            "delete": ["remove", "delete", "destroy"],
            "admin": ["admin", "manage", "configure", "privileged"]
        }
        
        # Role hierarchy (inheritance)
        self.role_hierarchy = role_hierarchy or {
            "admin": ["user", "guest"],
            "user": ["guest"]
        }
    
    def _get_user_permissions(self, user_roles: List[str]) -> Set[str]:
        """Get all permissions for a user based on their roles and hierarchy.
        
        Args:
            user_roles: List of user roles
            
        Returns:
            Set of all permissions the user has
        """
        all_permissions = set()
        
        for role in user_roles:
            if role not in self.roles:
                continue
            
            # Get direct permissions for this role
            role_permissions = self.roles[role].get("permissions", [])
            if "*" in role_permissions:
                # Wildcard permission - user has all permissions
                return {"*"}
            
            all_permissions.update(role_permissions)
            
            # Get inherited permissions from role hierarchy
            inherited_roles = self.role_hierarchy.get(role, [])
            for inherited_role in inherited_roles:
                if inherited_role in self.roles:
                    inherited_permissions = self.roles[inherited_role].get("permissions", [])
                    all_permissions.update(inherited_permissions)
        
        return all_permissions
    
    def _check_permission(self, user_permissions: Set[str], required_action: str) -> bool:
        """Check if user has permission for the required action.
        
        Args:
            user_permissions: Set of user permissions
            required_action: The action being performed
            
        Returns:
            True if user has permission, False otherwise
        """
        # Check for wildcard permission
        if "*" in user_permissions:
            return True
        
        # Check direct permission match
        if required_action in user_permissions:
            return True
        
        # Check permission mappings
        for permission, actions in self.permissions.items():
            if permission in user_permissions and required_action in actions:
                return True
        
        return False
    
    async def evaluate(self, context: Dict[str, Any]) -> Decision:
        """Evaluate RBAC policy.
        
        Args:
            context: The context containing user, action, resource information
            
        Returns:
            Decision indicating whether access is allowed
        """
        user = context.get("user", {})
        action = context.get("action", "")
        resource = context.get("resource", {})
        
        # Get user roles
        user_roles = user.get("roles", [])
        if not user_roles:
            return Decision.deny_decision(
                reason="User has no assigned roles",
                proof={
                    "user_roles": user_roles,
                    "action": action
                }
            )
        
        # Get all user permissions
        user_permissions = self._get_user_permissions(user_roles)
        
        # Check if user has permission for the action
        has_permission = self._check_permission(user_permissions, action)
        
        if has_permission:
            # Check resource-specific restrictions
            resource_type = resource.get("type", "")
            resource_owner = resource.get("owner", "")
            user_id = user.get("id", "")
            
            # Allow if user owns the resource or has admin role
            if (resource_owner == user_id or 
                "admin" in user_roles or 
                "*" in user_permissions):
                return Decision.allow_decision(
                    reason="User has permission and owns resource or is admin",
                    obligations=[
                        {
                            "type": "audit_log",
                            "description": "Log this RBAC-authorized operation"
                        }
                    ],
                    proof={
                        "user_roles": user_roles,
                        "user_permissions": list(user_permissions),
                        "action": action,
                        "resource_owner": resource_owner,
                        "user_id": user_id,
                        "permission_check": True
                    }
                )
            
            # Check if resource is public/shared
            resource_visibility = resource.get("visibility", "private")
            if resource_visibility in ["public", "shared"]:
                return Decision.allow_decision(
                    reason="User has permission and resource is public/shared",
                    proof={
                        "user_roles": user_roles,
                        "user_permissions": list(user_permissions),
                        "action": action,
                        "resource_visibility": resource_visibility,
                        "permission_check": True
                    }
                )
            
            # Check for explicit resource permissions
            resource_permissions = resource.get("permissions", {})
            if user_id in resource_permissions:
                user_resource_permissions = resource_permissions[user_id]
                if action in user_resource_permissions or "*" in user_resource_permissions:
                    return Decision.allow_decision(
                        reason="User has explicit resource permission",
                        proof={
                            "user_roles": user_roles,
                            "user_permissions": list(user_permissions),
                            "action": action,
                            "resource_permissions": user_resource_permissions,
                            "permission_check": True
                        }
                    )
            
            # Deny access to private resource without ownership
            return Decision.deny_decision(
                reason="User lacks permission for this private resource",
                obligations=[
                    {
                        "type": "request_access",
                        "description": "Request access from resource owner"
                    }
                ],
                proof={
                    "user_roles": user_roles,
                    "user_permissions": list(user_permissions),
                    "action": action,
                    "resource_owner": resource_owner,
                    "user_id": user_id,
                    "resource_visibility": resource_visibility,
                    "permission_check": True,
                    "ownership_check": False
                }
            )
        else:
            # User doesn't have permission for the action
            return Decision.deny_decision(
                reason="User lacks permission for this action",
                obligations=[
                    {
                        "type": "request_permission",
                        "description": "Request permission from administrator"
                    }
                ],
                proof={
                    "user_roles": user_roles,
                    "user_permissions": list(user_permissions),
                    "action": action,
                    "permission_check": False
                }
            )
