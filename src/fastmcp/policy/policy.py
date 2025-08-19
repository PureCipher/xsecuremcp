"""Policy interface and base classes."""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from .decision import Decision


class Policy(ABC):
    """Base class for all policies."""
    
    def __init__(self, name: str, version: str = "1.0.0"):
        self.name = name
        self.version = version
    
    @abstractmethod
    async def evaluate(self, context: Dict[str, Any]) -> Decision:
        """Evaluate the policy against the given context.
        
        Args:
            context: The context containing information about the request,
                    user, resource, action, etc.
        
        Returns:
            A Decision object indicating whether access is allowed or denied.
        """
        pass
    
    def get_metadata(self) -> Dict[str, Any]:
        """Get policy metadata."""
        return {
            "name": self.name,
            "version": self.version,
            "type": self.__class__.__name__,
        }


class PolicyContext:
    """Context for policy evaluation."""
    
    def __init__(
        self,
        user: Optional[Dict[str, Any]] = None,
        resource: Optional[Dict[str, Any]] = None,
        action: Optional[str] = None,
        environment: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        self.user = user or {}
        self.resource = resource or {}
        self.action = action
        self.environment = environment or {}
        self.extra = kwargs
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert context to dictionary."""
        return {
            "user": self.user,
            "resource": self.resource,
            "action": self.action,
            "environment": self.environment,
            **self.extra,
        }
